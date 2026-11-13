//! `approval.rs` — FR12, ADR-015: the supporter side of deviance approval.
//!
//! Story 6.4 builds what a node needs to decide, deterministically and from
//! chain state alone, whether it endorses a deviating block, and the message it
//! sends when it does: the outbound [`SupportMessage`]. Story 6.5 adds the
//! inbound side, the FR26 intake: the [`SupportView`] a received support is
//! parsed into and the relay-dedupe cache. The proposer-side accumulation and
//! the evidence block are Story 6.6's.

use moonblokz_chain_types::{HASH_SIZE, calculate_hash};
use moonblokz_crypto::MULTI_SIGNATURE_SIZE;

/// FR12 — the support message a node returns, through
/// [`crate::ReceiveBlockOutcome::AcceptedAndSendSupport`], when it endorses a
/// deviating block (D4, owned).
///
/// The bridge frames it into the radio `Support` message (DEC-187), whose
/// body after the type byte and the relay sender is the [`SupportView`]
/// layout: `deviation_sequence ‖ supporter_node_id ‖ proposer_node_id ‖
/// deviation_block_hash ‖ support_signature`. The signature is over the 45-byte content of
/// [`support_message_bytes`], made with the local node's multi-signature key.
///
/// `support_signature` holds the backend's serialized multi-signature bytes,
/// never the backend value itself, which is larger in memory and
/// backend-specific. Owned rather than borrowed: about 108 bytes carried on
/// the stack only along `receive_block`'s return, instead of a static scratch
/// buffer and a lifetime on the outcome.
// Same derive discipline as the outcome enums: no `Copy`/`Clone` in production;
// `Debug` only under test.
#[cfg_attr(test, derive(Debug))]
#[derive(PartialEq, Eq)]
pub struct SupportMessage {
    /// The endorsing (local) node.
    pub supporter_node_id: u32,
    /// The deviating block's creator, to whom the support is addressed.
    pub proposer_node_id: u32,
    /// The deviating block's sequence `p`.
    pub deviation_sequence: u32,
    /// The deviating block's hash.
    pub deviation_block_hash: [u8; HASH_SIZE],
    /// `MultiSignatureTrait::serialize()` of the local node's signature over
    /// [`support_message_bytes`].
    pub support_signature: [u8; MULTI_SIGNATURE_SIZE],
}

/// The circulating currency every subgroup seed uses until Story 7.6 (D1,
/// DEC-212).
///
/// DEC-192 seeds the subgroup with `circulating_currency(p − 1)` — every balance
/// plus every unspent UTXO amount — which no projection holds yet. Until Story
/// 7.6 builds it, the seed takes this fixed value at every position, the same on
/// every node, so the subgroup and its tests run. The seed then varies only
/// with `p` and the proposer and is grindable (AR-013's pre-DEC-192 state);
/// nothing is exposed, because production emits no support before Story 8.5,
/// and Story 7.6 must land before it.
pub(crate) const CIRCULATING_CURRENCY_STUB: u64 = 0;

/// Length of the subgroup seed preimage (D7): `"MBSEED"` ‖ `p` u32 ‖ currency
/// u64 ‖ proposer u32.
const SEED_PREIMAGE_SIZE: usize = 6 + 4 + 8 + 4;

/// Length of the signed support content (D7): `"MBSUP"` ‖ proposer u32 ‖ `p`
/// u32 ‖ the deviation block hash.
pub(crate) const SUPPORT_MESSAGE_SIZE: usize = 5 + 4 + 4 + HASH_SIZE;

/// ADR-015 / DEC-192 — the subgroup seed of a deviation at `sequence` by
/// `proposer`: `H("MBSEED" ‖ p ‖ circulating_currency(p − 1) ‖ proposer)`,
/// integers little-endian, the tag unterminated (D7, DEC-218).
pub(crate) fn subgroup_seed(sequence: u32, currency: u64, proposer: u32) -> [u8; HASH_SIZE] {
    let mut preimage = [0u8; SEED_PREIMAGE_SIZE];
    preimage[..6].copy_from_slice(b"MBSEED");
    preimage[6..10].copy_from_slice(&sequence.to_le_bytes());
    preimage[10..18].copy_from_slice(&currency.to_le_bytes());
    preimage[18..].copy_from_slice(&proposer.to_le_bytes());
    calculate_hash(&preimage)
}

/// ADR-015 — a node's ordering key in the subgroup draw:
/// `(H(seed ‖ node) mod 2³²) · 2³² + node`. The digest is read as a big-endian
/// number (the KB's hash-order convention), so `mod 2³²` is its last four
/// bytes (D7). The low word is the node id, so no two nodes tie.
pub(crate) fn node_value(seed: &[u8; HASH_SIZE], node: u32) -> u64 {
    let mut preimage = [0u8; HASH_SIZE + 4];
    preimage[..HASH_SIZE].copy_from_slice(seed);
    preimage[HASH_SIZE..].copy_from_slice(&node.to_le_bytes());
    let digest = calculate_hash(&preimage);
    let high = u32::from_be_bytes([digest[28], digest[29], digest[30], digest[31]]);
    (u64::from(high) << 32) | u64::from(node)
}

/// ADR-015 / DEC-172 — the subgroup size `m` for a voting set of `eligible`
/// nodes: `r_eff = min(required_support, ⌊|A'|/2⌋ + 1)` and
/// `m = min(2·r_eff − 1, |A'|)`. `None` when `A'` is empty: no approval.
pub(crate) fn subgroup_size(required_support: u8, eligible: u32) -> Option<u32> {
    if eligible == 0 {
        return None;
    }
    let r_eff = u32::from(required_support).min(eligible / 2 + 1);
    let m = (2 * r_eff).saturating_sub(1).min(eligible);
    (m > 0).then_some(m)
}

/// Whether `local` is among the `m` members of `A'` with the smallest
/// [`node_value`], by rank counting — one pass, no `m`-sized array.
/// `members` yields `A'` (it may include `local`, which never counts against
/// itself). Monotone: a larger `m` only adds members.
pub(crate) fn in_subgroup(
    seed: &[u8; HASH_SIZE],
    local: u32,
    members: impl Iterator<Item = u32>,
    m: u32,
) -> bool {
    let local_value = node_value(seed, local);
    let mut below = 0u32;
    for node in members {
        if node_value(seed, node) < local_value {
            below += 1;
            if below >= m {
                return false;
            }
        }
    }
    below < m
}

/// FR12 / DEC-187 — the 45 bytes a support signature covers:
/// `"MBSUP"` ‖ proposer u32 ‖ `p` u32 ‖ the deviation block hash (D7). Story
/// 6.5's intake verification reuses it.
pub(crate) fn support_message_bytes(
    proposer: u32,
    sequence: u32,
    hash: &[u8; HASH_SIZE],
) -> [u8; SUPPORT_MESSAGE_SIZE] {
    let mut bytes = [0u8; SUPPORT_MESSAGE_SIZE];
    bytes[..5].copy_from_slice(b"MBSUP");
    bytes[5..9].copy_from_slice(&proposer.to_le_bytes());
    bytes[9..13].copy_from_slice(&sequence.to_le_bytes());
    bytes[13..].copy_from_slice(hash);
    bytes
}

/// The `kind` of a ring entry that records an FR12 support. `1` is reserved
/// for Story 6.13's FR71 twin vote, which shares the ring (DEC-198).
pub(crate) const RING_KIND_SUPPORT: u8 = 0;
/// The `kind` byte of a never-used slot.
const RING_KIND_EMPTY: u8 = 0xFF;
/// Ring capacity (DEC-198).
const RING_SLOTS: usize = 16;
/// One entry: `kind u8 ‖ proposer u32 ‖ sequence u32 ‖ key u32`, little-endian,
/// packed so the ring is 16 × 13 = 208 bytes.
const RING_ENTRY_SIZE: usize = 13;

/// FR12 / DEC-198 / DEC-219 — the non-conflict record: the supports this node
/// has given, so it does not endorse two different blocks for one
/// `(proposer, p)`, and the monotone support floor `F`.
///
/// `F` is both the "resolved" boundary and the restart floor (D8): it is
/// raised to the active head at every ready entry and to `S_head − H` at every
/// evaluation, never lowered, and no support is given at `p ≤ F`. An entry at
/// `s ≤ F` is resolved — intake refuses every block there (FR58) — so its slot
/// is free. `S_head` itself can fall — a DEC-205 re-entry to collecting may
/// come back on a lower head — so raising `F` before any reuse, and never
/// lowering it, is what keeps a sequence from reopening.
///
/// Insert takes a free slot first. With all 16 live it reuses a live support
/// entry at the same sequence for another proposer — a later grace round's
/// candidate; the evicted proposer could only get a twin endorsed, FR70
/// evidence against it (D8) — and otherwise abstains: an entry at another
/// sequence, or for the same `(proposer, p)`, is never overwritten (DEC-198).
///
/// Non-durable (FR59): a restart is a fresh `init`, with an empty ring and
/// `F = 0` until the ready entry raises it. Never cleared otherwise, not even by
/// a re-entry to collecting: a cleared ring would let the node support a second,
/// conflicting block at a sequence it supported before.
#[cfg_attr(test, derive(PartialEq))]
pub(crate) struct NonConflictRing {
    entries: [[u8; RING_ENTRY_SIZE]; RING_SLOTS],
    floor: u32,
}

/// What the ring says about a candidate support (AC6).
#[cfg_attr(test, derive(Debug))]
#[derive(PartialEq, Eq)]
pub(crate) enum RingCheck {
    /// No live entry for this `(kind, proposer, sequence)`.
    Free,
    /// A live entry for this exact block: re-sending is allowed.
    SameBlock,
    /// A live entry for a different block: no support.
    Conflict,
}

impl NonConflictRing {
    /// An empty ring with `F = 0`.
    pub(crate) const fn new() -> Self {
        Self {
            entries: [[RING_KIND_EMPTY; RING_ENTRY_SIZE]; RING_SLOTS],
            floor: 0,
        }
    }

    /// The support floor `F`.
    pub(crate) fn floor(&self) -> u32 {
        self.floor
    }

    /// `F = max(F, to)`.
    pub(crate) fn raise_floor(&mut self, to: u32) {
        self.floor = self.floor.max(to);
    }

    /// The key of a deviation hash: its first four bytes (D8). The hash is
    /// already a SHA-256 digest, and no other node reads the key.
    pub(crate) fn key_of(hash: &[u8]) -> u32 {
        u32::from_le_bytes([hash[0], hash[1], hash[2], hash[3]])
    }

    fn decode(entry: &[u8; RING_ENTRY_SIZE]) -> (u8, u32, u32, u32) {
        let word = |at: usize| {
            u32::from_le_bytes([entry[at], entry[at + 1], entry[at + 2], entry[at + 3]])
        };
        (entry[0], word(1), word(5), word(9))
    }

    /// Whether a slot is free: never used, or resolved (`s ≤ F`).
    fn is_free(&self, entry: &[u8; RING_ENTRY_SIZE]) -> bool {
        let (kind, _, sequence, _) = Self::decode(entry);
        kind == RING_KIND_EMPTY || sequence <= self.floor
    }

    /// The live entry for `(kind, proposer, sequence)`, compared with `key`.
    pub(crate) fn check(&self, kind: u8, proposer: u32, sequence: u32, key: u32) -> RingCheck {
        for entry in &self.entries {
            if self.is_free(entry) {
                continue;
            }
            let (k, p, s, stored) = Self::decode(entry);
            if (k, p, s) == (kind, proposer, sequence) {
                return if stored == key {
                    RingCheck::SameBlock
                } else {
                    RingCheck::Conflict
                };
            }
        }
        RingCheck::Free
    }

    /// Records a support. Takes a free slot first; with every slot live, a live
    /// support entry at the same sequence for another proposer (D8: a later
    /// grace round's candidate — whose evicted proposer could then only get a
    /// twin, FR70 evidence against it); else `false`: the node abstains rather
    /// than overwrite (DEC-198). The caller has checked [`Self::check`].
    pub(crate) fn insert(&mut self, kind: u8, proposer: u32, sequence: u32, key: u32) -> bool {
        let slot = (0..RING_SLOTS)
            .find(|&i| self.is_free(&self.entries[i]))
            .or_else(|| {
                (0..RING_SLOTS).find(|&i| {
                    let (k, p, s, _) = Self::decode(&self.entries[i]);
                    kind == RING_KIND_SUPPORT
                        && k == RING_KIND_SUPPORT
                        && s == sequence
                        && p != proposer
                })
            });
        let Some(slot) = slot else {
            return false;
        };
        let entry = &mut self.entries[slot];
        entry[0] = kind;
        entry[1..5].copy_from_slice(&proposer.to_le_bytes());
        entry[5..9].copy_from_slice(&sequence.to_le_bytes());
        entry[9..13].copy_from_slice(&key.to_le_bytes());
        true
    }
}

/// Length of a support body (DEC-229): `deviation_sequence` u32 ‖
/// `supporter_node_id` u32 ‖ `proposer_node_id` u32 ‖ the deviation block hash ‖
/// the serialized multi-signature: 108 bytes with Schnorr, 92 with BLS.
const SUPPORT_BODY_SIZE: usize = 4 + 4 + 4 + HASH_SIZE + MULTI_SIGNATURE_SIZE;

/// Offset of the deviation block hash in a support body.
const SUPPORT_HASH_AT: usize = 12;

/// Offset of the signature in a support body.
const SUPPORT_SIGNATURE_AT: usize = SUPPORT_HASH_AT + HASH_SIZE;

/// FR26 — a received support message, borrowed (DEC-229).
///
/// It views the radio `Support` message's hop-invariant body, bytes `[5..len)`:
/// `deviation_sequence u32 ‖ supporter_node_id u32 ‖ proposer_node_id u32 ‖
/// deviation_block_hash ‖ support_signature`, integers little-endian (DEC-218).
/// The type byte and the relay sender lie outside it, so the classification
/// cannot depend on the transport origin.
///
/// [`SupportView::from_bytes`] is FR26 (i), the format check, as
/// `BlockView::from_bytes` is for blocks: the bridge treats its `None` exactly
/// like [`crate::ReceiveSupportOutcome::Rejected`] — the message is dropped and
/// not relayed — and calls [`crate::Blockchain::receive_support`] only with a
/// parsed view. The field reads are crate-private (system constraints §0).
pub struct SupportView<'a> {
    body: &'a [u8],
}

impl<'a> SupportView<'a> {
    /// The view over `body`, iff it is exactly one support body long (FR26
    /// (i)). Nothing else is checked here: the fields are classified by
    /// [`crate::Blockchain::receive_support`].
    pub fn from_bytes(body: &'a [u8]) -> Option<Self> {
        (body.len() == SUPPORT_BODY_SIZE).then_some(Self { body })
    }

    fn word(&self, at: usize) -> u32 {
        u32::from_le_bytes([
            self.body[at],
            self.body[at + 1],
            self.body[at + 2],
            self.body[at + 3],
        ])
    }

    /// The deviating block's sequence `p`.
    pub(crate) fn deviation_sequence(&self) -> u32 {
        self.word(0)
    }

    /// The node that signed.
    pub(crate) fn supporter(&self) -> u32 {
        self.word(4)
    }

    /// The deviating block's creator the support is addressed to.
    pub(crate) fn proposer(&self) -> u32 {
        self.word(8)
    }

    /// The deviating block's hash.
    pub(crate) fn hash(&self) -> [u8; HASH_SIZE] {
        let mut hash = [0u8; HASH_SIZE];
        hash.copy_from_slice(&self.body[SUPPORT_HASH_AT..SUPPORT_SIGNATURE_AT]);
        hash
    }

    /// The serialized multi-signature.
    pub(crate) fn signature(&self) -> &[u8] {
        &self.body[SUPPORT_SIGNATURE_AT..]
    }

    /// The body after `deviation_sequence`: the bytes the relay-dedupe key
    /// covers (DEC-230).
    pub(crate) fn tail(&self) -> &[u8] {
        &self.body[4..]
    }
}

/// The body after `deviation_sequence` — supporter ‖ proposer ‖ hash ‖
/// signature, the bytes the dedupe key covers — of a support this node emits,
/// so that its own message is keyed exactly like a received copy (AC3).
pub(crate) fn support_body_tail(
    supporter: u32,
    proposer: u32,
    hash: &[u8; HASH_SIZE],
    signature: &[u8; MULTI_SIGNATURE_SIZE],
) -> [u8; SUPPORT_BODY_SIZE - 4] {
    let mut tail = [0u8; SUPPORT_BODY_SIZE - 4];
    tail[..4].copy_from_slice(&supporter.to_le_bytes());
    tail[4..8].copy_from_slice(&proposer.to_le_bytes());
    tail[8..SUPPORT_SIGNATURE_AT - 4].copy_from_slice(hash);
    tail[SUPPORT_SIGNATURE_AT - 4..].copy_from_slice(signature);
    tail
}

/// The label of the relay-dedupe salt's sub-seed (DEC-230, AR11).
pub(crate) const DEDUPE_SALT_LABEL: &[u8] = b"support-dedupe";

/// Length of the dedupe key's preimage: the salt, then the body tail.
const DEDUPE_PREIMAGE_SIZE: usize = 8 + SUPPORT_BODY_SIZE - 4;

/// Relay-dedupe capacity (DEC-199).
const DEDUPE_SLOTS: usize = 128;

/// One entry: `sequence u32 ‖ key u32 ‖ node u32`, little-endian, packed so the
/// cache is 128 × 12 = 1 536 bytes.
const DEDUPE_ENTRY_SIZE: usize = 12;

/// FR26 (v) / DEC-199 / DEC-231 — the relay-dedupe cache: the supports this
/// node has accepted, hence relayed, so a copy is not relayed again.
///
/// A FIFO ring of `(sequence, key, node)` entries: an insert overwrites the
/// oldest one, and a hit does not refresh it. Only an accepted message is
/// inserted — the cache means "already relayed" — and the node's own emitted
/// supports too, so a neighbour's echo is not relayed back. An eviction costs
/// at most one duplicate relay, which FR26 accepts. Entries are key-agnostic:
/// Story 6.13's twin vote uses the same form, `(s, key, voter)`.
///
/// **The key** (DEC-230, code review 2026-11-13) is the first four bytes of
/// `SHA-256(salt ‖ tail)`: `tail` is the body after the sequence (supporter,
/// proposer, hash, signature), so a copy with only the proposer changed is
/// another entry, and `salt` is this node's secret, derived from its
/// construction seed. Without the salt a 4-byte key could be ground — about
/// `2³²` hashes find junk with a seen support's key — and the junk would make
/// a node that accepts it unverified drop the real copy. With it nobody can
/// compute this node's keys, and a collision found for one node does not
/// carry to another. The production seed must be unpredictable (the bridge,
/// AR12).
///
/// A never-used slot is all `0xFF` bytes. Only the junk triple `(u32::MAX,
/// 0xFFFF_FFFF, u32::MAX)` can match it, and treating that as a duplicate is
/// harmless.
///
/// Non-durable (FR59): a restart is a fresh `init`. Never cleared otherwise,
/// not even by a re-entry to collecting, which would only re-relay what the
/// neighbours already have.
#[cfg_attr(test, derive(PartialEq))]
pub(crate) struct SupportDedupe {
    entries: [[u8; DEDUPE_ENTRY_SIZE]; DEDUPE_SLOTS],
    next: u8,
    salt: [u8; 8],
}

impl SupportDedupe {
    /// An empty cache keyed with `salt`.
    pub(crate) const fn new(salt: u64) -> Self {
        Self {
            entries: [[0xFF; DEDUPE_ENTRY_SIZE]; DEDUPE_SLOTS],
            next: 0,
            salt: salt.to_le_bytes(),
        }
    }

    /// The key of a support body's `tail` (after its sequence) on this node.
    pub(crate) fn key(&self, tail: &[u8]) -> u32 {
        let mut preimage = [0u8; DEDUPE_PREIMAGE_SIZE];
        preimage[..8].copy_from_slice(&self.salt);
        preimage[8..].copy_from_slice(tail);
        NonConflictRing::key_of(&calculate_hash(&preimage))
    }

    fn entry(sequence: u32, key: u32, node: u32) -> [u8; DEDUPE_ENTRY_SIZE] {
        let mut entry = [0u8; DEDUPE_ENTRY_SIZE];
        entry[..4].copy_from_slice(&sequence.to_le_bytes());
        entry[4..8].copy_from_slice(&key.to_le_bytes());
        entry[8..].copy_from_slice(&node.to_le_bytes());
        entry
    }

    /// Whether `(sequence, key, node)` is cached.
    pub(crate) fn contains(&self, sequence: u32, key: u32, node: u32) -> bool {
        let wanted = Self::entry(sequence, key, node);
        self.entries.contains(&wanted)
    }

    /// Caches `(sequence, key, node)` over the oldest entry.
    pub(crate) fn insert(&mut self, sequence: u32, key: u32, node: u32) {
        self.entries[self.next as usize] = Self::entry(sequence, key, node);
        self.next = ((self.next as usize + 1) % DEDUPE_SLOTS) as u8;
    }
}

/// FR12 / DEC-185 / DEC-213 — the active-set counter: per node, how many blocks
/// of the active window it created; `A` is the set of nodes whose count is
/// above zero (D2, operating model §6, architecture §7.1).
///
/// Maintained only in ready state, at the window events, from reads the steps
/// already do: a block entering the window adds one for its creator, a block
/// leaving it or undone subtracts one, and the creator of the current tail —
/// the next block to leave — is kept from the read every tail advance already
/// makes. Built by one window walk at every ready entry; invalid
/// (`tail_creator == NONE_REF`) outside ready state, after a projection reset,
/// or after an arithmetic inconsistency, and then the node gives no support.
///
/// Counts are `u16`: Story 6.4 counts creators only, at most one per window
/// block, and the window is at most `SNAKE_CHAIN_LENGTH_MAX ≤ u16::MAX`
/// (asserted where the capacity is known). Story 6.6 re-checks the width when
/// evidence signers count too (O-037).
#[cfg_attr(test, derive(PartialEq))]
pub(crate) struct ActiveSetCounter<const MAX_NODES: usize> {
    counts: [u16; MAX_NODES],
    tail_creator: u32,
}

/// The `tail_creator` of an invalid counter.
const COUNTER_INVALID: u32 = u32::MAX;

impl<const MAX_NODES: usize> ActiveSetCounter<MAX_NODES> {
    /// In-place construction: all counts zero, invalid. Never a
    /// `MAX_NODES`-scaled stack temporary.
    pub(crate) fn init(slot: &mut core::mem::MaybeUninit<Self>) -> &mut Self {
        let p = slot.as_mut_ptr();
        // SAFETY: `p` comes from a live `&mut MaybeUninit<Self>`, so it is
        // non-null, aligned, valid for writes of `Self` and not aliased; both
        // fields are written before the slot is assumed initialized, and zero
        // is a valid `u16`.
        unsafe {
            (&raw mut (*p).counts)
                .cast::<u16>()
                .write_bytes(0, MAX_NODES);
            (&raw mut (*p).tail_creator).write(COUNTER_INVALID);
        }
        // SAFETY: every field of `Self` was written above.
        unsafe { slot.assume_init_mut() }
    }

    /// The by-value constructor, the executable specification of
    /// [`Self::init`]. Test-only.
    #[cfg(test)]
    pub(crate) fn new() -> Self {
        Self {
            counts: [0; MAX_NODES],
            tail_creator: COUNTER_INVALID,
        }
    }

    /// Whether the counter holds the current window.
    pub(crate) fn is_valid(&self) -> bool {
        self.tail_creator != COUNTER_INVALID
    }

    /// Marks the counter invalid until the next ready entry rebuilds it.
    pub(crate) fn invalidate(&mut self) {
        self.tail_creator = COUNTER_INVALID;
    }

    /// The creator of the current window tail.
    pub(crate) fn tail_creator(&self) -> u32 {
        self.tail_creator
    }

    /// Starts a build: every count zero, the tail's creator recorded.
    pub(crate) fn start_build(&mut self, tail_creator: u32) {
        self.counts.fill(0);
        self.tail_creator = tail_creator;
    }

    /// The window's count for `node`; 0 for an id beyond the capacity.
    /// Test-only: the evaluation reads membership through
    /// [`Self::in_set_at_parent`].
    #[cfg(test)]
    pub(crate) fn count(&self, node: u32) -> u16 {
        self.counts.get(node as usize).copied().unwrap_or(0)
    }

    /// A block by `creator` entered the window. Overflow, or an id beyond the
    /// capacity, invalidates the counter. A no-op while invalid.
    pub(crate) fn add(&mut self, creator: u32) {
        if !self.is_valid() {
            return;
        }
        match self.counts.get_mut(creator as usize) {
            Some(count) if *count < u16::MAX => *count += 1,
            _ => self.invalidate(),
        }
    }

    /// A block by `creator` left the window or was undone. Underflow
    /// invalidates the counter. A no-op while invalid.
    pub(crate) fn remove(&mut self, creator: u32) {
        if !self.is_valid() {
            return;
        }
        match self.counts.get_mut(creator as usize) {
            Some(count) if *count > 0 => *count -= 1,
            _ => self.invalidate(),
        }
    }

    /// Membership in `A` at `p − 1`, from the head's counts and the
    /// correction (D2): the `above` active blocks in `[p, S_head]`, all by
    /// `creator_d` (the shape check guarantees it), leave the window again,
    /// and the blocks they dropped return — `returned` when one of them is
    /// `node`'s, or counted in `returning_d` when by `creator_d`.
    pub(crate) fn in_set_at_parent(
        &self,
        node: u32,
        creator_d: u32,
        above: u32,
        returning_d: u32,
        returned: bool,
    ) -> bool {
        let Some(&count) = self.counts.get(node as usize) else {
            return false;
        };
        if node == creator_d {
            u32::from(count) + returning_d > above
        } else {
            count > 0 || returned
        }
    }

    /// The window advanced: the tail's creator leaves, and `new_tail_creator`'s
    /// block becomes the tail.
    pub(crate) fn advance_tail(&mut self, new_tail_creator: u32) {
        let leaving = self.tail_creator;
        self.remove(leaving);
        if self.is_valid() {
            self.tail_creator = new_tail_creator;
        }
    }

    /// Records the tail's creator after a chain switch's deferred advances,
    /// whose leaving creators the replay already removed.
    pub(crate) fn set_tail_creator(&mut self, creator: u32) {
        if self.is_valid() {
            self.tail_creator = creator;
        }
    }
}

/// Test-only overrides of the production seams (AC9). Production compiles each
/// seam to its constant: no field, no branch.
#[cfg(test)]
pub(crate) mod test_seams {
    use core::cell::Cell;

    std::thread_local! {
        /// The answer of `grace_admits` (D3); production returns `false` until
        /// Story 8.5.
        pub(crate) static GRACE_ADMITS: Cell<bool> = const { Cell::new(false) };
    }

    /// Sets the grace answer for this test thread.
    pub(crate) fn set_grace_admits(admits: bool) {
        GRACE_ADMITS.with(|cell| cell.set(admits));
    }

    pub(crate) fn grace_admits() -> bool {
        GRACE_ADMITS.with(Cell::get)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// AC9 — the 22-byte seed preimage, byte by byte, with a non-zero currency
    /// passed explicitly so the field's position and endianness are pinned
    /// despite the stub (D7).
    #[test]
    fn the_seed_preimage_is_pinned_byte_by_byte() {
        let expected: [u8; 22] = [
            b'M', b'B', b'S', b'E', b'E', b'D', // tag, no terminator
            0x04, 0x03, 0x02, 0x01, // p = 0x01020304 LE
            0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, // currency LE
            0x0D, 0x0C, 0x0B, 0x0A, // proposer = 0x0A0B0C0D LE
        ];
        assert_eq!(
            subgroup_seed(0x0102_0304, 0x1122_3344_5566_7788, 0x0A0B_0C0D),
            calculate_hash(&expected)
        );
    }

    /// AC9 / M3 — the 36-byte node-value preimage and `mod 2³²` as the
    /// digest's last four bytes, big-endian, with the node id as the low word.
    #[test]
    fn the_node_value_takes_the_digests_last_four_bytes() {
        let seed = subgroup_seed(7, 1000, 3);
        let mut preimage = [0u8; 36];
        preimage[..32].copy_from_slice(&seed);
        preimage[32..].copy_from_slice(&[0x2A, 0x00, 0x00, 0x00]); // node 42 LE
        let digest = calculate_hash(&preimage);
        let high = (u64::from(digest[28]) << 24)
            | (u64::from(digest[29]) << 16)
            | (u64::from(digest[30]) << 8)
            | u64::from(digest[31]);
        assert_eq!(node_value(&seed, 42), (high << 32) | 42);
    }

    /// AC9 — the 45-byte signed support content (D7, DEC-187).
    #[test]
    fn the_support_message_bytes_are_pinned() {
        let hash = [0xEE; HASH_SIZE];
        let bytes = support_message_bytes(0x0102_0304, 0x0A0B_0C0D, &hash);
        assert_eq!(&bytes[..5], b"MBSUP");
        assert_eq!(&bytes[5..9], &[0x04, 0x03, 0x02, 0x01]);
        assert_eq!(&bytes[9..13], &[0x0D, 0x0C, 0x0B, 0x0A]);
        assert_eq!(&bytes[13..], &hash);
        assert_eq!(bytes.len(), 45);
    }

    /// AC9 — the `r_eff` / `m` table (DEC-172); an empty `A'` has no subgroup.
    #[test]
    fn the_subgroup_size_table() {
        // (|A'|, required_support, m)
        let table = [
            (0, 1, None),
            (0, 2, None),
            (0, 40, None),
            (1, 1, Some(1)),
            (1, 2, Some(1)),
            (1, 40, Some(1)),
            (2, 1, Some(1)),
            (2, 2, Some(2)),
            (2, 40, Some(2)),
            (3, 1, Some(1)),
            (3, 2, Some(3)),
            (3, 40, Some(3)),
            (4, 1, Some(1)),
            (4, 2, Some(3)),
            (4, 40, Some(4)),
            (100, 1, Some(1)),
            (100, 2, Some(3)),
            (100, 40, Some(79)),
        ];
        for (eligible, required, m) in table {
            assert_eq!(
                subgroup_size(required, eligible),
                m,
                "|A'| = {eligible}, required_support = {required}"
            );
        }
    }

    /// A deterministic xorshift for the reference tests.
    fn next(state: &mut u64) -> u64 {
        *state ^= *state << 13;
        *state ^= *state >> 7;
        *state ^= *state << 17;
        *state
    }

    /// AC9 / M2 — rank counting equals a sort-based reference over random
    /// sets, and a larger `m` only adds members.
    #[test]
    fn rank_counting_matches_a_sorted_reference() {
        let mut state = 0x9E37_79B9_7F4A_7C15;
        for round in 0..40 {
            let seed = subgroup_seed(round, next(&mut state), round * 7 + 1);
            let size = 1 + (next(&mut state) % 30) as usize;
            let mut ids = [0u32; 30];
            for (i, id) in ids.iter_mut().enumerate().take(size) {
                *id = (i as u32) * 3 + (next(&mut state) % 3) as u32;
            }
            let members = &ids[..size];
            let mut values = [0u64; 30];
            for (value, &id) in values.iter_mut().zip(members) {
                *value = node_value(&seed, id);
            }
            values[..size].sort_unstable();
            for &local in members {
                let mut previous = false;
                for m in 1..=size as u32 {
                    let reference = values[..m as usize].contains(&node_value(&seed, local));
                    let counted = in_subgroup(&seed, local, members.iter().copied(), m);
                    assert_eq!(counted, reference, "round {round}, node {local}, m {m}");
                    assert!(counted || !previous, "a larger m only adds members");
                    previous = counted;
                }
            }
        }
    }

    const KEY_A: u32 = 0xAAAA_0001;
    const KEY_B: u32 = 0xBBBB_0002;

    /// AC9 — insert, conflict, and a re-send of the same block.
    #[test]
    fn the_ring_records_and_detects_conflicts() {
        let mut ring = NonConflictRing::new();
        assert_eq!(ring.check(RING_KIND_SUPPORT, 7, 10, KEY_A), RingCheck::Free);
        assert!(ring.insert(RING_KIND_SUPPORT, 7, 10, KEY_A));
        assert_eq!(
            ring.check(RING_KIND_SUPPORT, 7, 10, KEY_A),
            RingCheck::SameBlock
        );
        assert_eq!(
            ring.check(RING_KIND_SUPPORT, 7, 10, KEY_B),
            RingCheck::Conflict
        );
        // Another proposer, sequence or kind is a different record (M4: the
        // key is what tells a conflict from a re-send).
        assert_eq!(ring.check(RING_KIND_SUPPORT, 8, 10, KEY_B), RingCheck::Free);
        assert_eq!(ring.check(RING_KIND_SUPPORT, 7, 11, KEY_B), RingCheck::Free);
        assert_eq!(ring.check(1, 7, 10, KEY_B), RingCheck::Free);
        assert_eq!(NonConflictRing::key_of(&[1, 2, 3, 4, 5]), 0x0403_0201);
    }

    /// AC9 / D8 — a resolved slot (`s ≤ F`) is free and reused first; with
    /// every slot live, a same-`p` support for another proposer is reused (and
    /// only that slot), and otherwise the node abstains.
    #[test]
    fn the_ring_reuses_resolved_then_same_sequence_slots_else_abstains() {
        let mut ring = NonConflictRing::new();
        for i in 0..16 {
            assert!(ring.insert(RING_KIND_SUPPORT, i, 100 + i, KEY_A));
        }
        // Full of live entries at distinct sequences: abstain.
        assert!(!ring.insert(RING_KIND_SUPPORT, 99, 200, KEY_A));
        // Same sequence as entry 3 (proposer 3 at 103), another proposer: a
        // later grace round's candidate reuses that slot, and only that one.
        assert!(ring.insert(RING_KIND_SUPPORT, 50, 103, KEY_B));
        assert_eq!(
            ring.check(RING_KIND_SUPPORT, 50, 103, KEY_B),
            RingCheck::SameBlock
        );
        assert_eq!(
            ring.check(RING_KIND_SUPPORT, 3, 103, KEY_B),
            RingCheck::Free
        );
        for i in (0..16).filter(|&i| i != 3) {
            assert_eq!(
                ring.check(RING_KIND_SUPPORT, i, 100 + i, KEY_A),
                RingCheck::SameBlock,
                "entry {i} untouched"
            );
        }
        // The same proposer at the same sequence is never a reuse target.
        assert!(!ring.insert(RING_KIND_SUPPORT, 50, 103, KEY_A));
        // Raising F resolves entries at or below it: their slots are free, and
        // their sequences are closed (the evaluation refuses `p ≤ F`). A
        // resolved slot is taken before a same-`p` live one.
        ring.raise_floor(101);
        assert_eq!(
            ring.check(RING_KIND_SUPPORT, 0, 100, KEY_B),
            RingCheck::Free
        );
        assert!(ring.insert(RING_KIND_SUPPORT, 60, 103, KEY_A));
        assert_eq!(
            ring.check(RING_KIND_SUPPORT, 50, 103, KEY_B),
            RingCheck::SameBlock,
            "the same-p entry survives while a resolved slot is free"
        );
        assert!(ring.insert(RING_KIND_SUPPORT, 98, 201, KEY_A));
        assert!(!ring.insert(RING_KIND_SUPPORT, 97, 202, KEY_A));
    }

    /// AC9 / M9 — `F` is monotone: a lower value never lowers it, so a
    /// sequence once closed stays closed.
    #[test]
    fn the_support_floor_is_monotone() {
        let mut ring = NonConflictRing::new();
        assert_eq!(ring.floor(), 0);
        ring.raise_floor(40);
        ring.raise_floor(25);
        assert_eq!(ring.floor(), 40);
        assert!(ring.insert(RING_KIND_SUPPORT, 1, 41, KEY_A));
        ring.raise_floor(30);
        assert_eq!(
            ring.check(RING_KIND_SUPPORT, 1, 41, KEY_B),
            RingCheck::Conflict
        );
    }

    /// AC9 — the counter: `+1` / `−1`, invalid until built, and checked
    /// arithmetic that invalidates instead of wrapping.
    #[test]
    fn the_counter_counts_and_invalidates_on_inconsistency() {
        let mut counter = ActiveSetCounter::<4>::new();
        assert!(!counter.is_valid());
        counter.add(1);
        assert_eq!(counter.count(1), 0, "a no-op while invalid");
        counter.start_build(2);
        for node in [1, 1, 2] {
            counter.add(node);
        }
        assert_eq!((counter.count(1), counter.count(2)), (2, 1));
        counter.advance_tail(1);
        assert_eq!((counter.count(2), counter.tail_creator()), (0, 1));
        counter.remove(3);
        assert!(!counter.is_valid(), "underflow");
        counter.start_build(0);
        counter.add(4);
        assert!(!counter.is_valid(), "an id beyond the capacity");
        counter.start_build(0);
        for _ in 0..u16::MAX {
            counter.add(0);
        }
        assert!(counter.is_valid());
        counter.add(0);
        assert!(!counter.is_valid(), "overflow");
    }

    /// AC9 — the `p − 1` correction equals a recomputed reference: the counts
    /// of a window `[p − W, p − 1]` from the counts of `[S_head − W + 1,
    /// S_head]` with the blocks above `p − 1` (all by one creator, `d`'s)
    /// removed and the dropped ones returned — one of them `d`'s creator's.
    #[test]
    fn the_parent_correction_matches_a_recomputed_window() {
        const W: usize = 6;
        // Creators by sequence 0..12; the head is at 11, `p` at 9, and `d`'s
        // creator 6 also made block 4, which returns.
        let chain = [0u32, 1, 2, 3, 6, 4, 2, 0, 5, 6, 6, 6];
        let (head, p) = (11usize, 9usize);
        let creator_d = chain[p];
        let mut counter = ActiveSetCounter::<8>::new();
        counter.start_build(chain[head + 1 - W]);
        for &c in &chain[head + 1 - W..=head] {
            counter.add(c);
        }
        let above = (head - p + 1) as u32;
        let mut returning_d = 0;
        let mut returned = [false; 8];
        for &c in &chain[p - W..=head - W] {
            if c == creator_d {
                returning_d += 1;
            } else {
                returned[c as usize] = true;
            }
        }
        assert_eq!(returning_d, 1, "the fixture returns one of d's blocks");
        let mut reference = [0u32; 8];
        for &c in &chain[p - W..p] {
            reference[c as usize] += 1;
        }
        for node in 0..8u32 {
            let member = counter.in_set_at_parent(
                node,
                creator_d,
                above,
                returning_d,
                returned[node as usize],
            );
            assert_eq!(member, reference[node as usize] > 0, "node {node}");
        }
    }

    // ---- Story 6.5: the support view and the relay-dedupe cache ----

    fn body(
        sequence: u32,
        supporter: u32,
        proposer: u32,
        hash: u8,
        sig: u8,
    ) -> [u8; SUPPORT_BODY_SIZE] {
        let mut body = [0u8; SUPPORT_BODY_SIZE];
        body[..4].copy_from_slice(&sequence.to_le_bytes());
        body[4..].copy_from_slice(&support_body_tail(
            supporter,
            proposer,
            &[hash; HASH_SIZE],
            &[sig; MULTI_SIGNATURE_SIZE],
        ));
        body
    }

    /// AC2 (i) / D1 — `from_bytes` accepts exactly one support body, and the
    /// fields sit at the DEC-229 offsets, little-endian.
    #[test]
    fn a_support_view_takes_exactly_one_body() {
        let bytes = body(0x0102_0304, 7, 9, 0xAA, 0x55);
        assert_eq!(bytes.len(), 44 + MULTI_SIGNATURE_SIZE);
        assert_eq!(&bytes[..4], &[0x04, 0x03, 0x02, 0x01]);
        let view = SupportView::from_bytes(&bytes).expect("one body");
        assert_eq!(view.deviation_sequence(), 0x0102_0304);
        assert_eq!(view.supporter(), 7);
        assert_eq!(view.proposer(), 9);
        assert_eq!(view.hash(), [0xAA; HASH_SIZE]);
        assert_eq!(view.signature(), &[0x55; MULTI_SIGNATURE_SIZE][..]);
        assert!(SupportView::from_bytes(&bytes[..SUPPORT_BODY_SIZE - 1]).is_none());
        let mut long = [0u8; SUPPORT_BODY_SIZE + 1];
        long[..SUPPORT_BODY_SIZE].copy_from_slice(&bytes);
        assert!(SupportView::from_bytes(&long).is_none());
        assert!(SupportView::from_bytes(&[]).is_none());
    }

    /// D2 / N1 — the key covers every byte after the sequence, the proposer
    /// included, and an emitted message is keyed exactly as a received copy;
    /// it depends on the node's salt (code review 2026-11-13).
    #[test]
    fn the_dedupe_key_covers_the_proposer_and_matches_an_emitted_copy() {
        let cache = SupportDedupe::new(0x1234_5678_9ABC_DEF0);
        let key_of = |b: &[u8; SUPPORT_BODY_SIZE]| {
            cache.key(SupportView::from_bytes(b).expect("one body").tail())
        };
        let bytes = body(6, 3, 4, 1, 2);
        let key = key_of(&bytes);
        assert_eq!(
            key,
            cache.key(&support_body_tail(
                3,
                4,
                &[1; HASH_SIZE],
                &[2; MULTI_SIGNATURE_SIZE]
            ))
        );
        for other in [
            body(6, 3, 5, 1, 2),
            body(6, 3, 4, 9, 2),
            body(6, 3, 4, 1, 7),
            body(6, 8, 4, 1, 2),
        ] {
            assert_ne!(key_of(&other), key);
        }
        // The sequence lives in the entry, not the key.
        assert_eq!(key_of(&body(7, 3, 4, 1, 2)), key);
        // Another node's salt keys the same body differently.
        let other_node = SupportDedupe::new(0x1234_5678_9ABC_DEF1);
        assert_ne!(other_node.key(&bytes[4..]), key);
    }

    /// D3 — FIFO: the 129th insert drops the first, a hit refreshes nothing,
    /// and a never-used slot matches only the all-ones junk triple.
    #[test]
    fn the_dedupe_cache_is_a_fifo() {
        let mut cache = SupportDedupe::new(7);
        assert!(!cache.contains(0, 0, 0));
        assert!(
            cache.contains(u32::MAX, u32::MAX, u32::MAX),
            "the junk triple"
        );
        for i in 0..DEDUPE_SLOTS as u32 {
            cache.insert(i, i, i);
        }
        assert!((0..DEDUPE_SLOTS as u32).all(|i| cache.contains(i, i, i)));
        // A hit on the oldest does not save it from the next insert.
        assert!(cache.contains(0, 0, 0));
        cache.insert(1000, 1000, 1000);
        assert!(!cache.contains(0, 0, 0), "the oldest went first");
        assert!(cache.contains(1, 1, 1));
        assert!(cache.contains(1000, 1000, 1000));
        assert_eq!(core::mem::size_of::<SupportDedupe>(), 128 * 12 + 1 + 8);
    }
}
