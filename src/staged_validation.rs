//! `staged_validation.rs` — FR9 three-status / three-tier staged validation.
//!
//! Story 4.2 scope: the **FR9 status model**, the **Tier 1 intake gating**
//! check set, and the **signature-verification cache**. Tier 2 (Connected
//! promotion) and Tier 3 (Active promotion) are *declared* here — their
//! predicates are documented and the status-transition map is a concrete
//! function ([`is_legal_transition`]) — but their **drivers are tagged
//! forward**: no Connected/Active promotion is executed anywhere in Epic 4.
//! Tier 2 ancestry/lookup completion is realized by the FR3 processing pass
//! (Epic 5) and FR23 chain-switch (Epic 6); Tier 3 derived-state replay by
//! the same paths plus transaction/balance/UTXO validation (Epic 7).
//!
//! **Statelessness.** Architecture §4.2 characterizes this module as
//! "stateless tier 1/2/3 checks." The one piece of *state* the FR9 tiers
//! need — the signature-verification cache — is an owned value on
//! [`crate::api::Blockchain`], passed into the (still-stateless) check
//! functions by `&mut`. The check functions own no state themselves, so the
//! §4.2 characterization holds: the cache is a caller-provided optimization
//! aid, not module-internal state.
//!
//! **FR16 "store unless exact evidence."** Tier 1 rejects a block *only* on
//! evidence derivable from the block bytes alone (plus the durable-locked
//! chain-config). Anything that would need not-yet-available state — a
//! non-genesis block-creator's public key, a UTXO input's referenced-output
//! amount — is **not** exact evidence at Tier 1 and defers to Tier 2/3. This
//! is why the block-creator signature check is opportunistic (and ready-state
//! only, so absent from Epic 4's collecting focus) and why the complex-tx
//! `sum(inputs) ≥ sum(outputs)` check runs only when every input amount is
//! locally resolvable.

use moonblokz_chain_types::{
    BlockView, ComplexTransactionView, PAYLOAD_TYPE_APPROVAL, PAYLOAD_TYPE_BALANCE,
    PAYLOAD_TYPE_CHAIN_CONFIG, PAYLOAD_TYPE_TRANSACTION, calculate_hash,
};
use moonblokz_crypto::{
    CryptoTrait, PUBLIC_KEY_SIZE, PublicKey, PublicKeyTrait, Signature, SignatureTrait,
};

/// The only block header `version` the MVP supports (FR9 Tier 1). chain-types
/// already rejects `version == 0` at parse; Tier 1 restricts to the supported
/// set, currently `{1}`.
const SUPPORTED_VERSION: u8 = 1;

/// Node #0's canonical id — the FR69 trust-anchor subject and the FR6 /
/// FR54 permanent self-vote exception's node.
const NODE_ZERO_ID: u32 = 0;

/// Signature-verification cache capacity (FR9: "capacity is a build-time
/// compile-constant"). A module const, not a 10th `Blockchain` const generic —
/// same rationale as Story 4.1's `SPENT_BITS_BYTES` (avoid churning the public
/// API + every instantiation site). At 32 entries the cache is
/// `32 × size_of::<SigCacheEntry>()`; see the RAM note in the Story 4.2 file
/// (this structure is not budgeted in architecture §6/§7 — a flagged
/// discrepancy). Because `moonblokz-chain-types` pins the Schnorr backend
/// (`PUBLIC_KEY_SIZE == 32`), this crate is effectively Schnorr-only, so an
/// entry is ~112 B (two 32-byte hashes + a 32-byte key + result/timestamp/flag,
/// padded) and the cache ~3.6 KB — the BLS 96-byte-key case is not reachable
/// through chain-types.
pub(crate) const SIG_VERIFY_CACHE_CAPACITY: usize = 32;

/// FR9 stored-status of a block in the retained block-tree. **`Invalid` is
/// deliberately not a variant** — it is a *terminal classification*, never a
/// stored status: a block entering Invalid is atomically removed from the
/// tree, so no `BlockEntry` ever holds it. Stored in `BlockEntry.flags`
/// bits 1-2 (see `blocks.rs`).
#[cfg_attr(test, derive(Debug))]
#[derive(Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)] // Connected/Active are set only by Epic 5/6/7 promotion drivers.
pub(crate) enum BlockStatus {
    /// Bytes parse, `payload_type` is a known schema, every applicable Tier 1
    /// gating check passed. The only status assigned in Epic 4.
    Stored,
    /// A Stored block whose ancestry reaches the active chain and which passed
    /// Tier 2. *Driver tagged forward (Epic 6/7).*
    Connected,
    /// A Connected block (or a Stored block promoted in one FR3 step) that is
    /// on the selected active chain, Tier 3-verified. *Driver tagged forward
    /// (Epic 5/6/7).*
    Active,
}

/// The FR9 status-transition map. Returns whether `from → to` is one of the
/// declared legal promotion/demotion edges. **Declared, not driven in Epic 4:**
/// no caller performs any of these transitions within Epic 4 — the drivers are
/// the FR3 processing pass (`Stored → Active`, Epic 5), FR23 chain-switch
/// (`Connected → Active`, `Active → Connected`, Epic 6), and FR35 forward
/// extension (`Stored → Connected → Active`, Epic 6/7). The deletion edges
/// (`Stored/Connected/Active → terminal Invalid removal`) are not modeled as
/// status transitions — entering Invalid *is* removal from the tree, so it has
/// no target status; those paths are Tier 1 gating failure (this story), Tier
/// 2/3 gating failure, and FR5/FR8/FR17/FR19/FR57 (later epics).
#[allow(dead_code)] // exercised by tests; drivers land in Epic 5/6/7.
pub(crate) fn is_legal_transition(from: BlockStatus, to: BlockStatus) -> bool {
    use BlockStatus::{Active, Connected, Stored};
    matches!(
        (from, to),
        (Stored, Connected)  // Tier 2 promotion
            | (Connected, Active)  // Tier 3 promotion (chain-switch / forward-extension)
            | (Stored, Active)     // FR3 processing-pass one-step promotion
            | (Active, Connected)  // FR23 chain-switch demotion to side-branch
    )
}

/// Exact-evidence-of-invalidity forms produced by [`tier1_gate`] (FR16 / FR9
/// Tier 1). Story 4.3 maps each to a `ReceiveBlockOutcome::Rejected(RejectReason)`
/// discriminant. This is the caller-visible "failing exact-evidence form" of
/// AC5.
#[cfg_attr(test, derive(Debug))]
#[derive(Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)] // some variants are produced only once later stories exercise their paths.
pub(crate) enum Tier1Failure {
    /// Header `version` outside the supported set.
    UnsupportedVersion,
    /// `payload_type` matches no known schema (∉ {1,2,3,4}).
    UnknownPayloadType,
    /// A managed payload does not parse coherently — the declared item count
    /// disagrees with the bytes actually present, or a transaction/input/output
    /// is truncated. (The chain-types iterators stop silently on truncation;
    /// this is where the deferred Story 1.1/1.4 payload-coherence watch-item
    /// is enforced.)
    MalformedPayload,
    /// `block size > MAX_BLOCK_SIZE` per the durable-locked chain-config (AC8).
    BlockTooLarge,
    /// `sequence == u32::MAX` — FR53 (ii): the reserved ceiling sentinel is
    /// exact evidence of invalidity and is rejected at intake regardless of
    /// linkage.
    SequenceCeiling,
    /// FR6: a `payload_type=1` block contains both ≥1 registration (`type=2`)
    /// and ≥1 complex (`type=3`) transaction.
    RegistrationComplexMutualExclusion,
    /// `block.sequence ≤ anchor_sequence` for a node-transfer or a complex-tx
    /// balance input (FR9 Tier 1 intake monotonicity).
    AnchorSequenceNotBeforeBlock,
    /// FR6 no-self-vote: a transaction's `initializer` equals its `vote`
    /// (outside the permanent node-#0 and block-#0 exceptions).
    SelfVote,
    /// A complex transaction (all inputs locally resolvable) whose declared
    /// input amounts sum to less than its output amounts.
    InputsLessThanOutputs,
    /// A registration's `new_key_signature` does not verify over its
    /// `new_public_key` (or the key/signature bytes are malformed).
    InvalidNewKeySignature,
    /// FR69 (i): a registration with `new_node_id == 0` carries
    /// `new_public_key ≠ node_zero_public_key`.
    NodeZeroRegistrationKeyMismatch,
    /// FR69 (ii): a balance block NodeInfo entry with `owner == 0` carries
    /// `public_key ≠ node_zero_public_key`.
    NodeZeroBalanceKeyMismatch,
    /// FR69 (iii): a chain-config block's FR7 content-signature fails to
    /// verify against `node_zero_public_key`. **Declared but not produced in
    /// Epic 4** — see [`tier1_chain_config_block`]: chain-types has no
    /// payload_type=3 view to extract the content/signature split, so the
    /// mechanical verification is deferred. The variant exists so Story 4.3's
    /// `RejectReason` mapping is complete.
    ChainConfigContentSignatureInvalid,
}

// ---------------------------------------------------------------------------
// Signature-verification cache (FR9 cache contract, AC6)
// ---------------------------------------------------------------------------

#[derive(Clone, Copy)]
struct SigCacheEntry {
    key_hash: [u8; 32],
    sig_hash: [u8; 32],
    public_key: [u8; PUBLIC_KEY_SIZE],
    result: bool,
    inserted_at: u64,
    occupied: bool,
}

impl SigCacheEntry {
    const fn empty() -> Self {
        Self {
            key_hash: [0; 32],
            sig_hash: [0; 32],
            public_key: [0; PUBLIC_KEY_SIZE],
            result: false,
            inserted_at: 0,
            occupied: false,
        }
    }
}

/// Fixed-capacity, in-memory, non-durable signature-verification cache
/// (FR9 / FR59 / FR63). Keyed by `(canonical-signed-bytes-hash,
/// signature-hash, public-key)` with a Boolean result and a per-entry
/// insertion timestamp (from the FR46 `now: u64` time base — the module reads
/// no wall clock). On overflow the oldest-inserted entry is evicted
/// (deterministic lowest-index tie-break, so replay stays byte-identical). The
/// cache is a pure memoization of the deterministic
/// `verify_signature(message, signature, public_key)`: a cold or emptied cache
/// yields the same Boolean on a miss, so it changes only cost, never
/// classification.
///
/// **The key includes the signature hash — deliberately beyond FR9's literal
/// `(canonical-signed-bytes-hash, public-key)` wording.** `verify_signature`'s
/// result depends on all three of `(message, signature, public_key)`, so
/// keying on only `(message-hash, public-key)` would let a *second* claim
/// presenting a *different* signature over the same `(message, public_key)`
/// pair inherit the first claim's cached Boolean. That is a real
/// false-accept/false-reject: e.g. a valid registration for public key `P`
/// caches `true`, then a forged registration reusing `P` with a garbage
/// `new_key_signature` would hit the cache and be admitted — and the outcome
/// would depend on cache warmth (cold rejects, warm accepts), breaking FR9's
/// own "empty cache changes only cost, never classification" guarantee and
/// FR63 replay determinism. Including `sig_hash` makes the cache a faithful
/// memoization of the full verification function. (Flagged as an FR9-wording
/// discrepancy in the Story 4.2 file / deferred-work.md.)
#[allow(dead_code)] // `new`/`verify_cached` consumed via `Blockchain`; tests exercise directly.
pub(crate) struct SignatureVerificationCache<const CAP: usize> {
    entries: [SigCacheEntry; CAP],
}

#[allow(dead_code)]
impl<const CAP: usize> SignatureVerificationCache<CAP> {
    /// A compile-time-empty cache (FR59: empty on restart / construction).
    pub(crate) const fn new() -> Self {
        Self {
            entries: [SigCacheEntry::empty(); CAP],
        }
    }

    /// Number of occupied entries. Used by the `init_in_place` equivalence
    /// test to confirm the cache is constructed empty (FR59) identically via
    /// both `new()` and `init_in_place()`.
    pub(crate) fn occupied_count(&self) -> usize {
        self.entries.iter().filter(|e| e.occupied).count()
    }

    fn lookup(&self, key_hash: &[u8; 32], sig_hash: &[u8; 32], public_key: &[u8; PUBLIC_KEY_SIZE]) -> Option<bool> {
        self.entries
            .iter()
            .find(|e| e.occupied && &e.key_hash == key_hash && &e.sig_hash == sig_hash && &e.public_key == public_key)
            .map(|e| e.result)
    }

    fn store(&mut self, key_hash: [u8; 32], sig_hash: [u8; 32], public_key: [u8; PUBLIC_KEY_SIZE], result: bool, now: u64) {
        let new_entry = SigCacheEntry {
            key_hash,
            sig_hash,
            public_key,
            result,
            inserted_at: now,
            occupied: true,
        };
        // First empty slot, if any.
        if let Some(slot) = self.entries.iter_mut().find(|e| !e.occupied) {
            *slot = new_entry;
            return;
        }
        if CAP == 0 {
            return; // zero-capacity cache: pure pass-through, nothing to store.
        }
        // Oldest-first eviction: smallest `inserted_at`, lowest index on ties.
        let mut victim = 0usize;
        for i in 1..CAP {
            if self.entries[i].inserted_at < self.entries[victim].inserted_at {
                victim = i;
            }
        }
        self.entries[victim] = new_entry;
    }

    /// Verify `signature_bytes` over `preimage` against `public_key_bytes`,
    /// consulting the cache first. On a miss, converts the wire bytes to the
    /// concrete crypto types and calls `crypto.verify_signature`; malformed
    /// signature or key bytes cannot be a valid signature, so they resolve to
    /// `false` (exact evidence at the call site). The result is cached under
    /// `(hash(preimage), hash(signature_bytes), public_key)` — see the type
    /// doc for why the signature hash is part of the key.
    pub(crate) fn verify_cached<C: CryptoTrait>(
        &mut self,
        crypto: &C,
        preimage: &[u8],
        signature_bytes: &[u8],
        public_key_bytes: &[u8; PUBLIC_KEY_SIZE],
        now: u64,
    ) -> bool {
        let key_hash = calculate_hash(preimage);
        let sig_hash = calculate_hash(signature_bytes);
        if let Some(cached) = self.lookup(&key_hash, &sig_hash, public_key_bytes) {
            return cached;
        }
        let result = match (Signature::new(signature_bytes), PublicKey::new(public_key_bytes)) {
            (Ok(sig), Ok(pk)) => crypto.verify_signature(preimage, &sig, &pk),
            _ => false,
        };
        self.store(key_hash, sig_hash, *public_key_bytes, result, now);
        result
    }
}

// ---------------------------------------------------------------------------
// Tier 1 gating (FR9 Tier 1 / FR16, AC2/AC3/AC8)
// ---------------------------------------------------------------------------

/// Runs the full FR9 Tier 1 gating-check set over `block`, evaluable from the
/// block bytes alone plus the durable-locked chain-config (`block_size_limit`).
/// Returns `Ok(())` when no exact evidence of invalidity exists (the block is
/// admissible at `Stored`), or the first exact-evidence [`Tier1Failure`].
///
/// Stateless over passed-in references — the only mutated argument is the
/// signature cache (`&mut`), an optimization aid that never changes the verdict.
#[allow(dead_code)] // consumed by `Blockchain::tier1_admit` (api.rs).
pub(crate) fn tier1_gate<C: CryptoTrait, const CAP: usize>(
    block: &BlockView,
    node_zero_public_key: &[u8; PUBLIC_KEY_SIZE],
    block_size_limit: u16,
    crypto: &C,
    sig_cache: &mut SignatureVerificationCache<CAP>,
    now: u64,
) -> Result<(), Tier1Failure> {
    // Header-level checks (payload-independent).
    if block.version() != SUPPORTED_VERSION {
        return Err(Tier1Failure::UnsupportedVersion);
    }
    if block.sequence() == u32::MAX {
        return Err(Tier1Failure::SequenceCeiling); // FR53 (ii)
    }
    if block.len() > block_size_limit as usize {
        return Err(Tier1Failure::BlockTooLarge); // AC8 (durable-locked config)
    }

    // FR54 exception (i)+(c): block #0 waives the no-self-vote and the
    // `sequence > anchor_sequence` rules (the genesis self-transfer legitimately
    // has anchor_sequence == 0 and votes for node #0). The full FR54 bootstrap
    // exception set (gated on the sequence-AND-content-match conjunction, incl.
    // block #1 chain-config) is forward-tagged to the genesis path / Story 5.6;
    // Story 4.2 implements only the two waivers needed so a legitimately-received
    // genesis block is not falsely rejected here.
    let is_genesis_block_zero = block.sequence() == 0;

    match block.payload_type() {
        PAYLOAD_TYPE_TRANSACTION => {
            tier1_transaction_block(block, node_zero_public_key, crypto, sig_cache, now, is_genesis_block_zero)?;
        }
        PAYLOAD_TYPE_BALANCE => tier1_balance_block(block, node_zero_public_key)?,
        PAYLOAD_TYPE_CHAIN_CONFIG => tier1_chain_config_block(block, node_zero_public_key)?,
        PAYLOAD_TYPE_APPROVAL => {
            // Recognized schema. Approval-evidence payload Tier 1/3 checks are
            // owned by Epic 6 (FR12/FR27) — nothing to gate from block bytes
            // alone here beyond schema recognition.
        }
        _ => return Err(Tier1Failure::UnknownPayloadType),
    }

    Ok(())
}

fn tier1_transaction_block<C: CryptoTrait, const CAP: usize>(
    block: &BlockView,
    node_zero_public_key: &[u8; PUBLIC_KEY_SIZE],
    crypto: &C,
    sig_cache: &mut SignatureVerificationCache<CAP>,
    now: u64,
    is_genesis_block_zero: bool,
) -> Result<(), Tier1Failure> {
    let payload = block.transactions().ok_or(Tier1Failure::MalformedPayload)?;
    let declared = payload.count() as usize;
    let block_sequence = block.sequence();

    let mut seen = 0usize;
    let mut has_registration = false;
    let mut has_complex = false;

    for tx in payload.iter() {
        seen += 1;
        let vote = tx.vote();

        if let Some(nt) = tx.as_node_transfer() {
            if !is_genesis_block_zero && block_sequence <= nt.anchor_sequence() {
                return Err(Tier1Failure::AnchorSequenceNotBeforeBlock);
            }
            check_no_self_vote(nt.initializer(), vote, is_genesis_block_zero)?;
        } else if let Some(reg) = tx.as_registration() {
            has_registration = true;
            check_no_self_vote(reg.initializer(), vote, is_genesis_block_zero)?;
            // FR69 (i): node-#0 registration must carry the trust-anchor key.
            if reg.new_node_id() == NODE_ZERO_ID && reg.new_public_key() != &node_zero_public_key[..] {
                return Err(Tier1Failure::NodeZeroRegistrationKeyMismatch);
            }
            // new_key_signature proves possession: the new key signs its own
            // public-key bytes. Verified via the cache.
            let new_pk = to_pubkey_array(reg.new_public_key()).ok_or(Tier1Failure::InvalidNewKeySignature)?;
            if !sig_cache.verify_cached(crypto, reg.new_public_key(), reg.new_key_signature(), &new_pk, now) {
                return Err(Tier1Failure::InvalidNewKeySignature);
            }
        } else if let Some(cx) = tx.as_complex() {
            has_complex = true;
            tier1_complex_tx(&cx, vote, is_genesis_block_zero, block_sequence)?;
        } else {
            // Unknown transaction discriminator: the iterator yielded a view
            // whose type is none of {node-transfer, registration, complex}.
            return Err(Tier1Failure::MalformedPayload);
        }
    }

    // Payload coherence: the transaction iterator stops silently on a
    // truncated/malformed tail, so a short iteration means the declared count
    // over-reports the bytes actually present.
    if seen != declared {
        return Err(Tier1Failure::MalformedPayload);
    }

    // FR6 registration/complex mutual-exclusivity — evaluable from block bytes
    // alone; applies in every lifecycle state.
    if has_registration && has_complex {
        return Err(Tier1Failure::RegistrationComplexMutualExclusion);
    }

    Ok(())
}

fn tier1_complex_tx(
    cx: &ComplexTransactionView,
    vote: u32,
    is_genesis_block_zero: bool,
    block_sequence: u32,
) -> Result<(), Tier1Failure> {
    let mut input_seen = 0u32;
    let mut has_utxo_input = false;
    let mut declared_input_sum: u128 = 0;

    for input in cx.inputs() {
        input_seen += 1;
        if let Some(bal) = input.as_balance() {
            if !is_genesis_block_zero && block_sequence <= bal.anchor_sequence() {
                return Err(Tier1Failure::AnchorSequenceNotBeforeBlock);
            }
            check_no_self_vote(bal.initializer(), vote, is_genesis_block_zero)?;
            declared_input_sum = declared_input_sum.saturating_add(bal.amount() as u128);
        } else if input.as_utxo().is_some() {
            has_utxo_input = true;
        } else {
            return Err(Tier1Failure::MalformedPayload);
        }
    }
    if input_seen != cx.input_count() as u32 {
        return Err(Tier1Failure::MalformedPayload);
    }

    // Output pass (always, for coherence; amounts used only for the sum rule).
    let mut output_seen = 0u32;
    let mut output_sum: u128 = 0;
    for output in cx.outputs() {
        output_seen += 1;
        if let Some(u) = output.as_utxo() {
            output_sum = output_sum.saturating_add(u.amount() as u128);
        } else if let Some(b) = output.as_balance() {
            output_sum = output_sum.saturating_add(b.amount() as u128);
        } else {
            return Err(Tier1Failure::MalformedPayload);
        }
    }
    if output_seen != cx.output_count() as u32 {
        return Err(Tier1Failure::MalformedPayload);
    }

    // Zero-input complex tx (UTXO carry-forward, FR51) is exempt from the
    // structural sum rule entirely.
    if input_seen == 0 {
        return Ok(());
    }
    // The `sum(inputs) ≥ sum(outputs)` rule is exact evidence only when every
    // input amount is locally resolvable at intake. A UTXO input's amount lives
    // in its referenced output (not in the input bytes), so any UTXO input makes
    // the sum incomplete — the check defers to Tier 2 (FR9) rather than becoming
    // false exact evidence here.
    if !has_utxo_input && declared_input_sum < output_sum {
        return Err(Tier1Failure::InputsLessThanOutputs);
    }

    Ok(())
}

fn tier1_balance_block(
    block: &BlockView,
    node_zero_public_key: &[u8; PUBLIC_KEY_SIZE],
) -> Result<(), Tier1Failure> {
    let payload = block.balances().ok_or(Tier1Failure::MalformedPayload)?;
    let declared = payload.count() as usize;

    let mut seen = 0usize;
    for info in payload.iter() {
        seen += 1;
        // FR69 (ii): any NodeInfo entry for node #0 must carry the trust anchor.
        if info.owner() == NODE_ZERO_ID && info.public_key() != &node_zero_public_key[..] {
            return Err(Tier1Failure::NodeZeroBalanceKeyMismatch);
        }
    }
    if seen != declared {
        return Err(Tier1Failure::MalformedPayload);
    }
    Ok(())
}

/// FR69 (iii) / FR7 chain-config content-signature verification — **DEFERRED**.
///
/// `moonblokz-chain-types` exposes no `payload_type=3` (chain-config) payload
/// view: the `(configuration content, node-#0 content-signature)` split that
/// FR7 verifies has no defined wire layout to parse in this crate, and no
/// chain-config block is even constructible yet (no builder). Inventing the
/// layout here would risk diverging from the eventual real format, which
/// belongs with the chain-types owner / the chain-config crate.
///
/// So Story 4.2 *recognizes* `payload_type=3` as a known schema (it is not
/// rejected as [`Tier1Failure::UnknownPayloadType`]) but does not yet run the
/// content-signature check. [`Tier1Failure::ChainConfigContentSignatureInvalid`]
/// is declared for the day the check lands. The epics.md Story 5.6 note ("the
/// mechanical signature check exists from Epic 4 Story 4.2") assumes a
/// chain-config payload view that does not exist; tracked in
/// `deferred-work.md`. `node_zero_public_key` is threaded in so the eventual
/// implementation needs no signature change.
fn tier1_chain_config_block(
    _block: &BlockView,
    _node_zero_public_key: &[u8; PUBLIC_KEY_SIZE],
) -> Result<(), Tier1Failure> {
    Ok(())
}

/// FR6 no-self-vote (exact semantics): a transaction's `initializer` must not
/// equal its `vote`, with two exceptions. (1) Block #0 is fully waived (FR54
/// exception (i)). (2) The permanent node-#0 self-vote exception (a structural
/// constant of MoonBlokz semantics, chain-wide — *not* bootstrap-only): when
/// `initializer == 0`, `vote == 0` never violates. This guarantees node #0
/// always has a valid vote choice, preventing the early-chain bootstrap
/// deadlock.
fn check_no_self_vote(initializer: u32, vote: u32, is_genesis_block_zero: bool) -> Result<(), Tier1Failure> {
    if is_genesis_block_zero {
        return Ok(());
    }
    if initializer == NODE_ZERO_ID && vote == NODE_ZERO_ID {
        return Ok(());
    }
    if initializer == vote {
        return Err(Tier1Failure::SelfVote);
    }
    Ok(())
}

fn to_pubkey_array(bytes: &[u8]) -> Option<[u8; PUBLIC_KEY_SIZE]> {
    if bytes.len() != PUBLIC_KEY_SIZE {
        return None;
    }
    let mut arr = [0u8; PUBLIC_KEY_SIZE];
    arr.copy_from_slice(bytes);
    Some(arr)
}

#[cfg(test)]
mod tests {
    use super::*;
    use moonblokz_chain_types::{
        Block, BlockBuilder, BlockHeader, ComplexTransaction, HEADER_SIZE, NodeInfo, NodeTransfer,
        PAYLOAD_TYPE_BALANCE, PAYLOAD_TYPE_TRANSACTION, Registration,
    };
    use moonblokz_crypto::{Crypto, PRIVATE_KEY_SIZE};

    /// Block-size limit used by the "normal" Tier 1 tests (the chain-config
    /// stub's `current_block_size_limit()`).
    const NORMAL_LIMIT: u16 = 2016;
    const DUMMY_SIG: [u8; 64] = [0u8; 64];

    fn crypto(seed: u8) -> Crypto {
        Crypto::new([seed; PRIVATE_KEY_SIZE]).ok().expect("valid test private key")
    }

    fn pubkey_bytes(c: &Crypto) -> [u8; PUBLIC_KEY_SIZE] {
        *c.public_key().serialize()
    }

    fn header(sequence: u32, payload_type: u8) -> BlockHeader {
        BlockHeader {
            version: 1,
            sequence,
            creator: 0,
            mined_amount: 0,
            payload_type,
            consumed_votes: 0,
            first_voted_node: 0,
            consumed_votes_from_first_voted_node: 0,
            previous_hash: [0u8; 32],
            signature: [0u8; 64],
        }
    }

    fn node_transfer_block(seq: u32, vote: u32, anchor: u32, initializer: u32, signer: &Crypto) -> Block {
        let nt = NodeTransfer::new_signed(vote, anchor, initializer, 9, 100, 1, 0, signer);
        let mut builder = BlockBuilder::new().header(header(seq, PAYLOAD_TYPE_TRANSACTION));
        builder.add_node_transfer(&nt).ok().expect("add node transfer");
        builder.build_signed(signer).ok().expect("build signed")
    }

    fn empty_cache() -> SignatureVerificationCache<SIG_VERIFY_CACHE_CAPACITY> {
        SignatureVerificationCache::new()
    }

    /// Raw header-only block bytes for header-level malformation tests
    /// (`BlockView::from_bytes` only checks `len ∈ [122,2016]` and `version != 0`).
    fn raw_block(version: u8, sequence: u32, payload_type: u8) -> [u8; HEADER_SIZE] {
        let mut b = [0u8; HEADER_SIZE];
        b[0] = version;
        b[1..5].copy_from_slice(&sequence.to_le_bytes());
        b[13] = payload_type;
        b
    }

    // --- AC7: transition map -------------------------------------------------

    #[test]
    fn transition_map_declares_legal_edges() {
        use BlockStatus::{Active, Connected, Stored};
        assert!(is_legal_transition(Stored, Connected));
        assert!(is_legal_transition(Connected, Active));
        assert!(is_legal_transition(Stored, Active));
        assert!(is_legal_transition(Active, Connected));
        // No self-edges and no illegal reversals.
        assert!(!is_legal_transition(Stored, Stored));
        assert!(!is_legal_transition(Active, Stored));
        assert!(!is_legal_transition(Connected, Stored));
    }

    // --- AC6: signature-verification cache ----------------------------------

    #[test]
    fn cache_starts_empty() {
        let cache = SignatureVerificationCache::<4>::new();
        assert!(cache.lookup(&[0u8; 32], &[0u8; 32], &[0u8; PUBLIC_KEY_SIZE]).is_none());
    }

    #[test]
    fn cache_hit_returns_same_bool_as_verify() {
        let c = crypto(1);
        let pk = pubkey_bytes(&c);
        let msg = b"cache hit message";
        let sig = c.sign(msg);
        let sig_bytes = sig.serialize();
        let mut cache = SignatureVerificationCache::<4>::new();
        assert!(cache.verify_cached(&c, msg, sig_bytes, &pk, 1));
        // Second call is a cache hit and returns the same boolean.
        assert!(cache.verify_cached(&c, msg, sig_bytes, &pk, 2));
        assert_eq!(cache.lookup(&calculate_hash(msg), &calculate_hash(sig_bytes), &pk), Some(true));
    }

    #[test]
    fn empty_cache_same_outcome_as_warm() {
        // FR63: a zero-capacity (never-caching) cache and a warm cache produce
        // identical booleans — only the crypto-call count differs.
        let c = crypto(1);
        let pk = pubkey_bytes(&c);
        let msg = b"determinism message";
        let sig = c.sign(msg);
        let sig_bytes = sig.serialize();

        let mut warm = SignatureVerificationCache::<4>::new();
        let w1 = warm.verify_cached(&c, msg, sig_bytes, &pk, 1);
        let w2 = warm.verify_cached(&c, msg, sig_bytes, &pk, 2);

        let mut cold = SignatureVerificationCache::<0>::new();
        let c1 = cold.verify_cached(&c, msg, sig_bytes, &pk, 1);
        let c2 = cold.verify_cached(&c, msg, sig_bytes, &pk, 2);

        assert_eq!(w1, c1);
        assert_eq!(w2, c2);
        assert_eq!(w1, w2);
    }

    #[test]
    fn cache_result_is_false_for_bad_signature() {
        // A signature by key A over a message, verified against key B, is false;
        // the false result is cached and returned identically on the hit.
        let a = crypto(1);
        let b = crypto(2);
        let pk_b = pubkey_bytes(&b);
        let msg = b"wrong signer";
        let sig = a.sign(msg); // signed by A
        let sig_bytes = sig.serialize();
        let mut cache = SignatureVerificationCache::<4>::new();
        assert!(!cache.verify_cached(&a, msg, sig_bytes, &pk_b, 1));
        assert_eq!(cache.lookup(&calculate_hash(msg), &calculate_hash(sig_bytes), &pk_b), Some(false));
    }

    #[test]
    fn oldest_first_eviction() {
        let c = crypto(1);
        let pk = pubkey_bytes(&c);
        let mut cache = SignatureVerificationCache::<2>::new();
        let (s1, s2, s3) = (c.sign(b"m1"), c.sign(b"m2"), c.sign(b"m3"));
        cache.verify_cached(&c, b"m1", s1.serialize(), &pk, 1);
        cache.verify_cached(&c, b"m2", s2.serialize(), &pk, 2);
        // Third insert overflows capacity 2 → evicts the oldest (m1, t=1).
        cache.verify_cached(&c, b"m3", s3.serialize(), &pk, 3);
        assert!(
            cache.lookup(&calculate_hash(b"m1"), &calculate_hash(s1.serialize()), &pk).is_none(),
            "oldest entry must be evicted"
        );
        assert!(cache.lookup(&calculate_hash(b"m2"), &calculate_hash(s2.serialize()), &pk).is_some());
        assert!(cache.lookup(&calculate_hash(b"m3"), &calculate_hash(s3.serialize()), &pk).is_some());
    }

    #[test]
    fn cache_key_includes_signature_no_cross_signature_reuse() {
        // Regression (code-review finding, 2026-07-10): a *valid* signature over
        // (message M, key P) must NOT let a *different* (e.g. forged/garbage)
        // signature over the same (M, P) inherit the cached `true`. Otherwise a
        // forged registration reusing a public key would be admitted, and the
        // outcome would depend on cache warmth (breaking FR63).
        let c = crypto(1);
        let pk = pubkey_bytes(&c);
        let msg = b"reused message and key";
        let good = c.sign(msg);
        let good_bytes = good.serialize();

        let mut cache = SignatureVerificationCache::<4>::new();
        assert!(cache.verify_cached(&c, msg, good_bytes, &pk, 1), "valid signature verifies");

        // A garbage signature over the SAME (message, public key): must be false,
        // and identically false whether the cache is warm (above) or cold.
        let garbage = [0u8; 64];
        let warm = cache.verify_cached(&c, msg, &garbage, &pk, 2);
        let mut cold_cache = SignatureVerificationCache::<4>::new();
        let cold = cold_cache.verify_cached(&c, msg, &garbage, &pk, 2);
        assert!(!warm, "forged signature must not inherit the valid one's cached true");
        assert_eq!(warm, cold, "cold and warm caches must classify identically (FR63)");
    }

    // --- AC2: header-level Tier 1 checks (raw bytes) ------------------------

    #[test]
    fn tier1_rejects_unsupported_version() {
        let bytes = raw_block(2, 5, PAYLOAD_TYPE_APPROVAL);
        let block = BlockView::from_bytes(&bytes).ok().expect("parses");
        let c = crypto(1);
        let mut cache = empty_cache();
        assert_eq!(
            tier1_gate(&block, &pubkey_bytes(&c), NORMAL_LIMIT, &c, &mut cache, 0),
            Err(Tier1Failure::UnsupportedVersion)
        );
    }

    #[test]
    fn tier1_rejects_unknown_payload_type() {
        let bytes = raw_block(1, 5, 9);
        let block = BlockView::from_bytes(&bytes).ok().expect("parses");
        let c = crypto(1);
        let mut cache = empty_cache();
        assert_eq!(
            tier1_gate(&block, &pubkey_bytes(&c), NORMAL_LIMIT, &c, &mut cache, 0),
            Err(Tier1Failure::UnknownPayloadType)
        );
    }

    #[test]
    fn tier1_rejects_sequence_ceiling() {
        // FR53 (ii): sequence == u32::MAX is exact evidence.
        let bytes = raw_block(1, u32::MAX, PAYLOAD_TYPE_APPROVAL);
        let block = BlockView::from_bytes(&bytes).ok().expect("parses");
        let c = crypto(1);
        let mut cache = empty_cache();
        assert_eq!(
            tier1_gate(&block, &pubkey_bytes(&c), NORMAL_LIMIT, &c, &mut cache, 0),
            Err(Tier1Failure::SequenceCeiling)
        );
    }

    #[test]
    fn tier1_rejects_oversized_block_against_config_limit() {
        // AC8: the block-size limit is the durable-locked chain-config value.
        let bytes = raw_block(1, 5, PAYLOAD_TYPE_APPROVAL); // len == HEADER_SIZE == 122
        let block = BlockView::from_bytes(&bytes).ok().expect("parses");
        let c = crypto(1);
        let mut cache = empty_cache();
        assert_eq!(
            tier1_gate(&block, &pubkey_bytes(&c), 100 /* < 122 */, &c, &mut cache, 0),
            Err(Tier1Failure::BlockTooLarge)
        );
    }

    #[test]
    fn tier1_recognizes_chain_config_schema_without_content_check() {
        // FR69 (iii) content-signature verification is deferred (no chain-types
        // payload_type=3 view); the schema is still recognized (not rejected).
        let bytes = raw_block(1, 5, PAYLOAD_TYPE_CHAIN_CONFIG);
        let block = BlockView::from_bytes(&bytes).ok().expect("parses");
        let c = crypto(1);
        let mut cache = empty_cache();
        assert_eq!(tier1_gate(&block, &pubkey_bytes(&c), NORMAL_LIMIT, &c, &mut cache, 0), Ok(()));
    }

    // --- AC2/AC3: transaction-payload checks --------------------------------

    #[test]
    fn tier1_accepts_wellformed_node_transfer() {
        let c = crypto(1);
        let block = node_transfer_block(5, 3 /*vote*/, 4 /*anchor*/, 7 /*initializer*/, &c);
        let mut cache = empty_cache();
        assert_eq!(
            tier1_gate(&block.view(), &pubkey_bytes(&crypto(2)), NORMAL_LIMIT, &c, &mut cache, 0),
            Ok(())
        );
    }

    #[test]
    fn tier1_rejects_self_vote() {
        let c = crypto(1);
        // initializer == vote == 7 (both non-zero) → self-vote.
        let block = node_transfer_block(5, 7, 4, 7, &c);
        let mut cache = empty_cache();
        assert_eq!(
            tier1_gate(&block.view(), &pubkey_bytes(&crypto(2)), NORMAL_LIMIT, &c, &mut cache, 0),
            Err(Tier1Failure::SelfVote)
        );
    }

    #[test]
    fn tier1_permits_node_zero_self_vote() {
        // Permanent node-#0 exception: initializer 0, vote 0 is always allowed.
        let c = crypto(1);
        let block = node_transfer_block(5, 0, 4, 0, &c);
        let mut cache = empty_cache();
        assert_eq!(
            tier1_gate(&block.view(), &pubkey_bytes(&crypto(2)), NORMAL_LIMIT, &c, &mut cache, 0),
            Ok(())
        );
    }

    #[test]
    fn tier1_block_zero_waives_self_vote_and_anchor() {
        // FR54 exception (i)+(c): block #0 waives no-self-vote and the anchor
        // monotonicity rule (genesis self-transfer: initializer==vote, anchor==0==seq).
        let c = crypto(1);
        let block = node_transfer_block(0, 7, 0, 7, &c);
        let mut cache = empty_cache();
        assert_eq!(
            tier1_gate(&block.view(), &pubkey_bytes(&crypto(2)), NORMAL_LIMIT, &c, &mut cache, 0),
            Ok(())
        );
    }

    #[test]
    fn tier1_rejects_anchor_sequence_not_before_block() {
        let c = crypto(1);
        // anchor 10 ≥ block sequence 5.
        let block = node_transfer_block(5, 3, 10, 7, &c);
        let mut cache = empty_cache();
        assert_eq!(
            tier1_gate(&block.view(), &pubkey_bytes(&crypto(2)), NORMAL_LIMIT, &c, &mut cache, 0),
            Err(Tier1Failure::AnchorSequenceNotBeforeBlock)
        );
    }

    fn registration_block(seq: u32, new_node_id: u32, new_pk: &[u8; 32], signer: &Crypto) -> Block {
        let reg = Registration::new_signed(3 /*vote*/, 5 /*initializer*/, new_node_id, 0, 0, new_pk, signer);
        let mut builder = BlockBuilder::new().header(header(seq, PAYLOAD_TYPE_TRANSACTION));
        builder.add_registration(&reg).ok().expect("add registration");
        builder.build_signed(signer).ok().expect("build signed")
    }

    #[test]
    fn tier1_accepts_valid_registration() {
        let a = crypto(1);
        let pk_a = pubkey_bytes(&a);
        // new_node_id == 0 → FR69 (i) requires new_public_key == node_zero. Pass pk_a as both.
        let block = registration_block(5, 0, &pk_a, &a);
        let mut cache = empty_cache();
        assert_eq!(tier1_gate(&block.view(), &pk_a, NORMAL_LIMIT, &a, &mut cache, 0), Ok(()));
    }

    #[test]
    fn tier1_rejects_node_zero_registration_key_mismatch() {
        // FR69 (i): new_node_id == 0 but new_public_key != node_zero_public_key.
        let a = crypto(1);
        let b = crypto(2);
        let block = registration_block(5, 0, &pubkey_bytes(&a), &a);
        let mut cache = empty_cache();
        assert_eq!(
            tier1_gate(&block.view(), &pubkey_bytes(&b), NORMAL_LIMIT, &a, &mut cache, 0),
            Err(Tier1Failure::NodeZeroRegistrationKeyMismatch)
        );
    }

    #[test]
    fn tier1_rejects_invalid_new_key_signature() {
        // new_public_key = B's key, but the registration is signed by A, so
        // new_key_signature (A over B's pubkey) does not verify against B.
        // new_node_id = 9 (non-zero) so FR69 (i) is skipped and we reach the sig check.
        let a = crypto(1);
        let b = crypto(2);
        let block = registration_block(5, 9, &pubkey_bytes(&b), &a);
        let mut cache = empty_cache();
        assert_eq!(
            tier1_gate(&block.view(), &pubkey_bytes(&crypto(3)), NORMAL_LIMIT, &a, &mut cache, 0),
            Err(Tier1Failure::InvalidNewKeySignature)
        );
    }

    #[test]
    fn tier1_rejects_registration_complex_mutual_exclusion() {
        let a = crypto(1);
        let pk_a = pubkey_bytes(&a);
        let reg = Registration::new_signed(3, 5, 9, 0, 0, &pk_a, &a);
        let mut cx = ComplexTransaction::new(3 /*vote*/);
        cx.add_balance_input(4 /*anchor*/, 8 /*initializer*/, 50, 0, &DUMMY_SIG).ok().unwrap();
        cx.add_balance_output(9, 40).ok().unwrap();
        let mut builder = BlockBuilder::new().header(header(5, PAYLOAD_TYPE_TRANSACTION));
        builder.add_registration(&reg).ok().expect("add reg");
        builder.add_complex_transaction(&cx).ok().expect("add complex");
        let block = builder.build_signed(&a).ok().expect("build");
        let mut cache = empty_cache();
        assert_eq!(
            tier1_gate(&block.view(), &pk_a, NORMAL_LIMIT, &a, &mut cache, 0),
            Err(Tier1Failure::RegistrationComplexMutualExclusion)
        );
    }

    fn complex_block<F: FnOnce(&mut ComplexTransaction)>(seq: u32, vote: u32, signer: &Crypto, build: F) -> Block {
        let mut cx = ComplexTransaction::new(vote);
        build(&mut cx);
        let mut builder = BlockBuilder::new().header(header(seq, PAYLOAD_TYPE_TRANSACTION));
        builder.add_complex_transaction(&cx).ok().expect("add complex");
        builder.build_signed(signer).ok().expect("build signed")
    }

    #[test]
    fn tier1_rejects_complex_inputs_less_than_outputs() {
        let c = crypto(1);
        // all-balance-input complex tx (resolvable) with inputs 30 < outputs 50.
        let block = complex_block(5, 3, &c, |cx| {
            cx.add_balance_input(4, 8, 30, 0, &DUMMY_SIG).ok().unwrap();
            cx.add_balance_output(9, 50).ok().unwrap();
        });
        let mut cache = empty_cache();
        assert_eq!(
            tier1_gate(&block.view(), &pubkey_bytes(&crypto(2)), NORMAL_LIMIT, &c, &mut cache, 0),
            Err(Tier1Failure::InputsLessThanOutputs)
        );
    }

    #[test]
    fn tier1_defers_sum_check_with_unresolvable_utxo_input() {
        let c = crypto(1);
        // A UTXO input's amount is not in the input bytes → the sum rule is not
        // evaluable at Tier 1, so inputs<outputs is NOT exact evidence here.
        let block = complex_block(5, 3, &c, |cx| {
            cx.add_utxo_input(&[7u8; 32], 0, &DUMMY_SIG).ok().unwrap();
            cx.add_balance_output(9, 50).ok().unwrap();
        });
        let mut cache = empty_cache();
        assert_eq!(
            tier1_gate(&block.view(), &pubkey_bytes(&crypto(2)), NORMAL_LIMIT, &c, &mut cache, 0),
            Ok(())
        );
    }

    #[test]
    fn tier1_rejects_complex_balance_input_self_vote() {
        let c = crypto(1);
        // balance input initializer 8 == vote 8 → self-vote.
        let block = complex_block(5, 8, &c, |cx| {
            cx.add_balance_input(4, 8, 50, 0, &DUMMY_SIG).ok().unwrap();
            cx.add_balance_output(9, 40).ok().unwrap();
        });
        let mut cache = empty_cache();
        assert_eq!(
            tier1_gate(&block.view(), &pubkey_bytes(&crypto(2)), NORMAL_LIMIT, &c, &mut cache, 0),
            Err(Tier1Failure::SelfVote)
        );
    }

    // --- AC3: balance-block trust-anchor check (FR69 ii) --------------------

    fn balance_block(seq: u32, owner: u32, pubkey: &[u8; 32], signer: &Crypto) -> Block {
        let info = NodeInfo::new(owner, 100, 0, pubkey);
        let mut builder = BlockBuilder::new().header(header(seq, PAYLOAD_TYPE_BALANCE));
        builder.add_node_info(&info).ok().expect("add node info");
        builder.build_signed(signer).ok().expect("build signed")
    }

    #[test]
    fn tier1_accepts_balance_block_with_correct_node_zero_key() {
        let a = crypto(1);
        let pk_a = pubkey_bytes(&a);
        let block = balance_block(5, 0, &pk_a, &a);
        let mut cache = empty_cache();
        assert_eq!(tier1_gate(&block.view(), &pk_a, NORMAL_LIMIT, &a, &mut cache, 0), Ok(()));
    }

    #[test]
    fn tier1_rejects_balance_block_node_zero_key_mismatch() {
        // FR69 (ii): NodeInfo owner == 0 with public_key != node_zero_public_key.
        let a = crypto(1);
        let b = crypto(2);
        let block = balance_block(5, 0, &pubkey_bytes(&a), &a);
        let mut cache = empty_cache();
        assert_eq!(
            tier1_gate(&block.view(), &pubkey_bytes(&b), NORMAL_LIMIT, &a, &mut cache, 0),
            Err(Tier1Failure::NodeZeroBalanceKeyMismatch)
        );
    }
}
