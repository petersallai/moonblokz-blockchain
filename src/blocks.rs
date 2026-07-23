//! `blocks.rs` — FR18.
//!
//! Owns the bounded `BlockTable<MAX_BLOCKS>` (~45.6 KB at the default
//! `MAX_BLOCKS = 600`) — every retained block with its ancestry metadata,
//! the single authoritative `(sequence, block_hash)` duplicate-detection
//! index, and the co-located ADR-016 spent-bit vectors.
//!
//! Story 4.1 scope: the data layer only — `BlockEntry` layout, duplicate
//! detection, ancestry recovery, and bounded full-retention. The FR9 status
//! enum and transition map are Story 4.2's deliverable: `flags` reserves the
//! bits (see below) but this module does not interpret or validate status
//! transitions. `chain_heads.rs` (Story 4.4) owns tip-tracking, eviction,
//! and the chain-head arrival-timestamp retention FR18 requires (see the
//! note on that below); `BlockTable::insert` never evicts or overwrites a
//! non-empty slot — a full table is a terminal [`BlockTableError::Full`].
//!
//! **Ancestry identity is immutable once inserted — only deleted and
//! replaced.** `BlockTable` deliberately exposes no general `get_mut`/
//! update-by-index method (2026-07-04 design decision): a block's `hash`,
//! `sequence`, and (once resolved) `parent_ref` never change under it, so
//! any identity change goes through delete-then-`insert`, not an in-place
//! field write. **Narrow, invariant-preserving exceptions exist for
//! *non-identity* metadata**, each a distinct method (never a raw `get_mut`):
//! `adjust_head_ref_count` / `resolve_parent_ref` (FR19 structural
//! bookkeeping, Story 4.4), and — added in Story 5.4 — the FR6/FR4 value
//! setters `set_status` / `set_on_active_chain` / `set_spent_bit`. The last
//! three are **bidirectional and value-based on purpose**: the FR3 Ready
//! transition promotes `Stored→Active` + `on_active_chain=true` and flips
//! UTXO spent-bits `0→1`, while the FR5 recovery (Story 5.5) and the FR23
//! chain-switch (Epic 6) reverse the very same fields — so a one-way
//! `promote`/`flip` API would be wrong; both directions reuse one setter.
//! The block's `hash`/`sequence`/`parent_ref` stay immutable throughout.
//! `BlockTable`'s first deletion path lands in Story 4.4 alongside
//! `chain_heads.rs`'s eviction (FR19 chain_heads-eviction).
//!
//! **Chain-head arrival timestamp deferred to Story 4.4.** FR18 requires
//! retaining the local wall-clock arrival timestamp "at least for every
//! chain head block" and permits (but does not require) retaining it "for
//! every block... if its storage budget allows." Story 4.1 initially added
//! an `arrival_timestamp: u64` to every `BlockEntry`, but that widens each
//! entry from 76 B to 88 B padded — at `MAX_BLOCKS = 600` that is +7.2 KB,
//! which is immaterial against the Schnorr backend's ~67-77 KB SRAM margin
//! (architecture §7.3) but eats meaningfully into the BLS backend's already
//! tight ~7-17 KB margin. `chain_heads.rs`'s `ChainHeadEntry` (Story 4.4,
//! architecture §6.3) is a 40-entry table, not 600 — adding the same field
//! there costs ~320 B, not ~7.2 KB. Since FR18's actual minimum is
//! head-scoped, not per-block, Story 4.1 does not add the field at all;
//! Story 4.4 adds it to `ChainHeadEntry` instead.

use crate::staged_validation::BlockStatus;

/// Sentinel value for an unresolved parent reference and for an empty
/// slot's `sequence` (architecture §6.2). `pub(crate)` so the admission path
/// (`api::Blockchain::tier1_admit`) can insert a block with an as-yet-
/// unresolved parent (parent linking / recovery is Story 4.4).
pub(crate) const NONE_REF: u32 = u32::MAX;

/// ADR-016 spent-bit vector size in bytes, for the architecture §5 default
/// `MAX_BLOCK_UTXO_OUTPUT = 256` (256 / 8 = 32).
///
/// Not derived from `Blockchain`'s `MAX_BLOCK_UTXO_OUTPUT` const generic:
/// sizing a field from `N / 8` where `N` is a generic parameter requires the
/// unstable `generic_const_exprs` feature, which this workspace does not
/// enable (the same constraint already documented for
/// `moonblokz-crypto-lib`'s fixed-size array API). `spent_bits` is reserved
/// storage only in this story (populated by Epic 7) — Epic 7 resolves the
/// generic sizing question when it gives the field real semantics.
const SPENT_BITS_BYTES: usize = 32;

/// `flags` bit assignment: bit 0 is `is_on_active_chain` (Story 4.1); bits 1-2
/// carry the FR9 `BlockStatus` (Story 4.2, see [`crate::staged_validation::BlockStatus`]);
/// bits 3-7 are unused.
const FLAG_ON_ACTIVE_CHAIN: u8 = 0b0000_0001;

/// FR9 status bits (bits 1-2 of `flags`). Story 4.1 reserved these; Story 4.2
/// gives them meaning. Encoding: `Stored = 0b00`, `Connected = 0b01`,
/// `Active = 0b10` (`0b11` unused). Default `flags == 0` therefore decodes to
/// `Stored`, which is exactly the collecting-state default (FR9 / AC4) — no
/// change to `new()` / `new_empty()` is needed. `is_on_active_chain` (bit 0)
/// and the `Active` status (bits 1-2) are deliberately distinct: bit 0 is
/// tree-membership on the active-chain path (FR18/FR19 ancestry), the status
/// is the FR9 validation tier. Never conflate them.
const FLAG_STATUS_SHIFT: u8 = 1;
const FLAG_STATUS_MASK: u8 = 0b0000_0110;

/// Per-block ancestry and status metadata (FR18).
///
/// Fields are private; module-local code (including tests) uses direct
/// field access rather than an accessor surface, keeping the embedded API
/// surface small — the same discipline `moonblokz-mempool`'s `IndexEntry`
/// follows.
// No caller reads `head_ref_count`/`spent_bits` yet (Story 4.2/4.4/Epic 7
// consume them); silencing dead_code keeps the struct clean until those
// callers land, matching Story 1.2's scaffold convention.
#[allow(dead_code)]
pub(crate) struct BlockEntry {
    hash: [u8; 32],
    parent_ref: u32,
    sequence: u32,
    spent_bits: [u8; SPENT_BITS_BYTES],
    head_ref_count: u8,
    flags: u8,
    /// The block's exact serialized length in bytes, recorded at intake (Story
    /// 5.4). Durable backends store blocks in fixed-size slots and read them back
    /// zero-padded to the slot size (`MemoryBackend`), so a read-back block is not
    /// byte-identical to the block that was signed; the FR6 byte-exact checks
    /// (block-creator signature, chain-config content-identity) trim the read-back
    /// bytes to this length first. `0` for entries constructed directly in tests
    /// that never round-trip through storage. Fits the struct's existing 2-byte
    /// tail padding — `size_of::<BlockEntry>()` stays 76 B.
    len: u16,
}

// `new`/`is_on_active_chain`/`set_on_active_chain` are consumed starting
// with Story 4.2/4.3 (Story 4.1's own tests exercise them, but `cargo test`
// dead-code analysis runs against the non-test build too).
#[allow(dead_code)]
impl BlockEntry {
    /// An empty slot: `sequence == NONE_REF` is the sentinel `BlockTable`
    /// scans for.
    const fn new_empty() -> Self {
        Self {
            hash: [0; 32],
            parent_ref: NONE_REF,
            sequence: NONE_REF,
            spent_bits: [0; SPENT_BITS_BYTES],
            head_ref_count: 0,
            flags: 0,
            len: 0,
        }
    }

    /// Constructs an occupied entry. `parent_ref == NONE_REF` means no
    /// resolved parent (e.g. genesis, or an as-yet-unrecovered ancestor). `len`
    /// defaults to 0; the admission path stamps the block's true serialized
    /// length via [`Self::set_len`] before insertion (Story 5.4).
    pub(crate) fn new(hash: [u8; 32], parent_ref: u32, sequence: u32) -> Self {
        Self {
            hash,
            parent_ref,
            sequence,
            spent_bits: [0; SPENT_BITS_BYTES],
            head_ref_count: 0,
            flags: 0,
            len: 0,
        }
    }

    /// The block's exact serialized length recorded at intake (Story 5.4), or 0
    /// if never stamped (test entries that do not round-trip through storage).
    pub(crate) fn len(&self) -> u16 {
        self.len
    }

    /// Stamps the block's exact serialized length onto a `BlockEntry` value
    /// **before** it is inserted (Story 5.4 — the byte-exact FR6 checks trim a
    /// zero-padded read-back block to this length).
    pub(crate) fn set_len(&mut self, len: u16) {
        self.len = len;
    }

    fn is_empty_slot(&self) -> bool {
        self.sequence == NONE_REF
    }

    pub(crate) fn is_on_active_chain(&self) -> bool {
        self.flags & FLAG_ON_ACTIVE_CHAIN != 0
    }

    pub(crate) fn set_on_active_chain(&mut self, value: bool) {
        if value {
            self.flags |= FLAG_ON_ACTIVE_CHAIN;
        } else {
            self.flags &= !FLAG_ON_ACTIVE_CHAIN;
        }
    }

    /// Canonical block identity (FR11 key). Read by `chain_heads.rs` (Story 4.4)
    /// for tip tie-breaks (`head_block_id`) and event (ii) parent matching.
    pub(crate) fn hash(&self) -> &[u8; 32] {
        &self.hash
    }

    /// Block sequence. Read by `chain_heads.rs` for the FR19/FR63 `head_sequence`
    /// tie-break (architecture §6.3: no cached `head_sequence` — derived here).
    pub(crate) fn sequence(&self) -> u32 {
        self.sequence
    }

    /// Resolved parent index into `blocks`, or [`NONE_REF`] if unresolved
    /// (genesis, or an as-yet-unrecovered ancestor). Read by the FR19
    /// ancestry/eviction back-walks.
    pub(crate) fn parent_ref(&self) -> u32 {
        self.parent_ref
    }

    /// FR19 shared-ancestry reference count (number of `chain_heads` entries
    /// whose ancestry path includes this block).
    pub(crate) fn head_ref_count(&self) -> u8 {
        self.head_ref_count
    }

    /// Stamps the FR19 `head_ref_count` onto a `BlockEntry` value **before** it
    /// is inserted (event (i) — a new block's initial count, typically 1).
    /// In-place adjustment of an already-inserted block goes through
    /// [`BlockTable::adjust_head_ref_count`].
    pub(crate) fn set_head_ref_count(&mut self, count: u8) {
        self.head_ref_count = count;
    }

    /// FR9 stored status (bits 1-2 of `flags`). A brand-new entry decodes to
    /// [`BlockStatus::Stored`] (the collecting-state default, AC4).
    pub(crate) fn status(&self) -> BlockStatus {
        match (self.flags & FLAG_STATUS_MASK) >> FLAG_STATUS_SHIFT {
            0b01 => BlockStatus::Connected,
            0b10 => BlockStatus::Active,
            // 0b00 (Stored) and the unused 0b11 both decode to Stored — the
            // module never writes 0b11, and treating a stray bit pattern as
            // the least-promoted status fails safe.
            _ => BlockStatus::Stored,
        }
    }

    /// Writes the FR9 status into bits 1-2 without disturbing bit 0
    /// (`is_on_active_chain`) or the unused high bits.
    ///
    /// **Reserved for the Epic 5/6/7 promotion drivers; not exercised in
    /// Epic 4.** Within Epic 4 the only status ever assigned is `Stored`,
    /// which is already the `new()` default — so in practice this is only
    /// called (if at all) to set `Stored` explicitly at admission. A future
    /// promotion story that must change an *already-inserted* entry's status
    /// does so through the delete-then-`insert` discipline of Story 4.1 (no
    /// `get_mut` on `BlockTable`), not by mutating a stored entry in place;
    /// this setter is for stamping the status onto a `BlockEntry` value
    /// *before* it is inserted.
    pub(crate) fn set_status(&mut self, status: BlockStatus) {
        let bits: u8 = match status {
            BlockStatus::Stored => 0b00,
            BlockStatus::Connected => 0b01,
            BlockStatus::Active => 0b10,
        };
        self.flags =
            (self.flags & !FLAG_STATUS_MASK) | ((bits << FLAG_STATUS_SHIFT) & FLAG_STATUS_MASK);
    }

    /// ADR-016 UTXO spent-bit read (`bit` = 0-based position in this block's
    /// UTXO-output stream). An out-of-range bit reads as `true` (spent) — a
    /// fail-safe so a malformed / oversized reference can never be treated as
    /// unspent by the FR6 double-spend check (Story 5.4).
    pub(crate) fn spent_bit(&self, bit: usize) -> bool {
        let byte = bit / 8;
        if byte >= SPENT_BITS_BYTES {
            return true;
        }
        self.spent_bits[byte] & (1u8 << (bit % 8)) != 0
    }

    /// Sets UTXO spent-bit `bit` to `value` (ADR-016). Value-based and
    /// bidirectional (Story 5.4): the FR6 forward pass sets `0→1` on
    /// consumption, the FR5 rollback (Story 5.5) resets `1→0`. An
    /// out-of-range `bit` is ignored (the read side already fails safe).
    pub(crate) fn set_spent_bit(&mut self, bit: usize, value: bool) {
        let byte = bit / 8;
        if byte >= SPENT_BITS_BYTES {
            return;
        }
        let mask = 1u8 << (bit % 8);
        if value {
            self.spent_bits[byte] |= mask;
        } else {
            self.spent_bits[byte] &= !mask;
        }
    }
}

/// Errors from [`BlockTable::insert`]. Consumed starting with Story 4.3's
/// intake surface; Story 4.1's tests exercise it directly.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BlockTableError {
    /// No empty slot remains. Capacity-pressure eviction (FR19
    /// chain_heads-eviction) is Story 4.4's concern, not this table's.
    Full,
    /// `entry.sequence == NONE_REF` (`u32::MAX`) — the same sentinel value
    /// [`BlockEntry::is_empty_slot`] uses to mean "this slot is empty".
    /// Inserting such an entry would make an *occupied* slot indistinguishable
    /// from an empty one: `get`/`find` would treat it as absent (data
    /// becomes unreadable) and a later `insert` could silently overwrite it
    /// (data loss) — violating FR20's no-silent-collapse guarantee. FR53
    /// ("rejects u32::MAX-based chain extension in MVP", architecture §6.2)
    /// is expected to keep a real sequence from ever reaching `u32::MAX`
    /// before it gets this far; `insert` still checks it at runtime because it
    /// protects the table's empty-slot *representation*, not business logic.
    /// (FR11 de-duplication, by contrast, is now the caller's job — a
    /// debug-only assertion, not a runtime `BlockTableError`.)
    ReservedSequence,
}

/// Bounded block-tree (FR18) with the FR11 duplicate-detection index and
/// FR18/FR19 ancestry-walk support, over a fixed-capacity `MAX_BLOCKS`
/// array. `blocks[i] ⟷ storage_index = i` — no separate `storage_index`
/// field (architecture §6.2).
#[allow(dead_code)]
pub(crate) struct BlockTable<const MAX_BLOCKS: usize> {
    blocks: [BlockEntry; MAX_BLOCKS],
}

// `find`/`insert`/`get`/`walks_to_active_chain` are consumed starting with
// Story 4.2/4.3/4.4; `init_in_place` is already called from `api.rs`.
// Story 4.1's tests exercise every method directly.
#[allow(dead_code)]
impl<const MAX_BLOCKS: usize> BlockTable<MAX_BLOCKS> {
    /// Initializes `*dst` in place for embedded/task use: writes each
    /// `BlockEntry` directly to its final address through a raw pointer,
    /// one at a time, so no value the size of the whole `[BlockEntry;
    /// MAX_BLOCKS]` array (~45.6 KB at the default `MAX_BLOCKS = 600`)
    /// ever exists anywhere in this function. This is the table's only
    /// constructor.
    ///
    /// **An earlier by-value `new()` existed**, backed by a compile-time
    /// `const EMPTY: Self = Self { blocks: [BlockEntry::new_empty(); MAX_BLOCKS] }`.
    /// It was removed once every caller was confirmed able to use this
    /// constructor instead — see [`crate::api::Blockchain::init_in_place`]'s
    /// doc comment for why returning `Self` by value can't be made
    /// stack-cheap no matter how it's assembled internally. The
    /// const-bake-vs-runtime-loop stack measurement that justified `EMPTY`'s
    /// design while it existed (111 KiB for a mutated-local loop vs. 66.6 KiB
    /// for the const bulk-copy, both still 11-18× the 6 KiB task stack
    /// budget) is preserved in Story 4.1's code-review discussion /
    /// `deferred-work.md` for reference; it no longer applies to any code
    /// path here, since this function never materializes the whole array at
    /// all — each iteration writes one 76 B `BlockEntry` directly to its
    /// final address. Used by [`crate::api::Blockchain::init_in_place`]; see
    /// that method's doc comment for why and how to call it from a task.
    ///
    /// # Safety
    /// `dst` must be valid for writes of `Self` and non-overlapping with
    /// any other live reference. Writes over possibly-uninitialized memory
    /// without reading or dropping the old value, which is correct only
    /// because `dst` is not yet initialized.
    pub(crate) unsafe fn init_in_place(dst: *mut Self) {
        let blocks_ptr = unsafe { core::ptr::addr_of_mut!((*dst).blocks) } as *mut BlockEntry;
        for i in 0..MAX_BLOCKS {
            unsafe {
                blocks_ptr.add(i).write(BlockEntry::new_empty());
            }
        }
    }

    /// FR11 single authoritative duplicate-detection index: a bounded
    /// linear scan over `blocks`. `MAX_BLOCKS` is small (600 default) and
    /// no_std/no-alloc rules out a `HashMap`; this mirrors the O(N) lookup
    /// pattern already used by `moonblokz-vote`'s `top_creator`/
    /// `creator_at_rank` and `moonblokz-mempool`'s `get_by_hash`/
    /// `contains`. Revisit only if profiling shows it matters.
    pub(crate) fn find(&self, sequence: u32, hash: &[u8; 32]) -> Option<u32> {
        self.blocks
            .iter()
            .enumerate()
            .find(|(_, entry)| {
                !entry.is_empty_slot() && entry.sequence == sequence && &entry.hash == hash
            })
            .map(|(idx, _)| idx as u32)
    }

    /// Inserts `entry` into the first empty slot. Never evicts or
    /// overwrites a non-empty slot (FR20 — full retention; no silent
    /// collapse of side branches). Convenience wrapper over
    /// [`Self::next_free_index`] + [`Self::insert_at`] for callers (mainly
    /// tests) that do not run the storage-first two-step; the admission path
    /// uses `next_free_index` + `insert_at` directly to avoid the second scan.
    pub(crate) fn insert(&mut self, entry: BlockEntry) -> Result<u32, BlockTableError> {
        if entry.sequence == NONE_REF {
            return Err(BlockTableError::ReservedSequence);
        }
        match self.next_free_index() {
            Some(idx) => {
                self.insert_at(idx, entry);
                Ok(idx)
            }
            None => Err(BlockTableError::Full),
        }
    }

    /// Writes `entry` at a known-free `idx` (obtained from
    /// [`Self::next_free_index`]), skipping the free-slot re-scan `insert`
    /// performs. Used by the storage-first admission path, which has already
    /// peeked `idx` to persist the block there before mutating the tree.
    ///
    /// **The caller owns FR11 de-duplication.** The intake dispatcher's
    /// authoritative `(sequence, hash)` check runs before admission, so a
    /// duplicate reaching here is a caller bug — asserted in debug, not
    /// re-checked in release (embedded thrift: the public `receive_block`
    /// path establishes the not-a-duplicate invariant exactly once).
    pub(crate) fn insert_at(&mut self, idx: u32, entry: BlockEntry) {
        debug_assert!(
            entry.sequence != NONE_REF,
            "insert_at: reserved sentinel sequence"
        );
        debug_assert!(
            self.find(entry.sequence, &entry.hash).is_none(),
            "insert_at: caller must FR11-dedup before admission"
        );
        let slot = &mut self.blocks[idx as usize];
        debug_assert!(slot.is_empty_slot(), "insert_at: target slot must be free");
        *slot = entry;
    }

    /// Returns the entry at `idx`, or `None` if `idx` is out of bounds or
    /// names an empty slot.
    pub(crate) fn get(&self, idx: u32) -> Option<&BlockEntry> {
        self.blocks
            .get(idx as usize)
            .filter(|entry| !entry.is_empty_slot())
    }

    /// FR18/FR19 ancestry recovery: walks `parent_ref` from `start_idx`
    /// until an entry with `is_on_active_chain() == true` is found
    /// (`true`), or the walk cannot continue — an unresolved parent
    /// (`NONE_REF`), an out-of-bounds/empty slot, or the bounded step
    /// count is exhausted (`false`).
    ///
    /// Bounded by `MAX_BLOCKS` iterations, which is sufficient for two
    /// distinct reasons, not one: (1) a **well-formed** parent chain cannot
    /// visit more than `MAX_BLOCKS` distinct entries, because the table
    /// structurally cannot hold more than that many at once — this holds
    /// regardless of how `MAX_BLOCKS` relates to `SNAKE_CHAIN_LENGTH` (the
    /// AC's "bounded by the snake_chain window" language), so this bound is
    /// never tighter than correctness requires. (2) a **malformed/cyclic**
    /// `parent_ref` chain (e.g. a self-loop or a small cycle) revisits the
    /// same few entries repeatedly; `MAX_BLOCKS` iterations is at least one
    /// full lap around any cycle it could contain (a cycle's length can't
    /// exceed the table size either), so the loop is guaranteed to have
    /// already returned `true`/`false` by then rather than spinning forever
    /// — this is why the loop is safe against untrusted/malformed ancestry
    /// data, not merely "coincidentally" bounded. `blocks.rs` does not have
    /// access to `SNAKE_CHAIN_LENGTH` — that const generic lives on
    /// `Blockchain`, not `BlockTable` — so `MAX_BLOCKS` is used directly
    /// rather than threading the tighter window bound through.
    pub(crate) fn walks_to_active_chain(&self, start_idx: u32) -> bool {
        let mut current = start_idx;
        for _ in 0..MAX_BLOCKS {
            let Some(entry) = self.get(current) else {
                return false;
            };
            if entry.is_on_active_chain() {
                return true;
            }
            if entry.parent_ref == NONE_REF {
                return false;
            }
            current = entry.parent_ref;
        }
        false
    }

    /// Index of the first empty slot, or `None` if the table is full.
    ///
    /// Story 4.2's admission path uses this to write durable storage
    /// *before* mutating the tree: it persists the block at the slot
    /// [`Self::insert`] is about to choose, so a storage-save failure leaves
    /// the tree untouched (no leaked slot, which matters because there is no
    /// deletion path until Story 4.4). Because the module is single-threaded
    /// and nothing mutates the table between the two calls, `next_free_index`
    /// and the subsequent `insert` agree on the same slot.
    pub(crate) fn next_free_index(&self) -> Option<u32> {
        self.blocks
            .iter()
            .enumerate()
            .find(|(_, slot)| slot.is_empty_slot())
            .map(|(idx, _)| idx as u32)
    }

    /// Number of occupied slots. Used by the AC7 footprint invariant test;
    /// the `MAX_BLOCKS` ceiling is already structural (array-bounded), so
    /// this exists to catch a leaked slot (never freed) rather than an
    /// out-of-bounds write.
    pub(crate) fn len(&self) -> usize {
        self.blocks
            .iter()
            .filter(|entry| !entry.is_empty_slot())
            .count()
    }

    // -- Story 4.4 (FR19) chain_heads support: parent resolution, structural
    //    ref-count mutation, and the table's first deletion path. ------------

    /// FR19 event (i) parent resolution. A block's parent has a *known*
    /// sequence — `child_sequence − 1` — and a known hash (`previous_hash`), so
    /// this reuses the `(sequence, hash)` index without needing a
    /// find-by-hash-alone. Returns `None` for `child_sequence == 0` (genesis has
    /// no parent) or when the parent is not (yet) in the tree.
    pub(crate) fn find_parent(&self, previous_hash: &[u8; 32], child_sequence: u32) -> Option<u32> {
        let parent_sequence = child_sequence.checked_sub(1)?;
        self.find(parent_sequence, previous_hash)
    }

    /// FR19 shared-ancestry reference count of the block at `idx`, or `None` for
    /// an empty/out-of-bounds slot. Read by `chain_heads.rs` assertions + the
    /// eviction walk's post-conditions.
    pub(crate) fn head_ref_count(&self, idx: u32) -> Option<u8> {
        self.get(idx).map(|entry| entry.head_ref_count())
    }

    /// FR19 structural `head_ref_count` mutation on an **already-inserted**
    /// block (event (ii) back-walk increment; eviction back-walk decrement).
    /// Returns the new count, or `None` for an empty/out-of-bounds slot.
    ///
    /// **This is a deliberate, narrow exception to this module's "no in-place
    /// mutation — delete-then-`insert`" rule.** That rule is scoped to
    /// *ancestry-identity and status* bits (e.g. flipping `is_on_active_chain`
    /// during an FR23 chain-switch). `head_ref_count` is *structural
    /// bookkeeping* — FR19 defines it as "derived from the block-tree graph" and
    /// mutates it in place on blocks that have children; delete-then-reinsert
    /// would assign a new index and orphan every child's `parent_ref`. So the
    /// count is adjusted in place here, while identity/ancestry remain immutable.
    pub(crate) fn adjust_head_ref_count(&mut self, idx: u32, delta: i8) -> Option<u8> {
        let entry = self.blocks.get_mut(idx as usize)?;
        if entry.is_empty_slot() {
            return None;
        }
        let new_count = if delta >= 0 {
            let inc = delta as u8;
            debug_assert!(
                entry.head_ref_count.checked_add(inc).is_some(),
                "adjust_head_ref_count: head_ref_count overflow"
            );
            entry.head_ref_count.saturating_add(inc)
        } else {
            let dec = delta.unsigned_abs();
            debug_assert!(
                entry.head_ref_count >= dec,
                "adjust_head_ref_count: head_ref_count underflow"
            );
            entry.head_ref_count.saturating_sub(dec)
        };
        entry.head_ref_count = new_count;
        Some(new_count)
    }

    /// FR19 event (ii): resolve a tail-point's previously-missing parent link,
    /// setting `parent_ref` from [`NONE_REF`] to the now-present parent index.
    ///
    /// Same structural-not-identity rationale as [`Self::adjust_head_ref_count`]:
    /// a parent is only ever *resolved* (`NONE_REF → idx`), never *re-pointed*
    /// to a different block (that would be an identity change and is forbidden).
    /// Debug-asserts the current value is `NONE_REF`.
    pub(crate) fn resolve_parent_ref(&mut self, idx: u32, parent_idx: u32) {
        if let Some(entry) = self.blocks.get_mut(idx as usize) {
            debug_assert!(!entry.is_empty_slot(), "resolve_parent_ref: empty slot");
            debug_assert!(
                entry.parent_ref == NONE_REF,
                "resolve_parent_ref: only an unresolved parent may be resolved, never re-pointed"
            );
            entry.parent_ref = parent_idx;
        }
    }

    /// FR6/FR4 value setter — the block's FR9 `BlockStatus` (bits 1-2 of
    /// `flags`) on an **already-inserted** block. Bidirectional and value-based
    /// (Story 5.4): the FR3 Ready transition promotes `Stored→Active`; the FR5
    /// recovery (5.5) / FR23 chain-switch (Epic 6) reverse it. Same
    /// structural-not-identity rationale as [`Self::adjust_head_ref_count`] —
    /// the status bits are non-identity metadata; `hash`/`sequence`/`parent_ref`
    /// stay immutable. Returns `false` for an empty/out-of-bounds slot.
    pub(crate) fn set_status(&mut self, idx: u32, status: BlockStatus) -> bool {
        match self.blocks.get_mut(idx as usize) {
            Some(entry) if !entry.is_empty_slot() => {
                entry.set_status(status);
                true
            }
            _ => false,
        }
    }

    /// FR6/FR4 value setter — `is_on_active_chain` (bit 0 of `flags`) on an
    /// **already-inserted** block. Bidirectional (Story 5.4): the Ready
    /// transition sets `true` for every candidate block; the FR23 chain-switch
    /// (Epic 6) flips it both ways. Returns `false` for an empty/out-of-bounds
    /// slot.
    pub(crate) fn set_on_active_chain(&mut self, idx: u32, value: bool) -> bool {
        match self.blocks.get_mut(idx as usize) {
            Some(entry) if !entry.is_empty_slot() => {
                entry.set_on_active_chain(value);
                true
            }
            _ => false,
        }
    }

    /// ADR-016 UTXO spent-bit read at `bit` on the block at `idx`, or `None`
    /// for an empty/out-of-bounds slot. Read by the FR6 double-spend check
    /// (Story 5.4).
    pub(crate) fn spent_bit(&self, idx: u32, bit: usize) -> Option<bool> {
        self.get(idx).map(|entry| entry.spent_bit(bit))
    }

    /// ADR-016 UTXO spent-bit value setter on an **already-inserted** block
    /// (Story 5.4). Bidirectional: the FR6 forward pass sets `0→1` on
    /// consumption; the FR5 rollback (5.5) resets `1→0`. Returns `false` for an
    /// empty/out-of-bounds slot.
    pub(crate) fn set_spent_bit(&mut self, idx: u32, bit: usize, value: bool) -> bool {
        match self.blocks.get_mut(idx as usize) {
            Some(entry) if !entry.is_empty_slot() => {
                entry.set_spent_bit(bit, value);
                true
            }
            _ => false,
        }
    }

    /// Clears the entire UTXO spent-bit vector of the block at `idx` back to the
    /// all-zero construction default (ADR-016). Used by the FR6 pass's aborted-
    /// run rollback (Story 5.4 — the FR5 working-set-rollback UTXO half): a
    /// candidate that fails validation must not leave any spent-bit it flipped
    /// set. No-op for an empty/out-of-bounds slot.
    pub(crate) fn clear_spent_bits(&mut self, idx: u32) {
        if let Some(entry) = self.blocks.get_mut(idx as usize)
            && !entry.is_empty_slot()
        {
            entry.spent_bits = [0u8; SPENT_BITS_BYTES];
        }
    }

    /// FR19 eviction: free the slot at `idx` (reset to the empty-slot sentinel),
    /// returning whether an occupied block was removed. This is the block-tree's
    /// **first** deletion path (Story 4.1 deferred it here) — an authorized
    /// removal complementing FR16/FR17 (FR5/FR57 later). Because
    /// `blocks[i] ⟷ storage_index = i`, freeing the slot releases `storage_index
    /// = idx` for reuse; the durable bytes are overwritten by the next
    /// `save_block(idx, …)` (no eager flash erase — `StorageTrait` exposes no
    /// delete, and lazy overwrite-on-reuse is the sane embedded pattern; see the
    /// Story 4.4 "Eviction walk" Dev Note).
    pub(crate) fn delete(&mut self, idx: u32) -> bool {
        match self.blocks.get_mut(idx as usize) {
            Some(entry) if !entry.is_empty_slot() => {
                *entry = BlockEntry::new_empty();
                true
            }
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hash_of(byte: u8) -> [u8; 32] {
        [byte; 32]
    }

    /// Test-only stand-in for the deleted by-value `BlockTable::new()`:
    /// wraps the `MaybeUninit` + `init_in_place` + `assume_init()` calling
    /// convention once so individual tests don't each repeat `unsafe` code.
    fn empty_table<const N: usize>() -> BlockTable<N> {
        let mut table = core::mem::MaybeUninit::<BlockTable<N>>::uninit();
        unsafe {
            BlockTable::init_in_place(table.as_mut_ptr());
            table.assume_init()
        }
    }

    #[test]
    fn block_entry_size_is_within_budget() {
        // 32 hash + 4 parent_ref + 4 sequence + 32 spent_bits +
        // 1 head_ref_count + 1 flags + 2 len = 76 B effective, 4-byte aligned
        // (largest field is u32) -> 76 B, matching architecture §6.2. The
        // Story-5.4 `len: u16` field consumed the 2 bytes of tail padding the
        // 74-byte layout previously wasted, so the entry size is unchanged.
        // Pinned exactly, not just bounded, so a future field addition must
        // consciously update this (same discipline as chain-types'
        // `block_view_size_is_pointer_plus_length`).
        assert_eq!(core::mem::size_of::<BlockEntry>(), 76);
    }

    #[test]
    fn block_table_empty_slot_sentinel() {
        let table = empty_table::<4>();
        for i in 0..4 {
            assert!(table.get(i).is_none());
        }
        assert_eq!(table.len(), 0);
    }

    #[test]
    fn insert_assigns_index_and_is_findable() {
        let mut table = empty_table::<4>();
        let entry = BlockEntry::new(hash_of(1), NONE_REF, 0);
        let idx = table.insert(entry).unwrap();
        assert_eq!(table.find(0, &hash_of(1)), Some(idx));
        assert_eq!(table.len(), 1);
    }

    #[test]
    fn find_returns_none_for_unknown_sequence_hash() {
        let mut table = empty_table::<4>();
        table
            .insert(BlockEntry::new(hash_of(1), NONE_REF, 0))
            .unwrap();
        assert_eq!(table.find(1, &hash_of(1)), None);
        assert_eq!(table.find(0, &hash_of(2)), None);
    }

    /// FR11 de-duplication is the caller's responsibility (the intake
    /// dispatcher's authoritative `(sequence, hash)` check). `insert`/
    /// `insert_at` no longer re-check it in release; a duplicate is a caller
    /// bug, caught by a debug assertion. This documents that contract (debug
    /// builds only — the assertion is compiled out under `--release`).
    #[cfg(debug_assertions)]
    #[test]
    #[should_panic(expected = "FR11-dedup")]
    fn insert_at_debug_asserts_caller_deduplicates() {
        let mut table = empty_table::<4>();
        table
            .insert(BlockEntry::new(hash_of(1), NONE_REF, 0))
            .unwrap();
        // A second insert of the same (sequence, hash) trips the debug assert.
        let _ = table.insert(BlockEntry::new(hash_of(1), NONE_REF, 0));
    }

    #[test]
    fn insert_rejects_reserved_sequence_sentinel() {
        // sequence == NONE_REF (u32::MAX) would be indistinguishable from an
        // empty slot once stored — insert must refuse it up front rather
        // than silently creating an unreadable/overwritable occupied slot.
        let mut table = empty_table::<4>();
        let result = table.insert(BlockEntry::new(hash_of(1), NONE_REF, NONE_REF));
        assert_eq!(result, Err(BlockTableError::ReservedSequence));
        assert_eq!(table.len(), 0);
    }

    #[test]
    fn insert_rejects_when_table_full() {
        let mut table = empty_table::<2>();
        table
            .insert(BlockEntry::new(hash_of(1), NONE_REF, 0))
            .unwrap();
        table
            .insert(BlockEntry::new(hash_of(2), NONE_REF, 1))
            .unwrap();
        let result = table.insert(BlockEntry::new(hash_of(3), NONE_REF, 2));
        assert_eq!(result, Err(BlockTableError::Full));
        assert_eq!(table.len(), 2);
        // Existing entries undisturbed (FR20 — no silent collapse to make room).
        assert!(table.find(0, &hash_of(1)).is_some());
        assert!(table.find(1, &hash_of(2)).is_some());
    }

    #[test]
    fn ancestry_walk_finds_active_chain_through_multiple_hops() {
        let mut table = empty_table::<8>();
        let root = table
            .insert(BlockEntry::new(hash_of(0), NONE_REF, 0))
            .unwrap();
        // Mark the root on the active chain.
        table.blocks[root as usize].set_on_active_chain(true);

        let child1 = table.insert(BlockEntry::new(hash_of(1), root, 1)).unwrap();
        let child2 = table
            .insert(BlockEntry::new(hash_of(2), child1, 2))
            .unwrap();
        let tip = table
            .insert(BlockEntry::new(hash_of(3), child2, 3))
            .unwrap();

        assert!(table.walks_to_active_chain(tip));
    }

    #[test]
    fn ancestry_walk_returns_false_on_unresolved_parent() {
        let mut table = empty_table::<4>();
        let orphan = table
            .insert(BlockEntry::new(hash_of(1), NONE_REF, 5))
            .unwrap();
        assert!(!table.walks_to_active_chain(orphan));
    }

    #[test]
    fn ancestry_walk_is_bounded() {
        let mut table = empty_table::<4>();
        let a = table
            .insert(BlockEntry::new(hash_of(1), NONE_REF, 0))
            .unwrap();
        let b = table.insert(BlockEntry::new(hash_of(2), a, 1)).unwrap();
        // Introduce a malformed 2-cycle: a's parent_ref now points to b.
        table.blocks[a as usize].parent_ref = b;

        // Neither node is on the active chain; an unbounded walk would loop
        // forever. The bounded walk must terminate and report false.
        assert!(!table.walks_to_active_chain(b));
    }

    #[test]
    fn multiple_branches_all_retained() {
        let mut table = empty_table::<8>();
        let root = table
            .insert(BlockEntry::new(hash_of(0), NONE_REF, 0))
            .unwrap();
        let branch_a = table.insert(BlockEntry::new(hash_of(1), root, 1)).unwrap();
        let branch_b = table.insert(BlockEntry::new(hash_of(2), root, 1)).unwrap();

        assert_ne!(branch_a, branch_b);
        assert!(table.find(1, &hash_of(1)).is_some());
        assert!(table.find(1, &hash_of(2)).is_some());
        assert_eq!(table.len(), 3);
    }

    #[test]
    fn status_default_is_stored() {
        // AC1 / AC4: a brand-new entry (and an empty slot) decodes to Stored,
        // the collecting-state default — no explicit set_status needed.
        assert_eq!(
            BlockEntry::new(hash_of(1), NONE_REF, 0).status(),
            BlockStatus::Stored
        );
        assert_eq!(BlockEntry::new_empty().status(), BlockStatus::Stored);
    }

    #[test]
    fn status_round_trips_through_flags() {
        for status in [
            BlockStatus::Stored,
            BlockStatus::Connected,
            BlockStatus::Active,
        ] {
            let mut entry = BlockEntry::new(hash_of(1), NONE_REF, 0);
            entry.set_status(status);
            assert_eq!(entry.status(), status);
        }
    }

    #[test]
    fn status_and_active_chain_bit_are_independent() {
        // The FR9 status (bits 1-2) and is_on_active_chain (bit 0) must not
        // clobber each other — distinct concepts (architecture §6.2).
        let mut entry = BlockEntry::new(hash_of(1), NONE_REF, 0);
        entry.set_on_active_chain(true);
        entry.set_status(BlockStatus::Active);
        assert!(entry.is_on_active_chain());
        assert_eq!(entry.status(), BlockStatus::Active);

        entry.set_status(BlockStatus::Stored);
        assert!(
            entry.is_on_active_chain(),
            "flipping status must not clear the active-chain bit"
        );

        entry.set_status(BlockStatus::Connected);
        entry.set_on_active_chain(false);
        assert_eq!(
            entry.status(),
            BlockStatus::Connected,
            "clearing the active-chain bit must not disturb status"
        );
        assert!(!entry.is_on_active_chain());
    }

    #[test]
    fn block_table_footprint_invariant() {
        let mut table = empty_table::<4>();
        for i in 0..4u32 {
            table
                .insert(BlockEntry::new(hash_of(i as u8), NONE_REF, i))
                .unwrap();
            assert!(table.len() <= 4);
        }
        for entry in table.blocks.iter() {
            assert!(!entry.is_empty_slot());
        }
        assert_eq!(
            table.insert(BlockEntry::new(hash_of(99), NONE_REF, 99)),
            Err(BlockTableError::Full)
        );
    }
}
