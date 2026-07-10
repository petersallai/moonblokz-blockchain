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
//! **Once inserted, an entry is not mutated in place — only deleted and
//! replaced.** `BlockTable` deliberately exposes no `get_mut`/update-by-index
//! method (2026-07-04 design decision). Any change to an already-inserted
//! block's ancestry or status bits (e.g. flipping `is_on_active_chain`
//! during a future FR23 chain-switch) goes through delete-then-`insert`,
//! not an in-place field write. `BlockTable` itself has no deletion method
//! yet — that lands in Story 4.4 alongside `chain_heads.rs`'s eviction path,
//! the first authorized way to free a slot (FR19 chain_heads-eviction).
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

/// Sentinel value for an unresolved parent reference and for an empty
/// slot's `sequence` (architecture §6.2).
const NONE_REF: u32 = u32::MAX;

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

/// `flags` bit assignment: bit 0 is live in Story 4.1; bits 1-2 are reserved
/// for Story 4.2's FR9 status placeholder and are neither set nor
/// interpreted here; bits 3-7 are unused.
const FLAG_ON_ACTIVE_CHAIN: u8 = 0b0000_0001;

/// Per-block ancestry and status metadata (FR18).
///
/// `Copy`/`Clone` are derived solely so [`BlockTable::new`] can populate its
/// array with `[BlockEntry::new_empty(); MAX_BLOCKS]` (same rationale as
/// `moonblokz-mempool`'s `IndexEntry`). Fields are private; module-local
/// code (including tests) uses direct field access rather than an
/// accessor surface, keeping the embedded API surface small — the same
/// discipline `moonblokz-mempool`'s `IndexEntry` follows.
// No caller reads `head_ref_count`/`spent_bits` yet (Story 4.2/4.4/Epic 7
// consume them); silencing dead_code keeps the struct clean until those
// callers land, matching Story 1.2's scaffold convention. Rust's dead-code
// lint ignores derived-`Clone` "uses".
#[allow(dead_code)]
#[derive(Clone, Copy)]
pub(crate) struct BlockEntry {
    hash: [u8; 32],
    parent_ref: u32,
    sequence: u32,
    spent_bits: [u8; SPENT_BITS_BYTES],
    head_ref_count: u8,
    flags: u8,
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
        }
    }

    /// Constructs an occupied entry. `parent_ref == NONE_REF` means no
    /// resolved parent (e.g. genesis, or an as-yet-unrecovered ancestor).
    pub(crate) fn new(hash: [u8; 32], parent_ref: u32, sequence: u32) -> Self {
        Self {
            hash,
            parent_ref,
            sequence,
            spent_bits: [0; SPENT_BITS_BYTES],
            head_ref_count: 0,
            flags: 0,
        }
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
}

/// Errors from [`BlockTable::insert`]. Consumed starting with Story 4.3's
/// intake surface; Story 4.1's tests exercise it directly.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BlockTableError {
    /// No empty slot remains. Capacity-pressure eviction (FR19
    /// chain_heads-eviction) is Story 4.4's concern, not this table's.
    Full,
    /// An entry with the same `(sequence, hash)` is already present
    /// (FR11). `insert` checks this defensively even though the intended
    /// caller (Story 4.3's intake surface) is expected to call
    /// [`BlockTable::find`] first.
    DuplicateEntry,
    /// `entry.sequence == NONE_REF` (`u32::MAX`) — the same sentinel value
    /// [`BlockEntry::is_empty_slot`] uses to mean "this slot is empty".
    /// Inserting such an entry would make an *occupied* slot indistinguishable
    /// from an empty one: `get`/`find` would treat it as absent (data
    /// becomes unreadable) and a later `insert` could silently overwrite it
    /// (data loss) — violating FR20's no-silent-collapse guarantee. FR53
    /// ("rejects u32::MAX-based chain extension in MVP", architecture §6.2)
    /// is expected to keep a real sequence from ever reaching `u32::MAX`
    /// before it gets this far; `insert` still checks defensively, matching
    /// this table's other defensive checks.
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
// Story 4.2/4.3/4.4; `new` is already called from `api.rs`. Story 4.1's
// tests exercise every method directly.
#[allow(dead_code)]
impl<const MAX_BLOCKS: usize> BlockTable<MAX_BLOCKS> {
    /// Compile-time-constant empty table — one instance per `MAX_BLOCKS`
    /// monomorphization, evaluated by `rustc` at compile time rather than
    /// assembled element-by-element at runtime. `new()` copies this constant
    /// instead of evaluating `[BlockEntry::new_empty(); MAX_BLOCKS]` itself,
    /// so the ~45.6 KB initial value (`MAX_BLOCKS = 600`) is baked into the
    /// binary's read-only data and reproduced via a bulk copy — not built up
    /// as a live stack temporary on every call. Plain `static` was
    /// considered and rejected: architecture §10 (FR62 simulator
    /// compatibility) requires `Blockchain` to stay a plain owned value with
    /// no `'static`/global state, specifically so the desktop simulator can
    /// run many independent instances in one process; an associated `const`
    /// keeps that per-instance ownership while still moving the expensive
    /// part of construction to compile time.
    ///
    /// **Measured, not assumed (2026-07-04).** An alternative — zero-fill
    /// the array at runtime, then patch only the two non-zero sentinel
    /// fields per slot in a loop — was built and measured head-to-head on
    /// the real `thumbv6m-none-eabi` target under the project's actual
    /// release profile (`opt-level = "z"`, `lto = true`,
    /// `codegen-units = 1`). It costs ~0 flash bytes as predicted (no
    /// stored template), but needs **66% *more* stack** than this `const`
    /// (111 KiB vs. 66.6 KiB through `Blockchain::new()`'s real
    /// whole-struct-literal shape) — mutating a named local in a loop
    /// forces the compiler to materialize it as a real, non-elidable stack
    /// value, which is worse than this constant's single unconditional
    /// copy. Given architecture §2 states RAM, not flash, is the binding
    /// constraint, `const EMPTY` is the right choice on the metric that
    /// matters. Full numbers: Story 4.1 code-review discussion /
    /// `deferred-work.md`.
    ///
    /// **Neither approach makes `Blockchain::new()` stack-safe on its
    /// own.** Both measured figures are 11-18× the blockchain task's 6 KiB
    /// stack budget (architecture §8) — `Blockchain::new()`'s overall
    /// return-by-value pattern is the real driver, not this one field's
    /// construction strategy. That is a separate, larger architectural
    /// question, tracked in `deferred-work.md`, not resolved by this
    /// constant.
    const EMPTY: Self = Self {
        blocks: [BlockEntry::new_empty(); MAX_BLOCKS],
    };

    pub(crate) const fn new() -> Self {
        Self::EMPTY
    }

    /// Initializes `*dst` in place for embedded/task use: writes each
    /// `BlockEntry` directly to its final address through a raw pointer,
    /// one at a time, so no value the size of the whole `[BlockEntry;
    /// MAX_BLOCKS]` array (~45.6 KB at the default `MAX_BLOCKS = 600`)
    /// ever exists anywhere in this function — unlike `Self::EMPTY` (a
    /// `const`: cheap for [`Self::new`]'s by-value return, but still one
    /// addressable unit that has to be copied in bulk once it becomes a
    /// field of a larger owned value, e.g. `Blockchain`). Used by
    /// [`crate::api::Blockchain::init_in_place`]; see that method's doc
    /// comment for why and how to call it from a task.
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
            .find(|(_, entry)| !entry.is_empty_slot() && entry.sequence == sequence && &entry.hash == hash)
            .map(|(idx, _)| idx as u32)
    }

    /// Inserts `entry` into the first empty slot. Never evicts or
    /// overwrites a non-empty slot (FR20 — full retention; no silent
    /// collapse of side branches).
    pub(crate) fn insert(&mut self, entry: BlockEntry) -> Result<u32, BlockTableError> {
        if entry.sequence == NONE_REF {
            return Err(BlockTableError::ReservedSequence);
        }
        if self.find(entry.sequence, &entry.hash).is_some() {
            return Err(BlockTableError::DuplicateEntry);
        }
        match self.blocks.iter_mut().enumerate().find(|(_, slot)| slot.is_empty_slot()) {
            Some((idx, slot)) => {
                *slot = entry;
                Ok(idx as u32)
            }
            None => Err(BlockTableError::Full),
        }
    }

    /// Returns the entry at `idx`, or `None` if `idx` is out of bounds or
    /// names an empty slot.
    pub(crate) fn get(&self, idx: u32) -> Option<&BlockEntry> {
        self.blocks.get(idx as usize).filter(|entry| !entry.is_empty_slot())
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

    /// Number of occupied slots. Used by the AC7 footprint invariant test;
    /// the `MAX_BLOCKS` ceiling is already structural (array-bounded), so
    /// this exists to catch a leaked slot (never freed) rather than an
    /// out-of-bounds write.
    pub(crate) fn len(&self) -> usize {
        self.blocks.iter().filter(|entry| !entry.is_empty_slot()).count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hash_of(byte: u8) -> [u8; 32] {
        [byte; 32]
    }

    #[test]
    fn block_entry_size_is_within_budget() {
        // 32 hash + 4 parent_ref + 4 sequence + 32 spent_bits +
        // 1 head_ref_count + 1 flags = 74 B effective, 4-byte aligned
        // (largest field is u32) -> 76 B padded, matching architecture
        // §6.2 exactly. Pinned exactly, not just bounded, so a future field
        // addition must consciously update this (same discipline as
        // chain-types' `block_view_size_is_pointer_plus_length`).
        assert_eq!(core::mem::size_of::<BlockEntry>(), 76);
    }

    #[test]
    fn block_table_empty_slot_sentinel() {
        let table = BlockTable::<4>::new();
        for i in 0..4 {
            assert!(table.get(i).is_none());
        }
        assert_eq!(table.len(), 0);
    }

    #[test]
    fn insert_assigns_index_and_is_findable() {
        let mut table = BlockTable::<4>::new();
        let entry = BlockEntry::new(hash_of(1), NONE_REF, 0);
        let idx = table.insert(entry).unwrap();
        assert_eq!(table.find(0, &hash_of(1)), Some(idx));
        assert_eq!(table.len(), 1);
    }

    #[test]
    fn find_returns_none_for_unknown_sequence_hash() {
        let mut table = BlockTable::<4>::new();
        table.insert(BlockEntry::new(hash_of(1), NONE_REF, 0)).unwrap();
        assert_eq!(table.find(1, &hash_of(1)), None);
        assert_eq!(table.find(0, &hash_of(2)), None);
    }

    #[test]
    fn insert_rejects_duplicate_sequence_hash() {
        let mut table = BlockTable::<4>::new();
        table.insert(BlockEntry::new(hash_of(1), NONE_REF, 0)).unwrap();
        let result = table.insert(BlockEntry::new(hash_of(1), NONE_REF, 0));
        assert_eq!(result, Err(BlockTableError::DuplicateEntry));
        assert_eq!(table.len(), 1);
    }

    #[test]
    fn insert_rejects_reserved_sequence_sentinel() {
        // sequence == NONE_REF (u32::MAX) would be indistinguishable from an
        // empty slot once stored — insert must refuse it up front rather
        // than silently creating an unreadable/overwritable occupied slot.
        let mut table = BlockTable::<4>::new();
        let result = table.insert(BlockEntry::new(hash_of(1), NONE_REF, NONE_REF));
        assert_eq!(result, Err(BlockTableError::ReservedSequence));
        assert_eq!(table.len(), 0);
    }

    #[test]
    fn insert_rejects_when_table_full() {
        let mut table = BlockTable::<2>::new();
        table.insert(BlockEntry::new(hash_of(1), NONE_REF, 0)).unwrap();
        table.insert(BlockEntry::new(hash_of(2), NONE_REF, 1)).unwrap();
        let result = table.insert(BlockEntry::new(hash_of(3), NONE_REF, 2));
        assert_eq!(result, Err(BlockTableError::Full));
        assert_eq!(table.len(), 2);
        // Existing entries undisturbed (FR20 — no silent collapse to make room).
        assert!(table.find(0, &hash_of(1)).is_some());
        assert!(table.find(1, &hash_of(2)).is_some());
    }

    #[test]
    fn ancestry_walk_finds_active_chain_through_multiple_hops() {
        let mut table = BlockTable::<8>::new();
        let root = table.insert(BlockEntry::new(hash_of(0), NONE_REF, 0)).unwrap();
        // Mark the root on the active chain.
        let mut active_root = table.blocks[root as usize];
        active_root.set_on_active_chain(true);
        table.blocks[root as usize] = active_root;

        let child1 = table.insert(BlockEntry::new(hash_of(1), root, 1)).unwrap();
        let child2 = table.insert(BlockEntry::new(hash_of(2), child1, 2)).unwrap();
        let tip = table.insert(BlockEntry::new(hash_of(3), child2, 3)).unwrap();

        assert!(table.walks_to_active_chain(tip));
    }

    #[test]
    fn ancestry_walk_returns_false_on_unresolved_parent() {
        let mut table = BlockTable::<4>::new();
        let orphan = table.insert(BlockEntry::new(hash_of(1), NONE_REF, 5)).unwrap();
        assert!(!table.walks_to_active_chain(orphan));
    }

    #[test]
    fn ancestry_walk_is_bounded() {
        let mut table = BlockTable::<4>::new();
        let a = table.insert(BlockEntry::new(hash_of(1), NONE_REF, 0)).unwrap();
        let b = table.insert(BlockEntry::new(hash_of(2), a, 1)).unwrap();
        // Introduce a malformed 2-cycle: a's parent_ref now points to b.
        let mut cyclic_a = table.blocks[a as usize];
        cyclic_a.parent_ref = b;
        table.blocks[a as usize] = cyclic_a;

        // Neither node is on the active chain; an unbounded walk would loop
        // forever. The bounded walk must terminate and report false.
        assert!(!table.walks_to_active_chain(b));
    }

    #[test]
    fn multiple_branches_all_retained() {
        let mut table = BlockTable::<8>::new();
        let root = table.insert(BlockEntry::new(hash_of(0), NONE_REF, 0)).unwrap();
        let branch_a = table.insert(BlockEntry::new(hash_of(1), root, 1)).unwrap();
        let branch_b = table.insert(BlockEntry::new(hash_of(2), root, 1)).unwrap();

        assert_ne!(branch_a, branch_b);
        assert!(table.find(1, &hash_of(1)).is_some());
        assert!(table.find(1, &hash_of(2)).is_some());
        assert_eq!(table.len(), 3);
    }

    #[test]
    fn block_table_footprint_invariant() {
        let mut table = BlockTable::<4>::new();
        for i in 0..4u32 {
            table.insert(BlockEntry::new(hash_of(i as u8), NONE_REF, i)).unwrap();
            assert!(table.len() <= 4);
        }
        for entry in table.blocks.iter() {
            assert!(!entry.is_empty_slot());
        }
        assert_eq!(table.insert(BlockEntry::new(hash_of(99), NONE_REF, 99)), Err(BlockTableError::Full));
    }
}
