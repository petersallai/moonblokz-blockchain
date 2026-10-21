//! `branch_value.rs` — FR21.
//!
//! Stateless: the FR21 per-block value, the FR21 rank and operational
//! admissibility. The values
//! themselves live elsewhere (Story 6.1 D3):
//!
//! - the active branch's value is `Blockchain::active_branch_value`, because
//!   the active head is not always a `chain_heads` tip (a Stored child makes
//!   it interior and FR19 event (i) moves its entry to the child);
//! - a side head's value is its `ChainHeadEntry.branch_value`, meaningful iff
//!   the head block's status is `Connected`.
//!
//! A branch's value is the sum of the per-block values of the blocks on its
//! ancestry with sequence in `(S_tail, head]` — `S_tail` exclusive, so a tail
//! advance subtracts the value of the block that becomes the new `S_tail`
//! (D1). Every value shares `S_tail`, so values compare across branches.
//!
//! FR21 (iv), the chain switch (Story 6.3), changes no value: the new active
//! value is the new head's entry value, and the old active head's entry (if
//! one exists) receives the old `active_branch_value`.

use moonblokz_chain_types::BlockView;

/// The FR21 per-block value: the header `consumed_votes`. A replay block
/// between a deviation and its evidence block contributes 0 through its FR27
/// header override. A sum of at most `MAX_BLOCKS` such values cannot overflow
/// a `u64` (asserted at compile time in `Blockchain::walk_side_branch`).
/// The approval-evidence `supporter_vote_sum` arm is Story
/// 6.7's, added together with its validation (D2): until then an evidence
/// block contributes its header `consumed_votes`, which FR27 fixes at 0.
pub(crate) fn block_value(view: &BlockView<'_>) -> u64 {
    u64::from(view.consumed_votes())
}

/// The FR21 rank of a candidate tip: the branch value, then the larger
/// serialized tip size, then the lowest tip hash read big-endian (PRD FR21;
/// Story 6.2 D4, DEC-155: the tip creator is no criterion). Size and hash are
/// in RAM (`BlockEntry`), so ranking a head reads nothing. Byte arrays compare
/// lexicographically, which is the big-endian order.
pub(crate) struct Rank {
    pub(crate) value: u64,
    pub(crate) len: u16,
    pub(crate) hash: [u8; 32],
}

impl Rank {
    /// `true` iff `self` wins over `other` under the FR21 order.
    pub(crate) fn outranks(&self, other: &Rank) -> bool {
        use core::cmp::Reverse;
        (self.value, self.len, Reverse(self.hash)) > (other.value, other.len, Reverse(other.hash))
    }
}

/// FR21 operational admissibility of a Connected / Active candidate whose tip
/// is at sequence `tip`, on an active window `[tail, head]` (`S_tail`,
/// `S_head`) of configured length `w` (Story 6.2 D3, DEC-154).
///
/// The window only grows to `w` in Ready and then stays there (every extension
/// past it advances the tail once), so no maturity flag is kept: the chain has
/// matured iff `head − tail + 1 ≥ w`. Before that every candidate is
/// genesis-anchored and spans `#0` to its tip — the bootstrap case, always
/// admissible. Once matured, a candidate forks at or above `S_tail` (DEC-125)
/// and the active chain is retained down to `S_tail` (below-tail retention 0,
/// `snake_chain::BELOW_TAIL_RETENTION`), so its continuous tip-ending segment
/// is `[tail, tip]`: admissible iff it covers `w`, i.e. `tip ≥ tail + w − 1`.
/// Story 9.7 revisits this if it retains blocks below `S_tail`.
pub(crate) fn is_admissible(tail: u32, head: u32, tip: u32, w: u32) -> bool {
    let matured = u64::from(head) + 1 >= u64::from(tail) + u64::from(w);
    !matured || u64::from(tip) + 1 >= u64::from(tail) + u64::from(w)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rank(value: u64, len: u16, hash_byte: u8) -> Rank {
        Rank {
            value,
            len,
            hash: [hash_byte; 32],
        }
    }

    /// The FR21 order, criterion by criterion: each later key decides only a
    /// tie on every earlier one; there is no creator criterion (DEC-155).
    #[test]
    fn rank_orders_by_value_then_size_then_hash() {
        assert!(rank(2, 1, 9).outranks(&rank(1, 9, 0)), "value first");
        assert!(
            rank(1, 9, 9).outranks(&rank(1, 1, 0)),
            "then the larger block"
        );
        assert!(
            rank(1, 1, 0).outranks(&rank(1, 1, 1)),
            "then the lower hash"
        );
        assert!(
            !rank(1, 1, 0).outranks(&rank(1, 1, 0)),
            "a rank never outranks itself"
        );
    }

    /// DEC-154: before maturity every candidate is admissible; once the
    /// window spans `w`, only a candidate reaching `tail + w − 1`.
    #[test]
    fn admissibility_follows_the_window() {
        // W = 4, window [0, 2]: not matured, any tip.
        assert!(is_admissible(0, 2, 1, 4));
        // Window [7, 10]: matured. Tips 9 (segment 3) no, 10 and 11 yes.
        assert!(!is_admissible(7, 10, 9, 4));
        assert!(is_admissible(7, 10, 10, 4));
        assert!(is_admissible(7, 10, 11, 4));
        // The first matured window [0, 3].
        assert!(!is_admissible(0, 3, 2, 4));
        assert!(is_admissible(0, 3, 3, 4));
        // No overflow at the extremes.
        assert!(is_admissible(u32::MAX - 3, u32::MAX, u32::MAX, 4));
    }
}
