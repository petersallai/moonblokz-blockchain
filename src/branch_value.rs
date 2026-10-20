//! `branch_value.rs` — FR21.
//!
//! Stateless: the FR21 per-block value and the FR21 rank. The values
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
/// serialized tip size, then the lowest tip creator node id, then the lowest
/// tip hash read big-endian (PRD FR21; E6-9 / O-008). Byte arrays compare
/// lexicographically, which is the big-endian order.
pub(crate) struct Rank {
    pub(crate) value: u64,
    pub(crate) len: u16,
    pub(crate) creator: u32,
    pub(crate) hash: [u8; 32],
}

impl Rank {
    /// `true` iff `self` wins over `other` under the FR21 order.
    pub(crate) fn outranks(&self, other: &Rank) -> bool {
        use core::cmp::Reverse;
        (
            self.value,
            self.len,
            Reverse(self.creator),
            Reverse(self.hash),
        ) > (
            other.value,
            other.len,
            Reverse(other.creator),
            Reverse(other.hash),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rank(value: u64, len: u16, creator: u32, hash_byte: u8) -> Rank {
        Rank {
            value,
            len,
            creator,
            hash: [hash_byte; 32],
        }
    }

    /// The FR21 order, criterion by criterion: each later key decides only a
    /// tie on every earlier one.
    #[test]
    fn rank_orders_by_value_then_size_then_creator_then_hash() {
        assert!(rank(2, 1, 9, 9).outranks(&rank(1, 9, 0, 0)), "value first");
        assert!(
            rank(1, 9, 9, 9).outranks(&rank(1, 1, 0, 0)),
            "then the larger block"
        );
        assert!(
            rank(1, 1, 0, 9).outranks(&rank(1, 1, 1, 0)),
            "then the lower creator"
        );
        assert!(
            rank(1, 1, 0, 0).outranks(&rank(1, 1, 0, 1)),
            "then the lower hash"
        );
        assert!(
            !rank(1, 1, 0, 0).outranks(&rank(1, 1, 0, 0)),
            "a rank never outranks itself"
        );
    }
}
