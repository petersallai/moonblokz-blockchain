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

use moonblokz_chain_types::{ApprovalView, BlockView, PAYLOAD_TYPE_APPROVAL};
use moonblokz_crypto::MAX_AGGREGATED_SIGNATURES;

/// The largest FR21 value an evidence block can count (Story 6.7 D7, DEC-264),
/// a build constant: `MAX_AGGREGATED_SIGNATURES · MAX_NODES · (u32::MAX +
/// u16::MAX)`. No honest value reaches it — `supporter_vote_sum = B_k − cv(d)`
/// with `B_k = h · Σ_{j=0..k}(s_j + vs)`, `h ≤ MAX_AGGREGATED_SIGNATURES`, `k + 1
/// ≤ max_node_count ≤ MAX_NODES` (configuration §6 check 18), `s_j ≤ u32::MAX`
/// and `vs ≤ u16::MAX` — so the clamp only bounds a junk claim.
pub(crate) const fn value_cap<const MAX_NODES: usize>() -> u64 {
    (MAX_AGGREGATED_SIGNATURES as u64) * (MAX_NODES as u64) * (u32::MAX as u64 + u16::MAX as u64)
}

/// The FR21 per-block value. An approval evidence block (`payload_type == 4`)
/// counts its `supporter_vote_sum` (DEC-216), claimed until its Tier 3 runs
/// (Story 6.7 D2, DEC-259) and clamped at [`value_cap`] (D7, DEC-264); every
/// other block counts its header `consumed_votes`, so a replay block between a
/// deviation and its evidence contributes 0 through its FR27 header override.
/// The clamped value is a pure function of the bytes, so the incremental `+=` /
/// `−=` of FR21 stays exact. A sum of at most `MAX_BLOCKS` values cannot
/// overflow a `u64` (asserted at compile time in `Blockchain::walk_side_branch`).
/// An evidence payload that does not frame cannot pass Tier 1; it counts 0.
pub(crate) fn block_value<const MAX_NODES: usize>(view: &BlockView<'_>) -> u64 {
    if view.payload_type() == PAYLOAD_TYPE_APPROVAL {
        return ApprovalView::from_payload(view.payload()).map_or(0, |evidence| {
            evidence.supporter_vote_sum().min(value_cap::<MAX_NODES>())
        });
    }
    u64::from(view.consumed_votes())
}

/// The FR21 rank of a candidate tip: the branch value, then the larger
/// serialized tip size, then the lowest tip hash read big-endian (PRD FR21;
/// Story 6.2 D4, DEC-155: the tip creator is no criterion). Size and hash are
/// in RAM (`BlockEntry`), so ranking a head reads nothing. Byte arrays compare
/// lexicographically, which is the big-endian order.
pub(crate) struct Rank {
    pub(crate) value: u64,
    pub(crate) len: u32,
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
/// admissible. Once matured, a candidate forks at or above `S_head − H ≥
/// S_tail` (DEC-207, DEC-208), and its continuous tip-ending segment counts
/// from `S_tail`: the verification horizon below the tail is retained but not
/// counted (DEC-209), because a switch to a shorter tip would leave a matured
/// chain with a window shorter than `W` (DEC-205). So it is `[tail, tip]`:
/// admissible iff it covers `w`, i.e. `tip ≥ tail + w − 1`.
pub(crate) fn is_admissible(tail: u32, head: u32, tip: u32, w: u32) -> bool {
    let matured = u64::from(head) + 1 >= u64::from(tail) + u64::from(w);
    !matured || u64::from(tip) + 1 >= u64::from(tail) + u64::from(w)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rank(value: u64, len: u32, hash_byte: u8) -> Rank {
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
