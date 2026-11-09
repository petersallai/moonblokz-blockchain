//! `reconciliation.rs` — FR23, FR58.
//!
//! The reversible chain-switch reconciliation walk lives in `api.rs` as
//! private `Blockchain` methods (Story 6.3 D6, DEC-171), because the state it
//! rewrites is private to that module: `switch_toward` (the entry point
//! FR22's comparison calls), `undo_active_head` / `undo_committed_block` (the
//! backward walk's exact per-block inverse), the forward replay through the
//! shared per-block step against a virtual tail, `commit_switch` and
//! `restore_original`.
//!
//! This module holds the switch's admission rule. There is no deep zone and
//! no full-reconstruction path in ready state (DEC-159).

/// Whether a chain switch whose common ancestor is at sequence `ancestor` may
/// run in place (Story 6.3 AC1, Story 6.14 AC4; DEC-159, DEC-204, DEC-211),
/// given the sequences of the window tail, of the lowest retained active-chain
/// block (`root`, below the tail by at most the horizon) and of the active
/// head, the window `W` and the verification horizon `H`:
/// - the ancestor is in the window: `ancestor ≥ tail` — implied by the bound
///   under `H < W` (DEC-207), and kept as a real check (DEC-166);
/// - FR58's bound: `ancestor ≥ head − H`;
/// - every block the replay or a restore drops (`s − W`) or references
///   (`≥ s − W`) is retained: `max(ancestor + 1 − W, 0) ≥ root`. Nothing is
///   trusted; with the horizon full this coincides with the bound.
///
/// There is no completeness horizon (DEC-211): the walk may cross the FR3
/// pass's seed points, whose undo is identity on the values.
pub(crate) fn switch_admitted(
    ancestor: u32,
    tail: u32,
    root: u32,
    head: u32,
    w: u32,
    h: u32,
) -> bool {
    ancestor >= tail
        && ancestor.saturating_add(h) >= head
        && ancestor.saturating_add(1).saturating_sub(w) >= root
}

#[cfg(test)]
mod tests {
    use super::switch_admitted;

    #[test]
    fn the_admission_rule_follows_bound_and_retention() {
        // Arguments: ancestor, tail, root, head, W, H.
        // W = 4, H = 3: a genesis chain whose tail has not advanced admits any
        // fork within the bound, also one whose replay will cross W.
        assert!(switch_admitted(0, 0, 0, 3, 4, 3));
        assert!(switch_admitted(2, 0, 0, 3, 4, 3));
        // A tail that advanced with nothing retained below it (root 2 = tail,
        // head 5): the fork's replayed blocks would drop released blocks, so it
        // is refused even inside the bound.
        assert!(!switch_admitted(4, 2, 2, 5, 4, 3));
        // Only an ancestor at the head itself needs nothing below the root.
        assert!(switch_admitted(5, 2, 2, 5, 4, 3));
        // With the horizon full (W = 4, H = 2: head 9, tail 6, root 4) the
        // retention conjunct coincides with the bound: admitted at 7, refused
        // at 6.
        assert!(switch_admitted(7, 6, 4, 9, 4, 2));
        assert!(!switch_admitted(6, 6, 4, 9, 4, 2));
        // An ancestor below the tail is refused by the tail conjunct alone
        // (only reachable at H = W, which acceptance refuses: DEC-207).
        assert!(!switch_admitted(5, 6, 2, 9, 4, 4));
    }
}
