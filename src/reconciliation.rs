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
/// run in place (Story 6.3 AC1; DEC-159, DEC-167, DEC-204), given the
/// sequences of the lowest retained active-chain block (`root`, the tail
/// while no horizon is retained) and of the active head, the window `W`, the
/// verification horizon `H` and the completeness horizon `C`:
/// - the ancestor is retained: `ancestor ≥ root`;
/// - FR58's bound: `ancestor ≥ head − H`;
/// - no walk back across floor seeding: `ancestor ≥ C`;
/// - every block the replay or a restore drops (`s − W`) or references
///   (`≥ s − W + 1`) is retained: `max(ancestor + 1 − W, 0) ≥ root`. Nothing
///   is trusted; with the horizon retained (Story 6.14) this coincides with
///   the bound.
pub(crate) fn switch_admitted(
    ancestor: u32,
    root: u32,
    head: u32,
    w: u32,
    h: u32,
    complete_from: u32,
) -> bool {
    ancestor >= root
        && ancestor.saturating_add(h) >= head
        && ancestor >= complete_from
        && ancestor.saturating_add(1).saturating_sub(w) >= root
}

#[cfg(test)]
mod tests {
    use super::switch_admitted;

    #[test]
    fn the_admission_rule_follows_bound_completeness_and_retention() {
        // W = 4, H = 50: a genesis chain whose tail has not advanced admits
        // any fork, also one whose replay will cross W.
        assert!(switch_admitted(0, 0, 3, 4, 50, 0));
        assert!(switch_admitted(2, 0, 3, 4, 50, 0));
        // Once the tail has advanced (root 2, head 5), the fork's replayed
        // blocks would drop released blocks: refused, even inside H.
        assert!(!switch_admitted(4, 2, 5, 4, 50, 0));
        // Only an ancestor at the head itself needs nothing below the root.
        assert!(switch_admitted(5, 2, 5, 4, 50, 0));
        // With a retained horizon (root 0 below a tail at 2): admitted down to
        // the bound, refused below it.
        assert!(switch_admitted(3, 0, 5, 4, 2, 0));
        assert!(!switch_admitted(2, 0, 5, 4, 2, 0));
        // The completeness horizon C.
        assert!(!switch_admitted(2, 0, 3, 4, 50, 3));
        assert!(switch_admitted(3, 0, 3, 4, 50, 3));
        // An ancestor below the root is never retained.
        assert!(!switch_admitted(1, 2, 3, 4, 50, 0));
    }
}
