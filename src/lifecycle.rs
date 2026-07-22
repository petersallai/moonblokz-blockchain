//! `lifecycle.rs` — FR1–FR8, FR54, FR59.
//!
//! Owns the [`LifecyclePhase`] enum and the legal-transition rules for the
//! Collecting → Processing → Ready state machine. The 1-byte `lifecycle_phase`
//! field itself lives directly on `Blockchain` (architecture Decisions-log
//! row 12: a single field does not justify a separate state struct); this
//! module owns the *type* and the [`is_legal_transition`] predicate that the
//! guarded mutator `Blockchain::set_lifecycle_phase` enforces.
//!
//! Story 5.1 delivers the state machine, the init paths, and the
//! collecting-state not-ready gating. The dominant-chain acquisition (5.2),
//! processing-pass reconstruction (5.3), full-chain validation (5.4), atomic
//! recovery (5.5), chain-config commitment (5.6), and restart-equivalence
//! (5.7) drivers that *cause* the runtime transitions follow in later Epic-5
//! stories. See architecture §4.2.
//!
//! ## Not-ready gating contract (FR1)
//!
//! While the node is not [`LifecyclePhase::Ready`], every Ready-state-only behavior
//! returns a uniform not-ready indication, consulting the single
//! `Blockchain::is_ready()` gate. All follow one shape: read-only queries
//! return `Result<T, E>` with an `E::NotReady` arm (a `Result`, **not**
//! `Option`, so not-ready is distinct from a domain "absent" case — e.g.
//! `NotReady` ≠ `UnknownNode` ≠ zero balance); state-changing entry points
//! return `CallResult<Outcome>` with an `Outcome::NotReady` variant. Each
//! surface's *ready-state body* is built by its owning epic; Story 5.1 builds
//! only the gate. The gated surfaces + owning epic:
//! - transaction intake `receive_transaction` (FR14/FR10) — Epic 7;
//! - local transaction creation `submit_local_transaction` (FR55) — Epic 10;
//! - value/balance query `query_balance` + address-UTXO query (FR41) — Epic 10;
//! - block-retrieval `query_block_by_hash`/`query_block_by_sequence` (FR42) — Epic 10;
//! - transaction-state query (FR40), top-mempool-items exchange (FR43),
//!   creator-role determination (FR44) — Epic 10 / Epic 8: gated with the same
//!   `Result`/`NotReady` pattern by the owning epic, which also defines the
//!   method's ready-state return type (`TransactionState`, the mempool
//!   iterator, `CreatorRole`). Introducing those return types is part of the
//!   owning epic's body, so their gate lands with them.
//!
//! Not gated as public-method stubs: mempool replenishment (FR46) is gated
//! inside the Epic 8 scheduler (its deadline is simply not scheduled while
//! collecting), and support emission (FR12) inside Epic 6. Block intake
//! (FR9 Tier 1 / FR10 / FR16) and outbound parent-recovery (FR19) stay
//! **active** in collecting per FR1.

/// Authoritative-interpretation lifecycle phase (FR1–FR4).
///
/// - `Collecting`: empty chain or accumulating tree; Ready-state-only surfaces
///   return not-ready (FR1). Block intake + FR19 parent-recovery stay active.
/// - `Processing`: full-chain reconstruction in progress (FR3).
/// - `Ready`: validated active chain; full intake/query surface available
///   (FR4, FR9 fully active).
///
/// Represented as a bare 1-byte field on `Blockchain` (architecture
/// Decisions-log row 12). `PartialEq`/`Eq` back the gate checks and the
/// transition assertions; deliberately no `Copy`/`Clone` (binary-size
/// discipline — the value is matched/compared by reference, never duplicated),
/// `Debug` only under test.
#[cfg_attr(test, derive(Debug))]
#[derive(PartialEq, Eq)]
pub enum LifecyclePhase {
    Collecting,
    Processing,
    Ready,
}

/// Legal lifecycle transitions (FR1/FR4). The only runtime edges are
/// `Collecting → Processing` (FR2 stopping condition met, Story 5.2),
/// `Processing → Ready` (FR6 validation passed, FR4, Story 5.4), and
/// `Processing → Collecting` (FR5 atomic recovery, Story 5.5). There is **no**
/// direct `Collecting → Ready` edge, no `Ready → *` edge, and no self-loop.
///
/// Genesis (`Blockchain::process_genesis`) establishes the *initial* phase
/// `Ready` directly at bootstrap — that is initialization, not a runtime
/// transition, so it does not route through this predicate (architecture
/// §3.6). Join/restart pass through `Collecting`.
// Consumed by `Blockchain::set_lifecycle_phase`; both go live when the FR2/FR6/FR5
// runtime-transition drivers land (Stories 5.2/5.4/5.5). Declared-and-tagged-forward
// per the crate's discipline — allow dead_code until the first driver calls it.
#[allow(dead_code)]
pub(crate) fn is_legal_transition(from: &LifecyclePhase, to: &LifecyclePhase) -> bool {
    matches!(
        (from, to),
        (LifecyclePhase::Collecting, LifecyclePhase::Processing)
            | (LifecyclePhase::Processing, LifecyclePhase::Ready)
            | (LifecyclePhase::Processing, LifecyclePhase::Collecting)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legal_edges_accepted() {
        assert!(is_legal_transition(
            &LifecyclePhase::Collecting,
            &LifecyclePhase::Processing
        ));
        assert!(is_legal_transition(
            &LifecyclePhase::Processing,
            &LifecyclePhase::Ready
        ));
        assert!(is_legal_transition(
            &LifecyclePhase::Processing,
            &LifecyclePhase::Collecting
        ));
    }

    #[test]
    fn illegal_edges_rejected() {
        // No direct Collecting -> Ready edge (the whole point of FR1/FR4).
        assert!(!is_legal_transition(
            &LifecyclePhase::Collecting,
            &LifecyclePhase::Ready
        ));
        // Ready is terminal at runtime in Story 5.1 (chain-switch/recovery
        // that leave Ready arrive in later stories via their own edges).
        assert!(!is_legal_transition(
            &LifecyclePhase::Ready,
            &LifecyclePhase::Collecting
        ));
        assert!(!is_legal_transition(
            &LifecyclePhase::Ready,
            &LifecyclePhase::Processing
        ));
        // No self-loops.
        assert!(!is_legal_transition(
            &LifecyclePhase::Collecting,
            &LifecyclePhase::Collecting
        ));
        assert!(!is_legal_transition(
            &LifecyclePhase::Processing,
            &LifecyclePhase::Processing
        ));
        assert!(!is_legal_transition(
            &LifecyclePhase::Ready,
            &LifecyclePhase::Ready
        ));
    }
}
