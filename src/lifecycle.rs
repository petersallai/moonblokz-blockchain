//! `lifecycle.rs` — FR1–FR8, FR54, FR59.
//!
//! Owns the `lifecycle_phase: LifecyclePhase` field on `Blockchain` and the
//! Collecting → Processing → Ready transition orchestration.
//!
//! Skeleton placeholder (Story 1.2). Concrete state machine arrives in
//! Story 5.1 (state machine, init paths, collecting-state not-ready gating);
//! the dominant-chain acquisition, processing-pass, validation, recovery,
//! chain-config commitment, and restart-equivalence pieces follow in
//! Stories 5.2–5.7. See architecture §4.2.

#[allow(dead_code)]
pub(crate) struct LifecycleState;
