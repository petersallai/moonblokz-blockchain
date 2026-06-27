//! `scheduler.rs` — FR46.
//!
//! Owns the internal multi-deadline `SchedulerState` (~72 B per architecture
//! §4.2) — creator deadline, grace-period progression, replenishment, and
//! parent-recovery retry. Computes the minimum across all conditional
//! deadlines and surfaces it as the `NextCall::At(...)` returned with every
//! state-changing outcome (single-outcome scheduling-pull pattern).
//!
//! Skeleton placeholder (Story 1.2). Concrete `SchedulerState` and the AR4
//! `NextCall` computation arrive in Story 8.4.

#[allow(dead_code)]
pub(crate) struct SchedulerState;
