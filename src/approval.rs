//! `approval.rs` — FR12, FR15, FR27.
//!
//! Owns the `ApprovalAccumulator` (~2 KB, crypto-agnostic `MAX_BLOCK_SIZE`
//! buffer) used by the proposer side to gather support messages from the
//! deterministic ADR-015 subgroup, evaluate against `required_support`, and
//! emit approval-evidence blocks.
//!
//! Skeleton placeholder (Story 1.2). Subgroup selection + endorsement-
//! eligibility arrive in Story 6.4; proposer-side accumulation in Story 6.6.

#[allow(dead_code)]
pub(crate) struct ApprovalState;
