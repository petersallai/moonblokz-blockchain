//! `chain_heads.rs` — FR19.
//!
//! Owns the `ChainHeadsTable { heads: [ChainHeadEntry; MAX_BRANCH_COUNT] }`
//! (~1.28 KB at the default `MAX_BRANCH_COUNT = 40`) — tip set tracking with
//! Stored / Connected / Active status, branch-value cache, parent-recovery
//! scheduling, and bounded eviction policy.
//!
//! Skeleton placeholder (Story 1.2). `ChainHeadEntry` layout and the
//! tip-tracking + parent-recovery + bounded-eviction logic arrive in Story 4.4.

#[allow(dead_code)]
pub(crate) struct ChainHeadsState;
