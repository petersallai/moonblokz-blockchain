//! `staged_validation.rs` — FR9 three-tier check categorization.
//!
//! Stateless Tier 1 (intake-time gating), Tier 2 (Connected promotion,
//! ancestry-and-lookup-based), and Tier 3 (Active promotion, derived-state-
//! replay-based) check functions. Operates against `BlockTable`,
//! `NodeInfo` SoA arrays, and the signature-verification cache.
//!
//! Skeleton placeholder (Story 1.2). Tier 1 gating arrives in Story 4.2;
//! Tier 2 promotion drivers in Story 6.x; Tier 3 in Story 5.4 + Story 7.x.

// stateless
