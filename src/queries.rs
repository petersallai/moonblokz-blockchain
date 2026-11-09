//! `queries.rs` — FR40–FR43.
//!
//! Stateless read-only surface behind `Blockchain::serve_*` and `query_*`.
//! Resolves transaction-state, value-state (balance + UTXO), block-retrieval,
//! and top-mempool-items queries against the current active chain and
//! mempool, with ready-state gating per FR1/FR42.
//!
//! Skeleton placeholder (Story 1.2). Read-only contract + transaction-state
//! query arrive in Story 10.1; value-state in 10.2; block-retrieval in 10.3;
//! top-mempool-items in 10.4.
//!
//! "The active chain" is the window `[S_tail, S_head]`: below the tail lie the
//! FR58 verification horizon's blocks, which keep `is_on_active_chain` (Story
//! 6.14, DEC-206) but are not part of the active chain — test sequences, not
//! the flag.

// stateless
