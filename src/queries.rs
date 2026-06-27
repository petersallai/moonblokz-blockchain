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

// stateless
