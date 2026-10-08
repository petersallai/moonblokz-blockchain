//! `reconciliation.rs` — FR23, FR58.
//!
//! Stateless backward/forward walk that executes the reversible chain-switch
//! reconciliation workflow over the candidate branch, with cheap-zone in-place
//! handling and deep-zone full-reconstruction dispatch per the verification
//! horizon `H`.
//!
//! `H` is node-level and implementation-defined (FR58), derived from the
//! chain-configured window `W` — default `⌊W / 10⌋`, always `0 ≤ H ≤ W` — not
//! from the build's capacity, so it is not a const generic. Story 9.7 derives
//! it at its point of use.
//!
//! Skeleton placeholder (Story 1.2). The reversible workflow arrives in
//! Story 6.3; the cheap/deep-zone dispatch in Story 9.7.

// stateless
