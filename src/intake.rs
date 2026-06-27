//! `intake.rs` — FR10 / FR14 / FR16 / FR26.
//!
//! Stateless dispatcher behind `Blockchain::receive_block` /
//! `receive_transaction` / `receive_support` / `submit_local_transaction`.
//! Maps the FR9 staged-validation outcomes to the single-outcome
//! `ReceiveBlockOutcome` / `ReceiveTransactionOutcome` / `ReceiveSupportOutcome`
//! enums (single-outcome scheduling-pull pattern).
//!
//! Skeleton placeholder (Story 1.2). The deterministic classification surface
//! arrives in Story 4.3 (block intake), Story 7.3 (transaction intake), and
//! Story 6.5 (support intake).

// stateless
