//! `approval.rs` — FR12, ADR-015: the supporter side of deviance approval.
//!
//! Story 6.4 builds what a node needs to decide, deterministically and from
//! chain state alone, whether it endorses a deviating block, and the message it
//! sends when it does: the outbound [`SupportMessage`]. The proposer-side
//! accumulation and the evidence block are Story 6.6's.

use moonblokz_chain_types::HASH_SIZE;
use moonblokz_crypto::MULTI_SIGNATURE_SIZE;

/// FR12 — the support message a node returns, through
/// [`crate::ReceiveBlockOutcome::AcceptedAndSendSupport`], when it endorses a
/// deviating block (D4, owned).
///
/// The bridge frames it into the radio `Support` message (DEC-187): the radio
/// header's sequence and supporter fields carry `deviation_sequence` and
/// `supporter_node_id`. The signature is over the 45-byte content of
/// [`support_message_bytes`], made with the local node's multi-signature key.
///
/// `support_signature` holds the backend's serialized multi-signature bytes,
/// never the backend value itself, which is larger in memory and
/// backend-specific. Owned rather than borrowed: about 108 bytes carried on
/// the stack only along `receive_block`'s return, instead of a static scratch
/// buffer and a lifetime on the outcome.
// Same derive discipline as the outcome enums: no `Copy`/`Clone` in production;
// `Debug` only under test.
#[cfg_attr(test, derive(Debug))]
#[derive(PartialEq, Eq)]
pub struct SupportMessage {
    /// The endorsing (local) node.
    pub supporter_node_id: u32,
    /// The deviating block's creator, to whom the support is addressed.
    pub proposer_node_id: u32,
    /// The deviating block's sequence `p`.
    pub deviation_sequence: u32,
    /// The deviating block's hash.
    pub deviation_block_hash: [u8; HASH_SIZE],
    /// `MultiSignatureTrait::serialize()` of the local node's signature over
    /// [`support_message_bytes`].
    pub support_signature: [u8; MULTI_SIGNATURE_SIZE],
}
