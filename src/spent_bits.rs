//! `spent_bits.rs` — ADR-016, FR3, FR51, FR6.
//!
//! Stateless helpers over the per-block `BlockEntry.spent_bits` bitfields
//! co-located in `BlockTable` (bit read/write live on `BlockEntry` /
//! `BlockTable`). Story 5.4 adds the FR6 UTXO-input **reference resolution**
//! the double-spend check needs: mapping a wire `(tr_hash, output_index)`
//! reference to a position in a candidate block's UTXO-output stream (the
//! ADR-016 spent-bit index).
//!
//! **Reference-model divergence (flagged, `deferred-work.md`).** The wire
//! references a consumed output by the *referenced transaction's* hash
//! (`UtxoInputView::tr_hash`) plus `output_index`, whereas the PRD / ADR-016
//! spent-bit model addresses `(block_sequence, output_index)` into a per-block
//! bit vector. There is no tx-hash → block index in the crate, so
//! [`resolve_utxo_bit`] hashes candidate transactions to locate the containing
//! block and computes the block-level bit position by flattening that block's
//! UTXO outputs in order. `output_index` is interpreted as the index into the
//! *referenced transaction's* UTXO outputs; the returned bit is that output's
//! position in the whole block's UTXO-output stream.
//!
//! The FR34 block-navigation / UTXO cache that would make this O(1) instead of
//! a per-input transaction re-hash is Story 7.1; carry-forward driver is Story
//! 9.5.

use moonblokz_chain_types::BlockView;

/// Resolves a UTXO input reference `(tr_hash, output_index)` against a single
/// candidate block `view`: if the block contains a complex transaction whose
/// canonical hash equals `tr_hash`, returns the referenced output's position in
/// this block's flattened UTXO-output stream (the ADR-016 spent-bit index).
///
/// Returns `None` when the block holds no matching transaction, or when
/// `output_index` is out of bounds of the matched transaction's UTXO outputs.
/// A non-transaction block (`transactions()` is `None`) never matches.
pub(crate) fn resolve_utxo_bit(
    view: &BlockView,
    tr_hash: &[u8],
    output_index: u8,
) -> Option<usize> {
    let txs = view.transactions()?;
    // `base` = number of UTXO outputs contributed by complex transactions that
    // precede the current one in this block (their share of the block's
    // flattened UTXO-output stream).
    let mut base = 0usize;
    for tx in txs.iter() {
        let Some(cx) = tx.as_complex() else {
            continue;
        };
        let utxo_output_count = cx.outputs().filter(|o| o.as_utxo().is_some()).count();
        if &tx.hash()[..] == tr_hash {
            let oi = output_index as usize;
            return (oi < utxo_output_count).then_some(base + oi);
        }
        base += utxo_output_count;
    }
    None
}
