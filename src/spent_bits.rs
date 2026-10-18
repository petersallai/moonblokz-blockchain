//! `spent_bits.rs` — ADR-016, FR3, FR6, FR34, FR51.
//!
//! Stateless helpers over the per-block `BlockEntry.spent_bits` bitfields
//! co-located in `BlockTable` (bit read/write live on `BlockEntry` /
//! `BlockTable`).
//!
//! **The ADR-016 reference model.** A UTXO input names the output it spends
//! as `(block_sequence, output_index)`. `block_sequence` selects the
//! referenced block, a strict ancestor of the consuming block; `output_index`
//! is the output's position in that block's **UTXO-output stream**: UTXO
//! outputs only, transaction by transaction in block order, output by output
//! within each transaction (PRD FR34). That position is also the output's
//! spent-bit index, so resolving an input needs no transaction hash: the
//! resolver walks the in-memory ancestry to the referenced block, checks the
//! bit, and reads that one block to fetch the output ([`utxo_output_at`]).
//!
//! The FR34 UTXO cache that would make the amount lookup O(1) without the
//! read is Story 7.1; the carry-forward driver is Story 9.5.

use moonblokz_chain_types::BlockView;

/// Returns the `output_index`-th output of `view`'s UTXO-output stream as
/// `(address, amount)`, or `None` when the block has fewer UTXO outputs (or
/// is not a transaction block).
pub(crate) fn utxo_output_at(view: &BlockView, output_index: u8) -> Option<([u8; 32], u64)> {
    view.transactions()?
        .iter()
        .filter_map(|tx| tx.as_complex())
        .flat_map(|cx| cx.outputs())
        .filter_map(|output| output.as_utxo())
        .nth(output_index as usize)
        .and_then(|utxo| Some((utxo.address().try_into().ok()?, utxo.amount())))
}
