//! `available_utxo.rs` — ADR-016, FR3, FR6, FR34, FR51.
//!
//! Stateless helpers over the per-block `BlockEntry.available_utxo` bitfields
//! co-located in `BlockTable` (bit read/write live on `BlockEntry` /
//! `BlockTable`).
//!
//! **The bit meaning (DEC-132).** Bit *i* of a block's bitfield is 1 exactly
//! when the block's *i*-th UTXO output exists and is unspent on the current
//! derived chain; it is 0 when that output is spent, when the block has no
//! such output, and on every block outside the derived chain. The FR6 pass
//! sets an output's bit when it derives the block and clears it on the spend.
//! Because a set bit implies the output exists, the resolver rejects a missing
//! or spent output from RAM, and the FR51 tail-drop obligation is "any bit
//! set" — neither needs a storage read.
//!
//! **The ADR-016 reference model.** A UTXO input names the output it spends
//! as `(block_sequence, output_index)`. `block_sequence` selects the
//! referenced block, a strict ancestor of the consuming block; `output_index`
//! is the output's position in that block's **UTXO-output stream**: UTXO
//! outputs only, transaction by transaction in block order, output by output
//! within each transaction (PRD FR34). That position is also the output's bit
//! index, so resolving an input needs no transaction hash: the resolver walks
//! the in-memory ancestry to the referenced block, checks the bit, and reads
//! that one block for the output's amount and address ([`utxo_output_at`]).
//!
//! The FR34 UTXO cache that would make the amount lookup O(1) without the
//! read is Story 7.1; the carry-forward driver is Story 9.5.

use moonblokz_chain_types::BlockView;
use moonblokz_crypto::PUBLIC_KEY_SIZE;

/// Returns the `output_index`-th output of `view`'s UTXO-output stream as
/// `(address, amount)`, or `None` when the block has fewer UTXO outputs (or
/// is not a transaction block).
pub(crate) fn utxo_output_at(
    view: &BlockView,
    output_index: u16,
) -> Option<([u8; PUBLIC_KEY_SIZE], u64)> {
    view.transactions()?
        .iter()
        .filter_map(|tx| tx.as_complex())
        .flat_map(|cx| cx.outputs())
        .filter_map(|output| output.as_utxo())
        .nth(output_index as usize)
        .and_then(|utxo| Some((utxo.address().try_into().ok()?, utxo.amount())))
}

/// DEC-330: whether a block still holds an unspent UTXO output whose amount
/// exceeds the custodian `fee` — the only case in which FR51 owes a
/// carry-forward when the block drops, since an output at most the fee is
/// discarded (DEC-196(d)). `available(i)` is the block's available-UTXO bit
/// `i`; the amounts come from the block's bytes.
pub(crate) fn carries_output_above(
    view: &BlockView,
    available: impl Fn(usize) -> bool,
    fee: u64,
) -> bool {
    view.transactions().is_some_and(|txs| {
        txs.iter()
            .filter_map(|tx| tx.as_complex())
            .flat_map(|cx| cx.outputs())
            .filter_map(|output| output.as_utxo())
            .enumerate()
            .any(|(i, utxo)| available(i) && utxo.amount() > fee)
    })
}
