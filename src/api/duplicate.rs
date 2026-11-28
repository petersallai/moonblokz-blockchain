//! The FR6 window duplicate check (I-22; Story 7.3, DEC-349) and the
//! transaction uniqueness keys it and FR14 intake share (DEC-354).
//!
//! A transfer or a balance-only complex transaction is guarded by nothing but
//! its key: an earlier inclusion lies above its highest anchor (Tier 1), hence
//! inside the parent's window (DEC-174), so an exact scan of the ancestry down
//! to that floor is complete. No state is kept: the cached payload type skips
//! the blocks that carry no transaction without a read, and each other block is
//! read once per applied block, whatever its transaction count. A registration
//! is guarded by key uniqueness, a UTXO-bearing transaction by the spent bit.

use super::*;

/// Whether `tx` is in DEC-354's balance-only form: a transfer, or a complex
/// transaction with at least one input, every input a balance input — the
/// transactions only the window duplicate check guards.
pub(super) fn is_balance_only(tx: &TransactionView<'_>) -> bool {
    if tx.as_node_transfer().is_some() {
        return true;
    }
    tx.as_complex().is_some_and(|cx| {
        cx.input_count() != 0 && cx.inputs().all(|input| input.as_balance().is_some())
    })
}

/// The lowest sequence a block including `tx` can have: one above its highest
/// anchor or UTXO reference (Tier 1: each lies strictly below the block).
pub(super) fn inclusion_floor(tx: &TransactionView<'_>) -> u32 {
    let highest = if let Some(nt) = tx.as_node_transfer() {
        nt.anchor_sequence()
    } else if let Some(reg) = tx.as_registration() {
        reg.anchor_sequence()
    } else if let Some(cx) = tx.as_complex() {
        cx.inputs()
            .map(|input| {
                input
                    .as_balance()
                    .map(|bi| bi.anchor_sequence())
                    .or_else(|| input.as_utxo().map(|ui| ui.block_sequence()))
                    .unwrap_or(0)
            })
            .max()
            .unwrap_or(0)
    } else {
        0
    };
    highest.saturating_add(1)
}

/// FR14's uniqueness-key equality (DEC-354): a transfer by `(initializer,
/// receiver, amount, anchor_sequence, comment)`; a registration by
/// `new_public_key`; a balance-only complex transaction by its ordered balance
/// inputs' `(initializer, anchor_sequence, amount, comment)` — outputs, `vote`
/// and signatures excluded, so a fee-bumped variant is a duplicate; any other
/// complex transaction (UTXO-bearing, or zero-input) by its exact bytes.
pub(super) fn same_key(a: &TransactionView<'_>, b: &TransactionView<'_>) -> bool {
    if let (Some(x), Some(y)) = (a.as_node_transfer(), b.as_node_transfer()) {
        return x.initializer() == y.initializer()
            && x.receiver() == y.receiver()
            && x.amount() == y.amount()
            && x.anchor_sequence() == y.anchor_sequence()
            && x.comment() == y.comment();
    }
    if let (Some(x), Some(y)) = (a.as_registration(), b.as_registration()) {
        return x.new_public_key() == y.new_public_key();
    }
    let (Some(x), Some(y)) = (a.as_complex(), b.as_complex()) else {
        return false;
    };
    if !(is_balance_only(a) && is_balance_only(b)) {
        return a.as_bytes() == b.as_bytes();
    }
    x.input_count() == y.input_count()
        && x.inputs()
            .zip(y.inputs())
            .all(|(p, q)| match (p.as_balance(), q.as_balance()) {
                (Some(p), Some(q)) => {
                    p.initializer() == q.initializer()
                        && p.anchor_sequence() == q.anchor_sequence()
                        && p.amount() == q.amount()
                        && p.comment() == q.comment()
                }
                _ => false,
            })
}

impl<
    Crypto: CryptoTrait,
    Storage: StorageTrait,
    Config: ChainConfigTrait,
    const MAX_NODES: usize,
    const SNAKE_CHAIN_LENGTH_MAX: u32,
    const MAX_BLOCKS: usize,
    const MAX_BRANCH_COUNT: usize,
    const AVAILABLE_UTXO_BYTES: usize,
>
    Blockchain<
        Crypto,
        Storage,
        Config,
        MAX_NODES,
        SNAKE_CHAIN_LENGTH_MAX,
        MAX_BLOCKS,
        MAX_BRANCH_COUNT,
        AVAILABLE_UTXO_BYTES,
    >
{
    /// The FR6 window duplicate check of a transaction block whose parent is
    /// `parent` (DEC-349): whether one of its balance-only transactions shares
    /// its key with another of the same block, or with a transaction of a
    /// block on its ancestry at or above the lowest inclusion floor among them
    /// and at or above `below` (a window-anchored pass's segment start; below
    /// it is trusted history, DEC-129). `Err` on a failed read: local, never
    /// evidence.
    pub(super) fn block_carries_duplicate(
        &self,
        view: &BlockView<'_>,
        parent: u32,
        below: u32,
    ) -> Result<bool, ()> {
        let Some(txs) = view.transactions() else {
            return Ok(false);
        };
        let mut floor = u32::MAX;
        for (i, tx) in txs.iter().enumerate() {
            if !is_balance_only(&tx) {
                continue;
            }
            floor = floor.min(inclusion_floor(&tx));
            if txs.iter().take(i).any(|earlier| same_key(&earlier, &tx)) {
                return Ok(true);
            }
        }
        if floor == u32::MAX {
            return Ok(false);
        }
        self.ancestry_carries(parent, floor.max(below), &mut |included| {
            txs.iter()
                .any(|tx| is_balance_only(&tx) && same_key(&tx, included))
        })
    }

    /// Whether a transaction block on the ancestry from `parent` down to
    /// sequence `floor` carries a transaction `matches` accepts (DEC-349): a
    /// RAM walk up `parent_ref`; a block whose cached payload type is not a
    /// transaction block costs no read, every other one read once into this
    /// frame's buffer (DEC-136). `Err` on a failed read or an inconsistent
    /// ancestry.
    #[inline(never)]
    pub(super) fn ancestry_carries(
        &self,
        parent: u32,
        floor: u32,
        matches: &mut dyn FnMut(&TransactionView<'_>) -> bool,
    ) -> Result<bool, ()> {
        let mut buf = [0u8; MAX_BLOCK_SIZE];
        let mut idx = parent;
        let mut steps = 0usize;
        while idx != NONE_REF {
            let entry = self.blocks.get(idx).ok_or(())?;
            if entry.sequence() < floor {
                break;
            }
            steps += 1;
            if steps > MAX_BLOCKS {
                return Err(());
            }
            if entry.payload_type() == PAYLOAD_TYPE_TRANSACTION {
                #[cfg(test)]
                crate::approval::test_seams::count(
                    &crate::approval::test_seams::DUPLICATE_SCAN_READS,
                );
                let view = self.view_retained(idx, &mut buf).ok_or(())?;
                if let Some(txs) = view.transactions()
                    && txs.iter().any(|tx| matches(&tx))
                {
                    return Ok(true);
                }
            }
            idx = entry.parent_ref();
        }
        Ok(false)
    }
}
