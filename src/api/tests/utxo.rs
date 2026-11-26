//! Tests of the ADR-016 UTXO input checks in `api/step.rs` (Story 6.8).

use super::*;

// --- Story 6.8: ADR-016 sequence-indexed UTXO input -----------------------

/// Block 101: node 1 moves its whole balance into two UTXO outputs, 60
/// (index 0) and 40 (index 1).
fn utxo_mint_block(prev: [u8; 32]) -> Block {
    let tx = utxo_tx(101, &[], Some((1, 100)), &[Ok(60), Ok(40)]);
    complex_tx_block(101, prev, 3, 0, &[&tx])
}

/// AC8 (1) / Story 6.11 AC6.1 — deriving the mint sets one bit per UTXO
/// output; the spend clears the input's bit (and only it), and the
/// referenced amount reaches the balance output.
#[test]
fn utxo_spend_clears_the_bit_and_credits_the_amount() {
    let (mut bc, h100) = utxo_test_chain();
    let mint = utxo_mint_block(h100);
    let mi = admit(&mut bc, &mint);
    let tx = utxo_tx(102, &[(101, 1, 40)], None, &[Err((2, 40))]);
    let spend = complex_tx_block(102, mint.view().hash(), 3, 0, &[&tx]);
    let si = admit(&mut bc, &spend);

    bc.run_processing_pass(si).expect("pass succeeds");

    assert_eq!(bc.blocks.utxo_available(mi, 1), Some(false), "spent output");
    assert_eq!(
        bc.blocks.utxo_available(mi, 0),
        Some(true),
        "untouched output"
    );
    assert_eq!(
        bc.blocks.utxo_available(mi, 2),
        Some(false),
        "no third output"
    );
    assert_eq!(bc.node_info.balance_of(1), 0, "minted everything");
    assert_eq!(bc.node_info.balance_of(2), 40, "the UTXO's amount");
    assert_eq!(bc.node_info.balance_of(3), 0, "no fee, nothing mined");
}

/// AC8 (2) — a second spend of the same output, in a later block, is
/// `UtxoUnavailable` against that later block; the abort rolls every bit
/// back to "nothing derived".
#[test]
fn utxo_double_spend_across_blocks_is_unavailable() {
    let (mut bc, h100) = utxo_test_chain();
    let mint = utxo_mint_block(h100);
    let mi = admit(&mut bc, &mint);
    let tx = utxo_tx(102, &[(101, 0, 60)], None, &[Err((2, 60))]);
    let first = complex_tx_block(102, mint.view().hash(), 3, 0, &[&tx]);
    admit(&mut bc, &first);
    let tx = utxo_tx(103, &[(101, 0, 60)], None, &[Err((2, 60))]);
    let second = complex_tx_block(103, first.view().hash(), 3, 0, &[&tx]);
    let di = admit(&mut bc, &second);

    assert_eq!(
        bc.run_processing_pass(di),
        Err(ProcessingError::Invalid {
            block_idx: di,
            reason: ValidationReason::UtxoUnavailable,
        })
    );
    assert_eq!(bc.blocks.utxo_available(mi, 0), Some(false), "rolled back");
    assert_eq!(bc.blocks.utxo_available(mi, 1), Some(false), "rolled back");
}

/// Runs the pass over `mint ← spend(inputs)` and returns its verdict and
/// the spending block's slot.
fn spend_verdict(inputs: &[(u32, u16, u64)]) -> (Result<(), ProcessingError>, u32) {
    let (mut bc, h100) = utxo_test_chain();
    let mint = utxo_mint_block(h100);
    admit(&mut bc, &mint);
    // One 0-amount output: a complex transaction needs one (DEC-308).
    let tx = utxo_tx(102, inputs, None, &[Err((2, 0))]);
    let spend = complex_tx_block(102, mint.view().hash(), 3, 0, &[&tx]);
    let si = admit(&mut bc, &spend);
    (bc.run_processing_pass(si).map(|_| ()), si)
}

/// AC8 (3) / DEC-129 — on a window-anchored candidate a reference below
/// the anchor (99) is trusted pre-window history when it is at most `W`
/// (16) blocks back: no bit, and the declared amounts are trusted, so the
/// fee is still known (DEC-131).
#[test]
fn utxo_reference_below_a_window_anchor_is_trusted_within_w() {
    let (mut bc, h100) = utxo_test_chain();
    let mint = utxo_mint_block(h100);
    admit(&mut bc, &mint);
    let tx = utxo_tx(102, &[(98, 0, 50), (86, 3, 30)], None, &[Err((2, 70))]);
    let spend = complex_tx_block(102, mint.view().hash(), 3, 0, &[&tx]);
    let si = admit(&mut bc, &spend);

    bc.run_processing_pass(si).expect("pass succeeds");

    assert_eq!(bc.node_info.balance_of(2), 70, "the output is credited");
    assert_eq!(
        bc.node_info.balance_of(3),
        10,
        "fee 80 - 70 from the declared amounts"
    );
}

/// AC8 (3) / DEC-129 — a reference more than `W` blocks back is
/// `UtxoUnresolvable`, below the anchor or not.
#[test]
fn utxo_reference_beyond_w_is_unresolvable() {
    for referenced in [85, 50, 0] {
        let (verdict, si) = spend_verdict(&[(referenced, 0, 0)]);
        assert_eq!(
            verdict,
            Err(ProcessingError::Invalid {
                block_idx: si,
                reason: ValidationReason::UtxoUnresolvable,
            }),
            "block_sequence {referenced}"
        );
    }
}

/// DEC-129 boundary on a `W = 6` chain: exactly `W` back is trusted, one
/// more is not. #101 is a clean slot (Story 6.7 D8), so the spend sits at
/// #102 above a [`w6_clean_block`].
#[test]
fn utxo_distance_bound_is_exactly_w() {
    fn verdict(referenced: u32) -> (Result<(), ProcessingError>, u32) {
        let mut bc = new_w6_chain();
        let cfg = w6_config_anchor_block(99, [0xAB; 32]);
        bc.tier1_admit(&cfg.view(), &cfg.view().hash(), 0)
            .expect("config admitted");
        let seed = balance_block(100, cfg.view().hash(), &[(2, 0, 0, 0x32)], 3);
        bc.tier1_admit(&seed.view(), &seed.view().hash(), 0)
            .expect("seed admitted");
        let clean = w6_clean_block(101, seed.view().hash());
        bc.tier1_admit(&clean.view(), &clean.view().hash(), 0)
            .expect("clean slot admitted");
        let tx = utxo_tx(102, &[(referenced, 0, 5)], None, &[Err((2, 5))]);
        let spend = complex_tx_block(102, clean.view().hash(), 3, 0, &[&tx]);
        let si = bc
            .tier1_admit(&spend.view(), &spend.view().hash(), 0)
            .expect("spend admitted");
        (bc.run_processing_pass(si).map(|_| ()), si)
    }
    assert_eq!(verdict(96).0, Ok(()), "102 - 96 = W");
    let (result, si) = verdict(95);
    assert_eq!(
        result,
        Err(ProcessingError::Invalid {
            block_idx: si,
            reason: ValidationReason::UtxoUnresolvable,
        }),
        "102 - 95 > W"
    );
}

/// AC3 — without trust (a genesis-anchored candidate, or Ready, where
/// `NONE_REF` is the released tail) a reference below the anchor is
/// `UtxoUnresolvable`, even within `W`.
#[test]
fn utxo_reference_below_the_anchor_is_unresolvable_without_trust() {
    let (mut bc, h100) = utxo_test_chain();
    let mint = utxo_mint_block(h100);
    let mi = admit(&mut bc, &mint);
    assert!(matches!(
        bc.resolve_and_spend_utxo(mi, 102, 98, 0, 0, false),
        Err(UtxoSpendError::Invalid(ValidationReason::UtxoUnresolvable))
    ));
    assert!(matches!(
        bc.resolve_and_spend_utxo(mi, 102, 98, 0, 0, true),
        Ok(None)
    ));
}

/// AC8 (5) / Story 6.11 AC3 — an `output_index` past the referenced
/// block's UTXO outputs (or into a block with none) has no available bit:
/// exact evidence, decided from RAM. Story 6.15: the index is a `u16`, and an
/// index at or past the bitfield's width (`AVAILABLE_UTXO_BYTES · 8`, DEC-318)
/// is unavailable too; 256 never aliases output 0, as a truncation to `u8`
/// would make it.
#[test]
fn utxo_out_of_bounds_index_is_unavailable() {
    for (referenced, index) in [
        (101, 2),
        (101, TEST_UTXO_BYTES as u16 * 8),
        (101, 255),
        (101, 256),
        (101, u16::MAX),
        (100, 0),
        (99, 0),
    ] {
        let (verdict, si) = spend_verdict(&[(referenced, index, 0)]);
        assert_eq!(
            verdict,
            Err(ProcessingError::Invalid {
                block_idx: si,
                reason: ValidationReason::UtxoUnavailable,
            }),
            "({referenced}, {index})"
        );
    }
}

/// AC8 (4) — ADR-016 trade-off (FR39): an output at the same
/// `(sequence, index)` on a side branch is never found. The resolver only
/// visits the consuming block's ancestors, whose block 101 has no output
/// and so no available bit; the side branch was never derived.
#[test]
fn utxo_output_on_a_side_branch_is_not_resolvable() {
    let (mut bc, h100) = utxo_test_chain();
    let side = utxo_mint_block(h100);
    let side_idx = admit(&mut bc, &side);
    // The active ancestry's block 101 carries no UTXO output.
    let own = transfer_block(101, h100, 2, 3, 0, 0, 0);
    admit(&mut bc, &own);
    let tx = utxo_tx(102, &[(101, 0, 60)], None, &[Err((2, 60))]);
    let spend = complex_tx_block(102, own.view().hash(), 3, 0, &[&tx]);
    let si = admit(&mut bc, &spend);

    assert_eq!(
        bc.run_processing_pass(si),
        Err(ProcessingError::Invalid {
            block_idx: si,
            reason: ValidationReason::UtxoUnavailable,
        })
    );
    assert_eq!(
        bc.blocks.has_available_utxo(side_idx),
        Some(false),
        "a side branch is never derived: its whole bitfield stays 0"
    );
}

/// AC8 (7) / AC5 — Tier 1 rejects a UTXO input whose `block_sequence` is
/// not below the block's own, and the block is not stored (FR16).
#[test]
fn utxo_input_not_before_block_is_rejected_at_intake() {
    let (mut bc, h100) = utxo_test_chain();
    let stored = bc.blocks.len();
    for referenced in [101, 102] {
        let tx = utxo_tx(101, &[(referenced, 0, 1)], None, &[Err((2, 1))]);
        let block = complex_tx_block(101, h100, 3, 0, &[&tx]);
        assert_eq!(
            bc.tier1_admit(&block.view(), &block.view().hash(), 0),
            Err(AdmitError::Rejected(Tier1Failure::UtxoInputNotBeforeBlock))
        );
    }
    assert_eq!(bc.blocks.len(), stored, "nothing stored");
}

/// AC8 (8) / AC6 — the fee counts UTXO outputs: a balance input of 100
/// paid entirely into a UTXO output leaves no surplus, so the creator gets
/// its mined amount and nothing more (it used to get another 100).
#[test]
fn utxo_output_is_not_paid_out_as_fee() {
    let (mut bc, h100) = utxo_test_chain();
    let tx = utxo_tx(101, &[], Some((1, 100)), &[Ok(100)]);
    let block = complex_tx_block(101, h100, 3, 7, &[&tx]);
    let bi = admit(&mut bc, &block);

    bc.run_processing_pass(bi).expect("pass succeeds");

    assert_eq!(bc.node_info.balance_of(3), 7, "mined 7, fee 0");
    assert_eq!(bc.node_info.balance_of(1), 0);
}

/// AC8 (9) / D1 — the UTXO amount is an input: 50 (UTXO) + 10 (balance)
/// against 55 of outputs pays a fee of 5. Outputs above the declared
/// inputs never reach the pass: Tier 1 rejects them (DEC-131).
#[test]
fn utxo_amount_counts_as_input() {
    let (mut bc, h100) = utxo_test_chain();
    let tx = utxo_tx(101, &[], Some((1, 50)), &[Ok(50)]);
    let mint = complex_tx_block(101, h100, 3, 0, &[&tx]);
    admit(&mut bc, &mint);
    let over = utxo_tx(102, &[(101, 0, 50)], Some((1, 10)), &[Err((2, 61))]);
    let over = complex_tx_block(102, mint.view().hash(), 3, 0, &[&over]);
    assert_eq!(
        bc.tier1_admit(&over.view(), &over.view().hash(), 0),
        Err(AdmitError::Rejected(Tier1Failure::InputsLessThanOutputs))
    );
    let tx = utxo_tx(102, &[(101, 0, 50)], Some((1, 10)), &[Err((2, 55))]);
    let spend = complex_tx_block(102, mint.view().hash(), 3, 0, &[&tx]);
    let si = admit(&mut bc, &spend);

    bc.run_processing_pass(si).expect("pass succeeds");

    assert_eq!(bc.node_info.balance_of(3), 5, "fee = 60 - 55");
    assert_eq!(bc.node_info.balance_of(2), 55);
    assert_eq!(bc.node_info.balance_of(1), 40, "100 - 50 - 10");
}

/// DEC-131 — a declared amount that is not the referenced output's is
/// `UtxoAmountMismatch`; the abort leaves nothing derived.
#[test]
fn utxo_declared_amount_mismatch_is_invalid() {
    for declared in [39, 41] {
        let (mut bc, h100) = utxo_test_chain();
        let mint = utxo_mint_block(h100);
        let mi = admit(&mut bc, &mint);
        let tx = utxo_tx(102, &[(101, 1, declared)], None, &[Err((2, declared))]);
        let spend = complex_tx_block(102, mint.view().hash(), 3, 0, &[&tx]);
        let si = admit(&mut bc, &spend);
        assert_eq!(
            bc.run_processing_pass(si),
            Err(ProcessingError::Invalid {
                block_idx: si,
                reason: ValidationReason::UtxoAmountMismatch,
            }),
            "declared {declared}, output 40"
        );
        assert_eq!(bc.blocks.utxo_available(mi, 1), Some(false));
    }
}

/// AC8 (10) / AC2 — `output_index` counts the block's UTXO-output stream
/// across transactions, skipping balance outputs: the second
/// transaction's only UTXO output is index 2, not 0.
#[test]
fn utxo_output_index_spans_the_whole_block() {
    let (mut bc, h100) = utxo_test_chain();
    let first = utxo_tx(101, &[], Some((1, 60)), &[Ok(10), Err((2, 5)), Ok(45)]);
    let second = utxo_tx(101, &[], Some((1, 30)), &[Ok(30)]);
    let mint = complex_tx_block(101, h100, 3, 0, &[&first, &second]);
    let mi = admit(&mut bc, &mint);
    let tx = utxo_tx(102, &[(101, 2, 30)], None, &[Err((2, 30))]);
    let spend = complex_tx_block(102, mint.view().hash(), 3, 0, &[&tx]);
    let si = admit(&mut bc, &spend);

    bc.run_processing_pass(si).expect("pass succeeds");

    assert_eq!(bc.blocks.utxo_available(mi, 2), Some(false), "spent");
    assert_eq!(bc.blocks.utxo_available(mi, 0), Some(true));
    assert_eq!(bc.blocks.utxo_available(mi, 1), Some(true), "the 45 output");
    assert_eq!(
        bc.blocks.utxo_available(mi, 3),
        Some(false),
        "no fourth output"
    );
    assert_eq!(bc.node_info.balance_of(2), 5 + 30, "the 30 output");
    assert_eq!(bc.node_info.balance_of(3), 0, "no fee anywhere");
}

/// AC8 (2) — the same output named twice in one transaction, or by two
/// transactions of one block, is spent once: the second is
/// `UtxoUnavailable`.
#[test]
fn utxo_double_spend_within_one_block_is_unavailable() {
    let same_tx = utxo_tx(102, &[(101, 0, 60), (101, 0, 60)], None, &[Err((2, 60))]);
    let first = utxo_tx(102, &[(101, 0, 60)], None, &[Err((2, 60))]);
    let second = utxo_tx(102, &[(101, 0, 60)], None, &[Err((2, 60))]);
    for txs in [&[&same_tx][..], &[&first, &second][..]] {
        let (mut bc, h100) = utxo_test_chain();
        let mint = utxo_mint_block(h100);
        admit(&mut bc, &mint);
        let spend = complex_tx_block(102, mint.view().hash(), 3, 0, txs);
        let si = admit(&mut bc, &spend);
        assert_eq!(
            bc.run_processing_pass(si),
            Err(ProcessingError::Invalid {
                block_idx: si,
                reason: ValidationReason::UtxoUnavailable,
            }),
            "{} transaction(s)",
            txs.len()
        );
    }
}

/// AC6 — an input sum beyond `u64` is rejected at Tier 1 (DEC-011,
/// DEC-131); the block's fee total, summed across transactions, is checked
/// in the pass: `ValueOverflow`, never a clamped credit.
#[test]
fn utxo_value_overflow_is_invalid() {
    const HALF: u64 = 1 << 63;
    let (mut bc, h100) = utxo_test_chain();
    // Two zero-input carry-forwards, each a UTXO output of 2^63.
    let a = utxo_tx(101, &[], None, &[Ok(HALF)]);
    let b = utxo_tx(101, &[], None, &[Ok(HALF)]);
    let mint = complex_tx_block(101, h100, 3, 0, &[&a, &b]);
    admit(&mut bc, &mint);

    let both = utxo_tx(102, &[(101, 0, HALF), (101, 1, HALF)], None, &[]);
    let both = complex_tx_block(102, mint.view().hash(), 3, 0, &[&both]);
    assert_eq!(
        bc.tier1_admit(&both.view(), &both.view().hash(), 0),
        Err(AdmitError::Rejected(Tier1Failure::AmountOverflow))
    );

    // Each needs an output (DEC-308); a 0-amount one keeps the whole input
    // as the fee, so the two fees still overflow.
    let first = utxo_tx(102, &[(101, 0, HALF)], None, &[Err((2, 0))]);
    let second = utxo_tx(102, &[(101, 1, HALF)], None, &[Err((2, 0))]);
    let spend = complex_tx_block(102, mint.view().hash(), 3, 0, &[&first, &second]);
    let si = admit(&mut bc, &spend);
    assert_eq!(
        bc.run_processing_pass(si),
        Err(ProcessingError::Invalid {
            block_idx: si,
            reason: ValidationReason::ValueOverflow,
        })
    );
}

type FailingReadChain =
    Blockchain<Crypto, FailingReadStorage, TestConfig, 16, 16, TEST_MAX_BLOCKS, 4, TEST_UTXO_BYTES>;

/// The UTXO harness on a [`FailingReadChain`] whose reads all succeed
/// until a test arms `failing_slot`: chain-config anchor 99, balance block
/// 100, and the [`utxo_mint_block`] at 101. Returns the node, the mint and
/// its slot.
fn failing_read_utxo_chain() -> (FailingReadChain, Block, u32) {
    let crypto = Crypto::new([1u8; PRIVATE_KEY_SIZE]).ok().expect("key");
    let chain_config = locked_chain_config(&crypto, FailingReadChain::BUILD_LIMITS);
    let node_zero = *crypto.public_key().serialize();
    let storage = FailingReadStorage {
        inner: initialized_storage([1u8; PRIVATE_KEY_SIZE]),
        failing_slot: NONE_REF,
        reads_left: core::cell::Cell::new(0),
        failures_left: core::cell::Cell::new(u32::MAX),
        attempts: core::cell::Cell::new(0),
        reads: core::cell::Cell::new(0),
    };
    let mut slot = core::mem::MaybeUninit::<FailingReadChain>::uninit();
    FailingReadChain::init(&mut slot, crypto, storage, chain_config, 5, node_zero, 0);
    // SAFETY: `init` returned, so every field of `slot` is initialized.
    let mut bc = unsafe { slot.assume_init() };

    let cfg = chain_config_anchor_block(99, [0xAB; 32]);
    failing_read_admit(&mut bc, &cfg);
    let seed = balance_block(
        100,
        cfg.view().hash(),
        &[(1, 100, 0, 0x31), (2, 0, 0, 0x32), (3, 0, 0, 0x33)],
        3,
    );
    failing_read_admit(&mut bc, &seed);
    let mint = utxo_mint_block(seed.view().hash());
    let mi = failing_read_admit(&mut bc, &mint);
    (bc, mint, mi)
}

fn failing_read_admit(bc: &mut FailingReadChain, block: &Block) -> u32 {
    bc.tier1_admit(&block.view(), &block.view().hash(), 0)
        .expect("block admitted")
}

/// AC8 (6) / AC3 step 5 — a failed read of the referenced block is a local
/// fault: the pass reports `StorageRead`, never `Invalid`, so nothing is
/// charged against the spending block. (The FR5 driver's head fallback for
/// `StorageRead` is unchanged here; DEC-037 is Story 6.0.)
#[test]
fn utxo_read_failure_is_reported_as_storage_read() {
    let (mut bc, mint, mi) = failing_read_utxo_chain();
    let tx = utxo_tx(102, &[(101, 1, 40)], None, &[Err((2, 40))]);
    let spend = complex_tx_block(102, mint.view().hash(), 3, 0, &[&tx]);
    let si = failing_read_admit(&mut bc, &spend);

    bc.storage.failing_slot = mi;
    bc.storage.reads_left.set(1);
    let stored = bc.blocks.len();

    assert_eq!(
        bc.run_processing_pass(si),
        Err(ProcessingError::StorageRead)
    );
    assert_eq!(
        bc.storage.attempts.get(),
        2,
        "the segment walk read the block, then the resolver's read failed"
    );
    assert_eq!(bc.blocks.len(), stored, "the pass itself deletes nothing");
}

/// Story 6.11 AC3 / AC6.3 — an output whose bit is 0 is rejected before the
/// resolver reads the referenced block: past the block's outputs (no read
/// at all beyond the segment walk's), or already spent by an earlier block
/// (only that earlier spend reads).
#[test]
fn utxo_unavailable_output_is_rejected_without_a_read() {
    // (spending blocks' inputs, resolver reads expected on the mint)
    let past_the_outputs: &[&[(u32, u16, u64)]] = &[&[(101, 2, 0)]];
    let spent_earlier: &[&[(u32, u16, u64)]] = &[&[(101, 0, 60)], &[(101, 0, 60)]];
    for (spends, resolver_reads) in [(past_the_outputs, 0), (spent_earlier, 1)] {
        let (mut bc, mint, mi) = failing_read_utxo_chain();
        let mut prev = mint.view().hash();
        let mut tip = mi;
        for (k, inputs) in spends.iter().enumerate() {
            let seq = 102 + k as u32;
            let amount = inputs[0].2;
            let tx = utxo_tx(seq, inputs, None, &[Err((2, amount))]);
            let block = complex_tx_block(seq, prev, 3, 0, &[&tx]);
            prev = block.view().hash();
            tip = failing_read_admit(&mut bc, &block);
        }
        bc.storage.failing_slot = mi;
        bc.storage.reads_left.set(u32::MAX);

        assert_eq!(
            bc.run_processing_pass(tip),
            Err(ProcessingError::Invalid {
                block_idx: tip,
                reason: ValidationReason::UtxoUnavailable,
            })
        );
        assert_eq!(
            bc.storage.attempts.get(),
            1 + resolver_reads,
            "the segment walk's read, plus {resolver_reads} by the resolver"
        );
    }
}

/// Story 6.11 AC3 / D2 — a set bit whose output the stored bytes do not
/// hold means storage and RAM disagree: a local fault, never evidence
/// against the spending block.
#[test]
fn utxo_bit_without_its_output_is_a_local_fault() {
    let (mut bc, h100) = utxo_test_chain();
    let mint = utxo_mint_block(h100);
    let mi = admit(&mut bc, &mint);
    bc.run_processing_pass(mi).expect("the mint derives");
    assert_eq!(bc.blocks.utxo_available(mi, 2), Some(false));
    bc.blocks.set_utxo_available(mi, 2, true);

    assert!(matches!(
        bc.resolve_and_spend_utxo(mi, 102, 101, 2, 0, false),
        Err(UtxoSpendError::StorageRead)
    ));
    assert_eq!(bc.blocks.utxo_available(mi, 2), Some(true), "nothing spent");
}

/// An override set declaring `max_block_utxo_output = 1` and the window
/// [`TEST_W`].
fn one_utxo_output_config_builder() -> ChainConfigPayloadBuilder {
    let mut builder = window_config_builder(TEST_W);
    builder
        .add_literal(parameter::MAX_BLOCK_UTXO_OUTPUT, &1u16.to_le_bytes())
        .ok()
        .expect("a two-byte literal is well-formed");
    builder
}

/// Story 6.11 AC5 / AC6.7 — the Tier-1 UTXO-output cap enforces the chain's
/// value only once it is durably locked; a tentative one leaves the
/// bitfield-width bound in force (FR9).
#[test]
fn tier1_utxo_output_cap_is_the_locked_value_only() {
    let two_outputs = utxo_mint_block([0xCD; 32]);
    let one_output = complex_tx_block(
        101,
        [0xCD; 32],
        3,
        0,
        &[&utxo_tx(101, &[], Some((1, 9)), &[Ok(9)])],
    );

    // Tentative: a stray chain-config block declares the cap of 1.
    let mut bc = new_unconfigured_test_chain();
    let stray = chain_config_block_from(500, [0xEE; 32], &mut one_utxo_output_config_builder());
    bc.tier1_admit(&stray.view(), &stray.view().hash(), 0)
        .expect("the stray is admitted");
    assert!(bc.chain_config.tentative_content().is_some());
    assert_eq!(
        bc.chain_config
            .active_configuration()
            .map(|config| config.max_utxo_outputs()),
        Some(1),
        "the tentative configuration really declares the cap of 1"
    );
    assert!(
        bc.tier1_admit(&two_outputs.view(), &two_outputs.view().hash(), 0)
            .is_ok(),
        "a tentative-only cap must not reject the block (FR9)"
    );

    // Locked on the same content: the cap is enforced and nothing is stored.
    let (crypto, storage, _) = test_backends();
    let mut chain_config = empty_chain_config(TestChain::BUILD_LIMITS);
    chain_config
        .load_durable(one_utxo_output_config_builder().build_signed(&crypto))
        .ok()
        .expect("legal content");
    let mut bc = new_chain(crypto, storage, chain_config, 5, 0);
    let stored = bc.blocks.len();
    assert_eq!(
        bc.tier1_admit(&two_outputs.view(), &two_outputs.view().hash(), 0),
        Err(AdmitError::Rejected(Tier1Failure::TooManyUtxoOutputs))
    );
    assert_eq!(bc.blocks.len(), stored, "not stored");
    assert!(
        bc.tier1_admit(&one_output.view(), &one_output.view().hash(), 0)
            .is_ok(),
        "exactly the cap is admitted"
    );
}

/// Story 6.11 D3 (DEC-133) — the FR3 pass holds a block to its candidate's
/// own declared cap even while that configuration is only tentative: the
/// preload made it the value the lock is about to commit, so a block that
/// Tier 1 admitted under the bitfield-width bound cannot be adopted past it.
#[test]
fn fr3_pass_enforces_the_candidates_declared_utxo_output_cap() {
    let (mut bc, h100) = tentative_one_utxo_output_chain();
    let mint = utxo_mint_block(h100);
    let mi = admit(&mut bc, &mint);

    assert_eq!(
        bc.run_processing_pass(mi),
        Err(ProcessingError::Invalid {
            block_idx: mi,
            reason: ValidationReason::TooManyUtxoOutputs,
        })
    );
    assert_eq!(bc.blocks.utxo_available(mi, 0), Some(false), "rolled back");
}

/// Story 6.11 D3 boundary — exactly the declared cap passes the FR6 step.
#[test]
fn fr3_pass_admits_exactly_the_declared_utxo_output_cap() {
    let (mut bc, h100) = tentative_one_utxo_output_chain();
    let tx = utxo_tx(101, &[], Some((1, 100)), &[Ok(100)]);
    let block = complex_tx_block(101, h100, 3, 0, &[&tx]);
    let bi = admit(&mut bc, &block);

    bc.run_processing_pass(bi).expect("one output, cap one");
    assert_eq!(bc.blocks.utxo_available(bi, 0), Some(true));
}

/// An unconfigured node holding, tentatively, a chain-config anchor at 99
/// that declares `max_block_utxo_output = 1`, and the [`utxo_test_chain`]
/// balance block at 100 above it. Returns the node and block 100's hash.
fn tentative_one_utxo_output_chain() -> (TestChain, [u8; 32]) {
    let mut bc = new_unconfigured_test_chain();
    let cfg = chain_config_block_from(99, [0xAB; 32], &mut one_utxo_output_config_builder());
    admit(&mut bc, &cfg);
    assert!(
        bc.chain_config.tentative_content().is_some(),
        "tentative only"
    );
    let seed = balance_block(
        100,
        cfg.view().hash(),
        &[(1, 100, 0, 0x31), (2, 0, 0, 0x32), (3, 0, 0, 0x33)],
        3,
    );
    admit(&mut bc, &seed);
    (bc, seed.view().hash())
}

/// Story 6.11 AC2 / AC4 end to end — deriving a block sets exactly one bit
/// per UTXO output, which gives it the FR51 tail obligation; spending every
/// output clears it.
#[test]
fn utxo_derivation_drives_the_tail_obligation() {
    let (mut bc, h100) = utxo_test_chain();
    let mint = utxo_mint_block(h100);
    let mi = admit(&mut bc, &mint);
    bc.run_processing_pass(mi).expect("the mint derives");
    assert_eq!(bc.blocks.utxo_available(mi, 0), Some(true));
    assert_eq!(bc.blocks.utxo_available(mi, 1), Some(true));
    assert_eq!(
        bc.blocks.utxo_available(mi, 2),
        Some(false),
        "two outputs only"
    );
    assert_eq!(
        classify_tail_drop(&bc.blocks, &bc.node_info, mi),
        Ok(TailObligation::Utxo)
    );

    let tx = utxo_tx(102, &[(101, 0, 60), (101, 1, 40)], None, &[Err((2, 100))]);
    let spend = complex_tx_block(102, mint.view().hash(), 3, 0, &[&tx]);
    let si = admit(&mut bc, &spend);
    bc.run_processing_pass(si).expect("both outputs spent");
    assert_eq!(bc.blocks.has_available_utxo(mi), Some(false));
    assert_eq!(
        classify_tail_drop(&bc.blocks, &bc.node_info, mi),
        Ok(TailObligation::None)
    );
}

/// Review patch — the lock-time `BlockTooLarge` rollback follows a pass that
/// returned `Ok`, so it must clear the derived bits itself: a surviving
/// ancestor of the offender may not keep advertising its outputs.
#[test]
fn fr9_lock_time_size_rollback_leaves_no_available_utxo_bit() {
    let mut bc = new_unconfigured_w6_chain();
    // The three blocks below the window (`W + H`, DEC-177) are
    // [`w6_below`]'s; #100 is a one-entry balance block seeding node #3,
    // within the small limit. The UTXO blocks sit off the clean slots #101
    // and #104 (Story 6.7 D8), which hold node #3's transfers of nothing.
    let below = w6_below();
    for block in &below {
        let (outcome, _) = bc.receive_block(block.view(), 0);
        assert_eq!(outcome, ReceiveBlockOutcome::AcceptedSilently);
    }
    let clean = |seq: u32, prev: [u8; 32]| {
        let signer = Crypto::new([1u8; PRIVATE_KEY_SIZE]).ok().expect("test key");
        let nt = NodeTransfer::new_signed(0, seq - 1, 3, 3, 0, 0, 0, &signer);
        headed(seq, prev, 3, 1, 0, 3, 0, |b| {
            b.add_node_transfer(&nt).ok().expect("add transfer");
        })
    };
    // `max_node_id = 9`: the pre-window actors of #97..=#99 (nodes 7 and
    // 9) lie inside the derived node-id range.
    let base = balance_block(100, below[2].view().hash(), &[(3, 0, 0, 0x33)], 9);
    let s101 = clean(101, base.view().hash());
    let one = utxo_tx(102, &[], None, &[Ok(5)]);
    let b102 = complex_tx_block(102, s101.view().hash(), 3, 0, &[&one]);
    let three = utxo_tx(103, &[], None, &[Ok(5), Ok(6), Ok(7)]);
    let b103 = complex_tx_block(103, b102.view().hash(), 3, 0, &[&three]);
    let s104 = clean(104, b103.view().hash());
    let cfg = chain_config_block_from(105, s104.view().hash(), &mut small_limit_config_builder(W6));
    for small in below.iter().chain([&base, &s101, &b102, &s104, &cfg]) {
        assert!(small.len() <= SMALL_BLOCK_SIZE_LIMIT as usize);
    }
    assert!(b103.len() > SMALL_BLOCK_SIZE_LIMIT as usize);
    for block in [&base, &s101, &b102, &b103, &s104, &cfg] {
        let (outcome, _) = bc.receive_block(block.view(), 0);
        assert_eq!(outcome, ReceiveBlockOutcome::AcceptedSilently);
    }

    assert!(
        !bc.is_ready(),
        "the re-evaluation at the lock refuses the candidate"
    );
    assert!(
        bc.blocks.find(103, &b103.view().hash()).is_none(),
        "offender deleted"
    );
    let survivor = bc
        .blocks
        .find(102, &b102.view().hash())
        .expect("the offender's ancestor survives");
    assert_eq!(
        bc.blocks.has_available_utxo(survivor),
        Some(false),
        "no bit of the refused candidate survives"
    );
}
