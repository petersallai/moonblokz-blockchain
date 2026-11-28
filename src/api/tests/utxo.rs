//! Tests of the ADR-016 UTXO input checks in `api/step.rs` (Story 6.8).

use super::*;

// --- Story 6.8: ADR-016 sequence-indexed UTXO input -----------------------

/// Block 101: node 1 moves its whole balance into two UTXO outputs, 60 + fee
/// (index 0) and 40 + fee (index 1), paying the fixtures' complex fee, so a
/// spend of either can pay it too and still deliver 60 / 40.
fn utxo_mint_block(prev: [u8; 32]) -> Block {
    let tx = utxo_tx(
        101,
        &[],
        Some((1, 100 + 3 * CX_FEE)),
        &[Ok(60 + CX_FEE), Ok(40 + CX_FEE)],
    );
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
    let tx = utxo_tx(102, &[(101, 1, 40 + CX_FEE)], None, &[Err((2, 40))]);
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
    assert_eq!(
        bc.node_info.balance_of(1),
        NODE_ONE_FUNDS - 100 - 3 * CX_FEE,
        "the mint's input"
    );
    assert_eq!(bc.node_info.balance_of(2), 40, "the UTXO's amount");
    assert_eq!(
        bc.node_info.balance_of(3),
        2 * CX_FEE,
        "the mint's and the spend's fee, nothing mined"
    );
}

/// AC8 (2) — a second spend of the same output, in a later block, is
/// `UtxoUnavailable` against that later block; the abort rolls every bit
/// back to "nothing derived".
#[test]
fn utxo_double_spend_across_blocks_is_unavailable() {
    let (mut bc, h100) = utxo_test_chain();
    let mint = utxo_mint_block(h100);
    let mi = admit(&mut bc, &mint);
    let tx = utxo_tx(102, &[(101, 0, 60 + CX_FEE)], None, &[Err((2, 60))]);
    let first = complex_tx_block(102, mint.view().hash(), 3, 0, &[&tx]);
    admit(&mut bc, &first);
    let tx = utxo_tx(103, &[(101, 0, 60 + CX_FEE)], None, &[Err((2, 60))]);
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
/// the spending block's slot. Node 1's balance input pays the fee (FR56), so
/// the UTXO inputs under test keep their declared amounts.
fn spend_verdict(inputs: &[(u32, u16, u64)]) -> (Result<(), ProcessingError>, u32) {
    let (mut bc, h100) = utxo_test_chain();
    let mint = utxo_mint_block(h100);
    admit(&mut bc, &mint);
    // One 0-amount output: a complex transaction needs one (DEC-308).
    let tx = utxo_tx(102, inputs, Some((1, CX_FEE)), &[Err((2, 0))]);
    let spend = complex_tx_block(102, mint.view().hash(), 3, 0, &[&tx]);
    let si = admit(&mut bc, &spend);
    (bc.run_processing_pass(si).map(|_| ()), si)
}

/// AC8 (3) / DEC-129 — on a window-anchored candidate a reference below
/// the anchor (99) is trusted pre-window history when it is less than `W`
/// (16) blocks back (DEC-196): no bit, and the declared amounts are trusted, so the
/// fee is still known (DEC-131).
#[test]
fn utxo_reference_below_a_window_anchor_is_trusted_below_w() {
    let (mut bc, h100) = utxo_test_chain();
    let mint = utxo_mint_block(h100);
    admit(&mut bc, &mint);
    let tx = utxo_tx(
        102,
        &[(98, 0, 50 + CX_FEE), (87, 3, 30)],
        None,
        &[Err((2, 70))],
    );
    let spend = complex_tx_block(102, mint.view().hash(), 3, 0, &[&tx]);
    let si = admit(&mut bc, &spend);

    bc.run_processing_pass(si).expect("pass succeeds");

    assert_eq!(bc.node_info.balance_of(2), 70, "the output is credited");
    assert_eq!(
        bc.node_info.balance_of(3),
        CX_FEE + 10 + CX_FEE,
        "the mint's fee, then 80 + fee - 70 from the declared amounts"
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

/// DEC-196 / DEC-129 boundary on a `W = 6` chain: a reference `W − 1` back
/// is trusted, one exactly `W` back is not — the dropping tail block is
/// excluded (Story 7.3 AC5). #101 is a clean slot (Story 6.7 D8), so the
/// spend sits at #102 above a [`w6_clean_block`].
#[test]
fn utxo_distance_bound_is_below_w() {
    fn verdict(referenced: u32) -> (Result<(), ProcessingError>, u32) {
        let mut bc = new_w6_chain();
        let cfg = w6_config_anchor_block(99, [0xAB; 32]);
        bc.tier1_admit(&cfg.view(), &cfg.view().hash(), 0)
            .expect("config admitted");
        let seed = balance_block(100, cfg.view().hash(), &[(2, 0, 0, 0x32)], 3);
        bc.tier1_admit(&seed.view(), &seed.view().hash(), 0)
            .expect("seed admitted");
        let clean = w6_clean_block(101, seed.view().hash(), 1);
        bc.tier1_admit(&clean.view(), &clean.view().hash(), 0)
            .expect("clean slot admitted");
        let tx = utxo_tx(102, &[(referenced, 0, 5 + CX_FEE)], None, &[Err((2, 5))]);
        let spend = complex_tx_block(102, clean.view().hash(), 3, 0, &[&tx]);
        let si = bc
            .tier1_admit(&spend.view(), &spend.view().hash(), 0)
            .expect("spend admitted");
        (bc.run_processing_pass(si).map(|_| ()), si)
    }
    assert_eq!(verdict(97).0, Ok(()), "102 - 97 = W - 1");
    let (result, si) = verdict(96);
    assert_eq!(
        result,
        Err(ProcessingError::Invalid {
            block_idx: si,
            reason: ValidationReason::UtxoUnresolvable,
        }),
        "102 - 96 = W"
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
        bc.resolve_utxo(mi, 102, 98, 0, 0, false),
        Err(UtxoSpendError::Invalid(ValidationReason::UtxoUnresolvable))
    ));
    assert!(matches!(bc.resolve_utxo(mi, 102, 98, 0, 0, true), Ok(None)));
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
    let own = transfer_block(101, h100, 1, 3, 0, TEST_TRANSFER_FEE, 0);
    admit(&mut bc, &own);
    let tx = utxo_tx(102, &[(101, 0, 60 + CX_FEE)], None, &[Err((2, 60))]);
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

/// AC8 (8) / AC6 — the fee counts UTXO outputs: a balance input of
/// `100 + fee` paid into a UTXO output of 100 leaves only the fee as surplus,
/// so the creator gets its mined amount and the fee (it used to get another
/// 100). The chain
/// declares `mining_reward = 7`, which the block's `mined_amount` must equal
/// (Story 7.2).
#[test]
fn utxo_output_is_not_paid_out_as_fee() {
    let mut bc = rewarded_test_chain(7);
    let cfg_hash = admit_rewarded_anchor(&mut bc, 99, [0xAB; 32], 7);
    let seed = balance_block_mined(
        100,
        cfg_hash,
        &[(1, 100 + CX_FEE, 0, 0x31), (2, 0, 0, 0x32), (3, 0, 0, 0x33)],
        3,
        7,
    );
    admit(&mut bc, &seed);
    let tx = utxo_tx(101, &[], Some((1, 100 + CX_FEE)), &[Ok(100)]);
    let block = complex_tx_block(101, seed.view().hash(), 3, 7, &[&tx]);
    let bi = admit(&mut bc, &block);

    bc.run_processing_pass(bi).expect("pass succeeds");

    assert_eq!(
        bc.node_info.balance_of(3),
        7 + CX_FEE,
        "mined 7, the fee, not the 100"
    );
    assert_eq!(bc.node_info.balance_of(1), 0);
}

/// AC8 (9) / D1 — the UTXO amount is an input: 50 (UTXO) + 10 + fee
/// (balance) against 55 of outputs pays a fee of 5 + fee. Outputs above the declared
/// inputs never reach the pass: Tier 1 rejects them (DEC-131).
#[test]
fn utxo_amount_counts_as_input() {
    let (mut bc, h100) = utxo_test_chain();
    let tx = utxo_tx(101, &[], Some((1, 50 + CX_FEE)), &[Ok(50)]);
    let mint = complex_tx_block(101, h100, 3, 0, &[&tx]);
    admit(&mut bc, &mint);
    let over = utxo_tx(102, &[(101, 0, 50)], Some((1, 10)), &[Err((2, 61))]);
    let over = complex_tx_block(102, mint.view().hash(), 3, 0, &[&over]);
    assert_eq!(
        bc.tier1_admit(&over.view(), &over.view().hash(), 0),
        Err(AdmitError::Rejected(Tier1Failure::InputsLessThanOutputs))
    );
    let tx = utxo_tx(
        102,
        &[(101, 0, 50)],
        Some((1, 10 + CX_FEE)),
        &[Err((2, 55))],
    );
    let spend = complex_tx_block(102, mint.view().hash(), 3, 0, &[&tx]);
    let si = admit(&mut bc, &spend);

    bc.run_processing_pass(si).expect("pass succeeds");

    assert_eq!(
        bc.node_info.balance_of(3),
        CX_FEE + 5 + CX_FEE,
        "the mint's fee, then 60 + fee - 55"
    );
    assert_eq!(bc.node_info.balance_of(2), 55);
    assert_eq!(
        bc.node_info.balance_of(1),
        NODE_ONE_FUNDS - (50 + CX_FEE) - (10 + CX_FEE)
    );
}

/// DEC-131 — a declared amount that is not the referenced output's is
/// `UtxoAmountMismatch`; the abort leaves nothing derived.
#[test]
fn utxo_declared_amount_mismatch_is_invalid() {
    for declared in [39 + CX_FEE, 41 + CX_FEE] {
        let (mut bc, h100) = utxo_test_chain();
        let mint = utxo_mint_block(h100);
        let mi = admit(&mut bc, &mint);
        let tx = utxo_tx(
            102,
            &[(101, 1, declared)],
            None,
            &[Err((2, declared - CX_FEE))],
        );
        let spend = complex_tx_block(102, mint.view().hash(), 3, 0, &[&tx]);
        let si = admit(&mut bc, &spend);
        assert_eq!(
            bc.run_processing_pass(si),
            Err(ProcessingError::Invalid {
                block_idx: si,
                reason: ValidationReason::UtxoAmountMismatch,
            }),
            "declared {declared}, output 40 + fee"
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
    let first = utxo_tx(
        101,
        &[],
        Some((1, 60 + CX_FEE)),
        &[Ok(10), Err((2, 5)), Ok(45)],
    );
    let second = utxo_tx(101, &[], Some((1, 30 + 2 * CX_FEE)), &[Ok(30 + CX_FEE)]);
    let mint = complex_tx_block(101, h100, 3, 0, &[&first, &second]);
    let mi = admit(&mut bc, &mint);
    let tx = utxo_tx(102, &[(101, 2, 30 + CX_FEE)], None, &[Err((2, 30))]);
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
    assert_eq!(
        bc.node_info.balance_of(3),
        3 * CX_FEE,
        "the three transactions' fees"
    );
}

/// AC8 (2) — the same output named twice in one transaction, or by two
/// transactions of one block, is spent once: the second is
/// `UtxoUnavailable`.
#[test]
fn utxo_double_spend_within_one_block_is_unavailable() {
    let same_tx = utxo_tx(
        102,
        &[(101, 0, 60 + CX_FEE), (101, 0, 60 + CX_FEE)],
        None,
        &[Err((2, 60))],
    );
    let first = utxo_tx(102, &[(101, 0, 60 + CX_FEE)], None, &[Err((2, 60))]);
    let second = utxo_tx(102, &[(101, 0, 60 + CX_FEE)], None, &[Err((2, 60))]);
    // One transaction naming the output twice: Tier 1 evidence from the
    // bytes (Story 7.3 RD3).
    let (mut bc, h100) = utxo_test_chain();
    let mint = utxo_mint_block(h100);
    admit(&mut bc, &mint);
    let spend = complex_tx_block(102, mint.view().hash(), 3, 0, &[&same_tx]);
    assert_eq!(
        bc.tier1_admit(&spend.view(), &spend.view().hash(), 0).err(),
        Some(AdmitError::Rejected(Tier1Failure::DuplicateUtxoInput))
    );
    // Two transactions spending it: the second finds the bit cleared.
    let (mut bc, h100) = utxo_test_chain();
    let mint = utxo_mint_block(h100);
    admit(&mut bc, &mint);
    let spend = complex_tx_block(102, mint.view().hash(), 3, 0, &[&first, &second]);
    let si = admit(&mut bc, &spend);
    assert_eq!(
        bc.run_processing_pass(si),
        Err(ProcessingError::Invalid {
            block_idx: si,
            reason: ValidationReason::UtxoUnavailable,
        })
    );
}

/// AC6 — an input sum beyond `u64` is rejected at Tier 1 (DEC-011,
/// DEC-131); the block's fee total, summed across transactions, is checked
/// in the pass: `ValueOverflow`, never a clamped credit.
#[test]
fn utxo_value_overflow_is_invalid() {
    const HALF: u64 = 1 << 63;
    // No fee ceiling: under the default one, a fee of 2^63 is out of policy
    // before the total can overflow (FR56).
    let mut builder = uncapped_fee_config_builder();
    let mut bc = test_chain_on(&mut builder);
    let cfg_hash = admit_anchor_on(&mut bc, 99, [0xAB; 32], &mut builder, 0);
    let seed = balance_block(
        100,
        cfg_hash,
        &[(1, 0, 0, 0x31), (2, 0, 0, 0x32), (3, 0, 0, 0x33)],
        3,
    );
    admit(&mut bc, &seed);
    let h100 = seed.view().hash();
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

type FailingReadChain = Blockchain<
    Crypto,
    FailingReadStorage,
    TestConfig,
    16,
    16,
    TEST_MAX_BLOCKS,
    4,
    TEST_UTXO_BYTES,
    TEST_MEMPOOL_BYTES,
    TEST_MEMPOOL_ENTRIES,
>;

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
        &[
            (1, NODE_ONE_FUNDS, 0, 0x31),
            (2, 0, 0, 0x32),
            (3, 0, 0, 0x33),
        ],
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
    let tx = utxo_tx(102, &[(101, 1, 40 + CX_FEE)], None, &[Err((2, 40))]);
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

/// Story 6.11 AC3 / AC6.3, amended by DEC-353 (Story 7.3) — an output whose
/// bit is 0 costs the resolver one read, for its address, so the input's
/// signature is verified before the input is declared unavailable: past the
/// block's outputs the read finds nothing (one read beyond the segment
/// walk's), already spent by an earlier block it finds the output (that
/// earlier spend's read, plus this one).
#[test]
fn an_unavailable_output_is_read_once_before_it_is_refused() {
    // (spending blocks' inputs, resolver reads expected on the mint)
    let past_the_outputs: &[&[(u32, u16, u64)]] = &[&[(101, 2, 0)]];
    let spent_earlier: &[&[(u32, u16, u64)]] =
        &[&[(101, 0, 60 + CX_FEE)], &[(101, 0, 60 + CX_FEE)]];
    for (spends, resolver_reads) in [(past_the_outputs, 1), (spent_earlier, 2)] {
        let (mut bc, mint, mi) = failing_read_utxo_chain();
        let mut prev = mint.view().hash();
        let mut tip = mi;
        for (k, inputs) in spends.iter().enumerate() {
            let seq = 102 + k as u32;
            let amount = inputs[0].2;
            // Node 1's balance input pays the fee (FR56).
            let tx = utxo_tx(seq, inputs, Some((1, CX_FEE)), &[Err((2, amount))]);
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
        bc.resolve_utxo(mi, 102, 101, 2, 0, false),
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
    let tx = utxo_tx(101, &[], Some((1, 100 + CX_FEE)), &[Ok(100)]);
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
        &[
            (1, NODE_ONE_FUNDS, 0, 0x31),
            (2, 0, 0, 0x32),
            (3, 0, 0, 0x33),
        ],
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

    let tx = utxo_tx(
        102,
        &[(101, 0, 60 + CX_FEE), (101, 1, 40 + CX_FEE)],
        None,
        &[Err((2, 100))],
    );
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
        let nt = NodeTransfer::new_signed(0, seq - 1, 3, 3, 0, TEST_TRANSFER_FEE, 0, &signer);
        headed(seq, prev, 3, 1, 0, 3, 0, |b| {
            b.add_node_transfer(&nt).ok().expect("add transfer");
        })
    };
    // `max_node_id = 9`: the pre-window actors of #97..=#99 (nodes 7 and
    // 9) lie inside the derived node-id range.
    // Node #3 is funded for its clean slots' fees (FR56).
    let base = balance_block(100, below[2].view().hash(), &[(3, 1_000, 0, 0x33)], 9);
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

/// DEC-330 (AC4b) — the FR51 obligation reads the dropping block: unspent
/// outputs all at most the custodian fee (the code-baked 1) owe no
/// carry-forward, because each would be discarded and the carry-forward would
/// have no output (DEC-308); one output above the fee owes it. The RAM
/// pre-filter still says `Utxo` in both cases.
#[test]
fn the_tail_obligation_owes_a_carry_forward_only_above_the_custodian_fee() {
    for (outputs, owed) in [
        (&[Ok(1), Ok(1)][..], TailObligation::None),
        (&[Ok(1), Ok(2)][..], TailObligation::Utxo),
        (&[Ok(60), Ok(40)][..], TailObligation::Utxo),
    ] {
        let (mut bc, h100) = utxo_test_chain();
        let paid: u64 = outputs.iter().map(|o| o.as_ref().map_or(0, |a| *a)).sum();
        let tx = utxo_tx(101, &[], Some((1, paid + CX_FEE)), outputs);
        let mint = complex_tx_block(101, h100, 3, 0, &[&tx]);
        let mi = admit(&mut bc, &mint);
        bc.run_processing_pass(mi).expect("the mint derives");
        assert_eq!(
            classify_tail_drop(&bc.blocks, &bc.node_info, mi),
            Ok(TailObligation::Utxo),
            "the bitfield pre-filter"
        );
        assert_eq!(bc.tail_obligation(mi, true), Ok(owed), "{outputs:?}");
        // The binding the extension that drops the block must satisfy: a
        // plain block preserves nothing, so it may drop the block only when
        // nothing is owed (review patch, AC4b).
        let plain = linked_transfer_block(102, mint.view().hash());
        let expected = if owed == TailObligation::Utxo {
            TailBinding::Invalid
        } else {
            TailBinding::Advance
        };
        assert_eq!(
            tail_drop_binding(owed, &plain.view()),
            expected,
            "{outputs:?}"
        );
    }
}

/// DEC-330 — only a still-unspent output counts: spending the one output
/// above the fee leaves an all-below-fee block that owes nothing.
#[test]
fn a_spent_output_above_the_fee_no_longer_owes_a_carry_forward() {
    let (mut bc, h100) = utxo_test_chain();
    let tx = utxo_tx(
        101,
        &[],
        Some((1, 1 + 50 + 2 * CX_FEE)),
        &[Ok(1), Ok(50 + CX_FEE)],
    );
    let mint = complex_tx_block(101, h100, 3, 0, &[&tx]);
    let mi = admit(&mut bc, &mint);
    let spend = utxo_tx(102, &[(101, 1, 50 + CX_FEE)], None, &[Err((2, 50))]);
    let spend = complex_tx_block(102, mint.view().hash(), 3, 0, &[&spend]);
    let si = admit(&mut bc, &spend);
    bc.run_processing_pass(si).expect("the spend derives");
    assert_eq!(bc.blocks.utxo_available(mi, 0), Some(true));
    assert_eq!(bc.tail_obligation(mi, true), Ok(TailObligation::None));
}

/// DEC-330 — a block with no set bit is classified from RAM, with no read;
/// one with a set bit is read once, and a failed read is the node's own
/// failure (`TailUnreadable`), never "no obligation".
#[test]
fn the_tail_obligation_reads_only_with_a_set_bit_and_a_failed_read_is_local() {
    let (mut bc, _, mi) = failing_read_utxo_chain();
    // Admitted, not derived: no bit is set yet.
    bc.storage.failing_slot = mi;
    let reads = bc.storage.reads.get();
    assert_eq!(bc.tail_obligation(mi, true), Ok(TailObligation::None));
    assert_eq!(bc.storage.reads.get(), reads, "no set bit, no read");

    bc.storage.failing_slot = NONE_REF;
    bc.run_processing_pass(mi).expect("the mint derives");
    let reads = bc.storage.reads.get();
    assert_eq!(bc.tail_obligation(mi, true), Ok(TailObligation::Utxo));
    assert_eq!(bc.storage.reads.get(), reads + 1, "one read");

    bc.storage.failing_slot = mi;
    bc.storage.reads_left.set(0);
    assert_eq!(bc.tail_obligation(mi, true), Err(TailUnreadable));
}

/// Story 7.1 (AC2) — in the FR3 pass a UTXO input and a balance input are
/// each verified against their own key; a foreign key is exact evidence.
#[test]
fn the_fr3_pass_verifies_input_signatures() {
    let foreign = Crypto::new([2u8; PRIVATE_KEY_SIZE]).ok().expect("key");
    // A UTXO input of the mint's output 1, signed by a foreign key.
    let (mut bc, h100) = utxo_test_chain();
    let mint = utxo_mint_block(h100);
    admit(&mut bc, &mint);
    let tx = utxo_tx_signed(
        0,
        102,
        &[(101, 1, 40 + CX_FEE)],
        None,
        &[Err((2, 40))],
        &foreign,
    );
    let spend = complex_tx_block(102, mint.view().hash(), 3, 0, &[&tx]);
    let si = admit(&mut bc, &spend);
    assert_eq!(
        bc.run_processing_pass(si),
        Err(ProcessingError::Invalid {
            block_idx: si,
            reason: ValidationReason::UtxoSignatureInvalid,
        }),
        "UTXO input"
    );
    // A balance input of node 1 (funded by the harness), signed by a foreign key.
    let (mut bc, h100) = utxo_test_chain();
    let tx = utxo_tx_signed(
        0,
        101,
        &[],
        Some((1, 30 + CX_FEE)),
        &[Err((2, 30))],
        &foreign,
    );
    let spend = complex_tx_block(101, h100, 3, 0, &[&tx]);
    let si = admit(&mut bc, &spend);
    assert_eq!(
        bc.run_processing_pass(si),
        Err(ProcessingError::Invalid {
            block_idx: si,
            reason: ValidationReason::InputSignatureInvalid,
        }),
        "balance input"
    );
}

/// D4 (DEC-333) — a reference below a window-anchored candidate's anchor is
/// trusted pre-window history: no address exists to verify against, so its
/// signature is trusted with its existence and amount, whatever key signed it.
#[test]
fn a_trusted_below_anchor_input_needs_no_key() {
    let foreign = Crypto::new([2u8; PRIVATE_KEY_SIZE]).ok().expect("key");
    let (mut bc, h100) = utxo_test_chain();
    let mint = utxo_mint_block(h100);
    admit(&mut bc, &mint);
    let tx = utxo_tx_signed(
        0,
        102,
        &[(98, 0, 50 + CX_FEE), (87, 3, 30)],
        None,
        &[Err((2, 70))],
        &foreign,
    );
    let spend = complex_tx_block(102, mint.view().hash(), 3, 0, &[&tx]);
    let si = admit(&mut bc, &spend);
    bc.run_processing_pass(si)
        .expect("trusted below the anchor");
    assert_eq!(bc.node_info.balance_of(2), 70);
}

/// Review patch (Story 7.1) — a dropping block whose bits are set but whose
/// transactions do not parse is storage and RAM disagreeing: the amount
/// reader answers "unknown", never "no obligation".
#[test]
fn an_unparseable_dropping_block_owes_an_unknown_obligation() {
    let cfg = chain_config_anchor_block(99, [0xAB; 32]);
    assert_eq!(
        crate::available_utxo::carries_output_above(&cfg.view(), |_| true, 1),
        None,
        "a chain-config payload has no transaction list"
    );
}

/// Review patch (Story 7.1, AC4b) — an `IntegrityFailure` on the dropping
/// block's read is a local failure (`TailUnreadable`), never "no obligation".
#[test]
fn an_integrity_failure_on_the_dropping_block_is_local() {
    let crypto = Crypto::new([1u8; PRIVATE_KEY_SIZE]).ok().expect("key");
    let chain_config = locked_chain_config(&crypto, TestChain::BUILD_LIMITS);
    let node_zero = *crypto.public_key().serialize();
    let mut slot = core::mem::MaybeUninit::<
        Blockchain<
            _,
            _,
            _,
            16,
            16,
            TEST_MAX_BLOCKS,
            4,
            TEST_UTXO_BYTES,
            TEST_MEMPOOL_BYTES,
            TEST_MEMPOOL_ENTRIES,
        >,
    >::uninit();
    Blockchain::<
        _,
        _,
        _,
        16,
        16,
        TEST_MAX_BLOCKS,
        4,
        TEST_UTXO_BYTES,
        TEST_MEMPOOL_BYTES,
        TEST_MEMPOOL_ENTRIES,
    >::init(
        &mut slot,
        crypto,
        CorruptSlotsStorage,
        chain_config,
        5,
        node_zero,
        0,
    );
    // SAFETY: `init` returned, so every field of `slot` is initialized.
    let mut bc = unsafe { slot.assume_init() };
    // Slot 0 reads back `IntegrityFailure` (`CorruptSlotsStorage`).
    bc.blocks
        .insert_at(0, BlockEntry::new([7; 32], NONE_REF, 101));
    assert!(bc.blocks.set_utxo_available(0, 0, true));
    assert_eq!(bc.tail_obligation(0, true), Err(TailUnreadable));
}

/// Review patch (Story 7.1, AC6) — in an incomplete (window-anchored) pass a
/// balance input whose initializer the segment has not seeded is trusted with
/// the rest of its effects: node #0 is not seeded by the harness's balance
/// block, so its input passes whatever key signed it.
#[test]
fn an_unseeded_balance_initializer_is_trusted_in_an_incomplete_pass() {
    let (mut bc, h100) = utxo_test_chain();
    assert!(!bc.node_info.is_seeded(0), "the harness seeds nodes 1..=3");
    // It votes for node #1: past the harness's balance block the watermark is
    // known, and node #0 may not vote for itself (DEC-190).
    let tx = utxo_tx_signed(
        1,
        101,
        &[],
        Some((0, 30 + CX_FEE)),
        &[Err((2, 30))],
        &other_key(),
    );
    let block = complex_tx_block(101, h100, 3, 0, &[&tx]);
    let si = admit(&mut bc, &block);
    bc.run_processing_pass(si).expect("trusted, not verified");
}

/// Review patch (Story 7.1, AC6) — the FR3 pass refuses a signature lifted
/// from another transaction (the `vote` rewritten after signing) and a zeroed
/// signature, as the Ready extension does.
#[test]
fn the_fr3_pass_refuses_lifted_and_zeroed_input_signatures() {
    let signed = utxo_tx(102, &[(101, 1, 40 + CX_FEE)], None, &[Err((2, 40))]);
    let mut lifted = utxo_tx_vote(1, 102, &[(101, 1, 40 + CX_FEE)], None, &[Err((2, 40))]);
    let signature = input_signatures(&signed).remove(0);
    lifted
        .set_input_signature(0, signature.as_slice().try_into().expect("size"))
        .ok()
        .expect("input");
    let mut zeroed = utxo_tx(102, &[(101, 1, 40 + CX_FEE)], None, &[Err((2, 40))]);
    zeroed
        .set_input_signature(0, &[0u8; SIGNATURE_SIZE])
        .ok()
        .expect("input");
    for (tx, what) in [(&lifted, "lifted"), (&zeroed, "zeroed")] {
        let (mut bc, h100) = utxo_test_chain();
        let mint = utxo_mint_block(h100);
        admit(&mut bc, &mint);
        let spend = complex_tx_block(102, mint.view().hash(), 3, 0, &[tx]);
        let si = admit(&mut bc, &spend);
        assert_eq!(
            bc.run_processing_pass(si),
            Err(ProcessingError::Invalid {
                block_idx: si,
                reason: ValidationReason::UtxoSignatureInvalid,
            }),
            "{what}"
        );
    }
}
