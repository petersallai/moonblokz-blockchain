//! Story 7.3 — the per-block rules: the FR56 fee policy and the registration
//! price (AC6), DEC-174 in the step (AC4), DEC-190 (AC7), and the FR6 window
//! duplicate check with its uniqueness keys (AC8).

use super::super::duplicate::{inclusion_floor, is_balance_only, same_key};
use super::super::step::fee_violates;
use super::crediting::{REWARD_PER_NODE_PROGRAM, genesis_with};
use super::*;
use crate::approval::test_seams::{DUPLICATE_SCAN_READS, counted};

/// A node-#0 self-transfer of `amount` at `seq` on `prev`, anchored just below
/// `seq`, paying `fee` and voting `vote`.
fn self_transfer(seq: u32, prev: [u8; 32], amount: u64, fee: u32, vote: u32) -> Block {
    let nt = transfer_with(seq - 1, amount, fee, vote, 0);
    tx_block(seq, prev, 0, |b| {
        b.add_node_transfer(&nt).ok().expect("add transfer");
    })
}

fn transfer_with(anchor: u32, amount: u64, fee: u32, vote: u32, comment: u64) -> NodeTransfer {
    let signer = Crypto::new([1u8; PRIVATE_KEY_SIZE]).ok().expect("test key");
    NodeTransfer::new_signed(vote, anchor, 0, 0, amount, fee, comment, &signer)
}

fn view_of(bytes: &[u8]) -> TransactionView<'_> {
    TransactionView::from_bytes(bytes).expect("a transaction")
}

// --- AC6: the fee policy and the registration price -------------------------

/// FR56 (DEC-181, DEC-311): both bounds inclusive over the integers; an
/// overflowing lower product fails, an overflowing upper product holds; an
/// inverted range admits no fee.
#[test]
fn the_fee_predicate_is_exact_at_both_bounds() {
    assert!(!fee_violates(100, 100, 1, 10), "at the minimum");
    assert!(fee_violates(99, 100, 1, 10), "one below the minimum");
    assert!(!fee_violates(1_000, 100, 1, 10), "at the maximum");
    assert!(fee_violates(1_001, 100, 1, 10), "one above the maximum");
    for fee in [0, 400, 450, 500, u64::MAX] {
        assert!(fee_violates(fee, 100, 5, 4), "inverted range, fee {fee}");
    }
    assert!(
        fee_violates(u64::MAX, 2, u64::MAX, u64::MAX),
        "an overflowing lower product: too low"
    );
    assert!(
        !fee_violates(u64::MAX, 2, 1, u64::MAX),
        "an overflowing upper product: the upper bound holds"
    );
}

/// AC6 at the registry defaults (min 1, max 1 000 per byte): a transfer pays
/// between its size and a thousand times its size, both inclusive.
#[test]
fn a_transfer_pays_between_one_and_a_thousand_per_byte() {
    let (mut bc, _, b1) = ready_genesis(16);
    let prev = b1.view().hash();
    let size = NODE_TRANSFER_SIZE as u32;
    for (fee, reason) in [
        (size - 1, Some(ValidationReason::FeeOutOfPolicy)),
        (size, None),
        (1_000 * size, None),
        (1_000 * size + 1, Some(ValidationReason::FeeOutOfPolicy)),
    ] {
        let block = self_transfer(2, prev, 5, fee, 0);
        assert_eq!(step_reason(&mut bc, &block), reason, "fee {fee}");
    }
}

/// FR51 / FR56: a zero-input carry-forward pays no fee and is exempt.
#[test]
fn a_zero_input_carry_forward_is_fee_exempt() {
    let (mut bc, _, b1) = ready_genesis(16);
    let cx = utxo_tx(2, &[], None, &[Ok(5)]);
    let block = complex_tx_block(2, b1.view().hash(), 0, 0, &[&cx]);
    assert_eq!(step_reason(&mut bc, &block), None);
}

/// A chain whose `tx_fee_per_byte_min` reads the registered-node count
/// (`10 · count`) and whose maximum is the literal 5: served, the range is
/// inverted (10 > 5) and admits no fee (DEC-311); declined (a side block's
/// Tier 2), the check is skipped (DEC-305).
#[test]
fn an_inverted_range_admits_no_fee_and_a_declined_read_skips_it() {
    let mut builder = window_config_builder(TEST_W);
    builder
        .add_bytecode(
            parameter::TX_FEE_PER_BYTE_MIN,
            &REWARD_PER_NODE_PROGRAM[..7],
        )
        .ok()
        .expect("the program frames");
    builder
        .add_literal(parameter::TX_FEE_PER_BYTE_MAX, &5u64.to_le_bytes())
        .ok()
        .expect("an eight-byte literal is well-formed");
    let (mut bc, _, b1) = genesis_with(&builder);
    let prev = b1.view().hash();
    let size = NODE_TRANSFER_SIZE as u32;
    for fee in [size, 5 * size, 10 * size] {
        let block = self_transfer(2, prev, 5, fee, 0);
        assert_eq!(
            step_reason(&mut bc, &block),
            Some(ValidationReason::FeeOutOfPolicy),
            "fee {fee}"
        );
    }
    let nt = transfer_with(1, 5, size, 0, 0);
    let tx = view_of(nt.as_bytes());
    assert!(bc.fee_out_of_policy(&tx, true), "served: inverted");
    assert!(!bc.fee_out_of_policy(&tx, false), "declined: skipped");
}

/// DEC-312: a registration's carried price equals `registration_price` (the
/// default 100) at the pre-state — not more, not less.
#[test]
fn a_registration_carries_exactly_the_registration_price() {
    let (mut bc, _, b1) = ready_genesis(16);
    let prev = b1.view().hash();
    for (price, reason) in [
        (99, Some(ValidationReason::RegistrationPriceMismatch)),
        (100, None),
        (101, Some(ValidationReason::RegistrationPriceMismatch)),
    ] {
        let reg = registration_tx_priced(1, 0, 1, NODE_ONE_KEY, price, 0);
        let block = tx_block(2, prev, 0, |b| {
            b.add_registration(&reg).ok().expect("add registration");
        });
        assert_eq!(step_reason(&mut bc, &block), reason, "price {price}");
    }
}

/// DEC-355: the watermark precedes the price, so a registration for a later
/// slot fails the watermark, never its slot's price.
#[test]
fn a_registration_for_a_later_slot_fails_its_watermark_first() {
    let (mut bc, _, b1) = ready_genesis(16);
    let reg = registration_tx_priced(1, 0, 2, 0x32, 999, 0);
    let block = tx_block(2, b1.view().hash(), 0, |b| {
        b.add_registration(&reg).ok().expect("add registration");
    });
    assert_eq!(
        step_reason(&mut bc, &block),
        Some(ValidationReason::RegistrationWatermark)
    );
}

// --- AC4: DEC-174 in the step -------------------------------------------------

/// DEC-174 with the held `W` (16 on the test chain): an anchor at
/// `max(0, s − W)` passes, one below it fails; below `W` the bound is 0;
/// block #0 is exempt.
#[test]
fn the_step_bounds_an_anchor_by_the_parents_window_tail() {
    let (bc, _, _) = ready_genesis(16);
    assert!(!bc.anchor_below_window(4, 20), "s − W = 4");
    assert!(bc.anchor_below_window(3, 20));
    assert!(!bc.anchor_below_window(0, 10), "below W the bound is 0");
    assert!(!bc.anchor_below_window(0, 0), "block #0");
}

// --- AC7: DEC-190 -------------------------------------------------------------

/// DEC-190 (I-13): node #0 may vote 0 only while it is the only registered
/// node in the transaction's pre-state — a transfer, a later transaction of
/// the block that registered node #1, a registration and a balance input.
#[test]
fn node_zero_votes_for_itself_only_while_alone() {
    let (mut bc, _, b1) = ready_genesis(16);
    let prev = b1.view().hash();
    assert_eq!(
        step_reason(&mut bc, &self_transfer(2, prev, 5, TEST_TRANSFER_FEE, 0)),
        None,
        "alone"
    );
    let reg = registration_tx(1, 0, 1, NODE_ONE_KEY);
    let late = transfer_with(1, 5, TEST_TRANSFER_FEE, 0, 0);
    let in_block = tx_block(2, prev, 0, |b| {
        b.add_registration(&reg).ok().expect("add registration");
        b.add_node_transfer(&late).ok().expect("add transfer");
    });
    assert_eq!(
        step_reason(&mut bc, &in_block),
        Some(ValidationReason::NodeZeroSelfVote),
        "the transfer's pre-state holds node #1"
    );

    let r2 = register(2, prev, 1, NODE_ONE_KEY);
    assert_eq!(receive(&mut bc, &r2), ReceiveBlockOutcome::AcceptedSilently);
    let prev = r2.view().hash();
    let reg2 = registration_tx_priced(2, 0, 2, 0x32, TEST_REGISTRATION_PRICE, 0);
    let cx = utxo_tx(3, &[], Some((0, 5 + CX_FEE)), &[Err((1, 5))]);
    for (case, block) in [
        ("transfer", self_transfer(3, prev, 5, TEST_TRANSFER_FEE, 0)),
        (
            "registration",
            tx_block(3, prev, 0, |b| {
                b.add_registration(&reg2).ok().expect("add registration");
            }),
        ),
        ("balance input", complex_tx_block(3, prev, 0, 0, &[&cx])),
    ] {
        assert_eq!(
            step_reason(&mut bc, &block),
            Some(ValidationReason::NodeZeroSelfVote),
            "{case}"
        );
    }
    assert_eq!(
        step_reason(&mut bc, &self_transfer(3, prev, 5, TEST_TRANSFER_FEE, 1)),
        None,
        "a vote for node #1"
    );
}

// --- AC8: the window duplicate check and its keys -----------------------------

/// DEC-354: the transfer key ignores fee, vote and signature; a registration
/// is keyed by its new key; a balance-only complex transaction by its
/// balance inputs, outputs excluded; any other complex transaction by its
/// bytes; transactions of different kinds never match.
#[test]
fn the_uniqueness_keys() {
    let signer = Crypto::new([1u8; PRIVATE_KEY_SIZE]).ok().expect("key");
    let t = NodeTransfer::new_signed(0, 7, 0, 1, 50, 101, 3, &signer);
    let bumped = NodeTransfer::new_signed(1, 7, 0, 1, 50, 202, 3, &signer);
    let other_comment = NodeTransfer::new_signed(0, 7, 0, 1, 50, 101, 4, &signer);
    let other_receiver = NodeTransfer::new_signed(0, 7, 0, 2, 50, 101, 3, &signer);
    let t = view_of(t.as_bytes());
    assert!(same_key(&t, &view_of(bumped.as_bytes())), "fee and vote");
    assert!(!same_key(&t, &view_of(other_comment.as_bytes())));
    assert!(!same_key(&t, &view_of(other_receiver.as_bytes())));

    let r1 = registration_tx(1, 0, 1, NODE_ONE_KEY);
    let r2 = registration_tx(1, 0, 2, NODE_ONE_KEY);
    let r3 = registration_tx(1, 0, 2, 0x32);
    let r1 = view_of(r1.as_bytes());
    assert!(same_key(&r1, &view_of(r2.as_bytes())), "the same key");
    assert!(!same_key(&r1, &view_of(r3.as_bytes())));
    assert!(!same_key(&r1, &t), "kinds never match");

    let b1 = utxo_tx(5, &[], Some((0, 60)), &[Err((1, 10))]);
    let b2 = utxo_tx(5, &[], Some((0, 60)), &[Ok(20), Err((2, 5))]);
    let b3 = utxo_tx(6, &[], Some((0, 60)), &[Err((1, 10))]);
    let b1 = view_of(b1.as_bytes());
    assert!(is_balance_only(&b1));
    assert!(same_key(&b1, &view_of(b2.as_bytes())), "outputs excluded");
    assert!(!same_key(&b1, &view_of(b3.as_bytes())), "another anchor");

    let u1 = utxo_tx(5, &[(3, 0, 60)], None, &[Ok(50)]);
    let u2 = utxo_tx(5, &[(3, 0, 60)], None, &[Ok(40)]);
    let u1v = view_of(u1.as_bytes());
    assert!(!is_balance_only(&u1v));
    assert!(same_key(&u1v, &view_of(u1.as_bytes())), "identical bytes");
    assert!(
        !same_key(&u1v, &view_of(u2.as_bytes())),
        "a competing variant"
    );

    let z1 = utxo_tx(5, &[], None, &[Ok(5)]);
    let z2 = utxo_tx(5, &[], None, &[Ok(6)]);
    let z1 = view_of(z1.as_bytes());
    assert!(!is_balance_only(&z1), "zero inputs");
    assert!(!same_key(&z1, &view_of(z2.as_bytes())));
}

/// The inclusion floor: one above the highest anchor or UTXO reference.
#[test]
fn the_inclusion_floor_is_above_every_reference() {
    let t = transfer_with(7, 5, 101, 0, 0);
    assert_eq!(inclusion_floor(&view_of(t.as_bytes())), 8);
    let mut cx = moonblokz_chain_types::ComplexTransaction::new(0);
    cx.add_balance_input(3, 0, 1, 0, &[0u8; SIGNATURE_SIZE])
        .ok()
        .expect("input");
    cx.add_utxo_input(9, 0, 1, &[0u8; SIGNATURE_SIZE])
        .ok()
        .expect("input");
    cx.add_balance_input(5, 0, 1, 0, &[0u8; SIGNATURE_SIZE])
        .ok()
        .expect("input");
    cx.add_balance_output(0, 1).ok().expect("output");
    assert_eq!(inclusion_floor(&view_of(cx.as_bytes())), 10);
}

/// I-22 (DEC-349): a transfer twice in one block, a transfer whose key a
/// block on the ancestry already carries — re-signed with another fee
/// included — and a balance-only complex transaction with other outputs
/// are duplicates; another comment is not.
#[test]
fn a_key_is_included_once_within_the_window() {
    let (mut bc, _, b1) = ready_genesis(16);
    let t = transfer_with(1, 5, TEST_TRANSFER_FEE, 0, 0);
    let twice = tx_block(2, b1.view().hash(), 0, |b| {
        b.add_node_transfer(&t).ok().expect("first");
        b.add_node_transfer(&t).ok().expect("second");
    });
    assert_eq!(
        step_reason(&mut bc, &twice),
        Some(ValidationReason::DuplicateTransaction),
        "within one block"
    );

    let cx = utxo_tx(2, &[], Some((0, 5 + CX_FEE)), &[Err((0, 5))]);
    let b2 = tx_block(2, b1.view().hash(), 0, |b| {
        b.add_node_transfer(&t).ok().expect("transfer");
        b.add_complex_transaction(&cx).ok().expect("complex");
    });
    assert_eq!(receive(&mut bc, &b2), ReceiveBlockOutcome::AcceptedSilently);
    let prev = b2.view().hash();
    let bumped = transfer_with(1, 5, TEST_TRANSFER_FEE + 1, 0, 0);
    let other_outputs = utxo_tx(2, &[], Some((0, 5 + CX_FEE)), &[Ok(5)]);
    let again = |add: &dyn Fn(&mut BlockBuilder)| tx_block(3, prev, 0, |b| add(b));
    for (case, block) in [
        (
            "the same transfer",
            again(&|b| {
                b.add_node_transfer(&t).ok().expect("transfer");
            }),
        ),
        (
            "re-signed with another fee",
            again(&|b| {
                b.add_node_transfer(&bumped).ok().expect("transfer");
            }),
        ),
        (
            "a balance-only spend with other outputs",
            again(&|b| {
                b.add_complex_transaction(&other_outputs)
                    .ok()
                    .expect("complex");
            }),
        ),
    ] {
        assert_eq!(
            step_reason(&mut bc, &block),
            Some(ValidationReason::DuplicateTransaction),
            "{case}"
        );
    }
    let fresh = transfer_with(1, 5, TEST_TRANSFER_FEE, 0, 1);
    let distinct = again(&|b| {
        b.add_node_transfer(&fresh).ok().expect("transfer");
    });
    assert_eq!(step_reason(&mut bc, &distinct), None, "another comment");
}

/// DEC-349: the scan reads each transaction block between the lowest
/// inclusion floor and the parent once; a block that carries no transaction
/// (the balance block #3, the chain-config block #1) costs no read.
#[test]
fn the_duplicate_scan_reads_only_transaction_blocks_above_the_floor() {
    let (mut bc, _, b1) = ready_genesis(16);
    let b2 = self_transfer(2, b1.view().hash(), 5, TEST_TRANSFER_FEE, 0);
    assert_eq!(receive(&mut bc, &b2), ReceiveBlockOutcome::AcceptedSilently);
    let b3 = snapshot_block(&bc, 3, b2.view().hash());
    assert_eq!(receive(&mut bc, &b3), ReceiveBlockOutcome::AcceptedSilently);
    let prev = b3.view().hash();
    // Anchor 2: floor 3, only #3 (no read). Anchor 1: floor 2, #3 and #2
    // (one read). Anchor 0: floor 1, #3, #2 and #1 (one read).
    for (anchor, reads) in [(2, 0), (1, 1), (0, 1)] {
        let nt = transfer_with(anchor, 6, TEST_TRANSFER_FEE, 0, 9);
        let block = tx_block(4, prev, 0, |b| {
            b.add_node_transfer(&nt).ok().expect("transfer");
        });
        let before = counted(&DUPLICATE_SCAN_READS);
        assert_eq!(step_reason(&mut bc, &block), None, "anchor {anchor}");
        assert_eq!(
            counted(&DUPLICATE_SCAN_READS) - before,
            reads,
            "anchor {anchor}"
        );
    }
}

/// I-22 on the FR3 pass: a mesh node joining a chain whose #3 repeats #2's
/// transfer deletes #3 and goes Ready on the valid prefix, as the head
/// extension refuses it.
#[test]
fn the_fr3_pass_deletes_a_repeated_transaction() {
    let (mut g, b0, b1) = ready_genesis(16);
    let t = transfer_with(1, 5, TEST_TRANSFER_FEE, 0, 0);
    let b2 = tx_block(2, b1.view().hash(), 0, |b| {
        b.add_node_transfer(&t).ok().expect("transfer");
    });
    assert_eq!(receive(&mut g, &b2), ReceiveBlockOutcome::AcceptedSilently);
    let dup3 = tx_block(3, b2.view().hash(), 0, |b| {
        b.add_node_transfer(&t).ok().expect("transfer");
    });
    assert_eq!(
        receive(&mut g, &dup3),
        ReceiveBlockOutcome::Rejected(RejectReason::InvalidEvidence),
        "the head extension refuses it"
    );
    let mut mesh = new_unconfigured_test_chain();
    for block in [&dup3, &b2, &b1, &b0] {
        assert_eq!(
            receive(&mut mesh, block),
            ReceiveBlockOutcome::AcceptedSilently
        );
    }
    assert!(mesh.is_ready());
    assert_eq!(head_of(&mesh), (2, b2.view().hash()));
    assert!(
        mesh.blocks.find(3, &dup3.view().hash()).is_none(),
        "deleted"
    );
}
