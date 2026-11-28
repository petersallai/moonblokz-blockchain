//! Story 7.3 — the per-block rules: the FR56 fee policy and the registration
//! price (AC6), DEC-174 in the step (AC4), DEC-190 (AC7), and the FR6 window
//! duplicate check with its uniqueness keys (AC8).

use super::super::duplicate::{inclusion_floor, is_balance_only, same_key};
use super::super::step::fee_violates;
use super::crediting::{REWARD_PER_NODE_PROGRAM, genesis_with};
use super::intake::transfer_by;
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
    assert!(
        bc.fee_out_of_policy(&tx, bc.registered_count(true)),
        "served: inverted"
    );
    assert!(!bc.fee_out_of_policy(&tx, None), "declined: skipped");
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

/// DEC-312: every registration of a block is priced at the block's pre-state.
/// With `registration_price = 10 · count`, two registrations on a one-node
/// pre-state both carry 10, though the first moves the count to 2 — 20 for
/// the second is a mismatch.
#[test]
fn every_registration_of_a_block_is_priced_at_its_pre_state() {
    let mut builder = window_config_builder(TEST_W);
    builder
        .add_bytecode(parameter::REGISTRATION_PRICE, &REWARD_PER_NODE_PROGRAM[..7])
        .ok()
        .expect("the program frames");
    let (mut bc, _, b1) = genesis_with(&builder);
    let prev = b1.view().hash();
    let first = registration_tx_priced(1, 0, 1, NODE_ONE_KEY, 10, 0);
    for (price, reason) in [
        (10, None),
        (20, Some(ValidationReason::RegistrationPriceMismatch)),
    ] {
        let second = registration_tx_priced(1, 0, 2, 0x32, price, 1);
        let block = tx_block(2, prev, 0, |b| {
            b.add_registration(&first).ok().expect("first");
            b.add_registration(&second).ok().expect("second");
        });
        assert_eq!(step_reason(&mut bc, &block), reason, "second at {price}");
    }
}

/// DEC-312 for the FR56 fee policy: with `tx_fee_per_byte_max = 10 · count`,
/// a transfer after a registration in the same block is held to the
/// one-node pre-state's 10 per byte, not to the 20 the registration makes it.
#[test]
fn every_fee_of_a_block_is_judged_at_its_pre_state() {
    let mut builder = window_config_builder(TEST_W);
    builder
        .add_bytecode(
            parameter::TX_FEE_PER_BYTE_MAX,
            &REWARD_PER_NODE_PROGRAM[..7],
        )
        .ok()
        .expect("the program frames");
    let (mut bc, _, b1) = genesis_with(&builder);
    let prev = b1.view().hash();
    let reg = registration_tx(1, 0, 1, NODE_ONE_KEY);
    let size = NODE_TRANSFER_SIZE as u32;
    for (per_byte, reason) in [(10, None), (15, Some(ValidationReason::FeeOutOfPolicy))] {
        let nt = transfer_with(1, 5, per_byte * size, 1, 0);
        let block = tx_block(2, prev, 0, |b| {
            b.add_registration(&reg).ok().expect("registration");
            b.add_node_transfer(&nt).ok().expect("transfer");
        });
        assert_eq!(step_reason(&mut bc, &block), reason, "{per_byte} per byte");
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
    // (one read). Anchor 0: floor 0 — block #0 carries its self-transfer at
    // anchor 0 (FR54) — #3, #2, #1 and #0 (two reads).
    for (anchor, reads) in [(2, 0), (1, 1), (0, 2)] {
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

/// DEC-349: the scan never reaches below the window. A block `s` reads at
/// most its ancestors down to `s − W + 1`, however low a candidate's anchor
/// claims — an anchor below `s − W` is invalid anyway, judged after the scan.
#[test]
fn the_duplicate_scan_stops_at_the_window() {
    let (mut bc, _, b1) = ready_genesis_w6();
    let mut prev = b1.view().hash();
    // The replays the tail drops need, each in the block that drops its
    // source (FR49, FR50): node #0's balance at #6 (dropping #0), the chain
    // configuration at #7 (dropping #1); clean blocks otherwise (Story 6.7
    // D8: #5 and #8 must be).
    for seq in 2..=8 {
        let block = match seq {
            6 => snapshot_block(&bc, seq, prev),
            7 => w6_config_anchor_block(seq, prev),
            _ => w6_clean_block(seq, prev, 0),
        };
        assert_eq!(
            receive(&mut bc, &block),
            ReceiveBlockOutcome::AcceptedSilently,
            "#{seq}"
        );
        prev = block.view().hash();
    }
    let nt = transfer_with(0, 6, TEST_TRANSFER_FEE, 0, 9);
    let block = tx_block(9, prev, 0, |b| {
        b.add_node_transfer(&nt).ok().expect("transfer");
    });
    let before = counted(&DUPLICATE_SCAN_READS);
    assert_eq!(
        step_reason(&mut bc, &block),
        Some(ValidationReason::AnchorBelowWindow)
    );
    // #8, #5, #4 — #7 and #6 carry no transaction — down to `s − W + 1 = 4`;
    // not #3, #2 (the anchor's own floor is #1).
    assert_eq!(counted(&DUPLICATE_SCAN_READS) - before, 3, "the step");
    // Intake's scan for the next block #9 (Tier 1 would refuse this anchor
    // first; a UTXO reference below the window reaches the scan) — the same.
    let before = counted(&DUPLICATE_SCAN_READS);
    let head = bc.active_chain_head_idx;
    assert_eq!(
        bc.already_confirmed(&view_of(nt.as_bytes()), head, 9),
        Ok(false)
    );
    assert_eq!(counted(&DUPLICATE_SCAN_READS) - before, 3, "intake");
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

// --- Code review of Story 7.3 (P4, RD3) ----------------------------------------

/// P4 (I-22): block #0 carries node #0's self-transfer at anchor 0 (FR54), so
/// while `s − W ≤ 0` the scan reaches block #0 — a fee-bumped re-signing of it
/// is a duplicate in a block and Already-confirmed at intake.
#[test]
fn the_genesis_self_transfer_is_in_the_scan() {
    let (mut bc, b0, b1) = ready_genesis(16);
    let genesis = b0.view();
    let amount = genesis
        .transactions()
        .and_then(|txs| txs.iter().nth(1))
        .and_then(|tx| tx.as_node_transfer().map(|nt| nt.amount()))
        .expect("block #0's self-transfer");
    let replay = transfer_with(0, amount, TEST_TRANSFER_FEE, 0, 0);
    let block = tx_block(2, b1.view().hash(), 0, |b| {
        b.add_node_transfer(&replay).ok().expect("transfer");
    });
    assert_eq!(
        step_reason(&mut bc, &block),
        Some(ValidationReason::DuplicateTransaction)
    );
    let (outcome, _) = bc.receive_transaction(view_of(replay.as_bytes()), 0);
    assert_eq!(outcome, ReceiveTransactionOutcome::AlreadyConfirmed);
}

/// RD3: a receiver or a vote target at or above `max_node_count` (16 on the
/// test chains) can never exist: `NodeCountExceeded`, not the curable
/// `NodeIdOutOfRange` / `VoteTargetUnknown` one below it.
#[test]
fn an_id_at_the_node_cap_can_never_exist() {
    let (mut bc, _, b1) = ready_genesis(16);
    let prev = b1.view().hash();
    let to = |receiver, vote| {
        let signer = Crypto::new([1u8; PRIVATE_KEY_SIZE]).ok().expect("test key");
        let nt = NodeTransfer::new_signed(vote, 1, 0, receiver, 5, TEST_TRANSFER_FEE, 0, &signer);
        tx_block(2, prev, 0, |b| {
            b.add_node_transfer(&nt).ok().expect("transfer");
        })
    };
    for (receiver, vote, reason) in [
        (15, 0, ValidationReason::NodeIdOutOfRange),
        (16, 0, ValidationReason::NodeCountExceeded),
        (0, 15, ValidationReason::VoteTargetUnknown),
        (0, 16, ValidationReason::NodeCountExceeded),
    ] {
        assert_eq!(
            step_reason(&mut bc, &to(receiver, vote)),
            Some(reason),
            "receiver {receiver}, vote {vote}"
        );
    }
}

// --- Code review of Story 7.3 (P8): the rules on every path -------------------

/// `program` (a seven-byte parameter program) bound to `id` on the test
/// window, the rest at the registry defaults.
fn bound_builder(id: u8, program: &[u8]) -> ChainConfigPayloadBuilder {
    let mut builder = window_config_builder(TEST_W);
    builder
        .add_bytecode(id, program)
        .ok()
        .expect("the program frames");
    builder
}

/// FR9 Tier 2 of a side block (`tier2_check`, DEC-305) for the FR56 fee
/// policy and the DEC-312 price: a sibling of the active #2 is judged before
/// it is written. A literal bound is judged there — a fee below the literal
/// minimum and a price one above the literal `registration_price` are exact
/// evidence and nothing is stored. A chain-info-bound one
/// (`tx_fee_per_byte_min` or `registration_price` = `10 · count`) declines
/// and its check is skipped: the same violation, which the served pre-state
/// refuses, is stored as a side block (the switch replay judges it).
#[test]
fn tier_two_judges_a_literal_fee_or_price_and_skips_a_chain_info_bound_one() {
    let size = NODE_TRANSFER_SIZE as u32;
    let cheap = |prev| self_transfer(2, prev, 6, TEST_TRANSFER_FEE - 1, 0);
    let overpriced = |prev| {
        let reg = registration_tx_priced(1, 0, 1, NODE_ONE_KEY, TEST_REGISTRATION_PRICE + 1, 0);
        tx_block(2, prev, 0, |b| {
            b.add_registration(&reg).ok().expect("add registration");
        })
    };

    // Literal (the registry defaults): refused at Tier 2.
    for (case, side, reason) in [
        (
            "fee",
            cheap as fn([u8; 32]) -> Block,
            ValidationReason::FeeOutOfPolicy,
        ),
        (
            "price",
            overpriced,
            ValidationReason::RegistrationPriceMismatch,
        ),
    ] {
        let (mut bc, _, b1) = ready_genesis(16);
        let prev = b1.view().hash();
        let side = side(prev);
        assert_eq!(step_reason(&mut bc, &side), Some(reason), "{case}");
        let active = self_transfer(2, prev, 5, TEST_TRANSFER_FEE, 0);
        assert_eq!(
            receive(&mut bc, &active),
            ReceiveBlockOutcome::AcceptedSilently
        );
        assert_eq!(
            receive(&mut bc, &side),
            ReceiveBlockOutcome::Rejected(RejectReason::InvalidEvidence),
            "literal {case}: refused at Tier 2"
        );
        assert_eq!(status_of(&bc, &side), None, "literal {case}: not stored");
    }

    // Chain-info-bound (`10 · count`, one node: 10): skipped at Tier 2.
    for (case, id, side, active_fee, reason) in [
        (
            "fee",
            parameter::TX_FEE_PER_BYTE_MIN,
            (|prev| self_transfer(2, prev, 6, NODE_TRANSFER_SIZE as u32, 0))
                as fn([u8; 32]) -> Block,
            10 * size,
            ValidationReason::FeeOutOfPolicy,
        ),
        (
            "price",
            parameter::REGISTRATION_PRICE,
            overpriced,
            TEST_TRANSFER_FEE,
            ValidationReason::RegistrationPriceMismatch,
        ),
    ] {
        let (mut bc, _, b1) = genesis_with(&bound_builder(id, &REWARD_PER_NODE_PROGRAM[..7]));
        let prev = b1.view().hash();
        let side = side(prev);
        assert_eq!(
            step_reason(&mut bc, &side),
            Some(reason),
            "{case}: the served pre-state refuses it"
        );
        let active = self_transfer(2, prev, 5, active_fee, 0);
        assert_eq!(
            receive(&mut bc, &active),
            ReceiveBlockOutcome::AcceptedSilently
        );
        assert_eq!(
            receive(&mut bc, &side),
            ReceiveBlockOutcome::AcceptedSilently,
            "chain-info {case}: Tier 2 declines"
        );
        assert_eq!(
            status_of(&bc, &side),
            Some(BlockStatus::Connected),
            "chain-info {case}: stored beside the head"
        );
        assert_eq!(head_of(&bc), (2, active.view().hash()));
    }
}

/// I-22 / DEC-129: the window duplicate scan stops at `below`, the segment
/// start `a` of a window-anchored FR3 pass (`projection.anchor`) — a copy at
/// `a` is a duplicate, one below it is trusted pre-window history.
/// Ready, `W = 16`: #2 carries `t`; the candidate #4 repeats it.
#[test]
fn the_duplicate_scan_stops_at_the_segment_start() {
    let (mut bc, _, b1) = ready_genesis(16);
    let t = transfer_with(1, 5, TEST_TRANSFER_FEE, 0, 0);
    let b2 = tx_block(2, b1.view().hash(), 0, |b| {
        b.add_node_transfer(&t).ok().expect("transfer");
    });
    let b3 = self_transfer(3, b2.view().hash(), 6, TEST_TRANSFER_FEE, 0);
    for block in [&b2, &b3] {
        assert_eq!(
            receive(&mut bc, block),
            ReceiveBlockOutcome::AcceptedSilently
        );
    }
    let again = tx_block(4, b3.view().hash(), 0, |b| {
        b.add_node_transfer(&t).ok().expect("transfer");
    });
    let parent = bc.active_chain_head_idx;
    for (below, duplicate) in [(0, true), (2, true), (3, false)] {
        assert_eq!(
            bc.block_carries_duplicate(&again.view(), parent, below),
            Ok(duplicate),
            "a = {below}"
        );
    }
}

/// I-22 on a window-anchored FR3 pass (W6, `a = 97`): #101 repeats the
/// transfer of the segment's first block #97 — the scan reaches `a`
/// inclusive, so the pass refuses it. A joiner whose segment starts at
/// `a = 98` never holds #97: the same #101 validates (trusted history).
#[test]
fn a_window_anchored_pass_scans_down_to_its_segment_start() {
    let [b97, b98, b99] = w6_below();
    let c100 = w6_config_anchor_block(100, b99.view().hash());
    // #97's key (initializer 7 → 9, 100, anchor 96, comment 0), another vote.
    let signer = Crypto::new([1u8; PRIVATE_KEY_SIZE]).ok().expect("test key");
    let copy = NodeTransfer::new_signed(3, 96, 7, 9, 100, TEST_TRANSFER_FEE, 0, &signer);
    let again = tx_block(101, c100.view().hash(), 0, |b| {
        b.add_node_transfer(&copy).ok().expect("transfer");
    });
    let pass = |segment: &[&Block]| {
        let mut bc = new_w6_chain();
        for block in segment {
            let view = block.view();
            bc.tier1_admit(&view, &view.hash(), 0).expect("admitted");
        }
        let tip = bc.blocks.find(101, &again.view().hash()).expect("stored");
        (bc.run_processing_pass(tip).map(|_| ()), tip)
    };
    let (verdict, tip) = pass(&[&b97, &b98, &b99, &c100, &again]);
    assert_eq!(
        verdict,
        Err(ProcessingError::Invalid {
            block_idx: tip,
            reason: ValidationReason::DuplicateTransaction,
        }),
        "a = 97: the copy at a"
    );
    let (verdict, _) = pass(&[&b98, &b99, &c100, &again]);
    assert_eq!(verdict, Ok(()), "a = 98: the copy lies below a");
}

/// A genesis node on `builder` with node #0's `a2` (registering node #1 and
/// crediting it once) and its zero-valued tip `z3`: node #1's sibling of
/// `z3` at its real value (`I(1000)`) outranks it, so the FR23 switch
/// replays that sibling (Story 6.12 FR70: an honest fork).
fn zero_tip_on(builder: &ChainConfigPayloadBuilder) -> (TestChain, Block) {
    let (mut bc, _, b1) = genesis_with(builder);
    let a2 = alt(2, b1.view().hash(), 0, 0, 1, 7, true);
    let z3 = alt(3, a2.view().hash(), 0, 0, 1, 8, false);
    for block in [&a2, &z3] {
        assert_eq!(
            receive(&mut bc, block),
            ReceiveBlockOutcome::AcceptedSilently
        );
    }
    (bc, a2)
}

/// Node #1's heavier sibling of `z3` on `a2`: three votes for node #0, then
/// `extra`.
fn heavier_with(a2: &Block, extra: impl FnOnce(&mut BlockBuilder)) -> Block {
    let template = tx_block(3, a2.view().hash(), 0, |b| {
        votes_by(3, 1, 0, 3, 40)(b);
        extra(b);
    });
    resign(&template, 1, vote_snapshot(1000), NODE_ONE_KEY)
}

/// The Story 7.3 step rules refuse on the FR23 switch replay (Tier 3 of a
/// side branch): a heavier sibling carrying node #0's self-vote (DEC-190), a
/// transfer twice (I-22), or a fee above a chain-info-bound maximum (FR56 —
/// skipped at Tier 2, judged at the replay's served pre-state, DEC-305) is
/// deleted and the active chain stays; the same sibling with the fee at the
/// bound wins the switch. `tx_fee_per_byte_max = 10 · count` (two nodes: 20
/// per byte); every other fixture fee is the minimum.
#[test]
fn the_new_rules_refuse_on_a_switch_replay() {
    let builder = bound_builder(
        parameter::TX_FEE_PER_BYTE_MAX,
        &REWARD_PER_NODE_PROGRAM[..7],
    );
    let size = NODE_TRANSFER_SIZE as u32;
    let by_one = |fee: u32, comment: u64| transfer_by(1, NODE_ONE_KEY, 1, 7, 2, fee, 0, comment);
    let self_vote = transfer_with(2, 5, TEST_TRANSFER_FEE, 0, 9);
    let twice = by_one(TEST_TRANSFER_FEE, 1);
    let pricey = by_one(21 * size, 2);
    let at_bound = by_one(20 * size, 3);
    type Extra<'a> = &'a dyn Fn(&mut BlockBuilder);
    let cases: [(&str, Extra, Option<ValidationReason>); 4] = [
        (
            "node #0 voting for itself",
            &|b| {
                b.add_node_transfer(&self_vote).ok().expect("transfer");
            },
            Some(ValidationReason::NodeZeroSelfVote),
        ),
        (
            "a transfer twice",
            &|b| {
                b.add_node_transfer(&twice).ok().expect("first");
                b.add_node_transfer(&twice).ok().expect("second");
            },
            Some(ValidationReason::DuplicateTransaction),
        ),
        (
            "a fee above the chain-info maximum",
            &|b| {
                b.add_node_transfer(&pricey).ok().expect("transfer");
            },
            Some(ValidationReason::FeeOutOfPolicy),
        ),
        (
            "the fee at the chain-info maximum",
            &|b| {
                b.add_node_transfer(&at_bound).ok().expect("transfer");
            },
            None,
        ),
    ];
    for (case, extra, reason) in cases {
        let (mut bc, a2) = zero_tip_on(&builder);
        let z3 = head_of(&bc);
        let sibling = heavier_with(&a2, extra);
        // The reason the replay meets: the sibling as the extension of `a2`.
        let (mut probe, _, b1) = genesis_with(&builder);
        assert_eq!(a2.view().previous_hash(), b1.view().hash().as_slice());
        assert_eq!(
            receive(&mut probe, &a2),
            ReceiveBlockOutcome::AcceptedSilently
        );
        assert_eq!(step_reason(&mut probe, &sibling), reason, "{case}: on a2");
        assert_eq!(
            receive(&mut bc, &sibling),
            ReceiveBlockOutcome::AcceptedSilently,
            "{case}"
        );
        if reason.is_some() {
            assert_eq!(head_of(&bc), z3, "{case}: the active chain stays");
            assert_eq!(status_of(&bc, &sibling), None, "{case}: deleted");
        } else {
            assert_eq!(head_of(&bc), (3, sibling.view().hash()), "{case}: switched");
        }
    }
}

/// The Story 7.3 step rules on the FR3 pass: a mesh node joining a chain
/// whose #3 breaks one of them — a fee below the minimum (FR56), a price one
/// above `registration_price` (DEC-312), node #0 voting for itself once node
/// #1 exists (DEC-190) — deletes #3 and goes Ready on the valid prefix, as
/// the head extension refuses it (the duplicate:
/// [`the_fr3_pass_deletes_a_repeated_transaction`]).
#[test]
fn the_fr3_pass_deletes_a_block_breaking_a_new_rule() {
    let (_, b0, b1) = ready_genesis(16);
    let b2 = register(2, b1.view().hash(), 1, NODE_ONE_KEY);
    let prev = b2.view().hash();
    let overpriced = registration_tx_priced(2, 0, 2, 0x32, TEST_REGISTRATION_PRICE + 1, 1);
    for (case, bad3, reason) in [
        (
            "a fee below the minimum",
            self_transfer(3, prev, 5, TEST_TRANSFER_FEE - 1, 1),
            ValidationReason::FeeOutOfPolicy,
        ),
        (
            "a price above registration_price",
            tx_block(3, prev, 0, |b| {
                b.add_registration(&overpriced).ok().expect("registration");
            }),
            ValidationReason::RegistrationPriceMismatch,
        ),
        (
            "node #0 voting for itself",
            self_transfer(3, prev, 5, TEST_TRANSFER_FEE, 0),
            ValidationReason::NodeZeroSelfVote,
        ),
    ] {
        let (mut g, _, _) = ready_genesis(16);
        assert_eq!(receive(&mut g, &b2), ReceiveBlockOutcome::AcceptedSilently);
        assert_eq!(step_reason(&mut g, &bad3), Some(reason), "{case}");
        assert_eq!(
            receive(&mut g, &bad3),
            ReceiveBlockOutcome::Rejected(RejectReason::InvalidEvidence),
            "{case}: the head extension refuses it"
        );
        let mut mesh = new_unconfigured_test_chain();
        for block in [&bad3, &b2, &b1, &b0] {
            assert_eq!(
                receive(&mut mesh, block),
                ReceiveBlockOutcome::AcceptedSilently,
                "{case}"
            );
        }
        assert!(mesh.is_ready(), "{case}");
        assert_eq!(head_of(&mesh), (2, prev), "{case}: Ready on the prefix");
        assert!(
            mesh.blocks.find(3, &bad3.view().hash()).is_none(),
            "{case}: deleted"
        );
    }
}

/// NFR5 with the Story 7.3 rules: a chain paying fees at both FR56 bounds
/// (the minimum and `1 000 ·` size), registering nodes #1 and #2 at exactly
/// `registration_price`, and node #1 voting for node #0 (DEC-190's
/// alternative) — the FR3 pass of a mesh node fed the same blocks into the
/// same slots ends in the state the genesis node's head extensions reached.
#[test]
fn the_fr3_pass_equals_the_head_extension_under_the_new_rules() {
    let (mut g, b0, b1) = ready_genesis(16);
    let size = NODE_TRANSFER_SIZE as u32;
    let b2 = register(2, b1.view().hash(), 1, NODE_ONE_KEY);
    let fund = NodeTransfer::new_signed(
        1,
        2,
        0,
        1,
        NODE_ONE_FUNDS,
        TEST_TRANSFER_FEE,
        0,
        &Crypto::new([1u8; PRIVATE_KEY_SIZE]).ok().expect("key"),
    );
    let at_max = transfer_with(2, 5, 1_000 * size, 1, 1);
    let b3 = tx_block(3, b2.view().hash(), 0, |b| {
        b.add_node_transfer(&fund).ok().expect("funding");
        b.add_node_transfer(&at_max).ok().expect("at the maximum");
    });
    let reg = registration_tx(3, 0, 2, 0x32);
    let by_one = transfer_by(1, NODE_ONE_KEY, 0, 9, 3, TEST_TRANSFER_FEE, 0, 0);
    let b4 = tx_block(4, b3.view().hash(), 0, |b| {
        b.add_registration(&reg).ok().expect("registration");
        b.add_node_transfer(&by_one).ok().expect("node #1's vote");
    });
    for block in [&b2, &b3, &b4] {
        assert_eq!(
            receive(&mut g, block),
            ReceiveBlockOutcome::AcceptedSilently
        );
    }
    assert_eq!(head_of(&g), (4, b4.view().hash()));
    assert_eq!(g.node_info.max_known_node_id(), 2);

    let mut mesh = new_unconfigured_test_chain();
    for block in [&b0, &b1, &b2, &b3, &b4] {
        let view = block.view();
        mesh.tier1_admit(&view, &view.hash(), 0).expect("admitted");
    }
    mesh.drive_dominant_chain_acquisition();
    assert!(mesh.is_ready());
    // The one-way signature marks (DEC-157, Story 6.7 D2) are not derived
    // state: the founder wrote #0 and #1 itself and never judged them, the
    // pass did. Every other entry is compared as it stands.
    for block in [&b0, &b1] {
        let idx = slot(&g, block);
        assert_eq!(verified(&g, block), Some(false), "the founder's own");
        assert!(
            mesh.blocks
                .get(slot(&mesh, block))
                .is_some_and(|e| e.is_signatures_accepted())
        );
        g.blocks.mark_signatures_accepted(idx);
    }
    super::forward::assert_same_state(&mesh, &g, "pass vs head extension");
}

/// FR9 / DEC-174 at Tier 1, end to end through `tier1_admit`: the anchor's
/// lower bound `s − W` is enforced only once the configuration is durably
/// locked (`enforceable_active_chain_length` is `Some(W)`); while it is
/// tentative (`None`) an anchor below the window is not refused at Tier 1
/// (the per-block step judges it with the held `W`).
#[test]
fn tier_one_bounds_an_anchor_by_the_window_only_once_locked() {
    let s = 100;
    let signer = Crypto::new([1u8; PRIVATE_KEY_SIZE]).ok().expect("test key");
    let block = |anchor| {
        let nt = NodeTransfer::new_signed(3, anchor, 7, 9, 100, TEST_TRANSFER_FEE, 0, &signer);
        tx_block(s, [0xCD; 32], 0, |b| {
            b.add_node_transfer(&nt).ok().expect("transfer");
        })
    };
    let below = block(s - TEST_W - 1);
    let at_tail = block(s - TEST_W);

    // Tentative: a stray chain-config block declares `W = 16`.
    let mut bc = new_unconfigured_test_chain();
    let stray = chain_config_block_from(500, [0xEE; 32], &mut window_config_builder(TEST_W));
    bc.tier1_admit(&stray.view(), &stray.view().hash(), 0)
        .expect("the stray is admitted");
    assert!(bc.chain_config.tentative_content().is_some());
    assert_eq!(bc.active_chain_length(), Some(TEST_W), "held");
    assert_eq!(
        bc.enforceable_active_chain_length(),
        None,
        "not enforceable"
    );
    assert!(
        bc.tier1_admit(&below.view(), &below.view().hash(), 0)
            .is_ok(),
        "a tentative W must not refuse it"
    );

    // Locked on the same content: refused, nothing stored.
    let (crypto, storage, _) = test_backends();
    let mut chain_config = empty_chain_config(TestChain::BUILD_LIMITS);
    chain_config
        .load_durable(window_config_builder(TEST_W).build_signed(&crypto))
        .ok()
        .expect("legal content");
    let mut bc = new_chain(crypto, storage, chain_config, 5, 0);
    assert_eq!(bc.enforceable_active_chain_length(), Some(TEST_W));
    let stored = bc.blocks.len();
    assert_eq!(
        bc.tier1_admit(&below.view(), &below.view().hash(), 0),
        Err(AdmitError::Rejected(Tier1Failure::AnchorBelowWindow))
    );
    assert_eq!(bc.blocks.len(), stored, "not stored");
    assert!(
        bc.tier1_admit(&at_tail.view(), &at_tail.view().hash(), 0)
            .is_ok(),
        "an anchor at s − W is admitted"
    );
}
