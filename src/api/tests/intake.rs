//! Story 7.3 — FR14 ready-state transaction intake (AC1, AC2, AC9, AC10,
//! AC11): one outcome per submission, the dry-run that leaves no trace, and
//! the FR31 admission.

use super::super::transaction_intake::exceeds_block_room;
use super::crediting::{REWARD_PER_NODE_PROGRAM, genesis_with};
use super::window::{w6_balance_block, w6_founder};
use super::*;

type O = ReceiveTransactionOutcome;

/// Submits the transaction encoded in `bytes` and returns its outcome.
fn submit<
    C: CryptoTrait,
    S: StorageTrait,
    G: ChainConfigTrait,
    const N: usize,
    const L: u32,
    const B: usize,
    const H: usize,
    const U: usize,
    const MB: usize,
    const ME: usize,
>(
    bc: &mut Blockchain<C, S, G, N, L, B, H, U, MB, ME>,
    bytes: &[u8],
) -> O {
    let tx = TransactionView::from_bytes(bytes).expect("a transaction");
    bc.receive_transaction(tx, 0).0
}

/// A transfer by `initializer` (signed with `key`) to `receiver`, anchored at
/// `anchor`, paying `fee`, voting `vote`, with `comment`.
#[allow(clippy::too_many_arguments)]
pub(super) fn transfer_by(
    initializer: u32,
    key: u8,
    receiver: u32,
    amount: u64,
    anchor: u32,
    fee: u32,
    vote: u32,
    comment: u64,
) -> NodeTransfer {
    let signer = Crypto::new([key; PRIVATE_KEY_SIZE]).ok().expect("key");
    NodeTransfer::new_signed(
        vote,
        anchor,
        initializer,
        receiver,
        amount,
        fee,
        comment,
        &signer,
    )
}

/// Node #0's self-transfer anchored at `anchor`, at the minimum fee.
fn zero_transfer(anchor: u32, vote: u32, comment: u64) -> NodeTransfer {
    transfer_by(0, 1, 0, 5, anchor, TEST_TRANSFER_FEE, vote, comment)
}

/// The derived state a dry-run must leave untouched.
fn same_projection<S: StorageTrait, T: StorageTrait>(a: &Chain16<S>, b: &Chain16<T>) -> bool {
    a.node_info == b.node_info && a.vote_engine == b.vote_engine && a.blocks == b.blocks
}

// --- AC1: the gate --------------------------------------------------------------

/// AC1 — not Ready: `NotReady`, nothing admitted, and the pending
/// parent-recovery deadline (a Stored head awaits its parent), not `Idle`.
#[test]
fn intake_is_ready_only_and_keeps_the_recovery_deadline() {
    let mut bc = new_test_chain();
    bc.receive_block(node_transfer_block(5, 3, 4, 7).view(), 0);
    let t = zero_transfer(0, 0, 0);
    let (outcome, next) =
        bc.receive_transaction(TransactionView::from_bytes(t.as_bytes()).expect("tx"), 0);
    assert_eq!(outcome, O::NotReady);
    assert!(
        matches!(next, NextCall::At(_)),
        "the Stored head's deadline"
    );
    assert_eq!(bc.mempool.entry_count(), 0, "nothing admitted");
}

// --- AC9: Accepted, and a dry-run without a trace ----------------------------------

/// AC9 step 4 — a transfer, a registration, a balance-input spend and a UTXO
/// spend valid for the next block are Accepted and admitted; the dry-run
/// leaves the projections and every available-UTXO bit as they were.
#[test]
fn a_valid_transaction_is_accepted_and_the_dry_run_leaves_no_trace() {
    let (mut bc, mint) = faulty_utxo_genesis();
    let (replica, _) = faulty_utxo_genesis();
    let mint_idx = bc.active_chain_head_idx;
    let t = zero_transfer(2, 1, 0);
    let reg = registration_tx(2, 0, 2, 0x32);
    let cx = utxo_tx_vote(1, 4, &[], Some((0, 5 + CX_FEE)), &[Err((1, 5))]);
    let spend = utxo_tx(4, &[(3, 0, 60 + CX_FEE)], None, &[Err((1, 60))]);
    for bytes in [
        t.as_bytes(),
        reg.as_bytes(),
        cx.as_bytes(),
        spend.as_bytes(),
    ] {
        assert_eq!(submit(&mut bc, bytes), O::AcceptedToMempool);
        assert!(same_projection(&bc, &replica), "no trace");
    }
    assert_eq!(bc.mempool.entry_count(), 4);
    assert_eq!(bc.blocks.utxo_available(mint_idx, 0), Some(true));
    let _ = mint;
}

// --- AC9 step 3: Already-confirmed ----------------------------------------------

/// DEC-349 / DEC-352 / DEC-354 — on the chain: the same transfer and a
/// fee-bumped re-signing of it; a balance-only spend with other outputs; a
/// registration's key, whatever its id; a UTXO spend's identical bytes.
#[test]
fn a_transaction_on_the_chain_is_already_confirmed() {
    let (mut bc, mint) = faulty_utxo_genesis();
    let t = zero_transfer(3, 1, 0);
    let cx = utxo_tx_vote(1, 4, &[], Some((0, 5 + CX_FEE)), &[Err((1, 5))]);
    let spend = utxo_tx(4, &[(3, 0, 60 + CX_FEE)], None, &[Err((1, 60))]);
    let b4 = tx_block(4, mint.view().hash(), 0, |b| {
        b.add_node_transfer(&t).ok().expect("transfer");
        b.add_complex_transaction(&cx).ok().expect("balance spend");
        b.add_complex_transaction(&spend).ok().expect("utxo spend");
    });
    assert_eq!(receive(&mut bc, &b4), ReceiveBlockOutcome::AcceptedSilently);

    let bumped = transfer_by(0, 1, 0, 5, 3, TEST_TRANSFER_FEE + 9, 1, 0);
    let other_outputs = utxo_tx_vote(1, 4, &[], Some((0, 5 + CX_FEE)), &[Ok(5)]);
    let same_key_other_id = registration_tx(3, 0, 2, NODE_ONE_KEY);
    let same_key_same_id = registration_tx(1, 0, 1, NODE_ONE_KEY);
    for (case, bytes) in [
        ("the transfer", t.as_bytes()),
        ("re-signed with another fee", bumped.as_bytes()),
        (
            "a balance spend with other outputs",
            other_outputs.as_bytes(),
        ),
        ("its own registration", same_key_same_id.as_bytes()),
        ("its key under another id", same_key_other_id.as_bytes()),
        ("the UTXO spend", spend.as_bytes()),
    ] {
        assert_eq!(submit(&mut bc, bytes), O::AlreadyConfirmed, "{case}");
    }
    assert_eq!(bc.mempool.entry_count(), 0, "nothing admitted");
}

/// DEC-353 — a UTXO input whose bit is 0: a competing variant (validly
/// signed) is Deferred, a reference to an output the block does not hold
/// Deferred; a forged one is Deferred too while the referenced block (#3) lies
/// within the switchable zone (`h − H + 1 = −3`, RD4.3) — the zone's Rejected
/// side is `utxo_content_is_final_below_the_switch_bound`.
#[test]
fn a_spent_utxo_input_is_deferred_after_its_signature() {
    let (mut bc, mint) = faulty_utxo_genesis();
    let spend = utxo_tx(4, &[(3, 0, 60 + CX_FEE)], None, &[Err((1, 60))]);
    let b4 = complex_tx_block(4, mint.view().hash(), 0, 0, &[&spend]);
    assert_eq!(receive(&mut bc, &b4), ReceiveBlockOutcome::AcceptedSilently);
    let competing = utxo_tx(5, &[(3, 0, 60 + CX_FEE)], None, &[Ok(60)]);
    let forged = utxo_tx_signed(0, 5, &[(3, 0, 60 + CX_FEE)], None, &[Ok(60)], &other_key());
    let missing = utxo_tx(5, &[(3, 5, 60 + CX_FEE)], None, &[Ok(60)]);
    assert_eq!(submit(&mut bc, competing.as_bytes()), O::Deferred);
    assert_eq!(submit(&mut bc, forged.as_bytes()), O::Deferred);
    assert_eq!(submit(&mut bc, missing.as_bytes()), O::Deferred);
}

/// A read fault in the already-confirmed scan is the node's own, never a
/// verdict (DEC-349): a valid transfer is at most Deferred — it may be on the
/// chain — and a forged one is still Rejected, as the dry-run verifies its
/// signature whatever the scan came to (DEC-350).
#[test]
fn a_scan_read_fault_defers_only_what_the_dry_run_accepts() {
    let (mut bc, _) = faulty_utxo_genesis();
    bc.storage.failing_read_slot = bc.active_chain_head_idx;
    let forged = transfer_by(0, 2, 0, 5, 2, TEST_TRANSFER_FEE, 1, 0);
    let valid = zero_transfer(2, 1, 0);
    assert_eq!(submit(&mut bc, forged.as_bytes()), O::Rejected);
    assert_eq!(submit(&mut bc, valid.as_bytes()), O::Deferred);
    assert_eq!(bc.mempool.entry_count(), 1, "only the valid one held");
    bc.storage.failing_read_slot = NONE_REF;
    assert_eq!(
        submit(&mut bc, valid.as_bytes()),
        O::DuplicateInMempool,
        "readable again"
    );
}

/// DEC-353: an equivalent on the chain spent every UTXO input, so one set bit
/// rules it out — the scan does not run (no read); with every bit 0 it does.
#[test]
fn the_utxo_equivalence_scan_runs_only_when_every_input_is_spent() {
    use crate::approval::test_seams::{DUPLICATE_SCAN_READS, counted};
    let (mut bc, mint) = faulty_utxo_genesis();
    let spend = utxo_tx(4, &[(3, 0, 60 + CX_FEE)], None, &[Err((1, 60))]);
    let b4 = complex_tx_block(4, mint.view().hash(), 0, 0, &[&spend]);
    assert_eq!(receive(&mut bc, &b4), ReceiveBlockOutcome::AcceptedSilently);
    let one_unspent = utxo_tx(
        5,
        &[(3, 0, 60 + CX_FEE), (3, 1, 40 + CX_FEE)],
        None,
        &[Err((1, 100))],
    );
    let before = counted(&DUPLICATE_SCAN_READS);
    assert_eq!(submit(&mut bc, one_unspent.as_bytes()), O::Deferred);
    assert_eq!(counted(&DUPLICATE_SCAN_READS), before, "a set bit: no scan");
    let all_spent = utxo_tx(5, &[(3, 0, 60 + CX_FEE)], None, &[Ok(60)]);
    assert_eq!(submit(&mut bc, all_spent.as_bytes()), O::Deferred);
    assert!(
        counted(&DUPLICATE_SCAN_READS) > before,
        "every bit 0: scanned"
    );
}

// --- AC9 step 2: Duplicate-in-mempool -------------------------------------------

/// The key search covers every entry, Deferred ones included, by DEC-354's
/// keys: the same transfer, a re-signing with another fee, a Deferred entry
/// resubmitted. Competing UTXO variants are keyed by bytes and coexist.
#[test]
fn a_key_already_in_the_mempool_is_a_duplicate() {
    let (mut bc, _) = faulty_utxo_genesis();
    let t = zero_transfer(3, 1, 0);
    let bumped = transfer_by(0, 1, 0, 5, 3, TEST_TRANSFER_FEE + 9, 1, 0);
    // Node #1 is funded by the mint: a transfer of more than it holds waits.
    let short = transfer_by(
        1,
        NODE_ONE_KEY,
        0,
        NODE_ONE_FUNDS,
        3,
        TEST_TRANSFER_FEE,
        0,
        0,
    );
    let u1 = utxo_tx(4, &[(3, 0, 60 + CX_FEE)], None, &[Err((1, 60))]);
    let u2 = utxo_tx(4, &[(3, 0, 60 + CX_FEE)], None, &[Ok(60)]);
    assert_eq!(submit(&mut bc, t.as_bytes()), O::AcceptedToMempool);
    assert_eq!(submit(&mut bc, t.as_bytes()), O::DuplicateInMempool);
    assert_eq!(submit(&mut bc, bumped.as_bytes()), O::DuplicateInMempool);
    assert_eq!(submit(&mut bc, short.as_bytes()), O::Deferred);
    assert_eq!(submit(&mut bc, short.as_bytes()), O::DuplicateInMempool);
    assert_eq!(submit(&mut bc, u1.as_bytes()), O::AcceptedToMempool);
    assert_eq!(
        submit(&mut bc, u2.as_bytes()),
        O::AcceptedToMempool,
        "a competing variant"
    );
    assert_eq!(bc.mempool.entry_count(), 4);
    assert_eq!(bc.mempool.eligible_iter().count(), 3, "one Deferred entry");
}

// --- AC9 step 4: the reason table ----------------------------------------------

/// The Deferred causes (DEC-350's table): an unknown initializer, a vote
/// target not yet registered, a balance short of the debit (DEC-314), a
/// registration for a later slot (DEC-355), an anchor at `h + 1` (no upper
/// bound, FR14), a UTXO block at `h + 1`.
#[test]
fn what_a_later_chain_can_cure_is_deferred() {
    let (mut bc, _) = faulty_utxo_genesis();
    let unknown = transfer_by(5, 0x35, 0, 5, 3, TEST_TRANSFER_FEE, 0, 0);
    let target = transfer_by(0, 1, 0, 5, 3, TEST_TRANSFER_FEE, 7, 0);
    let short = transfer_by(
        1,
        NODE_ONE_KEY,
        0,
        NODE_ONE_FUNDS,
        3,
        TEST_TRANSFER_FEE,
        0,
        0,
    );
    let later_slot = registration_tx(3, 0, 3, 0x33);
    let future_anchor = zero_transfer(4, 1, 0);
    let future_utxo = utxo_tx(5, &[(4, 0, 60 + CX_FEE)], None, &[Ok(60)]);
    for (case, bytes) in [
        ("an unknown initializer", unknown.as_bytes()),
        ("an unknown vote target", target.as_bytes()),
        ("a short balance", short.as_bytes()),
        ("a later slot", later_slot.as_bytes()),
        ("an anchor at h + 1", future_anchor.as_bytes()),
        ("a UTXO block at h + 1", future_utxo.as_bytes()),
    ] {
        assert_eq!(submit(&mut bc, bytes), O::Deferred, "{case}");
    }
}

/// The Rejected causes: a forged signature of a known key, before an unknown
/// vote target (the signature first, DEC-350); node #0 voting for itself
/// (DEC-190); a fee below the minimum (FR56); a wrong price (DEC-312, D7); a
/// registration for a taken slot; a complex transaction without outputs
/// (DEC-308), with outputs above its inputs, or with no inputs (a
/// carry-forward is the creator's own).
#[test]
fn what_no_later_chain_cures_is_rejected() {
    let (mut bc, _) = faulty_utxo_genesis();
    let forged = transfer_by(0, 2, 0, 5, 3, TEST_TRANSFER_FEE, 1, 0);
    let forged_unknown_target = transfer_by(0, 2, 0, 5, 3, TEST_TRANSFER_FEE, 7, 0);
    let self_vote = zero_transfer(3, 0, 0);
    let cheap = transfer_by(0, 1, 0, 5, 3, TEST_TRANSFER_FEE - 1, 1, 0);
    let mispriced = registration_tx_priced(3, 0, 2, 0x32, 99, 1);
    let taken_slot = registration_tx(3, 0, 1, 0x39);
    let mut no_output = moonblokz_chain_types::ComplexTransaction::new(1);
    no_output
        .add_balance_input(3, 0, CX_FEE, 0, &[0u8; SIGNATURE_SIZE])
        .ok()
        .expect("input");
    let overspend = utxo_tx_vote(1, 4, &[], Some((0, 5)), &[Err((1, 6))]);
    // The registration and the balance-input arms of the signature-first
    // order (DEC-350): forged, voting for a node that does not exist (#7).
    let honest = registration_tx_priced(3, 0, 2, 0x32, TEST_REGISTRATION_PRICE, 7);
    let honest = TransactionView::from_bytes(honest.as_bytes()).expect("tx");
    let honest = honest.as_registration().expect("registration");
    let forged_registration = Registration::new(
        7,
        3,
        0,
        2,
        TEST_REGISTRATION_PRICE,
        TEST_REGISTRATION_FEE,
        honest.new_public_key().try_into().expect("key"),
        honest.new_key_signature().try_into().expect("proof"),
        &[0x55; SIGNATURE_SIZE],
    );
    let forged_input = utxo_tx_signed(
        7,
        4,
        &[],
        Some((0, 5 + CX_FEE)),
        &[Err((1, 5))],
        &other_key(),
    );
    let carry_forward = utxo_tx(4, &[], None, &[Ok(5)]);
    for (case, bytes) in [
        ("a forged signature", forged.as_bytes()),
        (
            "forged, to an unknown target",
            forged_unknown_target.as_bytes(),
        ),
        (
            "a forged registration, to an unknown target",
            forged_registration.as_bytes(),
        ),
        (
            "a forged balance input, to an unknown target",
            forged_input.as_bytes(),
        ),
        ("node #0 voting for itself", self_vote.as_bytes()),
        ("a fee below the minimum", cheap.as_bytes()),
        ("a wrong price", mispriced.as_bytes()),
        ("a taken slot", taken_slot.as_bytes()),
        ("no output", no_output.as_bytes()),
        ("outputs above inputs", overspend.as_bytes()),
        ("no input", carry_forward.as_bytes()),
    ] {
        assert_eq!(submit(&mut bc, bytes), O::Rejected, "{case}");
    }
    assert_eq!(bc.mempool.entry_count(), 0);
}

/// The dry-run restores a complex transaction that fails on its second
/// balance input after debiting the first.
#[test]
fn a_partly_applied_complex_transaction_is_restored() {
    // Node #2 is registered first: a transaction with node #0's and node #1's
    // inputs votes for neither (no self-vote).
    let (mut bc, mint) = faulty_utxo_genesis();
    let (mut replica, _) = faulty_utxo_genesis();
    let reg = registration_tx(3, 0, 2, 0x32);
    let b4 = tx_block(4, mint.view().hash(), 0, |b| {
        b.add_registration(&reg).ok().expect("registration");
    });
    for node in [&mut bc, &mut replica] {
        assert_eq!(receive(node, &b4), ReceiveBlockOutcome::AcceptedSilently);
    }
    let mut cx = moonblokz_chain_types::ComplexTransaction::new(2);
    cx.add_balance_input(4, 0, 100 + CX_FEE, 0, &[0u8; SIGNATURE_SIZE])
        .ok()
        .expect("input");
    cx.add_balance_input(4, 1, 2 * NODE_ONE_FUNDS, 0, &[0u8; SIGNATURE_SIZE])
        .ok()
        .expect("input");
    // The fee is exactly `CX_FEE`: node #1's input is short, not the fee.
    cx.add_balance_output(0, 100 + 2 * NODE_ONE_FUNDS)
        .ok()
        .expect("output");
    let one = Crypto::new([NODE_ONE_KEY; PRIVATE_KEY_SIZE])
        .ok()
        .expect("key");
    let zero = Crypto::new([1u8; PRIVATE_KEY_SIZE]).ok().expect("key");
    let mut buf = [0u8; moonblokz_chain_types::MAX_TRANSACTION_SIZE];
    let preimage = TransactionView::from_bytes(cx.as_bytes())
        .and_then(|v| v.input_signing_preimage(&mut buf).map(<[u8]>::to_vec))
        .expect("preimage");
    for (i, signer) in [&zero, &one].into_iter().enumerate() {
        let sig = signer.sign(&preimage);
        cx.set_input_signature(i as u8, sig.serialize())
            .ok()
            .expect("signature");
    }
    assert_eq!(
        submit(&mut bc, cx.as_bytes()),
        O::Deferred,
        "node #1 is short"
    );
    assert!(same_projection(&bc, &replica), "node #0's debit restored");
}

// --- The window bounds on a chain past `W` ----------------------------------------

/// A W6 founder at head #8 (`S_tail = 3`): a mint at #4 (one UTXO output of
/// `50 + CX_FEE`), node #0's balance replay at #6, the chain-config replay at
/// #7, clean blocks otherwise; node #0 is still the only node.
fn w6_founder_at_eight() -> W6Chain {
    let (mut founder, _, c1) = w6_founder();
    let mut prev = c1.view().hash();
    for seq in 2..=8 {
        let blk = match seq {
            4 => {
                let mint = utxo_tx(4, &[], Some((0, 50 + 2 * CX_FEE)), &[Ok(50 + CX_FEE)]);
                complex_tx_block(4, prev, 0, 0, &[&mint])
            }
            6 => w6_balance_block(Some(&founder), seq, prev),
            7 => w6_config_anchor_block(seq, prev),
            _ => w6_clean_block(seq, prev, 0),
        };
        extend_active_head(&mut founder, &blk, 0);
        prev = blk.view().hash();
    }
    assert_eq!(founder.active_snake_chain_window(), Ok((3, 8)));
    founder
}

/// FR14 / DEC-174 / DEC-196 on a W6 founder at head #8 (`S_tail = 3`): an
/// anchor at `S_tail` is accepted and one below Rejected; a UTXO reference
/// above `S_tail` resolves, one at `S_tail` is Rejected.
#[test]
fn the_acceptance_window_starts_at_the_tail() {
    let mut founder = w6_founder_at_eight();
    let at_tail = zero_transfer(3, 0, 1);
    let below_tail = zero_transfer(2, 0, 2);
    let above_tail = utxo_tx(9, &[(4, 0, 50 + CX_FEE)], None, &[Ok(50)]);
    let at_tail_utxo = utxo_tx(9, &[(3, 0, 50 + CX_FEE)], None, &[Ok(50)]);
    assert_eq!(
        submit(&mut founder, at_tail.as_bytes()),
        O::AcceptedToMempool
    );
    assert_eq!(submit(&mut founder, below_tail.as_bytes()), O::Rejected);
    assert_eq!(
        submit(&mut founder, above_tail.as_bytes()),
        O::AcceptedToMempool
    );
    assert_eq!(submit(&mut founder, at_tail_utxo.as_bytes()), O::Rejected);
}

// --- DEC-223, FR33 and determinism ------------------------------------------------

/// DEC-223: a transaction fits when it is at most the block-size limit less
/// the header and the two-byte transaction count.
#[test]
fn a_transaction_must_fit_a_block() {
    let limit = 1_000u32;
    let room = limit as usize - HEADER_SIZE - 2;
    assert!(!exceeds_block_room(room, limit));
    assert!(exceeds_block_room(room + 1, limit));
    assert!(
        exceeds_block_room(1, (HEADER_SIZE + 2) as u32),
        "no room at all"
    );
}

/// FR31 / FR33 (DEC-351): on a node whose own id is not node #0's, node #0's
/// transfers are not its own; once the mempool is full, an arrival that the
/// seeded draw picks is Rejected and changes nothing.
#[test]
fn an_arrival_the_eviction_draw_picks_is_rejected() {
    let (_, mut l, _) = support_chain(3);
    let mut rejected = 0;
    for comment in 0..40u64 {
        let t = zero_transfer(5, 1, comment);
        let before = l.mempool.entry_count();
        match submit(&mut l, t.as_bytes()) {
            O::AcceptedToMempool => {}
            O::Rejected => {
                rejected += 1;
                assert_eq!(l.mempool.entry_count(), before, "nothing changed");
            }
            other => panic!("unexpected {other:?}"),
        }
        assert!(l.mempool.entry_count() as usize <= TEST_MEMPOOL_ENTRIES);
    }
    assert!(rejected > 0, "the draw refused some arrival");
}

/// AC11 (FR14, FR63): the same submissions against the same state give the
/// same outcomes and the same mempool, whatever the clock reads.
#[test]
fn intake_is_deterministic_and_reads_no_clock() {
    let run = |now: u64| {
        let (mut bc, _) = faulty_utxo_genesis();
        let txs = [
            zero_transfer(3, 1, 0),
            zero_transfer(3, 1, 0),
            zero_transfer(3, 0, 1),
            transfer_by(
                1,
                NODE_ONE_KEY,
                0,
                NODE_ONE_FUNDS,
                3,
                TEST_TRANSFER_FEE,
                0,
                0,
            ),
        ];
        let outcomes: std::vec::Vec<O> = txs
            .iter()
            .map(|t| {
                let view = TransactionView::from_bytes(t.as_bytes()).expect("tx");
                bc.receive_transaction(view, now).0
            })
            .collect();
        (outcomes, bc.mempool.entry_count(), bc.mempool.byte_usage())
    };
    assert_eq!(run(0), run(9_999_999));
}

// --- Code review of Story 7.3 (RD1–RD4.3, P1, P2) ------------------------------

/// RD1: a transaction referencing `h + 1` or later is judged in full — Tier 1
/// at its inclusion floor, the key search, the dry-run — and capped at
/// Deferred; a reference above `h + W` is beyond the horizon (the addendum).
#[test]
fn a_future_reference_is_judged_in_full() {
    let (mut bc, _) = faulty_utxo_genesis(); // h = 3, W = 16
    let valid = zero_transfer(10, 1, 0);
    let forged = transfer_by(0, 2, 0, 5, 10, TEST_TRANSFER_FEE, 1, 0);
    let self_vote = transfer_by(1, NODE_ONE_KEY, 0, 5, 10, TEST_TRANSFER_FEE, 1, 0);
    let overspend = utxo_tx_vote(1, 11, &[], Some((0, 5)), &[Err((1, 6))]);
    for (case, bytes) in [
        ("forged", forged.as_bytes()),
        ("a self-vote", self_vote.as_bytes()),
        ("outputs above inputs", overspend.as_bytes()),
    ] {
        assert_eq!(submit(&mut bc, bytes), O::Rejected, "{case}");
    }
    assert_eq!(submit(&mut bc, valid.as_bytes()), O::Deferred, "valid");
    assert_eq!(
        submit(&mut bc, valid.as_bytes()),
        O::DuplicateInMempool,
        "its key is searched"
    );
    // The horizon: `h + W = 19` is the last reference judged.
    let at_horizon = zero_transfer(19, 1, 1);
    let beyond = zero_transfer(20, 1, 1);
    assert_eq!(submit(&mut bc, at_horizon.as_bytes()), O::Deferred);
    assert_eq!(submit(&mut bc, beyond.as_bytes()), O::Rejected);
    assert_eq!(bc.mempool.entry_count(), 2);
}

/// RD2: a registration's mempool key carries its sponsor. A copy under an
/// unknown sponsor (Deferred: no key to verify) does not shut the genuine
/// registration out; the genuine one's own retry is a duplicate.
#[test]
fn a_registration_copy_under_another_sponsor_does_not_block_it() {
    let (mut bc, _) = faulty_utxo_genesis();
    let genuine = registration_tx(3, 0, 2, 0x32);
    let view = TransactionView::from_bytes(genuine.as_bytes()).expect("tx");
    let reg = view.as_registration().expect("registration");
    let copy = Registration::new(
        1,
        3,
        9,
        2,
        TEST_REGISTRATION_PRICE,
        TEST_REGISTRATION_FEE,
        reg.new_public_key().try_into().expect("key"),
        reg.new_key_signature().try_into().expect("proof"),
        &[0x55; SIGNATURE_SIZE],
    );
    assert_eq!(submit(&mut bc, copy.as_bytes()), O::Deferred, "the copy");
    assert_eq!(
        submit(&mut bc, genuine.as_bytes()),
        O::AcceptedToMempool,
        "the genuine one"
    );
    assert_eq!(
        submit(&mut bc, genuine.as_bytes()),
        O::DuplicateInMempool,
        "its retry"
    );
}

/// RD3: what no chain can ever cure is Rejected — a receiver or a vote
/// target at or above `max_node_count` (16 here), one output spent twice in
/// one transaction; an id below the cap but above the watermark waits.
#[test]
fn what_no_chain_can_create_is_rejected() {
    let (mut bc, _) = faulty_utxo_genesis();
    let receiver = transfer_by(0, 1, 16, 5, 3, TEST_TRANSFER_FEE, 1, 0);
    let target = transfer_by(0, 1, 0, 5, 3, TEST_TRANSFER_FEE, 16, 0);
    let twice = utxo_tx(
        4,
        &[(3, 0, 60 + CX_FEE), (3, 0, 60 + CX_FEE)],
        None,
        &[Err((1, 120 + CX_FEE))],
    );
    for (case, bytes) in [
        ("a receiver at the cap", receiver.as_bytes()),
        ("a vote target at the cap", target.as_bytes()),
        ("one output twice", twice.as_bytes()),
    ] {
        assert_eq!(submit(&mut bc, bytes), O::Rejected, "{case}");
    }
    let below_cap = transfer_by(0, 1, 15, 5, 3, TEST_TRANSFER_FEE, 1, 0);
    assert_eq!(submit(&mut bc, below_cap.as_bytes()), O::Deferred);
}

/// P1 (DEC-350): every input signature whose key is known is verified before
/// any input's curable failure — a forged balance input after a UTXO input
/// whose output does not exist is Rejected, not Deferred.
#[test]
fn a_later_forged_input_is_not_hidden_by_an_earlier_curable_one() {
    let (mut bc, _) = faulty_utxo_genesis();
    // Node #1's balance input signed with the universal test key, not node
    // #1's own: forged. The UTXO input names output 5 of #3, which #3 lacks.
    let tx = utxo_tx_vote(0, 4, &[(3, 5, CX_FEE)], Some((1, 5)), &[Err((0, 5))]);
    assert_eq!(submit(&mut bc, tx.as_bytes()), O::Rejected);
    assert_eq!(bc.mempool.entry_count(), 0);
}

/// P2: a broken ancestry walk in the UTXO pre-check of the already-confirmed
/// scan is a fault, never "unspent" — the scan fault then caps the outcome.
#[test]
fn a_broken_walk_in_the_utxo_precheck_is_a_fault() {
    let (mut bc, _) = faulty_utxo_genesis();
    let head = bc.active_chain_head_idx;
    let spend = utxo_tx(4, &[(2, 0, CX_FEE)], None, &[Err((1, 1))]);
    let view = TransactionView::from_bytes(spend.as_bytes()).expect("tx");
    let parent = bc.blocks.get(head).expect("the head").parent_ref();
    bc.blocks.delete(parent);
    assert_eq!(bc.already_confirmed(&view, head, 4), Err(()));
}

/// RD4.3: a UTXO input's amount or address signature that disagrees with the
/// referenced block is Deferred while a switch can still replace that block
/// (`ref ≥ h − H + 1`, FR58) and Rejected below it. W6 founder, `H = 3`: the
/// mint at #3 is switchable at the heads #3..=#5 and final from #6.
#[test]
fn utxo_content_is_final_below_the_switch_bound() {
    let (mut bc, _, b1) = ready_genesis_w6();
    let b2 = w6_clean_block(2, b1.view().hash(), 0);
    assert_eq!(receive(&mut bc, &b2), ReceiveBlockOutcome::AcceptedSilently);
    let mint_tx = utxo_tx(
        3,
        &[],
        Some((0, 100 + 3 * CX_FEE)),
        &[Ok(60 + CX_FEE), Ok(40 + CX_FEE)],
    );
    let mint = complex_tx_block(3, b2.view().hash(), 0, 0, &[&mint_tx]);
    assert_eq!(
        receive(&mut bc, &mint),
        ReceiveBlockOutcome::AcceptedSilently
    );
    // A distinct output amount per round: a UTXO-bearing key is its bytes.
    let forged = |out| utxo_tx_signed(0, 7, &[(3, 1, 40 + CX_FEE)], None, &[Ok(out)], &other_key());
    let mismatch = |out| utxo_tx(7, &[(3, 1, 41 + CX_FEE)], None, &[Ok(out)]);
    assert_eq!(
        submit(&mut bc, forged(40).as_bytes()),
        O::Deferred,
        "forged, switchable"
    );
    assert_eq!(
        submit(&mut bc, mismatch(41).as_bytes()),
        O::Deferred,
        "amount, switchable"
    );

    let mut prev = mint.view().hash();
    for seq in 4..=6 {
        let block = if seq == 6 {
            snapshot_block(&bc, seq, prev)
        } else {
            w6_clean_block(seq, prev, 0)
        };
        assert_eq!(
            receive(&mut bc, &block),
            ReceiveBlockOutcome::AcceptedSilently,
            "#{seq}"
        );
        prev = block.view().hash();
        if seq == 5 {
            // The bound itself: `h − H + 1 = 3` is still switchable.
            assert_eq!(
                submit(&mut bc, forged(37).as_bytes()),
                O::Deferred,
                "at the bound"
            );
        }
    }
    assert_eq!(
        submit(&mut bc, forged(39).as_bytes()),
        O::Rejected,
        "forged, final"
    );
    assert_eq!(
        submit(&mut bc, mismatch(38).as_bytes()),
        O::Rejected,
        "amount, final"
    );
    let valid = utxo_tx(7, &[(3, 1, 40 + CX_FEE)], None, &[Ok(40)]);
    assert_eq!(submit(&mut bc, valid.as_bytes()), O::AcceptedToMempool);
}

// --- Code review of Story 7.3 (P8): the remaining rows ---------------------------

/// AC9 (D2): the dry-run leaves no trace after any outcome — the projections,
/// the available-UTXO bits, the head and the active value equal an untouched
/// replica's after an Accepted transfer and UTXO spend, a Deferred short
/// balance (the step's `InsufficientBalance`), a Rejected fee below the
/// minimum and a Rejected self-vote (the step's `FeeOutOfPolicy`,
/// `NodeZeroSelfVote`), an Already-confirmed and a Duplicate-in-mempool one.
#[test]
fn every_outcome_leaves_the_projection_as_it_was() {
    let (mut bc, mint) = faulty_utxo_genesis();
    let (mut replica, _) = faulty_utxo_genesis();
    let confirmed = zero_transfer(3, 1, 0);
    let b4 = tx_block(4, mint.view().hash(), 0, |b| {
        b.add_node_transfer(&confirmed).ok().expect("transfer");
    });
    for node in [&mut bc, &mut replica] {
        assert_eq!(receive(node, &b4), ReceiveBlockOutcome::AcceptedSilently);
    }
    let accepted = zero_transfer(4, 1, 1);
    let spend = utxo_tx(5, &[(3, 0, 60 + CX_FEE)], None, &[Err((1, 60))]);
    let short = transfer_by(
        1,
        NODE_ONE_KEY,
        0,
        NODE_ONE_FUNDS,
        4,
        TEST_TRANSFER_FEE,
        0,
        0,
    );
    let cheap = transfer_by(0, 1, 0, 5, 4, TEST_TRANSFER_FEE - 1, 1, 2);
    let self_vote = zero_transfer(4, 0, 3);
    for (case, bytes, outcome) in [
        ("a transfer", accepted.as_bytes(), O::AcceptedToMempool),
        ("a UTXO spend", spend.as_bytes(), O::AcceptedToMempool),
        ("a short balance", short.as_bytes(), O::Deferred),
        ("a fee below the minimum", cheap.as_bytes(), O::Rejected),
        (
            "node #0 voting for itself",
            self_vote.as_bytes(),
            O::Rejected,
        ),
        ("on the chain", confirmed.as_bytes(), O::AlreadyConfirmed),
        ("in the mempool", accepted.as_bytes(), O::DuplicateInMempool),
    ] {
        assert_eq!(submit(&mut bc, bytes), outcome, "{case}");
        assert!(same_projection(&bc, &replica), "{case}: no trace");
        assert_eq!(
            bc.active_chain_head_idx, replica.active_chain_head_idx,
            "{case}"
        );
        assert_eq!(
            bc.active_branch_value, replica.active_branch_value,
            "{case}"
        );
    }
    assert_eq!(bc.mempool.entry_count(), 3, "two Accepted, one Deferred");
}

/// DEC-354 / DEC-352: a transfer's key carries its initializer — the
/// confirmed transfer's fields under node #1 are a fresh transaction, while
/// node #0's own re-signing with another vote, or another vote and fee, is
/// Already-confirmed; a registration matches by its key alone, so the
/// confirmed key under another initializer is Already-confirmed.
#[test]
fn a_confirmed_key_matches_its_initializers_resignings_only() {
    let (mut bc, mint) = faulty_utxo_genesis();
    let confirmed = zero_transfer(3, 1, 0);
    let b4 = tx_block(4, mint.view().hash(), 0, |b| {
        b.add_node_transfer(&confirmed).ok().expect("transfer");
    });
    assert_eq!(receive(&mut bc, &b4), ReceiveBlockOutcome::AcceptedSilently);
    let other_vote = transfer_by(0, 1, 0, 5, 3, TEST_TRANSFER_FEE, 0, 0);
    let other_vote_and_fee = transfer_by(0, 1, 0, 5, 3, TEST_TRANSFER_FEE + 3, 0, 0);
    let key_under_node_one = registration_tx(3, 1, 2, NODE_ONE_KEY);
    for (case, bytes) in [
        ("another vote", other_vote.as_bytes()),
        ("another vote and fee", other_vote_and_fee.as_bytes()),
        (
            "a registered key under another initializer",
            key_under_node_one.as_bytes(),
        ),
    ] {
        assert_eq!(submit(&mut bc, bytes), O::AlreadyConfirmed, "{case}");
    }
    let copied = transfer_by(1, NODE_ONE_KEY, 0, 5, 3, TEST_TRANSFER_FEE, 0, 0);
    assert_eq!(
        submit(&mut bc, copied.as_bytes()),
        O::AcceptedToMempool,
        "the same fields under node #1: another key"
    );
}

/// DEC-354: a balance-only complex transaction is keyed by its balance
/// inputs — a fee-bumped variant (one less out, so one more fee) and one
/// with another vote are Duplicate-in-mempool; another input amount is not.
#[test]
fn a_fee_bumped_balance_only_complex_is_a_mempool_duplicate() {
    let (mut bc, _) = faulty_utxo_genesis();
    let cx = utxo_tx_vote(1, 4, &[], Some((0, 5 + CX_FEE)), &[Err((1, 5))]);
    let bumped = utxo_tx_vote(1, 4, &[], Some((0, 5 + CX_FEE)), &[Err((1, 4))]);
    let revoted = utxo_tx(4, &[], Some((0, 5 + CX_FEE)), &[Err((1, 5))]);
    let other_amount = utxo_tx_vote(1, 4, &[], Some((0, 6 + CX_FEE)), &[Err((1, 6))]);
    assert_eq!(submit(&mut bc, cx.as_bytes()), O::AcceptedToMempool);
    assert_eq!(submit(&mut bc, bumped.as_bytes()), O::DuplicateInMempool);
    assert_eq!(submit(&mut bc, revoted.as_bytes()), O::DuplicateInMempool);
    assert_eq!(
        submit(&mut bc, other_amount.as_bytes()),
        O::AcceptedToMempool
    );
    assert_eq!(bc.mempool.entry_count(), 2);
}

/// DEC-356 (D8) / DEC-174 on the W6 founder at head #8 (`S_tail = 3`): a
/// registration anchored at `S_tail` is accepted, one at `S_tail − 1`
/// Rejected — the transfer's bound.
#[test]
fn a_registrations_acceptance_window_starts_at_the_tail() {
    let mut founder = w6_founder_at_eight();
    let at_tail = registration_tx(3, 0, 1, NODE_ONE_KEY);
    let below_tail = registration_tx(2, 0, 1, 0x32);
    assert_eq!(
        submit(&mut founder, below_tail.as_bytes()),
        O::Rejected,
        "S_tail − 1"
    );
    assert_eq!(
        submit(&mut founder, at_tail.as_bytes()),
        O::AcceptedToMempool,
        "S_tail"
    );
}

/// DEC-355 (D7 order): a registration for a later slot is Deferred; once the
/// missing slot's registration is on the chain the same bytes are valid — a
/// node that holds them already answers Duplicate-in-mempool, a fresh node
/// that received the block first accepts them.
#[test]
fn a_later_slot_registration_is_accepted_once_its_slot_arrives() {
    let (mut bc, mint) = faulty_utxo_genesis();
    let (mut fresh, _) = faulty_utxo_genesis();
    let later = registration_tx(3, 0, 3, 0x33);
    assert_eq!(submit(&mut bc, later.as_bytes()), O::Deferred);
    let slot_two = registration_tx(3, 0, 2, 0x32);
    let b4 = tx_block(4, mint.view().hash(), 0, |b| {
        b.add_registration(&slot_two).ok().expect("registration");
    });
    for node in [&mut bc, &mut fresh] {
        assert_eq!(receive(node, &b4), ReceiveBlockOutcome::AcceptedSilently);
    }
    assert_eq!(
        submit(&mut bc, later.as_bytes()),
        O::DuplicateInMempool,
        "held already"
    );
    assert_eq!(
        submit(&mut fresh, later.as_bytes()),
        O::AcceptedToMempool,
        "its slot arrived"
    );
}

/// DEC-312 (`==`, not `≥`): a registration carrying the resolved price one
/// above or one below is Rejected, the exact price Accepted.
#[test]
fn a_registration_price_off_by_one_either_way_is_rejected() {
    let (mut bc, _) = faulty_utxo_genesis();
    for (price, outcome) in [
        (TEST_REGISTRATION_PRICE + 1, O::Rejected),
        (TEST_REGISTRATION_PRICE - 1, O::Rejected),
        (TEST_REGISTRATION_PRICE, O::AcceptedToMempool),
    ] {
        let reg = registration_tx_priced(3, 0, 2, 0x32, price, 1);
        assert_eq!(submit(&mut bc, reg.as_bytes()), outcome, "price {price}");
    }
}

/// DEC-311: an inverted fee range — `tx_fee_per_byte_min = 10 · count` (one
/// node: 10) above the literal maximum 5 — admits no fee, so intake Rejects
/// every transfer, whatever it pays, and a registration.
#[test]
fn an_inverted_fee_range_rejects_every_transaction_at_intake() {
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
    let (mut bc, _, _) = genesis_with(&builder);
    let size = NODE_TRANSFER_SIZE as u32;
    for per_byte in [1, 5, 10, 1_000] {
        let t = transfer_by(0, 1, 0, 5, 1, per_byte * size, 0, u64::from(per_byte));
        assert_eq!(
            submit(&mut bc, t.as_bytes()),
            O::Rejected,
            "{per_byte} per byte"
        );
    }
    let reg = registration_tx(1, 0, 1, NODE_ONE_KEY);
    assert_eq!(submit(&mut bc, reg.as_bytes()), O::Rejected, "registration");
    assert_eq!(bc.mempool.entry_count(), 0);
}

/// DEC-190 (I-13) at intake: node #0 voting 0 is Accepted while it is the
/// only registered node and Rejected once node #1 is; voting for node #1 it
/// is Accepted.
#[test]
fn node_zero_voting_for_itself_is_accepted_only_while_alone() {
    let (mut bc, _, b1) = ready_genesis(16);
    assert_eq!(
        submit(&mut bc, zero_transfer(1, 0, 0).as_bytes()),
        O::AcceptedToMempool,
        "alone"
    );
    let b2 = register(2, b1.view().hash(), 1, NODE_ONE_KEY);
    assert_eq!(receive(&mut bc, &b2), ReceiveBlockOutcome::AcceptedSilently);
    assert_eq!(
        submit(&mut bc, zero_transfer(2, 0, 1).as_bytes()),
        O::Rejected,
        "node #1 exists"
    );
    assert_eq!(
        submit(&mut bc, zero_transfer(2, 1, 2).as_bytes()),
        O::AcceptedToMempool,
        "a vote for node #1"
    );
}

/// A storage read fault in the dry-run is the node's own, never a verdict
/// (DEC-350): a UTXO spend of the mint's (3, 0), whose bit is set — so the
/// already-confirmed scan reads nothing (DEC-353) — meets the fault when the
/// step resolves the output, and is Deferred with no trace; readable again,
/// its retry is a mempool duplicate.
#[test]
fn a_dry_run_read_fault_defers() {
    use crate::approval::test_seams::{DUPLICATE_SCAN_READS, counted};
    let (mut bc, _) = faulty_utxo_genesis();
    let (replica, _) = faulty_utxo_genesis();
    bc.storage.failing_read_slot = bc.active_chain_head_idx; // the mint, #3
    let spend = utxo_tx(4, &[(3, 0, 60 + CX_FEE)], None, &[Err((1, 60))]);
    let before = counted(&DUPLICATE_SCAN_READS);
    assert_eq!(submit(&mut bc, spend.as_bytes()), O::Deferred);
    assert_eq!(counted(&DUPLICATE_SCAN_READS), before, "no scan read");
    assert!(same_projection(&bc, &replica), "no trace");
    assert_eq!(bc.mempool.entry_count(), 1, "held as Deferred");
    bc.storage.failing_read_slot = NONE_REF;
    assert_eq!(submit(&mut bc, spend.as_bytes()), O::DuplicateInMempool);
}

/// The overflow reasons are Rejected (DEC-350): a transfer of `u64::MAX`
/// whose debit `amount + fee` overflows, and a registration whose
/// `price + fee` does — both `ValueOverflow` in the step.
#[test]
fn an_overflow_is_rejected() {
    let (mut bc, mint) = faulty_utxo_genesis();
    let transfer = transfer_by(0, 1, 0, u64::MAX, 3, TEST_TRANSFER_FEE, 1, 0);
    let registration = registration_tx_priced(3, 0, 2, 0x32, u64::MAX, 1);
    let prev = mint.view().hash();
    for (case, block, bytes) in [
        (
            "a transfer",
            tx_block(4, prev, 0, |b| {
                b.add_node_transfer(&transfer).ok().expect("transfer");
            }),
            transfer.as_bytes(),
        ),
        (
            "a registration",
            tx_block(4, prev, 0, |b| {
                b.add_registration(&registration)
                    .ok()
                    .expect("registration");
            }),
            registration.as_bytes(),
        ),
    ] {
        assert_eq!(
            step_reason(&mut bc, &block),
            Some(ValidationReason::ValueOverflow),
            "{case}"
        );
        assert_eq!(submit(&mut bc, bytes), O::Rejected, "{case}");
    }
    assert_eq!(bc.mempool.entry_count(), 0);
}
