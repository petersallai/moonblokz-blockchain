//! Story 7.3 — FR14 ready-state transaction intake (AC1, AC2, AC9, AC10,
//! AC11): one outcome per submission, the dry-run that leaves no trace, and
//! the FR31 admission.

use super::super::transaction_intake::exceeds_block_room;
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
fn transfer_by(
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
/// signed) is Deferred, a forged one Rejected, a reference to an output the
/// block does not hold Deferred.
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
    assert_eq!(submit(&mut bc, forged.as_bytes()), O::Rejected);
    assert_eq!(submit(&mut bc, missing.as_bytes()), O::Deferred);
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
    let future_utxo = utxo_tx(5, &[(4, 0, 60)], None, &[Ok(10)]);
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
    let carry_forward = utxo_tx(4, &[], None, &[Ok(5)]);
    for (case, bytes) in [
        ("a forged signature", forged.as_bytes()),
        (
            "forged, to an unknown target",
            forged_unknown_target.as_bytes(),
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

/// FR14 / DEC-174 / DEC-196 on a W6 founder at head #8 (`S_tail = 3`): an
/// anchor at `S_tail` is accepted and one below Rejected; a UTXO reference
/// above `S_tail` resolves, one at `S_tail` is Rejected.
#[test]
fn the_acceptance_window_starts_at_the_tail() {
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
