//! Tests of `api/evidence.rs`.

use super::*;

// ---- Story 6.7: incoming approval-evidence validation ----

/// `proposer`'s complete evidence for its own deviation `d@6` on Story
/// 6.4's chain (two supports, in rank order), with `d` and the subgroup.
fn evidence_by(proposer: u32) -> (Block, Block, std::vec::Vec<u32>) {
    let (_, mut l, _, d, d_idx) = proposer_chain(proposer);
    accumulate(&mut l, &d, d_idx, 2);
    let members = l.approval.members().to_vec();
    let e = l.build_evidence_block(d_idx, 0).expect("evidence");
    (d, e, members)
}

/// Story 6.4's builder `g` (node #0, Ready) at `proposer`'s deviation
/// `d@6`, and the evidence `proposer` built for it: a second node about to
/// judge it as a direct extension.
fn evidence_observer(proposer: u32) -> (SupportChain, Block, Block) {
    let (mut g, mut l, _, d, d_idx) = proposer_chain(proposer);
    accumulate(&mut l, &d, d_idx, 2);
    let e = l.build_evidence_block(d_idx, 0).expect("evidence");
    assert_eq!(receive(&mut g, &d), ReceiveBlockOutcome::AcceptedSilently);
    assert_eq!(head_of(&g), (6, d.view().hash()));
    (g, d, e)
}

/// An evidence block at `seq` on `prev` by `creator` in the FR27 override
/// header, its payload `ev` laid out per DEC-195, signed with the creator's
/// fixture key (so Tier 1's creator signature passes).
fn evidence_block(seq: u32, prev: [u8; 32], creator: u32, ev: &Evidence) -> Block {
    let signer = Crypto::new([key_of(creator); PRIVATE_KEY_SIZE])
        .ok()
        .expect("key");
    let header = BlockHeader {
        version: 1,
        sequence: seq,
        creator,
        mined_amount: 0,
        payload_type: PAYLOAD_TYPE_APPROVAL,
        consumed_votes: 0,
        first_voted_node: creator,
        consumed_votes_from_first_voted_node: 0,
        previous_hash: prev,
        signature: [0u8; SIGNATURE_SIZE],
    };
    let bitmap_end = APPROVAL_PREFIX_SIZE + ev.bitmap.len();
    let late_at = bitmap_end + ev.aggregate.len() + APPROVAL_LATE_COUNT_SIZE;
    let len = late_at + APPROVAL_LATE_ENTRY_SIZE * ev.late.len();
    let mut builder = BlockBuilder::new().header(header);
    let payload = builder.approval_payload_mut(len).ok().expect("room");
    payload[..APPROVAL_DEVIATION_SEQUENCE_OFFSET]
        .copy_from_slice(&ev.supporter_vote_sum.to_le_bytes());
    payload[APPROVAL_DEVIATION_SEQUENCE_OFFSET..APPROVAL_M_OFFSET]
        .copy_from_slice(&ev.deviation_sequence.to_le_bytes());
    payload[APPROVAL_M_OFFSET] = ev.m as u8;
    payload[APPROVAL_PREFIX_SIZE..bitmap_end].copy_from_slice(&ev.bitmap);
    payload[bitmap_end..bitmap_end + ev.aggregate.len()].copy_from_slice(&ev.aggregate);
    payload[late_at - APPROVAL_LATE_COUNT_SIZE..late_at]
        .copy_from_slice(&(ev.late.len() as u16).to_le_bytes());
    for (i, (id, vote)) in ev.late.iter().enumerate() {
        let at = late_at + APPROVAL_LATE_ENTRY_SIZE * i;
        payload[at..at + 4].copy_from_slice(&id.to_le_bytes());
        payload[at + 4..at + 8].copy_from_slice(&vote.to_le_bytes());
    }
    builder.build_signed(&signer).ok().expect("build signed")
}

/// `e` (with `signers` marked) under the same header, its payload
/// re-assembled after `mutate` and re-signed by its creator: one changed
/// field of a passing evidence block.
fn evidence_with(e: &Block, signers: usize, mutate: impl FnOnce(&mut Evidence)) -> Block {
    let mut ev = evidence_of(e, signers);
    mutate(&mut ev);
    let view = e.view();
    let prev: [u8; 32] = view.previous_hash().try_into().expect("32 bytes");
    evidence_block(view.sequence(), prev, view.creator(), &ev)
}

/// The serialized aggregate of `signers`' supports for `proposer`'s block
/// `hash` at `p`, in this order.
fn aggregate_by(signers: &[u32], proposer: u32, p: u32, hash: &[u8; 32]) -> std::vec::Vec<u8> {
    let message = support_message_bytes(proposer, p, hash);
    let crypto: std::vec::Vec<Crypto> = signers
        .iter()
        .map(|&n| {
            Crypto::new([key_of(n); PRIVATE_KEY_SIZE])
                .ok()
                .expect("key")
        })
        .collect();
    let signatures: std::vec::Vec<MultiSignature> =
        crypto.iter().map(|c| c.multi_sign(&message)).collect();
    let keys: std::vec::Vec<[u8; PUBLIC_KEY_SIZE]> =
        crypto.iter().map(|c| *c.public_key().serialize()).collect();
    let signature_refs: std::vec::Vec<&MultiSignature> = signatures.iter().collect();
    let key_refs: std::vec::Vec<&[u8; PUBLIC_KEY_SIZE]> = keys.iter().collect();
    let aggregate = test_crypto()
        .aggregate_signatures(&signature_refs, &key_refs, &message)
        .ok()
        .expect("aggregates");
    let mut out = std::vec![
        0u8;
        AGGREGATED_SIGNATURE_CONSTANT_SIZE
            + AGGREGATED_SIGNATURE_VARIABLE_SIZE * signers.len()
    ];
    let len = aggregate.serialize(&mut out).ok().expect("serializes");
    out.truncate(len);
    out
}

/// Ready's projection for a direct extension of `bc`'s head: the active-set
/// counter corrected from the physical tail.
fn ready_projection<S: StorageTrait>(bc: &Chain16<S>) -> Projection {
    Projection {
        counter_tail: bc.physical_counter_tail(),
        ..Projection::COMPLETE
    }
}

/// A window-anchored FR3 pass's projection with the anchor `a`: the roster
/// known and every node's vote seeded unless a test changes it.
fn window_anchored(anchor: u32) -> Projection {
    Projection {
        complete: false,
        roster_bounded: true,
        saw_balance_block: true,
        vote_seed_from: 0,
        first_segment_registration: 0,
        run_unknown_below: 0,
        counter_tail: u32::MAX,
        anchor,
    }
}

/// The evidence check's verdict on `block` as an extension of `bc`'s head
/// under `projection`, on a scratch entry removed again: `Ok`,
/// `Err(Some(reason))` (exact evidence) or `Err(None)` (a local fault).
fn judge_on<S: StorageTrait>(
    bc: &mut Chain16<S>,
    block: &Block,
    projection: &Projection,
) -> Result<(), Option<ValidationReason>> {
    let view = block.view();
    let idx = bc.blocks.next_free_index().expect("a free slot");
    let mut entry = BlockEntry::new(view.hash(), bc.active_chain_head_idx, view.sequence());
    entry.set_payload_type(view.payload_type());
    bc.blocks.insert_at(idx, entry);
    let verdict = bc.judge_evidence(&view, idx, projection);
    bc.blocks.delete(idx);
    match verdict {
        Ok(()) => Ok(()),
        Err(ProcessingError::Invalid { reason, .. }) => Err(Some(reason)),
        Err(_) => Err(None),
    }
}

/// The FR21 value of the active window, block by block from storage.
fn window_value<S: StorageTrait>(bc: &Chain16<S>) -> u64 {
    let tail = bc
        .blocks
        .get(bc.snake_chain_tail_idx)
        .expect("a tail")
        .sequence();
    let mut sum = 0;
    let mut cur = bc.active_chain_head_idx;
    loop {
        let entry = bc.blocks.get(cur).expect("on the path");
        if entry.sequence() <= tail {
            return sum;
        }
        let mut buf = [0u8; MAX_BLOCK_SIZE];
        sum += block_value::<16>(&bc.view_retained(cur, &mut buf).expect("readable"));
        cur = entry.parent_ref();
    }
}

/// A held block's `(status, on the active chain, signatures accepted
/// (bit 6), creator signature verified (bit 5))`.
fn entry_of<S: StorageTrait>(
    bc: &Chain16<S>,
    block: &Block,
) -> Option<(BlockStatus, bool, bool, bool)> {
    let view = block.view();
    bc.blocks
        .find(view.sequence(), &view.hash())
        .and_then(|idx| bc.blocks.get(idx))
        .map(|entry| {
            (
                entry.status(),
                entry.is_on_active_chain(),
                entry.is_signatures_accepted(),
                entry.is_signature_verified(),
            )
        })
}

/// The fixture's own pin: an evidence block re-assembled field by field
/// with nothing changed carries the builder's payload, and passes.
#[test]
fn a_rebuilt_evidence_is_the_built_one() {
    let (mut g, _, e) = evidence_observer(4);
    let same = evidence_with(&e, 2, |_| {});
    assert_eq!(same.view().payload(), e.view().payload());
    let ready = ready_projection(&g);
    assert_eq!(judge_on(&mut g, &same, &ready), Ok(()));
}

// -- AC4: the FR27 run rules and the FR48 clean slot --

/// Four blocks that may not extend `d`'s open run (`g` at `d`, by 4):
/// a foreign creator, the proposer in deviation form, the proposer voting
/// for another node with `consumed_votes = 0` (only `first_voted ≠
/// creator` breaks the override form), the proposer with `consumed_votes ≠
/// 0` (only `cv ≠ 0` breaks it).
fn run_violations(g: &SupportChain, d: &Block) -> [(Block, ValidationReason); 4] {
    let foreign = normal_after(g, d, 3, 71);
    let deviation = deviation_after(g, d, 4, 72);
    assert_ne!(deviation.view().first_voted_node(), 4, "deviation form");
    let other_vote = reheader(&normal_after(g, d, 4, 74), 4, 0, 3, 0, key_of(4));
    assert_eq!(other_vote.view().consumed_votes(), 0);
    let consuming = reheader(&normal_after(g, d, 4, 73), 4, 7, 4, 0, key_of(4));
    assert_eq!(d.view().creator(), 4);
    [
        (foreign, ValidationReason::RunCreator),
        (deviation, ValidationReason::RunHeader),
        (other_vote, ValidationReason::RunHeader),
        (consuming, ValidationReason::RunHeader),
    ]
}

/// AC4 rules 1–2 at intake on the direct extension of `d`: each violation
/// is exact evidence, not stored; the proposer's override replay passes.
#[test]
fn the_run_rules_refuse_a_direct_extension() {
    let (mut g, _, _, d, _) = proposer_chain(4);
    assert_eq!(receive(&mut g, &d), ReceiveBlockOutcome::AcceptedSilently);
    assert_eq!(g.active_open_run, 6);
    for (block, reason) in run_violations(&g, &d) {
        assert_eq!(step_reason(&mut g, &block), Some(reason));
        assert_eq!(
            receive(&mut g, &block),
            ReceiveBlockOutcome::Rejected(RejectReason::InvalidEvidence)
        );
        assert_eq!(entry_of(&g, &block), None, "not stored");
    }
    let replay = normal_after(&g, &d, 4, 2);
    assert_eq!(step_reason(&mut g, &replay), None);
    assert_eq!(
        receive(&mut g, &replay),
        ReceiveBlockOutcome::AcceptedSilently
    );
    assert_eq!(head_of(&g), (7, replay.view().hash()));
    assert_eq!(g.active_open_run, 6, "a replay keeps the run open");
}

/// AC4 rules 1–2 at intake on a side block (Tier 2, the header walk): `d`
/// is active below the replay head, and each violation beside the replay
/// is refused.
#[test]
fn the_run_rules_refuse_a_side_block() {
    let (mut g, _, _, d, _) = proposer_chain(4);
    assert_eq!(receive(&mut g, &d), ReceiveBlockOutcome::AcceptedSilently);
    let replay = normal_after(&g, &d, 4, 2);
    assert_eq!(
        receive(&mut g, &replay),
        ReceiveBlockOutcome::AcceptedSilently
    );
    for (block, _) in run_violations(&g, &d) {
        assert_eq!(
            receive(&mut g, &block),
            ReceiveBlockOutcome::Rejected(RejectReason::InvalidEvidence)
        );
        assert_eq!(entry_of(&g, &block), None, "not stored");
    }
    assert_eq!(head_of(&g), (7, replay.view().hash()));
}

/// AC4 at connect: a foreign block above the run that arrives before its
/// parent is judged when the parent's arrival connects it (the stored
/// child), and deleted.
#[test]
fn the_run_rules_judge_a_stored_child_at_connect() {
    let (mut g, _, _, d, _) = proposer_chain(4);
    assert_eq!(receive(&mut g, &d), ReceiveBlockOutcome::AcceptedSilently);
    let replay = normal_after(&g, &d, 4, 2);
    let foreign = normal_after(&g, &replay, 3, 3);
    assert_eq!(
        receive(&mut g, &foreign),
        ReceiveBlockOutcome::AcceptedSilently,
        "an orphan: its parent is not held"
    );
    assert!(entry_of(&g, &foreign).is_some());
    assert_eq!(
        receive(&mut g, &replay),
        ReceiveBlockOutcome::AcceptedSilently
    );
    assert_eq!(head_of(&g), (7, replay.view().hash()));
    assert_eq!(entry_of(&g, &foreign), None, "deleted at connect");
}

/// AC4 in the FR3 pass: a restart over storage holding a foreign block
/// above `d` refuses it (FR5) and goes Ready on `d`, whose open run the
/// pass derived (the Ready-entry value).
#[test]
fn the_run_rules_hold_in_the_pass() {
    let (mut g, _, _, d, _) = proposer_chain(4);
    assert_eq!(receive(&mut g, &d), ReceiveBlockOutcome::AcceptedSilently);
    let foreign = normal_after(&g, &d, 3, 2);
    let idx = g.blocks.next_free_index().expect("a free slot");
    g.storage.save_block(idx, &foreign).ok().expect("save");
    let mut restarted = local_node(0, g.storage);
    restarted.initialize_from_storage(500);
    assert!(restarted.is_ready());
    assert_eq!(head_of(&restarted), (6, d.view().hash()));
    assert_eq!(entry_of(&restarted, &foreign), None, "deleted by FR5");
    assert_eq!(restarted.active_open_run, 6, "the pass's final run state");
}

/// AC4 rule 3: a type-4 block closes an open run by its creator, naming
/// its `p`: another `p`, another creator, and no open run (after the run
/// closed) are exact evidence; the real one passes.
#[test]
fn an_evidence_must_close_an_open_run() {
    let (mut g, d, e) = evidence_observer(4);
    let ev = evidence_of(&e, 2);
    let wrong_p = evidence_with(&e, 2, |ev| ev.deviation_sequence = 5);
    let by_other = evidence_block(7, d.view().hash(), 3, &ev);
    for (block, reason) in [
        (wrong_p, ValidationReason::EvidencePlacement),
        (by_other, ValidationReason::RunCreator),
    ] {
        assert_eq!(step_reason(&mut g, &block), Some(reason));
        assert_eq!(
            receive(&mut g, &block),
            ReceiveBlockOutcome::Rejected(RejectReason::InvalidEvidence)
        );
    }
    assert_eq!(receive(&mut g, &e), ReceiveBlockOutcome::AcceptedSilently);
    let no_run = evidence_block(8, e.view().hash(), 4, &ev);
    assert_eq!(
        step_reason(&mut g, &no_run),
        Some(ValidationReason::EvidencePlacement)
    );
    assert_eq!(
        receive(&mut g, &no_run),
        ReceiveBlockOutcome::Rejected(RejectReason::InvalidEvidence)
    );
    assert_eq!(head_of(&g), (7, e.view().hash()));
}

/// A block by `creator` at `seq` in override form (no ancestry: the rules
/// read only its bytes and the run).
fn override_at(seq: u32, creator: u32) -> Block {
    reheader(
        &transfer(seq, [0x5A; 32], 1, 1),
        creator,
        0,
        creator,
        0,
        key_of(creator),
    )
}

/// AC4 rule 4 (D1): with `p = 6`, `H = 8`, a replay ends at `p + H − 1 =
/// 13` and the evidence at `p + H = 14`; a tentative configuration (no
/// `H`) judges no bound.
#[test]
fn the_run_bound_admits_replays_to_p_plus_h_minus_one() {
    let (_, e, _) = evidence_by(5);
    let ev = evidence_of(&e, 2);
    let run = Some((6, 5));
    let h = Some(TEST_H);
    let last = 6 + TEST_H;
    let bound = Err(ValidationReason::RunBound);
    assert_eq!(run_rules(&override_at(last - 1, 5).view(), run, h), Ok(()));
    assert_eq!(run_rules(&override_at(last, 5).view(), run, h), bound);
    let evidence_at = |seq: u32| evidence_block(seq, [0x5A; 32], 5, &ev);
    assert_eq!(run_rules(&evidence_at(last).view(), run, h), Ok(()));
    assert_eq!(run_rules(&evidence_at(last + 1).view(), run, h), bound);
    assert_eq!(
        run_rules(&override_at(last, 5).view(), run, None),
        Ok(()),
        "no locked H: no verdict"
    );
}

/// AC4 rule 5 (D8): at a slot (`s ≡ H − 1`) a node-transfer block, an
/// evidence block and a complex transaction with only a balance output
/// are clean; a registration, a UTXO output, a balance block and a
/// chain-config block are not. Off the slots (`H − 2`, `H`, genesis) all
/// pass, and without a locked `H` nothing is judged.
#[test]
fn a_slot_holds_only_clean_blocks() {
    let (_, e, _) = evidence_by(4);
    let ev = evidence_of(&e, 2);
    let h = TEST_H;
    let blocks = |seq: u32| -> [(Block, bool); 9] {
        let prev = [0x5A; 32];
        let utxo = utxo_tx(seq, &[], Some((1, 100)), &[Ok(60)]);
        let balance_only = utxo_tx(seq, &[], Some((1, 100)), &[Err((2, 100))]);
        let mixed = utxo_tx(seq, &[], Some((1, 100)), &[Err((2, 40)), Ok(60)]);
        [
            // Every transaction and every output counts (review).
            (
                complex_tx_block(seq, prev, 3, 0, &[&balance_only, &utxo]),
                false,
            ),
            (complex_tx_block(seq, prev, 3, 0, &[&mixed]), false),
            (transfer(seq, prev, 1, 1), true),
            (evidence_block(seq, prev, 4, &ev), true),
            (complex_tx_block(seq, prev, 3, 0, &[&balance_only]), true),
            (register(seq, prev, 6, key_of(6)), false),
            (complex_tx_block(seq, prev, 3, 0, &[&utxo]), false),
            (balance_block(seq, prev, &[(0, 1, 0, 1)], 5), false),
            (
                chain_config_block_from(seq, prev, &mut window_config_builder(TEST_W)),
                false,
            ),
        ]
    };
    for (block, clean) in blocks(h - 1).iter().chain(&blocks(2 * h - 1)) {
        assert_eq!(
            slot_rule(&block.view(), Some(h)).is_ok(),
            *clean,
            "at {}: type {}",
            block.view().sequence(),
            block.view().payload_type()
        );
        assert_eq!(slot_rule(&block.view(), None), Ok(()), "no locked H");
    }
    for seq in [h - 2, h, 2 * h] {
        for (block, _) in blocks(seq) {
            assert_eq!(slot_rule(&block.view(), Some(h)), Ok(()), "off the slots");
        }
    }
    let genesis = chain_config_block_from(0, [0; 32], &mut window_config_builder(TEST_W));
    assert_eq!(slot_rule(&genesis.view(), Some(h)), Ok(()), "#0 is no slot");
}

/// AC4 rule 5 end to end: on Story 6.4's chain (`H = 8`) the slot #7
/// refuses a registration at intake and admits a transfer; a registration
/// at #6, off the slot, passes the step.
#[test]
fn a_ready_node_refuses_unclean_content_at_a_slot() {
    let (mut g, _, blocks) = support_chain(3);
    let at_six = real_on(
        &g,
        &register(6, blocks[5].view().hash(), 6, key_of(6)),
        0,
        1,
    );
    assert_eq!(step_reason(&mut g, &at_six), None, "off the slot");
    let x6 = normal_after(&g, &blocks[5], 2, 61);
    assert_eq!(receive(&mut g, &x6), ReceiveBlockOutcome::AcceptedSilently);
    let at_seven = real_on(&g, &register(7, x6.view().hash(), 6, key_of(6)), 0, 1);
    assert_eq!(
        step_reason(&mut g, &at_seven),
        Some(ValidationReason::SlotNotClean)
    );
    assert_eq!(
        receive(&mut g, &at_seven),
        ReceiveBlockOutcome::Rejected(RejectReason::InvalidEvidence)
    );
    let clean = normal_after(&g, &x6, 2, 62);
    assert_eq!(
        receive(&mut g, &clean),
        ReceiveBlockOutcome::AcceptedSilently
    );
    assert_eq!(head_of(&g), (7, clean.view().hash()));
}

/// AC4 (D4): `active_open_run` after each event — a deviation's commit
/// opens it, a replay keeps it, the evidence (built over the replay:
/// the rewind over two blocks) closes it, and the FR5 recovery resets it.
#[test]
fn the_open_run_follows_the_head() {
    let (mut g, mut l, _, d, d_idx) = proposer_chain(4);
    assert_eq!(g.active_open_run, NO_OPEN_RUN);
    assert_eq!(receive(&mut g, &d), ReceiveBlockOutcome::AcceptedSilently);
    assert_eq!(g.active_open_run, 6);
    let replay = normal_after(&g, &d, 4, 2);
    for node in [&mut g, &mut l] {
        assert_eq!(
            receive(node, &replay),
            ReceiveBlockOutcome::AcceptedSilently
        );
    }
    assert_eq!(g.active_open_run, 6);
    accumulate(&mut l, &d, d_idx, 2);
    let tip = l.active_chain_head_idx;
    let e = l
        .build_evidence_block(tip, 0)
        .expect("evidence over the replay");
    assert_eq!(e.view().sequence(), 8);
    let verified = counted(&AGGREGATE_VERIFICATIONS);
    assert_eq!(receive(&mut g, &e), ReceiveBlockOutcome::AcceptedSilently);
    assert_eq!(head_of(&g), (8, e.view().hash()));
    assert_eq!(counted(&AGGREGATE_VERIFICATIONS) - verified, 1);
    assert_eq!(g.active_open_run, NO_OPEN_RUN);
    l.lifecycle_phase = LifecyclePhase::Processing;
    assert_eq!(l.active_open_run, 6);
    l.recover_from_failed_pass(ProcessingError::StorageRead, NONE_REF);
    assert_eq!(l.active_open_run, NO_OPEN_RUN, "FR5 resets it");
}

/// AC4 (D4): a window-anchored pass trusts rules 1–4 while the run state
/// is unknown — a foreign block over an open run passes — and a
/// deviation-form block or an evidence block settles it (taken as no run,
/// the evidence would be misplaced); the slot rule applies throughout.
#[test]
fn an_unknown_run_state_trusts_rules_one_to_four() {
    let (mut g, d, e) = evidence_observer(4);
    let foreign = normal_after(&g, &d, 3, 71);
    let judge = |g: &mut SupportChain, block: &Block, projection: &mut Projection| {
        let view = block.view();
        let idx = g.blocks.next_free_index().expect("a free slot");
        let mut entry = BlockEntry::new(view.hash(), g.active_chain_head_idx, view.sequence());
        entry.set_payload_type(view.payload_type());
        g.blocks.insert_at(idx, entry);
        let verdict = g.check_run_rules(&view, idx, projection);
        g.blocks.delete(idx);
        run_rule_reason(verdict)
    };
    let mut unknown = Projection {
        run_unknown_below: 100,
        ..Projection::COMPLETE
    };
    assert_eq!(judge(&mut g, &foreign, &mut unknown), Ok(()), "trusted");
    assert_eq!(
        unknown.run_unknown_below, 100,
        "a normal block settles nothing"
    );
    let unclean = real_on(
        &g,
        &register(7, d.view().hash(), 6, key_of(6)),
        3,
        key_of(3),
    );
    assert_eq!(
        judge(&mut g, &unclean, &mut unknown),
        Err(ValidationReason::SlotNotClean),
        "the slot rule still applies"
    );
    let mut settled_by_evidence = Projection {
        run_unknown_below: 100,
        ..Projection::COMPLETE
    };
    assert_eq!(judge(&mut g, &e, &mut settled_by_evidence), Ok(()));
    assert_eq!(
        settled_by_evidence.run_unknown_below, 0,
        "an evidence settles it"
    );
    let deviation = deviation_after(&g, &d, 3, 72);
    assert_eq!(judge(&mut g, &deviation, &mut unknown), Ok(()));
    assert_eq!(unknown.run_unknown_below, 0, "a deviation settles it");
    assert_eq!(
        judge(&mut g, &foreign, &mut unknown),
        Err(ValidationReason::RunCreator),
        "exact from then on"
    );
}

/// `check_run_rules` for `block` on a scratch child of the head, and the
/// storage reads it made.
fn run_rule_reads(
    bc: &mut Chain16<FailingSupportStorage>,
    block: &Block,
) -> (Result<(), ValidationReason>, u32) {
    let view = block.view();
    let idx = bc.blocks.next_free_index().expect("a free slot");
    let mut entry = BlockEntry::new(view.hash(), bc.active_chain_head_idx, view.sequence());
    entry.set_payload_type(view.payload_type());
    bc.blocks.insert_at(idx, entry);
    let mut projection = Projection::COMPLETE;
    let reads = bc.storage.reads.get();
    let verdict = bc.check_run_rules(&view, idx, &mut projection);
    let read = bc.storage.reads.get() - reads;
    bc.blocks.delete(idx);
    (run_rule_reason(verdict), read)
}

/// A `check_run_rules` verdict as its evidence reason; a local fault is not
/// expected where this is used.
fn run_rule_reason(verdict: Result<(), ProcessingError>) -> Result<(), ValidationReason> {
    verdict.map_err(|err| match err {
        ProcessingError::Invalid { reason, .. } => reason,
        _ => panic!("a local fault, not a verdict"),
    })
}

/// `deviation_run_at(idx)` and the storage reads it made.
fn walk_reads(
    bc: &Chain16<FailingSupportStorage>,
    idx: u32,
) -> (Result<Option<(u32, u32)>, ()>, u32) {
    let reads = bc.storage.reads.get();
    let run = bc.deviation_run_at(idx);
    (run, bc.storage.reads.get() - reads)
}

/// AC4 (D4) read counts: the head's rules read nothing outside a run and
/// `d`'s header once inside one; the side walk stops on a normal header
/// (one read), walks a run to its `d`, and reads nothing above a type-4
/// entry (the RAM flag).
#[test]
fn the_run_rules_read_only_inside_a_run() {
    let (_, e, _) = evidence_by(4);
    let (mut g, mut l, blocks) = support_chain_on(3, failing_storage(3), 16, |_| {});
    let x6 = normal_after(&g, &blocks[5], 2, 61);
    assert_eq!(run_rule_reads(&mut l, &x6), (Ok(()), 0), "no run: RAM only");
    let a4 = l.blocks.find(4, &blocks[4].view().hash()).expect("#4");
    assert_ne!(blocks[4].view().consumed_votes(), 0);
    assert_eq!(walk_reads(&l, a4), (Ok(None), 1), "a normal header ends it");

    let d = deviation_after(&g, &blocks[5], 4, 1);
    assert_eq!(receive(&mut g, &d), ReceiveBlockOutcome::AcceptedSilently);
    assert_eq!(receive(&mut l, &d), ReceiveBlockOutcome::AcceptedSilently);
    let d_idx = l.active_chain_head_idx;
    let replay = normal_after(&g, &d, 4, 2);
    assert_eq!(run_rule_reads(&mut l, &replay), (Ok(()), 1), "d's header");
    assert_eq!(walk_reads(&l, d_idx), (Ok(Some((6, 4))), 1));
    assert_eq!(
        receive(&mut l, &replay),
        ReceiveBlockOutcome::AcceptedSilently
    );
    assert_eq!(
        walk_reads(&l, l.active_chain_head_idx),
        (Ok(Some((6, 4))), 2),
        "the replay, then d"
    );
    plant_child(&mut l, &e, d_idx, true, true);
    let e_idx = l.blocks.find(7, &e.view().hash()).expect("planted");
    assert_eq!(
        walk_reads(&l, e_idx),
        (Ok(None), 0),
        "a closed run: no read"
    );
}

/// AC4: a failed read in the side block's header walk is no evidence:
/// the foreign block above `d` (whose header cannot be read) is admitted,
/// not refused; readable, the same block is refused.
#[test]
fn a_read_fault_in_the_walk_is_not_evidence() {
    let (_, e, _) = evidence_by(4);
    for fault in [true, false] {
        walk_fault_case(&e, fault);
    }
}

fn walk_fault_case(e: &Block, fault: bool) {
    let (mut g, mut l, blocks) = support_chain_on(3, failing_storage(3), 16, |_| {});
    let d = deviation_after(&g, &blocks[5], 4, 1);
    assert_eq!(receive(&mut g, &d), ReceiveBlockOutcome::AcceptedSilently);
    for block in [&d, e] {
        assert_eq!(
            receive(&mut l, block),
            ReceiveBlockOutcome::AcceptedSilently
        );
    }
    assert_eq!(
        head_of(&l),
        (7, e.view().hash()),
        "the run closed on the head"
    );
    let foreign = normal_after(&g, &d, 3, 71);
    if fault {
        l.storage.failing_slot = l.blocks.find(6, &d.view().hash()).expect("d");
        assert_eq!(
            receive(&mut l, &foreign),
            ReceiveBlockOutcome::AcceptedSilently,
            "no verdict"
        );
        assert!(entry_of(&l, &foreign).is_some(), "held, not deleted");
    } else {
        assert_eq!(
            receive(&mut l, &foreign),
            ReceiveBlockOutcome::Rejected(RejectReason::InvalidEvidence)
        );
    }
    assert_eq!(head_of(&l), (7, e.view().hash()));
}

/// AC4 (D4) — in Ready, a block whose held parent is only Stored (neither
/// the head nor Connected) is judged at intake too, by the header walk: a
/// foreign block above a stored deviation is refused before its write.
#[test]
fn a_block_on_a_stored_deviation_is_judged_at_intake() {
    let (mut g, mut l, blocks) = support_chain(3);
    let d = deviation_after(&g, &blocks[5], 4, 1);
    assert_eq!(receive(&mut g, &d), ReceiveBlockOutcome::AcceptedSilently);
    plant(&mut l, &d, false, true);
    let foreign = normal_after(&g, &d, 3, 71);
    assert_eq!(
        receive(&mut l, &foreign),
        ReceiveBlockOutcome::Rejected(RejectReason::InvalidEvidence)
    );
    assert!(entry_of(&l, &foreign).is_none(), "not stored");
}

/// AC4 — a failed read of `d`'s header in the per-block step gives no
/// verdict: the block above the open run is held Stored, neither refused
/// nor applied or marked, and the run state stays (local I/O is never
/// evidence and never acceptance). Regression: it used to be committed.
#[test]
fn an_unreadable_deviation_header_neither_refuses_nor_applies() {
    let (mut g, mut l, blocks) = support_chain_on(3, failing_storage(3), 16, |_| {});
    let d = deviation_after(&g, &blocks[5], 4, 1);
    assert_eq!(receive(&mut g, &d), ReceiveBlockOutcome::AcceptedSilently);
    assert_eq!(receive(&mut l, &d), ReceiveBlockOutcome::AcceptedSilently);
    assert_eq!(l.active_open_run, 6);
    let foreign = normal_after(&g, &d, 3, 71);
    l.storage.failing_slot = l.blocks.find(6, &d.view().hash()).expect("d");
    assert_eq!(
        receive(&mut l, &foreign),
        ReceiveBlockOutcome::AcceptedSilently,
        "no verdict"
    );
    assert_eq!(head_of(&l), (6, d.view().hash()), "not applied");
    let (status, on_chain, accepted, _) = entry_of(&l, &foreign).expect("held");
    assert!(status == BlockStatus::Stored && !on_chain && !accepted);
    assert_eq!(l.active_open_run, 6);
}

// -- Story 6.7 code review (production code): the regressions --

/// Review (header-walk faults) — genesis #0 is never inside a run: the
/// walk from it answers "no run", not "unknown".
#[test]
fn the_run_walk_ends_at_genesis() {
    let (_, l, blocks) = support_chain(3);
    let genesis = l.blocks.find(0, &blocks[0].view().hash()).expect("#0");
    assert_eq!(l.deviation_run_at(genesis), Ok(None));
}

/// Review (header-walk faults) — at intake an unreadable ancestry still
/// judges the slot rule, which reads the block alone: a balance block at a
/// slot above a Stored deviation whose header cannot be read is refused
/// before its write, while a clean block there gets no verdict (held).
#[test]
fn an_unreadable_ancestry_still_judges_the_slot_at_intake() {
    let (mut g, mut l, blocks) = support_chain_on(3, failing_storage(3), 16, |_| {});
    let h = l.verification_horizon().expect("locked");
    assert_eq!(7 % h, h - 1, "#7 is a slot");
    let d = deviation_after(&g, &blocks[5], 4, 1);
    assert_eq!(receive(&mut g, &d), ReceiveBlockOutcome::AcceptedSilently);
    plant(&mut l, &d, false, true);
    l.storage.failing_slot = l.blocks.find(6, &d.view().hash()).expect("d");
    let template = balance_snapshot(&g, 7, d.view().hash(), &[2]);
    let unclean = reheader(&template, 4, 0, 4, 0, key_of(4));
    assert_eq!(
        receive(&mut l, &unclean),
        ReceiveBlockOutcome::Rejected(RejectReason::InvalidEvidence)
    );
    assert!(entry_of(&l, &unclean).is_none(), "not stored");
    let clean = normal_after(&g, &d, 4, 71);
    assert_eq!(
        receive(&mut l, &clean),
        ReceiveBlockOutcome::AcceptedSilently,
        "no verdict"
    );
    let (status, on_chain, accepted, _) = entry_of(&l, &clean).expect("held");
    assert!(status == BlockStatus::Stored && !on_chain && !accepted);
}

/// Review (AC10, D3) — only the local node's own evidence above `d`
/// releases its accumulator: another creator's evidence held above `d`
/// (it can be held unjudged after a walk fault at intake; planted here)
/// does not.
#[test]
fn a_foreign_evidence_above_d_does_not_release() {
    let (_, e, _) = evidence_by(4);
    let ev = evidence_of(&e, 2);
    let (_, mut l, _, d, d_idx) = proposer_chain(5);
    assert!(l.open_approval(d_idx));
    let foreign = evidence_block(7, d.view().hash(), 3, &ev);
    plant_child(&mut l, &foreign, d_idx, true, true);
    assert!(l.approval_live(), "not the proposer's");
    let own = evidence_block(7, d.view().hash(), 5, &ev);
    plant_child(&mut l, &own, d_idx, true, true);
    assert!(!l.approval_live(), "the proposer's own releases");
}

/// Review (AC8) — outside the pass the evidence check reads the
/// active-set counter only while it is valid: an invalid counter is a
/// local fault, never an `EvidenceSubgroup` verdict.
#[test]
fn an_invalid_counter_is_a_local_fault() {
    let (mut g, _, e) = evidence_observer(4);
    let ready = ready_projection(&g);
    g.active_set.invalidate();
    assert_eq!(judge_on(&mut g, &e, &ready), Err(None));
}

/// Review (AC5 step 1) — the pass builds its own counter over the window
/// at `p − 1`; a read fault there leaves it invalid: a local fault, no
/// verdict and nothing verified. The control: the same pass without the
/// fault accepts.
#[test]
fn a_window_read_fault_in_the_pass_is_local() {
    let (d, r, e, _) = replay_evidence();
    let pass = || Projection {
        counter_tail: u32::MAX,
        ..Projection::COMPLETE
    };
    let mut l = failing_observer(&d, &r);
    assert_eq!(judge_on(&mut l, &e, &pass()), Ok(()), "the control");
    let mut l = failing_observer(&d, &r);
    l.storage.failing_slot = l
        .ancestor_at(l.active_chain_head_idx, 3)
        .ok()
        .flatten()
        .expect("#3 in the window");
    let verified = counted(&AGGREGATE_VERIFICATIONS);
    assert_eq!(judge_on(&mut l, &e, &pass()), Err(None));
    assert!(l.storage.attempts.get() > 0, "the window read was hit");
    assert_eq!(counted(&AGGREGATE_VERIFICATIONS), verified);
}

/// Review (AC8) — a failed restore inside the FR3 pass is the pass's own
/// local failure: it does not also mark the root's re-entry due (a
/// second, spurious re-entry). Every read budget of `r` is tried; at least
/// one hits the restore (the engine is left changed). The control: the
/// same fault under Ready's projection marks it.
#[test]
fn a_failed_restore_in_the_pass_marks_no_reentry() {
    let (d, r, e, _) = replay_evidence();
    for in_pass in [true, false] {
        let mut restore_failures = 0;
        for reads in 0..4 {
            let mut l = failing_observer(&d, &r);
            let projection = if in_pass {
                Projection {
                    counter_tail: u32::MAX,
                    ..Projection::COMPLETE
                }
            } else {
                ready_projection(&l)
            };
            let before = engine_votes(&l);
            l.storage.failing_slot = l.active_chain_head_idx;
            l.storage.reads_left.set(reads);
            l.storage.failures_left.set(1);
            let verdict = judge_on(&mut l, &e, &projection);
            let restore_failed = engine_votes(&l) != before;
            if restore_failed {
                restore_failures += 1;
                assert_eq!(verdict, Err(None), "reads {reads}");
            }
            assert_eq!(
                l.reentry_due,
                restore_failed && !in_pass,
                "in the pass {in_pass}, reads {reads}"
            );
        }
        assert!(restore_failures > 0, "a restore failed (pass {in_pass})");
    }
}

// -- AC5 / AC6: the Tier-3 evidence check and the accepted mark --

/// AC5 / AC6: a valid evidence admitted by a second node as a direct
/// extension is verified exactly once, marked "signatures accepted" (bit
/// 6 with bit 5), and closes the run.
#[test]
fn a_valid_evidence_is_verified_once_and_marked() {
    let (mut g, _, e) = evidence_observer(4);
    let verified = counted(&AGGREGATE_VERIFICATIONS);
    assert_eq!(receive(&mut g, &e), ReceiveBlockOutcome::AcceptedSilently);
    assert_eq!(head_of(&g), (7, e.view().hash()));
    assert_eq!(counted(&AGGREGATE_VERIFICATIONS) - verified, 1);
    let (_, active, accepted, verified) = entry_of(&g, &e).expect("held");
    assert!(active && accepted && verified);
    assert_eq!(g.active_open_run, NO_OPEN_RUN);
}

/// AC6 (D2): the one marker sets bits 6 and 5 together; an empty slot is
/// refused.
#[test]
fn the_accepted_mark_sets_both_bits() {
    let mut table = BlockTable::<4, TEST_UTXO_BYTES>::new();
    let idx = table
        .insert(BlockEntry::new([7; 32], NONE_REF, 3))
        .expect("a slot");
    let bits = |table: &BlockTable<4, TEST_UTXO_BYTES>| {
        let entry = table.get(idx).expect("held");
        (
            entry.is_signatures_accepted(),
            entry.is_signature_verified(),
        )
    };
    assert_eq!(bits(&table), (false, false));
    assert!(table.mark_signatures_accepted(idx));
    assert_eq!(bits(&table), (true, true), "bit 6 implies bit 5");
    assert!(!table.mark_signatures_accepted(idx + 1), "an empty slot");
    table.clear_signatures_accepted();
    assert_eq!(bits(&table), (false, true), "the pass clears bit 6 only");
}

/// One invalid family: `mutate` applied to `proposer`'s evidence (with
/// two signers) gives `reason` from the check, the block is refused at
/// intake and not stored, and the real evidence passes afterwards.
fn refused_evidence_case(
    proposer: u32,
    reason: ValidationReason,
    mutate: impl FnOnce(&mut Evidence),
) {
    let (mut g, _, e) = evidence_observer(proposer);
    let bad = evidence_with(&e, 2, mutate);
    let ready = ready_projection(&g);
    assert_eq!(judge_on(&mut g, &bad, &ready), Err(Some(reason)));
    assert_eq!(
        receive(&mut g, &bad),
        ReceiveBlockOutcome::Rejected(RejectReason::InvalidEvidence)
    );
    assert_eq!(entry_of(&g, &bad), None, "not stored");
    assert_eq!(head_of(&g).0, 6);
    assert_eq!(receive(&mut g, &e), ReceiveBlockOutcome::AcceptedSilently);
    assert_eq!(head_of(&g), (7, e.view().hash()), "the control");
}

/// AC5 step 2: a wrong `m`, or fewer than `r_eff` signers (one support,
/// its own valid aggregate), is `EvidenceSubgroup`.
#[test]
fn a_wrong_subgroup_is_refused() {
    refused_evidence_case(4, ValidationReason::EvidenceSubgroup, |ev| ev.m += 1);
    let (d, _, members) = evidence_by(4);
    let hash = d.view().hash();
    refused_evidence_case(4, ValidationReason::EvidenceSubgroup, |ev| {
        ev.bitmap = std::vec![0b01];
        ev.aggregate = aggregate_by(&members[..1], 4, 6, &hash);
    });
}

/// AC5 step 4: `supporter_vote_sum` one above or below `B_k − cv(d)` is
/// `EvidenceVoteSum`, before any aggregate verification.
#[test]
fn a_wrong_vote_sum_is_refused() {
    let verified = counted(&AGGREGATE_VERIFICATIONS);
    refused_evidence_case(4, ValidationReason::EvidenceVoteSum, |ev| {
        ev.supporter_vote_sum += 1
    });
    refused_evidence_case(4, ValidationReason::EvidenceVoteSum, |ev| {
        ev.supporter_vote_sum -= 1
    });
    assert_eq!(
        counted(&AGGREGATE_VERIFICATIONS) - verified,
        2,
        "only the two controls are verified"
    );
}

/// AC5 step 4: proposer 2's late list (nodes 5 and 0) dropped, extended,
/// reordered, or with a wrong value at the tip is `EvidenceLateList`.
#[test]
fn a_wrong_late_list_is_refused() {
    let (_, e, _) = evidence_by(2);
    assert_eq!(evidence_of(&e, 2).late.len(), 2, "two late entries");
    let late = ValidationReason::EvidenceLateList;
    refused_evidence_case(2, late, |ev| {
        ev.late.pop();
    });
    refused_evidence_case(2, late, |ev| ev.late.push((4, 0)));
    refused_evidence_case(2, late, |ev| ev.late.swap(0, 1));
    refused_evidence_case(2, late, |ev| ev.late[0].1 += 1);
    // Review: the right count, one listed id wrong — beyond the roster
    // (99), or a registered node that is not late at `p − 1`.
    for id in [99, 1, 2, 4] {
        refused_evidence_case(2, late, |ev| ev.late[1].0 = id);
    }
    // `u` heads the order, so in front of node 0, with its true value at
    // the tip, it keeps the order, the count of late nodes above the last
    // entry and the values: only "late" refuses it.
    let (g, d, _) = evidence_observer(2);
    let u = d.view().first_voted_node();
    let at_tip = g
        .vote_engine
        .grown(g.vote_engine.accumulated_vote_of(u))
        .expect("grown");
    refused_evidence_case(2, late, |ev| ev.late[0] = (u, at_tip));
}

/// AC5 step 5: a corrupted aggregate byte (the framing kept) is
/// `EvidenceAggregate`. Under BLS a `count` other than the population
/// also ends there; under Schnorr the framing refuses it at Tier 1, before
/// any verification. AC13.4: under Schnorr the keys enter in rank order,
/// so an aggregate over the signers in swapped order does not verify (a
/// BLS aggregate is order-free).
#[test]
fn a_wrong_aggregate_is_refused() {
    refused_evidence_case(4, ValidationReason::EvidenceAggregate, |ev| {
        let last = ev.aggregate.len() - 1;
        ev.aggregate[last] ^= 1;
    });
    #[cfg(not(feature = "schnorr"))]
    refused_evidence_case(4, ValidationReason::EvidenceAggregate, |ev| {
        ev.aggregate[1] = ev.aggregate[1].wrapping_add(1)
    });
    #[cfg(feature = "schnorr")]
    {
        let (mut g, _, e) = evidence_observer(4);
        let bad = evidence_with(&e, 2, |ev| {
            ev.aggregate[1] = ev.aggregate[1].wrapping_add(1)
        });
        let verified = counted(&AGGREGATE_VERIFICATIONS);
        assert_eq!(
            receive(&mut g, &bad),
            ReceiveBlockOutcome::Rejected(RejectReason::InvalidEvidence)
        );
        assert_eq!(counted(&AGGREGATE_VERIFICATIONS), verified, "Tier 1");
        assert_eq!(head_of(&g).0, 6);

        let (d, e, members) = evidence_by(4);
        assert_eq!(evidence_of(&e, 2).bitmap, [0b011], "ranks 0 and 1");
        let hash = d.view().hash();
        refused_evidence_case(4, ValidationReason::EvidenceAggregate, |ev| {
            ev.aggregate = aggregate_by(&[members[1], members[0]], 4, 6, &hash)
        });
    }
}

/// The other valid evidence of proposer 2's deviation: ranks 0 and 2 of
/// `m = 3` marked instead of 0 and 1 (FR27 accepts any `n ≥ r_eff`).
fn alternative_evidence(d: &Block, e: &Block, members: &[u32]) -> Block {
    let hash = d.view().hash();
    evidence_with(e, 2, |ev| {
        assert_eq!(ev.bitmap, [0b011]);
        ev.bitmap = std::vec![0b101];
        ev.aggregate = aggregate_by(&[members[0], members[2]], 2, 6, &hash);
    })
}

/// A block by node 5 on `e_alt`, which a node holding `d`, `e_alt` builds
/// (any deviation and its evidence). Node 5 holds the chain's only vote
/// (1 000 at #5), so `x8` is worth more than 0 and the twin branch outranks
/// the active one by value, not by a hash-dependent tie-break.
fn child_of_alternative(d: &Block, e_alt: &Block) -> Block {
    let (mut g, _, _) = support_chain(2);
    for block in [d, e_alt] {
        assert_eq!(
            receive(&mut g, block),
            ReceiveBlockOutcome::AcceptedSilently
        );
    }
    assert_eq!(head_of(&g), (7, e_alt.view().hash()));
    normal_after(&g, e_alt, 5, 81)
}

/// Story 6.12 (FR70, DEC-273) — a second valid evidence of one deviation
/// is a twin: `e` and `e'` are the proposer's two children of `d` (FR16
/// admits only its blocks above `d`). FR21 ranks the twin branch above the
/// active one at `e'` or at `x8` (which, depends on the scheme's hashes and
/// sizes; the pre-6.12 test switched under every scheme); it is held
/// wherever it is compared, the node stays on the evidence it adopted first, `e'` is never
/// judged (no aggregate verification), and the values are exact. An honest proposer
/// never builds it (`holds_own_evidence`); Story 6.13's verdict lifts the
/// hold.
#[test]
fn a_second_evidence_of_one_deviation_is_a_held_twin() {
    let (d, e, members) = evidence_by(2);
    let e_alt = alternative_evidence(&d, &e, &members);
    let x8 = child_of_alternative(&d, &e_alt);
    let (mut g, _, built) = evidence_observer(2);
    assert_eq!(built.serialized_bytes(), e.serialized_bytes());
    assert_eq!(receive(&mut g, &e), ReceiveBlockOutcome::AcceptedSilently);
    let verified = counted(&AGGREGATE_VERIFICATIONS);
    assert_eq!(
        receive(&mut g, &e_alt),
        ReceiveBlockOutcome::AcceptedSilently
    );
    let alt_i = g.blocks.find(7, &e_alt.view().hash()).expect("held");
    let ranked_alt = g.switch_target([Some(alt_i), None]).is_some();
    assert_eq!(head_of(&g), (7, e.view().hash()), "held");
    assert_eq!(receive(&mut g, &x8), ReceiveBlockOutcome::AcceptedSilently);
    let x8i = g.blocks.find(8, &x8.view().hash()).expect("held");
    let ranked_x8 = g.switch_target([Some(x8i), None]).is_some();
    assert!(
        ranked_alt || ranked_x8,
        "FR21 ranks the twin branch first at one admission"
    );
    assert_eq!(head_of(&g), (7, e.view().hash()), "still held");
    assert!(entry_of(&g, &e).expect("held").1);
    assert_eq!(
        entry_of(&g, &e_alt).map(|entry| (entry.0, entry.1)),
        Some((BlockStatus::Connected, false))
    );
    assert_eq!(
        counted(&AGGREGATE_VERIFICATIONS) - verified,
        0,
        "e' is never judged"
    );
    assert_eq!(g.active_branch_value, window_value(&g));
}

/// AC5 / AC6 / AC9 / AC4 — a switch over evidence on both branches, an
/// honest fork (Story 6.12): the active `d2, e2` (proposer 2) and the
/// heavier `d4, e4, x8` (proposer 4's deviation at the same #6, another
/// creator). The walk undoes `e2` and `d2` (exact inverses), applies `e4`
/// (verified once, the FR23 cross-check holds), and every value is exact.
#[test]
fn a_switch_judges_the_evidence_of_the_new_branch() {
    let (d4, e4, _) = evidence_by(4);
    let x8 = child_of_alternative(&d4, &e4);
    let (mut g, d2, e2) = evidence_observer(2);
    assert_eq!(receive(&mut g, &e2), ReceiveBlockOutcome::AcceptedSilently);
    assert_eq!(head_of(&g), (7, e2.view().hash()));
    let verified = counted(&AGGREGATE_VERIFICATIONS);
    for block in [&d4, &e4, &x8] {
        assert_eq!(
            receive(&mut g, block),
            ReceiveBlockOutcome::AcceptedSilently
        );
    }
    assert_eq!(head_of(&g), (8, x8.view().hash()), "switched");
    assert!(entry_of(&g, &e4).expect("held").1);
    assert!(!entry_of(&g, &e2).expect("held").1);
    assert!(!entry_of(&g, &d2).expect("held").1);
    assert_eq!(
        counted(&AGGREGATE_VERIFICATIONS) - verified,
        1,
        "e4 once, on the walk"
    );
    assert!(entry_of(&g, &e4).expect("held").2);
    assert_eq!(g.active_open_run, NO_OPEN_RUN);
    assert_eq!(g.active_branch_value, window_value(&g));
}

/// AC6 — a switch to an evidence block that lies below the old head's
/// sequence: the active `x6..x8` (node 2's, worth nothing) gives way to
/// node 4's `d@6, e@7`, judged on the walk with the engine at `d`
/// below the old head #8. (The window is not full on this fixture, so the
/// counter's tail is #0 and the correction range is empty.)
#[test]
fn a_switch_to_an_evidence_below_the_old_head() {
    let (d, e, _) = evidence_by(4);
    let (mut g, _, blocks) = support_chain(3);
    let x6 = normal_after(&g, &blocks[5], 2, 61);
    assert_eq!(receive(&mut g, &x6), ReceiveBlockOutcome::AcceptedSilently);
    let x7 = normal_after(&g, &x6, 2, 62);
    assert_eq!(receive(&mut g, &x7), ReceiveBlockOutcome::AcceptedSilently);
    let x8 = normal_after(&g, &x7, 2, 63);
    assert_eq!(receive(&mut g, &x8), ReceiveBlockOutcome::AcceptedSilently);
    for x in [&x6, &x7, &x8] {
        assert_eq!(x.view().consumed_votes(), 0, "worth nothing");
    }
    assert_eq!(head_of(&g), (8, x8.view().hash()));
    let verified = counted(&AGGREGATE_VERIFICATIONS);
    for block in [&d, &e] {
        assert_eq!(
            receive(&mut g, block),
            ReceiveBlockOutcome::AcceptedSilently
        );
    }
    assert_eq!(
        head_of(&g),
        (7, e.view().hash()),
        "the lighter-by-length branch"
    );
    assert_eq!(counted(&AGGREGATE_VERIFICATIONS) - verified, 1);
    assert_eq!(g.active_open_run, NO_OPEN_RUN);
    assert_eq!(g.active_branch_value, window_value(&g));
}

/// AC6 / AC9 / AC4 — an aborted switch over a junk claim: `other`'s
/// deviation with an evidence claiming `u64::MAX` (worth
/// `value_cap::<16>()`) outweighs the active branch of `active` (its `d`
/// and evidence, or its `d` and a replay: the run left open). The walk
/// undoes the active blocks, refuses the junk at its Tier 3 (the vote
/// sum, before any aggregate verification), restores, and deletes it. The
/// restore verifies nothing again — no aggregate, and of the transaction
/// signatures only the new branch's `d` — and every value and the open run
/// are as before.
fn junk_switch_case(active: u32, other: u32, with_evidence: bool) {
    let (d_other, e_other, _) = evidence_by(other);
    let junk = evidence_with(&e_other, 2, |ev| ev.supporter_vote_sum = u64::MAX);
    assert_eq!(block_value::<16>(&junk.view()), value_cap::<16>());
    let (mut g, d, e) = evidence_observer(active);
    let top = if with_evidence {
        e
    } else {
        normal_after(&g, &d, active, 2)
    };
    assert_eq!(receive(&mut g, &top), ReceiveBlockOutcome::AcceptedSilently);
    let head = head_of(&g);
    assert_eq!(head, (7, top.view().hash()));
    let run = if with_evidence { NO_OPEN_RUN } else { 6 };
    assert_eq!(g.active_open_run, run);
    assert_eq!(
        receive(&mut g, &d_other),
        ReceiveBlockOutcome::AcceptedSilently
    );
    assert_eq!(head_of(&g), head, "d_other alone is lighter");
    let other_idx = g
        .blocks
        .find(6, &d_other.view().hash())
        .expect("a side block");
    let values = (
        g.active_branch_value,
        g.chain_heads.branch_value_of(other_idx),
    );
    assert_eq!(values.0, window_value(&g));
    let (aggregates, signatures) = (
        counted(&AGGREGATE_VERIFICATIONS),
        counted(&TX_SIGNATURE_VERIFICATIONS),
    );
    assert_eq!(
        receive(&mut g, &junk),
        ReceiveBlockOutcome::AcceptedSilently
    );
    assert_eq!(entry_of(&g, &junk), None, "deleted by the walk");
    assert_eq!(head_of(&g), head, "restored");
    assert_eq!(g.active_open_run, run, "the exact inverse");
    assert_eq!(counted(&AGGREGATE_VERIFICATIONS), aggregates);
    let other_txs = d_other.view().transactions().expect("txs").iter().count() as u32;
    assert_eq!(
        counted(&TX_SIGNATURE_VERIFICATIONS) - signatures,
        other_txs,
        "only d_other's, forward"
    );
    assert_eq!(
        (
            g.active_branch_value,
            g.chain_heads.branch_value_of(other_idx)
        ),
        values
    );
    assert_eq!(g.active_branch_value, window_value(&g));
    let (_, active, accepted, _) = entry_of(&g, &top).expect("held");
    assert!(active && accepted);
}

#[test]
fn an_aborted_switch_restores_without_judging_again() {
    junk_switch_case(4, 5, true);
}

#[test]
fn an_aborted_switch_restores_an_open_run() {
    junk_switch_case(5, 4, false);
}

/// AC6: a local fault in the step (`d`'s header unreadable from its first
/// read, the run rules') leaves the direct extension Stored, unmarked and
/// off the chain; once the read works, a later admission's continuation
/// judges it as a stored child of the head and accepts it.
#[test]
fn a_local_fault_leaves_the_evidence_unjudged() {
    let (_, e, _) = evidence_by(4);
    let (mut g, mut l, blocks) = support_chain_on(3, failing_storage(3), 16, |_| {});
    let d = deviation_after(&g, &blocks[5], 4, 1);
    assert_eq!(receive(&mut l, &d), ReceiveBlockOutcome::AcceptedSilently);
    assert_eq!(receive(&mut g, &d), ReceiveBlockOutcome::AcceptedSilently);
    let d_idx = l.active_chain_head_idx;
    l.storage.failing_slot = d_idx;
    assert_eq!(receive(&mut l, &e), ReceiveBlockOutcome::AcceptedSilently);
    let (status, _, accepted, _) = entry_of(&l, &e).expect("held");
    assert_eq!(status, BlockStatus::Stored);
    assert!(!accepted, "never marked on a local fault");
    assert_eq!(head_of(&l), (6, d.view().hash()));
    l.storage.failing_slot = NONE_REF;
    let verified = counted(&AGGREGATE_VERIFICATIONS);
    let sibling = normal_after(&g, &blocks[5], 2, 91);
    assert_eq!(
        receive(&mut l, &sibling),
        ReceiveBlockOutcome::AcceptedSilently
    );
    assert_eq!(head_of(&l), (7, e.view().hash()), "the stored child");
    assert_eq!(counted(&AGGREGATE_VERIFICATIONS) - verified, 1);
    assert!(entry_of(&l, &e).expect("held").2);
}

/// AC5 step 1 / AC6 (review): the evidence check's own read of `d`'s
/// header fails — the run rules' read before it succeeds — so the check
/// gives no verdict: the evidence is held Stored, unmarked, off the chain,
/// and nothing is verified.
#[test]
fn an_unreadable_deviation_header_in_the_evidence_check_is_local() {
    let (_, e, _) = evidence_by(4);
    let (mut g, mut l, blocks) = support_chain_on(3, failing_storage(3), 16, |_| {});
    let d = deviation_after(&g, &blocks[5], 4, 1);
    assert_eq!(receive(&mut l, &d), ReceiveBlockOutcome::AcceptedSilently);
    assert_eq!(receive(&mut g, &d), ReceiveBlockOutcome::AcceptedSilently);
    l.storage.failing_slot = l.active_chain_head_idx;
    l.storage.reads_left.set(1);
    let verified = counted(&AGGREGATE_VERIFICATIONS);
    assert_eq!(receive(&mut l, &e), ReceiveBlockOutcome::AcceptedSilently);
    assert!(
        l.storage.attempts.get() >= 2,
        "the run rules read d, then the check"
    );
    let (status, on_chain, accepted, _) = entry_of(&l, &e).expect("held");
    assert!(status == BlockStatus::Stored && !on_chain && !accepted);
    assert_eq!(counted(&AGGREGATE_VERIFICATIONS), verified);
    assert_eq!(head_of(&l), (6, d.view().hash()));
}

/// AC6: after a restart (FR59) the genesis-anchored pass judges the
/// evidence again — one verification — and accepts it.
#[test]
fn a_restart_judges_the_evidence_again() {
    let (mut g, _, e) = evidence_observer(4);
    assert_eq!(receive(&mut g, &e), ReceiveBlockOutcome::AcceptedSilently);
    let mut restarted = local_node(0, g.storage);
    let verified = counted(&AGGREGATE_VERIFICATIONS);
    let (outcome, _) = restarted.initialize_from_storage(500);
    assert_eq!(outcome, InitOutcome::ResumedReady);
    assert_eq!(head_of(&restarted), (7, e.view().hash()));
    assert_eq!(counted(&AGGREGATE_VERIFICATIONS) - verified, 1, "re-judged");
    assert!(entry_of(&restarted, &e).expect("held").2);
    assert_eq!(restarted.active_open_run, NO_OPEN_RUN);
}

// -- AC7: the FR3 pass --

/// AC7: a genesis-anchored pass checks the evidence exactly: a restart
/// over storage holding an evidence with a wrong vote sum refuses it
/// (FR5) and goes Ready on `d`.
#[test]
fn a_genesis_anchored_pass_refuses_an_invalid_evidence() {
    let (mut g, d, e) = evidence_observer(4);
    let junk = evidence_with(&e, 2, |ev| ev.supporter_vote_sum += 1);
    let idx = g.blocks.next_free_index().expect("a free slot");
    g.storage.save_block(idx, &junk).ok().expect("save");
    let mut restarted = local_node(0, g.storage);
    restarted.initialize_from_storage(500);
    assert!(restarted.is_ready());
    assert_eq!(head_of(&restarted), (6, d.view().hash()));
    assert_eq!(entry_of(&restarted, &junk), None, "deleted by FR5");
}

/// AC7 (D5) unit-level on Story 6.4's chain (`W = 16 > p`): in a
/// window-anchored pass the window at `p − 1` never lies in the segment,
/// so a junk claim is trusted; a genesis-anchored pass checks it exactly.
#[test]
fn a_window_anchored_pass_trusts_an_evidence_without_its_window() {
    let (mut g, _, e) = evidence_observer(4);
    let junk = evidence_with(&e, 2, |ev| ev.supporter_vote_sum += 1);
    let verified = counted(&AGGREGATE_VERIFICATIONS);
    assert_eq!(
        judge_on(&mut g, &junk, &window_anchored(0)),
        Ok(()),
        "trusted"
    );
    assert_eq!(
        counted(&AGGREGATE_VERIFICATIONS),
        verified,
        "nothing verified"
    );
    let genesis = Projection {
        counter_tail: u32::MAX,
        ..Projection::COMPLETE
    };
    assert_eq!(
        judge_on(&mut g, &junk, &genesis),
        Err(Some(ValidationReason::EvidenceVoteSum))
    );
    assert_eq!(judge_on(&mut g, &e, &genesis), Ok(()));
    assert_eq!(counted(&AGGREGATE_VERIFICATIONS) - verified, 1);
}

/// Story 6.4's chain on `W = 8` (`H = 4`), with node 2's clean blocks
/// `x6`, `x7` and node 5's balance deviation `d@8` (listing node 2; it drops
/// #0, node #0's seed source, as its replay): the window at `p − 1` is
/// `[0, 7]`, so `p − W = 0`, and `A' = {0, 2, 3, 4}` (`m = 4`, `r_eff = 3`).
/// Returns node #0 at `d` and node 5's evidence (built, never admitted: its
/// own drop of #1 would need a chain-config replay).
fn w8_evidence() -> (SupportChain, Block) {
    let (mut g, mut l, blocks) = support_chain_on(5, local_storage(5), 8, |_| {});
    let x6 = normal_after(&g, &blocks[5], 2, 61);
    for node in [&mut g, &mut l] {
        assert_eq!(receive(node, &x6), ReceiveBlockOutcome::AcceptedSilently);
    }
    let x7 = normal_after(&g, &x6, 2, 62);
    for node in [&mut g, &mut l] {
        assert_eq!(receive(node, &x7), ReceiveBlockOutcome::AcceptedSilently);
    }
    let top = g.vote_engine.top_creator().expect("a top");
    let snapshot = |n| vote_snapshot(g.vote_engine.accumulated_vote_of(n));
    let template = balance_snapshot(&g, 8, x7.view().hash(), &[2]);
    let d = reheader(&template, 5, snapshot(5), top, snapshot(top), key_of(5));
    for node in [&mut g, &mut l] {
        assert_eq!(receive(node, &d), ReceiveBlockOutcome::AcceptedSilently);
        assert_eq!(head_of(node), (8, d.view().hash()));
    }
    let d_idx = l.active_chain_head_idx;
    accumulate(&mut l, &d, d_idx, 3);
    let e = l.build_evidence_block(d_idx, 0).expect("evidence");
    (g, e)
}

/// Review (D5) — the window condition is judged before `d` is resolved:
/// an evidence whose `d` the pass cannot resolve (here above the tip) is
/// trusted under `p − W < a`, and a local fault only in the exact zone.
#[test]
fn the_window_condition_is_judged_before_d() {
    let (mut g, e) = w8_evidence();
    let unresolvable = evidence_with(&e, 3, |ev| ev.deviation_sequence = 100);
    assert_eq!(
        judge_on(&mut g, &unresolvable, &window_anchored(200)),
        Ok(())
    );
    assert_eq!(
        judge_on(&mut g, &unresolvable, &window_anchored(0)),
        Err(None),
        "the exact zone"
    );
}

/// AC7 (D5) — the exact zone of a window-anchored pass. Nodes from #2 on
/// count as registered inside the segment; #0 (seed source #0) and #1
/// (seed source #2) are vote-seeded through their sources, below `p`. With
/// `p − W = a` the evidence is then checked exactly (the real one
/// verifies, a junk claim is refused); trusted when each condition fails
/// alone: `p − W = a − 1`, the roster unknown, node #0's source below
/// `vote_seed_from`, and node 2 judged by its source, which is `d` itself
/// (its balance lists node 2): seeded at `p` only, so its vote at `p − 1`
/// is not known to be exact.
#[test]
fn a_window_anchored_pass_checks_its_exact_zone() {
    let (mut g, e) = w8_evidence();
    let junk = evidence_with(&e, 3, |ev| ev.supporter_vote_sum += 1);
    let base = || Projection {
        first_segment_registration: 2,
        ..window_anchored(0)
    };
    let exact = base();
    let verified = counted(&AGGREGATE_VERIFICATIONS);
    assert_eq!(judge_on(&mut g, &e, &exact), Ok(()));
    assert_eq!(counted(&AGGREGATE_VERIFICATIONS) - verified, 1, "exact");
    assert_eq!(
        judge_on(&mut g, &junk, &exact),
        Err(Some(ValidationReason::EvidenceVoteSum)),
        "every node seeded below p: exact"
    );
    for (projection, why) in [
        (
            Projection {
                anchor: 1,
                ..base()
            },
            "p − W = a − 1",
        ),
        (
            Projection {
                roster_bounded: false,
                ..base()
            },
            "the roster unknown",
        ),
        (
            Projection {
                vote_seed_from: 1,
                ..base()
            },
            "node #0 not vote-seeded",
        ),
        (
            Projection {
                first_segment_registration: 3,
                ..base()
            },
            "node 2 seeded at `p` only",
        ),
    ] {
        assert_eq!(judge_on(&mut g, &junk, &projection), Ok(()), "{why}");
    }
}

// -- AC9: the FR21 value arm --

/// AC9 (D7): an evidence block counts its claimed `supporter_vote_sum`,
/// clamped at `value_cap`: `u64::MAX` counts the cap, the cap and one below
/// count themselves.
#[test]
fn an_evidence_counts_its_claim_clamped_at_the_cap() {
    let (_, e, _) = evidence_by(4);
    let claimed = evidence_of(&e, 2).supporter_vote_sum;
    assert!(claimed > 0);
    assert_eq!(block_value::<16>(&e.view()), claimed);
    let cap = value_cap::<16>();
    for (claim, value) in [(u64::MAX, cap), (cap, cap), (cap - 1, cap - 1)] {
        let block = evidence_with(&e, 2, |ev| ev.supporter_vote_sum = claim);
        assert_eq!(block_value::<16>(&block.view()), value);
    }
}

// -- AC10: the stop on active evidence and the proposer's release --

/// AC10 (D3): the proposer's own evidence held as a side block (the
/// heavier `y@6` active) releases its accumulator, and the builder
/// refuses a tip at or above it.
#[test]
fn the_own_side_evidence_releases_the_accumulator() {
    let (_, mut l, _, d, d_idx, y) = sibling_proposer();
    accumulate(&mut l, &d, d_idx, 2);
    let e = l.build_evidence_block(d_idx, 0).expect("evidence");
    assert!(l.approval_live());
    plant_child(&mut l, &e, d_idx, true, true);
    let e_idx = l.blocks.find(7, &e.view().hash()).expect("held");
    assert!(
        !l.blocks.get(e_idx).expect("e").is_on_active_chain(),
        "a side block"
    );
    assert_eq!(head_of(&l), (6, y.view().hash()));
    assert!(!l.approval_live(), "released");
    assert!(l.build_evidence_block(d_idx, 0).is_none());
    assert!(l.build_evidence_block(e_idx, 0).is_none());
    assert_eq!(
        l.approval_step(7, Ok(TailObligation::None), 0, 0),
        ApprovalStep::Hold
    );
}

/// AC10 (D3): an evidence at `p` on another fork (its `p − 1` is not the
/// proposer's) stops nothing, even the proposer's own (review: the
/// ancestry condition of the release, not the creator's).
#[test]
fn an_evidence_on_another_fork_stops_nothing() {
    let (_, e, _) = evidence_by(4);
    let ev = evidence_of(&e, 2);
    let (g, mut l, blocks, _, d_idx) = proposer_chain(5);
    assert!(l.open_approval(d_idx));
    let x5 = normal_after(&g, &blocks[4], 2, 51);
    let x6 = normal_after(&g, &x5, 2, 52);
    for block in [&x5, &x6] {
        assert_eq!(
            receive(&mut l, block),
            ReceiveBlockOutcome::AcceptedSilently
        );
    }
    let x6_idx = l.blocks.find(6, &x6.view().hash()).expect("held");
    let other = evidence_block(7, x6.view().hash(), 5, &ev);
    assert_eq!(evidence_of(&other, 2).deviation_sequence, 6);
    plant_child(&mut l, &other, x6_idx, true, true);
    assert!(l.approval_live(), "another p − 1");
}

// -- AC13.3: AR16 replay --

/// AR16: one block stream — a deviation, an evidence with a wrong vote
/// sum, the valid one, a competing deviation and its junk claim — on two fresh modules gives identical
/// verdicts, heads, open runs and branch values.
#[test]
fn evidence_verdicts_are_replay_deterministic() {
    let (d4, e4, _) = evidence_by(4);
    let (d5, e5, _) = evidence_by(5);
    let bad_sum = evidence_with(&e4, 2, |ev| ev.supporter_vote_sum += 1);
    let junk = evidence_with(&e5, 2, |ev| ev.supporter_vote_sum = u64::MAX);
    let stream = [&d4, &bad_sum, &e4, &d5, &junk];
    let run = || {
        let (_, mut l, _) = support_chain(3);
        let outcomes: std::vec::Vec<ReceiveBlockOutcome> =
            stream.iter().map(|block| receive(&mut l, block)).collect();
        (
            outcomes,
            head_of(&l),
            l.active_open_run,
            l.active_branch_value,
            stream.map(|block| entry_of(&l, block).map(|entry| entry.0)),
        )
    };
    let first = run();
    assert_eq!(first.1, (7, e4.view().hash()));
    assert_eq!(
        first.0[1],
        ReceiveBlockOutcome::Rejected(RejectReason::InvalidEvidence)
    );
    assert_eq!(first.4[4], None, "the junk deleted");
    assert_eq!(first, run());
}

// -- Story 6.7 follow-up: the evidence check's local faults (N24a, N23),
// the tentative intake (N31), the registration signature on restore (N35b) --

/// Node 4's `d@6`, its replay `r@7`, its evidence `e@8` built over `r` (the
/// rewind reads `r`), and node 2's sibling `x@6` (a later admission).
fn replay_evidence() -> (Block, Block, Block, Block) {
    let (mut g, mut l, blocks, d, d_idx) = proposer_chain(4);
    let sibling = normal_after(&g, &blocks[5], 2, 91);
    assert_eq!(receive(&mut g, &d), ReceiveBlockOutcome::AcceptedSilently);
    let r = normal_after(&g, &d, 4, 2);
    assert_eq!(receive(&mut l, &r), ReceiveBlockOutcome::AcceptedSilently);
    accumulate(&mut l, &d, d_idx, 2);
    let tip = l.active_chain_head_idx;
    let e = l.build_evidence_block(tip, 0).expect("evidence over r");
    assert_eq!(e.view().sequence(), 8);
    (d, r, e, sibling)
}

/// Node 3 over a failing backend, Ready at `r` (`d`, `r` received).
fn failing_observer(d: &Block, r: &Block) -> Chain16<FailingSupportStorage> {
    let (_, mut l, _) = support_chain_on(3, failing_storage(3), 16, |_| {});
    for block in [d, r] {
        assert_eq!(
            receive(&mut l, block),
            ReceiveBlockOutcome::AcceptedSilently
        );
    }
    assert_eq!(head_of(&l), (7, r.view().hash()));
    l
}

/// N24a (AC5) — a refused rewind is a local fault, not evidence: with
/// `r`'s slot unreadable the projection cannot undo `r` (the run rules
/// read only `d`'s header and pass), so the evidence is admitted Stored,
/// unmarked and off the chain, the head unchanged; once the read works, a
/// later admission's continuation judges it and accepts it.
#[test]
fn an_unreadable_rewind_leaves_the_evidence_stored() {
    let (d, r, e, sibling) = replay_evidence();
    let mut l = failing_observer(&d, &r);
    l.storage.failing_slot = l.active_chain_head_idx;
    assert_eq!(receive(&mut l, &e), ReceiveBlockOutcome::AcceptedSilently);
    assert!(l.storage.attempts.get() > 0, "the rewind read r");
    let (status, active, accepted, _) = entry_of(&l, &e).expect("held, not deleted");
    assert_eq!(
        (status, active, accepted),
        (BlockStatus::Stored, false, false),
        "unjudged and unmarked"
    );
    assert_eq!(head_of(&l), (7, r.view().hash()));
    assert!(l.is_ready());
    l.storage.failing_slot = NONE_REF;
    let verified = counted(&AGGREGATE_VERIFICATIONS);
    assert_eq!(
        receive(&mut l, &sibling),
        ReceiveBlockOutcome::AcceptedSilently
    );
    assert_eq!(head_of(&l), (8, e.view().hash()), "judged and accepted");
    assert_eq!(counted(&AGGREGATE_VERIFICATIONS) - verified, 1);
    assert!(entry_of(&l, &e).expect("held").2);
}

/// N23 (AC8) — a failed restore inside the evidence check escalates at the
/// root: `r`'s first read (the rewind's undo) succeeds and its second (the
/// restore's re-apply) fails once. The check returns a local fault and
/// marks the re-entry due; the root skips the continuation, the driver and
/// the comparison while it is due (the engine is not at `r`), and
/// `receive_block` then re-enters collecting, whose spine re-derives the
/// tree and reaches Ready again at the evidence. Nothing is deleted, the
/// flag is consumed, and the engine equals a node that judged the evidence
/// without a fault.
#[test]
fn a_failed_restore_in_the_evidence_check_reenters_at_the_root() {
    let (d, r, e, _) = replay_evidence();
    let reference = {
        let mut clean = failing_observer(&d, &r);
        assert_eq!(
            receive(&mut clean, &e),
            ReceiveBlockOutcome::AcceptedSilently
        );
        assert_eq!(head_of(&clean), (8, e.view().hash()));
        engine_votes(&clean)
    };
    let mut l = failing_observer(&d, &r);
    l.storage.failing_slot = l.active_chain_head_idx;
    l.storage.reads_left.set(1);
    l.storage.failures_left.set(1);
    assert_eq!(receive(&mut l, &e), ReceiveBlockOutcome::AcceptedSilently);
    assert!(l.storage.attempts.get() >= 2, "the restore's read of r");
    assert_eq!(l.storage.failures_left.get(), 0, "the fault was hit");
    assert!(!l.reentry_due, "consumed at the root");
    assert!(l.is_ready(), "the re-entry's spine reached Ready again");
    assert_eq!(head_of(&l), (8, e.view().hash()));
    let (status, active, accepted, _) = entry_of(&l, &e).expect("not deleted");
    assert!(status == BlockStatus::Active && active && accepted);
    assert_eq!(
        engine_votes(&l),
        reference,
        "re-derived, not the broken engine"
    );
}

/// N31 (AC4, FR9) — outside Ready, intake judges rules 1–3 only until the
/// configuration is durably locked: a Collecting node holding the
/// tentative configuration of #1 (no genesis #0, so it stays Collecting)
/// admits a registration at the slot #7 (rule 5 waits for the lock), and
/// refuses a foreign creator above node 4's open run at #6
/// (`DeviationRun`).
#[test]
fn a_tentative_intake_judges_only_rules_one_to_three() {
    let (blocks, d, x6, foreign) = {
        let (mut g, _, blocks) = support_chain(3);
        let d = deviation_after(&g, &blocks[5], 4, 1);
        let x6 = normal_after(&g, &blocks[5], 2, 61);
        assert_eq!(receive(&mut g, &d), ReceiveBlockOutcome::AcceptedSilently);
        let foreign = normal_after(&g, &d, 3, 71);
        (blocks, d, x6, foreign)
    };
    let unclean = register(7, x6.view().hash(), 6, key_of(6));
    let mut c = local_node(3, local_storage(3));
    for block in blocks[1..].iter().chain([&d, &x6]) {
        assert_eq!(
            receive(&mut c, block),
            ReceiveBlockOutcome::AcceptedSilently
        );
    }
    assert_eq!(c.lifecycle_phase, LifecyclePhase::Collecting);
    assert!(c.chain_config.active_configuration().is_some(), "tentative");
    assert!(!c.chain_config.is_durable_locked());
    assert_eq!(
        slot_rule(&unclean.view(), Some(TEST_H)),
        Err(ValidationReason::SlotNotClean)
    );
    assert_eq!(
        receive(&mut c, &unclean),
        ReceiveBlockOutcome::AcceptedSilently,
        "rule 5 waits for the lock"
    );
    assert!(entry_of(&c, &unclean).is_some());
    assert_eq!(
        c.tier1_admit(&foreign.view(), &foreign.view().hash(), 0),
        Err(AdmitError::Rejected(Tier1Failure::DeviationRun))
    );
    assert_eq!(
        receive(&mut c, &foreign),
        ReceiveBlockOutcome::Rejected(RejectReason::InvalidEvidence)
    );
    assert_eq!(entry_of(&c, &foreign), None, "not stored");
}

/// N35b (AC6) — the registration signature is final with bit 6: an
/// aborted switch over junk undoes and restores node 1's registration
/// block `x6` (heavier than node 5's `d@6`) without verifying its
/// registration again; only `d`'s transaction is verified, forward.
#[test]
fn a_restore_verifies_no_registration_again() {
    let (d5, e5, _) = evidence_by(5);
    let junk = evidence_with(&e5, 2, |ev| ev.supporter_vote_sum = u64::MAX);
    let (mut g, _, blocks) = support_chain(3);
    let x6 = real_on(
        &g,
        &register(6, blocks[5].view().hash(), 6, key_of(6)),
        1,
        key_of(1),
    );
    assert!(
        x6.view().consumed_votes() > d5.view().consumed_votes(),
        "x6 is heavier"
    );
    assert_eq!(receive(&mut g, &x6), ReceiveBlockOutcome::AcceptedSilently);
    assert_eq!(receive(&mut g, &d5), ReceiveBlockOutcome::AcceptedSilently);
    assert_eq!(head_of(&g), (6, x6.view().hash()));
    let value = g.active_branch_value;
    let signatures = counted(&TX_SIGNATURE_VERIFICATIONS);
    assert_eq!(
        receive(&mut g, &junk),
        ReceiveBlockOutcome::AcceptedSilently
    );
    assert_eq!(entry_of(&g, &junk), None, "deleted by the walk");
    assert_eq!(head_of(&g), (6, x6.view().hash()), "restored");
    assert_eq!(
        g.node_info.max_known_node_id(),
        6,
        "the registration restored"
    );
    let d_txs = d5.view().transactions().expect("txs").iter().count() as u32;
    assert_eq!(counted(&TX_SIGNATURE_VERIFICATIONS) - signatures, d_txs);
    assert_eq!(g.active_branch_value, value);
}
