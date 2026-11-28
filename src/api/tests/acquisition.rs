//! Tests of `api/acquisition.rs`.

use super::*;

/// As [`node_transfer_block`], but chained to `prev` so the block can sit
/// above another in a candidate segment.
fn chained_node_transfer_block(
    seq: u32,
    prev: [u8; 32],
    vote: u32,
    anchor: u32,
    initializer: u32,
) -> Block {
    let signer = Crypto::new([1u8; PRIVATE_KEY_SIZE]).ok().expect("test key");
    let nt = NodeTransfer::new_signed(
        vote,
        anchor,
        initializer,
        9,
        100,
        TEST_TRANSFER_FEE,
        0,
        &signer,
    );
    let header = BlockHeader {
        version: 1,
        sequence: seq,
        creator: 0,
        mined_amount: 0,
        payload_type: PAYLOAD_TYPE_TRANSACTION,
        consumed_votes: 0,
        first_voted_node: 0,
        consumed_votes_from_first_voted_node: 0,
        previous_hash: prev,
        signature: [0u8; SIGNATURE_SIZE],
    };
    let mut builder = BlockBuilder::new().header(header);
    builder
        .add_node_transfer(&nt)
        .ok()
        .expect("add node transfer");
    builder.build_signed(&signer).ok().expect("build signed")
}

// --- Story 5.2: FR2 dominant-chain acquisition (stopping conditions + selection) ---

/// AC4/AC7 — an orphan block whose short segment neither reaches genesis nor
/// spans `W` leaves the node Collecting (no candidate); parent recovery still
/// schedules (the FR2 evaluation is side-effect-free w.r.t. the tick cadence).
#[test]
fn fr2_no_candidate_stays_collecting() {
    let mut bc = new_test_chain();
    let orphan = node_transfer_block(5, 3, 4, 7); // tail seq 5, len 1, not genesis
    let (outcome, next) = bc.receive_block(orphan.view(), 0);
    assert_eq!(outcome, ReceiveBlockOutcome::AcceptedSilently);
    assert!(bc.evaluate_stopping_condition().is_none());
    assert!(bc.current_phase() == LifecyclePhase::Collecting);
    assert!(
        matches!(next, NextCall::At(_)),
        "parent recovery still scheduled while collecting"
    );
}

/// Story 5.11 — FR2 measures a window-anchored segment against the
/// configured `W`, not the allocated capacity: on a build with capacity 16
/// configured with `W = 6` (`H = 3`), nine blocks qualify and eight do
/// not. The build is `TestChain`'s over [`W6Storage`], whose fourteen
/// slots hold the nine-block join.
#[test]
fn fr2_active_length_is_the_configured_w_not_the_capacity() {
    let (crypto, _, mut chain_config) = test_backends();
    chain_config
        .load_durable(window_config_builder(W6).build_signed(&crypto))
        .ok()
        .expect("a window below the capacity is accepted");
    let node_zero = *crypto.public_key().serialize();
    let mut slot = core::mem::MaybeUninit::<Chain16<W6Storage>>::uninit();
    Blockchain::init(
        &mut slot,
        crypto,
        w6_storage(),
        chain_config,
        5,
        node_zero,
        0,
    );
    // SAFETY: `init` returned, so every field of `slot` is initialized.
    let mut bc = unsafe { slot.assume_init() };
    assert_eq!(
        Chain16::<W6Storage>::BUILD_LIMITS.snake_chain_length_max,
        TEST_W
    );

    // The tail carries the configuration the node is locked on, as the FR8
    // final check requires.
    let below = w6_horizon_block();
    for block in &w6_below() {
        bc.receive_block(block.view(), 0);
    }
    let tail = w6_config_anchor_block(100, below.view().hash());
    bc.receive_block(tail.view(), 0);
    let mut prev = tail.view().hash();
    for seq in 101..=104 {
        let blk = linked_transfer_block(seq, prev);
        prev = blk.view().hash();
        bc.receive_block(blk.view(), 0);
    }
    assert!(
        bc.evaluate_stopping_condition().is_none(),
        "segment length 8 < W + H = 9"
    );

    let last = linked_transfer_block(105, prev);
    bc.receive_block(last.view(), 0);
    assert!(
        bc.is_ready(),
        "segment length 9 = W + H qualifies, on a build that allocated 16"
    );
}

/// Story 5.11 / 5.13 — with no configuration held the chain's window is
/// unknown, and no segment names a configuration, so nothing is a
/// candidate. A window-anchored segment as long as the build's whole capacity
/// is not: the capacity is not the window. Once block #1 brings the
/// configuration, the genesis-anchored segment carrying it qualifies — and
/// the window-anchored one still does not, because it names none.
#[test]
fn fr2_without_a_configuration_no_segment_qualifies() {
    let mut bc = new_unconfigured_w6_chain();
    let mut prev = [0xAB; 32];
    for seq in 100..=105 {
        let blk = linked_transfer_block(seq, prev);
        prev = blk.view().hash();
        bc.tier1_admit(&blk.view(), &blk.view().hash(), 0)
            .expect("a transfer block is admitted");
    }
    assert!(bc.chain_config.active_configuration().is_none());
    assert!(
        bc.evaluate_stopping_condition().is_none(),
        "six blocks fill the capacity of 6, but no window is known"
    );

    let genesis = genesis_zero_block(1_007);
    bc.tier1_admit(&genesis.view(), &genesis.view().hash(), 0)
        .expect("the genesis is admitted");
    assert!(
        bc.evaluate_stopping_condition().is_none(),
        "a genesis alone names no configuration"
    );

    let cfg = w6_config_anchor_block(1, genesis.view().hash());
    let cfg_idx = bc
        .tier1_admit(&cfg.view(), &cfg.view().hash(), 0)
        .expect("block #1 is admitted");
    assert_eq!(bc.active_chain_length(), Some(W6));
    assert_eq!(
        bc.evaluate_stopping_condition(),
        Some(cfg_idx),
        "the genesis-anchored segment carrying the configuration qualifies; \
         the longer window-anchored one, naming none, does not"
    );
}

/// Story 5.11 — `W <= SNAKE_CHAIN_LENGTH_MAX`, measured against this build's
/// own `BUILD_LIMITS` (FR8): a chain-config block declaring the capacity
/// loads, one declaring a window above it — or none, which resolves to the
/// default 500 — is exact evidence of invalidity and never reaches storage.
#[test]
fn fr8_window_is_bounded_by_this_builds_capacity() {
    let mut bc = new_unconfigured_test_chain();
    assert_eq!(TestChain::BUILD_LIMITS.snake_chain_length_max, TEST_W);

    for (over, why) in [
        (
            chain_config_block_from(100, [0xAB; 32], &mut window_config_builder(TEST_W + 1)),
            "a declared window one above the capacity",
        ),
        (
            chain_config_block_from(100, [0xAC; 32], &mut ChainConfigPayloadBuilder::new()),
            "an absent window, whose default exceeds the capacity",
        ),
    ] {
        let (outcome, _) = bc.receive_block(over.view(), 0);
        assert_eq!(
            outcome,
            ReceiveBlockOutcome::Rejected(RejectReason::InvalidEvidence),
            "{why} is refused"
        );
        assert_eq!(bc.block_tree_len(), 0, "{why} is not stored");
        assert!(bc.chain_config.active_configuration().is_none());
    }

    let at = chain_config_anchor_block(100, [0xAB; 32]);
    let (outcome, _) = bc.receive_block(at.view(), 0);
    assert_eq!(outcome, ReceiveBlockOutcome::AcceptedSilently);
    assert_eq!(bc.active_chain_length(), Some(TEST_W));
}

/// AC2/AC5/AC6 + Story 5.4 — receiving the genesis (a length-1
/// genesis-anchored segment) satisfies FR2 at once and, since block #0 passes
/// the (genesis-waived) FR6 invariant set, the node runs the full
/// Collecting→Processing→Ready transition in the one `receive_block` call. The
/// bootstrap-anchored genesis is recognized as the candidate (no intake
/// change, per the `:142` resolution) and stays the active head after the FR4
/// promotion.
#[test]
fn fr2_genesis_anchored_triggers_processing() {
    let mut bc = new_test_chain();
    let genesis = genesis_zero_block(1_007);
    // FR8 (Story 5.9, AC3): the candidate must name a configuration, so
    // block #1 carries the chain-config as the FR54 bootstrap emits it.
    // Admitted first, while it is still an orphan (no FR2 trigger), so the
    // genesis admission is what completes the genesis-anchored candidate —
    // which is the transition this test is about.
    let cfg = chain_config_anchor_block(1, genesis.view().hash());
    let (cfg_outcome, _) = bc.receive_block(cfg.view(), 100);
    assert_eq!(cfg_outcome, ReceiveBlockOutcome::AcceptedSilently);
    let (outcome, _) = bc.receive_block(genesis.view(), 100);
    assert_eq!(outcome, ReceiveBlockOutcome::AcceptedSilently);
    assert!(
        bc.blocks
            .get(0)
            .is_some_and(|entry| entry.is_on_active_chain()),
        "the genesis is on the active chain after the FR4 promotion (AC9)"
    );
    assert!(
        bc.is_ready(),
        "genesis-anchored candidate validates → Ready (FR6/FR4, Story 5.4)"
    );
}

/// AC3 — a node holding no configuration does not enter Processing, even
/// when the FR2 stopping condition is met: the FR3 derivation reads the FR37
/// vote parameters, and running it on `vote_parameters`' inert baseline
/// would produce a projection the node then goes `Ready` on. The block is
/// admitted; only the stage that needs the configuration is withheld
/// (specification §5.2). Compare `fr2_genesis_anchored_triggers_processing`,
/// which is the same submission against a configured node.
#[test]
fn fr2_stays_collecting_without_configuration() {
    let (crypto, storage, chain_config) = test_backends();
    let mut bc = new_chain(crypto, storage, chain_config, 5, 0);
    let genesis = genesis_zero_block(1_007);

    let (outcome, _) = bc.receive_block(genesis.view(), 100);

    assert_eq!(
        outcome,
        ReceiveBlockOutcome::AcceptedSilently,
        "the block itself is still admitted"
    );
    assert!(
        bc.current_phase() == LifecyclePhase::Collecting,
        "no configuration → no FR3 derivation, so no Processing and no Ready"
    );
    assert!(!bc.is_ready());
}

/// Defence in depth behind the FR2 gate: if a caller ever reaches the FR3
/// derivation without a configuration, the vote engine refuses rather than
/// accumulating on parameters nobody chose. Epic 6's deep-zone
/// re-derivation and Story 5.10's restart are the callers this protects.
#[test]
fn processing_pass_refuses_without_configuration() {
    let (crypto, storage, chain_config) = test_backends();
    let mut bc = new_chain(crypto, storage, chain_config, 5, 0);
    let genesis = genesis_zero_block(1_007);
    let (outcome, _) = bc.receive_block(genesis.view(), 100);
    assert_eq!(outcome, ReceiveBlockOutcome::AcceptedSilently);

    // The same candidate a configured node validates all the way to Ready
    // (see `fr2_genesis_anchored_triggers_processing`).
    assert_eq!(
        bc.run_processing_pass(0),
        Err(ProcessingError::Vote(VoteEngineError::NotParameterized)),
        "no FR37 parameters -> the derivation refuses, it does not guess"
    );
}

/// AC2 — an active-length segment (`>= W + H = 9`, `W = 6`) that does NOT
/// reach genesis triggers Processing; one block short (len 8) it stays
/// Collecting.
#[test]
fn fr2_active_length_triggers_at_w() {
    let mut bc = new_w6_chain();
    // The orphan #97 (unresolved parent) and its children #98, #99, the
    // chain-config block #100 the FR8 final check requires in scope (Story
    // 5.9, AC3), then children up to length 8 — one below `W + H = 9`
    // (DEC-177).
    let below = w6_horizon_block();
    for block in &w6_below() {
        bc.receive_block(block.view(), 0);
    }
    let tail = w6_config_anchor_block(100, below.view().hash());
    bc.receive_block(tail.view(), 0);
    let mut prev = tail.view().hash();
    for seq in 101..=104 {
        let blk = linked_transfer_block(seq, prev);
        prev = blk.view().hash();
        bc.receive_block(blk.view(), 0);
    }
    assert_eq!(bc.block_tree_len(), 8);
    assert!(
        bc.evaluate_stopping_condition().is_none(),
        "segment length 8 >= W, below W + H = 9"
    );
    assert!(bc.current_phase() == LifecyclePhase::Collecting);
    // The 9th block brings the continuous segment to length W + H = 9 → FR2
    // qualifies, and the window-anchored candidate (unseeded initializers, so
    // the per-node FR6 checks are pre-seed-skipped, and every block is
    // node-#0-signed against the trust anchor) validates → Ready (Story 5.4).
    let last = linked_transfer_block(105, prev);
    bc.receive_block(last.view(), 0);
    assert!(
        bc.is_ready(),
        "segment length 9 >= W + H → FR2 qualifies, FR6 validates → Ready"
    );
}

/// AC3 — selection takes the highest tip sequence; a same-sequence tie is
/// broken by the lowest tip hash (hash-only, in-memory). Built via
/// `tier1_admit` (which does not run the FR2 hook), so the multi-head tree can
/// be assembled before evaluating.
#[test]
fn fr2_selection_highest_sequence_then_lowest_hash() {
    let mut bc = new_test_chain();
    let g = genesis_zero_block(1_007);
    bc.tier1_admit(&g.view(), &g.view().hash(), 0)
        .expect("genesis admitted");
    // Block #1 names the configuration both branches inherit (Story 5.13).
    let cfg = chain_config_anchor_block(1, g.view().hash());
    bc.tier1_admit(&cfg.view(), &cfg.view().hash(), 0)
        .expect("config admitted");
    let gh = cfg.view().hash();
    // Two distinct seq-2 children of block #1 (a fork) → both
    // genesis-anchored, both tip seq 2 → tie broken by lower tip hash.
    let a = salted_linked_block(2, gh, 3);
    let b = salted_linked_block(2, gh, 4);
    let a_idx = bc
        .tier1_admit(&a.view(), &a.view().hash(), 0)
        .expect("A admitted");
    let b_idx = bc
        .tier1_admit(&b.view(), &b.view().hash(), 0)
        .expect("B admitted");
    let a_hash = a.view().hash();
    let b_hash = b.view().hash();
    let lower = if a_hash < b_hash { a_idx } else { b_idx };
    assert_eq!(
        bc.evaluate_stopping_condition(),
        Some(lower),
        "same-sequence tie → lower tip hash wins"
    );
    // Extend branch A to seq 3 → the higher sequence now outranks the tie.
    let c = salted_linked_block(3, a_hash, 3);
    let c_idx = bc
        .tier1_admit(&c.view(), &c.view().hash(), 0)
        .expect("C admitted");
    assert_eq!(
        bc.evaluate_stopping_condition(),
        Some(c_idx),
        "highest tip sequence wins over the lower-sequence tie"
    );
}

/// AC8 — the selected candidate is independent of admission order (FR63/NFR5):
/// building the same fork in two admission orders yields the same winning tip
/// hash (the block-table index differs by order, the chosen tip does not).
#[test]
fn fr2_selection_is_order_independent() {
    fn winner_hash(order: &[u32; 2], now: u64) -> [u8; 32] {
        let mut bc = new_test_chain();
        let g = genesis_zero_block(1_007);
        bc.tier1_admit(&g.view(), &g.view().hash(), now)
            .expect("genesis");
        let cfg = chain_config_anchor_block(1, g.view().hash());
        bc.tier1_admit(&cfg.view(), &cfg.view().hash(), now)
            .expect("config");
        let gh = cfg.view().hash();
        let blocks = [
            salted_linked_block(2, gh, order[0]),
            salted_linked_block(2, gh, order[1]),
        ];
        for blk in &blocks {
            bc.tier1_admit(&blk.view(), &blk.view().hash(), now)
                .expect("child admitted");
        }
        let win = bc
            .evaluate_stopping_condition()
            .expect("a genesis-anchored candidate qualifies");
        *bc.blocks.get(win).expect("winner is in the tree").hash()
    }
    // Order- AND now-independent (FR63/NFR5): the evaluator reads no clock/PRNG.
    assert_eq!(
        winner_hash(&[3, 4], 1_000),
        winner_hash(&[4, 3], 9_999_999),
        "same winning tip regardless of admission order or wall-clock base"
    );
}

/// AC6 — the bootstrap-anchored genesis does not pre-empt selection: a longer
/// non-genesis active-length branch at a higher tip sequence is chosen over
/// the anchored genesis's short branch (the evaluator never reads
/// `active_chain_head_idx`).
#[test]
fn fr2_anchored_genesis_does_not_preempt_higher_branch() {
    let mut bc = new_w6_chain();
    // Anchored genesis (a short genesis-anchored candidate).
    let g = genesis_zero_block(1_007);
    bc.tier1_admit(&g.view(), &g.view().hash(), 0)
        .expect("genesis admitted");
    assert_eq!(
        bc.current_active_head(),
        Some(0),
        "genesis is the placeholder anchor"
    );
    // Block #1 names the configuration, so the genesis branch is itself a
    // qualifying candidate (Story 5.13) — the one that must not win.
    let cfg = w6_config_anchor_block(1, g.view().hash());
    bc.tier1_admit(&cfg.view(), &cfg.view().hash(), 0)
        .expect("config admitted");
    // A separate non-genesis branch of length W + H = 9 (#97 → tip 105),
    // its window tail #100 naming the same configuration.
    let below = w6_horizon_block();
    for block in &w6_below() {
        bc.tier1_admit(&block.view(), &block.view().hash(), 0)
            .expect("the blocks below the window admitted");
    }
    let tail = w6_config_anchor_block(100, below.view().hash());
    bc.tier1_admit(&tail.view(), &tail.view().hash(), 0)
        .expect("tail admitted");
    let mut prev = tail.view().hash();
    let mut tip_idx = 0;
    for seq in 101..=105 {
        let blk = linked_transfer_block(seq, prev);
        prev = blk.view().hash();
        tip_idx = bc
            .tier1_admit(&blk.view(), &blk.view().hash(), 0)
            .expect("child admitted");
    }
    // Highest tip sequence (105) wins over the anchored genesis (seq 0).
    assert_eq!(
        bc.evaluate_stopping_condition(),
        Some(tip_idx),
        "the longer non-genesis branch is selected despite the genesis anchor"
    );
}

/// AC2 — a genesis-anchored segment longer than 1 but shorter than W still
/// qualifies (the genesis rule is length-independent — distinct from the
/// active-length rule).
#[test]
fn fr2_genesis_anchored_multiblock_below_w_qualifies() {
    let mut bc = new_test_chain(); // W = 16
    let g = genesis_zero_block(1_007);
    bc.tier1_admit(&g.view(), &g.view().hash(), 0)
        .expect("genesis admitted");
    // Block #1, carrying the configuration (Story 5.13) → a 2-block
    // genesis-anchored segment (< W).
    let c = chain_config_anchor_block(1, g.view().hash());
    let c_idx = bc
        .tier1_admit(&c.view(), &c.view().hash(), 0)
        .expect("child admitted");
    assert_eq!(
        bc.evaluate_stopping_condition(),
        Some(c_idx),
        "genesis-anchored qualifies at length 2, well below W = 16"
    );
}

// --- Story 5.3: FR3 processing-pass forward state reconstruction ---------

/// AC2/AC3 — the earliest balance block seeds per-node balance + public key
/// and initializes the `max_known_node_id` watermark from its `max_node_id`;
/// `VoteEngine` is seeded from the entries' `vote_count`.
#[test]
fn fr3_derives_balance_block_seed_and_watermark() {
    let mut bc = new_test_chain();
    // FR8 (Story 5.9, AC3): the candidate must carry a chain-config
    // block in scope, so the segment is anchored by one. Inert with
    // respect to everything below — see `chain_config_anchor_block`.
    let cfg_hash = admit_chain_config_anchor(&mut bc, 99, [0xAB; 32]);
    let anchor = balance_block(100, cfg_hash, &[(1, 500, 10, 0x31), (2, 300, 20, 0x32)], 2);
    let ai = bc
        .tier1_admit(&anchor.view(), &anchor.view().hash(), 0)
        .expect("balance anchor admitted");

    bc.run_processing_pass(ai).expect("pass succeeds");

    assert_eq!(bc.node_info.balance_of(1), 500);
    assert_eq!(bc.node_info.balance_of(2), 300);
    assert!(bc.node_info.public_key_of(1).is_some());
    assert!(bc.node_info.public_key_of(2).is_some());
    assert_eq!(
        bc.node_info.max_known_node_id(),
        2,
        "watermark from max_node_id"
    );
    // vote_count seeds accumulated vote; the balance block's own acceptance
    // applies FR37 interest (`⌊v / 10⌋` at the default `vote_interest` 100:
    // 10 becomes 11, 20 becomes 22) + creator(0) reset.
    assert_eq!(bc.vote_engine.accumulated_vote_of(1), 11);
    assert_eq!(bc.vote_engine.accumulated_vote_of(2), 22);
    // FR38 creator-order is a read-through of the vote registry: node 2
    // (vote 20) outranks node 1 (vote 10); the zero-vote tail follows by
    // ascending node id.
    assert_eq!(bc.vote_engine.top_creator(), Some(2));
    assert_eq!(bc.vote_engine.creator_at_rank(1), Some(1));
}

/// AC3 — a (non-genesis) registration seeds the new node (balance 0, public
/// key) and advances the watermark; the initializer is debited
/// `registration_price + fee`.
#[test]
fn fr3_derives_registration_and_watermark() {
    let mut bc = new_test_chain();
    // FR8 (Story 5.9, AC3): the candidate must carry a chain-config
    // block in scope, so the segment is anchored by one. Inert with
    // respect to everything below — see `chain_config_anchor_block`.
    let cfg_hash = admit_chain_config_anchor(&mut bc, 99, [0xAB; 32]);
    let anchor = balance_block(100, cfg_hash, &[(1, 1_000, 0, 0x31)], 1);
    bc.tier1_admit(&anchor.view(), &anchor.view().hash(), 0)
        .expect("anchor admitted");
    // FR6 registration monotonicity: `new_node_id` must be the pre-block
    // watermark + 1 (watermark is 1 from the balance block's max_node_id → 2).
    let reg = registration_block(101, anchor.view().hash(), 1, 2, 0x45);
    let ri = bc
        .tier1_admit(&reg.view(), &reg.view().hash(), 0)
        .expect("registration admitted");

    bc.run_processing_pass(ri).expect("pass succeeds");

    assert!(
        bc.node_info.public_key_of(2).is_some(),
        "new node registered"
    );
    assert_eq!(
        bc.node_info.balance_of(2),
        0,
        "new node balance is 0 (FR50)"
    );
    assert_eq!(bc.node_info.max_known_node_id(), 2, "watermark advanced");
    assert_eq!(
        bc.node_info.balance_of(1),
        1_000 - TEST_REGISTRATION_PRICE - TEST_REGISTRATION_FEE,
        "initializer debited registration_price + fee"
    );
}

/// AC2 — a node transfer between two seeded nodes moves the derived balances
/// (initializer debited amount + fee; receiver credited amount).
#[test]
fn fr3_derives_node_transfer_between_seeded_nodes() {
    let mut bc = new_test_chain();
    // FR8 (Story 5.9, AC3): the candidate must carry a chain-config
    // block in scope, so the segment is anchored by one. Inert with
    // respect to everything below — see `chain_config_anchor_block`.
    let cfg_hash = admit_chain_config_anchor(&mut bc, 99, [0xAB; 32]);
    let anchor = balance_block(100, cfg_hash, &[(1, 500, 0, 0x31), (2, 300, 0, 0x32)], 2);
    bc.tier1_admit(&anchor.view(), &anchor.view().hash(), 0)
        .expect("anchor admitted");
    // vote 0 — the permanent node-#0 vote-target exception (FR37/FR54), so the
    // FR6 vote-target check passes without seeding a dedicated target node.
    let tx = transfer_block(101, anchor.view().hash(), 1, 2, 100, TEST_TRANSFER_FEE, 0);
    let ti = bc
        .tier1_admit(&tx.view(), &tx.view().hash(), 0)
        .expect("transfer admitted");

    bc.run_processing_pass(ti).expect("pass succeeds");

    assert_eq!(
        bc.node_info.balance_of(1),
        500 - (100 + u64::from(TEST_TRANSFER_FEE)),
        "500 - (100 + fee)"
    );
    assert_eq!(bc.node_info.balance_of(2), 400, "300 + 100");
}

/// AC4 — pre-seed-zone auto-acceptance: transactions involving nodes with no
/// in-segment seed source are auto-accepted (their per-node balance effects
/// are skipped), and the pass neither panics nor invents balances.
#[test]
fn fr3_preseed_zone_auto_accepts() {
    let mut bc = new_test_chain();
    // FR8 (Story 5.9, AC3): the segment is anchored by a chain-config block,
    // which is inert here — see `chain_config_anchor_block`.
    let cfg_hash = admit_chain_config_anchor(&mut bc, 99, [0xAB; 32]);
    // A transfer from node 7 to node 9, neither ever seeded.
    let anchor = chained_node_transfer_block(100, cfg_hash, 3, 99, 7);
    let ai = bc
        .tier1_admit(&anchor.view(), &anchor.view().hash(), 0)
        .expect("anchor admitted");

    bc.run_processing_pass(ai)
        .expect("pass does not fail on unseeded nodes");

    assert!(!bc.node_info.is_seeded(7));
    assert_eq!(bc.node_info.balance_of(7), 0, "debit skipped (pre-seed)");
    assert_eq!(bc.node_info.balance_of(9), 0, "credit skipped (pre-seed)");
    // The vote credit still lands (vote accounting is roster-independent).
    assert_eq!(bc.vote_engine.accumulated_vote_of(3), 1000);
}

/// AC3 — a genesis-anchored segment with no balance block initializes the
/// watermark to 0 (FR54(h) bootstrap exception).
#[test]
fn fr3_genesis_anchored_watermark_zero() {
    let mut bc = new_test_chain();
    let g = genesis_zero_block(1_037);
    bc.tier1_admit(&g.view(), &g.view().hash(), 0)
        .expect("genesis admitted");
    // FR8 (Story 5.9, AC3): block #1 carries the chain-config. It contributes
    // no balance block, so the watermark this test measures is untouched.
    let ci = {
        let cfg = chain_config_anchor_block(1, g.view().hash());
        bc.tier1_admit(&cfg.view(), &cfg.view().hash(), 0)
            .expect("chain-config block admitted")
    };

    bc.run_processing_pass(ci).expect("pass succeeds");

    assert_eq!(
        bc.node_info.max_known_node_id(),
        0,
        "genesis-anchored, no balance block → watermark 0 (FR54(h))"
    );
}

/// AC1 — the backward mark follows only the selected branch: applying one
/// fork child's tip must not apply the sibling's effects.
#[test]
fn fr3_backward_mark_follows_selected_branch_only() {
    let mut bc = new_test_chain();
    // FR8 (Story 5.9, AC3): the candidate must carry a chain-config
    // block in scope, so the segment is anchored by one. Inert with
    // respect to everything below — see `chain_config_anchor_block`.
    let cfg_hash = admit_chain_config_anchor(&mut bc, 99, [0xAB; 32]);
    let anchor = balance_block(
        100,
        cfg_hash,
        &[(1, 1000, 0, 0x31), (2, 0, 0, 0x32), (3, 0, 0, 0x33)],
        3,
    );
    bc.tier1_admit(&anchor.view(), &anchor.view().hash(), 0)
        .expect("anchor admitted");
    let ah = anchor.view().hash();
    let left = transfer_block(101, ah, 1, 2, 100, TEST_TRANSFER_FEE, 0); // 1 → 2 (vote node #0)
    let right = transfer_block(101, ah, 1, 3, 200, TEST_TRANSFER_FEE, 0); // 1 → 3 (sibling; vote node #0)
    let li = bc
        .tier1_admit(&left.view(), &left.view().hash(), 0)
        .expect("left admitted");
    let _ri = bc
        .tier1_admit(&right.view(), &right.view().hash(), 0)
        .expect("right admitted");

    bc.run_processing_pass(li).expect("pass over left tip");

    assert_eq!(bc.node_info.balance_of(2), 100, "left branch applied");
    assert_eq!(bc.node_info.balance_of(3), 0, "sibling NOT applied");
    assert_eq!(
        bc.node_info.balance_of(1),
        1000 - 100 - u64::from(TEST_TRANSFER_FEE),
        "only left's 100 and fee debited"
    );
}

/// AC5 — the pass is not resumable: re-running it on the same candidate
/// re-derives from a clean working set to an identical projection.
#[test]
fn fr3_not_resumable_clean_reentry() {
    let mut bc = new_test_chain();
    // FR8 (Story 5.9, AC3): the candidate must carry a chain-config
    // block in scope, so the segment is anchored by one. Inert with
    // respect to everything below — see `chain_config_anchor_block`.
    let cfg_hash = admit_chain_config_anchor(&mut bc, 99, [0xAB; 32]);
    let anchor = balance_block(100, cfg_hash, &[(1, 500, 10, 0x31)], 1);
    bc.tier1_admit(&anchor.view(), &anchor.view().hash(), 0)
        .expect("anchor admitted");
    let tx = transfer_block(101, anchor.view().hash(), 1, 1, 0, TEST_TRANSFER_FEE, 0);
    let ti = bc
        .tier1_admit(&tx.view(), &tx.view().hash(), 0)
        .expect("tx admitted");

    bc.run_processing_pass(ti).expect("first pass");
    let b1 = bc.node_info.balance_of(1);
    let v1 = bc.vote_engine.accumulated_vote_of(1);

    bc.run_processing_pass(ti).expect("second pass (re-entry)");
    assert_eq!(
        bc.node_info.balance_of(1),
        b1,
        "balance identical after re-entry"
    );
    assert_eq!(
        bc.vote_engine.accumulated_vote_of(1),
        v1,
        "vote identical after re-entry (clean working set)"
    );
}

/// AC8 — the derived projection is `now`-independent and reproducible: the
/// same candidate admitted under two different `now` bases yields a
/// byte-identical projection.
#[test]
fn fr3_projection_is_clock_independent_and_reproducible() {
    fn run(now_base: u64) -> (u64, u64, u32, u32) {
        let mut bc = new_test_chain();
        // FR8 (Story 5.9, AC3): the candidate must carry a chain-config
        // block in scope, so the segment is anchored by one. Inert with
        // respect to everything below — see `chain_config_anchor_block`.
        let cfg_hash = admit_chain_config_anchor(&mut bc, 99, [0xAB; 32]);
        let anchor = balance_block(100, cfg_hash, &[(1, 500, 0, 0x31), (2, 300, 0, 0x32)], 2);
        let _ai = bc
            .tier1_admit(&anchor.view(), &anchor.view().hash(), now_base)
            .expect("anchor admitted");
        let tx = transfer_block(101, anchor.view().hash(), 1, 2, 100, TEST_TRANSFER_FEE, 0);
        let ti = bc
            .tier1_admit(&tx.view(), &tx.view().hash(), now_base + 5_000)
            .expect("tx admitted");
        bc.run_processing_pass(ti).expect("pass");
        (
            bc.node_info.balance_of(1),
            bc.node_info.balance_of(2),
            bc.vote_engine.accumulated_vote_of(0),
            bc.node_info.max_known_node_id(),
        )
    }
    assert_eq!(run(0), run(1_000_000), "projection independent of `now`");
}

/// AC9 (Story 5.4) — the FR4 Ready transition + FR9 Tier-3 Active-promotion
/// driver: a qualifying genesis-anchored candidate that passes FR6 moves
/// Collecting→Processing→Ready in one `receive_block`, every candidate block is
/// atomically promoted `Stored→Active` with `is_on_active_chain`, and
/// `active_chain_head_idx` is established at the tip.
#[test]
fn fr4_seam_reaches_ready_and_promotes_active() {
    let mut bc = new_test_chain();
    let genesis = genesis_zero_block(1_037);
    // FR8 (Story 5.9, AC3): block #1 carries the chain-config, admitted first
    // as an orphan so the genesis admission completes the candidate.
    let cfg = chain_config_anchor_block(1, genesis.view().hash());
    bc.receive_block(cfg.view(), 0);
    let (outcome, _next) = bc.receive_block(genesis.view(), 0);
    assert_eq!(outcome, ReceiveBlockOutcome::AcceptedSilently);
    assert!(
        bc.is_ready(),
        "valid genesis-anchored candidate → Ready (FR4)"
    );
    let tip = bc.active_chain_head_idx;
    assert_ne!(tip, NONE_REF, "active head established");
    let entry = bc.blocks.get(tip).expect("tip present");
    assert_eq!(
        entry.status(),
        BlockStatus::Active,
        "candidate tip promoted Stored→Active (FR9 Tier 3)"
    );
    assert!(entry.is_on_active_chain(), "tip is on the active chain");
}

/// AC10 (Story 5.4) + AC11(c)/(f) (Story 5.5, amended 2026-07-30) — the
/// FR6-failure path end to end, *including the immediate retry*: a
/// qualifying candidate that violates an FR6 invariant has its offender
/// deleted, and the shortened branch is re-evaluated and validated **inside
/// the same call**, so the node reaches Ready without waiting for another
/// admission. That is the whole point of the retry-on-`Invalid` rule: the
/// failed pass had already proved every block below the offender, and
/// `block_idx` names the earliest one.
///
/// The candidate `[#0 genesis, #1 chain-config, #2 registration]` is
/// continuous genesis-anchored (so FR2 qualifies on the genesis admission)
/// but block #2's `new_node_id = 5 ≠ watermark + 1 = 1` violates the FR6
/// registration-monotonicity rule. Block #1 is the chain-config the FR8
/// final check (Story 5.9, AC3) requires — and it has to be *below* the
/// offender, because the shortened branch the retry validates must still name
/// a configuration.
#[test]
fn fr5_seam_recovers_and_retries_invalid_candidate_in_one_call() {
    let mut bc = new_test_chain();
    let genesis = genesis_zero_block(1_000);
    let cfg = chain_config_anchor_block(1, genesis.view().hash());
    // Out-of-sequence registration child (new_node_id 5, expected 1).
    let child = registration_block(2, cfg.view().hash(), 1, 5, 0x45);
    // Admit the upper blocks first, while they are still orphans (Stored, no
    // FR2 — not yet anchored), then the genesis, so the continuous
    // genesis-anchored candidate qualifies on that last admission.
    let (outcome, _) = bc.receive_block(child.view(), 0);
    assert_eq!(
        outcome,
        ReceiveBlockOutcome::AcceptedSilently,
        "the orphan child is really admitted (the seam below is not vacuous)"
    );
    let (cfg_outcome, _) = bc.receive_block(cfg.view(), 0);
    assert_eq!(cfg_outcome, ReceiveBlockOutcome::AcceptedSilently);
    let child_idx = bc
        .blocks
        .find(2, &child.view().hash())
        .expect("child in the tree");
    assert!(bc.current_phase() == LifecyclePhase::Collecting);
    let (outcome, _) = bc.receive_block(genesis.view(), 0);
    assert_eq!(outcome, ReceiveBlockOutcome::AcceptedSilently);
    // AC11(a): the offender and its descendants are gone, the genesis and the
    // chain-config block survive.
    assert!(
        bc.blocks.get(child_idx).is_none(),
        "the offending block is deleted from the tree (and its durable slot freed)"
    );
    let genesis_idx = bc
        .blocks
        .find(0, &genesis.view().hash())
        .expect("genesis survives");
    let cfg_idx = bc
        .blocks
        .find(1, &cfg.view().hash())
        .expect("chain-config block survives");
    assert_eq!(bc.blocks.len(), 2);
    // AC11(f), amended: the shortened branch is re-evaluated in this very
    // call and validates, so the node is Ready on return — no second
    // admission, no tick, no wait for ambient traffic.
    assert!(
        bc.is_ready(),
        "the retry validates the shortened genesis-anchored candidate in-call"
    );
    assert_eq!(
        bc.active_chain_head_idx, cfg_idx,
        "the retry's Ready transition establishes the surviving tip as the active head"
    );
    assert_eq!(
        bc.blocks
            .get(genesis_idx)
            .expect("genesis present")
            .status(),
        BlockStatus::Active,
        "the surviving candidate is promoted Stored→Active by the retry"
    );
    // AC11(c): the offender's derived effect is gone — the retry re-derived
    // from the surviving segment alone, it did not resume the failed pass.
    assert!(
        !bc.node_info.is_seeded(5),
        "the offending registration's effect is absent from the working set"
    );
    assert_eq!(bc.node_info.max_known_node_id(), 0);
}

// --- Story 5.5: FR5 atomic recovery -------------------------------------

/// AC11(a) — an `Invalid` failure deletes the offending block **and** its
/// transitive descendants, and nothing else: a sibling subtree whose
/// ancestry does not pass through the target survives, as does the target's
/// own ancestor.
#[test]
fn fr5_deletes_offender_subtree_and_spares_sibling() {
    let mut bc = new_test_chain();
    let genesis = genesis_zero_block(1_000);
    let gi = bc
        .tier1_admit(&genesis.view(), &genesis.view().hash(), 0)
        .expect("genesis admitted");
    // Offending branch: genesis ← b1 ← b2.
    let b1 = transfer_block(1, genesis.view().hash(), 1, 2, 100, TEST_TRANSFER_FEE, 0);
    let bi1 = bc
        .tier1_admit(&b1.view(), &b1.view().hash(), 0)
        .expect("b1 admitted");
    let b2 = transfer_block(2, b1.view().hash(), 1, 2, 100, TEST_TRANSFER_FEE, 0);
    let bi2 = bc
        .tier1_admit(&b2.view(), &b2.view().hash(), 0)
        .expect("b2 admitted");
    // Sibling branch forking at the genesis (a different amount → a distinct
    // hash, so it is a genuine second child, not an FR11 duplicate).
    let c1 = transfer_block(1, genesis.view().hash(), 1, 2, 200, TEST_TRANSFER_FEE, 0);
    let ci1 = bc
        .tier1_admit(&c1.view(), &c1.view().hash(), 0)
        .expect("c1 admitted");
    assert_eq!(bc.blocks.len(), 4);

    bc.set_lifecycle_phase(LifecyclePhase::Processing);
    bc.recover_from_failed_pass(
        ProcessingError::Invalid {
            block_idx: bi1,
            reason: ValidationReason::UnseededActor,
        },
        bi2,
    );

    assert!(
        bc.blocks.get(bi1).is_none(),
        "the earliest offender is deleted"
    );
    assert!(
        bc.blocks.get(bi2).is_none(),
        "its transitive descendant is deleted too"
    );
    assert!(
        bc.blocks.get(gi).is_some(),
        "the target's ancestor survives"
    );
    assert!(
        bc.blocks.get(ci1).is_some(),
        "the sibling subtree is untouched"
    );
    assert_eq!(bc.blocks.len(), 2);
    // FR19 event (iv): only the sibling branch is still tracked, and the
    // genesis keeps no entry of its own (it still has the sibling child).
    assert_eq!(bc.chain_heads.count(), 1);
    assert!(bc.chain_heads.occupied_heads().any(|(h, _)| h == ci1));
    assert_eq!(bc.current_phase(), LifecyclePhase::Collecting);
}

/// AC11(b) — an arithmetic vote failure is not exact evidence against any
/// specific block, so exactly **one** block is deleted: the candidate head.
/// The local failures delete nothing.
/// Its parent becomes the new tip and stays tracked, so the shortened branch
/// remains an FR2 candidate.
#[test]
fn fr5_non_invalid_error_deletes_only_the_candidate_head() {
    fn run(err: ProcessingError) -> (usize, bool, bool) {
        let mut bc = new_test_chain();
        let genesis = genesis_zero_block(1_000);
        bc.tier1_admit(&genesis.view(), &genesis.view().hash(), 0)
            .expect("genesis admitted");
        let b1 = transfer_block(1, genesis.view().hash(), 1, 2, 100, TEST_TRANSFER_FEE, 0);
        let bi1 = bc
            .tier1_admit(&b1.view(), &b1.view().hash(), 0)
            .expect("b1 admitted");
        let b2 = transfer_block(2, b1.view().hash(), 1, 2, 100, TEST_TRANSFER_FEE, 0);
        let bi2 = bc
            .tier1_admit(&b2.view(), &b2.view().hash(), 0)
            .expect("b2 admitted");
        bc.set_lifecycle_phase(LifecyclePhase::Processing);
        bc.recover_from_failed_pass(err, bi2);
        (
            bc.blocks.len(),
            bc.blocks.get(bi2).is_none(),
            // The retargeted entry tracks b1 as the new tip.
            bc.chain_heads.occupied_heads().any(|(h, _)| h == bi1),
        )
    }
    // A local failure is no evidence at all: nothing is deleted (amended
    // FR5, DEC-037 and DEC-134).
    for err in [
        ProcessingError::StorageRead,
        ProcessingError::Vote(VoteEngineError::NotParameterized),
        ProcessingError::MissingBlock,
        ProcessingError::MarkOverflow,
    ] {
        assert_eq!(run(err).0, 3, "a local failure deletes nothing");
    }
    // `Vote(_)` is the one the head fallback exists for: the Story-5.4
    // review accepted that a vote failure carries no `block_idx`, and this
    // arm is what makes that imprecision safe.
    assert_eq!(
        run(ProcessingError::Vote(
            VoteEngineError::AccumulatedVoteOverflow
        )),
        (2, true, true),
        "the head fallback deletes exactly the candidate head and keeps \
         the shortened branch tracked"
    );
}

/// Task 2 / AC3 degenerate target: an `Invalid` whose `block_idx` names an
/// empty or out-of-range slot must still perform the rollback and the
/// reversion. That is the branch which skips `on_blocks_deleted` *and* the
/// `active_chain_head_idx` clearing through `if deleted_count > 0`, so it
/// needs coverage at the recovery level — `mark_subtree_of_empty_or_out_of_range_root_is_empty`
/// only proves the helper returns an empty set.
#[test]
fn fr5_degenerate_target_still_rolls_back_and_reverts() {
    let mut bc = new_test_chain();
    // FR8 (Story 5.9, AC3): the candidate must carry a chain-config
    // block in scope, so the segment is anchored by one. Inert with
    // respect to everything below — see `chain_config_anchor_block`.
    let cfg_hash = admit_chain_config_anchor(&mut bc, 99, [0xAB; 32]);
    let anchor = balance_block(100, cfg_hash, &[(1, 500, 10, 0x31), (2, 300, 20, 0x32)], 5);
    bc.tier1_admit(&anchor.view(), &anchor.view().hash(), 0)
        .expect("anchor admitted");
    let tx = transfer_block(101, anchor.view().hash(), 1, 2, 100, TEST_TRANSFER_FEE, 0);
    bc.tier1_admit(&tx.view(), &tx.view().hash(), 0)
        .expect("tx admitted");
    let reg = registration_block(102, tx.view().hash(), 1, 3, 0x43);
    let ri = bc
        .tier1_admit(&reg.view(), &reg.view().hash(), 0)
        .expect("registration admitted");

    // Dirty the working set for real, so the rollback has something to undo.
    bc.run_processing_pass(ri).expect_err("watermark violation");
    assert!(bc.node_info.is_seeded(1), "the aborted pass derived state");
    let blocks_before = bc.blocks.len();
    let mut heads_before = [(NONE_REF, NONE_REF); 4];
    for (slot, head) in heads_before.iter_mut().zip(bc.chain_heads.occupied_heads()) {
        *slot = head;
    }

    bc.set_lifecycle_phase(LifecyclePhase::Processing);
    bc.recover_from_failed_pass(
        ProcessingError::Invalid {
            block_idx: NONE_REF,
            reason: ValidationReason::RegistrationWatermark,
        },
        ri,
    );

    assert!(!bc.node_info.is_seeded(1), "rollback still runs");
    assert_eq!(bc.node_info.max_known_node_id(), 0, "watermark still reset");
    assert_eq!(
        bc.current_phase(),
        LifecyclePhase::Collecting,
        "reversion still runs"
    );
    assert_eq!(bc.blocks.len(), blocks_before, "nothing is deleted");
    let mut heads_after = [(NONE_REF, NONE_REF); 4];
    for (slot, head) in heads_after.iter_mut().zip(bc.chain_heads.occupied_heads()) {
        *slot = head;
    }
    assert_eq!(heads_after, heads_before, "the tip table is untouched");
}

/// AC11(c) — the working set is fully rolled back: per-node projection
/// (balances, keys, watermark), accumulated vote, and the surviving blocks'
/// available-UTXO bitfields. Driven through the real
/// `run_processing_pass` → `recover_from_failed_pass` pair over a
/// window-anchored candidate that derives state *before* it fails.
#[test]
fn fr5_working_set_is_clean_after_recovery() {
    let mut bc = new_test_chain();
    // FR8 (Story 5.9, AC3): the candidate must carry a chain-config
    // block in scope, so the segment is anchored by one. Inert with
    // respect to everything below — see `chain_config_anchor_block`.
    let cfg_hash = admit_chain_config_anchor(&mut bc, 99, [0xAB; 32]);
    // Window-anchored candidate: balance seed (watermark 5) → valid transfer
    // → out-of-sequence registration (id 3, expected 6).
    let anchor = balance_block(100, cfg_hash, &[(1, 500, 10, 0x31), (2, 300, 20, 0x32)], 5);
    let ai = bc
        .tier1_admit(&anchor.view(), &anchor.view().hash(), 0)
        .expect("anchor admitted");
    let tx = transfer_block(101, anchor.view().hash(), 1, 2, 100, TEST_TRANSFER_FEE, 0);
    let ti = bc
        .tier1_admit(&tx.view(), &tx.view().hash(), 0)
        .expect("tx admitted");
    let reg = registration_block(102, tx.view().hash(), 1, 3, 0x43);
    let ri = bc
        .tier1_admit(&reg.view(), &reg.view().hash(), 0)
        .expect("registration admitted");

    let err = bc.run_processing_pass(ri).expect_err("watermark violation");
    assert_eq!(
        err,
        ProcessingError::Invalid {
            block_idx: ri,
            reason: ValidationReason::RegistrationWatermark,
        }
    );
    // The aborted pass leaves its partial derivation behind — that is exactly
    // what the recovery has to discard.
    assert!(bc.node_info.is_seeded(1));
    assert_eq!(bc.node_info.max_known_node_id(), 5);

    bc.set_lifecycle_phase(LifecyclePhase::Processing);
    bc.recover_from_failed_pass(err, ri);

    assert!(!bc.node_info.is_seeded(1), "roster reset");
    assert!(!bc.node_info.is_seeded(2));
    assert_eq!(bc.node_info.balance_of(1), 0, "balances reset");
    assert_eq!(bc.node_info.balance_of(2), 0);
    assert!(bc.node_info.public_key_of(1).is_none(), "key mapping reset");
    assert_eq!(bc.node_info.max_known_node_id(), 0, "watermark reset");
    assert_eq!(
        bc.vote_engine.accumulated_vote_of(1),
        0,
        "accumulated vote reset"
    );
    assert_eq!(bc.vote_engine.accumulated_vote_of(2), 0);
    // The surviving segment's available-UTXO bits are at the clean all-zero baseline
    // (owned by the pass's entry/abort handling — recovery does not sweep
    // them a second time, and must not need to).
    for idx in [ai, ti] {
        for bit in 0..8 {
            assert_eq!(
                bc.blocks.utxo_available(idx, bit),
                Some(false),
                "no available-UTXO bit survives a failed candidate"
            );
        }
    }
    assert_eq!(bc.current_phase(), LifecyclePhase::Collecting);
}

/// AC11(d)/(e) — deleting the block `active_chain_head_idx` points at clears
/// the anchor placeholder (and empties `chain_heads`), which is what makes
/// re-acquisition of the discarded genesis possible: the single-genesis guard
/// keys on `active_chain_head_idx != NONE_REF`.
#[test]
fn fr5_clears_active_head_when_its_block_is_deleted() {
    let mut bc = new_test_chain();
    let genesis = genesis_zero_block(1_000);
    let gi = bc
        .tier1_admit(&genesis.view(), &genesis.view().hash(), 0)
        .expect("genesis admitted");
    let child = transfer_block(1, genesis.view().hash(), 1, 2, 100, TEST_TRANSFER_FEE, 0);
    let ci = bc
        .tier1_admit(&child.view(), &child.view().hash(), 0)
        .expect("child admitted");
    assert_eq!(bc.active_chain_head_idx, gi);

    // The genesis pair is not exempt: an `Invalid` pinned at block #0 deletes
    // it and everything descending from it (FR5 deletion is forward progress).
    bc.set_lifecycle_phase(LifecyclePhase::Processing);
    bc.recover_from_failed_pass(
        ProcessingError::Invalid {
            block_idx: gi,
            reason: ValidationReason::CreatorSignatureInvalid,
        },
        ci,
    );

    assert_eq!(bc.blocks.len(), 0, "the whole subtree is gone");
    assert_eq!(
        bc.active_chain_head_idx, NONE_REF,
        "the anchor placeholder is cleared with its target"
    );
    assert_eq!(bc.chain_heads.count(), 0, "no tracked tip remains");
    // Re-acquisition is now possible — the guard no longer refuses a genesis.
    assert!(
        bc.tier1_admit(&genesis.view(), &genesis.view().hash(), 0)
            .is_ok(),
        "a node that discarded its genesis can re-acquire one"
    );
}

/// AC7, amended 2026-07-30 — recovery restores the **whole** pre-acquisition
/// active-chain marking, not just the anchor index: every block's
/// `is_on_active_chain` bit is cleared, and the FR19 genesis bootstrap is
/// re-established on the surviving block #0. The pre-marked survivors here
/// stand in for a `promote_candidate_active` that ran before this recovery
/// (the Story-5.10 / Epic-6 reuse) — without the clearing they would keep
/// claiming to be on an active chain that no longer has a head.
#[test]
fn fr5_restores_active_chain_marking_and_keeps_the_genesis_bootstrap() {
    let mut bc = new_test_chain();
    let genesis = genesis_zero_block(1_000);
    let gi = bc
        .tier1_admit(&genesis.view(), &genesis.view().hash(), 0)
        .expect("genesis admitted");
    let b1 = transfer_block(1, genesis.view().hash(), 1, 2, 100, TEST_TRANSFER_FEE, 0);
    let bi1 = bc
        .tier1_admit(&b1.view(), &b1.view().hash(), 0)
        .expect("b1 admitted");
    let b2 = transfer_block(2, b1.view().hash(), 1, 2, 100, TEST_TRANSFER_FEE, 0);
    let bi2 = bc
        .tier1_admit(&b2.view(), &b2.view().hash(), 0)
        .expect("b2 admitted");
    // Stand in for a prior promotion: mark the whole chain Active and move
    // the anchor to the tip, exactly as `promote_candidate_active` would —
    // it writes the status and the bit together, so recovery must undo both.
    for idx in [gi, bi1, bi2] {
        bc.blocks.set_status(idx, BlockStatus::Active);
        bc.blocks.set_on_active_chain(idx, true);
    }
    bc.active_chain_head_idx = bi2;

    // Fail at b2 → only b2 is deleted; the genesis and b1 survive marked.
    bc.set_lifecycle_phase(LifecyclePhase::Processing);
    bc.recover_from_failed_pass(
        ProcessingError::Invalid {
            block_idx: bi2,
            reason: ValidationReason::CreatorSignatureInvalid,
        },
        bi2,
    );

    assert!(bc.blocks.get(bi2).is_none(), "the offender is deleted");
    assert!(
        !bc.blocks
            .get(bi1)
            .expect("b1 survives")
            .is_on_active_chain(),
        "a surviving non-genesis block no longer claims to be on the active chain"
    );
    assert!(
        bc.blocks
            .get(gi)
            .expect("genesis survives")
            .is_on_active_chain(),
        "the FR19 genesis bootstrap is re-established on the surviving block #0"
    );
    // FR9: collecting state holds every retained block at `Stored` — the
    // promotion's status half is undone with its flag half, and the genesis
    // is no exception (its bootstrap marking is not an FR9 promotion).
    for idx in [gi, bi1] {
        assert_eq!(
            bc.blocks.get(idx).expect("survivor").status(),
            BlockStatus::Stored,
            "every surviving block is back at Stored (FR9 collecting-state rule)"
        );
    }
    assert_eq!(
        bc.active_chain_head_idx, gi,
        "the anchor is restored to the genesis, not left at the deleted tip"
    );
    // The bootstrap is what keeps the shortened branch Connected: a demoted
    // head would carry the all-zero missing-parent hash and request it forever.
    assert!(
        bc.chain_heads.occupied_heads().any(|(head, _)| head == bi1),
        "the shortened branch is still tracked"
    );
}

/// AC11(g) — recovery is `now`-independent (FR63/NFR5): the same failing
/// candidate replayed under two wall-clocks produces the same deleted set,
/// the same tip table, the same phase, and the same anchor. Extends the
/// `receive_block_ignores_now` pattern of Stories 4.3/4.4/5.3.
#[test]
fn fr5_recovery_ignores_now() {
    // Compare *identity*, not cardinality: which slots survived, the tip
    // table's (head, tail-point) pairs, the anchor, the phase, and both
    // admission outcomes. `blocks.len()` alone cannot distinguish a
    // recovery that deleted a different block of the same count, and
    // discarding the outcomes would let the whole test pass vacuously if
    // both runs failed at intake and never reached the pass at all.
    #[derive(PartialEq, Debug)]
    struct Snapshot {
        occupied: [bool; 16],
        heads: [(u32, u32); 4],
        active: u32,
        ready: bool,
        outcomes: [ReceiveBlockOutcome; 2],
    }
    fn run(now: u64) -> Snapshot {
        let mut bc = new_test_chain();
        let genesis = genesis_zero_block(1_000);
        // Block #1 is the chain-config the FR8 final check requires below the
        // offender (Story 5.9, AC3) — see
        // `fr5_seam_recovers_and_retries_invalid_candidate_in_one_call`.
        let cfg = chain_config_anchor_block(1, genesis.view().hash());
        let child = registration_block(2, cfg.view().hash(), 1, 5, 0x45);
        let (first, _) = bc.receive_block(child.view(), now);
        bc.receive_block(cfg.view(), now.saturating_add(1_000));
        let (second, _) = bc.receive_block(genesis.view(), now.saturating_add(9_000));

        let mut occupied = [false; 16];
        for (slot, flag) in occupied.iter_mut().enumerate() {
            *flag = bc.blocks.get(slot as u32).is_some();
        }
        let mut heads = [(NONE_REF, NONE_REF); 4];
        for (entry, head) in heads.iter_mut().zip(bc.chain_heads.occupied_heads()) {
            *entry = head;
        }
        Snapshot {
            occupied,
            heads,
            active: bc.active_chain_head_idx,
            ready: bc.is_ready(),
            outcomes: [first, second],
        }
    }
    let baseline = run(0);
    assert_eq!(
        baseline,
        run(1_000_000),
        "the recovery outcome is identical across wall-clocks"
    );
    // Non-vacuity: both blocks really were admitted (so the FR2 gate ran the
    // pass), the pass really failed (phase back to Collecting), and the
    // deletion really happened (the offending child is gone).
    assert_eq!(
        baseline.outcomes,
        [
            ReceiveBlockOutcome::AcceptedSilently,
            ReceiveBlockOutcome::AcceptedSilently
        ],
        "both admissions succeeded, so the failing pass was actually reached"
    );
    assert!(
        baseline.ready,
        "the failed pass recovered and its in-call retry validated the shortened candidate"
    );
    assert_eq!(
        baseline.occupied.iter().filter(|slot| **slot).count(),
        2,
        "recovery deleted the offending subtree and left exactly the genesis \
         and the chain-config block"
    );
}

/// A `payload_type=1` block with an explicit `creator` + `mined_amount`
/// header and a single node transfer (used to exercise the FR36 creator
/// credit — the other builders hard-code `mined_amount: 0`, which would mask
/// a creator-credit bug).
fn credit_block(
    seq: u32,
    prev: [u8; 32],
    creator: u32,
    mined_amount: u32,
    initializer: u32,
    receiver: u32,
    amount: u64,
) -> Block {
    let signer = Crypto::new([1u8; PRIVATE_KEY_SIZE]).ok().expect("test key");
    let nt = NodeTransfer::new_signed(
        3,
        seq.saturating_sub(1),
        initializer,
        receiver,
        amount,
        TEST_TRANSFER_FEE,
        0,
        &signer,
    );
    let header = BlockHeader {
        version: 1,
        sequence: seq,
        creator,
        mined_amount,
        payload_type: PAYLOAD_TYPE_TRANSACTION,
        consumed_votes: 0,
        first_voted_node: 0,
        consumed_votes_from_first_voted_node: 0,
        previous_hash: prev,
        signature: [0u8; SIGNATURE_SIZE],
    };
    let mut builder = BlockBuilder::new().header(header);
    builder.add_node_transfer(&nt).ok().expect("add transfer");
    builder.build_signed(&signer).ok().expect("build signed")
}

/// AC4 / FR36 — the creator credit is auto-accepted (skipped) for an unseeded
/// creator (pre-seed zone): no phantom balance is written to an unknown
/// baseline. Uses a non-zero `mined_amount` so the credit is observable, on a
/// chain whose `mining_reward` it equals (Story 7.2).
#[test]
fn fr3_creator_credit_skipped_for_unseeded_creator() {
    let mut bc = rewarded_test_chain(500);
    // FR8 (Story 5.9, AC3): the candidate must carry a chain-config
    // block in scope, so the segment is anchored by one. Inert with
    // respect to everything below — see `chain_config_anchor_block`.
    let cfg_hash = admit_rewarded_anchor(&mut bc, 99, [0xAB; 32], 500);
    let blk = credit_block(100, cfg_hash, 8, 500, 7, 9, 0);
    let bi = bc
        .tier1_admit(&blk.view(), &blk.view().hash(), 0)
        .expect("block admitted");

    bc.run_processing_pass(bi).expect("pass succeeds");

    assert!(
        !bc.node_info.is_seeded(8),
        "unseeded creator is not seeded by its own credit"
    );
    assert_eq!(
        bc.node_info.balance_of(8),
        0,
        "FR36 creator credit skipped for a pre-seed-zone creator (AC4)"
    );
}

/// FR36 — a seeded creator IS credited its `mined_amount` (+ fees), which
/// equals the chain's `mining_reward` (Story 7.2).
#[test]
fn fr3_creator_credit_applied_to_seeded_creator() {
    let mut bc = rewarded_test_chain(500);
    // FR8 (Story 5.9, AC3): the candidate must carry a chain-config
    // block in scope, so the segment is anchored by one. Inert with
    // respect to everything below — see `chain_config_anchor_block`.
    let cfg_hash = admit_rewarded_anchor(&mut bc, 99, [0xAB; 32], 500);
    // max_node_id 9 so the transfer's (unseeded, pre-window) initializer 7 and
    // receiver 9 are within the valid node-id range — only node 3 is
    // individually seeded (partial FR50 coverage).
    let anchor = balance_block_mined(100, cfg_hash, &[(3, 100, 0, 0x33)], 9, 500);
    bc.tier1_admit(&anchor.view(), &anchor.view().hash(), 0)
        .expect("anchor admitted");
    let blk = credit_block(101, anchor.view().hash(), 3, 500, 7, 9, 0);
    let bi = bc
        .tier1_admit(&blk.view(), &blk.view().hash(), 0)
        .expect("credit block admitted");

    bc.run_processing_pass(bi).expect("pass succeeds");

    assert_eq!(
        bc.node_info.balance_of(3),
        600 + u64::from(TEST_TRANSFER_FEE),
        "seeded creator credited mined_amount and the fee (100 seed + 500 mined + fee)"
    );
}

/// AC3 (Story 5.4) — FR6 registration monotonicity: a registration whose
/// `new_node_id` is not `pre-block watermark + 1` is exact evidence of
/// invalidity. (In Story 5.3 the derive-only pass merely absorbed the id
/// monotonically; FR6 now *rejects* an out-of-sequence registration, routing
/// to the FR5 recovery via the earliest-offending-block error.)
#[test]
fn fr6_rejects_out_of_sequence_registration() {
    let mut bc = new_test_chain();
    // FR8 (Story 5.9, AC3): the candidate must carry a chain-config
    // block in scope, so the segment is anchored by one. Inert with
    // respect to everything below — see `chain_config_anchor_block`.
    let cfg_hash = admit_chain_config_anchor(&mut bc, 99, [0xAB; 32]);
    // Balance block declares max_node_id 5 → watermark 5; the next valid
    // registration id is 6. A registration for id 3 violates the stride-1 rule.
    let anchor = balance_block(100, cfg_hash, &[(1, 100, 0, 0x31)], 5);
    bc.tier1_admit(&anchor.view(), &anchor.view().hash(), 0)
        .expect("anchor admitted");
    let reg = registration_block(101, anchor.view().hash(), 1, 3, 0x43);
    let ri = bc
        .tier1_admit(&reg.view(), &reg.view().hash(), 0)
        .expect("registration admitted (Tier 1 does not check the watermark)");

    let result = bc.run_processing_pass(ri);
    assert_eq!(
        result,
        Err(ProcessingError::Invalid {
            block_idx: ri,
            reason: ValidationReason::RegistrationWatermark,
        }),
        "FR6 rejects a non-(watermark+1) registration as the earliest offender"
    );
}

// Note: the FR6 no-self-vote rule is a *structural* invariant checkable from
// block bytes alone, so it is enforced at Tier 1 intake (`staged_validation`,
// `Rejected(SelfVote)`) before a block can ever reach the Tier-3 processing
// pass — the FR6 re-affirmation in `validate_and_derive_block` is
// defense-in-depth. Self-vote rejection is therefore covered by the Tier-1
// tests; only the roster-dependent vote-target check below is Tier-3-only.

/// AC5 (Story 5.4) — FR6 vote-target existence: a `vote` that names a node
/// absent from the candidate roster at inclusion is exact evidence of
/// invalidity. (Node #0 and `vote == 0` remain the permanent exception.)
#[test]
fn fr6_rejects_unknown_vote_target() {
    let mut bc = new_test_chain();
    // FR8 (Story 5.9, AC3): the candidate must carry a chain-config
    // block in scope, so the segment is anchored by one. Inert with
    // respect to everything below — see `chain_config_anchor_block`.
    let cfg_hash = admit_chain_config_anchor(&mut bc, 99, [0xAB; 32]);
    // max_node_id 8 so the transfer's initializer 1 and receiver 2 are in range;
    // the vote target 9 is beyond the watermark → cannot exist.
    let anchor = balance_block(100, cfg_hash, &[(1, 500, 0, 0x31)], 8);
    bc.tier1_admit(&anchor.view(), &anchor.view().hash(), 0)
        .expect("anchor admitted");
    // Vote target 9 is beyond max_known_node_id (8) → not a possible node.
    let tx = transfer_block(101, anchor.view().hash(), 1, 2, 100, TEST_TRANSFER_FEE, 9);
    let ti = bc
        .tier1_admit(&tx.view(), &tx.view().hash(), 0)
        .expect("tx admitted");
    assert_eq!(
        bc.run_processing_pass(ti),
        Err(ProcessingError::Invalid {
            block_idx: ti,
            reason: ValidationReason::VoteTargetUnknown,
        }),
        "FR6 rejects an unknown vote target"
    );
}

/// FR6 node-existence bound — a transaction that references a node id beyond
/// `max_known_node_id` (contiguous ids ⇒ it cannot exist) is rejected on BOTH
/// sides: the initializer (input) and the receiver (output). This holds even for
/// an unseeded (pre-window) node — its existence is still range-checkable — so a
/// window-anchored candidate is not blindly trusted.
#[test]
fn fr6_rejects_out_of_range_referenced_node() {
    let mut bc = new_test_chain();
    // FR8 (Story 5.9, AC3): the candidate must carry a chain-config
    // block in scope, so the segment is anchored by one. Inert with
    // respect to everything below — see `chain_config_anchor_block`.
    let cfg_hash = admit_chain_config_anchor(&mut bc, 99, [0xAB; 32]);
    // Window-anchored, watermark 5 (only node 1 individually seeded).
    let anchor = balance_block(100, cfg_hash, &[(1, 500, 0, 0x31)], 5);
    bc.tier1_admit(&anchor.view(), &anchor.view().hash(), 0)
        .expect("anchor admitted");
    // Output side: receiver 99 is beyond the watermark.
    let out = transfer_block(101, anchor.view().hash(), 1, 99, 100, TEST_TRANSFER_FEE, 0);
    let oi = bc
        .tier1_admit(&out.view(), &out.view().hash(), 0)
        .expect("out admitted");
    assert_eq!(
        bc.run_processing_pass(oi),
        Err(ProcessingError::Invalid {
            block_idx: oi,
            reason: ValidationReason::NodeIdOutOfRange,
        }),
        "a transfer TO a node beyond the watermark is rejected (output side)"
    );
    // Input side: an (unseeded) initializer 88 is beyond the watermark — normally
    // an unseeded initializer is trusted on a window-anchored candidate, but its
    // existence is still range-bounded.
    let inp = transfer_block(101, anchor.view().hash(), 88, 2, 100, TEST_TRANSFER_FEE, 0);
    let ii = bc
        .tier1_admit(&inp.view(), &inp.view().hash(), 0)
        .expect("inp admitted");
    assert_eq!(
        bc.run_processing_pass(ii),
        Err(ProcessingError::Invalid {
            block_idx: ii,
            reason: ValidationReason::NodeIdOutOfRange,
        }),
        "a transfer FROM a node beyond the watermark is rejected (input side)"
    );
}

/// FR6 vote-target existence is a WATERMARK RANGE check, not a per-node
/// `is_seeded` lookup. A balance block covers only a subset of nodes (FR50) but
/// declares the full `max_node_id`; a transaction may legitimately vote for a
/// node that exists (id ≤ watermark) yet whose own balance-block coverage is
/// not present earlier in the window. This must be ACCEPTED — the pre-fix
/// `is_seeded(vote)` check would have falsely rejected it as `VoteTargetUnknown`.
#[test]
fn fr6_vote_target_in_range_but_not_individually_seeded_is_accepted() {
    let mut bc = new_test_chain();
    // FR8 (Story 5.9, AC3): the candidate must carry a chain-config
    // block in scope, so the segment is anchored by one. Inert with
    // respect to everything below — see `chain_config_anchor_block`.
    let cfg_hash = admit_chain_config_anchor(&mut bc, 99, [0xAB; 32]);
    // Partial-coverage balance block: seeds only node 1, but declares
    // max_node_id = 10 (nodes 2..=10 exist pre-window / elsewhere in the window
    // but are not individually seeded by THIS block).
    let anchor = balance_block(100, cfg_hash, &[(1, 500, 0, 0x31)], 10);
    bc.tier1_admit(&anchor.view(), &anchor.view().hash(), 0)
        .expect("anchor admitted");
    // Node 1 (seeded) votes for node 5: 5 ∉ seeded-set but 5 ≤ watermark(10).
    let tx = transfer_block(101, anchor.view().hash(), 1, 2, 100, TEST_TRANSFER_FEE, 5);
    let ti = bc
        .tier1_admit(&tx.view(), &tx.view().hash(), 0)
        .expect("tx admitted");
    assert_eq!(
        bc.run_processing_pass(ti).map(|_| ()),
        Ok(()),
        "a vote for an in-range node is accepted even if not individually seeded"
    );
    // Boundary: a vote for node 11 (> watermark 10) is still exact-evidence invalid.
    let tx2 = transfer_block(101, anchor.view().hash(), 1, 2, 100, TEST_TRANSFER_FEE, 11);
    let ti2 = bc
        .tier1_admit(&tx2.view(), &tx2.view().hash(), 0)
        .expect("tx2 admitted");
    assert_eq!(
        bc.run_processing_pass(ti2),
        Err(ProcessingError::Invalid {
            block_idx: ti2,
            reason: ValidationReason::VoteTargetUnknown,
        }),
        "a vote for a node beyond the watermark is still rejected"
    );
}

/// FR3/FR6 — on a WINDOW-anchored candidate the incremental watermark is only
/// authoritative once the first balance block establishes it. A registration
/// that precedes the first balance block is in the trusted pre-window region
/// (AC4): its monotonicity is NOT re-checked (it would otherwise be measured
/// against a still-0 watermark and falsely rejected). The earliest balance
/// block's `max_node_id` (read once at the end of the backward mark) seeds the
/// existence floor. Genesis-anchored candidates are unaffected — they re-derive
/// the watermark from block #0, so their registrations ARE monotonicity-checked
/// (covered by `fr6_rejects_out_of_sequence_registration`).
#[test]
fn fr6_window_anchored_registration_before_first_balance_is_trusted() {
    let mut bc = new_test_chain();
    // FR8 (Story 5.9, AC3): the candidate must carry a chain-config
    // block in scope, so the segment is anchored by one. Inert with
    // respect to everything below — see `chain_config_anchor_block`.
    let cfg_hash = admit_chain_config_anchor(&mut bc, 99, [0xAB; 32]);
    // Orphan anchor (seq 100, window-anchored): a registration for node 7 —
    // stride-1 against a 0 watermark would demand id 1, so the OLD per-0 check
    // would reject it. It precedes the segment's only balance block (seq 101).
    let reg = registration_block(100, cfg_hash, 1, 7, 0x47);
    bc.tier1_admit(&reg.view(), &reg.view().hash(), 0)
        .expect("registration admitted");
    // Balance block at seq 101: declares the full count (max_node_id 10) — the
    // existence floor — and seeds node 1.
    let bal = balance_block(101, reg.view().hash(), &[(1, 100, 0, 0x31)], 10);
    let bi = bc
        .tier1_admit(&bal.view(), &bal.view().hash(), 0)
        .expect("balance admitted");
    assert_eq!(
        bc.run_processing_pass(bi).map(|_| ()),
        Ok(()),
        "a window-anchored pre-first-balance registration is trusted, not \
         rejected against a 0 watermark"
    );
    // The registered node is on the roster afterwards.
    assert!(
        bc.node_info.is_seeded(7),
        "node 7 registered during the pass"
    );
}

/// AC2 (Story 5.4) — FR6 block-creator signature: a block whose creator key
/// is derivable (node #0 → the FR69 trust anchor) but whose signature was
/// produced by a different key is rejected (the first block-creator-signature
/// check in the crate).
#[test]
fn fr6_rejects_wrong_block_creator_signature() {
    let mut bc = new_test_chain();
    // A received block #0 is signature-checked at intake (DEC-270), so the
    // pass-side check is exercised on a later block: #2, creator node #0,
    // signed by the WRONG key ([9u8] ≠ the trust anchor pubkey([1u8])).
    // Outside Ready, intake does not judge it; the FR3 pass does.
    let genesis = genesis_zero_block(1_000);
    bc.tier1_admit(&genesis.view(), &genesis.view().hash(), 0)
        .expect("genesis admitted");
    // FR8 (Story 5.9, AC3): the candidate must name a configuration.
    let cfg = chain_config_anchor_block(1, genesis.view().hash());
    bc.tier1_admit(&cfg.view(), &cfg.view().hash(), 0)
        .expect("chain-config block admitted");
    let wrong = Crypto::new([9u8; PRIVATE_KEY_SIZE])
        .ok()
        .expect("wrong test key");
    let nt = NodeTransfer::new_signed(0, 1, 0, 9, 100, TEST_TRANSFER_FEE, 0, &wrong);
    let header = BlockHeader {
        version: 1,
        sequence: 2,
        creator: 0,
        mined_amount: 0,
        payload_type: PAYLOAD_TYPE_TRANSACTION,
        consumed_votes: 0,
        first_voted_node: 0,
        consumed_votes_from_first_voted_node: 0,
        previous_hash: cfg.view().hash(),
        signature: [0u8; SIGNATURE_SIZE],
    };
    let mut builder = BlockBuilder::new().header(header);
    builder.add_node_transfer(&nt).ok().expect("add transfer");
    let block = builder.build_signed(&wrong).ok().expect("build signed");
    let idx = bc
        .tier1_admit(&block.view(), &block.view().hash(), 0)
        .expect("admitted (outside Ready the creator signature is not a Tier 1 gate)");
    assert_eq!(
        bc.run_processing_pass(idx),
        Err(ProcessingError::Invalid {
            block_idx: idx,
            reason: ValidationReason::CreatorSignatureInvalid,
        }),
        "FR6 rejects a block-creator signature that fails against the derived key"
    );
}

/// AC7 (Story 5.4) — FR6 requires every balance block *after the earliest* to
/// carry `max_node_id` equal to the forward-traversal-tracked watermark at its
/// sequence; a divergence is exact evidence of invalidity. (Deferred from
/// Story 5.3, which only initialized the watermark from the earliest block.)
#[test]
fn fr6_rejects_later_balance_block_max_node_id_mismatch() {
    let mut bc = new_test_chain();
    // FR8 (Story 5.9, AC3): the candidate must carry a chain-config
    // block in scope, so the segment is anchored by one. Inert with
    // respect to everything below — see `chain_config_anchor_block`.
    let cfg_hash = admit_chain_config_anchor(&mut bc, 99, [0xAB; 32]);
    // Earliest balance block → watermark initialized to 1.
    let b0 = balance_block(100, cfg_hash, &[(1, 500, 0, 0x31)], 1);
    bc.tier1_admit(&b0.view(), &b0.view().hash(), 0)
        .expect("earliest balance block admitted");
    // A later balance block claims max_node_id 5 ≠ the tracked watermark 1.
    let b1 = balance_block(101, b0.view().hash(), &[(1, 400, 0, 0x31)], 5);
    let i1 = bc
        .tier1_admit(&b1.view(), &b1.view().hash(), 0)
        .expect("later balance block admitted");
    assert_eq!(
        bc.run_processing_pass(i1),
        Err(ProcessingError::Invalid {
            block_idx: i1,
            reason: ValidationReason::BalanceMaxNodeIdMismatch,
        }),
        "FR6 rejects a later balance block whose max_node_id diverges from the watermark"
    );
}

/// AC6 (Story 5.4) — FR6 chain-config compliance: a chain-config block
/// (`payload_type=3`) whose content is not byte-identical to the durable-locked
/// configuration is exact evidence of invalidity. (The FR7 content-signature
/// gate and establishing the lock from the candidate are Story 5.6.)
#[test]
fn fr6_rejects_divergent_chain_config() {
    // `new_test_chain` is durably locked on `BASE_CONFIG_CONTENT`; this
    // block carries a different (but equally well-framed) content region.
    let mut bc = new_test_chain();
    let header = BlockHeader {
        version: 1,
        sequence: 5,
        creator: 0,
        mined_amount: 0,
        payload_type: PAYLOAD_TYPE_CHAIN_CONFIG,
        consumed_votes: 0,
        first_voted_node: 0,
        consumed_votes_from_first_voted_node: 0,
        previous_hash: [0u8; 32],
        signature: [0u8; SIGNATURE_SIZE],
    };
    let signer = Crypto::new([1u8; PRIVATE_KEY_SIZE]).ok().expect("test key");
    let mut builder = BlockBuilder::new().header(header);
    let mut config_payload = window_config_builder(TEST_W);
    config_payload
        .add_literal(parameter::MINING_REWARD, &0u32.to_le_bytes())
        .ok()
        .expect("a one-entry override set frames");
    builder
        .set_chain_config_payload(config_payload.build_signed(&signer))
        .ok()
        .expect("set chain-config payload");
    let block = builder.build_signed(&signer).ok().expect("build signed");
    let idx = bc
        .tier1_admit(&block.view(), &block.view().hash(), 0)
        .expect("admitted (content-signature gate is Story 5.6)");
    assert_eq!(
        bc.run_processing_pass(idx),
        Err(ProcessingError::Invalid {
            block_idx: idx,
            reason: ValidationReason::ChainConfigMismatch,
        }),
        "FR6 rejects a chain-config block diverging from the durable-locked config"
    );
}

/// AC3 (Story 5.4) — FR6 registration `new_public_key` global uniqueness: a
/// registration whose new key collides with an already-seeded node's key is
/// exact evidence of invalidity.
#[test]
fn fr6_rejects_duplicate_public_key() {
    let mut bc = new_test_chain();
    // FR8 (Story 5.9, AC3): the candidate must carry a chain-config
    // block in scope, so the segment is anchored by one. Inert with
    // respect to everything below — see `chain_config_anchor_block`.
    let cfg_hash = admit_chain_config_anchor(&mut bc, 99, [0xAB; 32]);
    let anchor = balance_block(100, cfg_hash, &[(1, 500, 0, 0x31)], 1);
    bc.tier1_admit(&anchor.view(), &anchor.view().hash(), 0)
        .expect("anchor admitted");
    // pk_byte == 1 ⇒ new_public_key == pubkey([1u8]) == node 1's seeded key.
    let reg = registration_block(101, anchor.view().hash(), 1, 2, 1);
    let ri = bc
        .tier1_admit(&reg.view(), &reg.view().hash(), 0)
        .expect("registration admitted");
    assert_eq!(
        bc.run_processing_pass(ri),
        Err(ProcessingError::Invalid {
            block_idx: ri,
            reason: ValidationReason::DuplicatePublicKey,
        }),
        "FR6 rejects a registration whose new_public_key duplicates a seeded node's key"
    );
}

/// AC2/AC4 (Story 5.4) — on a GENESIS-anchored candidate (re-derivable in full
/// from block #0) there is no pre-seed trust zone: a transaction whose
/// initializer was never registered/seeded acts before it exists and is exact
/// evidence of invalidity (`UnseededActor`) — unlike a window-anchored
/// candidate, which legitimately trusts such pre-window history.
#[test]
fn fr6_rejects_unseeded_actor_on_genesis_anchored_candidate() {
    let mut bc = new_test_chain();
    // Genesis block #0 seeds node #0 only (FR54); node 1 never registers.
    let genesis = genesis_zero_block(1_000);
    bc.tier1_admit(&genesis.view(), &genesis.view().hash(), 0)
        .expect("genesis admitted");
    // FR8 (Story 5.9, AC3): block #1 carries the chain-config the candidate
    // must name — the existence check precedes the forward traversal (PRD
    // FR3), and it sits below the offender so the walk still reaches it.
    let cfg = chain_config_anchor_block(1, genesis.view().hash());
    bc.tier1_admit(&cfg.view(), &cfg.view().hash(), 0)
        .expect("chain-config block admitted");
    // Block #2: a transfer whose initializer (node 1) never registered.
    let child = transfer_block(2, cfg.view().hash(), 1, 2, 100, TEST_TRANSFER_FEE, 0);
    let ci = bc
        .tier1_admit(&child.view(), &child.view().hash(), 0)
        .expect("child admitted");
    assert_eq!(
        bc.run_processing_pass(ci),
        Err(ProcessingError::Invalid {
            block_idx: ci,
            reason: ValidationReason::UnseededActor,
        }),
        "genesis-anchored: an unseeded initializer is invalid (no pre-seed trust)"
    );
}

// ---- Story 6.10: received genesis blocks in the FR3 pass ----

/// Admits `blocks` in order and returns the last one's index.
fn admit_all(bc: &mut TestChain, blocks: &[&Block]) -> u32 {
    let mut last = NONE_REF;
    for block in blocks {
        last = bc
            .tier1_admit(&block.view(), &block.view().hash(), 0)
            .expect("admitted");
    }
    last
}

/// Story 6.10 AC5 / AC6 (DEC-269, D4): the FR36 genesis exception at
/// sequence 1 needs the chain-config content too. A transaction block at
/// sequence 1 is an ordinary block: its creator, node #0, is credited its
/// `mined_amount` (before 6.10 the sequence alone exempted it).
#[test]
fn a_sequence_one_transaction_block_gets_the_ordinary_fr36_credit() {
    // A chain whose `mining_reward` is 5, so `mined_amount = 5` is valid
    // (FR6, Story 7.2) and the credit observable.
    let mut bc = rewarded_test_chain(5);
    let genesis = genesis_zero_block(1_000);
    let signer = Crypto::new([1u8; PRIVATE_KEY_SIZE]).ok().expect("test key");
    let nt = NodeTransfer::new_signed(0, 0, 0, 0, 0, TEST_TRANSFER_FEE, 0, &signer);
    let header = BlockHeader {
        version: 1,
        sequence: 1,
        creator: 0,
        mined_amount: 5,
        payload_type: PAYLOAD_TYPE_TRANSACTION,
        consumed_votes: 0,
        first_voted_node: 0,
        consumed_votes_from_first_voted_node: 0,
        previous_hash: genesis.view().hash(),
        signature: [0u8; SIGNATURE_SIZE],
    };
    let mut builder = BlockBuilder::new().header(header);
    builder.add_node_transfer(&nt).ok().expect("add transfer");
    let one = builder.build_signed(&signer).ok().expect("build signed");
    let cfg = chain_config_block_mined(2, one.view().hash(), &mut rewarded_config_builder(5), 5);
    // #2 and #1 first, as orphans, so block #0's arrival completes the
    // genesis-anchored candidate and the node goes Ready on it (FR2–FR4).
    for block in [&cfg, &one, &genesis] {
        let (outcome, _) = bc.receive_block(block.view(), 0);
        assert_eq!(outcome, ReceiveBlockOutcome::AcceptedSilently);
    }
    assert!(bc.is_ready());
    // Block #2, a non-genesis chain-config block, is replay-bearing (FR36
    // (c), DEC-306): node #0 also earns its `mined_amount` and the 100
    // `replay_block_reward`.
    assert_eq!(
        bc.node_info.balance_of(0),
        1_000 + 5 + 5 + 100,
        "the minted 1 000 plus block #1's mined_amount, plus block #2's credit"
    );
    // The chain-switch inverse uses the same predicate: undoing #2 and then
    // #1 takes the credit back (`api/switch.rs` `undo_committed_block`).
    assert_eq!(bc.undo_active_head(), Ok(()), "#2 undone");
    assert_eq!(bc.undo_active_head(), Ok(()), "#1 undone");
    assert_eq!(
        bc.node_info.balance_of(0),
        1_000,
        "block #1's credit is undone"
    );
}

/// Story 6.10 AC5 / AC6: a chain-config block at sequence 1 whose content is
/// not the held configuration is condemned by the per-block step — the
/// content half of block #1's genesis exception.
#[test]
fn a_sequence_one_config_block_of_other_content_is_condemned() {
    let mut bc = new_test_chain();
    let genesis = genesis_zero_block(1_000);
    let mut other = alt_config_builder();
    let one = chain_config_block_from(1, genesis.view().hash(), &mut other);
    let tip = admit_all(&mut bc, &[&genesis, &one]);
    assert_eq!(
        bc.run_processing_pass(tip),
        Err(ProcessingError::Invalid {
            block_idx: tip,
            reason: ValidationReason::ChainConfigMismatch,
        })
    );
}

/// Story 6.10 AC4 / AC6 (DEC-271): block #0's transaction signatures are
/// verified against the trust anchor like any transaction's. Each block #0
/// below has the fixed shape, a valid creator signature and a valid proof of
/// possession, so intake admits it; one transaction signature is not the
/// anchor's.
#[test]
fn block_zero_transaction_signatures_are_verified() {
    let wrong = Crypto::new([9u8; PRIVATE_KEY_SIZE])
        .ok()
        .expect("wrong key");
    let (anchor, registration, transfer) = genesis_zero_transactions(1_000);
    // The self-transfer signed by another key.
    let bad_transfer = NodeTransfer::new_signed(0, 0, 0, 0, 1_000, 0, 0, &wrong);
    // The registration with the anchor's proof of possession but another
    // key's transaction signature.
    let reg_view = TransactionView::from_bytes(registration.as_bytes())
        .and_then(|tx| tx.as_registration())
        .expect("a registration");
    let pop: [u8; SIGNATURE_SIZE] = reg_view
        .new_key_signature()
        .try_into()
        .expect("signature size");
    let bad_registration = Registration::new(
        0,
        0,
        0,
        0,
        0,
        0,
        anchor.public_key().serialize(),
        &pop,
        wrong.sign(b"not this transaction").serialize(),
    );
    for (reg, nt) in [
        (&registration, &bad_transfer),
        (&bad_registration, &transfer),
    ] {
        let mut bc = new_test_chain();
        let genesis = block_zero_from(reg, nt, [0u8; 32], &anchor);
        let cfg = chain_config_anchor_block(1, genesis.view().hash());
        let idx = admit_all(&mut bc, &[&genesis]);
        let tip = admit_all(&mut bc, &[&cfg]);
        assert_eq!(
            bc.run_processing_pass(tip),
            Err(ProcessingError::Invalid {
                block_idx: idx,
                reason: ValidationReason::TransactionSignatureInvalid,
            })
        );
    }
}
