//! Tests of `api/admission.rs`.

use super::*;

// --- Story 4.2: FR9 Tier 1 admission entry point ------------------------

/// AC4: a Tier 1-passing block is admitted at `Stored` and persisted.
#[test]
fn tier1_admit_inserts_at_stored() {
    let mut bc = new_test_chain();
    let block = node_transfer_block(5, 3, 4, 7);
    let idx = bc
        .tier1_admit(&block.view(), &block.view().hash(), 1_000)
        .expect("well-formed block is admitted");
    assert_eq!(bc.blocks.len(), 1);
    assert_eq!(
        bc.blocks.get(idx).expect("entry present").status(),
        BlockStatus::Stored,
        "collecting-state admission is always Stored (AC4)"
    );
    // Durable storage received the block (storage-first admission).
    assert!(bc.storage.read_block(idx).is_ok());
}

/// AC5: a Tier 1 failure returns the exact-evidence form and stores nothing.
#[test]
fn tier1_admit_rejects_and_does_not_store() {
    let mut bc = new_test_chain();
    // initializer == vote == 7 → FR6 self-vote.
    let block = node_transfer_block(5, 7, 4, 7);
    let result = bc.tier1_admit(&block.view(), &block.view().hash(), 1_000);
    assert_eq!(result, Err(AdmitError::Rejected(Tier1Failure::SelfVote)));
    assert_eq!(bc.blocks.len(), 0, "a rejected block must not be stored");
}

// (FR11 de-duplication is owned by `classify_block`, not `tier1_admit`, so
// there is no `tier1_admit` duplicate case — the dedup outcome is covered
// by `intake::tests::receive_block_duplicate_is_duplicate_known`.)

// --- Story 4.4: FR19 chain_heads admission / scheduler / bootstrap -------

/// AC7 — a genesis block (sequence 0, no parent) anchors the active chain: it
/// becomes a Connected head, `active_chain_head_idx` is set, and no Stored
/// head (hence no parent-recovery tick) is scheduled.
#[test]
fn receive_block_genesis_anchors_active_head() {
    // A joining node, holding no configuration yet — the order in which a
    // real node meets a chain, and the only order in which the genesis can be
    // observed on its own: once a configuration is held, the genesis
    // admission completes an FR2 candidate and the whole lifecycle runs
    // inside this same call.
    let mut bc = new_unconfigured_test_chain();
    // Block-zero waives the self-vote / anchor Tier 1 checks.
    let genesis = node_transfer_block(0, 7, 0, 7);
    let (outcome, _) = bc.receive_block(genesis.view(), 100);
    assert_eq!(outcome, ReceiveBlockOutcome::AcceptedSilently);
    assert_eq!(
        bc.current_active_head(),
        Some(0),
        "genesis is the active head"
    );
    // FR8 (Story 5.9): block #1 carries the chain-config, exactly as the FR54
    // bootstrap emits it. It loads the tentative configuration (AC2) and
    // completes a candidate that names one (AC3), so the node goes Ready —
    // which is what makes the `NextCall::Idle` assertion below non-vacuous:
    // the intervals it would need are now available, and there is genuinely
    // no Stored head left to schedule.
    let cfg = chain_config_anchor_block(1, genesis.view().hash());
    let (outcome, next) = bc.receive_block(cfg.view(), 100);
    assert_eq!(outcome, ReceiveBlockOutcome::AcceptedSilently);
    assert!(
        bc.blocks
            .get(0)
            .is_some_and(|entry| entry.is_on_active_chain()),
        "the genesis still anchors the active chain"
    );
    assert!(
        matches!(next, NextCall::Idle),
        "a fully-connected active chain schedules no parent recovery"
    );
}

/// AC7 — a non-genesis first block with an unresolved parent creates a Stored
/// head and schedules the initial parent-recovery tick.
#[test]
fn receive_block_orphan_creates_stored_head_and_schedules() {
    let mut bc = new_test_chain();
    let orphan = node_transfer_block(5, 3, 4, 7);
    let (outcome, next) = bc.receive_block(orphan.view(), 1_000);
    assert_eq!(outcome, ReceiveBlockOutcome::AcceptedSilently);
    assert!(bc.current_active_head().is_none());
    assert!(
        matches!(next, NextCall::At(_)),
        "orphan schedules parent recovery"
    );
}

/// AC2 — `on_tick` emits exactly one FR19 request for the Stored head, with
/// the tail-point's missing-parent hash and `tail.sequence − 1`.
#[test]
fn on_tick_emits_parent_recovery_request() {
    let mut bc = new_test_chain();
    let orphan = node_transfer_block(5, 3, 4, 7); // previous_hash == [0; 32]
    bc.receive_block(orphan.view(), 0);
    // Advance past the FR46 global cooldown + per-head retry (lrt == 0).
    let (outcome, next) = bc.on_tick(1_000_000);
    match outcome {
        TickOutcome::SendParentRecoveryRequest(req) => {
            assert_eq!(req.missing_parent_hash(), &[0u8; 32]);
            assert_eq!(req.claimed_parent_sequence(), 4, "tail.sequence - 1");
        }
        TickOutcome::Idle => panic!("a Stored head past its retry window must emit"),
    }
    assert!(
        matches!(next, NextCall::At(_)),
        "Stored head still awaits its parent"
    );
}

/// AC2/AC3 — the FR46 global emit cooldown suppresses a second emission within
/// `parent_recovery_min_emit_interval`, even with an eligible head.
#[test]
fn on_tick_global_cooldown_suppresses_second_emission() {
    let mut bc = new_test_chain();
    // Two orphan heads so a head is always eligible.
    bc.receive_block(node_transfer_block(5, 3, 4, 7).view(), 0);
    bc.receive_block(linked_transfer_block(9, [0xAB; 32]).view(), 0);
    let t = 1_000_000;
    let (first, _) = bc.on_tick(t);
    assert!(matches!(first, TickOutcome::SendParentRecoveryRequest(_)));
    // min_emit is 10_000ms; a tick 5_000ms later is inside the cooldown.
    let (second, _) = bc.on_tick(t + 5_000);
    assert_eq!(second, TickOutcome::Idle, "global cooldown suppresses");
    // Past the cooldown, emission resumes.
    let (third, _) = bc.on_tick(t + 10_000);
    assert!(matches!(third, TickOutcome::SendParentRecoveryRequest(_)));
}

/// The `NextCall` is the **exact** next-eligible instant (AR4 pull model),
/// not `now + a fixed periodic tick`. A fresh orphan (`lrt == 0`, module
/// never emitted) is gated only by the FR46 boot-time global cooldown, so the
/// deadline is `min_emit` regardless of `now`; after an emission it is the
/// per-head window end.
#[test]
fn parent_recovery_nextcall_is_exact_deadline() {
    let mut bc = new_test_chain();
    let orphan = node_transfer_block(5, 3, 4, 7);
    // min_emit (stub) = 10_000; last_emit = 0 → deadline = max(0, 10_000).
    let (_, next) = bc.receive_block(orphan.view(), 5_000);
    assert!(
        matches!(next, NextCall::At(10_000)),
        "exact cooldown deadline, independent of now (5_000)"
    );
    // Emit at a large now; the next deadline is the per-head window end
    // (lrt 1_000_000 + per_head_retry 120_000), not now + a fixed interval.
    let (_, next2) = bc.on_tick(1_000_000);
    assert!(
        matches!(next2, NextCall::At(1_120_000)),
        "exact per-head window end after emission"
    );
}

/// AC3 — a fresh chain (no Stored heads) ticks Idle with no wake-up.
#[test]
fn on_tick_idle_without_stored_heads() {
    let mut bc = new_test_chain();
    let (outcome, next) = bc.on_tick(5_000);
    assert_eq!(outcome, TickOutcome::Idle);
    assert!(matches!(next, NextCall::Idle));
}

/// AC4 — an extend admission advances the single head (no second head).
#[test]
fn receive_block_extend_advances_head() {
    let mut bc = new_test_chain();
    let a = node_transfer_block(5, 3, 4, 7);
    bc.receive_block(a.view(), 0);
    let a_hash = a.view().hash();
    let b = linked_transfer_block(6, a_hash);
    let (outcome, _) = bc.receive_block(b.view(), 0);
    assert_eq!(outcome, ReceiveBlockOutcome::AcceptedSilently);
    assert_eq!(bc.block_tree_len(), 2);
    // Still one Stored head (A's orphan tail), advanced to B: on_tick emits a
    // request whose claimed parent is A's missing parent (tail seq 5 - 1 = 4).
    let (outcome, _) = bc.on_tick(1_000_000);
    match outcome {
        TickOutcome::SendParentRecoveryRequest(req) => {
            assert_eq!(req.claimed_parent_sequence(), 4);
        }
        TickOutcome::Idle => {
            panic!("the advanced Stored head must still request its tail parent")
        }
    }
}

/// AC9 — replaying an identical block + tick sequence against two fresh chains
/// yields identical emitted `ParentRecoveryRequest`s and tree/head state,
/// regardless of the `now` values used for scheduling.
#[test]
fn parent_recovery_is_deterministic_replay() {
    // `no_std`: collect emitted claimed-sequences into a fixed array
    // (at most one per tick).
    fn run(ticks: &[u64; 3]) -> (usize, [Option<u32>; 3]) {
        let mut bc = new_test_chain();
        // Three orphan heads with distinct sequences.
        for seq in [7u32, 5, 9] {
            bc.receive_block(node_transfer_block(seq, 3, seq - 1, 7).view(), 0);
        }
        let mut claimed: [Option<u32>; 3] = [None; 3];
        for (i, &t) in ticks.iter().enumerate() {
            if let (TickOutcome::SendParentRecoveryRequest(req), _) = bc.on_tick(t) {
                claimed[i] = Some(req.claimed_parent_sequence());
            }
        }
        (bc.block_tree_len(), claimed)
    }
    // Widely spaced ticks so each clears the global cooldown + per-head retry.
    let ticks = [1_000_000, 2_000_000, 3_000_000];
    let (len_a, claims_a) = run(&ticks);
    let (len_b, claims_b) = run(&ticks);
    assert_eq!(len_a, len_b);
    assert_eq!(
        claims_a, claims_b,
        "identical emission order across replays"
    );
    // Deterministic selection: smallest head_sequence (5) first → claimed 4.
    assert_eq!(claims_a[0], Some(4));
}

// --- Story 5.1: lifecycle state machine, init paths, not-ready gating -----

/// AC1/AC3 — a freshly constructed node (join path via `init`) is in
/// `Collecting` and not ready.
#[test]
fn fresh_node_is_collecting_and_not_ready() {
    let bc = new_test_chain();
    assert!(bc.current_phase() == LifecyclePhase::Collecting);
    assert!(!bc.is_ready());
}

/// AC2 — a node that authored genesis is `Ready` (init-time direct-set, not a
/// runtime transition).
#[test]
fn genesis_node_is_ready() {
    let (crypto, storage, chain_config) = test_backends();
    let mut bc = new_chain(crypto, storage, chain_config, 0, 1);
    bc.process_genesis(1_000_000_000, &BASE_CONFIG_CONTENT)
        .ok()
        .expect("genesis must succeed");
    assert!(bc.current_phase() == LifecyclePhase::Ready);
    assert!(bc.is_ready());
}

/// AC1 — the guarded mutator accepts every legal runtime edge.
#[test]
fn set_lifecycle_phase_accepts_legal_edges() {
    // Collecting → Processing → Ready.
    let mut bc = new_test_chain();
    bc.set_lifecycle_phase(LifecyclePhase::Processing);
    assert!(bc.current_phase() == LifecyclePhase::Processing);
    bc.set_lifecycle_phase(LifecyclePhase::Ready);
    assert!(bc.current_phase() == LifecyclePhase::Ready);

    // Processing → Collecting (FR5 recovery edge).
    let mut bc2 = new_test_chain();
    bc2.set_lifecycle_phase(LifecyclePhase::Processing);
    bc2.set_lifecycle_phase(LifecyclePhase::Collecting);
    assert!(bc2.current_phase() == LifecyclePhase::Collecting);
}

/// AC1 — the guarded mutator rejects the illegal direct `Collecting → Ready`
/// edge (debug-assert; `cargo test` runs debug).
#[test]
#[should_panic(expected = "illegal lifecycle transition")]
fn set_lifecycle_phase_rejects_collecting_to_ready() {
    let mut bc = new_test_chain();
    bc.set_lifecycle_phase(LifecyclePhase::Ready);
}

/// AC5 — the snake-chain window seam is phase-gated: `None` while not Ready
/// (so FR60 stays inactive and every admitted block is Stored, AC6).
#[test]
fn snake_chain_window_none_while_collecting() {
    let bc = new_test_chain();
    assert_eq!(
        bc.active_snake_chain_window(),
        Err(SnakeChainWindowError::NotReady)
    );
}

/// AC3 — the join follow-up on empty durable storage keeps the node
/// Collecting and reports `StartedCollecting`.
#[test]
fn initialize_from_storage_empty_starts_collecting() {
    let mut bc = new_test_chain();
    let (outcome, next) = bc.initialize_from_storage(0);
    assert_eq!(outcome, InitOutcome::StartedCollecting);
    assert!(matches!(next, NextCall::Idle));
    assert!(bc.current_phase() == LifecyclePhase::Collecting);
}

/// AC4 — the read-only queries return `Err(NotReady)` while Collecting (a
/// `Result`, so not-ready is a distinct signal, not `None`).
#[test]
fn collecting_gates_ready_only_queries() {
    let bc = new_test_chain();
    assert_eq!(bc.query_balance(1), Err(BalanceQueryError::NotReady));
    assert!(matches!(
        bc.query_block_by_hash(&[0u8; 32]),
        Err(BlockQueryError::NotReady)
    ));
    assert!(matches!(
        bc.query_block_by_sequence(0),
        Err(BlockQueryError::NotReady)
    ));
    assert_eq!(
        bc.query_transaction_state(&[0u8; 32]),
        Err(TxStateQueryError::NotReady)
    );
}

/// AC4 — state-changing Ready-state-only intake surfaces return `NotReady` with
/// `NextCall::Idle` while Collecting.
#[test]
fn collecting_gates_transaction_intake() {
    let mut bc = new_test_chain();
    let block = node_transfer_block(5, 3, 4, 7);
    let bv = block.view();
    let payload = bv.transactions().expect("transaction payload");

    let tx1 = payload.iter().next().expect("one transaction");
    let (o1, n1) = bc.receive_transaction(tx1, 1_000);
    assert_eq!(o1, ReceiveTransactionOutcome::NotReady);
    assert!(matches!(n1, NextCall::Idle));

    let tx2 = payload.iter().next().expect("one transaction");
    let (o2, n2) = bc.submit_local_transaction(tx2, 1_000);
    assert_eq!(o2, LocalTransactionOutcome::NotReady);
    assert!(matches!(n2, NextCall::Idle));
}

/// AC5 — the single-genesis guard: once an anchor exists, a second distinct
/// `sequence == 0` block is rejected as invalid evidence (FR16) — not stored,
/// not made a Stored orphan (which would emit perpetual bogus parent-recovery
/// and break the `chain_heads` "tail never seq 0" invariant), and it never
/// reseats the active chain.
#[test]
fn single_genesis_guard_rejects_second_seq0() {
    // Unconfigured: the guard is an admission property, decided from the
    // block bytes and `active_chain_head_idx` alone. Holding a configuration
    // would let the first genesis complete an FR2 candidate and run the
    // Epic-5 lifecycle inside the same call, which would be testing the
    // lifecycle rather than the guard.
    let mut bc = new_unconfigured_test_chain();

    // First genesis (seq 0) anchors the active chain at slot 0.
    let g1 = node_transfer_block(0, 7, 0, 7);
    let (o1, _) = bc.receive_block(g1.view(), 100);
    assert_eq!(o1, ReceiveBlockOutcome::AcceptedSilently);
    assert_eq!(bc.active_chain_head_idx, 0);
    assert_eq!(bc.current_active_head(), Some(0));
    assert_eq!(bc.blocks.len(), 1);

    // A second, distinct seq-0 block (different vote/initializer → different
    // hash) is rejected and leaves the chain untouched.
    let g2 = node_transfer_block(0, 3, 0, 3);
    assert_ne!(
        g1.view().hash(),
        g2.view().hash(),
        "distinct genesis blocks"
    );
    let (o2, _) = bc.receive_block(g2.view(), 200);
    assert_eq!(
        o2,
        ReceiveBlockOutcome::Rejected(RejectReason::InvalidEvidence)
    );
    assert_eq!(
        bc.active_chain_head_idx, 0,
        "second genesis must not reseat the active chain"
    );
    assert_eq!(bc.blocks.len(), 1, "second genesis must not be stored");
    assert_eq!(bc.chain_heads.count(), 1, "no spurious Stored head created");
}

/// AC8 (FR63/NFR5) — the lifecycle/gating surface is deterministic and
/// wall-clock-independent: replaying the identical init + block sequence with
/// **different** `now` values yields identical phase, active-head, and gate
/// outcomes. `now` affects only scheduling, never a phase/gate decision.
#[test]
fn lifecycle_surface_is_now_independent() {
    fn run(now_base: u64) -> (bool, Option<u32>, bool, bool) {
        let mut bc = new_test_chain();
        // Empty-storage init path (join).
        let (init_outcome, _) = bc.initialize_from_storage(now_base);
        assert_eq!(init_outcome, InitOutcome::StartedCollecting);
        // Anchor a genesis, then a rejected second genesis — with now derived
        // from now_base so the two runs use different timestamps.
        let g1 = node_transfer_block(0, 7, 0, 7);
        let o1 = bc.receive_block(g1.view(), now_base + 10).0;
        let g2 = node_transfer_block(0, 3, 0, 3);
        let o2 = bc.receive_block(g2.view(), now_base + 20).0;
        (
            o1 == ReceiveBlockOutcome::AcceptedSilently,
            bc.current_active_head(),
            o2 == ReceiveBlockOutcome::Rejected(RejectReason::InvalidEvidence),
            bc.is_ready(),
        )
    }
    // Two replays with widely different wall-clock bases must agree.
    assert_eq!(run(1_000), run(9_999_999));
}

// ---- Story 6.15: the chain's node cap (DEC-228) ----

/// A configuration declaring the window `w`, its test horizon and the node
/// cap `cap` instead of [`TEST_MAX_NODES`].
fn capped_config_builder(w: u32, cap: u32) -> ChainConfigPayloadBuilder {
    let mut builder = ChainConfigPayloadBuilder::new();
    for (id, value) in [
        (parameter::ACTIVE_CHAIN_LENGTH, w),
        (parameter::VERIFICATION_HORIZON, test_horizon(w)),
        (parameter::MAX_NODE_COUNT, cap),
    ] {
        builder
            .add_literal(id, &value.to_le_bytes())
            .ok()
            .expect("a four-byte literal is well-formed");
    }
    declare_build_scheme(&mut builder);
    builder
}

/// AC10: at a Ready head extension a registration at `max_node_count` is
/// exact evidence, and one below it is accepted and seeds its key. The cap
/// is the chain's 2, far below the build's `MAX_NODES` (16), so only the
/// chain rule can refuse it.
#[test]
fn fr6_registration_at_the_node_cap_is_evidence_in_ready() {
    let (crypto, storage, chain_config) = test_backends();
    let mut bc = new_chain(crypto, storage, chain_config, 0, 0);
    let genesis = bc
        .process_genesis(CURRENCY, capped_config_builder(TEST_W, 2).content())
        .ok()
        .expect("genesis succeeds");
    assert!(bc.is_ready());

    let one = register(2, genesis.block_one.view().hash(), 1, 0x31);
    assert_eq!(
        receive(&mut bc, &one),
        ReceiveBlockOutcome::AcceptedSilently
    );
    assert_eq!(head_of(&bc).1, one.view().hash());
    assert!(bc.node_info.is_seeded(1), "an id below the cap registers");

    let two = register(3, one.view().hash(), 2, 0x32);
    assert_eq!(
        receive(&mut bc, &two),
        ReceiveBlockOutcome::Rejected(RejectReason::InvalidEvidence)
    );
    assert_eq!(head_of(&bc).1, one.view().hash());
    assert!(!bc.node_info.is_seeded(2));
    assert_eq!(bc.node_info.max_known_node_id(), 1);

    // The contrast: the same blocks on a chain whose cap is 3 are both
    // accepted, so only the cap refused the registration above.
    let (crypto, storage, chain_config) = test_backends();
    let mut wide = new_chain(crypto, storage, chain_config, 0, 0);
    let wide_genesis = wide
        .process_genesis(CURRENCY, capped_config_builder(TEST_W, 3).content())
        .ok()
        .expect("genesis succeeds");
    let one = register(2, wide_genesis.block_one.view().hash(), 1, 0x31);
    assert_eq!(
        receive(&mut wide, &one),
        ReceiveBlockOutcome::AcceptedSilently
    );
    let two = register(3, one.view().hash(), 2, 0x32);
    assert_eq!(
        receive(&mut wide, &two),
        ReceiveBlockOutcome::AcceptedSilently
    );
    assert!(wide.node_info.is_seeded(2));
}

/// AC10: the FR3 pass applies the same rule to a registration (here the
/// fixture cap, `TEST_MAX_NODES` = 16, with the watermark at 15, so the id
/// is otherwise the expected next one).
#[test]
fn fr6_registration_at_the_node_cap_is_evidence_in_the_pass() {
    let mut bc = new_test_chain();
    let cfg_hash = admit_chain_config_anchor(&mut bc, 99, [0xAB; 32]);
    let anchor = balance_block(100, cfg_hash, &[(1, 500, 10, 0x31)], TEST_MAX_NODES - 1);
    bc.tier1_admit(&anchor.view(), &anchor.view().hash(), 0)
        .expect("anchor admitted");
    let reg = registration_block(101, anchor.view().hash(), 1, TEST_MAX_NODES, 0x43);
    let ri = bc
        .tier1_admit(&reg.view(), &reg.view().hash(), 0)
        .expect("registration admitted");
    assert_eq!(
        bc.run_processing_pass(ri).map(|_| ()),
        Err(ProcessingError::Invalid {
            block_idx: ri,
            reason: ValidationReason::NodeCountExceeded,
        })
    );
}

/// AC10: the equality the guard removal rests on — the cap equals the
/// build's `MAX_NODES` (16) — and the last id below it registers and gets
/// its slot.
#[test]
fn fr6_registration_just_below_the_node_cap_registers() {
    let mut bc = new_test_chain();
    let cfg_hash = admit_chain_config_anchor(&mut bc, 99, [0xAB; 32]);
    let anchor = balance_block(100, cfg_hash, &[(1, 500, 10, 0x31)], TEST_MAX_NODES - 2);
    bc.tier1_admit(&anchor.view(), &anchor.view().hash(), 0)
        .expect("anchor admitted");
    let reg = registration_block(101, anchor.view().hash(), 1, TEST_MAX_NODES - 1, 0x43);
    let ri = bc
        .tier1_admit(&reg.view(), &reg.view().hash(), 0)
        .expect("registration admitted");
    assert!(bc.run_processing_pass(ri).is_ok());
    assert!(bc.node_info.is_seeded(TEST_MAX_NODES - 1));
    assert_eq!(bc.node_info.max_known_node_id(), TEST_MAX_NODES - 1);
}

/// AC10: a balance block naming an id at the cap is exact evidence; one just
/// below it is not refused by the rule.
#[test]
fn fr6_balance_block_at_the_node_cap_is_evidence() {
    let mut bc = new_test_chain();
    let cfg_hash = admit_chain_config_anchor(&mut bc, 99, [0xAB; 32]);
    let over = balance_block(100, cfg_hash, &[(1, 500, 10, 0x31)], TEST_MAX_NODES);
    let oi = bc
        .tier1_admit(&over.view(), &over.view().hash(), 0)
        .expect("admitted");
    // The over-cap block is the floor of this window-anchored candidate: it
    // is condemned before it can seed the watermark.
    assert_eq!(
        bc.run_processing_pass(oi).map(|_| ()),
        Err(ProcessingError::Invalid {
            block_idx: oi,
            reason: ValidationReason::NodeCountExceeded,
        })
    );

    let mut bc = new_test_chain();
    let cfg_hash = admit_chain_config_anchor(&mut bc, 99, [0xAB; 32]);
    let at_limit = balance_block(100, cfg_hash, &[(1, 500, 10, 0x31)], TEST_MAX_NODES - 1);
    let ai = bc
        .tier1_admit(&at_limit.view(), &at_limit.view().hash(), 0)
        .expect("admitted");
    assert!(bc.run_processing_pass(ai).is_ok());
}
