//! Tests of `api/chain_config.rs`.

use super::*;

/// AC2 — the neutrality proof: with the base override set (the window alone)
/// the configuration module resolves every parameter the blockchain reads to
/// the exact constant the retired `FixedChainConfig` returned. This is what
/// lets the rest of the suite keep its expected values unchanged, and it
/// replaces the stub's own `fixed_returns_expected_constants`.
#[test]
fn code_baked_defaults_reproduce_the_retired_stub() {
    let (crypto, _, _) = test_backends();
    let chain_config = locked_chain_config(&crypto, TestChain::BUILD_LIMITS);
    let config = chain_config
        .active_configuration()
        .expect("a locked module answers with a handle");

    assert_eq!(config.inter_block_interval_ms(), 60_000);
    assert_eq!(config.grace_period_window_ms(), 30_000);
    assert_eq!(config.block_size_limit(), 2016);
    assert_eq!(config.max_utxo_outputs(), 255);
    assert_eq!(config.required_support(), 40);
    assert_eq!(config.vote_scale().get(), 1000);
    assert_eq!(config.vote_interest(), 5);
    assert_eq!(config.parent_recovery_per_head_retry_interval_ms(), 120_000);
    assert_eq!(config.parent_recovery_min_emit_interval_ms(), 10_000);
    // The one value the fixtures declare rather than default (Story 5.11).
    assert_eq!(config.active_chain_length(), TEST_W);
    assert!(chain_config.is_durable_locked());
}

/// AC3 — before any configuration is loaded the block-size limit falls back
/// to the framing bound, and the parent-recovery scheduler stands down.
/// (Project Lead ruling, 2026-09-19.)
#[test]
fn unconfigured_node_falls_back_to_the_framing_bound_and_idles() {
    let (crypto, storage, chain_config) = test_backends();
    let mut bc = new_chain(crypto, storage, chain_config, 5, 0);

    assert_eq!(bc.block_size_limit(), MAX_BLOCK_SIZE as u32);
    assert!(bc.parent_recovery_intervals().is_none());
    let (outcome, next) = bc.on_tick(1_000_000);
    assert!(matches!(outcome, TickOutcome::Idle));
    assert!(matches!(next, NextCall::Idle));
}

/// Story 5.12, AC4/AC5 — in Ready the scheduler's programs read the
/// registered-node count at the head: after genesis one node is registered.
#[test]
fn chain_info_reaches_the_scheduler_in_ready() {
    let (crypto, storage, chain_config) = test_backends();
    let mut bc = new_chain(crypto, storage, chain_config, 0, 0);
    let builder = node_count_cadence_builder();
    bc.process_genesis(1_000_000_000, builder.content())
        .ok()
        .expect("genesis succeeds");
    assert!(bc.is_ready());
    assert_eq!(
        bc.chain_info_at_head()
            .read(chain_info::REGISTERED_NODE_COUNT, &[]),
        Some(1)
    );
    assert_eq!(
        bc.parent_recovery_intervals().map(|(min_emit, _)| min_emit),
        Some(1_000),
        "one registered node, one second"
    );
}

/// Story 5.12, AC5 — the value is the derived watermark plus one, not a
/// constant: a pass that registers node 2 on top of a balance block naming
/// nodes up to 1 leaves three registered nodes, served once Ready.
#[test]
fn chain_info_reads_the_derived_watermark() {
    let mut bc = new_test_chain();
    let cfg_hash = admit_chain_config_anchor(&mut bc, 99, [0xAB; 32]);
    let anchor = balance_block(100, cfg_hash, &[(1, 100, 0, 0x31)], 1);
    bc.tier1_admit(&anchor.view(), &anchor.view().hash(), 0)
        .expect("anchor admitted");
    let reg = registration_block(101, anchor.view().hash(), 1, 2, 0x45);
    let ri = bc
        .tier1_admit(&reg.view(), &reg.view().hash(), 0)
        .expect("registration admitted");
    bc.run_processing_pass(ri).expect("pass succeeds");
    assert_eq!(
        bc.chain_info_at_head()
            .read(chain_info::REGISTERED_NODE_COUNT, &[]),
        None,
        "not Ready yet"
    );

    bc.set_lifecycle_phase(LifecyclePhase::Processing);
    bc.set_lifecycle_phase(LifecyclePhase::Ready);
    let info = bc.chain_info_at_head();
    assert_eq!(info.read(chain_info::REGISTERED_NODE_COUNT, &[]), Some(3));
    assert_eq!(
        info.read(chain_info::REGISTERED_NODE_COUNT, &[0]),
        None,
        "identifier 1 takes no arguments"
    );
}

/// Story 5.12, AC4 — while Collecting there is no active chain: the read is
/// declined and the program falls back to the code-baked default.
#[test]
fn chain_info_is_declined_while_collecting() {
    let (crypto, storage, _) = test_backends();
    let mut chain_config = empty_chain_config(TestChain::BUILD_LIMITS);
    chain_config
        .load_durable(node_count_cadence_builder().build_signed(&crypto))
        .ok()
        .expect("the content is accepted");
    let bc = new_chain(crypto, storage, chain_config, 5, 0);
    assert!(!bc.is_ready());
    assert_eq!(
        bc.chain_info_at_head()
            .read(chain_info::REGISTERED_NODE_COUNT, &[]),
        None
    );
    assert_eq!(
        bc.parent_recovery_intervals().map(|(min_emit, _)| min_emit),
        Some(10_000),
        "declined, so the code-baked default"
    );
}

/// An override set that is **well-formed but structurally illegal**:
/// `vote_scale = 0`, which the configuration module refuses on a bound (it is
/// the denominator of the FR37 anti-capture rule). The framing is valid, so
/// the envelope walks and the FR7 signature verifies — the refusal comes from
/// the module, which is the ordering AC2 is about.
fn bound_violating_config_builder() -> ChainConfigPayloadBuilder {
    let mut builder = ChainConfigPayloadBuilder::new();
    builder
        .add_literal(parameter::VOTE_SCALE, &0u16.to_le_bytes())
        .ok()
        .expect("the entry itself is well-formed; the bound is what fails");
    builder
}

// =======================================================================
// Story 5.9 — FR7 content-signature commitment + FR8 tentative/durable
// =======================================================================

/// AC2 — the **first** chain-config block whose FR7 signature verifies and
/// whose content the module accepts is loaded tentatively, and is retained
/// like any other admitted block.
#[test]
fn fr8_first_config_block_loads_tentatively() {
    let mut bc = new_unconfigured_test_chain();
    assert!(
        bc.chain_config.active_configuration().is_none(),
        "a joining node starts with no configuration"
    );
    let cfg = chain_config_anchor_block(100, [0xAB; 32]);

    let (outcome, _) = bc.receive_block(cfg.view(), 0);

    assert_eq!(outcome, ReceiveBlockOutcome::AcceptedSilently);
    let idx = bc
        .blocks
        .find(100, &cfg.view().hash())
        .expect("the config block is retained (FR8)");
    assert_eq!(
        bc.chain_config.tentative_content(),
        Some(content_of(&cfg)),
        "the content region is held tentatively, signature trailer excluded"
    );
    assert!(
        !bc.chain_config.is_durable_locked(),
        "a join-path load is tentative, never a lock"
    );
    assert_eq!(
        bc.tentative_config_block_idx, idx,
        "the provenance names the retained block"
    );
}

/// AC2 — a valid-signature config block whose content violates a structural
/// bound is exact evidence of invalidity (FR16): it does not enter durable
/// storage, and no tentative configuration remains loaded.
#[test]
fn fr8_bound_violating_content_is_rejected_and_stores_nothing() {
    let mut bc = new_unconfigured_test_chain();
    let cfg = chain_config_block_from(100, [0xAB; 32], &mut bound_violating_config_builder());

    let (outcome, _) = bc.receive_block(cfg.view(), 0);

    assert_eq!(
        outcome,
        ReceiveBlockOutcome::Rejected(RejectReason::InvalidEvidence),
        "a refused content is exact evidence, not a silent discard"
    );
    assert_eq!(
        bc.blocks.len(),
        0,
        "the block never entered durable storage"
    );
    assert!(
        bc.chain_config.active_configuration().is_none(),
        "no configuration remains loaded after a refusal"
    );
    assert_eq!(bc.tentative_config_block_idx, NONE_REF);
}

/// AC2 + AC7 — a second chain-config block arriving while the configuration
/// is merely **tentative** must neither override it nor be discarded.
///
/// Both halves matter. FR8 says such a block "shall be stored in the
/// block-tree subject to FR16 and shall not override the tentative
/// configuration"; and the AC6 mismatch path *depends* on it being retained,
/// because the content it adopts comes from a config block that disagrees
/// with the current tentative. A tentative-keyed FR17 gate would discard
/// exactly the block the recovery needs.
#[test]
fn fr8_second_config_block_while_tentative_neither_overrides_nor_is_discarded() {
    let mut bc = new_unconfigured_test_chain();
    let first = chain_config_anchor_block(100, [0xAB; 32]);
    bc.receive_block(first.view(), 0);
    let first_idx = bc
        .blocks
        .find(100, &first.view().hash())
        .expect("first config block retained");

    let second = chain_config_block_from(101, first.view().hash(), &mut alt_config_builder());
    let (outcome, _) = bc.receive_block(second.view(), 0);

    assert_eq!(
        outcome,
        ReceiveBlockOutcome::AcceptedSilently,
        "FR17 must stand down while the configuration is only tentative"
    );
    assert!(
        bc.blocks.find(101, &second.view().hash()).is_some(),
        "the disagreeing block is retained, not discarded"
    );
    assert_eq!(
        bc.chain_config.tentative_content(),
        Some(content_of(&first)),
        "the tentative configuration is not overridden"
    );
    assert_eq!(
        bc.tentative_config_block_idx, first_idx,
        "provenance still names the first block"
    );
}

/// AC7 — once the configuration is durably locked, the FR17 gate *does* fire:
/// a config block whose content differs is silently discarded. The contrast
/// with the test above is the whole of AC7.
#[test]
fn fr17_discards_mismatching_config_block_only_once_durably_locked() {
    let mut bc = new_test_chain(); // durably locked on the base override set
    let cfg = chain_config_block_from(100, [0xAB; 32], &mut alt_config_builder());

    let (outcome, _) = bc.receive_block(cfg.view(), 0);

    assert_eq!(
        outcome,
        ReceiveBlockOutcome::Rejected(RejectReason::InvalidEvidence),
        "post-lock, a disagreeing config block is discarded (FR17)"
    );
    assert_eq!(bc.blocks.len(), 0);
}

/// AC3 — a candidate segment carrying **no** chain-config block cannot
/// satisfy FR6 chain-config compliance, so the pass refuses it and the FR5
/// recovery rolls it back.
#[test]
fn fr8_candidate_without_config_block_is_refused() {
    let mut bc = new_test_chain();
    let genesis = genesis_zero_block(1_037);
    let gi = bc
        .tier1_admit(&genesis.view(), &genesis.view().hash(), 0)
        .expect("genesis admitted");

    assert_eq!(
        bc.run_processing_pass(gi),
        Err(ProcessingError::Invalid {
            block_idx: gi,
            reason: ValidationReason::MissingChainConfigBlock,
        }),
        "a candidate naming no configuration is not a chain to go Ready on"
    );
}

/// Story 5.13 — a segment that names no configuration is not an FR2
/// candidate at all, so nothing is deleted for it. Before 5.13 it qualified,
/// failed the FR8 final check, and FR5 deleted its head — a valid block —
/// once per re-qualification.
#[test]
fn fr2_segment_naming_no_configuration_is_not_a_candidate() {
    // A window-anchored segment of W + H − 1 = 8 blocks (#98..=#105),
    // none of them a chain-config block, on a configured node.
    let mut bc = new_w6_chain();
    let base = node_transfer_block(98, 3, 97, 7);
    let mut prev = base.view().hash();
    let above: [Block; 7] = core::array::from_fn(|i| {
        let blk = linked_transfer_block(99 + i as u32, prev);
        prev = blk.view().hash();
        blk
    });
    for blk in core::iter::once(&base).chain(&above) {
        bc.receive_block(blk.view(), 0);
    }

    assert!(
        bc.evaluate_stopping_condition().is_none(),
        "longer than W, but the segment names no configuration"
    );
    assert!(
        bc.current_phase() == LifecyclePhase::Collecting,
        "no pass ran"
    );
    assert_eq!(bc.block_tree_len(), 8, "nothing was deleted");

    // The segment's own configuration arriving above it makes it a
    // candidate, which validates. #106 is not a clean slot (`H = 3`).
    let cfg = w6_config_anchor_block(106, prev);
    bc.receive_block(cfg.view(), 0);
    assert!(bc.is_ready(), "the segment now names its configuration");
    // Nothing was deleted for the waiting: the nine-block segment is
    // exactly `W + H`, so its Ready entry keeps #98..=#100 in the horizon
    // (FR58, Story 6.14).
    assert_eq!(bc.block_tree_len(), 9, "every block survived the wait");
    assert!(
        bc.block_tree_contains(98, &base.view().hash()),
        "#98 is the horizon root"
    );
    for blk in above.iter().chain([&cfg]) {
        let view = blk.view();
        assert!(bc.block_tree_contains(view.sequence(), &view.hash()));
    }
    assert_eq!(bc.active_snake_chain_window(), Ok((101, 106)));
    assert_eq!(
        bc.current_active_head(),
        Some(106),
        "the active head is the config block that completed the segment"
    );
}

/// AC4 + AC5 — the Ready transition commits the configuration durably exactly
/// once, and deletes every disagreeing chain-config block in the tree,
/// transitively, without touching the active chain.
///
/// The side branch is built to be the hard case: it forks at the genesis, its
/// config block disagrees, and it carries a descendant above that block, so
/// the cleanup has to be transitive and has to follow up on `chain_heads`.
#[test]
fn fr8_ready_locks_durably_and_deletes_disagreeing_config_subtrees() {
    let mut bc = new_unconfigured_test_chain();
    let genesis = genesis_zero_block(1_000);
    // Main branch: #0 → cfg A (#1) → cfg A (#2) → cfg A (#3), tip sequence 3.
    // Three blocks carrying *identical* content, which AC3 permits and in
    // fact requires: every in-scope config block must be byte-identical to
    // the tentative. They are chain-config blocks rather than transfers
    // because the candidate is genesis-anchored, where there is no pre-seed
    // trust zone — a transfer between unregistered nodes would fail FR6 as an
    // unseeded actor, and this test is not about that.
    let cfg_a = chain_config_anchor_block(1, genesis.view().hash());
    let main_2 = chain_config_anchor_block(2, cfg_a.view().hash());
    let main_3 = chain_config_anchor_block(3, main_2.view().hash());
    // Side branch off the genesis: cfg B (#1') → tx (#2'). Tip sequence 2, so
    // FR2 selection prefers the main branch's higher tip. The side branch is
    // never validated (it is not the candidate), so its transfer block's
    // unseeded actors are irrelevant — it is here to prove the cleanup is
    // transitive and follows up on `chain_heads`.
    let cfg_b = chain_config_block_from(1, genesis.view().hash(), &mut alt_config_builder());
    let side_2 = linked_transfer_block(2, cfg_b.view().hash());

    // Config A first, so it is the tentative (AC2). Everything is admitted
    // while still orphaned — window-anchored segments far below W = 16, so no
    // FR2 trigger — and the genesis comes last to connect them all at once.
    for block in [&cfg_a, &main_2, &main_3, &cfg_b, &side_2] {
        let (outcome, _) = bc.receive_block(block.view(), 0);
        assert_eq!(
            outcome,
            ReceiveBlockOutcome::AcceptedSilently,
            "every block is admitted before the genesis connects them"
        );
    }
    assert_eq!(
        bc.chain_config.tentative_content(),
        Some(content_of(&cfg_a)),
        "config A is the tentative; config B is retained but does not override"
    );

    let (outcome, _) = bc.receive_block(genesis.view(), 0);
    assert_eq!(outcome, ReceiveBlockOutcome::AcceptedSilently);

    // AC4: the commitment is durable, over config A's content.
    assert!(bc.is_ready(), "the main candidate validates → Ready");
    assert!(bc.chain_config.is_durable_locked(), "FR8 lock engaged");
    assert_eq!(
        bc.chain_config.durable_content(),
        Some(content_of(&cfg_a)),
        "the locked content is the candidate's own"
    );
    // AC5: config B and its descendant are gone, transitively.
    assert!(
        bc.blocks.find(1, &cfg_b.view().hash()).is_none(),
        "the disagreeing config block is deleted"
    );
    assert!(
        bc.blocks.find(2, &side_2.view().hash()).is_none(),
        "and so is its descendant, which is unverifiable without it"
    );
    // The active chain is untouched — a consequence of AC3, not a precaution.
    for (seq, block) in [(0u32, &genesis), (1, &cfg_a), (2, &main_2), (3, &main_3)] {
        let idx = bc
            .blocks
            .find(seq, &block.view().hash())
            .unwrap_or_else(|| panic!("main-branch block at sequence {seq} survives"));
        assert!(
            bc.blocks
                .get(idx)
                .is_some_and(|entry| entry.is_on_active_chain()),
            "main-branch block at sequence {seq} is on the active chain"
        );
    }
    assert_eq!(bc.blocks.len(), 4, "exactly the active chain remains");
}

/// AC4 — a second durable commitment is **refused**, not silently re-applied.
/// The set-once guarantee is the configuration module's (Story 5.7); this
/// asserts the lifecycle does not paper over it.
#[test]
fn fr8_second_durable_commit_is_refused() {
    let mut bc = new_unconfigured_test_chain();
    let genesis = genesis_zero_block(1_000);
    let cfg = chain_config_anchor_block(1, genesis.view().hash());
    bc.receive_block(cfg.view(), 0);
    bc.receive_block(genesis.view(), 0);
    assert!(bc.chain_config.is_durable_locked(), "locked once");
    let cfg_idx = bc
        .blocks
        .find(1, &cfg.view().hash())
        .expect("config block on the active chain");

    assert!(
        bc.commit_durable_chain_config(cfg_idx).is_err(),
        "the lock is set-once for the lifetime of the chain"
    );
    assert!(
        bc.chain_config.is_durable_locked(),
        "and the refusal leaves the existing lock intact"
    );
    // The lifecycle refuses above because the storage seam is itself set-once,
    // so that assertion alone never reaches the module. Assert the module's
    // own refusal directly — it is the guarantee AC4 actually names, and the
    // one this story must not paper over.
    assert!(
        bc.chain_config.promote_durable().is_err(),
        "the configuration module refuses a second promotion in its own right"
    );
}

/// AC6 — on a final-check content mismatch the node adopts the candidate's
/// own first in-scope config content and re-runs the pass over the same
/// candidate, in the same call, reaching Ready without waiting for another
/// admission. The superseded tentative's block is removed.
#[test]
fn fr8_mismatch_adopts_candidate_content_and_reruns_in_one_call() {
    let mut bc = new_unconfigured_test_chain();
    // An off-candidate config block arrives first and becomes the tentative.
    // Sequence 500, alone: a length-1 window-anchored segment never qualifies
    // under FR2, so it is never itself a candidate.
    let stray = chain_config_block_from(500, [0xEE; 32], &mut alt_config_builder());
    bc.receive_block(stray.view(), 0);
    assert_eq!(
        bc.chain_config.tentative_content(),
        Some(content_of(&stray)),
        "the stray block supplied the tentative configuration"
    );

    let genesis = genesis_zero_block(1_000);
    let cfg = chain_config_anchor_block(1, genesis.view().hash());
    bc.receive_block(cfg.view(), 0);
    let (outcome, _) = bc.receive_block(genesis.view(), 0);

    assert_eq!(outcome, ReceiveBlockOutcome::AcceptedSilently);
    assert!(
        bc.is_ready(),
        "the adopt-retry validated the same candidate inside the same call"
    );
    assert_eq!(
        bc.chain_config.durable_content(),
        Some(content_of(&cfg)),
        "the chain's own configuration was adopted and locked, not the stray's"
    );
    assert!(
        bc.blocks.find(500, &stray.view().hash()).is_none(),
        "the superseded tentative's block is removed"
    );
    assert_eq!(bc.blocks.len(), 2, "genesis + the chain's config block");
}

/// AC6 — a candidate carrying **two differing** config contents can never
/// satisfy AC3 under any adoption, so it takes the hard FR5 rollback with no
/// adopt-retry. This is the one shape that could otherwise oscillate
/// adopt→mismatch→adopt, so the test's termination is part of what it proves.
///
/// The arrival order is the adversarial one: the *upper* config block loads
/// the tentative first, so the run is `pass → adopt → pass → FR5 → pass`,
/// exercising both single-use retry tokens in one call — the worst case the
/// three-pass bound permits, and no more.
#[test]
fn fr8_two_differing_config_contents_take_the_hard_rollback() {
    let mut bc = new_unconfigured_test_chain();
    let genesis = genesis_zero_block(1_000);
    let cfg_a = chain_config_anchor_block(1, genesis.view().hash());
    let cfg_b = chain_config_block_from(2, cfg_a.view().hash(), &mut alt_config_builder());

    // B first: it becomes the tentative, so the pass mismatches at A — the
    // candidate's *first* config block — and the adopt path fires.
    bc.receive_block(cfg_b.view(), 0);
    assert_eq!(
        bc.chain_config.tentative_content(),
        Some(content_of(&cfg_b)),
        "the upper config block supplied the tentative"
    );
    bc.receive_block(cfg_a.view(), 0);
    let (outcome, _) = bc.receive_block(genesis.view(), 0);

    assert_eq!(outcome, ReceiveBlockOutcome::AcceptedSilently);
    // B is exact evidence of non-compliance once A is adopted, so FR5 deletes
    // it; the shortened candidate then validates on the Story-5.5 retry.
    assert!(
        bc.blocks.find(2, &cfg_b.view().hash()).is_none(),
        "the second, disagreeing config block is deleted as exact evidence"
    );
    assert!(bc.is_ready(), "the shortened candidate validates");
    assert_eq!(
        bc.chain_config.durable_content(),
        Some(content_of(&cfg_a)),
        "the chain locked on its first in-scope configuration"
    );
    assert_eq!(bc.blocks.len(), 2, "genesis + config A");
}

/// AC8 — when an FR5 recovery deletes the subtree containing the tentatively
/// loaded config block, the tentative configuration goes with it: the
/// justification for holding it is gone.
#[test]
fn fr8_recovery_unloads_a_deleted_tentative_configuration() {
    let mut bc = new_unconfigured_test_chain();
    let cfg = chain_config_anchor_block(100, [0xAB; 32]);
    bc.receive_block(cfg.view(), 0);
    let cfg_idx = bc
        .blocks
        .find(100, &cfg.view().hash())
        .expect("config block retained");
    assert!(bc.chain_config.active_configuration().is_some());

    bc.set_lifecycle_phase(LifecyclePhase::Processing);
    bc.recover_from_failed_pass(
        ProcessingError::Invalid {
            block_idx: cfg_idx,
            reason: ValidationReason::PreviousHashMismatch,
        },
        cfg_idx,
    );

    assert!(bc.blocks.get(cfg_idx).is_none(), "the block was deleted");
    assert!(
        bc.chain_config.active_configuration().is_none(),
        "the tentative configuration is discarded with its block"
    );
    assert_eq!(bc.tentative_config_block_idx, NONE_REF);
}

/// AC8 — and only then. A recovery whose delete-set does not contain the
/// tentative's block leaves the configuration loaded.
#[test]
fn fr8_recovery_keeps_a_surviving_tentative_configuration() {
    let mut bc = new_unconfigured_test_chain();
    let cfg = chain_config_anchor_block(100, [0xAB; 32]);
    bc.receive_block(cfg.view(), 0);
    let cfg_idx = bc
        .blocks
        .find(100, &cfg.view().hash())
        .expect("config block retained");
    // An unrelated orphan on its own branch — deleting it cannot reach the
    // config block.
    let other = node_transfer_block(200, 3, 199, 7);
    bc.receive_block(other.view(), 0);
    let other_idx = bc
        .blocks
        .find(200, &other.view().hash())
        .expect("other block retained");

    bc.set_lifecycle_phase(LifecyclePhase::Processing);
    bc.recover_from_failed_pass(
        ProcessingError::Invalid {
            block_idx: other_idx,
            reason: ValidationReason::PreviousHashMismatch,
        },
        other_idx,
    );

    assert!(
        bc.blocks.get(cfg_idx).is_some(),
        "the config block survives"
    );
    assert_eq!(
        bc.chain_config.tentative_content(),
        Some(content_of(&cfg)),
        "an untouched tentative configuration stays loaded"
    );
    assert_eq!(bc.tentative_config_block_idx, cfg_idx);
}

/// AC8 — a **durable-locked** configuration is never unloaded. The lock is
/// irrevocable for the lifetime of the chain, and the module enforces that
/// itself, which is why the recovery needs no lock check of its own.
#[test]
fn fr8_recovery_never_unloads_a_durable_configuration() {
    let mut bc = new_test_chain(); // durably locked on the base override set
    let cfg = chain_config_anchor_block(100, [0xAB; 32]);
    bc.receive_block(cfg.view(), 0);
    let cfg_idx = bc
        .blocks
        .find(100, &cfg.view().hash())
        .expect("a matching config block is admitted post-lock");

    bc.set_lifecycle_phase(LifecyclePhase::Processing);
    bc.recover_from_failed_pass(
        ProcessingError::Invalid {
            block_idx: cfg_idx,
            reason: ValidationReason::PreviousHashMismatch,
        },
        cfg_idx,
    );

    assert!(bc.blocks.get(cfg_idx).is_none(), "the block was deleted");
    assert!(
        bc.chain_config.is_durable_locked(),
        "the FR8 lock survives the deletion of the block that carried it"
    );
}

/// AC9 — the commitment lifecycle is wall-clock-independent (FR63/NFR5): the
/// same block set replayed under two clocks produces the same lock, the same
/// cleanup delete-set and the same tree.
#[test]
fn fr8_commitment_ignores_now() {
    fn run(now: u64) -> ([bool; 16], bool, bool, usize) {
        let mut bc = new_unconfigured_test_chain();
        let genesis = genesis_zero_block(1_000);
        let cfg_a = chain_config_anchor_block(1, genesis.view().hash());
        let cfg_b = chain_config_block_from(1, genesis.view().hash(), &mut alt_config_builder());
        let side = linked_transfer_block(2, cfg_b.view().hash());
        let main_2 = chain_config_anchor_block(2, cfg_a.view().hash());
        let main_3 = chain_config_anchor_block(3, main_2.view().hash());
        for (step, block) in [&cfg_a, &main_2, &main_3, &cfg_b, &side, &genesis]
            .into_iter()
            .enumerate()
        {
            bc.receive_block(block.view(), now.saturating_add(step as u64 * 1_000));
        }
        let mut occupied = [false; 16];
        for (slot, flag) in occupied.iter_mut().enumerate() {
            *flag = bc.blocks.get(slot as u32).is_some();
        }
        (
            occupied,
            bc.is_ready(),
            bc.chain_config.is_durable_locked(),
            bc.blocks.len(),
        )
    }
    let baseline = run(0);
    assert_eq!(
        baseline,
        run(5_000_000),
        "the FR8 lock and the AC5 cleanup are identical across wall-clocks"
    );
    // Non-vacuity: the run really reached the lock and really cleaned up.
    assert!(
        baseline.1 && baseline.2,
        "the replay reached the durable lock"
    );
    assert_eq!(baseline.3, 4, "the side branch was cleaned up");
}

/// AC9 — and it is arrival-order-independent where FR8 requires it: whichever
/// config block happens to load the tentative first, the node converges on
/// the same locked configuration and the same retained tree. The two orders
/// get there by different routes — one locks directly (AC5 cleans up), the
/// other adopts and re-runs (AC6 removes the superseded block) — and that the
/// destination is identical is the property.
#[test]
fn fr8_lock_is_arrival_order_independent() {
    fn run(config_a_first: bool) -> (bool, usize, [u8; 2]) {
        let mut bc = new_unconfigured_test_chain();
        let genesis = genesis_zero_block(1_000);
        let cfg_a = chain_config_anchor_block(1, genesis.view().hash());
        let cfg_b = chain_config_block_from(1, genesis.view().hash(), &mut alt_config_builder());
        let side = linked_transfer_block(2, cfg_b.view().hash());
        let main_2 = chain_config_anchor_block(2, cfg_a.view().hash());
        let main_3 = chain_config_anchor_block(3, main_2.view().hash());
        // Only the order of the two *config* blocks differs; the main branch
        // is the FR2 winner either way (tip sequence 3 against 2).
        let order: [&Block; 6] = if config_a_first {
            [&cfg_a, &cfg_b, &side, &main_2, &main_3, &genesis]
        } else {
            [&cfg_b, &side, &cfg_a, &main_2, &main_3, &genesis]
        };
        for block in order {
            bc.receive_block(block.view(), 0);
        }
        // The locked content as a fingerprint: its first two bytes are the
        // `config_value_count`, which is 4 for the base override set config A
        // carries (window, horizon, node cap and scheme) and 5 for config B's.
        let locked = bc
            .chain_config
            .durable_content()
            .map(|content| [content[0], content[1]])
            .unwrap_or([0xFF, 0xFF]);
        (bc.is_ready(), bc.blocks.len(), locked)
    }

    let a_first = run(true);
    assert_eq!(
        a_first,
        run(false),
        "both arrival orders converge on the same lock and the same tree"
    );
    assert_eq!(
        a_first,
        (true, 4, [4, 0]),
        "and they converge on config A — the candidate's own — with the side branch gone"
    );
}

/// FR3 candidate chain-config preload — the ordering that keeps a stale
/// tentative from costing a valid block.
///
/// PRD FR3 requires the candidate's *own* configuration content to be the
/// basis of every chain-config-derived check in the forward traversal. This
/// is the scenario where that ordering is load-bearing rather than
/// decorative, and every step of it is reachable:
///
/// 1. A large balance block is admitted while the node holds no
///    configuration, so intake measures it against the framing ceiling.
/// 2. A stray, off-candidate chain-config block then loads a tentative that
///    declares a *small* `block_size_limit`.
/// 3. The candidate completes, and its own chain-config block declares the
///    default limit — under which the balance block is perfectly legal.
///
/// With the preload, the divergence is caught before a single candidate block
/// is validated: the node adopts the candidate's content and re-runs, and the
/// balance block is measured against the limit its own chain set. Without it,
/// the forward walk reaches the balance block first and deletes it as
/// `BlockTooLarge` under a limit no block on that chain was ever subject to.
#[test]
fn fr3_preload_prevents_a_stale_tentative_from_condemning_a_valid_block() {
    let mut bc = new_unconfigured_w6_chain();
    // (1) A balance block bigger than the small limit the stray will declare,
    // admitted while the node is unconfigured.
    // `max_node_id = 9` so the linked transfers' pre-window actors (nodes 7
    // and 9) are inside the derived node-id range; three entries so the block
    // comfortably exceeds the stray's declared limit.
    let below = w6_horizon_block();
    for block in &w6_below() {
        let (outcome, _) = bc.receive_block(block.view(), 0);
        assert_eq!(outcome, ReceiveBlockOutcome::AcceptedSilently);
    }
    let big = balance_block(
        100,
        below.view().hash(),
        &[(1, 500, 0, 0x31), (2, 300, 0, 0x32), (3, 100, 0, 0x33)],
        9,
    );
    assert!(
        big.len() > SMALL_BLOCK_SIZE_LIMIT as usize,
        "the fixture is only meaningful if the block exceeds the stray's limit"
    );
    let b101 = linked_transfer_block(101, big.view().hash());
    let b102 = linked_transfer_block(102, b101.view().hash());
    let b103 = linked_transfer_block(103, b102.view().hash());
    let b104 = linked_transfer_block(104, b103.view().hash());
    for block in [&big, &b101, &b102, &b103, &b104] {
        let (outcome, _) = bc.receive_block(block.view(), 0);
        assert_eq!(
            outcome,
            ReceiveBlockOutcome::AcceptedSilently,
            "admitted while unconfigured, against the framing ceiling"
        );
    }

    // (2) The stray loads a tentative declaring the small limit. Off-candidate
    // and alone, so it is never itself an FR2 candidate.
    let stray = chain_config_block_from(500, [0xEE; 32], &mut small_limit_config_builder(W6));
    bc.receive_block(stray.view(), 0);
    assert!(
        bc.chain_config.tentative_content().is_some(),
        "the stray supplied the tentative configuration"
    );

    // (3) The candidate's own chain-config block completes the segment at
    // W + H = 9 and triggers FR2.
    let cfg = w6_config_anchor_block(105, b104.view().hash());
    let (outcome, _) = bc.receive_block(cfg.view(), 0);

    assert_eq!(outcome, ReceiveBlockOutcome::AcceptedSilently);
    assert!(
        bc.blocks.find(100, &big.view().hash()).is_some(),
        "the balance block was never measured against a limit its chain did not set"
    );
    assert!(bc.is_ready(), "the adopt-retry validated the candidate");
    assert_eq!(
        bc.chain_config.durable_content(),
        Some(content_of(&cfg)),
        "the chain locked on its own configuration, not the stray's"
    );
    assert!(
        bc.blocks.find(500, &stray.view().hash()).is_none(),
        "the superseded tentative's block is gone"
    );
}

// --- Code-review regressions (2026-09-20) -------------------------------

/// The acquisition loop must not retry a pass once the recovery has taken the
/// configuration with it.
///
/// `receive_block` evaluates its "a configuration is loaded" gate once, on
/// entry. The AC8 step-3b unload can retract the configuration *inside* the
/// loop — whenever the FR5 delete-set happens to contain the block that
/// supplied the tentative — and the `Invalid` retry token is still armed at
/// that point. The retry then runs a whole pass with no configuration at all,
/// which Story 5.8's FR2 gate exists precisely to prevent.
///
/// What that costs depends on the shape. In this one the unconfigured pass
/// reaches the Ready path over a candidate carrying no chain-config block,
/// tripping the AC3 assertion in debug and silently abandoning the transition
/// in release. In a shape where the pass instead refuses at the first FR37
/// vote effect, the refusal is `Vote(NotParameterized)` — which carries no
/// `block_idx`, so the FR5 fallback deletes the **candidate head**: a valid
/// block destroyed for the node's own missing configuration. The guard is
/// against re-entering at all, so it covers both.
///
/// The candidate is `[#0 genesis, #1 invalid, #2 chain-config]`, so the
/// offender's subtree contains the config block and the unload fires.
#[test]
fn fr5_retry_stops_when_recovery_unloads_the_configuration() {
    let mut bc = new_unconfigured_test_chain();
    let genesis = genesis_zero_block(1_000);
    // Out-of-sequence registration (new_node_id 5, expected 1) — invalid.
    let bad = registration_block(1, genesis.view().hash(), 1, 5, 0x45);
    let cfg = chain_config_anchor_block(2, bad.view().hash());
    for block in [&cfg, &bad] {
        bc.receive_block(block.view(), 0);
    }
    assert!(
        bc.chain_config.active_configuration().is_some(),
        "the config block supplied a tentative configuration"
    );

    let (outcome, _) = bc.receive_block(genesis.view(), 0);

    assert_eq!(outcome, ReceiveBlockOutcome::AcceptedSilently);
    // The offender and the config block above it are gone, and the unload
    // fired — but the genesis, which is not evidence of anything, survives.
    assert!(
        bc.chain_config.active_configuration().is_none(),
        "the recovery unloaded the tentative with the block that carried it"
    );
    assert!(
        bc.blocks.find(0, &genesis.view().hash()).is_some(),
        "the genesis must not be deleted by a retry the node can no longer run"
    );
    assert_eq!(bc.blocks.len(), 1, "exactly the genesis remains");
    assert!(bc.current_phase() == LifecyclePhase::Collecting);
}

/// PRD FR9: a merely-tentative chain-config must not reject an arriving block.
///
/// The block-size limit is a chain-config-derived value, and FR9 says such
/// values "produce Invalid classification (and downstream deletion) only after
/// the chain-configuration is durably locked". A stray config block declaring
/// a tight limit therefore must not cost a joining node the legitimate blocks
/// of the chain it is actually trying to join — otherwise which blocks a node
/// retains depends on the order its peers happened to gossip them (AC9).
#[test]
fn fr9_tentative_block_size_limit_does_not_reject_at_intake() {
    let mut bc = new_unconfigured_test_chain();
    let stray = chain_config_block_from(500, [0xEE; 32], &mut small_limit_config_builder(TEST_W));
    bc.receive_block(stray.view(), 0);
    assert!(
        bc.chain_config.tentative_content().is_some(),
        "the stray declares the tight limit, tentatively"
    );

    let big = balance_block(
        100,
        [0xAB; 32],
        &[(1, 500, 0, 0x31), (2, 300, 0, 0x32), (3, 100, 0, 0x33)],
        9,
    );
    assert!(big.len() > SMALL_BLOCK_SIZE_LIMIT as usize);

    let (outcome, _) = bc.receive_block(big.view(), 0);

    assert_eq!(
        outcome,
        ReceiveBlockOutcome::AcceptedSilently,
        "a tentative-only size failure must not reject the block (FR9)"
    );
    assert!(
        bc.blocks.find(100, &big.view().hash()).is_some(),
        "and it must be retained in durable storage"
    );
}

/// PRD FR9's other half: the deferred enforcement is re-run at the durable
/// lock, which is one of the two moments FR9 names.
///
/// A candidate that declares a limit its own blocks exceed is not a chain this
/// node may adopt — but the verdict is reached at the commitment, not while
/// the configuration is still tentative, and it arrives as an ordinary FR5
/// rollback with nothing promoted and nothing locked.
#[test]
fn fr9_size_limit_is_reevaluated_at_the_durable_lock() {
    let mut bc = new_unconfigured_w6_chain();
    // A nine-block (`W + H`) window-anchored candidate whose own
    // chain-config declares a limit the balance block near its base exceeds.
    let below = w6_horizon_block();
    for block in &w6_below() {
        let (outcome, _) = bc.receive_block(block.view(), 0);
        assert_eq!(outcome, ReceiveBlockOutcome::AcceptedSilently);
    }
    let big = balance_block(
        100,
        below.view().hash(),
        &[(1, 500, 0, 0x31), (2, 300, 0, 0x32), (3, 100, 0, 0x33)],
        9,
    );
    assert!(big.len() > SMALL_BLOCK_SIZE_LIMIT as usize);
    let b101 = linked_transfer_block(101, big.view().hash());
    let b102 = linked_transfer_block(102, b101.view().hash());
    let b103 = linked_transfer_block(103, b102.view().hash());
    let b104 = linked_transfer_block(104, b103.view().hash());
    let cfg = chain_config_block_from(105, b104.view().hash(), &mut small_limit_config_builder(W6));
    for block in [&big, &b101, &b102, &b103, &b104, &cfg] {
        let (outcome, _) = bc.receive_block(block.view(), 0);
        assert_eq!(
            outcome,
            ReceiveBlockOutcome::AcceptedSilently,
            "every block is admitted — the limit is not enforceable yet (FR9)"
        );
    }

    assert!(
        !bc.is_ready(),
        "the re-evaluation at the lock refuses the candidate"
    );
    assert!(
        !bc.chain_config.is_durable_locked(),
        "and nothing was locked: the verdict precedes the commitment"
    );
    assert!(
        bc.blocks.find(100, &big.view().hash()).is_none(),
        "the offending block is the one FR5 deletes"
    );
    assert!(
        bc.current_phase() == LifecyclePhase::Collecting,
        "the FR5 recovery reverted the phase"
    );
}

/// PRD FR8: a chain-config block whose content violates a structural bound
/// "shall not enter durable storage" — unconditionally, not only when it is
/// the block that happens to load.
///
/// The FR17 gate cannot cover this: it stands down while the configuration is
/// merely tentative (AC7), which is exactly the window in which a second,
/// structurally illegal config block can arrive.
#[test]
fn fr8_bound_violating_content_is_refused_even_when_not_loading() {
    let mut bc = new_unconfigured_test_chain();
    let first = chain_config_anchor_block(100, [0xAB; 32]);
    bc.receive_block(first.view(), 0);
    assert!(
        bc.chain_config.tentative_content().is_some(),
        "a configuration is already held, so the next one cannot load"
    );

    let illegal = chain_config_block_from(
        101,
        first.view().hash(),
        &mut bound_violating_config_builder(),
    );
    let (outcome, _) = bc.receive_block(illegal.view(), 0);

    assert_eq!(
        outcome,
        ReceiveBlockOutcome::Rejected(RejectReason::InvalidEvidence),
        "a bound violation is exact evidence whether or not the block loads"
    );
    assert!(
        bc.blocks.find(101, &illegal.view().hash()).is_none(),
        "and it does not enter durable storage"
    );
    assert_eq!(
        bc.chain_config.tentative_content(),
        Some(content_of(&first)),
        "the held configuration is untouched by the refusal"
    );
}
