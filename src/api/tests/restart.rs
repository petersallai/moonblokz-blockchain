//! Tests of `api/restart.rs`.

use super::*;

// ===================================================================
// FR59 — restart equivalence (Story 5.10)
//
// `MemoryBackend` lives in RAM, so a "power cycle" is modelled the only
// way it can be: the durable backend is carried into a freshly
// constructed node while every piece of derived state — tree, heads,
// projection, configuration — starts empty, exactly as it would after a
// reboot.
// ===================================================================

/// Drives an unconfigured node to `Ready` the way the network does: a
/// genesis plus chain-config blocks, admitted while orphaned so the genesis
/// connects them all at once. Reaching `Ready` runs the real FR8 durable
/// commit, which is what puts the configuration into the control plane —
/// the durable evidence the restart later reads back.
fn node_ready_from_the_mesh() -> (TestChain, Block, Block) {
    let mut bc = new_unconfigured_test_chain();
    let genesis = genesis_zero_block(1_000);
    let cfg = chain_config_anchor_block(1, genesis.view().hash());
    for block in [&cfg, &genesis] {
        let (outcome, _) = bc.receive_block(block.view(), 0);
        assert_eq!(outcome, ReceiveBlockOutcome::AcceptedSilently);
    }
    assert!(bc.is_ready(), "precondition: the node reached Ready");
    assert!(
        bc.chain_config.is_durable_locked(),
        "precondition: reaching Ready performed the FR8 durable commit"
    );
    (bc, genesis, cfg)
}

/// AC1/AC3 precondition, proven end to end through the real storage seam:
/// a block shorter than a slot comes back padded, and only the structural
/// length recovery still finds the block inside it. Without this, every
/// hash the rebuild computes would be wrong.
#[test]
fn fr59_a_short_block_survives_the_storage_round_trip() {
    let (_, mut storage, _) = test_backends();
    let block = genesis_zero_block(1_007);
    let exact = block.serialized_bytes();
    assert!(
        exact.len() < MAX_BLOCK_SIZE,
        "precondition: shorter than a slot"
    );
    storage.save_block(0, &block).ok().expect("save");

    let read_back = storage.read_block(0).ok().expect("read");
    assert_eq!(
        read_back.len(),
        MAX_BLOCK_SIZE,
        "the backend returns the whole padded slot - this is the problem FR59 faces"
    );

    let view = TestChain::exact_view(read_back.serialized_bytes())
        .expect("the exact length is recoverable");
    assert_eq!(
        view.serialized_bytes(),
        exact,
        "byte-identical to what was saved"
    );
    assert_eq!(view.hash(), block.view().hash(), "and so is the hash");
    assert_ne!(
        read_back.view().hash(),
        block.view().hash(),
        "while the padded read-back hashes to something else entirely"
    );
}

/// AC5/AC2 — the whole spine: rebuild from durable blocks, restore the FR8
/// lock from the control plane, re-run FR2/FR3/FR6 and land in `Ready`.
#[test]
fn fr59_restart_rebuilds_and_reaches_ready() {
    let (bc, genesis, cfg) = node_ready_from_the_mesh();
    let active_before = bc.current_active_head();

    let mut restarted = restart(bc);
    assert!(
        restarted.chain_config.active_configuration().is_none(),
        "precondition: the restarted node starts with nothing"
    );

    let (outcome, _) = restarted.initialize_from_storage(500);

    assert_eq!(outcome, InitOutcome::ResumedReady);
    assert!(
        restarted.is_ready(),
        "FR4 reached through the ordinary spine"
    );
    assert!(
        restarted.chain_config.is_durable_locked(),
        "AC2 - the FR8 lock is restored from the control plane"
    );
    assert_eq!(
        restarted.current_active_head(),
        active_before,
        "the same active chain is re-derived"
    );
    assert!(
        restarted.blocks.find(0, &genesis.view().hash()).is_some()
            && restarted.blocks.find(1, &cfg.view().hash()).is_some(),
        "both durable blocks are back in the tree, indexed by (sequence, hash)"
    );
}

/// AC5 — no qualifying candidate means the node simply stays `Collecting`
/// and keeps its blocks, which FR59 step (4) states explicitly.
#[test]
fn fr59_restart_stays_collecting_without_a_qualifying_candidate() {
    let mut bc = new_unconfigured_test_chain();
    // A lone orphan far above the window: admitted, but neither
    // genesis-anchored nor long enough to satisfy FR2.
    let cfg = chain_config_anchor_block(100, [0xAB; 32]);
    let (outcome, _) = bc.receive_block(cfg.view(), 0);
    assert_eq!(outcome, ReceiveBlockOutcome::AcceptedSilently);

    let mut restarted = restart(bc);
    let (outcome, _) = restarted.initialize_from_storage(500);

    assert_eq!(outcome, InitOutcome::ResumedCollecting);
    assert_eq!(restarted.current_phase(), LifecyclePhase::Collecting);
    assert_eq!(restarted.blocks.len(), 1, "the retained block survived");
}

/// AC8 — the equivalence the story exists to deliver: a restarted node and a
/// fresh node fed the same blocks agree on the active chain, the phase, and
/// the locked configuration.
#[test]
fn fr59_restart_is_equivalent_to_a_fresh_node_fed_the_same_blocks() {
    let (bc, genesis, cfg) = node_ready_from_the_mesh();
    let mut restarted = restart(bc);
    let (outcome, _) = restarted.initialize_from_storage(500);
    assert_eq!(outcome, InitOutcome::ResumedReady);

    // The comparison node never restarts: it receives the same two blocks.
    let mut fresh = new_unconfigured_test_chain();
    for block in [&cfg, &genesis] {
        let (outcome, _) = fresh.receive_block(block.view(), 0);
        assert_eq!(outcome, ReceiveBlockOutcome::AcceptedSilently);
    }

    assert_eq!(restarted.is_ready(), fresh.is_ready());
    assert_eq!(restarted.current_active_head(), fresh.current_active_head());
    assert_eq!(restarted.blocks.len(), fresh.blocks.len());
    // AC8 names the projection and the chain_heads set explicitly, and the
    // review found that omitting them hid a real bug: every rebuilt Stored
    // head had lost its missing-parent hash, which a chain_heads comparison
    // would have caught immediately.
    assert_eq!(
        restarted.chain_heads.count(),
        fresh.chain_heads.count(),
        "AC8 - the same chain_heads set"
    );
    assert_eq!(
        restarted.node_info.max_known_node_id(),
        fresh.node_info.max_known_node_id(),
        "AC8 - the same derived projection"
    );
    assert_eq!(
        restarted.chain_config.durable_content(),
        fresh.chain_config.durable_content(),
        "both committed the same configuration"
    );
    for (sequence, hash) in [(0u32, genesis.view().hash()), (1u32, cfg.view().hash())] {
        assert_eq!(
            restarted.blocks.find(sequence, &hash).is_some(),
            fresh.blocks.find(sequence, &hash).is_some(),
            "the two trees hold the same blocks"
        );
    }
}

/// AC3 — durable slots are not necessarily contiguous, so the scan must run
/// the whole capacity rather than stopping at the first empty slot. A node
/// that stopped early would silently lose its chain.
#[test]
fn fr59_restart_scan_does_not_stop_at_the_first_empty_slot() {
    let (_, mut storage, _) = test_backends();
    let genesis = genesis_zero_block(1_000);
    let cfg = chain_config_anchor_block(1, genesis.view().hash());
    // Deliberately leaving slot 0 empty and scattering the blocks.
    storage.save_block(1, &genesis).ok().expect("save");
    storage.save_block(3, &cfg).ok().expect("save");

    let crypto = Crypto::new([1u8; PRIVATE_KEY_SIZE])
        .ok()
        .expect("test private key");
    let mut bc = new_chain(
        crypto,
        storage,
        empty_chain_config(TestChain::BUILD_LIMITS),
        5,
        0,
    );
    let (_, _) = bc.initialize_from_storage(500);

    assert_eq!(bc.blocks.len(), 2, "both scattered blocks were found");
    assert!(bc.blocks.get(1).is_some() && bc.blocks.get(3).is_some());
    assert!(
        bc.blocks.get(0).is_none() && bc.blocks.get(2).is_none(),
        "blocks land at their own durable index, never compacted"
    );
}

/// AC3 — durable order is not topological. A parent written to a *higher*
/// slot than its child must still be linked, which is why linkage is a
/// second pass over the completed table rather than done inline.
#[test]
fn fr59_restart_links_parents_stored_after_their_children() {
    let (_, mut storage, _) = test_backends();
    let genesis = genesis_zero_block(1_000);
    let child = chain_config_anchor_block(1, genesis.view().hash());
    // Child first, parent second — the order a one-pass rebuild would break on.
    storage.save_block(0, &child).ok().expect("save");
    storage.save_block(1, &genesis).ok().expect("save");

    let crypto = Crypto::new([1u8; PRIVATE_KEY_SIZE])
        .ok()
        .expect("test private key");
    let mut bc = new_chain(
        crypto,
        storage,
        empty_chain_config(TestChain::BUILD_LIMITS),
        5,
        0,
    );
    let (_, _) = bc.initialize_from_storage(500);

    let child_idx = bc
        .blocks
        .find(1, &child.view().hash())
        .expect("the child is in the tree");
    let parent_idx = bc
        .blocks
        .find(0, &genesis.view().hash())
        .expect("the parent is in the tree");
    assert_eq!(
        bc.blocks.get(child_idx).map(|entry| entry.parent_ref()),
        Some(parent_idx),
        "the child resolved to its parent despite the inverted slot order"
    );
}

/// AC7 — a retained side branch survives the restart with its fork point
/// intact; FR20 forbids silently collapsing it.
#[test]
fn fr59_restart_preserves_side_branches() {
    let mut bc = new_unconfigured_test_chain();
    // A fork that survives to be tested: the branch root is itself an orphan
    // far above the window, so no FR2 candidate ever qualifies and neither
    // the FR5 recovery nor the FR8 lock-time cleanup can prune a branch
    // before the restart. The two tips differ in payload type, which is what
    // makes them distinct blocks at the same sequence rather than duplicates.
    let root = linked_transfer_block(100, [0xAB; 32]);
    let tip_a = linked_transfer_block(101, root.view().hash());
    let tip_b = chain_config_anchor_block(101, root.view().hash());
    for block in [&root, &tip_a, &tip_b] {
        let (outcome, _) = bc.receive_block(block.view(), 0);
        assert_eq!(outcome, ReceiveBlockOutcome::AcceptedSilently);
    }
    assert_eq!(
        bc.chain_heads.count(),
        2,
        "precondition: the tree really forked, and both tips are tracked"
    );
    assert!(!bc.is_ready(), "precondition: no candidate qualified");

    let mut restarted = restart(bc);
    let (outcome, _) = restarted.initialize_from_storage(500);

    assert_eq!(outcome, InitOutcome::ResumedCollecting);
    assert_eq!(restarted.blocks.len(), 3, "no branch was collapsed (FR20)");
    assert_eq!(
        restarted.chain_heads.count(),
        2,
        "AC7 - both branches are tracked again after the rebuild"
    );

    let root_idx = restarted
        .blocks
        .find(100, &root.view().hash())
        .expect("the fork point is retained");
    for tip in [&tip_a, &tip_b] {
        let tip_idx = restarted
            .blocks
            .find(101, &tip.view().hash())
            .expect("both tips are retained");
        assert_eq!(
            restarted
                .blocks
                .get(tip_idx)
                .map(|entry| entry.parent_ref()),
            Some(root_idx),
            "and both still hang off the same fork point"
        );
    }
}

/// AC9 (ratified 2026-09-20) — `StorageTrait` has no delete, so a block
/// removed before the shutdown is still readable afterwards and comes back.
/// The rebuilt tree is therefore **not** the pre-shutdown tree; what is
/// guaranteed is that the node still converges, because the deletion drivers
/// are deterministic and re-fire.
#[test]
fn fr59_restart_resurrects_a_deleted_block_and_still_converges() {
    let (mut bc, genesis, _cfg) = node_ready_from_the_mesh();

    // The post-deletion durable state, reproduced exactly: bytes present in
    // a slot, no entry in the tree. That is all `BlockTable::delete` leaves
    // behind, because `StorageTrait` has no delete and the slot is only
    // reclaimed when a later `save_block` overwrites it.
    let orphaned = linked_transfer_block(5, [0x77; 32]);
    bc.storage.save_block(6, &orphaned).ok().expect("save");
    assert!(
        bc.blocks.find(5, &orphaned.view().hash()).is_none(),
        "precondition: the block is durable but not in the pre-restart tree"
    );
    let head_before = bc.current_active_head();

    let mut restarted = restart(bc);
    let (outcome, _) = restarted.initialize_from_storage(500);

    assert!(
        restarted.blocks.find(5, &orphaned.view().hash()).is_some(),
        "AC9 - a slot that was never overwritten reads back and is admitted again"
    );
    assert_eq!(
        outcome,
        InitOutcome::ResumedReady,
        "and the node still converges on its chain"
    );
    assert_eq!(
        restarted.current_active_head(),
        head_before,
        "the resurrected block did not disturb the active chain"
    );
    assert!(
        restarted.blocks.find(0, &genesis.view().hash()).is_some(),
        "the genesis is still there"
    );
}

/// Writes an approval payload's `late_count` (the field before the late
/// entries, at `fixed − 2` of the payload).
fn payload_late_count(raw: &mut [u8], fixed: usize, late_count: u16) {
    raw[HEADER_SIZE + fixed - 2..HEADER_SIZE + fixed].copy_from_slice(&late_count.to_le_bytes());
}

/// AC3/AC11 — a slot whose payload does not frame coherently is skipped, not
/// fatal: one bad slot must not cost the node its chain. The fixture is an
/// approval block (Story 6.6 AC2) whose `late_count` frames it far beyond
/// the slot, so `content_length` refuses rather than guesses.
#[test]
fn fr59_restart_skips_a_slot_whose_length_cannot_be_recovered() {
    let (_, mut storage, _) = test_backends();
    let genesis = genesis_zero_block(1_000);
    storage.save_block(0, &genesis).ok().expect("save");

    const FIXED: usize = moonblokz_chain_types::approval_fixed_size(1, 1);
    let fixed = FIXED;
    let mut raw = [0u8; HEADER_SIZE + FIXED];
    raw[0] = 1; // version
    raw[13] = moonblokz_chain_types::PAYLOAD_TYPE_APPROVAL;
    let payload = &mut raw[HEADER_SIZE..];
    payload[12] = 1; // m
    payload[13] = 0b1; // one signer
    #[cfg(feature = "schnorr")]
    payload[14..16].copy_from_slice(&1u16.to_be_bytes()); // Schnorr's signer count
    let framed = Block::from_bytes(&raw).ok().expect("parses");
    assert_eq!(
        framed.content_length(),
        Some(framed.len()),
        "premise: with no late entry the fixture frames"
    );
    payload_late_count(&mut raw, fixed, u16::MAX);
    let undecodable = Block::from_bytes(&raw)
        .ok()
        .expect("structurally parseable, just not measurable");
    assert_eq!(
        undecodable.content_length(),
        None,
        "the late count overruns it"
    );
    storage.save_block(1, &undecodable).ok().expect("save");

    let crypto = Crypto::new([1u8; PRIVATE_KEY_SIZE])
        .ok()
        .expect("test private key");
    let mut bc = new_chain(
        crypto,
        storage,
        empty_chain_config(TestChain::BUILD_LIMITS),
        5,
        0,
    );
    let (_, _) = bc.initialize_from_storage(500);

    assert_eq!(bc.blocks.len(), 1, "the unmeasurable slot is skipped");
    assert!(
        bc.blocks.find(0, &genesis.view().hash()).is_some(),
        "and the good block is still recovered"
    );
}

/// AC11 — a populated store whose control plane cannot be read is refused,
/// not panicked on and not silently rebuilt: the node would be reconstructing
/// a chain without knowing the configuration it was accepted under.
#[test]
fn fr59_restart_rejects_a_populated_store_with_an_unreadable_control_plane() {
    // Never `init`ed, so `load_control_data` fails - but `save_block` still
    // writes into the slot region, so blocks are readable.
    let mut storage = MemoryBackend::<{ 8 * MAX_BLOCK_SIZE + 8000 }>::new();
    let genesis = genesis_zero_block(1_000);
    storage.save_block(0, &genesis).ok().expect("save");

    let crypto = Crypto::new([1u8; PRIVATE_KEY_SIZE])
        .ok()
        .expect("test private key");
    let mut bc = new_chain(
        crypto,
        storage,
        empty_chain_config(TestChain::BUILD_LIMITS),
        5,
        0,
    );

    let (outcome, next) = bc.initialize_from_storage(500);

    assert_eq!(
        outcome,
        InitOutcome::Rejected(RestartRejectReason::ControlPlaneUnreadable)
    );
    assert!(matches!(next, NextCall::Idle));
    assert_eq!(bc.blocks.len(), 0, "nothing was rebuilt");
}

/// The same unreadable control plane with an *empty* store is not an error:
/// that is exactly what a fresh node looks like, and Story 5.1's join path
/// must keep working.
#[test]
fn fr59_an_empty_store_is_a_fresh_join_even_without_a_control_plane() {
    let storage = MemoryBackend::<{ 8 * MAX_BLOCK_SIZE + 8000 }>::new();
    let crypto = Crypto::new([1u8; PRIVATE_KEY_SIZE])
        .ok()
        .expect("test private key");
    let mut bc = new_chain(
        crypto,
        storage,
        empty_chain_config(TestChain::BUILD_LIMITS),
        5,
        0,
    );

    let (outcome, next) = bc.initialize_from_storage(500);

    assert_eq!(outcome, InitOutcome::StartedCollecting);
    assert!(matches!(next, NextCall::Idle));
    assert_eq!(bc.current_phase(), LifecyclePhase::Collecting);
}

/// FR8's tentative phase is not durable, so a node that shut down before the
/// lock comes back holding nothing — yet its retained tree still carries the
/// config block it had adopted. Re-adopting is what keeps the restart
/// equivalent to a fresh node fed the same blocks; without it the node holds
/// no configuration and cannot run the FR3 derivation at all.
#[test]
fn fr59_restart_reestablishes_a_tentative_when_nothing_was_locked() {
    let mut bc = new_unconfigured_test_chain();
    let cfg = chain_config_anchor_block(100, [0xAB; 32]);
    let (outcome, _) = bc.receive_block(cfg.view(), 0);
    assert_eq!(outcome, ReceiveBlockOutcome::AcceptedSilently);
    assert!(
        !bc.chain_config.is_durable_locked(),
        "precondition: the configuration is only tentative"
    );
    let mut restarted = restart(bc);
    let (_, _) = restarted.initialize_from_storage(500);

    assert!(
        !restarted.chain_config.is_durable_locked(),
        "a tentative is re-established as a tentative, never promoted by a restart"
    );
    assert_eq!(
        restarted.chain_config.tentative_content(),
        Some(content_of(&cfg)),
        "the same configuration content is held again, from the retained block"
    );
}

/// AC10 — the rebuild is a pure function of the durable footprint: the same
/// store restarted twice yields the same outcome and the same tree.
#[test]
fn fr59_restart_is_deterministic() {
    let (bc, _, _) = node_ready_from_the_mesh();

    let mut first = restart(bc);
    let (first_outcome, _) = first.initialize_from_storage(500);
    let first_len = first.blocks.len();
    let first_head = first.current_active_head();
    let first_heads = first.chain_heads.count();
    let first_phase = first.current_phase();
    let mut first_tree = [None; 16];
    for (idx, cell) in first_tree.iter_mut().enumerate() {
        *cell = first
            .blocks
            .get(idx as u32)
            .map(|entry| (entry.sequence(), *entry.hash(), entry.parent_ref()));
    }

    // Restart the *same* durable store a second time, from scratch again.
    let mut second = restart(first);
    // A different `now`: it must not influence the reconstruction.
    let (second_outcome, _) = second.initialize_from_storage(9_999);

    assert_eq!(first_outcome, second_outcome);
    assert_eq!(first_len, second.blocks.len());
    assert_eq!(first_head, second.current_active_head());
    assert_eq!(
        first_heads,
        second.chain_heads.count(),
        "same chain_heads set"
    );
    assert_eq!(first_phase, second.current_phase(), "same phase trace");
    // AC10 asks for the same *tree*, not merely the same block count.
    for idx in 0..16u32 {
        assert_eq!(
            first_tree[idx as usize],
            second.blocks.get(idx).map(|entry| (
                entry.sequence(),
                *entry.hash(),
                entry.parent_ref()
            )),
            "slot {idx} must rebuild identically"
        );
    }
}

// ---- Review regressions (2026-09-21) --------------------------------

/// **Review finding, confirmed by execution.** Every rebuilt Stored head used
/// to come back with an all-zero `missing_parent_hash`, so FR19 emitted
/// parent-recovery requests for a hash that can never resolve — for the
/// lifetime of the node. Asserted through the observable outbound request
/// rather than the cache field, which is what a peer would actually receive.
#[test]
fn fr59_restart_preserves_the_missing_parent_hash_of_a_stored_head() {
    let mut bc = new_unconfigured_test_chain();
    let orphan = chain_config_anchor_block(100, [0xAB; 32]);
    let (outcome, _) = bc.receive_block(orphan.view(), 0);
    assert_eq!(outcome, ReceiveBlockOutcome::AcceptedSilently);

    let mut restarted = restart(bc);
    let (_, _) = restarted.initialize_from_storage(500);

    let (tick, _) = restarted.on_tick(1_000_000);
    match tick {
        TickOutcome::SendParentRecoveryRequest(request) => {
            assert_eq!(
                request.missing_parent_hash(),
                &[0xAB; 32],
                "the restarted node must request the parent the branch actually names"
            );
        }
        _ => panic!("a Stored head should schedule FR19 parent recovery after a restart"),
    }
}

/// **Review finding, confirmed by execution.** The single-genesis rule lives
/// in `tier1_admit`, which the rebuild bypasses, so two distinct sequence-0
/// blocks both entered the tree — a state live intake cannot produce.
#[test]
fn fr59_restart_admits_at_most_one_genesis() {
    let (_, mut storage, _) = test_backends();
    let genesis_a = genesis_zero_block(1_000);
    let genesis_b = genesis_zero_block(1_007);
    assert_ne!(
        genesis_a.view().hash(),
        genesis_b.view().hash(),
        "precondition: two distinct sequence-0 blocks"
    );
    storage.save_block(0, &genesis_a).ok().expect("save");
    storage.save_block(1, &genesis_b).ok().expect("save");

    let crypto = Crypto::new([1u8; PRIVATE_KEY_SIZE])
        .ok()
        .expect("test private key");
    let mut bc = new_chain(
        crypto,
        storage,
        empty_chain_config(TestChain::BUILD_LIMITS),
        5,
        0,
    );
    let (_, _) = bc.initialize_from_storage(500);

    let genesis_count = (0..16u32)
        .filter(|idx| {
            bc.blocks
                .get(*idx)
                .is_some_and(|entry| entry.sequence() == 0)
        })
        .count();
    assert_eq!(
        genesis_count, 1,
        "the rebuild must honour the single-genesis rule that tier1_admit enforces"
    );
    assert!(
        bc.blocks.find(0, &genesis_a.view().hash()).is_some(),
        "first by index wins, matching the live first-come rule"
    );
}

/// `initialize_from_storage` is a one-shot boot step. A second call used to
/// be guarded only by `debug_assert!`s, which compile out in exactly the
/// release builds that run on the device.
#[test]
fn fr59_a_second_initialize_from_storage_is_refused() {
    let (bc, _, _) = node_ready_from_the_mesh();
    let mut restarted = restart(bc);
    let (first, _) = restarted.initialize_from_storage(500);
    assert_eq!(first, InitOutcome::ResumedReady);
    let blocks_after_first = restarted.blocks.len();

    let (second, _) = restarted.initialize_from_storage(600);

    assert_eq!(
        second,
        InitOutcome::Rejected(RestartRejectReason::AlreadyInitialized)
    );
    assert_eq!(
        restarted.blocks.len(),
        blocks_after_first,
        "the refused call must not have touched the tree"
    );
}

/// AC11's second trigger: a store whose slots are all unreadable is damaged,
/// not empty, and must not be reported as a fresh join — that would discard
/// the node's whole chain silently.
#[test]
fn fr59_a_store_whose_every_slot_is_corrupt_is_refused() {
    let crypto = Crypto::new([1u8; PRIVATE_KEY_SIZE])
        .ok()
        .expect("test private key");
    let chain_config = empty_chain_config(TestChain::BUILD_LIMITS);
    let node_zero = *crypto.public_key().serialize();
    let mut slot =
        core::mem::MaybeUninit::<Blockchain<_, _, _, 16, 16, TEST_MAX_BLOCKS, 4, 16>>::uninit();
    let bc = Blockchain::<_, _, _, 16, 16, TEST_MAX_BLOCKS, 4, 16>::init(
        &mut slot,
        crypto,
        CorruptSlotsStorage,
        chain_config,
        5,
        node_zero,
        0,
    );

    let (outcome, _) = bc.initialize_from_storage(500);

    assert_eq!(
        outcome,
        InitOutcome::Rejected(RestartRejectReason::NoUsableTree)
    );
    assert_eq!(bc.blocks.len(), 0);
}

/// The irrevocable FR8/FR54 lock must not be taken on the control plane's
/// word alone: the block it carries is verified through the same FR7 gate
/// the revocable tentative path uses (review decision, 2026-09-21).
#[test]
fn fr59_a_control_plane_config_failing_fr7_is_refused() {
    let (_, mut storage, _) = test_backends();
    // A chain-config block whose content signature is not node #0's.
    let mut forged = chain_config_anchor_block(1, [0u8; 32]);
    let tampered = {
        let mut bytes = [0u8; MAX_BLOCK_SIZE];
        let exact = forged.serialized_bytes();
        bytes[..exact.len()].copy_from_slice(exact);
        // Flip a byte inside the content region, invalidating the signature
        // over it while leaving the envelope framing intact.
        bytes[HEADER_SIZE + 2] ^= 0xFF;
        Block::from_bytes(&bytes[..exact.len()])
            .ok()
            .expect("still structurally a block")
    };
    forged = tampered;
    storage
        .set_chain_configuration(&forged)
        .ok()
        .expect("control plane accepts it - storage does not verify signatures");
    let genesis = genesis_zero_block(1_000);
    storage.save_block(0, &genesis).ok().expect("save");

    let crypto = Crypto::new([1u8; PRIVATE_KEY_SIZE])
        .ok()
        .expect("test private key");
    let mut bc = new_chain(
        crypto,
        storage,
        empty_chain_config(TestChain::BUILD_LIMITS),
        5,
        0,
    );

    let (outcome, _) = bc.initialize_from_storage(500);

    assert_eq!(
        outcome,
        InitOutcome::Rejected(RestartRejectReason::ChainConfigUnusable)
    );
    assert!(
        !bc.chain_config.is_durable_locked(),
        "an unverifiable configuration must never become an irrevocable lock"
    );
}

/// AC9's convergence argument named the FR8 lock-time cleanups, but they sit
/// behind `if !is_durable_locked()` in the spine and so never ran on a
/// restart. An off-chain mismatching chain-config block survived forever.
#[test]
fn fr59_restart_cleans_up_an_off_chain_mismatching_config_block() {
    let (mut bc, _, _) = node_ready_from_the_mesh();
    // Validly signed by node #0, but carrying different content from the
    // configuration the chain locked. The live path refuses it outright.
    let mismatching = chain_config_block_from(100, [0xAB; 32], &mut alt_config_builder());
    let (live, _) = bc.receive_block(mismatching.view(), 0);
    assert_ne!(
        live,
        ReceiveBlockOutcome::AcceptedSilently,
        "precondition: the live path refuses a post-lock mismatching config"
    );
    // Plant it directly in a durable slot, as a pre-lock session would have.
    bc.storage.save_block(6, &mismatching).ok().expect("save");

    let mut restarted = restart(bc);
    let (outcome, _) = restarted.initialize_from_storage(500);

    assert_eq!(outcome, InitOutcome::ResumedReady);
    assert!(
        restarted
            .blocks
            .find(100, &mismatching.view().hash())
            .is_none(),
        "the restored lock must re-run its mismatch cleanup over the rebuilt tree"
    );
}

// ---- A refused restart must not be ignorable (2026-09-21) ------------

/// The refusal only protects the chain if the module stops accepting work.
/// Before this guard, a caller that ignored `Rejected(_)` kept feeding the
/// node, and because the rebuild left an empty tree over a populated store
/// the first admission took slot 0 and `save_block` overwrote a durable
/// block — the node silently destroying the chain it failed to load.
#[test]
fn a_refused_restart_stops_accepting_blocks_instead_of_overwriting_the_chain() {
    let (_, mut storage, _) = test_backends();
    // A control-plane configuration whose content signature no longer
    // verifies, so the restart refuses with `ChainConfigUnusable`.
    let cfg = chain_config_anchor_block(1, [0u8; 32]);
    let tampered = {
        let mut bytes = [0u8; MAX_BLOCK_SIZE];
        let exact = cfg.serialized_bytes();
        bytes[..exact.len()].copy_from_slice(exact);
        bytes[HEADER_SIZE + 2] ^= 0xFF;
        Block::from_bytes(&bytes[..exact.len()])
            .ok()
            .expect("still structurally a block")
    };
    storage
        .set_chain_configuration(&tampered)
        .ok()
        .expect("the control plane does not verify signatures");
    let genesis = genesis_zero_block(1_000);
    let durable_hash = genesis.view().hash();
    storage.save_block(0, &genesis).ok().expect("save");

    let crypto = Crypto::new([1u8; PRIVATE_KEY_SIZE])
        .ok()
        .expect("test private key");
    let mut bc = new_chain(
        crypto,
        storage,
        empty_chain_config(TestChain::BUILD_LIMITS),
        5,
        0,
    );
    let (outcome, _) = bc.initialize_from_storage(500);
    assert_eq!(
        outcome,
        InitOutcome::Rejected(RestartRejectReason::ChainConfigUnusable)
    );

    // The caller ignores the refusal and keeps feeding the node.
    let incoming = chain_config_anchor_block(100, [0xCD; 32]);
    let (admitted, next) = bc.receive_block(incoming.view(), 600);

    assert_eq!(
        admitted,
        ReceiveBlockOutcome::Rejected(RejectReason::Unstorable),
        "an operational refusal - the block may be valid, but this node cannot store anything"
    );
    assert!(matches!(next, NextCall::Idle));
    assert_eq!(bc.blocks.len(), 0, "and nothing entered the tree");

    let slot0 = bc
        .storage
        .read_block(0)
        .ok()
        .and_then(|block| TestChain::exact_view(block.serialized_bytes()).map(|v| v.hash()));
    assert_eq!(
        slot0,
        Some(durable_hash),
        "the durable block the restart could not load is still intact"
    );
}

/// The same guard for the other refusal that leaves an unrebuilt store.
#[test]
fn a_no_usable_tree_refusal_also_stops_accepting_blocks() {
    let crypto = Crypto::new([1u8; PRIVATE_KEY_SIZE])
        .ok()
        .expect("test private key");
    let node_zero = *crypto.public_key().serialize();
    let mut slot =
        core::mem::MaybeUninit::<Blockchain<_, _, _, 16, 16, TEST_MAX_BLOCKS, 4, 16>>::uninit();
    let bc = Blockchain::<_, _, _, 16, 16, TEST_MAX_BLOCKS, 4, 16>::init(
        &mut slot,
        crypto,
        CorruptSlotsStorage,
        empty_chain_config(TestChain::BUILD_LIMITS),
        5,
        node_zero,
        0,
    );
    let (outcome, _) = bc.initialize_from_storage(500);
    assert_eq!(
        outcome,
        InitOutcome::Rejected(RestartRejectReason::NoUsableTree)
    );

    let incoming = genesis_zero_block(1_000);
    let (admitted, _) = bc.receive_block(incoming.view(), 600);
    assert_eq!(
        admitted,
        ReceiveBlockOutcome::Rejected(RejectReason::Unstorable)
    );
}

/// `AlreadyInitialized` must **not** poison the node: it means the node is
/// already up and running, and the caller simply asked twice.
#[test]
fn a_duplicate_initialize_call_does_not_stop_a_healthy_node() {
    let (bc, _, _) = node_ready_from_the_mesh();
    let mut restarted = restart(bc);
    let (first, _) = restarted.initialize_from_storage(500);
    assert_eq!(first, InitOutcome::ResumedReady);

    let (second, _) = restarted.initialize_from_storage(600);
    assert_eq!(
        second,
        InitOutcome::Rejected(RestartRejectReason::AlreadyInitialized)
    );

    let incoming = linked_transfer_block(7, [0x99; 32]);
    let (admitted, _) = restarted.receive_block(incoming.view(), 700);
    assert_ne!(
        admitted,
        ReceiveBlockOutcome::Rejected(RejectReason::Unstorable),
        "a healthy node must keep working after a spurious second init call"
    );
}
