//! Tests of `api/forward.rs`.

use super::*;

// ===================================================================
// Story 6.0 — Ready-state active-head forward extension
// ===================================================================

/// AC2 / AC10.4: the derived state of two nodes is identical — `node_info`,
/// the vote engine, the whole block table (statuses, chain flags,
/// available-UTXO bits), `chain_heads`, the head and the tail.
fn assert_same_state<S: StorageTrait, T: StorageTrait>(a: &Chain16<S>, b: &Chain16<T>, what: &str) {
    assert!(a.node_info == b.node_info, "{what}: node_info");
    assert!(a.vote_engine == b.vote_engine, "{what}: votes");
    assert!(a.blocks == b.blocks, "{what}: block table");
    assert!(a.chain_heads == b.chain_heads, "{what}: chain_heads");
    assert_eq!(
        a.active_chain_head_idx, b.active_chain_head_idx,
        "{what}: head"
    );
    assert_eq!(
        a.snake_chain_tail_idx, b.snake_chain_tail_idx,
        "{what}: tail"
    );
    assert_eq!(a.lifecycle_phase, b.lifecycle_phase, "{what}: phase");
}

/// The durable slot `idx` holds the same bytes on both nodes.
fn same_slot<S: StorageTrait, T: StorageTrait>(a: &Chain16<S>, b: &Chain16<T>, idx: u32) -> bool {
    match (a.storage.read_block(idx), b.storage.read_block(idx)) {
        (Ok(x), Ok(y)) => x.serialized_bytes() == y.serialized_bytes(),
        (Err(_), Err(_)) => true,
        _ => false,
    }
}

/// The UTXO fixture on a genesis node: #2 registers node 1, #3 mints two
/// UTXO outputs (60, 40) from node #0's balance. Returns the node and #3.
fn utxo_genesis() -> (TestChain, Block) {
    let (mut bc, _, b1) = ready_genesis(16);
    let reg = register(2, b1.view().hash(), 1, 0x31);
    assert_eq!(
        receive(&mut bc, &reg),
        ReceiveBlockOutcome::AcceptedSilently
    );
    let mint_tx = utxo_tx(3, &[], Some((0, 100)), &[Ok(60), Ok(40)]);
    let mint = complex_tx_block(3, reg.view().hash(), 0, 0, &[&mint_tx]);
    assert_eq!(
        receive(&mut bc, &mint),
        ReceiveBlockOutcome::AcceptedSilently
    );
    assert_eq!(head_of(&bc).1, mint.view().hash());
    (bc, mint)
}

// --- Task 2.2: every inverse is exact (apply ∘ invert = identity) -------

#[test]
fn step_inverses_restore_the_derived_state_exactly() {
    // Node transfer, registration, and a complex transaction with a UTXO
    // spend, a balance input and a balance output — each applied by the
    // step and inverted, on a node that has a replica.
    let (mut bc, mint) = utxo_genesis();
    let (replica, _) = utxo_genesis();
    let (seq, prev) = (4, mint.view().hash());
    let nt = transfer_tx(seq, 1, 500);
    let reg = registration_tx(0, 2, 0x32);
    let cx = utxo_tx(seq, &[(3, 1, 40)], Some((0, 10)), &[Err((1, 45))]);
    let blocks = [
        tx_block(seq, prev, 0, |b| {
            b.add_node_transfer(&nt).ok().expect("transfer");
        }),
        tx_block(seq, prev, 0, |b| {
            b.add_registration(&reg).ok().expect("registration");
        }),
        complex_tx_block(seq, prev, 0, 0, &[&cx]),
    ];
    for block in &blocks {
        assert_eq!(step_reason(&mut bc, block), None, "the block is valid");
        assert_same_state(&bc, &replica, "after apply and invert");
    }
}

// --- AC10.1: direct extension -------------------------------------------

#[test]
fn forward_extension_promotes_each_direct_extension() {
    let (mut bc, _, b1) = ready_genesis(16);
    let reg = register(2, b1.view().hash(), 1, 0x31);
    let t3 = transfer(3, reg.view().hash(), 1, 100);
    let t4 = transfer(4, t3.view().hash(), 1, 50);
    for block in [&reg, &t3, &t4] {
        assert_eq!(
            receive(&mut bc, block),
            ReceiveBlockOutcome::AcceptedSilently
        );
        let idx = bc
            .blocks
            .find(block.view().sequence(), &block.view().hash())
            .expect("stored");
        assert_eq!(
            bc.current_active_head(),
            Some(idx),
            "D19: the head advances"
        );
        let entry = bc.blocks.get(idx).expect("entry");
        assert_eq!(entry.status(), BlockStatus::Active);
        assert!(entry.is_on_active_chain());
    }
    assert_eq!(bc.node_info.max_known_node_id(), 1);
    assert_eq!(bc.node_info.balance_of(1), 150);
    // Registration 50 + 1, transfers 101 + 51; every fee back to the
    // creator, node #0.
    assert_eq!(bc.node_info.balance_of(0), CURRENCY - 51 - 101 - 51 + 3);
    assert!(bc.is_ready());
}

// --- AC10.2: orphan continuation ----------------------------------------

#[test]
fn forward_extension_continues_over_a_stored_orphan() {
    let (mut bc, _, b1) = ready_genesis(16);
    let a = transfer(2, b1.view().hash(), 0, 7);
    let b = transfer(3, a.view().hash(), 0, 8);
    assert_eq!(receive(&mut bc, &b), ReceiveBlockOutcome::AcceptedSilently);
    let bi = bc.blocks.find(3, &b.view().hash()).expect("orphan stored");
    assert_eq!(
        bc.blocks.get(bi).map(|e| e.status()),
        Some(BlockStatus::Stored)
    );
    assert_eq!(head_of(&bc).0, 1, "the orphan does not move the head");

    assert_eq!(receive(&mut bc, &a), ReceiveBlockOutcome::AcceptedSilently);
    assert_eq!(
        head_of(&bc),
        (3, b.view().hash()),
        "A at intake, B by continuation"
    );
    assert_eq!(
        bc.blocks.get(bi).map(|e| e.status()),
        Some(BlockStatus::Active)
    );
    assert!(!bc.chain_heads.has_stored_head());
    assert_eq!(bc.chain_heads.count(), 1, "no zombie entry for A");
}

// --- AC10.3: sibling choice (D5) ----------------------------------------

#[test]
fn forward_extension_takes_the_lowest_hash_sibling_on_an_equal_rank() {
    let (mut bc, _, b1) = ready_genesis(16);
    let a = transfer(2, b1.view().hash(), 0, 7);
    let c1 = transfer(3, a.view().hash(), 0, 8);
    let c2 = transfer(3, a.view().hash(), 0, 9);
    for c in [&c1, &c2] {
        assert_eq!(receive(&mut bc, c), ReceiveBlockOutcome::AcceptedSilently);
    }
    assert_eq!(receive(&mut bc, &a), ReceiveBlockOutcome::AcceptedSilently);
    let (low, high) = if c1.view().hash() < c2.view().hash() {
        (&c1, &c2)
    } else {
        (&c2, &c1)
    };
    // Equal value, size and creator: the FR21 rank falls to the hash.
    assert_eq!(head_of(&bc), (3, low.view().hash()), "the lower hash wins");
    let hi = bc.blocks.find(3, &high.view().hash()).expect("loser kept");
    // Story 6.1: the loser is a side block the driver connected.
    assert_eq!(
        bc.blocks.get(hi).map(|e| e.status()),
        Some(BlockStatus::Connected)
    );
    assert!(
        bc.chain_heads.occupied_heads().any(|(h, _)| h == hi),
        "the loser is a tracked side head"
    );
    assert!(!bc.chain_heads.has_stored_head(), "and a Connected one");
}

// --- AC10.4: invalid direct extension (AC3, AC2) ------------------------

/// Feeds `bad` to a node and asserts the AC3 refusal: `InvalidEvidence`,
/// nothing stored, and every piece of derived state identical to a replica
/// that never saw it (AC2). `reason` pins why, against a third replica.
fn assert_refused_at_intake(build: impl Fn() -> TestChain, bad: &Block, reason: ValidationReason) {
    let mut bc = build();
    let replica = build();
    let mut probe = build();
    assert_eq!(step_reason(&mut probe, bad), Some(reason));
    assert_same_state(&probe, &replica, "the probe left nothing behind");
    let free = bc.blocks.next_free_index().expect("a free slot");
    assert_eq!(
        receive(&mut bc, bad),
        ReceiveBlockOutcome::Rejected(RejectReason::InvalidEvidence)
    );
    assert_same_state(&bc, &replica, "refused extension");
    assert_eq!(bc.blocks.next_free_index(), Some(free), "no slot used");
    assert!(same_slot(&bc, &replica, free), "storage unchanged");
}

#[test]
fn invalid_direct_extension_is_not_stored_and_leaves_no_trace() {
    let genesis = || ready_genesis(16).0;
    let (_, _, b1) = ready_genesis(16);
    let prev = b1.view().hash();
    // Insufficient balance after an earlier, valid transfer in the block.
    let ok = transfer_tx(2, 0, 10);
    let broke = transfer_tx(2, 0, CURRENCY);
    let overspend = tx_block(2, prev, 0, |b| {
        b.add_node_transfer(&ok).ok().expect("first");
        b.add_node_transfer(&broke).ok().expect("second");
    });
    assert_refused_at_intake(genesis, &overspend, ValidationReason::InsufficientBalance);

    // A duplicate key after an earlier registration's debit and seeding.
    let first = registration_tx(0, 1, 0x31);
    let dup = registration_tx(0, 2, 0x31);
    let duplicate = tx_block(2, prev, 0, |b| {
        b.add_registration(&first).ok().expect("first");
        b.add_registration(&dup).ok().expect("second");
    });
    assert_refused_at_intake(genesis, &duplicate, ValidationReason::DuplicatePublicKey);

    // A UTXO spend after an earlier input spent the same output.
    let utxo = || utxo_genesis().0;
    let (_, mint) = utxo_genesis();
    let spend = utxo_tx(4, &[(3, 0, 60)], None, &[Err((1, 60))]);
    let again = utxo_tx(4, &[(3, 0, 60)], None, &[Err((1, 60))]);
    let double = complex_tx_block(4, mint.view().hash(), 0, 0, &[&spend, &again]);
    assert_refused_at_intake(utxo, &double, ValidationReason::UtxoUnavailable);
}

// --- AC10.5: invalid stored child (AC4, AC5) ----------------------------

#[test]
fn invalid_stored_child_is_deleted_with_its_descendants() {
    let (mut bc, _, b1) = ready_genesis(16);
    let (mut replica, _, _) = ready_genesis(16);
    let a = transfer(2, b1.view().hash(), 0, 7);
    let bad = transfer(3, a.view().hash(), 0, CURRENCY);
    let below = transfer(4, bad.view().hash(), 0, 8);
    for block in [&below, &bad] {
        assert_eq!(
            receive(&mut bc, block),
            ReceiveBlockOutcome::AcceptedSilently
        );
    }
    assert_eq!(bc.blocks.len(), 4, "both orphans stored");

    assert_eq!(receive(&mut bc, &a), ReceiveBlockOutcome::AcceptedSilently);
    assert_eq!(
        receive(&mut replica, &a),
        ReceiveBlockOutcome::AcceptedSilently
    );
    assert_eq!(head_of(&bc), (2, a.view().hash()), "A stays the head");
    assert!(
        bc.blocks.find(3, &bad.view().hash()).is_none(),
        "child deleted"
    );
    assert!(
        bc.blocks.find(4, &below.view().hash()).is_none(),
        "with its descendant"
    );
    assert!(bc.is_ready(), "no FR5 recovery in Ready");
    // Nothing of the failed child reached the derived state.
    assert!(bc.node_info == replica.node_info);
    assert!(bc.vote_engine == replica.vote_engine);
}

// --- AC10.6: local failures (AC6) ---------------------------------------

#[test]
fn read_failure_at_intake_stores_the_extension_and_retries_it() {
    let (mut bc, mint) = faulty_utxo_genesis();
    let (replica, _) = faulty_utxo_genesis();
    let mint_idx = bc.active_chain_head_idx;
    let tx = utxo_tx(4, &[(3, 1, 40)], None, &[Err((1, 40))]);
    let spend = complex_tx_block(4, mint.view().hash(), 0, 0, &[&tx]);

    bc.storage.failing_read_slot = mint_idx;
    assert_eq!(
        receive(&mut bc, &spend),
        ReceiveBlockOutcome::AcceptedSilently
    );
    let si = bc
        .blocks
        .find(4, &spend.view().hash())
        .expect("stored, not blamed");
    assert_eq!(
        bc.blocks.get(si).map(|e| e.status()),
        Some(BlockStatus::Stored)
    );
    assert_eq!(bc.active_chain_head_idx, mint_idx, "head unchanged");
    assert!(bc.node_info == replica.node_info, "derived state unchanged");
    assert!(bc.vote_engine == replica.vote_engine);
    assert_eq!(
        bc.blocks.utxo_available(mint_idx, 1),
        Some(true),
        "bit restored"
    );

    // The fault clears; the next admission — any block — extends it.
    bc.storage.failing_read_slot = NONE_REF;
    let unrelated = node_transfer_block(9, 3, 8, 7);
    assert_eq!(
        receive(&mut bc, &unrelated),
        ReceiveBlockOutcome::AcceptedSilently
    );
    assert_eq!(bc.active_chain_head_idx, si, "the retry extended the head");
    assert_eq!(bc.blocks.utxo_available(mint_idx, 1), Some(false));
    assert_eq!(bc.node_info.balance_of(1), 40);
}

#[test]
fn save_failure_inverts_the_extension_and_is_unstorable() {
    let (mut bc, mint) = faulty_utxo_genesis();
    let (replica, _) = faulty_utxo_genesis();
    let tx = utxo_tx(4, &[(3, 1, 40)], Some((0, 5)), &[Err((1, 44))]);
    let spend = complex_tx_block(4, mint.view().hash(), 0, 0, &[&tx]);
    bc.storage.fail_saves = true;
    assert_eq!(
        receive(&mut bc, &spend),
        ReceiveBlockOutcome::Rejected(RejectReason::Unstorable)
    );
    assert_same_state(&bc, &replica, "save failure");
}

// --- AC10.7: the window path --------------------------------------------

#[test]
fn window_extension_past_w_advances_and_binds() {
    // Binding `Invalid` at intake: dropping #0 needs a balance block (FR50).
    let (mut bc, b5) = full_w6_genesis();
    let (replica, _) = full_w6_genesis();
    let plain = transfer(6, b5.view().hash(), 0, 9);
    assert_eq!(
        receive(&mut bc, &plain),
        ReceiveBlockOutcome::Rejected(RejectReason::InvalidEvidence)
    );
    assert_same_state(&bc, &replica, "binding refusal stores nothing");

    // A stored child failing its binding is deleted. The snapshot at #6
    // advances the tail to #1 (chain-config), so a transfer at #7 cannot
    // drop it (FR49) — admitted first as an orphan, judged by continuation.
    let replay = snapshot_block(&bc, 6, b5.view().hash());
    let child = transfer(7, replay.view().hash(), 0, 9);
    assert_eq!(
        receive(&mut bc, &child),
        ReceiveBlockOutcome::AcceptedSilently
    );
    assert_eq!(
        receive(&mut bc, &replay),
        ReceiveBlockOutcome::AcceptedSilently
    );
    assert_eq!(head_of(&bc), (6, replay.view().hash()));
    assert_eq!(
        bc.active_snake_chain_window(),
        Ok((1, 6)),
        "the extension past W advanced the tail in the same step"
    );
    let genesis_idx = bc.blocks.find(0, &bc_genesis_hash());
    assert!(genesis_idx.is_some(), "#0 entered the horizon (Story 6.14)");
    assert_eq!(genesis_idx, Some(bc.horizon_root()));
    assert!(
        bc.blocks.find(7, &child.view().hash()).is_none(),
        "child deleted"
    );
    let replay_idx = bc.active_chain_head_idx;
    assert!(
        bc.node_info.is_seed_source(replay_idx),
        "D9: the seed source moved"
    );
    // Story 6.4 AC9 3c: a head extension that advanced the tail.
    assert_active_set_matches(&bc, "after the tail advance");
}

/// Block #0 of every genesis node in this section (it is deterministic).
fn bc_genesis_hash() -> [u8; 32] {
    ready_genesis(16).1.view().hash()
}

/// AC10.7 — a classification failure is a local one: no mutation, no
/// verdict. Since Story 6.11 the classification reads no storage, so its
/// only failure is a tail naming an empty slot; that is reached here by
/// corrupting the index and judging directly, since `receive_block`'s FR60
/// window asserts the same invariant in debug builds.
#[test]
fn window_classification_failure_changes_nothing() {
    let (mut bc, b5) = full_w6_genesis();
    let (replica, _) = full_w6_genesis();
    let real_tail = bc.snake_chain_tail_idx;
    let replay = snapshot_block(&bc, 6, b5.view().hash());
    let view = replay.view();
    let idx = bc.blocks.next_free_index().expect("free");
    let head = bc.active_chain_head_idx;
    bc.blocks
        .insert_at(idx, BlockEntry::new(view.hash(), head, view.sequence()));
    bc.snake_chain_tail_idx = idx + 1; // an empty slot
    assert!(matches!(
        bc.judge_head_extension(&view, idx, bc.snake_chain_tail_idx),
        Extension::Local
    ));
    bc.snake_chain_tail_idx = real_tail;
    bc.blocks.delete(idx);
    assert_same_state(&bc, &replica, "classification failure");

    // With the tail readable again, the same block extends the head.
    assert_eq!(
        receive(&mut bc, &replay),
        ReceiveBlockOutcome::AcceptedSilently
    );
    assert_eq!(head_of(&bc), (6, replay.view().hash()));
}

// --- AC10.8: genesis-node equivalence (AC8) -----------------------------

#[test]
fn genesis_node_and_mesh_node_derive_the_same_state() {
    let (mut g, b0, b1) = ready_genesis(16);
    assert_eq!(
        g.blocks.get(0).map(|e| e.status()),
        Some(BlockStatus::Active)
    );
    assert_eq!(
        g.blocks.get(1).map(|e| e.status()),
        Some(BlockStatus::Active)
    );
    let mut m = new_unconfigured_test_chain();
    for block in [&b0, &b1] {
        assert_eq!(
            receive(&mut m, block),
            ReceiveBlockOutcome::AcceptedSilently
        );
    }
    assert!(m.is_ready(), "the mesh node joined through FR3");
    let reg = register(2, b1.view().hash(), 1, 0x31);
    let t3 = transfer(3, reg.view().hash(), 1, 100);
    for block in [&reg, &t3] {
        assert_eq!(
            receive(&mut g, block),
            ReceiveBlockOutcome::AcceptedSilently
        );
        assert_eq!(
            receive(&mut m, block),
            ReceiveBlockOutcome::AcceptedSilently
        );
    }
    assert!(g.node_info == m.node_info, "node_info");
    assert!(g.vote_engine == m.vote_engine, "votes");
    for idx in 0..4 {
        let (a, b) = (g.blocks.get(idx).expect("g"), m.blocks.get(idx).expect("m"));
        assert_eq!(a.hash(), b.hash());
        assert_eq!(a.status(), b.status());
        assert_eq!(a.is_on_active_chain(), b.is_on_active_chain());
    }
    assert_eq!(head_of(&g), head_of(&m));
}

// --- AC10.9: FR3 / restart / double-run equivalence (AC9) ---------------

/// The AC9 sequence on a genesis node: a registration, a transfer, a mined
/// UTXO mint, a spend, and a matching balance block. Returns the node and
/// the blocks in chain order, #0 first.
fn extended_genesis() -> (TestChain, [Block; 7]) {
    let (mut bc, b0, b1) = ready_genesis(16);
    let reg = register(2, b1.view().hash(), 1, 0x31);
    receive(&mut bc, &reg);
    let t3 = transfer(3, reg.view().hash(), 1, 100);
    receive(&mut bc, &t3);
    let mint_tx = utxo_tx(4, &[], Some((0, 100)), &[Ok(60), Ok(40)]);
    let mint = complex_tx_block(4, t3.view().hash(), 0, 25, &[&mint_tx]);
    receive(&mut bc, &mint);
    let spend_tx = utxo_tx(5, &[(4, 0, 60)], None, &[Err((1, 59))]);
    let spend = complex_tx_block(5, mint.view().hash(), 0, 0, &[&spend_tx]);
    receive(&mut bc, &spend);
    let snap = snapshot_block(&bc, 6, spend.view().hash());
    receive(&mut bc, &snap);
    assert_eq!(
        head_of(&bc),
        (6, snap.view().hash()),
        "every block extended"
    );
    (bc, [b0, b1, reg, t3, mint, spend, snap])
}

#[test]
fn forward_extension_matches_fr3_restart_and_replay() {
    let (a, blocks) = extended_genesis();
    assert_eq!(a.blocks.utxo_available(4, 0), Some(false), "spent");
    assert_eq!(a.blocks.utxo_available(4, 1), Some(true), "unspent");

    // (1) A fresh node receiving the same blocks while Collecting reaches
    // Ready through FR3 over all of them: orphans first, genesis last.
    let mut b = new_unconfigured_test_chain();
    for block in blocks.iter().rev() {
        assert_eq!(
            receive(&mut b, block),
            ReceiveBlockOutcome::AcceptedSilently
        );
    }
    assert!(b.is_ready());
    assert_eq!(head_of(&b), head_of(&a));
    assert_eq!(
        b.node_info.max_known_node_id(),
        a.node_info.max_known_node_id()
    );
    for node in 0..16 {
        assert_eq!(b.node_info.balance_of(node), a.node_info.balance_of(node));
        assert_eq!(
            b.node_info.public_key_of(node),
            a.node_info.public_key_of(node)
        );
        assert_eq!(
            b.vote_engine.accumulated_vote_of(node),
            a.vote_engine.accumulated_vote_of(node)
        );
    }
    for block in &blocks {
        let view = block.view();
        let ai = a.blocks.find(view.sequence(), &view.hash()).expect("a");
        let bi = b.blocks.find(view.sequence(), &view.hash()).expect("b");
        let (ea, eb) = (a.blocks.get(ai).expect("a"), b.blocks.get(bi).expect("b"));
        assert_eq!(ea.status(), eb.status(), "#{}", view.sequence());
        assert_eq!(ea.is_on_active_chain(), eb.is_on_active_chain());
        for bit in 0..16 {
            assert_eq!(ea.utxo_available(bit), eb.utxo_available(bit));
        }
        assert_eq!(
            a.node_info.is_seed_source(ai),
            b.node_info.is_seed_source(bi),
            "seed source #{}",
            view.sequence()
        );
    }

    // (2) Restart of A rebuilds the same state from its own slots.
    let (a, _) = extended_genesis();
    let (reference, _) = extended_genesis();
    let mut restarted = restart(a);
    let _ = restarted.initialize_from_storage(0);
    assert!(restarted.is_ready());
    assert!(
        restarted.node_info == reference.node_info,
        "restart node_info"
    );
    assert!(
        restarted.vote_engine == reference.vote_engine,
        "restart votes"
    );
    assert_eq!(head_of(&restarted), head_of(&reference));
    for idx in 0..7 {
        let (x, y) = (
            restarted.blocks.get(idx).expect("restarted"),
            reference.blocks.get(idx).expect("reference"),
        );
        assert_eq!(x.status(), y.status());
        assert_eq!(x.is_on_active_chain(), y.is_on_active_chain());
        for bit in 0..16 {
            assert_eq!(x.utxo_available(bit), y.utxo_available(bit));
        }
    }

    // (3) The same admission sequence twice gives the same state.
    let (twice, _) = extended_genesis();
    assert_same_state(&twice, &reference, "double run");
}

// --- AC10.10: chain_heads cache and eviction protection (AC7) -----------

#[test]
fn promoted_head_has_current_caches() {
    let (mut bc, _, b1) = ready_genesis(16);
    let a = transfer(2, b1.view().hash(), 0, 7);
    receive(&mut bc, &a);
    let head = bc.active_chain_head_idx;
    assert!(
        bc.chain_heads
            .occupied_heads()
            .any(|(h, anchor)| h == head && anchor == head),
        "the head's entry anchors on the head itself, not the old head"
    );
}

// --- AC10.11: balance block (D9) ----------------------------------------

/// A balance block by node #0 with `mined_amount`.
fn mined_balance_block(
    seq: u32,
    prev: [u8; 32],
    entries: &[(u32, u64, u32, u8)],
    max_node_id: u32,
    mined: u32,
) -> Block {
    use moonblokz_chain_types::NodeInfo;
    let signer = Crypto::new([1u8; PRIVATE_KEY_SIZE]).ok().expect("test key");
    let real_key = *signer.public_key().serialize();
    let header = BlockHeader {
        version: 1,
        sequence: seq,
        creator: 0,
        mined_amount: mined,
        payload_type: PAYLOAD_TYPE_BALANCE,
        consumed_votes: 0,
        first_voted_node: 0,
        consumed_votes_from_first_voted_node: 0,
        previous_hash: prev,
        signature: [0u8; SIGNATURE_SIZE],
    };
    let mut builder = BlockBuilder::new().header(header);
    for &(owner, balance, vote_count, _) in entries {
        let ni = NodeInfo::new(owner, balance, vote_count, &real_key);
        builder.add_node_info(&ni).ok().expect("add node info");
    }
    builder
        .set_max_node_id(max_node_id)
        .ok()
        .expect("max node id");
    builder.build_signed(&signer).ok().expect("build signed")
}

#[test]
fn balance_block_repeats_the_pre_state_in_ready() {
    // Two nodes: #0 (the creator) and #1, registered at #2. A transfer at
    // #3 gives #1 a vote so the snapshot has a non-trivial vote count.
    let build = || {
        let (mut bc, _, b1) = ready_genesis(16);
        let reg = register(2, b1.view().hash(), 1, 0x31);
        receive(&mut bc, &reg);
        let nt = NodeTransfer::new_signed(
            1,
            2,
            0,
            1,
            10,
            1,
            0,
            &Crypto::new([1u8; PRIVATE_KEY_SIZE]).ok().expect("key"),
        );
        let t3 = tx_block(3, reg.view().hash(), 0, |b| {
            b.add_node_transfer(&nt).ok().expect("transfer");
        });
        receive(&mut bc, &t3);
        (bc, t3)
    };
    let (mut bc, t3) = build();
    let prev = t3.view().hash();
    let (owner, balance, votes, _) = node_zero_snapshot(&bc);
    assert!(bc.vote_engine.accumulated_vote_of(1) > 0, "precondition");

    // Each mismatching field of a seeded entry is Invalid (FR50).
    for entry in [
        (owner, balance - 1, votes, 0),
        (owner, balance, votes + 1, 0),
        // Node #1's key is `pubkey(0x31)`; the builder writes node #0's.
        (
            1,
            bc.node_info.balance_of(1),
            bc.vote_engine.accumulated_vote_of(1),
            0,
        ),
    ] {
        let bad = mined_balance_block(4, prev, &[entry], 1, 3);
        assert_eq!(
            step_reason(&mut bc, &bad),
            Some(ValidationReason::BalanceSnapshotMismatch)
        );
    }
    // An entry for a node that does not exist is Invalid in Ready.
    let ghost = mined_balance_block(4, prev, &[(2, 0, 0, 0)], 1, 3);
    assert_eq!(
        step_reason(&mut bc, &ghost),
        Some(ValidationReason::NodeIdOutOfRange)
    );

    // A mismatch as a stored child is deleted, derived state untouched.
    let (mut replica, _) = build();
    let mut bad_child_chain = build().0;
    let filler = transfer(4, prev, 0, 7);
    let bad = mined_balance_block(5, filler.view().hash(), &[(owner, 0, votes, 0)], 1, 3);
    receive(&mut bad_child_chain, &bad);
    receive(&mut bad_child_chain, &filler);
    receive(&mut replica, &filler);
    assert!(
        bad_child_chain.blocks.find(5, &bad.view().hash()).is_none(),
        "deleted"
    );
    assert!(bad_child_chain.node_info == replica.node_info);
    assert!(bad_child_chain.vote_engine == replica.vote_engine);

    // The matching snapshot is accepted: the entries leave balances and
    // votes as they were; only the block-level effects apply.
    let good = mined_balance_block(4, prev, &[(owner, balance, votes, 0)], 1, 3);
    let vote_one = bc.vote_engine.accumulated_vote_of(1);
    assert_eq!(
        receive(&mut bc, &good),
        ReceiveBlockOutcome::AcceptedSilently
    );
    assert_eq!(head_of(&bc), (4, good.view().hash()));
    assert_eq!(
        bc.node_info.balance_of(0),
        balance + 3,
        "the creator credit"
    );
    assert_eq!(
        bc.vote_engine.accumulated_vote_of(0),
        0,
        "the creator reset"
    );
    assert!(
        bc.vote_engine.accumulated_vote_of(1) >= vote_one,
        "only interest applies to the listed-or-not others"
    );
    let gi = bc.active_chain_head_idx;
    assert!(
        bc.node_info.is_seed_source(gi),
        "node #0's seed source moved"
    );
}

#[test]
fn balance_block_snapshot_is_checked_in_fr3() {
    // A genesis-anchored FR3 pass over a balance block whose snapshot
    // disagrees deletes it (FR5); the matching one is adopted.
    let (g, b0, b1) = ready_genesis(16);
    let (owner, balance, votes, _) = node_zero_snapshot(&g);
    for (entry_balance, adopted) in [(balance + 1, false), (balance, true)] {
        let snap = balance_block(2, b1.view().hash(), &[(owner, entry_balance, votes, 0)], 0);
        let mut m = new_unconfigured_test_chain();
        for block in [&snap, &b1, &b0] {
            receive(&mut m, block);
        }
        assert!(m.is_ready());
        assert_eq!(m.blocks.find(2, &snap.view().hash()).is_some(), adopted);
        assert_eq!(head_of(&m).0, if adopted { 2 } else { 1 });
    }
    // A window-anchored pass seeds an unseeded entry (floor seeding).
    let (mut bc, _) = utxo_test_chain();
    let tip = (0..16u32)
        .find(|&i| bc.blocks.get(i).is_some_and(|e| e.sequence() == 100))
        .expect("#100");
    assert_eq!(bc.run_processing_pass(tip).map(|_| ()), Ok(()));
    assert!(bc.node_info.is_seeded(1));
    assert_eq!(bc.node_info.balance_of(1), 100);
}

// --- AC10.12: complete context in Ready (D3) ----------------------------

#[test]
fn ready_has_no_trust_zone() {
    let (mut bc, _, b1) = ready_genesis(16);
    let prev = b1.view().hash();
    // An unseeded creator.
    let signer = Crypto::new([1u8; PRIVATE_KEY_SIZE]).ok().expect("key");
    let header = BlockHeader {
        version: 1,
        sequence: 2,
        creator: 5,
        mined_amount: 0,
        payload_type: PAYLOAD_TYPE_TRANSACTION,
        consumed_votes: 0,
        first_voted_node: 0,
        consumed_votes_from_first_voted_node: 0,
        previous_hash: prev,
        signature: [0u8; SIGNATURE_SIZE],
    };
    let nt = transfer_tx(2, 0, 1);
    let mut builder = BlockBuilder::new().header(header);
    builder.add_node_transfer(&nt).ok().expect("transfer");
    let by_stranger = builder.build_signed(&signer).ok().expect("build");
    assert_eq!(
        step_reason(&mut bc, &by_stranger),
        Some(ValidationReason::UnseededActor)
    );
    // An initializer that is not seeded (here: does not exist).
    let foreign = transfer_block(2, prev, 7, 0, 1, 1, 0);
    assert_eq!(
        step_reason(&mut bc, &foreign),
        Some(ValidationReason::UnseededActor)
    );
    // As a stored child, it is deleted.
    let a = transfer(2, prev, 0, 7);
    let child = transfer_block(3, a.view().hash(), 7, 0, 1, 1, 0);
    receive(&mut bc, &child);
    receive(&mut bc, &a);
    assert_eq!(head_of(&bc), (2, a.view().hash()));
    assert!(bc.blocks.find(3, &child.view().hash()).is_none());
}

/// DEC-134 — a `parent_ref` into a freed slot is the node's own index
/// defect: the pass reports `MissingBlock`, the recovery deletes nothing,
/// unlinks the dangling reference, and the block becomes a Stored
/// tail-point that FR19 asks its real parent for.
#[test]
fn missing_block_repairs_the_index_and_deletes_nothing() {
    let mut bc = new_test_chain();
    let genesis = genesis_zero_block(1_000);
    bc.tier1_admit(&genesis.view(), &genesis.view().hash(), 0)
        .expect("genesis admitted");
    let b1 = transfer_block(1, genesis.view().hash(), 1, 2, 100, 1, 0);
    bc.tier1_admit(&b1.view(), &b1.view().hash(), 0)
        .expect("b1 admitted");
    let b2 = transfer_block(2, b1.view().hash(), 1, 2, 100, 1, 0);
    let bi2 = bc
        .tier1_admit(&b2.view(), &b2.view().hash(), 0)
        .expect("b2 admitted");
    // The defect: b2 names a slot that holds no block.
    let freed = bc.blocks.next_free_index().expect("free");
    bc.blocks.set_parent_ref(bi2, NONE_REF);
    bc.blocks.set_parent_ref(bi2, freed);

    bc.set_lifecycle_phase(LifecyclePhase::Processing);
    let err = bc
        .run_processing_pass(bi2)
        .expect_err("the walk meets the freed slot");
    assert_eq!(err, ProcessingError::MissingBlock);
    bc.recover_from_failed_pass(err, bi2);

    assert_eq!(bc.blocks.len(), 3, "nothing deleted");
    assert_eq!(bc.current_phase(), LifecyclePhase::Collecting);
    assert_eq!(
        bc.blocks.get(bi2).map(|e| e.parent_ref()),
        Some(NONE_REF),
        "unlinked"
    );
    assert!(
        (0..4).any(|slot| bc.chain_heads.stored_head_tail(slot) == Some(bi2)),
        "b2 is a Stored tail-point"
    );
    let (outcome, _) = bc.on_tick(u64::MAX / 2);
    match outcome {
        TickOutcome::SendParentRecoveryRequest(req) => {
            assert_eq!(
                req.missing_parent_hash(),
                &b1.view().hash(),
                "asks for its parent"
            );
            assert_eq!(req.claimed_parent_sequence(), 1);
        }
        _ => panic!("a parent-recovery request is due"),
    }
}

// --- Code review 2026-10-18 -------------------------------------------

/// Review patch — a registration by a not-yet-seeded initializer (a
/// window-anchored pass, before its seed source) still pays its fee to a
/// seeded creator, so the creator's balance stays exact for D9.
#[test]
fn registration_fee_reaches_the_creator_when_the_initializer_is_unseeded() {
    let mut bc = new_test_chain();
    let cfg_hash = admit_chain_config_anchor(&mut bc, 99, [0xAB; 32]);
    // Node 0 (the creator) is listed; node 4 exists but is not.
    let seed = balance_block(100, cfg_hash, &[(0, 1_000, 0, 0)], 4);
    admit(&mut bc, &seed);
    let reg = registration_block(101, seed.view().hash(), 4, 5, 0x45);
    let tip = admit(&mut bc, &reg);
    assert_eq!(bc.run_processing_pass(tip).map(|_| ()), Ok(()));
    assert!(
        !bc.node_info.is_seeded(4),
        "precondition: unseeded initializer"
    );
    assert_eq!(
        bc.node_info.balance_of(0),
        1_001,
        "the fee reached the creator"
    );
}

/// Review patch — a complex transaction that fails after a UTXO spend, a
/// balance-input debit and a balance-output credit is inverted exactly.
#[test]
fn partially_applied_complex_transaction_is_inverted_exactly() {
    let (mut bc, mint) = utxo_genesis();
    let (replica, _) = utxo_genesis();
    // Node 9 does not exist: the second output fails its range check.
    let cx = utxo_tx(4, &[(3, 0, 60)], Some((0, 10)), &[Err((1, 5)), Err((9, 5))]);
    let block = complex_tx_block(4, mint.view().hash(), 0, 0, &[&cx]);
    assert_eq!(
        step_reason(&mut bc, &block),
        Some(ValidationReason::NodeIdOutOfRange)
    );
    assert_same_state(&bc, &replica, "partial complex inversion");
}

/// Review patch — a credit that would overflow the creator's balance is
/// `BalanceOverflow`, and nothing of the block remains applied.
#[test]
fn creator_credit_overflow_is_invalid() {
    let build = || {
        let (crypto, storage, chain_config) = test_backends();
        let mut bc = new_chain(crypto, storage, chain_config, 0, 0);
        let genesis = bc
            .process_genesis(u64::MAX, window_config_builder(16).content())
            .ok()
            .expect("genesis succeeds");
        (bc, genesis.block_one)
    };
    let (mut bc, b1) = build();
    let (replica, _) = build();
    // A self-transfer pays its fee of 1 back to node #0, the creator,
    // whose balance is then `u64::MAX - 1`; `mined_amount = 2` overflows.
    let nt = transfer_tx(2, 0, 1);
    let block = tx_block(2, b1.view().hash(), 2, |b| {
        b.add_node_transfer(&nt).ok().expect("transfer");
    });
    assert_eq!(
        step_reason(&mut bc, &block),
        Some(ValidationReason::BalanceOverflow)
    );
    assert_same_state(&bc, &replica, "overflow refusal");
}

/// DEC-138 — the vote apply runs before `chain_heads` learns of a direct
/// extension. A local refusal there (no vote parameters) keeps the block,
/// written and Stored, tracked as a head, with the derivation inverted.
#[test]
fn local_vote_refusal_after_the_write_keeps_the_extension_stored() {
    let (mut bc, _, b1) = ready_genesis(16);
    let (replica, _, _) = ready_genesis(16);
    // An engine that holds no FR37 parameters (the test oracle's state).
    bc.vote_engine = VoteEngine::new();
    let a = transfer(2, b1.view().hash(), 0, 7);
    assert_eq!(receive(&mut bc, &a), ReceiveBlockOutcome::AcceptedSilently);
    let ai = bc.blocks.find(2, &a.view().hash()).expect("stored");
    assert_eq!(
        bc.blocks.get(ai).map(|e| e.status()),
        Some(BlockStatus::Stored)
    );
    assert_eq!(head_of(&bc).0, 1, "the head did not move");
    assert!(
        bc.chain_heads.occupied_heads().any(|(h, _)| h == ai),
        "tracked as a head"
    );
    assert!(
        bc.node_info == replica.node_info,
        "the derivation was inverted"
    );
}

// ===================================================================
// Story 6.1 — FR21 branch value and side-block Tier 2
// ===================================================================

// ===================================================================
// Story 6.2 — real vote headers for active-chain fixtures (I-09)
// ===================================================================

/// AC10.1 / AC3 — seeding at every Ready entry: the genesis node holds 0
/// (its block #1 carries no value), a genesis-anchored mesh join sums
/// `(#0, #1]`, a window-anchored FR3 join sums its window — each equal to
/// the brute force.
#[test]
fn branch_value_is_seeded_at_every_ready_entry() {
    let (genesis, _, _) = ready_genesis(16);
    assert_eq!(genesis.active_branch_value, 0);
    assert_eq!(
        genesis.active_branch_value,
        brute_value(&genesis, genesis.active_chain_head_idx)
    );
    // A genesis-anchored mesh join over #0..#3, orphans first: #1 and #2
    // are node #0's (worth 0), #3 node #1's after 3 credits (real values,
    // I-09).
    let (_, b0, b1) = ready_genesis(16);
    let a2 = alt(2, b1.view().hash(), 0, 0, 3, 7, true);
    let a3 = alt(3, a2.view().hash(), 1, 3, 0, 8, false);
    let mut mesh = new_unconfigured_test_chain();
    for blk in [&a3, &a2, &b1, &b0] {
        assert_eq!(
            receive(&mut mesh, blk),
            ReceiveBlockOutcome::AcceptedSilently
        );
    }
    assert!(mesh.is_ready());
    assert_eq!(head_of(&mesh), (3, a3.view().hash()));
    assert_eq!(v(&a3), 3015);
    assert_eq!(
        mesh.active_branch_value,
        v(&b1) + v(&a2) + v(&a3),
        "#1..#3 count, #0 is S_tail"
    );
    assert_eq!(
        mesh.active_branch_value,
        brute_value(&mesh, mesh.active_chain_head_idx)
    );
    let (w6, _) = valued_w6();
    assert_eq!(
        w6.active_branch_value,
        3 + 5 + 7 + 11 + 13,
        "the anchor is S_tail"
    );
    assert_eq!(
        w6.active_branch_value,
        brute_value(&w6, w6.active_chain_head_idx)
    );
}

/// AC10.3 / AC5 / AC9; Story 6.14 — a tail advance subtracts the block
/// that becomes `S_tail`, from the active value and from a side head forked
/// above it (with `H = 3` a fork at #103 stays inside FR58's bound after the
/// advance); a fresh node reaching Ready through FR3 over the same blocks
/// holds the same values. The horizon below the tail is never summed.
#[test]
fn tail_advance_subtracts_the_new_tail_everywhere() {
    let (mut a, [anchor, b101, b102, b103, b104, b105]) = valued_w6();
    // A fork at #103, judged before its write (D4) and valued by the walk;
    // worth less than the active branch, so no switch is attempted. #104
    // is a clean slot (Story 6.7 D8): the side block is a transfer.
    let side = revalue(&salted_linked_block(104, b103.view().hash(), 6), 1);
    assert_eq!(
        a.receive_block(side.view(), 0).0,
        ReceiveBlockOutcome::AcceptedSilently
    );
    let si = slot(&a, &side);
    assert_eq!(
        a.blocks.get(si).map(|e| e.status()),
        Some(BlockStatus::Connected)
    );
    assert_eq!(a.chain_heads.branch_value_of(si), Some(3 + 5 + 7 + 1));
    assert_eq!(a.chain_heads.branch_value_of(si), Some(brute_value(&a, si)));

    // Dropping the chain-config anchor needs a chain-config extension.
    let b106 = real_on(&a, &w6_config_anchor_block(106, b105.view().hash()), 0, 1);
    extend_active_head(&mut a, &b106, 0);
    assert_eq!(a.active_snake_chain_window(), Ok((101, 106)));
    assert_eq!(
        a.active_branch_value,
        5 + 7 + 11 + 13 + v(&b106),
        "#101 left the sum, #100 never was in it"
    );
    assert_eq!(
        a.active_branch_value,
        brute_value(&a, a.active_chain_head_idx)
    );
    assert_eq!(a.chain_heads.branch_value_of(si), Some(5 + 7 + 1));
    assert_eq!(a.chain_heads.branch_value_of(si), Some(brute_value(&a, si)));

    // A fresh node, orphans first, reaches the same values through FR3 on
    // `98..=106` — `W + H` long, so #97 is not needed.
    let [_, b98, b99] = w6_below();
    let mut b = new_w6_chain();
    for blk in [
        &side, &b106, &b105, &b104, &b103, &b102, &b101, &anchor, &b99, &b98,
    ] {
        assert_eq!(
            b.receive_block(blk.view(), 0).0,
            ReceiveBlockOutcome::AcceptedSilently
        );
    }
    assert!(b.is_ready());
    assert_eq!(b.active_snake_chain_window(), Ok((101, 106)));
    assert_eq!(b.active_branch_value, a.active_branch_value);
    let bs = slot(&b, &side);
    assert_eq!(
        b.blocks.get(bs).map(|e| e.status()),
        Some(BlockStatus::Connected)
    );
    assert_eq!(b.chain_heads.branch_value_of(bs), Some(5 + 7 + 1));
    // Story 6.4 AC9 3c: built at a window-anchored ready entry.
    assert_active_set_matches(&b, "window-anchored entry");
}

/// AC10.3 / AC5 — the new tail's value is read before anything changes: a
/// failed read is a local failure, and the next admission extends.
#[test]
fn failed_new_tail_read_is_a_local_failure() {
    // `W = 6`: the window fills at #5. The clean slots #2 and #5 (Story
    // 6.7 D8) hold node #0's transfers; node #1 registers at #3 and
    // creates #4.
    let (mut bc, b1) = faulty_genesis(W6);
    let b2 = real_on(
        &bc,
        &tx_block(2, b1.view().hash(), 0, votes_for(2, 0, 1, 6)),
        0,
        1,
    );
    assert_eq!(receive(&mut bc, &b2), ReceiveBlockOutcome::AcceptedSilently);
    let b3 = alt(3, b2.view().hash(), 0, 0, 2, 7, true);
    let b4 = alt(4, b3.view().hash(), 1, 2, 0, 8, false);
    for blk in [&b3, &b4] {
        assert_eq!(receive(&mut bc, blk), ReceiveBlockOutcome::AcceptedSilently);
    }
    let b5 = real_on(
        &bc,
        &tx_block(5, b4.view().hash(), 0, votes_for(5, 0, 1, 9)),
        0,
        1,
    );
    assert_eq!(receive(&mut bc, &b5), ReceiveBlockOutcome::AcceptedSilently);
    let before = bc.active_branch_value;
    let snapshot = snapshot_block(&bc, 6, b5.view().hash());
    bc.storage.failing_read_slot = 1; // #1 becomes the tail
    assert_eq!(
        receive(&mut bc, &snapshot),
        ReceiveBlockOutcome::AcceptedSilently
    );
    assert_eq!(head_of(&bc), (5, b5.view().hash()), "not extended");
    assert_eq!(status_of(&bc, &snapshot), Some(BlockStatus::Stored));
    assert_eq!(bc.active_branch_value, before);
    assert_eq!(bc.active_snake_chain_window(), Ok((0, 5)));

    bc.storage.failing_read_slot = NONE_REF;
    let unrelated = node_transfer_block(3, 3, 2, 7);
    assert_eq!(
        receive(&mut bc, &unrelated),
        ReceiveBlockOutcome::AcceptedSilently
    );
    assert_eq!(
        head_of(&bc),
        (6, snapshot.view().hash()),
        "the retry extended"
    );
    assert_eq!(bc.active_snake_chain_window(), Ok((1, 6)));
    assert_eq!(v(&b4), 2010);
    assert_eq!(
        bc.active_branch_value,
        v(&b2) + v(&b3) + v(&b4) + v(&b5) + v(&snapshot)
    );
    assert_eq!(
        bc.active_branch_value,
        brute_value(&bc, bc.active_chain_head_idx)
    );
}

/// AC10.2 / AC4 — event (i) for both entry points: a direct extension, and
/// a continuation over a stored orphan.
#[test]
fn branch_value_follows_direct_and_continuation_extensions() {
    let (mut bc, _, b1) = ready_genesis(16);
    let b2 = alt(2, b1.view().hash(), 0, 0, 5, 7, true);
    assert_eq!(receive(&mut bc, &b2), ReceiveBlockOutcome::AcceptedSilently);
    assert_eq!(bc.active_branch_value, v(&b2));
    let b3 = alt(3, b2.view().hash(), 1, 5, 3, 8, false);
    let b4 = alt(4, b3.view().hash(), 0, 3, 7, 9, false);
    assert_eq!(receive(&mut bc, &b4), ReceiveBlockOutcome::AcceptedSilently);
    assert_eq!(receive(&mut bc, &b3), ReceiveBlockOutcome::AcceptedSilently);
    assert_eq!(head_of(&bc), (4, b4.view().hash()));
    assert_eq!((v(&b3), v(&b4)), (5025, 3015), "distinct real values");
    assert_eq!(bc.active_branch_value, v(&b2) + v(&b3) + v(&b4));
    assert_eq!(
        bc.active_branch_value,
        brute_value(&bc, bc.active_chain_head_idx)
    );
}

/// Two siblings of `parent` (node #0's, which gave node #1 `credits`) at
/// `seq`: node #1's, worth its real `I(1000 · credits)`, and node #0's side
/// block with the free value `low`, where the higher-valued one has the
/// higher hash — so the hash alone would pick the other. Returns
/// `(high, low)`.
fn ranked_pair(seq: u32, parent: [u8; 32], credits: u32, low: u32) -> (Block, Block) {
    for amount in 10..200 {
        let h = alt(seq, parent, 1, credits, 0, amount, false);
        let l = valued(seq, parent, low, amount + 1000);
        if h.view().hash() > l.view().hash() {
            return (h, l);
        }
    }
    panic!("no pair found");
}

/// AC10.6 / AC8 — the continuation's sibling choice is the FR21 rank: the
/// higher value wins over a lower hash, and on an equal value the larger
/// block wins. The other sibling becomes a Connected side head.
#[test]
fn sibling_choice_follows_the_fr21_rank() {
    let (mut bc, _, b1) = ready_genesis(16);
    let parent = alt(2, b1.view().hash(), 0, 0, 9, 7, true);
    let (high, low) = ranked_pair(3, parent.view().hash(), 9, 4);
    for blk in [&low, &high, &parent] {
        assert_eq!(receive(&mut bc, blk), ReceiveBlockOutcome::AcceptedSilently);
    }
    assert_eq!(head_of(&bc), (3, high.view().hash()), "value before hash");
    let li = slot(&bc, &low);
    assert_eq!(status_of(&bc, &low), Some(BlockStatus::Connected));
    assert_eq!(bc.chain_heads.branch_value_of(li), Some(v(&parent) + 4));
    assert_eq!(
        bc.chain_heads.branch_value_of(li),
        Some(brute_value(&bc, li))
    );

    // Equal value: the larger block wins, even with the higher hash.
    // `large` is node #1's real block (two transactions); `small` a side
    // block with the same free value.
    let (mut bc, _, b1) = ready_genesis(16);
    let parent = alt(2, b1.view().hash(), 0, 0, 6, 7, true);
    let prev = parent.view().hash();
    let (large, small) = (0..200)
        .find_map(|amount| {
            let large = resign(
                &tx_block(3, prev, 0, |b| {
                    votes_for(3, 1, 2, amount)(b);
                }),
                1,
                vote_snapshot(6000),
                NODE_ONE_KEY,
            );
            let small = valued(3, prev, vote_snapshot(6000), amount + 1000);
            (large.view().hash() > small.view().hash()).then_some((large, small))
        })
        .expect("a pair");
    for blk in [&small, &large, &parent] {
        assert_eq!(receive(&mut bc, blk), ReceiveBlockOutcome::AcceptedSilently);
    }
    assert_eq!(head_of(&bc), (3, large.view().hash()), "size before hash");
    // Chosen by rank, not left over by a Tier 3 refusal of `small`.
    assert_eq!(status_of(&bc, &small), Some(BlockStatus::Connected));
    assert_eq!(
        bc.chain_heads.branch_value_of(slot(&bc, &small)),
        Some(v(&parent) + v(&small))
    );
}

/// AC8 (code review 2026-10-20) — an unreadable sibling is a local
/// failure, never a choice: the continuation stops with both siblings
/// Stored, and ranks them once the fault clears.
#[test]
fn unreadable_sibling_stops_the_continuation() {
    let (mut bc, b1) = faulty_genesis(16);
    let parent = alt(2, b1.view().hash(), 0, 0, 9, 7, true);
    let (high, low) = ranked_pair(3, parent.view().hash(), 9, 4);
    for blk in [&low, &high] {
        assert_eq!(receive(&mut bc, blk), ReceiveBlockOutcome::AcceptedSilently);
    }
    bc.storage.failing_read_slot = slot(&bc, &high);
    assert_eq!(
        receive(&mut bc, &parent),
        ReceiveBlockOutcome::AcceptedSilently
    );
    assert_eq!(
        head_of(&bc),
        (2, parent.view().hash()),
        "the continuation stopped"
    );
    assert_eq!(status_of(&bc, &high), Some(BlockStatus::Stored));
    assert_eq!(
        status_of(&bc, &low),
        Some(BlockStatus::Stored),
        "not taken instead"
    );

    bc.storage.failing_read_slot = NONE_REF;
    let unrelated = node_transfer_block(9, 3, 8, 7);
    assert_eq!(
        receive(&mut bc, &unrelated),
        ReceiveBlockOutcome::AcceptedSilently
    );
    assert_eq!(
        head_of(&bc),
        (3, high.view().hash()),
        "ranked after the fault"
    );
    let li = slot(&bc, &low);
    assert_eq!(status_of(&bc, &low), Some(BlockStatus::Connected));
    assert_eq!(
        bc.chain_heads.branch_value_of(li),
        Some(brute_value(&bc, li))
    );
}

/// AC10.4 / AC10.12 / D4 — side blocks with a Connected or Active parent
/// are judged before their write: a fork from an older active block, the
/// extension of a Connected side head (incremental, no read of it), and a
/// fork from an interior Connected block — each Connected and valued as
/// the brute force; the active value is untouched.
#[test]
fn side_blocks_are_judged_before_their_write_and_valued() {
    let (mut bc, b1) = faulty_genesis(16);
    let a2 = alt(2, b1.view().hash(), 0, 0, 2, 7, true);
    let a3 = alt(3, a2.view().hash(), 1, 2, 0, 8, false);
    for blk in [&a2, &a3] {
        assert_eq!(receive(&mut bc, blk), ReceiveBlockOutcome::AcceptedSilently);
    }
    let active = bc.active_branch_value;
    assert_eq!(active, v(&a2) + v(&a3));

    let f3 = valued(3, a2.view().hash(), 9, 20);
    assert_eq!(receive(&mut bc, &f3), ReceiveBlockOutcome::AcceptedSilently);
    let fi = slot(&bc, &f3);
    assert_eq!(status_of(&bc, &f3), Some(BlockStatus::Connected));
    assert_eq!(bc.chain_heads.branch_value_of(fi), Some(v(&a2) + 9));
    assert_eq!(
        bc.chain_heads.branch_value_of(fi),
        Some(brute_value(&bc, fi))
    );

    // The extension reads nothing of itself: its slot's reads fail.
    let f4 = valued(4, f3.view().hash(), 4, 21);
    bc.storage.failing_read_slot = bc.blocks.next_free_index().expect("a slot");
    assert_eq!(receive(&mut bc, &f4), ReceiveBlockOutcome::AcceptedSilently);
    bc.storage.failing_read_slot = NONE_REF;
    let f4i = slot(&bc, &f4);
    assert_eq!(status_of(&bc, &f4), Some(BlockStatus::Connected));
    assert_eq!(bc.chain_heads.branch_value_of(f4i), Some(v(&a2) + 9 + 4));
    assert_eq!(
        bc.chain_heads.branch_value_of(f4i),
        Some(brute_value(&bc, f4i))
    );

    // f3 is interior now: a second child of it is a fork, walked.
    let g4 = valued(4, f3.view().hash(), 6, 22);
    assert_eq!(receive(&mut bc, &g4), ReceiveBlockOutcome::AcceptedSilently);
    let gi = slot(&bc, &g4);
    assert_eq!(status_of(&bc, &g4), Some(BlockStatus::Connected));
    assert_eq!(bc.chain_heads.branch_value_of(gi), Some(v(&a2) + 9 + 6));
    assert_eq!(
        bc.chain_heads.branch_value_of(gi),
        Some(brute_value(&bc, gi))
    );
    assert_eq!(
        bc.active_branch_value, active,
        "side blocks leave the active value"
    );
    assert_eq!(head_of(&bc), (3, a3.view().hash()));
}

/// AC10.7 / AC10.12 — a side block failing Tier 2 at intake is refused and
/// nothing is stored: a declared amount other than the output's, an output
/// index beyond the referenced block's outputs, and a fork from an interior
/// Connected block.
#[test]
fn side_block_failing_tier2_at_intake_is_not_stored() {
    for (index, amount) in [(0, 61), (5, 60)] {
        let (mut bc, mint, _) = utxo_side_fixture();
        let (replica, _, _) = utxo_side_fixture();
        let bad = side_spend(4, mint.view().hash(), index, amount);
        let free = bc.blocks.next_free_index().expect("a free slot");
        assert_eq!(
            receive(&mut bc, &bad),
            ReceiveBlockOutcome::Rejected(RejectReason::InvalidEvidence)
        );
        assert_same_state(&bc, &replica, "refused side block");
        assert_eq!(bc.blocks.next_free_index(), Some(free), "no slot used");
        assert!(same_slot(&bc, &replica, free), "storage unchanged");
    }

    // A fork from an interior Connected block is refused the same way.
    let (mut bc, mint, _) = utxo_side_fixture();
    let p4 = valued(4, mint.view().hash(), 4, 30);
    let p5 = valued(5, p4.view().hash(), 5, 31);
    for blk in [&p4, &p5] {
        assert_eq!(receive(&mut bc, blk), ReceiveBlockOutcome::AcceptedSilently);
    }
    let free = bc.blocks.next_free_index().expect("a free slot");
    let bad = side_spend(5, p4.view().hash(), 0, 61);
    assert_eq!(
        receive(&mut bc, &bad),
        ReceiveBlockOutcome::Rejected(RejectReason::InvalidEvidence)
    );
    assert_eq!(bc.blocks.next_free_index(), Some(free), "no slot used");

    // The matching amount passes: Connected, no bit touched.
    let (mut bc, mint, _) = utxo_side_fixture();
    let good = side_spend(4, mint.view().hash(), 0, 60);
    assert_eq!(
        receive(&mut bc, &good),
        ReceiveBlockOutcome::AcceptedSilently
    );
    assert_eq!(status_of(&bc, &good), Some(BlockStatus::Connected));
    assert_eq!(bc.blocks.utxo_available(slot(&bc, &mint), 0), Some(true));
}

/// AC6 / D4 — a local failure inside the pre-store Tier 2 is no evidence:
/// the block is stored Stored, and the driver connects it once the fault
/// clears.
#[test]
fn tier2_read_failure_at_intake_is_retried_by_the_driver() {
    let (mut bc, mint, _) = utxo_side_fixture();
    let good = side_spend(4, mint.view().hash(), 0, 60);
    bc.storage.failing_read_slot = slot(&bc, &mint);
    assert_eq!(
        receive(&mut bc, &good),
        ReceiveBlockOutcome::AcceptedSilently
    );
    assert_eq!(
        status_of(&bc, &good),
        Some(BlockStatus::Stored),
        "not blamed"
    );

    bc.storage.failing_read_slot = NONE_REF;
    let unrelated = node_transfer_block(9, 3, 8, 7);
    assert_eq!(
        receive(&mut bc, &unrelated),
        ReceiveBlockOutcome::AcceptedSilently
    );
    let gi = slot(&bc, &good);
    assert_eq!(status_of(&bc, &good), Some(BlockStatus::Connected));
    assert_eq!(
        bc.chain_heads.branch_value_of(gi),
        Some(brute_value(&bc, gi))
    );
}

/// AC10.5 / AC10.7 / D8 — an orphan side chain stored before its Tier 2
/// could run: its parent's arrival connects it, the driver finds the
/// failing block, deletes it with its descendants, and values the entry
/// retargeted onto the surviving Connected parent. The active state is
/// untouched and the node stays Ready. Each failure kind: a declared amount
/// other than the output's, an output index beyond it, a reference more
/// than `W` back.
#[test]
fn driver_deletes_a_failing_side_block_and_values_the_retarget() {
    for (index, amount) in [(0, 61), (5, 60)] {
        let (mut bc, mint, _) = utxo_side_fixture();
        let (replica, _, _) = utxo_side_fixture();
        let p4 = valued(4, mint.view().hash(), 4, 30);
        let bad5 = revalue(&side_spend(5, p4.view().hash(), index, amount), 5);
        let c6 = valued(6, bad5.view().hash(), 6, 31);
        for blk in [&c6, &bad5, &p4] {
            assert_eq!(receive(&mut bc, blk), ReceiveBlockOutcome::AcceptedSilently);
        }
        assert_eq!(status_of(&bc, &bad5), None, "deleted");
        assert_eq!(status_of(&bc, &c6), None, "with its descendant");
        let pi = slot(&bc, &p4);
        assert_eq!(status_of(&bc, &p4), Some(BlockStatus::Connected));
        assert_eq!(
            bc.chain_heads.branch_value_of(pi),
            Some(brute_value(&bc, pi))
        );
        assert!(bc.is_ready());
        assert!(bc.node_info == replica.node_info);
        assert!(bc.vote_engine == replica.vote_engine);
        assert_eq!(bc.active_branch_value, replica.active_branch_value);
        for bit in 0..2 {
            assert_eq!(
                bc.blocks.utxo_available(slot(&bc, &mint), bit),
                replica.blocks.utxo_available(slot(&replica, &mint), bit),
                "active available-UTXO bits untouched"
            );
        }
    }

    // A reference more than `W` back, on the W6 window. The side branch
    // forks inside FR58's bound (`A = S_head − H`, DEC-208) and is worth
    // less than the active branch, so no switch is attempted. `far` sits
    // off the clean slots (Story 6.7 D8), its parent `p104` on one.
    let (mut bc, [_, _, _, b103, _, _]) = valued_w6();
    let p104 = revalue(&salted_linked_block(104, b103.view().hash(), 6), 1);
    let tx = utxo_tx(105, &[(98, 0, 50)], None, &[Ok(50)]);
    let far = complex_tx_block(105, p104.view().hash(), 0, 0, &[&tx]);
    for blk in [&far, &p104] {
        assert_eq!(
            bc.receive_block(blk.view(), 0).0,
            ReceiveBlockOutcome::AcceptedSilently
        );
    }
    assert!(
        bc.blocks.find(105, &far.view().hash()).is_none(),
        "deleted by the driver"
    );
    let pi = slot(&bc, &p104);
    assert_eq!(
        bc.blocks.get(pi).map(|e| e.status()),
        Some(BlockStatus::Connected)
    );
    assert_eq!(
        bc.chain_heads.branch_value_of(pi),
        Some(brute_value(&bc, pi))
    );

    // A valid orphan chain connects whole.
    let (mut bc, mint, _) = utxo_side_fixture();
    let p4 = valued(4, mint.view().hash(), 4, 30);
    let q5 = valued(5, p4.view().hash(), 5, 31);
    let q6 = valued(6, q5.view().hash(), 6, 32);
    for blk in [&q6, &q5, &p4] {
        assert_eq!(receive(&mut bc, blk), ReceiveBlockOutcome::AcceptedSilently);
    }
    for blk in [&p4, &q5, &q6] {
        assert_eq!(status_of(&bc, blk), Some(BlockStatus::Connected));
    }
    let qi = slot(&bc, &q6);
    assert_eq!(
        bc.chain_heads.branch_value_of(qi),
        Some(brute_value(&bc, qi))
    );
}

/// AC10.8 / D6; Story 6.14 AC4 — a side block's UTXO reference into the
/// verification horizon resolves against the retained block: it is no
/// longer trusted pre-window history, so an output the horizon block does
/// not hold is evidence. More than `W` back it is evidence too.
#[test]
fn side_reference_into_the_horizon_is_resolved() {
    let (mut bc, [_, _, b102, _, _, _]) = valued_w6();
    let tx = utxo_tx(103, &[(99, 0, 50)], None, &[Ok(50)]);
    let missing = complex_tx_block(103, b102.view().hash(), 0, 0, &[&tx]);
    assert_eq!(
        bc.receive_block(missing.view(), 0).0,
        ReceiveBlockOutcome::Rejected(RejectReason::InvalidEvidence),
        "#99 is retained and holds no output 0"
    );

    let tx = utxo_tx(103, &[(96, 0, 50)], None, &[Ok(50)]);
    let too_far = complex_tx_block(103, b102.view().hash(), 0, 0, &[&tx]);
    assert_eq!(
        bc.receive_block(too_far.view(), 0).0,
        ReceiveBlockOutcome::Rejected(RejectReason::InvalidEvidence)
    );
}

/// AC10.9 — a read failure during the side walk changes nothing; the next
/// admission connects the branch.
#[test]
fn side_walk_read_failure_is_retried() {
    let (mut bc, mint, _) = utxo_side_fixture();
    let p4 = valued(4, mint.view().hash(), 4, 30);
    let q5 = valued(5, p4.view().hash(), 5, 31);
    assert_eq!(receive(&mut bc, &q5), ReceiveBlockOutcome::AcceptedSilently);
    bc.storage.failing_read_slot = slot(&bc, &q5);
    assert_eq!(receive(&mut bc, &p4), ReceiveBlockOutcome::AcceptedSilently);
    assert_eq!(status_of(&bc, &p4), Some(BlockStatus::Connected));
    assert_eq!(
        status_of(&bc, &q5),
        Some(BlockStatus::Stored),
        "left pending"
    );

    bc.storage.failing_read_slot = NONE_REF;
    let unrelated = node_transfer_block(9, 3, 8, 7);
    assert_eq!(
        receive(&mut bc, &unrelated),
        ReceiveBlockOutcome::AcceptedSilently
    );
    let qi = slot(&bc, &q5);
    assert_eq!(status_of(&bc, &q5), Some(BlockStatus::Connected));
    assert_eq!(
        bc.chain_heads.branch_value_of(qi),
        Some(brute_value(&bc, qi))
    );
}

/// AC10.11 / AC9.3 — two admission orders of one block set hold the same
/// values and statuses; a restart rebuilds them.
#[test]
fn branch_values_are_order_independent_and_survive_a_restart() {
    let build = |order: &[usize]| {
        let (mut bc, _, b1) = ready_genesis(16);
        let a2 = alt(2, b1.view().hash(), 0, 0, 2, 7, true);
        let a3 = alt(3, a2.view().hash(), 1, 2, 3, 8, false);
        let a4 = alt(4, a3.view().hash(), 0, 3, 4, 9, false);
        let a5 = alt(5, a4.view().hash(), 1, 4, 0, 10, false);
        let f3 = valued(3, a2.view().hash(), 9, 20);
        let f4 = valued(4, f3.view().hash(), 6, 21);
        let blocks = [a2, a3, a4, a5, f3, f4];
        for &i in order {
            assert_eq!(
                receive(&mut bc, &blocks[i]),
                ReceiveBlockOutcome::AcceptedSilently
            );
        }
        (bc, blocks)
    };
    let (x, blocks) = build(&[0, 1, 2, 3, 4, 5]);
    // The side branch before the active extensions, child first.
    let (y, _) = build(&[0, 1, 5, 4, 2, 3]);
    assert_eq!(x.active_branch_value, y.active_branch_value);
    assert_eq!(
        x.active_branch_value,
        brute_value(&x, x.active_chain_head_idx)
    );
    for blk in &blocks {
        assert_eq!(status_of(&x, blk), status_of(&y, blk));
        let (xi, yi) = (slot(&x, blk), slot(&y, blk));
        if x.blocks.get(xi).map(|e| e.status()) == Some(BlockStatus::Connected) {
            assert_eq!(
                x.chain_heads.branch_value_of(xi),
                y.chain_heads.branch_value_of(yi)
            );
        }
    }
    let f4 = &blocks[5];
    let fi = slot(&x, f4);
    assert_eq!(x.chain_heads.branch_value_of(fi), Some(brute_value(&x, fi)));

    let reference_active = x.active_branch_value;
    let reference_side = x.chain_heads.branch_value_of(fi);
    let mut restarted = restart(x);
    let _ = restarted.initialize_from_storage(0);
    assert!(restarted.is_ready());
    assert_eq!(restarted.active_branch_value, reference_active);
    let ri = slot(&restarted, f4);
    assert_eq!(
        restarted.blocks.get(ri).map(|e| e.status()),
        Some(BlockStatus::Connected)
    );
    assert_eq!(restarted.chain_heads.branch_value_of(ri), reference_side);
}

// --- Story 7.1: complex-transaction input signatures (DEC-196, I-21) -----

/// AC6 — on the Ready head extension every input is verified against its own
/// key: a UTXO input against the output's address, a balance input against
/// its initializer's key. A foreign key, a signature lifted from another
/// transaction (the `vote` rewritten after signing) and a zeroed signature are
/// each refused at intake, exact evidence, nothing stored or applied.
#[test]
fn input_signatures_are_verified_on_the_ready_extension() {
    let utxo = || utxo_genesis().0;
    let (_, mint) = utxo_genesis();
    let prev = mint.view().hash();
    let refused = |cx: &moonblokz_chain_types::ComplexTransaction| {
        let block = complex_tx_block(4, prev, 0, 0, &[cx]);
        assert_refused_at_intake(utxo, &block, ValidationReason::InputSignatureInvalid);
    };

    // A UTXO input signed by a key other than the output's address.
    refused(&utxo_tx_signed(
        0,
        4,
        &[(3, 0, 60)],
        None,
        &[Err((1, 60))],
        &other_key(),
    ));
    // A balance input signed by a key other than node #0's.
    refused(&utxo_tx_signed(
        0,
        4,
        &[],
        Some((0, 10)),
        &[Err((1, 10))],
        &other_key(),
    ));

    // Valid signatures moved onto a transaction whose `vote` differs: every
    // input commits to the vote, so every one fails.
    let signed = utxo_tx(4, &[(3, 0, 60)], Some((0, 10)), &[Err((1, 70))]);
    let mut lifted = utxo_tx_vote(1, 4, &[(3, 0, 60)], Some((0, 10)), &[Err((1, 70))]);
    for (i, signature) in input_signatures(&signed).iter().enumerate() {
        lifted
            .set_input_signature(i as u8, signature.as_slice().try_into().expect("size"))
            .ok()
            .expect("input");
    }
    refused(&lifted);

    // A zeroed signature.
    let mut zeroed = utxo_tx(4, &[(3, 0, 60)], None, &[Err((1, 60))]);
    zeroed
        .set_input_signature(0, &[0u8; SIGNATURE_SIZE])
        .ok()
        .expect("input");
    refused(&zeroed);

    // The correctly signed transaction is accepted.
    let mut bc = utxo_genesis().0;
    let good = complex_tx_block(4, prev, 0, 0, &[&signed]);
    assert_eq!(
        receive(&mut bc, &good),
        ReceiveBlockOutcome::AcceptedSilently
    );
    assert_eq!(head_of(&bc).1, good.view().hash());
}

/// AC3 (DEC-332) — resolve, verify, then spend: a transaction whose UTXO input
/// verified and was spent, and whose later balance input then fails its
/// signature, leaves nothing applied — the UTXO bit set again, the balances
/// and every other projection as before.
#[test]
fn a_failed_input_signature_leaves_nothing_applied() {
    let (mut bc, mint) = utxo_genesis();
    let (replica, _) = utxo_genesis();
    let mut cx = utxo_tx(4, &[(3, 0, 60)], Some((0, 10)), &[Err((1, 70))]);
    let mut buf = [0u8; moonblokz_chain_types::MAX_TRANSACTION_SIZE];
    let len = TransactionView::from_bytes(cx.as_bytes())
        .and_then(|v| v.input_signing_preimage(&mut buf).map(|p| p.len()))
        .expect("complex");
    let foreign = other_key().sign(&buf[..len]);
    cx.set_input_signature(1, foreign.serialize())
        .ok()
        .expect("the balance input");
    let block = complex_tx_block(4, mint.view().hash(), 0, 0, &[&cx]);
    assert_eq!(
        step_reason(&mut bc, &block),
        Some(ValidationReason::InputSignatureInvalid)
    );
    let mi = bc.active_chain_head_idx;
    assert_eq!(bc.blocks.utxo_available(mi, 0), Some(true), "not spent");
    assert_same_state(&bc, &replica, "failed input signature");
}

/// DEC-334 — a block whose signatures this node has accepted (bit 6) is
/// derived again without verifying its input signatures; resolution and the
/// spend still run. With the bit clear, each input is verified once.
#[test]
fn accepted_signatures_skip_input_verification_only() {
    for (accepted, verifications) in [(true, 0), (false, 1)] {
        let (mut bc, mint) = utxo_genesis();
        let mi = bc.active_chain_head_idx;
        assert_eq!(bc.undo_active_head(), Ok(()));
        if !accepted {
            bc.blocks.clear_signatures_accepted();
        }
        let parent = *bc
            .blocks
            .get(bc.active_chain_head_idx)
            .expect("parent")
            .hash();
        let before = crate::approval::test_seams::counted(&TX_SIGNATURE_VERIFICATIONS);
        let mut projection = Projection::COMPLETE;
        bc.derive_block(&mint.view(), mi, Some(parent), &mut projection)
            .expect("the mint derives again");
        assert_eq!(
            crate::approval::test_seams::counted(&TX_SIGNATURE_VERIFICATIONS) - before,
            verifications,
            "accepted: {accepted}"
        );
    }
}

/// Review patch (Story 7.1, D5) — under the bit-6 skip the UTXO input is
/// still resolved and spent: re-deriving an accepted spend after undoing it
/// verifies nothing and clears the referenced bit again.
#[test]
fn the_bit_six_skip_still_resolves_and_spends() {
    let (mut bc, mint) = utxo_genesis();
    let mi = bc.active_chain_head_idx;
    let tx = utxo_tx(4, &[(3, 0, 60)], None, &[Err((1, 60))]);
    let spend = complex_tx_block(4, mint.view().hash(), 0, 0, &[&tx]);
    assert_eq!(
        receive(&mut bc, &spend),
        ReceiveBlockOutcome::AcceptedSilently
    );
    let si = bc.active_chain_head_idx;
    assert_eq!(bc.undo_active_head(), Ok(()));
    assert_eq!(
        bc.blocks.utxo_available(mi, 0),
        Some(true),
        "the undo restored it"
    );
    let before = crate::approval::test_seams::counted(&TX_SIGNATURE_VERIFICATIONS);
    let mut projection = Projection::COMPLETE;
    bc.derive_block(&spend.view(), si, Some(mint.view().hash()), &mut projection)
        .expect("the spend derives again");
    assert_eq!(
        crate::approval::test_seams::counted(&TX_SIGNATURE_VERIFICATIONS) - before,
        0,
        "accepted signatures are not verified again"
    );
    assert_eq!(bc.blocks.utxo_available(mi, 0), Some(false), "spent again");
}
