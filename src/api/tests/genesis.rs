//! Tests of `api/genesis.rs`.

use super::*;

/// `init`'s field writes (`blocks` / `chain_heads` filled
/// element-by-element through the nested tables' own `init`, the
/// scalars written one by one) must land every field in its correct
/// default state — a wrong field order, a skipped field, or an
/// off-by-one inside the `unsafe` block would silently corrupt memory
/// rather than panic, so this is verified directly rather than trusted
/// by construction.
///
/// The destructuring is deliberately exhaustive (no `..`): adding a field
/// to `Blockchain` makes this test fail to *compile* until the new field
/// is both initialized in `init` and asserted here — the one obligation
/// the safe signature cannot enforce, pinned at compile time instead of
/// by a reviewer's eye. Never compare two nodes byte-for-byte for this
/// purpose: padding bytes are uninitialized, and Miri rejects reading them.
#[test]
fn init_sets_expected_defaults() {
    let (crypto, storage, chain_config) = construction_backends();
    let mut bc_slot =
        core::mem::MaybeUninit::<Blockchain<_, _, _, 16, 16, TEST_MAX_BLOCKS, 4, 16>>::uninit();
    let bc = Blockchain::<_, _, _, 16, 16, TEST_MAX_BLOCKS, 4, 16>::init(
        &mut bc_slot,
        crypto,
        storage,
        chain_config,
        7,
        [3u8; PUBLIC_KEY_SIZE],
        0xDEAD_BEEF,
    );

    let Blockchain {
        crypto: _,       // moved in as given; opaque backend
        storage: _,      // moved in as given; opaque backend
        chain_config: _, // moved in as given
        local_node_id,
        node_zero_public_key,
        prng: _, // seeded from `prng_seed`; its state is opaque by design
        lifecycle_phase,
        restart_refused,
        blocks,
        chain_heads,
        node_info,
        vote_engine,
        last_parent_request_emit_timestamp,
        active_chain_head_idx,
        tentative_config_block_idx,
        snake_chain_tail_idx,
        active_branch_value,
        active_set,
        non_conflict,
        support_dedupe,
        approval,
        active_open_run,
        reentry_due,
    } = &*bc;

    assert_eq!(*local_node_id, 7);
    assert!(*lifecycle_phase == LifecyclePhase::Collecting);
    assert!(
        !*restart_refused,
        "a freshly constructed node has refused nothing"
    );
    assert_eq!(*node_zero_public_key, [3u8; PUBLIC_KEY_SIZE]);
    assert_eq!(blocks.len(), 0);
    // Story 4.4: the `chain_heads` table + scheduler state must init to
    // their empty/sentinel values too (`ChainHeadsTable::init` writes
    // every entry element-by-element).
    assert_eq!(chain_heads.count(), 0);
    assert_eq!(node_info.max_known_node_id(), 0);
    assert!(!node_info.is_seeded(0));
    // All-zero vote order is headed by node 0 (bootstrap rule).
    assert_eq!(vote_engine.top_creator(), Some(0));
    assert_eq!(*last_parent_request_emit_timestamp, 0);
    assert_eq!(*active_chain_head_idx, NONE_REF);
    assert_eq!(*tentative_config_block_idx, NONE_REF);
    assert_eq!(*snake_chain_tail_idx, NONE_REF);
    assert_eq!(*active_branch_value, 0);
    // Story 6.4: no window yet, so no active set; an empty ring, `F = 0`.
    assert!(!active_set.is_valid());
    assert!((0..16).all(|node| active_set.count(node) == 0));
    assert!(*non_conflict == NonConflictRing::new());
    assert_eq!(non_conflict.floor(), 0);
    // Story 6.5: an empty relay-dedupe cache.
    assert!(
        *support_dedupe
            == SupportDedupe::new(Prng::new(0xDEAD_BEEF).derive_subseed(DEDUPE_SALT_LABEL))
    );
    // Story 6.6: no accumulator.
    assert!(approval.deviation().is_none());
    assert!(*approval == ApprovalAccumulator::new());
    // Story 6.7: no open deviation run.
    assert_eq!(*active_open_run, NO_OPEN_RUN);
    assert!(!*reentry_due);
    assert_eq!(bc.local_node_id(), 7);
}

/// `init` must produce exactly what the by-value specification `new()`
/// produces. Both sides are destructured exhaustively (no `..`): adding a
/// field to `Blockchain` is a compile error in `new()`'s literal *and*
/// here until it is initialized and compared. The opaque backends
/// (`crypto`, `storage`, `chain_config`) are moved in as given on both
/// sides and carry no `PartialEq`; every field this crate writes is
/// compared. Never compare the two byte-for-byte: padding is
/// uninitialized, and Miri rejects reading it.
#[test]
fn init_is_equivalent_to_new() {
    let (crypto, storage, chain_config) = construction_backends();
    let mut slot =
        core::mem::MaybeUninit::<Blockchain<_, _, _, 16, 16, TEST_MAX_BLOCKS, 4, 16>>::uninit();
    let built = Blockchain::<_, _, _, 16, 16, TEST_MAX_BLOCKS, 4, 16>::init(
        &mut slot,
        crypto,
        storage,
        chain_config,
        7,
        [3u8; PUBLIC_KEY_SIZE],
        0xDEAD_BEEF,
    );
    let (crypto, storage, chain_config) = construction_backends();
    let spec = Blockchain::<_, _, _, 16, 16, TEST_MAX_BLOCKS, 4, 16>::new(
        crypto,
        storage,
        chain_config,
        7,
        [3u8; PUBLIC_KEY_SIZE],
        0xDEAD_BEEF,
    );

    let Blockchain {
        crypto: _,
        storage: _,
        chain_config: _,
        local_node_id,
        node_zero_public_key,
        prng,
        lifecycle_phase,
        restart_refused,
        blocks,
        chain_heads,
        node_info,
        vote_engine,
        last_parent_request_emit_timestamp,
        active_chain_head_idx,
        tentative_config_block_idx,
        snake_chain_tail_idx,
        active_branch_value,
        active_set,
        non_conflict,
        support_dedupe,
        approval,
        active_open_run,
        reentry_due,
    } = &*built;
    let Blockchain {
        crypto: _,
        storage: _,
        chain_config: _,
        local_node_id: spec_local_node_id,
        node_zero_public_key: spec_node_zero_public_key,
        prng: spec_prng,
        lifecycle_phase: spec_lifecycle_phase,
        restart_refused: spec_restart_refused,
        blocks: spec_blocks,
        chain_heads: spec_chain_heads,
        node_info: spec_node_info,
        vote_engine: spec_vote_engine,
        last_parent_request_emit_timestamp: spec_last_parent_request_emit_timestamp,
        active_chain_head_idx: spec_active_chain_head_idx,
        tentative_config_block_idx: spec_tentative_config_block_idx,
        snake_chain_tail_idx: spec_snake_chain_tail_idx,
        active_branch_value: spec_active_branch_value,
        active_set: spec_active_set,
        non_conflict: spec_non_conflict,
        support_dedupe: spec_support_dedupe,
        approval: spec_approval,
        active_open_run: spec_active_open_run,
        reentry_due: spec_reentry_due,
    } = &spec;

    assert_eq!(local_node_id, spec_local_node_id);
    assert_eq!(node_zero_public_key, spec_node_zero_public_key);
    assert!(prng == spec_prng);
    assert!(lifecycle_phase == spec_lifecycle_phase);
    assert!(restart_refused == spec_restart_refused);
    assert!(blocks == spec_blocks);
    assert!(chain_heads == spec_chain_heads);
    assert!(node_info == spec_node_info);
    assert!(vote_engine == spec_vote_engine);
    assert_eq!(
        last_parent_request_emit_timestamp,
        spec_last_parent_request_emit_timestamp
    );
    assert_eq!(active_chain_head_idx, spec_active_chain_head_idx);
    assert_eq!(tentative_config_block_idx, spec_tentative_config_block_idx);
    assert_eq!(snake_chain_tail_idx, spec_snake_chain_tail_idx);
    assert_eq!(active_branch_value, spec_active_branch_value);
    assert!(active_set == spec_active_set);
    assert!(non_conflict == spec_non_conflict);
    assert!(support_dedupe == spec_support_dedupe);
    assert!(approval == spec_approval);
    assert_eq!(active_open_run, spec_active_open_run);
    assert_eq!(reentry_due, spec_reentry_due);
}

/// AC1, AC4, AC5 — successful genesis bootstrap on `local_node_id == 0`
/// yields **both** Block #0 and Block #1 in a single `process_genesis`
/// call (no `NextCall`), with no embassy deps anywhere in the harness.
#[test]
fn walking_skeleton_genesis_success() {
    let (crypto, storage, chain_config) = test_backends();
    let expected_node_zero_public_key = *crypto.public_key().serialize();
    let initial_chain_config_bytes = OTHER_CONFIG_CONTENT;

    let mut bc = new_chain(crypto, storage, chain_config, 0, 0xDEAD_BEEF_CAFE_F00D);
    let GenesisBlocks {
        block_zero,
        block_one,
    } = bc
        .process_genesis(1_000_000_000, &initial_chain_config_bytes)
        .ok()
        .expect("genesis with local_node_id == 0 must succeed (FR54)");

    // --- Block #0: registration + self-transfer ---
    assert_eq!(block_zero.sequence(), 0);
    assert_eq!(block_zero.creator(), 0);
    assert_eq!(block_zero.version(), 1);
    assert_eq!(block_zero.payload_type(), PAYLOAD_TYPE_TRANSACTION);
    assert!(
        any_nonzero(block_zero.signature()),
        "Block #0 must be signed"
    );
    let mut transactions = block_zero
        .transactions()
        .expect("genesis Block #0 should contain transaction payload")
        .iter();
    let registration = transactions
        .next()
        .expect("first genesis transaction should register node #0")
        .as_registration()
        .expect("first genesis transaction should be Registration");
    assert_eq!(
        registration.new_public_key(),
        &expected_node_zero_public_key
    );
    assert!(any_nonzero(registration.new_key_signature()));
    assert!(any_nonzero(registration.signature()));
    let self_transfer = transactions
        .next()
        .expect("second genesis transaction should seed node #0 balance")
        .as_node_transfer()
        .expect("second genesis transaction should be NodeTransfer");
    assert!(any_nonzero(self_transfer.signature()));
    assert!(transactions.next().is_none());

    // --- Block #1: chain-config, chained to Block #0 ---
    assert_eq!(block_one.sequence(), 1);
    assert_eq!(block_one.version(), 1);
    assert_eq!(block_one.payload_type(), PAYLOAD_TYPE_CHAIN_CONFIG);
    assert_eq!(
        block_one.previous_hash(),
        &block_zero.hash()[..],
        "Block #1 must chain to Block #0"
    );
    let block_one_config = block_one
        .view()
        .chain_config()
        .expect("Block #1 must frame a chain-config envelope");
    assert_eq!(
        block_one_config.content(),
        &initial_chain_config_bytes[..],
        "Block #1 carries the initial chain-config content verbatim"
    );
    assert!(
        bc.crypto.verify_signature(
            &initial_chain_config_bytes[..],
            &Signature::new(block_one_config.content_signature())
                .ok()
                .expect("the trailer is a well-formed signature"),
            bc.crypto.public_key(),
        ),
        "FR54: node #0 signs Block #1's content region"
    );
    assert!(
        any_nonzero(block_one.signature()),
        "Block #1 must be signed"
    );

    assert_eq!(
        bc.chain_config.durable_content(),
        Some(&initial_chain_config_bytes[..]),
        "FR54: genesis leaves the configuration durably locked on its content"
    );
    // Node #0 authored the whole chain — it is immediately Ready.
    assert!(bc.current_phase() == LifecyclePhase::Ready);
    assert_eq!(bc.local_node_id(), 0);

    // Both genesis blocks are mirrored into the in-memory tree (in sync with
    // storage), forming the active chain with Block #1 as the tip.
    assert_eq!(bc.blocks.len(), 2);
    assert_eq!(bc.active_chain_head_idx, 1, "Block #1 is the active tip");
    let head_0 = bc.blocks.get(0).expect("Block #0 in tree");
    let head_1 = bc.blocks.get(1).expect("Block #1 in tree");
    assert!(head_0.is_on_active_chain());
    assert!(head_1.is_on_active_chain());
    assert_eq!(head_1.sequence(), 1);
    assert_eq!(head_1.parent_ref(), 0, "Block #1 parent is Block #0's slot");
    assert_eq!(bc.chain_heads.count(), 1, "one active head after genesis");
}

/// The single genesis head is **Connected** (on the active chain), not a
/// Stored tail-point — so there is nothing to parent-recover: `on_tick`
/// stays `Idle` and no `SendParentRecoveryRequest` is emitted for the
/// self-authored chain. Guards against a misclassified genesis head.
#[test]
fn genesis_head_is_connected_no_parent_recovery() {
    let (crypto, storage, chain_config) = test_backends();
    let mut bc = new_chain(crypto, storage, chain_config, 0, 0);
    bc.process_genesis(1_000_000_000, &BASE_CONFIG_CONTENT)
        .ok()
        .expect("genesis must succeed");

    assert!(
        !bc.chain_heads.has_stored_head(),
        "the genesis head must be Connected, not a Stored tail-point"
    );
    let (outcome, _next) = bc.on_tick(1_000_000);
    assert!(
        matches!(outcome, TickOutcome::Idle),
        "a complete genesis chain schedules no parent-recovery"
    );
}

/// AC2 — `local_node_id != 0` refuses genesis and leaves the chain empty.
/// The `Err(_)` arm is forward-compat for the additional
/// `GenesisRejectReason` variants Story 5.6+ introduces.
#[allow(unreachable_patterns)]
#[test]
fn walking_skeleton_refuses_non_zero_local_node_id() {
    let (crypto, storage, chain_config) = test_backends();
    let mut bc = new_chain(crypto, storage, chain_config, 1, 0);

    let outcome = bc.process_genesis(1_000_000_000, &[]);

    match outcome {
        Err(GenesisRejectReason::LocalNodeIdNotZero) => {}
        Err(_) => panic!("expected LocalNodeIdNotZero refusal"),
        Ok(_) => panic!("FR54 precondition must refuse local_node_id != 0"),
    }
    // Nothing was loaded on the refusal path.
    assert!(!bc.chain_config.is_durable_locked());
}

/// Genesis content whose signature trailer would push the payload past
/// `MAX_PAYLOAD_SIZE` is refused before anything is written.
#[test]
fn walking_skeleton_rejects_oversized_initial_chain_config() {
    let (crypto, storage, chain_config) = test_backends();
    let oversized = [0u8; MAX_PAYLOAD_SIZE - SIGNATURE_SIZE + 1];
    let mut bc = new_chain(crypto, storage, chain_config, 0, 0);

    let outcome = bc.process_genesis(1_000_000_000, &oversized);

    match outcome {
        Err(GenesisRejectReason::InitialChainConfigTooLarge) => {}
        Err(_) => panic!("expected InitialChainConfigTooLarge refusal"),
        Ok(_) => panic!("oversized initial chain-config bytes must be refused"),
    }
}

/// A node whose configuration is already durably locked has been
/// bootstrapped, so genesis is refused before it can overwrite the lock
/// (`StorageNotEmpty`). FR54's lock is set-once.
#[test]
fn walking_skeleton_refuses_genesis_when_chain_config_already_locked() {
    let (crypto, storage, _) = test_backends();
    let chain_config = locked_chain_config(&crypto, TestChain::BUILD_LIMITS);
    let mut bc = new_chain(crypto, storage, chain_config, 0, 0);

    let outcome = bc.process_genesis(1_000_000_000, &OTHER_CONFIG_CONTENT);

    match outcome {
        Err(GenesisRejectReason::StorageNotEmpty) => {}
        Err(_) => panic!("expected StorageNotEmpty refusal"),
        Ok(_) => panic!("genesis must not overwrite a durably locked configuration"),
    }
    // The locked content is untouched.
    assert_eq!(
        bc.chain_config.durable_content(),
        Some(&BASE_CONFIG_CONTENT[..])
    );
}

/// Genesis is a one-shot bootstrap: a second `process_genesis` on the same
/// node refuses with `StorageNotEmpty` (the chain now carries genesis state).
#[test]
fn walking_skeleton_refuses_second_genesis() {
    let (crypto, storage, chain_config) = test_backends();
    let mut bc = new_chain(crypto, storage, chain_config, 0, 0);

    let first = bc.process_genesis(1_000_000_000, &BASE_CONFIG_CONTENT);
    assert!(first.is_ok(), "first genesis must succeed");

    let second = bc.process_genesis(1_000_000_000, &OTHER_CONFIG_CONTENT);
    match second {
        Err(GenesisRejectReason::StorageNotEmpty) => {}
        Err(_) => panic!("expected StorageNotEmpty on the second genesis"),
        Ok(_) => panic!("genesis must run at most once per chain"),
    }
}

/// Storage persistence failure refuses genesis; no `Created` outcome is
/// returned when a genesis block cannot be retained locally.
#[test]
fn walking_skeleton_refuses_storage_save_failure() {
    let private_key = [1u8; PRIVATE_KEY_SIZE];
    let crypto = Crypto::new(private_key)
        .ok()
        .expect("test private key should be accepted by the backend");
    let chain_config = empty_chain_config(TestChain::BUILD_LIMITS);
    let node_zero = *crypto.public_key().serialize();

    let mut bc_slot =
        core::mem::MaybeUninit::<Blockchain<_, _, _, 16, 16, TEST_MAX_BLOCKS, 4, 16>>::uninit();
    let bc = Blockchain::<_, _, _, 16, 16, TEST_MAX_BLOCKS, 4, 16>::init(
        &mut bc_slot,
        crypto,
        BlockWriteFailsStorage,
        chain_config,
        0,
        node_zero,
        0,
    );

    let outcome = bc.process_genesis(1_000_000_000, &BASE_CONFIG_CONTENT);

    match outcome {
        Err(GenesisRejectReason::StorageSaveFailed) => {}
        Err(_) => panic!("expected StorageSaveFailed refusal"),
        Ok(_) => panic!("genesis must not succeed when a genesis block cannot be persisted"),
    }
    // FR54's lock is set-once, so a refusal that engaged it would refuse
    // every retry for the life of the process. The content is held
    // tentatively until the last durable write succeeds, so a storage
    // failure leaves the node able to bootstrap again.
    assert!(
        !bc.chain_config.is_durable_locked(),
        "a genesis that failed on storage must not leave the configuration locked"
    );
    assert!(
        bc.chain_config.tentative_content().is_some(),
        "the accepted content is held tentatively, ready to be replaced by a retry"
    );
}

/// The durable configuration seam needs the storage control plane; block
/// writes do not. Without an up-front check an uninitialized backend would
/// persist both genesis blocks and then refuse the configuration, and the
/// non-empty-chain guard would turn away every retry for the life of the
/// process. The precondition is therefore checked with the other pre-write
/// guards, and nothing is written.
#[test]
fn walking_skeleton_refuses_uninitialized_storage() {
    let private_key = [1u8; PRIVATE_KEY_SIZE];
    let crypto = Crypto::new(private_key)
        .ok()
        .expect("test private key should be accepted by the backend");
    // Never `init`ed: `save_block` would succeed, `set_chain_configuration`
    // would not.
    let storage = MemoryBackend::<{ 8 * MAX_BLOCK_SIZE + 8000 }>::new();
    let chain_config = empty_chain_config(TestChain::BUILD_LIMITS);
    let node_zero = *crypto.public_key().serialize();
    let mut bc_slot = core::mem::MaybeUninit::<TestChain>::uninit();
    let bc = TestChain::init(&mut bc_slot, crypto, storage, chain_config, 0, node_zero, 0);

    let outcome = bc.process_genesis(1_000_000_000, &BASE_CONFIG_CONTENT);

    match outcome {
        Err(GenesisRejectReason::StorageNotInitialized) => {}
        Err(_) => panic!("expected StorageNotInitialized refusal"),
        Ok(_) => panic!("genesis must not run without a usable control plane"),
    }
    assert_eq!(bc.blocks.len(), 0, "no block reached the in-memory tree");
    assert!(
        bc.storage.read_block(0).is_err(),
        "no block reached storage either"
    );
    assert!(!bc.chain_config.is_durable_locked());
}

/// A configuration whose own `block_size_limit` is smaller than the genesis
/// blocks it frames would produce a chain no node can accept: every peer
/// refuses Block #1 at Tier 1, and the founder's own restart refuses it at
/// FR6. Genesis must not create it.
#[test]
fn walking_skeleton_refuses_genesis_blocks_above_the_declared_limit() {
    let (crypto, storage, chain_config) = test_backends();
    let mut bc = new_chain(crypto, storage, chain_config, 0, 0);
    // `block_size_limit` (id 3) declared as 300: legal for the registry
    // (> HEADER_SIZE, <= MAX_BLOCK_SIZE), smaller than Block #0. The window
    // entry is the one every content on this harness carries. A support
    // threshold of 1 keeps the limit above the room a one-signer approval
    // needs (configuration §6 check 20), so only the genesis size refuses.
    let w = TEST_W.to_le_bytes();
    let h = test_horizon(TEST_W).to_le_bytes();
    let n = TEST_MAX_NODES.to_le_bytes();
    let content = [
        6u8,
        0,
        parameter::BLOCK_SIZE_LIMIT,
        4,
        0x2C,
        0x01,
        0,
        0,
        parameter::REQUIRED_SUPPORT,
        1,
        1,
        parameter::ACTIVE_CHAIN_LENGTH,
        4,
        w[0],
        w[1],
        w[2],
        w[3],
        parameter::VERIFICATION_HORIZON,
        4,
        h[0],
        h[1],
        h[2],
        h[3],
        parameter::MAX_NODE_COUNT,
        4,
        n[0],
        n[1],
        n[2],
        n[3],
        parameter::SIGNATURE_SCHEME,
        1,
        moonblokz_crypto::SIGNATURE_SCHEME,
    ];

    let outcome = bc.process_genesis(1_000_000_000, &content);

    match outcome {
        Err(GenesisRejectReason::GenesisBlockExceedsBlockSizeLimit) => {}
        Err(_) => panic!("expected GenesisBlockExceedsBlockSizeLimit refusal"),
        Ok(_) => panic!("genesis must not create a chain that rejects its own blocks"),
    }
    assert_eq!(bc.blocks.len(), 0, "nothing was written");
    assert!(!bc.chain_config.is_durable_locked());
}

/// AC3 — read-only queries are typed to **not** carry `NextCall`.
/// This is a compile-time guarantee: `current_phase` returns
/// `LifecyclePhase` directly (not `CallResult<LifecyclePhase>`), and
/// `local_node_id` returns `u32` directly.
#[test]
fn walking_skeleton_query_carries_no_next_call() {
    let (crypto, storage, chain_config) = test_backends();
    let mut bc = new_chain(crypto, storage, chain_config, 0, 0);
    bc.process_genesis(1_000_000_000, &BASE_CONFIG_CONTENT)
        .ok()
        .expect("genesis must succeed for local_node_id == 0");

    // Type-level assertion: the query result is `LifecyclePhase`,
    // not `(LifecyclePhase, NextCall)`. If the signature ever drifts
    // back to `CallResult`, this annotation will fail to compile.
    let phase: LifecyclePhase = bc.current_phase();
    assert!(phase == LifecyclePhase::Ready);

    let node_id: u32 = bc.local_node_id();
    assert_eq!(node_id, 0);
}

/// Story 6.10 AC1 (DEC-269): the block #0 that `process_genesis` builds is
/// exactly the fixed FR54 description that Tier 1 requires of a received one,
/// so a joining node admits it.
#[test]
fn process_genesis_block_zero_has_the_tier1_genesis_shape() {
    let (bc, block_zero, block_one) = ready_genesis(TEST_W);
    for block in [&block_zero, &block_one] {
        assert_eq!(
            tier1_gate(
                &block.view(),
                &bc.node_zero_public_key,
                bc.enforceable_block_size_limit(),
                bc.enforceable_max_utxo_outputs(),
                &bc.crypto,
            ),
            Ok(())
        );
    }
    // A fresh joiner admits both through the whole intake gate, block #0's
    // creator signature included (DEC-270).
    let mut joiner = new_unconfigured_test_chain();
    for block in [&block_zero, &block_one] {
        assert!(
            joiner
                .tier1_admit(&block.view(), &block.view().hash(), 0)
                .is_ok()
        );
    }
    assert_eq!(joiner.current_active_head(), Some(0));
}
