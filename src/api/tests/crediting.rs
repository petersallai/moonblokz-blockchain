//! Story 7.2 — the FR6 `mined_amount` check, the FR36 (c) replay reward, the
//! DEC-178 liveness credit through the shared per-block step, and the
//! pre-state chain-info source with its rule-5 skip (DEC-305, DEC-340).

use super::fixtures::*;
use super::*;

/// `mining_reward = 10 · GETCHAININFO 1` (the registered-node count).
const REWARD_PER_NODE_PROGRAM: [u8; 8] = [
    0x71,
    chain_info::REGISTERED_NODE_COUNT,
    0,
    0x10,
    10,
    0x42,
    0x01,
    0x00,
];

fn node_count_reward_builder() -> ChainConfigPayloadBuilder {
    let mut builder = window_config_builder(TEST_W);
    builder
        .add_bytecode(parameter::MINING_REWARD, &REWARD_PER_NODE_PROGRAM[..7])
        .ok()
        .expect("the program frames");
    builder
}

fn genesis_with(builder: &ChainConfigPayloadBuilder) -> (TestChain, Block, Block) {
    let (crypto, storage, chain_config) = test_backends();
    let mut bc = new_chain(crypto, storage, chain_config, 0, 0);
    let genesis = bc
        .process_genesis(CURRENCY, builder.content())
        .ok()
        .expect("genesis succeeds");
    (bc, genesis.block_zero, genesis.block_one)
}

fn registration_with_reward(seq: u32, prev: [u8; 32], node: u32, mined: u32) -> Block {
    tx_block(seq, prev, mined, |b| {
        b.add_registration(&registration_tx(0, node, key_of(node)))
            .ok()
            .expect("add registration");
    })
}

// --- AC6: `mined_amount = mining_reward` -------------------------------------

#[test]
fn a_wrong_mined_amount_is_refused_in_ready_and_at_tier_two() {
    let (mut bc, _, b1) = ready_genesis(TEST_W);
    // Direct intake: the reward is the default 0.
    let bad = transfer_with_mined(2, b1.view().hash(), 7);
    assert_eq!(
        step_reason(&mut bc, &bad),
        Some(ValidationReason::MinedAmountMismatch)
    );
    let free = bc.blocks.next_free_index();
    assert_eq!(
        receive(&mut bc, &bad),
        ReceiveBlockOutcome::Rejected(RejectReason::InvalidEvidence)
    );
    assert_eq!(bc.blocks.next_free_index(), free, "nothing stored");

    // A side block beside an active #2: the literal reward is judged at
    // Tier 2, before the block is written.
    let good = transfer(2, b1.view().hash(), 0, 1);
    assert_eq!(
        receive(&mut bc, &good),
        ReceiveBlockOutcome::AcceptedSilently
    );
    let side = transfer_with_mined(2, b1.view().hash(), 9);
    assert_eq!(
        receive(&mut bc, &side),
        ReceiveBlockOutcome::Rejected(RejectReason::InvalidEvidence)
    );
    assert_eq!(status_of(&bc, &side), None);

    // A stored child: held as an orphan, judged by the continuation when its
    // parent arrives, and deleted as exact evidence.
    let (mut bc, _, b1) = ready_genesis(TEST_W);
    let b2 = transfer(2, b1.view().hash(), 0, 1);
    let bad3 = transfer_with_mined(3, b2.view().hash(), 7);
    assert_eq!(
        receive(&mut bc, &bad3),
        ReceiveBlockOutcome::AcceptedSilently
    );
    assert_eq!(receive(&mut bc, &b2), ReceiveBlockOutcome::AcceptedSilently);
    assert_eq!(head_of(&bc), (2, b2.view().hash()), "the child is refused");
    assert_eq!(status_of(&bc, &bad3), None, "deleted");
}

#[test]
fn a_wrong_mined_amount_is_deleted_by_the_fr3_pass() {
    let (_, b0, b1) = ready_genesis(TEST_W);
    let bad = transfer_with_mined(2, b1.view().hash(), 7);
    let mut mesh = new_unconfigured_test_chain();
    for block in [&bad, &b1, &b0] {
        assert_eq!(
            receive(&mut mesh, block),
            ReceiveBlockOutcome::AcceptedSilently
        );
    }
    assert!(mesh.is_ready());
    assert_eq!(head_of(&mesh), (1, b1.view().hash()), "Ready on the prefix");
    assert!(mesh.blocks.find(2, &bad.view().hash()).is_none(), "deleted");
}

/// A node-transfer block by node #0 with `mined`.
fn transfer_with_mined(seq: u32, prev: [u8; 32], mined: u32) -> Block {
    let nt = transfer_tx(seq, 0, 1);
    tx_block(seq, prev, mined, |b| {
        b.add_node_transfer(&nt).ok().expect("add transfer");
    })
}

// --- AC4: the pre-state chain-info source ------------------------------------

/// A size-dependent reward: the genesis node and a genesis-anchored joiner
/// serve the count at each block's pre-state and agree; a block carrying the
/// value of the wrong position is refused.
#[test]
fn a_size_dependent_reward_is_judged_at_the_pre_state() {
    let builder = node_count_reward_builder();
    let (mut g, b0, b1) = genesis_with(&builder);
    // #2 registers node 1: its pre-state count is 1, so the reward is 10.
    let b2 = registration_with_reward(2, b1.view().hash(), 1, 10);
    assert_eq!(receive(&mut g, &b2), ReceiveBlockOutcome::AcceptedSilently);
    // #3's pre-state has two nodes: 20, not #2's 10.
    let stale = transfer_with_mined(3, b2.view().hash(), 10);
    assert_eq!(
        step_reason(&mut g, &stale),
        Some(ValidationReason::MinedAmountMismatch)
    );
    let b3 = transfer_with_mined(3, b2.view().hash(), 20);
    assert_eq!(receive(&mut g, &b3), ReceiveBlockOutcome::AcceptedSilently);
    assert_eq!(head_of(&g), (3, b3.view().hash()));

    // A genesis-anchored joiner serves the same values in its FR3 pass.
    let mut joiner = new_unconfigured_test_chain();
    for block in [&b3, &b2, &b1, &b0] {
        assert_eq!(
            receive(&mut joiner, block),
            ReceiveBlockOutcome::AcceptedSilently
        );
    }
    assert!(joiner.is_ready());
    assert_eq!(head_of(&joiner), head_of(&g));
    assert_eq!(
        joiner.node_info.max_known_node_id(),
        g.node_info.max_known_node_id()
    );
    for node in 0..TEST_MAX_NODES {
        assert_eq!(
            joiner.node_info.balance_of(node),
            g.node_info.balance_of(node),
            "balance of {node}"
        );
        assert_eq!(
            joiner.node_info.public_key_of(node),
            g.node_info.public_key_of(node),
            "key of {node}"
        );
    }
    assert!(joiner.vote_engine == g.vote_engine, "the same votes");
}

/// Rule 5: where the source declines, a check whose resolution read
/// chain-info is skipped, never evaluated against the fall-through value;
/// a literal reward never declines, so it is always checked.
#[test]
fn a_declined_chain_info_read_skips_the_check() {
    let builder = node_count_reward_builder();
    let (mut g, _, b1) = genesis_with(&builder);
    let wrong = transfer_with_mined(2, b1.view().hash(), 999);
    assert!(
        g.mined_amount_mismatch(&wrong.view(), true),
        "served: judged"
    );
    assert!(
        !g.mined_amount_mismatch(&wrong.view(), false),
        "declined: skipped"
    );
    // The fall-through value (the default 0) is not what a declined read
    // checks against either.
    let zero = transfer_with_mined(2, b1.view().hash(), 0);
    assert!(!g.mined_amount_mismatch(&zero.view(), false));
    assert!(g.mined_amount_mismatch(&zero.view(), true));
    let _ = receive(&mut g, &zero);

    let (literal, _, b1) = ready_genesis(TEST_W);
    let wrong = transfer_with_mined(2, b1.view().hash(), 1);
    assert!(
        literal.mined_amount_mismatch(&wrong.view(), false),
        "a literal is checked even where chain-info declines"
    );
}

/// A nested `GETCONFIG` reads chain-info through the same source, so its
/// decline is recorded too: `mining_reward = GETCONFIG(registration_price)`
/// with `registration_price = 10 · GETCHAININFO 1`.
#[test]
fn a_nested_decline_is_recorded() {
    let mut builder = window_config_builder(TEST_W);
    builder
        .add_bytecode(
            parameter::MINING_REWARD,
            &[0x70, parameter::REGISTRATION_PRICE, 0, 0x01],
        )
        .ok()
        .expect("the program frames");
    builder
        .add_bytecode(parameter::REGISTRATION_PRICE, &REWARD_PER_NODE_PROGRAM[..7])
        .ok()
        .expect("the program frames");
    let (g, _, b1) = genesis_with(&builder);
    let source = g.chain_info_pre_state(false);
    let reward = g
        .chain_config
        .active_configuration()
        .expect("held")
        .with_chain_info(&source)
        .mining_reward();
    assert_eq!(reward, 100, "the nested price fell through to its default");
    assert!(source.declined(), "and the decline is visible");
    let served = g.chain_info_pre_state(true);
    let reward = g
        .chain_config
        .active_configuration()
        .expect("held")
        .with_chain_info(&served)
        .mining_reward();
    assert_eq!(reward, 10, "one node: 10");
    assert!(!served.declined());
    let at_ten = transfer_with_mined(2, b1.view().hash(), 10);
    assert!(!g.mined_amount_mismatch(&at_ten.view(), true));
}

/// The proposer's post-deviation header carries the reward resolved at the
/// head's post-state, the value the validator resolves at its pre-state.
#[test]
fn the_post_deviation_header_carries_the_mining_reward() {
    let builder = node_count_reward_builder();
    let (g, _, b1) = genesis_with(&builder);
    let header = g
        .post_deviation_header(1, b1.view().hash())
        .expect("a header");
    assert_eq!(header.mined_amount, 10, "one registered node");
}

// --- AC5: the FR36 (c) replay reward ----------------------------------------

fn same_projection<S: StorageTrait, T: StorageTrait>(a: &Chain16<S>, b: &Chain16<T>, what: &str) {
    assert!(a.node_info == b.node_info, "{what}: node_info");
    assert!(a.vote_engine == b.vote_engine, "{what}: votes");
}

#[test]
fn a_replay_bearing_block_pays_the_reward_once_and_undoes_it() {
    // A balance block (FR50).
    let (mut bc, _, b1) = ready_genesis(TEST_W);
    let (replica, _, _) = ready_genesis(TEST_W);
    let before = bc.node_info.balance_of(0);
    let balance = snapshot_block(&bc, 2, b1.view().hash());
    assert_eq!(
        receive(&mut bc, &balance),
        ReceiveBlockOutcome::AcceptedSilently
    );
    assert_eq!(bc.node_info.balance_of(0), before + 100, "balance block");
    assert_eq!(bc.undo_active_head(), Ok(()));
    same_projection(&bc, &replica, "balance block undone");

    // A transaction block with two zero-input carry-forwards (FR51): one
    // reward, however many carry-forwards it holds.
    let (mut bc, _, b1) = ready_genesis(TEST_W);
    let (replica, _, _) = ready_genesis(TEST_W);
    let before = bc.node_info.balance_of(0);
    let carry_a = utxo_tx(2, &[], None, &[Ok(5)]);
    let carry_b = utxo_tx(2, &[], None, &[Ok(6)]);
    let carrying = complex_tx_block(2, b1.view().hash(), 0, 0, &[&carry_a, &carry_b]);
    assert_eq!(
        receive(&mut bc, &carrying),
        ReceiveBlockOutcome::AcceptedSilently
    );
    assert_eq!(
        bc.node_info.balance_of(0),
        before + 100,
        "two carry-forwards"
    );
    assert_eq!(bc.undo_active_head(), Ok(()));
    same_projection(&bc, &replica, "carry-forward block undone");

    // An ordinary transfer block earns only its fee.
    let (mut bc, _, b1) = ready_genesis(TEST_W);
    let before = bc.node_info.balance_of(0);
    let plain = transfer(2, b1.view().hash(), 0, 10);
    assert_eq!(
        receive(&mut bc, &plain),
        ReceiveBlockOutcome::AcceptedSilently
    );
    assert_eq!(
        bc.node_info.balance_of(0),
        before,
        "a self-transfer and its self-paid fee net out; no reward"
    );

    // The genesis blocks earn nothing (FR54): node #0 holds the mint alone.
    let (bc, _, _) = ready_genesis(TEST_W);
    assert_eq!(bc.node_info.balance_of(0), CURRENCY);
}

#[test]
fn a_replay_reward_that_overflows_the_creator_is_invalid() {
    let (crypto, storage, chain_config) = test_backends();
    let mut bc = new_chain(crypto, storage, chain_config, 0, 0);
    let genesis = bc
        .process_genesis(u64::MAX - 50, window_config_builder(TEST_W).content())
        .ok()
        .expect("genesis succeeds");
    let balance = snapshot_block(&bc, 2, genesis.block_one.view().hash());
    assert_eq!(
        step_reason(&mut bc, &balance),
        Some(ValidationReason::BalanceOverflow)
    );
}

// --- AC3: the liveness credit through the step -------------------------------

/// On the W6 harness (`H = 3`, #2 a clean slot): node #0 registers node #1
/// at #3, and node #1 creates #4, so node #0 — the creator of #1 — gains
/// `⌈1000 / 5⌉ = 200` (DEC-178). At #3 the candidate (node #0, creator of
/// #0) is the block's own creator, so nothing is credited there. The undo
/// takes the credit back.
#[test]
fn the_liveness_credit_reaches_the_creator_of_s_minus_h() {
    let (mut bc, _, b1) = ready_genesis_w6();
    let b2 = transfer(2, b1.view().hash(), 0, 1);
    assert_eq!(receive(&mut bc, &b2), ReceiveBlockOutcome::AcceptedSilently);
    let b3 = register(3, b2.view().hash(), 1, NODE_ONE_KEY);
    assert_eq!(receive(&mut bc, &b3), ReceiveBlockOutcome::AcceptedSilently);
    assert_eq!(
        bc.vote_engine.accumulated_vote_of(0),
        0,
        "reset at #3, and no credit to the block's own creator"
    );
    let before = (
        bc.node_info.balance_of(0),
        bc.vote_engine.accumulated_vote_of(1),
    );
    let b4 = real_on(
        &bc,
        &tx_block(4, b3.view().hash(), 0, votes_for(4, 1, 1, 70)),
        1,
        NODE_ONE_KEY,
    );
    assert_eq!(bc.liveness_candidate(NONE_REF, 2, 0), Ok(None), "s < H");
    assert_eq!(receive(&mut bc, &b4), ReceiveBlockOutcome::AcceptedSilently);
    assert_eq!(head_of(&bc), (4, b4.view().hash()));
    assert_eq!(bc.vote_engine.accumulated_vote_of(0), 200);
    let b4_idx = bc.active_chain_head_idx;
    assert_eq!(bc.liveness_candidate(b4_idx, 4, 0), Ok(Some(0)));
    // A window-anchored pass below `a + H` asks for no candidate (DEC-210).
    assert_eq!(bc.liveness_candidate(b4_idx, 4, 5), Ok(None));

    assert_eq!(bc.undo_active_head(), Ok(()));
    assert_eq!(bc.vote_engine.accumulated_vote_of(0), 0, "undone");
    assert_eq!(
        (
            bc.node_info.balance_of(0),
            bc.vote_engine.accumulated_vote_of(1)
        ),
        before
    );
}

/// An unreadable `s − H` is the node's own failure, never evidence: the
/// candidate read fails, and nothing is refused as invalid.
#[test]
fn an_unreadable_liveness_ancestor_is_local() {
    let (mut bc, b1) = faulty_genesis(W6);
    let b2 = transfer(2, b1.view().hash(), 0, 1);
    assert_eq!(receive(&mut bc, &b2), ReceiveBlockOutcome::AcceptedSilently);
    let b3 = transfer(3, b2.view().hash(), 0, 1);
    bc.storage.failing_read_slot = 0;
    assert_eq!(receive(&mut bc, &b3), ReceiveBlockOutcome::AcceptedSilently);
    assert_eq!(
        status_of(&bc, &b3),
        Some(BlockStatus::Stored),
        "a local fault"
    );
    bc.storage.failing_read_slot = NONE_REF;
}

// --- AC4: the custodian fee in the FR51 tail classification (DEC-330) -------

/// `custodian_fee = 10 · GETCHAININFO 1`: served, the program's 10 decides
/// (two outputs of 5 owe nothing, though the default fee 1 would owe them);
/// declined, the binding is not judged at all, never against the fall-through
/// fee (DEC-340).
#[test]
fn a_chain_info_custodian_fee_binds_the_tail_classification() {
    let mut builder = window_config_builder(TEST_W);
    builder
        .add_bytecode(parameter::CUSTODIAN_FEE, &REWARD_PER_NODE_PROGRAM[..7])
        .ok()
        .expect("the program frames");
    for (outputs, served) in [
        (&[Ok(5), Ok(5)][..], TailObligation::None),
        (&[Ok(60), Ok(40)][..], TailObligation::Utxo),
    ] {
        let (mut bc, _, b1) = genesis_with(&builder);
        let tx = utxo_tx(2, &[], Some((0, 100)), outputs);
        let mint = complex_tx_block(2, b1.view().hash(), 0, 0, &[&tx]);
        assert_eq!(
            receive(&mut bc, &mint),
            ReceiveBlockOutcome::AcceptedSilently
        );
        let mi = bc.active_chain_head_idx;
        assert_eq!(bc.tail_obligation(mi, true), Ok(served), "{outputs:?}");
        assert_eq!(
            bc.tail_obligation(mi, false),
            Ok(TailObligation::None),
            "declined: not judged ({outputs:?})"
        );
    }
}
