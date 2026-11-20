//! Tests of `api/window.rs`.

use super::*;

// ===================================================================
// Story 9.1 — snake-chain window mechanics and the FR48 tail drop
// ===================================================================

/// A node-zero genesis bootstrap on a chain whose configuration declares the
/// window `w` (TestChain capacity 16).
fn genesis_node_with_window(w: u32) -> TestChain {
    let (crypto, storage, chain_config) = test_backends();
    let mut bc = new_chain(crypto, storage, chain_config, 0, 0);
    let builder = window_config_builder(w);
    bc.process_genesis(1_000_000_000, builder.content())
        .ok()
        .expect("genesis succeeds");
    bc
}

/// A node-#0 founder on the W6 configuration, Ready on its FR54 genesis
/// ([`Blockchain::process_genesis`]), and the blocks #0 and #1 it wrote.
fn w6_founder() -> (W6Chain, Block, Block) {
    let (crypto, _, _) = test_backends();
    let node_zero = *crypto.public_key().serialize();
    let mut slot = core::mem::MaybeUninit::<W6Chain>::uninit();
    let chain_config = empty_chain_config(W6Chain::BUILD_LIMITS);
    Blockchain::init(
        &mut slot,
        crypto,
        w6_storage(),
        chain_config,
        0,
        node_zero,
        0,
    );
    // SAFETY: `init` returned, so every field of `slot` is initialized.
    let mut founder = unsafe { slot.assume_init() };
    let genesis = founder
        .process_genesis(CURRENCY, window_config_builder(W6).content())
        .ok()
        .expect("genesis succeeds");
    (founder, genesis.block_zero, genesis.block_one)
}

/// The W6 segment's balance block at `seq`, repeating node #0's entry as
/// `bc` holds it (the first, #102, seeds it with nothing).
fn w6_balance_block(bc: Option<&W6Chain>, seq: u32, prev: [u8; 32]) -> Block {
    let (balance, vote, max) = bc.map_or((0, 0, 9), |bc| {
        (
            bc.node_info.balance_of(0),
            bc.vote_engine.accumulated_vote_of(0),
            bc.node_info.max_known_node_id(),
        )
    });
    balance_block(seq, prev, &[(0, balance, vote, 1)], max)
}

/// The block that extends a Ready W6 head at `seq` (on `prev`, the head):
/// the replay the block it drops needs — chain-config for #100, #106, …
/// (FR49), node #0's balance for #102, #108, … (FR50) — and otherwise a
/// [`w6_clean_block`], which also fills the clean slots `≡ 2 (mod 3)`.
fn w6_extension(bc: &W6Chain, seq: u32, prev: [u8; 32]) -> Block {
    match (seq - 100) % 6 {
        0 => w6_config_anchor_block(seq, prev),
        2 => w6_balance_block(Some(bc), seq, prev),
        _ => w6_clean_block(seq, prev),
    }
}

/// A `W6Chain` that went Ready on the window-anchored segment `97..=last`
/// (`last ≤ 107`; #97..=#99 from [`w6_below`]), its tail block #100 the
/// chain-config block the FR8 final check requires and #102 a balance
/// block seeding node #0, so a Ready extension can name it
/// ([`w6_extension`]); the others are plain transfers. Returns the node
/// and the hash of each block, indexed by `seq - 100`.
fn w6_ready_on_segment(last: u32) -> (W6Chain, [[u8; 32]; 8]) {
    let mut bc = new_w6_chain();
    let mut hashes = [[0u8; 32]; 8];
    for below in w6_below() {
        bc.tier1_admit(&below.view(), &below.view().hash(), 0)
            .expect("the blocks below the window admitted");
    }
    let below = w6_horizon_block();
    let anchor = w6_config_anchor_block(100, below.view().hash());
    hashes[0] = anchor.view().hash();
    bc.tier1_admit(&anchor.view(), &hashes[0], 0)
        .expect("anchor admitted");
    for seq in 101..=last {
        // #106 drops the chain-config block #100, so it is its replay
        // (FR49): the FR3 pass binds it (Story 6.14 AC9).
        let prev = hashes[(seq - 101) as usize];
        let blk = match seq {
            102 => w6_balance_block(None, seq, prev),
            106 => w6_config_anchor_block(seq, prev),
            107 => w6_clean_block(seq, prev),
            _ => linked_transfer_block(seq, prev),
        };
        hashes[(seq - 100) as usize] = blk.view().hash();
        bc.tier1_admit(&blk.view(), &blk.view().hash(), 0)
            .expect("block admitted");
    }
    bc.drive_dominant_chain_acquisition();
    assert!(bc.is_ready(), "precondition: the segment validated");
    (bc, hashes)
}

/// AC10.1 / AC2 — genesis: the tail is block #0 and the window is `(0, 1)`;
/// with `W > 2` nothing is released (the bootstrap growth phase).
#[test]
fn snake_genesis_tail_is_block_zero() {
    let bc = genesis_node_with_window(16);
    assert_eq!(bc.snake_chain_tail_idx, 0);
    assert_eq!(bc.active_snake_chain_window(), Ok((0, 1)));
    assert_eq!(bc.block_tree_len(), 2);
}

/// AC2 — `W = 2` admits no verification horizon: `H` must be at least 3,
/// below `W` and divide it (configuration §6 checks 15 and 21, Story 6.7
/// D8), so neither `H = 1` nor `H = 2` is legal, and genesis refuses the
/// content before anything is written. (This test pinned that a `W = 2`
/// genesis is already `W` long and releases nothing; the smallest window
/// with a legal horizon is now 6, which genesis never fills.)
#[test]
fn snake_genesis_at_w_two_is_refused() {
    for h in [1, 2] {
        let (crypto, storage, chain_config) = test_backends();
        let mut bc = new_chain(crypto, storage, chain_config, 0, 0);
        let builder = window_horizon_config_builder(2, h);
        assert!(
            matches!(
                bc.process_genesis(1_000_000_000, builder.content()),
                Err(GenesisRejectReason::InitialChainConfigRejected)
            ),
            "W = 2, H = {h} is refused"
        );
        assert_eq!(bc.block_tree_len(), 0, "nothing was written");
        assert!(!bc.chain_config.is_durable_locked());
    }
}

/// Story 6.17 D10 (DEC-252) — genesis founds a chain only on the build's own
/// signature scheme: a content naming another scheme is refused, and one
/// that leaves ID 33 out (the shape the encoder writes for a Schnorr chain)
/// is accepted on `schnorr` only, since the default is `schnorr`.
#[test]
fn genesis_founds_a_chain_of_the_builds_scheme_only() {
    let content = |scheme: Option<u8>| {
        let mut builder = ChainConfigPayloadBuilder::new();
        for (id, value) in [
            (parameter::ACTIVE_CHAIN_LENGTH, TEST_W),
            (parameter::VERIFICATION_HORIZON, test_horizon(TEST_W)),
            (parameter::MAX_NODE_COUNT, TEST_MAX_NODES),
        ] {
            builder
                .add_literal(id, &value.to_le_bytes())
                .ok()
                .expect("a four-byte literal is well-formed");
        }
        if let Some(scheme) = scheme {
            builder
                .add_literal(parameter::SIGNATURE_SCHEME, &[scheme])
                .ok()
                .expect("a one-byte literal is well-formed");
        }
        builder
    };
    // The outcome and how many blocks it wrote.
    let genesis = |scheme: Option<u8>| {
        let (crypto, storage, chain_config) = test_backends();
        let mut bc = new_chain(crypto, storage, chain_config, 0, 0);
        let outcome = match bc.process_genesis(1_000_000_000, content(scheme).content()) {
            Ok(_) => "founded",
            Err(GenesisRejectReason::InitialChainConfigRejected) => "content refused",
            Err(_) => "another refusal",
        };
        (outcome, bc.block_tree_len())
    };
    let own = moonblokz_crypto::SIGNATURE_SCHEME;
    assert_eq!(genesis(Some((own + 1) % 3)), ("content refused", 0));
    assert_eq!(genesis(Some((own + 2) % 3)), ("content refused", 0));
    assert_eq!(genesis(Some(own)), ("founded", 2));
    assert_eq!(
        genesis(None),
        if own == 0 {
            ("founded", 2)
        } else {
            ("content refused", 0)
        },
        "an absent ID 33 means schnorr"
    );
}

/// AC2 — `W = 1` admits no verification horizon (`3 ≤ H < W` is empty,
/// DEC-207, Story 6.7 D8), so genesis refuses the content before anything
/// is written.
#[test]
fn snake_genesis_at_w_one_is_refused() {
    let (crypto, storage, chain_config) = test_backends();
    let mut bc = new_chain(crypto, storage, chain_config, 0, 0);
    let builder = window_horizon_config_builder(1, 1);
    assert!(matches!(
        bc.process_genesis(1_000_000_000, builder.content()),
        Err(GenesisRejectReason::InitialChainConfigRejected)
    ));
    assert_eq!(bc.block_tree_len(), 0, "nothing was written");
    assert!(!bc.chain_config.is_durable_locked());
}

/// AC10.2 / AC3; Story 6.14 AC6 — Ready entry on a genesis-anchored segment
/// of length `W + H + 1` keeps the window `W` long and `H` blocks below it,
/// and releases exactly the one block beyond them. The extra blocks are
/// chain-config replays, which FR6 accepts on a genesis-anchored candidate;
/// the retained #1 is one. The segment is a founder's FR54 genesis, which
/// seeds node #0, so the clean slots #2, #5 and #8 (Story 6.7 D8) hold
/// [`w6_clean_block`]s, and #6, which drops #0 (node #0's seed source),
/// is node #0's balance replay (FR50); the founder builds them.
#[test]
fn snake_ready_entry_on_a_longer_genesis_segment_releases_the_excess() {
    let mut bc = new_w6_chain();
    let (mut founder, genesis, b1) = w6_founder();
    for block in [&genesis, &b1] {
        bc.tier1_admit(&block.view(), &block.view().hash(), 0)
            .expect("genesis admitted");
    }
    let mut prev = b1.view().hash();
    for seq in 2..=9 {
        let blk = match seq {
            6 => w6_balance_block(Some(&founder), seq, prev),
            _ if seq % 3 == 2 => w6_clean_block(seq, prev),
            _ => w6_config_anchor_block(seq, prev),
        };
        assert_eq!(
            founder.receive_block(blk.view(), 0).0,
            ReceiveBlockOutcome::AcceptedSilently
        );
        prev = blk.view().hash();
        bc.tier1_admit(&blk.view(), &prev, 0)
            .expect("block admitted");
    }
    bc.drive_dominant_chain_acquisition();
    assert!(bc.is_ready());
    assert_eq!(bc.active_snake_chain_window(), Ok((4, 9)));
    assert_eq!(bc.block_tree_len(), 9, "W blocks and H = 3 below them");
    assert!(bc.blocks.get(0).is_none(), "#0 left the horizon: released");
    let root = bc.blocks.get(1).expect("#1 in the horizon");
    assert_eq!(root.sequence(), 1);
    assert_eq!(root.parent_ref(), NONE_REF);
    assert!(root.is_on_active_chain());
    assert_eq!(bc.horizon_root(), 1);
    let tail = bc.blocks.get(bc.snake_chain_tail_idx).expect("tail");
    assert_eq!(tail.sequence(), 4);
    assert_eq!(tail.parent_ref(), 3, "the tail stays linked to the horizon");
    assert!(tail.is_on_active_chain());
    assert!(!bc.chain_heads.has_stored_head());
}

/// AC10.3; Story 6.14 AC6 — Ready entry on a window-anchored segment of
/// exactly `W + H` releases nothing: the window is `100..=105` and #97,
/// #98 and #99 are the horizon.
#[test]
fn snake_ready_entry_on_exactly_w_plus_h_releases_nothing() {
    let (bc, _) = w6_ready_on_segment(105);
    assert_eq!(bc.active_snake_chain_window(), Ok((100, 105)));
    assert_eq!(bc.block_tree_len(), 9);
    let [b97, b98, b99] = w6_below();
    assert!(slot_of(&bc, 98, &b98.view().hash()).is_some(), "#98 kept");
    assert!(slot_of(&bc, 99, &b99.view().hash()).is_some(), "#99 kept");
    assert_eq!(
        Some(bc.horizon_root()),
        slot_of(&bc, 97, &b97.view().hash()),
        "#97 is the root"
    );
    // O-024: the adopted chain's head is Connected, not a Stored head still
    // asking for the anchor's parent.
    assert!(!bc.chain_heads.has_stored_head());
}

/// Review patch; Story 6.14 AC3 — a seed source that the window drops stays
/// named while it is in the horizon, and stops naming its slot only when it
/// leaves the horizon: the node stays seeded, and the unrelated block that
/// reuses the slot does not classify as a seed source.
#[test]
fn snake_released_seed_source_does_not_follow_the_slot() {
    let (mut bc, h) = w6_ready_on_segment(105);
    let slot_99 = slot_of(&bc, 99, &w6_horizon_block().view().hash()).expect("#99");
    let slot_100 = slot_of(&bc, 100, &h[0]).expect("#100");
    let key = *bc.crypto.public_key().serialize();
    bc.node_info.seed_node(1, &key, 0, slot_100);
    let mut prev = h[5];
    let mut head = [0u8; 32];
    for seq in 106..=109 {
        let blk = w6_extension(&bc, seq, prev);
        extend_active_head(&mut bc, &blk, 0);
        prev = blk.view().hash();
        head = prev;
        assert_eq!(bc.active_snake_chain_window(), Ok((seq - 5, seq)));
        if seq < 109 {
            assert!(
                bc.node_info.is_seed_source(slot_100),
                "#100 entered the horizon (H = 3) and keeps the pointer"
            );
        }
    }
    assert!(slot_of(&bc, 100, &h[0]).is_none(), "#100 left the horizon");
    assert!(bc.node_info.is_seeded(1), "the node stays seeded");
    assert!(bc.node_info.key_is_registered(&key));
    assert!(!bc.node_info.is_seed_source(slot_100));
    // #109 took #99's freed slot; the next admission reuses #100's.
    assert_eq!(slot_of(&bc, 109, &head), Some(slot_99));
    let orphan = node_transfer_block(111, 3, 110, 7);
    let (outcome, _) = bc.receive_block(orphan.view(), 0);
    assert_eq!(outcome, ReceiveBlockOutcome::AcceptedSilently);
    assert_eq!(slot_of(&bc, 111, &orphan.view().hash()), Some(slot_100));
    assert_eq!(
        classify_tail_drop(&bc.blocks, &bc.node_info, slot_100),
        Ok(TailObligation::None),
        "the reused slot is not anyone's seed source"
    );
}

/// Review patch; Story 6.14 AC3 — the window advance refuses, at runtime, a
/// tail that is off the active path or is the head.
#[test]
fn snake_advance_refuses_a_tail_off_the_active_path() {
    let (mut bc, h) = w6_ready_on_segment(105);
    let b106 = w6_extension(&bc, 106, h[5]);
    extend_active_head(&mut bc, &b106, 0);
    let fork = salted_linked_block(106, h[5], 9);
    let fork_idx = admit_fork(&mut bc, &fork, 0);
    let len = bc.block_tree_len();
    let real_tail = bc.snake_chain_tail_idx;
    bc.snake_chain_tail_idx = fork_idx; // not on the active path
    assert!(!bc.advance_snake_chain_tail());
    bc.snake_chain_tail_idx = bc.active_chain_head_idx; // the head
    assert!(!bc.advance_snake_chain_tail());
    assert_eq!(bc.block_tree_len(), len, "nothing released");
    bc.snake_chain_tail_idx = real_tail;
    assert!(bc.advance_snake_chain_tail());
}

/// Admits a fork through Tier 1 and its Ready Tier 2, Connected, without
/// the FR22 comparison: these tests exercise the window, the horizon and
/// the reclamation, and a fork carrying a pre-window actor would lose the
/// FR23 replay it could otherwise win on a hash tie (Story 6.14 D6 lets a
/// window-anchored chain switch).
fn admit_fork(bc: &mut W6Chain, fork: &Block, now: u64) -> u32 {
    let view = fork.view();
    let idx = bc
        .tier1_admit(&view, &view.hash(), now)
        .expect("the fork is admitted");
    assert_eq!(
        bc.blocks.get(idx).map(|e| e.status()),
        Some(BlockStatus::Connected)
    );
    idx
}

/// One drive step's record: the new `S_tail`, the dropped tail's slot, and
/// the classification and binding decided before the window advanced.
type DriveRecord = (u32, u32, TailObligation, TailBinding);

/// One step of the drive in [`drive_past_w`]: classify the tail, decide
/// the binding for `extension`, then extend — the forward extension
/// advances the window. Returns the trace record.
fn drive_step(bc: &mut W6Chain, extension: &Block, now: u64) -> DriveRecord {
    let released = bc.snake_chain_tail_idx;
    let obligation =
        classify_tail_drop(&bc.blocks, &bc.node_info, released).expect("the tail is readable");
    let binding = tail_drop_binding(obligation, &extension.view());
    extend_active_head(bc, extension, now);
    assert_ne!(bc.snake_chain_tail_idx, released, "the window advances");
    let (s_tail, _) = bc.active_snake_chain_window().expect("Ready");
    (s_tail, released, obligation, binding)
}

/// The AC10.4 drive (Story 6.14): from the window `100..=105` with #97,
/// #98 and #99 in the horizon (`W = 6`, `H = 3`), two head extensions.
/// Only forks inside FR58's bound can arrive (`S_new > S_head − H`), each
/// forking at the deepest point the bound admits: before the first, a fork
/// off #102, two blocks deep; before the second, a fork off #103; after
/// it, a fork off #104. Returns the trace, the node, and the hashes
/// `[#102 fork, its child, #103 fork, #104 fork, #106]`.
fn drive_past_w(now: u64) -> ([DriveRecord; 2], W6Chain, [[u8; 32]; 5]) {
    let (mut bc, h) = w6_ready_on_segment(105);
    let fork_a = salted_linked_block(103, h[2], 5);
    let fork_a_child = salted_linked_block(104, fork_a.view().hash(), 5);
    for blk in [&fork_a, &fork_a_child] {
        admit_fork(&mut bc, blk, now);
    }
    // Dropping #100 (chain-config) needs a chain-config extension (FR49).
    let b106 = w6_extension(&bc, 106, h[5]);
    let first = drive_step(&mut bc, &b106, now);
    let fork_b = salted_linked_block(104, h[3], 8);
    admit_fork(&mut bc, &fork_b, now);
    assert!(!bc.chain_heads.has_stored_head(), "every fork is Connected");
    // A Ready projection is complete (Story 6.0 D3): this segment seeds no
    // node but #0, so the extension names no other actor; #107 is a clean
    // slot (Story 6.7 D8).
    let b107 = w6_extension(&bc, 107, b106.view().hash());
    let second = drive_step(&mut bc, &b107, now);
    // A fork inside the bound (`A = S_head − H`) is kept.
    let keep = salted_linked_block(105, h[4], 6);
    admit_fork(&mut bc, &keep, now);
    (
        [first, second],
        bc,
        [
            fork_a.view().hash(),
            fork_a_child.view().hash(),
            fork_b.view().hash(),
            keep.view().hash(),
            b106.view().hash(),
        ],
    )
}

/// AC10.4 / AC5 / AC6; Story 6.14 AC3 / AC5 — the window advance one block
/// at a time: tail positions, the dropped block kept in the horizon, the
/// block leaving the horizon released and its successor unlinked, and the
/// FR58 reclamation (DEC-208): a branch whose fork point falls below
/// `S_head − H` is deleted whole at the extension that moves it out, a
/// branch inside the bound is kept, and nothing is left asking for a parent.
#[test]
fn snake_drive_past_w() {
    let [b97, b98, b99] = w6_below();
    let (h, slot_97, slot_98, slot_100, slot_101) = {
        let (bc, h) = w6_ready_on_segment(105);
        (
            h,
            slot_of(&bc, 97, &b97.view().hash()),
            slot_of(&bc, 98, &b98.view().hash()),
            slot_of(&bc, 100, &h[0]),
            slot_of(&bc, 101, &h[1]),
        )
    };
    let (trace, mut bc, [fork_a, fork_a_child, fork_b, keep, b106]) = drive_past_w(1_000);

    assert_eq!(
        trace[0],
        (
            101,
            slot_100.expect("#100"),
            TailObligation::ChainConfig,
            TailBinding::Advance
        )
    );
    assert_eq!(
        trace[1],
        (
            102,
            slot_101.expect("#101"),
            TailObligation::None,
            TailBinding::Advance
        )
    );
    assert_eq!(bc.active_snake_chain_window(), Ok((102, 107)));

    // The horizon keeps #99, #100 and #101: #99 from the entry, and the
    // blocks the window dropped; #97 and #98 left the horizon and were
    // released.
    assert!(slot_of(&bc, 97, &b97.view().hash()).is_none());
    assert!(slot_of(&bc, 98, &b98.view().hash()).is_none());
    assert!(slot_97.is_some(), "precondition: #97 was retained at entry");
    assert!(slot_98.is_some(), "precondition: #98 was retained at entry");
    let root_idx = slot_of(&bc, 99, &b99.view().hash()).expect("#99 in the horizon");
    assert_eq!(bc.horizon_root(), root_idx);
    let root = bc.blocks.get(root_idx).expect("root");
    assert_eq!(root.parent_ref(), NONE_REF, "unlinked from the freed slot");
    assert!(root.is_on_active_chain(), "D1: the horizon keeps the flag");
    assert_eq!(root.status(), BlockStatus::Active);
    let mut below_idx = root_idx;
    for (seq, hash) in [(100, &h[0]), (101, &h[1])] {
        let idx = slot_of(&bc, seq, hash).expect("in the horizon");
        let entry = bc.blocks.get(idx).expect("held");
        assert_eq!(entry.parent_ref(), below_idx);
        assert!(entry.is_on_active_chain(), "D1: the horizon keeps the flag");
        below_idx = idx;
    }
    let tail = bc.blocks.get(bc.snake_chain_tail_idx).expect("tail");
    assert_eq!(tail.sequence(), 102);
    assert_eq!(tail.parent_ref(), below_idx, "the tail stays linked");

    // FR58: the branch forked at #102 left the bound with #106's
    // extension; the one forked at #103 with #107's.
    assert!(slot_of(&bc, 103, &fork_a).is_none(), "#102 fork deleted");
    assert!(
        slot_of(&bc, 104, &fork_a_child).is_none(),
        "with its descendant"
    );
    assert!(slot_of(&bc, 104, &fork_b).is_none(), "#103 fork deleted");
    let keep_idx = slot_of(&bc, 105, &keep).expect("in-bound fork retained");
    let b104_idx = slot_of(&bc, 104, &h[4]).expect("#104");
    assert_eq!(
        bc.blocks.get(keep_idx).map(|e| e.parent_ref()),
        Some(b104_idx),
        "still attached to #104, the bound"
    );
    assert!(slot_of(&bc, 106, &b106).is_some(), "#106");
    assert_eq!(
        bc.block_tree_len(),
        10,
        "#99..#101 in the horizon, #102..#107, and the #104 fork"
    );

    // No head is left asking for a parent.
    assert!(!bc.chain_heads.has_stored_head());
    assert_eq!(
        bc.chain_heads.count(),
        2,
        "the active head and the #104 fork"
    );
    let (outcome, _) = bc.on_tick(u64::MAX / 2);
    assert!(!matches!(
        outcome,
        TickOutcome::SendParentRecoveryRequest(_)
    ));
}

/// Review r2 (DEC-127) — a Collecting genesis anchor that the adopted chain
/// does not contain loses its flag at the promotion and is reclaimed at
/// Ready entry, so its branch neither looks Connected nor lingers. Live
/// path: only block #0 arrived, so the genesis branch names no
/// configuration and FR2 adopts a window-anchored segment instead. Also
/// pins that the head recompute runs before the Ready-entry reclamation.
#[test]
fn snake_ready_entry_reclaims_a_genesis_island() {
    let mut bc = new_w6_chain();
    let genesis = genesis_zero_block(1_037);
    let (outcome, _) = bc.receive_block(genesis.view(), 0);
    assert_eq!(outcome, ReceiveBlockOutcome::AcceptedSilently);
    let gi = slot_of(&bc, 0, &genesis.view().hash()).expect("genesis stored");
    assert!(
        bc.blocks.get(gi).is_some_and(|e| e.is_on_active_chain()),
        "precondition: the Collecting bootstrap anchor"
    );
    let below = w6_horizon_block();
    for block in &w6_below() {
        bc.receive_block(block.view(), 0);
    }
    let anchor = w6_config_anchor_block(100, below.view().hash());
    bc.receive_block(anchor.view(), 0);
    let mut prev = anchor.view().hash();
    for seq in 101..=105 {
        let blk = linked_transfer_block(seq, prev);
        prev = blk.view().hash();
        bc.receive_block(blk.view(), 0);
    }
    assert!(bc.is_ready(), "the window-anchored segment won");
    assert_eq!(bc.active_snake_chain_window(), Ok((100, 105)));
    assert!(
        slot_of(&bc, 0, &genesis.view().hash()).is_none(),
        "island reclaimed"
    );
    assert_eq!(bc.block_tree_len(), 9, "#97..#105");
    assert_eq!(bc.chain_heads.count(), 1, "only the active head");
    assert!(!bc.chain_heads.has_stored_head());
}

/// FR58 fragment reclamation (DEC-161 as tightened by DEC-208): at a head
/// extension, a Stored fragment whose missing parent lies at `q ≤ S_head −
/// H` is deleted whole — the retained active block at `q` would have
/// linked it, so it diverges outside the bound — and one with `q > S_head −
/// H` may still connect and stays. Both are admitted in Ready before the
/// extension (`S_new > S_head − H` at admission).
#[test]
fn snake_extension_reclaims_fragments_that_can_never_connect() {
    let (mut bc, h) = w6_ready_on_segment(105);
    // After the extension, S_head − H = 103.
    let stale = node_transfer_block(104, 3, 103, 7); // q = 103
    let alive = node_transfer_block(105, 3, 104, 7); // q = 104
    for blk in [&stale, &alive] {
        let (outcome, _) = bc.receive_block(blk.view(), 0);
        assert_eq!(outcome, ReceiveBlockOutcome::AcceptedSilently);
    }
    let stored_before: [Option<u32>; 4] =
        core::array::from_fn(|s| bc.chain_heads.stored_head_tail(s));
    assert_eq!(stored_before.iter().flatten().count(), 2, "precondition");

    let b106 = w6_extension(&bc, 106, h[5]);
    extend_active_head(&mut bc, &b106, 0);
    assert_eq!(bc.active_snake_chain_window(), Ok((101, 106)));

    assert!(
        slot_of(&bc, 104, &stale.view().hash()).is_none(),
        "stale fragment deleted"
    );
    let alive_idx = slot_of(&bc, 105, &alive.view().hash()).expect("may still connect");
    let stored_after: [Option<u32>; 4] =
        core::array::from_fn(|s| bc.chain_heads.stored_head_tail(s));
    assert_eq!(
        stored_after.iter().flatten().count(),
        1,
        "only the live fragment is Stored"
    );
    assert!(stored_after.contains(&Some(alive_idx)));
    // The active chain and the horizon are untouched by the reclamation.
    let [_, b98, b99] = w6_below();
    assert!(slot_of(&bc, 98, &b98.view().hash()).is_some(), "#98 kept");
    assert!(slot_of(&bc, 99, &b99.view().hash()).is_some(), "#99 kept");
    for (i, seq) in (100..=106).enumerate() {
        let hash = if seq == 106 { b106.view().hash() } else { h[i] };
        assert!(slot_of(&bc, seq, &hash).is_some(), "active #{seq} kept");
    }
}

/// AC10.8 — AR16 replay (FR63): the same event sequence twice gives
/// identical tail positions, releases, classifications and decisions,
/// whatever the wall clock reads.
#[test]
fn snake_drive_is_replay_deterministic() {
    let (first, a, _) = drive_past_w(1_000);
    let (second, b, _) = drive_past_w(9_999_999);
    assert_eq!(first, second);
    assert_eq!(a.active_snake_chain_window(), b.active_snake_chain_window());
    assert_eq!(a.snake_chain_tail_idx, b.snake_chain_tail_idx);
}

/// AC10.5 / AC4 — FR60 goes live through the real `receive_block` path: a
/// block at `S_head + W` or beyond, or below `S_tail`, is `OutOfWindow`.
#[test]
fn snake_fr60_window_is_live_in_ready() {
    // Genesis on W = 16: window (0, 1).
    let mut bc = genesis_node_with_window(16);
    let (outcome, _) = bc.receive_block(node_transfer_block(17, 3, 16, 7).view(), 0);
    assert_eq!(
        outcome,
        ReceiveBlockOutcome::Rejected(RejectReason::OutOfWindow)
    );
    let (outcome, _) = bc.receive_block(node_transfer_block(16, 3, 15, 7).view(), 0);
    assert_eq!(
        outcome,
        ReceiveBlockOutcome::AcceptedSilently,
        "S_head + W - 1"
    );

    // W = 6, entered Ready on 97..=106 → window (101, 106).
    let (mut bc, _) = w6_ready_on_segment(106);
    assert_eq!(bc.active_snake_chain_window(), Ok((101, 106)));
    let below = node_transfer_block(100, 3, 99, 7);
    let (outcome, _) = bc.receive_block(below.view(), 0);
    assert_eq!(
        outcome,
        ReceiveBlockOutcome::Rejected(RejectReason::OutOfWindow),
        "below S_tail — a block at #100, the horizon's sequence"
    );
    let (outcome, _) = bc.receive_block(node_transfer_block(112, 3, 111, 7).view(), 0);
    assert_eq!(
        outcome,
        ReceiveBlockOutcome::Rejected(RejectReason::OutOfWindow)
    );
    let (outcome, _) = bc.receive_block(node_transfer_block(111, 3, 110, 7).view(), 0);
    assert_eq!(outcome, ReceiveBlockOutcome::AcceptedSilently);
}

/// AC10.9 / AC1 — every site that clears or resets the active head clears
/// the tail, and the tail is `NONE_REF` whenever the phase is not Ready.
/// Each reset path is entered with a tail deliberately set, so the clear is
/// what is under test, not the starting value.
#[test]
fn snake_reset_sites_clear_the_tail() {
    // Tier-1 genesis anchor (Collecting).
    let mut bc = new_test_chain();
    bc.snake_chain_tail_idx = 3;
    let genesis = genesis_zero_block(1_037);
    let gi = bc
        .tier1_admit(&genesis.view(), &genesis.view().hash(), 0)
        .expect("genesis admitted");
    assert!(!bc.is_ready());
    assert_eq!(bc.snake_chain_tail_idx, NONE_REF);

    // FR5 recovery (Processing → Collecting).
    bc.set_lifecycle_phase(LifecyclePhase::Processing);
    bc.snake_chain_tail_idx = gi;
    bc.recover_from_failed_pass(ProcessingError::MissingBlock, gi);
    assert!(!bc.is_ready());
    assert_eq!(bc.snake_chain_tail_idx, NONE_REF);

    // Restart rebuild.
    let mut bc = new_test_chain();
    bc.snake_chain_tail_idx = 0;
    bc.rebuild_block_tree_from_storage(0);
    assert!(!bc.is_ready());
    assert_eq!(bc.snake_chain_tail_idx, NONE_REF);

    // Subtree deletion that takes the active head. Production reaches it
    // only outside Ready (the FR8 adopt path runs in Processing), so the
    // node is put there; the tail is the genesis window's.
    let mut bc = genesis_node_with_window(16);
    assert_ne!(bc.snake_chain_tail_idx, NONE_REF);
    bc.lifecycle_phase = LifecyclePhase::Processing;
    let head = bc.active_chain_head_idx;
    bc.delete_subtree_with_followup(head);
    assert!(!bc.is_ready());
    assert_eq!(bc.active_chain_head_idx, NONE_REF);
    assert_eq!(bc.snake_chain_tail_idx, NONE_REF);
}

/// AC3 + Ratified Decision 3; Story 6.14 AC6 — a released block's durable
/// bytes survive (lazy release), so a restart re-admits it, and the Ready
/// re-entry releases it again: the restarted node holds the same window
/// and the same horizon.
#[test]
fn snake_restart_rereleases_a_resurrected_tail_block() {
    let (bc, h) = w6_ready_on_segment(106);
    assert_eq!(bc.block_tree_len(), 9);
    let [lowest, b98, _] = w6_below();
    assert!(
        slot_of(&bc, 97, &lowest.view().hash()).is_none(),
        "#97 released"
    );
    let storage = bc.storage;
    let crypto = Crypto::new([1u8; PRIVATE_KEY_SIZE]).ok().expect("key");
    let chain_config = empty_chain_config(W6Chain::BUILD_LIMITS);
    let node_zero = *crypto.public_key().serialize();
    let mut slot = core::mem::MaybeUninit::uninit();
    W6Chain::init(&mut slot, crypto, storage, chain_config, 5, node_zero, 0);
    // SAFETY: `init` returned, so every field of `slot` is initialized.
    let mut restarted = unsafe { slot.assume_init() };
    restarted.initialize_from_storage(500);
    assert!(restarted.is_ready());
    assert_eq!(restarted.active_snake_chain_window(), Ok((101, 106)));
    assert_eq!(restarted.block_tree_len(), 9);
    assert!(slot_of(&restarted, 97, &lowest.view().hash()).is_none());
    let root = slot_of(&restarted, 98, &b98.view().hash()).expect("#98 in the horizon");
    assert_eq!(restarted.horizon_root(), root);
    assert!(
        slot_of(&restarted, 100, &h[0]).is_some(),
        "#100 in the horizon"
    );
}

// ===================================================================
// Story 6.14 — verification horizon, FR58 bound, W + H, FR3 binding
// ===================================================================

/// Admits `blocks` on a Collecting W6 node through Tier 1 only, without the
/// FR2 hook, so a test can run the pass on a tip of its choice.
fn admit_all(bc: &mut W6Chain, blocks: &[&Block]) {
    for blk in blocks {
        let view = blk.view();
        bc.tier1_admit(&view, &view.hash(), 0).expect("admitted");
    }
}

/// AC9 / AC12.8 — the FR3 pass evaluates the FR48 binding of every block
/// whose dropped block lies in the segment, and a skipped replay is exact
/// evidence (DEC-204). Genesis-anchored (a founder's FR54 genesis, built by
/// the founder): #6 replays node #0's seed source #0, and #7 drops the
/// chain-config block #1; the clean slots #2 and #5 (Story 6.7 D8) hold
/// node-#0 transfers, as does the skip. Window-anchored with `a = 97`:
/// #106 drops #100 (`s ≥ a + W`); #103..=#105 drop #97..=#99, which carry
/// nothing, and #101, #102 drop blocks below the segment (pre-window
/// trust).
#[test]
fn fr3_pass_evaluates_the_binding_inside_the_segment() {
    let (mut founder, g, c1) = w6_founder();
    let mut prev = c1.view().hash();
    let mut chain = std::vec![g, c1];
    for seq in 2..=6 {
        let blk = match seq {
            6 => w6_balance_block(Some(&founder), seq, prev),
            _ if seq % 3 == 2 => w6_clean_block(seq, prev),
            _ => w6_config_anchor_block(seq, prev),
        };
        assert_eq!(
            founder.receive_block(blk.view(), 0).0,
            ReceiveBlockOutcome::AcceptedSilently
        );
        prev = blk.view().hash();
        chain.push(blk);
    }
    let skip = w6_clean_block(7, prev);
    let replay = w6_config_anchor_block(7, prev);
    let mut bc = new_w6_chain();
    let refs: std::vec::Vec<&Block> = chain.iter().chain([&skip, &replay]).collect();
    admit_all(&mut bc, &refs);
    let si = bc.blocks.find(7, &skip.view().hash()).expect("stored");
    assert!(matches!(
        bc.run_processing_pass(si),
        Err(ProcessingError::Invalid {
            block_idx,
            reason: ValidationReason::TailDropUnpreserved,
        }) if block_idx == si
    ));
    let ri = bc.blocks.find(7, &replay.view().hash()).expect("stored");
    assert!(
        bc.run_processing_pass(ri).is_ok(),
        "the chain-config replay preserves #1"
    );
    // Through the acquisition: FR5 deletes only the offender, and the node
    // enters Ready on the prefix.
    let mut bc = new_w6_chain();
    let refs: std::vec::Vec<&Block> = chain.iter().chain([&skip]).collect();
    admit_all(&mut bc, &refs);
    bc.drive_dominant_chain_acquisition();
    assert!(bc.is_ready());
    assert!(
        bc.blocks.find(7, &skip.view().hash()).is_none(),
        "offender deleted"
    );
    assert_eq!(
        bc.blocks.get(bc.active_chain_head_idx).map(|e| *e.hash()),
        Some(prev)
    );
    assert_eq!(
        bc.block_tree_len(),
        7,
        "#0 in the horizon, #1..#6 the window"
    );

    let mut bc = new_w6_chain();
    let [b97, b98, below] = w6_below();
    let c100 = w6_config_anchor_block(100, below.view().hash());
    let b101 = linked_transfer_block(101, c100.view().hash());
    let b102 = linked_transfer_block(102, b101.view().hash());
    let b103 = linked_transfer_block(103, b102.view().hash());
    let b104 = linked_transfer_block(104, b103.view().hash());
    let b105 = linked_transfer_block(105, b104.view().hash());
    let skip = linked_transfer_block(106, b105.view().hash());
    admit_all(
        &mut bc,
        &[
            &b97, &b98, &below, &c100, &b101, &b102, &b103, &b104, &b105, &skip,
        ],
    );
    let si = bc.blocks.find(106, &skip.view().hash()).expect("stored");
    assert!(matches!(
        bc.run_processing_pass(si),
        Err(ProcessingError::Invalid {
            block_idx,
            reason: ValidationReason::TailDropUnpreserved,
        }) if block_idx == si
    ));
    let ti = bc.blocks.find(105, &b105.view().hash()).expect("stored");
    assert!(bc.run_processing_pass(ti).is_ok());
}

/// AC8 / AC12.9 (DEC-177) — on a window-anchored candidate with `a = 99`
/// and `H = 3`, node #3's vote is seeded by its first entry at or after
/// #102 (the entry at #102): before it, its forged header at #101 is
/// auto-accepted and the D9 vote compare is skipped; after it, its forged
/// header at #103 is judged and refused.
#[test]
fn fr3_pass_seeds_a_window_anchored_vote_at_a_plus_h() {
    let mut bc = new_w6_chain();
    let floor = balance_block(99, [0xAB; 32], &[(3, 0, 0, 0x33)], 3);
    let cfg = w6_config_anchor_block(100, floor.view().hash());
    let early = headed(
        101,
        cfg.view().hash(),
        3,
        1,
        777,
        3,
        0,
        votes_for(101, 3, 1, 40),
    );
    // The vote seed: the entry repeats #3's balance (credited #101's fee)
    // and states a vote the pass never derived.
    let seed = balance_block(102, early.view().hash(), &[(3, 1, 1000, 0x33)], 3);
    let tip = tx_block(103, seed.view().hash(), 0, votes_for(103, 3, 1, 41));
    let late = headed(
        103,
        seed.view().hash(),
        3,
        1,
        777,
        3,
        0,
        votes_for(103, 3, 1, 42),
    );
    admit_all(&mut bc, &[&floor, &cfg, &early, &seed, &tip, &late]);
    let ti = bc.blocks.find(103, &tip.view().hash()).expect("stored");
    assert!(
        bc.run_processing_pass(ti).is_ok(),
        "the forged header before the vote seed is auto-accepted"
    );
    let li = bc.blocks.find(103, &late.view().hash()).expect("stored");
    assert!(matches!(
        bc.run_processing_pass(li),
        Err(ProcessingError::Invalid {
            block_idx,
            reason: ValidationReason::VoteHeaderMismatch,
        }) if block_idx == li
    ));
}

/// AC5 / AC12.5 (DEC-208) — Ready intake refuses a block at `S_new ≤ S_head
/// − H` as Out-of-Snake-Chain-Window and stores nothing: a late child of a
/// window block and a late child of a horizon block. A re-sent horizon
/// block is already known; a fork inside the bound is admitted.
#[test]
fn ready_intake_refuses_blocks_outside_the_switch_bound() {
    let (mut bc, h) = w6_ready_on_segment(105);
    let len = bc.block_tree_len();
    let late = salted_linked_block(102, h[1], 9);
    let below = w6_horizon_block();
    let under = salted_linked_block(100, below.view().hash(), 9);
    for blk in [&late, &under] {
        assert_eq!(
            bc.receive_block(blk.view(), 0).0,
            ReceiveBlockOutcome::Rejected(RejectReason::OutOfWindow)
        );
    }
    assert_eq!(bc.block_tree_len(), len, "nothing stored");
    assert_eq!(
        bc.receive_block(below.view(), 0).0,
        ReceiveBlockOutcome::DuplicateKnown
    );
    let fork = salted_linked_block(103, h[2], 9);
    admit_fork(&mut bc, &fork, 0);
    assert_eq!(bc.block_tree_len(), len + 1);
}

/// Every block below `S_tail` is a flagged, Active block of the active
/// path, `H` of them, and the root's only child is its successor (D1,
/// DEC-206) — after advances and reclamation, and after a restart.
fn assert_horizon_is_the_active_path(bc: &W6Chain, h: u32) {
    let (s_tail, _) = bc.active_snake_chain_window().expect("Ready");
    let mut below = 0;
    for idx in 0..16u32 {
        if let Some(entry) = bc.blocks.get(idx)
            && entry.sequence() < s_tail
        {
            below += 1;
            assert!(entry.is_on_active_chain());
            assert_eq!(entry.status(), BlockStatus::Active);
        }
    }
    assert_eq!(below, h);
    let root = bc.horizon_root();
    let children = (0..16u32)
        .filter(|&idx| bc.blocks.get(idx).is_some_and(|e| e.parent_ref() == root))
        .count();
    assert_eq!(children, 1, "the root's only child is its successor");
}

/// AC12.3 — the D1 invariant: the horizon holds only the active path.
#[test]
fn the_horizon_holds_only_the_active_path() {
    let (_, bc, _) = drive_past_w(1_000);
    assert_horizon_is_the_active_path(&bc, 3);

    let storage = bc.storage;
    let crypto = Crypto::new([1u8; PRIVATE_KEY_SIZE]).ok().expect("key");
    let chain_config = empty_chain_config(W6Chain::BUILD_LIMITS);
    let node_zero = *crypto.public_key().serialize();
    let mut slot = core::mem::MaybeUninit::uninit();
    W6Chain::init(&mut slot, crypto, storage, chain_config, 5, node_zero, 0);
    // SAFETY: `init` returned, so every field of `slot` is initialized.
    let mut restarted = unsafe { slot.assume_init() };
    restarted.initialize_from_storage(500);
    assert!(restarted.is_ready());
    assert_eq!(restarted.active_snake_chain_window(), Ok((102, 107)));
    assert_horizon_is_the_active_path(&restarted, 3);

    // AC12.6 — the restarted node's projections equal a fresh node's fed
    // the same retained blocks.
    let mut fresh = new_w6_chain();
    let mut buf = [0u8; MAX_BLOCK_SIZE];
    for idx in 0..16u32 {
        // The exact stored length, as the node itself reads it back.
        if let Some(view) = restarted.view_retained(idx, &mut buf) {
            fresh.receive_block(view, 0);
        }
    }
    assert!(fresh.is_ready());
    assert_eq!(
        fresh.active_snake_chain_window(),
        restarted.active_snake_chain_window()
    );
    let hash_at = |bc: &W6Chain, idx: u32| bc.blocks.get(idx).map(|e| *e.hash());
    assert_eq!(
        hash_at(&fresh, fresh.active_chain_head_idx),
        hash_at(&restarted, restarted.active_chain_head_idx)
    );
    assert_eq!(
        hash_at(&fresh, fresh.horizon_root()),
        hash_at(&restarted, restarted.horizon_root())
    );
    // Node #0's seed source is #102, held at different slots by the two
    // nodes (they admitted the blocks in different orders), so the node
    // projections are compared through the blocks the pointers name.
    assert_same_nodes(&fresh, &restarted);
    assert!(fresh.vote_engine == restarted.vote_engine);
    assert_eq!(fresh.active_branch_value, restarted.active_branch_value);
}

/// AC12.6 (Story 6.14) on an FR50-complete projection (Story 6.7): a
/// released block below the horizon (#98) that moves node 3's vote, and a
/// restart that re-admits it from its intact slot and derives over it,
/// still give a fresh node's projection — node 3's latest seed source
/// (#102) lies in the window, as FR50 keeps every registered node's, so
/// both seed it there and nothing below it reaches the head. (The shared
/// W6 segment seeds only node #0; there an unseeded node's inexact vote
/// depends on the anchor, which is why its blocks below the window move
/// no vote.)
#[test]
fn a_restart_equals_a_fresh_node_once_every_vote_is_seeded() {
    let b97 = salted_linked_block(97, [0xAB; 32], 0);
    let b98 = salted_linked_block(98, b97.view().hash(), 3);
    let b99 = salted_linked_block(99, b98.view().hash(), 0);
    let mut bc = new_w6_chain();
    for below in [&b97, &b98, &b99] {
        bc.tier1_admit(&below.view(), &below.view().hash(), 0)
            .expect("below the window");
    }
    let mut prev = w6_config_anchor_block(100, b99.view().hash());
    bc.tier1_admit(&prev.view(), &prev.view().hash(), 0)
        .expect("anchor");
    for seq in 101..=105 {
        let blk = if seq == 102 {
            balance_block(seq, prev.view().hash(), &[(0, 0, 0, 1), (3, 0, 0, 1)], 9)
        } else {
            linked_transfer_block(seq, prev.view().hash())
        };
        bc.tier1_admit(&blk.view(), &blk.view().hash(), 0)
            .expect("segment block");
        prev = blk;
    }
    bc.drive_dominant_chain_acquisition();
    assert!(bc.is_ready());
    assert!(bc.node_info.is_seeded(3), "node 3 is seeded at #102");
    for seq in [106, 107] {
        let next = w6_extension(&bc, seq, prev.view().hash());
        extend_active_head(&mut bc, &next, 0);
        prev = next;
    }
    assert_eq!(bc.active_snake_chain_window(), Ok((102, 107)));

    let storage = bc.storage;
    let crypto = Crypto::new([1u8; PRIVATE_KEY_SIZE]).ok().expect("key");
    let chain_config = empty_chain_config(W6Chain::BUILD_LIMITS);
    let node_zero = *crypto.public_key().serialize();
    let mut slot = core::mem::MaybeUninit::uninit();
    W6Chain::init(&mut slot, crypto, storage, chain_config, 5, node_zero, 0);
    // SAFETY: `init` returned, so every field of `slot` is initialized.
    let mut restarted = unsafe { slot.assume_init() };
    restarted.initialize_from_storage(500);
    assert!(restarted.is_ready());

    let mut fresh = new_w6_chain();
    let mut buf = [0u8; MAX_BLOCK_SIZE];
    for idx in 0..16u32 {
        if let Some(view) = restarted.view_retained(idx, &mut buf) {
            fresh.receive_block(view, 0);
        }
    }
    assert!(fresh.is_ready());
    assert_same_nodes(&fresh, &restarted);
    assert!(fresh.vote_engine == restarted.vote_engine);
    assert_eq!(fresh.active_branch_value, restarted.active_branch_value);
}

/// Compares two W6 nodes node by node (all 16) and block by block: the
/// derived state a chain switch must leave exactly as a fresh pass does.
/// Seed sources are compared by the block they name, not by slot.
fn assert_same_nodes(a: &W6Chain, b: &W6Chain) {
    let source = |bc: &W6Chain, node: u32| match bc.node_info.seed_source_of(node) {
        Some(SEED_SOURCE_RELEASED) | None => None,
        Some(slot) => bc.blocks.get(slot).map(|e| *e.hash()),
    };
    for node in 0..16 {
        assert_eq!(a.node_info.balance_of(node), b.node_info.balance_of(node));
        assert_eq!(
            a.vote_engine.accumulated_vote_of(node),
            b.vote_engine.accumulated_vote_of(node)
        );
        assert_eq!(
            a.node_info.public_key_of(node),
            b.node_info.public_key_of(node)
        );
        assert_eq!(a.node_info.is_seeded(node), b.node_info.is_seeded(node));
        assert_eq!(source(a, node), source(b, node), "node {node}: seed source");
    }
    assert_eq!(
        a.node_info.max_known_node_id(),
        b.node_info.max_known_node_id()
    );
    for idx in 0..16u32 {
        if let Some(entry) = a.blocks.get(idx)
            && let Some(other) = b.blocks.find(entry.sequence(), entry.hash())
        {
            assert_eq!(
                a.blocks.has_available_utxo(idx),
                b.blocks.has_available_utxo(other)
            );
        }
    }
    assert_eq!(a.active_branch_value, b.active_branch_value);
    assert_eq!(a.active_snake_chain_window(), b.active_snake_chain_window());
}

/// AC4 / AC12.4 / AC5 (DEC-211, DEC-208) — a switch on a window-anchored
/// node may undo the balance block that seeded nodes in its FR3 pass: the
/// head #102 floor-seeds node #4 and vote-seeds node #3 (`a = 94`, `H = 3`,
/// #3 floor-seeded at #96; [`vote_seed_prefix`]). The undo is identity on
/// the values, so the switched node ends where a node that joined the new
/// chain directly ends — the ground truth, since a fresh pass on honest
/// blocks is (Story 6.0's FR3 equivalence). A forged sibling of the winner is
/// refused by the replay and leaves the node exactly as it was; the winner
/// arrives as a four-block branch, and the commit's sweep deletes the
/// demoted head.
#[test]
fn a_switch_undoes_seed_points_as_identity() {
    let prefix = vote_seed_prefix(4);
    let b101 = &prefix[7];
    let entries = [(3, 1, 1000, 0x33), (4, 70, 500, 0x34)];
    let seed = balance_block(102, b101.view().hash(), &entries, 4);
    let joiner = || {
        let mut bc = new_w6_chain();
        for blk in prefix.iter().chain([&seed]) {
            assert_eq!(
                bc.receive_block(blk.view(), 0).0,
                ReceiveBlockOutcome::AcceptedSilently
            );
        }
        assert!(bc.is_ready());
        assert_eq!(bc.active_snake_chain_window(), Ok((97, 102)));
        bc
    };
    let (mut j, replica) = (joiner(), joiner());

    // The winner: the same replay by #3, worth its real vote at #101.
    let replay = balance_block(102, b101.view().hash(), &entries, 4);
    let f102 = resign(&replay, 3, vote_snapshot(1000), 1);
    assert!(v(&f102) > v(&seed), "the replay by #3 outranks the head");

    // A forged sibling: attempted, refused by the replay (I-09), restored.
    let forged = resign(&replay, 3, vote_snapshot(1000) + 1, 1);
    assert_eq!(
        j.receive_block(forged.view(), 0).0,
        ReceiveBlockOutcome::AcceptedSilently
    );
    assert!(
        j.blocks.find(102, &forged.view().hash()).is_none(),
        "deleted"
    );
    assert!(j.node_info == replica.node_info);
    assert!(j.vote_engine == replica.vote_engine);
    assert_eq!(j.active_branch_value, replica.active_branch_value);

    // The ground truth: a node that joins the new chain directly.
    let mut direct = new_w6_chain();
    for blk in prefix.iter().chain([&f102]) {
        assert_eq!(
            direct.receive_block(blk.view(), 0).0,
            ReceiveBlockOutcome::AcceptedSilently
        );
    }
    assert!(direct.is_ready());
    // #103 replays the chain-config block #97 it drops; #104 is a clean
    // slot (Story 6.7 D8): node #4, seeded by #102 with 70, transfers
    // nothing to itself; #105 is any block.
    let f103 = real_on(
        &direct,
        &w6_config_anchor_block(103, f102.view().hash()),
        0,
        1,
    );
    extend_active_head(&mut direct, &f103, 0);
    let signer = Crypto::new([1u8; PRIVATE_KEY_SIZE]).ok().expect("test key");
    let idle = NodeTransfer::new_signed(0, 103, 4, 4, 0, 0, 0, &signer);
    let f104 = real_on(
        &direct,
        &tx_block(104, f103.view().hash(), 0, |b| {
            b.add_node_transfer(&idle).ok().expect("add transfer");
        }),
        0,
        1,
    );
    extend_active_head(&mut direct, &f104, 0);
    let f105 = real_on(
        &direct,
        &w6_config_anchor_block(105, f104.view().hash()),
        0,
        1,
    );
    extend_active_head(&mut direct, &f105, 0);

    // The four-block branch, orphan first: the switch goes to #105
    // across both seed points.
    for blk in [&f105, &f104, &f103, &f102] {
        assert_eq!(
            j.receive_block(blk.view(), 0).0,
            ReceiveBlockOutcome::AcceptedSilently
        );
    }
    assert_eq!(
        j.blocks.get(j.active_chain_head_idx).map(|e| *e.hash()),
        Some(f105.view().hash()),
        "switched across the seed points"
    );
    assert!(
        j.blocks.find(102, &seed.view().hash()).is_none(),
        "the demoted head forks at #101 = S_head − H − 1: swept at the commit"
    );
    assert_same_nodes(&j, &direct);
}

/// AC12.3 — a block that enters the horizon keeps its available-UTXO bits;
/// they leave with its slot when it leaves the horizon.
#[test]
fn a_horizon_block_keeps_its_available_utxo_bits() {
    let (mut bc, h) = w6_ready_on_segment(105);
    let slot_100 = slot_of(&bc, 100, &h[0]).expect("#100");
    assert!(bc.blocks.set_utxo_available(slot_100, 0, true));
    let mut prev = h[5];
    for seq in 106..=108 {
        let blk = w6_extension(&bc, seq, prev);
        extend_active_head(&mut bc, &blk, 0);
        prev = blk.view().hash();
        assert_eq!(bc.active_snake_chain_window(), Ok((seq - 5, seq)));
        assert_eq!(
            bc.blocks.utxo_available(slot_100, 0),
            Some(true),
            "kept in the horizon (H = 3)"
        );
    }
    let b109 = w6_extension(&bc, 109, prev);
    extend_active_head(&mut bc, &b109, 0);
    assert!(slot_of(&bc, 100, &h[0]).is_none(), "#100 left the horizon");
    assert_ne!(bc.blocks.utxo_available(slot_100, 0), Some(true));
}

/// AC12.2 — the configured `H` reaches the bound: the same late block is
/// refused at `H = 3` and admitted at `H = 4`. The W6 harness admits only
/// `H = 3` (configuration §6 check 21: `H ≥ 3` divides `W`), and 12 is the
/// smallest window with two adjacent legal horizons, so the pair runs on a
/// genesis chain of `TestChain`, whose capacity holds it: the head is #6
/// and the late block a child of #2, at `S_new = S_head − 3`. Every block
/// is a plain transfer, clean on either horizon's slots (Story 6.7 D8).
#[test]
fn the_configured_horizon_reaches_the_bound() {
    for (h, expected) in [
        (3, ReceiveBlockOutcome::Rejected(RejectReason::OutOfWindow)),
        (4, ReceiveBlockOutcome::AcceptedSilently),
    ] {
        let (crypto, storage, chain_config) = test_backends();
        let mut bc = new_chain(crypto, storage, chain_config, 0, 0);
        let genesis = bc
            .process_genesis(CURRENCY, window_horizon_config_builder(12, h).content())
            .ok()
            .expect("genesis succeeds");
        let mut prev = genesis.block_one.view().hash();
        let mut at_two = prev;
        for seq in 2..=6 {
            let blk = transfer(seq, prev, 0, 7);
            assert_eq!(
                receive(&mut bc, &blk),
                ReceiveBlockOutcome::AcceptedSilently
            );
            prev = blk.view().hash();
            if seq == 2 {
                at_two = prev;
            }
        }
        assert_eq!(head_of(&bc), (6, prev));
        let late = transfer(3, at_two, 0, 8);
        assert_eq!(receive(&mut bc, &late), expected, "H = {h}");
    }
}

/// AC12.3 / AC5 — Ready entry reclaims a branch forked below `S_head − H`
/// that was retained while collecting.
#[test]
fn ready_entry_reclaims_a_deep_fork() {
    let mut bc = new_w6_chain();
    let [b97, b98, below] = w6_below();
    let anchor = w6_config_anchor_block(100, below.view().hash());
    let b101 = linked_transfer_block(101, anchor.view().hash());
    let b102 = linked_transfer_block(102, b101.view().hash());
    let b103 = linked_transfer_block(103, b102.view().hash());
    let b104 = linked_transfer_block(104, b103.view().hash());
    let b105 = linked_transfer_block(105, b104.view().hash());
    let deep = salted_linked_block(102, b101.view().hash(), 5);
    admit_all(
        &mut bc,
        &[
            &b97, &b98, &below, &anchor, &b101, &deep, &b102, &b103, &b104, &b105,
        ],
    );
    bc.drive_dominant_chain_acquisition();
    assert!(bc.is_ready());
    assert_eq!(
        bc.blocks.get(bc.active_chain_head_idx).map(|e| *e.hash()),
        Some(b105.view().hash())
    );
    assert!(
        bc.blocks.find(102, &deep.view().hash()).is_none(),
        "forked at #101 ≤ S_head − H − 1"
    );
    assert_eq!(bc.block_tree_len(), 9);
    assert_eq!(bc.chain_heads.count(), 1);
}

/// Review patch — a young genesis chain (`S_head + 1 < H`) still reclaims a
/// fragment whose missing parent is at or below its tail (#0): it can
/// never arrive, being a second genesis (Story 9.1's criterion).
#[test]
fn a_young_chain_reclaims_a_fragment_below_its_tail() {
    let (mut bc, _, b1) = ready_genesis(16);
    let stray = node_transfer_block(1, 3, 0, 7);
    assert_eq!(
        receive(&mut bc, &stray),
        ReceiveBlockOutcome::AcceptedSilently
    );
    assert!(bc.chain_heads.has_stored_head(), "precondition: a fragment");
    let b2 = transfer(2, b1.view().hash(), 0, 7);
    assert_eq!(receive(&mut bc, &b2), ReceiveBlockOutcome::AcceptedSilently);
    assert_eq!(head_of(&bc), (2, b2.view().hash()));
    assert!(
        bc.blocks.find(1, &stray.view().hash()).is_none(),
        "reclaimed at the extension"
    );
    assert!(!bc.chain_heads.has_stored_head());
}

/// The window-anchored W6 prefix `#94..=#101` below a vote seed at #102:
/// node-#0 self-transfers voting for node #0 at #94, #95, #98 and #99
/// (clean, so #95 and #98 may be slots, Story 6.7 D8), the floor #96 (a
/// balance block floor-seeding node #3, `max_node_id` given, whose drop
/// the #102 balance block replays), the chain-config block #97 (the window
/// tail at #102), node #3's forged-vote header `early` at #100, and #101
/// (votes for #3, a slot). A join on #94..=#102 is `W + H = 9` blocks,
/// `a = 94`, so node #3's vote is seeded at its first entry at or after
/// `a + H = 97`.
fn vote_seed_prefix(max_node_id: u32) -> [Block; 8] {
    let p94 = tx_block(94, [0xAB; 32], 0, votes_for(94, 0, 1, 50));
    let p95 = tx_block(95, p94.view().hash(), 0, votes_for(95, 0, 1, 51));
    let floor = balance_block(96, p95.view().hash(), &[(3, 0, 0, 0x33)], max_node_id);
    let cfg = w6_config_anchor_block(97, floor.view().hash());
    let p98 = tx_block(98, cfg.view().hash(), 0, votes_for(98, 0, 1, 52));
    let p99 = tx_block(99, p98.view().hash(), 0, votes_for(99, 0, 1, 53));
    let early = headed(
        100,
        p99.view().hash(),
        3,
        1,
        777,
        3,
        0,
        votes_for(100, 3, 1, 40),
    );
    let b101 = tx_block(101, early.view().hash(), 0, votes_for(101, 3, 1, 41));
    [p94, p95, floor, cfg, p98, p99, early, b101]
}

/// The D6 scenario's admissions at wall clock `now`, then one extension
/// past the switch (a horizon release): the joiner's head, window, root,
/// tree size, values and the two nodes' derived state.
fn switch_across_a_vote_seed(now: u64) -> (W6Chain, [u8; 32]) {
    let prefix = vote_seed_prefix(3);
    let b101 = &prefix[7];
    let seed = balance_block(102, b101.view().hash(), &[(3, 1, 1000, 0x33)], 3);
    let replay = balance_block(102, b101.view().hash(), &[(3, 1, 1000, 0x33)], 3);
    let f102 = resign(&replay, 3, vote_snapshot(1000), 1);
    let mut bc = new_w6_chain();
    for blk in prefix.iter().chain([&seed, &f102]) {
        assert_eq!(
            bc.receive_block(blk.view(), now).0,
            ReceiveBlockOutcome::AcceptedSilently
        );
    }
    let cfg103 = real_on(&bc, &w6_config_anchor_block(103, f102.view().hash()), 0, 1);
    extend_active_head(&mut bc, &cfg103, now);
    (bc, f102.view().hash())
}

/// AC11 — AR16 replay (FR63, NFR5): a `W + H` join, a switch within the
/// bound across a vote seed, and an extension that releases a horizon
/// block reproduce whatever the wall clock reads.
#[test]
fn horizon_switch_and_release_are_replay_deterministic() {
    let (a, fa) = switch_across_a_vote_seed(1_000);
    let (b, fb) = switch_across_a_vote_seed(9_999_999);
    assert_eq!(fa, fb);
    assert_eq!(a.active_snake_chain_window(), Ok((98, 103)));
    assert_eq!(a.active_snake_chain_window(), b.active_snake_chain_window());
    assert_eq!(a.active_chain_head_idx, b.active_chain_head_idx);
    assert_eq!(a.snake_chain_tail_idx, b.snake_chain_tail_idx);
    assert_eq!(a.horizon_root(), b.horizon_root());
    assert_eq!(a.block_tree_len(), b.block_tree_len());
    assert_eq!(a.active_branch_value, b.active_branch_value);
    assert!(a.node_info == b.node_info);
    assert!(a.vote_engine == b.vote_engine);
    let prefix = vote_seed_prefix(3);
    assert!(
        a.blocks.find(94, &prefix[0].view().hash()).is_none(),
        "#94 left the horizon"
    );
    assert!(
        a.blocks.find(95, &prefix[1].view().hash()).is_some(),
        "#95 is still in the horizon (H = 3)"
    );
}
