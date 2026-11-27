//! Story 7.7: the late-node reset and hold on the blockchain's paths — the
//! evidence block's list with `u` first (DEC-344), the hold's exit read
//! (DEC-346) on the commit, the switch undo and the rewind.

use super::*;
use crate::api::chain_config::late_hold_length_of;

/// A transaction block by `creator` on `prev` (the head of `g`) whose
/// node-#0 transfers vote once for each of `targets`, worth its real value.
fn votes_after(g: &SupportChain, prev: &Block, creator: u32, targets: &[u32], salt: u64) -> Block {
    let seq = prev.view().sequence() + 1;
    let targets = targets.to_vec();
    let template = tx_block(seq, prev.view().hash(), 0, move |b| {
        for (i, &target) in targets.iter().enumerate() {
            votes_for(seq, target, 1, salt + 1000 * i as u64)(b);
        }
    });
    real_on(g, &template, creator, key_of(creator))
}

fn vote_of(bc: &SupportChain, node: u32) -> u32 {
    bc.vote_engine.accumulated_vote_of(node)
}

/// Story 6.4's chain on `W = 16` with the horizon `H = 4` (so `L = 4`), and
/// proposer 2's deviation `d@6` on it, active at the proposer `l` — the
/// [`proposer_chain`] of this horizon.
fn proposer_chain_h4() -> (SupportChain, SupportChain, Block, u32) {
    let config = window_horizon_config_builder(TEST_W, 4);
    let (g, mut l, blocks) = support_chain_with(2, local_storage(2), config);
    let d = deviation_after(&g, &blocks[5], 2, 1);
    assert_eq!(receive(&mut l, &d), ReceiveBlockOutcome::AcceptedSilently);
    let d_idx = l.blocks.find(6, &d.view().hash()).expect("d held");
    (g, l, d, d_idx)
}

/// Proposer 2's run on Story 6.4's chain (`H = L = 4`): its deviation `d@6`
/// (`u = 1`), a replay `r@7` that votes for `u`, and the evidence `e@8` the
/// proposer builds on `r`. Returns node #0 `g` and the proposer `l`, both at
/// `r`, and `d`, `r`, `e`.
fn run_with_replay() -> (SupportChain, SupportChain, Block, Block, Block) {
    let (mut g, mut l, d, d_idx) = proposer_chain_h4();
    accumulate(&mut l, &d, d_idx, 2);
    assert_eq!(receive(&mut g, &d), ReceiveBlockOutcome::AcceptedSilently);
    let r = votes_after(&g, &d, 2, &[1], 70);
    for node in [&mut g, &mut l] {
        assert_eq!(receive(node, &r), ReceiveBlockOutcome::AcceptedSilently);
    }
    let e = l
        .build_evidence_block(l.active_chain_head_idx, 0)
        .expect("the evidence");
    assert_eq!(e.view().sequence(), 8);
    assert_eq!(g.late_hold_length(), Some(4), "L = H = 4");
    (g, l, d, r, e)
}

/// AC4 / AC9 (DEC-344): `u` gains a credit inside its run (a replay voting
/// for it); the evidence lists it first with that credit's grown value and
/// resets it with the other listed nodes; undoing the evidence restores the
/// projection exactly. (Node ids name slots differently on two nodes, so a
/// projection is compared with a replica of the same node.)
#[test]
fn the_evidence_resets_u_with_its_run_credit_and_the_undo_restores_it() {
    let (mut g, l, d, _, e) = run_with_replay();
    let (replica, _, _, _, _) = run_with_replay();
    let u = d.view().first_voted_node();
    assert_eq!(u, 1);
    let credited = vote_of(&g, u);
    assert!(credited >= 1000, "u credited inside its run");
    let late = evidence_of(&e, 2).late;
    let ids: std::vec::Vec<u32> = late.iter().map(|&(id, _)| id).collect();
    assert_eq!(ids, [1, 5, 0], "u first, then the late nodes");
    assert_eq!(
        late[0].1,
        g.vote_engine.grown(credited).expect("grows"),
        "u's value at the tip"
    );

    assert_eq!(receive(&mut g, &e), ReceiveBlockOutcome::AcceptedSilently);
    for n in [1, 5, 0] {
        assert_eq!(vote_of(&g, n), 0, "node {n} reset");
    }
    assert_eq!(g.undo_active_head(), Ok(()));
    assert!(g.vote_engine == l.vote_engine, "the votes and holds at r");
    assert!(g.node_info == replica.node_info, "the projection at r");
}

/// AC5 / AC9 (DEC-337, DEC-346): the listed nodes, `u` included, get no
/// credit at `e + 1 … e + L` (9–12) and one at `e + L + 1`; an unlisted
/// node is credited throughout. A second node that took the same blocks
/// agrees on every vote and hold.
#[test]
fn the_listed_nodes_are_held_for_l_blocks_after_the_evidence() {
    let (mut g, mut l, _, _, e) = run_with_replay();
    for node in [&mut g, &mut l] {
        assert_eq!(receive(node, &e), ReceiveBlockOutcome::AcceptedSilently);
    }
    let mut prev = e;
    for seq in 9..=13u32 {
        let block = votes_after(&g, &prev, 3, &[1, 5, 4], u64::from(seq));
        let control = vote_of(&g, 4);
        for node in [&mut g, &mut l] {
            assert_eq!(receive(node, &block), ReceiveBlockOutcome::AcceptedSilently);
        }
        let expected = if seq <= 12 { 0 } else { 1000 };
        assert_eq!(vote_of(&g, 1), expected, "u at {seq}");
        assert_eq!(vote_of(&g, 5), expected, "node 5 at {seq}");
        assert!(vote_of(&g, 4) > control, "the unlisted node at {seq}");
        prev = block;
    }
    assert!(g.vote_engine == l.vote_engine);
}

/// AC6 / AC9 (DEC-346): undoing the exit block `e + L` (12) restores the
/// hold it released, so the projection equals a replica that stopped at
/// 11; one more undo (11) equals the votes at 10.
#[test]
fn undoing_the_exit_block_restores_the_hold() {
    let (mut g, _, _, _, e) = run_with_replay();
    let (mut l, _, _, _, _) = run_with_replay();
    for node in [&mut g, &mut l] {
        assert_eq!(receive(node, &e), ReceiveBlockOutcome::AcceptedSilently);
    }
    let mut blocks: std::vec::Vec<Block> = std::vec::Vec::new();
    for seq in 9..=12u32 {
        let block = votes_after(&g, blocks.last().unwrap_or(&e), 3, &[5], u64::from(seq));
        assert_eq!(
            receive(&mut g, &block),
            ReceiveBlockOutcome::AcceptedSilently
        );
        blocks.push(block);
    }
    for block in &blocks[..2] {
        assert_eq!(
            receive(&mut l, block),
            ReceiveBlockOutcome::AcceptedSilently
        );
    }
    let at_10 = engine_votes(&l);
    assert_eq!(
        receive(&mut l, &blocks[2]),
        ReceiveBlockOutcome::AcceptedSilently
    );
    // `g` at 12 (released), `l` at 11 (held): undo 12.
    assert_eq!(head_of(&g).0, 12);
    assert_eq!(g.undo_active_head(), Ok(()));
    assert!(
        g.vote_engine == l.vote_engine,
        "the exit undone: held again"
    );
    assert!(g.node_info == l.node_info);
    assert_eq!(g.undo_active_head(), Ok(()));
    assert_eq!(engine_votes(&g), at_10);
}

/// AC6 / AC9 (DEC-238, DEC-258, DEC-346): a second run whose rewind crosses
/// the first evidence's exit block. Proposer 2 deviates again at 11 (inside
/// the hold of `e@8`, which ends after 12) and replays at 12, both voting
/// for the held node 0; its evidence's rewind undoes 12 (the exit) and 11,
/// steps at 10 and re-applies them. The late values it writes equal the
/// live engine's at the tip, and node #0 accepts the evidence.
#[test]
fn a_rewind_across_the_exit_block_reproduces_the_live_engine() {
    let (mut g, mut l, _, _, e) = run_with_replay();
    for node in [&mut g, &mut l] {
        assert_eq!(receive(node, &e), ReceiveBlockOutcome::AcceptedSilently);
    }
    // The proposer creates 9 and 10 itself: reset at 10, it ranks below the
    // held nodes 0 and 1 (all at 0, lower ids), so its next late list names
    // them.
    let mut prev = e;
    for seq in 9..=10u32 {
        let block = votes_after(&g, &prev, 2, &[4], u64::from(seq));
        for node in [&mut g, &mut l] {
            assert_eq!(receive(node, &block), ReceiveBlockOutcome::AcceptedSilently);
        }
        prev = block;
    }
    let d2 = deviation_after(&g, &prev, 2, 90);
    assert_eq!(d2.view().sequence(), 11);
    for node in [&mut g, &mut l] {
        assert_eq!(receive(node, &d2), ReceiveBlockOutcome::AcceptedSilently);
    }
    let d2_idx = l.blocks.find(11, &d2.view().hash()).expect("held");
    assert!(l.open_approval(d2_idx), "open");
    let r_eff = usize::from(l.approval.counts().1);
    l.approval.clear();
    accumulate(&mut l, &d2, d2_idx, r_eff);
    let r2 = votes_after(&g, &d2, 2, &[0], 91);
    for node in [&mut g, &mut l] {
        assert_eq!(receive(node, &r2), ReceiveBlockOutcome::AcceptedSilently);
    }
    assert_eq!(vote_of(&g, 0), 0, "node 0 still held at 11 and 12");
    let live = l.vote_engine.accumulated_vote_of(0);

    let e2 = l
        .build_evidence_block(l.active_chain_head_idx, 0)
        .expect("the second evidence");
    assert!(
        g.vote_engine == l.vote_engine,
        "the rewind restored the engine"
    );
    let late = evidence_of(&e2, r_eff).late;
    assert!(
        late.iter().any(|&(id, _)| id == 0),
        "node 0 ranks above the proposer"
    );
    for (id, value) in late {
        assert_eq!(
            value,
            l.vote_engine
                .grown(l.vote_engine.accumulated_vote_of(id))
                .expect("grows"),
            "node {id}: the rewind's tip value is the live one"
        );
    }
    assert_eq!(live, 0);
    assert_eq!(receive(&mut g, &e2), ReceiveBlockOutcome::AcceptedSilently);
    assert_eq!(head_of(&g).0, 13);
}

/// AC6: an unreadable exit block is the node's own fault — the step refuses
/// before the engine runs and nothing changes.
#[test]
fn an_unreadable_exit_block_is_local() {
    let (mut g, _, _, r, e) = run_with_replay();
    // An evidence block planted with its slot unwritten: its read fails.
    plant(&mut g, &e, true, false);
    let planted = g.blocks.find(8, &e.view().hash()).expect("planted");
    let next = votes_after(&g, &r, 3, &[5], 33);
    let head = g.active_chain_head_idx;
    let before = engine_votes(&g);
    let outcome = g.run_vote_step(&next.view(), head, false, None, Some(planted));
    assert!(matches!(outcome, VoteRun::Unread));
    assert_eq!(engine_votes(&g), before);
}

/// AC9: `L = min(H, 255)` — the hold count's `u8` holds every build's
/// count, and `H > 255` holds for 255 blocks.
#[test]
fn the_hold_length_is_capped_at_255() {
    for (h, l) in [(3, 3), (50, 50), (255, 255), (256, 255), (u32::MAX, 255)] {
        assert_eq!(late_hold_length_of(h), l, "H = {h}");
    }
}
