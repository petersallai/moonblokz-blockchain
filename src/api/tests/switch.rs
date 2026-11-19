//! Tests of `api/switch.rs`.

use super::*;

// ===================================================================
// Story 6.2 — FR22 re-evaluation, FR28 two-stage scoring, I-09, D6
// ===================================================================

/// The FR22 decision observed through the FR23 switch (Story 6.3): a
/// winner with a forged value (a free header, [`valued`]) is attempted,
/// refused by the replay's I-09 check and deleted with its descendants —
/// the block is gone while the active head stayed.
fn attempted<S: StorageTrait>(bc: &Chain16<S>, block: &Block) -> bool {
    status_of(bc, block).is_none()
}

/// AC10.1 / AC10.2 / AC2; Story 6.3 AC11.1 — trigger (i): a side
/// extension that outranks the active branch is switched to; a lower one
/// is not. The real-header branch `g3`, `g4` (node #1 then node #0, the
/// `alt` alternation from `a2`) wins only with `g4`; a forged-value fork
/// from an older active block (#1) is attempted and deleted.
#[test]
fn fr22_side_extension_and_fork_that_outrank_switch() {
    let (mut bc, b1, a2, a3) = two_creator_chain();
    let a3i = slot(&bc, &a3);
    // `g3` ties `a3` (both worth 1005, one transaction): a higher hash
    // keeps it below the active tip.
    let g3 = (20..400)
        .map(|salt| alt(3, a2.view().hash(), 1, 1, 1, salt, false))
        .find(|g| g.view().len() == a3.view().len() && g.view().hash() > a3.view().hash())
        .expect("a same-size sibling with a higher hash");
    assert_eq!(receive(&mut bc, &g3), ReceiveBlockOutcome::AcceptedSilently);
    assert_eq!(status_of(&bc, &g3), Some(BlockStatus::Connected));
    assert_eq!(head_of(&bc), (3, a3.view().hash()), "a tie lost by hash");
    // EXTEND past the active value: `g4` (node #0, credited once by
    // `g3`) is worth 1005 more.
    let g4 = alt(4, g3.view().hash(), 0, 1, 0, 21, false);
    assert_eq!(receive(&mut bc, &g4), ReceiveBlockOutcome::AcceptedSilently);
    assert_eq!(head_of(&bc), (4, g4.view().hash()), "switched");
    assert_eq!(bc.active_branch_value, v(&g3) + v(&g4));
    assert_eq!(status_of(&bc, &a3), Some(BlockStatus::Connected));
    assert_eq!(status_of(&bc, &g3), Some(BlockStatus::Active));
    assert_eq!(
        bc.chain_heads.branch_value_of(a3i),
        Some(v(&a3)),
        "the old head keeps the old active value (FR21 (iv))"
    );
    // The comparison itself (AC4): the active head and no candidate.
    assert_eq!(
        bc.switch_target([Some(bc.active_chain_head_idx), None]),
        None
    );
    assert_eq!(bc.switch_target([None, None]), None);
    // FORK from an older active block (#1) with a forged value: the
    // comparison picks it, the replay refuses it (I-09), and the active
    // chain stays.
    let f2 = valued(2, b1.view().hash(), 5000, 22);
    assert_eq!(receive(&mut bc, &f2), ReceiveBlockOutcome::AcceptedSilently);
    assert!(attempted(&bc, &f2));
    assert_eq!(head_of(&bc), (4, g4.view().hash()));
}

/// AC10.1 / D4 — on an equal value the larger tip wins: a smaller side
/// tip is not compared up whatever its hash, a larger one is (its forged
/// value is then refused by the replay, Story 6.3).
#[test]
fn fr22_equal_value_goes_to_the_larger_tip() {
    // The active tip `a3` carries two transactions.
    let (mut bc, _, b1) = ready_genesis(16);
    let a2 = alt(2, b1.view().hash(), 0, 0, 1, 7, true);
    let a3 = alt(3, a2.view().hash(), 1, 1, 2, 8, false);
    for blk in [&a2, &a3] {
        assert_eq!(receive(&mut bc, blk), ReceiveBlockOutcome::AcceptedSilently);
    }
    let tip = a3.view();
    for lower_hash in [true, false] {
        // Open-ended: the tip's hash follows the scheme's keys, and a tip
        // near either end leaves few siblings on that side.
        let smaller = (100..100_000)
            .map(|amount| valued(3, a2.view().hash(), 1005, amount))
            .find(|blk| (blk.view().hash() < tip.hash()) == lower_hash)
            .expect("a one-transaction sibling");
        assert!(smaller.view().len() < tip.len());
        assert_eq!(
            receive(&mut bc, &smaller),
            ReceiveBlockOutcome::AcceptedSilently
        );
        assert!(
            !attempted(&bc, &smaller),
            "smaller, lower hash: {lower_hash}"
        );
    }
    let larger = revalue(
        &tx_block(3, a2.view().hash(), 0, votes_for(3, 0, 3, 500)),
        1005,
    );
    assert!(larger.view().len() > tip.len());
    assert_eq!(
        receive(&mut bc, &larger),
        ReceiveBlockOutcome::AcceptedSilently
    );
    assert!(attempted(&bc, &larger));
    assert_eq!(head_of(&bc), (3, a3.view().hash()));
}

/// AC10.1 / D4 — on an equal value and size the lower tip hash wins,
/// whatever the creators: node #0's side tip loses to node #1's active
/// tip when its hash is higher (the old creator criterion would pick it).
/// The winner's forged value is refused by the replay (Story 6.3).
#[test]
fn fr22_tie_goes_to_the_lower_hash_not_the_creator() {
    for want_lower in [true, false] {
        let (mut bc, _, a2, a3) = two_creator_chain();
        let tip = a3.view();
        let side = (100..100_000)
            .map(|amount| valued(3, a2.view().hash(), 1005, amount))
            .find(|blk| {
                let view = blk.view();
                view.len() == tip.len() && (view.hash() < tip.hash()) == want_lower
            })
            .expect("a same-size sibling");
        assert_eq!(
            receive(&mut bc, &side),
            ReceiveBlockOutcome::AcceptedSilently
        );
        assert_eq!(
            attempted(&bc, &side),
            want_lower,
            "lower hash: {want_lower}"
        );
        assert_eq!(head_of(&bc), (3, a3.view().hash()));
    }
}

/// AC10.3 / AC10.4 / AC9 — trigger (ii): orphan side heads connected by
/// their parent's arrival; of two, the higher-ranked is the target, in
/// any arrival order. Trigger (v): a Tier 2 deletion's retarget onto a
/// Connected block that outranks. Each target's forged value is refused
/// by the replay (Story 6.3), which deletes it and nothing below it.
#[test]
fn fr22_connected_orphans_and_the_retarget_reach_the_seam() {
    let run = |order: &[usize]| {
        let (mut bc, _, a2, a3) = two_creator_chain();
        let m3 = valued(3, a2.view().hash(), 0, 30);
        let p4 = valued(4, m3.view().hash(), 100, 31);
        let q4 = valued(4, m3.view().hash(), 2000, 32);
        for &i in order {
            let blk = [&m3, &p4, &q4][i];
            assert_eq!(receive(&mut bc, blk), ReceiveBlockOutcome::AcceptedSilently);
        }
        assert_eq!(head_of(&bc), (3, a3.view().hash()));
        (
            attempted(&bc, &q4),
            attempted(&bc, &p4),
            status_of(&bc, &m3),
        )
    };
    for order in [[1, 2, 0], [2, 1, 0], [0, 1, 2]] {
        assert_eq!(
            run(&order),
            (true, false, Some(BlockStatus::Connected)),
            "order {order:?}"
        );
    }

    // The retarget: `bad5` waits for `p4`, so `p4`'s own entry merges
    // away; the driver deletes `bad5` and values the entry it retargets
    // onto `p4`, which the comparison then picks.
    let (mut bc, mint, _) = utxo_side_fixture();
    let p4 = valued(4, mint.view().hash(), 5000, 30);
    let bad5 = revalue(&side_spend(5, p4.view().hash(), 0, 61), 5);
    for blk in [&bad5, &p4] {
        assert_eq!(receive(&mut bc, blk), ReceiveBlockOutcome::AcceptedSilently);
    }
    assert_eq!(status_of(&bc, &bad5), None, "deleted");
    assert!(attempted(&bc, &p4));
}

/// AC10.5 / AC10.11 — Ready entry compares the side heads it values: a
/// mesh join through FR3 onto `#0..#4` with a heavier side fork `f3`, and
/// again after a restart, whose rebuild also marks the active blocks'
/// signatures verified. `f3`'s forged value is refused by the replay each
/// time (Story 6.3); the restart resurrects its lazily freed bytes (R3).
#[test]
fn fr22_ready_entry_and_restart_compare_side_heads() {
    let (_, b0, b1) = ready_genesis(16);
    let a2 = alt(2, b1.view().hash(), 0, 0, 1, 7, true);
    let a3 = alt(3, a2.view().hash(), 1, 1, 1, 8, false);
    let a4 = alt(4, a3.view().hash(), 0, 1, 0, 9, false);
    let f3 = valued(3, a2.view().hash(), 5000, 20);
    let mut mesh = new_unconfigured_test_chain();
    for blk in [&f3, &a4, &a3, &a2, &b1, &b0] {
        assert_eq!(
            receive(&mut mesh, blk),
            ReceiveBlockOutcome::AcceptedSilently
        );
    }
    assert!(mesh.is_ready());
    assert_eq!(head_of(&mesh), (4, a4.view().hash()));
    assert!(attempted(&mesh, &f3));

    let mut restarted = restart(mesh);
    let _ = restarted.initialize_from_storage(0);
    assert!(restarted.is_ready());
    assert_eq!(head_of(&restarted), (4, a4.view().hash()));
    assert!(attempted(&restarted, &f3));
    for blk in [&a2, &a3, &a4] {
        let idx = slot(&restarted, blk);
        assert!(
            restarted
                .blocks
                .get(idx)
                .is_some_and(|entry| entry.is_signature_verified()),
            "the rebuild marked #{}",
            blk.view().sequence()
        );
    }
}

/// AC10.6 / AC3 / D3; Story 6.14 D4 / D6 — on the matured W6 window
/// `[100, 105]` with `H = 3` below it, a heavier side branch shorter than
/// the window is not admissible: the horizon is not counted (DEC-209).
/// Extended to cover the window it is, and the switch now runs — there is
/// no completeness horizon (DEC-211) — so the replay refuses its forged
/// value and deletes the branch; the active chain stays. The late case:
/// once the head has moved on, a branch at the old head sequence waits for
/// its own extension. Side blocks are transfers, clean on the slot #104
/// (Story 6.7 D8).
#[test]
fn fr22_admissibility_follows_the_w6_window() {
    let (mut bc, [_, _, b102, _, _, b105]) = valued_w6();
    let s103 = valued(103, b102.view().hash(), 999, 6);
    assert_eq!(
        bc.receive_block(s103.view(), 0).0,
        ReceiveBlockOutcome::AcceptedSilently
    );
    let si = slot(&bc, &s103);
    assert!(bc.chain_heads.branch_value_of(si) > Some(bc.active_branch_value));
    assert_eq!(
        bc.switch_target([Some(si), None]),
        None,
        "segment [100, 103] < W; the horizon below it is not counted"
    );
    let s104 = valued(104, s103.view().hash(), 1, 7);
    assert_eq!(
        bc.receive_block(s104.view(), 0).0,
        ReceiveBlockOutcome::AcceptedSilently
    );
    assert_eq!(
        bc.switch_target([Some(slot(&bc, &s104)), None]),
        None,
        "segment [100, 104] < W"
    );
    let s105 = valued(105, s104.view().hash(), 1, 10);
    assert_eq!(
        bc.receive_block(s105.view(), 0).0,
        ReceiveBlockOutcome::AcceptedSilently
    );
    assert!(
        [&s103, &s104, &s105].iter().all(|blk| bc
            .blocks
            .find(blk.view().sequence(), &blk.view().hash())
            .is_none()),
        "attempted, refused by the replay (I-09) and deleted"
    );
    assert_eq!(
        bc.blocks.get(bc.active_chain_head_idx).map(|e| *e.hash()),
        Some(b105.view().hash()),
        "the active chain stays"
    );

    // The late case (D3; AC10.10): the head moved on to #106, so a branch
    // at #105 is one short until it reaches #106.
    let (mut bc, [_, _, _, _, b104, b105]) = valued_w6();
    let b106 = real_on(&bc, &w6_config_anchor_block(106, b105.view().hash()), 0, 1);
    extend_active_head(&mut bc, &b106, 0);
    assert_eq!(bc.active_snake_chain_window(), Ok((101, 106)));
    let n105 = valued(105, b104.view().hash(), 500, 8);
    assert_eq!(
        bc.receive_block(n105.view(), 0).0,
        ReceiveBlockOutcome::AcceptedSilently
    );
    let n5 = slot(&bc, &n105);
    assert_eq!(
        bc.switch_target([Some(n5), None]),
        None,
        "not admissible yet"
    );
    let n106 = valued(106, n105.view().hash(), 0, 9);
    assert_eq!(
        bc.receive_block(n106.view(), 0).0,
        ReceiveBlockOutcome::AcceptedSilently
    );
    assert!(
        bc.blocks.find(105, &n105.view().hash()).is_none(),
        "admissible at #106: attempted and deleted"
    );
    assert_eq!(
        bc.blocks.get(bc.active_chain_head_idx).map(|e| *e.hash()),
        Some(b106.view().hash())
    );
}

/// AC10.7 / AC7 — the non-triggers compare nothing. A winning fork whose
/// switch hit a local fault (its own block cannot be read back by the
/// pre-pass; Story 6.3 AC6: kept, nothing deleted) stays a side head that
/// would be attempted if compared — its forged value would be refused and
/// deleted. Active extensions, direct and by continuation, leave it
/// alone; a zero-valued side block compares only itself.
#[test]
fn fr22_non_triggers_compare_nothing() {
    let (mut bc, b1) = faulty_genesis(16);
    let a2 = alt(2, b1.view().hash(), 0, 0, 1, 7, true);
    assert_eq!(receive(&mut bc, &a2), ReceiveBlockOutcome::AcceptedSilently);
    let f2 = valued(2, b1.view().hash(), 5000, 20);
    // `f2` is valued from the view in hand; the switch's pre-pass must
    // read it back.
    bc.storage.failing_read_slot = bc.blocks.next_free_index().expect("a free slot");
    assert_eq!(receive(&mut bc, &f2), ReceiveBlockOutcome::AcceptedSilently);
    bc.storage.failing_read_slot = NONE_REF;
    assert_eq!(status_of(&bc, &f2), Some(BlockStatus::Connected), "kept");
    assert_eq!(head_of(&bc), (2, a2.view().hash()));
    let a3 = alt(3, a2.view().hash(), 1, 1, 1, 8, false);
    assert_eq!(receive(&mut bc, &a3), ReceiveBlockOutcome::AcceptedSilently);
    let a4 = alt(4, a3.view().hash(), 0, 1, 1, 9, false);
    let a5 = alt(5, a4.view().hash(), 1, 1, 0, 10, false);
    for blk in [&a5, &a4] {
        assert_eq!(receive(&mut bc, blk), ReceiveBlockOutcome::AcceptedSilently);
    }
    assert_eq!(head_of(&bc), (5, a5.view().hash()));
    let fi = slot(&bc, &f2);
    let fv = bc.chain_heads.branch_value_of(fi).expect("valued");
    assert!(fv > bc.active_branch_value, "it would still win");
    assert!(!attempted(&bc, &f2), "active extensions compare nothing");
    // A side block worth 0 (a replay-like value, FR22 (b)) is an ordinary
    // trigger (i): it cannot win, and it does not compare `f2`.
    let zero = valued(3, a2.view().hash(), 0, 23);
    assert_eq!(
        receive(&mut bc, &zero),
        ReceiveBlockOutcome::AcceptedSilently
    );
    assert!(!attempted(&bc, &zero), "a zero-valued side block");
    assert!(!attempted(&bc, &f2));
}

/// AC10.8 / D4 — the comparison reads nothing: a value-and-size tie is
/// decided by hash while the active tip's slot fails every read. The
/// tying block extends a Connected side head, which is valued with no
/// read either (Story 6.1 D4). The switch the comparison then calls must
/// read that tip to undo it: a local failure, kept with nothing deleted
/// (Story 6.3 AC6).
#[test]
fn fr22_comparison_reads_nothing() {
    let (mut bc, b1) = faulty_genesis(16);
    let a2 = alt(2, b1.view().hash(), 0, 0, 1, 7, true);
    let a3 = alt(3, a2.view().hash(), 1, 1, 0, 8, false);
    let g2 = valued(2, b1.view().hash(), 5, 20);
    for blk in [&a2, &a3, &g2] {
        assert_eq!(receive(&mut bc, blk), ReceiveBlockOutcome::AcceptedSilently);
    }
    assert!(!attempted(&bc, &g2));
    let tip = a3.view();
    let side = (100..100_000)
        .map(|amount| valued(3, g2.view().hash(), 1000, amount))
        .find(|blk| blk.view().len() == tip.len() && blk.view().hash() < tip.hash())
        .expect("a same-size extension with a lower hash");
    bc.storage.failing_read_slot = slot(&bc, &a3);
    assert_eq!(
        receive(&mut bc, &side),
        ReceiveBlockOutcome::AcceptedSilently
    );
    let si = slot(&bc, &side);
    assert_eq!(
        bc.chain_heads.branch_value_of(si),
        Some(bc.active_branch_value)
    );
    assert_eq!(
        bc.switch_target([Some(si), None]),
        Some(si),
        "decided without a read"
    );
    assert_eq!(status_of(&bc, &side), Some(BlockStatus::Connected), "kept");
    assert_eq!(head_of(&bc), (3, a3.view().hash()));
}

/// AC10.13 (first negative check) — the comparison runs after the
/// continuation: a fork that outranks the active branch at its intake but
/// not once the same admission's continuation promotes a pending child
/// (left Stored by a read fault) does not switch.
#[test]
fn fr22_compares_after_the_continuation() {
    let (mut bc, mint) = faulty_utxo_genesis();
    let b4 = alt(4, mint.view().hash(), 0, 0, 5, 7, false);
    assert_eq!(receive(&mut bc, &b4), ReceiveBlockOutcome::AcceptedSilently);
    let tx = utxo_tx(5, &[(3, 1, 40)], None, &[Err((1, 40))]);
    // Node #1: credited once by the mint and five times by `b4`.
    let c5 = resign(
        &complex_tx_block(5, b4.view().hash(), 0, 0, &[&tx]),
        1,
        vote_snapshot(vote_snapshot(1000) + 5000),
        NODE_ONE_KEY,
    );
    bc.storage.failing_read_slot = slot(&bc, &mint);
    assert_eq!(receive(&mut bc, &c5), ReceiveBlockOutcome::AcceptedSilently);
    assert_eq!(
        status_of(&bc, &c5),
        Some(BlockStatus::Stored),
        "a local failure"
    );
    bc.storage.failing_read_slot = NONE_REF;

    let x = valued(4, mint.view().hash(), 3000, 40);
    assert_eq!(receive(&mut bc, &x), ReceiveBlockOutcome::AcceptedSilently);
    assert_eq!(head_of(&bc), (5, c5.view().hash()), "the continuation ran");
    assert_eq!(bc.active_branch_value, v(&b4) + v(&c5));
    let xv = bc
        .chain_heads
        .branch_value_of(slot(&bc, &x))
        .expect("x is a valued side head");
    assert!(xv < bc.active_branch_value);
    assert!(!attempted(&bc, &x));
}

/// AC10.9 / AC5 — I-09 at Ready intake: each inconsistent vote header is
/// `Rejected(InvalidEvidence)` with nothing stored; the correct deviation
/// is accepted and penalizes the top; the credits it gave the top and
/// itself are wiped. Node #1 (3000) is the top after `a2`.
#[test]
fn i09_vote_headers_are_verified_at_ready_intake() {
    let (mut bc, _, b1) = ready_genesis(16);
    let a2 = alt(2, b1.view().hash(), 0, 0, 3, 7, true);
    assert_eq!(receive(&mut bc, &a2), ReceiveBlockOutcome::AcceptedSilently);
    assert_eq!(bc.vote_engine.top_creator(), Some(1));
    let prev = a2.view().hash();
    let refused = [
        // A normal block counting its own credit (the old definition).
        headed(
            3,
            prev,
            1,
            NODE_ONE_KEY,
            3015 + 1000,
            1,
            0,
            votes_for(3, 1, 1, 40),
        ),
        // A normal block with a wrong value.
        headed(3, prev, 1, NODE_ONE_KEY, 2000, 1, 0, votes_for(3, 0, 1, 41)),
        // The normal form with a deviation field (Tier 1 form).
        headed(3, prev, 1, NODE_ONE_KEY, 3015, 1, 5, votes_for(3, 0, 1, 42)),
        // A deviation naming a node that is not the top.
        headed(3, prev, 0, 1, 0, 5, 10, votes_for(3, 0, 1, 43)),
        // A deviation with a wrong snapshot of the top.
        headed(3, prev, 0, 1, 0, 1, 3000, votes_for(3, 0, 1, 44)),
        // A deviation counting its own credit (AR-005).
        headed(3, prev, 0, 1, 1000, 1, 3015, votes_for(3, 0, 1, 45)),
        // A deviation above the top's snapshot (Tier 1 form).
        headed(3, prev, 0, 1, 4000, 1, 3015, votes_for(3, 0, 1, 46)),
    ];
    for (i, bad) in refused.iter().enumerate() {
        let free = bc.blocks.next_free_index();
        assert_eq!(
            receive(&mut bc, bad),
            ReceiveBlockOutcome::Rejected(RejectReason::InvalidEvidence),
            "case {i}"
        );
        assert_eq!(
            bc.blocks.next_free_index(),
            free,
            "case {i}: nothing stored"
        );
    }
    let d3 = headed(3, prev, 0, 1, 0, 1, 3015, |b| {
        votes_for(3, 0, 1, 47)(b);
        votes_for(3, 1, 1, 48)(b);
    });
    assert_eq!(receive(&mut bc, &d3), ReceiveBlockOutcome::AcceptedSilently);
    assert_eq!(head_of(&bc), (3, d3.view().hash()));
    assert_eq!(bc.vote_engine.accumulated_vote_of(1), 0, "the penalty");
    assert_eq!(bc.vote_engine.accumulated_vote_of(0), 0, "the reset");
}

/// AC10.9 — in the FR3 pass an inconsistent vote header is evidence: a
/// mesh join deletes it and goes Ready on the valid prefix.
#[test]
fn i09_mismatch_in_the_fr3_pass_is_deleted() {
    let (_, b0, b1) = ready_genesis(16);
    let a2 = alt(2, b1.view().hash(), 0, 0, 3, 7, true);
    let prev = a2.view().hash();
    let bad = [
        // A wrong normal value.
        headed(3, prev, 1, NODE_ONE_KEY, 2000, 1, 0, votes_for(3, 0, 1, 50)),
        // A deviation naming a node that is not the top.
        headed(3, prev, 0, 1, 0, 2, 10, votes_for(3, 0, 1, 51)),
        // A deviation with a wrong snapshot of the top.
        headed(3, prev, 0, 1, 0, 1, 3000, votes_for(3, 0, 1, 52)),
        // A deviation counting its own credit (AR-005).
        headed(3, prev, 0, 1, 1000, 1, 3015, votes_for(3, 0, 1, 53)),
    ];
    for (i, bad3) in bad.iter().enumerate() {
        let mut mesh = new_unconfigured_test_chain();
        for blk in [bad3, &a2, &b1, &b0] {
            assert_eq!(
                receive(&mut mesh, blk),
                ReceiveBlockOutcome::AcceptedSilently,
                "case {i}"
            );
        }
        assert!(mesh.is_ready(), "case {i}");
        assert_eq!(head_of(&mesh), (2, a2.view().hash()), "case {i}");
        assert!(
            mesh.blocks.find(3, &bad3.view().hash()).is_none(),
            "case {i}: deleted"
        );
    }
}

/// AC6 — the header vote form is Tier 1 in every phase: a Collecting node
/// refuses a malformed header and stores nothing.
#[test]
fn header_vote_form_is_refused_while_collecting() {
    let mut bc = new_unconfigured_test_chain();
    assert!(!bc.is_ready());
    for bad in [
        headed(5, [0x33; 32], 0, 1, 10, 1, 5, votes_for(5, 0, 1, 60)),
        headed(5, [0x33; 32], 0, 1, 0, 0, 7, votes_for(5, 0, 1, 61)),
    ] {
        let free = bc.blocks.next_free_index();
        assert_eq!(
            receive(&mut bc, &bad),
            ReceiveBlockOutcome::Rejected(RejectReason::InvalidEvidence)
        );
        assert_eq!(bc.blocks.next_free_index(), free, "nothing stored");
    }
}

/// AC10.11 / D6 — branch-independent keys beyond node #0: a node seeded at
/// or below `S_tail` (by its seed-source block's sequence) and a node whose
/// seed source was released are judged at intake; a node seeded inside the
/// window is not. A direct head extension and a good orphan by node #0 are
/// stored marked.
#[test]
fn branch_independent_keys_beyond_node_zero() {
    let (mut bc, b0, b1) = ready_genesis(16);
    let a2 = alt(2, b1.view().hash(), 0, 0, 1, 7, true);
    assert_eq!(receive(&mut bc, &a2), ReceiveBlockOutcome::AcceptedSilently);
    let key = |byte: u8| {
        *Crypto::new([byte; PRIVATE_KEY_SIZE])
            .ok()
            .expect("key")
            .public_key()
            .serialize()
    };
    // Test seeding (white box): node 5 at #0, which is `S_tail`; node 6
    // with its source released; node 7 at #2, inside the window.
    let (b0i, a2i) = (slot(&bc, &b0), slot(&bc, &a2));
    bc.node_info.seed_node(5, &key(0x55), 0, b0i);
    bc.node_info
        .seed_node(6, &key(0x56), 0, SEED_SOURCE_RELEASED);
    bc.node_info.seed_node(7, &key(0x57), 0, a2i);
    // Worth 0, below the larger active tip `a2` (also 0): these intake
    // tests do not reach a chain switch (Story 6.3).
    let side = |creator: u32, signer: u8, salt: u64| {
        resign(&valued(2, b1.view().hash(), 0, salt), creator, 0, signer)
    };
    for (creator, salt) in [(5, 30), (6, 31)] {
        let free = bc.blocks.next_free_index();
        assert_eq!(
            receive(&mut bc, &side(creator, 0x66, salt)),
            ReceiveBlockOutcome::Rejected(RejectReason::InvalidEvidence),
            "node {creator}: forged"
        );
        assert_eq!(bc.blocks.next_free_index(), free);
        let good = side(creator, 0x50 + creator as u8, salt + 10);
        assert_eq!(
            receive(&mut bc, &good),
            ReceiveBlockOutcome::AcceptedSilently
        );
        let gi = slot(&bc, &good);
        assert!(
            bc.blocks.get(gi).is_some_and(|e| e.is_signature_verified()),
            "node {creator}: marked"
        );
    }
    let inside = side(7, 0x66, 40);
    assert_eq!(
        receive(&mut bc, &inside),
        ReceiveBlockOutcome::AcceptedSilently
    );
    let ii = slot(&bc, &inside);
    assert!(
        bc.blocks
            .get(ii)
            .is_some_and(|e| !e.is_signature_verified())
    );

    // Node #0: a direct head extension and a good orphan, each marked.
    let a3 = alt(3, a2.view().hash(), 0, 0, 0, 41, false);
    assert_eq!(receive(&mut bc, &a3), ReceiveBlockOutcome::AcceptedSilently);
    assert_eq!(head_of(&bc), (3, a3.view().hash()));
    let orphan = transfer(9, [0x44; 32], 0, 5);
    assert_eq!(
        receive(&mut bc, &orphan),
        ReceiveBlockOutcome::AcceptedSilently
    );
    for blk in [&a3, &orphan] {
        let idx = slot(&bc, blk);
        assert!(
            bc.blocks
                .get(idx)
                .is_some_and(|e| e.is_signature_verified())
        );
    }
}

/// AC10.10 / FR28 — the two-stage scoring end to end. With `av(u) = 3000`
/// above `av(x) = 0`: an active deviation `d` loses to the late normal block
/// `n` of the top creator; with `n` active first, `d` does not win. The
/// credits `d` carries do not count. With `av(u) = av(x) = 0` the values
/// tie and the FR21 tie-break decides.
#[test]
fn fr28_two_stage_scoring_end_to_end() {
    let setup = |out: u32| {
        let (mut bc, _, b1) = ready_genesis(16);
        let a2 = alt(2, b1.view().hash(), 0, 0, out, 7, true);
        assert_eq!(receive(&mut bc, &a2), ReceiveBlockOutcome::AcceptedSilently);
        (bc, a2)
    };
    let deviation = |a2: &Block| {
        headed(
            3,
            a2.view().hash(),
            0,
            1,
            0,
            1,
            3015,
            votes_for(3, 1, 2, 60),
        )
    };
    let normal = |a2: &Block| alt(3, a2.view().hash(), 1, 3, 0, 61, false);

    let (mut bc, a2) = setup(3);
    let (d, n) = (deviation(&a2), normal(&a2));
    assert_eq!(receive(&mut bc, &d), ReceiveBlockOutcome::AcceptedSilently);
    assert_eq!(
        head_of(&bc),
        (3, d.view().hash()),
        "the deviation is active at once"
    );
    assert_eq!(receive(&mut bc, &n), ReceiveBlockOutcome::AcceptedSilently);
    assert_eq!(v(&n), 3015);
    assert_eq!(
        head_of(&bc),
        (3, n.view().hash()),
        "the late normal block wins: switched (Story 6.3)"
    );
    assert_eq!(status_of(&bc, &d), Some(BlockStatus::Connected));

    let (mut bc, a2) = setup(3);
    let (d, n) = (deviation(&a2), normal(&a2));
    assert_eq!(receive(&mut bc, &n), ReceiveBlockOutcome::AcceptedSilently);
    assert_eq!(receive(&mut bc, &d), ReceiveBlockOutcome::AcceptedSilently);
    assert_eq!(status_of(&bc, &d), Some(BlockStatus::Connected));
    assert_eq!(
        head_of(&bc),
        (3, n.view().hash()),
        "the deviation does not overtake"
    );

    // The tie: the all-zero state, node #0 on top; node #1 deviates. Both
    // are worth 0 and carry one transaction, so the hash decides: pinned
    // for each order of the two hashes. The pair comes from two small
    // pools, so neither order hangs on where one block's hash happens to
    // fall (every block is signed, and signing is slow in a debug build).
    let prev = setup(0).1.view().hash();
    let ds: [Block; 4] = core::array::from_fn(|i| {
        headed(
            3,
            prev,
            1,
            NODE_ONE_KEY,
            0,
            0,
            0,
            votes_for(3, 1, 1, 60 + i as u64),
        )
    });
    let ns: [Block; 8] = core::array::from_fn(|i| alt(3, prev, 0, 0, 0, 71 + i as u64, false));
    for n_lower in [true, false] {
        let (mut bc, a2) = setup(0);
        assert_eq!(a2.view().hash(), prev);
        assert_eq!(bc.vote_engine.top_creator(), Some(0));
        let (d, n) = ds
            .iter()
            .flat_map(|d| ns.iter().map(move |n| (d, n)))
            .find(|(d, n)| {
                n.view().len() == d.view().len() && (n.view().hash() < d.view().hash()) == n_lower
            })
            .expect("a same-size deviation and normal block in this order");
        assert_eq!(receive(&mut bc, d), ReceiveBlockOutcome::AcceptedSilently);
        assert_eq!(receive(&mut bc, n), ReceiveBlockOutcome::AcceptedSilently);
        let winner = if n_lower { n } else { d };
        assert_eq!(
            head_of(&bc),
            (3, winner.view().hash()),
            "n has the lower hash: {n_lower}"
        );
    }
}

/// AC10.11 / AC6 / D6 — Ready intake: a bad creator signature under a
/// branch-independent key is refused before the write, for a fork and for
/// an orphan; a good one is stored marked verified; a key that is not
/// branch-independent (node #1, registered inside the window) is not
/// judged and carries no mark. The header vote form is refused at Tier 1.
#[test]
fn ready_intake_checks_branch_independent_signatures() {
    let (mut bc, _, b1) = ready_genesis(16);
    let a2 = alt(2, b1.view().hash(), 0, 0, 1, 7, true);
    assert_eq!(receive(&mut bc, &a2), ReceiveBlockOutcome::AcceptedSilently);
    let forged_fork = resign(&valued(3, b1.view().hash(), 500, 20), 0, 500, 0x66);
    let forged_orphan = resign(&transfer(9, [0x55; 32], 0, 5), 0, 0, 0x66);
    let bad_form = headed(3, b1.view().hash(), 0, 1, 10, 1, 5, votes_for(3, 0, 1, 21));
    for bad in [&forged_fork, &forged_orphan, &bad_form] {
        let free = bc.blocks.next_free_index();
        assert_eq!(
            receive(&mut bc, bad),
            ReceiveBlockOutcome::Rejected(RejectReason::InvalidEvidence)
        );
        assert_eq!(bc.blocks.next_free_index(), free, "nothing stored");
    }
    let good = valued(3, b1.view().hash(), 500, 22);
    assert_eq!(
        receive(&mut bc, &good),
        ReceiveBlockOutcome::AcceptedSilently
    );
    let gi = slot(&bc, &good);
    assert!(bc.blocks.get(gi).is_some_and(|e| e.is_signature_verified()));
    // Node #1 on a branch forked below its registration: its key is not
    // branch-independent, so a bad signature is not judged at intake.
    // Worth 0, below the larger active tip `a2`: no chain switch (Story
    // 6.3), which would refuse it (node #1 is registered in `a2`).
    let unjudged = resign(&valued(2, b1.view().hash(), 0, 23), 1, 0, 0x66);
    assert_eq!(
        receive(&mut bc, &unjudged),
        ReceiveBlockOutcome::AcceptedSilently
    );
    let ui = slot(&bc, &unjudged);
    assert!(
        bc.blocks
            .get(ui)
            .is_some_and(|e| !e.is_signature_verified())
    );
    assert!(!BlockEntry::new([0; 32], NONE_REF, 1).is_signature_verified());
}

/// AC10.11 / D6 — verify once: a Stored child marked verified is promoted
/// by the continuation without its signature being checked again (here a
/// bad one, so a re-check would delete it); unmarked, it is deleted. The
/// freed slot's next occupant starts unmarked.
#[test]
fn a_verified_block_is_not_verified_again() {
    for marked in [true, false] {
        let (mut bc, _, b1) = ready_genesis(16);
        let a2 = alt(2, b1.view().hash(), 0, 0, 1, 7, true);
        let bad3 = resign(
            &alt(3, a2.view().hash(), 1, 1, 0, 8, false),
            1,
            vote_snapshot(1000),
            0x66,
        );
        assert_eq!(
            receive(&mut bc, &bad3),
            ReceiveBlockOutcome::AcceptedSilently
        );
        let bi = slot(&bc, &bad3);
        assert!(
            bc.blocks
                .get(bi)
                .is_some_and(|e| !e.is_signature_verified())
        );
        if marked {
            assert!(bc.blocks.mark_signature_verified(bi));
        }
        assert_eq!(receive(&mut bc, &a2), ReceiveBlockOutcome::AcceptedSilently);
        if marked {
            assert_eq!(head_of(&bc), (3, bad3.view().hash()), "not re-verified");
        } else {
            assert_eq!(head_of(&bc), (2, a2.view().hash()));
            assert_eq!(status_of(&bc, &bad3), None, "verified, refused, deleted");
            assert_eq!(bc.blocks.next_free_index(), Some(bi));
            let next = resign(&valued(3, [0x66; 32], 0, 24), 1, 0, NODE_ONE_KEY);
            assert_eq!(
                receive(&mut bc, &next),
                ReceiveBlockOutcome::AcceptedSilently
            );
            assert!(
                bc.blocks
                    .get(bi)
                    .is_some_and(|e| !e.is_signature_verified())
            );
        }
    }
}

// ===================================================================
// Story 6.3 — FR23 reversible chain switch
// ===================================================================

/// AC10 / AC11 — `a`'s derived state equals `b`'s for every block `b`
/// holds (matched by sequence and hash, since slots differ): `node_info`,
/// the vote engine, the active value and the window, and per block its
/// status, chain flag and available-UTXO bits, ignoring the one-way
/// signature mark (DEC-157). Every block only `a` holds is off the active
/// chain with no bit set (no phantom bits, 6.11).
fn assert_same_projection<S: StorageTrait, T: StorageTrait>(
    a: &Chain16<S>,
    b: &Chain16<T>,
    what: &str,
) {
    // `node_info` per node: seed sources are slots, so they are compared
    // as the blocks they name.
    let source = |bc_blocks: &BlockTable<TEST_MAX_BLOCKS>, src: Option<u32>| match src {
        Some(idx) if idx != SEED_SOURCE_RELEASED => {
            bc_blocks.get(idx).map(|e| Some((e.sequence(), *e.hash())))
        }
        other => Some(other.map(|_| (u32::MAX, [0u8; 32]))),
    };
    assert_eq!(
        a.node_info.max_known_node_id(),
        b.node_info.max_known_node_id(),
        "{what}: watermark"
    );
    for node in 0..16u32 {
        assert_eq!(
            a.node_info.balance_of(node),
            b.node_info.balance_of(node),
            "{what}: balance {node}"
        );
        assert_eq!(
            a.node_info.public_key_of(node),
            b.node_info.public_key_of(node),
            "{what}: key {node}"
        );
        assert_eq!(
            source(&a.blocks, a.node_info.seed_source_of(node)),
            source(&b.blocks, b.node_info.seed_source_of(node)),
            "{what}: seed source {node}"
        );
    }
    assert!(a.vote_engine == b.vote_engine, "{what}: votes");
    assert_eq!(
        a.active_branch_value, b.active_branch_value,
        "{what}: value"
    );
    let hash_of =
        |bc_blocks: &BlockTable<TEST_MAX_BLOCKS>, idx: u32| bc_blocks.get(idx).map(|e| *e.hash());
    assert_eq!(
        hash_of(&a.blocks, a.active_chain_head_idx),
        hash_of(&b.blocks, b.active_chain_head_idx),
        "{what}: head"
    );
    assert_eq!(
        hash_of(&a.blocks, a.snake_chain_tail_idx),
        hash_of(&b.blocks, b.snake_chain_tail_idx),
        "{what}: tail"
    );
    // `chain_heads`, by head block: every entry `b` holds is in `a` with
    // the same connection, the same anchor block and — for a Connected
    // side head — the same value (FR19 event (iii), no demotion, FR21
    // (iv)). An entry only `a` holds names a side head off the chain. The
    // active head's own entry is skipped: it carries no value (DEC-144),
    // and it exists only while the head has no side child.
    type Entry = Option<((u32, [u8; 32]), bool, Option<[u8; 32]>, Option<u64>)>;
    let entries = |bc_blocks: &BlockTable<TEST_MAX_BLOCKS>, heads: &ChainHeadsTable<4>| {
        let mut out: [Entry; 4] = [None; 4];
        for (slot, (head, anchor)) in heads.occupied_heads().enumerate() {
            let entry = bc_blocks.get(head).expect("an entry names a block");
            if entry.status() == BlockStatus::Active {
                continue;
            }
            let connected = (0..4).any(|s| heads.connected_head_at(s) == Some(head));
            let value = if entry.status() == BlockStatus::Connected {
                heads.branch_value_of(head)
            } else {
                None
            };
            out[slot] = Some((
                (entry.sequence(), *entry.hash()),
                connected,
                bc_blocks.get(anchor).map(|e| *e.hash()),
                value,
            ));
        }
        out
    };
    let (ha, hb) = (
        entries(&a.blocks, &a.chain_heads),
        entries(&b.blocks, &b.chain_heads),
    );
    for eb in hb.iter().flatten() {
        assert!(
            ha.iter().flatten().any(|ea| ea == eb),
            "{what}: chain_heads entry #{} missing or different",
            (eb.0).0
        );
    }
    for ea in ha.iter().flatten() {
        if !hb.iter().flatten().any(|eb| eb.0 == ea.0) {
            let ((seq, hash), ..) = *ea;
            assert!(
                a.blocks
                    .find(seq, &hash)
                    .and_then(|i| a.blocks.get(i))
                    .is_some_and(|e| !e.is_on_active_chain()),
                "{what}: an extra entry #{seq} names a side head"
            );
        }
    }
    let mut matched = [false; 16];
    for idx in 0..16u32 {
        let Some(eb) = b.blocks.get(idx) else {
            continue;
        };
        let ai = a
            .blocks
            .find(eb.sequence(), eb.hash())
            .unwrap_or_else(|| panic!("{what}: #{} missing", eb.sequence()));
        matched[ai as usize] = true;
        let ea = a.blocks.get(ai).expect("found");
        assert_eq!(
            ea.status(),
            eb.status(),
            "{what}: status of #{}",
            eb.sequence()
        );
        assert_eq!(
            ea.is_on_active_chain(),
            eb.is_on_active_chain(),
            "{what}: flag of #{}",
            eb.sequence()
        );
        for bit in 0..AVAILABLE_UTXO_BYTES * 8 {
            assert_eq!(
                a.blocks.utxo_available(ai, bit),
                b.blocks.utxo_available(idx, bit),
                "{what}: bit {bit} of #{}",
                eb.sequence()
            );
        }
    }
    for idx in 0..16u32 {
        if let Some(ea) = a.blocks.get(idx)
            && !matched[idx as usize]
        {
            assert!(
                !ea.is_on_active_chain(),
                "{what}: extra #{} off chain",
                ea.sequence()
            );
            assert_eq!(
                a.blocks.has_available_utxo(idx),
                Some(false),
                "{what}: extra #{} holds no bit",
                ea.sequence()
            );
        }
    }
}

/// [`two_creator_chain`] on a [`FailingReadStorage`] node, unarmed.
fn failing_two_creator_chain() -> (Chain16<FailingReadStorage>, Block, Block, Block) {
    let (mut bc, b1) = failing_genesis(16);
    let a2 = alt(2, b1.view().hash(), 0, 0, 1, 7, true);
    let a3 = alt(3, a2.view().hash(), 1, 1, 0, 8, false);
    for blk in [&a2, &a3] {
        assert_eq!(receive(&mut bc, blk), ReceiveBlockOutcome::AcceptedSilently);
    }
    (bc, b1, a2, a3)
}

/// [`two_creator_chain`] on a [`FaultyStorage`] node.
fn faulty_two_creator_chain() -> (Chain16<FaultyStorage>, Block, Block, Block) {
    let (mut bc, b1) = faulty_genesis(16);
    let a2 = alt(2, b1.view().hash(), 0, 0, 1, 7, true);
    let a3 = alt(3, a2.view().hash(), 1, 1, 0, 8, false);
    for blk in [&a2, &a3] {
        assert_eq!(receive(&mut bc, blk), ReceiveBlockOutcome::AcceptedSilently);
    }
    (bc, b1, a2, a3)
}

/// A genesis node on `W = w` over a [`FailingReadStorage`], unarmed.
fn failing_genesis(w: u32) -> (Chain16<FailingReadStorage>, Block) {
    let crypto = Crypto::new([1u8; PRIVATE_KEY_SIZE]).ok().expect("key");
    let chain_config = empty_chain_config(TestChain::BUILD_LIMITS);
    let node_zero = *crypto.public_key().serialize();
    let storage = FailingReadStorage {
        inner: initialized_storage([1u8; PRIVATE_KEY_SIZE]),
        failing_slot: NONE_REF,
        reads_left: core::cell::Cell::new(0),
        failures_left: core::cell::Cell::new(u32::MAX),
        attempts: core::cell::Cell::new(0),
        reads: core::cell::Cell::new(0),
    };
    let mut slot = core::mem::MaybeUninit::<Chain16<FailingReadStorage>>::uninit();
    Chain16::<FailingReadStorage>::init(&mut slot, crypto, storage, chain_config, 0, node_zero, 0);
    // SAFETY: `init` returned, so every field of `slot` is initialized.
    let mut bc = unsafe { slot.assume_init() };
    let genesis = bc
        .process_genesis(CURRENCY, window_config_builder(w).content())
        .ok()
        .expect("genesis");
    (bc, genesis.block_one)
}

/// On [`two_creator_chain`], `s3`: node #1's sibling of `a3`, worth the
/// same 1005 but larger (three credits for node #0), so it wins.
fn heavier_sibling(a2: &Block) -> Block {
    alt(3, a2.view().hash(), 1, 1, 3, 40, false)
}

/// AC11.1 / AC10 — depth 1 and depth 2: the switch lands on the state a
/// fresh node derives on the new chain alone; the abandoned blocks are
/// Connected, off the chain, with no bit; the old head keeps the old
/// active value; the replayed blocks carry the signature mark.
#[test]
fn fr23_switch_matches_a_fresh_node_on_the_new_chain() {
    let (mut bc, _, a2, a3) = two_creator_chain();
    let s3 = heavier_sibling(&a2);
    assert_eq!(receive(&mut bc, &s3), ReceiveBlockOutcome::AcceptedSilently);
    assert_eq!(head_of(&bc), (3, s3.view().hash()));
    assert_eq!(status_of(&bc, &a3), Some(BlockStatus::Connected));
    assert_eq!(bc.chain_heads.branch_value_of(slot(&bc, &a3)), Some(1005));
    assert!(
        bc.blocks
            .get(slot(&bc, &s3))
            .is_some_and(|e| e.is_signature_verified())
    );
    let (mut fresh, _, b1) = ready_genesis(16);
    for blk in [&a2, &s3] {
        assert_eq!(
            receive(&mut fresh, blk),
            ReceiveBlockOutcome::AcceptedSilently
        );
    }
    assert_same_projection(&bc, &fresh, "depth 1");
    let _ = b1; // the fresh node's own genesis

    // Depth 2: `g3` ties `a3` and loses by hash; `g4` makes it win.
    let (mut bc, _, a2, a3) = two_creator_chain();
    let g3 = (20..400)
        .map(|salt| alt(3, a2.view().hash(), 1, 1, 1, salt, false))
        .find(|g| g.view().len() == a3.view().len() && g.view().hash() > a3.view().hash())
        .expect("a same-size sibling with a higher hash");
    let g4 = alt(4, g3.view().hash(), 0, 1, 0, 21, false);
    for blk in [&g3, &g4] {
        assert_eq!(receive(&mut bc, blk), ReceiveBlockOutcome::AcceptedSilently);
    }
    assert_eq!(head_of(&bc), (4, g4.view().hash()));
    let (mut fresh, _, _) = ready_genesis(16);
    for blk in [&a2, &g3, &g4] {
        assert_eq!(
            receive(&mut fresh, blk),
            ReceiveBlockOutcome::AcceptedSilently
        );
    }
    assert_same_projection(&bc, &fresh, "depth 2");
}

/// AC2 — the committed-block undo is the exact inverse of the per-block
/// step, for every block kind: applied as a head extension and undone,
/// the node equals a twin that never saw the block; genesis #1 undone and
/// re-applied equals itself.
#[test]
fn fr23_undo_inverts_every_block_kind() {
    fn check<S: StorageTrait, T: StorageTrait>(
        mut bc: Chain16<S>,
        twin: &Chain16<T>,
        block: &Block,
        what: &str,
    ) {
        assert_eq!(
            receive(&mut bc, block),
            ReceiveBlockOutcome::AcceptedSilently,
            "{what}"
        );
        assert_eq!(head_of(&bc).1, block.view().hash(), "{what}: applied");
        let idx = bc.active_chain_head_idx;
        assert_eq!(bc.undo_active_head(), Ok(()), "{what}: undone");
        assert_eq!(
            bc.blocks.get(idx).map(|e| e.status()),
            Some(BlockStatus::Connected)
        );
        assert_same_projection(&bc, twin, what);
    }
    // A registration (node #0's `a2`).
    let (bc, _, b1) = ready_genesis(16);
    let (twin, _, _) = ready_genesis(16);
    check(
        bc,
        &twin,
        &alt(2, b1.view().hash(), 0, 0, 1, 7, true),
        "registration",
    );
    // A transfer crediting its creator a fee (node #1's `a3`).
    let (bc, _, a2, _) = {
        let (mut bc, _, b1) = ready_genesis(16);
        let a2 = alt(2, b1.view().hash(), 0, 0, 1, 7, true);
        assert_eq!(receive(&mut bc, &a2), ReceiveBlockOutcome::AcceptedSilently);
        (bc, (), a2, ())
    };
    let twin = {
        let (mut twin, _, _) = ready_genesis(16);
        assert_eq!(
            receive(&mut twin, &a2),
            ReceiveBlockOutcome::AcceptedSilently
        );
        twin
    };
    check(
        bc,
        &twin,
        &alt(3, a2.view().hash(), 1, 1, 2, 8, false),
        "creator credit",
    );
    // A balance block: node #0's seed source moves back to #0.
    let (bc, _, b1) = ready_genesis(16);
    let (twin, _, _) = ready_genesis(16);
    let snapshot = snapshot_block(&bc, 2, b1.view().hash());
    check(bc, &twin, &snapshot, "balance");
    // A deviation (node #0 on node #1's top rank, fr28's `d`).
    let setup = || {
        let (mut bc, _, b1) = ready_genesis(16);
        let a2 = alt(2, b1.view().hash(), 0, 0, 3, 7, true);
        assert_eq!(receive(&mut bc, &a2), ReceiveBlockOutcome::AcceptedSilently);
        (bc, a2)
    };
    let ((bc, a2), (twin, _)) = (setup(), setup());
    let d = headed(
        3,
        a2.view().hash(),
        0,
        1,
        0,
        1,
        3015,
        votes_for(3, 1, 2, 60),
    );
    check(bc, &twin, &d, "deviation");
    // A complex block spending a UTXO into two outputs.
    let (bc, mint) = faulty_utxo_genesis();
    let (twin, _) = faulty_utxo_genesis();
    let tx = utxo_tx(4, &[(3, 0, 60)], None, &[Ok(30), Ok(30)]);
    check(
        bc,
        &twin,
        &complex_tx_block(4, mint.view().hash(), 0, 0, &[&tx]),
        "utxo",
    );
    // A complex block paying its creator a fee (60 in, 50 out).
    let (bc, mint) = faulty_utxo_genesis();
    let (twin, _) = faulty_utxo_genesis();
    let tx = utxo_tx(4, &[(3, 0, 60)], None, &[Ok(50)]);
    check(
        bc,
        &twin,
        &complex_tx_block(4, mint.view().hash(), 0, 0, &[&tx]),
        "utxo fee",
    );

    // Genesis #1: undone, then re-applied by the same step.
    let (mut bc, _, b1) = ready_genesis(16);
    let (twin, _, _) = ready_genesis(16);
    let idx = slot(&bc, &b1);
    assert_eq!(bc.undo_active_head(), Ok(()));
    let tail = bc.snake_chain_tail_idx;
    match bc.apply_stored_child(idx, tail) {
        ChildStep::Applied {
            advance: None,
            value,
            creator,
        } => bc.promote_replayed(idx, value, creator),
        _ => panic!("genesis #1 re-applies"),
    }
    assert_same_projection(&bc, &twin, "genesis #1");
}

/// AC11.3 / FR39 — the replay resolves UTXO references against the chain
/// it builds: a shared output the abandoned branch spent is spendable on
/// the new one, and the abandoned branch's outputs leave no bit; an
/// output that exists only on the abandoned branch is unresolvable, so
/// the block spending it is refused, the original chain restored and the
/// block deleted.
#[test]
fn fr23_replay_resolves_utxo_against_the_new_chain() {
    // `o4`: node #1 spends (3, 0) into one output (worth 1005).
    let spend = |outputs: &[Result<u64, (u32, u64)>]| {
        let tx = utxo_tx(4, &[(3, 0, 60)], None, outputs);
        move |mint: &Block| complex_tx_block(4, mint.view().hash(), 0, 0, &[&tx])
    };
    let (mut bc, mint) = faulty_utxo_genesis();
    let o4 = resign(
        &spend(&[Ok(60)])(&mint),
        1,
        vote_snapshot(1000),
        NODE_ONE_KEY,
    );
    assert_eq!(receive(&mut bc, &o4), ReceiveBlockOutcome::AcceptedSilently);
    let (mi, oi) = (slot(&bc, &mint), slot(&bc, &o4));
    assert_eq!(bc.blocks.utxo_available(mi, 0), Some(false));
    assert_eq!(bc.blocks.utxo_available(oi, 0), Some(true));
    // `n4` spends the same (3, 0) into two outputs: same value, larger.
    let n4 = resign(
        &spend(&[Ok(30), Ok(30)])(&mint),
        1,
        vote_snapshot(1000),
        NODE_ONE_KEY,
    );
    assert_eq!(receive(&mut bc, &n4), ReceiveBlockOutcome::AcceptedSilently);
    assert_eq!(head_of(&bc), (4, n4.view().hash()));
    let ni = slot(&bc, &n4);
    assert_eq!(bc.blocks.utxo_available(mi, 0), Some(false), "spent by n4");
    assert_eq!(bc.blocks.utxo_available(mi, 1), Some(true));
    assert_eq!(
        bc.blocks.has_available_utxo(oi),
        Some(false),
        "o4 holds no bit"
    );
    assert_eq!(bc.blocks.utxo_available(ni, 0), Some(true));
    assert_eq!(bc.blocks.utxo_available(ni, 1), Some(true));

    // An output only the abandoned branch holds: `x5` spends (4, 0),
    // which on its own branch is `x4`, a block without outputs.
    let (mut bc, mint) = faulty_utxo_genesis();
    let (mut twin, _) = faulty_utxo_genesis();
    let o4 = resign(
        &spend(&[Ok(60)])(&mint),
        1,
        vote_snapshot(1000),
        NODE_ONE_KEY,
    );
    assert_eq!(receive(&mut bc, &o4), ReceiveBlockOutcome::AcceptedSilently);
    assert_eq!(
        receive(&mut twin, &o4),
        ReceiveBlockOutcome::AcceptedSilently
    );
    let x4 = resign(
        &tx_block(4, mint.view().hash(), 0, votes_for(4, 0, 1, 90)),
        1,
        vote_snapshot(1000),
        NODE_ONE_KEY,
    );
    let tx = utxo_tx(5, &[(4, 0, 60)], None, &[Ok(60)]);
    let x5 = resign(
        &complex_tx_block(5, x4.view().hash(), 0, 0, &[&tx]),
        0,
        vote_snapshot(1000),
        1,
    );
    for blk in [&x5, &x4] {
        assert_eq!(receive(&mut bc, blk), ReceiveBlockOutcome::AcceptedSilently);
    }
    assert_eq!(head_of(&bc), (4, o4.view().hash()), "restored");
    assert_eq!(status_of(&bc, &x5), None, "refused and deleted");
    assert_eq!(status_of(&bc, &x4), Some(BlockStatus::Connected));
    assert_eq!(
        bc.chain_heads.branch_value_of(slot(&bc, &x4)),
        Some(brute_value(&bc, slot(&bc, &x4)))
    );
    assert_same_projection(&bc, &twin, "restored after a bad reference");
}

/// AC11.4 / D4 — switching back over a balance block restores each
/// listed owner's previous seed source: node #0 its registration in #0,
/// node #1 its registration block; a node no block names is released.
#[test]
fn fr23_seed_sources_are_restored_by_the_backward_scan() {
    let (mut bc, b0, b1) = ready_genesis(16);
    let b0i = slot(&bc, &b0);
    assert_eq!(bc.node_info.seed_source_of(0), Some(b0i));
    let r2 = register(2, b1.view().hash(), 1, NODE_ONE_KEY);
    assert_eq!(receive(&mut bc, &r2), ReceiveBlockOutcome::AcceptedSilently);
    let r2i = slot(&bc, &r2);
    let (_, balance0, vote0, _) = node_zero_snapshot(&bc);
    let s3 = {
        use moonblokz_chain_types::NodeInfo;
        let key = |byte: u8| {
            *Crypto::new([byte; PRIVATE_KEY_SIZE])
                .ok()
                .expect("key")
                .public_key()
                .serialize()
        };
        let header = BlockHeader {
            version: 1,
            sequence: 3,
            creator: 0,
            mined_amount: 0,
            payload_type: PAYLOAD_TYPE_BALANCE,
            consumed_votes: 0,
            first_voted_node: 0,
            consumed_votes_from_first_voted_node: 0,
            previous_hash: r2.view().hash(),
            signature: [0u8; SIGNATURE_SIZE],
        };
        let mut builder = BlockBuilder::new().header(header);
        for (owner, balance, vote, byte) in [(0, balance0, vote0, 1), (1, 0, 0, NODE_ONE_KEY)] {
            builder
                .add_node_info(&NodeInfo::new(owner, balance, vote, &key(byte)))
                .ok()
                .expect("add node info");
        }
        builder.set_max_node_id(1).ok().expect("max node id");
        let signer = Crypto::new([1u8; PRIVATE_KEY_SIZE]).ok().expect("key");
        builder.build_signed(&signer).ok().expect("build signed")
    };
    assert_eq!(receive(&mut bc, &s3), ReceiveBlockOutcome::AcceptedSilently);
    let s3i = slot(&bc, &s3);
    assert_eq!(bc.node_info.seed_source_of(0), Some(s3i));
    assert_eq!(bc.node_info.seed_source_of(1), Some(s3i));
    // A larger sibling of `s3` (worth 0 as well) wins.
    let n3 = tx_block(3, r2.view().hash(), 0, votes_for(3, 0, 3, 80));
    assert_eq!(receive(&mut bc, &n3), ReceiveBlockOutcome::AcceptedSilently);
    assert_eq!(head_of(&bc), (3, n3.view().hash()));
    assert_eq!(bc.node_info.seed_source_of(0), Some(b0i));
    assert_eq!(bc.node_info.seed_source_of(1), Some(r2i));
    let (mut fresh, _, _) = ready_genesis(16);
    for blk in [&r2, &n3] {
        assert_eq!(
            receive(&mut fresh, blk),
            ReceiveBlockOutcome::AcceptedSilently
        );
    }
    assert_same_projection(&bc, &fresh, "seed sources");
    // No block below names node 9: released.
    let mut out = [NONE_REF];
    assert_eq!(
        bc.previous_seed_sources(bc.active_chain_head_idx, &[9], &mut out),
        Ok(())
    );
    assert_eq!(out, [SEED_SOURCE_RELEASED]);
}

/// AC11.5 / DEC-147 — registration-key uniqueness on the new branch: a key
/// the shared chain registered is refused at the replay; a key only the
/// abandoned branch registered is free.
#[test]
fn fr23_replay_checks_key_uniqueness_on_the_new_branch() {
    let (mut bc, _, a2, a3) = two_creator_chain();
    let (twin, _, _, _) = two_creator_chain();
    let dup = resign(
        &tx_block(3, a2.view().hash(), 0, |b| {
            b.add_registration(&registration_tx(0, 2, NODE_ONE_KEY))
                .ok()
                .expect("add registration");
        }),
        1,
        vote_snapshot(1000),
        NODE_ONE_KEY,
    );
    assert!(dup.view().len() > a3.view().len());
    assert_eq!(
        receive(&mut bc, &dup),
        ReceiveBlockOutcome::AcceptedSilently
    );
    assert_eq!(
        status_of(&bc, &dup),
        None,
        "a duplicate key on its own branch"
    );
    assert_same_projection(&bc, &twin, "duplicate key");

    let (mut bc, _, b1) = ready_genesis(16);
    let a2 = alt(2, b1.view().hash(), 0, 0, 1, 7, true);
    let a3 = alt(3, a2.view().hash(), 1, 1, 0, 8, false);
    for blk in [&a2, &a3] {
        assert_eq!(receive(&mut bc, blk), ReceiveBlockOutcome::AcceptedSilently);
    }
    let n2 = alt(2, b1.view().hash(), 0, 0, 1, 99, true);
    let n3 = alt(3, n2.view().hash(), 1, 1, 3, 98, false);
    for blk in [&n3, &n2] {
        assert_eq!(receive(&mut bc, blk), ReceiveBlockOutcome::AcceptedSilently);
    }
    assert_eq!(
        head_of(&bc),
        (3, n3.view().hash()),
        "the abandoned key is free"
    );
}

/// AC11.6 / AC6 — exact evidence at the first, a middle and the last new
/// block: the original chain is restored exactly, the offender goes with
/// its descendants, and the entry retargeted onto its parent carries the
/// parent's value.
#[test]
fn fr23_evidence_restores_and_deletes_the_offender() {
    for bad in 0..3 {
        let (mut bc, _, a2, a3) = two_creator_chain();
        let (twin, _, _, _) = two_creator_chain();
        let forge = |i: usize, block: Block, creator: u32, key: u8| {
            if i == bad {
                resign(&block, creator, block.view().consumed_votes() + 7, key)
            } else {
                block
            }
        };
        let x3 = forge(
            0,
            alt(3, a2.view().hash(), 1, 1, 1, 50, false),
            1,
            NODE_ONE_KEY,
        );
        let x4 = forge(1, alt(4, x3.view().hash(), 0, 1, 1, 51, false), 0, 1);
        let x5 = forge(
            2,
            alt(5, x4.view().hash(), 1, 1, 0, 52, false),
            1,
            NODE_ONE_KEY,
        );
        let blocks = [&x3, &x4, &x5];
        for blk in [&x5, &x4, &x3] {
            assert_eq!(receive(&mut bc, blk), ReceiveBlockOutcome::AcceptedSilently);
        }
        assert_eq!(head_of(&bc), (3, a3.view().hash()), "bad #{}", bad + 3);
        for (i, blk) in blocks.iter().enumerate() {
            if i >= bad {
                assert_eq!(status_of(&bc, blk), None, "bad #{}: deleted", bad + 3);
            } else {
                assert_eq!(status_of(&bc, blk), Some(BlockStatus::Connected));
            }
        }
        if bad > 0 {
            let pi = slot(&bc, blocks[bad - 1]);
            assert_eq!(
                bc.chain_heads.branch_value_of(pi),
                Some(brute_value(&bc, pi)),
                "bad #{}: the retarget's value",
                bad + 3
            );
        }
        assert_same_projection(&bc, &twin, "after evidence");
    }
}

/// AC11.6 / AC6 — local failures restore with no deletion: a read in the
/// backward walk, in the forward replay (a UTXO output below the common
/// ancestor) and in the seed-source scan. The candidate switches at its
/// next trigger. A save never happens: the switch writes nothing.
#[test]
fn fr23_local_failures_keep_the_candidate() {
    // Backward walk: `a3` reads once (`s3`'s FORK valuation), then
    // fails for the undo.
    let (mut bc, _, a2, a3) = failing_two_creator_chain();
    let s3 = heavier_sibling(&a2);
    bc.storage.failing_slot = slot(&bc, &a3);
    bc.storage.reads_left.set(1);
    assert_eq!(receive(&mut bc, &s3), ReceiveBlockOutcome::AcceptedSilently);
    assert_eq!(head_of(&bc), (3, a3.view().hash()));
    assert_eq!(status_of(&bc, &s3), Some(BlockStatus::Connected), "kept");
    assert_eq!(bc.storage.attempts.get(), 2, "valued, then the undo failed");
    bc.storage.failing_slot = NONE_REF;
    let si = slot(&bc, &s3);
    assert_eq!(
        bc.switch_toward(si),
        SwitchOutcome::Switched,
        "at the next try"
    );
    assert_eq!(head_of(&bc), (3, s3.view().hash()));

    // No durable write (AC7): `s3`'s switch is kept once (its pre-pass
    // cannot read it back), then runs with every save failing.
    let (mut bc, _, a2, a3) = faulty_two_creator_chain();
    let s3 = heavier_sibling(&a2);
    bc.storage.failing_read_slot = bc.blocks.next_free_index().expect("a free slot");
    assert_eq!(receive(&mut bc, &s3), ReceiveBlockOutcome::AcceptedSilently);
    assert_eq!(head_of(&bc), (3, a3.view().hash()), "kept");
    bc.storage.failing_read_slot = NONE_REF;
    bc.storage.fail_saves = true;
    let si = slot(&bc, &s3);
    assert_eq!(bc.switch_toward(si), SwitchOutcome::Switched);
    assert_eq!(head_of(&bc), (3, s3.view().hash()));
    bc.storage.fail_saves = false;

    // Forward replay: `n4` spends from the mint, which cannot be read.
    let (mut bc, mint) = faulty_utxo_genesis();
    let o4 = real_on(&bc, &transfer(4, mint.view().hash(), 0, 7), 1, NODE_ONE_KEY);
    assert_eq!(receive(&mut bc, &o4), ReceiveBlockOutcome::AcceptedSilently);
    let tx = utxo_tx_vote(1, 4, &[(3, 0, 60)], None, &[Ok(60)]);
    let n4 = complex_tx_block(4, mint.view().hash(), 0, 0, &[&tx]);
    assert_eq!(receive(&mut bc, &n4), ReceiveBlockOutcome::AcceptedSilently);
    assert_eq!(status_of(&bc, &n4), Some(BlockStatus::Connected));
    let n5 = resign(
        &transfer(5, n4.view().hash(), 0, 9),
        1,
        vote_snapshot(vote_snapshot(1000) + 1000),
        NODE_ONE_KEY,
    );
    bc.storage.failing_read_slot = slot(&bc, &mint);
    assert_eq!(receive(&mut bc, &n5), ReceiveBlockOutcome::AcceptedSilently);
    assert_eq!(head_of(&bc), (4, o4.view().hash()), "kept");
    // Story 6.7 review: `n5`'s run walk cannot read the mint, so its Tier 2
    // gives no verdict and it stays Stored (local).
    assert_eq!(status_of(&bc, &n5), Some(BlockStatus::Stored));
    bc.storage.failing_read_slot = NONE_REF;
    // `n5`'s transfer credited node #0 once.
    let n6 = resign(
        &transfer(6, n5.view().hash(), 0, 10),
        0,
        vote_snapshot(1000),
        1,
    );
    assert_eq!(receive(&mut bc, &n6), ReceiveBlockOutcome::AcceptedSilently);
    assert_eq!(
        head_of(&bc),
        (6, n6.view().hash()),
        "switched at the next trigger"
    );

    // Seed-source scan: #0 cannot be read.
    let (mut bc, b1) = faulty_genesis(16);
    let a2 = snapshot_block(&bc, 2, b1.view().hash());
    assert_eq!(receive(&mut bc, &a2), ReceiveBlockOutcome::AcceptedSilently);
    let n2 = tx_block(2, b1.view().hash(), 0, votes_for(2, 0, 3, 81));
    bc.storage.failing_read_slot = 0;
    assert_eq!(receive(&mut bc, &n2), ReceiveBlockOutcome::AcceptedSilently);
    assert_eq!(head_of(&bc), (2, a2.view().hash()), "kept");
    assert_eq!(status_of(&bc, &n2), Some(BlockStatus::Connected));
    assert_eq!(bc.node_info.seed_source_of(0), Some(slot(&bc, &a2)));
}

/// AC11.6 / AC6, DEC-205 — a restore failure: `a3`'s re-read fails
/// while the original chain is re-applied, and the node re-enters
/// collecting over the retained tree. A transient fault: the re-entry
/// reaches `Ready` again in the same call, on `a3`, equal to a node that
/// never saw the forgery. A persistent one: the re-entry's pass fails
/// locally, the node stays collecting with nothing of the original chain
/// deleted, and the next admission after the fault clears it brings the
/// node back to `Ready`.
#[test]
fn fr23_restore_failure_reenters_collecting() {
    let (mut fresh, _, _) = ready_genesis(16);
    for transient in [true, false] {
        let (mut bc, b1) = failing_genesis(16);
        let a2 = alt(2, b1.view().hash(), 0, 0, 1, 7, true);
        let a3 = alt(3, a2.view().hash(), 1, 1, 0, 8, false);
        for blk in [&a2, &a3] {
            assert_eq!(receive(&mut bc, blk), ReceiveBlockOutcome::AcceptedSilently);
            if transient {
                assert_eq!(
                    receive(&mut fresh, blk),
                    ReceiveBlockOutcome::AcceptedSilently
                );
            }
        }
        let forged = resign(&heavier_sibling(&a2), 1, 2000, NODE_ONE_KEY);
        assert_eq!(
            receive(&mut bc, &forged),
            ReceiveBlockOutcome::AcceptedSilently
        );
        assert_eq!(status_of(&bc, &forged), None, "attempted once, deleted");
        // A second forgery, now with `a3` readable twice only: the FORK
        // valuation and the undo; the restore's re-read fails.
        let forged = resign(&heavier_sibling(&a2), 1, 2001, NODE_ONE_KEY);
        bc.storage.failing_slot = slot(&bc, &a3);
        bc.storage.reads_left.set(2);
        bc.storage
            .failures_left
            .set(if transient { 1 } else { u32::MAX });
        assert_eq!(
            receive(&mut bc, &forged),
            ReceiveBlockOutcome::AcceptedSilently
        );
        assert_eq!(
            status_of(&bc, &forged),
            None,
            "the offender is still deleted"
        );
        if transient {
            assert!(bc.is_ready(), "re-entered ready in the same call");
            assert_eq!(head_of(&bc), (3, a3.view().hash()));
            assert_same_projection(&bc, &fresh, "re-entered on a3");
            continue;
        }
        assert!(!bc.is_ready(), "the re-entry's pass failed locally");
        for blk in [&a2, &a3] {
            assert_eq!(status_of(&bc, blk), Some(BlockStatus::Stored));
        }
        bc.storage.failing_slot = NONE_REF;
        let a4 = alt(4, a3.view().hash(), 0, 0, 0, 9, false);
        assert_eq!(receive(&mut bc, &a4), ReceiveBlockOutcome::AcceptedSilently);
        assert!(bc.is_ready());
        assert_eq!(head_of(&bc), (4, a4.view().hash()));
        assert_eq!(
            receive(&mut fresh, &a4),
            ReceiveBlockOutcome::AcceptedSilently
        );
        assert_same_projection(&bc, &fresh, "ready again on a4");
    }
}

/// AC11.7 / D3 — on W6 (`#0, #1, b2..=b5`, tail not advanced) the new
/// branch from `b2` crosses `W`: its replay advances a virtual tail past
/// #0, #1 and finally `b2`, the common ancestor. The failing case: `n7`
/// skips the chain-config replay #1 needs (exact evidence) after the
/// virtual tail passed #0, and the original branch is restored exactly,
/// #0 still retained. The success case: the commit moves #0, #1 and `b2`,
/// the common ancestor, out of the window, and with it releases the
/// abandoned branch — the release a failure after it could not have
/// undone. The branch is `W` blocks long, so it runs on the fourteen-slot
/// storage ([`full_w6_genesis`]).
#[test]
fn fr23_tail_advances_wait_for_the_commit() {
    // Every block is node #0's and worth 0; `n6` replays #0 (node #0's
    // seed source), `n8` drops `b2`, which holds no obligation, and makes
    // the tip larger than `b5`. #5 and #8 are clean slots.
    let branch = |bc: &Chain16<W6Storage>, b2: &Block, last_is_replay: bool| {
        let n3 = transfer(3, b2.view().hash(), 0, 51);
        let n4 = transfer(4, n3.view().hash(), 0, 54);
        let n5 = transfer(5, n4.view().hash(), 0, 55);
        let n6 = snapshot_block(bc, 6, n5.view().hash());
        let n7 = if last_is_replay {
            w6_config_anchor_block(7, n6.view().hash())
        } else {
            tx_block(7, n6.view().hash(), 0, votes_for(7, 0, 3, 52))
        };
        let n8 = tx_block(8, n7.view().hash(), 0, votes_for(8, 0, 3, 53));
        [n3, n4, n5, n6, n7, n8]
    };
    let (_, _, b1) = ready_genesis_w6();
    let b2 = transfer(2, b1.view().hash(), 0, 7);
    for last_is_replay in [false, true] {
        let (mut bc, b5) = full_w6_genesis();
        let (twin, _) = full_w6_genesis();
        let blocks = branch(&bc, &b2, last_is_replay);
        assert!(blocks[5].view().len() > b5.view().len());
        for blk in blocks.iter().rev() {
            assert_eq!(receive(&mut bc, blk), ReceiveBlockOutcome::AcceptedSilently);
        }
        if last_is_replay {
            assert_eq!(head_of(&bc), (8, blocks[5].view().hash()));
            assert_eq!(bc.active_snake_chain_window(), Ok((3, 8)));
            assert_eq!(status_of(&bc, &b5), None, "released with b2's forks");
            let (mut fresh, _, _) = ready_genesis_w6();
            assert_eq!(
                receive(&mut fresh, &b2),
                ReceiveBlockOutcome::AcceptedSilently
            );
            for blk in &blocks {
                assert_eq!(
                    receive(&mut fresh, blk),
                    ReceiveBlockOutcome::AcceptedSilently
                );
            }
            assert_same_projection(&bc, &fresh, "committed");
            // Story 6.4 AC9 3c: the deferred advances' decrements.
            assert_active_set_matches(&bc, "committed with advances");
        } else {
            assert_eq!(head_of(&bc), (5, b5.view().hash()), "restored");
            assert_eq!(bc.active_snake_chain_window(), Ok((0, 5)));
            assert_eq!(status_of(&bc, &blocks[4]), None, "skipped replay: deleted");
            assert_eq!(status_of(&bc, &blocks[5]), None, "with its descendant");
            assert_eq!(status_of(&bc, &blocks[3]), Some(BlockStatus::Connected));
            assert_same_projection(&bc, &twin, "restored after the advances");
            // Story 6.4 AC9 3c: the unwound virtual advances.
            assert_active_set_matches(&bc, "restored after the advances");
        }
    }
}

/// AC11.8 / DEC-204; Story 6.14 AC4 — once the tail has advanced, a heavier
/// admissible fork inside `H` is switched toward in place: its replayed
/// block at #6 is bound against the dropped block the horizon retained
/// (#0, node #0's seed source), and skipping that replay is exact
/// evidence. The fork is deleted and the original chain restored.
#[test]
fn fr23_replay_binds_against_the_horizon() {
    let (mut bc, b5) = full_w6_genesis();
    let (mut twin, _) = full_w6_genesis();
    let r6 = snapshot_block(&bc, 6, b5.view().hash());
    for node in [&mut bc, &mut twin] {
        assert_eq!(receive(node, &r6), ReceiveBlockOutcome::AcceptedSilently);
    }
    assert_eq!(bc.active_snake_chain_window(), Ok((1, 6)));
    assert_eq!(
        bc.blocks.get(bc.horizon_root()).map(|e| e.sequence()),
        Some(0),
        "#0 is retained below the tail"
    );
    let s6 = tx_block(6, b5.view().hash(), 0, votes_for(6, 0, 3, 60));
    assert_eq!(receive(&mut bc, &s6), ReceiveBlockOutcome::AcceptedSilently);
    assert_eq!(status_of(&bc, &s6), None, "the skipped replay deleted it");
    assert_eq!(head_of(&bc), (6, r6.view().hash()));
    assert_same_projection(&bc, &twin, "restored");
}

/// AC11.9 / D5 — the pre-pass: a bad signature by a creator registered at
/// or below the common ancestor is deleted before anything is touched (no
/// read of the old head); one by a creator
/// registered above it is refused by the replay instead, which restores
/// and deletes it.
///
/// Rebased by Story 6.4 (D3): a forged sibling whose parent is an active
/// block (`a2`) is now caught by Tier 1 at intake, measured against the key
/// at its parent, so the pre-pass case uses a forged block on a side block
/// (`s3`), whose parent is off the active chain and keeps the tail bound.
#[test]
fn fr23_signature_prepass() {
    let (mut bc, _, a2, a3) = failing_two_creator_chain();
    let forged_sibling = resign(&heavier_sibling(&a2), 1, vote_snapshot(1000), 0x66);
    assert_eq!(
        receive(&mut bc, &forged_sibling),
        ReceiveBlockOutcome::Rejected(RejectReason::InvalidEvidence),
        "Tier 1 judges it against the key at its active parent"
    );
    let s3 = (20..400)
        .map(|salt| alt(3, a2.view().hash(), 1, 1, 0, salt, false))
        .find(|g| g.view().len() == a3.view().len() && g.view().hash() > a3.view().hash())
        .expect("a same-size sibling with a higher hash");
    assert_eq!(receive(&mut bc, &s3), ReceiveBlockOutcome::AcceptedSilently);
    assert_eq!(head_of(&bc), (3, a3.view().hash()), "a tie lost by hash");
    let bad = resign(
        &alt(4, s3.view().hash(), 0, 1, 0, 41, false),
        1,
        vote_snapshot(1000),
        0x66,
    );
    bc.storage.failing_slot = slot(&bc, &a3);
    bc.storage.reads_left.set(1);
    assert_eq!(
        receive(&mut bc, &bad),
        ReceiveBlockOutcome::AcceptedSilently
    );
    assert_eq!(status_of(&bc, &bad), None, "deleted by the pre-pass");
    assert_eq!(head_of(&bc), (3, a3.view().hash()));
    assert_eq!(
        bc.storage.attempts.get(),
        0,
        "the fork already exists at s3: nothing of the old branch is read"
    );
    bc.storage.failing_slot = NONE_REF;

    let (mut bc, b1, _, a3) = two_creator_chain();
    let (twin, _, _, _) = two_creator_chain();
    let n2 = alt(2, b1.view().hash(), 0, 0, 1, 55, true);
    let n3 = resign(
        &alt(3, n2.view().hash(), 1, 1, 3, 56, false),
        1,
        vote_snapshot(1000),
        0x66,
    );
    for blk in [&n3, &n2] {
        assert_eq!(receive(&mut bc, blk), ReceiveBlockOutcome::AcceptedSilently);
    }
    assert_eq!(head_of(&bc), (3, a3.view().hash()));
    assert_eq!(status_of(&bc, &n3), None, "refused by the replay");
    let n2i = slot(&bc, &n2);
    assert!(
        bc.blocks
            .get(n2i)
            .is_some_and(|e| e.is_signature_verified())
    );
    assert_same_projection(&bc, &twin, "after the replay's refusal");
}

/// AC10 — the same block set in three admission orders ends on the same
/// head with the same derived state, through zero, one or two switches.
#[test]
fn fr23_admission_order_does_not_change_the_outcome() {
    let base = || {
        let (mut bc, _, b1) = ready_genesis(16);
        let a2 = alt(2, b1.view().hash(), 0, 0, 1, 7, true);
        assert_eq!(receive(&mut bc, &a2), ReceiveBlockOutcome::AcceptedSilently);
        (bc, a2)
    };
    let (_, a2) = base();
    let a3 = alt(3, a2.view().hash(), 1, 1, 0, 8, false);
    let g3 = (20..400)
        .map(|salt| alt(3, a2.view().hash(), 1, 1, 1, salt, false))
        .find(|g| g.view().len() == a3.view().len() && g.view().hash() > a3.view().hash())
        .expect("a same-size sibling with a higher hash");
    let g4 = alt(4, g3.view().hash(), 0, 1, 0, 21, false);
    let orders = [[&a3, &g3, &g4], [&g4, &g3, &a3], [&g3, &a3, &g4]];
    let run = |order: &[&Block; 3]| {
        let (mut bc, _) = base();
        for blk in order {
            assert_eq!(receive(&mut bc, blk), ReceiveBlockOutcome::AcceptedSilently);
        }
        assert_eq!(head_of(&bc), (4, g4.view().hash()));
        bc
    };
    let first = run(&orders[0]);
    for (i, order) in orders.iter().enumerate().skip(1) {
        let other = run(order);
        assert_same_projection(&other, &first, if i == 1 { "order 2" } else { "order 3" });
    }
}

/// AC11.6 / AC6, DEC-205 — a restore failure while undoing the replayed
/// prefix: the walk stops on the new branch at `x3`, the offender `x4`
/// is deleted, and the node re-enters collecting over the retained tree.
/// The fault is transient, so the re-entry reaches `Ready` again in the
/// same call, and its comparison leaves the node equal to one fed the
/// same blocks without the offender, whichever tip FR2 picked.
#[test]
fn fr23_restore_failure_on_the_new_branch_reenters_collecting() {
    let blocks = |a2: &Block| {
        let x3 = alt(3, a2.view().hash(), 1, 1, 1, 70, false);
        let x4 = resign(&alt(4, x3.view().hash(), 0, 1, 0, 71, false), 0, 9, 1);
        (x3, x4)
    };
    // Count `x3`'s reads on a twin, then fail its last one: the
    // restore's undo.
    let reads = {
        let (mut twin, _, a2, _) = failing_two_creator_chain();
        let (x3, x4) = blocks(&a2);
        assert_eq!(
            receive(&mut twin, &x4),
            ReceiveBlockOutcome::AcceptedSilently
        );
        twin.storage.failing_slot = twin.blocks.next_free_index().expect("a free slot");
        twin.storage.reads_left.set(1000);
        assert_eq!(
            receive(&mut twin, &x3),
            ReceiveBlockOutcome::AcceptedSilently
        );
        assert_eq!(head_of(&twin).0, 3, "the twin restored fully");
        twin.storage.attempts.get()
    };
    let (mut bc, _, a2, a3) = failing_two_creator_chain();
    let (x3, x4) = blocks(&a2);
    assert_eq!(receive(&mut bc, &x4), ReceiveBlockOutcome::AcceptedSilently);
    bc.storage.failing_slot = bc.blocks.next_free_index().expect("a free slot");
    bc.storage.reads_left.set(reads - 1);
    bc.storage.failures_left.set(1);
    assert_eq!(receive(&mut bc, &x3), ReceiveBlockOutcome::AcceptedSilently);
    assert_eq!(
        bc.storage.failures_left.get(),
        0,
        "the restore's undo failed"
    );
    assert_eq!(status_of(&bc, &x4), None, "the offender is deleted");
    assert!(bc.is_ready(), "re-entered ready in the same call");
    let (mut fresh, _, _) = ready_genesis(16);
    for blk in [&a2, &a3, &x3] {
        assert_eq!(
            receive(&mut fresh, blk),
            ReceiveBlockOutcome::AcceptedSilently
        );
    }
    assert_eq!(head_of(&bc), head_of(&fresh));
    assert_same_projection(&bc, &fresh, "re-entered without the offender");
}

/// AC10 — switch, then restart: FR2 picks the sequence-3 tip with the
/// lower hash, `a3`, so only the restart's comparison can bring the head
/// back to the heavier `s3`.
#[test]
fn fr23_switch_survives_a_restart() {
    let (mut bc, _, a2, a3) = two_creator_chain();
    let s3 = (40..400)
        .map(|salt| alt(3, a2.view().hash(), 1, 1, 3, salt, false))
        .find(|s| s.view().hash() > a3.view().hash())
        .expect("a heavier sibling with a higher hash");
    assert_eq!(receive(&mut bc, &s3), ReceiveBlockOutcome::AcceptedSilently);
    assert_eq!(head_of(&bc), (3, s3.view().hash()));
    let mut restarted = restart(bc);
    let _ = restarted.initialize_from_storage(0);
    assert!(restarted.is_ready());
    assert_eq!(head_of(&restarted), (3, s3.view().hash()));
}
