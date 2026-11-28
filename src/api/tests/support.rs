//! Tests of `api/support.rs`.

use super::*;

// ---- Story 6.4: ADR-015 subgroup selection and FR12 support emission ----

/// AC2 — the size pin (deferred-work D8): the owned support message and the
/// outcome that carries it. Three `u32`s, the hash and the backend's
/// serialized multi-signature, with no padding; the outcome adds its tag,
/// rounded to the `u32` alignment: 108 / 112 B on `schnorr` (64-byte
/// signature), 92 / 96 B on `bls-min-sig` (48), 140 / 144 B on `bls-min-pk`
/// (96).
#[test]
fn the_support_outcome_has_its_pinned_size() {
    use moonblokz_chain_types::HASH_SIZE;
    use moonblokz_crypto::MULTI_SIGNATURE_SIZE;
    let message = core::mem::size_of::<SupportMessage>();
    assert_eq!(message, 3 * 4 + HASH_SIZE + MULTI_SIGNATURE_SIZE);
    assert_eq!(core::mem::size_of::<ReceiveBlockOutcome>(), message + 4);
}

/// AC3 — a forged direct extension of the head is exact evidence, never
/// stored: the deferred-work "FR16 Ready-state direct-extension signature
/// check → 6.4", already built by Story 6.0, pinned here.
#[test]
fn a_forged_direct_extension_is_refused() {
    let (mut bc, _, _, a3) = two_creator_chain();
    let direct = headed(
        4,
        a3.view().hash(),
        1,
        0x43,
        0,
        1,
        0,
        votes_for(4, 0, 1, 903),
    );
    assert_eq!(
        receive(&mut bc, &direct),
        ReceiveBlockOutcome::Rejected(RejectReason::InvalidEvidence)
    );
    assert_eq!(status_of(&bc, &direct), None, "not stored");
}

/// AC9 test 4 (D3) — Tier 1 measures a block whose parent is a flagged
/// active-chain block against the key at its parent, not at the tail.
/// Node #1 is registered by `a2` (sequence 2) above the tail (#0), so the
/// old bound left its siblings unverified.
#[test]
fn tier1_verifies_a_sibling_against_the_key_at_its_active_parent() {
    // Seeded inside `(tail, p − 1]`: a sibling of `a3` on `a2` is
    // verified, and a bad signature is exact evidence, never stored.
    let (mut bc, _, a2, _) = two_creator_chain();
    let good = headed(
        3,
        a2.view().hash(),
        1,
        NODE_ONE_KEY,
        0,
        1,
        0,
        votes_for(3, 0, 1, 900),
    );
    assert_eq!(
        receive(&mut bc, &good),
        ReceiveBlockOutcome::AcceptedSilently
    );
    assert_eq!(verified(&bc, &good), Some(true));
    let forged = headed(
        3,
        a2.view().hash(),
        1,
        0x43,
        0,
        1,
        0,
        votes_for(3, 0, 1, 901),
    );
    assert_eq!(
        receive(&mut bc, &forged),
        ReceiveBlockOutcome::Rejected(RejectReason::InvalidEvidence)
    );
    assert_eq!(status_of(&bc, &forged), None, "not stored");

    // Seeded above `p − 1`: a node #1 sibling of `a2` on `b1` is admitted
    // unverified — its key is not its branch's key at `p − 1 = 1`.
    let (mut bc, b1, _, _) = two_creator_chain();
    let early = headed(
        2,
        b1.view().hash(),
        1,
        NODE_ONE_KEY,
        0,
        1,
        0,
        votes_for(2, 0, 1, 902),
    );
    assert_eq!(
        receive(&mut bc, &early),
        ReceiveBlockOutcome::AcceptedSilently
    );
    assert_eq!(verified(&bc, &early), Some(false));
}

// -- Story 6.4 fixtures: a separate local node on a multi-creator chain --

/// AC9 test 1 (shape (a), AC7) — a direct-extension deviation by node 4:
/// node 3, in `A' = {0, 3}` and so in the subgroup, endorses it, and the
/// signature verifies over the 45-byte content. Also AC9 test 3b (M8): the
/// chain is in its growth phase (`S_head + 1 < W`) and its tail #0 is a
/// seed source, so nothing is due.
#[test]
fn a_direct_deviation_is_endorsed() {
    set_grace_admits(true);
    let (g, mut l, blocks) = support_chain(3);
    assert_active_set_matches(&l, "after the extensions");
    let x = deviation_after(&g, &blocks[5], 4, 1);
    let message = support_for(&mut l, &x).expect("support");
    assert_eq!(head_of(&l), (6, x.view().hash()), "x is active (shape (a))");
    assert_eq!(message.supporter_node_id, 3);
    assert_eq!(message.proposer_node_id, 4);
    assert_eq!(message.deviation_sequence, 6);
    assert_eq!(message.deviation_block_hash, x.view().hash());
    let signature = MultiSignature::new(&message.support_signature)
        .ok()
        .expect("well-formed");
    let bytes = support_message_bytes(4, 6, &x.view().hash());
    assert!(
        l.crypto
            .verify_multi_signature(&bytes, &signature, l.crypto.public_key())
    );
    // A re-send for the same block is allowed (AC6).
    assert_eq!(
        l.non_conflict.check(
            RING_KIND_SUPPORT,
            4,
            6,
            NonConflictRing::key_of(&x.view().hash())
        ),
        RingCheck::SameBlock
    );
    assert_active_set_matches(&l, "after the deviation");
    set_grace_admits(false);
}

/// AC9 test 2 (shape (b)) — `d`, node 5's approval-less deviation, is
/// active at 6; node 2's lighter sibling `x` stays a side block, verified
/// at Tier 1 against the key at #5, and node 3 endorses both. Then the
/// switch case: the heavier sibling becomes active through FR22 and is
/// endorsed in shape (a).
#[test]
fn a_sibling_of_an_approval_less_deviation_is_endorsed() {
    set_grace_admits(true);
    {
        let (g, mut l, blocks) = support_chain(3);
        let d = deviation_after(&g, &blocks[5], 5, 1);
        assert!(support_for(&mut l, &d).is_some(), "d itself, in shape (a)");
        let x = deviation_after(&g, &blocks[5], 2, 2);
        let message = support_for(&mut l, &x).expect("support for the sibling");
        assert_eq!(
            (message.proposer_node_id, message.deviation_sequence),
            (2, 6)
        );
        assert_eq!(head_of(&l), (6, d.view().hash()), "x stays a side block");
        assert_eq!(status_of(&l, &x), Some(BlockStatus::Connected));
        assert_eq!(verified(&l, &x), Some(true));
    }

    // The switch: the lighter `d` (node 2) first, then the heavier `x`
    // (node 5), which FR22 makes active.
    let (g, mut l, blocks) = support_chain(3);
    let d = deviation_after(&g, &blocks[5], 2, 3);
    assert!(support_for(&mut l, &d).is_some());
    let x = deviation_after(&g, &blocks[5], 5, 4);
    let message = support_for(&mut l, &x).expect("support after the switch");
    assert_eq!(head_of(&l), (6, x.view().hash()), "switched to x");
    assert_eq!(message.proposer_node_id, 5);
    assert_active_set_matches(&l, "after the switch");
    set_grace_admits(false);
}

/// AC9 test 3 — no support: each test starts from the eligible fixture of
/// test 1 (or test 2 for the shape-(b) cases) with one condition flipped.
#[test]
fn no_support_while_collecting() {
    set_grace_admits(true);
    let (g, _, blocks) = support_chain(3);
    let x = deviation_after(&g, &blocks[5], 4, 1);
    let mut collecting = local_node(3, local_storage(3));
    assert_eq!(support_for(&mut collecting, &x), None);
    set_grace_admits(false);
}

/// AC9 test 3 — `x` by `u` is no deviation (normal form).
#[test]
fn no_support_for_a_block_by_u() {
    set_grace_admits(true);
    let (g, mut l, blocks) = support_chain(3);
    assert_eq!(
        support_for(&mut l, &normal_after(&g, &blocks[5], 1, 1)),
        None
    );
    set_grace_admits(false);
}

/// AC9 test 3 — the local node is the proposer.
#[test]
fn no_support_when_local_is_the_proposer() {
    set_grace_admits(true);
    let (g, mut l, blocks) = support_chain(4);
    assert_eq!(
        support_for(&mut l, &deviation_after(&g, &blocks[5], 4, 1)),
        None
    );
    set_grace_admits(false);
}

/// AC9 test 3 / M1 — the local node is `u`, although `u` is in `A`.
#[test]
fn no_support_when_local_is_u() {
    set_grace_admits(true);
    let (g, mut l, blocks) = support_chain(1);
    assert_eq!(
        support_for(&mut l, &deviation_after(&g, &blocks[5], 4, 1)),
        None
    );
    set_grace_admits(false);
}

/// AC9 test 3 — the local node created nothing in the window.
#[test]
fn no_support_when_local_is_outside_the_window() {
    set_grace_admits(true);
    let (g, mut l, blocks) = support_chain(2);
    assert_eq!(
        support_for(&mut l, &deviation_after(&g, &blocks[5], 4, 1)),
        None
    );
    set_grace_admits(false);
}

/// AC9 test 3 — the grace seam at its production value.
#[test]
fn no_support_while_grace_refuses() {
    set_grace_admits(false);
    let (g, mut l, blocks) = support_chain(3);
    assert_eq!(
        support_for(&mut l, &deviation_after(&g, &blocks[5], 4, 1)),
        None
    );
}

/// AC9 test 3 / M4 — a conflicting second candidate at the same
/// `(proposer, p)`: node 2's two siblings of node 5's `d` both pass the
/// shape, so only the non-conflict record refuses the second.
#[test]
fn no_support_for_a_conflicting_candidate() {
    set_grace_admits(true);
    let (g, mut l, blocks) = support_chain(3);
    assert!(support_for(&mut l, &deviation_after(&g, &blocks[5], 5, 1)).is_some());
    assert!(support_for(&mut l, &deviation_after(&g, &blocks[5], 2, 2)).is_some());
    assert_eq!(
        support_for(&mut l, &deviation_after(&g, &blocks[5], 2, 3)),
        None
    );
    set_grace_admits(false);
}

/// AC9 test 3 — `u`'s own block at `p` is held (DEC-183): a forged-value
/// block by node 1 on #5, a light side block beside test 2's `d`.
#[test]
fn no_support_once_us_block_is_held() {
    set_grace_admits(true);
    let (g, mut l, blocks) = support_chain(3);
    assert!(support_for(&mut l, &deviation_after(&g, &blocks[5], 5, 1)).is_some());
    let template = tx_block(6, blocks[5].view().hash(), 0, votes_for(6, 0, 1, 77));
    let u_block = reheader(&template, 1, 0, 1, 0, key_of(1));
    assert_eq!(
        receive(&mut l, &u_block),
        ReceiveBlockOutcome::AcceptedSilently
    );
    assert_eq!(
        support_for(&mut l, &deviation_after(&g, &blocks[5], 2, 2)),
        None
    );
    set_grace_admits(false);
}

/// AC9 test 3 — converted by Story 6.7 D4 (it pinned that a block above
/// `p` by another creator fails shape (b) for a sibling's support): inside
/// `d`'s open run only `d`'s creator may extend it (FR27 rule 1,
/// `RunCreator`), so the supporter refuses that block at intake and its
/// head stays `d`. A head above `d` is `d`'s creator's or `d`'s evidence,
/// so shape (b)'s foreign-creator stop is unreachable.
#[test]
fn a_supporter_refuses_another_creator_above_p() {
    set_grace_admits(true);
    let (mut g, mut l, blocks) = support_chain(3);
    let d = deviation_after(&g, &blocks[5], 5, 1);
    let _ = receive(&mut g, &d);
    assert!(support_for(&mut l, &d).is_some());
    let above = normal_after(&g, &d, 3, 2);
    assert_eq!(
        step_reason(&mut l, &above),
        Some(ValidationReason::RunCreator)
    );
    assert_eq!(
        receive(&mut l, &above),
        ReceiveBlockOutcome::Rejected(RejectReason::InvalidEvidence)
    );
    assert_eq!(head_of(&l), (6, d.view().hash()));
    set_grace_admits(false);
}

/// AC9 test 3 — a ring full of live entries at other sequences: abstain.
#[test]
fn no_support_with_a_full_ring() {
    set_grace_admits(true);
    let (g, mut l, blocks) = support_chain(3);
    for i in 0..16 {
        assert!(l.non_conflict.insert(RING_KIND_SUPPORT, 9, 7 + i, i));
    }
    assert_eq!(
        support_for(&mut l, &deviation_after(&g, &blocks[5], 4, 1)),
        None
    );
    set_grace_admits(false);
}

/// AC9 / M7 — `A` is taken at `p − 1`: node 5's deviation `d` and its own
/// block above put node 5 into the window at the head, but not at #5, so
/// node 5 does not endorse a sibling of `d`.
#[test]
fn the_active_set_is_taken_at_the_parent() {
    set_grace_admits(true);
    let (mut g, mut l, blocks) = support_chain(5);
    let d = deviation_after(&g, &blocks[5], 5, 1);
    // `x` is built at #5, so its header names the top at `p − 1`.
    let x = deviation_after(&g, &blocks[5], 2, 3);
    let _ = receive(&mut g, &d);
    assert_eq!(support_for(&mut l, &d), None, "local = proposer");
    let d7 = normal_after(&g, &d, 5, 2);
    assert_eq!(receive(&mut l, &d7), ReceiveBlockOutcome::AcceptedSilently);
    assert!(l.active_set.count(5) > 0, "node 5 is in A at the head");
    assert_eq!(support_for(&mut l, &x), None);
    set_grace_admits(false);
}

/// Story 6.6 AC6 / D6 pin (flipped from 6.4's M5) — FR12's replay
/// completion is anchored at `p`: on `W = 8` the chain `0..=7` is full once
/// `x` lands and the next extension would drop #0, node #0's seed source,
/// but `x` at #7 itself drops nothing, so it is endorsed. (`W = 7`, which
/// needed no block #6, has no legal horizon: configuration §6 check 21.)
#[test]
fn support_ignores_an_obligation_due_above_the_deviation() {
    set_grace_admits(true);
    let (mut g, mut l, blocks) = support_chain_on(3, local_storage(3), 8, |_| {});
    let b6 = normal_after(&g, &blocks[5], 1, 2);
    for node in [&mut g, &mut l] {
        assert_eq!(receive(node, &b6), ReceiveBlockOutcome::AcceptedSilently);
    }
    let x = deviation_after(&g, &b6, 4, 1);
    assert!(support_for(&mut l, &x).is_some());
    assert_eq!(head_of(&l), (7, x.view().hash()), "x is active");
    set_grace_admits(false);
}

/// AC9 — `p + H ≤ S_head` after the head advanced in the same call: `x`
/// arrives after its eight descendants (`H = 8` on these `W = 16`
/// chains), which the drive promotes behind it, so `x` is out of the
/// switch bound by the time it is evaluated. Its run admits only its
/// creator's replays up to `p + H − 1` (Story 6.7 D4), so the eighth
/// descendant, at `p + H`, is `x`'s evidence: proposer #4 (`pl`) completes
/// its package and builds it.
#[test]
fn no_support_after_the_head_advanced_past_the_horizon() {
    set_grace_admits(true);
    let (mut g, mut pl, _, x, x_idx) = proposer_chain(4);
    accumulate(&mut pl, &x, x_idx, 2);
    let (_, mut l, _) = support_chain(3);
    let _ = receive(&mut g, &x);
    let mut descendants = core::array::from_fn::<Option<Block>, 8, _>(|_| None);
    let mut prev_hash = x.view().hash();
    for (i, slot) in descendants.iter_mut().enumerate() {
        let seq = 7 + i as u32;
        let block = if seq == 14 {
            pl.build_evidence_block(pl.active_chain_head_idx, 0)
                .expect("complete")
        } else {
            let template = tx_block(seq, prev_hash, 0, votes_to(seq, 0, 1, 500 + seq as u64));
            real_on(&g, &template, 4, key_of(4))
        };
        for node in [&mut g, &mut pl] {
            assert_eq!(receive(node, &block), ReceiveBlockOutcome::AcceptedSilently);
        }
        prev_hash = block.view().hash();
        *slot = Some(block);
    }
    for block in descendants.iter().rev().flatten() {
        assert_eq!(
            receive(&mut l, block),
            ReceiveBlockOutcome::AcceptedSilently
        );
    }
    assert_eq!(support_for(&mut l, &x), None);
    assert_eq!(head_of(&l).0, 14, "the drive promoted the descendants");
    set_grace_admits(false);
}

/// AC9 — `p ≤ F` after a restart: the restarted node's floor is its
/// ready-entry head (DEC-198), so the sibling it would have endorsed
/// (test 2) is refused.
#[test]
fn no_support_at_or_below_the_restart_floor() {
    set_grace_admits(true);
    let (g, mut l, blocks) = support_chain(3);
    let d = deviation_after(&g, &blocks[5], 5, 1);
    assert!(support_for(&mut l, &d).is_some());
    let mut restarted = local_node(3, l.storage);
    let _ = restarted.initialize_from_storage(0);
    assert!(restarted.is_ready());
    assert_eq!(restarted.non_conflict.floor(), 6);
    assert_active_set_matches(&restarted, "after the restart");
    assert_eq!(
        support_for(&mut restarted, &deviation_after(&g, &blocks[5], 2, 2)),
        None
    );
    set_grace_admits(false);
}

/// AC6 — the ring survives a DEC-205 re-entry to collecting that lands
/// on a lower head: `x` (node 4 at 6) was endorsed, then lost, and the
/// node re-entered on #5, so `F = 5` no longer covers 6 — only the record
/// refuses a conflicting candidate there. The same candidate is endorsed
/// on a node that never endorsed `x`.
#[test]
fn the_ring_survives_a_re_entry() {
    set_grace_admits(true);
    let (g, mut l, blocks) = support_chain(3);
    let x = deviation_after(&g, &blocks[5], 4, 1);
    assert!(support_for(&mut l, &x).is_some());
    let lost = slot(&l, &x);
    l.delete_subtree_with_followup(lost);
    let _ = l.reenter_collecting(0);
    assert!(l.is_ready(), "the re-entry reached Ready again");
    assert_eq!(head_of(&l).0, 5, "on a lower head");
    assert_eq!(l.non_conflict.floor(), 5);
    assert_active_set_matches(&l, "after the re-entry");
    let other = deviation_after(&g, &blocks[5], 4, 2);
    assert_eq!(support_for(&mut l, &other), None, "the record survives");
    let (_, mut fresh, _) = support_chain(3);
    assert!(support_for(&mut fresh, &other).is_some());
    set_grace_admits(false);
}

/// AC9 / M2 — with `required_support = 1` the subgroup is the one member
/// of `A' = {0, 3}` with the smaller node value: exactly that node — node
/// #0 (the builder) or node 3 — endorses.
#[test]
fn only_the_m_smallest_node_values_endorse() {
    set_grace_admits(true);
    let (mut g, mut l, blocks) = support_chain_on(3, local_storage(3), 16, |c| {
        c.add_literal(parameter::REQUIRED_SUPPORT, &[1])
            .ok()
            .expect("a one-byte literal");
    });
    let x = deviation_after(&g, &blocks[5], 4, 1);
    let by_three = support_for(&mut l, &x).is_some();
    let by_zero = support_for(&mut g, &x).is_some();
    let seed = subgroup_seed(6, CIRCULATING_CURRENCY_STUB, 4);
    let zero_is_smaller = node_value(&seed, 0) < node_value(&seed, 3);
    assert_eq!((by_zero, by_three), (zero_is_smaller, !zero_is_smaller));
    set_grace_admits(false);
}

/// AC9 test 3d — with the seams at their production values an evaluation
/// reads nothing at all: the shape-(b) sibling's evaluation, which reads
/// `d`'s header once the grace seam admits, reads no block in production.
/// Measured on the evaluation itself: the rest of `receive_block` (the FR22
/// comparison) may read regardless.
#[test]
fn an_evaluation_in_production_reads_nothing() {
    set_grace_admits(false);
    let storage = FailingReadStorage {
        inner: initialized_storage([key_of(3); PRIVATE_KEY_SIZE]),
        failing_slot: NONE_REF,
        reads_left: core::cell::Cell::new(u32::MAX),
        failures_left: core::cell::Cell::new(0),
        attempts: core::cell::Cell::new(0),
        reads: core::cell::Cell::new(0),
    };
    let (g, mut l, blocks) = support_chain_on(3, storage, 16, |_| {});
    let d = deviation_after(&g, &blocks[5], 5, 1);
    assert_eq!(support_for(&mut l, &d), None);
    let x = deviation_after(&g, &blocks[5], 2, 2);
    assert_eq!(support_for(&mut l, &x), None);
    let x_idx = slot(&l, &x);
    let first_voted = x.view().first_voted_node();
    let before = l.storage.reads.get();
    assert_eq!(l.evaluate_support(x_idx, 2, first_voted), None);
    assert_eq!(l.storage.reads.get(), before, "no read in production");
    set_grace_admits(true);
    assert!(l.evaluate_support(x_idx, 2, first_voted).is_some());
    assert!(
        l.storage.reads.get() > before,
        "the admitted evaluation reads"
    );
    set_grace_admits(false);
}

/// AC9 test 4, second half, and AC3's known safe case — node 5's `d` is a
/// balance block that lists node 2, so node 2's seed source moves above
/// `p − 1`: node 2's sibling `x` is admitted unverified and gets no
/// support. Test 2 is the same with a transaction `d`, where `x` is
/// verified and endorsed.
#[test]
fn an_unverified_sibling_gets_no_support() {
    set_grace_admits(true);
    let (g, mut l, blocks) = support_chain(3);
    let top = g.vote_engine.top_creator().expect("a top");
    let snapshot = |n| vote_snapshot(g.vote_engine.accumulated_vote_of(n));
    let template = balance_snapshot(&g, 6, blocks[5].view().hash(), &[2]);
    let d = reheader(&template, 5, snapshot(5), top, snapshot(top), key_of(5));
    let _ = support_for(&mut l, &d);
    assert_eq!(head_of(&l), (6, d.view().hash()), "d is active");
    let x = deviation_after(&g, &blocks[5], 2, 2);
    assert_eq!(support_for(&mut l, &x), None);
    assert_eq!(verified(&l, &x), Some(false));
    set_grace_admits(false);
}

/// AC8 — two nodes fed the same blocks in the same order decide alike
/// and emit byte-identical messages; here `d` then its sibling `x`.
#[test]
fn support_is_replay_deterministic() {
    set_grace_admits(true);
    let (g, mut first, blocks) = support_chain(3);
    let (_, mut second, _) = support_chain(3);
    let d = deviation_after(&g, &blocks[5], 5, 1);
    let x = deviation_after(&g, &blocks[5], 2, 2);
    let one = (support_for(&mut first, &d), support_for(&mut first, &x));
    let two = (support_for(&mut second, &d), support_for(&mut second, &x));
    assert!(one.0.is_some() && one.1.is_some());
    assert_eq!(one, two);
    set_grace_admits(false);
}

/// AC8 — the other arrival order: `x` (lighter) arrives first and is
/// endorsed as a direct extension; the heavier `d` then wins FR22 and is
/// endorsed after the switch. Again two nodes agree byte for byte.
#[test]
fn support_is_replay_deterministic_in_the_other_order() {
    set_grace_admits(true);
    let (g, mut first, blocks) = support_chain(3);
    let (_, mut second, _) = support_chain(3);
    let d = deviation_after(&g, &blocks[5], 5, 1);
    let x = deviation_after(&g, &blocks[5], 2, 2);
    let one = (support_for(&mut first, &x), support_for(&mut first, &d));
    let two = (support_for(&mut second, &x), support_for(&mut second, &d));
    assert!(one.0.is_some() && one.1.is_some());
    assert_eq!(head_of(&first), (6, d.view().hash()));
    assert_eq!(one, two);
    set_grace_admits(false);
}

/// The Story 6.4 chain on `W = 8` (`H = 4`) carried past genesis, so its
/// tail has advanced: [`support_chain_on`]'s `b0..=a5`, then `a6` (node 2,
/// one credit for node 3), `a7` (node 5, one for node 2), `r8` (node #0's
/// balance replay of node #0, dropping #0), `r9` (node 3's chain-config
/// replay, dropping #1), `r10` (node #0's balance replay of nodes 1..=5,
/// dropping #2) and `a11` (node 3, one credit for node 1). The window at
/// #11 is `[4, 11]`, and node 4's only block in it is `a4`: an extension at
/// 12 drops `a4`, which then lies in the horizon. `u` stays node 1.
fn long_support_chain(local: u32) -> (SupportChain, SupportChain, [Block; 6]) {
    long_support_chain_on(local, local_storage(local))
}

/// [`long_support_chain`] with the local node over `storage`.
fn long_support_chain_on<S: StorageTrait>(
    local: u32,
    storage: S,
) -> (SupportChain, Chain16<S>, [Block; 6]) {
    let (mut g, mut l, base) = support_chain_on(local, storage, 8, |_| {});
    let both = |g: &mut SupportChain, l: &mut Chain16<S>, block: &Block| {
        assert_eq!(receive(g, block), ReceiveBlockOutcome::AcceptedSilently);
        assert_eq!(receive(l, block), ReceiveBlockOutcome::AcceptedSilently);
    };
    let a6 = normal_votes(&g, &base[5], 2, 3);
    both(&mut g, &mut l, &a6);
    let a7 = normal_votes(&g, &a6, 5, 2);
    both(&mut g, &mut l, &a7);
    let r8 = real_on(
        &g,
        &balance_snapshot(&g, 8, a7.view().hash(), &[0]),
        0,
        key_of(0),
    );
    both(&mut g, &mut l, &r8);
    let template = chain_config_block_from(9, r8.view().hash(), &mut window_config_builder(8));
    let r9 = real_on(&g, &template, 3, key_of(3));
    both(&mut g, &mut l, &r9);
    let r10 = real_on(
        &g,
        &balance_snapshot(&g, 10, r9.view().hash(), &[1, 2, 3, 4, 5]),
        0,
        key_of(0),
    );
    both(&mut g, &mut l, &r10);
    let a11 = normal_votes(&g, &r10, 3, 1);
    both(&mut g, &mut l, &a11);
    assert_eq!(head_of(&l).0, 11);
    assert_eq!(l.active_snake_chain_window(), Ok((4, 11)));
    assert_eq!(g.vote_engine.top_creator(), Some(1), "precondition: u = 1");
    assert_active_set_matches(&l, "past genesis");
    let [_, _, _, _, a4, _] = base;
    (g, l, [a4, a6, a7, r8, r10, a11])
}

/// A normal-form block by `creator` on `prev` (the active head of `g`),
/// one credit for `target`.
fn normal_votes(g: &SupportChain, prev: &Block, creator: u32, target: u32) -> Block {
    let seq = prev.view().sequence() + 1;
    let template = tx_block(
        seq,
        prev.view().hash(),
        0,
        votes_for(seq, target, 1, 100 * u64::from(seq)),
    );
    real_on(g, &template, creator, key_of(creator))
}

/// AC9 (the `p − 1` correction on a chain, M7's returning half) — node 2's
/// deviation at 12 drops `a4`, node 4's only block in the window of #11:
/// node 4 is in `A` at `p − 1` only through the returning block, read back
/// from the horizon, and endorses.
#[test]
fn a_dropped_block_returns_its_creator_to_the_parent_window() {
    set_grace_admits(true);
    let (g, mut l, blocks) = long_support_chain(4);
    let x = deviation_after(&g, &blocks[5], 2, 1);
    let message = support_for(&mut l, &x).expect("node 4 is in A at #11");
    assert_eq!(message.supporter_node_id, 4);
    assert_eq!(head_of(&l), (12, x.view().hash()));
    assert_eq!(l.active_snake_chain_window(), Ok((5, 12)));
    assert_eq!(
        l.active_set.count(4),
        0,
        "node 4 left the window at the head"
    );
    assert_active_set_matches(&l, "after the tail advance");
    set_grace_admits(false);
}

/// AC9 (the `returning_d` branch) — node 4's own deviation `d` at 12
/// drops `a4`, node 4's block: at #11 node 4 counts once (`a4`), at the
/// head once (`d`); the correction removes `d` and returns `a4`, so node 4
/// — `d`'s creator, not the proposer of the sibling `x` — endorses `x`.
#[test]
fn a_returning_block_of_ds_creator_keeps_it_in_the_parent_window() {
    set_grace_admits(true);
    let (g, mut l, blocks) = long_support_chain(4);
    let d = deviation_after(&g, &blocks[5], 4, 1);
    assert_eq!(support_for(&mut l, &d), None, "local = proposer");
    assert_eq!(head_of(&l), (12, d.view().hash()));
    let x = deviation_after(&g, &blocks[5], 2, 2);
    let message = support_for(&mut l, &x).expect("node 4 is in A at #11");
    assert_eq!(message.proposer_node_id, 2);
    set_grace_admits(false);
}

/// AC9 test 3 — shape (b) with a sibling in normal form: node 2's block
/// beside node 5's `d` names itself as `first_voted_node`, a
/// non-deviation under I-10, so it gets no support (test 2's deviating
/// sibling does).
#[test]
fn no_support_for_a_normal_form_sibling() {
    set_grace_admits(true);
    let (g, mut l, blocks) = support_chain(3);
    assert!(support_for(&mut l, &deviation_after(&g, &blocks[5], 5, 1)).is_some());
    let sibling = normal_after(&g, &blocks[5], 2, 2);
    assert_eq!(support_for(&mut l, &sibling), None);
    assert_eq!(verified(&l, &sibling), Some(true));
    set_grace_admits(false);
}

// ---- Story 6.5: FR26 support intake ----

/// Story 6.4's chain received by node 2 (registered, never a creator, so
/// no support of its own), with node 4's deviation `x` at 6 on its active
/// chain: `u = 1`, `A = {0, 1, 3, 4}`, `A' = {0, 3}`, `m = 2`.
fn on_chain_receiver() -> (SupportChain, SupportChain, [Block; 6], Block) {
    let (g, mut r, blocks) = support_chain(2);
    let x = deviation_after(&g, &blocks[5], 4, 1);
    assert_eq!(receive(&mut r, &x), ReceiveBlockOutcome::AcceptedSilently);
    assert_eq!(
        head_of(&r),
        (6, x.view().hash()),
        "x is on the active chain"
    );
    (g, r, blocks, x)
}

/// AC7 test 1 — the message node 3 emits for node 4's direct deviation
/// (6.4) is accepted by node 2, which holds the deviation on its active
/// chain, and a second copy is a duplicate. The relay sender is not part
/// of the body, so transport independence holds by construction.
#[test]
fn an_endorsement_of_an_on_chain_deviation_is_accepted_once() {
    set_grace_admits(true);
    let (g3, mut l3, blocks3) = support_chain(3);
    let x3 = deviation_after(&g3, &blocks3[5], 4, 1);
    let message = support_for(&mut l3, &x3).expect("node 3 endorses");
    set_grace_admits(false);
    let (_, mut r, _, x) = on_chain_receiver();
    assert_eq!(
        x.view().hash(),
        x3.view().hash(),
        "the same deterministic chain"
    );
    assert_eq!(intake(&mut r, &message), ReceiveSupportOutcome::Accepted);
    assert_eq!(intake(&mut r, &message), ReceiveSupportOutcome::Rejected);
}

/// AC7 test 2 — on the active chain, a bad signature from a derivable
/// supporter is rejected, the good one accepted.
#[test]
fn an_on_chain_support_with_a_bad_signature_is_rejected() {
    let (_, mut r, _, x) = on_chain_receiver();
    let h = x.view().hash();
    assert_eq!(
        intake(&mut r, &forged(support_by(3, 4, 6, h))),
        ReceiveSupportOutcome::Rejected
    );
    assert_eq!(
        intake(&mut r, &support_by(3, 4, 6, h)),
        ReceiveSupportOutcome::Accepted
    );
}

/// AC7 test 2 / N4 — (iii): the signed proposer must be `d`'s creator.
#[test]
fn an_on_chain_support_naming_another_proposer_is_rejected() {
    let (_, mut r, _, x) = on_chain_receiver();
    let h = x.view().hash();
    assert_eq!(
        intake(&mut r, &support_by(3, 5, 6, h)),
        ReceiveSupportOutcome::Rejected
    );
    assert_eq!(
        intake(&mut r, &support_by(3, 4, 6, h)),
        ReceiveSupportOutcome::Accepted
    );
}

/// AC7 test 2 — (iii): no support for a block in normal form (`u`'s own).
#[test]
fn an_on_chain_support_for_a_normal_form_block_is_rejected() {
    let (g, mut r, blocks) = support_chain(2);
    let n = normal_after(&g, &blocks[5], 1, 1);
    assert_eq!(receive(&mut r, &n), ReceiveBlockOutcome::AcceptedSilently);
    assert_eq!(head_of(&r), (6, n.view().hash()));
    assert_eq!(
        intake(&mut r, &support_by(3, 1, 6, n.view().hash())),
        ReceiveSupportOutcome::Rejected
    );
}

/// AC7 test 2 — (iv-b): the proposer, `u` and an idle node are outside
/// `A'`; node #0 is in it.
#[test]
fn an_on_chain_support_from_outside_the_subgroup_is_rejected() {
    let (_, mut r, _, x) = on_chain_receiver();
    let h = x.view().hash();
    for outsider in [4, 1, 2] {
        assert_eq!(
            intake(&mut r, &support_by(outsider, 4, 6, h)),
            ReceiveSupportOutcome::Rejected,
            "node {outsider}"
        );
    }
    assert_eq!(
        intake(&mut r, &support_by(0, 4, 6, h)),
        ReceiveSupportOutcome::Accepted
    );
}

/// AC7 test 2 / N11 — the watermark: an id above `max_known_node_id`, and
/// one beyond `MAX_NODES` (no panic), are rejected on the active chain.
#[test]
fn an_on_chain_support_from_an_unknown_id_is_rejected() {
    let (_, mut r, _, x) = on_chain_receiver();
    let h = x.view().hash();
    assert_eq!(r.node_info.max_known_node_id(), 5);
    for unknown in [9, 20] {
        assert_eq!(
            intake(&mut r, &support_by(unknown, 4, 6, h)),
            ReceiveSupportOutcome::Rejected,
            "node {unknown}"
        );
    }
}

/// AC7 test 2 / M2 — with `required_support = 1` only the one member of
/// `A' = {0, 3}` with the smaller node value is accepted.
#[test]
fn only_a_support_from_the_m_smallest_is_accepted() {
    let (g, mut r, blocks) = support_chain_on(2, local_storage(2), 16, |c| {
        c.add_literal(parameter::REQUIRED_SUPPORT, &[1])
            .ok()
            .expect("a one-byte literal");
    });
    let x = deviation_after(&g, &blocks[5], 4, 1);
    assert_eq!(receive(&mut r, &x), ReceiveBlockOutcome::AcceptedSilently);
    let seed = subgroup_seed(6, CIRCULATING_CURRENCY_STUB, 4);
    let (inside, outside) = if node_value(&seed, 0) < node_value(&seed, 3) {
        (0, 3)
    } else {
        (3, 0)
    };
    let h = x.view().hash();
    assert_eq!(
        intake(&mut r, &support_by(outside, 4, 6, h)),
        ReceiveSupportOutcome::Rejected
    );
    assert_eq!(
        intake(&mut r, &support_by(inside, 4, 6, h)),
        ReceiveSupportOutcome::Accepted
    );
}

/// AC7 test 2 / N3 — (iv-a): an approval block above `d` on the active
/// chain is its evidence, so a support for `d` is rejected; the subgroup
/// half alone would accept it.
#[test]
fn an_on_chain_support_after_the_evidence_is_rejected() {
    let (mut g, mut r, _, x) = on_chain_receiver();
    let _ = receive(&mut g, &x);
    let y = normal_after(&g, &x, 4, 2);
    assert_eq!(receive(&mut r, &y), ReceiveBlockOutcome::AcceptedSilently);
    assert_eq!(head_of(&r).0, 7);
    let h = x.view().hash();
    assert_eq!(
        intake(&mut r, &support_by(0, 4, 6, h)),
        ReceiveSupportOutcome::Accepted
    );
    let y_idx = slot(&r, &y);
    r.blocks.stamp_payload_type(y_idx, PAYLOAD_TYPE_APPROVAL);
    assert_eq!(
        intake(&mut r, &support_by(3, 4, 6, h)),
        ReceiveSupportOutcome::Rejected
    );
}

/// AC1 — a node that refused its restart rejects everything and schedules
/// nothing, as `receive_block` does.
#[test]
fn a_node_that_refused_its_restart_rejects_supports() {
    let (_, mut r, _, x) = on_chain_receiver();
    r.restart_refused = true;
    let body = body_of(&support_by(3, 4, 6, x.view().hash()));
    let (outcome, next) = r.receive_support(SupportView::from_bytes(&body).expect("one body"), 0);
    assert_eq!(outcome, ReceiveSupportOutcome::Rejected);
    assert!(matches!(next, NextCall::Idle));
}

/// AC7 test 3 — collecting: only node #0's key is derivable, so any other
/// supporter is accepted on format and dedupe alone, and node #0's bad
/// signature is rejected.
#[test]
fn a_collecting_node_checks_only_node_zeros_signature() {
    let mut c = local_node(2, local_storage(2));
    assert!(!c.is_ready());
    let h = [7u8; 32];
    assert_eq!(
        intake(&mut c, &forged(support_by(3, 4, 6, h))),
        ReceiveSupportOutcome::Accepted
    );
    assert_eq!(
        intake(&mut c, &forged(support_by(0, 4, 6, h))),
        ReceiveSupportOutcome::Rejected
    );
    assert_eq!(
        intake(&mut c, &support_by(0, 4, 6, h)),
        ReceiveSupportOutcome::Accepted
    );
}

/// AC7 test 3 / N8 — a deviation the ready node does not hold: node #0's
/// key is derivable, so its bad signature is rejected; node 3's key is
/// seeded at #2, above the tail #0, so not derivable (D4's narrow reach),
/// and its bad signature is relayed (AR-023). No released seed source is
/// reachable in these fixtures, so node #0 stands for the derivable case.
#[test]
fn a_ready_node_checks_a_derivable_key_off_the_active_chain() {
    let (_, mut r, _) = support_chain(2);
    let h = [7u8; 32];
    assert_eq!(
        intake(&mut r, &forged(support_by(0, 4, 6, h))),
        ReceiveSupportOutcome::Rejected
    );
    assert_eq!(
        intake(&mut r, &forged(support_by(3, 4, 6, h))),
        ReceiveSupportOutcome::Accepted
    );
}

/// AC7 test 3 — a support for 6.4's shape-(b) sibling, held as a side
/// block: (iii) and (iv) are deferred, so even the proposer's own
/// "support" (outside `A'` if checked) is accepted.
#[test]
fn a_support_for_a_side_block_defers_the_active_chain_checks() {
    let (g, mut r, blocks) = support_chain(2);
    let d = deviation_after(&g, &blocks[5], 5, 1);
    assert_eq!(receive(&mut r, &d), ReceiveBlockOutcome::AcceptedSilently);
    let x = deviation_after(&g, &blocks[5], 2, 2);
    assert_eq!(receive(&mut r, &x), ReceiveBlockOutcome::AcceptedSilently);
    assert_eq!(head_of(&r), (6, d.view().hash()), "x is a side block");
    let h = x.view().hash();
    assert_eq!(
        intake(&mut r, &support_by(3, 2, 6, h)),
        ReceiveSupportOutcome::Accepted
    );
    assert_eq!(
        intake(&mut r, &support_by(2, 2, 6, h)),
        ReceiveSupportOutcome::Accepted
    );
    // (iii) is deferred too: a wrong proposer is not checked here.
    assert_eq!(
        intake(&mut r, &support_by(3, 9, 6, h)),
        ReceiveSupportOutcome::Accepted
    );
}

/// AC7 test 3 / N5 — `a3` at 3 is flagged on the active chain but lies
/// below the tail #4: outside the window it is not "on the active chain",
/// so a support naming the wrong proposer is deferred, not rejected.
#[test]
fn a_support_below_the_tail_is_deferred() {
    let (_, mut r, _) = long_support_chain(2);
    assert_eq!(r.active_snake_chain_window(), Ok((4, 11)));
    let a3 = r
        .ancestor_at(r.active_chain_head_idx, 3)
        .ok()
        .flatten()
        .expect("a3 in the horizon");
    let entry = r.blocks.get(a3).expect("held");
    assert!(entry.is_on_active_chain());
    let h = *entry.hash();
    assert_eq!(
        intake(&mut r, &support_by(2, 9, 3, h)),
        ReceiveSupportOutcome::Accepted
    );
}

/// AC7 test 3 — converted by Story 6.7 D4 (it pinned that at
/// `p + H ≤ S_head` the subgroup half is deferred). `d`'s run admits only
/// its creator's replays up to `p + H − 1` (W = 8, H = 4, `d` at 12, its
/// creator's blocks at 13..=15): a fourth replay, at `p + H`, is refused
/// (`RunBound`), and a head at `p + H` is `d`'s evidence, which (iv-a)
/// answers first, so the deferral is unreachable. At the last head before
/// the bound the subgroup half runs (`u` is refused), and the watermark
/// and the evidence half run as before.
#[test]
fn a_run_ends_before_the_subgroup_half_defers() {
    let (mut g, mut r, blocks) = long_support_chain(2);
    let d = deviation_after(&g, &blocks[5], 4, 1);
    assert_eq!(receive(&mut r, &d), ReceiveBlockOutcome::AcceptedSilently);
    let _ = receive(&mut g, &d);
    let both = |g: &mut SupportChain, r: &mut SupportChain, block: &Block| {
        for node in [g, r] {
            assert_eq!(receive(node, block), ReceiveBlockOutcome::AcceptedSilently);
        }
    };
    let y = normal_after(&g, &d, 4, 2);
    both(&mut g, &mut r, &y);
    let y14 = normal_after(&g, &y, 4, 3);
    both(&mut g, &mut r, &y14);
    let y15 = normal_after(&g, &y14, 4, 4);
    both(&mut g, &mut r, &y15);
    assert_eq!(head_of(&r).0, 15, "p + H − 1");
    let over = normal_after(&g, &y15, 4, 5);
    assert_eq!(step_reason(&mut r, &over), Some(ValidationReason::RunBound));
    assert_eq!(
        receive(&mut r, &over),
        ReceiveBlockOutcome::Rejected(RejectReason::InvalidEvidence)
    );
    let h = d.view().hash();
    // `u` (node 1) is outside `A'`: the subgroup half runs and refuses it.
    assert_eq!(
        intake(&mut r, &support_by(1, 4, 12, h)),
        ReceiveSupportOutcome::Rejected
    );
    for unknown in [9, 20] {
        assert_eq!(
            intake(&mut r, &support_by(unknown, 4, 12, h)),
            ReceiveSupportOutcome::Rejected,
            "node {unknown}"
        );
    }
    let y_idx = slot(&r, &y);
    r.blocks.stamp_payload_type(y_idx, PAYLOAD_TYPE_APPROVAL);
    assert_eq!(
        intake(&mut r, &support_by(3, 4, 12, h)),
        ReceiveSupportOutcome::Rejected
    );
}

/// AC7 test 3 — converted by Story 6.7 D4 (it pinned that another
/// creator above `d`, an FR27 violation, defers the subgroup half): the
/// violation is now refused at intake (rule 1, `RunCreator`), so the head
/// stays `x` and the subgroup half runs: the idle node 2, outside `A'`,
/// is rejected.
#[test]
fn a_refused_foreign_creator_leaves_the_subgroup_half_running() {
    let (mut g, mut r, _, x) = on_chain_receiver();
    let _ = receive(&mut g, &x);
    let above = normal_after(&g, &x, 3, 2);
    assert_eq!(
        step_reason(&mut r, &above),
        Some(ValidationReason::RunCreator)
    );
    assert_eq!(
        receive(&mut r, &above),
        ReceiveBlockOutcome::Rejected(RejectReason::InvalidEvidence)
    );
    assert_eq!(head_of(&r), (6, x.view().hash()));
    assert_eq!(
        intake(&mut r, &support_by(2, 4, 6, x.view().hash())),
        ReceiveSupportOutcome::Rejected
    );
}

/// AC7 test 3 / N9 — an invalid active-set counter defers the subgroup
/// half instead of giving a verdict.
#[test]
fn an_invalid_counter_defers_the_subgroup_half() {
    let (_, mut r, _, x) = on_chain_receiver();
    r.active_set.invalidate();
    assert_eq!(
        intake(&mut r, &support_by(2, 4, 6, x.view().hash())),
        ReceiveSupportOutcome::Accepted
    );
}

/// AC7 test 3 / N10 — a failed read in the `p − 1` correction (`a4`,
/// dropped by node 2's deviation at 12) defers the subgroup half: `u`
/// (node 1), outside `A'`, is rejected when the read succeeds and accepted
/// when it fails.
#[test]
fn a_failed_read_in_the_correction_defers_the_subgroup_half() {
    let storage = || FailingReadStorage {
        inner: local_storage(2),
        failing_slot: NONE_REF,
        reads_left: core::cell::Cell::new(0),
        failures_left: core::cell::Cell::new(0),
        attempts: core::cell::Cell::new(0),
        reads: core::cell::Cell::new(0),
    };
    for failing in [false, true] {
        let (g, mut r, blocks) = long_support_chain_on(2, storage());
        let a4 = blocks[0].view();
        let d = deviation_after(&g, &blocks[5], 2, 1);
        assert_eq!(receive(&mut r, &d), ReceiveBlockOutcome::AcceptedSilently);
        if failing {
            r.storage.failing_slot = r.blocks.find(4, &a4.hash()).expect("a4 in the horizon");
            r.storage.failures_left.set(u32::MAX);
        }
        let expected = if failing {
            ReceiveSupportOutcome::Accepted
        } else {
            ReceiveSupportOutcome::Rejected
        };
        assert_eq!(
            intake(&mut r, &support_by(1, 2, 12, d.view().hash())),
            expected
        );
    }
}

/// AC7 test 3b (iv-c), case (a) — a verified block of `u` beside the
/// on-chain `d` stops the relay.
#[test]
fn a_verified_u_block_beside_an_on_chain_deviation_stops_the_relay() {
    let (_, mut r, blocks, x) = on_chain_receiver();
    let h = x.view().hash();
    assert_eq!(
        intake(&mut r, &support_by(0, 4, 6, h)),
        ReceiveSupportOutcome::Accepted
    );
    let u = u_block(&blocks, &[&x]);
    assert_eq!(receive(&mut r, &u), ReceiveBlockOutcome::AcceptedSilently);
    assert_eq!(verified(&r, &u), Some(true));
    assert_eq!(head_of(&r), (6, h), "d stays active");
    assert_eq!(
        intake(&mut r, &support_by(3, 4, 6, h)),
        ReceiveSupportOutcome::Rejected
    );
}

/// AC7 test 3b / N13 / N15, flipped by Story 6.6 D5 — an unverified
/// `u`-block (node 5's balance deviation `d` lists node 1, moving its seed
/// source above `p − 1`) stops neither the relay nor, now, 6.4's emission
/// for a sibling: only a validated block silences a deviation.
#[test]
fn an_unverified_u_block_stops_neither_emission_nor_relay() {
    set_grace_admits(true);
    let (g, mut l, blocks) = support_chain(3);
    let top = g.vote_engine.top_creator().expect("a top");
    let snapshot = |n| vote_snapshot(g.vote_engine.accumulated_vote_of(n));
    let template = balance_snapshot(&g, 6, blocks[5].view().hash(), &[1]);
    let d = reheader(&template, 5, snapshot(5), top, snapshot(top), key_of(5));
    assert!(support_for(&mut l, &d).is_some());
    let u = u_block(&blocks, &[&d]);
    assert_eq!(receive(&mut l, &u), ReceiveBlockOutcome::AcceptedSilently);
    assert_eq!(verified(&l, &u), Some(false), "node 1's key moved above #5");
    assert_eq!(head_of(&l), (6, d.view().hash()));
    assert_eq!(
        intake(&mut l, &support_by(0, 5, 6, d.view().hash())),
        ReceiveSupportOutcome::Accepted,
        "relay: an unverified u-block does not count"
    );
    let x = deviation_after(&g, &blocks[5], 2, 2);
    assert!(
        support_for(&mut l, &x).is_some(),
        "emission: only a validated u-block counts (D5)"
    );
    assert_eq!(verified(&l, &x), Some(true));
    set_grace_admits(false);
}

/// AC7 test 3b, case (b) — the deviation is held off the active chain
/// (6.4's shape-(b) sibling), and `u`'s verified block stands beside it.
#[test]
fn a_u_block_stops_the_relay_for_a_held_side_deviation() {
    let (g, mut r, blocks) = support_chain(2);
    let d = deviation_after(&g, &blocks[5], 5, 1);
    assert_eq!(receive(&mut r, &d), ReceiveBlockOutcome::AcceptedSilently);
    let x = deviation_after(&g, &blocks[5], 2, 2);
    assert_eq!(receive(&mut r, &x), ReceiveBlockOutcome::AcceptedSilently);
    let h = x.view().hash();
    assert_eq!(
        intake(&mut r, &support_by(0, 2, 6, h)),
        ReceiveSupportOutcome::Accepted
    );
    let u = u_block(&blocks, &[&d, &x]);
    assert_eq!(receive(&mut r, &u), ReceiveBlockOutcome::AcceptedSilently);
    assert_eq!(verified(&r, &u), Some(true));
    assert_eq!(
        intake(&mut r, &support_by(3, 2, 6, h)),
        ReceiveSupportOutcome::Rejected
    );
}

/// AC7 test 3b, case (c) — the deviation is not held; `u` comes from the
/// active approval-less deviation at 6.
#[test]
fn a_u_block_stops_the_relay_for_an_unheld_deviation() {
    let (g, mut r, blocks) = support_chain(2);
    let d = deviation_after(&g, &blocks[5], 5, 1);
    assert_eq!(receive(&mut r, &d), ReceiveBlockOutcome::AcceptedSilently);
    let unknown = [9u8; 32];
    assert_eq!(
        intake(&mut r, &support_by(0, 2, 6, unknown)),
        ReceiveSupportOutcome::Accepted
    );
    let u = u_block(&blocks, &[&d]);
    assert_eq!(receive(&mut r, &u), ReceiveBlockOutcome::AcceptedSilently);
    assert_eq!(
        intake(&mut r, &support_by(3, 2, 6, unknown)),
        ReceiveSupportOutcome::Rejected
    );
}

/// AC7 test 3b, case (d) — the deviation is not held and the active block
/// at 6 is `u`'s own, in normal form: `u` cannot be derived, so the stop is
/// not evaluable and the support is relayed (a known gap: the common case,
/// where the deviation itself was received, is case (b)).
#[test]
fn the_u_block_stop_is_not_evaluable_without_a_deviation_header() {
    let (g, mut r, blocks) = support_chain(2);
    let n = normal_after(&g, &blocks[5], 1, 1);
    assert_eq!(receive(&mut r, &n), ReceiveBlockOutcome::AcceptedSilently);
    assert_eq!(
        intake(&mut r, &support_by(3, 2, 6, [9u8; 32])),
        ReceiveSupportOutcome::Accepted
    );
    // No active block at all at 7 (above the head): not evaluable either.
    assert_eq!(
        intake(&mut r, &support_by(3, 2, 7, [9u8; 32])),
        ReceiveSupportOutcome::Accepted
    );
}

/// AC7 test 3b — a failed read of a candidate sibling never rejects: the
/// `u`-block of case (a) is unreadable, so the relay goes on.
#[test]
fn a_failed_read_of_a_sibling_does_not_stop_the_relay() {
    let storage = FailingReadStorage {
        inner: local_storage(2),
        failing_slot: NONE_REF,
        reads_left: core::cell::Cell::new(0),
        failures_left: core::cell::Cell::new(0),
        attempts: core::cell::Cell::new(0),
        reads: core::cell::Cell::new(0),
    };
    let (g, mut r, blocks) = support_chain_on(2, storage, 16, |_| {});
    let x = deviation_after(&g, &blocks[5], 4, 1);
    assert_eq!(receive(&mut r, &x), ReceiveBlockOutcome::AcceptedSilently);
    let u = u_block(&blocks, &[&x]);
    assert_eq!(receive(&mut r, &u), ReceiveBlockOutcome::AcceptedSilently);
    assert_eq!(
        verified(&r, &u),
        Some(true),
        "the validated filter admits u"
    );
    r.storage.failing_slot = slot(&r, &u);
    r.storage.failures_left.set(u32::MAX);
    assert_eq!(
        intake(&mut r, &support_by(3, 4, 6, x.view().hash())),
        ReceiveSupportOutcome::Accepted
    );
    assert!(r.storage.attempts.get() > 0, "u's header read was tried");
}

/// AC7 test 4 / N6 — a rejected support is not cached, an accepted one is;
/// and the cache survives a DEC-205 re-entry to collecting.
#[test]
fn only_accepted_supports_are_cached_and_the_cache_survives_a_re_entry() {
    let (_, mut r, _, x) = on_chain_receiver();
    let h = x.view().hash();
    let rejected = support_by(2, 4, 6, h);
    assert_eq!(intake(&mut r, &rejected), ReceiveSupportOutcome::Rejected);
    let body = body_of(&rejected);
    let view = SupportView::from_bytes(&body).expect("one body");
    assert!(
        !r.support_dedupe
            .contains(6, r.support_dedupe.key(view.tail()), 2)
    );
    let accepted = support_by(3, 4, 6, h);
    assert_eq!(intake(&mut r, &accepted), ReceiveSupportOutcome::Accepted);
    let x_idx = slot(&r, &x);
    r.delete_subtree_with_followup(x_idx);
    let _ = r.reenter_collecting(0);
    assert_eq!(
        intake(&mut r, &accepted),
        ReceiveSupportOutcome::Rejected,
        "still cached after the re-entry"
    );
}

/// AC7 test 4 — FIFO eviction through the API: after 128 newer accepted
/// supports the first one is accepted again.
#[test]
fn an_evicted_support_is_accepted_again() {
    let mut c = local_node(2, local_storage(2));
    // Collecting checks no signature but node #0's: unsigned is fine.
    let message = |i: u32| SupportMessage {
        supporter_node_id: 1000 + i,
        proposer_node_id: 4,
        deviation_sequence: 6,
        deviation_block_hash: [3u8; 32],
        support_signature: [0u8; MULTI_SIGNATURE_SIZE],
    };
    assert_eq!(intake(&mut c, &message(0)), ReceiveSupportOutcome::Accepted);
    assert_eq!(intake(&mut c, &message(0)), ReceiveSupportOutcome::Rejected);
    for i in 1..=128 {
        assert_eq!(intake(&mut c, &message(i)), ReceiveSupportOutcome::Accepted);
    }
    assert_eq!(intake(&mut c, &message(0)), ReceiveSupportOutcome::Accepted);
    assert_eq!(
        intake(&mut c, &message(128)),
        ReceiveSupportOutcome::Rejected
    );
}

/// AC7 test 5 / AC3 — a node's own emitted support is cached: its echo is
/// not relayed back.
#[test]
fn a_nodes_own_support_is_not_relayed_back() {
    set_grace_admits(true);
    let (g, mut l, blocks) = support_chain(3);
    let x = deviation_after(&g, &blocks[5], 4, 1);
    let message = support_for(&mut l, &x).expect("node 3 endorses");
    set_grace_admits(false);
    assert_eq!(intake(&mut l, &message), ReceiveSupportOutcome::Rejected);
}

/// AC7 test 6 / N7 — support intake schedules nothing, so it reports the
/// pending parent-recovery deadline, never `Idle`.
#[test]
fn support_intake_keeps_the_pending_deadline() {
    let (mut g, mut r, blocks) = support_chain(2);
    let x = deviation_after(&g, &blocks[5], 4, 1);
    let _ = receive(&mut g, &x);
    let orphan = normal_after(&g, &x, 4, 2);
    assert_eq!(
        receive(&mut r, &orphan),
        ReceiveBlockOutcome::AcceptedSilently
    );
    let NextCall::At(expected) = r.next_parent_recovery_call() else {
        panic!("precondition: a Stored head awaits its parent");
    };
    let body = body_of(&support_by(3, 4, 6, x.view().hash()));
    let (_, next) = r.receive_support(SupportView::from_bytes(&body).expect("one body"), 0);
    assert!(matches!(next, NextCall::At(t) if t == expected));
}

/// AC4 / N2 — the subgroup helper guards its own index: an id beyond
/// `max_known_node_id`, even beyond `MAX_NODES`, is no member, with no
/// reliance on the intake watermark.
#[test]
fn the_subgroup_helper_refuses_an_out_of_range_id_itself() {
    let (_, r, blocks, x) = on_chain_receiver();
    let parent = slot(&r, &blocks[5]);
    assert_eq!(
        r.in_subgroup_at(3, 6, parent, 4, 1, 4, 1, 16, 40),
        Some(true)
    );
    for node in [9, 20, u32::MAX] {
        assert_eq!(
            r.in_subgroup_at(node, 6, parent, 4, 1, 4, 1, 16, 40),
            Some(false)
        );
    }
    assert_eq!(head_of(&r), (6, x.view().hash()));
}

/// Review patch (edge case) — an unresolved parent is not a parent: the
/// sibling scan defers on `NONE_REF` instead of matching every root.
#[test]
fn the_sibling_scan_defers_on_an_unresolved_parent() {
    let (_, r, blocks, _) = on_chain_receiver();
    assert_eq!(r.creator_block_at(NONE_REF, 6, 1, [0, 0], true), None);
    let parent = slot(&r, &blocks[5]);
    assert_eq!(r.creator_block_at(parent, 6, 1, [0, 0], true), Some(false));
}

/// Review patch (N8 as specified) — a non-zero supporter whose seed source
/// is the tail is derivable off the active chain, so its bad signature is
/// rejected and its good one accepted. The seed source is moved there by
/// hand: no block fixture reaches it (D4's narrow reach).
#[test]
fn a_key_seeded_at_the_tail_is_checked_off_the_active_chain() {
    let (_, mut r, _) = support_chain(2);
    let tail = r.snake_chain_tail_idx;
    r.node_info.move_seed_source(3, tail);
    let h = [7u8; 32];
    assert_eq!(
        intake(&mut r, &forged(support_by(3, 4, 6, h))),
        ReceiveSupportOutcome::Rejected
    );
    assert_eq!(
        intake(&mut r, &support_by(3, 4, 6, h)),
        ReceiveSupportOutcome::Accepted
    );
}

/// Review patch (AC7 3b, case (b)) — `u`'s own block is the active block
/// at 6 and node 4's deviation is held beside it: the active `u`-block
/// stops the relay (the `is_on_active_chain` arm of the validated filter).
#[test]
fn an_active_u_block_stops_the_relay_for_a_held_deviation() {
    let (g, mut r, blocks) = support_chain(2);
    let n = normal_after(&g, &blocks[5], 1, 1);
    assert_eq!(receive(&mut r, &n), ReceiveBlockOutcome::AcceptedSilently);
    let x = deviation_after(&g, &blocks[5], 4, 1);
    assert_eq!(receive(&mut r, &x), ReceiveBlockOutcome::AcceptedSilently);
    assert_eq!(head_of(&r), (6, n.view().hash()), "u's block stays active");
    assert_eq!(
        intake(&mut r, &support_by(3, 4, 6, x.view().hash())),
        ReceiveSupportOutcome::Rejected
    );
}

/// Review patch (AC7 test 4, D2) — a copy with only the proposer changed
/// is another dedupe entry: it does not take the real support's slot.
#[test]
fn a_proposer_forgery_does_not_take_the_real_supports_slot() {
    let mut c = local_node(2, local_storage(2));
    let real = support_by(3, 4, 6, [7u8; 32]);
    let mut forgery = support_by(3, 4, 6, [7u8; 32]);
    forgery.proposer_node_id = 5;
    assert_eq!(
        intake(&mut c, &forgery),
        ReceiveSupportOutcome::Accepted,
        "relayed unverified (AR-023)"
    );
    assert_eq!(intake(&mut c, &real), ReceiveSupportOutcome::Accepted);
    assert_eq!(intake(&mut c, &real), ReceiveSupportOutcome::Rejected);
}

/// AC7 test 7 (AR16) — two nodes fed the same blocks and the same support
/// stream classify it identically.
#[test]
fn support_intake_is_replay_deterministic() {
    let run = || {
        let (_, mut r, _, x) = on_chain_receiver();
        let h = x.view().hash();
        let stream = [
            support_by(3, 4, 6, h),
            support_by(3, 4, 6, h),
            forged(support_by(0, 4, 6, h)),
            support_by(2, 4, 6, h),
            support_by(0, 4, 6, h),
            forged(support_by(3, 4, 7, [5u8; 32])),
            support_by(9, 4, 6, h),
        ];
        let outcomes = stream.map(|m| intake(&mut r, &m));
        // 128 deferred junk supports evict the stream's entries.
        for i in 0..128 {
            let junk = SupportMessage {
                supporter_node_id: 1000 + i,
                proposer_node_id: 4,
                deviation_sequence: 7,
                deviation_block_hash: [3u8; 32],
                support_signature: [0u8; MULTI_SIGNATURE_SIZE],
            };
            assert_eq!(intake(&mut r, &junk), ReceiveSupportOutcome::Accepted);
        }
        (outcomes, intake(&mut r, &support_by(3, 4, 6, h)))
    };
    let (first, after_eviction) = run();
    let (second, second_after_eviction) = run();
    assert_eq!(first, second);
    assert_eq!(after_eviction, second_after_eviction);
    assert_eq!(after_eviction, ReceiveSupportOutcome::Accepted, "evicted");
    assert_eq!(
        first,
        [
            ReceiveSupportOutcome::Accepted,
            ReceiveSupportOutcome::Rejected,
            ReceiveSupportOutcome::Rejected,
            ReceiveSupportOutcome::Rejected,
            ReceiveSupportOutcome::Accepted,
            ReceiveSupportOutcome::Accepted,
            ReceiveSupportOutcome::Rejected,
        ]
    );
}
