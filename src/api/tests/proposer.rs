//! Tests of `api/proposer.rs`.

use super::*;

// ---- Story 6.6: proposer-side accumulation and the evidence block ----

/// ADR-015 recomputed by hand: `a_prime` sorted by node value under the
/// seed of `proposer`'s deviation at 6, the first `m` of them.
fn expected_members(proposer: u32, a_prime: &[u32]) -> std::vec::Vec<u32> {
    expected_members_at(6, proposer, a_prime)
}

fn expected_members_at(p: u32, proposer: u32, a_prime: &[u32]) -> std::vec::Vec<u32> {
    let seed = subgroup_seed(p, CIRCULATING_CURRENCY_STUB, proposer);
    let mut ids: std::vec::Vec<u32> = a_prime.to_vec();
    ids.sort_by_key(|&n| node_value(&seed, n));
    let r = a_prime.len() / 2 + 1;
    ids.truncate((2 * r - 1).min(a_prime.len()));
    ids
}

/// Whether `aggregate` verifies over `proposer`'s support content at 6 for
/// `hash` against `signers`' fixture keys in this order.
fn aggregate_verifies_at(
    aggregate: &[u8],
    p: u32,
    proposer: u32,
    hash: &[u8; 32],
    signers: &[u32],
) -> bool {
    use moonblokz_crypto::AggregatedSignature;
    let Ok(aggregate) = AggregatedSignature::new(aggregate) else {
        return false;
    };
    let keys: std::vec::Vec<PublicKey> = signers
        .iter()
        .map(|&n| {
            let bytes = *Crypto::new([key_of(n); PRIVATE_KEY_SIZE])
                .ok()
                .expect("key")
                .public_key()
                .serialize();
            PublicKey::new(&bytes).ok().expect("a key")
        })
        .collect();
    let refs: std::vec::Vec<&PublicKey> = keys.iter().collect();
    test_crypto().verify_aggregated_signature(
        &support_message_bytes(proposer, p, hash),
        &aggregate,
        &refs,
    )
}

/// [`plant`], flagged on the active chain: the evidence scans' stand-in
/// for an active evidence block (Story 6.7 D3: only those stop).
fn plant_on_chain<S: StorageTrait>(bc: &mut Chain16<S>, block: &Block, stored: bool) {
    plant(bc, block, true, stored);
    let view = block.view();
    let idx = bc
        .blocks
        .find(view.sequence(), &view.hash())
        .expect("planted");
    assert!(bc.blocks.set_on_active_chain(idx, true));
}

/// Node 4's complete evidence for its deviation at 6 (`A' = {0, 3}`): the
/// block other nodes see.
fn node_four_evidence() -> Block {
    let (_, mut l, _, d, d_idx) = proposer_chain(4);
    accumulate(&mut l, &d, d_idx, 2);
    l.build_evidence_block(d_idx, 0).expect("evidence")
}

/// AC9 test 1 — the subgroup at open equals the hand recomputation, in
/// the direct case (head = `d`) and in the sibling case. (A held `d` under
/// a head at `p − 1` cannot be built here: a Ready node promotes every
/// direct extension it admits.)
#[test]
fn open_ranks_the_subgroup_in_every_case() {
    let (_, mut l, _, _, d_idx) = proposer_chain(5);
    assert!(l.open_approval(d_idx));
    assert_eq!(l.approval.members(), &expected_members(5, &[0, 3, 4])[..]);
    assert_eq!(l.approval.counts(), (3, 2, 0));

    let (_, mut l, _, _, d_idx, _) = sibling_proposer();
    assert!(l.open_approval(d_idx));
    assert_eq!(l.approval.members(), &expected_members(2, &[0, 3, 4])[..]);
    let (_, mut direct, _, _, direct_idx) = proposer_chain(2);
    assert!(direct.open_approval(direct_idx));
    assert_eq!(l.approval.members(), direct.approval.members());
}

/// AC9 test 1 — a refusal of AC4 returns `false` and changes nothing.
fn assert_refused<S: StorageTrait>(bc: &mut Chain16<S>, idx: u32, what: &str) {
    assert!(!bc.open_approval(idx), "{what}");
    assert!(bc.approval.deviation().is_none(), "{what}: nothing changed");
}

#[test]
fn open_refuses_while_not_ready_or_for_a_foreign_block() {
    // Not ready, all else as for a passing open.
    let (_, mut l, _, _, d_idx) = proposer_chain(5);
    l.lifecycle_phase = LifecyclePhase::Collecting;
    assert_refused(&mut l, d_idx, "not ready");
    let (g, mut l, blocks) = support_chain(5);
    let foreign = deviation_after(&g, &blocks[5], 4, 1);
    assert_eq!(
        receive(&mut l, &foreign),
        ReceiveBlockOutcome::AcceptedSilently
    );
    let idx = l.blocks.find(6, &foreign.view().hash()).expect("held");
    assert_refused(&mut l, idx, "another node's deviation");
}

#[test]
fn open_refuses_a_normal_form_block() {
    let (g, mut l, blocks) = support_chain(5);
    let normal = normal_after(&g, &blocks[5], 5, 1);
    assert_eq!(
        receive(&mut l, &normal),
        ReceiveBlockOutcome::AcceptedSilently
    );
    let idx = l.blocks.find(6, &normal.view().hash()).expect("held");
    assert_refused(&mut l, idx, "normal form");
}

#[test]
fn open_refuses_at_or_below_the_floor_or_without_an_active_set() {
    let (_, mut l, _, _, d_idx) = proposer_chain(5);
    l.non_conflict.raise_floor(5);
    assert!(l.open_approval(d_idx), "p = F + 1 opens");
    l.approval.clear();
    l.non_conflict.raise_floor(6);
    assert_refused(&mut l, d_idx, "p ≤ F");
    let (_, mut l, _, _, d_idx) = proposer_chain(5);
    l.active_set.invalidate();
    assert_refused(&mut l, d_idx, "no valid active set");
}

/// Converted by Story 6.7 D4 (it pinned that the open refuses with
/// another creator above `p − 1`): that block is refused at intake (rule
/// 1, `RunCreator`), so the proposer's head stays `d` and the open holds.
#[test]
fn a_refused_foreign_creator_leaves_the_open_possible() {
    let (mut g, mut l, _, d, d_idx) = proposer_chain(5);
    assert_eq!(receive(&mut g, &d), ReceiveBlockOutcome::AcceptedSilently);
    let foreign_above = normal_after(&g, &d, 3, 2);
    assert_eq!(
        step_reason(&mut l, &foreign_above),
        Some(ValidationReason::RunCreator)
    );
    assert_eq!(
        receive(&mut l, &foreign_above),
        ReceiveBlockOutcome::Rejected(RejectReason::InvalidEvidence)
    );
    assert_eq!(head_of(&l), (6, d.view().hash()));
    assert!(l.open_approval(d_idx), "nothing foreign above p − 1");
}

#[test]
fn open_refuses_past_the_horizon() {
    // The head reaches `p + H` only through `d`'s own evidence, which
    // closes its run (Story 6.7 D4: replays end by `p + H − 1`), so the
    // package is completed first and the evidence is the block at #14.
    let (mut g, mut l, _, d, d_idx) = proposer_chain(5);
    accumulate(&mut l, &d, d_idx, 2);
    assert_eq!(receive(&mut g, &d), ReceiveBlockOutcome::AcceptedSilently);
    let mut prev = d;
    for salt in 0..7 {
        let next = normal_after(&g, &prev, 5, 10 + salt);
        assert_eq!(
            receive(&mut g, &next),
            ReceiveBlockOutcome::AcceptedSilently
        );
        assert_eq!(
            receive(&mut l, &next),
            ReceiveBlockOutcome::AcceptedSilently
        );
        prev = next;
    }
    let evidence = l
        .build_evidence_block(l.active_chain_head_idx, 0)
        .expect("complete");
    // Head 13: `p + H = 14 > 13`, the last head that opens.
    assert_eq!(head_of(&l).0, 13);
    l.approval.clear();
    assert!(l.open_approval(d_idx), "the boundary control");
    l.approval.clear();
    assert_eq!(
        receive(&mut l, &evidence),
        ReceiveBlockOutcome::AcceptedSilently
    );
    assert_eq!(head_of(&l).0, 14);
    // `F` followed `S_head − H` to 6: reset it, so only the bound refuses.
    l.non_conflict = NonConflictRing::new();
    assert_refused(&mut l, d_idx, "p + H ≤ S_head");
}

/// AC9 test 1 — a second open (the proposer's next deviation, at 8 on
/// its own `d`'s evidence) replaces the first; a refused one keeps it.
/// The second deviation follows the evidence: inside `d`'s open run only
/// override-form blocks by its creator may follow it (Story 6.7 D4).
#[test]
fn a_second_open_replaces_the_first() {
    let (mut g, mut l, _, d, d_idx) = proposer_chain(5);
    accumulate(&mut l, &d, d_idx, 2);
    let evidence = l.build_evidence_block(d_idx, 0).expect("complete");
    assert_eq!(evidence.view().sequence(), 7);
    assert_eq!(receive(&mut g, &d), ReceiveBlockOutcome::AcceptedSilently);
    for node in [&mut g, &mut l] {
        assert_eq!(
            receive(node, &evidence),
            ReceiveBlockOutcome::AcceptedSilently
        );
    }
    let second = deviation_after(&g, &evidence, 5, 2);
    assert_eq!(
        receive(&mut l, &second),
        ReceiveBlockOutcome::AcceptedSilently
    );
    let second_idx = l.blocks.find(8, &second.view().hash()).expect("held");
    assert!(l.open_approval(second_idx));
    assert_eq!(l.approval.deviation(), Some((8, &second.view().hash())));
    assert_eq!(
        l.approval.counts().2,
        0,
        "the first one's supports do not carry over"
    );
    l.non_conflict.raise_floor(6);
    assert!(!l.open_approval(d_idx));
    assert_eq!(
        l.approval.deviation(),
        Some((8, &second.view().hash())),
        "kept"
    );
}

/// AC9 test 2 (direct case) — a non-member is rejected and not stored; the
/// first support of a rank is stored, a duplicate rank and a support past
/// `r_eff` are accepted and not stored; another tuple is untouched. Each
/// support is verified once (by FR26 (ii)), and (iv-b) never runs for the
/// own tuple.
#[test]
fn accumulation_keeps_the_first_support_of_each_rank() {
    let (_, mut l, _, d, d_idx) = proposer_chain(5);
    assert!(l.open_approval(d_idx));
    let h = d.view().hash();
    let members: std::vec::Vec<u32> = l.approval.members().to_vec();
    let (verifications, subgroup_evals) = (counted(&VERIFICATIONS), counted(&SUBGROUP_EVALS));
    for non_member in [1, 2] {
        assert_eq!(
            intake(&mut l, &support_by(non_member, 5, 6, h)),
            ReceiveSupportOutcome::Rejected
        );
    }
    assert_eq!(held(&l), 0);
    assert_eq!(
        intake(&mut l, &support_by(members[0], 5, 6, h)),
        ReceiveSupportOutcome::Accepted
    );
    assert_eq!(held(&l), 1);
    assert_eq!(counted(&VERIFICATIONS) - verifications, 3, "once each");
    assert_eq!(counted(&SUBGROUP_EVALS), subgroup_evals, "(iv-b) skipped");
    // A copy past the dedupe cache: the rank is held.
    l.support_dedupe = SupportDedupe::new(7);
    assert_eq!(
        intake(&mut l, &support_by(members[0], 5, 6, h)),
        ReceiveSupportOutcome::Accepted
    );
    assert_eq!(held(&l), 1);
    assert_eq!(
        intake(&mut l, &support_by(members[1], 5, 6, h)),
        ReceiveSupportOutcome::Accepted
    );
    assert_eq!(held(&l), 2);
    assert_eq!(
        intake(&mut l, &support_by(members[2], 5, 6, h)),
        ReceiveSupportOutcome::Accepted,
        "past r_eff"
    );
    assert_eq!(held(&l), 2);
    assert_eq!(
        intake(&mut l, &support_by(3, 4, 6, [0x5A; 32])),
        ReceiveSupportOutcome::Accepted,
        "another tuple: a plain relay"
    );
    assert_eq!(held(&l), 2);
    assert_eq!(l.approval.deviation(), Some((6, &h)));
}

/// AC9 test 2 (sibling case) — FR26 defers the signature, so the
/// accumulator verifies it, once: a bad one is rejected and not stored.
#[test]
fn sibling_supports_are_verified_by_the_accumulator() {
    let (_, mut l, _, d, d_idx, _) = sibling_proposer();
    assert!(l.open_approval(d_idx));
    let h = d.view().hash();
    // A member other than node #0, whose key is always derivable: its key
    // was registered at #2, above `S_tail`, so FR26 defers (ii).
    let first = *l
        .approval
        .members()
        .iter()
        .find(|&&n| n != 0)
        .expect("a member");
    let tail = l
        .blocks
        .get(l.snake_chain_tail_idx)
        .expect("tail")
        .sequence();
    assert!(
        !l.key_is_branch_independent(first, tail),
        "deferred by FR26"
    );
    assert_eq!(
        intake(&mut l, &forged(support_by(first, 2, 6, h))),
        ReceiveSupportOutcome::Rejected
    );
    assert_eq!(held(&l), 0);
    assert_eq!(
        intake(&mut l, &support_by(1, 2, 6, h)),
        ReceiveSupportOutcome::Rejected
    );
    let verifications = counted(&VERIFICATIONS);
    assert_eq!(
        intake(&mut l, &support_by(first, 2, 6, h)),
        ReceiveSupportOutcome::Accepted
    );
    assert_eq!(held(&l), 1);
    assert_eq!(
        counted(&VERIFICATIONS) - verifications,
        1,
        "deferred, then once"
    );
}

/// AC9 test 3 — the RAM discard triggers clear the accumulator at the next
/// own-tuple intake (or at once: re-entry to collecting).
#[test]
fn a_dead_accumulator_is_cleared() {
    let at_intake = |l: &mut SupportChain, d: &Block| {
        assert!(l.approval.deviation().is_some(), "open until the intake");
        let member = l.approval.members()[0];
        assert_eq!(
            intake(l, &support_by(member, 5, 6, d.view().hash())),
            ReceiveSupportOutcome::Accepted,
            "a plain relay"
        );
        l.approval.deviation().is_none()
    };
    let (_, mut l, _, d, d_idx) = proposer_chain(5);
    assert!(l.open_approval(d_idx));
    l.non_conflict.raise_floor(6);
    assert!(at_intake(&mut l, &d), "p ≤ F while incomplete");

    let (_, mut l, _, d, d_idx) = proposer_chain(5);
    assert!(l.open_approval(d_idx));
    let parent = l.blocks.get(d_idx).expect("d").parent_ref();
    l.blocks.set_on_active_chain(parent, false);
    assert!(!l.approval_live());
    assert!(at_intake(&mut l, &d), "p − 1 left the active chain");

    let (_, mut l, _, d, d_idx, _) = sibling_proposer();
    assert!(l.open_approval(d_idx));
    l.blocks.delete(d_idx);
    assert!(l.approval.deviation().is_some());
    let member = l.approval.members()[0];
    assert_eq!(
        intake(&mut l, &support_by(member, 2, 6, d.view().hash())),
        ReceiveSupportOutcome::Accepted
    );
    assert!(l.approval.deviation().is_none(), "d deleted");

    let (_, mut l, _, _, d_idx) = proposer_chain(5);
    assert!(l.open_approval(d_idx));
    l.reenter_collecting(0);
    assert!(l.approval.deviation().is_none(), "re-entry to collecting");
}

/// AC9 test 3 — validated blocks stop the proposer, unverified ones do
/// not: a validated `u`-block at `p`; a planted evidence for a deviation at
/// `p`, unverified and then verified; the sibling's heavier active head
/// keeps it (DEC-200).
#[test]
fn only_validated_blocks_stop_the_accumulator() {
    let (_, mut l, blocks, d, d_idx) = proposer_chain(5);
    assert!(l.open_approval(d_idx));
    assert!(l.approval_live());
    let u = u_block(&blocks, &[&d]);
    assert_eq!(receive(&mut l, &u), ReceiveBlockOutcome::AcceptedSilently);
    assert_eq!(verified(&l, &u), Some(true));
    assert!(!l.approval_live(), "a validated u-block");

    let (_, mut l, _, _, d_idx, _) = sibling_proposer();
    assert!(l.open_approval(d_idx));
    assert!(l.approval_live(), "the heavier sibling keeps it");
}

/// AC9 test 3, Story 6.7 D3 (AR-025 closed): only an active evidence at
/// `p` stops the proposer — a planted side evidence does not, unverified or
/// signature-verified — and a failed read of an active one never discards.
/// Each case builds its chain in its own helper frame (the test-thread
/// stack, 6.6); an active evidence is always planted verified (it passed
/// Tier 3), so `verified` varies only the side cases.
#[test]
fn only_an_active_evidence_stops_the_accumulator() {
    for (on_chain, verified, stored, live, why) in [
        (false, false, true, true, "an unverified side evidence"),
        (
            false,
            true,
            true,
            true,
            "a signature-verified side evidence",
        ),
        (true, true, true, false, "an active evidence at p"),
        (true, true, false, true, "a failed read never discards"),
    ] {
        evidence_stop_case(on_chain, verified, stored, live, why);
    }
}

fn evidence_stop_case(on_chain: bool, verified: bool, stored: bool, live: bool, why: &str) {
    let evidence = node_four_evidence();
    let (_, mut l, _, _, d_idx) = proposer_chain(5);
    assert!(l.open_approval(d_idx));
    if on_chain {
        plant_on_chain(&mut l, &evidence, stored);
    } else {
        plant(&mut l, &evidence, verified, stored);
    }
    assert_eq!(l.approval_live(), live, "{why}");
}

/// AC9 test 3 — an unverified `u`-block (the 6.5 fixture: node 5's
/// balance deviation lists node 1, moving its key above `p − 1`) does not
/// stop the accumulator.
#[test]
fn an_unverified_u_block_does_not_stop_the_accumulator() {
    let (g, mut l, blocks) = support_chain(5);
    let top = g.vote_engine.top_creator().expect("a top");
    let snapshot = |n| vote_snapshot(g.vote_engine.accumulated_vote_of(n));
    let template = balance_snapshot(&g, 6, blocks[5].view().hash(), &[1]);
    let d = reheader(&template, 5, snapshot(5), top, snapshot(top), key_of(5));
    assert_eq!(receive(&mut l, &d), ReceiveBlockOutcome::AcceptedSilently);
    let d_idx = l.blocks.find(6, &d.view().hash()).expect("held");
    assert!(l.open_approval(d_idx));
    let u = u_block(&blocks, &[&d]);
    assert_eq!(receive(&mut l, &u), ReceiveBlockOutcome::AcceptedSilently);
    assert_eq!(verified(&l, &u), Some(false));
    assert!(l.approval_live());
}

/// AC9 test 3 — the proposer's own evidence, admitted, releases it.
#[test]
fn the_own_evidence_releases_the_accumulator() {
    let (_, mut l, _, d, d_idx) = proposer_chain(5);
    accumulate(&mut l, &d, d_idx, 2);
    let e = l.build_evidence_block(d_idx, 0).expect("evidence");
    assert!(l.approval_live(), "building releases nothing");
    assert_eq!(receive(&mut l, &e), ReceiveBlockOutcome::AcceptedSilently);
    assert_eq!(head_of(&l), (7, e.view().hash()));
    assert!(!l.approval_live(), "released");
    assert_eq!(
        l.approval_step(7, Ok(TailObligation::None), 0, 0),
        ApprovalStep::Hold
    );
}

/// AC9 test 4 — 6.4's emission gains the evidence half: an active
/// evidence at `p` stops it, a side one does not, verified or not (Story
/// 6.7 D3, AR-025 closed), and a failed read of an active one stops it (the
/// conservative side). An active evidence is always planted verified.
#[test]
fn the_evidence_half_stops_emission() {
    set_grace_admits(true);
    let evidence = node_four_evidence();
    for (on_chain, verified, stored, endorsed) in [
        (true, true, true, false),
        (false, true, true, true),
        (false, false, true, true),
        (true, true, false, false),
    ] {
        let (g, mut l, blocks) = support_chain(3);
        if on_chain {
            plant_on_chain(&mut l, &evidence, stored);
        } else {
            plant(&mut l, &evidence, verified, stored);
        }
        let x = deviation_after(&g, &blocks[5], 4, 1);
        assert_eq!(
            support_for(&mut l, &x).is_some(),
            endorsed,
            "on chain {on_chain}, verified {verified}, stored {stored}"
        );
    }
    set_grace_admits(false);
}

/// AC9 test 4 / D6 converse — a candidate whose own drop is obligated
/// gets no support unless it is the matching replay: block #0 is node
/// #0's seed source; a transaction block does not preserve it, a balance
/// block does.
#[test]
fn an_obligated_own_drop_needs_its_replay() {
    let (g, mut l, blocks) = support_chain(5);
    let zero = l.blocks.find(0, &blocks[0].view().hash()).expect("#0");
    assert_eq!(
        classify_tail_drop(&l.blocks, &l.node_info, zero),
        Ok(TailObligation::SeedSource)
    );
    let x = deviation_after(&g, &blocks[5], 4, 1);
    let top = g.vote_engine.top_creator().expect("a top");
    let snapshot = |n| vote_snapshot(g.vote_engine.accumulated_vote_of(n));
    let template = balance_snapshot(&g, 6, blocks[5].view().hash(), &[1]);
    let balance = reheader(&template, 5, snapshot(5), top, snapshot(top), key_of(5));
    assert_eq!(receive(&mut l, &x), ReceiveBlockOutcome::AcceptedSilently);
    assert_eq!(
        receive(&mut l, &balance),
        ReceiveBlockOutcome::AcceptedSilently
    );
    let x_idx = l.blocks.find(6, &x.view().hash()).expect("x held");
    let b_idx = l
        .blocks
        .find(6, &balance.view().hash())
        .expect("balance held");
    assert!(
        !l.extension_preserves(x_idx, zero),
        "a transaction block drops it"
    );
    assert!(
        l.extension_preserves(b_idx, zero),
        "a balance block replays it"
    );
    let clean = l.blocks.find(5, &blocks[5].view().hash()).expect("#5");
    assert_eq!(
        classify_tail_drop(&l.blocks, &l.node_info, clean),
        Ok(TailObligation::None)
    );
    assert!(l.extension_preserves(x_idx, clean), "nothing to preserve");
    let free = l.blocks.next_free_index().expect("a free slot");
    assert!(
        !l.extension_preserves(x_idx, free),
        "an unclassifiable drop never endorses"
    );
}

/// AC9 test 5 — the builder at the threshold: proposer 2, credited at #6
/// by node 3 so that its deviation `d@7` consumes votes and it ranks `k ≥
/// 2` at `p − 1`; its supports arrive out of rank order. The block frames
/// exactly, a second node admits it on `d`, its header carries the FR27
/// overrides, its bitmap has exactly the held ranks LSB-first, its
/// aggregate verifies in rank order, and its value and late list equal the
/// hand computation (DEC-216, DEC-184).
#[test]
fn the_evidence_block_carries_the_approval() {
    let (mut g, mut l, blocks) = support_chain(2);
    let template = tx_block(6, blocks[5].view().hash(), 0, votes_for(6, 2, 1, 600));
    let a6 = real_on(&g, &template, 3, key_of(3));
    assert_eq!(receive(&mut g, &a6), ReceiveBlockOutcome::AcceptedSilently);
    assert_eq!(receive(&mut l, &a6), ReceiveBlockOutcome::AcceptedSilently);
    let d = deviation_after(&g, &a6, 2, 1);
    assert_eq!(receive(&mut l, &d), ReceiveBlockOutcome::AcceptedSilently);
    let d_idx = l.blocks.find(7, &d.view().hash()).expect("d");
    assert!(l.open_approval(d_idx));
    let h = d.view().hash();
    let members: std::vec::Vec<u32> = l.approval.members().to_vec();
    assert_eq!(members, expected_members_at(7, 2, &[0, 3, 4]));
    for &n in &[members[2], members[0]] {
        assert_eq!(
            intake(&mut l, &support_by(n, 2, 7, h)),
            ReceiveSupportOutcome::Accepted
        );
    }
    let before = engine_votes(&l);
    let e = l.build_evidence_block(d_idx, 0).expect("evidence");
    assert_eq!(engine_votes(&l), before, "the engine is byte-identical");

    // (a) framing, (c) the header.
    let view = e.view();
    assert_eq!(e.content_length(), Some(e.len()));
    assert_eq!(
        (
            view.version(),
            view.sequence(),
            view.creator(),
            view.payload_type()
        ),
        (1, 8, 2, PAYLOAD_TYPE_APPROVAL)
    );
    assert_eq!(
        (
            view.consumed_votes(),
            view.first_voted_node(),
            view.consumed_votes_from_first_voted_node()
        ),
        (0, 2, 0)
    );
    assert_eq!((view.mined_amount(), view.previous_hash()), (0, &h[..]));

    // (d) the bitmap and the aggregate.
    let ev = evidence_of(&e, 2);
    assert_eq!((ev.deviation_sequence, ev.m), (7, 3));
    assert_eq!(ev.bitmap, [0b101]);
    assert!(aggregate_verifies_at(
        &ev.aggregate,
        7,
        2,
        &h,
        &[members[0], members[2]]
    ));
    #[cfg(feature = "schnorr")]
    assert!(
        !aggregate_verifies_at(&ev.aggregate, 7, 2, &h, &[members[2], members[0]]),
        "bound to the rank order"
    );

    // (e) DEC-216 at `p − 1` (`g` is at #6): `B_k = r_eff · Σ_{j ≤ k}
    // (grown(av(n_j)) + vs)`, minus `d`'s consumed votes.
    let engine = &g.vote_engine;
    let vs = u64::from(
        g.chain_config
            .active_configuration()
            .expect("config")
            .vote_scale()
            .get(),
    );
    let u = engine.top_creator().expect("a top");
    assert_eq!(u, d.view().first_voted_node());
    let mut above: std::vec::Vec<u32> = (0..16).filter(|&n| engine.ranks_above(n, 2)).collect();
    above.sort_by(|&a, &b| {
        if engine.ranks_above(a, b) {
            core::cmp::Ordering::Less
        } else if engine.ranks_above(b, a) {
            core::cmp::Ordering::Greater
        } else {
            core::cmp::Ordering::Equal
        }
    });
    assert!(above.len() >= 2, "k ≥ 2");
    let sum: u64 = above
        .iter()
        .chain(&[2])
        .map(|&n| u64::from(engine.grown(engine.accumulated_vote_of(n)).expect("grows")) + vs)
        .sum();
    let cv = u64::from(d.view().consumed_votes());
    assert!(cv > 0, "d consumes votes");
    assert_eq!(ev.supporter_vote_sum, 2 * sum - cv);

    // (f) the late list: the ranks above the proposer but `u`, in creator
    // order, valued after the evidence's interest step at the tip (`d`).
    let late: std::vec::Vec<(u32, u32)> = above
        .iter()
        .filter(|&&n| n != u)
        .map(|&n| {
            (
                n,
                l.vote_engine
                    .grown(l.vote_engine.accumulated_vote_of(n))
                    .expect("grows"),
            )
        })
        .collect();
    assert_eq!(ev.late, late);

    // (b) a second node admits it on `d`.
    assert_eq!(receive(&mut g, &d), ReceiveBlockOutcome::AcceptedSilently);
    assert_eq!(receive(&mut g, &e), ReceiveBlockOutcome::AcceptedSilently);
    assert_eq!(head_of(&g), (8, e.view().hash()));
}

/// AC9 test 5 (f) — the late list is the prefix that fits: one entry room.
#[test]
fn the_late_list_is_truncated_to_the_room() {
    let (_, mut l, _, d, d_idx) = proposer_chain(2);
    accumulate(&mut l, &d, d_idx, 2);
    let full = l.build_evidence_block(d_idx, 0).expect("untruncated");
    assert_eq!(
        evidence_of(&full, 2).late.len(),
        2,
        "nodes 5 and 0 above it"
    );
    let fixed = moonblokz_chain_types::approval_fixed_size(3, 2);
    let with_room = |l: &mut SupportChain, room: usize| {
        crate::approval::test_seams::PAYLOAD_ROOM.with(|cell| cell.set(room));
        let e = l.build_evidence_block(d_idx, 0);
        crate::approval::test_seams::PAYLOAD_ROOM.with(|cell| cell.set(usize::MAX));
        e
    };
    let one = with_room(&mut l, fixed + APPROVAL_LATE_ENTRY_SIZE).expect("one entry");
    let ev = evidence_of(&one, 2);
    assert_eq!(
        ev.late,
        evidence_of(&full, 2).late[..1],
        "the prefix in creator order"
    );
    assert_eq!(ev.late[0].0, 5);
    assert_eq!(one.view().payload().len(), fixed + APPROVAL_LATE_ENTRY_SIZE);
    let none = with_room(&mut l, fixed).expect("no room for a late entry");
    assert!(evidence_of(&none, 2).late.is_empty());
    assert_eq!(none.view().payload().len(), fixed);
    assert!(
        with_room(&mut l, fixed - 1).is_none(),
        "the fixed part does not fit"
    );
}

/// AC9 test 5 — the DEC-200 sibling case builds, from `d`'s own branch
/// projected off the active chain, exactly the block the direct case
/// builds; the live engine (at `y`) is restored. Below the threshold:
/// nothing.
#[test]
fn the_sibling_case_builds_the_direct_case_block() {
    let (_, mut direct, _, d, direct_idx) = proposer_chain(2);
    accumulate(&mut direct, &d, direct_idx, 1);
    assert!(
        direct.build_evidence_block(direct_idx, 0).is_none(),
        "below r_eff"
    );
    let member = direct.approval.members()[1];
    assert_eq!(
        intake(&mut direct, &support_by(member, 2, 6, d.view().hash())),
        ReceiveSupportOutcome::Accepted
    );
    let expected = direct.build_evidence_block(direct_idx, 0).expect("direct");

    let (mut g, mut l, _, sibling_d, d_idx, _) = sibling_proposer();
    assert_eq!(sibling_d.view().hash(), d.view().hash());
    accumulate(&mut l, &sibling_d, d_idx, 2);
    let before = engine_votes(&l);
    let e = l.build_evidence_block(d_idx, 0).expect("sibling");
    assert_eq!(engine_votes(&l), before, "the engine stays at y");
    assert_ne!(
        engine_votes(&l),
        engine_votes(&direct),
        "y, not d, is applied"
    );
    assert_eq!(e.serialized_bytes(), expected.serialized_bytes());
    assert_eq!(receive(&mut g, &d), ReceiveBlockOutcome::AcceptedSilently);
    assert_eq!(receive(&mut g, &e), ReceiveBlockOutcome::AcceptedSilently);
}

/// AC9 test 7 — every branch of FR29's decision function.
#[test]
fn approval_step_follows_fr29() {
    let (_, fresh, _) = support_chain(5);
    assert_eq!(
        fresh.approval_step(6, Ok(TailObligation::None), 0, 0),
        ApprovalStep::Hold
    );

    let (_, mut l, _, d, d_idx) = proposer_chain(5);
    let delay = u64::from(
        l.chain_config
            .active_configuration()
            .expect("config")
            .deviation_replay_insertion_delay_ms(),
    );
    accumulate(&mut l, &d, d_idx, 1);
    let seed = Ok(TailObligation::SeedSource);
    assert_eq!(
        l.approval_step(6, Ok(TailObligation::None), 0, 0),
        ApprovalStep::Hold
    );
    assert_eq!(
        l.approval_step(6, Err(TailUnreadable), 0, 0),
        ApprovalStep::Hold
    );
    // Paced from the last emission (`d`'s, then each replay's), not from
    // `now`; the boundary is inclusive.
    assert_eq!(
        l.approval_step(6, seed, 100, 150),
        ApprovalStep::WaitUntil(100 + delay)
    );
    assert_eq!(
        l.approval_step(6, seed, 100, 100 + delay - 1),
        ApprovalStep::WaitUntil(100 + delay)
    );
    assert_eq!(
        l.approval_step(6, seed, 100, 100 + delay),
        ApprovalStep::Replay
    );
    assert_eq!(
        l.approval_step(6, Ok(TailObligation::Utxo), 100, 100 + delay),
        ApprovalStep::Replay,
        "any obligation kind"
    );
    // D6 cap while incomplete: a replay at 14 would close `p = 6` (`H = 8`).
    assert_eq!(l.approval_step(12, seed, 0, delay), ApprovalStep::Replay);
    assert_eq!(l.approval_step(13, seed, 0, delay), ApprovalStep::Hold);

    let member = l.approval.members()[1];
    assert_eq!(
        intake(&mut l, &support_by(member, 5, 6, d.view().hash())),
        ReceiveSupportOutcome::Accepted
    );
    assert_eq!(
        l.approval_step(6, Ok(TailObligation::None), 100, 100),
        ApprovalStep::Evidence,
        "never paced"
    );
    assert_eq!(
        l.approval_step(6, Err(TailUnreadable), 100, 100),
        ApprovalStep::Hold,
        "an unreadable tail is never taken as no obligation"
    );
    // Story 6.7 D1 (DEC-258): the cap holds complete or not — a replay at
    // 14 would leave the evidence no position by `p + H = 14`.
    assert_eq!(l.approval_step(12, seed, 0, delay), ApprovalStep::Replay);
    assert_eq!(
        l.approval_step(13, seed, 0, delay),
        ApprovalStep::Hold,
        "no lift for a complete package"
    );
}

/// AC9 test 7 — converted by Story 6.7 D4 (DEC-258; it pinned DEC-240's
/// D6 lift: a complete package outliving the bound on its own replays).
/// A deviation's run ends by `p + H`: the proposer's replays fill
/// `p + 1 ..= p + H − 1`, and one more at `p + H` is refused (rule 4,
/// `RunBound`) whether its package is complete or not. A complete package
/// builds its evidence over that rewind, and the evidence fits at
/// `p + H`, closing the run.
#[test]
fn a_run_ends_by_the_bound_complete_or_not() {
    for complete in [true, false] {
        let (mut g, mut l, _, d, d_idx) = proposer_chain(5);
        accumulate(&mut l, &d, d_idx, if complete { 2 } else { 1 });
        assert_eq!(receive(&mut g, &d), ReceiveBlockOutcome::AcceptedSilently);
        let mut prev = d;
        for salt in 0..7 {
            let next = normal_after(&g, &prev, 5, 10 + salt);
            assert_eq!(
                receive(&mut g, &next),
                ReceiveBlockOutcome::AcceptedSilently
            );
            assert_eq!(
                receive(&mut l, &next),
                ReceiveBlockOutcome::AcceptedSilently
            );
            prev = next;
        }
        assert_eq!(head_of(&l).0, 13, "p + H − 1");
        let over = normal_after(&g, &prev, 5, 17);
        assert_eq!(
            run_rules(&over.view(), Some((6, 5)), l.verification_horizon()),
            Err(ValidationReason::RunBound)
        );
        for node in [&mut g, &mut l] {
            assert_eq!(
                receive(node, &over),
                ReceiveBlockOutcome::Rejected(RejectReason::InvalidEvidence),
                "a replay at p + H"
            );
        }
        assert_eq!(head_of(&l).0, 13);
        assert!(l.approval_live(), "still inside the bound");
        let tip = l.active_chain_head_idx;
        let evidence = l.build_evidence_block(tip, 0);
        assert_eq!(evidence.is_some(), complete);
        if let Some(e) = evidence {
            assert_eq!(e.view().sequence(), 14, "p + H");
            assert_eq!(receive(&mut g, &e), ReceiveBlockOutcome::AcceptedSilently);
            assert_eq!(head_of(&g), (14, e.view().hash()), "the run closes");
        }
    }
}

/// AC9 test 8 — the ordering pin: on `W = 8` the evidence on `d@7` would
/// drop #0, node #0's seed source, without its replay; a Ready node refuses
/// it (Story 9.1's binding), and `approval_step` asks for the replay first.
/// (`W = 7`, which put `d` at 6, has no legal horizon: configuration §6
/// check 21; node 1's normal block `b6` fills the extra window slot.)
#[test]
fn an_evidence_over_an_obligated_drop_is_refused() {
    let (mut g, mut l, blocks) = support_chain_on(4, local_storage(4), 8, |_| {});
    let b6 = normal_after(&g, &blocks[5], 1, 2);
    for node in [&mut g, &mut l] {
        assert_eq!(receive(node, &b6), ReceiveBlockOutcome::AcceptedSilently);
    }
    let d = deviation_after(&g, &b6, 4, 1);
    assert_eq!(receive(&mut l, &d), ReceiveBlockOutcome::AcceptedSilently);
    let d_idx = l.blocks.find(7, &d.view().hash()).expect("held");
    accumulate(&mut l, &d, d_idx, 2);
    let zero = l.blocks.find(0, &blocks[0].view().hash()).expect("#0");
    let obligation = classify_tail_drop(&l.blocks, &l.node_info, zero);
    assert_eq!(obligation, Ok(TailObligation::SeedSource));
    let delay = u64::from(
        l.chain_config
            .active_configuration()
            .expect("config")
            .deviation_replay_insertion_delay_ms(),
    );
    assert_eq!(
        l.approval_step(7, obligation, 0, delay),
        ApprovalStep::Replay,
        "the replay comes first"
    );
    let e = l.build_evidence_block(d_idx, 0).expect("built regardless");
    assert_eq!(receive(&mut g, &d), ReceiveBlockOutcome::AcceptedSilently);
    assert_eq!(
        receive(&mut g, &e),
        ReceiveBlockOutcome::Rejected(RejectReason::InvalidEvidence),
        "Tier 3: the drop of #0 is not preserved"
    );
    assert_eq!(head_of(&g), (7, d.view().hash()));
}

/// Proposer 5 over a failing backend, complete, with its own block `d7`
/// above `d`: returns the node, `d`'s slot and the head's.
fn failing_proposer() -> (Chain16<FailingSupportStorage>, u32, u32) {
    let (mut g, mut l, blocks) = support_chain_on(5, failing_storage(5), 16, |_| {});
    let d = deviation_after(&g, &blocks[5], 5, 1);
    assert_eq!(receive(&mut l, &d), ReceiveBlockOutcome::AcceptedSilently);
    assert_eq!(receive(&mut g, &d), ReceiveBlockOutcome::AcceptedSilently);
    let d7 = normal_after(&g, &d, 5, 2);
    assert_eq!(receive(&mut l, &d7), ReceiveBlockOutcome::AcceptedSilently);
    let d_idx = l.blocks.find(6, &d.view().hash()).expect("d");
    accumulate(&mut l, &d, d_idx, 2);
    let tip = l.active_chain_head_idx;
    (l, d_idx, tip)
}

/// AC9 test 8b — the scoped rewind: a read failure during the rewind
/// restores the engine; a failure while restoring re-enters collecting; a
/// refused pre-check changes nothing.
#[test]
fn the_rewind_restores_or_reenters_collecting() {
    // `d`'s second read is the rewind's undo of `d` (after the builder's
    // header read): fails, `d7` is re-applied.
    let (mut l, d_idx, tip) = failing_proposer();
    let before = engine_votes(&l);
    l.storage.failing_slot = d_idx;
    l.storage.reads_left.set(1);
    assert!(l.build_evidence_block(tip, 0).is_none());
    assert_eq!(engine_votes(&l), before);
    assert_eq!(
        l.storage.attempts.get(),
        2,
        "it failed at the rewind's undo of d"
    );
    assert!(l.is_ready());
    assert!(l.approval.deviation().is_some());
    l.storage.failing_slot = NONE_REF;
    let before = engine_votes(&l);
    assert!(
        l.build_evidence_block(tip, 0).is_some(),
        "the fault was transient"
    );
    assert_eq!(engine_votes(&l), before);

    // `d7`'s second read is the restore's re-apply: re-entry (DEC-205).
    let (mut l, _, tip) = failing_proposer();
    l.storage.failing_slot = tip;
    l.storage.reads_left.set(1);
    assert!(l.build_evidence_block(tip, 0).is_none());
    assert!(!l.is_ready(), "re-entered collecting");
    assert!(l.approval.deviation().is_none());

    // A tip that is not the head in the direct case: refused up front.
    let (mut l, d_idx, _) = failing_proposer();
    let (before, reads) = (engine_votes(&l), l.storage.reads.get());
    assert!(l.build_evidence_block(d_idx, 0).is_none());
    assert_eq!(engine_votes(&l), before);
    assert_eq!(
        l.storage.reads.get() - reads,
        1,
        "the header read only: no vote step ran"
    );
    assert!(l.is_ready() && l.approval.deviation().is_some());
}

/// AC9 test 8b — a failure on the sibling branch's first application:
/// `y` is re-applied and the engine is byte-identical.
#[test]
fn a_failed_sibling_application_restores_the_engine() {
    let (g, mut l, blocks) = support_chain_on(2, failing_storage(2), 16, |_| {});
    let d = deviation_after(&g, &blocks[5], 2, 1);
    assert_eq!(receive(&mut l, &d), ReceiveBlockOutcome::AcceptedSilently);
    let y = deviation_after(&g, &blocks[5], 5, 4);
    assert_eq!(receive(&mut l, &y), ReceiveBlockOutcome::AcceptedSilently);
    let d_idx = l.blocks.find(6, &d.view().hash()).expect("d");
    accumulate(&mut l, &d, d_idx, 2);
    let before = engine_votes(&l);
    let reads = l.storage.attempts.get();
    l.storage.failing_slot = d_idx;
    // `d`'s read before the application: the builder's header read.
    l.storage.reads_left.set(1);
    assert!(l.build_evidence_block(d_idx, 0).is_none());
    assert_eq!(engine_votes(&l), before);
    assert!(l.is_ready());
    assert_eq!(
        l.storage.attempts.get() - reads,
        2,
        "it failed at the application"
    );
}

/// AC9 test 9 — AR16 replay: a fixed support stream (duplicates,
/// non-members, a bad signature) and fixed ticks, run twice on fresh
/// modules, give byte-identical evidence and steps.
#[test]
fn the_evidence_is_replay_deterministic() {
    fn run() -> (std::vec::Vec<u8>, [ApprovalStep; 3]) {
        let (_, mut l, _, d, d_idx) = proposer_chain(2);
        assert!(l.open_approval(d_idx));
        let h = d.view().hash();
        let members: std::vec::Vec<u32> = l.approval.members().to_vec();
        let stream = [
            forged(support_by(members[1], 2, 6, h)),
            support_by(1, 2, 6, h),
            support_by(members[2], 2, 6, h),
            support_by(members[2], 2, 6, h),
            support_by(members[0], 2, 6, h),
            support_by(members[1], 2, 6, h),
        ];
        for message in &stream {
            let _ = intake(&mut l, message);
        }
        let steps = [
            l.approval_step(6, Ok(TailObligation::Utxo), 10, 20),
            l.approval_step(6, Ok(TailObligation::None), 10, 20),
            l.approval_step(6, Err(TailUnreadable), 10, 20),
        ];
        let e = l.build_evidence_block(d_idx, 30).expect("evidence");
        (e.serialized_bytes().to_vec(), steps)
    }
    assert_eq!(run(), run());
}

/// Story 6.6 (the investigation that found it, 2026-11-17): a valid block
/// with bytes after its last transaction, signed over all its wire bytes
/// (since Story 6.12, the FR70 preimage of all of them: the trailing bytes are
/// in `H(payload)`), was accepted live and lost at restart (the restart trims it to its
/// framed length, which no longer verifies, and cut the chain below it).
/// Tier 1 now refuses it as exact evidence; the clean block survives a
/// restart.
#[test]
fn a_block_with_bytes_after_its_payload_is_refused() {
    let (g, mut l, blocks) = support_chain(3);
    let clean = normal_after(&g, &blocks[5], 1, 7);
    let mut raw = std::vec::Vec::from(clean.serialized_bytes());
    raw.extend_from_slice(&[0xAB, 0xCD, 0xEF]);
    let signature_at = HEADER_SIZE - SIGNATURE_SIZE;
    let signer = Crypto::new([key_of(1); PRIVATE_KEY_SIZE])
        .ok()
        .expect("key");
    let preimage = BlockView::from_bytes(&raw)
        .ok()
        .expect("parses")
        .signing_preimage();
    let signature = signer.sign(&preimage);
    raw[signature_at..HEADER_SIZE].copy_from_slice(signature.serialize());
    let trailing = Block::from_bytes(&raw).ok().expect("parses");
    // The signature is valid: the refusal below is the framing's, not the
    // signature's (Story 6.12).
    assert!(signer.verify_signature(
        &trailing.view().signing_preimage(),
        &signature,
        signer.public_key()
    ));
    assert_eq!(trailing.content_length(), Some(clean.len()));
    assert_eq!(
        receive(&mut l, &trailing),
        ReceiveBlockOutcome::Rejected(RejectReason::InvalidEvidence)
    );
    assert_eq!(head_of(&l).0, 5);

    assert_eq!(
        receive(&mut l, &clean),
        ReceiveBlockOutcome::AcceptedSilently
    );
    let mut restarted = local_node(3, l.storage);
    let (outcome, _) = restarted.initialize_from_storage(500);
    assert_eq!(outcome, InitOutcome::ResumedReady);
    assert_eq!(
        head_of(&restarted),
        (6, clean.view().hash()),
        "survives a restart"
    );
}

/// Code review P1 — a dead accumulator does not stand in for (iv-b): with
/// `p ≤ F` while incomplete, an own-tuple support from a node outside the
/// subgroup is classified as a plain relay, (iv-b) included, and rejected.
#[test]
fn a_dead_accumulator_does_not_skip_the_subgroup_check() {
    let (_, mut l, _, d, d_idx) = proposer_chain(5);
    assert!(l.open_approval(d_idx));
    l.non_conflict.raise_floor(6);
    let evals = counted(&SUBGROUP_EVALS);
    assert_eq!(
        intake(&mut l, &support_by(2, 5, 6, d.view().hash())),
        ReceiveSupportOutcome::Rejected,
        "node 2 is outside A at p − 1"
    );
    assert_eq!(counted(&SUBGROUP_EVALS) - evals, 1, "(iv-b) ran");
}

/// Code review P2 — the sibling branch is applied only when its vote
/// header matches the `p − 1` state: `d` claims consumed votes its creator
/// never held, so `undo_block` could not restore the engine; the builder
/// refuses and the engine is byte-identical.
#[test]
fn a_sibling_branch_with_a_wrong_vote_header_is_not_applied() {
    let (g, mut l, blocks) = support_chain(2);
    let top = g.vote_engine.top_creator().expect("a top");
    let snapshot = |n| vote_snapshot(g.vote_engine.accumulated_vote_of(n));
    let template = tx_block(6, blocks[5].view().hash(), 0, votes_for(6, 0, 1, 1));
    let d = reheader(
        &template,
        2,
        snapshot(2) + 77,
        top,
        snapshot(top) + 77,
        key_of(2),
    );
    // `y` first: `d` arrives as a side block, which no Tier 3 judges.
    let y = deviation_after(&g, &blocks[5], 5, 4);
    assert_eq!(receive(&mut l, &y), ReceiveBlockOutcome::AcceptedSilently);
    assert_eq!(receive(&mut l, &d), ReceiveBlockOutcome::AcceptedSilently);
    assert_eq!(head_of(&l), (6, y.view().hash()), "d is a held sibling");
    let d_idx = l.blocks.find(6, &d.view().hash()).expect("d");
    accumulate(&mut l, &d, d_idx, 2);
    let before = engine_votes(&l);
    assert!(l.build_evidence_block(d_idx, 0).is_none());
    assert_eq!(engine_votes(&l), before);
    assert!(l.is_ready());
}

/// Code review (tests) — DEC-256 on a real evidence block: framed, it
/// passes Tier 1; one byte after it, it is malformed.
#[test]
fn tier1_refuses_a_framed_evidence_with_a_byte_after_it() {
    let e = node_four_evidence();
    let (_, l, _) = support_chain(3);
    let gate = |view: &BlockView| {
        tier1_gate(
            view,
            &l.node_zero_public_key,
            MAX_BLOCK_SIZE as u32,
            UTXO_BITFIELD_WIDTH,
            &l.crypto,
        )
    };
    assert_eq!(gate(&e.view()), Ok(()));
    let n = e.len();
    let mut bytes = [0u8; MAX_BLOCK_SIZE];
    bytes[..n].copy_from_slice(e.serialized_bytes());
    let longer = BlockView::from_bytes(&bytes[..n + 1]).ok().expect("parses");
    assert_eq!(gate(&longer), Err(Tier1Failure::MalformedPayload));
}

// ---- Story 6.6 code review (tests): the remaining branches ----

/// An evidence block at 8 for proposer 2's deviation at 7 (the DEC-216
/// fixture): it names sequence 7.
fn evidence_naming_seven() -> Block {
    let (mut g, mut l, blocks) = support_chain(2);
    let template = tx_block(6, blocks[5].view().hash(), 0, votes_for(6, 2, 1, 600));
    let a6 = real_on(&g, &template, 3, key_of(3));
    assert_eq!(receive(&mut g, &a6), ReceiveBlockOutcome::AcceptedSilently);
    assert_eq!(receive(&mut l, &a6), ReceiveBlockOutcome::AcceptedSilently);
    let d = deviation_after(&g, &a6, 2, 1);
    assert_eq!(receive(&mut l, &d), ReceiveBlockOutcome::AcceptedSilently);
    let d_idx = l.blocks.find(7, &d.view().hash()).expect("d");
    accumulate(&mut l, &d, d_idx, 2);
    l.build_evidence_block(d_idx, 0).expect("evidence")
}

/// ADR-015 with a `required_support`: the `m` smallest node values.
fn expected_members_rs(p: u32, proposer: u32, a_prime: &[u32], rs: u8) -> std::vec::Vec<u32> {
    let seed = subgroup_seed(p, CIRCULATING_CURRENCY_STUB, proposer);
    let mut ids: std::vec::Vec<u32> = a_prime.to_vec();
    ids.sort_by_key(|&n| node_value(&seed, n));
    let m = subgroup_size(rs, a_prime.len() as u32).expect("A' not empty") as usize;
    ids.truncate(m);
    ids
}

/// AC9 test 1 — the sibling shape: the active block at `p` is the
/// proposer's own twin, not another proposer's deviation.
#[test]
fn open_refuses_a_twin_as_the_sibling() {
    let (g, mut l, blocks) = support_chain(2);
    let twin = deviation_after(&g, &blocks[5], 2, 9);
    let d = deviation_after(&g, &blocks[5], 2, 1);
    assert_eq!(
        receive(&mut l, &twin),
        ReceiveBlockOutcome::AcceptedSilently
    );
    assert_eq!(receive(&mut l, &d), ReceiveBlockOutcome::AcceptedSilently);
    let (head, d_hash) = (head_of(&l).1, d.view().hash());
    let (active, side) = if head == d_hash {
        (&d, &twin)
    } else {
        (&twin, &d)
    };
    assert_eq!(head, active.view().hash());
    let idx = l.blocks.find(6, &side.view().hash()).expect("held");
    assert_refused(
        &mut l,
        idx,
        "the active block at p is the proposer's own twin",
    );
}

/// AC9 test 1 — `m < |A'|`: with `required_support = 1`, `r_eff = m = 1`
/// of `A' = {0, 3, 4}`, so the bounded insertion evicts; one support
/// completes it, and the evidence carries one signer.
#[test]
fn the_subgroup_keeps_the_m_smallest_node_values() {
    let (g, mut l, blocks) = support_chain_on(5, local_storage(5), 16, |c| {
        c.add_literal(parameter::REQUIRED_SUPPORT, &[1u8])
            .ok()
            .expect("a one-byte literal");
    });
    let d = deviation_after(&g, &blocks[5], 5, 1);
    assert_eq!(receive(&mut l, &d), ReceiveBlockOutcome::AcceptedSilently);
    let d_idx = l.blocks.find(6, &d.view().hash()).expect("d");
    assert!(l.open_approval(d_idx));
    let expected = expected_members_rs(6, 5, &[0, 3, 4], 1);
    assert_eq!(expected.len(), 1);
    assert_eq!(l.approval.members(), &expected[..]);
    assert_eq!(l.approval.counts(), (1, 1, 0));
    let other = *[0u32, 3, 4]
        .iter()
        .find(|&&n| n != expected[0])
        .expect("a non-member");
    let h = d.view().hash();
    assert_eq!(
        intake(&mut l, &support_by(other, 5, 6, h)),
        ReceiveSupportOutcome::Rejected
    );
    assert_eq!(
        intake(&mut l, &support_by(expected[0], 5, 6, h)),
        ReceiveSupportOutcome::Accepted
    );
    let e = l
        .build_evidence_block(d_idx, 0)
        .expect("one signer completes it");
    let ev = evidence_of(&e, 1);
    assert_eq!((ev.m, ev.bitmap.as_slice()), (1, &[0b1][..]));
}

/// AC9 test 3 — DEC-200: a heavier approval-less sibling arriving after
/// the open demotes `d`, and the accumulator lives on.
#[test]
fn a_heavier_sibling_after_the_open_keeps_the_accumulator() {
    let (g, mut l, blocks) = support_chain(2);
    let d = deviation_after(&g, &blocks[5], 2, 1);
    assert_eq!(receive(&mut l, &d), ReceiveBlockOutcome::AcceptedSilently);
    let d_idx = l.blocks.find(6, &d.view().hash()).expect("d");
    assert!(l.open_approval(d_idx));
    let y = deviation_after(&g, &blocks[5], 5, 4);
    assert_eq!(receive(&mut l, &y), ReceiveBlockOutcome::AcceptedSilently);
    assert_eq!(head_of(&l), (6, y.view().hash()), "demoted by FR22");
    assert!(l.approval_live());
    assert_eq!(l.approval.deviation(), Some((6, &d.view().hash())));
}

/// AC4 — the FR5 recovery clears the accumulator.
#[test]
fn the_fr5_recovery_clears_the_accumulator() {
    let (_, mut l, _, _, d_idx) = proposer_chain(5);
    assert!(l.open_approval(d_idx));
    l.lifecycle_phase = LifecyclePhase::Processing;
    l.recover_from_failed_pass(ProcessingError::StorageRead, NONE_REF);
    assert!(l.approval.deviation().is_none());
}

/// AC5 / AC6 — before a deferred verification the read half runs: a
/// validated evidence at `p` clears the accumulator at the intake, and
/// the support is a plain relay.
#[test]
fn a_deferred_support_after_a_validated_evidence_clears_it() {
    let evidence = node_four_evidence();
    let (_, mut l, _, d, d_idx, _) = sibling_proposer();
    assert!(l.open_approval(d_idx));
    plant_on_chain(&mut l, &evidence, true);
    let member = *l
        .approval
        .members()
        .iter()
        .find(|&&n| n != 0)
        .expect("a member");
    assert_eq!(
        intake(&mut l, &support_by(member, 2, 6, d.view().hash())),
        ReceiveSupportOutcome::Accepted
    );
    assert!(l.approval.deviation().is_none());
    assert_eq!(held(&l), 0);
}

/// AC6 — local I/O never discards: `d`'s header unreadable leaves the
/// evidence half alone; a `u`-candidate whose read fails does not count;
/// an evidence naming another sequence does not stop.
#[test]
fn local_read_failures_and_other_sequences_never_discard() {
    let evidence = node_four_evidence();
    let (mut l, d_idx, _) = failing_proposer();
    l.storage.failing_slot = d_idx;
    assert!(
        l.approval_live(),
        "d unreadable: only the evidence half runs"
    );
    plant_on_chain(&mut l, &evidence, true);
    assert!(
        !l.approval_live(),
        "which still stops at an active evidence"
    );

    let (_, mut l, blocks, d, d_idx) = proposer_chain(5);
    assert!(l.open_approval(d_idx));
    let parent = l.blocks.get(d_idx).expect("d").parent_ref();
    let u = u_block(&blocks, &[&d]);
    plant_child(&mut l, &u, parent, true, false);
    assert!(
        l.approval_live(),
        "an unreadable u-candidate does not count"
    );
    let (_, mut l, blocks, d, d_idx) = proposer_chain(5);
    assert!(l.open_approval(d_idx));
    let parent = l.blocks.get(d_idx).expect("d").parent_ref();
    let u = u_block(&blocks, &[&d]);
    plant_child(&mut l, &u, parent, true, true);
    assert!(!l.approval_live(), "the control: a readable one does");

    let seven = evidence_naming_seven();
    let (_, mut l, _, _, d_idx) = proposer_chain(5);
    assert!(l.open_approval(d_idx));
    plant_on_chain(&mut l, &seven, true);
    assert!(l.approval_live(), "evidence for the deviation at 7, not 6");
}

/// AC7 — the builder refuses: a validated `u`-block at `p` although the
/// package is complete; a tip off `d`'s branch. A foreign creator above
/// `d` no longer reaches the builder: it is refused at intake (Story 6.7
/// D4, rule 1), and the builder then builds on `d` (converted).
#[test]
fn the_builder_refuses_a_resolved_or_off_branch_tip() {
    let (_, mut l, blocks, d, d_idx) = proposer_chain(5);
    accumulate(&mut l, &d, d_idx, 2);
    let u = u_block(&blocks, &[&d]);
    assert_eq!(receive(&mut l, &u), ReceiveBlockOutcome::AcceptedSilently);
    assert!(l.build_evidence_block(d_idx, 0).is_none(), "resolved at p");

    let (_, mut l, _, d, d_idx, y) = sibling_proposer();
    accumulate(&mut l, &d, d_idx, 2);
    let y_idx = l.blocks.find(6, &y.view().hash()).expect("y");
    let parent = l.blocks.get(d_idx).expect("d").parent_ref();
    assert!(l.build_evidence_block(y_idx, 0).is_none(), "y's branch");
    assert!(l.build_evidence_block(parent, 0).is_none(), "below p");
    assert!(l.build_evidence_block(d_idx, 0).is_some(), "the control");

    let (mut g, mut l, _, d, d_idx) = proposer_chain(5);
    accumulate(&mut l, &d, d_idx, 2);
    assert_eq!(receive(&mut g, &d), ReceiveBlockOutcome::AcceptedSilently);
    let foreign = normal_after(&g, &d, 3, 2);
    assert_eq!(
        step_reason(&mut l, &foreign),
        Some(ValidationReason::RunCreator)
    );
    assert_eq!(
        receive(&mut l, &foreign),
        ReceiveBlockOutcome::Rejected(RejectReason::InvalidEvidence)
    );
    let before = engine_votes(&l);
    let head = l.active_chain_head_idx;
    assert_eq!(head, d_idx, "the head stays d");
    assert!(
        l.build_evidence_block(head, 0).is_some(),
        "the proposer's own branch"
    );
    assert_eq!(engine_votes(&l), before);
    assert!(l.is_ready());
}

/// The DEC-200 sibling case with branches longer than one block: the
/// active `y@6, y7` (node 5) and the proposer's held `d@6, d7` (node 2).
/// Returns the proposer, complete, with `d`'s and `d7`'s slots.
fn long_sibling<S: StorageTrait>(storage: S) -> (Chain16<S>, Block, u32, u32) {
    let (mut g, mut l, blocks) = support_chain_on(2, storage, 16, |_| {});
    let (mut gy, _, _) = support_chain(2);
    let y = deviation_after(&g, &blocks[5], 5, 4);
    assert_eq!(receive(&mut gy, &y), ReceiveBlockOutcome::AcceptedSilently);
    let y7 = normal_after(&gy, &y, 5, 5);
    let d = deviation_after(&g, &blocks[5], 2, 1);
    assert_eq!(receive(&mut g, &d), ReceiveBlockOutcome::AcceptedSilently);
    let d7 = normal_after(&g, &d, 2, 2);
    for block in [&y, &y7, &d, &d7] {
        assert_eq!(
            receive(&mut l, block),
            ReceiveBlockOutcome::AcceptedSilently
        );
    }
    assert_eq!(head_of(&l), (7, y7.view().hash()), "y's branch is active");
    let d_idx = l.blocks.find(6, &d.view().hash()).expect("d");
    let d7_idx = l.blocks.find(7, &d7.view().hash()).expect("d7");
    accumulate(&mut l, &d, d_idx, 2);
    (l, d7, d_idx, d7_idx)
}

/// AC9 tests 5 / 8b — a sibling branch of two blocks: the evidence on
/// `d7` equals the direct case's; a failure applying `d7` (after `d`)
/// undoes `d` and restores; a failure undoing `d7` re-enters collecting.
#[test]
fn a_longer_sibling_branch_builds_and_restores() {
    let (mut l, d7, _, d7_idx) = long_sibling(local_storage(2));
    let before = engine_votes(&l);
    let e = l.build_evidence_block(d7_idx, 0).expect("evidence on d7");
    assert_eq!(engine_votes(&l), before);
    let (_, mut direct, _, d, d_idx) = proposer_chain(2);
    assert_eq!(
        receive(&mut direct, &d7),
        ReceiveBlockOutcome::AcceptedSilently
    );
    accumulate(&mut direct, &d, d_idx, 2);
    let tip = direct.active_chain_head_idx;
    let expected = direct.build_evidence_block(tip, 0).expect("direct");
    assert_eq!(e.serialized_bytes(), expected.serialized_bytes());

    let (mut l, _, _, d7_idx) = long_sibling(failing_storage(2));
    let before = engine_votes(&l);
    l.storage.failing_slot = d7_idx;
    assert!(l.build_evidence_block(d7_idx, 0).is_none());
    assert_eq!(l.storage.attempts.get(), 1, "the application of d7");
    assert_eq!(engine_votes(&l), before);
    assert!(l.is_ready());

    let (mut l, _, _, d7_idx) = long_sibling(failing_storage(2));
    l.storage.failing_slot = d7_idx;
    l.storage.reads_left.set(1);
    assert!(l.build_evidence_block(d7_idx, 0).is_none());
    // The second read (the undo) fails; the re-entry reads it again, and
    // its spine may reach Ready again in the same call (DEC-205), so the
    // re-entry shows in the cleared accumulator.
    assert!(l.storage.attempts.get() >= 2, "the undo of d7");
    assert!(l.approval.deviation().is_none(), "re-entered collecting");
}

/// AC9 test 8b — a block above `p − 1` not held: refused before any vote
/// step, the engine untouched.
#[test]
fn a_missing_block_above_the_parent_refuses_up_front() {
    let (mut g, mut l, blocks) = support_chain_on(5, failing_storage(5), 16, |_| {});
    let d = deviation_after(&g, &blocks[5], 5, 1);
    assert_eq!(receive(&mut g, &d), ReceiveBlockOutcome::AcceptedSilently);
    let d7 = normal_after(&g, &d, 5, 2);
    assert_eq!(receive(&mut g, &d7), ReceiveBlockOutcome::AcceptedSilently);
    let d8 = normal_after(&g, &d7, 5, 3);
    for block in [&d, &d7, &d8] {
        assert_eq!(
            receive(&mut l, block),
            ReceiveBlockOutcome::AcceptedSilently
        );
    }
    let d_idx = l.blocks.find(6, &d.view().hash()).expect("d");
    accumulate(&mut l, &d, d_idx, 2);
    let d7_idx = l.blocks.find(7, &d7.view().hash()).expect("d7");
    l.blocks.delete(d7_idx);
    let (before, reads) = (engine_votes(&l), l.storage.reads.get());
    let head = l.active_chain_head_idx;
    assert!(l.build_evidence_block(head, 0).is_none());
    assert_eq!(engine_votes(&l), before);
    assert_eq!(l.storage.reads.get() - reads, 1, "the header read only");
}
