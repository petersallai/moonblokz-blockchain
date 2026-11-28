//! Story 6.13 — the twin fact block (payload type 5): its Tier-1 and Tier-3
//! checks (I-43), the run it opens, the twin round's support, the FR72 credit
//! drop and an approval's exception to the FR70 hold (DEC-276..282).
//!
//! The world is [`two_creator_chain`]: node #1's `a3` on node #0's `a2` is
//! active, and node #1's sibling `y` of `a3` is its twin. In the window ending
//! at the twins' parent `a2` only node #0 created blocks, so the round's
//! voting set `A` at `P` without `c = 1` is `{0}`: `m = 1`, the subgroup
//! `[0]`. That is the independent oracle the round-opening blocks carry.

use super::fixtures::*;
use super::*;
use crate::api::fact::CreditDrop;
use crate::approval::{
    NonConflictRing, RING_KIND_TWIN, node_value, subgroup_size, support_message_bytes, twin_seed,
};
use crate::staged_validation::tier1_gate;
use moonblokz_chain_types::{calculate_hash, twin_fact_size};

/// Node #1's sibling of `a3` on `a2`, worth more (6.12's twin of `a3`).
fn twin_y(a2: &Block) -> Block {
    alt(3, a2.view().hash(), 1, 1, 3, 40, false)
}

/// A twin fact block at `seq` on `prev` by `creator` (signed with `[key; 32]`),
/// worth `consumed`, proving `proof` with `snapshot` and `members`; a
/// round-opening one carries round 0.
#[allow(clippy::too_many_arguments)]
fn fact_with(
    seq: u32,
    prev: [u8; 32],
    creator: u32,
    key: u8,
    consumed: u32,
    proof: &Block,
    snapshot: u32,
    members: &[u32],
) -> Block {
    fact_round(
        seq, prev, creator, key, consumed, proof, snapshot, 0, members,
    )
}

/// [`fact_with`] carrying round `j` (written only when `members` is not
/// empty, as the layout has it).
#[allow(clippy::too_many_arguments)]
fn fact_round(
    seq: u32,
    prev: [u8; 32],
    creator: u32,
    key: u8,
    consumed: u32,
    proof: &Block,
    snapshot: u32,
    j: u32,
    members: &[u32],
) -> Block {
    let signer = Crypto::new([key; PRIVATE_KEY_SIZE]).ok().expect("test key");
    let mut builder = BlockBuilder::new().header(BlockHeader {
        version: 1,
        sequence: seq,
        creator,
        mined_amount: 0,
        payload_type: 0,
        consumed_votes: consumed,
        first_voted_node: creator,
        consumed_votes_from_first_voted_node: 0,
        previous_hash: prev,
        signature: [0u8; SIGNATURE_SIZE],
    });
    let payload = builder
        .twin_fact_payload_mut(twin_fact_size(members.len()))
        .ok()
        .expect("fits");
    let view = proof.view();
    payload[..HEADER_SIZE].copy_from_slice(&view.serialized_bytes()[..HEADER_SIZE]);
    payload[HEADER_SIZE..HEADER_SIZE + 32].copy_from_slice(&calculate_hash(view.payload()));
    payload[HEADER_SIZE + 32..HEADER_SIZE + 36].copy_from_slice(&snapshot.to_le_bytes());
    payload[HEADER_SIZE + 36] = u8::try_from(members.len()).expect("m");
    if !members.is_empty() {
        payload[HEADER_SIZE + 37..HEADER_SIZE + 41].copy_from_slice(&j.to_le_bytes());
    }
    for (i, member) in members.iter().enumerate() {
        let at = HEADER_SIZE + 41 + 4 * i;
        payload[at..at + 4].copy_from_slice(&member.to_le_bytes());
    }
    builder.build_signed(&signer).ok().expect("signs")
}

/// The fact block proving `proof` on `head`, with the real header of `bc`'s
/// top creator and the real snapshot of `proof`'s creator: `bc` stands at
/// `head`.
fn fact_on<S: StorageTrait>(
    bc: &Chain16<S>,
    head: &Block,
    proof: &Block,
    members: &[u32],
) -> Block {
    fact_at(
        bc,
        head.view().sequence(),
        head.view().hash(),
        proof,
        members,
    )
}

/// [`fact_on`] over a head given by its sequence and hash.
fn fact_at<S: StorageTrait>(
    bc: &Chain16<S>,
    head_seq: u32,
    head_hash: [u8; 32],
    proof: &Block,
    members: &[u32],
) -> Block {
    let creator = bc.vote_engine.top_creator().expect("a top");
    let engine = &bc.vote_engine;
    fact_with(
        head_seq + 1,
        head_hash,
        creator,
        key_of(creator),
        vote_snapshot(engine.accumulated_vote_of(creator)),
        proof,
        vote_snapshot(engine.accumulated_vote_of(proof.view().creator())),
        members,
    )
}

/// The per-block step's verdict on `block` as a direct extension of `bc`'s
/// head, the I-43 check included, on a scratch entry removed again.
fn fact_reason<S: StorageTrait>(bc: &mut Chain16<S>, block: &Block) -> Option<ValidationReason> {
    let view = block.view();
    let idx = bc.blocks.next_free_index().expect("a free slot");
    let head = bc.active_chain_head_idx;
    let head_hash = *bc.blocks.get(head).expect("head").hash();
    let mut entry = BlockEntry::new(view.hash(), head, view.sequence());
    entry.set_payload(&view);
    bc.blocks.insert_at(idx, entry);
    let mut projection = Projection {
        counter_tail: bc.physical_counter_tail(),
        ..Projection::COMPLETE
    };
    let verdict = bc
        .derive_block(&view, idx, Some(head_hash), &mut projection)
        .and_then(|_| bc.judge_evidence_step(&view, idx, &projection));
    bc.blocks.delete(idx);
    match verdict {
        Ok(()) => None,
        Err(ProcessingError::Invalid { reason, .. }) => Some(reason),
        Err(other) => panic!("not a validation failure: {other:?}"),
    }
}

/// [`two_creator_chain`] with `y` admitted (held: a twin of `a3`).
fn twin_chain() -> (TestChain, Block, Block, Block) {
    let (mut bc, _, a2, a3) = two_creator_chain();
    let y = twin_y(&a2);
    assert_eq!(receive(&mut bc, &y), ReceiveBlockOutcome::AcceptedSilently);
    assert_eq!(head_of(&bc), (3, a3.view().hash()), "y is held");
    (bc, a2, a3, y)
}

/// Room for a chain past `s + W` (32 slots).
type LongStorage = MemoryBackend<{ 32 * MAX_BLOCK_SIZE + 8000 }>;

/// [`two_creator_chain`] over [`LongStorage`], extended to `last` with
/// creators alternating (#0 at even sequences), each block crediting the
/// next creator once; `y` is not admitted. Each block carries its creator's
/// real vote, so the DEC-178 liveness credit, due from `s = H`, is in it.
/// Returns the chain, `a2`, and the head's hash.
fn long_chain(last: u32) -> (Chain16<LongStorage>, Block, [u8; 32]) {
    let mut storage = LongStorage::new();
    storage
        .init([1u8; PRIVATE_KEY_SIZE], 0, [0u8; INIT_PARAMS_SIZE])
        .ok()
        .expect("the test backend initializes");
    let mut bc = local_node(0, storage);
    let genesis = bc
        .process_genesis(CURRENCY, window_config_builder(16).content())
        .ok()
        .expect("genesis succeeds");
    let a2 = alt(2, genesis.block_one.view().hash(), 0, 0, 1, 7, true);
    let a3 = alt(3, a2.view().hash(), 1, 1, 0, 8, false);
    for block in [&a2, &a3] {
        assert_eq!(
            receive(&mut bc, block),
            ReceiveBlockOutcome::AcceptedSilently
        );
    }
    let mut prev = a3.view().hash();
    for seq in 4..=last {
        let creator = u32::from(seq % 2 == 1);
        let received = u32::from(seq != 4);
        let block = alt(seq, prev, creator, received, 1, 100 + u64::from(seq), false);
        let key = if creator == 0 { 1 } else { NODE_ONE_KEY };
        let block = real_on(&bc, &block, creator, key);
        assert_eq!(
            receive(&mut bc, &block),
            ReceiveBlockOutcome::AcceptedSilently,
            "seq {seq}"
        );
        prev = block.view().hash();
    }
    assert_eq!(head_of(&bc), (last, prev));
    (bc, a2, prev)
}

/// An approval evidence block at `seq` on `prev` closing the run opened at
/// `p`, by node #0 under the run header, claiming `vote_sum`, signed by the
/// one-member subgroup `[0]` over `hash(opener)` (or junk).
fn approval_on(
    seq: u32,
    prev: [u8; 32],
    p: u32,
    opener: &Block,
    vote_sum: u64,
    junk: bool,
) -> Block {
    approval_over(seq, prev, p, opener.view().hash(), vote_sum, junk)
}

/// [`approval_on`] whose subgroup signed `signed` as the opener's hash.
fn approval_over(
    seq: u32,
    prev: [u8; 32],
    p: u32,
    signed: [u8; 32],
    vote_sum: u64,
    junk: bool,
) -> Block {
    let mut aggregate = {
        let message = support_message_bytes(0, p, &signed);
        let node_zero = Crypto::new([key_of(0); PRIVATE_KEY_SIZE])
            .ok()
            .expect("key");
        let signature = node_zero.multi_sign(&message);
        let key = *node_zero.public_key().serialize();
        let aggregate = test_crypto()
            .aggregate_signatures(&[&signature], &[&key], &message)
            .ok()
            .expect("aggregates");
        let mut out =
            std::vec![0u8; AGGREGATED_SIGNATURE_CONSTANT_SIZE + AGGREGATED_SIGNATURE_VARIABLE_SIZE];
        let len = aggregate.serialize(&mut out).ok().expect("serializes");
        out.truncate(len);
        out
    };
    if junk {
        let last = aggregate.len() - 1;
        aggregate[last] ^= 0x01;
    }
    let len = APPROVAL_PREFIX_SIZE + 1 + aggregate.len() + 2;
    let signer = Crypto::new([key_of(0); PRIVATE_KEY_SIZE])
        .ok()
        .expect("key");
    let mut builder = BlockBuilder::new().header(BlockHeader {
        version: 1,
        sequence: seq,
        creator: 0,
        mined_amount: 0,
        payload_type: 0,
        consumed_votes: 0,
        first_voted_node: 0,
        consumed_votes_from_first_voted_node: 0,
        previous_hash: prev,
        signature: [0u8; SIGNATURE_SIZE],
    });
    let payload = builder.approval_payload_mut(len).ok().expect("fits");
    payload[..8].copy_from_slice(&vote_sum.to_le_bytes());
    payload[8..12].copy_from_slice(&p.to_le_bytes());
    payload[APPROVAL_M_OFFSET] = 1;
    payload[APPROVAL_PREFIX_SIZE] = 1;
    payload[APPROVAL_PREFIX_SIZE + 1..APPROVAL_PREFIX_SIZE + 1 + aggregate.len()]
        .copy_from_slice(&aggregate);
    builder.build_signed(&signer).ok().expect("signs")
}

// --- AC1 / AC2: Tier 1 and the cache ---------------------------------------

#[test]
fn the_payload_type_cache_holds_types_one_to_five() {
    for payload_type in 1..=5 {
        let mut entry = BlockEntry::<TEST_UTXO_BYTES>::new([0; 32], NONE_REF, 7);
        entry.set_payload_type(payload_type);
        assert_eq!(entry.payload_type(), payload_type);
        // Only a type-5 entry names an equivocator (unstamped here: 0).
        assert_eq!(entry.equivocator_filter().is_some(), payload_type == 5);
    }
}

/// The type's high bit (bit 7) survives every other flag setter.
#[test]
fn the_high_type_bit_survives_the_other_flag_setters() {
    let mut entry = BlockEntry::<TEST_UTXO_BYTES>::new([0; 32], NONE_REF, 7);
    entry.set_payload_type(PAYLOAD_TYPE_TWIN_FACT);
    entry.set_signature_verified();
    entry.set_on_active_chain(true);
    entry.set_on_active_chain(false);
    entry.set_head_ref_count(3);
    entry.set_head_ref_count(0);
    entry.set_status(BlockStatus::Connected);
    entry.set_len(500);
    for bit in 0..TestChain::UTXO_BITFIELD_WIDTH as usize {
        entry.set_utxo_available(bit, true);
        entry.set_utxo_available(bit, false);
    }
    assert_eq!(entry.payload_type(), PAYLOAD_TYPE_TWIN_FACT);
    // And the low bits do not leak into it: type 1 after type 5.
    entry.set_payload_type(PAYLOAD_TYPE_TRANSACTION);
    assert_eq!(entry.payload_type(), PAYLOAD_TYPE_TRANSACTION);
}

#[test]
fn tier1_refuses_a_malformed_proof_or_repeated_members() {
    let (bc, a2, a3, y) = twin_chain();
    let gate = |block: &Block| {
        tier1_gate(
            &block.view(),
            &bc.node_zero_public_key,
            MAX_BLOCK_SIZE as u32,
            TestChain::UTXO_BITFIELD_WIDTH,
            None,
            &bc.crypto,
        )
    };
    assert_eq!(gate(&fact_on(&bc, &a3, &y, &[0])), Ok(()));
    assert_eq!(gate(&fact_on(&bc, &a3, &y, &[0, 1])), Ok(()), "distinct");
    assert_eq!(
        gate(&fact_on(&bc, &a3, &y, &[1, 1])),
        Err(Tier1Failure::MalformedPayload),
        "a repeated member"
    );
    // The proof's sequence must lie below the fact block's own.
    let same_height = fact_with(3, a2.view().hash(), 0, key_of(0), 0, &y, 0, &[0]);
    assert_eq!(gate(&same_height), Err(Tier1Failure::MalformedPayload));
    // A proof of a fact block is no twin proof.
    let inner = fact_on(&bc, &a3, &y, &[0]);
    let nested = fact_with(9, inner.view().hash(), 0, key_of(0), 0, &inner, 0, &[0]);
    assert_eq!(gate(&nested), Err(Tier1Failure::MalformedPayload));
}

// --- AC3: I-43 at Tier 3 ---------------------------------------------------

#[test]
fn a_round_opening_fact_block_is_accepted_supported_and_resets_the_equivocator() {
    let (mut bc, _, a3, y) = twin_chain();
    let e = fact_on(&bc, &a3, &y, &[0]);
    let ReceiveBlockOutcome::AcceptedAndSendSupport(support) = receive(&mut bc, &e) else {
        panic!("the local node, the round's only member, supports it");
    };
    assert_eq!(
        (
            support.supporter_node_id,
            support.proposer_node_id,
            support.deviation_sequence,
            support.deviation_block_hash
        ),
        (0, 0, 4, e.view().hash())
    );
    assert_eq!(head_of(&bc), (4, e.view().hash()));
    assert_eq!(bc.vote_engine.accumulated_vote_of(1), 0, "c's twin reset");
    // Intake: `c` is not in the carried subgroup `[0]`, so its support for
    // the round is refused (FR26 for a twin round, AC5).
    let hash = e.view().hash();
    assert_eq!(
        intake(&mut bc, &support_by(1, 0, 4, hash)),
        ReceiveSupportOutcome::Rejected
    );
    let entry = bc.blocks.get(slot(&bc, &e)).expect("held");
    assert_eq!(entry.payload_type(), PAYLOAD_TYPE_TWIN_FACT);
    assert_eq!(entry.equivocator_filter(), Some(1));
    assert!(bc.active_open_run != u32::MAX, "it opens a run");
}

#[test]
fn every_i43_rule_refuses_its_violation() {
    let (mut bc, a2, a3, y) = twin_chain();
    let good = fact_on(&bc, &a3, &y, &[0]);
    assert_eq!(fact_reason(&mut bc, &good), None);
    let top = bc.vote_engine.top_creator().expect("top");
    let valid = |proof: &Block, snapshot: u32, members: &[u32]| {
        fact_with(
            4,
            a3.view().hash(),
            top,
            key_of(top),
            0,
            proof,
            snapshot,
            members,
        )
    };
    // Rule 2: the proof is the branch's own block.
    assert_eq!(
        fact_reason(&mut bc, &valid(&a3, 0, &[0])),
        Some(ValidationReason::TwinFactProof)
    );
    // Rule 1: the branch's block at 3 is node #1's, the proof node #0's.
    let node_zero_on_a2 = alt(3, a2.view().hash(), 0, 0, 1, 50, false);
    assert_eq!(
        fact_reason(&mut bc, &valid(&node_zero_on_a2, 0, &[0])),
        Some(ValidationReason::TwinFactProof)
    );
    // Rule 1: node #1's block at 3 on another parent is no twin of `a3`.
    let off_parent = alt(3, [0x5A; 32], 1, 1, 3, 40, false);
    assert_eq!(
        fact_reason(&mut bc, &valid(&off_parent, 0, &[0])),
        Some(ValidationReason::TwinFactProof)
    );
    // Rule 3: a proof whose signature does not verify.
    let mut bytes = std::vec::Vec::from(y.serialized_bytes());
    bytes[HEADER_SIZE - 1] ^= 0x01;
    let forged = Block::from_bytes(&bytes).ok().expect("parses");
    assert_eq!(
        fact_reason(&mut bc, &valid(&forged, 0, &[0])),
        Some(ValidationReason::TwinFactProof)
    );
    // Rule 5: penalty-only at `q ≤ s + H − 1`.
    assert_eq!(
        fact_reason(&mut bc, &valid(&y, 0, &[])),
        Some(ValidationReason::TwinFactKind)
    );
    // Rule 6: not the round's subgroup.
    assert_eq!(
        fact_reason(&mut bc, &valid(&y, 0, &[1])),
        Some(ValidationReason::TwinFactSubgroup)
    );
    // A list of the wrong size. That `c` is left out of `A` is pinned by
    // `the_round_excludes_the_equivocator_from_a`, where `c` in `A` would
    // change the subgroup at the same size.
    assert_eq!(
        fact_reason(&mut bc, &valid(&y, 0, &[0, 1])),
        Some(ValidationReason::TwinFactSubgroup),
        "the wrong size"
    );
    // Rule 7: the snapshot.
    assert_eq!(
        fact_reason(&mut bc, &valid(&y, 5, &[0])),
        Some(ValidationReason::TwinFactSnapshot)
    );
}

#[test]
fn one_fact_block_per_creator_and_sequence_in_the_window() {
    let (mut bc, _, a3, y) = twin_chain();
    let e = fact_on(&bc, &a3, &y, &[0]);
    assert!(matches!(
        receive(&mut bc, &e),
        ReceiveBlockOutcome::AcceptedAndSendSupport(_)
    ));
    let head = slot(&bc, &e);
    assert_eq!(bc.fact_unique(head, 16, 1, 3), Ok(false), "(1, 3) is taken");
    assert_eq!(bc.fact_unique(head, 16, 1, 2), Ok(true));
    assert_eq!(bc.fact_unique(head, 16, 0, 3), Ok(true));
}

/// A late twin (FR70): `y` arrives when the head is 10, so a fact block at
/// `q = 11 = s + H` is penalty-only. A round-opening one there is refused
/// (rule 5); the penalty-only one is accepted, gathers no support, opens no
/// run and drops `c`'s credits for `H` blocks.
#[test]
fn a_late_twin_gets_a_penalty_only_fact_block() {
    let (mut bc, a2, head) = long_chain(10);
    let y = twin_y(&a2);
    assert_eq!(receive(&mut bc, &y), ReceiveBlockOutcome::AcceptedSilently);
    assert_eq!(head_of(&bc), (10, head), "y is held");
    let opening = fact_at(&bc, 10, head, &y, &[0]);
    assert_eq!(
        fact_reason(&mut bc, &opening),
        Some(ValidationReason::TwinFactKind),
        "q > s + H − 1 opens no round"
    );
    let penalty = fact_at(&bc, 10, head, &y, &[]);
    assert_eq!(fact_reason(&mut bc, &penalty), None);
    assert_eq!(
        receive(&mut bc, &penalty),
        ReceiveBlockOutcome::AcceptedSilently,
        "no round, no support"
    );
    assert_eq!(head_of(&bc), (11, penalty.view().hash()));
    assert_eq!(bc.active_open_run, u32::MAX, "no run");
    let idx = slot(&bc, &penalty);
    assert_eq!(
        bc.blocks.get(idx).expect("held").equivocator_filter(),
        Some(1)
    );
    let drop = CreditDrop::<_, TEST_MAX_BLOCKS, 16, TEST_UTXO_BYTES>::new(
        &bc.blocks,
        &bc.storage,
        idx,
        Some(8),
    );
    assert!(drop.excluded(1) && !drop.excluded(0));
}

/// I-43 rule 4a: a fact block at `q ≥ s + W` is refused, whatever it carries.
/// A chain past `s + W` needs balance snapshots before the genesis leaves the
/// window, so the rule (pure arithmetic, checked first) is judged on a
/// scratch entry at `q` over the real tip.
#[test]
fn a_fact_block_past_the_window_is_refused() {
    let (mut bc, _, a3, y) = twin_chain();
    let judge = |bc: &mut TestChain, q: u32| {
        let block = fact_with(q, a3.view().hash(), 0, key_of(0), 0, &y, 0, &[]);
        let view = block.view();
        let idx = bc.blocks.next_free_index().expect("a free slot");
        let mut entry = BlockEntry::new(view.hash(), slot(bc, &a3), q);
        entry.set_payload(&view);
        bc.blocks.insert_at(idx, entry);
        let verdict = bc.judge_twin_fact(&view, idx, &Projection::COMPLETE);
        bc.blocks.delete(idx);
        match verdict {
            Err(ProcessingError::Invalid { reason, .. }) => Some(reason),
            _ => None,
        }
    };
    // `s + W = 19`.
    assert_eq!(judge(&mut bc, 19), Some(ValidationReason::TwinFactWindow));
    assert_ne!(judge(&mut bc, 18), Some(ValidationReason::TwinFactWindow));
}

// --- AC4 / D8: the run, the slot -------------------------------------------

/// FR27 rule 4 on a run a fact block opened at `q = 4` (`H = 8`): a replay
/// ends at `q + H − 1 = 11`, the approval at `q + H = 12`.
#[test]
fn a_fact_run_is_bound_like_a_deviation_run() {
    use crate::api::evidence::run_rules;
    let (bc, _, a3, y) = twin_chain();
    let e = fact_on(&bc, &a3, &y, &[0]);
    let (run, h, bound) = (Some((4, 0)), Some(8), Err(ValidationReason::RunBound));
    let replay = |seq: u32| alt(seq, [0x5A; 32], 0, 0, 1, u64::from(seq), false);
    let approval = |seq: u32| approval_on(seq, [0x5A; 32], 4, &e, 0, false);
    assert_eq!(run_rules(&replay(11).view(), run, h), Ok(()));
    assert_eq!(run_rules(&replay(12).view(), run, h), bound);
    assert_eq!(run_rules(&approval(12).view(), run, h), Ok(()));
    assert_eq!(run_rules(&approval(13).view(), run, h), bound);
}

#[test]
fn a_round_opening_fact_block_opens_a_run_of_its_creator() {
    let (mut bc, _, a3, y) = twin_chain();
    let e = fact_on(&bc, &a3, &y, &[0]);
    receive(&mut bc, &e);
    // Node #1 above node #0's opener.
    let foreign = alt(5, e.view().hash(), 1, 0, 0, 77, false);
    assert_eq!(
        fact_reason(&mut bc, &foreign),
        Some(ValidationReason::RunCreator)
    );
    // A fact block inside the run.
    let inside = fact_with(5, e.view().hash(), 0, key_of(0), 0, &y, 0, &[0]);
    assert_eq!(
        fact_reason(&mut bc, &inside),
        Some(ValidationReason::EvidencePlacement)
    );
}

#[test]
fn a_fact_block_is_clean_at_a_slot() {
    let (bc, _, a3, y) = twin_chain();
    let e = fact_on(&bc, &a3, &y, &[0]);
    // H = 8: sequence 7 is a slot; the rule reads only the payload kind.
    let at_slot = fact_with(7, a3.view().hash(), 0, key_of(0), 0, &y, 0, &[0]);
    assert_eq!(
        crate::api::evidence::slot_rule(&at_slot.view(), Some(8)),
        Ok(())
    );
    assert_eq!(crate::api::evidence::slot_rule(&e.view(), Some(8)), Ok(()));
    assert!(crate::api::evidence::opens_run(&e.view()));
    let penalty_only = fact_with(7, a3.view().hash(), 0, key_of(0), 0, &y, 0, &[]);
    assert!(!crate::api::evidence::opens_run(&penalty_only.view()));
}

// --- AC5: the twin round's support -----------------------------------------

#[test]
fn a_twin_round_is_supported_once_per_round_and_keyed_by_its_index() {
    let mut ring = NonConflictRing::new();
    assert!(!ring.holds(RING_KIND_TWIN, 1, 3, 0));
    assert!(ring.insert(RING_KIND_TWIN, 1, 3, 0));
    assert!(ring.holds(RING_KIND_TWIN, 1, 3, 0));
    assert!(!ring.holds(RING_KIND_TWIN, 1, 3, 1), "another round");
    assert!(ring.insert(RING_KIND_TWIN, 1, 3, 1), "rounds coexist");
    assert!(ring.holds(RING_KIND_TWIN, 1, 3, 0));

    // A second admission of the round's opener emits nothing more.
    let (mut bc, _, a3, y) = twin_chain();
    let e = fact_on(&bc, &a3, &y, &[0]);
    receive(&mut bc, &e);
    let idx = slot(&bc, &e);
    assert!(
        bc.non_conflict.holds(RING_KIND_TWIN, 1, 3, 0),
        "the round's entry is (c, s, j)"
    );
    assert!(
        bc.evaluate_twin_support(idx, 0, 0).is_none(),
        "already supported"
    );
}

#[test]
fn a_node_on_the_other_twin_does_not_support_the_round() {
    // The opener on `y`'s branch is a side block for a node on `a3`.
    let (mut bc, _, _, y) = twin_chain();
    let top = 0;
    let e_y = fact_with(
        4,
        y.view().hash(),
        top,
        key_of(top),
        vote_snapshot(1000),
        &y,
        0,
        &[0],
    );
    assert_eq!(
        receive(&mut bc, &e_y),
        ReceiveBlockOutcome::AcceptedSilently
    );
    let idx = slot(&bc, &e_y);
    // Not for want of a signature, a membership or a ring entry: the parent
    // `y` is off the local active chain.
    assert_eq!(verified(&bc, &e_y), Some(true));
    assert!(!bc.non_conflict.holds(RING_KIND_TWIN, 1, 3, 0));
    assert!(bc.evaluate_twin_support(idx, 0, 0).is_none());
}

// --- AC6: the FR72 credit drop ---------------------------------------------

#[test]
fn credits_to_the_equivocator_are_dropped_inside_the_horizon() {
    let (mut bc, _, a3, y) = twin_chain();
    let e = fact_on(&bc, &a3, &y, &[0]);
    receive(&mut bc, &e);
    // Node #0's run block voting twice for node #1.
    let five = alt(5, e.view().hash(), 0, 0, 2, 31, false);
    assert_eq!(
        receive(&mut bc, &five),
        ReceiveBlockOutcome::AcceptedSilently
    );
    assert_eq!(head_of(&bc), (5, five.view().hash()));
    assert_eq!(bc.vote_engine.accumulated_vote_of(1), 0, "no credit");

    // Control: the same votes without a fact block are credited — once,
    // under the per-target cap (DEC-176).
    let (mut control, _, _, a3) = two_creator_chain();
    let four = alt(4, a3.view().hash(), 0, 0, 2, 31, false);
    assert_eq!(
        receive(&mut control, &four),
        ReceiveBlockOutcome::AcceptedSilently
    );
    assert_eq!(control.vote_engine.accumulated_vote_of(1), 1000);
}

/// The set reads exactly `[b − H, b − 1]`: a fact block `H` below the block
/// counts, one further down does not, whatever the window.
#[test]
fn the_credit_drop_reads_the_horizon_not_the_window() {
    let (mut bc, _, a3, y) = twin_chain();
    let e = fact_on(&bc, &a3, &y, &[0]);
    receive(&mut bc, &e);
    let e_idx = slot(&bc, &e);
    // A synthetic chain of plain entries above `e` (sequence 4).
    let mut parent = e_idx;
    let mut tips = std::vec::Vec::new();
    for seq in 5..=13u32 {
        let mut entry = BlockEntry::new([seq as u8; 32], parent, seq);
        entry.set_payload_type(PAYLOAD_TYPE_TRANSACTION);
        let idx = bc.blocks.next_free_index().expect("free");
        bc.blocks.insert_at(idx, entry);
        tips.push((seq, idx));
        parent = idx;
    }
    for (seq, idx) in tips {
        // The block above `idx` is `seq + 1`; it drops credits while `e`
        // (4) lies in `[seq + 1 − 8, seq]`.
        let expected = seq < 4 + 8; // b = seq + 1 ≤ e + H
        assert_eq!(
            CreditDrop::<_, TEST_MAX_BLOCKS, 16, TEST_UTXO_BYTES>::new(
                &bc.blocks,
                &bc.storage,
                idx,
                Some(8)
            )
            .excluded(1),
            expected,
            "b = {}",
            seq + 1
        );
        assert!(
            !CreditDrop::<_, TEST_MAX_BLOCKS, 16, TEST_UTXO_BYTES>::new(
                &bc.blocks,
                &bc.storage,
                idx,
                Some(8)
            )
            .excluded(0),
            "only c"
        );
    }
}

// --- AC7: the approval's exception to the hold -----------------------------

/// The other side's opener `e_y` on `y` (node #0, the top there with 1 000
/// from `y`'s three votes, one credit under DEC-176), proving `a3`.
fn opener_on_y(y: &Block, a3: &Block) -> Block {
    fact_with(
        4,
        y.view().hash(),
        0,
        key_of(0),
        vote_snapshot(1000),
        a3,
        0,
        &[0],
    )
}

#[test]
fn an_unapproved_round_on_the_other_twin_stays_held() {
    let (mut bc, _, a3, y) = twin_chain();
    let e_y = opener_on_y(&y, &a3);
    assert_eq!(
        receive(&mut bc, &e_y),
        ReceiveBlockOutcome::AcceptedSilently
    );
    let head = slot(&bc, &e_y);
    assert_eq!(
        bc.switch_target([Some(head), None]),
        Some(head),
        "it outranks"
    );
    assert_eq!(head_of(&bc), (3, a3.view().hash()), "held: no approval");
    let a3_idx = slot(&bc, &a3);
    assert!(!bc.approved_against(head, 3, a3_idx));
    assert!(status_of(&bc, &y).is_some());
}

#[test]
fn an_approved_round_on_the_other_twin_lifts_the_hold_and_switches() {
    let (mut bc, _, a3, y) = twin_chain();
    let e_y = opener_on_y(&y, &a3);
    receive(&mut bc, &e_y);
    let approval = approval_on(5, e_y.view().hash(), 4, &e_y, 1000, false);
    assert_eq!(
        receive(&mut bc, &approval),
        ReceiveBlockOutcome::AcceptedSilently
    );
    assert_eq!(
        head_of(&bc),
        (5, approval.view().hash()),
        "the approval lifted the hold and the replay accepted it"
    );
    assert_eq!(status_of(&bc, &a3), Some(BlockStatus::Connected));
}

#[test]
fn a_junk_approval_lifts_the_hold_once_and_is_deleted_on_the_replay() {
    let (mut bc, _, a3, y) = twin_chain();
    let e_y = opener_on_y(&y, &a3);
    receive(&mut bc, &e_y);
    let approval = approval_on(5, e_y.view().hash(), 4, &e_y, 1000, true);
    receive(&mut bc, &approval);
    assert_eq!(head_of(&bc), (3, a3.view().hash()), "restored");
    assert_eq!(status_of(&bc, &approval), None, "deleted as exact evidence");
    assert!(status_of(&bc, &e_y).is_some(), "the opener stays");
}

/// An approval whose aggregate signs another block's hash (`a3`, the twin the
/// round proves) is no approval of `e_y`: the replay deletes it as exact
/// evidence and the node returns to `a3`.
#[test]
fn an_approval_over_another_hash_is_deleted_on_the_replay() {
    let (mut bc, _, a3, y) = twin_chain();
    let e_y = opener_on_y(&y, &a3);
    receive(&mut bc, &e_y);
    let approval = approval_over(5, e_y.view().hash(), 4, a3.view().hash(), 1000, false);
    receive(&mut bc, &approval);
    assert_eq!(head_of(&bc), (3, a3.view().hash()), "restored");
    assert_eq!(status_of(&bc, &approval), None, "deleted as exact evidence");
}

// --- FR59 / FR63 -----------------------------------------------------------

#[test]
fn a_restart_restamps_the_fact_block() {
    let (mut bc, _, a3, y) = twin_chain();
    let e = fact_on(&bc, &a3, &y, &[0]);
    receive(&mut bc, &e);
    let mut bc = restart(bc);
    let (outcome, _) = bc.initialize_from_storage(0);
    assert_eq!(
        outcome,
        InitOutcome::ResumedReady,
        "the FR3 pass accepts the fact block"
    );
    let entry = bc
        .blocks
        .get(bc.blocks.find(4, &e.view().hash()).expect("rebuilt"))
        .expect("held");
    assert_eq!(entry.payload_type(), PAYLOAD_TYPE_TWIN_FACT);
    assert_eq!(entry.equivocator_filter(), Some(1));
}

/// AR16 (FR63): one stream — a twin, its round's opener, a run block with
/// votes for the equivocator — replayed twice gives equal outcomes, heads
/// and votes.
#[test]
fn twin_resolution_is_replay_deterministic() {
    let run = || {
        let (mut bc, _, a2, a3) = two_creator_chain();
        let y = twin_y(&a2);
        let mut outcomes = std::vec::Vec::new();
        outcomes.push(receive(&mut bc, &y));
        let e = fact_on(&bc, &a3, &y, &[0]);
        outcomes.push(receive(&mut bc, &e));
        let five = alt(5, e.view().hash(), 0, 0, 2, 31, false);
        outcomes.push(receive(&mut bc, &five));
        let votes: std::vec::Vec<u32> = (0..2)
            .map(|n| bc.vote_engine.accumulated_vote_of(n))
            .collect();
        (outcomes, head_of(&bc), votes, bc.active_branch_value)
    };
    assert_eq!(run(), run());
}

/// AR16 over the approved round and the penalty-only block: equal outcomes,
/// heads and votes on a replay.
#[test]
fn approval_and_penalty_streams_are_replay_deterministic() {
    let approved = || {
        let (mut bc, _, a3, y) = twin_chain();
        let e_y = opener_on_y(&y, &a3);
        let approval = approval_on(5, e_y.view().hash(), 4, &e_y, 1000, false);
        let outcomes = [receive(&mut bc, &e_y), receive(&mut bc, &approval)];
        let votes = [0, 1].map(|n| bc.vote_engine.accumulated_vote_of(n));
        (outcomes, head_of(&bc), votes, bc.active_branch_value)
    };
    assert_eq!(approved(), approved());
    let penalty = || {
        let (mut bc, a2, head) = long_chain(10);
        let y = twin_y(&a2);
        let fact = fact_at(&bc, 10, head, &y, &[]);
        let outcomes = [receive(&mut bc, &y), receive(&mut bc, &fact)];
        let votes = [0, 1].map(|n| bc.vote_engine.accumulated_vote_of(n));
        (outcomes, head_of(&bc), votes, bc.active_branch_value)
    };
    assert_eq!(penalty(), penalty());
}

/// T4 (c): the round's seed is bound to the opener's rank `j`. On the Story
/// 6.4 chain (`a3` node 1, `a4` node 4, `a5` node 3; node 1 on top) node #3
/// twins `a5` on `a4`. `A` at `a4` without node 3 is `{0, 1, 4}` (`m = 3`), so
/// the members' order depends on the seed. A retry by a node of rank `j ≥ 1`
/// must carry round `j`'s order, not round 0's.
#[test]
fn the_round_seed_is_bound_to_the_openers_rank() {
    let (_, mut l, [_, _, _, _, a4, a5]) = support_chain(0);
    let y = resign(
        &tx_block(5, a4.view().hash(), 0, votes_for(5, 2, 1, 9_999)),
        3,
        a5.view().consumed_votes(),
        key_of(3),
    );
    let engine = &l.vote_engine;
    let top = engine.top_creator().expect("top");
    assert_eq!(top, 1);
    // A retry opener: the node of rank `j`, a deviation naming the top.
    let (opener, j) = [0u32, 2, 4, 5]
        .into_iter()
        .map(|n| {
            (
                n,
                (0..6).filter(|&m| engine.ranks_above(m, n)).count() as u32,
            )
        })
        .find(|&(_, j)| j >= 1)
        .expect("a lower rank");
    let order = |j: u32| {
        let seed = twin_seed(5, 0, 3, j);
        let mut members = [0u32, 1, 4];
        members.sort_by_key(|&n| node_value(&seed, n));
        assert_eq!(subgroup_size(40, 3), Some(3));
        members
    };
    assert_ne!(order(0), order(j), "precondition: the rounds differ");
    let opener_block = |first_voted: u32, carried: u32, members: [u32; 3]| {
        let signer = Crypto::new([key_of(opener); PRIVATE_KEY_SIZE])
            .ok()
            .expect("key");
        let template = fact_round(
            6,
            a5.view().hash(),
            opener,
            key_of(opener),
            0,
            &y,
            0,
            carried,
            &members,
        );
        let view = template.view();
        let mut builder = BlockBuilder::new().header(BlockHeader {
            version: 1,
            sequence: 6,
            creator: opener,
            mined_amount: 0,
            payload_type: 0,
            consumed_votes: vote_snapshot(engine.accumulated_vote_of(opener)),
            first_voted_node: first_voted,
            consumed_votes_from_first_voted_node: if first_voted == opener {
                0
            } else {
                vote_snapshot(engine.accumulated_vote_of(first_voted))
            },
            previous_hash: a5.view().hash(),
            signature: [0u8; SIGNATURE_SIZE],
        });
        let mut payload = std::vec::Vec::from(view.payload());
        payload[HEADER_SIZE + 32..HEADER_SIZE + 36]
            .copy_from_slice(&vote_snapshot(engine.accumulated_vote_of(3)).to_le_bytes());
        builder
            .twin_fact_payload_mut(payload.len())
            .ok()
            .expect("fits")
            .copy_from_slice(&payload);
        builder.build_signed(&signer).ok().expect("signs")
    };
    let retry = |carried: u32, members: [u32; 3]| opener_block(top, carried, members);
    let right = retry(j, order(j));
    // Round 0's order under the right index, and round 0 claimed whole: the
    // carried `j` is the opener's rank (DN1), and the order is round `j`'s.
    let wrong = [(j, order(0)), (0, order(0)), (0, order(j))].map(|(c, m)| retry(c, m));
    // P2: the same round in normal form, by a node that is not the top.
    let normal = opener_block(opener, j, order(j));
    assert_eq!(fact_reason(&mut l, &right), None);
    assert_eq!(
        fact_reason(&mut l, &normal),
        Some(ValidationReason::TwinFactKind)
    );
    for block in &wrong {
        assert_eq!(
            fact_reason(&mut l, block),
            Some(ValidationReason::TwinFactSubgroup)
        );
    }
}

/// FR72: the fact block's snapshot carries the vote the equivocator banked
/// between its twin and the fact block, and undoing the block restores it. In
/// this two-node world the opener is the equivocator itself (the top), so its
/// creator reset and the twin reset coincide (AC6); the vote crate's own test
/// observes the twin reset alone.
#[test]
fn the_snapshot_restores_credits_banked_since_the_twin() {
    let (mut bc, _, a3, y) = twin_chain();
    // Node #0's block voting twice for node #1 (the equivocator).
    let b4 = alt(4, a3.view().hash(), 0, 0, 2, 61, false);
    assert_eq!(receive(&mut bc, &b4), ReceiveBlockOutcome::AcceptedSilently);
    let banked = bc.vote_engine.accumulated_vote_of(1);
    assert_eq!(banked, 1000, "two votes, one credit (DEC-176)");
    let e = fact_on(&bc, &b4, &y, &[0]);
    let snapshot = TwinFactView::from_payload(e.view().payload())
        .expect("frames")
        .snapshot();
    assert_eq!(snapshot, vote_snapshot(banked));
    assert!(matches!(
        receive(&mut bc, &e),
        ReceiveBlockOutcome::AcceptedAndSendSupport(_)
    ));
    assert_eq!(bc.vote_engine.accumulated_vote_of(1), 0, "the twin reset");
    // The inverse: undoing the fact block restores the banked credits.
    let bytes = std::vec::Vec::from(e.serialized_bytes());
    let parent = slot(&bc, &b4);
    let h = bc.verification_horizon();
    let drop = CreditDrop::<_, TEST_MAX_BLOCKS, 16, TEST_UTXO_BYTES>::new(
        &bc.blocks,
        &bc.storage,
        parent,
        h,
    );
    let view = BlockView::from_bytes(&bytes).ok().expect("parses");
    bc.vote_engine
        .undo_block(view, |node| drop.excluded(node), None, None)
        .expect("undoes");
    assert_eq!(bc.vote_engine.accumulated_vote_of(1), banked);
}

/// I-43 rule 4 end to end: once a round for `(1, 3)` is approved and its run
/// closed, a second fact block for `(1, 3)` in the window is refused.
#[test]
fn a_second_fact_block_for_one_conflict_is_refused() {
    let (mut bc, _, a3, y) = twin_chain();
    let e = fact_on(&bc, &a3, &y, &[0]);
    receive(&mut bc, &e);
    let approval = approval_on(5, e.view().hash(), 4, &e, 1000, false);
    assert_eq!(
        receive(&mut bc, &approval),
        ReceiveBlockOutcome::AcceptedSilently
    );
    assert_eq!(head_of(&bc), (5, approval.view().hash()), "the run closed");
    let again = fact_on(&bc, &approval, &y, &[0]);
    assert_eq!(
        fact_reason(&mut bc, &again),
        Some(ValidationReason::TwinFactWindow)
    );
}

/// T4 (c): `A` at `P` is taken without `c` even when `c` created blocks in
/// `P`'s window. On the Story 6.4 chain node #1 (`a3`) also creates `a6` and
/// twins it: `A` at `a5` is `{0, 1, 3, 4}`, the round's set `{0, 3, 4}` (`m =
/// 3`; with `c` it would be `m = 4`).
#[test]
fn the_round_excludes_the_equivocator_from_a() {
    let (_, mut l, [_, _, _, _, _, a5]) = support_chain(0);
    let a6 = real_on(
        &l,
        &tx_block(6, a5.view().hash(), 0, votes_for(6, 2, 1, 6_100)),
        1,
        key_of(1),
    );
    assert_eq!(receive(&mut l, &a6), ReceiveBlockOutcome::AcceptedSilently);
    let y6 = resign(
        &tx_block(6, a5.view().hash(), 0, votes_for(6, 4, 1, 6_200)),
        1,
        a6.view().consumed_votes(),
        key_of(1),
    );
    let seed = twin_seed(6, 0, 1, 0);
    let mut members = [0u32, 3, 4];
    members.sort_by_key(|&n| node_value(&seed, n));
    assert_eq!(subgroup_size(40, 3), Some(3));
    let e = fact_on(&l, &a6, &y6, &members);
    assert_eq!(fact_reason(&mut l, &e), None);
}

/// DEC-280 on a build whose node ids exceed 16 bits (`MAX_NODES = 70 000`,
/// the predicate's own parameter): a filter match is confirmed by reading the
/// fact block. The equivocator is node #1, so node 65 537 (low 16 bits 1)
/// matches the filter and is refused by the read; a failed read is a fault,
/// and `reads_hold` reports it before any engine step.
#[test]
fn a_wide_build_confirms_a_filter_match_by_reading_the_block() {
    let (mut bc, _, a3, y) = twin_chain();
    let e = fact_on(&bc, &a3, &y, &[0]);
    receive(&mut bc, &e);
    let e_idx = slot(&bc, &e);
    let mut parent = e_idx;
    for seq in 5..=6u32 {
        let mut entry = BlockEntry::new([seq as u8; 32], parent, seq);
        entry.set_payload_type(PAYLOAD_TYPE_TRANSACTION);
        let idx = bc.blocks.next_free_index().expect("free");
        bc.blocks.insert_at(idx, entry);
        parent = idx;
    }
    let wide = CreditDrop::<_, TEST_MAX_BLOCKS, 70_000, TEST_UTXO_BYTES>::new(
        &bc.blocks,
        &bc.storage,
        parent,
        Some(8),
    );
    assert!(wide.excluded(1), "the read confirms c = 1");
    assert!(
        !wide.excluded(65_537),
        "a 16-bit collision, refused by the read"
    );
    assert!(!wide.excluded(2));
    assert!(!wide.faulted());
    let narrow = CreditDrop::<_, TEST_MAX_BLOCKS, 16, TEST_UTXO_BYTES>::new(
        &bc.blocks,
        &bc.storage,
        parent,
        Some(8),
    );
    assert!(narrow.excluded(1), "the filter is the id");

    // A fact entry whose block cannot be read: the confirm read fails.
    let mut ghost = BlockEntry::new([0xEE; 32], parent, 7);
    ghost.set_payload(&e.view());
    let ghost_idx = bc.blocks.next_free_index().expect("free");
    bc.blocks.insert_at(ghost_idx, ghost);
    let faulty = CreditDrop::<_, TEST_MAX_BLOCKS, 70_000, TEST_UTXO_BYTES>::new(
        &bc.blocks,
        &bc.storage,
        ghost_idx,
        Some(8),
    );
    let five = alt(8, [0xEE; 32], 0, 0, 2, 31, false);
    assert!(
        !faulty.reads_hold(&five.view(), None),
        "the pre-check reports the fault"
    );
    assert!(faulty.faulted());
    let unread = CreditDrop::<_, TEST_MAX_BLOCKS, 70_000, TEST_UTXO_BYTES>::new(
        &bc.blocks,
        &bc.storage,
        ghost_idx,
        Some(8),
    );
    assert!(!unread.excluded(1), "a failed read answers not excluded");
    assert!(unread.faulted(), "and raises the fault");
}

// --- Code review: the patches' own pins ------------------------------------

/// `block` (a fact block) re-signed with `key` under a deviation header
/// naming `first_voted` with `recorded`: its payload unchanged.
fn as_deviation(block: &Block, first_voted: u32, recorded: u32, key: u8) -> Block {
    let view = block.view();
    let signer = Crypto::new([key; PRIVATE_KEY_SIZE]).ok().expect("key");
    let mut builder = BlockBuilder::new().header(BlockHeader {
        version: 1,
        sequence: view.sequence(),
        creator: view.creator(),
        mined_amount: 0,
        payload_type: 0,
        consumed_votes: view.consumed_votes(),
        first_voted_node: first_voted,
        consumed_votes_from_first_voted_node: recorded,
        previous_hash: view.previous_hash().try_into().expect("32 bytes"),
        signature: [0u8; SIGNATURE_SIZE],
    });
    builder
        .twin_fact_payload_mut(view.payload().len())
        .ok()
        .expect("fits")
        .copy_from_slice(view.payload());
    builder.build_signed(&signer).ok().expect("signs")
}

/// P1: a penalty-only fact block in deviation form (node #4 under the top,
/// at `q = 13 = s + H` on the Story 6.4 chain, `c = 3`, `s = 5`) is an
/// ordinary deviation: its supporters back it through the deviation's
/// intake, its proposer builds the approval over the deviation's subgroup,
/// and a validator accepts that approval.
#[test]
fn a_penalty_only_fact_block_in_deviation_form_is_an_ordinary_deviation() {
    // A node that is not the top at #13 (node #4 is, on the support chain
    // whose registrations vote for node #1, DEC-190).
    const K: u32 = 5;
    let (mut g, mut l, [_, _, _, _, a4, a5]) = support_chain(K);
    let y = resign(
        &tx_block(5, a4.view().hash(), 0, votes_for(5, 2, 1, 9_999)),
        3,
        a5.view().consumed_votes(),
        key_of(3),
    );
    let mut run: std::vec::Vec<Block> = std::vec::Vec::new();
    for seq in 6..=12u32 {
        let top = g.vote_engine.top_creator().expect("top");
        let block = normal_after(&g, run.last().unwrap_or(&a5), top, 600 + u64::from(seq));
        for node in [&mut g, &mut l] {
            assert_eq!(receive(node, &block), ReceiveBlockOutcome::AcceptedSilently);
        }
        run.push(block);
    }
    let prev = run.last().expect("12");
    let top = g.vote_engine.top_creator().expect("top");
    assert_ne!(top, K, "precondition: a deviation");
    let snapshot = |n| vote_snapshot(g.vote_engine.accumulated_vote_of(n));
    let normal = fact_with(
        13,
        prev.view().hash(),
        K,
        key_of(K),
        snapshot(K),
        &y,
        snapshot(3),
        &[],
    );
    let d = as_deviation(&normal, top, snapshot(top), key_of(K));
    assert_eq!(receive(&mut l, &d), ReceiveBlockOutcome::AcceptedSilently);
    assert_eq!(head_of(&l), (13, d.view().hash()));
    let d_idx = slot(&l, &d);
    assert!(l.open_approval(d_idx), "the deviation's accumulator opens");
    let members = l.approval.members().to_vec();
    let r_eff = members.len() / 2 + 1;
    for &member in &members[..r_eff] {
        assert_eq!(
            intake(&mut l, &support_by(member, K, 13, d.view().hash())),
            ReceiveSupportOutcome::Accepted,
            "member {member}: the deviation's intake"
        );
    }
    let e = l.build_evidence_block(d_idx, 0).expect("evidence");
    // A member, fed the same chain, supports `d` through the deviation's arm.
    let (_, mut v, _) = support_chain(members[0]);
    for block in &run {
        assert_eq!(
            receive(&mut v, block),
            ReceiveBlockOutcome::AcceptedSilently
        );
    }
    set_grace_admits(true);
    let support = support_for(&mut v, &d);
    set_grace_admits(false);
    assert!(support.is_some(), "the deviation's support");
    for block in [&d, &e] {
        assert_eq!(
            receive(&mut g, block),
            ReceiveBlockOutcome::AcceptedSilently
        );
    }
    assert_eq!(head_of(&g), (14, e.view().hash()), "the approval passes");
}

/// P4: the round's stop counts an active approval for `(c, s, P)` only.
#[test]
fn only_an_active_approval_of_the_same_conflict_stops_the_round() {
    let (mut bc, a2, a3, y) = twin_chain();
    let e = fact_on(&bc, &a3, &y, &[0]);
    receive(&mut bc, &e);
    let approval = approval_on(5, e.view().hash(), 4, &e, 1000, false);
    assert_eq!(
        receive(&mut bc, &approval),
        ReceiveBlockOutcome::AcceptedSilently
    );
    assert_eq!(head_of(&bc), (5, approval.view().hash()), "precondition");
    let p = a2.view().hash();
    assert_eq!(bc.holds_twin_approval(1, 3, &p), Some(true));
    assert_eq!(
        bc.holds_twin_approval(1, 3, &[0x5A; 32]),
        Some(false),
        "another P"
    );
    assert_eq!(bc.holds_twin_approval(1, 2, &p), Some(false), "another s");
    let idx = slot(&bc, &approval);
    assert!(bc.blocks.set_on_active_chain(idx, false));
    assert_eq!(
        bc.holds_twin_approval(1, 3, &p),
        Some(false),
        "a side approval has passed no Tier 3"
    );
}

/// P6: `A` at `P` leaves out a node whose only blocks lie above `P`. On the
/// Story 6.4 chain node #3 twins `a5` on `a4` (`A` at `a4` is `{0, 1, 4}`);
/// node #5 creates `a7`, so the counter at the tip holds it once, and the
/// correction subtracts it again (`m = 3`, not 4).
#[test]
fn a_node_that_entered_the_window_above_p_is_not_in_the_round() {
    let (_, mut l, [_, _, _, _, a4, a5]) = support_chain(0);
    let a6 = real_on(
        &l,
        &tx_block(6, a5.view().hash(), 0, votes_for(6, 5, 2, 6_100)),
        1,
        key_of(1),
    );
    assert_eq!(receive(&mut l, &a6), ReceiveBlockOutcome::AcceptedSilently);
    assert_eq!(l.vote_engine.top_creator(), Some(5), "precondition");
    let a7 = real_on(
        &l,
        &tx_block(7, a6.view().hash(), 0, votes_to(7, 0, 1, 7_100)),
        5,
        key_of(5),
    );
    assert_eq!(receive(&mut l, &a7), ReceiveBlockOutcome::AcceptedSilently);
    let y = resign(
        &tx_block(5, a4.view().hash(), 0, votes_for(5, 2, 1, 9_999)),
        3,
        a5.view().consumed_votes(),
        key_of(3),
    );
    let seed = twin_seed(5, 0, 3, 0);
    let mut members = [0u32, 1, 4];
    members.sort_by_key(|&n| node_value(&seed, n));
    let e = fact_on(&l, &a7, &y, &members);
    assert_eq!(fact_reason(&mut l, &e), None);
}

/// P3: a support for a held round off the active chain is checked against
/// its carried subgroup: node #1 (`c`, not in `[0]`) is refused.
#[test]
fn an_off_chain_round_takes_supports_from_its_members_only() {
    let (mut bc, _, a3, y) = twin_chain();
    let e_y = opener_on_y(&y, &a3);
    receive(&mut bc, &e_y);
    assert_eq!(
        intake(&mut bc, &support_by(1, 0, 4, e_y.view().hash())),
        ReceiveSupportOutcome::Rejected
    );
}

/// P3: the round's support needs the opener's signature verified.
#[test]
fn an_unverified_opener_gets_no_support() {
    let (mut bc, _, a3, y) = twin_chain();
    let e = fact_on(&bc, &a3, &y, &[0]);
    plant(&mut bc, &e, false, true);
    let idx = slot(&bc, &e);
    assert!(bc.blocks.set_parent_ref(idx, slot(&bc, &a3)));
    assert!(bc.evaluate_twin_support(idx, 0, 0).is_none(), "unverified");
    assert!(bc.blocks.mark_signature_verified(idx));
    assert!(bc.evaluate_twin_support(idx, 0, 0).is_some(), "verified");
}
