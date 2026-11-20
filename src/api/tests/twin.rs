//! Story 6.12 — FR70 twin blocks: the twin check and the FR22 hold
//! (DEC-273). A twin is a sibling with the same creator; the hold keeps the
//! node on the twin it adopted first and lets an honest fork through.

use super::fixtures::*;
use super::*;
use crate::api::switch::Twin;

/// The switch toward `block` ran and its replay refused it: a forged-value
/// winner (a free header) is deleted with its descendants by the I-09 check,
/// so it is gone while the active head stayed. A held candidate is never
/// attempted and stays.
fn attempted<S: StorageTrait>(bc: &Chain16<S>, block: &Block) -> bool {
    status_of(bc, block).is_none()
}

/// On [`two_creator_chain`]: node #1's sibling of `a3` (node #1's), worth
/// the same 1005 but larger (three credits for node #0) — FR21 ranks it
/// above `a3`, so only the hold keeps `a3`.
fn twin_of_a3(a2: &Block, salt: u64) -> Block {
    alt(3, a2.view().hash(), 1, 1, 3, salt, false)
}

/// Node #0's block on `a2` worth 0 (node #0 created `a2` and holds no
/// vote): the lower-valued block of an honest fork against `a3`.
fn node_zero_on_a2(a2: &Block, salt: u64) -> Block {
    alt(3, a2.view().hash(), 0, 0, 1, salt, false)
}

/// AC3 — a twin of the active block that outranks it is held: no switch,
/// the twin branch stays stored and valued, and extending it changes
/// nothing; the active chain keeps extending.
#[test]
fn a_twin_of_the_active_block_is_held() {
    let (mut bc, _, a2, a3) = two_creator_chain();
    let x = twin_of_a3(&a2, 40);
    assert_eq!(receive(&mut bc, &x), ReceiveBlockOutcome::AcceptedSilently);
    let xi = slot(&bc, &x);
    assert_eq!(
        bc.switch_target([Some(xi), None]),
        Some(xi),
        "FR21 ranks the twin above the active branch"
    );
    assert_eq!(head_of(&bc), (3, a3.view().hash()), "held");
    assert_eq!(status_of(&bc, &x), Some(BlockStatus::Connected));
    assert_eq!(bc.chain_heads.branch_value_of(xi), Some(1005));

    // Extending the twin branch changes nothing: its first divergent block
    // is still the twin.
    let x4 = alt(4, x.view().hash(), 0, 3, 0, 21, false);
    assert_eq!(receive(&mut bc, &x4), ReceiveBlockOutcome::AcceptedSilently);
    assert_eq!(head_of(&bc), (3, a3.view().hash()), "still held");
    assert_eq!(status_of(&bc, &x4), Some(BlockStatus::Connected));

    // The chain keeps extending (DEC-163: nothing is frozen).
    let a4 = alt(4, a3.view().hash(), 0, 0, 1, 9, false);
    assert_eq!(receive(&mut bc, &a4), ReceiveBlockOutcome::AcceptedSilently);
    assert_eq!(head_of(&bc), (4, a4.view().hash()));
}

/// AC3 positive control — an honest fork, a different creator at the
/// divergence point: the expected creator's late `a3` (node #1, 1005)
/// beats node #0's `d3` (worth 0), and the node switches.
#[test]
fn an_honest_fork_switches() {
    let (mut bc, _, b1) = ready_genesis(16);
    let a2 = alt(2, b1.view().hash(), 0, 0, 1, 7, true);
    let d3 = node_zero_on_a2(&a2, 50);
    let a3 = alt(3, a2.view().hash(), 1, 1, 0, 8, false);
    for blk in [&a2, &d3] {
        assert_eq!(receive(&mut bc, blk), ReceiveBlockOutcome::AcceptedSilently);
    }
    assert_eq!(head_of(&bc), (3, d3.view().hash()));
    assert_eq!(receive(&mut bc, &a3), ReceiveBlockOutcome::AcceptedSilently);
    assert_eq!(head_of(&bc), (3, a3.view().hash()), "switched");
    assert_eq!(status_of(&bc, &d3), Some(BlockStatus::Connected));
}

/// AC3 / D3 — a held candidate drops out and the next-ranked one is
/// compared. Built in collecting so neither side head is switched to on
/// arrival: at the Ready entry FR2 picks `d3` (the lowest tip hash), the
/// driver's best is node #0's forged twin `x` (5000), which the hold keeps,
/// and `a3` (node #1, 1005) is no candidate of that comparison. One
/// comparison of both then skips `x` and switches to `a3`.
#[test]
fn a_held_twin_yields_to_the_next_ranked_candidate() {
    let (_, b0, b1) = ready_genesis(16);
    let a2 = alt(2, b1.view().hash(), 0, 0, 1, 7, true);
    let a3 = alt(3, a2.view().hash(), 1, 1, 0, 8, false);
    let (d3, x) = (100..2000)
        .find_map(|salt| {
            let d3 = node_zero_on_a2(&a2, salt);
            let x = revalue(&node_zero_on_a2(&a2, salt + 5000), 5000);
            let lowest = d3.view().hash() < a3.view().hash() && d3.view().hash() < x.view().hash();
            lowest.then_some((d3, x))
        })
        .expect("a d3 with the lowest tip hash");
    let mut bc = new_unconfigured_test_chain();
    for blk in [&x, &a3, &d3, &a2, &b1, &b0] {
        assert_eq!(receive(&mut bc, blk), ReceiveBlockOutcome::AcceptedSilently);
    }
    assert!(bc.is_ready());
    assert_eq!(
        head_of(&bc),
        (3, d3.view().hash()),
        "x held at the Ready entry"
    );
    assert_eq!(status_of(&bc, &x), Some(BlockStatus::Connected));
    let (xi, a3i) = (slot(&bc, &x), slot(&bc, &a3));
    assert_eq!(
        bc.switch_target([Some(xi), Some(a3i)]),
        Some(xi),
        "FR21 ranks the twin first"
    );
    bc.compare_and_switch([Some(xi), Some(a3i)], 0);
    assert_eq!(head_of(&bc), (3, a3.view().hash()), "the next-ranked won");
    assert!(!attempted(&bc, &x), "the held twin was never attempted");
}

/// FR70: blocks of one creator at one sequence on different parents are no
/// twins. Node #0's `h4` sits on node #0's `h3`, an honest fork of `a3`, and
/// shares creator and sequence with the active `a4`: the comparison is not
/// held, so the forged branch is attempted and the replay deletes it.
#[test]
fn same_creator_blocks_on_different_parents_are_not_held() {
    let (mut bc, _, a2, a3) = two_creator_chain();
    let a4 = alt(4, a3.view().hash(), 0, 0, 1, 9, false);
    assert_eq!(receive(&mut bc, &a4), ReceiveBlockOutcome::AcceptedSilently);
    let h3 = node_zero_on_a2(&a2, 60);
    let h4 = revalue(&alt(4, h3.view().hash(), 0, 0, 1, 61, false), 5000);
    assert_eq!(receive(&mut bc, &h3), ReceiveBlockOutcome::AcceptedSilently);
    assert_eq!(receive(&mut bc, &h4), ReceiveBlockOutcome::AcceptedSilently);
    assert_eq!(head_of(&bc), (4, a4.view().hash()));
    assert!(attempted(&bc, &h4), "compared, switched toward, refused");
}

/// AC2 — the check itself. An honest pair costs no verification (the
/// creators differ); an unverified twin is verified once, and the caller's
/// mark spares the next check; a forged sibling of the same claimed creator
/// is no twin. Exact counter deltas.
#[test]
fn the_twin_check_verifies_once_and_only_a_same_creator_sibling() {
    let (mut bc, _, a2, a3) = two_creator_chain();
    let a3i = slot(&bc, &a3);
    let count = || BLOCK_SIGNATURE_VERIFICATIONS.with(|c| c.get());
    let a2i = slot(&bc, &a2);

    let honest = node_zero_on_a2(&a2, 70);
    plant_child(&mut bc, &honest, a2i, false, true);
    let before = count();
    assert_eq!(bc.twin_of(slot(&bc, &honest), a3i), Twin::No);
    assert_eq!(count() - before, 0, "the creators differ: nothing verified");

    let x = twin_of_a3(&a2, 71);
    plant_child(&mut bc, &x, a2i, false, true);
    let xi = slot(&bc, &x);
    let before = count();
    assert_eq!(bc.twin_of(xi, a3i), Twin::Yes { verified_now: true });
    assert_eq!(count() - before, 1);
    bc.blocks.mark_signature_verified(xi);
    let before = count();
    assert_eq!(
        bc.twin_of(xi, a3i),
        Twin::Yes {
            verified_now: false
        }
    );
    assert_eq!(count() - before, 0, "the mark spares the second check");

    // Node #1's claimed header signed with another key.
    let forged = headed(3, a2.view().hash(), 1, 0x42, 1005, 1, 0, |b| {
        votes_for(3, 0, 2, 72)(b)
    });
    plant_child(&mut bc, &forged, a2i, false, true);
    let before = count();
    assert_eq!(bc.twin_of(slot(&bc, &forged), a3i), Twin::No);
    assert_eq!(count() - before, 1);
}

/// AC2 — a read that fails is no evidence: the twin is held and nothing is
/// deleted. `a3` is read once to value the fork, then the twin check's read
/// fails; the switch is never attempted (its undo would read `a3` again).
#[test]
fn a_failed_read_holds_and_deletes_nothing() {
    let (mut bc, _, a2, a3) = failing_two_creator_chain();
    bc.storage.failing_slot = slot(&bc, &a3);
    bc.storage.reads_left.set(1);
    bc.storage.attempts.set(0);
    let x = twin_of_a3(&a2, 40);
    assert_eq!(receive(&mut bc, &x), ReceiveBlockOutcome::AcceptedSilently);
    assert_eq!(head_of(&bc), (3, a3.view().hash()));
    assert_eq!(status_of(&bc, &x), Some(BlockStatus::Connected));
    assert_eq!(status_of(&bc, &a3), Some(BlockStatus::Active));
    assert_eq!(
        bc.storage.attempts.get(),
        2,
        "valued, then the twin check failed"
    );
}

/// AC3 — the restart comparison holds too: FR2 resumes on `a3` (the lower
/// tip hash) and the driver's best, the larger twin, is not switched to.
#[test]
fn the_restart_comparison_holds_a_twin() {
    let (mut bc, _, a2, a3) = two_creator_chain();
    let x = (40..400)
        .map(|salt| twin_of_a3(&a2, salt))
        .find(|x| x.view().hash() > a3.view().hash())
        .expect("a twin with a higher hash");
    assert_eq!(receive(&mut bc, &x), ReceiveBlockOutcome::AcceptedSilently);
    let mut restarted = restart(bc);
    let _ = restarted.initialize_from_storage(0);
    assert!(restarted.is_ready());
    assert_eq!(head_of(&restarted), (3, a3.view().hash()));
    assert_eq!(status_of(&restarted, &x), Some(BlockStatus::Connected));
}

/// AR16 (FR63): one stream — a twin, an extension of the active head, and
/// an honest fork whose second block shares creator and sequence with the
/// active head on another parent — gives the same outcomes, head, value and
/// entries on two fresh modules.
#[test]
fn twin_handling_is_replay_deterministic() {
    let (_, _, a2, a3) = two_creator_chain();
    let x = twin_of_a3(&a2, 40);
    let a4 = alt(4, a3.view().hash(), 0, 0, 1, 9, false);
    let h3 = node_zero_on_a2(&a2, 60);
    let h4 = revalue(&alt(4, h3.view().hash(), 0, 0, 1, 61, false), 5000);
    let stream = [&x, &a4, &h3, &h4];
    let run = || {
        let (mut bc, _, _, _) = two_creator_chain();
        let outcomes: std::vec::Vec<ReceiveBlockOutcome> =
            stream.iter().map(|block| receive(&mut bc, block)).collect();
        (
            outcomes,
            head_of(&bc),
            bc.active_branch_value,
            stream.map(|block| status_of(&bc, block)),
        )
    };
    let first = run();
    assert_eq!(first.1, (4, a4.view().hash()));
    assert_eq!(
        first.3,
        [
            Some(BlockStatus::Connected),
            Some(BlockStatus::Active),
            Some(BlockStatus::Connected),
            None
        ],
        "the twin held, the fork's forged block deleted"
    );
    assert_eq!(first, run());
}
