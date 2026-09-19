//! `intake.rs` — FR10 / FR14 / FR16 / FR26.
//!
//! Stateless classification dispatcher behind `Blockchain::receive_block`.
//! Story 4.3 realizes the deterministic single-outcome block-intake surface:
//! it maps every submitted block to exactly one [`ReceiveBlockOutcome`]
//! (single-outcome scheduling-pull pattern, AR4) by composing
//!
//! 1. the FR11 `(sequence, block_hash)` duplicate check (Story 4.1 index),
//! 2. the FR60 out-of-snake-chain-window discard (ready state only),
//! 3. the FR17 chain-config content-mismatch silent-discard (durable-locked),
//! 4. the Story 4.2 Tier 1 admission gate ([`Blockchain::tier1_admit`]).
//!
//! The dispatcher owns no state: it operates on the passed `&mut Blockchain`
//! (to reach the block-tree, chain-config, and Tier 1 admission) plus the
//! caller-supplied active-window bounds. The stateless FR60 window verdict and
//! the FR17 content comparison are the pure functions below.
//!
//! Transaction intake (FR14, Story 7.3) and support intake (FR26, Story 6.5)
//! layer onto this same file later.

use moonblokz_chain_types::{BlockView, HEADER_SIZE, PAYLOAD_TYPE_CHAIN_CONFIG};
use moonblokz_crypto::CryptoTrait;
use moonblokz_storage::StorageTrait;

use crate::api::{AdmitError, Blockchain, ReceiveBlockOutcome, RejectReason};
use moonblokz_configuration::ChainConfigTrait;

/// FR60 snake-chain-window position of an incoming block relative to the
/// current active-chain `(S_tail, S_head)` bounds.
#[cfg_attr(test, derive(Debug, PartialEq, Eq))]
pub(crate) enum WindowVerdict {
    /// `S_tail <= S_new < S_head + W` — the block can coexist with the active
    /// chain inside one `snake_chain` window; admit it to staged validation.
    InWindow,
    /// `S_new >= S_head + W` — too far ahead to be bridged by any reachable
    /// ancestor chain (FR60 forward case; drives the `long-disconnect-detected`
    /// diagnostic).
    TooFarAhead,
    /// `S_new < S_tail` — older than the local active-chain tail (FR60 backward
    /// case).
    BelowTail,
}

/// FR60 window classification. `w` is the configured `snake_chain` window size
/// (`SNAKE_CHAIN_LENGTH`). `s_head + w` is widened to `u64` so a head sequence
/// near the FR53 `u32::MAX` ceiling cannot wrap (FR53's `u32::MAX` refusal is
/// Epic 8; this function must be correct without relying on it).
pub(crate) fn snake_chain_window_verdict(
    s_new: u32,
    s_tail: u32,
    s_head: u32,
    w: u32,
) -> WindowVerdict {
    if u64::from(s_new) >= u64::from(s_head) + u64::from(w) {
        WindowVerdict::TooFarAhead
    } else if s_new < s_tail {
        WindowVerdict::BelowTail
    } else {
        WindowVerdict::InWindow
    }
}

/// FR17 content match: `true` iff the incoming chain-config block carries the
/// **content region** the durable-locked configuration holds.
///
/// Content, not the whole payload: a chain-config payload is the content region
/// followed by node #0's content signature (Story 5.7 envelope), and the module
/// retains and returns the content. Comparing whole payloads would make a
/// faithful replay of the locked configuration look like a mismatch as soon as
/// the signature trailer exists. The signature itself is not this gate's
/// business — it is the FR7 Tier-1 trust-anchor check (Story 5.9).
///
/// A payload whose envelope does not frame (truncated block, padding, a
/// malformed entry) carries no content region and therefore cannot match.
pub(crate) fn chain_config_content_matches(block: &BlockView<'_>, locked_content: &[u8]) -> bool {
    // `HEADER_SIZE` is referenced to anchor the "payload == bytes[HEADER_SIZE..]"
    // contract this comparison depends on; the envelope view walks exactly that
    // slice.
    debug_assert!(block.len() >= HEADER_SIZE);
    match block.chain_config() {
        Some(view) => view.content() == locked_content,
        None => false,
    }
}

/// FR10 deterministic single-outcome block-intake classifier.
///
/// Returns exactly one [`ReceiveBlockOutcome`], derived only from the block
/// bytes, the block-tree state, the active-window bounds, and the durable-locked
/// chain-config — never from `now`, a PRNG draw, or the transport origin (there
/// is no origin parameter), so two submissions of identical bytes against
/// identical state always classify identically (FR10 / FR63).
///
/// `window` is `Some((S_tail, S_head))` in ready state and `None` in collecting
/// state (the FR60 window check and its `long-disconnect-detected` log are
/// suppressed when `None`). In Epic 4 the module is always collecting, so
/// `receive_block` always passes `None`; the ready-state path is exercised by
/// injecting a window here directly (see tests / the `active_snake_chain_window`
/// seam).
///
/// Check order — FR11 dedup → FR60 window → FR17 chain-config → Tier 1 — is
/// load-bearing: FR11 is the authoritative duplicate index and must win over a
/// window that has since advanced past a still-retained block's sequence; the
/// FR60 and FR17 gates must both short-circuit *before* [`Blockchain::tier1_admit`],
/// which stores.
pub(crate) fn classify_block<
    C,
    S,
    Cfg,
    const MAX_NODES: usize,
    const SNAKE_CHAIN_LENGTH: u32,
    const VERIFICATION_HORIZON: usize,
    const MAX_BLOCKS: usize,
    const MAX_BRANCH_COUNT: usize,
    const MAX_BLOCK_UTXO_OUTPUT: usize,
>(
    bc: &mut Blockchain<
        C,
        S,
        Cfg,
        MAX_NODES,
        SNAKE_CHAIN_LENGTH,
        VERIFICATION_HORIZON,
        MAX_BLOCKS,
        MAX_BRANCH_COUNT,
        MAX_BLOCK_UTXO_OUTPUT,
    >,
    block: &BlockView<'_>,
    window: Option<(u32, u32)>,
    now: u64,
) -> ReceiveBlockOutcome
where
    C: CryptoTrait,
    S: StorageTrait,
    Cfg: ChainConfigTrait,
{
    // FR60 window width: a zero-width window (`SNAKE_CHAIN_LENGTH == 0`) would
    // set the upper bound to `s_head` and misclassify the head sequence itself
    // as `TooFarAhead`. No real config uses 0 (architecture §5 default is 500),
    // so reject it at compile time — evaluated once per monomorphization.
    const {
        assert!(
            SNAKE_CHAIN_LENGTH >= 1,
            "SNAKE_CHAIN_LENGTH (FR60 window width) must be >= 1"
        )
    };

    // 1. FR11 duplicate detection — authoritative, ahead of the window/config
    //    gates so an already-known block is `DuplicateKnown` even if the active
    //    window has since advanced past its sequence (nothing prunes the tree by
    //    window in Epic 4).
    let hash = block.hash();
    if bc.block_tree_contains(block.sequence(), &hash) {
        return ReceiveBlockOutcome::DuplicateKnown;
    }

    // 2. FR60 out-of-snake-chain-window discard — ready state only. `None`
    //    (collecting) suppresses both the check and the `long-disconnect-detected`
    //    log (AC7).
    if let Some((s_tail, s_head)) = window {
        match snake_chain_window_verdict(block.sequence(), s_tail, s_head, SNAKE_CHAIN_LENGTH) {
            WindowVerdict::TooFarAhead => {
                // FR64 (Epic 11 `LogSink`): emit `long-disconnect-detected`
                // carrying S_new = block.sequence(), the incoming block hash,
                // and the local (S_tail, S_head). Deferred — see deferred-work.md.
                return ReceiveBlockOutcome::Rejected(RejectReason::OutOfWindow);
            }
            WindowVerdict::BelowTail => {
                return ReceiveBlockOutcome::Rejected(RejectReason::OutOfWindow);
            }
            WindowVerdict::InWindow => {}
        }
    }

    // 3. FR17 chain-config content-mismatch silent-discard. Only fires once the
    //    configuration is durably locked; a matching replay falls through to
    //    Tier 1 and is stored. The module answers with the locked content
    //    exactly when the lock is held, so the lock state and the comparand are
    //    one read, not two — before genesis, and on a joining node that holds
    //    nothing, there is no lock and the gate stands down (unchanged
    //    behaviour).
    if block.payload_type() == PAYLOAD_TYPE_CHAIN_CONFIG
        && let Some(locked_content) = bc.durable_chain_config_content()
        && !chain_config_content_matches(block, locked_content)
    {
        // FR64 (Epic 11 `LogSink`): emit `chain-config-mismatch-discarded`
        // carrying the discarded block hash, block.sequence(), and
        // block.creator(). Deferred — see deferred-work.md.
        return ReceiveBlockOutcome::Rejected(RejectReason::InvalidEvidence);
    }

    // 4. Story 4.2 Tier 1 admission. `hash` (computed once in step 1) is
    //    threaded in; admission trusts this dispatcher's FR11 dedup and does
    //    not re-check it, then does the storage-first insert at `Stored` and
    //    runs the Story 4.4 FR19 chain_heads mutation events (`now` stamps the
    //    head arrival timestamp / bootstrap scheduling).
    match bc.tier1_admit(block, &hash, now) {
        Ok(_) => ReceiveBlockOutcome::AcceptedSilently,
        Err(AdmitError::Rejected(_)) => {
            ReceiveBlockOutcome::Rejected(RejectReason::InvalidEvidence)
        }
        // Operational (capacity/persistence) refusal — NOT an FR10 validity
        // classification. `TableFull` becomes unreachable once Story 4.4
        // `chain_heads` eviction lands.
        Err(AdmitError::TableFull) | Err(AdmitError::StorageSaveFailed) => {
            ReceiveBlockOutcome::Rejected(RejectReason::Unstorable)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::NextCall;
    use moonblokz_chain_types::{
        Block, BlockBuilder, BlockHeader, CONFIG_VALUE_COUNT_SIZE, MAX_BLOCK_SIZE, NodeTransfer,
        PAYLOAD_TYPE_TRANSACTION,
    };
    use moonblokz_configuration::{ChainConfiguration, NoopConfigChangeSink, parameter};
    use moonblokz_crypto::{
        Crypto, PRIVATE_KEY_SIZE, PublicKeyTrait, SIGNATURE_SIZE, SignatureTrait,
    };
    use moonblokz_storage::backend_memory::MemoryBackend;

    type TestConfig = ChainConfiguration<NoopConfigChangeSink>;

    type TestChain = Blockchain<
        Crypto,
        MemoryBackend<{ 8 * MAX_BLOCK_SIZE + 8000 }>,
        TestConfig,
        16,
        16,
        4,
        16,
        4,
        16,
    >;

    /// The empty override set as a **content region** — every parameter
    /// resolves to its code-baked default.
    const EMPTY_CONFIG_CONTENT: [u8; CONFIG_VALUE_COUNT_SIZE] = [0, 0];

    /// A second content region, equally valid and distinct in bytes: one
    /// literal entry declaring `vote_interest`'s own default value.
    const OTHER_CONFIG_CONTENT: [u8; 5] = [1, 0, parameter::VOTE_INTEREST, 1, 5];

    /// Frames `content` as a chain-config payload: the content region followed
    /// by node #0's signature over it (the Story 5.7 envelope).
    fn framed_config_payload(content: &[u8]) -> ([u8; CFG_PAYLOAD_BUF], usize) {
        let mut payload = [0u8; CFG_PAYLOAD_BUF];
        let payload_len = content.len() + SIGNATURE_SIZE;
        payload[..content.len()].copy_from_slice(content);
        payload[content.len()..payload_len].copy_from_slice(crypto().sign(content).serialize());
        (payload, payload_len)
    }

    /// A configuration module, optionally already durably locked on `content`.
    fn chain_config_module(content: Option<&[u8]>) -> TestConfig {
        let mut config = ChainConfiguration::new(NoopConfigChangeSink, TestChain::BUILD_LIMITS);
        if let Some(content) = content {
            let (payload, len) = framed_config_payload(content);
            config
                .load_durable(&payload[..len])
                .ok()
                .expect("framed content is accepted");
        }
        config
    }
    // W = SNAKE_CHAIN_LENGTH = 16 for these tests.
    const W: u32 = 16;

    fn crypto() -> Crypto {
        Crypto::new([1u8; PRIVATE_KEY_SIZE]).ok().expect("test key")
    }

    /// A configured node: the configuration is durably locked on the empty
    /// override set, which is the post-genesis state every classification test
    /// but the join-path one assumes.
    fn new_test_chain() -> TestChain {
        chain_with_config(chain_config_module(Some(&EMPTY_CONFIG_CONTENT)))
    }

    /// A durably-locked chain whose configuration content is `content`.
    fn locked_test_chain(content: &[u8]) -> TestChain {
        chain_with_config(chain_config_module(Some(content)))
    }

    /// A joining node that holds no configuration at all — the state before
    /// Story 5.9's tentative load.
    fn unconfigured_test_chain() -> TestChain {
        chain_with_config(chain_config_module(None))
    }

    fn chain_with_config(chain_config: TestConfig) -> TestChain {
        let c = crypto();
        let node_zero = *c.public_key().serialize();
        let storage = MemoryBackend::<{ 8 * MAX_BLOCK_SIZE + 8000 }>::new();
        let mut bc_slot = core::mem::MaybeUninit::<TestChain>::uninit();
        TestChain::init(&mut bc_slot, c, storage, chain_config, 5, node_zero, 0);
        // SAFETY: `init` returned, so every field of `bc_slot` is initialized.
        unsafe { bc_slot.assume_init() }
    }

    /// A well-formed Tier-1-passing transaction block (`seq > anchor`, no
    /// self-vote). The block-creator signature is not a Tier 1 gate in Epic 4.
    fn node_transfer_block(seq: u32, vote: u32, anchor: u32, initializer: u32) -> Block {
        let signer = crypto();
        let nt = NodeTransfer::new_signed(vote, anchor, initializer, 9, 100, 1, 0, &signer);
        let header = BlockHeader {
            version: 1,
            sequence: seq,
            creator: 0,
            mined_amount: 0,
            payload_type: PAYLOAD_TYPE_TRANSACTION,
            consumed_votes: 0,
            first_voted_node: 0,
            consumed_votes_from_first_voted_node: 0,
            previous_hash: [0u8; 32],
            signature: [0u8; 64],
        };
        let mut builder = BlockBuilder::new().header(header);
        builder
            .add_node_transfer(&nt)
            .ok()
            .expect("add node transfer");
        builder.build_signed(&signer).ok().expect("build signed")
    }

    /// A `payload_type=3` chain-config block: a canonical header built via
    /// `BlockBuilder` (so the wire-field offsets live in the library, not in
    /// this test — the header stays correct if `BlockHeader`'s layout changes)
    /// followed by the given raw payload appended at `HEADER_SIZE`, the one
    /// structural fact (`block == [header | payload]`) that
    /// `chain_config_content_matches` itself relies on. `from_bytes` infers the
    /// payload as everything after `HEADER_SIZE`. The block signature is
    /// irrelevant — the FR17 discard fires before any signature check, and
    /// `from_bytes` validates only `len ∈ [122, 2016]` and `version != 0`.
    /// Creator stays 0 (only read by the deferred FR64 log).
    // Fixed buffer + used length (const-generic `HEADER_SIZE + P` array sizing
    // would need the unstable `generic_const_exprs`). Callers parse `&buf[..len]`.
    /// A framed chain-config payload: a small content region plus the
    /// signature trailer.
    const CFG_PAYLOAD_BUF: usize = 16 + SIGNATURE_SIZE;
    const CFG_BUF: usize = HEADER_SIZE + CFG_PAYLOAD_BUF;
    fn chain_config_block_bytes(seq: u32, payload: &[u8]) -> ([u8; CFG_BUF], usize) {
        // Header-only block (no payload added) → a canonical HEADER_SIZE-byte
        // header laid out by `build_signed`'s named-offset code.
        let header_only = BlockBuilder::new()
            .header(BlockHeader {
                version: 1,
                sequence: seq,
                creator: 0,
                mined_amount: 0,
                payload_type: PAYLOAD_TYPE_CHAIN_CONFIG,
                consumed_votes: 0,
                first_voted_node: 0,
                consumed_votes_from_first_voted_node: 0,
                previous_hash: [0u8; 32],
                signature: [0u8; 64],
            })
            .build_signed(&crypto())
            .ok()
            .expect("build header-only chain-config block");
        let mut b = [0u8; CFG_BUF];
        b[..HEADER_SIZE].copy_from_slice(&header_only.view().serialized_bytes()[..HEADER_SIZE]);
        b[HEADER_SIZE..HEADER_SIZE + payload.len()].copy_from_slice(payload);
        (b, HEADER_SIZE + payload.len())
    }

    // --- AC6: pure window verdict -------------------------------------------

    #[test]
    fn window_verdict_in_window_interior() {
        assert_eq!(
            snake_chain_window_verdict(10, 5, 20, W),
            WindowVerdict::InWindow
        );
    }

    #[test]
    fn window_verdict_in_window_at_tail_boundary() {
        // S_new == S_tail is in-window (inclusive lower bound).
        assert_eq!(
            snake_chain_window_verdict(5, 5, 20, W),
            WindowVerdict::InWindow
        );
    }

    #[test]
    fn window_verdict_in_window_just_below_ahead_boundary() {
        // S_head + W - 1 is the last in-window sequence.
        assert_eq!(
            snake_chain_window_verdict(20 + W - 1, 5, 20, W),
            WindowVerdict::InWindow
        );
    }

    #[test]
    fn window_verdict_too_far_ahead_at_boundary() {
        // S_new == S_head + W is the first out-of-window (exclusive upper bound).
        assert_eq!(
            snake_chain_window_verdict(20 + W, 5, 20, W),
            WindowVerdict::TooFarAhead
        );
    }

    #[test]
    fn window_verdict_below_tail() {
        assert_eq!(
            snake_chain_window_verdict(4, 5, 20, W),
            WindowVerdict::BelowTail
        );
    }

    #[test]
    fn window_verdict_no_overflow_near_u32_max() {
        // `s_head + W` overflows u32 here (MAX-3 + 16 = MAX+13). Widened to u64
        // the upper bound is MAX+13, so s_new = MAX is IN-window. A u32 wrap
        // would compute the bound as 12 and misclassify MAX as TooFarAhead — so
        // InWindow proves the widening prevents the wrap.
        assert_eq!(
            snake_chain_window_verdict(u32::MAX, 0, u32::MAX - 3, W),
            WindowVerdict::InWindow
        );
        // Upper bound still within range (MAX-20 + 16 = MAX-4): MAX is out ahead.
        assert_eq!(
            snake_chain_window_verdict(u32::MAX, 0, u32::MAX - 20, W),
            WindowVerdict::TooFarAhead
        );
    }

    // --- AC8: pure content match --------------------------------------------

    #[test]
    fn chain_config_content_matches_equal_and_differing() {
        let (payload, payload_len) = framed_config_payload(&OTHER_CONFIG_CONTENT);
        let (block, len) = chain_config_block_bytes(1, &payload[..payload_len]);
        let view = BlockView::from_bytes(&block[..len])
            .ok()
            .expect("valid raw block");
        assert!(chain_config_content_matches(&view, &OTHER_CONFIG_CONTENT));
        // Differing content, shorter locked, longer locked all fail.
        assert!(!chain_config_content_matches(&view, &EMPTY_CONFIG_CONTENT));
        assert!(!chain_config_content_matches(
            &view,
            &OTHER_CONFIG_CONTENT[..4]
        ));
        assert!(!chain_config_content_matches(&view, &[1, 0, 7, 1, 5, 0]));
    }

    /// A payload that is not a framed envelope — here the empty payload of a
    /// header-only block — carries no content region, so it matches nothing.
    /// Before the Story 5.7 envelope this compared raw payload bytes and an
    /// empty payload "matched" an empty locked configuration; content that is
    /// not even framed can no longer be the locked content.
    #[test]
    fn chain_config_unframed_payload_never_matches() {
        let (empty, len) = chain_config_block_bytes(1, &[]);
        let view = BlockView::from_bytes(&empty[..len])
            .ok()
            .expect("header-only block is valid");
        assert!(!chain_config_content_matches(&view, &EMPTY_CONFIG_CONTENT));
        assert!(!chain_config_content_matches(&view, &[]));
    }

    // --- AC4: accepted-new --------------------------------------------------

    #[test]
    fn receive_block_accepts_new_stores_silently() {
        let mut bc = new_test_chain();
        let block = node_transfer_block(5, 3, 4, 7);
        let (outcome, next) = bc.receive_block(block.view(), 1_000);
        assert_eq!(outcome, ReceiveBlockOutcome::AcceptedSilently);
        // Story 4.4: a non-genesis block with an unresolved parent (its
        // `previous_hash` is zero-filled here) becomes a Stored `chain_heads`
        // head, so `receive_block` schedules the FR19 parent-recovery tick.
        assert!(
            matches!(next, NextCall::At(_)),
            "an orphan block schedules parent recovery"
        );
        assert_eq!(bc.block_tree_len(), 1, "accepted block is stored");
    }

    // --- AC3: duplicate -----------------------------------------------------

    #[test]
    fn receive_block_duplicate_is_duplicate_known() {
        let mut bc = new_test_chain();
        let block = node_transfer_block(5, 3, 4, 7);
        assert_eq!(
            bc.receive_block(block.view(), 1).0,
            ReceiveBlockOutcome::AcceptedSilently
        );
        let (outcome, _) = bc.receive_block(block.view(), 2);
        assert_eq!(outcome, ReceiveBlockOutcome::DuplicateKnown);
        assert_eq!(bc.block_tree_len(), 1, "duplicate is not re-stored");
    }

    // --- AC5: Tier 1 failure ------------------------------------------------

    #[test]
    fn receive_block_tier1_fail_is_rejected_invalid_evidence() {
        let mut bc = new_test_chain();
        // initializer == vote == 7 → FR6 self-vote → Tier 1 reject.
        let block = node_transfer_block(5, 7, 4, 7);
        let (outcome, _) = bc.receive_block(block.view(), 1);
        assert_eq!(
            outcome,
            ReceiveBlockOutcome::Rejected(RejectReason::InvalidEvidence)
        );
        assert_eq!(bc.block_tree_len(), 0, "rejected block is not stored");
    }

    // --- Unstorable: operational refusal, NOT an FR10 validity verdict ------

    #[test]
    fn receive_block_operational_refusal_is_unstorable() {
        // The `Unstorable` arm maps the operational refusals
        // `AdmitError::{TableFull, StorageSaveFailed}` — a valid block that could
        // not be persisted/retained, distinct from an `InvalidEvidence` validity
        // verdict. Story 4.4 `chain_heads` eviction makes the `TableFull` path
        // effectively unreachable (a full block-table is relieved by evicting the
        // smallest non-active head), so this exercises the surviving
        // `StorageSaveFailed → Unstorable` path directly with a zero-capacity
        // storage seam: the very first admission fails to persist and must
        // classify `Unstorable`, not `InvalidEvidence` (the block is valid).
        let c = crypto();
        let node_zero = *c.public_key().serialize();
        let storage = MemoryBackend::<0>::new();
        let mut bc_slot =
            core::mem::MaybeUninit::<Blockchain<_, _, _, 16, 16, 4, 16, 4, 16>>::uninit();
        let bc = Blockchain::<_, _, _, 16, 16, 4, 16, 4, 16>::init(
            &mut bc_slot,
            c,
            storage,
            chain_config_module(Some(&EMPTY_CONFIG_CONTENT)),
            5,
            node_zero,
            0,
        );
        let block = node_transfer_block(5, 3, 4, 7);
        let (outcome, _) = bc.receive_block(block.view(), 0);
        assert_eq!(
            outcome,
            ReceiveBlockOutcome::Rejected(RejectReason::Unstorable),
            "an unpersistable-but-valid block yields Unstorable, not InvalidEvidence"
        );
        assert_eq!(
            bc.block_tree_len(),
            0,
            "the unstorable block is not added to the tree"
        );
    }

    // --- AC3 precedence: dedup beats window ---------------------------------

    #[test]
    fn classify_dedup_precedes_window() {
        let mut bc = new_test_chain();
        let block = node_transfer_block(5, 3, 4, 7);
        // Store it first (collecting path, no window).
        assert_eq!(
            classify_block(&mut bc, &block.view(), None, 0),
            ReceiveBlockOutcome::AcceptedSilently
        );
        // Now inject a window under which seq 5 is out-of-window (below tail);
        // FR11 dedup must still win.
        let outcome = classify_block(&mut bc, &block.view(), Some((100, 200)), 0);
        assert_eq!(outcome, ReceiveBlockOutcome::DuplicateKnown);
    }

    // --- AC6: out-of-window (ready) -----------------------------------------

    #[test]
    fn classify_out_of_window_forward() {
        let mut bc = new_test_chain();
        // S_tail=0, S_head=5, W=16 → out-of-window forward at seq >= 21.
        let block = node_transfer_block(21, 3, 4, 7);
        let outcome = classify_block(&mut bc, &block.view(), Some((0, 5)), 0);
        assert_eq!(
            outcome,
            ReceiveBlockOutcome::Rejected(RejectReason::OutOfWindow)
        );
        assert_eq!(bc.block_tree_len(), 0, "out-of-window block is not stored");
    }

    #[test]
    fn classify_out_of_window_below_tail() {
        let mut bc = new_test_chain();
        // S_tail=10 → seq 5 is below tail.
        let block = node_transfer_block(5, 3, 4, 7);
        let outcome = classify_block(&mut bc, &block.view(), Some((10, 20)), 0);
        assert_eq!(
            outcome,
            ReceiveBlockOutcome::Rejected(RejectReason::OutOfWindow)
        );
        assert_eq!(bc.block_tree_len(), 0, "below-tail block is not stored");
    }

    #[test]
    fn classify_in_window_ready_is_accepted() {
        let mut bc = new_test_chain();
        // seq 5 within [S_tail=0, S_head+W=21).
        let block = node_transfer_block(5, 3, 4, 7);
        let outcome = classify_block(&mut bc, &block.view(), Some((0, 5)), 0);
        assert_eq!(outcome, ReceiveBlockOutcome::AcceptedSilently);
        assert_eq!(bc.block_tree_len(), 1);
    }

    // --- AC7: collecting suppresses the window ------------------------------

    #[test]
    fn classify_collecting_suppresses_window() {
        let mut bc = new_test_chain();
        // A high sequence that WOULD be out-of-window under any small window is
        // admitted in collecting state (window == None).
        let block = node_transfer_block(9_999, 3, 4, 7);
        let outcome = classify_block(&mut bc, &block.view(), None, 0);
        assert_eq!(outcome, ReceiveBlockOutcome::AcceptedSilently);
        assert_eq!(bc.block_tree_len(), 1);
    }

    // --- AC8: chain-config silent discard / replay --------------------------

    #[test]
    fn chain_config_matching_replay_proceeds() {
        // Locked content == this block's content → legitimate replay → stored.
        let mut bc = locked_test_chain(&OTHER_CONFIG_CONTENT);
        let (payload, payload_len) = framed_config_payload(&OTHER_CONFIG_CONTENT);
        let (bytes, len) = chain_config_block_bytes(2, &payload[..payload_len]);
        let view = BlockView::from_bytes(&bytes[..len])
            .ok()
            .expect("valid raw block");
        let outcome = classify_block(&mut bc, &view, None, 0);
        // payload_type=3 is a recognized schema; Tier 1 stores it.
        assert_eq!(outcome, ReceiveBlockOutcome::AcceptedSilently);
        assert_eq!(
            bc.block_tree_len(),
            1,
            "matching chain-config replay is stored"
        );
    }

    #[test]
    fn chain_config_mismatch_is_discarded() {
        let mut bc = locked_test_chain(&OTHER_CONFIG_CONTENT);
        // Different content from the locked configuration → FR17 silent discard.
        let (payload, payload_len) = framed_config_payload(&EMPTY_CONFIG_CONTENT);
        let (bytes, len) = chain_config_block_bytes(2, &payload[..payload_len]);
        let view = BlockView::from_bytes(&bytes[..len])
            .ok()
            .expect("valid raw block");
        let outcome = classify_block(&mut bc, &view, None, 0);
        assert_eq!(
            outcome,
            ReceiveBlockOutcome::Rejected(RejectReason::InvalidEvidence)
        );
        assert_eq!(
            bc.block_tree_len(),
            0,
            "mismatched chain-config is not stored"
        );
    }

    /// The join path: a node that holds no configuration has no locked content
    /// to compare against, so the FR17 gate stands down and the block proceeds
    /// to Tier 1 and is stored — exactly as it did when the gate's lock flag was
    /// hard-coded and the retained bytes were absent.
    #[test]
    fn chain_config_gate_stands_down_without_configuration() {
        let mut bc = unconfigured_test_chain();
        let (payload, payload_len) = framed_config_payload(&OTHER_CONFIG_CONTENT);
        let (bytes, len) = chain_config_block_bytes(2, &payload[..payload_len]);
        let view = BlockView::from_bytes(&bytes[..len])
            .ok()
            .expect("valid raw block");
        let outcome = classify_block(&mut bc, &view, None, 0);
        assert_eq!(outcome, ReceiveBlockOutcome::AcceptedSilently);
        assert_eq!(bc.block_tree_len(), 1);
    }

    // --- AC2 / AC9: determinism ---------------------------------------------

    #[test]
    fn receive_block_ignores_now() {
        let mut bc_a = new_test_chain();
        let mut bc_b = new_test_chain();
        let block = node_transfer_block(5, 3, 4, 7);
        let a = bc_a.receive_block(block.view(), 1).0;
        let b = bc_b.receive_block(block.view(), 999_999).0;
        assert_eq!(a, b, "classification must not depend on `now`");
    }

    #[test]
    fn receive_block_deterministic_replay() {
        // Same submission sequence against two fresh chains → identical outcome
        // vectors and identical resulting tree sizes (FR63).
        let submissions = [
            node_transfer_block(5, 3, 4, 7), // accepted
            node_transfer_block(5, 3, 4, 7), // duplicate
            node_transfer_block(6, 7, 4, 7), // self-vote → rejected
            node_transfer_block(7, 3, 4, 7), // accepted
        ];
        let run = || {
            let mut bc = new_test_chain();
            let outcomes: [ReceiveBlockOutcome; 4] =
                core::array::from_fn(|i| bc.receive_block(submissions[i].view(), i as u64).0);
            (outcomes, bc.block_tree_len())
        };
        let (o1, len1) = run();
        let (o2, len2) = run();
        assert_eq!(o1, o2);
        assert_eq!(len1, len2);
        assert_eq!(
            o1,
            [
                ReceiveBlockOutcome::AcceptedSilently,
                ReceiveBlockOutcome::DuplicateKnown,
                ReceiveBlockOutcome::Rejected(RejectReason::InvalidEvidence),
                ReceiveBlockOutcome::AcceptedSilently,
            ]
        );
        assert_eq!(len1, 2, "two accepted blocks stored");
    }
}
