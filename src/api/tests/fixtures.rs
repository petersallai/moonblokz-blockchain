//! Test fixtures used by more than one test file, in their original order.

use super::*;

pub(super) type TestChain = Blockchain<
    Crypto,
    MemoryBackend<{ 8 * MAX_BLOCK_SIZE + 8000 }>,
    TestConfig,
    16,
    16,
    TEST_MAX_BLOCKS,
    4,
    TEST_UTXO_BYTES,
>;

pub(super) fn new_test_chain() -> TestChain {
    let (crypto, storage, _) = test_backends();
    // A node that already holds a chain configuration — the state every
    // post-genesis test assumes, and what the retired stub gave them for
    // free by answering every accessor unconditionally.
    let chain_config = locked_chain_config(&crypto, TestChain::BUILD_LIMITS);
    let node_zero = *crypto.public_key().serialize();
    let mut bc_slot = core::mem::MaybeUninit::<TestChain>::uninit();
    TestChain::init(&mut bc_slot, crypto, storage, chain_config, 5, node_zero, 0);
    // SAFETY: `init` returned, so every field of `bc_slot` is initialized.
    unsafe { bc_slot.assume_init() }
}

pub(super) fn node_transfer_block(seq: u32, vote: u32, anchor: u32, initializer: u32) -> Block {
    // The block-creator signature is not a Tier 1 gate in Epic 4
    // (opportunistic / ready-state), so any signer works for these tests.
    let signer = Crypto::new([1u8; PRIVATE_KEY_SIZE]).ok().expect("test key");
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
        signature: [0u8; SIGNATURE_SIZE],
    };
    let mut builder = BlockBuilder::new().header(header);
    builder
        .add_node_transfer(&nt)
        .ok()
        .expect("add node transfer");
    builder.build_signed(&signer).ok().expect("build signed")
}

/// Block #0 of the fixed FR54 shape (DEC-269), built by the same builder as
/// `process_genesis` and signed by the universal test key — the test chains'
/// trust anchor — carrying `amount`. Distinct amounts give distinct blocks #0.
pub(super) fn genesis_zero_block(amount: u64) -> Block {
    let signer = Crypto::new([1u8; PRIVATE_KEY_SIZE]).ok().expect("test key");
    let anchor = *signer.public_key().serialize();
    let mut header = [0u8; HEADER_SIZE];
    header[0] = 1;
    let mut block = Block::from_bytes(&header).ok().expect("header-only block");
    crate::api::genesis::genesis_block_zero(&signer, &anchor, amount, &mut block);
    block
}

/// A block #0 assembled from its parts, for the Story 6.10 intake and pass
/// tests that need one field changed: the two transactions in the fixed
/// order, under a canonical header with `previous_hash` = `prev`, signed by
/// `block_signer`.
pub(super) fn block_zero_from(
    registration: &Registration,
    transfer: &NodeTransfer,
    prev: [u8; 32],
    block_signer: &Crypto,
) -> Block {
    let header = BlockHeader {
        version: 1,
        sequence: 0,
        creator: 0,
        mined_amount: 0,
        payload_type: PAYLOAD_TYPE_TRANSACTION,
        consumed_votes: 0,
        first_voted_node: 0,
        consumed_votes_from_first_voted_node: 0,
        previous_hash: prev,
        signature: [0u8; SIGNATURE_SIZE],
    };
    let mut builder = BlockBuilder::new().header(header);
    builder
        .add_registration(registration)
        .ok()
        .expect("add registration");
    builder
        .add_node_transfer(transfer)
        .ok()
        .expect("add transfer");
    builder
        .build_signed(block_signer)
        .ok()
        .expect("build signed")
}

/// The test anchor's own block #0 transactions: node #0's registration and a
/// self-transfer of `amount`, both signed by the universal test key.
pub(super) fn genesis_zero_transactions(amount: u64) -> (Crypto, Registration, NodeTransfer) {
    let anchor = Crypto::new([1u8; PRIVATE_KEY_SIZE]).ok().expect("test key");
    let anchor_pk = *anchor.public_key().serialize();
    let registration = Registration::new_signed(0, 0, 0, 0, 0, &anchor_pk, &anchor);
    let transfer = NodeTransfer::new_signed(0, 0, 0, 0, amount, 0, 0, &anchor);
    (anchor, registration, transfer)
}

/// A transfer block whose `previous_hash` is set to `prev` (so it can extend
/// a specific parent). `node_transfer_block` zero-fills `previous_hash`, which
/// makes an orphan (Stored head); this helper links a child to its parent.
pub(super) fn linked_transfer_block(seq: u32, prev: [u8; 32]) -> Block {
    let signer = Crypto::new([1u8; PRIVATE_KEY_SIZE]).ok().expect("test key");
    let nt = NodeTransfer::new_signed(3, seq.saturating_sub(1), 7, 9, 100, 1, 0, &signer);
    let header = BlockHeader {
        version: 1,
        sequence: seq,
        creator: 0,
        mined_amount: 0,
        payload_type: PAYLOAD_TYPE_TRANSACTION,
        consumed_votes: 0,
        first_voted_node: 0,
        consumed_votes_from_first_voted_node: 0,
        previous_hash: prev,
        signature: [0u8; SIGNATURE_SIZE],
    };
    let mut builder = BlockBuilder::new().header(header);
    builder
        .add_node_transfer(&nt)
        .ok()
        .expect("add node transfer");
    builder.build_signed(&signer).ok().expect("build signed")
}

/// A linked child block with a tweakable `vote` salt, so two blocks at the same
/// `(sequence, previous_hash)` get distinct hashes — for the tie-break test.
pub(super) fn salted_linked_block(seq: u32, prev: [u8; 32], vote: u32) -> Block {
    let signer = Crypto::new([1u8; PRIVATE_KEY_SIZE]).ok().expect("test key");
    let nt = NodeTransfer::new_signed(vote, seq.saturating_sub(1), 7, 9, 100, 1, 0, &signer);
    let header = BlockHeader {
        version: 1,
        sequence: seq,
        creator: 0,
        mined_amount: 0,
        payload_type: PAYLOAD_TYPE_TRANSACTION,
        consumed_votes: 0,
        first_voted_node: 0,
        consumed_votes_from_first_voted_node: 0,
        previous_hash: prev,
        signature: [0u8; SIGNATURE_SIZE],
    };
    let mut builder = BlockBuilder::new().header(header);
    builder
        .add_node_transfer(&nt)
        .ok()
        .expect("add node transfer");
    builder.build_signed(&signer).ok().expect("build signed")
}

/// The window [`W6Chain`]'s configurations declare: its whole capacity.
/// 6 is the smallest window with a legal horizon (configuration §6 check
/// 21: `H ≥ 3` divides `W`, `H < W`), and its horizon is 3, so the clean
/// slots (Story 6.7 D8) are the sequences `≡ 2 (mod 3)`.
pub(super) const W6: u32 = 6;

/// A test chain with a small active-chain capacity (`SNAKE_CHAIN_LENGTH_MAX =
/// 6`), configured with a window of the same length, so an active-length
/// segment fits the test harness's block storage. Same shape as
/// `new_test_chain` otherwise (local_node_id 5, join/Collecting), but on
/// [`W6Storage`].
pub(super) type W6Chain = Blockchain<Crypto, W6Storage, TestConfig, 16, 6, 16, 4, TEST_UTXO_BYTES>;

/// The W6 harness's storage: fourteen block slots. A window-anchored join
/// holds `W + H = 9` blocks; the others are kept for forks and extensions
/// (a switch across the seed points needs a four-block branch beside the
/// join).
pub(super) type W6Storage = MemoryBackend<{ 14 * MAX_BLOCK_SIZE + 8000 }>;

/// A [`W6Storage`] initialized as [`test_backends`]' storage is.
pub(super) fn w6_storage() -> W6Storage {
    let mut storage = W6Storage::new();
    storage
        .init([1u8; PRIVATE_KEY_SIZE], 0, [0u8; INIT_PARAMS_SIZE])
        .ok()
        .expect("the test backend initializes");
    storage
}

/// A [`W6Chain`] durably locked on its configuration (`W = 6`, `H = 3`),
/// Collecting.
pub(super) fn new_w6_chain() -> W6Chain {
    let (crypto, _, _) = test_backends();
    let storage = w6_storage();
    // This harness's own capacities, not `TestChain`'s: its window is 6.
    let mut chain_config = empty_chain_config(W6Chain::BUILD_LIMITS);
    chain_config
        .load_durable(window_config_builder(W6).build_signed(&crypto))
        .ok()
        .expect("the W6 configuration is accepted content");
    let node_zero = *crypto.public_key().serialize();
    let mut slot = core::mem::MaybeUninit::uninit();
    Blockchain::init(&mut slot, crypto, storage, chain_config, 5, node_zero, 0);
    // SAFETY: `init` returned, so every field of `slot` is initialized.
    unsafe { slot.assume_init() }
}

/// As [`new_w6_chain`], but holding **no** configuration — the joining node's
/// starting state on the small-window harness.
pub(super) fn new_unconfigured_w6_chain() -> W6Chain {
    let (crypto, _, _) = test_backends();
    let storage = w6_storage();
    let chain_config = empty_chain_config(W6Chain::BUILD_LIMITS);
    let node_zero = *crypto.public_key().serialize();
    let mut slot = core::mem::MaybeUninit::uninit();
    Blockchain::init(&mut slot, crypto, storage, chain_config, 5, node_zero, 0);
    // SAFETY: `init` returned, so every field of `slot` is initialized.
    unsafe { slot.assume_init() }
}

/// A `payload_type=1` block carrying a single registration transaction,
/// linked to `prev`. Signatures are placeholders — FR3 derivation does not
/// verify them (FR6 signature validation is Story 5.4).
pub(super) fn registration_block(
    seq: u32,
    prev: [u8; 32],
    initializer: u32,
    new_node_id: u32,
    pk_byte: u8,
) -> Block {
    // Story 5.4 verifies BOTH signatures of a registration against DIFFERENT
    // keys, and enforces `new_public_key` uniqueness — so a valid registration
    // needs two signers: the **initializer** ([1u8], the universal seeded key —
    // see `balance_block`) signs the transaction, and the **new node key**
    // ([pk_byte], a distinct key giving a unique `new_public_key`) signs the
    // proof-of-possession. `Registration::new_signed` uses one signer for both,
    // which cannot express a cross-key registration, so build it via
    // `Registration::new` with the two signatures computed separately.
    let init_signer = Crypto::new([1u8; PRIVATE_KEY_SIZE]).ok().expect("init key");
    let new_signer = Crypto::new([pk_byte; PRIVATE_KEY_SIZE])
        .ok()
        .expect("new key");
    let new_pk = *new_signer.public_key().serialize();
    let mut new_key_sig = [0u8; SIGNATURE_SIZE];
    new_key_sig.copy_from_slice(&new_signer.prove_possession().serialize()[..SIGNATURE_SIZE]);
    // The transaction signature signs the tx bytes with its signature field
    // zeroed and the new-key signature already present (the `new_signed`
    // convention), produced here by the initializer's key.
    let zero = [0u8; SIGNATURE_SIZE];
    let unsigned = Registration::new(
        0,
        initializer,
        new_node_id,
        50,
        1,
        &new_pk,
        &new_key_sig,
        &zero,
    );
    let mut tx_sig = [0u8; SIGNATURE_SIZE];
    tx_sig.copy_from_slice(&init_signer.sign(unsigned.as_bytes()).serialize()[..SIGNATURE_SIZE]);
    let reg = Registration::new(
        0,
        initializer,
        new_node_id,
        50,
        1,
        &new_pk,
        &new_key_sig,
        &tx_sig,
    );
    let signer = init_signer;
    let header = BlockHeader {
        version: 1,
        sequence: seq,
        creator: 0,
        mined_amount: 0,
        payload_type: PAYLOAD_TYPE_TRANSACTION,
        consumed_votes: 0,
        first_voted_node: 0,
        consumed_votes_from_first_voted_node: 0,
        previous_hash: prev,
        signature: [0u8; SIGNATURE_SIZE],
    };
    let mut builder = BlockBuilder::new().header(header);
    builder
        .add_registration(&reg)
        .ok()
        .expect("add registration");
    builder.build_signed(&signer).ok().expect("build signed")
}

/// A `payload_type=2` balance block with one `NodeInfo` entry per
/// `(owner, balance, vote_count, pk_byte)` tuple, and the given `max_node_id`.
/// A validly-signed chain-config block carrying the **base override set** —
/// the exact content `new_test_chain`'s configuration is locked on, so it
/// satisfies the FR6/FR8 content-identity check — chained to `prev`.
///
/// Every fixture that drives a candidate to a successful pass needs one of
/// these, because the FR8 final check (Story 5.9, AC3) makes a candidate
/// segment without a chain-config block in scope invalid. Placed as the
/// segment's **anchor** (lowest sequence) so it is provably inert with
/// respect to everything the fixtures assert: the shared FR37/FR36 tail runs
/// against all-zero derived state at that point, so the anti-capture interest
/// is 0 (growth on 0 is 0), the creator-vote reset overwrites a 0 with a 0,
/// and `mined_amount = 0` credits nothing. A fixture's original purpose is
/// therefore preserved exactly, not approximately.
///
/// `creator` is node 0, which the fixtures leave unseeded — so the
/// per-creator FR6 checks are skipped by the pre-seed-zone rule — and which
/// signs with the universal test key anyway, so the block is well-formed even
/// where a fixture *does* seed node 0.
pub(super) fn chain_config_anchor_block(seq: u32, prev: [u8; 32]) -> Block {
    chain_config_block_from(seq, prev, &mut window_config_builder(TEST_W))
}

/// [`chain_config_anchor_block`] for the [`W6Chain`] harness, whose
/// configuration declares its own window, [`W6`].
pub(super) fn w6_config_anchor_block(seq: u32, prev: [u8; 32]) -> Block {
    chain_config_block_from(seq, prev, &mut window_config_builder(W6))
}

/// A chain-config block at `seq`, chained to `prev`, carrying whatever
/// content `payload_builder` has framed, signed by node #0 over exactly that
/// content region.
///
/// Takes the builder by `&mut` because `build_signed` returns a slice of the
/// builder's own buffer; the caller owns the builder so the borrow outlives
/// the call.
pub(super) fn chain_config_block_from(
    seq: u32,
    prev: [u8; 32],
    payload_builder: &mut ChainConfigPayloadBuilder,
) -> Block {
    chain_config_block_mined(seq, prev, payload_builder, 0)
}

/// [`chain_config_block_from`] with a `mined_amount`: on a chain that declares
/// a `mining_reward`, every non-genesis block must carry it (FR6, Story 7.2).
pub(super) fn chain_config_block_mined(
    seq: u32,
    prev: [u8; 32],
    payload_builder: &mut ChainConfigPayloadBuilder,
    mined_amount: u32,
) -> Block {
    let signer = Crypto::new([1u8; PRIVATE_KEY_SIZE]).ok().expect("test key");
    let header = BlockHeader {
        version: 1,
        sequence: seq,
        creator: 0,
        mined_amount,
        payload_type: PAYLOAD_TYPE_CHAIN_CONFIG,
        consumed_votes: 0,
        first_voted_node: 0,
        consumed_votes_from_first_voted_node: 0,
        previous_hash: prev,
        signature: [0u8; SIGNATURE_SIZE],
    };
    let payload = payload_builder.build_signed(&signer);
    let mut builder = BlockBuilder::new().header(header);
    builder
        .set_chain_config_payload(payload)
        .ok()
        .expect("override set fits the payload");
    builder.build_signed(&signer).ok().expect("build signed")
}

/// A **second, equally valid** override set, distinct in bytes from the base
/// one: the base entries plus a literal declaring `mining_reward`'s own
/// default value 0. It resolves every parameter identically to the base set, so a node
/// adopting it behaves the same — the only thing that differs is the content
/// bytes, which is exactly what the FR7/FR8 byte-identity rules turn on.
pub(super) fn alt_config_builder() -> ChainConfigPayloadBuilder {
    let mut builder = window_config_builder(TEST_W);
    builder
        .add_literal(parameter::MINING_REWARD, &0u32.to_le_bytes())
        .ok()
        .expect("one literal entry is well-formed");
    builder
}

/// A deliberately small — but entirely legal — `block_size_limit`, used to
/// build a tentative configuration that disagrees with a candidate's own.
/// Above `HEADER_SIZE`, so the configuration module accepts it, and far
/// below the build's block capacity, so a realistic block can exceed it.
///
/// Five bytes above the largest of the test configuration block (its
/// 32-byte content: the four-byte `W`, `H`, block-size and node-cap entries
/// and the one-byte scheme and support entries), the one-entry balance
/// block and the one-transfer block (a clean slot's, Story 6.7 D8), so all
/// fit; below the three-entry balance block and the three-output
/// transaction block the fixtures exceed it with. Derived from the scheme's
/// sizes (Story 6.17): 230 / 231 / 294 B under `schnorr` / `bls-min-sig` /
/// `bls-min-pk`, against 254 / 430 / 334 B for the smaller of the two large
/// fixtures.
pub(super) const SMALL_BLOCK_SIZE_LIMIT: u32 = {
    let config_block = HEADER_SIZE + 32 + SIGNATURE_SIZE;
    let balance_block = HEADER_SIZE + 8 + NODE_INFO_SIZE;
    let transfer_block = HEADER_SIZE + 2 + moonblokz_chain_types::NODE_TRANSFER_SIZE;
    let mut largest = config_block;
    if balance_block > largest {
        largest = balance_block;
    }
    if transfer_block > largest {
        largest = transfer_block;
    }
    (largest + 5) as u32
};

/// An override set declaring [`SMALL_BLOCK_SIZE_LIMIT`] and the window `w`.
/// It also declares `required_support = 1`: a limit this small leaves room
/// only for a one-signer approval evidence, and acceptance refuses a limit
/// below the evidence the declared threshold needs (configuration §6
/// check 20; the default threshold 40 needs well over a kilobyte).
pub(super) fn small_limit_config_builder(w: u32) -> ChainConfigPayloadBuilder {
    let mut builder = window_config_builder(w);
    builder
        .add_literal(
            parameter::BLOCK_SIZE_LIMIT,
            &SMALL_BLOCK_SIZE_LIMIT.to_le_bytes(),
        )
        .ok()
        .expect("a four-byte literal is well-formed");
    builder
        .add_literal(parameter::REQUIRED_SUPPORT, &[1])
        .ok()
        .expect("a one-byte literal is well-formed");
    builder
}

/// The content region of a chain-config block, as the FR7/FR8 comparisons
/// see it.
pub(super) fn content_of(block: &Block) -> &[u8] {
    block
        .view()
        .chain_config()
        .expect("a chain-config block frames")
        .content()
}

/// Admits a [`chain_config_anchor_block`] at `seq` chained to `prev` and
/// returns its hash, for use as the next block's `previous_hash`. The block
/// is deliberately admitted through `tier1_admit`, so the FR7 content
/// signature is really verified on the way in.
/// The test window's override set plus `mining_reward = reward` (ID 5).
pub(super) fn rewarded_config_builder(reward: u32) -> ChainConfigPayloadBuilder {
    let mut builder = window_config_builder(TEST_W);
    builder
        .add_literal(parameter::MINING_REWARD, &reward.to_le_bytes())
        .ok()
        .expect("a four-byte literal is well-formed");
    builder
}

/// [`new_test_chain`] durably locked on [`rewarded_config_builder`], for the
/// FR36 (a) credit tests: since Story 7.2 a block's `mined_amount` must equal
/// the chain's `mining_reward` (FR6, DEC-217), so a credit is observable only
/// on a chain that declares one.
pub(super) fn rewarded_test_chain(reward: u32) -> TestChain {
    let (crypto, storage, _) = test_backends();
    let mut chain_config = empty_chain_config(TestChain::BUILD_LIMITS);
    chain_config
        .load_durable(rewarded_config_builder(reward).build_signed(&crypto))
        .ok()
        .expect("a rewarded override set is accepted content");
    let node_zero = *crypto.public_key().serialize();
    let mut bc_slot = core::mem::MaybeUninit::<TestChain>::uninit();
    TestChain::init(&mut bc_slot, crypto, storage, chain_config, 5, node_zero, 0);
    // SAFETY: `init` returned, so every field of `bc_slot` is initialized.
    unsafe { bc_slot.assume_init() }
}

/// [`admit_chain_config_anchor`] for a [`rewarded_test_chain`]: the anchor
/// carries the rewarded content and the reward as its `mined_amount`.
pub(super) fn admit_rewarded_anchor(
    bc: &mut TestChain,
    seq: u32,
    prev: [u8; 32],
    reward: u32,
) -> [u8; 32] {
    let cfg = chain_config_block_mined(seq, prev, &mut rewarded_config_builder(reward), reward);
    let hash = cfg.view().hash();
    bc.tier1_admit(&cfg.view(), &hash, 0)
        .expect("chain-config anchor admitted");
    hash
}

pub(super) fn admit_chain_config_anchor(bc: &mut TestChain, seq: u32, prev: [u8; 32]) -> [u8; 32] {
    let cfg = chain_config_anchor_block(seq, prev);
    let hash = cfg.view().hash();
    bc.tier1_admit(&cfg.view(), &hash, 0)
        .expect("chain-config anchor admitted");
    hash
}

pub(super) fn balance_block(
    seq: u32,
    prev: [u8; 32],
    entries: &[(u32, u64, u32, u8)],
    max_node_id: u32,
) -> Block {
    balance_block_mined(seq, prev, entries, max_node_id, 0)
}

/// [`balance_block`] with a `mined_amount` (a chain declaring a
/// `mining_reward`, Story 7.2).
pub(super) fn balance_block_mined(
    seq: u32,
    prev: [u8; 32],
    entries: &[(u32, u64, u32, u8)],
    max_node_id: u32,
    mined: u32,
) -> Block {
    use moonblokz_chain_types::NodeInfo;
    let signer = Crypto::new([1u8; PRIVATE_KEY_SIZE]).ok().expect("test key");
    // Seed every node with the *real* universal test public key (node zero's,
    // = `pubkey([1u8])`), not a raw `[pk_byte; 32]` pattern: Story 5.4 verifies
    // block-creator + transaction signatures against the derived key, and all
    // test blocks/txs are `[1u8]`-signed — so a seeded node's key must be a
    // genuine key that key produces. `pk_byte` is retained in the tuple API
    // for call-site readability but no longer distinguishes the stored key.
    let real_key = *signer.public_key().serialize();
    let header = BlockHeader {
        version: 1,
        sequence: seq,
        creator: 0,
        mined_amount: mined,
        payload_type: PAYLOAD_TYPE_BALANCE,
        consumed_votes: 0,
        first_voted_node: 0,
        consumed_votes_from_first_voted_node: 0,
        previous_hash: prev,
        signature: [0u8; SIGNATURE_SIZE],
    };
    let mut builder = BlockBuilder::new().header(header);
    for &(owner, balance, vote_count, _pk_byte) in entries {
        let ni = NodeInfo::new(owner, balance, vote_count, &real_key);
        builder.add_node_info(&ni).ok().expect("add node info");
    }
    builder
        .set_max_node_id(max_node_id)
        .ok()
        .expect("set max node id");
    builder.build_signed(&signer).ok().expect("build signed")
}

/// A `payload_type=1` block with a single node transfer of `amount` (+`fee`)
/// from `initializer` to `receiver`, linked to `prev`.
pub(super) fn transfer_block(
    seq: u32,
    prev: [u8; 32],
    initializer: u32,
    receiver: u32,
    amount: u64,
    fee: u32,
    vote: u32,
) -> Block {
    let signer = Crypto::new([1u8; PRIVATE_KEY_SIZE]).ok().expect("test key");
    let nt = NodeTransfer::new_signed(
        vote,
        seq.saturating_sub(1),
        initializer,
        receiver,
        amount,
        fee,
        0,
        &signer,
    );
    let header = BlockHeader {
        version: 1,
        sequence: seq,
        creator: 0,
        mined_amount: 0,
        payload_type: PAYLOAD_TYPE_TRANSACTION,
        consumed_votes: 0,
        first_voted_node: 0,
        consumed_votes_from_first_voted_node: 0,
        previous_hash: prev,
        signature: [0u8; SIGNATURE_SIZE],
    };
    let mut builder = BlockBuilder::new().header(header);
    builder.add_node_transfer(&nt).ok().expect("add transfer");
    builder.build_signed(&signer).ok().expect("build signed")
}

/// Carries `bc`'s durable storage into a brand-new node. The new node gets a
/// fresh, *unconfigured* configuration module and an empty tree: everything
/// it ends up holding, it recovered from the durable footprint.
pub(super) fn restart(bc: TestChain) -> TestChain {
    let storage = bc.storage;
    let crypto = Crypto::new([1u8; PRIVATE_KEY_SIZE])
        .ok()
        .expect("test private key should be accepted by the backend");
    let chain_config = empty_chain_config(TestChain::BUILD_LIMITS);
    new_chain(crypto, storage, chain_config, 5, 0)
}

/// The three blocks below every W6 window-anchored segment, #97, #98 and
/// #99: with `H = 3` a window-anchored join needs `W + H = 9` blocks
/// (DEC-177), so each segment `100..` starts three blocks lower, and they
/// then lie in the FR58 horizon below the window `100..=105`. #97 is an
/// orphan. Plain transfers: they carry no essential state, so dropping
/// them binds nothing, and #98, a clean slot (Story 6.7 D8), is one. Their
/// vote names the creator, node #0, whose vote the creator-vote reset
/// clears in the same block, so they move no vote: a restart that
/// re-admits one from its released slot (lazy release) and re-derives over
/// it reaches the projection a node fed only the retained blocks does
/// (AC12.6, [`the_horizon_holds_only_the_active_path`]).
pub(super) fn w6_below() -> [Block; 3] {
    let b97 = salted_linked_block(97, [0xAB; 32], 0);
    let b98 = salted_linked_block(98, b97.view().hash(), 0);
    let b99 = salted_linked_block(99, b98.view().hash(), 0);
    [b97, b98, b99]
}

/// The top block below the window, #99 (see [`w6_below`]).
pub(super) fn w6_horizon_block() -> Block {
    let [_, _, b99] = w6_below();
    b99
}

/// A clean (Story 6.7 D8) block at `seq` on `prev`: one node transfer of
/// nothing, fee 0, by node #0 to itself, voting for its creator. Valid
/// wherever node #0 is seeded, so it extends a Ready W6 head at any
/// position, a clean slot included.
pub(super) fn w6_clean_block(seq: u32, prev: [u8; 32]) -> Block {
    let signer = Crypto::new([1u8; PRIVATE_KEY_SIZE]).ok().expect("test key");
    let nt = NodeTransfer::new_signed(0, seq - 1, 0, 0, 0, 0, 0, &signer);
    tx_block(seq, prev, 0, |b| {
        b.add_node_transfer(&nt).ok().expect("add transfer");
    })
}

pub(super) fn slot_of(bc: &W6Chain, seq: u32, hash: &[u8; 32]) -> Option<u32> {
    bc.blocks.find(seq, hash)
}

/// Receives `block` as a child of the active head; the Story 6.0 forward
/// extension makes it the new head and, past `W`, advances the tail.
pub(super) fn extend_active_head(bc: &mut W6Chain, block: &Block, now: u64) -> u32 {
    let (outcome, _) = bc.receive_block(block.view(), now);
    assert_eq!(outcome, ReceiveBlockOutcome::AcceptedSilently);
    let view = block.view();
    let idx = slot_of(bc, view.sequence(), &view.hash()).expect("stored");
    assert_eq!(bc.active_chain_head_idx, idx, "the extension is the head");
    assert_eq!(
        bc.blocks.get(idx).map(|e| e.status()),
        Some(BlockStatus::Active)
    );
    idx
}

/// A `payload_type=1` block of complex transactions, chained to `prev` and
/// created by `creator`. The UTXO-side builder deferred-work D32 asked for.
/// The header is in override form (`first_voted_node == creator`,
/// Story 6.7 D4): a block by a creator other than `first_voted_node` is a
/// deviation, whose open run would bind every block above it.
pub(super) fn complex_tx_block(
    seq: u32,
    prev: [u8; 32],
    creator: u32,
    mined_amount: u32,
    txs: &[&moonblokz_chain_types::ComplexTransaction],
) -> Block {
    let signer = Crypto::new([1u8; PRIVATE_KEY_SIZE]).ok().expect("test key");
    let header = BlockHeader {
        version: 1,
        sequence: seq,
        creator,
        mined_amount,
        payload_type: PAYLOAD_TYPE_TRANSACTION,
        consumed_votes: 0,
        first_voted_node: creator,
        consumed_votes_from_first_voted_node: 0,
        previous_hash: prev,
        signature: [0u8; SIGNATURE_SIZE],
    };
    let mut builder = BlockBuilder::new().header(header);
    for tx in txs {
        builder
            .add_complex_transaction(tx)
            .ok()
            .expect("add complex");
    }
    builder.build_signed(&signer).ok().expect("build signed")
}

/// One complex transaction (vote 0, the node-#0 exception): the given
/// UTXO inputs `(block_sequence, output_index, declared amount)`, an optional balance input
/// `(initializer, amount)` anchored just below `seq`, then the outputs, each
/// `Ok(amount)` for a UTXO output or `Err((receiver, amount))` for a
/// balance output, in order.
pub(super) fn utxo_tx(
    seq: u32,
    utxo_inputs: &[(u32, u16, u64)],
    balance_input: Option<(u32, u64)>,
    outputs: &[Result<u64, (u32, u64)>],
) -> moonblokz_chain_types::ComplexTransaction {
    utxo_tx_vote(0, seq, utxo_inputs, balance_input, outputs)
}

/// [`utxo_tx`] whose `vote` names `vote`.
pub(super) fn utxo_tx_vote(
    vote: u32,
    seq: u32,
    utxo_inputs: &[(u32, u16, u64)],
    balance_input: Option<(u32, u64)>,
    outputs: &[Result<u64, (u32, u64)>],
) -> moonblokz_chain_types::ComplexTransaction {
    let signer = Crypto::new([1u8; PRIVATE_KEY_SIZE]).ok().expect("test key");
    utxo_tx_signed(vote, seq, utxo_inputs, balance_input, outputs, &signer)
}

/// [`utxo_tx_vote`] with every input signed by `signer` (DEC-196). Every UTXO
/// output pays the universal test key (`pubkey([1u8])`), the key every seeded
/// test node holds, so a `[1u8]`-signed spend of it verifies.
pub(super) fn utxo_tx_signed(
    vote: u32,
    seq: u32,
    utxo_inputs: &[(u32, u16, u64)],
    balance_input: Option<(u32, u64)>,
    outputs: &[Result<u64, (u32, u64)>],
    signer: &Crypto,
) -> moonblokz_chain_types::ComplexTransaction {
    let address = *Crypto::new([1u8; PRIVATE_KEY_SIZE])
        .ok()
        .expect("test key")
        .public_key()
        .serialize();
    let mut cx = moonblokz_chain_types::ComplexTransaction::new(vote);
    for &(block_sequence, output_index, amount) in utxo_inputs {
        cx.add_utxo_input(block_sequence, output_index, amount, &[0u8; SIGNATURE_SIZE])
            .ok()
            .expect("add utxo input");
    }
    if let Some((initializer, amount)) = balance_input {
        cx.add_balance_input(seq - 1, initializer, amount, 0, &[0u8; SIGNATURE_SIZE])
            .ok()
            .expect("add balance input");
    }
    for output in outputs {
        match *output {
            Ok(amount) => cx.add_utxo_output(&address, amount),
            Err((receiver, amount)) => cx.add_balance_output(receiver, amount),
        }
        .ok()
        .expect("add output");
    }
    sign_inputs(&mut cx, signer);
    cx
}

/// A key no seeded test node holds: its signatures verify against nothing.
pub(super) fn other_key() -> Crypto {
    Crypto::new([2u8; PRIVATE_KEY_SIZE]).ok().expect("test key")
}

/// The signatures of `cx`'s inputs, in order.
pub(super) fn input_signatures(
    cx: &moonblokz_chain_types::ComplexTransaction,
) -> std::vec::Vec<std::vec::Vec<u8>> {
    let view = TransactionView::from_bytes(cx.as_bytes()).expect("a transaction");
    view.as_complex()
        .expect("complex")
        .inputs()
        .map(|input| match (input.as_utxo(), input.as_balance()) {
            (Some(u), _) => u.signature().to_vec(),
            (_, Some(b)) => b.signature().to_vec(),
            _ => unreachable!("an input is UTXO or balance"),
        })
        .collect()
}

/// Signs every input of `cx` with `signer` over the DEC-196 preimage.
pub(super) fn sign_inputs(cx: &mut moonblokz_chain_types::ComplexTransaction, signer: &Crypto) {
    let mut buf = [0u8; moonblokz_chain_types::MAX_TRANSACTION_SIZE];
    let len = TransactionView::from_bytes(cx.as_bytes())
        .and_then(|view| view.input_signing_preimage(&mut buf).map(|p| p.len()))
        .expect("a complex transaction");
    let signature = signer.sign(&buf[..len]);
    let inputs = cx.as_bytes()[5];
    for i in 0..inputs {
        cx.set_input_signature(i, signature.serialize())
            .ok()
            .expect("input exists");
    }
}

pub(super) fn admit(bc: &mut TestChain, block: &Block) -> u32 {
    bc.tier1_admit(&block.view(), &block.view().hash(), 0)
        .expect("block admitted")
}

/// The UTXO harness: a chain-config anchor at 99, then a balance block at
/// 100 seeding node 1 with 100 and nodes 2 and 3 (the creator) with 0.
pub(super) fn utxo_test_chain() -> (TestChain, [u8; 32]) {
    let mut bc = new_test_chain();
    let cfg_hash = admit_chain_config_anchor(&mut bc, 99, [0xAB; 32]);
    let seed = balance_block(
        100,
        cfg_hash,
        &[(1, 100, 0, 0x31), (2, 0, 0, 0x32), (3, 0, 0, 0x33)],
        3,
    );
    admit(&mut bc, &seed);
    (bc, seed.view().hash())
}

/// A storage backend whose reads of one slot start failing after a set
/// number of successful ones, counting every attempt on that slot. The
/// fault lasts `failures_left` reads (persistent by default).
/// `N` is the inner backend's size: 8 slots unless a test needs more
/// (Story 6.5's longer chain uses 16).
pub(super) struct FailingReadStorage<const N: usize = { 8 * MAX_BLOCK_SIZE + 8000 }> {
    pub(super) inner: MemoryBackend<N>,
    pub(super) failing_slot: u32,
    pub(super) reads_left: core::cell::Cell<u32>,
    pub(super) failures_left: core::cell::Cell<u32>,
    pub(super) attempts: core::cell::Cell<u32>,
    /// Every read, of any slot (Story 6.4 AC9 3d).
    pub(super) reads: core::cell::Cell<u32>,
}

impl<const N: usize> StorageTrait for FailingReadStorage<N> {
    fn init(
        &mut self,
        private_key: [u8; PRIVATE_KEY_SIZE],
        own_node_id: u32,
        init_params: [u8; INIT_PARAMS_SIZE],
    ) -> Result<(), StorageError> {
        self.inner.init(private_key, own_node_id, init_params)
    }

    fn save_block(&mut self, idx: u32, block: &Block) -> Result<(), StorageError> {
        self.inner.save_block(idx, block)
    }

    fn read_block_into(
        &self,
        idx: u32,
        out: &mut [u8; MAX_BLOCK_SIZE],
    ) -> Result<(), StorageError> {
        self.reads.set(self.reads.get() + 1);
        if idx == self.failing_slot {
            self.attempts.set(self.attempts.get() + 1);
            let left = self.reads_left.get();
            if left == 0 {
                let failures = self.failures_left.get();
                if failures > 0 {
                    self.failures_left.set(failures - 1);
                    return Err(StorageError::BackendIo { code: 9 });
                }
            } else {
                self.reads_left.set(left - 1);
            }
        }
        self.inner.read_block_into(idx, out)
    }

    fn capacity(&self) -> u32 {
        self.inner.capacity()
    }

    fn set_chain_configuration(&mut self, block: &Block) -> Result<(), StorageError> {
        self.inner.set_chain_configuration(block)
    }

    fn load_control_data(&mut self) -> Result<ControlPlaneData, StorageError> {
        self.inner.load_control_data()
    }
}

/// Every chain of this section shares `TestChain`'s capacities; only the
/// storage differs (the fault-injecting one of AC6).
pub(super) type Chain16<S> =
    Blockchain<Crypto, S, TestConfig, 16, 16, TEST_MAX_BLOCKS, 4, TEST_UTXO_BYTES>;

/// The FR54 currency of every genesis node in this section.
pub(super) const CURRENCY: u64 = 1_000_000_000;

/// A node-#0 genesis node on `W = w`: Ready, with the complete projection
/// the per-block step derived over #0 / #1 (D6). Returns it with the two
/// genesis blocks.
pub(super) fn ready_genesis(w: u32) -> (TestChain, Block, Block) {
    let (crypto, storage, chain_config) = test_backends();
    let mut bc = new_chain(crypto, storage, chain_config, 0, 0);
    let genesis = bc
        .process_genesis(CURRENCY, window_config_builder(w).content())
        .ok()
        .expect("genesis succeeds");
    (bc, genesis.block_zero, genesis.block_one)
}

/// [`ready_genesis`] on `W = 6` over the W6 harness's fourteen-slot
/// storage ([`W6Storage`]): a full window and a branch as long as it fit.
pub(super) fn ready_genesis_w6() -> (Chain16<W6Storage>, Block, Block) {
    let (crypto, _, chain_config) = test_backends();
    let node_zero = *crypto.public_key().serialize();
    let mut slot = core::mem::MaybeUninit::<Chain16<W6Storage>>::uninit();
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
    let mut bc = unsafe { slot.assume_init() };
    let genesis = bc
        .process_genesis(CURRENCY, window_config_builder(W6).content())
        .ok()
        .expect("genesis succeeds");
    (bc, genesis.block_zero, genesis.block_one)
}

pub(super) fn head_of<S: StorageTrait>(bc: &Chain16<S>) -> (u32, [u8; 32]) {
    let entry = bc.blocks.get(bc.active_chain_head_idx).expect("a head");
    (entry.sequence(), *entry.hash())
}

pub(super) fn receive<S: StorageTrait>(bc: &mut Chain16<S>, block: &Block) -> ReceiveBlockOutcome {
    bc.receive_block(block.view(), 0).0
}

/// A registration of `new_node_id` by `initializer`, its key from
/// `pk_byte` (the cross-key construction of [`registration_block`]).
pub(super) fn registration_tx(initializer: u32, new_node_id: u32, pk_byte: u8) -> Registration {
    let init_signer = Crypto::new([1u8; PRIVATE_KEY_SIZE]).ok().expect("init key");
    let new_signer = Crypto::new([pk_byte; PRIVATE_KEY_SIZE])
        .ok()
        .expect("new key");
    let new_pk = *new_signer.public_key().serialize();
    let mut new_key_sig = [0u8; SIGNATURE_SIZE];
    new_key_sig.copy_from_slice(&new_signer.prove_possession().serialize()[..SIGNATURE_SIZE]);
    let zero = [0u8; SIGNATURE_SIZE];
    let unsigned = Registration::new(
        0,
        initializer,
        new_node_id,
        50,
        1,
        &new_pk,
        &new_key_sig,
        &zero,
    );
    let mut tx_sig = [0u8; SIGNATURE_SIZE];
    tx_sig.copy_from_slice(&init_signer.sign(unsigned.as_bytes()).serialize()[..SIGNATURE_SIZE]);
    Registration::new(
        0,
        initializer,
        new_node_id,
        50,
        1,
        &new_pk,
        &new_key_sig,
        &tx_sig,
    )
}

/// A transaction block by node #0 with `mined_amount`, its payload added
/// by `add`.
pub(super) fn tx_block(
    seq: u32,
    prev: [u8; 32],
    mined: u32,
    add: impl FnOnce(&mut BlockBuilder),
) -> Block {
    let signer = Crypto::new([1u8; PRIVATE_KEY_SIZE]).ok().expect("test key");
    let header = BlockHeader {
        version: 1,
        sequence: seq,
        creator: 0,
        mined_amount: mined,
        payload_type: PAYLOAD_TYPE_TRANSACTION,
        consumed_votes: 0,
        first_voted_node: 0,
        consumed_votes_from_first_voted_node: 0,
        previous_hash: prev,
        signature: [0u8; SIGNATURE_SIZE],
    };
    let mut builder = BlockBuilder::new().header(header);
    add(&mut builder);
    builder.build_signed(&signer).ok().expect("build signed")
}

/// A node #0 → `receiver` transfer of `amount` (fee 1, vote 0).
pub(super) fn transfer_tx(seq: u32, receiver: u32, amount: u64) -> NodeTransfer {
    let signer = Crypto::new([1u8; PRIVATE_KEY_SIZE]).ok().expect("test key");
    NodeTransfer::new_signed(0, seq - 1, 0, receiver, amount, 1, 0, &signer)
}

pub(super) fn transfer(seq: u32, prev: [u8; 32], receiver: u32, amount: u64) -> Block {
    let nt = transfer_tx(seq, receiver, amount);
    tx_block(seq, prev, 0, |b| {
        b.add_node_transfer(&nt).ok().expect("add transfer");
    })
}

pub(super) fn register(seq: u32, prev: [u8; 32], new_node_id: u32, pk_byte: u8) -> Block {
    let reg = registration_tx(0, new_node_id, pk_byte);
    tx_block(seq, prev, 0, |b| {
        b.add_registration(&reg).ok().expect("add registration");
    })
}

/// Node #0's current `(balance, vote_count)` — a matching D9 snapshot.
pub(super) fn node_zero_snapshot<S: StorageTrait>(bc: &Chain16<S>) -> (u32, u64, u32, u8) {
    (
        0,
        bc.node_info.balance_of(0),
        bc.vote_engine.accumulated_vote_of(0),
        0,
    )
}

/// The reason the fallible half of the step gives for `block` as an
/// extension of the head, run on a scratch entry that is removed again.
/// `None` on success, whose effects are then inverted, so either way the
/// node is left as it was.
pub(super) fn step_reason<S: StorageTrait>(
    bc: &mut Chain16<S>,
    block: &Block,
) -> Option<ValidationReason> {
    let view = block.view();
    let idx = bc.blocks.next_free_index().expect("a free slot");
    let head = bc.active_chain_head_idx;
    let head_hash = *bc.blocks.get(head).expect("head").hash();
    bc.blocks
        .insert_at(idx, BlockEntry::new(view.hash(), head, view.sequence()));
    let mut projection = Projection::COMPLETE;
    let reason = match bc.derive_block(&view, idx, Some(head_hash), &mut projection) {
        Ok(_) => {
            bc.invert_transactions(&view, idx, usize::MAX);
            None
        }
        Err(ProcessingError::Invalid { reason, .. }) => Some(reason),
        Err(other) => panic!("not a validation failure: {other:?}"),
    };
    bc.blocks.delete(idx);
    reason
}

/// A backend that can fail reads of one slot and every block write.
pub(super) struct FaultyStorage {
    inner: MemoryBackend<{ 8 * MAX_BLOCK_SIZE + 8000 }>,
    pub(super) failing_read_slot: u32,
    pub(super) fail_saves: bool,
}

impl StorageTrait for FaultyStorage {
    fn init(
        &mut self,
        private_key: [u8; PRIVATE_KEY_SIZE],
        own_node_id: u32,
        init_params: [u8; INIT_PARAMS_SIZE],
    ) -> Result<(), StorageError> {
        self.inner.init(private_key, own_node_id, init_params)
    }

    fn save_block(&mut self, idx: u32, block: &Block) -> Result<(), StorageError> {
        if self.fail_saves {
            return Err(StorageError::BackendIo { code: 7 });
        }
        self.inner.save_block(idx, block)
    }

    fn read_block_into(
        &self,
        idx: u32,
        out: &mut [u8; MAX_BLOCK_SIZE],
    ) -> Result<(), StorageError> {
        if idx == self.failing_read_slot {
            return Err(StorageError::BackendIo { code: 9 });
        }
        self.inner.read_block_into(idx, out)
    }

    fn capacity(&self) -> u32 {
        self.inner.capacity()
    }

    fn set_chain_configuration(&mut self, block: &Block) -> Result<(), StorageError> {
        self.inner.set_chain_configuration(block)
    }

    fn load_control_data(&mut self) -> Result<ControlPlaneData, StorageError> {
        self.inner.load_control_data()
    }
}

/// [`utxo_genesis`] on a [`FaultyStorage`] whose faults are disarmed.
pub(super) fn faulty_utxo_genesis() -> (Chain16<FaultyStorage>, Block) {
    let crypto = Crypto::new([1u8; PRIVATE_KEY_SIZE]).ok().expect("key");
    let chain_config = empty_chain_config(TestChain::BUILD_LIMITS);
    let node_zero = *crypto.public_key().serialize();
    let storage = FaultyStorage {
        inner: initialized_storage([1u8; PRIVATE_KEY_SIZE]),
        failing_read_slot: NONE_REF,
        fail_saves: false,
    };
    let mut slot = core::mem::MaybeUninit::<Chain16<FaultyStorage>>::uninit();
    Chain16::<FaultyStorage>::init(&mut slot, crypto, storage, chain_config, 0, node_zero, 0);
    // SAFETY: `init` returned, so every field of `slot` is initialized.
    let mut bc = unsafe { slot.assume_init() };
    let genesis = bc
        .process_genesis(CURRENCY, window_config_builder(16).content())
        .ok()
        .expect("genesis");
    let reg = register(2, genesis.block_one.view().hash(), 1, 0x31);
    assert_eq!(
        receive(&mut bc, &reg),
        ReceiveBlockOutcome::AcceptedSilently
    );
    // Its vote credits node #1 once, so a block of node #1 above it is
    // worth `I(1000)` (Story 6.3: the side-branch fixtures need an active
    // branch their small free values do not outrank).
    let mint_tx = utxo_tx_vote(1, 3, &[], Some((0, 100)), &[Ok(60), Ok(40)]);
    let mint = complex_tx_block(3, reg.view().hash(), 0, 0, &[&mint_tx]);
    assert_eq!(
        receive(&mut bc, &mint),
        ReceiveBlockOutcome::AcceptedSilently
    );
    (bc, mint)
}

/// A genesis node on `W = 6` ([`ready_genesis_w6`]) with #2..=#5 added
/// (transfers, clean on the slots #2 and #5, Story 6.7 D8): the window is
/// full (`0..=5`), and its tail #0 is node #0's seed source (its
/// registration).
pub(super) fn full_w6_genesis() -> (Chain16<W6Storage>, Block) {
    let (mut bc, _, b1) = ready_genesis_w6();
    let mut prev = b1;
    for seq in 2..=5 {
        let block = transfer(seq, prev.view().hash(), 0, 5 + u64::from(seq));
        assert_eq!(
            receive(&mut bc, &block),
            ReceiveBlockOutcome::AcceptedSilently
        );
        prev = block;
    }
    assert_eq!(bc.active_snake_chain_window(), Ok((0, 5)));
    (bc, prev)
}

pub(super) fn snapshot_block<S: StorageTrait>(bc: &Chain16<S>, seq: u32, prev: [u8; 32]) -> Block {
    balance_block(
        seq,
        prev,
        &[node_zero_snapshot(bc)],
        bc.node_info.max_known_node_id(),
    )
}

/// `block` rebuilt with header `consumed_votes` — its FR21 value — and
/// re-signed by node #0. Transaction and chain-config payloads. On the
/// active chain the value must be real (I-09, Story 6.2): use [`alt`] or
/// [`real_on`] there; `revalue` serves side blocks, which get no Tier 3.
pub(super) fn revalue(block: &Block, consumed_votes: u32) -> Block {
    let view = block.view();
    resign(block, view.creator(), consumed_votes, 1)
}

/// `block`'s payload under a header by `creator` (signed with the key
/// `[key; 32]`) in the normal vote form, worth `consumed_votes`.
pub(super) fn resign(block: &Block, creator: u32, consumed_votes: u32, key: u8) -> Block {
    let view = block.view();
    let signer = Crypto::new([key; PRIVATE_KEY_SIZE]).ok().expect("test key");
    let header = BlockHeader {
        version: view.version(),
        sequence: view.sequence(),
        creator,
        mined_amount: view.mined_amount(),
        payload_type: view.payload_type(),
        consumed_votes,
        first_voted_node: creator,
        consumed_votes_from_first_voted_node: 0,
        previous_hash: view.previous_hash().try_into().expect("32 bytes"),
        signature: [0u8; SIGNATURE_SIZE],
    };
    let mut builder = BlockBuilder::new().header(header);
    if let Some(txs) = view.transactions() {
        for tx in txs.iter() {
            builder
                .add_transaction_bytes(tx.as_bytes())
                .ok()
                .expect("transaction");
        }
    } else if let Some(payload) = view.balances() {
        use moonblokz_chain_types::NodeInfo;
        for info in payload.iter() {
            let key: [u8; PUBLIC_KEY_SIZE] = info.public_key().try_into().expect("public key");
            let ni = NodeInfo::new(info.owner(), info.balance(), info.vote_count(), &key);
            builder.add_node_info(&ni).ok().expect("add node info");
        }
        builder
            .set_max_node_id(payload.max_node_id())
            .ok()
            .expect("set max node id");
    } else {
        builder
            .set_chain_config_payload(view.payload())
            .ok()
            .expect("chain-config payload");
    }
    builder.build_signed(&signer).ok().expect("build signed")
}

/// A node #0 self-transfer of `amount` at `seq`, worth `value` — a free
/// header value, so for side blocks only (see [`revalue`]).
pub(super) fn valued(seq: u32, prev: [u8; 32], value: u32, amount: u64) -> Block {
    revalue(&transfer(seq, prev, 0, amount), value)
}

/// Node #1's key byte wherever these fixtures register it.
pub(super) const NODE_ONE_KEY: u8 = 0x31;

/// `I(av)`: FR37 step 1 under the test configuration (`vote_scale` 1000,
/// the default `vote_interest` 100, so the bump is `min(⌊av / 10⌋, 1000)`) — the
/// post-interest, pre-credit snapshot a block's `consumed_votes` carries
/// (DEC-156).
pub(super) fn vote_snapshot(av: u32) -> u32 {
    av + (av / 10).min(1000)
}

/// The FR21 value of `block`: its header `consumed_votes`.
pub(super) fn v(block: &Block) -> u64 {
    u64::from(block.view().consumed_votes())
}

/// `n` node-#0 self-transfers at `seq` whose `vote` names `target`, their
/// amounts from `salt` (distinct transactions).
pub(super) fn votes_for(
    seq: u32,
    target: u32,
    n: u32,
    salt: u64,
) -> impl FnOnce(&mut BlockBuilder) {
    move |b| {
        let signer = Crypto::new([1u8; PRIVATE_KEY_SIZE]).ok().expect("test key");
        for i in 0..n {
            let nt =
                NodeTransfer::new_signed(target, seq - 1, 0, 0, salt + u64::from(i), 1, 0, &signer);
            b.add_node_transfer(&nt).ok().expect("add vote");
        }
    }
}

/// An active-chain block by node `creator` (#0 or #1) carrying its real
/// FR21 value on a chain whose creators alternate between #0 and #1, each
/// block crediting only the next creator. `received` is the number of votes
/// the previous block cast for `creator`; under the per-target credit cap
/// (DEC-176, Story 7.2) any number of them is one credit, which is its whole
/// accumulated vote, since its own last block reset it — so `consumed_votes
/// = I(1000)` (1100 at the default `vote_interest` 100) when `received ≥ 1`, else
/// 0. The block casts `out` votes for the other node (or, with `out == 0`,
/// one for its own creator, which the reset wipes). `register` puts node
/// #1's registration first. The chains are shorter than `H`, so no liveness
/// credit (DEC-178) enters.
pub(super) fn alt(
    seq: u32,
    prev: [u8; 32],
    creator: u32,
    received: u32,
    out: u32,
    salt: u64,
    register: bool,
) -> Block {
    let other = 1 - creator;
    let template = tx_block(seq, prev, 0, |b| {
        if register {
            b.add_registration(&registration_tx(0, 1, NODE_ONE_KEY))
                .ok()
                .expect("add registration");
        }
        if out == 0 {
            votes_for(seq, creator, 1, salt)(b);
        } else {
            votes_for(seq, other, out, salt)(b);
        }
    });
    let key = if creator == 0 { 1 } else { NODE_ONE_KEY };
    resign(
        &template,
        creator,
        vote_snapshot(1000 * received.min(1)),
        key,
    )
}

/// `block` as `creator`'s (signed with `key`), worth its real FR21 value on
/// `state` — the chain whose active head is the block's parent (I-09).
pub(super) fn real_on<
    C: CryptoTrait,
    S: StorageTrait,
    G: ChainConfigTrait,
    const N: usize,
    const L: u32,
    const B: usize,
    const H: usize,
    const U: usize,
>(
    state: &Blockchain<C, S, G, N, L, B, H, U>,
    block: &Block,
    creator: u32,
    key: u8,
) -> Block {
    let av = state.vote_engine.accumulated_vote_of(creator);
    resign(block, creator, vote_snapshot(av), key)
}

/// FR21 by brute force: the values of `head`'s ancestry above `S_tail`,
/// read back from storage block by block.
pub(super) fn brute_value<
    C: CryptoTrait,
    S: StorageTrait,
    G: ChainConfigTrait,
    const N: usize,
    const L: u32,
    const B: usize,
    const H: usize,
    const U: usize,
>(
    bc: &Blockchain<C, S, G, N, L, B, H, U>,
    head: u32,
) -> u64 {
    let tail = bc
        .blocks
        .get(bc.snake_chain_tail_idx)
        .expect("a tail")
        .sequence();
    let mut sum = 0;
    let mut cur = head;
    loop {
        let entry = bc.blocks.get(cur).expect("on the path");
        if entry.sequence() <= tail {
            return sum;
        }
        let mut buf = [0u8; MAX_BLOCK_SIZE];
        sum += u64::from(
            bc.view_retained(cur, &mut buf)
                .expect("readable")
                .consumed_votes(),
        );
        cur = entry.parent_ref();
    }
}

pub(super) fn slot<
    C: CryptoTrait,
    S: StorageTrait,
    G: ChainConfigTrait,
    const N: usize,
    const L: u32,
    const B: usize,
    const H: usize,
    const U: usize,
>(
    bc: &Blockchain<C, S, G, N, L, B, H, U>,
    block: &Block,
) -> u32 {
    let view = block.view();
    bc.blocks
        .find(view.sequence(), &view.hash())
        .expect("retained")
}

pub(super) fn status_of<S: StorageTrait>(bc: &Chain16<S>, block: &Block) -> Option<BlockStatus> {
    let view = block.view();
    bc.blocks
        .find(view.sequence(), &view.hash())
        .and_then(|idx| bc.blocks.get(idx))
        .map(|entry| entry.status())
}

/// The window-anchored W6 segment `100..=105` with the values 2 (the
/// chain-config anchor), 3, 5, 7, 11, 13, Ready through FR3, above the
/// `H = 3` plain blocks of [`w6_below`] (the horizon). Returns the node
/// and the six window blocks.
pub(super) fn valued_w6() -> (W6Chain, [Block; 6]) {
    let mut bc = new_w6_chain();
    for below in w6_below() {
        bc.tier1_admit(&below.view(), &below.view().hash(), 0)
            .expect("a block below the window admitted");
    }
    let anchor = revalue(
        &w6_config_anchor_block(100, w6_horizon_block().view().hash()),
        2,
    );
    let mut prev = anchor.view().hash();
    let rest: [Block; 5] = core::array::from_fn(|i| {
        let blk = revalue(
            &linked_transfer_block(101 + i as u32, prev),
            [3, 5, 7, 11, 13][i],
        );
        prev = blk.view().hash();
        blk
    });
    let [b101, b102, b103, b104, b105] = rest;
    for blk in [&anchor, &b101, &b102, &b103, &b104, &b105] {
        bc.tier1_admit(&blk.view(), &blk.view().hash(), 0)
            .expect("admitted");
    }
    bc.drive_dominant_chain_acquisition();
    assert!(bc.is_ready(), "precondition: the segment validated");
    (bc, [anchor, b101, b102, b103, b104, b105])
}

/// A genesis node on a [`FaultyStorage`] whose faults are disarmed, on
/// `W = w`.
pub(super) fn faulty_genesis(w: u32) -> (Chain16<FaultyStorage>, Block) {
    let crypto = Crypto::new([1u8; PRIVATE_KEY_SIZE]).ok().expect("key");
    let chain_config = empty_chain_config(TestChain::BUILD_LIMITS);
    let node_zero = *crypto.public_key().serialize();
    let storage = FaultyStorage {
        inner: initialized_storage([1u8; PRIVATE_KEY_SIZE]),
        failing_read_slot: NONE_REF,
        fail_saves: false,
    };
    let mut slot = core::mem::MaybeUninit::<Chain16<FaultyStorage>>::uninit();
    Chain16::<FaultyStorage>::init(&mut slot, crypto, storage, chain_config, 0, node_zero, 0);
    // SAFETY: `init` returned, so every field of `slot` is initialized.
    let mut bc = unsafe { slot.assume_init() };
    let genesis = bc
        .process_genesis(CURRENCY, window_config_builder(w).content())
        .ok()
        .expect("genesis");
    (bc, genesis.block_one)
}

/// [`faulty_utxo_genesis`] with one more active block, so the mint at #3
/// is an older active block a side branch can fork from. Returns the node,
/// the mint and #4.
pub(super) fn utxo_side_fixture() -> (Chain16<FaultyStorage>, Block, Block) {
    let (mut bc, mint) = faulty_utxo_genesis();
    // Node #1's, credited once by the mint: worth `I(1000)` = 1100 (I-09),
    // above the free values the side blocks of these Tier 2 tests carry,
    // so none of them is switched to (Story 6.3).
    let b4 = real_on(&bc, &transfer(4, mint.view().hash(), 0, 7), 1, NODE_ONE_KEY);
    assert_eq!(receive(&mut bc, &b4), ReceiveBlockOutcome::AcceptedSilently);
    (bc, mint, b4)
}

/// A side block at `seq` on `prev` spending `(3, index)` with the declared
/// `amount` into one UTXO output.
pub(super) fn side_spend(seq: u32, prev: [u8; 32], index: u16, amount: u64) -> Block {
    let tx = utxo_tx(seq, &[(3, index, amount)], None, &[Ok(amount)]);
    complex_tx_block(seq, prev, 0, 0, &[&tx])
}

/// A transaction block with explicit vote header fields, signed with
/// `[key; 32]` — deviation blocks and malformed headers.
#[allow(clippy::too_many_arguments)]
pub(super) fn headed(
    seq: u32,
    prev: [u8; 32],
    creator: u32,
    key: u8,
    consumed: u32,
    first_voted: u32,
    recorded: u32,
    add: impl FnOnce(&mut BlockBuilder),
) -> Block {
    let signer = Crypto::new([key; PRIVATE_KEY_SIZE]).ok().expect("key");
    let header = BlockHeader {
        version: 1,
        sequence: seq,
        creator,
        mined_amount: 0,
        payload_type: PAYLOAD_TYPE_TRANSACTION,
        consumed_votes: consumed,
        first_voted_node: first_voted,
        consumed_votes_from_first_voted_node: recorded,
        previous_hash: prev,
        signature: [0u8; SIGNATURE_SIZE],
    };
    let mut builder = BlockBuilder::new().header(header);
    add(&mut builder);
    builder.build_signed(&signer).ok().expect("build signed")
}

/// A genesis node on `W = 16` with `a2` (node #0's, registering node #1
/// and crediting it once) and `a3` (node #1's, worth 1100).
pub(super) fn two_creator_chain() -> (TestChain, Block, Block, Block) {
    let (mut bc, _, b1) = ready_genesis(16);
    let a2 = alt(2, b1.view().hash(), 0, 0, 1, 7, true);
    let a3 = alt(3, a2.view().hash(), 1, 1, 0, 8, false);
    for blk in [&a2, &a3] {
        assert_eq!(receive(&mut bc, blk), ReceiveBlockOutcome::AcceptedSilently);
    }
    assert_eq!(bc.active_branch_value, 1100);
    (bc, b1, a2, a3)
}

/// Whether `block` is held with its creator signature marked verified.
pub(super) fn verified<S: StorageTrait>(bc: &Chain16<S>, block: &Block) -> Option<bool> {
    let view = block.view();
    bc.blocks
        .find(view.sequence(), &view.hash())
        .and_then(|idx| bc.blocks.get(idx))
        .map(|entry| entry.is_signature_verified())
}

/// `block`'s transaction or balance payload under a new header:
/// `creator`, signed with `[key; 32]`, with the given vote fields (the
/// deviation form of [`resign`]).
pub(super) fn reheader(
    block: &Block,
    creator: u32,
    consumed: u32,
    first_voted: u32,
    recorded: u32,
    key: u8,
) -> Block {
    use moonblokz_chain_types::NodeInfo;
    let view = block.view();
    let signer = Crypto::new([key; PRIVATE_KEY_SIZE]).ok().expect("test key");
    let header = BlockHeader {
        version: view.version(),
        sequence: view.sequence(),
        creator,
        mined_amount: view.mined_amount(),
        payload_type: view.payload_type(),
        consumed_votes: consumed,
        first_voted_node: first_voted,
        consumed_votes_from_first_voted_node: recorded,
        previous_hash: view.previous_hash().try_into().expect("32 bytes"),
        signature: [0u8; SIGNATURE_SIZE],
    };
    let mut builder = BlockBuilder::new().header(header);
    if let Some(txs) = view.transactions() {
        for tx in txs.iter() {
            builder
                .add_transaction_bytes(tx.as_bytes())
                .ok()
                .expect("transaction");
        }
    } else if let Some(payload) = view.balances() {
        for info in payload.iter() {
            let key: [u8; PUBLIC_KEY_SIZE] = info.public_key().try_into().expect("public key");
            let ni = NodeInfo::new(info.owner(), info.balance(), info.vote_count(), &key);
            builder.add_node_info(&ni).ok().expect("add node info");
        }
        builder
            .set_max_node_id(payload.max_node_id())
            .ok()
            .expect("set max node id");
    }
    builder.build_signed(&signer).ok().expect("build signed")
}

/// A balance block on `prev` repeating `nodes`' state on `state` (the
/// active head is the block's parent) with their own keys, its header to be
/// set by [`real_on`] or [`reheader`].
pub(super) fn balance_snapshot<S: StorageTrait>(
    state: &Chain16<S>,
    seq: u32,
    prev: [u8; 32],
    nodes: &[u32],
) -> Block {
    use moonblokz_chain_types::NodeInfo;
    let signer = Crypto::new([1u8; PRIVATE_KEY_SIZE]).ok().expect("test key");
    let header = BlockHeader {
        version: 1,
        sequence: seq,
        creator: 0,
        mined_amount: 0,
        payload_type: PAYLOAD_TYPE_BALANCE,
        consumed_votes: 0,
        first_voted_node: 0,
        consumed_votes_from_first_voted_node: 0,
        previous_hash: prev,
        signature: [0u8; SIGNATURE_SIZE],
    };
    let mut builder = BlockBuilder::new().header(header);
    for &n in nodes {
        let key = *Crypto::new([key_of(n); PRIVATE_KEY_SIZE])
            .ok()
            .expect("node key")
            .public_key()
            .serialize();
        let ni = NodeInfo::new(
            n,
            state.node_info.balance_of(n),
            state.vote_engine.accumulated_vote_of(n),
            &key,
        );
        builder.add_node_info(&ni).ok().expect("add node info");
    }
    builder
        .set_max_node_id(state.node_info.max_known_node_id())
        .ok()
        .expect("set max node id");
    builder.build_signed(&signer).ok().expect("build signed")
}

/// `template` as a deviation by `creator` on `state`, whose active head is
/// the block's parent: real snapshots, `first_voted_node` the top of the
/// order at `p − 1` (I-09, FR37).
fn deviation_on<S: StorageTrait>(state: &Chain16<S>, template: &Block, creator: u32) -> Block {
    let top = state.vote_engine.top_creator().expect("a top creator");
    let snapshot = |n| vote_snapshot(state.vote_engine.accumulated_vote_of(n));
    reheader(
        template,
        creator,
        snapshot(creator),
        top,
        snapshot(top),
        key_of(creator),
    )
}

/// The key byte of node `n` in these fixtures (node #0's is `1`). Every
/// fixture key byte stays below `0x74`: a BLS private key is a big-endian
/// scalar below the group order `r = 0x73ed…`, so `[0x74; 32]` and above
/// are not keys under `bls-min-sig` / `bls-min-pk`.
pub(super) fn key_of(n: u32) -> u8 {
    assert!(n < 0x44, "a fixture key byte must stay below 0x74");
    if n == 0 { 1 } else { 0x30 + n as u8 }
}

/// A node with its own key and id over `storage`, trusting node #0's key
/// as the FR69 anchor, not yet configured.
pub(super) fn local_node<S: StorageTrait>(local: u32, storage: S) -> Chain16<S> {
    let crypto = Crypto::new([key_of(local); PRIVATE_KEY_SIZE])
        .ok()
        .expect("local key");
    let node_zero = *Crypto::new([1u8; PRIVATE_KEY_SIZE])
        .ok()
        .expect("node #0 key")
        .public_key()
        .serialize();
    let mut slot = core::mem::MaybeUninit::uninit();
    Blockchain::init(
        &mut slot,
        crypto,
        storage,
        empty_chain_config(TestChain::BUILD_LIMITS),
        local,
        node_zero,
        0,
    );
    // SAFETY: `init` returned, so every field of `slot` is initialized.
    unsafe { slot.assume_init() }
}

/// Room for the longer chains of these tests (16 slots).
type SupportStorage = MemoryBackend<{ 16 * MAX_BLOCK_SIZE + 8000 }>;

pub(super) fn local_storage(local: u32) -> SupportStorage {
    let mut storage = SupportStorage::new();
    storage
        .init(
            [key_of(local); PRIVATE_KEY_SIZE],
            0,
            [0u8; INIT_PARAMS_SIZE],
        )
        .ok()
        .expect("the test backend initializes");
    storage
}

pub(super) type SupportChain = Chain16<SupportStorage>;

/// The Story 6.4 chain on `W = w` (configuration `extra` added): genesis
/// by node #0, then `a2` (node #0, registering nodes 1..=5), `a3` (node 1,
/// one credit for node 4), `a4` (node 4, three for node 1) and `a5` (node
/// 3, one for node 5). At #5 node 1 tops the order (`u = 1`), node 5 holds
/// 1000 and nodes 0, 2, 3 and 4 hold 0; `A = {0, 1, 3, 4}`; node 2 is
/// registered but never creates. Returns the builder `g` (node #0, local
/// id 0), the `local` node fed the same blocks over `storage`, Ready, and
/// the blocks `b0..=a5`.
pub(super) fn support_chain_on<S: StorageTrait>(
    local: u32,
    storage: S,
    w: u32,
    extra: impl FnOnce(&mut ChainConfigPayloadBuilder),
) -> (SupportChain, Chain16<S>, [Block; 6]) {
    let mut config = window_config_builder(w);
    extra(&mut config);
    support_chain_with(local, storage, config)
}

/// [`support_chain_on`] on the configuration `config` (Story 7.7: a horizon
/// short enough for a whole late-node hold to fit the test storage).
pub(super) fn support_chain_with<S: StorageTrait>(
    local: u32,
    storage: S,
    config: ChainConfigPayloadBuilder,
) -> (SupportChain, Chain16<S>, [Block; 6]) {
    let mut g = local_node(0, local_storage(0));
    let genesis = g
        .process_genesis(CURRENCY, config.content())
        .ok()
        .expect("genesis");
    let (b0, b1) = (genesis.block_zero, genesis.block_one);
    let mut l = local_node(local, storage);
    for block in [&b1, &b0] {
        assert_eq!(
            receive(&mut l, block),
            ReceiveBlockOutcome::AcceptedSilently
        );
    }
    assert!(l.is_ready(), "precondition: the local node is Ready");

    let regs = tx_block(2, b1.view().hash(), 0, |b| {
        for n in 1..=5 {
            b.add_registration(&registration_tx(0, n, key_of(n)))
                .ok()
                .expect("add registration");
        }
    });
    let a2 = real_on(&g, &regs, 0, 1);
    let next = |g: &mut SupportChain, l: &mut Chain16<S>, prev: &Block, plan: (u32, u32, u32)| {
        assert_eq!(receive(g, prev), ReceiveBlockOutcome::AcceptedSilently);
        assert_eq!(receive(l, prev), ReceiveBlockOutcome::AcceptedSilently);
        let (creator, target, n) = plan;
        let seq = prev.view().sequence() + 1;
        let template = tx_block(
            seq,
            prev.view().hash(),
            0,
            votes_for(seq, target, n, 100 * u64::from(seq)),
        );
        real_on(g, &template, creator, key_of(creator))
    };
    let a3 = next(&mut g, &mut l, &a2, (1, 4, 1));
    let a4 = next(&mut g, &mut l, &a3, (4, 1, 3));
    let a5 = next(&mut g, &mut l, &a4, (3, 5, 1));
    assert_eq!(receive(&mut g, &a5), ReceiveBlockOutcome::AcceptedSilently);
    assert_eq!(receive(&mut l, &a5), ReceiveBlockOutcome::AcceptedSilently);
    assert_eq!(head_of(&l).0, 5);
    assert_eq!(g.vote_engine.top_creator(), Some(1), "precondition: u = 1");
    assert!(g.vote_engine.accumulated_vote_of(5) > 0);
    assert_eq!(g.vote_engine.accumulated_vote_of(2), 0);
    (g, l, [b0, b1, a2, a3, a4, a5])
}

pub(super) fn support_chain(local: u32) -> (SupportChain, SupportChain, [Block; 6]) {
    support_chain_on(local, local_storage(local), 16, |_| {})
}

/// A deviation by `creator` on `prev` (the active head of `g`), its
/// transaction from `salt`.
pub(super) fn deviation_after(g: &SupportChain, prev: &Block, creator: u32, salt: u64) -> Block {
    let seq = prev.view().sequence() + 1;
    let template = tx_block(seq, prev.view().hash(), 0, votes_for(seq, 0, 1, salt));
    deviation_on(g, &template, creator)
}

/// A normal-form block by `creator` on `prev` (the active head of `g`).
pub(super) fn normal_after(g: &SupportChain, prev: &Block, creator: u32, salt: u64) -> Block {
    let seq = prev.view().sequence() + 1;
    let template = tx_block(seq, prev.view().hash(), 0, votes_for(seq, 0, 1, salt));
    real_on(g, &template, creator, key_of(creator))
}

/// The support `node` sends for `block`, if any.
pub(super) fn support_for<S: StorageTrait>(
    node: &mut Chain16<S>,
    block: &Block,
) -> Option<SupportMessage> {
    match receive(node, block) {
        ReceiveBlockOutcome::AcceptedAndSendSupport(message) => Some(message),
        ReceiveBlockOutcome::AcceptedSilently => None,
        other => panic!("unexpected outcome {other:?}"),
    }
}

/// AC9 3c — the active set equals a window walk recomputed from storage.
pub(super) fn assert_active_set_matches<
    C: CryptoTrait,
    S: StorageTrait,
    G: ChainConfigTrait,
    const N: usize,
    const L: u32,
    const B: usize,
    const H: usize,
    const U: usize,
>(
    bc: &Blockchain<C, S, G, N, L, B, H, U>,
    what: &str,
) {
    assert!(bc.active_set.is_valid(), "{what}: the active set is built");
    let mut reference = [0u16; N];
    let tail = bc.snake_chain_tail_idx;
    let mut cur = bc.active_chain_head_idx;
    loop {
        let mut buf = [0u8; MAX_BLOCK_SIZE];
        let creator = bc.view_retained(cur, &mut buf).expect("readable").creator();
        reference[creator as usize] += 1;
        if cur == tail {
            assert_eq!(
                bc.active_set.tail_creator(),
                creator,
                "{what}: tail creator"
            );
            break;
        }
        cur = bc.blocks.get(cur).expect("on the path").parent_ref();
    }
    for (node, count) in reference.iter().enumerate() {
        assert_eq!(
            bc.active_set.count(node as u32),
            *count,
            "{what}: node {node}"
        );
    }
}

/// The body `message` travels as (DEC-229): its sequence, then
/// [`support_body_tail`].
pub(super) fn body_of(message: &SupportMessage) -> [u8; 44 + MULTI_SIGNATURE_SIZE] {
    let mut body = [0u8; 44 + MULTI_SIGNATURE_SIZE];
    body[..4].copy_from_slice(&message.deviation_sequence.to_le_bytes());
    body[4..].copy_from_slice(&support_body_tail(
        message.supporter_node_id,
        message.proposer_node_id,
        &message.deviation_block_hash,
        &message.support_signature,
    ));
    body
}

/// A support by `supporter`, signed with its fixture key, for `proposer`'s
/// block `hash` at `p`.
pub(super) fn support_by(supporter: u32, proposer: u32, p: u32, hash: [u8; 32]) -> SupportMessage {
    let signer = Crypto::new([key_of(supporter); PRIVATE_KEY_SIZE])
        .ok()
        .expect("fixture key");
    SupportMessage {
        supporter_node_id: supporter,
        proposer_node_id: proposer,
        deviation_sequence: p,
        deviation_block_hash: hash,
        support_signature: *signer
            .multi_sign(&support_message_bytes(proposer, p, &hash))
            .serialize(),
    }
}

/// `message` with its signature's last byte flipped.
pub(super) fn forged(mut message: SupportMessage) -> SupportMessage {
    message.support_signature[MULTI_SIGNATURE_SIZE - 1] ^= 1;
    message
}

pub(super) fn intake<S: StorageTrait>(
    node: &mut Chain16<S>,
    message: &SupportMessage,
) -> ReceiveSupportOutcome {
    let body = body_of(message);
    node.receive_support(SupportView::from_bytes(&body).expect("one body"), 0)
        .0
}

/// A light block by `u` (node 1) on #5: its own normal-form block at 6,
/// signed with its real key, whose hash is above every block in `beside`.
/// The equal-value siblings at 6 are retained in hash order, so a `u`-block
/// below the deviation would not be held at all. The hashes follow the
/// keys, which differ per signature scheme, so the vote's amount is
/// searched rather than fixed.
pub(super) fn u_block(blocks: &[Block; 6], beside: &[&Block]) -> Block {
    (0..100_000)
        .map(|salt| {
            let template = tx_block(6, blocks[5].view().hash(), 0, votes_for(6, 0, 1, salt));
            reheader(&template, 1, 0, 1, 0, key_of(1))
        })
        .find(|u| beside.iter().all(|b| u.view().hash() > b.view().hash()))
        .expect("a u-block above its siblings")
}

/// The proposer `local` on Story 6.4's chain with its own deviation `d` at
/// 6 received (it becomes the active head: the direct case). Returns the
/// builder `g` (still at #5), the proposer, the blocks, `d` and its slot.
pub(super) fn proposer_chain(local: u32) -> (SupportChain, SupportChain, [Block; 6], Block, u32) {
    let (g, mut l, blocks) = support_chain(local);
    let d = deviation_after(&g, &blocks[5], local, 1);
    assert_eq!(receive(&mut l, &d), ReceiveBlockOutcome::AcceptedSilently);
    assert_eq!(head_of(&l), (6, d.view().hash()), "d is active");
    let d_idx = l.blocks.find(6, &d.view().hash()).expect("d held");
    (g, l, blocks, d, d_idx)
}

/// Every node's accumulated vote: the engine's whole observable state.
pub(super) fn engine_votes<S: StorageTrait>(bc: &Chain16<S>) -> [u32; 16] {
    core::array::from_fn(|n| bc.vote_engine.accumulated_vote_of(n as u32))
}

pub(super) fn held<S: StorageTrait>(bc: &Chain16<S>) -> u8 {
    bc.approval.counts().2
}

/// The evidence payload fields a test checks: `(supporter_vote_sum,
/// deviation_sequence, m, bitmap, aggregate bytes, late entries)`.
pub(super) struct Evidence {
    pub(super) supporter_vote_sum: u64,
    pub(super) deviation_sequence: u32,
    pub(super) m: usize,
    pub(super) bitmap: std::vec::Vec<u8>,
    pub(super) aggregate: std::vec::Vec<u8>,
    pub(super) late: std::vec::Vec<(u32, u32)>,
}

pub(super) fn evidence_of(block: &Block, signers: usize) -> Evidence {
    let payload = block.view().payload();
    let m = usize::from(payload[12]);
    let bitmap_end = 13 + m.div_ceil(8);
    let aggregate_len =
        AGGREGATED_SIGNATURE_CONSTANT_SIZE + AGGREGATED_SIGNATURE_VARIABLE_SIZE * signers;
    let fixed = moonblokz_chain_types::approval_fixed_size(m, signers);
    assert_eq!(bitmap_end + aggregate_len + 2, fixed);
    let late_count = usize::from(u16::from_le_bytes([payload[fixed - 2], payload[fixed - 1]]));
    let word = |at: usize| u32::from_le_bytes(payload[at..at + 4].try_into().expect("4"));
    Evidence {
        supporter_vote_sum: u64::from_le_bytes(payload[..8].try_into().expect("8")),
        deviation_sequence: word(8),
        m,
        bitmap: payload[13..bitmap_end].to_vec(),
        aggregate: payload[bitmap_end..bitmap_end + aggregate_len].to_vec(),
        late: (0..late_count)
            .map(|i| (word(fixed + 8 * i), word(fixed + 8 * i + 4)))
            .collect(),
    }
}

pub(super) fn test_crypto() -> Crypto {
    Crypto::new([1u8; PRIVATE_KEY_SIZE]).ok().expect("key")
}

/// Proposer 2's deviation `d` held off the active chain: node 5's heavier
/// approval-less deviation `y@6` is the active head (DEC-200's sibling
/// case). Returns `g`, the proposer, the blocks, `d`, its slot and `y`.
pub(super) fn sibling_proposer() -> (SupportChain, SupportChain, [Block; 6], Block, u32, Block) {
    let (g, mut l, blocks) = support_chain(2);
    let d = deviation_after(&g, &blocks[5], 2, 1);
    assert_eq!(receive(&mut l, &d), ReceiveBlockOutcome::AcceptedSilently);
    let y = deviation_after(&g, &blocks[5], 5, 4);
    assert_eq!(receive(&mut l, &y), ReceiveBlockOutcome::AcceptedSilently);
    assert_eq!(head_of(&l), (6, y.view().hash()), "the heavier sibling");
    let d_idx = l.blocks.find(6, &d.view().hash()).expect("d held");
    assert!(!l.blocks.get(d_idx).expect("d").is_on_active_chain());
    (g, l, blocks, d, d_idx, y)
}

/// Opens the accumulator and feeds the first `n` members' supports.
pub(super) fn accumulate<S: StorageTrait>(bc: &mut Chain16<S>, d: &Block, d_idx: u32, n: usize) {
    assert!(bc.open_approval(d_idx), "open");
    let (p, proposer, h) = (d.view().sequence(), d.view().creator(), d.view().hash());
    let members: std::vec::Vec<u32> = bc.approval.members().to_vec();
    for &member in &members[..n] {
        assert_eq!(
            intake(bc, &support_by(member, proposer, p, h)),
            ReceiveSupportOutcome::Accepted
        );
    }
    assert_eq!(usize::from(held(bc)), n);
}

/// Puts `block` into `bc`'s table and storage as a retained entry with no
/// parent: a planted block (verified or not) for the evidence scans.
/// `stored == false` leaves its slot unwritten, so its read fails.
pub(super) fn plant<S: StorageTrait>(
    bc: &mut Chain16<S>,
    block: &Block,
    verified: bool,
    stored: bool,
) {
    let view = block.view();
    let mut entry = BlockEntry::new(view.hash(), NONE_REF, view.sequence());
    entry.set_payload_type(view.payload_type());
    entry.set_len(block.len() as u32);
    if verified {
        entry.set_signature_verified();
    }
    let idx = bc.blocks.insert(entry).expect("a free slot");
    if stored {
        bc.storage.save_block(idx, block).ok().expect("save");
    }
}

pub(super) type FailingSupportStorage = FailingReadStorage<{ 16 * MAX_BLOCK_SIZE + 8000 }>;

pub(super) fn failing_storage(local: u32) -> FailingSupportStorage {
    FailingReadStorage {
        inner: local_storage(local),
        failing_slot: u32::MAX,
        reads_left: core::cell::Cell::new(0),
        failures_left: core::cell::Cell::new(u32::MAX),
        attempts: core::cell::Cell::new(0),
        reads: core::cell::Cell::new(0),
    }
}

/// [`plant`] with a parent: a retained child of `parent`.
pub(super) fn plant_child<S: StorageTrait>(
    bc: &mut Chain16<S>,
    block: &Block,
    parent: u32,
    verified: bool,
    stored: bool,
) {
    let view = block.view();
    let mut entry = BlockEntry::new(view.hash(), parent, view.sequence());
    entry.set_payload_type(view.payload_type());
    entry.set_len(block.len() as u32);
    if verified {
        entry.set_signature_verified();
    }
    let idx = bc.blocks.insert(entry).expect("a free slot");
    if stored {
        bc.storage.save_block(idx, block).ok().expect("save");
    }
}

// -- Story 6.12: honest (different-creator) forks ----------------------------

/// Story 6.12 (FR70): `template` as `creator`'s block (signed with `[key;
/// 32]`), worth its real FR21 value on the chain a `W = 16` genesis node
/// reaches by receiving `path` (I-09). The node a sibling of the same creator
/// would be a twin of has another creator here, so a fork built from it is
/// honest and FR22 may switch to it.
pub(super) fn real_after(path: &[&Block], template: &Block, creator: u32, key: u8) -> Block {
    let (mut fresh, _, _) = ready_genesis(16);
    for blk in path {
        assert_eq!(
            receive(&mut fresh, blk),
            ReceiveBlockOutcome::AcceptedSilently
        );
    }
    real_on(&fresh, template, creator, key)
}

/// Story 6.12 (FR70): [`valued`] by `creator` (signed with `[key; 32]`): a
/// one-transfer block with a forged value, so an honest-fork winner the
/// replay refuses (I-09) when `creator` is seeded on its branch.
pub(super) fn valued_by(
    seq: u32,
    prev: [u8; 32],
    value: u32,
    amount: u64,
    creator: u32,
    key: u8,
) -> Block {
    resign(&transfer(seq, prev, 0, amount), creator, value, key)
}

/// A genesis node on `W = w` over a [`FailingReadStorage`], unarmed.
pub(super) fn failing_genesis(w: u32) -> (Chain16<FailingReadStorage>, Block) {
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

/// [`two_creator_chain`] on a [`FailingReadStorage`] node, unarmed.
pub(super) fn failing_two_creator_chain() -> (Chain16<FailingReadStorage>, Block, Block, Block) {
    let (mut bc, b1) = failing_genesis(16);
    let a2 = alt(2, b1.view().hash(), 0, 0, 1, 7, true);
    let a3 = alt(3, a2.view().hash(), 1, 1, 0, 8, false);
    for blk in [&a2, &a3] {
        assert_eq!(receive(&mut bc, blk), ReceiveBlockOutcome::AcceptedSilently);
    }
    (bc, b1, a2, a3)
}
