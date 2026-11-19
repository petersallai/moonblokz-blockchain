//! Tests of `api`: the harness (backends, chain constructors, common builders).
//! Each test file mirrors a production module of `api`; fixtures shared by
//! more than one file live in `fixtures.rs`.

use super::*;
use moonblokz_chain_types::{ChainConfigPayloadBuilder, MAX_BLOCK_SIZE};
use moonblokz_configuration::{ChainConfiguration, NoopConfigChangeSink, parameter};
use moonblokz_crypto::{
    AggregatedSignature, Crypto, CryptoError, MultiSignature, PRIVATE_KEY_SIZE, PublicKey,
    Signature, SignatureTrait,
};
use moonblokz_storage::{
    ControlPlaneData, INIT_PARAMS_SIZE, StorageError, backend_memory::MemoryBackend,
};

fn any_nonzero(bytes: &[u8]) -> bool {
    bytes.iter().any(|value| *value != 0)
}

/// The configuration seam under test: the real module with the no-op change
/// sink. There is no stub any more — the tests exercise the same crate the
/// firmware does.
type TestConfig = ChainConfiguration<NoopConfigChangeSink>;

/// The window the suite's configurations declare: `TestChain`'s whole
/// active-chain capacity.
///
/// A content that leaves `active_chain_length` out resolves it to the
/// default 500, which these harnesses — built small so a segment fits test
/// storage — cannot hold, so acceptance refuses it (FR8). Declaring the
/// capacity keeps every other parameter at its code-baked default.
const TEST_W: u32 = 16;

/// The verification horizon the `TEST_W` configurations declare beside the
/// window (configuration §6 check 15, `H < W`; see [`test_horizon`]).
/// The default 50 is not below any test window, so a content must declare
/// it. The test backend stores eight blocks, so a `TEST_W` chain never
/// holds a head above #7: at 7 the FR58 bound never binds there, and the
/// bound, the horizon and the reclamation are exercised on the W6 harness,
/// which declares `H = 3`. `H` divides `W` and is at least 3
/// (configuration §6 check 21, Story 6.7 D8), so 8 replaced 7; the clean
/// slots (D8) are then #7, #15, ….
const TEST_H: u32 = 8;

/// The horizon a test configuration with window `w` declares: `TEST_H` on
/// the `TEST_W` harnesses, and the smallest legal horizon on every smaller
/// window: the least divisor of `w` from 3 up (check 21; `H < W`, check 15).
/// The W6 harness then declares 3 and joins on `W + H = 9` blocks, keeping
/// five of its backend's fourteen slots for forks ([`W6Storage`]). A window
/// with no such divisor (4 or a prime) has no legal horizon: it panics, at
/// compile time in a `const` item and otherwise when the test builds its
/// configuration. A window above `TEST_W` also declares `TEST_H`, legal
/// or not: only the FR8 capacity tests build one, and the capacity bound
/// refuses it first.
const fn test_horizon(w: u32) -> u32 {
    if w >= TEST_W {
        return TEST_H;
    }
    let mut h = 3;
    while h < w {
        if w.is_multiple_of(h) {
            return h;
        }
        h += 1;
    }
    panic!("no legal horizon below this window");
}

/// The network node cap every test configuration declares (DEC-228): the
/// test chains' `MAX_NODES`. The default 1000 exceeds it, so acceptance
/// would refuse a content that left it out (configuration §6 check 18).
const TEST_MAX_NODES: u32 = 16;

/// The block table of the `TEST_W` harnesses: the window, the horizon and
/// one competing branch of depth `H` (configuration §6 check 16). The test
/// backend stores eight blocks, so the size only has to pass the check.
const TEST_MAX_BLOCKS: usize = TEST_W as usize + 2 * TEST_H as usize;

/// The base override set as a **content region**: one literal entry
/// declaring `active_chain_length = TEST_W`. Every other parameter resolves
/// to its code-baked default, and those defaults are exactly the constants
/// the retired `FixedChainConfig` returned — which is why the suite's
/// expected values are unchanged. The last entry declares the build's
/// signature scheme ([`declare_build_scheme`]).
const BASE_CONFIG_CONTENT: [u8; 23] = [
    4,
    0,
    parameter::ACTIVE_CHAIN_LENGTH,
    4,
    TEST_W.to_le_bytes()[0],
    TEST_W.to_le_bytes()[1],
    TEST_W.to_le_bytes()[2],
    TEST_W.to_le_bytes()[3],
    parameter::VERIFICATION_HORIZON,
    4,
    test_horizon(TEST_W).to_le_bytes()[0],
    test_horizon(TEST_W).to_le_bytes()[1],
    test_horizon(TEST_W).to_le_bytes()[2],
    test_horizon(TEST_W).to_le_bytes()[3],
    parameter::MAX_NODE_COUNT,
    4,
    TEST_MAX_NODES.to_le_bytes()[0],
    TEST_MAX_NODES.to_le_bytes()[1],
    TEST_MAX_NODES.to_le_bytes()[2],
    TEST_MAX_NODES.to_le_bytes()[3],
    parameter::SIGNATURE_SCHEME,
    1,
    moonblokz_crypto::SIGNATURE_SCHEME,
];

/// A second content region, valid and **distinct in bytes** but resolving
/// identically: the base entry plus a literal declaring `vote_interest`'s
/// own default. Used where a test needs two different chain-config contents.
const OTHER_CONFIG_CONTENT: [u8; 26] = [
    5,
    0,
    parameter::ACTIVE_CHAIN_LENGTH,
    4,
    TEST_W.to_le_bytes()[0],
    TEST_W.to_le_bytes()[1],
    TEST_W.to_le_bytes()[2],
    TEST_W.to_le_bytes()[3],
    parameter::VERIFICATION_HORIZON,
    4,
    test_horizon(TEST_W).to_le_bytes()[0],
    test_horizon(TEST_W).to_le_bytes()[1],
    test_horizon(TEST_W).to_le_bytes()[2],
    test_horizon(TEST_W).to_le_bytes()[3],
    parameter::MAX_NODE_COUNT,
    4,
    TEST_MAX_NODES.to_le_bytes()[0],
    TEST_MAX_NODES.to_le_bytes()[1],
    TEST_MAX_NODES.to_le_bytes()[2],
    TEST_MAX_NODES.to_le_bytes()[3],
    parameter::VOTE_INTEREST,
    1,
    5,
    parameter::SIGNATURE_SCHEME,
    1,
    moonblokz_crypto::SIGNATURE_SCHEME,
];

/// An override set declaring the window `w` and its test horizon — the
/// base every fixture builder starts from.
fn window_config_builder(w: u32) -> ChainConfigPayloadBuilder {
    window_horizon_config_builder(w, test_horizon(w))
}

/// An override set declaring the window `w` and the horizon `h`.
fn window_horizon_config_builder(w: u32, h: u32) -> ChainConfigPayloadBuilder {
    let mut builder = ChainConfigPayloadBuilder::new();
    builder
        .add_literal(parameter::ACTIVE_CHAIN_LENGTH, &w.to_le_bytes())
        .ok()
        .expect("a four-byte literal is well-formed");
    builder
        .add_literal(parameter::VERIFICATION_HORIZON, &h.to_le_bytes())
        .ok()
        .expect("a four-byte literal is well-formed");
    builder
        .add_literal(parameter::MAX_NODE_COUNT, &TEST_MAX_NODES.to_le_bytes())
        .ok()
        .expect("a four-byte literal is well-formed");
    declare_build_scheme(&mut builder);
    builder
}

/// Declares the build's signature scheme, which every chain must state
/// unless it is the default `schnorr` (configuration check 19, DEC-252):
/// the test configurations state it on every scheme, so one fixture set
/// serves all three.
fn declare_build_scheme(builder: &mut ChainConfigPayloadBuilder) {
    builder
        .add_literal(
            parameter::SIGNATURE_SCHEME,
            &[moonblokz_crypto::SIGNATURE_SCHEME],
        )
        .ok()
        .expect("a one-byte literal is well-formed");
}

/// Storage whose control plane is fine and whose block writes are not.
///
/// `MemoryBackend` cannot express this: a backend large enough to
/// initialize is large enough to hold blocks. The pair matters because
/// genesis has two distinct storage failure modes and they refuse at
/// different points — one before any write, one after the first.
/// Storage whose control plane is fine and every block slot is corrupt.
/// `MemoryBackend` cannot express this — it has no per-slot integrity check
/// and so can never return `IntegrityFailure`, which only the rp2040 backend
/// produces. Without a stub, the skip arm that matters on real hardware is
/// unexercised.
struct CorruptSlotsStorage;

impl StorageTrait for CorruptSlotsStorage {
    fn init(
        &mut self,
        _private_key: [u8; PRIVATE_KEY_SIZE],
        _own_node_id: u32,
        _init_params: [u8; INIT_PARAMS_SIZE],
    ) -> Result<(), StorageError> {
        Ok(())
    }

    fn save_block(&mut self, _idx: u32, _block: &Block) -> Result<(), StorageError> {
        Ok(())
    }

    fn read_block_into(
        &self,
        idx: u32,
        _out: &mut [u8; MAX_BLOCK_SIZE],
    ) -> Result<(), StorageError> {
        // Two slots are occupied-but-corrupt; the rest are genuinely empty.
        if idx < 2 {
            Err(StorageError::IntegrityFailure)
        } else {
            Err(StorageError::BlockAbsent)
        }
    }

    fn capacity(&self) -> u32 {
        8
    }

    fn set_chain_configuration(&mut self, _block: &Block) -> Result<(), StorageError> {
        Ok(())
    }

    fn load_control_data(&mut self) -> Result<ControlPlaneData, StorageError> {
        Ok(ControlPlaneData {
            private_key: [1u8; PRIVATE_KEY_SIZE],
            own_node_id: 0,
            init_params: [0u8; INIT_PARAMS_SIZE],
            chain_configuration: None,
        })
    }
}

struct BlockWriteFailsStorage;

impl StorageTrait for BlockWriteFailsStorage {
    fn init(
        &mut self,
        _private_key: [u8; PRIVATE_KEY_SIZE],
        _own_node_id: u32,
        _init_params: [u8; INIT_PARAMS_SIZE],
    ) -> Result<(), StorageError> {
        Ok(())
    }

    fn save_block(&mut self, _storage_index: u32, _block: &Block) -> Result<(), StorageError> {
        Err(StorageError::InvalidIndex)
    }

    fn read_block_into(
        &self,
        _storage_index: u32,
        _out: &mut [u8; MAX_BLOCK_SIZE],
    ) -> Result<(), StorageError> {
        Err(StorageError::BlockAbsent)
    }

    fn capacity(&self) -> u32 {
        0
    }

    fn set_chain_configuration(&mut self, _block: &Block) -> Result<(), StorageError> {
        Ok(())
    }

    fn load_control_data(&mut self) -> Result<ControlPlaneData, StorageError> {
        Ok(ControlPlaneData {
            private_key: [1u8; PRIVATE_KEY_SIZE],
            own_node_id: 0,
            init_params: [0u8; INIT_PARAMS_SIZE],
            chain_configuration: None,
        })
    }
}

/// A storage backend in the state a booted node's is: its control plane is
/// initialized, which the durable `set_chain_configuration` seam requires.
fn initialized_storage(
    private_key: [u8; PRIVATE_KEY_SIZE],
) -> MemoryBackend<{ 8 * MAX_BLOCK_SIZE + 8000 }> {
    let mut storage = MemoryBackend::<{ 8 * MAX_BLOCK_SIZE + 8000 }>::new();
    storage
        .init(private_key, 0, [0u8; INIT_PARAMS_SIZE])
        .ok()
        .expect("the test backend initializes");
    storage
}

/// A configuration module holding no configuration — the state every node
/// starts in, and the one `process_genesis` requires (FR54's lock is
/// set-once).
/// `limits` is the receiving chain's own `BUILD_LIMITS`, never a default:
/// the module's §6 checks measure a declared value against exactly what it
/// was handed, so a fixture that lends one chain's capacities to another
/// would test the bound against a capacity that build does not have.
fn empty_chain_config(limits: BuildLimits) -> TestConfig {
    ChainConfiguration::new(NoopConfigChangeSink, limits)
}

/// A configuration module already durably locked on an override set that
/// declares the window at `limits`' full capacity, standing in for "genesis
/// has run" wherever a test needs a configured node without bootstrapping
/// one.
fn locked_chain_config(crypto: &Crypto, limits: BuildLimits) -> TestConfig {
    let mut config = empty_chain_config(limits);
    let mut builder = window_config_builder(limits.snake_chain_length_max);
    config
        .load_durable(builder.build_signed(crypto))
        .ok()
        .expect("a window at the build's capacity is accepted content");
    config
}

/// The crypto seam for the construction tests — a stand-in that performs
/// no cryptography.
///
/// `init` and `new` only *move* the backend into the node; neither ever
/// calls it. The Miri gate (`cargo +nightly miri test init_`) therefore
/// has no reason to pay for a real signature backend, whose `Crypto::new`
/// alone runs an EC scalar multiplication — interpreted, that dominates
/// the whole run. Every method past construction is `unimplemented!()`:
/// reaching one would mean a construction test had begun exercising
/// crypto, which is exactly what this type exists to prevent. Every other
/// test keeps the real backend, so the trait seam is still exercised
/// end-to-end.
struct NoCrypto;

impl CryptoTrait for NoCrypto {
    fn new(_private_key_bytes: [u8; PRIVATE_KEY_SIZE]) -> Result<Self, CryptoError> {
        Ok(Self)
    }

    fn public_key(&self) -> &PublicKey {
        unimplemented!("construction never reads the public key")
    }

    fn sign(&self, _message: &[u8]) -> Signature {
        unimplemented!("construction never signs")
    }

    fn multi_sign(&self, _message: &[u8]) -> MultiSignature {
        unimplemented!("construction never signs")
    }

    fn verify_multi_signature(
        &self,
        _message: &[u8],
        _multi_signature: &MultiSignature,
        _public_key: &PublicKey,
    ) -> bool {
        unimplemented!("construction never verifies")
    }

    fn verify_signature(
        &self,
        _message: &[u8],
        _signature: &Signature,
        _public_key: &PublicKey,
    ) -> bool {
        unimplemented!("construction never verifies")
    }

    fn aggregate_signatures(
        &self,
        _signatures: &[&MultiSignature],
        _public_keys: &[&[u8; PUBLIC_KEY_SIZE]],
        _message: &[u8],
    ) -> Result<AggregatedSignature, CryptoError> {
        unimplemented!("construction never aggregates")
    }

    fn verify_aggregated_signature(
        &self,
        _message: &[u8],
        _aggregated_signature: &AggregatedSignature,
        _public_keys: &[&PublicKey],
    ) -> bool {
        unimplemented!("construction never verifies")
    }

    fn prove_possession(&self) -> Signature {
        unimplemented!("construction never proves possession")
    }

    fn verify_possession(&self, _public_key: &PublicKey, _proof: &Signature) -> bool {
        unimplemented!("construction never verifies")
    }
}

/// Helper: the same triple as [`test_backends`] with [`NoCrypto`] in place
/// of the signature backend, for the two construction tests.
fn construction_backends() -> (
    NoCrypto,
    MemoryBackend<{ 8 * MAX_BLOCK_SIZE + 8000 }>,
    TestConfig,
) {
    (
        NoCrypto,
        MemoryBackend::<{ 8 * MAX_BLOCK_SIZE + 8000 }>::new(),
        empty_chain_config(TestChain::BUILD_LIMITS),
    )
}

/// Helper: construct a (Crypto, MemoryBackend, TestConfig) triple for the
/// walking-skeleton tests. Uses real backends so the trait-bound seam is
/// exercised end-to-end; the configuration module is **empty**, which is
/// what the genesis path requires of a node about to bootstrap.
fn test_backends() -> (
    Crypto,
    MemoryBackend<{ 8 * MAX_BLOCK_SIZE + 8000 }>,
    TestConfig,
) {
    let private_key = [1u8; PRIVATE_KEY_SIZE];
    let crypto = Crypto::new(private_key)
        .ok()
        .expect("test private key should be accepted by the backend");
    let storage = initialized_storage(private_key);
    let chain_config = empty_chain_config(TestChain::BUILD_LIMITS);
    (crypto, storage, chain_config)
}

/// A node that holds **no** configuration at all — the joining node's real
/// starting state, before any chain-config block has reached it.
///
/// Needed by the admission tests: on a node that already holds a
/// configuration, an admitted block can complete an FR2 candidate and run the
/// whole Epic-5 lifecycle inside `receive_block`, which is exactly what an
/// admission test must not have happening underneath it.
fn new_unconfigured_test_chain() -> TestChain {
    let (crypto, storage, chain_config) = test_backends();
    new_chain(crypto, storage, chain_config, 5, 0)
}

/// Helper: build an empty node via `init` ready for a
/// `process_genesis` call. Genesis is node-zero-only, so node zero's own
/// key (derived from `crypto`) is stored as the trust anchor.
fn new_chain(
    crypto: Crypto,
    storage: MemoryBackend<{ 8 * MAX_BLOCK_SIZE + 8000 }>,
    chain_config: TestConfig,
    local_node_id: u32,
    prng_seed: u64,
) -> Blockchain<
    Crypto,
    MemoryBackend<{ 8 * MAX_BLOCK_SIZE + 8000 }>,
    TestConfig,
    16,
    16,
    TEST_MAX_BLOCKS,
    4,
    16,
> {
    let node_zero = *crypto.public_key().serialize();
    let mut bc_slot = core::mem::MaybeUninit::uninit();
    Blockchain::init(
        &mut bc_slot,
        crypto,
        storage,
        chain_config,
        local_node_id,
        node_zero,
        prng_seed,
    );
    // SAFETY: `init` returned, so every field of `bc_slot` is initialized.
    unsafe { bc_slot.assume_init() }
}

/// `init`'s field writes (`blocks` / `chain_heads` filled
/// element-by-element through the nested tables' own `init`, the
/// scalars written one by one) must land every field in its correct
/// default state — a wrong field order, a skipped field, or an
/// off-by-one inside the `unsafe` block would silently corrupt memory
/// rather than panic, so this is verified directly rather than trusted
/// by construction.
///
/// The destructuring is deliberately exhaustive (no `..`): adding a field
/// to `Blockchain` makes this test fail to *compile* until the new field
/// is both initialized in `init` and asserted here — the one obligation
/// the safe signature cannot enforce, pinned at compile time instead of
/// by a reviewer's eye. Never compare two nodes byte-for-byte for this
/// purpose: padding bytes are uninitialized, and Miri rejects reading them.
#[test]
fn init_sets_expected_defaults() {
    let (crypto, storage, chain_config) = construction_backends();
    let mut bc_slot =
        core::mem::MaybeUninit::<Blockchain<_, _, _, 16, 16, TEST_MAX_BLOCKS, 4, 16>>::uninit();
    let bc = Blockchain::<_, _, _, 16, 16, TEST_MAX_BLOCKS, 4, 16>::init(
        &mut bc_slot,
        crypto,
        storage,
        chain_config,
        7,
        [3u8; PUBLIC_KEY_SIZE],
        0xDEAD_BEEF,
    );

    let Blockchain {
        crypto: _,       // moved in as given; opaque backend
        storage: _,      // moved in as given; opaque backend
        chain_config: _, // moved in as given
        local_node_id,
        node_zero_public_key,
        prng: _, // seeded from `prng_seed`; its state is opaque by design
        lifecycle_phase,
        restart_refused,
        blocks,
        chain_heads,
        node_info,
        vote_engine,
        last_parent_request_emit_timestamp,
        active_chain_head_idx,
        tentative_config_block_idx,
        snake_chain_tail_idx,
        active_branch_value,
        active_set,
        non_conflict,
        support_dedupe,
        approval,
        active_open_run,
        reentry_due,
    } = &*bc;

    assert_eq!(*local_node_id, 7);
    assert!(*lifecycle_phase == LifecyclePhase::Collecting);
    assert!(
        !*restart_refused,
        "a freshly constructed node has refused nothing"
    );
    assert_eq!(*node_zero_public_key, [3u8; PUBLIC_KEY_SIZE]);
    assert_eq!(blocks.len(), 0);
    // Story 4.4: the `chain_heads` table + scheduler state must init to
    // their empty/sentinel values too (`ChainHeadsTable::init` writes
    // every entry element-by-element).
    assert_eq!(chain_heads.count(), 0);
    assert_eq!(node_info.max_known_node_id(), 0);
    assert!(!node_info.is_seeded(0));
    // All-zero vote order is headed by node 0 (bootstrap rule).
    assert_eq!(vote_engine.top_creator(), Some(0));
    assert_eq!(*last_parent_request_emit_timestamp, 0);
    assert_eq!(*active_chain_head_idx, NONE_REF);
    assert_eq!(*tentative_config_block_idx, NONE_REF);
    assert_eq!(*snake_chain_tail_idx, NONE_REF);
    assert_eq!(*active_branch_value, 0);
    // Story 6.4: no window yet, so no active set; an empty ring, `F = 0`.
    assert!(!active_set.is_valid());
    assert!((0..16).all(|node| active_set.count(node) == 0));
    assert!(*non_conflict == NonConflictRing::new());
    assert_eq!(non_conflict.floor(), 0);
    // Story 6.5: an empty relay-dedupe cache.
    assert!(
        *support_dedupe
            == SupportDedupe::new(Prng::new(0xDEAD_BEEF).derive_subseed(DEDUPE_SALT_LABEL))
    );
    // Story 6.6: no accumulator.
    assert!(approval.deviation().is_none());
    assert!(*approval == ApprovalAccumulator::new());
    // Story 6.7: no open deviation run.
    assert_eq!(*active_open_run, NO_OPEN_RUN);
    assert!(!*reentry_due);
    assert_eq!(bc.local_node_id(), 7);
}

/// `init` must produce exactly what the by-value specification `new()`
/// produces. Both sides are destructured exhaustively (no `..`): adding a
/// field to `Blockchain` is a compile error in `new()`'s literal *and*
/// here until it is initialized and compared. The opaque backends
/// (`crypto`, `storage`, `chain_config`) are moved in as given on both
/// sides and carry no `PartialEq`; every field this crate writes is
/// compared. Never compare the two byte-for-byte: padding is
/// uninitialized, and Miri rejects reading it.
#[test]
fn init_is_equivalent_to_new() {
    let (crypto, storage, chain_config) = construction_backends();
    let mut slot =
        core::mem::MaybeUninit::<Blockchain<_, _, _, 16, 16, TEST_MAX_BLOCKS, 4, 16>>::uninit();
    let built = Blockchain::<_, _, _, 16, 16, TEST_MAX_BLOCKS, 4, 16>::init(
        &mut slot,
        crypto,
        storage,
        chain_config,
        7,
        [3u8; PUBLIC_KEY_SIZE],
        0xDEAD_BEEF,
    );
    let (crypto, storage, chain_config) = construction_backends();
    let spec = Blockchain::<_, _, _, 16, 16, TEST_MAX_BLOCKS, 4, 16>::new(
        crypto,
        storage,
        chain_config,
        7,
        [3u8; PUBLIC_KEY_SIZE],
        0xDEAD_BEEF,
    );

    let Blockchain {
        crypto: _,
        storage: _,
        chain_config: _,
        local_node_id,
        node_zero_public_key,
        prng,
        lifecycle_phase,
        restart_refused,
        blocks,
        chain_heads,
        node_info,
        vote_engine,
        last_parent_request_emit_timestamp,
        active_chain_head_idx,
        tentative_config_block_idx,
        snake_chain_tail_idx,
        active_branch_value,
        active_set,
        non_conflict,
        support_dedupe,
        approval,
        active_open_run,
        reentry_due,
    } = &*built;
    let Blockchain {
        crypto: _,
        storage: _,
        chain_config: _,
        local_node_id: spec_local_node_id,
        node_zero_public_key: spec_node_zero_public_key,
        prng: spec_prng,
        lifecycle_phase: spec_lifecycle_phase,
        restart_refused: spec_restart_refused,
        blocks: spec_blocks,
        chain_heads: spec_chain_heads,
        node_info: spec_node_info,
        vote_engine: spec_vote_engine,
        last_parent_request_emit_timestamp: spec_last_parent_request_emit_timestamp,
        active_chain_head_idx: spec_active_chain_head_idx,
        tentative_config_block_idx: spec_tentative_config_block_idx,
        snake_chain_tail_idx: spec_snake_chain_tail_idx,
        active_branch_value: spec_active_branch_value,
        active_set: spec_active_set,
        non_conflict: spec_non_conflict,
        support_dedupe: spec_support_dedupe,
        approval: spec_approval,
        active_open_run: spec_active_open_run,
        reentry_due: spec_reentry_due,
    } = &spec;

    assert_eq!(local_node_id, spec_local_node_id);
    assert_eq!(node_zero_public_key, spec_node_zero_public_key);
    assert!(prng == spec_prng);
    assert!(lifecycle_phase == spec_lifecycle_phase);
    assert!(restart_refused == spec_restart_refused);
    assert!(blocks == spec_blocks);
    assert!(chain_heads == spec_chain_heads);
    assert!(node_info == spec_node_info);
    assert!(vote_engine == spec_vote_engine);
    assert_eq!(
        last_parent_request_emit_timestamp,
        spec_last_parent_request_emit_timestamp
    );
    assert_eq!(active_chain_head_idx, spec_active_chain_head_idx);
    assert_eq!(tentative_config_block_idx, spec_tentative_config_block_idx);
    assert_eq!(snake_chain_tail_idx, spec_snake_chain_tail_idx);
    assert_eq!(active_branch_value, spec_active_branch_value);
    assert!(active_set == spec_active_set);
    assert!(non_conflict == spec_non_conflict);
    assert!(support_dedupe == spec_support_dedupe);
    assert!(approval == spec_approval);
    assert_eq!(active_open_run, spec_active_open_run);
    assert_eq!(reentry_due, spec_reentry_due);
}

/// AC2 — the neutrality proof: with the base override set (the window alone)
/// the configuration module resolves every parameter the blockchain reads to
/// the exact constant the retired `FixedChainConfig` returned. This is what
/// lets the rest of the suite keep its expected values unchanged, and it
/// replaces the stub's own `fixed_returns_expected_constants`.
#[test]
fn code_baked_defaults_reproduce_the_retired_stub() {
    let (crypto, _, _) = test_backends();
    let chain_config = locked_chain_config(&crypto, TestChain::BUILD_LIMITS);
    let config = chain_config
        .active_configuration()
        .expect("a locked module answers with a handle");

    assert_eq!(config.inter_block_interval_ms(), 60_000);
    assert_eq!(config.grace_period_window_ms(), 30_000);
    assert_eq!(config.block_size_limit(), 2016);
    assert_eq!(config.max_utxo_outputs(), 255);
    assert_eq!(config.required_support(), 40);
    assert_eq!(config.vote_scale().get(), 1000);
    assert_eq!(config.vote_interest(), 5);
    assert_eq!(config.parent_recovery_per_head_retry_interval_ms(), 120_000);
    assert_eq!(config.parent_recovery_min_emit_interval_ms(), 10_000);
    // The one value the fixtures declare rather than default (Story 5.11).
    assert_eq!(config.active_chain_length(), TEST_W);
    assert!(chain_config.is_durable_locked());
}

/// AC3 — before any configuration is loaded the block-size limit falls back
/// to the framing bound, and the parent-recovery scheduler stands down.
/// (Project Lead ruling, 2026-09-19.)
#[test]
fn unconfigured_node_falls_back_to_the_framing_bound_and_idles() {
    let (crypto, storage, chain_config) = test_backends();
    let mut bc = new_chain(crypto, storage, chain_config, 5, 0);

    assert_eq!(bc.block_size_limit(), MAX_BLOCK_SIZE as u32);
    assert!(bc.parent_recovery_intervals().is_none());
    let (outcome, next) = bc.on_tick(1_000_000);
    assert!(matches!(outcome, TickOutcome::Idle));
    assert!(matches!(next, NextCall::Idle));
}

/// Story 5.12 — a parameter program reading the registered-node count:
/// `parent_recovery_min_emit_interval_ms = GETCHAININFO 1, 0; PUSH_U16 1000; MUL`.
fn node_count_cadence_builder() -> ChainConfigPayloadBuilder {
    let mut builder = window_config_builder(TEST_W);
    builder
        .add_bytecode(
            parameter::PARENT_RECOVERY_MIN_EMIT_INTERVAL_MS,
            &[
                0x71,
                chain_info::REGISTERED_NODE_COUNT,
                0,
                0x11,
                0xE8,
                0x03,
                0x42,
                0x01,
            ],
        )
        .ok()
        .expect("the program frames");
    builder
}

/// Story 5.12, AC4/AC5 — in Ready the scheduler's programs read the
/// registered-node count at the head: after genesis one node is registered.
#[test]
fn chain_info_reaches_the_scheduler_in_ready() {
    let (crypto, storage, chain_config) = test_backends();
    let mut bc = new_chain(crypto, storage, chain_config, 0, 0);
    let builder = node_count_cadence_builder();
    bc.process_genesis(1_000_000_000, builder.content())
        .ok()
        .expect("genesis succeeds");
    assert!(bc.is_ready());
    assert_eq!(
        bc.chain_info_at_head()
            .read(chain_info::REGISTERED_NODE_COUNT, &[]),
        Some(1)
    );
    assert_eq!(
        bc.parent_recovery_intervals().map(|(min_emit, _)| min_emit),
        Some(1_000),
        "one registered node, one second"
    );
}

/// Story 5.12, AC5 — the value is the derived watermark plus one, not a
/// constant: a pass that registers node 2 on top of a balance block naming
/// nodes up to 1 leaves three registered nodes, served once Ready.
#[test]
fn chain_info_reads_the_derived_watermark() {
    let mut bc = new_test_chain();
    let cfg_hash = admit_chain_config_anchor(&mut bc, 99, [0xAB; 32]);
    let anchor = balance_block(100, cfg_hash, &[(1, 100, 0, 0x31)], 1);
    bc.tier1_admit(&anchor.view(), &anchor.view().hash(), 0)
        .expect("anchor admitted");
    let reg = registration_block(101, anchor.view().hash(), 1, 2, 0x45);
    let ri = bc
        .tier1_admit(&reg.view(), &reg.view().hash(), 0)
        .expect("registration admitted");
    bc.run_processing_pass(ri).expect("pass succeeds");
    assert_eq!(
        bc.chain_info_at_head()
            .read(chain_info::REGISTERED_NODE_COUNT, &[]),
        None,
        "not Ready yet"
    );

    bc.set_lifecycle_phase(LifecyclePhase::Processing);
    bc.set_lifecycle_phase(LifecyclePhase::Ready);
    let info = bc.chain_info_at_head();
    assert_eq!(info.read(chain_info::REGISTERED_NODE_COUNT, &[]), Some(3));
    assert_eq!(
        info.read(chain_info::REGISTERED_NODE_COUNT, &[0]),
        None,
        "identifier 1 takes no arguments"
    );
}

/// Story 5.12, AC4 — while Collecting there is no active chain: the read is
/// declined and the program falls back to the code-baked default.
#[test]
fn chain_info_is_declined_while_collecting() {
    let (crypto, storage, _) = test_backends();
    let mut chain_config = empty_chain_config(TestChain::BUILD_LIMITS);
    chain_config
        .load_durable(node_count_cadence_builder().build_signed(&crypto))
        .ok()
        .expect("the content is accepted");
    let bc = new_chain(crypto, storage, chain_config, 5, 0);
    assert!(!bc.is_ready());
    assert_eq!(
        bc.chain_info_at_head()
            .read(chain_info::REGISTERED_NODE_COUNT, &[]),
        None
    );
    assert_eq!(
        bc.parent_recovery_intervals().map(|(min_emit, _)| min_emit),
        Some(10_000),
        "declined, so the code-baked default"
    );
}

/// AC1, AC4, AC5 — successful genesis bootstrap on `local_node_id == 0`
/// yields **both** Block #0 and Block #1 in a single `process_genesis`
/// call (no `NextCall`), with no embassy deps anywhere in the harness.
#[test]
fn walking_skeleton_genesis_success() {
    let (crypto, storage, chain_config) = test_backends();
    let expected_node_zero_public_key = *crypto.public_key().serialize();
    let initial_chain_config_bytes = OTHER_CONFIG_CONTENT;

    let mut bc = new_chain(crypto, storage, chain_config, 0, 0xDEAD_BEEF_CAFE_F00D);
    let GenesisBlocks {
        block_zero,
        block_one,
    } = bc
        .process_genesis(1_000_000_000, &initial_chain_config_bytes)
        .ok()
        .expect("genesis with local_node_id == 0 must succeed (FR54)");

    // --- Block #0: registration + self-transfer ---
    assert_eq!(block_zero.sequence(), 0);
    assert_eq!(block_zero.creator(), 0);
    assert_eq!(block_zero.version(), 1);
    assert_eq!(block_zero.payload_type(), PAYLOAD_TYPE_TRANSACTION);
    assert!(
        any_nonzero(block_zero.signature()),
        "Block #0 must be signed"
    );
    let mut transactions = block_zero
        .transactions()
        .expect("genesis Block #0 should contain transaction payload")
        .iter();
    let registration = transactions
        .next()
        .expect("first genesis transaction should register node #0")
        .as_registration()
        .expect("first genesis transaction should be Registration");
    assert_eq!(
        registration.new_public_key(),
        &expected_node_zero_public_key
    );
    assert!(any_nonzero(registration.new_key_signature()));
    assert!(any_nonzero(registration.signature()));
    let self_transfer = transactions
        .next()
        .expect("second genesis transaction should seed node #0 balance")
        .as_node_transfer()
        .expect("second genesis transaction should be NodeTransfer");
    assert!(any_nonzero(self_transfer.signature()));
    assert!(transactions.next().is_none());

    // --- Block #1: chain-config, chained to Block #0 ---
    assert_eq!(block_one.sequence(), 1);
    assert_eq!(block_one.version(), 1);
    assert_eq!(block_one.payload_type(), PAYLOAD_TYPE_CHAIN_CONFIG);
    assert_eq!(
        block_one.previous_hash(),
        &block_zero.hash()[..],
        "Block #1 must chain to Block #0"
    );
    let block_one_config = block_one
        .view()
        .chain_config()
        .expect("Block #1 must frame a chain-config envelope");
    assert_eq!(
        block_one_config.content(),
        &initial_chain_config_bytes[..],
        "Block #1 carries the initial chain-config content verbatim"
    );
    assert!(
        bc.crypto.verify_signature(
            &initial_chain_config_bytes[..],
            &Signature::new(block_one_config.content_signature())
                .ok()
                .expect("the trailer is a well-formed signature"),
            bc.crypto.public_key(),
        ),
        "FR54: node #0 signs Block #1's content region"
    );
    assert!(
        any_nonzero(block_one.signature()),
        "Block #1 must be signed"
    );

    assert_eq!(
        bc.chain_config.durable_content(),
        Some(&initial_chain_config_bytes[..]),
        "FR54: genesis leaves the configuration durably locked on its content"
    );
    // Node #0 authored the whole chain — it is immediately Ready.
    assert!(bc.current_phase() == LifecyclePhase::Ready);
    assert_eq!(bc.local_node_id(), 0);

    // Both genesis blocks are mirrored into the in-memory tree (in sync with
    // storage), forming the active chain with Block #1 as the tip.
    assert_eq!(bc.blocks.len(), 2);
    assert_eq!(bc.active_chain_head_idx, 1, "Block #1 is the active tip");
    let head_0 = bc.blocks.get(0).expect("Block #0 in tree");
    let head_1 = bc.blocks.get(1).expect("Block #1 in tree");
    assert!(head_0.is_on_active_chain());
    assert!(head_1.is_on_active_chain());
    assert_eq!(head_1.sequence(), 1);
    assert_eq!(head_1.parent_ref(), 0, "Block #1 parent is Block #0's slot");
    assert_eq!(bc.chain_heads.count(), 1, "one active head after genesis");
}

/// The single genesis head is **Connected** (on the active chain), not a
/// Stored tail-point — so there is nothing to parent-recover: `on_tick`
/// stays `Idle` and no `SendParentRecoveryRequest` is emitted for the
/// self-authored chain. Guards against a misclassified genesis head.
#[test]
fn genesis_head_is_connected_no_parent_recovery() {
    let (crypto, storage, chain_config) = test_backends();
    let mut bc = new_chain(crypto, storage, chain_config, 0, 0);
    bc.process_genesis(1_000_000_000, &BASE_CONFIG_CONTENT)
        .ok()
        .expect("genesis must succeed");

    assert!(
        !bc.chain_heads.has_stored_head(),
        "the genesis head must be Connected, not a Stored tail-point"
    );
    let (outcome, _next) = bc.on_tick(1_000_000);
    assert!(
        matches!(outcome, TickOutcome::Idle),
        "a complete genesis chain schedules no parent-recovery"
    );
}

/// AC2 — `local_node_id != 0` refuses genesis and leaves the chain empty.
/// The `Err(_)` arm is forward-compat for the additional
/// `GenesisRejectReason` variants Story 5.6+ introduces.
#[allow(unreachable_patterns)]
#[test]
fn walking_skeleton_refuses_non_zero_local_node_id() {
    let (crypto, storage, chain_config) = test_backends();
    let mut bc = new_chain(crypto, storage, chain_config, 1, 0);

    let outcome = bc.process_genesis(1_000_000_000, &[]);

    match outcome {
        Err(GenesisRejectReason::LocalNodeIdNotZero) => {}
        Err(_) => panic!("expected LocalNodeIdNotZero refusal"),
        Ok(_) => panic!("FR54 precondition must refuse local_node_id != 0"),
    }
    // Nothing was loaded on the refusal path.
    assert!(!bc.chain_config.is_durable_locked());
}

/// Genesis content whose signature trailer would push the payload past
/// `MAX_PAYLOAD_SIZE` is refused before anything is written.
#[test]
fn walking_skeleton_rejects_oversized_initial_chain_config() {
    let (crypto, storage, chain_config) = test_backends();
    let oversized = [0u8; MAX_PAYLOAD_SIZE - SIGNATURE_SIZE + 1];
    let mut bc = new_chain(crypto, storage, chain_config, 0, 0);

    let outcome = bc.process_genesis(1_000_000_000, &oversized);

    match outcome {
        Err(GenesisRejectReason::InitialChainConfigTooLarge) => {}
        Err(_) => panic!("expected InitialChainConfigTooLarge refusal"),
        Ok(_) => panic!("oversized initial chain-config bytes must be refused"),
    }
}

/// A node whose configuration is already durably locked has been
/// bootstrapped, so genesis is refused before it can overwrite the lock
/// (`StorageNotEmpty`). FR54's lock is set-once.
#[test]
fn walking_skeleton_refuses_genesis_when_chain_config_already_locked() {
    let (crypto, storage, _) = test_backends();
    let chain_config = locked_chain_config(&crypto, TestChain::BUILD_LIMITS);
    let mut bc = new_chain(crypto, storage, chain_config, 0, 0);

    let outcome = bc.process_genesis(1_000_000_000, &OTHER_CONFIG_CONTENT);

    match outcome {
        Err(GenesisRejectReason::StorageNotEmpty) => {}
        Err(_) => panic!("expected StorageNotEmpty refusal"),
        Ok(_) => panic!("genesis must not overwrite a durably locked configuration"),
    }
    // The locked content is untouched.
    assert_eq!(
        bc.chain_config.durable_content(),
        Some(&BASE_CONFIG_CONTENT[..])
    );
}

/// Genesis is a one-shot bootstrap: a second `process_genesis` on the same
/// node refuses with `StorageNotEmpty` (the chain now carries genesis state).
#[test]
fn walking_skeleton_refuses_second_genesis() {
    let (crypto, storage, chain_config) = test_backends();
    let mut bc = new_chain(crypto, storage, chain_config, 0, 0);

    let first = bc.process_genesis(1_000_000_000, &BASE_CONFIG_CONTENT);
    assert!(first.is_ok(), "first genesis must succeed");

    let second = bc.process_genesis(1_000_000_000, &OTHER_CONFIG_CONTENT);
    match second {
        Err(GenesisRejectReason::StorageNotEmpty) => {}
        Err(_) => panic!("expected StorageNotEmpty on the second genesis"),
        Ok(_) => panic!("genesis must run at most once per chain"),
    }
}

/// Storage persistence failure refuses genesis; no `Created` outcome is
/// returned when a genesis block cannot be retained locally.
#[test]
fn walking_skeleton_refuses_storage_save_failure() {
    let private_key = [1u8; PRIVATE_KEY_SIZE];
    let crypto = Crypto::new(private_key)
        .ok()
        .expect("test private key should be accepted by the backend");
    let chain_config = empty_chain_config(TestChain::BUILD_LIMITS);
    let node_zero = *crypto.public_key().serialize();

    let mut bc_slot =
        core::mem::MaybeUninit::<Blockchain<_, _, _, 16, 16, TEST_MAX_BLOCKS, 4, 16>>::uninit();
    let bc = Blockchain::<_, _, _, 16, 16, TEST_MAX_BLOCKS, 4, 16>::init(
        &mut bc_slot,
        crypto,
        BlockWriteFailsStorage,
        chain_config,
        0,
        node_zero,
        0,
    );

    let outcome = bc.process_genesis(1_000_000_000, &BASE_CONFIG_CONTENT);

    match outcome {
        Err(GenesisRejectReason::StorageSaveFailed) => {}
        Err(_) => panic!("expected StorageSaveFailed refusal"),
        Ok(_) => panic!("genesis must not succeed when a genesis block cannot be persisted"),
    }
    // FR54's lock is set-once, so a refusal that engaged it would refuse
    // every retry for the life of the process. The content is held
    // tentatively until the last durable write succeeds, so a storage
    // failure leaves the node able to bootstrap again.
    assert!(
        !bc.chain_config.is_durable_locked(),
        "a genesis that failed on storage must not leave the configuration locked"
    );
    assert!(
        bc.chain_config.tentative_content().is_some(),
        "the accepted content is held tentatively, ready to be replaced by a retry"
    );
}

/// The durable configuration seam needs the storage control plane; block
/// writes do not. Without an up-front check an uninitialized backend would
/// persist both genesis blocks and then refuse the configuration, and the
/// non-empty-chain guard would turn away every retry for the life of the
/// process. The precondition is therefore checked with the other pre-write
/// guards, and nothing is written.
#[test]
fn walking_skeleton_refuses_uninitialized_storage() {
    let private_key = [1u8; PRIVATE_KEY_SIZE];
    let crypto = Crypto::new(private_key)
        .ok()
        .expect("test private key should be accepted by the backend");
    // Never `init`ed: `save_block` would succeed, `set_chain_configuration`
    // would not.
    let storage = MemoryBackend::<{ 8 * MAX_BLOCK_SIZE + 8000 }>::new();
    let chain_config = empty_chain_config(TestChain::BUILD_LIMITS);
    let node_zero = *crypto.public_key().serialize();
    let mut bc_slot = core::mem::MaybeUninit::<TestChain>::uninit();
    let bc = TestChain::init(&mut bc_slot, crypto, storage, chain_config, 0, node_zero, 0);

    let outcome = bc.process_genesis(1_000_000_000, &BASE_CONFIG_CONTENT);

    match outcome {
        Err(GenesisRejectReason::StorageNotInitialized) => {}
        Err(_) => panic!("expected StorageNotInitialized refusal"),
        Ok(_) => panic!("genesis must not run without a usable control plane"),
    }
    assert_eq!(bc.blocks.len(), 0, "no block reached the in-memory tree");
    assert!(
        bc.storage.read_block(0).is_err(),
        "no block reached storage either"
    );
    assert!(!bc.chain_config.is_durable_locked());
}

/// A configuration whose own `block_size_limit` is smaller than the genesis
/// blocks it frames would produce a chain no node can accept: every peer
/// refuses Block #1 at Tier 1, and the founder's own restart refuses it at
/// FR6. Genesis must not create it.
#[test]
fn walking_skeleton_refuses_genesis_blocks_above_the_declared_limit() {
    let (crypto, storage, chain_config) = test_backends();
    let mut bc = new_chain(crypto, storage, chain_config, 0, 0);
    // `block_size_limit` (id 3) declared as 300: legal for the registry
    // (> HEADER_SIZE, <= MAX_BLOCK_SIZE), smaller than Block #0. The window
    // entry is the one every content on this harness carries. A support
    // threshold of 1 keeps the limit above the room a one-signer approval
    // needs (configuration §6 check 20), so only the genesis size refuses.
    let w = TEST_W.to_le_bytes();
    let h = test_horizon(TEST_W).to_le_bytes();
    let n = TEST_MAX_NODES.to_le_bytes();
    let content = [
        6u8,
        0,
        parameter::BLOCK_SIZE_LIMIT,
        4,
        0x2C,
        0x01,
        0,
        0,
        parameter::REQUIRED_SUPPORT,
        1,
        1,
        parameter::ACTIVE_CHAIN_LENGTH,
        4,
        w[0],
        w[1],
        w[2],
        w[3],
        parameter::VERIFICATION_HORIZON,
        4,
        h[0],
        h[1],
        h[2],
        h[3],
        parameter::MAX_NODE_COUNT,
        4,
        n[0],
        n[1],
        n[2],
        n[3],
        parameter::SIGNATURE_SCHEME,
        1,
        moonblokz_crypto::SIGNATURE_SCHEME,
    ];

    let outcome = bc.process_genesis(1_000_000_000, &content);

    match outcome {
        Err(GenesisRejectReason::GenesisBlockExceedsBlockSizeLimit) => {}
        Err(_) => panic!("expected GenesisBlockExceedsBlockSizeLimit refusal"),
        Ok(_) => panic!("genesis must not create a chain that rejects its own blocks"),
    }
    assert_eq!(bc.blocks.len(), 0, "nothing was written");
    assert!(!bc.chain_config.is_durable_locked());
}

/// AC3 — read-only queries are typed to **not** carry `NextCall`.
/// This is a compile-time guarantee: `current_phase` returns
/// `LifecyclePhase` directly (not `CallResult<LifecyclePhase>`), and
/// `local_node_id` returns `u32` directly.
#[test]
fn walking_skeleton_query_carries_no_next_call() {
    let (crypto, storage, chain_config) = test_backends();
    let mut bc = new_chain(crypto, storage, chain_config, 0, 0);
    bc.process_genesis(1_000_000_000, &BASE_CONFIG_CONTENT)
        .ok()
        .expect("genesis must succeed for local_node_id == 0");

    // Type-level assertion: the query result is `LifecyclePhase`,
    // not `(LifecyclePhase, NextCall)`. If the signature ever drifts
    // back to `CallResult`, this annotation will fail to compile.
    let phase: LifecyclePhase = bc.current_phase();
    assert!(phase == LifecyclePhase::Ready);

    let node_id: u32 = bc.local_node_id();
    assert_eq!(node_id, 0);
}

// --- Story 4.2: FR9 Tier 1 admission entry point ------------------------

type TestChain = Blockchain<
    Crypto,
    MemoryBackend<{ 8 * MAX_BLOCK_SIZE + 8000 }>,
    TestConfig,
    16,
    16,
    TEST_MAX_BLOCKS,
    4,
    16,
>;

fn new_test_chain() -> TestChain {
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

/// As [`node_transfer_block`], but chained to `prev` so the block can sit
/// above another in a candidate segment.
fn chained_node_transfer_block(
    seq: u32,
    prev: [u8; 32],
    vote: u32,
    anchor: u32,
    initializer: u32,
) -> Block {
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

fn node_transfer_block(seq: u32, vote: u32, anchor: u32, initializer: u32) -> Block {
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

/// AC4: a Tier 1-passing block is admitted at `Stored` and persisted.
#[test]
fn tier1_admit_inserts_at_stored() {
    let mut bc = new_test_chain();
    let block = node_transfer_block(5, 3, 4, 7);
    let idx = bc
        .tier1_admit(&block.view(), &block.view().hash(), 1_000)
        .expect("well-formed block is admitted");
    assert_eq!(bc.blocks.len(), 1);
    assert_eq!(
        bc.blocks.get(idx).expect("entry present").status(),
        BlockStatus::Stored,
        "collecting-state admission is always Stored (AC4)"
    );
    // Durable storage received the block (storage-first admission).
    assert!(bc.storage.read_block(idx).is_ok());
}

/// AC5: a Tier 1 failure returns the exact-evidence form and stores nothing.
#[test]
fn tier1_admit_rejects_and_does_not_store() {
    let mut bc = new_test_chain();
    // initializer == vote == 7 → FR6 self-vote.
    let block = node_transfer_block(5, 7, 4, 7);
    let result = bc.tier1_admit(&block.view(), &block.view().hash(), 1_000);
    assert_eq!(result, Err(AdmitError::Rejected(Tier1Failure::SelfVote)));
    assert_eq!(bc.blocks.len(), 0, "a rejected block must not be stored");
}

// (FR11 de-duplication is owned by `classify_block`, not `tier1_admit`, so
// there is no `tier1_admit` duplicate case — the dedup outcome is covered
// by `intake::tests::receive_block_duplicate_is_duplicate_known`.)

// --- Story 4.4: FR19 chain_heads admission / scheduler / bootstrap -------

/// A transfer block whose `previous_hash` is set to `prev` (so it can extend
/// a specific parent). `node_transfer_block` zero-fills `previous_hash`, which
/// makes an orphan (Stored head); this helper links a child to its parent.
fn linked_transfer_block(seq: u32, prev: [u8; 32]) -> Block {
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

/// AC7 — a genesis block (sequence 0, no parent) anchors the active chain: it
/// becomes a Connected head, `active_chain_head_idx` is set, and no Stored
/// head (hence no parent-recovery tick) is scheduled.
#[test]
fn receive_block_genesis_anchors_active_head() {
    // A joining node, holding no configuration yet — the order in which a
    // real node meets a chain, and the only order in which the genesis can be
    // observed on its own: once a configuration is held, the genesis
    // admission completes an FR2 candidate and the whole lifecycle runs
    // inside this same call.
    let mut bc = new_unconfigured_test_chain();
    // Block-zero waives the self-vote / anchor Tier 1 checks.
    let genesis = node_transfer_block(0, 7, 0, 7);
    let (outcome, _) = bc.receive_block(genesis.view(), 100);
    assert_eq!(outcome, ReceiveBlockOutcome::AcceptedSilently);
    assert_eq!(
        bc.current_active_head(),
        Some(0),
        "genesis is the active head"
    );
    // FR8 (Story 5.9): block #1 carries the chain-config, exactly as the FR54
    // bootstrap emits it. It loads the tentative configuration (AC2) and
    // completes a candidate that names one (AC3), so the node goes Ready —
    // which is what makes the `NextCall::Idle` assertion below non-vacuous:
    // the intervals it would need are now available, and there is genuinely
    // no Stored head left to schedule.
    let cfg = chain_config_anchor_block(1, genesis.view().hash());
    let (outcome, next) = bc.receive_block(cfg.view(), 100);
    assert_eq!(outcome, ReceiveBlockOutcome::AcceptedSilently);
    assert!(
        bc.blocks
            .get(0)
            .is_some_and(|entry| entry.is_on_active_chain()),
        "the genesis still anchors the active chain"
    );
    assert!(
        matches!(next, NextCall::Idle),
        "a fully-connected active chain schedules no parent recovery"
    );
}

/// AC7 — a non-genesis first block with an unresolved parent creates a Stored
/// head and schedules the initial parent-recovery tick.
#[test]
fn receive_block_orphan_creates_stored_head_and_schedules() {
    let mut bc = new_test_chain();
    let orphan = node_transfer_block(5, 3, 4, 7);
    let (outcome, next) = bc.receive_block(orphan.view(), 1_000);
    assert_eq!(outcome, ReceiveBlockOutcome::AcceptedSilently);
    assert!(bc.current_active_head().is_none());
    assert!(
        matches!(next, NextCall::At(_)),
        "orphan schedules parent recovery"
    );
}

/// AC2 — `on_tick` emits exactly one FR19 request for the Stored head, with
/// the tail-point's missing-parent hash and `tail.sequence − 1`.
#[test]
fn on_tick_emits_parent_recovery_request() {
    let mut bc = new_test_chain();
    let orphan = node_transfer_block(5, 3, 4, 7); // previous_hash == [0; 32]
    bc.receive_block(orphan.view(), 0);
    // Advance past the FR46 global cooldown + per-head retry (lrt == 0).
    let (outcome, next) = bc.on_tick(1_000_000);
    match outcome {
        TickOutcome::SendParentRecoveryRequest(req) => {
            assert_eq!(req.missing_parent_hash(), &[0u8; 32]);
            assert_eq!(req.claimed_parent_sequence(), 4, "tail.sequence - 1");
        }
        TickOutcome::Idle => panic!("a Stored head past its retry window must emit"),
    }
    assert!(
        matches!(next, NextCall::At(_)),
        "Stored head still awaits its parent"
    );
}

/// AC2/AC3 — the FR46 global emit cooldown suppresses a second emission within
/// `parent_recovery_min_emit_interval`, even with an eligible head.
#[test]
fn on_tick_global_cooldown_suppresses_second_emission() {
    let mut bc = new_test_chain();
    // Two orphan heads so a head is always eligible.
    bc.receive_block(node_transfer_block(5, 3, 4, 7).view(), 0);
    bc.receive_block(linked_transfer_block(9, [0xAB; 32]).view(), 0);
    let t = 1_000_000;
    let (first, _) = bc.on_tick(t);
    assert!(matches!(first, TickOutcome::SendParentRecoveryRequest(_)));
    // min_emit is 10_000ms; a tick 5_000ms later is inside the cooldown.
    let (second, _) = bc.on_tick(t + 5_000);
    assert_eq!(second, TickOutcome::Idle, "global cooldown suppresses");
    // Past the cooldown, emission resumes.
    let (third, _) = bc.on_tick(t + 10_000);
    assert!(matches!(third, TickOutcome::SendParentRecoveryRequest(_)));
}

/// The `NextCall` is the **exact** next-eligible instant (AR4 pull model),
/// not `now + a fixed periodic tick`. A fresh orphan (`lrt == 0`, module
/// never emitted) is gated only by the FR46 boot-time global cooldown, so the
/// deadline is `min_emit` regardless of `now`; after an emission it is the
/// per-head window end.
#[test]
fn parent_recovery_nextcall_is_exact_deadline() {
    let mut bc = new_test_chain();
    let orphan = node_transfer_block(5, 3, 4, 7);
    // min_emit (stub) = 10_000; last_emit = 0 → deadline = max(0, 10_000).
    let (_, next) = bc.receive_block(orphan.view(), 5_000);
    assert!(
        matches!(next, NextCall::At(10_000)),
        "exact cooldown deadline, independent of now (5_000)"
    );
    // Emit at a large now; the next deadline is the per-head window end
    // (lrt 1_000_000 + per_head_retry 120_000), not now + a fixed interval.
    let (_, next2) = bc.on_tick(1_000_000);
    assert!(
        matches!(next2, NextCall::At(1_120_000)),
        "exact per-head window end after emission"
    );
}

/// AC3 — a fresh chain (no Stored heads) ticks Idle with no wake-up.
#[test]
fn on_tick_idle_without_stored_heads() {
    let mut bc = new_test_chain();
    let (outcome, next) = bc.on_tick(5_000);
    assert_eq!(outcome, TickOutcome::Idle);
    assert!(matches!(next, NextCall::Idle));
}

/// AC4 — an extend admission advances the single head (no second head).
#[test]
fn receive_block_extend_advances_head() {
    let mut bc = new_test_chain();
    let a = node_transfer_block(5, 3, 4, 7);
    bc.receive_block(a.view(), 0);
    let a_hash = a.view().hash();
    let b = linked_transfer_block(6, a_hash);
    let (outcome, _) = bc.receive_block(b.view(), 0);
    assert_eq!(outcome, ReceiveBlockOutcome::AcceptedSilently);
    assert_eq!(bc.block_tree_len(), 2);
    // Still one Stored head (A's orphan tail), advanced to B: on_tick emits a
    // request whose claimed parent is A's missing parent (tail seq 5 - 1 = 4).
    let (outcome, _) = bc.on_tick(1_000_000);
    match outcome {
        TickOutcome::SendParentRecoveryRequest(req) => {
            assert_eq!(req.claimed_parent_sequence(), 4);
        }
        TickOutcome::Idle => {
            panic!("the advanced Stored head must still request its tail parent")
        }
    }
}

/// AC9 — replaying an identical block + tick sequence against two fresh chains
/// yields identical emitted `ParentRecoveryRequest`s and tree/head state,
/// regardless of the `now` values used for scheduling.
#[test]
fn parent_recovery_is_deterministic_replay() {
    // `no_std`: collect emitted claimed-sequences into a fixed array
    // (at most one per tick).
    fn run(ticks: &[u64; 3]) -> (usize, [Option<u32>; 3]) {
        let mut bc = new_test_chain();
        // Three orphan heads with distinct sequences.
        for seq in [7u32, 5, 9] {
            bc.receive_block(node_transfer_block(seq, 3, seq - 1, 7).view(), 0);
        }
        let mut claimed: [Option<u32>; 3] = [None; 3];
        for (i, &t) in ticks.iter().enumerate() {
            if let (TickOutcome::SendParentRecoveryRequest(req), _) = bc.on_tick(t) {
                claimed[i] = Some(req.claimed_parent_sequence());
            }
        }
        (bc.block_tree_len(), claimed)
    }
    // Widely spaced ticks so each clears the global cooldown + per-head retry.
    let ticks = [1_000_000, 2_000_000, 3_000_000];
    let (len_a, claims_a) = run(&ticks);
    let (len_b, claims_b) = run(&ticks);
    assert_eq!(len_a, len_b);
    assert_eq!(
        claims_a, claims_b,
        "identical emission order across replays"
    );
    // Deterministic selection: smallest head_sequence (5) first → claimed 4.
    assert_eq!(claims_a[0], Some(4));
}

// --- Story 5.1: lifecycle state machine, init paths, not-ready gating -----

/// AC1/AC3 — a freshly constructed node (join path via `init`) is in
/// `Collecting` and not ready.
#[test]
fn fresh_node_is_collecting_and_not_ready() {
    let bc = new_test_chain();
    assert!(bc.current_phase() == LifecyclePhase::Collecting);
    assert!(!bc.is_ready());
}

/// AC2 — a node that authored genesis is `Ready` (init-time direct-set, not a
/// runtime transition).
#[test]
fn genesis_node_is_ready() {
    let (crypto, storage, chain_config) = test_backends();
    let mut bc = new_chain(crypto, storage, chain_config, 0, 1);
    bc.process_genesis(1_000_000_000, &BASE_CONFIG_CONTENT)
        .ok()
        .expect("genesis must succeed");
    assert!(bc.current_phase() == LifecyclePhase::Ready);
    assert!(bc.is_ready());
}

/// AC1 — the guarded mutator accepts every legal runtime edge.
#[test]
fn set_lifecycle_phase_accepts_legal_edges() {
    // Collecting → Processing → Ready.
    let mut bc = new_test_chain();
    bc.set_lifecycle_phase(LifecyclePhase::Processing);
    assert!(bc.current_phase() == LifecyclePhase::Processing);
    bc.set_lifecycle_phase(LifecyclePhase::Ready);
    assert!(bc.current_phase() == LifecyclePhase::Ready);

    // Processing → Collecting (FR5 recovery edge).
    let mut bc2 = new_test_chain();
    bc2.set_lifecycle_phase(LifecyclePhase::Processing);
    bc2.set_lifecycle_phase(LifecyclePhase::Collecting);
    assert!(bc2.current_phase() == LifecyclePhase::Collecting);
}

/// AC1 — the guarded mutator rejects the illegal direct `Collecting → Ready`
/// edge (debug-assert; `cargo test` runs debug).
#[test]
#[should_panic(expected = "illegal lifecycle transition")]
fn set_lifecycle_phase_rejects_collecting_to_ready() {
    let mut bc = new_test_chain();
    bc.set_lifecycle_phase(LifecyclePhase::Ready);
}

/// AC5 — the snake-chain window seam is phase-gated: `None` while not Ready
/// (so FR60 stays inactive and every admitted block is Stored, AC6).
#[test]
fn snake_chain_window_none_while_collecting() {
    let bc = new_test_chain();
    assert_eq!(
        bc.active_snake_chain_window(),
        Err(SnakeChainWindowError::NotReady)
    );
}

/// AC3 — the join follow-up on empty durable storage keeps the node
/// Collecting and reports `StartedCollecting`.
#[test]
fn initialize_from_storage_empty_starts_collecting() {
    let mut bc = new_test_chain();
    let (outcome, next) = bc.initialize_from_storage(0);
    assert_eq!(outcome, InitOutcome::StartedCollecting);
    assert!(matches!(next, NextCall::Idle));
    assert!(bc.current_phase() == LifecyclePhase::Collecting);
}

/// AC4 — the read-only queries return `Err(NotReady)` while Collecting (a
/// `Result`, so not-ready is a distinct signal, not `None`).
#[test]
fn collecting_gates_ready_only_queries() {
    let bc = new_test_chain();
    assert_eq!(bc.query_balance(1), Err(BalanceQueryError::NotReady));
    assert!(matches!(
        bc.query_block_by_hash(&[0u8; 32]),
        Err(BlockQueryError::NotReady)
    ));
    assert!(matches!(
        bc.query_block_by_sequence(0),
        Err(BlockQueryError::NotReady)
    ));
    assert_eq!(
        bc.query_transaction_state(&[0u8; 32]),
        Err(TxStateQueryError::NotReady)
    );
}

/// AC4 — state-changing Ready-state-only intake surfaces return `NotReady` with
/// `NextCall::Idle` while Collecting.
#[test]
fn collecting_gates_transaction_intake() {
    let mut bc = new_test_chain();
    let block = node_transfer_block(5, 3, 4, 7);
    let bv = block.view();
    let payload = bv.transactions().expect("transaction payload");

    let tx1 = payload.iter().next().expect("one transaction");
    let (o1, n1) = bc.receive_transaction(tx1, 1_000);
    assert_eq!(o1, ReceiveTransactionOutcome::NotReady);
    assert!(matches!(n1, NextCall::Idle));

    let tx2 = payload.iter().next().expect("one transaction");
    let (o2, n2) = bc.submit_local_transaction(tx2, 1_000);
    assert_eq!(o2, LocalTransactionOutcome::NotReady);
    assert!(matches!(n2, NextCall::Idle));
}

/// AC5 — the single-genesis guard: once an anchor exists, a second distinct
/// `sequence == 0` block is rejected as invalid evidence (FR16) — not stored,
/// not made a Stored orphan (which would emit perpetual bogus parent-recovery
/// and break the `chain_heads` "tail never seq 0" invariant), and it never
/// reseats the active chain.
#[test]
fn single_genesis_guard_rejects_second_seq0() {
    // Unconfigured: the guard is an admission property, decided from the
    // block bytes and `active_chain_head_idx` alone. Holding a configuration
    // would let the first genesis complete an FR2 candidate and run the
    // Epic-5 lifecycle inside the same call, which would be testing the
    // lifecycle rather than the guard.
    let mut bc = new_unconfigured_test_chain();

    // First genesis (seq 0) anchors the active chain at slot 0.
    let g1 = node_transfer_block(0, 7, 0, 7);
    let (o1, _) = bc.receive_block(g1.view(), 100);
    assert_eq!(o1, ReceiveBlockOutcome::AcceptedSilently);
    assert_eq!(bc.active_chain_head_idx, 0);
    assert_eq!(bc.current_active_head(), Some(0));
    assert_eq!(bc.blocks.len(), 1);

    // A second, distinct seq-0 block (different vote/initializer → different
    // hash) is rejected and leaves the chain untouched.
    let g2 = node_transfer_block(0, 3, 0, 3);
    assert_ne!(
        g1.view().hash(),
        g2.view().hash(),
        "distinct genesis blocks"
    );
    let (o2, _) = bc.receive_block(g2.view(), 200);
    assert_eq!(
        o2,
        ReceiveBlockOutcome::Rejected(RejectReason::InvalidEvidence)
    );
    assert_eq!(
        bc.active_chain_head_idx, 0,
        "second genesis must not reseat the active chain"
    );
    assert_eq!(bc.blocks.len(), 1, "second genesis must not be stored");
    assert_eq!(bc.chain_heads.count(), 1, "no spurious Stored head created");
}

/// AC8 (FR63/NFR5) — the lifecycle/gating surface is deterministic and
/// wall-clock-independent: replaying the identical init + block sequence with
/// **different** `now` values yields identical phase, active-head, and gate
/// outcomes. `now` affects only scheduling, never a phase/gate decision.
#[test]
fn lifecycle_surface_is_now_independent() {
    fn run(now_base: u64) -> (bool, Option<u32>, bool, bool) {
        let mut bc = new_test_chain();
        // Empty-storage init path (join).
        let (init_outcome, _) = bc.initialize_from_storage(now_base);
        assert_eq!(init_outcome, InitOutcome::StartedCollecting);
        // Anchor a genesis, then a rejected second genesis — with now derived
        // from now_base so the two runs use different timestamps.
        let g1 = node_transfer_block(0, 7, 0, 7);
        let o1 = bc.receive_block(g1.view(), now_base + 10).0;
        let g2 = node_transfer_block(0, 3, 0, 3);
        let o2 = bc.receive_block(g2.view(), now_base + 20).0;
        (
            o1 == ReceiveBlockOutcome::AcceptedSilently,
            bc.current_active_head(),
            o2 == ReceiveBlockOutcome::Rejected(RejectReason::InvalidEvidence),
            bc.is_ready(),
        )
    }
    // Two replays with widely different wall-clock bases must agree.
    assert_eq!(run(1_000), run(9_999_999));
}

// --- Story 5.2: FR2 dominant-chain acquisition (stopping conditions + selection) ---

/// A linked child block with a tweakable `vote` salt, so two blocks at the same
/// `(sequence, previous_hash)` get distinct hashes — for the tie-break test.
fn salted_linked_block(seq: u32, prev: [u8; 32], vote: u32) -> Block {
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

/// AC4/AC7 — an orphan block whose short segment neither reaches genesis nor
/// spans `W` leaves the node Collecting (no candidate); parent recovery still
/// schedules (the FR2 evaluation is side-effect-free w.r.t. the tick cadence).
#[test]
fn fr2_no_candidate_stays_collecting() {
    let mut bc = new_test_chain();
    let orphan = node_transfer_block(5, 3, 4, 7); // tail seq 5, len 1, not genesis
    let (outcome, next) = bc.receive_block(orphan.view(), 0);
    assert_eq!(outcome, ReceiveBlockOutcome::AcceptedSilently);
    assert!(bc.evaluate_stopping_condition().is_none());
    assert!(bc.current_phase() == LifecyclePhase::Collecting);
    assert!(
        matches!(next, NextCall::At(_)),
        "parent recovery still scheduled while collecting"
    );
}

/// Story 5.11 — FR2 measures a window-anchored segment against the
/// configured `W`, not the allocated capacity: on a build with capacity 16
/// configured with `W = 6` (`H = 3`), nine blocks qualify and eight do
/// not. The build is `TestChain`'s over [`W6Storage`], whose fourteen
/// slots hold the nine-block join.
#[test]
fn fr2_active_length_is_the_configured_w_not_the_capacity() {
    let (crypto, _, mut chain_config) = test_backends();
    chain_config
        .load_durable(window_config_builder(W6).build_signed(&crypto))
        .ok()
        .expect("a window below the capacity is accepted");
    let node_zero = *crypto.public_key().serialize();
    let mut slot = core::mem::MaybeUninit::<Chain16<W6Storage>>::uninit();
    Blockchain::init(
        &mut slot,
        crypto,
        w6_storage(),
        chain_config,
        5,
        node_zero,
        0,
    );
    // SAFETY: `init` returned, so every field of `slot` is initialized.
    let mut bc = unsafe { slot.assume_init() };
    assert_eq!(
        Chain16::<W6Storage>::BUILD_LIMITS.snake_chain_length_max,
        TEST_W
    );

    // The tail carries the configuration the node is locked on, as the FR8
    // final check requires.
    let below = w6_horizon_block();
    for block in &w6_below() {
        bc.receive_block(block.view(), 0);
    }
    let tail = w6_config_anchor_block(100, below.view().hash());
    bc.receive_block(tail.view(), 0);
    let mut prev = tail.view().hash();
    for seq in 101..=104 {
        let blk = linked_transfer_block(seq, prev);
        prev = blk.view().hash();
        bc.receive_block(blk.view(), 0);
    }
    assert!(
        bc.evaluate_stopping_condition().is_none(),
        "segment length 8 < W + H = 9"
    );

    let last = linked_transfer_block(105, prev);
    bc.receive_block(last.view(), 0);
    assert!(
        bc.is_ready(),
        "segment length 9 = W + H qualifies, on a build that allocated 16"
    );
}

/// Story 5.11 / 5.13 — with no configuration held the chain's window is
/// unknown, and no segment names a configuration, so nothing is a
/// candidate. A window-anchored segment as long as the build's whole capacity
/// is not: the capacity is not the window. Once block #1 brings the
/// configuration, the genesis-anchored segment carrying it qualifies — and
/// the window-anchored one still does not, because it names none.
#[test]
fn fr2_without_a_configuration_no_segment_qualifies() {
    let mut bc = new_unconfigured_w6_chain();
    let mut prev = [0xAB; 32];
    for seq in 100..=105 {
        let blk = linked_transfer_block(seq, prev);
        prev = blk.view().hash();
        bc.tier1_admit(&blk.view(), &blk.view().hash(), 0)
            .expect("a transfer block is admitted");
    }
    assert!(bc.chain_config.active_configuration().is_none());
    assert!(
        bc.evaluate_stopping_condition().is_none(),
        "six blocks fill the capacity of 6, but no window is known"
    );

    let genesis = node_transfer_block(0, 7, 0, 7);
    bc.tier1_admit(&genesis.view(), &genesis.view().hash(), 0)
        .expect("the genesis is admitted");
    assert!(
        bc.evaluate_stopping_condition().is_none(),
        "a genesis alone names no configuration"
    );

    let cfg = w6_config_anchor_block(1, genesis.view().hash());
    let cfg_idx = bc
        .tier1_admit(&cfg.view(), &cfg.view().hash(), 0)
        .expect("block #1 is admitted");
    assert_eq!(bc.active_chain_length(), Some(W6));
    assert_eq!(
        bc.evaluate_stopping_condition(),
        Some(cfg_idx),
        "the genesis-anchored segment carrying the configuration qualifies; \
         the longer window-anchored one, naming none, does not"
    );
}

/// Story 5.11 — `W <= SNAKE_CHAIN_LENGTH_MAX`, measured against this build's
/// own `BUILD_LIMITS` (FR8): a chain-config block declaring the capacity
/// loads, one declaring a window above it — or none, which resolves to the
/// default 500 — is exact evidence of invalidity and never reaches storage.
#[test]
fn fr8_window_is_bounded_by_this_builds_capacity() {
    let mut bc = new_unconfigured_test_chain();
    assert_eq!(TestChain::BUILD_LIMITS.snake_chain_length_max, TEST_W);

    for (over, why) in [
        (
            chain_config_block_from(100, [0xAB; 32], &mut window_config_builder(TEST_W + 1)),
            "a declared window one above the capacity",
        ),
        (
            chain_config_block_from(100, [0xAC; 32], &mut ChainConfigPayloadBuilder::new()),
            "an absent window, whose default exceeds the capacity",
        ),
    ] {
        let (outcome, _) = bc.receive_block(over.view(), 0);
        assert_eq!(
            outcome,
            ReceiveBlockOutcome::Rejected(RejectReason::InvalidEvidence),
            "{why} is refused"
        );
        assert_eq!(bc.block_tree_len(), 0, "{why} is not stored");
        assert!(bc.chain_config.active_configuration().is_none());
    }

    let at = chain_config_anchor_block(100, [0xAB; 32]);
    let (outcome, _) = bc.receive_block(at.view(), 0);
    assert_eq!(outcome, ReceiveBlockOutcome::AcceptedSilently);
    assert_eq!(bc.active_chain_length(), Some(TEST_W));
}

/// AC2/AC5/AC6 + Story 5.4 — receiving the genesis (a length-1
/// genesis-anchored segment) satisfies FR2 at once and, since block #0 passes
/// the (genesis-waived) FR6 invariant set, the node runs the full
/// Collecting→Processing→Ready transition in the one `receive_block` call. The
/// bootstrap-anchored genesis is recognized as the candidate (no intake
/// change, per the `:142` resolution) and stays the active head after the FR4
/// promotion.
#[test]
fn fr2_genesis_anchored_triggers_processing() {
    let mut bc = new_test_chain();
    let genesis = node_transfer_block(0, 7, 0, 7);
    // FR8 (Story 5.9, AC3): the candidate must name a configuration, so
    // block #1 carries the chain-config as the FR54 bootstrap emits it.
    // Admitted first, while it is still an orphan (no FR2 trigger), so the
    // genesis admission is what completes the genesis-anchored candidate —
    // which is the transition this test is about.
    let cfg = chain_config_anchor_block(1, genesis.view().hash());
    let (cfg_outcome, _) = bc.receive_block(cfg.view(), 100);
    assert_eq!(cfg_outcome, ReceiveBlockOutcome::AcceptedSilently);
    let (outcome, _) = bc.receive_block(genesis.view(), 100);
    assert_eq!(outcome, ReceiveBlockOutcome::AcceptedSilently);
    assert!(
        bc.blocks
            .get(0)
            .is_some_and(|entry| entry.is_on_active_chain()),
        "the genesis is on the active chain after the FR4 promotion (AC9)"
    );
    assert!(
        bc.is_ready(),
        "genesis-anchored candidate validates → Ready (FR6/FR4, Story 5.4)"
    );
}

/// AC3 — a node holding no configuration does not enter Processing, even
/// when the FR2 stopping condition is met: the FR3 derivation reads the FR37
/// vote parameters, and running it on `vote_parameters`' inert baseline
/// would produce a projection the node then goes `Ready` on. The block is
/// admitted; only the stage that needs the configuration is withheld
/// (specification §5.2). Compare `fr2_genesis_anchored_triggers_processing`,
/// which is the same submission against a configured node.
#[test]
fn fr2_stays_collecting_without_configuration() {
    let (crypto, storage, chain_config) = test_backends();
    let mut bc = new_chain(crypto, storage, chain_config, 5, 0);
    let genesis = node_transfer_block(0, 7, 0, 7);

    let (outcome, _) = bc.receive_block(genesis.view(), 100);

    assert_eq!(
        outcome,
        ReceiveBlockOutcome::AcceptedSilently,
        "the block itself is still admitted"
    );
    assert!(
        bc.current_phase() == LifecyclePhase::Collecting,
        "no configuration → no FR3 derivation, so no Processing and no Ready"
    );
    assert!(!bc.is_ready());
}

/// Defence in depth behind the FR2 gate: if a caller ever reaches the FR3
/// derivation without a configuration, the vote engine refuses rather than
/// accumulating on parameters nobody chose. Epic 6's deep-zone
/// re-derivation and Story 5.10's restart are the callers this protects.
#[test]
fn processing_pass_refuses_without_configuration() {
    let (crypto, storage, chain_config) = test_backends();
    let mut bc = new_chain(crypto, storage, chain_config, 5, 0);
    let genesis = node_transfer_block(0, 7, 0, 7);
    let (outcome, _) = bc.receive_block(genesis.view(), 100);
    assert_eq!(outcome, ReceiveBlockOutcome::AcceptedSilently);

    // The same candidate a configured node validates all the way to Ready
    // (see `fr2_genesis_anchored_triggers_processing`).
    assert_eq!(
        bc.run_processing_pass(0),
        Err(ProcessingError::Vote(VoteEngineError::NotParameterized)),
        "no FR37 parameters -> the derivation refuses, it does not guess"
    );
}

/// The window [`W6Chain`]'s configurations declare: its whole capacity.
/// 6 is the smallest window with a legal horizon (configuration §6 check
/// 21: `H ≥ 3` divides `W`, `H < W`), and its horizon is 3, so the clean
/// slots (Story 6.7 D8) are the sequences `≡ 2 (mod 3)`.
const W6: u32 = 6;

/// A test chain with a small active-chain capacity (`SNAKE_CHAIN_LENGTH_MAX =
/// 6`), configured with a window of the same length, so an active-length
/// segment fits the test harness's block storage. Same shape as
/// `new_test_chain` otherwise (local_node_id 5, join/Collecting), but on
/// [`W6Storage`].
type W6Chain = Blockchain<Crypto, W6Storage, TestConfig, 16, 6, 16, 4, 16>;

/// The W6 harness's storage: fourteen block slots. A window-anchored join
/// holds `W + H = 9` blocks; the others are kept for forks and extensions
/// (a switch across the seed points needs a four-block branch beside the
/// join).
type W6Storage = MemoryBackend<{ 14 * MAX_BLOCK_SIZE + 8000 }>;

/// A [`W6Storage`] initialized as [`test_backends`]' storage is.
fn w6_storage() -> W6Storage {
    let mut storage = W6Storage::new();
    storage
        .init([1u8; PRIVATE_KEY_SIZE], 0, [0u8; INIT_PARAMS_SIZE])
        .ok()
        .expect("the test backend initializes");
    storage
}

/// A [`W6Chain`] durably locked on its configuration (`W = 6`, `H = 3`),
/// Collecting.
fn new_w6_chain() -> W6Chain {
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
fn new_unconfigured_w6_chain() -> W6Chain {
    let (crypto, _, _) = test_backends();
    let storage = w6_storage();
    let chain_config = empty_chain_config(W6Chain::BUILD_LIMITS);
    let node_zero = *crypto.public_key().serialize();
    let mut slot = core::mem::MaybeUninit::uninit();
    Blockchain::init(&mut slot, crypto, storage, chain_config, 5, node_zero, 0);
    // SAFETY: `init` returned, so every field of `slot` is initialized.
    unsafe { slot.assume_init() }
}

/// AC2 — an active-length segment (`>= W + H = 9`, `W = 6`) that does NOT
/// reach genesis triggers Processing; one block short (len 8) it stays
/// Collecting.
#[test]
fn fr2_active_length_triggers_at_w() {
    let mut bc = new_w6_chain();
    // The orphan #97 (unresolved parent) and its children #98, #99, the
    // chain-config block #100 the FR8 final check requires in scope (Story
    // 5.9, AC3), then children up to length 8 — one below `W + H = 9`
    // (DEC-177).
    let below = w6_horizon_block();
    for block in &w6_below() {
        bc.receive_block(block.view(), 0);
    }
    let tail = w6_config_anchor_block(100, below.view().hash());
    bc.receive_block(tail.view(), 0);
    let mut prev = tail.view().hash();
    for seq in 101..=104 {
        let blk = linked_transfer_block(seq, prev);
        prev = blk.view().hash();
        bc.receive_block(blk.view(), 0);
    }
    assert_eq!(bc.block_tree_len(), 8);
    assert!(
        bc.evaluate_stopping_condition().is_none(),
        "segment length 8 >= W, below W + H = 9"
    );
    assert!(bc.current_phase() == LifecyclePhase::Collecting);
    // The 9th block brings the continuous segment to length W + H = 9 → FR2
    // qualifies, and the window-anchored candidate (unseeded initializers, so
    // the per-node FR6 checks are pre-seed-skipped, and every block is
    // node-#0-signed against the trust anchor) validates → Ready (Story 5.4).
    let last = linked_transfer_block(105, prev);
    bc.receive_block(last.view(), 0);
    assert!(
        bc.is_ready(),
        "segment length 9 >= W + H → FR2 qualifies, FR6 validates → Ready"
    );
}

/// AC3 — selection takes the highest tip sequence; a same-sequence tie is
/// broken by the lowest tip hash (hash-only, in-memory). Built via
/// `tier1_admit` (which does not run the FR2 hook), so the multi-head tree can
/// be assembled before evaluating.
#[test]
fn fr2_selection_highest_sequence_then_lowest_hash() {
    let mut bc = new_test_chain();
    let g = node_transfer_block(0, 7, 0, 7);
    bc.tier1_admit(&g.view(), &g.view().hash(), 0)
        .expect("genesis admitted");
    // Block #1 names the configuration both branches inherit (Story 5.13).
    let cfg = chain_config_anchor_block(1, g.view().hash());
    bc.tier1_admit(&cfg.view(), &cfg.view().hash(), 0)
        .expect("config admitted");
    let gh = cfg.view().hash();
    // Two distinct seq-2 children of block #1 (a fork) → both
    // genesis-anchored, both tip seq 2 → tie broken by lower tip hash.
    let a = salted_linked_block(2, gh, 3);
    let b = salted_linked_block(2, gh, 4);
    let a_idx = bc
        .tier1_admit(&a.view(), &a.view().hash(), 0)
        .expect("A admitted");
    let b_idx = bc
        .tier1_admit(&b.view(), &b.view().hash(), 0)
        .expect("B admitted");
    let a_hash = a.view().hash();
    let b_hash = b.view().hash();
    let lower = if a_hash < b_hash { a_idx } else { b_idx };
    assert_eq!(
        bc.evaluate_stopping_condition(),
        Some(lower),
        "same-sequence tie → lower tip hash wins"
    );
    // Extend branch A to seq 3 → the higher sequence now outranks the tie.
    let c = salted_linked_block(3, a_hash, 3);
    let c_idx = bc
        .tier1_admit(&c.view(), &c.view().hash(), 0)
        .expect("C admitted");
    assert_eq!(
        bc.evaluate_stopping_condition(),
        Some(c_idx),
        "highest tip sequence wins over the lower-sequence tie"
    );
}

/// AC8 — the selected candidate is independent of admission order (FR63/NFR5):
/// building the same fork in two admission orders yields the same winning tip
/// hash (the block-table index differs by order, the chosen tip does not).
#[test]
fn fr2_selection_is_order_independent() {
    fn winner_hash(order: &[u32; 2], now: u64) -> [u8; 32] {
        let mut bc = new_test_chain();
        let g = node_transfer_block(0, 7, 0, 7);
        bc.tier1_admit(&g.view(), &g.view().hash(), now)
            .expect("genesis");
        let cfg = chain_config_anchor_block(1, g.view().hash());
        bc.tier1_admit(&cfg.view(), &cfg.view().hash(), now)
            .expect("config");
        let gh = cfg.view().hash();
        let blocks = [
            salted_linked_block(2, gh, order[0]),
            salted_linked_block(2, gh, order[1]),
        ];
        for blk in &blocks {
            bc.tier1_admit(&blk.view(), &blk.view().hash(), now)
                .expect("child admitted");
        }
        let win = bc
            .evaluate_stopping_condition()
            .expect("a genesis-anchored candidate qualifies");
        *bc.blocks.get(win).expect("winner is in the tree").hash()
    }
    // Order- AND now-independent (FR63/NFR5): the evaluator reads no clock/PRNG.
    assert_eq!(
        winner_hash(&[3, 4], 1_000),
        winner_hash(&[4, 3], 9_999_999),
        "same winning tip regardless of admission order or wall-clock base"
    );
}

/// AC6 — the bootstrap-anchored genesis does not pre-empt selection: a longer
/// non-genesis active-length branch at a higher tip sequence is chosen over
/// the anchored genesis's short branch (the evaluator never reads
/// `active_chain_head_idx`).
#[test]
fn fr2_anchored_genesis_does_not_preempt_higher_branch() {
    let mut bc = new_w6_chain();
    // Anchored genesis (a short genesis-anchored candidate).
    let g = node_transfer_block(0, 7, 0, 7);
    bc.tier1_admit(&g.view(), &g.view().hash(), 0)
        .expect("genesis admitted");
    assert_eq!(
        bc.current_active_head(),
        Some(0),
        "genesis is the placeholder anchor"
    );
    // Block #1 names the configuration, so the genesis branch is itself a
    // qualifying candidate (Story 5.13) — the one that must not win.
    let cfg = w6_config_anchor_block(1, g.view().hash());
    bc.tier1_admit(&cfg.view(), &cfg.view().hash(), 0)
        .expect("config admitted");
    // A separate non-genesis branch of length W + H = 9 (#97 → tip 105),
    // its window tail #100 naming the same configuration.
    let below = w6_horizon_block();
    for block in &w6_below() {
        bc.tier1_admit(&block.view(), &block.view().hash(), 0)
            .expect("the blocks below the window admitted");
    }
    let tail = w6_config_anchor_block(100, below.view().hash());
    bc.tier1_admit(&tail.view(), &tail.view().hash(), 0)
        .expect("tail admitted");
    let mut prev = tail.view().hash();
    let mut tip_idx = 0;
    for seq in 101..=105 {
        let blk = linked_transfer_block(seq, prev);
        prev = blk.view().hash();
        tip_idx = bc
            .tier1_admit(&blk.view(), &blk.view().hash(), 0)
            .expect("child admitted");
    }
    // Highest tip sequence (105) wins over the anchored genesis (seq 0).
    assert_eq!(
        bc.evaluate_stopping_condition(),
        Some(tip_idx),
        "the longer non-genesis branch is selected despite the genesis anchor"
    );
}

/// AC2 — a genesis-anchored segment longer than 1 but shorter than W still
/// qualifies (the genesis rule is length-independent — distinct from the
/// active-length rule).
#[test]
fn fr2_genesis_anchored_multiblock_below_w_qualifies() {
    let mut bc = new_test_chain(); // W = 16
    let g = node_transfer_block(0, 7, 0, 7);
    bc.tier1_admit(&g.view(), &g.view().hash(), 0)
        .expect("genesis admitted");
    // Block #1, carrying the configuration (Story 5.13) → a 2-block
    // genesis-anchored segment (< W).
    let c = chain_config_anchor_block(1, g.view().hash());
    let c_idx = bc
        .tier1_admit(&c.view(), &c.view().hash(), 0)
        .expect("child admitted");
    assert_eq!(
        bc.evaluate_stopping_condition(),
        Some(c_idx),
        "genesis-anchored qualifies at length 2, well below W = 16"
    );
}

// --- Story 5.3: FR3 processing-pass forward state reconstruction ---------

/// A `payload_type=1` block carrying a single registration transaction,
/// linked to `prev`. Signatures are placeholders — FR3 derivation does not
/// verify them (FR6 signature validation is Story 5.4).
fn registration_block(
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
fn chain_config_anchor_block(seq: u32, prev: [u8; 32]) -> Block {
    chain_config_block_from(seq, prev, &mut window_config_builder(TEST_W))
}

/// [`chain_config_anchor_block`] for the [`W6Chain`] harness, whose
/// configuration declares its own window, [`W6`].
fn w6_config_anchor_block(seq: u32, prev: [u8; 32]) -> Block {
    chain_config_block_from(seq, prev, &mut window_config_builder(W6))
}

/// A chain-config block at `seq`, chained to `prev`, carrying whatever
/// content `payload_builder` has framed, signed by node #0 over exactly that
/// content region.
///
/// Takes the builder by `&mut` because `build_signed` returns a slice of the
/// builder's own buffer; the caller owns the builder so the borrow outlives
/// the call.
fn chain_config_block_from(
    seq: u32,
    prev: [u8; 32],
    payload_builder: &mut ChainConfigPayloadBuilder,
) -> Block {
    let signer = Crypto::new([1u8; PRIVATE_KEY_SIZE]).ok().expect("test key");
    let header = BlockHeader {
        version: 1,
        sequence: seq,
        creator: 0,
        mined_amount: 0,
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
/// one: the base entry plus a literal declaring `vote_interest`'s own default
/// value. It resolves every parameter identically to the base set, so a node
/// adopting it behaves the same — the only thing that differs is the content
/// bytes, which is exactly what the FR7/FR8 byte-identity rules turn on.
fn alt_config_builder() -> ChainConfigPayloadBuilder {
    let mut builder = window_config_builder(TEST_W);
    builder
        .add_literal(parameter::VOTE_INTEREST, &[5])
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
const SMALL_BLOCK_SIZE_LIMIT: u32 = {
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
fn small_limit_config_builder(w: u32) -> ChainConfigPayloadBuilder {
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

/// An override set that is **well-formed but structurally illegal**:
/// `vote_scale = 0`, which the configuration module refuses on a bound (it is
/// the denominator of the FR37 anti-capture rule). The framing is valid, so
/// the envelope walks and the FR7 signature verifies — the refusal comes from
/// the module, which is the ordering AC2 is about.
fn bound_violating_config_builder() -> ChainConfigPayloadBuilder {
    let mut builder = ChainConfigPayloadBuilder::new();
    builder
        .add_literal(parameter::VOTE_SCALE, &0u16.to_le_bytes())
        .ok()
        .expect("the entry itself is well-formed; the bound is what fails");
    builder
}

/// The content region of a chain-config block, as the FR7/FR8 comparisons
/// see it.
fn content_of(block: &Block) -> &[u8] {
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
fn admit_chain_config_anchor(bc: &mut TestChain, seq: u32, prev: [u8; 32]) -> [u8; 32] {
    let cfg = chain_config_anchor_block(seq, prev);
    let hash = cfg.view().hash();
    bc.tier1_admit(&cfg.view(), &hash, 0)
        .expect("chain-config anchor admitted");
    hash
}

fn balance_block(
    seq: u32,
    prev: [u8; 32],
    entries: &[(u32, u64, u32, u8)],
    max_node_id: u32,
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
        mined_amount: 0,
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
fn transfer_block(
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

/// AC2/AC3 — the earliest balance block seeds per-node balance + public key
/// and initializes the `max_known_node_id` watermark from its `max_node_id`;
/// `VoteEngine` is seeded from the entries' `vote_count`.
#[test]
fn fr3_derives_balance_block_seed_and_watermark() {
    let mut bc = new_test_chain();
    // FR8 (Story 5.9, AC3): the candidate must carry a chain-config
    // block in scope, so the segment is anchored by one. Inert with
    // respect to everything below — see `chain_config_anchor_block`.
    let cfg_hash = admit_chain_config_anchor(&mut bc, 99, [0xAB; 32]);
    let anchor = balance_block(100, cfg_hash, &[(1, 500, 10, 0x31), (2, 300, 20, 0x32)], 2);
    let ai = bc
        .tier1_admit(&anchor.view(), &anchor.view().hash(), 0)
        .expect("balance anchor admitted");

    bc.run_processing_pass(ai).expect("pass succeeds");

    assert_eq!(bc.node_info.balance_of(1), 500);
    assert_eq!(bc.node_info.balance_of(2), 300);
    assert!(bc.node_info.public_key_of(1).is_some());
    assert!(bc.node_info.public_key_of(2).is_some());
    assert_eq!(
        bc.node_info.max_known_node_id(),
        2,
        "watermark from max_node_id"
    );
    // vote_count seeds accumulated vote; the balance block's own acceptance
    // applies FR37 interest (0 on values < vote_scale) + creator(0) reset.
    assert_eq!(bc.vote_engine.accumulated_vote_of(1), 10);
    assert_eq!(bc.vote_engine.accumulated_vote_of(2), 20);
    // FR38 creator-order is a read-through of the vote registry: node 2
    // (vote 20) outranks node 1 (vote 10); the zero-vote tail follows by
    // ascending node id.
    assert_eq!(bc.vote_engine.top_creator(), Some(2));
    assert_eq!(bc.vote_engine.creator_at_rank(1), Some(1));
}

/// AC3 — a (non-genesis) registration seeds the new node (balance 0, public
/// key) and advances the watermark; the initializer is debited
/// `registration_price + fee`.
#[test]
fn fr3_derives_registration_and_watermark() {
    let mut bc = new_test_chain();
    // FR8 (Story 5.9, AC3): the candidate must carry a chain-config
    // block in scope, so the segment is anchored by one. Inert with
    // respect to everything below — see `chain_config_anchor_block`.
    let cfg_hash = admit_chain_config_anchor(&mut bc, 99, [0xAB; 32]);
    let anchor = balance_block(100, cfg_hash, &[(1, 100, 0, 0x31)], 1);
    bc.tier1_admit(&anchor.view(), &anchor.view().hash(), 0)
        .expect("anchor admitted");
    // FR6 registration monotonicity: `new_node_id` must be the pre-block
    // watermark + 1 (watermark is 1 from the balance block's max_node_id → 2).
    let reg = registration_block(101, anchor.view().hash(), 1, 2, 0x45);
    let ri = bc
        .tier1_admit(&reg.view(), &reg.view().hash(), 0)
        .expect("registration admitted");

    bc.run_processing_pass(ri).expect("pass succeeds");

    assert!(
        bc.node_info.public_key_of(2).is_some(),
        "new node registered"
    );
    assert_eq!(
        bc.node_info.balance_of(2),
        0,
        "new node balance is 0 (FR50)"
    );
    assert_eq!(bc.node_info.max_known_node_id(), 2, "watermark advanced");
    assert_eq!(
        bc.node_info.balance_of(1),
        49,
        "initializer debited registration_price(50) + fee(1)"
    );
}

/// AC2 — a node transfer between two seeded nodes moves the derived balances
/// (initializer debited amount + fee; receiver credited amount).
#[test]
fn fr3_derives_node_transfer_between_seeded_nodes() {
    let mut bc = new_test_chain();
    // FR8 (Story 5.9, AC3): the candidate must carry a chain-config
    // block in scope, so the segment is anchored by one. Inert with
    // respect to everything below — see `chain_config_anchor_block`.
    let cfg_hash = admit_chain_config_anchor(&mut bc, 99, [0xAB; 32]);
    let anchor = balance_block(100, cfg_hash, &[(1, 500, 0, 0x31), (2, 300, 0, 0x32)], 2);
    bc.tier1_admit(&anchor.view(), &anchor.view().hash(), 0)
        .expect("anchor admitted");
    // vote 0 — the permanent node-#0 vote-target exception (FR37/FR54), so the
    // FR6 vote-target check passes without seeding a dedicated target node.
    let tx = transfer_block(101, anchor.view().hash(), 1, 2, 100, 1, 0);
    let ti = bc
        .tier1_admit(&tx.view(), &tx.view().hash(), 0)
        .expect("transfer admitted");

    bc.run_processing_pass(ti).expect("pass succeeds");

    assert_eq!(bc.node_info.balance_of(1), 399, "500 - (100 + 1)");
    assert_eq!(bc.node_info.balance_of(2), 400, "300 + 100");
}

/// AC4 — pre-seed-zone auto-acceptance: transactions involving nodes with no
/// in-segment seed source are auto-accepted (their per-node balance effects
/// are skipped), and the pass neither panics nor invents balances.
#[test]
fn fr3_preseed_zone_auto_accepts() {
    let mut bc = new_test_chain();
    // FR8 (Story 5.9, AC3): the segment is anchored by a chain-config block,
    // which is inert here — see `chain_config_anchor_block`.
    let cfg_hash = admit_chain_config_anchor(&mut bc, 99, [0xAB; 32]);
    // A transfer from node 7 to node 9, neither ever seeded.
    let anchor = chained_node_transfer_block(100, cfg_hash, 3, 99, 7);
    let ai = bc
        .tier1_admit(&anchor.view(), &anchor.view().hash(), 0)
        .expect("anchor admitted");

    bc.run_processing_pass(ai)
        .expect("pass does not fail on unseeded nodes");

    assert!(!bc.node_info.is_seeded(7));
    assert_eq!(bc.node_info.balance_of(7), 0, "debit skipped (pre-seed)");
    assert_eq!(bc.node_info.balance_of(9), 0, "credit skipped (pre-seed)");
    // The vote credit still lands (vote accounting is roster-independent).
    assert_eq!(bc.vote_engine.accumulated_vote_of(3), 1000);
}

/// AC3 — a genesis-anchored segment with no balance block initializes the
/// watermark to 0 (FR54(h) bootstrap exception).
#[test]
fn fr3_genesis_anchored_watermark_zero() {
    let mut bc = new_test_chain();
    let g = node_transfer_block(0, 3, 0, 7);
    bc.tier1_admit(&g.view(), &g.view().hash(), 0)
        .expect("genesis admitted");
    // FR8 (Story 5.9, AC3): block #1 carries the chain-config. It contributes
    // no balance block, so the watermark this test measures is untouched.
    let ci = {
        let cfg = chain_config_anchor_block(1, g.view().hash());
        bc.tier1_admit(&cfg.view(), &cfg.view().hash(), 0)
            .expect("chain-config block admitted")
    };

    bc.run_processing_pass(ci).expect("pass succeeds");

    assert_eq!(
        bc.node_info.max_known_node_id(),
        0,
        "genesis-anchored, no balance block → watermark 0 (FR54(h))"
    );
}

/// AC1 — the backward mark follows only the selected branch: applying one
/// fork child's tip must not apply the sibling's effects.
#[test]
fn fr3_backward_mark_follows_selected_branch_only() {
    let mut bc = new_test_chain();
    // FR8 (Story 5.9, AC3): the candidate must carry a chain-config
    // block in scope, so the segment is anchored by one. Inert with
    // respect to everything below — see `chain_config_anchor_block`.
    let cfg_hash = admit_chain_config_anchor(&mut bc, 99, [0xAB; 32]);
    let anchor = balance_block(
        100,
        cfg_hash,
        &[(1, 1000, 0, 0x31), (2, 0, 0, 0x32), (3, 0, 0, 0x33)],
        3,
    );
    bc.tier1_admit(&anchor.view(), &anchor.view().hash(), 0)
        .expect("anchor admitted");
    let ah = anchor.view().hash();
    let left = transfer_block(101, ah, 1, 2, 100, 0, 0); // 1 → 2 (vote node #0)
    let right = transfer_block(101, ah, 1, 3, 200, 0, 0); // 1 → 3 (sibling; vote node #0)
    let li = bc
        .tier1_admit(&left.view(), &left.view().hash(), 0)
        .expect("left admitted");
    let _ri = bc
        .tier1_admit(&right.view(), &right.view().hash(), 0)
        .expect("right admitted");

    bc.run_processing_pass(li).expect("pass over left tip");

    assert_eq!(bc.node_info.balance_of(2), 100, "left branch applied");
    assert_eq!(bc.node_info.balance_of(3), 0, "sibling NOT applied");
    assert_eq!(bc.node_info.balance_of(1), 900, "only left's 100 debited");
}

/// AC5 — the pass is not resumable: re-running it on the same candidate
/// re-derives from a clean working set to an identical projection.
#[test]
fn fr3_not_resumable_clean_reentry() {
    let mut bc = new_test_chain();
    // FR8 (Story 5.9, AC3): the candidate must carry a chain-config
    // block in scope, so the segment is anchored by one. Inert with
    // respect to everything below — see `chain_config_anchor_block`.
    let cfg_hash = admit_chain_config_anchor(&mut bc, 99, [0xAB; 32]);
    let anchor = balance_block(100, cfg_hash, &[(1, 500, 10, 0x31)], 1);
    bc.tier1_admit(&anchor.view(), &anchor.view().hash(), 0)
        .expect("anchor admitted");
    let tx = transfer_block(101, anchor.view().hash(), 1, 1, 0, 3, 0);
    let ti = bc
        .tier1_admit(&tx.view(), &tx.view().hash(), 0)
        .expect("tx admitted");

    bc.run_processing_pass(ti).expect("first pass");
    let b1 = bc.node_info.balance_of(1);
    let v1 = bc.vote_engine.accumulated_vote_of(1);

    bc.run_processing_pass(ti).expect("second pass (re-entry)");
    assert_eq!(
        bc.node_info.balance_of(1),
        b1,
        "balance identical after re-entry"
    );
    assert_eq!(
        bc.vote_engine.accumulated_vote_of(1),
        v1,
        "vote identical after re-entry (clean working set)"
    );
}

/// AC8 — the derived projection is `now`-independent and reproducible: the
/// same candidate admitted under two different `now` bases yields a
/// byte-identical projection.
#[test]
fn fr3_projection_is_clock_independent_and_reproducible() {
    fn run(now_base: u64) -> (u64, u64, u32, u32) {
        let mut bc = new_test_chain();
        // FR8 (Story 5.9, AC3): the candidate must carry a chain-config
        // block in scope, so the segment is anchored by one. Inert with
        // respect to everything below — see `chain_config_anchor_block`.
        let cfg_hash = admit_chain_config_anchor(&mut bc, 99, [0xAB; 32]);
        let anchor = balance_block(100, cfg_hash, &[(1, 500, 0, 0x31), (2, 300, 0, 0x32)], 2);
        let _ai = bc
            .tier1_admit(&anchor.view(), &anchor.view().hash(), now_base)
            .expect("anchor admitted");
        let tx = transfer_block(101, anchor.view().hash(), 1, 2, 100, 1, 0);
        let ti = bc
            .tier1_admit(&tx.view(), &tx.view().hash(), now_base + 5_000)
            .expect("tx admitted");
        bc.run_processing_pass(ti).expect("pass");
        (
            bc.node_info.balance_of(1),
            bc.node_info.balance_of(2),
            bc.vote_engine.accumulated_vote_of(0),
            bc.node_info.max_known_node_id(),
        )
    }
    assert_eq!(run(0), run(1_000_000), "projection independent of `now`");
}

/// AC9 (Story 5.4) — the FR4 Ready transition + FR9 Tier-3 Active-promotion
/// driver: a qualifying genesis-anchored candidate that passes FR6 moves
/// Collecting→Processing→Ready in one `receive_block`, every candidate block is
/// atomically promoted `Stored→Active` with `is_on_active_chain`, and
/// `active_chain_head_idx` is established at the tip.
#[test]
fn fr4_seam_reaches_ready_and_promotes_active() {
    let mut bc = new_test_chain();
    let genesis = node_transfer_block(0, 3, 0, 7);
    // FR8 (Story 5.9, AC3): block #1 carries the chain-config, admitted first
    // as an orphan so the genesis admission completes the candidate.
    let cfg = chain_config_anchor_block(1, genesis.view().hash());
    bc.receive_block(cfg.view(), 0);
    let (outcome, _next) = bc.receive_block(genesis.view(), 0);
    assert_eq!(outcome, ReceiveBlockOutcome::AcceptedSilently);
    assert!(
        bc.is_ready(),
        "valid genesis-anchored candidate → Ready (FR4)"
    );
    let tip = bc.active_chain_head_idx;
    assert_ne!(tip, NONE_REF, "active head established");
    let entry = bc.blocks.get(tip).expect("tip present");
    assert_eq!(
        entry.status(),
        BlockStatus::Active,
        "candidate tip promoted Stored→Active (FR9 Tier 3)"
    );
    assert!(entry.is_on_active_chain(), "tip is on the active chain");
}

/// AC10 (Story 5.4) + AC11(c)/(f) (Story 5.5, amended 2026-07-30) — the
/// FR6-failure path end to end, *including the immediate retry*: a
/// qualifying candidate that violates an FR6 invariant has its offender
/// deleted, and the shortened branch is re-evaluated and validated **inside
/// the same call**, so the node reaches Ready without waiting for another
/// admission. That is the whole point of the retry-on-`Invalid` rule: the
/// failed pass had already proved every block below the offender, and
/// `block_idx` names the earliest one.
///
/// The candidate `[#0 genesis, #1 chain-config, #2 registration]` is
/// continuous genesis-anchored (so FR2 qualifies on the genesis admission)
/// but block #2's `new_node_id = 5 ≠ watermark + 1 = 1` violates the FR6
/// registration-monotonicity rule. Block #1 is the chain-config the FR8
/// final check (Story 5.9, AC3) requires — and it has to be *below* the
/// offender, because the shortened branch the retry validates must still name
/// a configuration.
#[test]
fn fr5_seam_recovers_and_retries_invalid_candidate_in_one_call() {
    let mut bc = new_test_chain();
    let genesis = node_transfer_block(0, 0, 0, 0);
    let cfg = chain_config_anchor_block(1, genesis.view().hash());
    // Out-of-sequence registration child (new_node_id 5, expected 1).
    let child = registration_block(2, cfg.view().hash(), 1, 5, 0x45);
    // Admit the upper blocks first, while they are still orphans (Stored, no
    // FR2 — not yet anchored), then the genesis, so the continuous
    // genesis-anchored candidate qualifies on that last admission.
    let (outcome, _) = bc.receive_block(child.view(), 0);
    assert_eq!(
        outcome,
        ReceiveBlockOutcome::AcceptedSilently,
        "the orphan child is really admitted (the seam below is not vacuous)"
    );
    let (cfg_outcome, _) = bc.receive_block(cfg.view(), 0);
    assert_eq!(cfg_outcome, ReceiveBlockOutcome::AcceptedSilently);
    let child_idx = bc
        .blocks
        .find(2, &child.view().hash())
        .expect("child in the tree");
    assert!(bc.current_phase() == LifecyclePhase::Collecting);
    let (outcome, _) = bc.receive_block(genesis.view(), 0);
    assert_eq!(outcome, ReceiveBlockOutcome::AcceptedSilently);
    // AC11(a): the offender and its descendants are gone, the genesis and the
    // chain-config block survive.
    assert!(
        bc.blocks.get(child_idx).is_none(),
        "the offending block is deleted from the tree (and its durable slot freed)"
    );
    let genesis_idx = bc
        .blocks
        .find(0, &genesis.view().hash())
        .expect("genesis survives");
    let cfg_idx = bc
        .blocks
        .find(1, &cfg.view().hash())
        .expect("chain-config block survives");
    assert_eq!(bc.blocks.len(), 2);
    // AC11(f), amended: the shortened branch is re-evaluated in this very
    // call and validates, so the node is Ready on return — no second
    // admission, no tick, no wait for ambient traffic.
    assert!(
        bc.is_ready(),
        "the retry validates the shortened genesis-anchored candidate in-call"
    );
    assert_eq!(
        bc.active_chain_head_idx, cfg_idx,
        "the retry's Ready transition establishes the surviving tip as the active head"
    );
    assert_eq!(
        bc.blocks
            .get(genesis_idx)
            .expect("genesis present")
            .status(),
        BlockStatus::Active,
        "the surviving candidate is promoted Stored→Active by the retry"
    );
    // AC11(c): the offender's derived effect is gone — the retry re-derived
    // from the surviving segment alone, it did not resume the failed pass.
    assert!(
        !bc.node_info.is_seeded(5),
        "the offending registration's effect is absent from the working set"
    );
    assert_eq!(bc.node_info.max_known_node_id(), 0);
}

// --- Story 5.5: FR5 atomic recovery -------------------------------------

/// AC11(a) — an `Invalid` failure deletes the offending block **and** its
/// transitive descendants, and nothing else: a sibling subtree whose
/// ancestry does not pass through the target survives, as does the target's
/// own ancestor.
#[test]
fn fr5_deletes_offender_subtree_and_spares_sibling() {
    let mut bc = new_test_chain();
    let genesis = node_transfer_block(0, 0, 0, 0);
    let gi = bc
        .tier1_admit(&genesis.view(), &genesis.view().hash(), 0)
        .expect("genesis admitted");
    // Offending branch: genesis ← b1 ← b2.
    let b1 = transfer_block(1, genesis.view().hash(), 1, 2, 100, 1, 0);
    let bi1 = bc
        .tier1_admit(&b1.view(), &b1.view().hash(), 0)
        .expect("b1 admitted");
    let b2 = transfer_block(2, b1.view().hash(), 1, 2, 100, 1, 0);
    let bi2 = bc
        .tier1_admit(&b2.view(), &b2.view().hash(), 0)
        .expect("b2 admitted");
    // Sibling branch forking at the genesis (a different amount → a distinct
    // hash, so it is a genuine second child, not an FR11 duplicate).
    let c1 = transfer_block(1, genesis.view().hash(), 1, 2, 200, 1, 0);
    let ci1 = bc
        .tier1_admit(&c1.view(), &c1.view().hash(), 0)
        .expect("c1 admitted");
    assert_eq!(bc.blocks.len(), 4);

    bc.set_lifecycle_phase(LifecyclePhase::Processing);
    bc.recover_from_failed_pass(
        ProcessingError::Invalid {
            block_idx: bi1,
            reason: ValidationReason::UnseededActor,
        },
        bi2,
    );

    assert!(
        bc.blocks.get(bi1).is_none(),
        "the earliest offender is deleted"
    );
    assert!(
        bc.blocks.get(bi2).is_none(),
        "its transitive descendant is deleted too"
    );
    assert!(
        bc.blocks.get(gi).is_some(),
        "the target's ancestor survives"
    );
    assert!(
        bc.blocks.get(ci1).is_some(),
        "the sibling subtree is untouched"
    );
    assert_eq!(bc.blocks.len(), 2);
    // FR19 event (iv): only the sibling branch is still tracked, and the
    // genesis keeps no entry of its own (it still has the sibling child).
    assert_eq!(bc.chain_heads.count(), 1);
    assert!(bc.chain_heads.occupied_heads().any(|(h, _)| h == ci1));
    assert_eq!(bc.current_phase(), LifecyclePhase::Collecting);
}

/// AC11(b) — an arithmetic vote failure is not exact evidence against any
/// specific block, so exactly **one** block is deleted: the candidate head.
/// The local failures delete nothing.
/// Its parent becomes the new tip and stays tracked, so the shortened branch
/// remains an FR2 candidate.
#[test]
fn fr5_non_invalid_error_deletes_only_the_candidate_head() {
    fn run(err: ProcessingError) -> (usize, bool, bool) {
        let mut bc = new_test_chain();
        let genesis = node_transfer_block(0, 0, 0, 0);
        bc.tier1_admit(&genesis.view(), &genesis.view().hash(), 0)
            .expect("genesis admitted");
        let b1 = transfer_block(1, genesis.view().hash(), 1, 2, 100, 1, 0);
        let bi1 = bc
            .tier1_admit(&b1.view(), &b1.view().hash(), 0)
            .expect("b1 admitted");
        let b2 = transfer_block(2, b1.view().hash(), 1, 2, 100, 1, 0);
        let bi2 = bc
            .tier1_admit(&b2.view(), &b2.view().hash(), 0)
            .expect("b2 admitted");
        bc.set_lifecycle_phase(LifecyclePhase::Processing);
        bc.recover_from_failed_pass(err, bi2);
        (
            bc.blocks.len(),
            bc.blocks.get(bi2).is_none(),
            // The retargeted entry tracks b1 as the new tip.
            bc.chain_heads.occupied_heads().any(|(h, _)| h == bi1),
        )
    }
    // A local failure is no evidence at all: nothing is deleted (amended
    // FR5, DEC-037 and DEC-134).
    for err in [
        ProcessingError::StorageRead,
        ProcessingError::Vote(VoteEngineError::NotParameterized),
        ProcessingError::MissingBlock,
        ProcessingError::MarkOverflow,
    ] {
        assert_eq!(run(err).0, 3, "a local failure deletes nothing");
    }
    // `Vote(_)` is the one the head fallback exists for: the Story-5.4
    // review accepted that a vote failure carries no `block_idx`, and this
    // arm is what makes that imprecision safe.
    assert_eq!(
        run(ProcessingError::Vote(
            VoteEngineError::AccumulatedVoteOverflow
        )),
        (2, true, true),
        "the head fallback deletes exactly the candidate head and keeps \
         the shortened branch tracked"
    );
}

/// Task 2 / AC3 degenerate target: an `Invalid` whose `block_idx` names an
/// empty or out-of-range slot must still perform the rollback and the
/// reversion. That is the branch which skips `on_blocks_deleted` *and* the
/// `active_chain_head_idx` clearing through `if deleted_count > 0`, so it
/// needs coverage at the recovery level — `mark_subtree_of_empty_or_out_of_range_root_is_empty`
/// only proves the helper returns an empty set.
#[test]
fn fr5_degenerate_target_still_rolls_back_and_reverts() {
    let mut bc = new_test_chain();
    // FR8 (Story 5.9, AC3): the candidate must carry a chain-config
    // block in scope, so the segment is anchored by one. Inert with
    // respect to everything below — see `chain_config_anchor_block`.
    let cfg_hash = admit_chain_config_anchor(&mut bc, 99, [0xAB; 32]);
    let anchor = balance_block(100, cfg_hash, &[(1, 500, 10, 0x31), (2, 300, 20, 0x32)], 5);
    bc.tier1_admit(&anchor.view(), &anchor.view().hash(), 0)
        .expect("anchor admitted");
    let tx = transfer_block(101, anchor.view().hash(), 1, 2, 100, 1, 0);
    bc.tier1_admit(&tx.view(), &tx.view().hash(), 0)
        .expect("tx admitted");
    let reg = registration_block(102, tx.view().hash(), 1, 3, 0x43);
    let ri = bc
        .tier1_admit(&reg.view(), &reg.view().hash(), 0)
        .expect("registration admitted");

    // Dirty the working set for real, so the rollback has something to undo.
    bc.run_processing_pass(ri).expect_err("watermark violation");
    assert!(bc.node_info.is_seeded(1), "the aborted pass derived state");
    let blocks_before = bc.blocks.len();
    let mut heads_before = [(NONE_REF, NONE_REF); 4];
    for (slot, head) in heads_before.iter_mut().zip(bc.chain_heads.occupied_heads()) {
        *slot = head;
    }

    bc.set_lifecycle_phase(LifecyclePhase::Processing);
    bc.recover_from_failed_pass(
        ProcessingError::Invalid {
            block_idx: NONE_REF,
            reason: ValidationReason::RegistrationWatermark,
        },
        ri,
    );

    assert!(!bc.node_info.is_seeded(1), "rollback still runs");
    assert_eq!(bc.node_info.max_known_node_id(), 0, "watermark still reset");
    assert_eq!(
        bc.current_phase(),
        LifecyclePhase::Collecting,
        "reversion still runs"
    );
    assert_eq!(bc.blocks.len(), blocks_before, "nothing is deleted");
    let mut heads_after = [(NONE_REF, NONE_REF); 4];
    for (slot, head) in heads_after.iter_mut().zip(bc.chain_heads.occupied_heads()) {
        *slot = head;
    }
    assert_eq!(heads_after, heads_before, "the tip table is untouched");
}

/// AC11(c) — the working set is fully rolled back: per-node projection
/// (balances, keys, watermark), accumulated vote, and the surviving blocks'
/// available-UTXO bitfields. Driven through the real
/// `run_processing_pass` → `recover_from_failed_pass` pair over a
/// window-anchored candidate that derives state *before* it fails.
#[test]
fn fr5_working_set_is_clean_after_recovery() {
    let mut bc = new_test_chain();
    // FR8 (Story 5.9, AC3): the candidate must carry a chain-config
    // block in scope, so the segment is anchored by one. Inert with
    // respect to everything below — see `chain_config_anchor_block`.
    let cfg_hash = admit_chain_config_anchor(&mut bc, 99, [0xAB; 32]);
    // Window-anchored candidate: balance seed (watermark 5) → valid transfer
    // → out-of-sequence registration (id 3, expected 6).
    let anchor = balance_block(100, cfg_hash, &[(1, 500, 10, 0x31), (2, 300, 20, 0x32)], 5);
    let ai = bc
        .tier1_admit(&anchor.view(), &anchor.view().hash(), 0)
        .expect("anchor admitted");
    let tx = transfer_block(101, anchor.view().hash(), 1, 2, 100, 1, 0);
    let ti = bc
        .tier1_admit(&tx.view(), &tx.view().hash(), 0)
        .expect("tx admitted");
    let reg = registration_block(102, tx.view().hash(), 1, 3, 0x43);
    let ri = bc
        .tier1_admit(&reg.view(), &reg.view().hash(), 0)
        .expect("registration admitted");

    let err = bc.run_processing_pass(ri).expect_err("watermark violation");
    assert_eq!(
        err,
        ProcessingError::Invalid {
            block_idx: ri,
            reason: ValidationReason::RegistrationWatermark,
        }
    );
    // The aborted pass leaves its partial derivation behind — that is exactly
    // what the recovery has to discard.
    assert!(bc.node_info.is_seeded(1));
    assert_eq!(bc.node_info.max_known_node_id(), 5);

    bc.set_lifecycle_phase(LifecyclePhase::Processing);
    bc.recover_from_failed_pass(err, ri);

    assert!(!bc.node_info.is_seeded(1), "roster reset");
    assert!(!bc.node_info.is_seeded(2));
    assert_eq!(bc.node_info.balance_of(1), 0, "balances reset");
    assert_eq!(bc.node_info.balance_of(2), 0);
    assert!(bc.node_info.public_key_of(1).is_none(), "key mapping reset");
    assert_eq!(bc.node_info.max_known_node_id(), 0, "watermark reset");
    assert_eq!(
        bc.vote_engine.accumulated_vote_of(1),
        0,
        "accumulated vote reset"
    );
    assert_eq!(bc.vote_engine.accumulated_vote_of(2), 0);
    // The surviving segment's available-UTXO bits are at the clean all-zero baseline
    // (owned by the pass's entry/abort handling — recovery does not sweep
    // them a second time, and must not need to).
    for idx in [ai, ti] {
        for bit in 0..8 {
            assert_eq!(
                bc.blocks.utxo_available(idx, bit),
                Some(false),
                "no available-UTXO bit survives a failed candidate"
            );
        }
    }
    assert_eq!(bc.current_phase(), LifecyclePhase::Collecting);
}

/// AC11(d)/(e) — deleting the block `active_chain_head_idx` points at clears
/// the anchor placeholder (and empties `chain_heads`), which is what makes
/// re-acquisition of the discarded genesis possible: the single-genesis guard
/// keys on `active_chain_head_idx != NONE_REF`.
#[test]
fn fr5_clears_active_head_when_its_block_is_deleted() {
    let mut bc = new_test_chain();
    let genesis = node_transfer_block(0, 0, 0, 0);
    let gi = bc
        .tier1_admit(&genesis.view(), &genesis.view().hash(), 0)
        .expect("genesis admitted");
    let child = transfer_block(1, genesis.view().hash(), 1, 2, 100, 1, 0);
    let ci = bc
        .tier1_admit(&child.view(), &child.view().hash(), 0)
        .expect("child admitted");
    assert_eq!(bc.active_chain_head_idx, gi);

    // The genesis pair is not exempt: an `Invalid` pinned at block #0 deletes
    // it and everything descending from it (FR5 deletion is forward progress).
    bc.set_lifecycle_phase(LifecyclePhase::Processing);
    bc.recover_from_failed_pass(
        ProcessingError::Invalid {
            block_idx: gi,
            reason: ValidationReason::CreatorSignatureInvalid,
        },
        ci,
    );

    assert_eq!(bc.blocks.len(), 0, "the whole subtree is gone");
    assert_eq!(
        bc.active_chain_head_idx, NONE_REF,
        "the anchor placeholder is cleared with its target"
    );
    assert_eq!(bc.chain_heads.count(), 0, "no tracked tip remains");
    // Re-acquisition is now possible — the guard no longer refuses a genesis.
    assert!(
        bc.tier1_admit(&genesis.view(), &genesis.view().hash(), 0)
            .is_ok(),
        "a node that discarded its genesis can re-acquire one"
    );
}

/// AC7, amended 2026-07-30 — recovery restores the **whole** pre-acquisition
/// active-chain marking, not just the anchor index: every block's
/// `is_on_active_chain` bit is cleared, and the FR19 genesis bootstrap is
/// re-established on the surviving block #0. The pre-marked survivors here
/// stand in for a `promote_candidate_active` that ran before this recovery
/// (the Story-5.10 / Epic-6 reuse) — without the clearing they would keep
/// claiming to be on an active chain that no longer has a head.
#[test]
fn fr5_restores_active_chain_marking_and_keeps_the_genesis_bootstrap() {
    let mut bc = new_test_chain();
    let genesis = node_transfer_block(0, 0, 0, 0);
    let gi = bc
        .tier1_admit(&genesis.view(), &genesis.view().hash(), 0)
        .expect("genesis admitted");
    let b1 = transfer_block(1, genesis.view().hash(), 1, 2, 100, 1, 0);
    let bi1 = bc
        .tier1_admit(&b1.view(), &b1.view().hash(), 0)
        .expect("b1 admitted");
    let b2 = transfer_block(2, b1.view().hash(), 1, 2, 100, 1, 0);
    let bi2 = bc
        .tier1_admit(&b2.view(), &b2.view().hash(), 0)
        .expect("b2 admitted");
    // Stand in for a prior promotion: mark the whole chain Active and move
    // the anchor to the tip, exactly as `promote_candidate_active` would —
    // it writes the status and the bit together, so recovery must undo both.
    for idx in [gi, bi1, bi2] {
        bc.blocks.set_status(idx, BlockStatus::Active);
        bc.blocks.set_on_active_chain(idx, true);
    }
    bc.active_chain_head_idx = bi2;

    // Fail at b2 → only b2 is deleted; the genesis and b1 survive marked.
    bc.set_lifecycle_phase(LifecyclePhase::Processing);
    bc.recover_from_failed_pass(
        ProcessingError::Invalid {
            block_idx: bi2,
            reason: ValidationReason::CreatorSignatureInvalid,
        },
        bi2,
    );

    assert!(bc.blocks.get(bi2).is_none(), "the offender is deleted");
    assert!(
        !bc.blocks
            .get(bi1)
            .expect("b1 survives")
            .is_on_active_chain(),
        "a surviving non-genesis block no longer claims to be on the active chain"
    );
    assert!(
        bc.blocks
            .get(gi)
            .expect("genesis survives")
            .is_on_active_chain(),
        "the FR19 genesis bootstrap is re-established on the surviving block #0"
    );
    // FR9: collecting state holds every retained block at `Stored` — the
    // promotion's status half is undone with its flag half, and the genesis
    // is no exception (its bootstrap marking is not an FR9 promotion).
    for idx in [gi, bi1] {
        assert_eq!(
            bc.blocks.get(idx).expect("survivor").status(),
            BlockStatus::Stored,
            "every surviving block is back at Stored (FR9 collecting-state rule)"
        );
    }
    assert_eq!(
        bc.active_chain_head_idx, gi,
        "the anchor is restored to the genesis, not left at the deleted tip"
    );
    // The bootstrap is what keeps the shortened branch Connected: a demoted
    // head would carry the all-zero missing-parent hash and request it forever.
    assert!(
        bc.chain_heads.occupied_heads().any(|(head, _)| head == bi1),
        "the shortened branch is still tracked"
    );
}

/// AC11(g) — recovery is `now`-independent (FR63/NFR5): the same failing
/// candidate replayed under two wall-clocks produces the same deleted set,
/// the same tip table, the same phase, and the same anchor. Extends the
/// `receive_block_ignores_now` pattern of Stories 4.3/4.4/5.3.
#[test]
fn fr5_recovery_ignores_now() {
    // Compare *identity*, not cardinality: which slots survived, the tip
    // table's (head, tail-point) pairs, the anchor, the phase, and both
    // admission outcomes. `blocks.len()` alone cannot distinguish a
    // recovery that deleted a different block of the same count, and
    // discarding the outcomes would let the whole test pass vacuously if
    // both runs failed at intake and never reached the pass at all.
    #[derive(PartialEq, Debug)]
    struct Snapshot {
        occupied: [bool; 16],
        heads: [(u32, u32); 4],
        active: u32,
        ready: bool,
        outcomes: [ReceiveBlockOutcome; 2],
    }
    fn run(now: u64) -> Snapshot {
        let mut bc = new_test_chain();
        let genesis = node_transfer_block(0, 0, 0, 0);
        // Block #1 is the chain-config the FR8 final check requires below the
        // offender (Story 5.9, AC3) — see
        // `fr5_seam_recovers_and_retries_invalid_candidate_in_one_call`.
        let cfg = chain_config_anchor_block(1, genesis.view().hash());
        let child = registration_block(2, cfg.view().hash(), 1, 5, 0x45);
        let (first, _) = bc.receive_block(child.view(), now);
        bc.receive_block(cfg.view(), now.saturating_add(1_000));
        let (second, _) = bc.receive_block(genesis.view(), now.saturating_add(9_000));

        let mut occupied = [false; 16];
        for (slot, flag) in occupied.iter_mut().enumerate() {
            *flag = bc.blocks.get(slot as u32).is_some();
        }
        let mut heads = [(NONE_REF, NONE_REF); 4];
        for (entry, head) in heads.iter_mut().zip(bc.chain_heads.occupied_heads()) {
            *entry = head;
        }
        Snapshot {
            occupied,
            heads,
            active: bc.active_chain_head_idx,
            ready: bc.is_ready(),
            outcomes: [first, second],
        }
    }
    let baseline = run(0);
    assert_eq!(
        baseline,
        run(1_000_000),
        "the recovery outcome is identical across wall-clocks"
    );
    // Non-vacuity: both blocks really were admitted (so the FR2 gate ran the
    // pass), the pass really failed (phase back to Collecting), and the
    // deletion really happened (the offending child is gone).
    assert_eq!(
        baseline.outcomes,
        [
            ReceiveBlockOutcome::AcceptedSilently,
            ReceiveBlockOutcome::AcceptedSilently
        ],
        "both admissions succeeded, so the failing pass was actually reached"
    );
    assert!(
        baseline.ready,
        "the failed pass recovered and its in-call retry validated the shortened candidate"
    );
    assert_eq!(
        baseline.occupied.iter().filter(|slot| **slot).count(),
        2,
        "recovery deleted the offending subtree and left exactly the genesis \
         and the chain-config block"
    );
}

/// A `payload_type=1` block with an explicit `creator` + `mined_amount`
/// header and a single node transfer (used to exercise the FR36 creator
/// credit — the other builders hard-code `mined_amount: 0`, which would mask
/// a creator-credit bug).
fn credit_block(
    seq: u32,
    prev: [u8; 32],
    creator: u32,
    mined_amount: u32,
    initializer: u32,
    receiver: u32,
    amount: u64,
) -> Block {
    let signer = Crypto::new([1u8; PRIVATE_KEY_SIZE]).ok().expect("test key");
    let nt = NodeTransfer::new_signed(
        3,
        seq.saturating_sub(1),
        initializer,
        receiver,
        amount,
        0,
        0,
        &signer,
    );
    let header = BlockHeader {
        version: 1,
        sequence: seq,
        creator,
        mined_amount,
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

/// AC4 / FR36 — the creator credit is auto-accepted (skipped) for an unseeded
/// creator (pre-seed zone): no phantom balance is written to an unknown
/// baseline. Uses a non-zero `mined_amount` so the credit is observable.
#[test]
fn fr3_creator_credit_skipped_for_unseeded_creator() {
    let mut bc = new_test_chain();
    // FR8 (Story 5.9, AC3): the candidate must carry a chain-config
    // block in scope, so the segment is anchored by one. Inert with
    // respect to everything below — see `chain_config_anchor_block`.
    let cfg_hash = admit_chain_config_anchor(&mut bc, 99, [0xAB; 32]);
    let blk = credit_block(100, cfg_hash, 8, 500, 7, 9, 0);
    let bi = bc
        .tier1_admit(&blk.view(), &blk.view().hash(), 0)
        .expect("block admitted");

    bc.run_processing_pass(bi).expect("pass succeeds");

    assert!(
        !bc.node_info.is_seeded(8),
        "unseeded creator is not seeded by its own credit"
    );
    assert_eq!(
        bc.node_info.balance_of(8),
        0,
        "FR36 creator credit skipped for a pre-seed-zone creator (AC4)"
    );
}

/// FR36 — a seeded creator IS credited its `mined_amount` (+ fees).
#[test]
fn fr3_creator_credit_applied_to_seeded_creator() {
    let mut bc = new_test_chain();
    // FR8 (Story 5.9, AC3): the candidate must carry a chain-config
    // block in scope, so the segment is anchored by one. Inert with
    // respect to everything below — see `chain_config_anchor_block`.
    let cfg_hash = admit_chain_config_anchor(&mut bc, 99, [0xAB; 32]);
    // max_node_id 9 so the transfer's (unseeded, pre-window) initializer 7 and
    // receiver 9 are within the valid node-id range — only node 3 is
    // individually seeded (partial FR50 coverage).
    let anchor = balance_block(100, cfg_hash, &[(3, 100, 0, 0x33)], 9);
    bc.tier1_admit(&anchor.view(), &anchor.view().hash(), 0)
        .expect("anchor admitted");
    let blk = credit_block(101, anchor.view().hash(), 3, 500, 7, 9, 0);
    let bi = bc
        .tier1_admit(&blk.view(), &blk.view().hash(), 0)
        .expect("credit block admitted");

    bc.run_processing_pass(bi).expect("pass succeeds");

    assert_eq!(
        bc.node_info.balance_of(3),
        600,
        "seeded creator credited mined_amount (100 seed + 500 mined)"
    );
}

/// AC3 (Story 5.4) — FR6 registration monotonicity: a registration whose
/// `new_node_id` is not `pre-block watermark + 1` is exact evidence of
/// invalidity. (In Story 5.3 the derive-only pass merely absorbed the id
/// monotonically; FR6 now *rejects* an out-of-sequence registration, routing
/// to the FR5 recovery via the earliest-offending-block error.)
#[test]
fn fr6_rejects_out_of_sequence_registration() {
    let mut bc = new_test_chain();
    // FR8 (Story 5.9, AC3): the candidate must carry a chain-config
    // block in scope, so the segment is anchored by one. Inert with
    // respect to everything below — see `chain_config_anchor_block`.
    let cfg_hash = admit_chain_config_anchor(&mut bc, 99, [0xAB; 32]);
    // Balance block declares max_node_id 5 → watermark 5; the next valid
    // registration id is 6. A registration for id 3 violates the stride-1 rule.
    let anchor = balance_block(100, cfg_hash, &[(1, 100, 0, 0x31)], 5);
    bc.tier1_admit(&anchor.view(), &anchor.view().hash(), 0)
        .expect("anchor admitted");
    let reg = registration_block(101, anchor.view().hash(), 1, 3, 0x43);
    let ri = bc
        .tier1_admit(&reg.view(), &reg.view().hash(), 0)
        .expect("registration admitted (Tier 1 does not check the watermark)");

    let result = bc.run_processing_pass(ri);
    assert_eq!(
        result,
        Err(ProcessingError::Invalid {
            block_idx: ri,
            reason: ValidationReason::RegistrationWatermark,
        }),
        "FR6 rejects a non-(watermark+1) registration as the earliest offender"
    );
}

// Note: the FR6 no-self-vote rule is a *structural* invariant checkable from
// block bytes alone, so it is enforced at Tier 1 intake (`staged_validation`,
// `Rejected(SelfVote)`) before a block can ever reach the Tier-3 processing
// pass — the FR6 re-affirmation in `validate_and_derive_block` is
// defense-in-depth. Self-vote rejection is therefore covered by the Tier-1
// tests; only the roster-dependent vote-target check below is Tier-3-only.

/// AC5 (Story 5.4) — FR6 vote-target existence: a `vote` that names a node
/// absent from the candidate roster at inclusion is exact evidence of
/// invalidity. (Node #0 and `vote == 0` remain the permanent exception.)
#[test]
fn fr6_rejects_unknown_vote_target() {
    let mut bc = new_test_chain();
    // FR8 (Story 5.9, AC3): the candidate must carry a chain-config
    // block in scope, so the segment is anchored by one. Inert with
    // respect to everything below — see `chain_config_anchor_block`.
    let cfg_hash = admit_chain_config_anchor(&mut bc, 99, [0xAB; 32]);
    // max_node_id 8 so the transfer's initializer 1 and receiver 2 are in range;
    // the vote target 9 is beyond the watermark → cannot exist.
    let anchor = balance_block(100, cfg_hash, &[(1, 500, 0, 0x31)], 8);
    bc.tier1_admit(&anchor.view(), &anchor.view().hash(), 0)
        .expect("anchor admitted");
    // Vote target 9 is beyond max_known_node_id (8) → not a possible node.
    let tx = transfer_block(101, anchor.view().hash(), 1, 2, 100, 1, 9);
    let ti = bc
        .tier1_admit(&tx.view(), &tx.view().hash(), 0)
        .expect("tx admitted");
    assert_eq!(
        bc.run_processing_pass(ti),
        Err(ProcessingError::Invalid {
            block_idx: ti,
            reason: ValidationReason::VoteTargetUnknown,
        }),
        "FR6 rejects an unknown vote target"
    );
}

/// FR6 node-existence bound — a transaction that references a node id beyond
/// `max_known_node_id` (contiguous ids ⇒ it cannot exist) is rejected on BOTH
/// sides: the initializer (input) and the receiver (output). This holds even for
/// an unseeded (pre-window) node — its existence is still range-checkable — so a
/// window-anchored candidate is not blindly trusted.
#[test]
fn fr6_rejects_out_of_range_referenced_node() {
    let mut bc = new_test_chain();
    // FR8 (Story 5.9, AC3): the candidate must carry a chain-config
    // block in scope, so the segment is anchored by one. Inert with
    // respect to everything below — see `chain_config_anchor_block`.
    let cfg_hash = admit_chain_config_anchor(&mut bc, 99, [0xAB; 32]);
    // Window-anchored, watermark 5 (only node 1 individually seeded).
    let anchor = balance_block(100, cfg_hash, &[(1, 500, 0, 0x31)], 5);
    bc.tier1_admit(&anchor.view(), &anchor.view().hash(), 0)
        .expect("anchor admitted");
    // Output side: receiver 99 is beyond the watermark.
    let out = transfer_block(101, anchor.view().hash(), 1, 99, 100, 1, 0);
    let oi = bc
        .tier1_admit(&out.view(), &out.view().hash(), 0)
        .expect("out admitted");
    assert_eq!(
        bc.run_processing_pass(oi),
        Err(ProcessingError::Invalid {
            block_idx: oi,
            reason: ValidationReason::NodeIdOutOfRange,
        }),
        "a transfer TO a node beyond the watermark is rejected (output side)"
    );
    // Input side: an (unseeded) initializer 88 is beyond the watermark — normally
    // an unseeded initializer is trusted on a window-anchored candidate, but its
    // existence is still range-bounded.
    let inp = transfer_block(101, anchor.view().hash(), 88, 2, 100, 1, 0);
    let ii = bc
        .tier1_admit(&inp.view(), &inp.view().hash(), 0)
        .expect("inp admitted");
    assert_eq!(
        bc.run_processing_pass(ii),
        Err(ProcessingError::Invalid {
            block_idx: ii,
            reason: ValidationReason::NodeIdOutOfRange,
        }),
        "a transfer FROM a node beyond the watermark is rejected (input side)"
    );
}

/// FR6 vote-target existence is a WATERMARK RANGE check, not a per-node
/// `is_seeded` lookup. A balance block covers only a subset of nodes (FR50) but
/// declares the full `max_node_id`; a transaction may legitimately vote for a
/// node that exists (id ≤ watermark) yet whose own balance-block coverage is
/// not present earlier in the window. This must be ACCEPTED — the pre-fix
/// `is_seeded(vote)` check would have falsely rejected it as `VoteTargetUnknown`.
#[test]
fn fr6_vote_target_in_range_but_not_individually_seeded_is_accepted() {
    let mut bc = new_test_chain();
    // FR8 (Story 5.9, AC3): the candidate must carry a chain-config
    // block in scope, so the segment is anchored by one. Inert with
    // respect to everything below — see `chain_config_anchor_block`.
    let cfg_hash = admit_chain_config_anchor(&mut bc, 99, [0xAB; 32]);
    // Partial-coverage balance block: seeds only node 1, but declares
    // max_node_id = 10 (nodes 2..=10 exist pre-window / elsewhere in the window
    // but are not individually seeded by THIS block).
    let anchor = balance_block(100, cfg_hash, &[(1, 500, 0, 0x31)], 10);
    bc.tier1_admit(&anchor.view(), &anchor.view().hash(), 0)
        .expect("anchor admitted");
    // Node 1 (seeded) votes for node 5: 5 ∉ seeded-set but 5 ≤ watermark(10).
    let tx = transfer_block(101, anchor.view().hash(), 1, 2, 100, 1, 5);
    let ti = bc
        .tier1_admit(&tx.view(), &tx.view().hash(), 0)
        .expect("tx admitted");
    assert_eq!(
        bc.run_processing_pass(ti).map(|_| ()),
        Ok(()),
        "a vote for an in-range node is accepted even if not individually seeded"
    );
    // Boundary: a vote for node 11 (> watermark 10) is still exact-evidence invalid.
    let tx2 = transfer_block(101, anchor.view().hash(), 1, 2, 100, 1, 11);
    let ti2 = bc
        .tier1_admit(&tx2.view(), &tx2.view().hash(), 0)
        .expect("tx2 admitted");
    assert_eq!(
        bc.run_processing_pass(ti2),
        Err(ProcessingError::Invalid {
            block_idx: ti2,
            reason: ValidationReason::VoteTargetUnknown,
        }),
        "a vote for a node beyond the watermark is still rejected"
    );
}

/// FR3/FR6 — on a WINDOW-anchored candidate the incremental watermark is only
/// authoritative once the first balance block establishes it. A registration
/// that precedes the first balance block is in the trusted pre-window region
/// (AC4): its monotonicity is NOT re-checked (it would otherwise be measured
/// against a still-0 watermark and falsely rejected). The earliest balance
/// block's `max_node_id` (read once at the end of the backward mark) seeds the
/// existence floor. Genesis-anchored candidates are unaffected — they re-derive
/// the watermark from block #0, so their registrations ARE monotonicity-checked
/// (covered by `fr6_rejects_out_of_sequence_registration`).
#[test]
fn fr6_window_anchored_registration_before_first_balance_is_trusted() {
    let mut bc = new_test_chain();
    // FR8 (Story 5.9, AC3): the candidate must carry a chain-config
    // block in scope, so the segment is anchored by one. Inert with
    // respect to everything below — see `chain_config_anchor_block`.
    let cfg_hash = admit_chain_config_anchor(&mut bc, 99, [0xAB; 32]);
    // Orphan anchor (seq 100, window-anchored): a registration for node 7 —
    // stride-1 against a 0 watermark would demand id 1, so the OLD per-0 check
    // would reject it. It precedes the segment's only balance block (seq 101).
    let reg = registration_block(100, cfg_hash, 1, 7, 0x47);
    bc.tier1_admit(&reg.view(), &reg.view().hash(), 0)
        .expect("registration admitted");
    // Balance block at seq 101: declares the full count (max_node_id 10) — the
    // existence floor — and seeds node 1.
    let bal = balance_block(101, reg.view().hash(), &[(1, 100, 0, 0x31)], 10);
    let bi = bc
        .tier1_admit(&bal.view(), &bal.view().hash(), 0)
        .expect("balance admitted");
    assert_eq!(
        bc.run_processing_pass(bi).map(|_| ()),
        Ok(()),
        "a window-anchored pre-first-balance registration is trusted, not \
         rejected against a 0 watermark"
    );
    // The registered node is on the roster afterwards.
    assert!(
        bc.node_info.is_seeded(7),
        "node 7 registered during the pass"
    );
}

/// AC2 (Story 5.4) — FR6 block-creator signature: a block whose creator key
/// is derivable (node #0 → the FR69 trust anchor) but whose signature was
/// produced by a different key is rejected (the first block-creator-signature
/// check in the crate).
#[test]
fn fr6_rejects_wrong_block_creator_signature() {
    let mut bc = new_test_chain();
    // A genesis (#0) block, creator = node #0, but signed by the WRONG key
    // ([9u8] ≠ the trust anchor pubkey([1u8])).
    let wrong = Crypto::new([9u8; PRIVATE_KEY_SIZE])
        .ok()
        .expect("wrong test key");
    let nt = NodeTransfer::new_signed(0, 0, 0, 9, 100, 1, 0, &wrong);
    let header = BlockHeader {
        version: 1,
        sequence: 0,
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
    builder.add_node_transfer(&nt).ok().expect("add transfer");
    let block = builder.build_signed(&wrong).ok().expect("build signed");
    let idx = bc
        .tier1_admit(&block.view(), &block.view().hash(), 0)
        .expect("admitted (creator signature is not a Tier 1 gate)");
    // FR8 (Story 5.9, AC3): the candidate must name a configuration, and the
    // existence check runs before the forward traversal (PRD FR3) — so
    // without block #1 the pass would report the whole-candidate verdict
    // instead of the per-block one under test. The config block sits *above*
    // the offender, so the walk still reaches #0 first.
    let cfg = chain_config_anchor_block(1, block.view().hash());
    let tip = bc
        .tier1_admit(&cfg.view(), &cfg.view().hash(), 0)
        .expect("chain-config block admitted");
    assert_eq!(
        bc.run_processing_pass(tip),
        Err(ProcessingError::Invalid {
            block_idx: idx,
            reason: ValidationReason::CreatorSignatureInvalid,
        }),
        "FR6 rejects a block-creator signature that fails against the derived key"
    );
}

/// AC7 (Story 5.4) — FR6 requires every balance block *after the earliest* to
/// carry `max_node_id` equal to the forward-traversal-tracked watermark at its
/// sequence; a divergence is exact evidence of invalidity. (Deferred from
/// Story 5.3, which only initialized the watermark from the earliest block.)
#[test]
fn fr6_rejects_later_balance_block_max_node_id_mismatch() {
    let mut bc = new_test_chain();
    // FR8 (Story 5.9, AC3): the candidate must carry a chain-config
    // block in scope, so the segment is anchored by one. Inert with
    // respect to everything below — see `chain_config_anchor_block`.
    let cfg_hash = admit_chain_config_anchor(&mut bc, 99, [0xAB; 32]);
    // Earliest balance block → watermark initialized to 1.
    let b0 = balance_block(100, cfg_hash, &[(1, 500, 0, 0x31)], 1);
    bc.tier1_admit(&b0.view(), &b0.view().hash(), 0)
        .expect("earliest balance block admitted");
    // A later balance block claims max_node_id 5 ≠ the tracked watermark 1.
    let b1 = balance_block(101, b0.view().hash(), &[(1, 400, 0, 0x31)], 5);
    let i1 = bc
        .tier1_admit(&b1.view(), &b1.view().hash(), 0)
        .expect("later balance block admitted");
    assert_eq!(
        bc.run_processing_pass(i1),
        Err(ProcessingError::Invalid {
            block_idx: i1,
            reason: ValidationReason::BalanceMaxNodeIdMismatch,
        }),
        "FR6 rejects a later balance block whose max_node_id diverges from the watermark"
    );
}

/// AC6 (Story 5.4) — FR6 chain-config compliance: a chain-config block
/// (`payload_type=3`) whose content is not byte-identical to the durable-locked
/// configuration is exact evidence of invalidity. (The FR7 content-signature
/// gate and establishing the lock from the candidate are Story 5.6.)
#[test]
fn fr6_rejects_divergent_chain_config() {
    // `new_test_chain` is durably locked on `BASE_CONFIG_CONTENT`; this
    // block carries a different (but equally well-framed) content region.
    let mut bc = new_test_chain();
    let header = BlockHeader {
        version: 1,
        sequence: 5,
        creator: 0,
        mined_amount: 0,
        payload_type: PAYLOAD_TYPE_CHAIN_CONFIG,
        consumed_votes: 0,
        first_voted_node: 0,
        consumed_votes_from_first_voted_node: 0,
        previous_hash: [0u8; 32],
        signature: [0u8; SIGNATURE_SIZE],
    };
    let signer = Crypto::new([1u8; PRIVATE_KEY_SIZE]).ok().expect("test key");
    let mut builder = BlockBuilder::new().header(header);
    let mut config_payload = window_config_builder(TEST_W);
    config_payload
        .add_literal(parameter::VOTE_INTEREST, &[5])
        .ok()
        .expect("a one-entry override set frames");
    builder
        .set_chain_config_payload(config_payload.build_signed(&signer))
        .ok()
        .expect("set chain-config payload");
    let block = builder.build_signed(&signer).ok().expect("build signed");
    let idx = bc
        .tier1_admit(&block.view(), &block.view().hash(), 0)
        .expect("admitted (content-signature gate is Story 5.6)");
    assert_eq!(
        bc.run_processing_pass(idx),
        Err(ProcessingError::Invalid {
            block_idx: idx,
            reason: ValidationReason::ChainConfigMismatch,
        }),
        "FR6 rejects a chain-config block diverging from the durable-locked config"
    );
}

/// AC3 (Story 5.4) — FR6 registration `new_public_key` global uniqueness: a
/// registration whose new key collides with an already-seeded node's key is
/// exact evidence of invalidity.
#[test]
fn fr6_rejects_duplicate_public_key() {
    let mut bc = new_test_chain();
    // FR8 (Story 5.9, AC3): the candidate must carry a chain-config
    // block in scope, so the segment is anchored by one. Inert with
    // respect to everything below — see `chain_config_anchor_block`.
    let cfg_hash = admit_chain_config_anchor(&mut bc, 99, [0xAB; 32]);
    let anchor = balance_block(100, cfg_hash, &[(1, 500, 0, 0x31)], 1);
    bc.tier1_admit(&anchor.view(), &anchor.view().hash(), 0)
        .expect("anchor admitted");
    // pk_byte == 1 ⇒ new_public_key == pubkey([1u8]) == node 1's seeded key.
    let reg = registration_block(101, anchor.view().hash(), 1, 2, 1);
    let ri = bc
        .tier1_admit(&reg.view(), &reg.view().hash(), 0)
        .expect("registration admitted");
    assert_eq!(
        bc.run_processing_pass(ri),
        Err(ProcessingError::Invalid {
            block_idx: ri,
            reason: ValidationReason::DuplicatePublicKey,
        }),
        "FR6 rejects a registration whose new_public_key duplicates a seeded node's key"
    );
}

/// AC2/AC4 (Story 5.4) — on a GENESIS-anchored candidate (re-derivable in full
/// from block #0) there is no pre-seed trust zone: a transaction whose
/// initializer was never registered/seeded acts before it exists and is exact
/// evidence of invalidity (`UnseededActor`) — unlike a window-anchored
/// candidate, which legitimately trusts such pre-window history.
#[test]
fn fr6_rejects_unseeded_actor_on_genesis_anchored_candidate() {
    let mut bc = new_test_chain();
    // Genesis block #0 seeds no node (a bare transfer, not a node-#0 registration).
    let genesis = node_transfer_block(0, 0, 0, 0);
    bc.tier1_admit(&genesis.view(), &genesis.view().hash(), 0)
        .expect("genesis admitted");
    // FR8 (Story 5.9, AC3): block #1 carries the chain-config the candidate
    // must name — the existence check precedes the forward traversal (PRD
    // FR3), and it sits below the offender so the walk still reaches it.
    let cfg = chain_config_anchor_block(1, genesis.view().hash());
    bc.tier1_admit(&cfg.view(), &cfg.view().hash(), 0)
        .expect("chain-config block admitted");
    // Block #2: a transfer whose initializer (node 1) never registered.
    let child = transfer_block(2, cfg.view().hash(), 1, 2, 100, 1, 0);
    let ci = bc
        .tier1_admit(&child.view(), &child.view().hash(), 0)
        .expect("child admitted");
    assert_eq!(
        bc.run_processing_pass(ci),
        Err(ProcessingError::Invalid {
            block_idx: ci,
            reason: ValidationReason::UnseededActor,
        }),
        "genesis-anchored: an unseeded initializer is invalid (no pre-seed trust)"
    );
}

// =======================================================================
// Story 5.9 — FR7 content-signature commitment + FR8 tentative/durable
// =======================================================================

/// AC2 — the **first** chain-config block whose FR7 signature verifies and
/// whose content the module accepts is loaded tentatively, and is retained
/// like any other admitted block.
#[test]
fn fr8_first_config_block_loads_tentatively() {
    let mut bc = new_unconfigured_test_chain();
    assert!(
        bc.chain_config.active_configuration().is_none(),
        "a joining node starts with no configuration"
    );
    let cfg = chain_config_anchor_block(100, [0xAB; 32]);

    let (outcome, _) = bc.receive_block(cfg.view(), 0);

    assert_eq!(outcome, ReceiveBlockOutcome::AcceptedSilently);
    let idx = bc
        .blocks
        .find(100, &cfg.view().hash())
        .expect("the config block is retained (FR8)");
    assert_eq!(
        bc.chain_config.tentative_content(),
        Some(content_of(&cfg)),
        "the content region is held tentatively, signature trailer excluded"
    );
    assert!(
        !bc.chain_config.is_durable_locked(),
        "a join-path load is tentative, never a lock"
    );
    assert_eq!(
        bc.tentative_config_block_idx, idx,
        "the provenance names the retained block"
    );
}

/// AC2 — a valid-signature config block whose content violates a structural
/// bound is exact evidence of invalidity (FR16): it does not enter durable
/// storage, and no tentative configuration remains loaded.
#[test]
fn fr8_bound_violating_content_is_rejected_and_stores_nothing() {
    let mut bc = new_unconfigured_test_chain();
    let cfg = chain_config_block_from(100, [0xAB; 32], &mut bound_violating_config_builder());

    let (outcome, _) = bc.receive_block(cfg.view(), 0);

    assert_eq!(
        outcome,
        ReceiveBlockOutcome::Rejected(RejectReason::InvalidEvidence),
        "a refused content is exact evidence, not a silent discard"
    );
    assert_eq!(
        bc.blocks.len(),
        0,
        "the block never entered durable storage"
    );
    assert!(
        bc.chain_config.active_configuration().is_none(),
        "no configuration remains loaded after a refusal"
    );
    assert_eq!(bc.tentative_config_block_idx, NONE_REF);
}

/// AC2 + AC7 — a second chain-config block arriving while the configuration
/// is merely **tentative** must neither override it nor be discarded.
///
/// Both halves matter. FR8 says such a block "shall be stored in the
/// block-tree subject to FR16 and shall not override the tentative
/// configuration"; and the AC6 mismatch path *depends* on it being retained,
/// because the content it adopts comes from a config block that disagrees
/// with the current tentative. A tentative-keyed FR17 gate would discard
/// exactly the block the recovery needs.
#[test]
fn fr8_second_config_block_while_tentative_neither_overrides_nor_is_discarded() {
    let mut bc = new_unconfigured_test_chain();
    let first = chain_config_anchor_block(100, [0xAB; 32]);
    bc.receive_block(first.view(), 0);
    let first_idx = bc
        .blocks
        .find(100, &first.view().hash())
        .expect("first config block retained");

    let second = chain_config_block_from(101, first.view().hash(), &mut alt_config_builder());
    let (outcome, _) = bc.receive_block(second.view(), 0);

    assert_eq!(
        outcome,
        ReceiveBlockOutcome::AcceptedSilently,
        "FR17 must stand down while the configuration is only tentative"
    );
    assert!(
        bc.blocks.find(101, &second.view().hash()).is_some(),
        "the disagreeing block is retained, not discarded"
    );
    assert_eq!(
        bc.chain_config.tentative_content(),
        Some(content_of(&first)),
        "the tentative configuration is not overridden"
    );
    assert_eq!(
        bc.tentative_config_block_idx, first_idx,
        "provenance still names the first block"
    );
}

/// AC7 — once the configuration is durably locked, the FR17 gate *does* fire:
/// a config block whose content differs is silently discarded. The contrast
/// with the test above is the whole of AC7.
#[test]
fn fr17_discards_mismatching_config_block_only_once_durably_locked() {
    let mut bc = new_test_chain(); // durably locked on the base override set
    let cfg = chain_config_block_from(100, [0xAB; 32], &mut alt_config_builder());

    let (outcome, _) = bc.receive_block(cfg.view(), 0);

    assert_eq!(
        outcome,
        ReceiveBlockOutcome::Rejected(RejectReason::InvalidEvidence),
        "post-lock, a disagreeing config block is discarded (FR17)"
    );
    assert_eq!(bc.blocks.len(), 0);
}

/// AC3 — a candidate segment carrying **no** chain-config block cannot
/// satisfy FR6 chain-config compliance, so the pass refuses it and the FR5
/// recovery rolls it back.
#[test]
fn fr8_candidate_without_config_block_is_refused() {
    let mut bc = new_test_chain();
    let genesis = node_transfer_block(0, 3, 0, 7);
    let gi = bc
        .tier1_admit(&genesis.view(), &genesis.view().hash(), 0)
        .expect("genesis admitted");

    assert_eq!(
        bc.run_processing_pass(gi),
        Err(ProcessingError::Invalid {
            block_idx: gi,
            reason: ValidationReason::MissingChainConfigBlock,
        }),
        "a candidate naming no configuration is not a chain to go Ready on"
    );
}

/// Story 5.13 — a segment that names no configuration is not an FR2
/// candidate at all, so nothing is deleted for it. Before 5.13 it qualified,
/// failed the FR8 final check, and FR5 deleted its head — a valid block —
/// once per re-qualification.
#[test]
fn fr2_segment_naming_no_configuration_is_not_a_candidate() {
    // A window-anchored segment of W + H − 1 = 8 blocks (#98..=#105),
    // none of them a chain-config block, on a configured node.
    let mut bc = new_w6_chain();
    let base = node_transfer_block(98, 3, 97, 7);
    let mut prev = base.view().hash();
    let above: [Block; 7] = core::array::from_fn(|i| {
        let blk = linked_transfer_block(99 + i as u32, prev);
        prev = blk.view().hash();
        blk
    });
    for blk in core::iter::once(&base).chain(&above) {
        bc.receive_block(blk.view(), 0);
    }

    assert!(
        bc.evaluate_stopping_condition().is_none(),
        "longer than W, but the segment names no configuration"
    );
    assert!(
        bc.current_phase() == LifecyclePhase::Collecting,
        "no pass ran"
    );
    assert_eq!(bc.block_tree_len(), 8, "nothing was deleted");

    // The segment's own configuration arriving above it makes it a
    // candidate, which validates. #106 is not a clean slot (`H = 3`).
    let cfg = w6_config_anchor_block(106, prev);
    bc.receive_block(cfg.view(), 0);
    assert!(bc.is_ready(), "the segment now names its configuration");
    // Nothing was deleted for the waiting: the nine-block segment is
    // exactly `W + H`, so its Ready entry keeps #98..=#100 in the horizon
    // (FR58, Story 6.14).
    assert_eq!(bc.block_tree_len(), 9, "every block survived the wait");
    assert!(
        bc.block_tree_contains(98, &base.view().hash()),
        "#98 is the horizon root"
    );
    for blk in above.iter().chain([&cfg]) {
        let view = blk.view();
        assert!(bc.block_tree_contains(view.sequence(), &view.hash()));
    }
    assert_eq!(bc.active_snake_chain_window(), Ok((101, 106)));
    assert_eq!(
        bc.current_active_head(),
        Some(106),
        "the active head is the config block that completed the segment"
    );
}

/// AC4 + AC5 — the Ready transition commits the configuration durably exactly
/// once, and deletes every disagreeing chain-config block in the tree,
/// transitively, without touching the active chain.
///
/// The side branch is built to be the hard case: it forks at the genesis, its
/// config block disagrees, and it carries a descendant above that block, so
/// the cleanup has to be transitive and has to follow up on `chain_heads`.
#[test]
fn fr8_ready_locks_durably_and_deletes_disagreeing_config_subtrees() {
    let mut bc = new_unconfigured_test_chain();
    let genesis = node_transfer_block(0, 0, 0, 0);
    // Main branch: #0 → cfg A (#1) → cfg A (#2) → cfg A (#3), tip sequence 3.
    // Three blocks carrying *identical* content, which AC3 permits and in
    // fact requires: every in-scope config block must be byte-identical to
    // the tentative. They are chain-config blocks rather than transfers
    // because the candidate is genesis-anchored, where there is no pre-seed
    // trust zone — a transfer between unregistered nodes would fail FR6 as an
    // unseeded actor, and this test is not about that.
    let cfg_a = chain_config_anchor_block(1, genesis.view().hash());
    let main_2 = chain_config_anchor_block(2, cfg_a.view().hash());
    let main_3 = chain_config_anchor_block(3, main_2.view().hash());
    // Side branch off the genesis: cfg B (#1') → tx (#2'). Tip sequence 2, so
    // FR2 selection prefers the main branch's higher tip. The side branch is
    // never validated (it is not the candidate), so its transfer block's
    // unseeded actors are irrelevant — it is here to prove the cleanup is
    // transitive and follows up on `chain_heads`.
    let cfg_b = chain_config_block_from(1, genesis.view().hash(), &mut alt_config_builder());
    let side_2 = linked_transfer_block(2, cfg_b.view().hash());

    // Config A first, so it is the tentative (AC2). Everything is admitted
    // while still orphaned — window-anchored segments far below W = 16, so no
    // FR2 trigger — and the genesis comes last to connect them all at once.
    for block in [&cfg_a, &main_2, &main_3, &cfg_b, &side_2] {
        let (outcome, _) = bc.receive_block(block.view(), 0);
        assert_eq!(
            outcome,
            ReceiveBlockOutcome::AcceptedSilently,
            "every block is admitted before the genesis connects them"
        );
    }
    assert_eq!(
        bc.chain_config.tentative_content(),
        Some(content_of(&cfg_a)),
        "config A is the tentative; config B is retained but does not override"
    );

    let (outcome, _) = bc.receive_block(genesis.view(), 0);
    assert_eq!(outcome, ReceiveBlockOutcome::AcceptedSilently);

    // AC4: the commitment is durable, over config A's content.
    assert!(bc.is_ready(), "the main candidate validates → Ready");
    assert!(bc.chain_config.is_durable_locked(), "FR8 lock engaged");
    assert_eq!(
        bc.chain_config.durable_content(),
        Some(content_of(&cfg_a)),
        "the locked content is the candidate's own"
    );
    // AC5: config B and its descendant are gone, transitively.
    assert!(
        bc.blocks.find(1, &cfg_b.view().hash()).is_none(),
        "the disagreeing config block is deleted"
    );
    assert!(
        bc.blocks.find(2, &side_2.view().hash()).is_none(),
        "and so is its descendant, which is unverifiable without it"
    );
    // The active chain is untouched — a consequence of AC3, not a precaution.
    for (seq, block) in [(0u32, &genesis), (1, &cfg_a), (2, &main_2), (3, &main_3)] {
        let idx = bc
            .blocks
            .find(seq, &block.view().hash())
            .unwrap_or_else(|| panic!("main-branch block at sequence {seq} survives"));
        assert!(
            bc.blocks
                .get(idx)
                .is_some_and(|entry| entry.is_on_active_chain()),
            "main-branch block at sequence {seq} is on the active chain"
        );
    }
    assert_eq!(bc.blocks.len(), 4, "exactly the active chain remains");
}

/// AC4 — a second durable commitment is **refused**, not silently re-applied.
/// The set-once guarantee is the configuration module's (Story 5.7); this
/// asserts the lifecycle does not paper over it.
#[test]
fn fr8_second_durable_commit_is_refused() {
    let mut bc = new_unconfigured_test_chain();
    let genesis = node_transfer_block(0, 0, 0, 0);
    let cfg = chain_config_anchor_block(1, genesis.view().hash());
    bc.receive_block(cfg.view(), 0);
    bc.receive_block(genesis.view(), 0);
    assert!(bc.chain_config.is_durable_locked(), "locked once");
    let cfg_idx = bc
        .blocks
        .find(1, &cfg.view().hash())
        .expect("config block on the active chain");

    assert!(
        bc.commit_durable_chain_config(cfg_idx).is_err(),
        "the lock is set-once for the lifetime of the chain"
    );
    assert!(
        bc.chain_config.is_durable_locked(),
        "and the refusal leaves the existing lock intact"
    );
    // The lifecycle refuses above because the storage seam is itself set-once,
    // so that assertion alone never reaches the module. Assert the module's
    // own refusal directly — it is the guarantee AC4 actually names, and the
    // one this story must not paper over.
    assert!(
        bc.chain_config.promote_durable().is_err(),
        "the configuration module refuses a second promotion in its own right"
    );
}

/// AC6 — on a final-check content mismatch the node adopts the candidate's
/// own first in-scope config content and re-runs the pass over the same
/// candidate, in the same call, reaching Ready without waiting for another
/// admission. The superseded tentative's block is removed.
#[test]
fn fr8_mismatch_adopts_candidate_content_and_reruns_in_one_call() {
    let mut bc = new_unconfigured_test_chain();
    // An off-candidate config block arrives first and becomes the tentative.
    // Sequence 500, alone: a length-1 window-anchored segment never qualifies
    // under FR2, so it is never itself a candidate.
    let stray = chain_config_block_from(500, [0xEE; 32], &mut alt_config_builder());
    bc.receive_block(stray.view(), 0);
    assert_eq!(
        bc.chain_config.tentative_content(),
        Some(content_of(&stray)),
        "the stray block supplied the tentative configuration"
    );

    let genesis = node_transfer_block(0, 0, 0, 0);
    let cfg = chain_config_anchor_block(1, genesis.view().hash());
    bc.receive_block(cfg.view(), 0);
    let (outcome, _) = bc.receive_block(genesis.view(), 0);

    assert_eq!(outcome, ReceiveBlockOutcome::AcceptedSilently);
    assert!(
        bc.is_ready(),
        "the adopt-retry validated the same candidate inside the same call"
    );
    assert_eq!(
        bc.chain_config.durable_content(),
        Some(content_of(&cfg)),
        "the chain's own configuration was adopted and locked, not the stray's"
    );
    assert!(
        bc.blocks.find(500, &stray.view().hash()).is_none(),
        "the superseded tentative's block is removed"
    );
    assert_eq!(bc.blocks.len(), 2, "genesis + the chain's config block");
}

/// AC6 — a candidate carrying **two differing** config contents can never
/// satisfy AC3 under any adoption, so it takes the hard FR5 rollback with no
/// adopt-retry. This is the one shape that could otherwise oscillate
/// adopt→mismatch→adopt, so the test's termination is part of what it proves.
///
/// The arrival order is the adversarial one: the *upper* config block loads
/// the tentative first, so the run is `pass → adopt → pass → FR5 → pass`,
/// exercising both single-use retry tokens in one call — the worst case the
/// three-pass bound permits, and no more.
#[test]
fn fr8_two_differing_config_contents_take_the_hard_rollback() {
    let mut bc = new_unconfigured_test_chain();
    let genesis = node_transfer_block(0, 0, 0, 0);
    let cfg_a = chain_config_anchor_block(1, genesis.view().hash());
    let cfg_b = chain_config_block_from(2, cfg_a.view().hash(), &mut alt_config_builder());

    // B first: it becomes the tentative, so the pass mismatches at A — the
    // candidate's *first* config block — and the adopt path fires.
    bc.receive_block(cfg_b.view(), 0);
    assert_eq!(
        bc.chain_config.tentative_content(),
        Some(content_of(&cfg_b)),
        "the upper config block supplied the tentative"
    );
    bc.receive_block(cfg_a.view(), 0);
    let (outcome, _) = bc.receive_block(genesis.view(), 0);

    assert_eq!(outcome, ReceiveBlockOutcome::AcceptedSilently);
    // B is exact evidence of non-compliance once A is adopted, so FR5 deletes
    // it; the shortened candidate then validates on the Story-5.5 retry.
    assert!(
        bc.blocks.find(2, &cfg_b.view().hash()).is_none(),
        "the second, disagreeing config block is deleted as exact evidence"
    );
    assert!(bc.is_ready(), "the shortened candidate validates");
    assert_eq!(
        bc.chain_config.durable_content(),
        Some(content_of(&cfg_a)),
        "the chain locked on its first in-scope configuration"
    );
    assert_eq!(bc.blocks.len(), 2, "genesis + config A");
}

/// AC8 — when an FR5 recovery deletes the subtree containing the tentatively
/// loaded config block, the tentative configuration goes with it: the
/// justification for holding it is gone.
#[test]
fn fr8_recovery_unloads_a_deleted_tentative_configuration() {
    let mut bc = new_unconfigured_test_chain();
    let cfg = chain_config_anchor_block(100, [0xAB; 32]);
    bc.receive_block(cfg.view(), 0);
    let cfg_idx = bc
        .blocks
        .find(100, &cfg.view().hash())
        .expect("config block retained");
    assert!(bc.chain_config.active_configuration().is_some());

    bc.set_lifecycle_phase(LifecyclePhase::Processing);
    bc.recover_from_failed_pass(
        ProcessingError::Invalid {
            block_idx: cfg_idx,
            reason: ValidationReason::PreviousHashMismatch,
        },
        cfg_idx,
    );

    assert!(bc.blocks.get(cfg_idx).is_none(), "the block was deleted");
    assert!(
        bc.chain_config.active_configuration().is_none(),
        "the tentative configuration is discarded with its block"
    );
    assert_eq!(bc.tentative_config_block_idx, NONE_REF);
}

/// AC8 — and only then. A recovery whose delete-set does not contain the
/// tentative's block leaves the configuration loaded.
#[test]
fn fr8_recovery_keeps_a_surviving_tentative_configuration() {
    let mut bc = new_unconfigured_test_chain();
    let cfg = chain_config_anchor_block(100, [0xAB; 32]);
    bc.receive_block(cfg.view(), 0);
    let cfg_idx = bc
        .blocks
        .find(100, &cfg.view().hash())
        .expect("config block retained");
    // An unrelated orphan on its own branch — deleting it cannot reach the
    // config block.
    let other = node_transfer_block(200, 3, 199, 7);
    bc.receive_block(other.view(), 0);
    let other_idx = bc
        .blocks
        .find(200, &other.view().hash())
        .expect("other block retained");

    bc.set_lifecycle_phase(LifecyclePhase::Processing);
    bc.recover_from_failed_pass(
        ProcessingError::Invalid {
            block_idx: other_idx,
            reason: ValidationReason::PreviousHashMismatch,
        },
        other_idx,
    );

    assert!(
        bc.blocks.get(cfg_idx).is_some(),
        "the config block survives"
    );
    assert_eq!(
        bc.chain_config.tentative_content(),
        Some(content_of(&cfg)),
        "an untouched tentative configuration stays loaded"
    );
    assert_eq!(bc.tentative_config_block_idx, cfg_idx);
}

/// AC8 — a **durable-locked** configuration is never unloaded. The lock is
/// irrevocable for the lifetime of the chain, and the module enforces that
/// itself, which is why the recovery needs no lock check of its own.
#[test]
fn fr8_recovery_never_unloads_a_durable_configuration() {
    let mut bc = new_test_chain(); // durably locked on the base override set
    let cfg = chain_config_anchor_block(100, [0xAB; 32]);
    bc.receive_block(cfg.view(), 0);
    let cfg_idx = bc
        .blocks
        .find(100, &cfg.view().hash())
        .expect("a matching config block is admitted post-lock");

    bc.set_lifecycle_phase(LifecyclePhase::Processing);
    bc.recover_from_failed_pass(
        ProcessingError::Invalid {
            block_idx: cfg_idx,
            reason: ValidationReason::PreviousHashMismatch,
        },
        cfg_idx,
    );

    assert!(bc.blocks.get(cfg_idx).is_none(), "the block was deleted");
    assert!(
        bc.chain_config.is_durable_locked(),
        "the FR8 lock survives the deletion of the block that carried it"
    );
}

/// AC9 — the commitment lifecycle is wall-clock-independent (FR63/NFR5): the
/// same block set replayed under two clocks produces the same lock, the same
/// cleanup delete-set and the same tree.
#[test]
fn fr8_commitment_ignores_now() {
    fn run(now: u64) -> ([bool; 16], bool, bool, usize) {
        let mut bc = new_unconfigured_test_chain();
        let genesis = node_transfer_block(0, 0, 0, 0);
        let cfg_a = chain_config_anchor_block(1, genesis.view().hash());
        let cfg_b = chain_config_block_from(1, genesis.view().hash(), &mut alt_config_builder());
        let side = linked_transfer_block(2, cfg_b.view().hash());
        let main_2 = chain_config_anchor_block(2, cfg_a.view().hash());
        let main_3 = chain_config_anchor_block(3, main_2.view().hash());
        for (step, block) in [&cfg_a, &main_2, &main_3, &cfg_b, &side, &genesis]
            .into_iter()
            .enumerate()
        {
            bc.receive_block(block.view(), now.saturating_add(step as u64 * 1_000));
        }
        let mut occupied = [false; 16];
        for (slot, flag) in occupied.iter_mut().enumerate() {
            *flag = bc.blocks.get(slot as u32).is_some();
        }
        (
            occupied,
            bc.is_ready(),
            bc.chain_config.is_durable_locked(),
            bc.blocks.len(),
        )
    }
    let baseline = run(0);
    assert_eq!(
        baseline,
        run(5_000_000),
        "the FR8 lock and the AC5 cleanup are identical across wall-clocks"
    );
    // Non-vacuity: the run really reached the lock and really cleaned up.
    assert!(
        baseline.1 && baseline.2,
        "the replay reached the durable lock"
    );
    assert_eq!(baseline.3, 4, "the side branch was cleaned up");
}

/// AC9 — and it is arrival-order-independent where FR8 requires it: whichever
/// config block happens to load the tentative first, the node converges on
/// the same locked configuration and the same retained tree. The two orders
/// get there by different routes — one locks directly (AC5 cleans up), the
/// other adopts and re-runs (AC6 removes the superseded block) — and that the
/// destination is identical is the property.
#[test]
fn fr8_lock_is_arrival_order_independent() {
    fn run(config_a_first: bool) -> (bool, usize, [u8; 2]) {
        let mut bc = new_unconfigured_test_chain();
        let genesis = node_transfer_block(0, 0, 0, 0);
        let cfg_a = chain_config_anchor_block(1, genesis.view().hash());
        let cfg_b = chain_config_block_from(1, genesis.view().hash(), &mut alt_config_builder());
        let side = linked_transfer_block(2, cfg_b.view().hash());
        let main_2 = chain_config_anchor_block(2, cfg_a.view().hash());
        let main_3 = chain_config_anchor_block(3, main_2.view().hash());
        // Only the order of the two *config* blocks differs; the main branch
        // is the FR2 winner either way (tip sequence 3 against 2).
        let order: [&Block; 6] = if config_a_first {
            [&cfg_a, &cfg_b, &side, &main_2, &main_3, &genesis]
        } else {
            [&cfg_b, &side, &cfg_a, &main_2, &main_3, &genesis]
        };
        for block in order {
            bc.receive_block(block.view(), 0);
        }
        // The locked content as a fingerprint: its first two bytes are the
        // `config_value_count`, which is 4 for the base override set config A
        // carries (window, horizon, node cap and scheme) and 5 for config B's.
        let locked = bc
            .chain_config
            .durable_content()
            .map(|content| [content[0], content[1]])
            .unwrap_or([0xFF, 0xFF]);
        (bc.is_ready(), bc.blocks.len(), locked)
    }

    let a_first = run(true);
    assert_eq!(
        a_first,
        run(false),
        "both arrival orders converge on the same lock and the same tree"
    );
    assert_eq!(
        a_first,
        (true, 4, [4, 0]),
        "and they converge on config A — the candidate's own — with the side branch gone"
    );
}

/// FR3 candidate chain-config preload — the ordering that keeps a stale
/// tentative from costing a valid block.
///
/// PRD FR3 requires the candidate's *own* configuration content to be the
/// basis of every chain-config-derived check in the forward traversal. This
/// is the scenario where that ordering is load-bearing rather than
/// decorative, and every step of it is reachable:
///
/// 1. A large balance block is admitted while the node holds no
///    configuration, so intake measures it against the framing ceiling.
/// 2. A stray, off-candidate chain-config block then loads a tentative that
///    declares a *small* `block_size_limit`.
/// 3. The candidate completes, and its own chain-config block declares the
///    default limit — under which the balance block is perfectly legal.
///
/// With the preload, the divergence is caught before a single candidate block
/// is validated: the node adopts the candidate's content and re-runs, and the
/// balance block is measured against the limit its own chain set. Without it,
/// the forward walk reaches the balance block first and deletes it as
/// `BlockTooLarge` under a limit no block on that chain was ever subject to.
#[test]
fn fr3_preload_prevents_a_stale_tentative_from_condemning_a_valid_block() {
    let mut bc = new_unconfigured_w6_chain();
    // (1) A balance block bigger than the small limit the stray will declare,
    // admitted while the node is unconfigured.
    // `max_node_id = 9` so the linked transfers' pre-window actors (nodes 7
    // and 9) are inside the derived node-id range; three entries so the block
    // comfortably exceeds the stray's declared limit.
    let below = w6_horizon_block();
    for block in &w6_below() {
        let (outcome, _) = bc.receive_block(block.view(), 0);
        assert_eq!(outcome, ReceiveBlockOutcome::AcceptedSilently);
    }
    let big = balance_block(
        100,
        below.view().hash(),
        &[(1, 500, 0, 0x31), (2, 300, 0, 0x32), (3, 100, 0, 0x33)],
        9,
    );
    assert!(
        big.len() > SMALL_BLOCK_SIZE_LIMIT as usize,
        "the fixture is only meaningful if the block exceeds the stray's limit"
    );
    let b101 = linked_transfer_block(101, big.view().hash());
    let b102 = linked_transfer_block(102, b101.view().hash());
    let b103 = linked_transfer_block(103, b102.view().hash());
    let b104 = linked_transfer_block(104, b103.view().hash());
    for block in [&big, &b101, &b102, &b103, &b104] {
        let (outcome, _) = bc.receive_block(block.view(), 0);
        assert_eq!(
            outcome,
            ReceiveBlockOutcome::AcceptedSilently,
            "admitted while unconfigured, against the framing ceiling"
        );
    }

    // (2) The stray loads a tentative declaring the small limit. Off-candidate
    // and alone, so it is never itself an FR2 candidate.
    let stray = chain_config_block_from(500, [0xEE; 32], &mut small_limit_config_builder(W6));
    bc.receive_block(stray.view(), 0);
    assert!(
        bc.chain_config.tentative_content().is_some(),
        "the stray supplied the tentative configuration"
    );

    // (3) The candidate's own chain-config block completes the segment at
    // W + H = 9 and triggers FR2.
    let cfg = w6_config_anchor_block(105, b104.view().hash());
    let (outcome, _) = bc.receive_block(cfg.view(), 0);

    assert_eq!(outcome, ReceiveBlockOutcome::AcceptedSilently);
    assert!(
        bc.blocks.find(100, &big.view().hash()).is_some(),
        "the balance block was never measured against a limit its chain did not set"
    );
    assert!(bc.is_ready(), "the adopt-retry validated the candidate");
    assert_eq!(
        bc.chain_config.durable_content(),
        Some(content_of(&cfg)),
        "the chain locked on its own configuration, not the stray's"
    );
    assert!(
        bc.blocks.find(500, &stray.view().hash()).is_none(),
        "the superseded tentative's block is gone"
    );
}

// --- Code-review regressions (2026-09-20) -------------------------------

/// The acquisition loop must not retry a pass once the recovery has taken the
/// configuration with it.
///
/// `receive_block` evaluates its "a configuration is loaded" gate once, on
/// entry. The AC8 step-3b unload can retract the configuration *inside* the
/// loop — whenever the FR5 delete-set happens to contain the block that
/// supplied the tentative — and the `Invalid` retry token is still armed at
/// that point. The retry then runs a whole pass with no configuration at all,
/// which Story 5.8's FR2 gate exists precisely to prevent.
///
/// What that costs depends on the shape. In this one the unconfigured pass
/// reaches the Ready path over a candidate carrying no chain-config block,
/// tripping the AC3 assertion in debug and silently abandoning the transition
/// in release. In a shape where the pass instead refuses at the first FR37
/// vote effect, the refusal is `Vote(NotParameterized)` — which carries no
/// `block_idx`, so the FR5 fallback deletes the **candidate head**: a valid
/// block destroyed for the node's own missing configuration. The guard is
/// against re-entering at all, so it covers both.
///
/// The candidate is `[#0 genesis, #1 invalid, #2 chain-config]`, so the
/// offender's subtree contains the config block and the unload fires.
#[test]
fn fr5_retry_stops_when_recovery_unloads_the_configuration() {
    let mut bc = new_unconfigured_test_chain();
    let genesis = node_transfer_block(0, 0, 0, 0);
    // Out-of-sequence registration (new_node_id 5, expected 1) — invalid.
    let bad = registration_block(1, genesis.view().hash(), 1, 5, 0x45);
    let cfg = chain_config_anchor_block(2, bad.view().hash());
    for block in [&cfg, &bad] {
        bc.receive_block(block.view(), 0);
    }
    assert!(
        bc.chain_config.active_configuration().is_some(),
        "the config block supplied a tentative configuration"
    );

    let (outcome, _) = bc.receive_block(genesis.view(), 0);

    assert_eq!(outcome, ReceiveBlockOutcome::AcceptedSilently);
    // The offender and the config block above it are gone, and the unload
    // fired — but the genesis, which is not evidence of anything, survives.
    assert!(
        bc.chain_config.active_configuration().is_none(),
        "the recovery unloaded the tentative with the block that carried it"
    );
    assert!(
        bc.blocks.find(0, &genesis.view().hash()).is_some(),
        "the genesis must not be deleted by a retry the node can no longer run"
    );
    assert_eq!(bc.blocks.len(), 1, "exactly the genesis remains");
    assert!(bc.current_phase() == LifecyclePhase::Collecting);
}

/// PRD FR9: a merely-tentative chain-config must not reject an arriving block.
///
/// The block-size limit is a chain-config-derived value, and FR9 says such
/// values "produce Invalid classification (and downstream deletion) only after
/// the chain-configuration is durably locked". A stray config block declaring
/// a tight limit therefore must not cost a joining node the legitimate blocks
/// of the chain it is actually trying to join — otherwise which blocks a node
/// retains depends on the order its peers happened to gossip them (AC9).
#[test]
fn fr9_tentative_block_size_limit_does_not_reject_at_intake() {
    let mut bc = new_unconfigured_test_chain();
    let stray = chain_config_block_from(500, [0xEE; 32], &mut small_limit_config_builder(TEST_W));
    bc.receive_block(stray.view(), 0);
    assert!(
        bc.chain_config.tentative_content().is_some(),
        "the stray declares the tight limit, tentatively"
    );

    let big = balance_block(
        100,
        [0xAB; 32],
        &[(1, 500, 0, 0x31), (2, 300, 0, 0x32), (3, 100, 0, 0x33)],
        9,
    );
    assert!(big.len() > SMALL_BLOCK_SIZE_LIMIT as usize);

    let (outcome, _) = bc.receive_block(big.view(), 0);

    assert_eq!(
        outcome,
        ReceiveBlockOutcome::AcceptedSilently,
        "a tentative-only size failure must not reject the block (FR9)"
    );
    assert!(
        bc.blocks.find(100, &big.view().hash()).is_some(),
        "and it must be retained in durable storage"
    );
}

/// PRD FR9's other half: the deferred enforcement is re-run at the durable
/// lock, which is one of the two moments FR9 names.
///
/// A candidate that declares a limit its own blocks exceed is not a chain this
/// node may adopt — but the verdict is reached at the commitment, not while
/// the configuration is still tentative, and it arrives as an ordinary FR5
/// rollback with nothing promoted and nothing locked.
#[test]
fn fr9_size_limit_is_reevaluated_at_the_durable_lock() {
    let mut bc = new_unconfigured_w6_chain();
    // A nine-block (`W + H`) window-anchored candidate whose own
    // chain-config declares a limit the balance block near its base exceeds.
    let below = w6_horizon_block();
    for block in &w6_below() {
        let (outcome, _) = bc.receive_block(block.view(), 0);
        assert_eq!(outcome, ReceiveBlockOutcome::AcceptedSilently);
    }
    let big = balance_block(
        100,
        below.view().hash(),
        &[(1, 500, 0, 0x31), (2, 300, 0, 0x32), (3, 100, 0, 0x33)],
        9,
    );
    assert!(big.len() > SMALL_BLOCK_SIZE_LIMIT as usize);
    let b101 = linked_transfer_block(101, big.view().hash());
    let b102 = linked_transfer_block(102, b101.view().hash());
    let b103 = linked_transfer_block(103, b102.view().hash());
    let b104 = linked_transfer_block(104, b103.view().hash());
    let cfg = chain_config_block_from(105, b104.view().hash(), &mut small_limit_config_builder(W6));
    for block in [&big, &b101, &b102, &b103, &b104, &cfg] {
        let (outcome, _) = bc.receive_block(block.view(), 0);
        assert_eq!(
            outcome,
            ReceiveBlockOutcome::AcceptedSilently,
            "every block is admitted — the limit is not enforceable yet (FR9)"
        );
    }

    assert!(
        !bc.is_ready(),
        "the re-evaluation at the lock refuses the candidate"
    );
    assert!(
        !bc.chain_config.is_durable_locked(),
        "and nothing was locked: the verdict precedes the commitment"
    );
    assert!(
        bc.blocks.find(100, &big.view().hash()).is_none(),
        "the offending block is the one FR5 deletes"
    );
    assert!(
        bc.current_phase() == LifecyclePhase::Collecting,
        "the FR5 recovery reverted the phase"
    );
}

/// PRD FR8: a chain-config block whose content violates a structural bound
/// "shall not enter durable storage" — unconditionally, not only when it is
/// the block that happens to load.
///
/// The FR17 gate cannot cover this: it stands down while the configuration is
/// merely tentative (AC7), which is exactly the window in which a second,
/// structurally illegal config block can arrive.
#[test]
fn fr8_bound_violating_content_is_refused_even_when_not_loading() {
    let mut bc = new_unconfigured_test_chain();
    let first = chain_config_anchor_block(100, [0xAB; 32]);
    bc.receive_block(first.view(), 0);
    assert!(
        bc.chain_config.tentative_content().is_some(),
        "a configuration is already held, so the next one cannot load"
    );

    let illegal = chain_config_block_from(
        101,
        first.view().hash(),
        &mut bound_violating_config_builder(),
    );
    let (outcome, _) = bc.receive_block(illegal.view(), 0);

    assert_eq!(
        outcome,
        ReceiveBlockOutcome::Rejected(RejectReason::InvalidEvidence),
        "a bound violation is exact evidence whether or not the block loads"
    );
    assert!(
        bc.blocks.find(101, &illegal.view().hash()).is_none(),
        "and it does not enter durable storage"
    );
    assert_eq!(
        bc.chain_config.tentative_content(),
        Some(content_of(&first)),
        "the held configuration is untouched by the refusal"
    );
}

// ===================================================================
// FR59 — restart equivalence (Story 5.10)
//
// `MemoryBackend` lives in RAM, so a "power cycle" is modelled the only
// way it can be: the durable backend is carried into a freshly
// constructed node while every piece of derived state — tree, heads,
// projection, configuration — starts empty, exactly as it would after a
// reboot.
// ===================================================================

/// Carries `bc`'s durable storage into a brand-new node. The new node gets a
/// fresh, *unconfigured* configuration module and an empty tree: everything
/// it ends up holding, it recovered from the durable footprint.
fn restart(bc: TestChain) -> TestChain {
    let storage = bc.storage;
    let crypto = Crypto::new([1u8; PRIVATE_KEY_SIZE])
        .ok()
        .expect("test private key should be accepted by the backend");
    let chain_config = empty_chain_config(TestChain::BUILD_LIMITS);
    new_chain(crypto, storage, chain_config, 5, 0)
}

/// Drives an unconfigured node to `Ready` the way the network does: a
/// genesis plus chain-config blocks, admitted while orphaned so the genesis
/// connects them all at once. Reaching `Ready` runs the real FR8 durable
/// commit, which is what puts the configuration into the control plane —
/// the durable evidence the restart later reads back.
fn node_ready_from_the_mesh() -> (TestChain, Block, Block) {
    let mut bc = new_unconfigured_test_chain();
    let genesis = node_transfer_block(0, 0, 0, 0);
    let cfg = chain_config_anchor_block(1, genesis.view().hash());
    for block in [&cfg, &genesis] {
        let (outcome, _) = bc.receive_block(block.view(), 0);
        assert_eq!(outcome, ReceiveBlockOutcome::AcceptedSilently);
    }
    assert!(bc.is_ready(), "precondition: the node reached Ready");
    assert!(
        bc.chain_config.is_durable_locked(),
        "precondition: reaching Ready performed the FR8 durable commit"
    );
    (bc, genesis, cfg)
}

/// AC1/AC3 precondition, proven end to end through the real storage seam:
/// a block shorter than a slot comes back padded, and only the structural
/// length recovery still finds the block inside it. Without this, every
/// hash the rebuild computes would be wrong.
#[test]
fn fr59_a_short_block_survives_the_storage_round_trip() {
    let (_, mut storage, _) = test_backends();
    let block = node_transfer_block(0, 7, 0, 7);
    let exact = block.serialized_bytes();
    assert!(
        exact.len() < MAX_BLOCK_SIZE,
        "precondition: shorter than a slot"
    );
    storage.save_block(0, &block).ok().expect("save");

    let read_back = storage.read_block(0).ok().expect("read");
    assert_eq!(
        read_back.len(),
        MAX_BLOCK_SIZE,
        "the backend returns the whole padded slot - this is the problem FR59 faces"
    );

    let view = TestChain::exact_view(read_back.serialized_bytes())
        .expect("the exact length is recoverable");
    assert_eq!(
        view.serialized_bytes(),
        exact,
        "byte-identical to what was saved"
    );
    assert_eq!(view.hash(), block.view().hash(), "and so is the hash");
    assert_ne!(
        read_back.view().hash(),
        block.view().hash(),
        "while the padded read-back hashes to something else entirely"
    );
}

/// AC5/AC2 — the whole spine: rebuild from durable blocks, restore the FR8
/// lock from the control plane, re-run FR2/FR3/FR6 and land in `Ready`.
#[test]
fn fr59_restart_rebuilds_and_reaches_ready() {
    let (bc, genesis, cfg) = node_ready_from_the_mesh();
    let active_before = bc.current_active_head();

    let mut restarted = restart(bc);
    assert!(
        restarted.chain_config.active_configuration().is_none(),
        "precondition: the restarted node starts with nothing"
    );

    let (outcome, _) = restarted.initialize_from_storage(500);

    assert_eq!(outcome, InitOutcome::ResumedReady);
    assert!(
        restarted.is_ready(),
        "FR4 reached through the ordinary spine"
    );
    assert!(
        restarted.chain_config.is_durable_locked(),
        "AC2 - the FR8 lock is restored from the control plane"
    );
    assert_eq!(
        restarted.current_active_head(),
        active_before,
        "the same active chain is re-derived"
    );
    assert!(
        restarted.blocks.find(0, &genesis.view().hash()).is_some()
            && restarted.blocks.find(1, &cfg.view().hash()).is_some(),
        "both durable blocks are back in the tree, indexed by (sequence, hash)"
    );
}

/// AC5 — no qualifying candidate means the node simply stays `Collecting`
/// and keeps its blocks, which FR59 step (4) states explicitly.
#[test]
fn fr59_restart_stays_collecting_without_a_qualifying_candidate() {
    let mut bc = new_unconfigured_test_chain();
    // A lone orphan far above the window: admitted, but neither
    // genesis-anchored nor long enough to satisfy FR2.
    let cfg = chain_config_anchor_block(100, [0xAB; 32]);
    let (outcome, _) = bc.receive_block(cfg.view(), 0);
    assert_eq!(outcome, ReceiveBlockOutcome::AcceptedSilently);

    let mut restarted = restart(bc);
    let (outcome, _) = restarted.initialize_from_storage(500);

    assert_eq!(outcome, InitOutcome::ResumedCollecting);
    assert_eq!(restarted.current_phase(), LifecyclePhase::Collecting);
    assert_eq!(restarted.blocks.len(), 1, "the retained block survived");
}

/// AC8 — the equivalence the story exists to deliver: a restarted node and a
/// fresh node fed the same blocks agree on the active chain, the phase, and
/// the locked configuration.
#[test]
fn fr59_restart_is_equivalent_to_a_fresh_node_fed_the_same_blocks() {
    let (bc, genesis, cfg) = node_ready_from_the_mesh();
    let mut restarted = restart(bc);
    let (outcome, _) = restarted.initialize_from_storage(500);
    assert_eq!(outcome, InitOutcome::ResumedReady);

    // The comparison node never restarts: it receives the same two blocks.
    let mut fresh = new_unconfigured_test_chain();
    for block in [&cfg, &genesis] {
        let (outcome, _) = fresh.receive_block(block.view(), 0);
        assert_eq!(outcome, ReceiveBlockOutcome::AcceptedSilently);
    }

    assert_eq!(restarted.is_ready(), fresh.is_ready());
    assert_eq!(restarted.current_active_head(), fresh.current_active_head());
    assert_eq!(restarted.blocks.len(), fresh.blocks.len());
    // AC8 names the projection and the chain_heads set explicitly, and the
    // review found that omitting them hid a real bug: every rebuilt Stored
    // head had lost its missing-parent hash, which a chain_heads comparison
    // would have caught immediately.
    assert_eq!(
        restarted.chain_heads.count(),
        fresh.chain_heads.count(),
        "AC8 - the same chain_heads set"
    );
    assert_eq!(
        restarted.node_info.max_known_node_id(),
        fresh.node_info.max_known_node_id(),
        "AC8 - the same derived projection"
    );
    assert_eq!(
        restarted.chain_config.durable_content(),
        fresh.chain_config.durable_content(),
        "both committed the same configuration"
    );
    for (sequence, hash) in [(0u32, genesis.view().hash()), (1u32, cfg.view().hash())] {
        assert_eq!(
            restarted.blocks.find(sequence, &hash).is_some(),
            fresh.blocks.find(sequence, &hash).is_some(),
            "the two trees hold the same blocks"
        );
    }
}

/// AC3 — durable slots are not necessarily contiguous, so the scan must run
/// the whole capacity rather than stopping at the first empty slot. A node
/// that stopped early would silently lose its chain.
#[test]
fn fr59_restart_scan_does_not_stop_at_the_first_empty_slot() {
    let (_, mut storage, _) = test_backends();
    let genesis = node_transfer_block(0, 0, 0, 0);
    let cfg = chain_config_anchor_block(1, genesis.view().hash());
    // Deliberately leaving slot 0 empty and scattering the blocks.
    storage.save_block(1, &genesis).ok().expect("save");
    storage.save_block(3, &cfg).ok().expect("save");

    let crypto = Crypto::new([1u8; PRIVATE_KEY_SIZE])
        .ok()
        .expect("test private key");
    let mut bc = new_chain(
        crypto,
        storage,
        empty_chain_config(TestChain::BUILD_LIMITS),
        5,
        0,
    );
    let (_, _) = bc.initialize_from_storage(500);

    assert_eq!(bc.blocks.len(), 2, "both scattered blocks were found");
    assert!(bc.blocks.get(1).is_some() && bc.blocks.get(3).is_some());
    assert!(
        bc.blocks.get(0).is_none() && bc.blocks.get(2).is_none(),
        "blocks land at their own durable index, never compacted"
    );
}

/// AC3 — durable order is not topological. A parent written to a *higher*
/// slot than its child must still be linked, which is why linkage is a
/// second pass over the completed table rather than done inline.
#[test]
fn fr59_restart_links_parents_stored_after_their_children() {
    let (_, mut storage, _) = test_backends();
    let genesis = node_transfer_block(0, 0, 0, 0);
    let child = chain_config_anchor_block(1, genesis.view().hash());
    // Child first, parent second — the order a one-pass rebuild would break on.
    storage.save_block(0, &child).ok().expect("save");
    storage.save_block(1, &genesis).ok().expect("save");

    let crypto = Crypto::new([1u8; PRIVATE_KEY_SIZE])
        .ok()
        .expect("test private key");
    let mut bc = new_chain(
        crypto,
        storage,
        empty_chain_config(TestChain::BUILD_LIMITS),
        5,
        0,
    );
    let (_, _) = bc.initialize_from_storage(500);

    let child_idx = bc
        .blocks
        .find(1, &child.view().hash())
        .expect("the child is in the tree");
    let parent_idx = bc
        .blocks
        .find(0, &genesis.view().hash())
        .expect("the parent is in the tree");
    assert_eq!(
        bc.blocks.get(child_idx).map(|entry| entry.parent_ref()),
        Some(parent_idx),
        "the child resolved to its parent despite the inverted slot order"
    );
}

/// AC7 — a retained side branch survives the restart with its fork point
/// intact; FR20 forbids silently collapsing it.
#[test]
fn fr59_restart_preserves_side_branches() {
    let mut bc = new_unconfigured_test_chain();
    // A fork that survives to be tested: the branch root is itself an orphan
    // far above the window, so no FR2 candidate ever qualifies and neither
    // the FR5 recovery nor the FR8 lock-time cleanup can prune a branch
    // before the restart. The two tips differ in payload type, which is what
    // makes them distinct blocks at the same sequence rather than duplicates.
    let root = linked_transfer_block(100, [0xAB; 32]);
    let tip_a = linked_transfer_block(101, root.view().hash());
    let tip_b = chain_config_anchor_block(101, root.view().hash());
    for block in [&root, &tip_a, &tip_b] {
        let (outcome, _) = bc.receive_block(block.view(), 0);
        assert_eq!(outcome, ReceiveBlockOutcome::AcceptedSilently);
    }
    assert_eq!(
        bc.chain_heads.count(),
        2,
        "precondition: the tree really forked, and both tips are tracked"
    );
    assert!(!bc.is_ready(), "precondition: no candidate qualified");

    let mut restarted = restart(bc);
    let (outcome, _) = restarted.initialize_from_storage(500);

    assert_eq!(outcome, InitOutcome::ResumedCollecting);
    assert_eq!(restarted.blocks.len(), 3, "no branch was collapsed (FR20)");
    assert_eq!(
        restarted.chain_heads.count(),
        2,
        "AC7 - both branches are tracked again after the rebuild"
    );

    let root_idx = restarted
        .blocks
        .find(100, &root.view().hash())
        .expect("the fork point is retained");
    for tip in [&tip_a, &tip_b] {
        let tip_idx = restarted
            .blocks
            .find(101, &tip.view().hash())
            .expect("both tips are retained");
        assert_eq!(
            restarted
                .blocks
                .get(tip_idx)
                .map(|entry| entry.parent_ref()),
            Some(root_idx),
            "and both still hang off the same fork point"
        );
    }
}

/// AC9 (ratified 2026-09-20) — `StorageTrait` has no delete, so a block
/// removed before the shutdown is still readable afterwards and comes back.
/// The rebuilt tree is therefore **not** the pre-shutdown tree; what is
/// guaranteed is that the node still converges, because the deletion drivers
/// are deterministic and re-fire.
#[test]
fn fr59_restart_resurrects_a_deleted_block_and_still_converges() {
    let (mut bc, genesis, _cfg) = node_ready_from_the_mesh();

    // The post-deletion durable state, reproduced exactly: bytes present in
    // a slot, no entry in the tree. That is all `BlockTable::delete` leaves
    // behind, because `StorageTrait` has no delete and the slot is only
    // reclaimed when a later `save_block` overwrites it.
    let orphaned = linked_transfer_block(5, [0x77; 32]);
    bc.storage.save_block(6, &orphaned).ok().expect("save");
    assert!(
        bc.blocks.find(5, &orphaned.view().hash()).is_none(),
        "precondition: the block is durable but not in the pre-restart tree"
    );
    let head_before = bc.current_active_head();

    let mut restarted = restart(bc);
    let (outcome, _) = restarted.initialize_from_storage(500);

    assert!(
        restarted.blocks.find(5, &orphaned.view().hash()).is_some(),
        "AC9 - a slot that was never overwritten reads back and is admitted again"
    );
    assert_eq!(
        outcome,
        InitOutcome::ResumedReady,
        "and the node still converges on its chain"
    );
    assert_eq!(
        restarted.current_active_head(),
        head_before,
        "the resurrected block did not disturb the active chain"
    );
    assert!(
        restarted.blocks.find(0, &genesis.view().hash()).is_some(),
        "the genesis is still there"
    );
}

/// Writes an approval payload's `late_count` (the field before the late
/// entries, at `fixed − 2` of the payload).
fn payload_late_count(raw: &mut [u8], fixed: usize, late_count: u16) {
    raw[HEADER_SIZE + fixed - 2..HEADER_SIZE + fixed].copy_from_slice(&late_count.to_le_bytes());
}

/// AC3/AC11 — a slot whose payload does not frame coherently is skipped, not
/// fatal: one bad slot must not cost the node its chain. The fixture is an
/// approval block (Story 6.6 AC2) whose `late_count` frames it far beyond
/// the slot, so `content_length` refuses rather than guesses.
#[test]
fn fr59_restart_skips_a_slot_whose_length_cannot_be_recovered() {
    let (_, mut storage, _) = test_backends();
    let genesis = node_transfer_block(0, 0, 0, 0);
    storage.save_block(0, &genesis).ok().expect("save");

    const FIXED: usize = moonblokz_chain_types::approval_fixed_size(1, 1);
    let fixed = FIXED;
    let mut raw = [0u8; HEADER_SIZE + FIXED];
    raw[0] = 1; // version
    raw[13] = moonblokz_chain_types::PAYLOAD_TYPE_APPROVAL;
    let payload = &mut raw[HEADER_SIZE..];
    payload[12] = 1; // m
    payload[13] = 0b1; // one signer
    #[cfg(feature = "schnorr")]
    payload[14..16].copy_from_slice(&1u16.to_be_bytes()); // Schnorr's signer count
    let framed = Block::from_bytes(&raw).ok().expect("parses");
    assert_eq!(
        framed.content_length(),
        Some(framed.len()),
        "premise: with no late entry the fixture frames"
    );
    payload_late_count(&mut raw, fixed, u16::MAX);
    let undecodable = Block::from_bytes(&raw)
        .ok()
        .expect("structurally parseable, just not measurable");
    assert_eq!(
        undecodable.content_length(),
        None,
        "the late count overruns it"
    );
    storage.save_block(1, &undecodable).ok().expect("save");

    let crypto = Crypto::new([1u8; PRIVATE_KEY_SIZE])
        .ok()
        .expect("test private key");
    let mut bc = new_chain(
        crypto,
        storage,
        empty_chain_config(TestChain::BUILD_LIMITS),
        5,
        0,
    );
    let (_, _) = bc.initialize_from_storage(500);

    assert_eq!(bc.blocks.len(), 1, "the unmeasurable slot is skipped");
    assert!(
        bc.blocks.find(0, &genesis.view().hash()).is_some(),
        "and the good block is still recovered"
    );
}

/// AC11 — a populated store whose control plane cannot be read is refused,
/// not panicked on and not silently rebuilt: the node would be reconstructing
/// a chain without knowing the configuration it was accepted under.
#[test]
fn fr59_restart_rejects_a_populated_store_with_an_unreadable_control_plane() {
    // Never `init`ed, so `load_control_data` fails - but `save_block` still
    // writes into the slot region, so blocks are readable.
    let mut storage = MemoryBackend::<{ 8 * MAX_BLOCK_SIZE + 8000 }>::new();
    let genesis = node_transfer_block(0, 0, 0, 0);
    storage.save_block(0, &genesis).ok().expect("save");

    let crypto = Crypto::new([1u8; PRIVATE_KEY_SIZE])
        .ok()
        .expect("test private key");
    let mut bc = new_chain(
        crypto,
        storage,
        empty_chain_config(TestChain::BUILD_LIMITS),
        5,
        0,
    );

    let (outcome, next) = bc.initialize_from_storage(500);

    assert_eq!(
        outcome,
        InitOutcome::Rejected(RestartRejectReason::ControlPlaneUnreadable)
    );
    assert!(matches!(next, NextCall::Idle));
    assert_eq!(bc.blocks.len(), 0, "nothing was rebuilt");
}

/// The same unreadable control plane with an *empty* store is not an error:
/// that is exactly what a fresh node looks like, and Story 5.1's join path
/// must keep working.
#[test]
fn fr59_an_empty_store_is_a_fresh_join_even_without_a_control_plane() {
    let storage = MemoryBackend::<{ 8 * MAX_BLOCK_SIZE + 8000 }>::new();
    let crypto = Crypto::new([1u8; PRIVATE_KEY_SIZE])
        .ok()
        .expect("test private key");
    let mut bc = new_chain(
        crypto,
        storage,
        empty_chain_config(TestChain::BUILD_LIMITS),
        5,
        0,
    );

    let (outcome, next) = bc.initialize_from_storage(500);

    assert_eq!(outcome, InitOutcome::StartedCollecting);
    assert!(matches!(next, NextCall::Idle));
    assert_eq!(bc.current_phase(), LifecyclePhase::Collecting);
}

/// FR8's tentative phase is not durable, so a node that shut down before the
/// lock comes back holding nothing — yet its retained tree still carries the
/// config block it had adopted. Re-adopting is what keeps the restart
/// equivalent to a fresh node fed the same blocks; without it the node holds
/// no configuration and cannot run the FR3 derivation at all.
#[test]
fn fr59_restart_reestablishes_a_tentative_when_nothing_was_locked() {
    let mut bc = new_unconfigured_test_chain();
    let cfg = chain_config_anchor_block(100, [0xAB; 32]);
    let (outcome, _) = bc.receive_block(cfg.view(), 0);
    assert_eq!(outcome, ReceiveBlockOutcome::AcceptedSilently);
    assert!(
        !bc.chain_config.is_durable_locked(),
        "precondition: the configuration is only tentative"
    );
    let mut restarted = restart(bc);
    let (_, _) = restarted.initialize_from_storage(500);

    assert!(
        !restarted.chain_config.is_durable_locked(),
        "a tentative is re-established as a tentative, never promoted by a restart"
    );
    assert_eq!(
        restarted.chain_config.tentative_content(),
        Some(content_of(&cfg)),
        "the same configuration content is held again, from the retained block"
    );
}

/// AC10 — the rebuild is a pure function of the durable footprint: the same
/// store restarted twice yields the same outcome and the same tree.
#[test]
fn fr59_restart_is_deterministic() {
    let (bc, _, _) = node_ready_from_the_mesh();

    let mut first = restart(bc);
    let (first_outcome, _) = first.initialize_from_storage(500);
    let first_len = first.blocks.len();
    let first_head = first.current_active_head();
    let first_heads = first.chain_heads.count();
    let first_phase = first.current_phase();
    let mut first_tree = [None; 16];
    for (idx, cell) in first_tree.iter_mut().enumerate() {
        *cell = first
            .blocks
            .get(idx as u32)
            .map(|entry| (entry.sequence(), *entry.hash(), entry.parent_ref()));
    }

    // Restart the *same* durable store a second time, from scratch again.
    let mut second = restart(first);
    // A different `now`: it must not influence the reconstruction.
    let (second_outcome, _) = second.initialize_from_storage(9_999);

    assert_eq!(first_outcome, second_outcome);
    assert_eq!(first_len, second.blocks.len());
    assert_eq!(first_head, second.current_active_head());
    assert_eq!(
        first_heads,
        second.chain_heads.count(),
        "same chain_heads set"
    );
    assert_eq!(first_phase, second.current_phase(), "same phase trace");
    // AC10 asks for the same *tree*, not merely the same block count.
    for idx in 0..16u32 {
        assert_eq!(
            first_tree[idx as usize],
            second.blocks.get(idx).map(|entry| (
                entry.sequence(),
                *entry.hash(),
                entry.parent_ref()
            )),
            "slot {idx} must rebuild identically"
        );
    }
}

// ---- Review regressions (2026-09-21) --------------------------------

/// **Review finding, confirmed by execution.** Every rebuilt Stored head used
/// to come back with an all-zero `missing_parent_hash`, so FR19 emitted
/// parent-recovery requests for a hash that can never resolve — for the
/// lifetime of the node. Asserted through the observable outbound request
/// rather than the cache field, which is what a peer would actually receive.
#[test]
fn fr59_restart_preserves_the_missing_parent_hash_of_a_stored_head() {
    let mut bc = new_unconfigured_test_chain();
    let orphan = chain_config_anchor_block(100, [0xAB; 32]);
    let (outcome, _) = bc.receive_block(orphan.view(), 0);
    assert_eq!(outcome, ReceiveBlockOutcome::AcceptedSilently);

    let mut restarted = restart(bc);
    let (_, _) = restarted.initialize_from_storage(500);

    let (tick, _) = restarted.on_tick(1_000_000);
    match tick {
        TickOutcome::SendParentRecoveryRequest(request) => {
            assert_eq!(
                request.missing_parent_hash(),
                &[0xAB; 32],
                "the restarted node must request the parent the branch actually names"
            );
        }
        _ => panic!("a Stored head should schedule FR19 parent recovery after a restart"),
    }
}

/// **Review finding, confirmed by execution.** The single-genesis rule lives
/// in `tier1_admit`, which the rebuild bypasses, so two distinct sequence-0
/// blocks both entered the tree — a state live intake cannot produce.
#[test]
fn fr59_restart_admits_at_most_one_genesis() {
    let (_, mut storage, _) = test_backends();
    let genesis_a = node_transfer_block(0, 0, 0, 0);
    let genesis_b = node_transfer_block(0, 7, 0, 7);
    assert_ne!(
        genesis_a.view().hash(),
        genesis_b.view().hash(),
        "precondition: two distinct sequence-0 blocks"
    );
    storage.save_block(0, &genesis_a).ok().expect("save");
    storage.save_block(1, &genesis_b).ok().expect("save");

    let crypto = Crypto::new([1u8; PRIVATE_KEY_SIZE])
        .ok()
        .expect("test private key");
    let mut bc = new_chain(
        crypto,
        storage,
        empty_chain_config(TestChain::BUILD_LIMITS),
        5,
        0,
    );
    let (_, _) = bc.initialize_from_storage(500);

    let genesis_count = (0..16u32)
        .filter(|idx| {
            bc.blocks
                .get(*idx)
                .is_some_and(|entry| entry.sequence() == 0)
        })
        .count();
    assert_eq!(
        genesis_count, 1,
        "the rebuild must honour the single-genesis rule that tier1_admit enforces"
    );
    assert!(
        bc.blocks.find(0, &genesis_a.view().hash()).is_some(),
        "first by index wins, matching the live first-come rule"
    );
}

/// `initialize_from_storage` is a one-shot boot step. A second call used to
/// be guarded only by `debug_assert!`s, which compile out in exactly the
/// release builds that run on the device.
#[test]
fn fr59_a_second_initialize_from_storage_is_refused() {
    let (bc, _, _) = node_ready_from_the_mesh();
    let mut restarted = restart(bc);
    let (first, _) = restarted.initialize_from_storage(500);
    assert_eq!(first, InitOutcome::ResumedReady);
    let blocks_after_first = restarted.blocks.len();

    let (second, _) = restarted.initialize_from_storage(600);

    assert_eq!(
        second,
        InitOutcome::Rejected(RestartRejectReason::AlreadyInitialized)
    );
    assert_eq!(
        restarted.blocks.len(),
        blocks_after_first,
        "the refused call must not have touched the tree"
    );
}

/// AC11's second trigger: a store whose slots are all unreadable is damaged,
/// not empty, and must not be reported as a fresh join — that would discard
/// the node's whole chain silently.
#[test]
fn fr59_a_store_whose_every_slot_is_corrupt_is_refused() {
    let crypto = Crypto::new([1u8; PRIVATE_KEY_SIZE])
        .ok()
        .expect("test private key");
    let chain_config = empty_chain_config(TestChain::BUILD_LIMITS);
    let node_zero = *crypto.public_key().serialize();
    let mut slot =
        core::mem::MaybeUninit::<Blockchain<_, _, _, 16, 16, TEST_MAX_BLOCKS, 4, 16>>::uninit();
    let bc = Blockchain::<_, _, _, 16, 16, TEST_MAX_BLOCKS, 4, 16>::init(
        &mut slot,
        crypto,
        CorruptSlotsStorage,
        chain_config,
        5,
        node_zero,
        0,
    );

    let (outcome, _) = bc.initialize_from_storage(500);

    assert_eq!(
        outcome,
        InitOutcome::Rejected(RestartRejectReason::NoUsableTree)
    );
    assert_eq!(bc.blocks.len(), 0);
}

/// The irrevocable FR8/FR54 lock must not be taken on the control plane's
/// word alone: the block it carries is verified through the same FR7 gate
/// the revocable tentative path uses (review decision, 2026-09-21).
#[test]
fn fr59_a_control_plane_config_failing_fr7_is_refused() {
    let (_, mut storage, _) = test_backends();
    // A chain-config block whose content signature is not node #0's.
    let mut forged = chain_config_anchor_block(1, [0u8; 32]);
    let tampered = {
        let mut bytes = [0u8; MAX_BLOCK_SIZE];
        let exact = forged.serialized_bytes();
        bytes[..exact.len()].copy_from_slice(exact);
        // Flip a byte inside the content region, invalidating the signature
        // over it while leaving the envelope framing intact.
        bytes[HEADER_SIZE + 2] ^= 0xFF;
        Block::from_bytes(&bytes[..exact.len()])
            .ok()
            .expect("still structurally a block")
    };
    forged = tampered;
    storage
        .set_chain_configuration(&forged)
        .ok()
        .expect("control plane accepts it - storage does not verify signatures");
    let genesis = node_transfer_block(0, 0, 0, 0);
    storage.save_block(0, &genesis).ok().expect("save");

    let crypto = Crypto::new([1u8; PRIVATE_KEY_SIZE])
        .ok()
        .expect("test private key");
    let mut bc = new_chain(
        crypto,
        storage,
        empty_chain_config(TestChain::BUILD_LIMITS),
        5,
        0,
    );

    let (outcome, _) = bc.initialize_from_storage(500);

    assert_eq!(
        outcome,
        InitOutcome::Rejected(RestartRejectReason::ChainConfigUnusable)
    );
    assert!(
        !bc.chain_config.is_durable_locked(),
        "an unverifiable configuration must never become an irrevocable lock"
    );
}

/// AC9's convergence argument named the FR8 lock-time cleanups, but they sit
/// behind `if !is_durable_locked()` in the spine and so never ran on a
/// restart. An off-chain mismatching chain-config block survived forever.
#[test]
fn fr59_restart_cleans_up_an_off_chain_mismatching_config_block() {
    let (mut bc, _, _) = node_ready_from_the_mesh();
    // Validly signed by node #0, but carrying different content from the
    // configuration the chain locked. The live path refuses it outright.
    let mismatching = chain_config_block_from(100, [0xAB; 32], &mut alt_config_builder());
    let (live, _) = bc.receive_block(mismatching.view(), 0);
    assert_ne!(
        live,
        ReceiveBlockOutcome::AcceptedSilently,
        "precondition: the live path refuses a post-lock mismatching config"
    );
    // Plant it directly in a durable slot, as a pre-lock session would have.
    bc.storage.save_block(6, &mismatching).ok().expect("save");

    let mut restarted = restart(bc);
    let (outcome, _) = restarted.initialize_from_storage(500);

    assert_eq!(outcome, InitOutcome::ResumedReady);
    assert!(
        restarted
            .blocks
            .find(100, &mismatching.view().hash())
            .is_none(),
        "the restored lock must re-run its mismatch cleanup over the rebuilt tree"
    );
}

// ---- A refused restart must not be ignorable (2026-09-21) ------------

/// The refusal only protects the chain if the module stops accepting work.
/// Before this guard, a caller that ignored `Rejected(_)` kept feeding the
/// node, and because the rebuild left an empty tree over a populated store
/// the first admission took slot 0 and `save_block` overwrote a durable
/// block — the node silently destroying the chain it failed to load.
#[test]
fn a_refused_restart_stops_accepting_blocks_instead_of_overwriting_the_chain() {
    let (_, mut storage, _) = test_backends();
    // A control-plane configuration whose content signature no longer
    // verifies, so the restart refuses with `ChainConfigUnusable`.
    let cfg = chain_config_anchor_block(1, [0u8; 32]);
    let tampered = {
        let mut bytes = [0u8; MAX_BLOCK_SIZE];
        let exact = cfg.serialized_bytes();
        bytes[..exact.len()].copy_from_slice(exact);
        bytes[HEADER_SIZE + 2] ^= 0xFF;
        Block::from_bytes(&bytes[..exact.len()])
            .ok()
            .expect("still structurally a block")
    };
    storage
        .set_chain_configuration(&tampered)
        .ok()
        .expect("the control plane does not verify signatures");
    let genesis = node_transfer_block(0, 0, 0, 0);
    let durable_hash = genesis.view().hash();
    storage.save_block(0, &genesis).ok().expect("save");

    let crypto = Crypto::new([1u8; PRIVATE_KEY_SIZE])
        .ok()
        .expect("test private key");
    let mut bc = new_chain(
        crypto,
        storage,
        empty_chain_config(TestChain::BUILD_LIMITS),
        5,
        0,
    );
    let (outcome, _) = bc.initialize_from_storage(500);
    assert_eq!(
        outcome,
        InitOutcome::Rejected(RestartRejectReason::ChainConfigUnusable)
    );

    // The caller ignores the refusal and keeps feeding the node.
    let incoming = chain_config_anchor_block(100, [0xCD; 32]);
    let (admitted, next) = bc.receive_block(incoming.view(), 600);

    assert_eq!(
        admitted,
        ReceiveBlockOutcome::Rejected(RejectReason::Unstorable),
        "an operational refusal - the block may be valid, but this node cannot store anything"
    );
    assert!(matches!(next, NextCall::Idle));
    assert_eq!(bc.blocks.len(), 0, "and nothing entered the tree");

    let slot0 = bc
        .storage
        .read_block(0)
        .ok()
        .and_then(|block| TestChain::exact_view(block.serialized_bytes()).map(|v| v.hash()));
    assert_eq!(
        slot0,
        Some(durable_hash),
        "the durable block the restart could not load is still intact"
    );
}

/// The same guard for the other refusal that leaves an unrebuilt store.
#[test]
fn a_no_usable_tree_refusal_also_stops_accepting_blocks() {
    let crypto = Crypto::new([1u8; PRIVATE_KEY_SIZE])
        .ok()
        .expect("test private key");
    let node_zero = *crypto.public_key().serialize();
    let mut slot =
        core::mem::MaybeUninit::<Blockchain<_, _, _, 16, 16, TEST_MAX_BLOCKS, 4, 16>>::uninit();
    let bc = Blockchain::<_, _, _, 16, 16, TEST_MAX_BLOCKS, 4, 16>::init(
        &mut slot,
        crypto,
        CorruptSlotsStorage,
        empty_chain_config(TestChain::BUILD_LIMITS),
        5,
        node_zero,
        0,
    );
    let (outcome, _) = bc.initialize_from_storage(500);
    assert_eq!(
        outcome,
        InitOutcome::Rejected(RestartRejectReason::NoUsableTree)
    );

    let incoming = node_transfer_block(0, 0, 0, 0);
    let (admitted, _) = bc.receive_block(incoming.view(), 600);
    assert_eq!(
        admitted,
        ReceiveBlockOutcome::Rejected(RejectReason::Unstorable)
    );
}

/// `AlreadyInitialized` must **not** poison the node: it means the node is
/// already up and running, and the caller simply asked twice.
#[test]
fn a_duplicate_initialize_call_does_not_stop_a_healthy_node() {
    let (bc, _, _) = node_ready_from_the_mesh();
    let mut restarted = restart(bc);
    let (first, _) = restarted.initialize_from_storage(500);
    assert_eq!(first, InitOutcome::ResumedReady);

    let (second, _) = restarted.initialize_from_storage(600);
    assert_eq!(
        second,
        InitOutcome::Rejected(RestartRejectReason::AlreadyInitialized)
    );

    let incoming = linked_transfer_block(7, [0x99; 32]);
    let (admitted, _) = restarted.receive_block(incoming.view(), 700);
    assert_ne!(
        admitted,
        ReceiveBlockOutcome::Rejected(RejectReason::Unstorable),
        "a healthy node must keep working after a spurious second init call"
    );
}

// ===================================================================
// Story 9.1 — snake-chain window mechanics and the FR48 tail drop
// ===================================================================

use crate::snake_chain::{TailBinding, TailObligation, tail_drop_binding};

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
fn w6_below() -> [Block; 3] {
    let b97 = salted_linked_block(97, [0xAB; 32], 0);
    let b98 = salted_linked_block(98, b97.view().hash(), 0);
    let b99 = salted_linked_block(99, b98.view().hash(), 0);
    [b97, b98, b99]
}

/// The top block below the window, #99 (see [`w6_below`]).
fn w6_horizon_block() -> Block {
    let [_, _, b99] = w6_below();
    b99
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

/// A clean (Story 6.7 D8) block at `seq` on `prev`: one node transfer of
/// nothing, fee 0, by node #0 to itself, voting for its creator. Valid
/// wherever node #0 is seeded, so it extends a Ready W6 head at any
/// position, a clean slot included.
fn w6_clean_block(seq: u32, prev: [u8; 32]) -> Block {
    let signer = Crypto::new([1u8; PRIVATE_KEY_SIZE]).ok().expect("test key");
    let nt = NodeTransfer::new_signed(0, seq - 1, 0, 0, 0, 0, 0, &signer);
    tx_block(seq, prev, 0, |b| {
        b.add_node_transfer(&nt).ok().expect("add transfer");
    })
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

fn slot_of(bc: &W6Chain, seq: u32, hash: &[u8; 32]) -> Option<u32> {
    bc.blocks.find(seq, hash)
}

/// Receives `block` as a child of the active head; the Story 6.0 forward
/// extension makes it the new head and, past `W`, advances the tail.
fn extend_active_head(bc: &mut W6Chain, block: &Block, now: u64) -> u32 {
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
    let genesis = node_transfer_block(0, 3, 0, 7);
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
    let genesis = node_transfer_block(0, 3, 0, 7);
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

// --- Story 6.8: ADR-016 sequence-indexed UTXO input -----------------------

/// A `payload_type=1` block of complex transactions, chained to `prev` and
/// created by `creator`. The UTXO-side builder deferred-work D32 asked for.
/// The header is in override form (`first_voted_node == creator`,
/// Story 6.7 D4): a block by a creator other than `first_voted_node` is a
/// deviation, whose open run would bind every block above it.
fn complex_tx_block(
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
fn utxo_tx(
    seq: u32,
    utxo_inputs: &[(u32, u16, u64)],
    balance_input: Option<(u32, u64)>,
    outputs: &[Result<u64, (u32, u64)>],
) -> moonblokz_chain_types::ComplexTransaction {
    utxo_tx_vote(0, seq, utxo_inputs, balance_input, outputs)
}

/// [`utxo_tx`] whose `vote` names `vote`.
fn utxo_tx_vote(
    vote: u32,
    seq: u32,
    utxo_inputs: &[(u32, u16, u64)],
    balance_input: Option<(u32, u64)>,
    outputs: &[Result<u64, (u32, u64)>],
) -> moonblokz_chain_types::ComplexTransaction {
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
            Ok(amount) => cx.add_utxo_output(&[0xA5; PUBLIC_KEY_SIZE], amount),
            Err((receiver, amount)) => cx.add_balance_output(receiver, amount),
        }
        .ok()
        .expect("add output");
    }
    cx
}

fn admit(bc: &mut TestChain, block: &Block) -> u32 {
    bc.tier1_admit(&block.view(), &block.view().hash(), 0)
        .expect("block admitted")
}

/// The UTXO harness: a chain-config anchor at 99, then a balance block at
/// 100 seeding node 1 with 100 and nodes 2 and 3 (the creator) with 0.
fn utxo_test_chain() -> (TestChain, [u8; 32]) {
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

/// Block 101: node 1 moves its whole balance into two UTXO outputs, 60
/// (index 0) and 40 (index 1).
fn utxo_mint_block(prev: [u8; 32]) -> Block {
    let tx = utxo_tx(101, &[], Some((1, 100)), &[Ok(60), Ok(40)]);
    complex_tx_block(101, prev, 3, 0, &[&tx])
}

/// AC8 (1) / Story 6.11 AC6.1 — deriving the mint sets one bit per UTXO
/// output; the spend clears the input's bit (and only it), and the
/// referenced amount reaches the balance output.
#[test]
fn utxo_spend_clears_the_bit_and_credits_the_amount() {
    let (mut bc, h100) = utxo_test_chain();
    let mint = utxo_mint_block(h100);
    let mi = admit(&mut bc, &mint);
    let tx = utxo_tx(102, &[(101, 1, 40)], None, &[Err((2, 40))]);
    let spend = complex_tx_block(102, mint.view().hash(), 3, 0, &[&tx]);
    let si = admit(&mut bc, &spend);

    bc.run_processing_pass(si).expect("pass succeeds");

    assert_eq!(bc.blocks.utxo_available(mi, 1), Some(false), "spent output");
    assert_eq!(
        bc.blocks.utxo_available(mi, 0),
        Some(true),
        "untouched output"
    );
    assert_eq!(
        bc.blocks.utxo_available(mi, 2),
        Some(false),
        "no third output"
    );
    assert_eq!(bc.node_info.balance_of(1), 0, "minted everything");
    assert_eq!(bc.node_info.balance_of(2), 40, "the UTXO's amount");
    assert_eq!(bc.node_info.balance_of(3), 0, "no fee, nothing mined");
}

/// AC8 (2) — a second spend of the same output, in a later block, is
/// `UtxoUnavailable` against that later block; the abort rolls every bit
/// back to "nothing derived".
#[test]
fn utxo_double_spend_across_blocks_is_unavailable() {
    let (mut bc, h100) = utxo_test_chain();
    let mint = utxo_mint_block(h100);
    let mi = admit(&mut bc, &mint);
    let tx = utxo_tx(102, &[(101, 0, 60)], None, &[Err((2, 60))]);
    let first = complex_tx_block(102, mint.view().hash(), 3, 0, &[&tx]);
    admit(&mut bc, &first);
    let tx = utxo_tx(103, &[(101, 0, 60)], None, &[Err((2, 60))]);
    let second = complex_tx_block(103, first.view().hash(), 3, 0, &[&tx]);
    let di = admit(&mut bc, &second);

    assert_eq!(
        bc.run_processing_pass(di),
        Err(ProcessingError::Invalid {
            block_idx: di,
            reason: ValidationReason::UtxoUnavailable,
        })
    );
    assert_eq!(bc.blocks.utxo_available(mi, 0), Some(false), "rolled back");
    assert_eq!(bc.blocks.utxo_available(mi, 1), Some(false), "rolled back");
}

/// Runs the pass over `mint ← spend(inputs)` and returns its verdict and
/// the spending block's slot.
fn spend_verdict(inputs: &[(u32, u16, u64)]) -> (Result<(), ProcessingError>, u32) {
    let (mut bc, h100) = utxo_test_chain();
    let mint = utxo_mint_block(h100);
    admit(&mut bc, &mint);
    let tx = utxo_tx(102, inputs, None, &[]);
    let spend = complex_tx_block(102, mint.view().hash(), 3, 0, &[&tx]);
    let si = admit(&mut bc, &spend);
    (bc.run_processing_pass(si).map(|_| ()), si)
}

/// AC8 (3) / DEC-129 — on a window-anchored candidate a reference below
/// the anchor (99) is trusted pre-window history when it is at most `W`
/// (16) blocks back: no bit, and the declared amounts are trusted, so the
/// fee is still known (DEC-131).
#[test]
fn utxo_reference_below_a_window_anchor_is_trusted_within_w() {
    let (mut bc, h100) = utxo_test_chain();
    let mint = utxo_mint_block(h100);
    admit(&mut bc, &mint);
    let tx = utxo_tx(102, &[(98, 0, 50), (86, 3, 30)], None, &[Err((2, 70))]);
    let spend = complex_tx_block(102, mint.view().hash(), 3, 0, &[&tx]);
    let si = admit(&mut bc, &spend);

    bc.run_processing_pass(si).expect("pass succeeds");

    assert_eq!(bc.node_info.balance_of(2), 70, "the output is credited");
    assert_eq!(
        bc.node_info.balance_of(3),
        10,
        "fee 80 - 70 from the declared amounts"
    );
}

/// AC8 (3) / DEC-129 — a reference more than `W` blocks back is
/// `UtxoUnresolvable`, below the anchor or not.
#[test]
fn utxo_reference_beyond_w_is_unresolvable() {
    for referenced in [85, 50, 0] {
        let (verdict, si) = spend_verdict(&[(referenced, 0, 0)]);
        assert_eq!(
            verdict,
            Err(ProcessingError::Invalid {
                block_idx: si,
                reason: ValidationReason::UtxoUnresolvable,
            }),
            "block_sequence {referenced}"
        );
    }
}

/// DEC-129 boundary on a `W = 6` chain: exactly `W` back is trusted, one
/// more is not. #101 is a clean slot (Story 6.7 D8), so the spend sits at
/// #102 above a [`w6_clean_block`].
#[test]
fn utxo_distance_bound_is_exactly_w() {
    fn verdict(referenced: u32) -> (Result<(), ProcessingError>, u32) {
        let mut bc = new_w6_chain();
        let cfg = w6_config_anchor_block(99, [0xAB; 32]);
        bc.tier1_admit(&cfg.view(), &cfg.view().hash(), 0)
            .expect("config admitted");
        let seed = balance_block(100, cfg.view().hash(), &[(2, 0, 0, 0x32)], 3);
        bc.tier1_admit(&seed.view(), &seed.view().hash(), 0)
            .expect("seed admitted");
        let clean = w6_clean_block(101, seed.view().hash());
        bc.tier1_admit(&clean.view(), &clean.view().hash(), 0)
            .expect("clean slot admitted");
        let tx = utxo_tx(102, &[(referenced, 0, 5)], None, &[Err((2, 5))]);
        let spend = complex_tx_block(102, clean.view().hash(), 3, 0, &[&tx]);
        let si = bc
            .tier1_admit(&spend.view(), &spend.view().hash(), 0)
            .expect("spend admitted");
        (bc.run_processing_pass(si).map(|_| ()), si)
    }
    assert_eq!(verdict(96).0, Ok(()), "102 - 96 = W");
    let (result, si) = verdict(95);
    assert_eq!(
        result,
        Err(ProcessingError::Invalid {
            block_idx: si,
            reason: ValidationReason::UtxoUnresolvable,
        }),
        "102 - 95 > W"
    );
}

/// AC3 — without trust (a genesis-anchored candidate, or Ready, where
/// `NONE_REF` is the released tail) a reference below the anchor is
/// `UtxoUnresolvable`, even within `W`.
#[test]
fn utxo_reference_below_the_anchor_is_unresolvable_without_trust() {
    let (mut bc, h100) = utxo_test_chain();
    let mint = utxo_mint_block(h100);
    let mi = admit(&mut bc, &mint);
    assert!(matches!(
        bc.resolve_and_spend_utxo(mi, 102, 98, 0, 0, false),
        Err(UtxoSpendError::Invalid(ValidationReason::UtxoUnresolvable))
    ));
    assert!(matches!(
        bc.resolve_and_spend_utxo(mi, 102, 98, 0, 0, true),
        Ok(None)
    ));
}

/// AC8 (5) / Story 6.11 AC3 — an `output_index` past the referenced
/// block's UTXO outputs (or into a block with none) has no available bit:
/// exact evidence, decided from RAM. Story 6.15: the index is a `u16`, and
/// one past the 256-bit bitfield is unavailable too — 256 never aliases
/// output 0, as a truncation to `u8` would make it.
#[test]
fn utxo_out_of_bounds_index_is_unavailable() {
    for (referenced, index) in [
        (101, 2),
        (101, 255),
        (101, 256),
        (101, u16::MAX),
        (100, 0),
        (99, 0),
    ] {
        let (verdict, si) = spend_verdict(&[(referenced, index, 0)]);
        assert_eq!(
            verdict,
            Err(ProcessingError::Invalid {
                block_idx: si,
                reason: ValidationReason::UtxoUnavailable,
            }),
            "({referenced}, {index})"
        );
    }
}

/// AC8 (4) — ADR-016 trade-off (FR39): an output at the same
/// `(sequence, index)` on a side branch is never found. The resolver only
/// visits the consuming block's ancestors, whose block 101 has no output
/// and so no available bit; the side branch was never derived.
#[test]
fn utxo_output_on_a_side_branch_is_not_resolvable() {
    let (mut bc, h100) = utxo_test_chain();
    let side = utxo_mint_block(h100);
    let side_idx = admit(&mut bc, &side);
    // The active ancestry's block 101 carries no UTXO output.
    let own = transfer_block(101, h100, 2, 3, 0, 0, 0);
    admit(&mut bc, &own);
    let tx = utxo_tx(102, &[(101, 0, 60)], None, &[Err((2, 60))]);
    let spend = complex_tx_block(102, own.view().hash(), 3, 0, &[&tx]);
    let si = admit(&mut bc, &spend);

    assert_eq!(
        bc.run_processing_pass(si),
        Err(ProcessingError::Invalid {
            block_idx: si,
            reason: ValidationReason::UtxoUnavailable,
        })
    );
    assert_eq!(
        bc.blocks.has_available_utxo(side_idx),
        Some(false),
        "a side branch is never derived: its whole bitfield stays 0"
    );
}

/// AC8 (7) / AC5 — Tier 1 rejects a UTXO input whose `block_sequence` is
/// not below the block's own, and the block is not stored (FR16).
#[test]
fn utxo_input_not_before_block_is_rejected_at_intake() {
    let (mut bc, h100) = utxo_test_chain();
    let stored = bc.blocks.len();
    for referenced in [101, 102] {
        let tx = utxo_tx(101, &[(referenced, 0, 1)], None, &[Err((2, 1))]);
        let block = complex_tx_block(101, h100, 3, 0, &[&tx]);
        assert_eq!(
            bc.tier1_admit(&block.view(), &block.view().hash(), 0),
            Err(AdmitError::Rejected(Tier1Failure::UtxoInputNotBeforeBlock))
        );
    }
    assert_eq!(bc.blocks.len(), stored, "nothing stored");
}

/// AC8 (8) / AC6 — the fee counts UTXO outputs: a balance input of 100
/// paid entirely into a UTXO output leaves no surplus, so the creator gets
/// its mined amount and nothing more (it used to get another 100).
#[test]
fn utxo_output_is_not_paid_out_as_fee() {
    let (mut bc, h100) = utxo_test_chain();
    let tx = utxo_tx(101, &[], Some((1, 100)), &[Ok(100)]);
    let block = complex_tx_block(101, h100, 3, 7, &[&tx]);
    let bi = admit(&mut bc, &block);

    bc.run_processing_pass(bi).expect("pass succeeds");

    assert_eq!(bc.node_info.balance_of(3), 7, "mined 7, fee 0");
    assert_eq!(bc.node_info.balance_of(1), 0);
}

/// AC8 (9) / D1 — the UTXO amount is an input: 50 (UTXO) + 10 (balance)
/// against 55 of outputs pays a fee of 5. Outputs above the declared
/// inputs never reach the pass: Tier 1 rejects them (DEC-131).
#[test]
fn utxo_amount_counts_as_input() {
    let (mut bc, h100) = utxo_test_chain();
    let tx = utxo_tx(101, &[], Some((1, 50)), &[Ok(50)]);
    let mint = complex_tx_block(101, h100, 3, 0, &[&tx]);
    admit(&mut bc, &mint);
    let over = utxo_tx(102, &[(101, 0, 50)], Some((1, 10)), &[Err((2, 61))]);
    let over = complex_tx_block(102, mint.view().hash(), 3, 0, &[&over]);
    assert_eq!(
        bc.tier1_admit(&over.view(), &over.view().hash(), 0),
        Err(AdmitError::Rejected(Tier1Failure::InputsLessThanOutputs))
    );
    let tx = utxo_tx(102, &[(101, 0, 50)], Some((1, 10)), &[Err((2, 55))]);
    let spend = complex_tx_block(102, mint.view().hash(), 3, 0, &[&tx]);
    let si = admit(&mut bc, &spend);

    bc.run_processing_pass(si).expect("pass succeeds");

    assert_eq!(bc.node_info.balance_of(3), 5, "fee = 60 - 55");
    assert_eq!(bc.node_info.balance_of(2), 55);
    assert_eq!(bc.node_info.balance_of(1), 40, "100 - 50 - 10");
}

/// DEC-131 — a declared amount that is not the referenced output's is
/// `UtxoAmountMismatch`; the abort leaves nothing derived.
#[test]
fn utxo_declared_amount_mismatch_is_invalid() {
    for declared in [39, 41] {
        let (mut bc, h100) = utxo_test_chain();
        let mint = utxo_mint_block(h100);
        let mi = admit(&mut bc, &mint);
        let tx = utxo_tx(102, &[(101, 1, declared)], None, &[Err((2, declared))]);
        let spend = complex_tx_block(102, mint.view().hash(), 3, 0, &[&tx]);
        let si = admit(&mut bc, &spend);
        assert_eq!(
            bc.run_processing_pass(si),
            Err(ProcessingError::Invalid {
                block_idx: si,
                reason: ValidationReason::UtxoAmountMismatch,
            }),
            "declared {declared}, output 40"
        );
        assert_eq!(bc.blocks.utxo_available(mi, 1), Some(false));
    }
}

/// AC8 (10) / AC2 — `output_index` counts the block's UTXO-output stream
/// across transactions, skipping balance outputs: the second
/// transaction's only UTXO output is index 2, not 0.
#[test]
fn utxo_output_index_spans_the_whole_block() {
    let (mut bc, h100) = utxo_test_chain();
    let first = utxo_tx(101, &[], Some((1, 60)), &[Ok(10), Err((2, 5)), Ok(45)]);
    let second = utxo_tx(101, &[], Some((1, 30)), &[Ok(30)]);
    let mint = complex_tx_block(101, h100, 3, 0, &[&first, &second]);
    let mi = admit(&mut bc, &mint);
    let tx = utxo_tx(102, &[(101, 2, 30)], None, &[Err((2, 30))]);
    let spend = complex_tx_block(102, mint.view().hash(), 3, 0, &[&tx]);
    let si = admit(&mut bc, &spend);

    bc.run_processing_pass(si).expect("pass succeeds");

    assert_eq!(bc.blocks.utxo_available(mi, 2), Some(false), "spent");
    assert_eq!(bc.blocks.utxo_available(mi, 0), Some(true));
    assert_eq!(bc.blocks.utxo_available(mi, 1), Some(true), "the 45 output");
    assert_eq!(
        bc.blocks.utxo_available(mi, 3),
        Some(false),
        "no fourth output"
    );
    assert_eq!(bc.node_info.balance_of(2), 5 + 30, "the 30 output");
    assert_eq!(bc.node_info.balance_of(3), 0, "no fee anywhere");
}

/// AC8 (2) — the same output named twice in one transaction, or by two
/// transactions of one block, is spent once: the second is
/// `UtxoUnavailable`.
#[test]
fn utxo_double_spend_within_one_block_is_unavailable() {
    let same_tx = utxo_tx(102, &[(101, 0, 60), (101, 0, 60)], None, &[Err((2, 60))]);
    let first = utxo_tx(102, &[(101, 0, 60)], None, &[Err((2, 60))]);
    let second = utxo_tx(102, &[(101, 0, 60)], None, &[Err((2, 60))]);
    for txs in [&[&same_tx][..], &[&first, &second][..]] {
        let (mut bc, h100) = utxo_test_chain();
        let mint = utxo_mint_block(h100);
        admit(&mut bc, &mint);
        let spend = complex_tx_block(102, mint.view().hash(), 3, 0, txs);
        let si = admit(&mut bc, &spend);
        assert_eq!(
            bc.run_processing_pass(si),
            Err(ProcessingError::Invalid {
                block_idx: si,
                reason: ValidationReason::UtxoUnavailable,
            }),
            "{} transaction(s)",
            txs.len()
        );
    }
}

/// AC6 — an input sum beyond `u64` is rejected at Tier 1 (DEC-011,
/// DEC-131); the block's fee total, summed across transactions, is checked
/// in the pass: `ValueOverflow`, never a clamped credit.
#[test]
fn utxo_value_overflow_is_invalid() {
    const HALF: u64 = 1 << 63;
    let (mut bc, h100) = utxo_test_chain();
    // Two zero-input carry-forwards, each a UTXO output of 2^63.
    let a = utxo_tx(101, &[], None, &[Ok(HALF)]);
    let b = utxo_tx(101, &[], None, &[Ok(HALF)]);
    let mint = complex_tx_block(101, h100, 3, 0, &[&a, &b]);
    admit(&mut bc, &mint);

    let both = utxo_tx(102, &[(101, 0, HALF), (101, 1, HALF)], None, &[]);
    let both = complex_tx_block(102, mint.view().hash(), 3, 0, &[&both]);
    assert_eq!(
        bc.tier1_admit(&both.view(), &both.view().hash(), 0),
        Err(AdmitError::Rejected(Tier1Failure::AmountOverflow))
    );

    let first = utxo_tx(102, &[(101, 0, HALF)], None, &[]);
    let second = utxo_tx(102, &[(101, 1, HALF)], None, &[]);
    let spend = complex_tx_block(102, mint.view().hash(), 3, 0, &[&first, &second]);
    let si = admit(&mut bc, &spend);
    assert_eq!(
        bc.run_processing_pass(si),
        Err(ProcessingError::Invalid {
            block_idx: si,
            reason: ValidationReason::ValueOverflow,
        })
    );
}

/// A storage backend whose reads of one slot start failing after a set
/// number of successful ones, counting every attempt on that slot. The
/// fault lasts `failures_left` reads (persistent by default).
/// `N` is the inner backend's size: 8 slots unless a test needs more
/// (Story 6.5's longer chain uses 16).
struct FailingReadStorage<const N: usize = { 8 * MAX_BLOCK_SIZE + 8000 }> {
    inner: MemoryBackend<N>,
    failing_slot: u32,
    reads_left: core::cell::Cell<u32>,
    failures_left: core::cell::Cell<u32>,
    attempts: core::cell::Cell<u32>,
    /// Every read, of any slot (Story 6.4 AC9 3d).
    reads: core::cell::Cell<u32>,
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

type FailingReadChain =
    Blockchain<Crypto, FailingReadStorage, TestConfig, 16, 16, TEST_MAX_BLOCKS, 4, 16>;

/// The UTXO harness on a [`FailingReadChain`] whose reads all succeed
/// until a test arms `failing_slot`: chain-config anchor 99, balance block
/// 100, and the [`utxo_mint_block`] at 101. Returns the node, the mint and
/// its slot.
fn failing_read_utxo_chain() -> (FailingReadChain, Block, u32) {
    let crypto = Crypto::new([1u8; PRIVATE_KEY_SIZE]).ok().expect("key");
    let chain_config = locked_chain_config(&crypto, FailingReadChain::BUILD_LIMITS);
    let node_zero = *crypto.public_key().serialize();
    let storage = FailingReadStorage {
        inner: initialized_storage([1u8; PRIVATE_KEY_SIZE]),
        failing_slot: NONE_REF,
        reads_left: core::cell::Cell::new(0),
        failures_left: core::cell::Cell::new(u32::MAX),
        attempts: core::cell::Cell::new(0),
        reads: core::cell::Cell::new(0),
    };
    let mut slot = core::mem::MaybeUninit::<FailingReadChain>::uninit();
    FailingReadChain::init(&mut slot, crypto, storage, chain_config, 5, node_zero, 0);
    // SAFETY: `init` returned, so every field of `slot` is initialized.
    let mut bc = unsafe { slot.assume_init() };

    let cfg = chain_config_anchor_block(99, [0xAB; 32]);
    failing_read_admit(&mut bc, &cfg);
    let seed = balance_block(
        100,
        cfg.view().hash(),
        &[(1, 100, 0, 0x31), (2, 0, 0, 0x32), (3, 0, 0, 0x33)],
        3,
    );
    failing_read_admit(&mut bc, &seed);
    let mint = utxo_mint_block(seed.view().hash());
    let mi = failing_read_admit(&mut bc, &mint);
    (bc, mint, mi)
}

fn failing_read_admit(bc: &mut FailingReadChain, block: &Block) -> u32 {
    bc.tier1_admit(&block.view(), &block.view().hash(), 0)
        .expect("block admitted")
}

/// AC8 (6) / AC3 step 5 — a failed read of the referenced block is a local
/// fault: the pass reports `StorageRead`, never `Invalid`, so nothing is
/// charged against the spending block. (The FR5 driver's head fallback for
/// `StorageRead` is unchanged here; DEC-037 is Story 6.0.)
#[test]
fn utxo_read_failure_is_reported_as_storage_read() {
    let (mut bc, mint, mi) = failing_read_utxo_chain();
    let tx = utxo_tx(102, &[(101, 1, 40)], None, &[Err((2, 40))]);
    let spend = complex_tx_block(102, mint.view().hash(), 3, 0, &[&tx]);
    let si = failing_read_admit(&mut bc, &spend);

    bc.storage.failing_slot = mi;
    bc.storage.reads_left.set(1);
    let stored = bc.blocks.len();

    assert_eq!(
        bc.run_processing_pass(si),
        Err(ProcessingError::StorageRead)
    );
    assert_eq!(
        bc.storage.attempts.get(),
        2,
        "the segment walk read the block, then the resolver's read failed"
    );
    assert_eq!(bc.blocks.len(), stored, "the pass itself deletes nothing");
}

/// Story 6.11 AC3 / AC6.3 — an output whose bit is 0 is rejected before the
/// resolver reads the referenced block: past the block's outputs (no read
/// at all beyond the segment walk's), or already spent by an earlier block
/// (only that earlier spend reads).
#[test]
fn utxo_unavailable_output_is_rejected_without_a_read() {
    // (spending blocks' inputs, resolver reads expected on the mint)
    let past_the_outputs: &[&[(u32, u16, u64)]] = &[&[(101, 2, 0)]];
    let spent_earlier: &[&[(u32, u16, u64)]] = &[&[(101, 0, 60)], &[(101, 0, 60)]];
    for (spends, resolver_reads) in [(past_the_outputs, 0), (spent_earlier, 1)] {
        let (mut bc, mint, mi) = failing_read_utxo_chain();
        let mut prev = mint.view().hash();
        let mut tip = mi;
        for (k, inputs) in spends.iter().enumerate() {
            let seq = 102 + k as u32;
            let amount = inputs[0].2;
            let tx = utxo_tx(seq, inputs, None, &[Err((2, amount))]);
            let block = complex_tx_block(seq, prev, 3, 0, &[&tx]);
            prev = block.view().hash();
            tip = failing_read_admit(&mut bc, &block);
        }
        bc.storage.failing_slot = mi;
        bc.storage.reads_left.set(u32::MAX);

        assert_eq!(
            bc.run_processing_pass(tip),
            Err(ProcessingError::Invalid {
                block_idx: tip,
                reason: ValidationReason::UtxoUnavailable,
            })
        );
        assert_eq!(
            bc.storage.attempts.get(),
            1 + resolver_reads,
            "the segment walk's read, plus {resolver_reads} by the resolver"
        );
    }
}

/// Story 6.11 AC3 / D2 — a set bit whose output the stored bytes do not
/// hold means storage and RAM disagree: a local fault, never evidence
/// against the spending block.
#[test]
fn utxo_bit_without_its_output_is_a_local_fault() {
    let (mut bc, h100) = utxo_test_chain();
    let mint = utxo_mint_block(h100);
    let mi = admit(&mut bc, &mint);
    bc.run_processing_pass(mi).expect("the mint derives");
    assert_eq!(bc.blocks.utxo_available(mi, 2), Some(false));
    bc.blocks.set_utxo_available(mi, 2, true);

    assert!(matches!(
        bc.resolve_and_spend_utxo(mi, 102, 101, 2, 0, false),
        Err(UtxoSpendError::StorageRead)
    ));
    assert_eq!(bc.blocks.utxo_available(mi, 2), Some(true), "nothing spent");
}

/// An override set declaring `max_block_utxo_output = 1` and the window
/// [`TEST_W`].
fn one_utxo_output_config_builder() -> ChainConfigPayloadBuilder {
    let mut builder = window_config_builder(TEST_W);
    builder
        .add_literal(parameter::MAX_BLOCK_UTXO_OUTPUT, &1u16.to_le_bytes())
        .ok()
        .expect("a two-byte literal is well-formed");
    builder
}

/// Story 6.11 AC5 / AC6.7 — the Tier-1 UTXO-output cap enforces the chain's
/// value only once it is durably locked; a tentative one leaves the
/// bitfield-width bound in force (FR9).
#[test]
fn tier1_utxo_output_cap_is_the_locked_value_only() {
    let two_outputs = utxo_mint_block([0xCD; 32]);
    let one_output = complex_tx_block(
        101,
        [0xCD; 32],
        3,
        0,
        &[&utxo_tx(101, &[], Some((1, 9)), &[Ok(9)])],
    );

    // Tentative: a stray chain-config block declares the cap of 1.
    let mut bc = new_unconfigured_test_chain();
    let stray = chain_config_block_from(500, [0xEE; 32], &mut one_utxo_output_config_builder());
    bc.tier1_admit(&stray.view(), &stray.view().hash(), 0)
        .expect("the stray is admitted");
    assert!(bc.chain_config.tentative_content().is_some());
    assert_eq!(
        bc.chain_config
            .active_configuration()
            .map(|config| config.max_utxo_outputs()),
        Some(1),
        "the tentative configuration really declares the cap of 1"
    );
    assert!(
        bc.tier1_admit(&two_outputs.view(), &two_outputs.view().hash(), 0)
            .is_ok(),
        "a tentative-only cap must not reject the block (FR9)"
    );

    // Locked on the same content: the cap is enforced and nothing is stored.
    let (crypto, storage, _) = test_backends();
    let mut chain_config = empty_chain_config(TestChain::BUILD_LIMITS);
    chain_config
        .load_durable(one_utxo_output_config_builder().build_signed(&crypto))
        .ok()
        .expect("legal content");
    let mut bc = new_chain(crypto, storage, chain_config, 5, 0);
    let stored = bc.blocks.len();
    assert_eq!(
        bc.tier1_admit(&two_outputs.view(), &two_outputs.view().hash(), 0),
        Err(AdmitError::Rejected(Tier1Failure::TooManyUtxoOutputs))
    );
    assert_eq!(bc.blocks.len(), stored, "not stored");
    assert!(
        bc.tier1_admit(&one_output.view(), &one_output.view().hash(), 0)
            .is_ok(),
        "exactly the cap is admitted"
    );
}

/// Story 6.11 D3 (DEC-133) — the FR3 pass holds a block to its candidate's
/// own declared cap even while that configuration is only tentative: the
/// preload made it the value the lock is about to commit, so a block that
/// Tier 1 admitted under the bitfield-width bound cannot be adopted past it.
#[test]
fn fr3_pass_enforces_the_candidates_declared_utxo_output_cap() {
    let (mut bc, h100) = tentative_one_utxo_output_chain();
    let mint = utxo_mint_block(h100);
    let mi = admit(&mut bc, &mint);

    assert_eq!(
        bc.run_processing_pass(mi),
        Err(ProcessingError::Invalid {
            block_idx: mi,
            reason: ValidationReason::TooManyUtxoOutputs,
        })
    );
    assert_eq!(bc.blocks.utxo_available(mi, 0), Some(false), "rolled back");
}

/// Story 6.11 D3 boundary — exactly the declared cap passes the FR6 step.
#[test]
fn fr3_pass_admits_exactly_the_declared_utxo_output_cap() {
    let (mut bc, h100) = tentative_one_utxo_output_chain();
    let tx = utxo_tx(101, &[], Some((1, 100)), &[Ok(100)]);
    let block = complex_tx_block(101, h100, 3, 0, &[&tx]);
    let bi = admit(&mut bc, &block);

    bc.run_processing_pass(bi).expect("one output, cap one");
    assert_eq!(bc.blocks.utxo_available(bi, 0), Some(true));
}

/// An unconfigured node holding, tentatively, a chain-config anchor at 99
/// that declares `max_block_utxo_output = 1`, and the [`utxo_test_chain`]
/// balance block at 100 above it. Returns the node and block 100's hash.
fn tentative_one_utxo_output_chain() -> (TestChain, [u8; 32]) {
    let mut bc = new_unconfigured_test_chain();
    let cfg = chain_config_block_from(99, [0xAB; 32], &mut one_utxo_output_config_builder());
    admit(&mut bc, &cfg);
    assert!(
        bc.chain_config.tentative_content().is_some(),
        "tentative only"
    );
    let seed = balance_block(
        100,
        cfg.view().hash(),
        &[(1, 100, 0, 0x31), (2, 0, 0, 0x32), (3, 0, 0, 0x33)],
        3,
    );
    admit(&mut bc, &seed);
    (bc, seed.view().hash())
}

/// Story 6.11 AC2 / AC4 end to end — deriving a block sets exactly one bit
/// per UTXO output, which gives it the FR51 tail obligation; spending every
/// output clears it.
#[test]
fn utxo_derivation_drives_the_tail_obligation() {
    let (mut bc, h100) = utxo_test_chain();
    let mint = utxo_mint_block(h100);
    let mi = admit(&mut bc, &mint);
    bc.run_processing_pass(mi).expect("the mint derives");
    assert_eq!(bc.blocks.utxo_available(mi, 0), Some(true));
    assert_eq!(bc.blocks.utxo_available(mi, 1), Some(true));
    assert_eq!(
        bc.blocks.utxo_available(mi, 2),
        Some(false),
        "two outputs only"
    );
    assert_eq!(
        classify_tail_drop(&bc.blocks, &bc.node_info, mi),
        Ok(TailObligation::Utxo)
    );

    let tx = utxo_tx(102, &[(101, 0, 60), (101, 1, 40)], None, &[Err((2, 100))]);
    let spend = complex_tx_block(102, mint.view().hash(), 3, 0, &[&tx]);
    let si = admit(&mut bc, &spend);
    bc.run_processing_pass(si).expect("both outputs spent");
    assert_eq!(bc.blocks.has_available_utxo(mi), Some(false));
    assert_eq!(
        classify_tail_drop(&bc.blocks, &bc.node_info, mi),
        Ok(TailObligation::None)
    );
}

/// Review patch — the lock-time `BlockTooLarge` rollback follows a pass that
/// returned `Ok`, so it must clear the derived bits itself: a surviving
/// ancestor of the offender may not keep advertising its outputs.
#[test]
fn fr9_lock_time_size_rollback_leaves_no_available_utxo_bit() {
    let mut bc = new_unconfigured_w6_chain();
    // The three blocks below the window (`W + H`, DEC-177) are
    // [`w6_below`]'s; #100 is a one-entry balance block seeding node #3,
    // within the small limit. The UTXO blocks sit off the clean slots #101
    // and #104 (Story 6.7 D8), which hold node #3's transfers of nothing.
    let below = w6_below();
    for block in &below {
        let (outcome, _) = bc.receive_block(block.view(), 0);
        assert_eq!(outcome, ReceiveBlockOutcome::AcceptedSilently);
    }
    let clean = |seq: u32, prev: [u8; 32]| {
        let signer = Crypto::new([1u8; PRIVATE_KEY_SIZE]).ok().expect("test key");
        let nt = NodeTransfer::new_signed(0, seq - 1, 3, 3, 0, 0, 0, &signer);
        headed(seq, prev, 3, 1, 0, 3, 0, |b| {
            b.add_node_transfer(&nt).ok().expect("add transfer");
        })
    };
    // `max_node_id = 9`: the pre-window actors of #97..=#99 (nodes 7 and
    // 9) lie inside the derived node-id range.
    let base = balance_block(100, below[2].view().hash(), &[(3, 0, 0, 0x33)], 9);
    let s101 = clean(101, base.view().hash());
    let one = utxo_tx(102, &[], None, &[Ok(5)]);
    let b102 = complex_tx_block(102, s101.view().hash(), 3, 0, &[&one]);
    let three = utxo_tx(103, &[], None, &[Ok(5), Ok(6), Ok(7)]);
    let b103 = complex_tx_block(103, b102.view().hash(), 3, 0, &[&three]);
    let s104 = clean(104, b103.view().hash());
    let cfg = chain_config_block_from(105, s104.view().hash(), &mut small_limit_config_builder(W6));
    for small in below.iter().chain([&base, &s101, &b102, &s104, &cfg]) {
        assert!(small.len() <= SMALL_BLOCK_SIZE_LIMIT as usize);
    }
    assert!(b103.len() > SMALL_BLOCK_SIZE_LIMIT as usize);
    for block in [&base, &s101, &b102, &b103, &s104, &cfg] {
        let (outcome, _) = bc.receive_block(block.view(), 0);
        assert_eq!(outcome, ReceiveBlockOutcome::AcceptedSilently);
    }

    assert!(
        !bc.is_ready(),
        "the re-evaluation at the lock refuses the candidate"
    );
    assert!(
        bc.blocks.find(103, &b103.view().hash()).is_none(),
        "offender deleted"
    );
    let survivor = bc
        .blocks
        .find(102, &b102.view().hash())
        .expect("the offender's ancestor survives");
    assert_eq!(
        bc.blocks.has_available_utxo(survivor),
        Some(false),
        "no bit of the refused candidate survives"
    );
}

// ===================================================================
// Story 6.0 — Ready-state active-head forward extension
// ===================================================================

/// Every chain of this section shares `TestChain`'s capacities; only the
/// storage differs (the fault-injecting one of AC6).
type Chain16<S> = Blockchain<Crypto, S, TestConfig, 16, 16, TEST_MAX_BLOCKS, 4, 16>;

/// The FR54 currency of every genesis node in this section.
const CURRENCY: u64 = 1_000_000_000;

/// A node-#0 genesis node on `W = w`: Ready, with the complete projection
/// the per-block step derived over #0 / #1 (D6). Returns it with the two
/// genesis blocks.
fn ready_genesis(w: u32) -> (TestChain, Block, Block) {
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
fn ready_genesis_w6() -> (Chain16<W6Storage>, Block, Block) {
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

fn head_of<S: StorageTrait>(bc: &Chain16<S>) -> (u32, [u8; 32]) {
    let entry = bc.blocks.get(bc.active_chain_head_idx).expect("a head");
    (entry.sequence(), *entry.hash())
}

fn receive<S: StorageTrait>(bc: &mut Chain16<S>, block: &Block) -> ReceiveBlockOutcome {
    bc.receive_block(block.view(), 0).0
}

/// A registration of `new_node_id` by `initializer`, its key from
/// `pk_byte` (the cross-key construction of [`registration_block`]).
fn registration_tx(initializer: u32, new_node_id: u32, pk_byte: u8) -> Registration {
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
fn tx_block(seq: u32, prev: [u8; 32], mined: u32, add: impl FnOnce(&mut BlockBuilder)) -> Block {
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
fn transfer_tx(seq: u32, receiver: u32, amount: u64) -> NodeTransfer {
    let signer = Crypto::new([1u8; PRIVATE_KEY_SIZE]).ok().expect("test key");
    NodeTransfer::new_signed(0, seq - 1, 0, receiver, amount, 1, 0, &signer)
}

fn transfer(seq: u32, prev: [u8; 32], receiver: u32, amount: u64) -> Block {
    let nt = transfer_tx(seq, receiver, amount);
    tx_block(seq, prev, 0, |b| {
        b.add_node_transfer(&nt).ok().expect("add transfer");
    })
}

fn register(seq: u32, prev: [u8; 32], new_node_id: u32, pk_byte: u8) -> Block {
    let reg = registration_tx(0, new_node_id, pk_byte);
    tx_block(seq, prev, 0, |b| {
        b.add_registration(&reg).ok().expect("add registration");
    })
}

/// Node #0's current `(balance, vote_count)` — a matching D9 snapshot.
fn node_zero_snapshot<S: StorageTrait>(bc: &Chain16<S>) -> (u32, u64, u32, u8) {
    (
        0,
        bc.node_info.balance_of(0),
        bc.vote_engine.accumulated_vote_of(0),
        0,
    )
}

/// AC2 / AC10.4: the derived state of two nodes is identical — `node_info`,
/// the vote engine, the whole block table (statuses, chain flags,
/// available-UTXO bits), `chain_heads`, the head and the tail.
fn assert_same_state<S: StorageTrait, T: StorageTrait>(a: &Chain16<S>, b: &Chain16<T>, what: &str) {
    assert!(a.node_info == b.node_info, "{what}: node_info");
    assert!(a.vote_engine == b.vote_engine, "{what}: votes");
    assert!(a.blocks == b.blocks, "{what}: block table");
    assert!(a.chain_heads == b.chain_heads, "{what}: chain_heads");
    assert_eq!(
        a.active_chain_head_idx, b.active_chain_head_idx,
        "{what}: head"
    );
    assert_eq!(
        a.snake_chain_tail_idx, b.snake_chain_tail_idx,
        "{what}: tail"
    );
    assert_eq!(a.lifecycle_phase, b.lifecycle_phase, "{what}: phase");
}

/// The durable slot `idx` holds the same bytes on both nodes.
fn same_slot<S: StorageTrait, T: StorageTrait>(a: &Chain16<S>, b: &Chain16<T>, idx: u32) -> bool {
    match (a.storage.read_block(idx), b.storage.read_block(idx)) {
        (Ok(x), Ok(y)) => x.serialized_bytes() == y.serialized_bytes(),
        (Err(_), Err(_)) => true,
        _ => false,
    }
}

/// The reason the fallible half of the step gives for `block` as an
/// extension of the head, run on a scratch entry that is removed again.
/// `None` on success, whose effects are then inverted, so either way the
/// node is left as it was.
fn step_reason<S: StorageTrait>(bc: &mut Chain16<S>, block: &Block) -> Option<ValidationReason> {
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

/// The UTXO fixture on a genesis node: #2 registers node 1, #3 mints two
/// UTXO outputs (60, 40) from node #0's balance. Returns the node and #3.
fn utxo_genesis() -> (TestChain, Block) {
    let (mut bc, _, b1) = ready_genesis(16);
    let reg = register(2, b1.view().hash(), 1, 0x31);
    assert_eq!(
        receive(&mut bc, &reg),
        ReceiveBlockOutcome::AcceptedSilently
    );
    let mint_tx = utxo_tx(3, &[], Some((0, 100)), &[Ok(60), Ok(40)]);
    let mint = complex_tx_block(3, reg.view().hash(), 0, 0, &[&mint_tx]);
    assert_eq!(
        receive(&mut bc, &mint),
        ReceiveBlockOutcome::AcceptedSilently
    );
    assert_eq!(head_of(&bc).1, mint.view().hash());
    (bc, mint)
}

// --- Task 2.2: every inverse is exact (apply ∘ invert = identity) -------

#[test]
fn step_inverses_restore_the_derived_state_exactly() {
    // Node transfer, registration, and a complex transaction with a UTXO
    // spend, a balance input and a balance output — each applied by the
    // step and inverted, on a node that has a twin.
    let (mut bc, mint) = utxo_genesis();
    let (twin, _) = utxo_genesis();
    let (seq, prev) = (4, mint.view().hash());
    let nt = transfer_tx(seq, 1, 500);
    let reg = registration_tx(0, 2, 0x32);
    let cx = utxo_tx(seq, &[(3, 1, 40)], Some((0, 10)), &[Err((1, 45))]);
    let blocks = [
        tx_block(seq, prev, 0, |b| {
            b.add_node_transfer(&nt).ok().expect("transfer");
        }),
        tx_block(seq, prev, 0, |b| {
            b.add_registration(&reg).ok().expect("registration");
        }),
        complex_tx_block(seq, prev, 0, 0, &[&cx]),
    ];
    for block in &blocks {
        assert_eq!(step_reason(&mut bc, block), None, "the block is valid");
        assert_same_state(&bc, &twin, "after apply and invert");
    }
}

// --- AC10.1: direct extension -------------------------------------------

#[test]
fn forward_extension_promotes_each_direct_extension() {
    let (mut bc, _, b1) = ready_genesis(16);
    let reg = register(2, b1.view().hash(), 1, 0x31);
    let t3 = transfer(3, reg.view().hash(), 1, 100);
    let t4 = transfer(4, t3.view().hash(), 1, 50);
    for block in [&reg, &t3, &t4] {
        assert_eq!(
            receive(&mut bc, block),
            ReceiveBlockOutcome::AcceptedSilently
        );
        let idx = bc
            .blocks
            .find(block.view().sequence(), &block.view().hash())
            .expect("stored");
        assert_eq!(
            bc.current_active_head(),
            Some(idx),
            "D19: the head advances"
        );
        let entry = bc.blocks.get(idx).expect("entry");
        assert_eq!(entry.status(), BlockStatus::Active);
        assert!(entry.is_on_active_chain());
    }
    assert_eq!(bc.node_info.max_known_node_id(), 1);
    assert_eq!(bc.node_info.balance_of(1), 150);
    // Registration 50 + 1, transfers 101 + 51; every fee back to the
    // creator, node #0.
    assert_eq!(bc.node_info.balance_of(0), CURRENCY - 51 - 101 - 51 + 3);
    assert!(bc.is_ready());
}

// --- AC10.2: orphan continuation ----------------------------------------

#[test]
fn forward_extension_continues_over_a_stored_orphan() {
    let (mut bc, _, b1) = ready_genesis(16);
    let a = transfer(2, b1.view().hash(), 0, 7);
    let b = transfer(3, a.view().hash(), 0, 8);
    assert_eq!(receive(&mut bc, &b), ReceiveBlockOutcome::AcceptedSilently);
    let bi = bc.blocks.find(3, &b.view().hash()).expect("orphan stored");
    assert_eq!(
        bc.blocks.get(bi).map(|e| e.status()),
        Some(BlockStatus::Stored)
    );
    assert_eq!(head_of(&bc).0, 1, "the orphan does not move the head");

    assert_eq!(receive(&mut bc, &a), ReceiveBlockOutcome::AcceptedSilently);
    assert_eq!(
        head_of(&bc),
        (3, b.view().hash()),
        "A at intake, B by continuation"
    );
    assert_eq!(
        bc.blocks.get(bi).map(|e| e.status()),
        Some(BlockStatus::Active)
    );
    assert!(!bc.chain_heads.has_stored_head());
    assert_eq!(bc.chain_heads.count(), 1, "no zombie entry for A");
}

// --- AC10.3: sibling choice (D5) ----------------------------------------

#[test]
fn forward_extension_takes_the_lowest_hash_sibling_on_an_equal_rank() {
    let (mut bc, _, b1) = ready_genesis(16);
    let a = transfer(2, b1.view().hash(), 0, 7);
    let c1 = transfer(3, a.view().hash(), 0, 8);
    let c2 = transfer(3, a.view().hash(), 0, 9);
    for c in [&c1, &c2] {
        assert_eq!(receive(&mut bc, c), ReceiveBlockOutcome::AcceptedSilently);
    }
    assert_eq!(receive(&mut bc, &a), ReceiveBlockOutcome::AcceptedSilently);
    let (low, high) = if c1.view().hash() < c2.view().hash() {
        (&c1, &c2)
    } else {
        (&c2, &c1)
    };
    // Equal value, size and creator: the FR21 rank falls to the hash.
    assert_eq!(head_of(&bc), (3, low.view().hash()), "the lower hash wins");
    let hi = bc.blocks.find(3, &high.view().hash()).expect("loser kept");
    // Story 6.1: the loser is a side block the driver connected.
    assert_eq!(
        bc.blocks.get(hi).map(|e| e.status()),
        Some(BlockStatus::Connected)
    );
    assert!(
        bc.chain_heads.occupied_heads().any(|(h, _)| h == hi),
        "the loser is a tracked side head"
    );
    assert!(!bc.chain_heads.has_stored_head(), "and a Connected one");
}

// --- AC10.4: invalid direct extension (AC3, AC2) ------------------------

/// Feeds `bad` to a node and asserts the AC3 refusal: `InvalidEvidence`,
/// nothing stored, and every piece of derived state identical to a twin
/// that never saw it (AC2). `reason` pins why, against a third twin.
fn assert_refused_at_intake(build: impl Fn() -> TestChain, bad: &Block, reason: ValidationReason) {
    let mut bc = build();
    let twin = build();
    let mut probe = build();
    assert_eq!(step_reason(&mut probe, bad), Some(reason));
    assert_same_state(&probe, &twin, "the probe left nothing behind");
    let free = bc.blocks.next_free_index().expect("a free slot");
    assert_eq!(
        receive(&mut bc, bad),
        ReceiveBlockOutcome::Rejected(RejectReason::InvalidEvidence)
    );
    assert_same_state(&bc, &twin, "refused extension");
    assert_eq!(bc.blocks.next_free_index(), Some(free), "no slot used");
    assert!(same_slot(&bc, &twin, free), "storage unchanged");
}

#[test]
fn invalid_direct_extension_is_not_stored_and_leaves_no_trace() {
    let genesis = || ready_genesis(16).0;
    let (_, _, b1) = ready_genesis(16);
    let prev = b1.view().hash();
    // Insufficient balance after an earlier, valid transfer in the block.
    let ok = transfer_tx(2, 0, 10);
    let broke = transfer_tx(2, 0, CURRENCY);
    let overspend = tx_block(2, prev, 0, |b| {
        b.add_node_transfer(&ok).ok().expect("first");
        b.add_node_transfer(&broke).ok().expect("second");
    });
    assert_refused_at_intake(genesis, &overspend, ValidationReason::InsufficientBalance);

    // A duplicate key after an earlier registration's debit and seeding.
    let first = registration_tx(0, 1, 0x31);
    let dup = registration_tx(0, 2, 0x31);
    let duplicate = tx_block(2, prev, 0, |b| {
        b.add_registration(&first).ok().expect("first");
        b.add_registration(&dup).ok().expect("second");
    });
    assert_refused_at_intake(genesis, &duplicate, ValidationReason::DuplicatePublicKey);

    // A UTXO spend after an earlier input spent the same output.
    let utxo = || utxo_genesis().0;
    let (_, mint) = utxo_genesis();
    let spend = utxo_tx(4, &[(3, 0, 60)], None, &[Err((1, 60))]);
    let again = utxo_tx(4, &[(3, 0, 60)], None, &[Err((1, 60))]);
    let double = complex_tx_block(4, mint.view().hash(), 0, 0, &[&spend, &again]);
    assert_refused_at_intake(utxo, &double, ValidationReason::UtxoUnavailable);
}

// --- AC10.5: invalid stored child (AC4, AC5) ----------------------------

#[test]
fn invalid_stored_child_is_deleted_with_its_descendants() {
    let (mut bc, _, b1) = ready_genesis(16);
    let (mut twin, _, _) = ready_genesis(16);
    let a = transfer(2, b1.view().hash(), 0, 7);
    let bad = transfer(3, a.view().hash(), 0, CURRENCY);
    let below = transfer(4, bad.view().hash(), 0, 8);
    for block in [&below, &bad] {
        assert_eq!(
            receive(&mut bc, block),
            ReceiveBlockOutcome::AcceptedSilently
        );
    }
    assert_eq!(bc.blocks.len(), 4, "both orphans stored");

    assert_eq!(receive(&mut bc, &a), ReceiveBlockOutcome::AcceptedSilently);
    assert_eq!(
        receive(&mut twin, &a),
        ReceiveBlockOutcome::AcceptedSilently
    );
    assert_eq!(head_of(&bc), (2, a.view().hash()), "A stays the head");
    assert!(
        bc.blocks.find(3, &bad.view().hash()).is_none(),
        "child deleted"
    );
    assert!(
        bc.blocks.find(4, &below.view().hash()).is_none(),
        "with its descendant"
    );
    assert!(bc.is_ready(), "no FR5 recovery in Ready");
    // Nothing of the failed child reached the derived state.
    assert!(bc.node_info == twin.node_info);
    assert!(bc.vote_engine == twin.vote_engine);
}

// --- AC10.6: local failures (AC6) ---------------------------------------

/// A backend that can fail reads of one slot and every block write.
struct FaultyStorage {
    inner: MemoryBackend<{ 8 * MAX_BLOCK_SIZE + 8000 }>,
    failing_read_slot: u32,
    fail_saves: bool,
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
fn faulty_utxo_genesis() -> (Chain16<FaultyStorage>, Block) {
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

#[test]
fn read_failure_at_intake_stores_the_extension_and_retries_it() {
    let (mut bc, mint) = faulty_utxo_genesis();
    let (twin, _) = faulty_utxo_genesis();
    let mint_idx = bc.active_chain_head_idx;
    let tx = utxo_tx(4, &[(3, 1, 40)], None, &[Err((1, 40))]);
    let spend = complex_tx_block(4, mint.view().hash(), 0, 0, &[&tx]);

    bc.storage.failing_read_slot = mint_idx;
    assert_eq!(
        receive(&mut bc, &spend),
        ReceiveBlockOutcome::AcceptedSilently
    );
    let si = bc
        .blocks
        .find(4, &spend.view().hash())
        .expect("stored, not blamed");
    assert_eq!(
        bc.blocks.get(si).map(|e| e.status()),
        Some(BlockStatus::Stored)
    );
    assert_eq!(bc.active_chain_head_idx, mint_idx, "head unchanged");
    assert!(bc.node_info == twin.node_info, "derived state unchanged");
    assert!(bc.vote_engine == twin.vote_engine);
    assert_eq!(
        bc.blocks.utxo_available(mint_idx, 1),
        Some(true),
        "bit restored"
    );

    // The fault clears; the next admission — any block — extends it.
    bc.storage.failing_read_slot = NONE_REF;
    let unrelated = node_transfer_block(9, 3, 8, 7);
    assert_eq!(
        receive(&mut bc, &unrelated),
        ReceiveBlockOutcome::AcceptedSilently
    );
    assert_eq!(bc.active_chain_head_idx, si, "the retry extended the head");
    assert_eq!(bc.blocks.utxo_available(mint_idx, 1), Some(false));
    assert_eq!(bc.node_info.balance_of(1), 40);
}

#[test]
fn save_failure_inverts_the_extension_and_is_unstorable() {
    let (mut bc, mint) = faulty_utxo_genesis();
    let (twin, _) = faulty_utxo_genesis();
    let tx = utxo_tx(4, &[(3, 1, 40)], Some((0, 5)), &[Err((1, 44))]);
    let spend = complex_tx_block(4, mint.view().hash(), 0, 0, &[&tx]);
    bc.storage.fail_saves = true;
    assert_eq!(
        receive(&mut bc, &spend),
        ReceiveBlockOutcome::Rejected(RejectReason::Unstorable)
    );
    assert_same_state(&bc, &twin, "save failure");
}

// --- AC10.7: the window path --------------------------------------------

/// A genesis node on `W = 6` ([`ready_genesis_w6`]) with #2..=#5 added
/// (transfers, clean on the slots #2 and #5, Story 6.7 D8): the window is
/// full (`0..=5`), and its tail #0 is node #0's seed source (its
/// registration).
fn full_w6_genesis() -> (Chain16<W6Storage>, Block) {
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

fn snapshot_block<S: StorageTrait>(bc: &Chain16<S>, seq: u32, prev: [u8; 32]) -> Block {
    balance_block(
        seq,
        prev,
        &[node_zero_snapshot(bc)],
        bc.node_info.max_known_node_id(),
    )
}

#[test]
fn window_extension_past_w_advances_and_binds() {
    // Binding `Invalid` at intake: dropping #0 needs a balance block (FR50).
    let (mut bc, b5) = full_w6_genesis();
    let (twin, _) = full_w6_genesis();
    let plain = transfer(6, b5.view().hash(), 0, 9);
    assert_eq!(
        receive(&mut bc, &plain),
        ReceiveBlockOutcome::Rejected(RejectReason::InvalidEvidence)
    );
    assert_same_state(&bc, &twin, "binding refusal stores nothing");

    // A stored child failing its binding is deleted. The snapshot at #6
    // advances the tail to #1 (chain-config), so a transfer at #7 cannot
    // drop it (FR49) — admitted first as an orphan, judged by continuation.
    let replay = snapshot_block(&bc, 6, b5.view().hash());
    let child = transfer(7, replay.view().hash(), 0, 9);
    assert_eq!(
        receive(&mut bc, &child),
        ReceiveBlockOutcome::AcceptedSilently
    );
    assert_eq!(
        receive(&mut bc, &replay),
        ReceiveBlockOutcome::AcceptedSilently
    );
    assert_eq!(head_of(&bc), (6, replay.view().hash()));
    assert_eq!(
        bc.active_snake_chain_window(),
        Ok((1, 6)),
        "the extension past W advanced the tail in the same step"
    );
    let genesis_idx = bc.blocks.find(0, &bc_genesis_hash());
    assert!(genesis_idx.is_some(), "#0 entered the horizon (Story 6.14)");
    assert_eq!(genesis_idx, Some(bc.horizon_root()));
    assert!(
        bc.blocks.find(7, &child.view().hash()).is_none(),
        "child deleted"
    );
    let replay_idx = bc.active_chain_head_idx;
    assert!(
        bc.node_info.is_seed_source(replay_idx),
        "D9: the seed source moved"
    );
    // Story 6.4 AC9 3c: a head extension that advanced the tail.
    assert_active_set_matches(&bc, "after the tail advance");
}

/// Block #0 of every genesis node in this section (it is deterministic).
fn bc_genesis_hash() -> [u8; 32] {
    ready_genesis(16).1.view().hash()
}

/// AC10.7 — a classification failure is a local one: no mutation, no
/// verdict. Since Story 6.11 the classification reads no storage, so its
/// only failure is a tail naming an empty slot; that is reached here by
/// corrupting the index and judging directly, since `receive_block`'s FR60
/// window asserts the same invariant in debug builds.
#[test]
fn window_classification_failure_changes_nothing() {
    let (mut bc, b5) = full_w6_genesis();
    let (twin, _) = full_w6_genesis();
    let real_tail = bc.snake_chain_tail_idx;
    let replay = snapshot_block(&bc, 6, b5.view().hash());
    let view = replay.view();
    let idx = bc.blocks.next_free_index().expect("free");
    let head = bc.active_chain_head_idx;
    bc.blocks
        .insert_at(idx, BlockEntry::new(view.hash(), head, view.sequence()));
    bc.snake_chain_tail_idx = idx + 1; // an empty slot
    assert!(matches!(
        bc.judge_head_extension(&view, idx, bc.snake_chain_tail_idx),
        Extension::Local
    ));
    bc.snake_chain_tail_idx = real_tail;
    bc.blocks.delete(idx);
    assert_same_state(&bc, &twin, "classification failure");

    // With the tail readable again, the same block extends the head.
    assert_eq!(
        receive(&mut bc, &replay),
        ReceiveBlockOutcome::AcceptedSilently
    );
    assert_eq!(head_of(&bc), (6, replay.view().hash()));
}

// --- AC10.8: genesis-node equivalence (AC8) -----------------------------

#[test]
fn genesis_node_and_mesh_node_derive_the_same_state() {
    let (mut g, b0, b1) = ready_genesis(16);
    assert_eq!(
        g.blocks.get(0).map(|e| e.status()),
        Some(BlockStatus::Active)
    );
    assert_eq!(
        g.blocks.get(1).map(|e| e.status()),
        Some(BlockStatus::Active)
    );
    let mut m = new_unconfigured_test_chain();
    for block in [&b0, &b1] {
        assert_eq!(
            receive(&mut m, block),
            ReceiveBlockOutcome::AcceptedSilently
        );
    }
    assert!(m.is_ready(), "the mesh node joined through FR3");
    let reg = register(2, b1.view().hash(), 1, 0x31);
    let t3 = transfer(3, reg.view().hash(), 1, 100);
    for block in [&reg, &t3] {
        assert_eq!(
            receive(&mut g, block),
            ReceiveBlockOutcome::AcceptedSilently
        );
        assert_eq!(
            receive(&mut m, block),
            ReceiveBlockOutcome::AcceptedSilently
        );
    }
    assert!(g.node_info == m.node_info, "node_info");
    assert!(g.vote_engine == m.vote_engine, "votes");
    for idx in 0..4 {
        let (a, b) = (g.blocks.get(idx).expect("g"), m.blocks.get(idx).expect("m"));
        assert_eq!(a.hash(), b.hash());
        assert_eq!(a.status(), b.status());
        assert_eq!(a.is_on_active_chain(), b.is_on_active_chain());
    }
    assert_eq!(head_of(&g), head_of(&m));
}

// --- AC10.9: FR3 / restart / double-run equivalence (AC9) ---------------

/// The AC9 sequence on a genesis node: a registration, a transfer, a mined
/// UTXO mint, a spend, and a matching balance block. Returns the node and
/// the blocks in chain order, #0 first.
fn extended_genesis() -> (TestChain, [Block; 7]) {
    let (mut bc, b0, b1) = ready_genesis(16);
    let reg = register(2, b1.view().hash(), 1, 0x31);
    receive(&mut bc, &reg);
    let t3 = transfer(3, reg.view().hash(), 1, 100);
    receive(&mut bc, &t3);
    let mint_tx = utxo_tx(4, &[], Some((0, 100)), &[Ok(60), Ok(40)]);
    let mint = complex_tx_block(4, t3.view().hash(), 0, 25, &[&mint_tx]);
    receive(&mut bc, &mint);
    let spend_tx = utxo_tx(5, &[(4, 0, 60)], None, &[Err((1, 59))]);
    let spend = complex_tx_block(5, mint.view().hash(), 0, 0, &[&spend_tx]);
    receive(&mut bc, &spend);
    let snap = snapshot_block(&bc, 6, spend.view().hash());
    receive(&mut bc, &snap);
    assert_eq!(
        head_of(&bc),
        (6, snap.view().hash()),
        "every block extended"
    );
    (bc, [b0, b1, reg, t3, mint, spend, snap])
}

#[test]
fn forward_extension_matches_fr3_restart_and_replay() {
    let (a, blocks) = extended_genesis();
    assert_eq!(a.blocks.utxo_available(4, 0), Some(false), "spent");
    assert_eq!(a.blocks.utxo_available(4, 1), Some(true), "unspent");

    // (1) A fresh node receiving the same blocks while Collecting reaches
    // Ready through FR3 over all of them: orphans first, genesis last.
    let mut b = new_unconfigured_test_chain();
    for block in blocks.iter().rev() {
        assert_eq!(
            receive(&mut b, block),
            ReceiveBlockOutcome::AcceptedSilently
        );
    }
    assert!(b.is_ready());
    assert_eq!(head_of(&b), head_of(&a));
    assert_eq!(
        b.node_info.max_known_node_id(),
        a.node_info.max_known_node_id()
    );
    for node in 0..16 {
        assert_eq!(b.node_info.balance_of(node), a.node_info.balance_of(node));
        assert_eq!(
            b.node_info.public_key_of(node),
            a.node_info.public_key_of(node)
        );
        assert_eq!(
            b.vote_engine.accumulated_vote_of(node),
            a.vote_engine.accumulated_vote_of(node)
        );
    }
    for block in &blocks {
        let view = block.view();
        let ai = a.blocks.find(view.sequence(), &view.hash()).expect("a");
        let bi = b.blocks.find(view.sequence(), &view.hash()).expect("b");
        let (ea, eb) = (a.blocks.get(ai).expect("a"), b.blocks.get(bi).expect("b"));
        assert_eq!(ea.status(), eb.status(), "#{}", view.sequence());
        assert_eq!(ea.is_on_active_chain(), eb.is_on_active_chain());
        for bit in 0..16 {
            assert_eq!(ea.utxo_available(bit), eb.utxo_available(bit));
        }
        assert_eq!(
            a.node_info.is_seed_source(ai),
            b.node_info.is_seed_source(bi),
            "seed source #{}",
            view.sequence()
        );
    }

    // (2) Restart of A rebuilds the same state from its own slots.
    let (a, _) = extended_genesis();
    let (reference, _) = extended_genesis();
    let mut restarted = restart(a);
    let _ = restarted.initialize_from_storage(0);
    assert!(restarted.is_ready());
    assert!(
        restarted.node_info == reference.node_info,
        "restart node_info"
    );
    assert!(
        restarted.vote_engine == reference.vote_engine,
        "restart votes"
    );
    assert_eq!(head_of(&restarted), head_of(&reference));
    for idx in 0..7 {
        let (x, y) = (
            restarted.blocks.get(idx).expect("restarted"),
            reference.blocks.get(idx).expect("reference"),
        );
        assert_eq!(x.status(), y.status());
        assert_eq!(x.is_on_active_chain(), y.is_on_active_chain());
        for bit in 0..16 {
            assert_eq!(x.utxo_available(bit), y.utxo_available(bit));
        }
    }

    // (3) The same admission sequence twice gives the same state.
    let (twice, _) = extended_genesis();
    assert_same_state(&twice, &reference, "double run");
}

// --- AC10.10: chain_heads cache and eviction protection (AC7) -----------

#[test]
fn promoted_head_has_current_caches() {
    let (mut bc, _, b1) = ready_genesis(16);
    let a = transfer(2, b1.view().hash(), 0, 7);
    receive(&mut bc, &a);
    let head = bc.active_chain_head_idx;
    assert!(
        bc.chain_heads
            .occupied_heads()
            .any(|(h, anchor)| h == head && anchor == head),
        "the head's entry anchors on the head itself, not the old head"
    );
}

// --- AC10.11: balance block (D9) ----------------------------------------

/// A balance block by node #0 with `mined_amount`.
fn mined_balance_block(
    seq: u32,
    prev: [u8; 32],
    entries: &[(u32, u64, u32, u8)],
    max_node_id: u32,
    mined: u32,
) -> Block {
    use moonblokz_chain_types::NodeInfo;
    let signer = Crypto::new([1u8; PRIVATE_KEY_SIZE]).ok().expect("test key");
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
    for &(owner, balance, vote_count, _) in entries {
        let ni = NodeInfo::new(owner, balance, vote_count, &real_key);
        builder.add_node_info(&ni).ok().expect("add node info");
    }
    builder
        .set_max_node_id(max_node_id)
        .ok()
        .expect("max node id");
    builder.build_signed(&signer).ok().expect("build signed")
}

#[test]
fn balance_block_repeats_the_pre_state_in_ready() {
    // Two nodes: #0 (the creator) and #1, registered at #2. A transfer at
    // #3 gives #1 a vote so the snapshot has a non-trivial vote count.
    let build = || {
        let (mut bc, _, b1) = ready_genesis(16);
        let reg = register(2, b1.view().hash(), 1, 0x31);
        receive(&mut bc, &reg);
        let nt = NodeTransfer::new_signed(
            1,
            2,
            0,
            1,
            10,
            1,
            0,
            &Crypto::new([1u8; PRIVATE_KEY_SIZE]).ok().expect("key"),
        );
        let t3 = tx_block(3, reg.view().hash(), 0, |b| {
            b.add_node_transfer(&nt).ok().expect("transfer");
        });
        receive(&mut bc, &t3);
        (bc, t3)
    };
    let (mut bc, t3) = build();
    let prev = t3.view().hash();
    let (owner, balance, votes, _) = node_zero_snapshot(&bc);
    assert!(bc.vote_engine.accumulated_vote_of(1) > 0, "precondition");

    // Each mismatching field of a seeded entry is Invalid (FR50).
    for entry in [
        (owner, balance - 1, votes, 0),
        (owner, balance, votes + 1, 0),
        // Node #1's key is `pubkey(0x31)`; the builder writes node #0's.
        (
            1,
            bc.node_info.balance_of(1),
            bc.vote_engine.accumulated_vote_of(1),
            0,
        ),
    ] {
        let bad = mined_balance_block(4, prev, &[entry], 1, 3);
        assert_eq!(
            step_reason(&mut bc, &bad),
            Some(ValidationReason::BalanceSnapshotMismatch)
        );
    }
    // An entry for a node that does not exist is Invalid in Ready.
    let ghost = mined_balance_block(4, prev, &[(2, 0, 0, 0)], 1, 3);
    assert_eq!(
        step_reason(&mut bc, &ghost),
        Some(ValidationReason::NodeIdOutOfRange)
    );

    // A mismatch as a stored child is deleted, derived state untouched.
    let (mut twin, _) = build();
    let mut bad_child_chain = build().0;
    let filler = transfer(4, prev, 0, 7);
    let bad = mined_balance_block(5, filler.view().hash(), &[(owner, 0, votes, 0)], 1, 3);
    receive(&mut bad_child_chain, &bad);
    receive(&mut bad_child_chain, &filler);
    receive(&mut twin, &filler);
    assert!(
        bad_child_chain.blocks.find(5, &bad.view().hash()).is_none(),
        "deleted"
    );
    assert!(bad_child_chain.node_info == twin.node_info);
    assert!(bad_child_chain.vote_engine == twin.vote_engine);

    // The matching snapshot is accepted: the entries leave balances and
    // votes as they were; only the block-level effects apply.
    let good = mined_balance_block(4, prev, &[(owner, balance, votes, 0)], 1, 3);
    let vote_one = bc.vote_engine.accumulated_vote_of(1);
    assert_eq!(
        receive(&mut bc, &good),
        ReceiveBlockOutcome::AcceptedSilently
    );
    assert_eq!(head_of(&bc), (4, good.view().hash()));
    assert_eq!(
        bc.node_info.balance_of(0),
        balance + 3,
        "the creator credit"
    );
    assert_eq!(
        bc.vote_engine.accumulated_vote_of(0),
        0,
        "the creator reset"
    );
    assert!(
        bc.vote_engine.accumulated_vote_of(1) >= vote_one,
        "only interest applies to the listed-or-not others"
    );
    let gi = bc.active_chain_head_idx;
    assert!(
        bc.node_info.is_seed_source(gi),
        "node #0's seed source moved"
    );
}

#[test]
fn balance_block_snapshot_is_checked_in_fr3() {
    // A genesis-anchored FR3 pass over a balance block whose snapshot
    // disagrees deletes it (FR5); the matching one is adopted.
    let (g, b0, b1) = ready_genesis(16);
    let (owner, balance, votes, _) = node_zero_snapshot(&g);
    for (entry_balance, adopted) in [(balance + 1, false), (balance, true)] {
        let snap = balance_block(2, b1.view().hash(), &[(owner, entry_balance, votes, 0)], 0);
        let mut m = new_unconfigured_test_chain();
        for block in [&snap, &b1, &b0] {
            receive(&mut m, block);
        }
        assert!(m.is_ready());
        assert_eq!(m.blocks.find(2, &snap.view().hash()).is_some(), adopted);
        assert_eq!(head_of(&m).0, if adopted { 2 } else { 1 });
    }
    // A window-anchored pass seeds an unseeded entry (floor seeding).
    let (mut bc, _) = utxo_test_chain();
    let tip = (0..16u32)
        .find(|&i| bc.blocks.get(i).is_some_and(|e| e.sequence() == 100))
        .expect("#100");
    assert_eq!(bc.run_processing_pass(tip).map(|_| ()), Ok(()));
    assert!(bc.node_info.is_seeded(1));
    assert_eq!(bc.node_info.balance_of(1), 100);
}

// --- AC10.12: complete context in Ready (D3) ----------------------------

#[test]
fn ready_has_no_trust_zone() {
    let (mut bc, _, b1) = ready_genesis(16);
    let prev = b1.view().hash();
    // An unseeded creator.
    let signer = Crypto::new([1u8; PRIVATE_KEY_SIZE]).ok().expect("key");
    let header = BlockHeader {
        version: 1,
        sequence: 2,
        creator: 5,
        mined_amount: 0,
        payload_type: PAYLOAD_TYPE_TRANSACTION,
        consumed_votes: 0,
        first_voted_node: 0,
        consumed_votes_from_first_voted_node: 0,
        previous_hash: prev,
        signature: [0u8; SIGNATURE_SIZE],
    };
    let nt = transfer_tx(2, 0, 1);
    let mut builder = BlockBuilder::new().header(header);
    builder.add_node_transfer(&nt).ok().expect("transfer");
    let by_stranger = builder.build_signed(&signer).ok().expect("build");
    assert_eq!(
        step_reason(&mut bc, &by_stranger),
        Some(ValidationReason::UnseededActor)
    );
    // An initializer that is not seeded (here: does not exist).
    let foreign = transfer_block(2, prev, 7, 0, 1, 1, 0);
    assert_eq!(
        step_reason(&mut bc, &foreign),
        Some(ValidationReason::UnseededActor)
    );
    // As a stored child, it is deleted.
    let a = transfer(2, prev, 0, 7);
    let child = transfer_block(3, a.view().hash(), 7, 0, 1, 1, 0);
    receive(&mut bc, &child);
    receive(&mut bc, &a);
    assert_eq!(head_of(&bc), (2, a.view().hash()));
    assert!(bc.blocks.find(3, &child.view().hash()).is_none());
}

/// DEC-134 — a `parent_ref` into a freed slot is the node's own index
/// defect: the pass reports `MissingBlock`, the recovery deletes nothing,
/// unlinks the dangling reference, and the block becomes a Stored
/// tail-point that FR19 asks its real parent for.
#[test]
fn missing_block_repairs_the_index_and_deletes_nothing() {
    let mut bc = new_test_chain();
    let genesis = node_transfer_block(0, 0, 0, 0);
    bc.tier1_admit(&genesis.view(), &genesis.view().hash(), 0)
        .expect("genesis admitted");
    let b1 = transfer_block(1, genesis.view().hash(), 1, 2, 100, 1, 0);
    bc.tier1_admit(&b1.view(), &b1.view().hash(), 0)
        .expect("b1 admitted");
    let b2 = transfer_block(2, b1.view().hash(), 1, 2, 100, 1, 0);
    let bi2 = bc
        .tier1_admit(&b2.view(), &b2.view().hash(), 0)
        .expect("b2 admitted");
    // The defect: b2 names a slot that holds no block.
    let freed = bc.blocks.next_free_index().expect("free");
    bc.blocks.set_parent_ref(bi2, NONE_REF);
    bc.blocks.set_parent_ref(bi2, freed);

    bc.set_lifecycle_phase(LifecyclePhase::Processing);
    let err = bc
        .run_processing_pass(bi2)
        .expect_err("the walk meets the freed slot");
    assert_eq!(err, ProcessingError::MissingBlock);
    bc.recover_from_failed_pass(err, bi2);

    assert_eq!(bc.blocks.len(), 3, "nothing deleted");
    assert_eq!(bc.current_phase(), LifecyclePhase::Collecting);
    assert_eq!(
        bc.blocks.get(bi2).map(|e| e.parent_ref()),
        Some(NONE_REF),
        "unlinked"
    );
    assert!(
        (0..4).any(|slot| bc.chain_heads.stored_head_tail(slot) == Some(bi2)),
        "b2 is a Stored tail-point"
    );
    let (outcome, _) = bc.on_tick(u64::MAX / 2);
    match outcome {
        TickOutcome::SendParentRecoveryRequest(req) => {
            assert_eq!(
                req.missing_parent_hash(),
                &b1.view().hash(),
                "asks for its parent"
            );
            assert_eq!(req.claimed_parent_sequence(), 1);
        }
        _ => panic!("a parent-recovery request is due"),
    }
}

// --- Code review 2026-10-18 -------------------------------------------

/// Review patch — a registration by a not-yet-seeded initializer (a
/// window-anchored pass, before its seed source) still pays its fee to a
/// seeded creator, so the creator's balance stays exact for D9.
#[test]
fn registration_fee_reaches_the_creator_when_the_initializer_is_unseeded() {
    let mut bc = new_test_chain();
    let cfg_hash = admit_chain_config_anchor(&mut bc, 99, [0xAB; 32]);
    // Node 0 (the creator) is listed; node 4 exists but is not.
    let seed = balance_block(100, cfg_hash, &[(0, 1_000, 0, 0)], 4);
    admit(&mut bc, &seed);
    let reg = registration_block(101, seed.view().hash(), 4, 5, 0x45);
    let tip = admit(&mut bc, &reg);
    assert_eq!(bc.run_processing_pass(tip).map(|_| ()), Ok(()));
    assert!(
        !bc.node_info.is_seeded(4),
        "precondition: unseeded initializer"
    );
    assert_eq!(
        bc.node_info.balance_of(0),
        1_001,
        "the fee reached the creator"
    );
}

/// Review patch — a complex transaction that fails after a UTXO spend, a
/// balance-input debit and a balance-output credit is inverted exactly.
#[test]
fn partially_applied_complex_transaction_is_inverted_exactly() {
    let (mut bc, mint) = utxo_genesis();
    let (twin, _) = utxo_genesis();
    // Node 9 does not exist: the second output fails its range check.
    let cx = utxo_tx(4, &[(3, 0, 60)], Some((0, 10)), &[Err((1, 5)), Err((9, 5))]);
    let block = complex_tx_block(4, mint.view().hash(), 0, 0, &[&cx]);
    assert_eq!(
        step_reason(&mut bc, &block),
        Some(ValidationReason::NodeIdOutOfRange)
    );
    assert_same_state(&bc, &twin, "partial complex inversion");
}

/// Review patch — a credit that would overflow the creator's balance is
/// `BalanceOverflow`, and nothing of the block remains applied.
#[test]
fn creator_credit_overflow_is_invalid() {
    let build = || {
        let (crypto, storage, chain_config) = test_backends();
        let mut bc = new_chain(crypto, storage, chain_config, 0, 0);
        let genesis = bc
            .process_genesis(u64::MAX, window_config_builder(16).content())
            .ok()
            .expect("genesis succeeds");
        (bc, genesis.block_one)
    };
    let (mut bc, b1) = build();
    let (twin, _) = build();
    // A self-transfer pays its fee of 1 back to node #0, the creator,
    // whose balance is then `u64::MAX - 1`; `mined_amount = 2` overflows.
    let nt = transfer_tx(2, 0, 1);
    let block = tx_block(2, b1.view().hash(), 2, |b| {
        b.add_node_transfer(&nt).ok().expect("transfer");
    });
    assert_eq!(
        step_reason(&mut bc, &block),
        Some(ValidationReason::BalanceOverflow)
    );
    assert_same_state(&bc, &twin, "overflow refusal");
}

/// DEC-138 — the vote apply runs before `chain_heads` learns of a direct
/// extension. A local refusal there (no vote parameters) keeps the block,
/// written and Stored, tracked as a head, with the derivation inverted.
#[test]
fn local_vote_refusal_after_the_write_keeps_the_extension_stored() {
    let (mut bc, _, b1) = ready_genesis(16);
    let (twin, _, _) = ready_genesis(16);
    // An engine that holds no FR37 parameters (the test oracle's state).
    bc.vote_engine = VoteEngine::new();
    let a = transfer(2, b1.view().hash(), 0, 7);
    assert_eq!(receive(&mut bc, &a), ReceiveBlockOutcome::AcceptedSilently);
    let ai = bc.blocks.find(2, &a.view().hash()).expect("stored");
    assert_eq!(
        bc.blocks.get(ai).map(|e| e.status()),
        Some(BlockStatus::Stored)
    );
    assert_eq!(head_of(&bc).0, 1, "the head did not move");
    assert!(
        bc.chain_heads.occupied_heads().any(|(h, _)| h == ai),
        "tracked as a head"
    );
    assert!(
        bc.node_info == twin.node_info,
        "the derivation was inverted"
    );
}

// ===================================================================
// Story 6.1 — FR21 branch value and side-block Tier 2
// ===================================================================

/// `block` rebuilt with header `consumed_votes` — its FR21 value — and
/// re-signed by node #0. Transaction and chain-config payloads. On the
/// active chain the value must be real (I-09, Story 6.2): use [`alt`] or
/// [`real_on`] there; `revalue` serves side blocks, which get no Tier 3.
fn revalue(block: &Block, consumed_votes: u32) -> Block {
    let view = block.view();
    resign(block, view.creator(), consumed_votes, 1)
}

/// `block`'s payload under a header by `creator` (signed with the key
/// `[key; 32]`) in the normal vote form, worth `consumed_votes`.
fn resign(block: &Block, creator: u32, consumed_votes: u32, key: u8) -> Block {
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
fn valued(seq: u32, prev: [u8; 32], value: u32, amount: u64) -> Block {
    revalue(&transfer(seq, prev, 0, amount), value)
}

// ===================================================================
// Story 6.2 — real vote headers for active-chain fixtures (I-09)
// ===================================================================

/// Node #1's key byte wherever these fixtures register it.
const NODE_ONE_KEY: u8 = 0x31;

/// `I(av)`: FR37 step 1 under the test configuration (`vote_scale` 1000,
/// `vote_interest` 5, so the bump is `min(⌊av / 200⌋, 1000)`) — the
/// post-interest, pre-credit snapshot a block's `consumed_votes` carries
/// (DEC-156).
fn vote_snapshot(av: u32) -> u32 {
    av + (av / 200).min(1000)
}

/// The FR21 value of `block`: its header `consumed_votes`.
fn v(block: &Block) -> u64 {
    u64::from(block.view().consumed_votes())
}

/// `n` node-#0 self-transfers at `seq` whose `vote` names `target`, their
/// amounts from `salt` (distinct transactions).
fn votes_for(seq: u32, target: u32, n: u32, salt: u64) -> impl FnOnce(&mut BlockBuilder) {
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
/// block crediting only the next creator. `received` is the number of
/// credits the previous block gave `creator` — its whole accumulated vote,
/// since its own last block reset it — so `consumed_votes =
/// I(1000 · received)` (= `1005 · received` while `received ≤ 200`, below
/// the interest cap). The block casts `out` credits
/// for the other node (or, with `out == 0`, one for its own creator, which
/// the reset wipes). `register` puts node #1's registration first.
fn alt(
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
    resign(&template, creator, vote_snapshot(1000 * received), key)
}

/// `block` as `creator`'s (signed with `key`), worth its real FR21 value on
/// `state` — the chain whose active head is the block's parent (I-09).
fn real_on<
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
fn brute_value<
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

fn slot<
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

fn status_of<S: StorageTrait>(bc: &Chain16<S>, block: &Block) -> Option<BlockStatus> {
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
fn valued_w6() -> (W6Chain, [Block; 6]) {
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

/// AC10.1 / AC3 — seeding at every Ready entry: the genesis node holds 0
/// (its block #1 carries no value), a genesis-anchored mesh join sums
/// `(#0, #1]`, a window-anchored FR3 join sums its window — each equal to
/// the brute force.
#[test]
fn branch_value_is_seeded_at_every_ready_entry() {
    let (genesis, _, _) = ready_genesis(16);
    assert_eq!(genesis.active_branch_value, 0);
    assert_eq!(
        genesis.active_branch_value,
        brute_value(&genesis, genesis.active_chain_head_idx)
    );
    // A genesis-anchored mesh join over #0..#3, orphans first: #1 and #2
    // are node #0's (worth 0), #3 node #1's after 3 credits (real values,
    // I-09).
    let (_, b0, b1) = ready_genesis(16);
    let a2 = alt(2, b1.view().hash(), 0, 0, 3, 7, true);
    let a3 = alt(3, a2.view().hash(), 1, 3, 0, 8, false);
    let mut mesh = new_unconfigured_test_chain();
    for blk in [&a3, &a2, &b1, &b0] {
        assert_eq!(
            receive(&mut mesh, blk),
            ReceiveBlockOutcome::AcceptedSilently
        );
    }
    assert!(mesh.is_ready());
    assert_eq!(head_of(&mesh), (3, a3.view().hash()));
    assert_eq!(v(&a3), 3015);
    assert_eq!(
        mesh.active_branch_value,
        v(&b1) + v(&a2) + v(&a3),
        "#1..#3 count, #0 is S_tail"
    );
    assert_eq!(
        mesh.active_branch_value,
        brute_value(&mesh, mesh.active_chain_head_idx)
    );
    let (w6, _) = valued_w6();
    assert_eq!(
        w6.active_branch_value,
        3 + 5 + 7 + 11 + 13,
        "the anchor is S_tail"
    );
    assert_eq!(
        w6.active_branch_value,
        brute_value(&w6, w6.active_chain_head_idx)
    );
}

/// AC10.3 / AC5 / AC9; Story 6.14 — a tail advance subtracts the block
/// that becomes `S_tail`, from the active value and from a side head forked
/// above it (with `H = 3` a fork at #103 stays inside FR58's bound after the
/// advance); a fresh node reaching Ready through FR3 over the same blocks
/// holds the same values. The horizon below the tail is never summed.
#[test]
fn tail_advance_subtracts_the_new_tail_everywhere() {
    let (mut a, [anchor, b101, b102, b103, b104, b105]) = valued_w6();
    // A fork at #103, judged before its write (D4) and valued by the walk;
    // worth less than the active branch, so no switch is attempted. #104
    // is a clean slot (Story 6.7 D8): the side block is a transfer.
    let side = revalue(&salted_linked_block(104, b103.view().hash(), 6), 1);
    assert_eq!(
        a.receive_block(side.view(), 0).0,
        ReceiveBlockOutcome::AcceptedSilently
    );
    let si = slot(&a, &side);
    assert_eq!(
        a.blocks.get(si).map(|e| e.status()),
        Some(BlockStatus::Connected)
    );
    assert_eq!(a.chain_heads.branch_value_of(si), Some(3 + 5 + 7 + 1));
    assert_eq!(a.chain_heads.branch_value_of(si), Some(brute_value(&a, si)));

    // Dropping the chain-config anchor needs a chain-config extension.
    let b106 = real_on(&a, &w6_config_anchor_block(106, b105.view().hash()), 0, 1);
    extend_active_head(&mut a, &b106, 0);
    assert_eq!(a.active_snake_chain_window(), Ok((101, 106)));
    assert_eq!(
        a.active_branch_value,
        5 + 7 + 11 + 13 + v(&b106),
        "#101 left the sum, #100 never was in it"
    );
    assert_eq!(
        a.active_branch_value,
        brute_value(&a, a.active_chain_head_idx)
    );
    assert_eq!(a.chain_heads.branch_value_of(si), Some(5 + 7 + 1));
    assert_eq!(a.chain_heads.branch_value_of(si), Some(brute_value(&a, si)));

    // A fresh node, orphans first, reaches the same values through FR3 on
    // `98..=106` — `W + H` long, so #97 is not needed.
    let [_, b98, b99] = w6_below();
    let mut b = new_w6_chain();
    for blk in [
        &side, &b106, &b105, &b104, &b103, &b102, &b101, &anchor, &b99, &b98,
    ] {
        assert_eq!(
            b.receive_block(blk.view(), 0).0,
            ReceiveBlockOutcome::AcceptedSilently
        );
    }
    assert!(b.is_ready());
    assert_eq!(b.active_snake_chain_window(), Ok((101, 106)));
    assert_eq!(b.active_branch_value, a.active_branch_value);
    let bs = slot(&b, &side);
    assert_eq!(
        b.blocks.get(bs).map(|e| e.status()),
        Some(BlockStatus::Connected)
    );
    assert_eq!(b.chain_heads.branch_value_of(bs), Some(5 + 7 + 1));
    // Story 6.4 AC9 3c: built at a window-anchored ready entry.
    assert_active_set_matches(&b, "window-anchored entry");
}

/// A genesis node on a [`FaultyStorage`] whose faults are disarmed, on
/// `W = w`.
fn faulty_genesis(w: u32) -> (Chain16<FaultyStorage>, Block) {
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

/// AC10.3 / AC5 — the new tail's value is read before anything changes: a
/// failed read is a local failure, and the next admission extends.
#[test]
fn failed_new_tail_read_is_a_local_failure() {
    // `W = 6`: the window fills at #5. The clean slots #2 and #5 (Story
    // 6.7 D8) hold node #0's transfers; node #1 registers at #3 and
    // creates #4.
    let (mut bc, b1) = faulty_genesis(W6);
    let b2 = real_on(
        &bc,
        &tx_block(2, b1.view().hash(), 0, votes_for(2, 0, 1, 6)),
        0,
        1,
    );
    assert_eq!(receive(&mut bc, &b2), ReceiveBlockOutcome::AcceptedSilently);
    let b3 = alt(3, b2.view().hash(), 0, 0, 2, 7, true);
    let b4 = alt(4, b3.view().hash(), 1, 2, 0, 8, false);
    for blk in [&b3, &b4] {
        assert_eq!(receive(&mut bc, blk), ReceiveBlockOutcome::AcceptedSilently);
    }
    let b5 = real_on(
        &bc,
        &tx_block(5, b4.view().hash(), 0, votes_for(5, 0, 1, 9)),
        0,
        1,
    );
    assert_eq!(receive(&mut bc, &b5), ReceiveBlockOutcome::AcceptedSilently);
    let before = bc.active_branch_value;
    let snapshot = snapshot_block(&bc, 6, b5.view().hash());
    bc.storage.failing_read_slot = 1; // #1 becomes the tail
    assert_eq!(
        receive(&mut bc, &snapshot),
        ReceiveBlockOutcome::AcceptedSilently
    );
    assert_eq!(head_of(&bc), (5, b5.view().hash()), "not extended");
    assert_eq!(status_of(&bc, &snapshot), Some(BlockStatus::Stored));
    assert_eq!(bc.active_branch_value, before);
    assert_eq!(bc.active_snake_chain_window(), Ok((0, 5)));

    bc.storage.failing_read_slot = NONE_REF;
    let unrelated = node_transfer_block(3, 3, 2, 7);
    assert_eq!(
        receive(&mut bc, &unrelated),
        ReceiveBlockOutcome::AcceptedSilently
    );
    assert_eq!(
        head_of(&bc),
        (6, snapshot.view().hash()),
        "the retry extended"
    );
    assert_eq!(bc.active_snake_chain_window(), Ok((1, 6)));
    assert_eq!(v(&b4), 2010);
    assert_eq!(
        bc.active_branch_value,
        v(&b2) + v(&b3) + v(&b4) + v(&b5) + v(&snapshot)
    );
    assert_eq!(
        bc.active_branch_value,
        brute_value(&bc, bc.active_chain_head_idx)
    );
}

/// AC10.2 / AC4 — event (i) for both entry points: a direct extension, and
/// a continuation over a stored orphan.
#[test]
fn branch_value_follows_direct_and_continuation_extensions() {
    let (mut bc, _, b1) = ready_genesis(16);
    let b2 = alt(2, b1.view().hash(), 0, 0, 5, 7, true);
    assert_eq!(receive(&mut bc, &b2), ReceiveBlockOutcome::AcceptedSilently);
    assert_eq!(bc.active_branch_value, v(&b2));
    let b3 = alt(3, b2.view().hash(), 1, 5, 3, 8, false);
    let b4 = alt(4, b3.view().hash(), 0, 3, 7, 9, false);
    assert_eq!(receive(&mut bc, &b4), ReceiveBlockOutcome::AcceptedSilently);
    assert_eq!(receive(&mut bc, &b3), ReceiveBlockOutcome::AcceptedSilently);
    assert_eq!(head_of(&bc), (4, b4.view().hash()));
    assert_eq!((v(&b3), v(&b4)), (5025, 3015), "distinct real values");
    assert_eq!(bc.active_branch_value, v(&b2) + v(&b3) + v(&b4));
    assert_eq!(
        bc.active_branch_value,
        brute_value(&bc, bc.active_chain_head_idx)
    );
}

/// Two siblings of `parent` (node #0's, which gave node #1 `credits`) at
/// `seq`: node #1's, worth its real `I(1000 · credits)`, and node #0's side
/// block with the free value `low`, where the higher-valued one has the
/// higher hash — so the hash alone would pick the other. Returns
/// `(high, low)`.
fn ranked_pair(seq: u32, parent: [u8; 32], credits: u32, low: u32) -> (Block, Block) {
    for amount in 10..200 {
        let h = alt(seq, parent, 1, credits, 0, amount, false);
        let l = valued(seq, parent, low, amount + 1000);
        if h.view().hash() > l.view().hash() {
            return (h, l);
        }
    }
    panic!("no pair found");
}

/// AC10.6 / AC8 — the continuation's sibling choice is the FR21 rank: the
/// higher value wins over a lower hash, and on an equal value the larger
/// block wins. The other sibling becomes a Connected side head.
#[test]
fn sibling_choice_follows_the_fr21_rank() {
    let (mut bc, _, b1) = ready_genesis(16);
    let parent = alt(2, b1.view().hash(), 0, 0, 9, 7, true);
    let (high, low) = ranked_pair(3, parent.view().hash(), 9, 4);
    for blk in [&low, &high, &parent] {
        assert_eq!(receive(&mut bc, blk), ReceiveBlockOutcome::AcceptedSilently);
    }
    assert_eq!(head_of(&bc), (3, high.view().hash()), "value before hash");
    let li = slot(&bc, &low);
    assert_eq!(status_of(&bc, &low), Some(BlockStatus::Connected));
    assert_eq!(bc.chain_heads.branch_value_of(li), Some(v(&parent) + 4));
    assert_eq!(
        bc.chain_heads.branch_value_of(li),
        Some(brute_value(&bc, li))
    );

    // Equal value: the larger block wins, even with the higher hash.
    // `large` is node #1's real block (two transactions); `small` a side
    // block with the same free value.
    let (mut bc, _, b1) = ready_genesis(16);
    let parent = alt(2, b1.view().hash(), 0, 0, 6, 7, true);
    let prev = parent.view().hash();
    let (large, small) = (0..200)
        .find_map(|amount| {
            let large = resign(
                &tx_block(3, prev, 0, |b| {
                    votes_for(3, 1, 2, amount)(b);
                }),
                1,
                vote_snapshot(6000),
                NODE_ONE_KEY,
            );
            let small = valued(3, prev, vote_snapshot(6000), amount + 1000);
            (large.view().hash() > small.view().hash()).then_some((large, small))
        })
        .expect("a pair");
    for blk in [&small, &large, &parent] {
        assert_eq!(receive(&mut bc, blk), ReceiveBlockOutcome::AcceptedSilently);
    }
    assert_eq!(head_of(&bc), (3, large.view().hash()), "size before hash");
    // Chosen by rank, not left over by a Tier 3 refusal of `small`.
    assert_eq!(status_of(&bc, &small), Some(BlockStatus::Connected));
    assert_eq!(
        bc.chain_heads.branch_value_of(slot(&bc, &small)),
        Some(v(&parent) + v(&small))
    );
}

/// AC8 (code review 2026-10-20) — an unreadable sibling is a local
/// failure, never a choice: the continuation stops with both siblings
/// Stored, and ranks them once the fault clears.
#[test]
fn unreadable_sibling_stops_the_continuation() {
    let (mut bc, b1) = faulty_genesis(16);
    let parent = alt(2, b1.view().hash(), 0, 0, 9, 7, true);
    let (high, low) = ranked_pair(3, parent.view().hash(), 9, 4);
    for blk in [&low, &high] {
        assert_eq!(receive(&mut bc, blk), ReceiveBlockOutcome::AcceptedSilently);
    }
    bc.storage.failing_read_slot = slot(&bc, &high);
    assert_eq!(
        receive(&mut bc, &parent),
        ReceiveBlockOutcome::AcceptedSilently
    );
    assert_eq!(
        head_of(&bc),
        (2, parent.view().hash()),
        "the continuation stopped"
    );
    assert_eq!(status_of(&bc, &high), Some(BlockStatus::Stored));
    assert_eq!(
        status_of(&bc, &low),
        Some(BlockStatus::Stored),
        "not taken instead"
    );

    bc.storage.failing_read_slot = NONE_REF;
    let unrelated = node_transfer_block(9, 3, 8, 7);
    assert_eq!(
        receive(&mut bc, &unrelated),
        ReceiveBlockOutcome::AcceptedSilently
    );
    assert_eq!(
        head_of(&bc),
        (3, high.view().hash()),
        "ranked after the fault"
    );
    let li = slot(&bc, &low);
    assert_eq!(status_of(&bc, &low), Some(BlockStatus::Connected));
    assert_eq!(
        bc.chain_heads.branch_value_of(li),
        Some(brute_value(&bc, li))
    );
}

/// AC10.4 / AC10.12 / D4 — side blocks with a Connected or Active parent
/// are judged before their write: a fork from an older active block, the
/// extension of a Connected side head (incremental, no read of it), and a
/// fork from an interior Connected block — each Connected and valued as
/// the brute force; the active value is untouched.
#[test]
fn side_blocks_are_judged_before_their_write_and_valued() {
    let (mut bc, b1) = faulty_genesis(16);
    let a2 = alt(2, b1.view().hash(), 0, 0, 2, 7, true);
    let a3 = alt(3, a2.view().hash(), 1, 2, 0, 8, false);
    for blk in [&a2, &a3] {
        assert_eq!(receive(&mut bc, blk), ReceiveBlockOutcome::AcceptedSilently);
    }
    let active = bc.active_branch_value;
    assert_eq!(active, v(&a2) + v(&a3));

    let f3 = valued(3, a2.view().hash(), 9, 20);
    assert_eq!(receive(&mut bc, &f3), ReceiveBlockOutcome::AcceptedSilently);
    let fi = slot(&bc, &f3);
    assert_eq!(status_of(&bc, &f3), Some(BlockStatus::Connected));
    assert_eq!(bc.chain_heads.branch_value_of(fi), Some(v(&a2) + 9));
    assert_eq!(
        bc.chain_heads.branch_value_of(fi),
        Some(brute_value(&bc, fi))
    );

    // The extension reads nothing of itself: its slot's reads fail.
    let f4 = valued(4, f3.view().hash(), 4, 21);
    bc.storage.failing_read_slot = bc.blocks.next_free_index().expect("a slot");
    assert_eq!(receive(&mut bc, &f4), ReceiveBlockOutcome::AcceptedSilently);
    bc.storage.failing_read_slot = NONE_REF;
    let f4i = slot(&bc, &f4);
    assert_eq!(status_of(&bc, &f4), Some(BlockStatus::Connected));
    assert_eq!(bc.chain_heads.branch_value_of(f4i), Some(v(&a2) + 9 + 4));
    assert_eq!(
        bc.chain_heads.branch_value_of(f4i),
        Some(brute_value(&bc, f4i))
    );

    // f3 is interior now: a second child of it is a fork, walked.
    let g4 = valued(4, f3.view().hash(), 6, 22);
    assert_eq!(receive(&mut bc, &g4), ReceiveBlockOutcome::AcceptedSilently);
    let gi = slot(&bc, &g4);
    assert_eq!(status_of(&bc, &g4), Some(BlockStatus::Connected));
    assert_eq!(bc.chain_heads.branch_value_of(gi), Some(v(&a2) + 9 + 6));
    assert_eq!(
        bc.chain_heads.branch_value_of(gi),
        Some(brute_value(&bc, gi))
    );
    assert_eq!(
        bc.active_branch_value, active,
        "side blocks leave the active value"
    );
    assert_eq!(head_of(&bc), (3, a3.view().hash()));
}

/// [`faulty_utxo_genesis`] with one more active block, so the mint at #3
/// is an older active block a side branch can fork from. Returns the node,
/// the mint and #4.
fn utxo_side_fixture() -> (Chain16<FaultyStorage>, Block, Block) {
    let (mut bc, mint) = faulty_utxo_genesis();
    // Node #1's, credited once by the mint: worth `I(1000)` = 1005 (I-09),
    // above the free values the side blocks of these Tier 2 tests carry,
    // so none of them is switched to (Story 6.3).
    let b4 = real_on(&bc, &transfer(4, mint.view().hash(), 0, 7), 1, NODE_ONE_KEY);
    assert_eq!(receive(&mut bc, &b4), ReceiveBlockOutcome::AcceptedSilently);
    (bc, mint, b4)
}

/// A side block at `seq` on `prev` spending `(3, index)` with the declared
/// `amount` into one UTXO output.
fn side_spend(seq: u32, prev: [u8; 32], index: u16, amount: u64) -> Block {
    let tx = utxo_tx(seq, &[(3, index, amount)], None, &[Ok(amount)]);
    complex_tx_block(seq, prev, 0, 0, &[&tx])
}

/// AC10.7 / AC10.12 — a side block failing Tier 2 at intake is refused and
/// nothing is stored: a declared amount other than the output's, an output
/// index beyond the referenced block's outputs, and a fork from an interior
/// Connected block.
#[test]
fn side_block_failing_tier2_at_intake_is_not_stored() {
    for (index, amount) in [(0, 61), (5, 60)] {
        let (mut bc, mint, _) = utxo_side_fixture();
        let (twin, _, _) = utxo_side_fixture();
        let bad = side_spend(4, mint.view().hash(), index, amount);
        let free = bc.blocks.next_free_index().expect("a free slot");
        assert_eq!(
            receive(&mut bc, &bad),
            ReceiveBlockOutcome::Rejected(RejectReason::InvalidEvidence)
        );
        assert_same_state(&bc, &twin, "refused side block");
        assert_eq!(bc.blocks.next_free_index(), Some(free), "no slot used");
        assert!(same_slot(&bc, &twin, free), "storage unchanged");
    }

    // A fork from an interior Connected block is refused the same way.
    let (mut bc, mint, _) = utxo_side_fixture();
    let p4 = valued(4, mint.view().hash(), 4, 30);
    let p5 = valued(5, p4.view().hash(), 5, 31);
    for blk in [&p4, &p5] {
        assert_eq!(receive(&mut bc, blk), ReceiveBlockOutcome::AcceptedSilently);
    }
    let free = bc.blocks.next_free_index().expect("a free slot");
    let bad = side_spend(5, p4.view().hash(), 0, 61);
    assert_eq!(
        receive(&mut bc, &bad),
        ReceiveBlockOutcome::Rejected(RejectReason::InvalidEvidence)
    );
    assert_eq!(bc.blocks.next_free_index(), Some(free), "no slot used");

    // The matching amount passes: Connected, no bit touched.
    let (mut bc, mint, _) = utxo_side_fixture();
    let good = side_spend(4, mint.view().hash(), 0, 60);
    assert_eq!(
        receive(&mut bc, &good),
        ReceiveBlockOutcome::AcceptedSilently
    );
    assert_eq!(status_of(&bc, &good), Some(BlockStatus::Connected));
    assert_eq!(bc.blocks.utxo_available(slot(&bc, &mint), 0), Some(true));
}

/// AC6 / D4 — a local failure inside the pre-store Tier 2 is no evidence:
/// the block is stored Stored, and the driver connects it once the fault
/// clears.
#[test]
fn tier2_read_failure_at_intake_is_retried_by_the_driver() {
    let (mut bc, mint, _) = utxo_side_fixture();
    let good = side_spend(4, mint.view().hash(), 0, 60);
    bc.storage.failing_read_slot = slot(&bc, &mint);
    assert_eq!(
        receive(&mut bc, &good),
        ReceiveBlockOutcome::AcceptedSilently
    );
    assert_eq!(
        status_of(&bc, &good),
        Some(BlockStatus::Stored),
        "not blamed"
    );

    bc.storage.failing_read_slot = NONE_REF;
    let unrelated = node_transfer_block(9, 3, 8, 7);
    assert_eq!(
        receive(&mut bc, &unrelated),
        ReceiveBlockOutcome::AcceptedSilently
    );
    let gi = slot(&bc, &good);
    assert_eq!(status_of(&bc, &good), Some(BlockStatus::Connected));
    assert_eq!(
        bc.chain_heads.branch_value_of(gi),
        Some(brute_value(&bc, gi))
    );
}

/// AC10.5 / AC10.7 / D8 — an orphan side chain stored before its Tier 2
/// could run: its parent's arrival connects it, the driver finds the
/// failing block, deletes it with its descendants, and values the entry
/// retargeted onto the surviving Connected parent. The active state is
/// untouched and the node stays Ready. Each failure kind: a declared amount
/// other than the output's, an output index beyond it, a reference more
/// than `W` back.
#[test]
fn driver_deletes_a_failing_side_block_and_values_the_retarget() {
    for (index, amount) in [(0, 61), (5, 60)] {
        let (mut bc, mint, _) = utxo_side_fixture();
        let (twin, _, _) = utxo_side_fixture();
        let p4 = valued(4, mint.view().hash(), 4, 30);
        let bad5 = revalue(&side_spend(5, p4.view().hash(), index, amount), 5);
        let c6 = valued(6, bad5.view().hash(), 6, 31);
        for blk in [&c6, &bad5, &p4] {
            assert_eq!(receive(&mut bc, blk), ReceiveBlockOutcome::AcceptedSilently);
        }
        assert_eq!(status_of(&bc, &bad5), None, "deleted");
        assert_eq!(status_of(&bc, &c6), None, "with its descendant");
        let pi = slot(&bc, &p4);
        assert_eq!(status_of(&bc, &p4), Some(BlockStatus::Connected));
        assert_eq!(
            bc.chain_heads.branch_value_of(pi),
            Some(brute_value(&bc, pi))
        );
        assert!(bc.is_ready());
        assert!(bc.node_info == twin.node_info);
        assert!(bc.vote_engine == twin.vote_engine);
        assert_eq!(bc.active_branch_value, twin.active_branch_value);
        for bit in 0..2 {
            assert_eq!(
                bc.blocks.utxo_available(slot(&bc, &mint), bit),
                twin.blocks.utxo_available(slot(&twin, &mint), bit),
                "active available-UTXO bits untouched"
            );
        }
    }

    // A reference more than `W` back, on the W6 window. The side branch
    // forks inside FR58's bound (`A = S_head − H`, DEC-208) and is worth
    // less than the active branch, so no switch is attempted. `far` sits
    // off the clean slots (Story 6.7 D8), its parent `p104` on one.
    let (mut bc, [_, _, _, b103, _, _]) = valued_w6();
    let p104 = revalue(&salted_linked_block(104, b103.view().hash(), 6), 1);
    let tx = utxo_tx(105, &[(98, 0, 50)], None, &[Ok(50)]);
    let far = complex_tx_block(105, p104.view().hash(), 0, 0, &[&tx]);
    for blk in [&far, &p104] {
        assert_eq!(
            bc.receive_block(blk.view(), 0).0,
            ReceiveBlockOutcome::AcceptedSilently
        );
    }
    assert!(
        bc.blocks.find(105, &far.view().hash()).is_none(),
        "deleted by the driver"
    );
    let pi = slot(&bc, &p104);
    assert_eq!(
        bc.blocks.get(pi).map(|e| e.status()),
        Some(BlockStatus::Connected)
    );
    assert_eq!(
        bc.chain_heads.branch_value_of(pi),
        Some(brute_value(&bc, pi))
    );

    // A valid orphan chain connects whole.
    let (mut bc, mint, _) = utxo_side_fixture();
    let p4 = valued(4, mint.view().hash(), 4, 30);
    let q5 = valued(5, p4.view().hash(), 5, 31);
    let q6 = valued(6, q5.view().hash(), 6, 32);
    for blk in [&q6, &q5, &p4] {
        assert_eq!(receive(&mut bc, blk), ReceiveBlockOutcome::AcceptedSilently);
    }
    for blk in [&p4, &q5, &q6] {
        assert_eq!(status_of(&bc, blk), Some(BlockStatus::Connected));
    }
    let qi = slot(&bc, &q6);
    assert_eq!(
        bc.chain_heads.branch_value_of(qi),
        Some(brute_value(&bc, qi))
    );
}

/// AC10.8 / D6; Story 6.14 AC4 — a side block's UTXO reference into the
/// verification horizon resolves against the retained block: it is no
/// longer trusted pre-window history, so an output the horizon block does
/// not hold is evidence. More than `W` back it is evidence too.
#[test]
fn side_reference_into_the_horizon_is_resolved() {
    let (mut bc, [_, _, b102, _, _, _]) = valued_w6();
    let tx = utxo_tx(103, &[(99, 0, 50)], None, &[Ok(50)]);
    let missing = complex_tx_block(103, b102.view().hash(), 0, 0, &[&tx]);
    assert_eq!(
        bc.receive_block(missing.view(), 0).0,
        ReceiveBlockOutcome::Rejected(RejectReason::InvalidEvidence),
        "#99 is retained and holds no output 0"
    );

    let tx = utxo_tx(103, &[(96, 0, 50)], None, &[Ok(50)]);
    let too_far = complex_tx_block(103, b102.view().hash(), 0, 0, &[&tx]);
    assert_eq!(
        bc.receive_block(too_far.view(), 0).0,
        ReceiveBlockOutcome::Rejected(RejectReason::InvalidEvidence)
    );
}

/// AC10.9 — a read failure during the side walk changes nothing; the next
/// admission connects the branch.
#[test]
fn side_walk_read_failure_is_retried() {
    let (mut bc, mint, _) = utxo_side_fixture();
    let p4 = valued(4, mint.view().hash(), 4, 30);
    let q5 = valued(5, p4.view().hash(), 5, 31);
    assert_eq!(receive(&mut bc, &q5), ReceiveBlockOutcome::AcceptedSilently);
    bc.storage.failing_read_slot = slot(&bc, &q5);
    assert_eq!(receive(&mut bc, &p4), ReceiveBlockOutcome::AcceptedSilently);
    assert_eq!(status_of(&bc, &p4), Some(BlockStatus::Connected));
    assert_eq!(
        status_of(&bc, &q5),
        Some(BlockStatus::Stored),
        "left pending"
    );

    bc.storage.failing_read_slot = NONE_REF;
    let unrelated = node_transfer_block(9, 3, 8, 7);
    assert_eq!(
        receive(&mut bc, &unrelated),
        ReceiveBlockOutcome::AcceptedSilently
    );
    let qi = slot(&bc, &q5);
    assert_eq!(status_of(&bc, &q5), Some(BlockStatus::Connected));
    assert_eq!(
        bc.chain_heads.branch_value_of(qi),
        Some(brute_value(&bc, qi))
    );
}

/// AC10.11 / AC9.3 — two admission orders of one block set hold the same
/// values and statuses; a restart rebuilds them.
#[test]
fn branch_values_are_order_independent_and_survive_a_restart() {
    let build = |order: &[usize]| {
        let (mut bc, _, b1) = ready_genesis(16);
        let a2 = alt(2, b1.view().hash(), 0, 0, 2, 7, true);
        let a3 = alt(3, a2.view().hash(), 1, 2, 3, 8, false);
        let a4 = alt(4, a3.view().hash(), 0, 3, 4, 9, false);
        let a5 = alt(5, a4.view().hash(), 1, 4, 0, 10, false);
        let f3 = valued(3, a2.view().hash(), 9, 20);
        let f4 = valued(4, f3.view().hash(), 6, 21);
        let blocks = [a2, a3, a4, a5, f3, f4];
        for &i in order {
            assert_eq!(
                receive(&mut bc, &blocks[i]),
                ReceiveBlockOutcome::AcceptedSilently
            );
        }
        (bc, blocks)
    };
    let (x, blocks) = build(&[0, 1, 2, 3, 4, 5]);
    // The side branch before the active extensions, child first.
    let (y, _) = build(&[0, 1, 5, 4, 2, 3]);
    assert_eq!(x.active_branch_value, y.active_branch_value);
    assert_eq!(
        x.active_branch_value,
        brute_value(&x, x.active_chain_head_idx)
    );
    for blk in &blocks {
        assert_eq!(status_of(&x, blk), status_of(&y, blk));
        let (xi, yi) = (slot(&x, blk), slot(&y, blk));
        if x.blocks.get(xi).map(|e| e.status()) == Some(BlockStatus::Connected) {
            assert_eq!(
                x.chain_heads.branch_value_of(xi),
                y.chain_heads.branch_value_of(yi)
            );
        }
    }
    let f4 = &blocks[5];
    let fi = slot(&x, f4);
    assert_eq!(x.chain_heads.branch_value_of(fi), Some(brute_value(&x, fi)));

    let reference_active = x.active_branch_value;
    let reference_side = x.chain_heads.branch_value_of(fi);
    let mut restarted = restart(x);
    let _ = restarted.initialize_from_storage(0);
    assert!(restarted.is_ready());
    assert_eq!(restarted.active_branch_value, reference_active);
    let ri = slot(&restarted, f4);
    assert_eq!(
        restarted.blocks.get(ri).map(|e| e.status()),
        Some(BlockStatus::Connected)
    );
    assert_eq!(restarted.chain_heads.branch_value_of(ri), reference_side);
}
// ===================================================================
// Story 6.2 — FR22 re-evaluation, FR28 two-stage scoring, I-09, D6
// ===================================================================

/// A transaction block with explicit vote header fields, signed with
/// `[key; 32]` — deviation blocks and malformed headers.
#[allow(clippy::too_many_arguments)]
fn headed(
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

/// The FR22 decision observed through the FR23 switch (Story 6.3): a
/// winner with a forged value (a free header, [`valued`]) is attempted,
/// refused by the replay's I-09 check and deleted with its descendants —
/// the block is gone while the active head stayed.
fn attempted<S: StorageTrait>(bc: &Chain16<S>, block: &Block) -> bool {
    status_of(bc, block).is_none()
}

/// A genesis node on `W = 16` with `a2` (node #0's, registering node #1
/// and crediting it once) and `a3` (node #1's, worth 1005).
fn two_creator_chain() -> (TestChain, Block, Block, Block) {
    let (mut bc, _, b1) = ready_genesis(16);
    let a2 = alt(2, b1.view().hash(), 0, 0, 1, 7, true);
    let a3 = alt(3, a2.view().hash(), 1, 1, 0, 8, false);
    for blk in [&a2, &a3] {
        assert_eq!(receive(&mut bc, blk), ReceiveBlockOutcome::AcceptedSilently);
    }
    assert_eq!(bc.active_branch_value, 1005);
    (bc, b1, a2, a3)
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
/// blocks is (Story 6.0's FR3 equivalence). A forged twin of the winner is
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
    let (mut j, twin) = (joiner(), joiner());

    // The winner: the same replay by #3, worth its real vote at #101.
    let replay = balance_block(102, b101.view().hash(), &entries, 4);
    let f102 = resign(&replay, 3, vote_snapshot(1000), 1);
    assert!(v(&f102) > v(&seed), "the replay by #3 outranks the head");

    // A forged twin: attempted, refused by the replay (I-09), restored.
    let forged = resign(&replay, 3, vote_snapshot(1000) + 1, 1);
    assert_eq!(
        j.receive_block(forged.view(), 0).0,
        ReceiveBlockOutcome::AcceptedSilently
    );
    assert!(
        j.blocks.find(102, &forged.view().hash()).is_none(),
        "deleted"
    );
    assert!(j.node_info == twin.node_info);
    assert!(j.vote_engine == twin.vote_engine);
    assert_eq!(j.active_branch_value, twin.active_branch_value);

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

// ---- Story 6.15: the chain's node cap (DEC-228) ----

/// A configuration declaring the window `w`, its test horizon and the node
/// cap `cap` instead of [`TEST_MAX_NODES`].
fn capped_config_builder(w: u32, cap: u32) -> ChainConfigPayloadBuilder {
    let mut builder = ChainConfigPayloadBuilder::new();
    for (id, value) in [
        (parameter::ACTIVE_CHAIN_LENGTH, w),
        (parameter::VERIFICATION_HORIZON, test_horizon(w)),
        (parameter::MAX_NODE_COUNT, cap),
    ] {
        builder
            .add_literal(id, &value.to_le_bytes())
            .ok()
            .expect("a four-byte literal is well-formed");
    }
    declare_build_scheme(&mut builder);
    builder
}

/// AC10: at a Ready head extension a registration at `max_node_count` is
/// exact evidence, and one below it is accepted and seeds its key. The cap
/// is the chain's 2, far below the build's `MAX_NODES` (16), so only the
/// chain rule can refuse it.
#[test]
fn fr6_registration_at_the_node_cap_is_evidence_in_ready() {
    let (crypto, storage, chain_config) = test_backends();
    let mut bc = new_chain(crypto, storage, chain_config, 0, 0);
    let genesis = bc
        .process_genesis(CURRENCY, capped_config_builder(TEST_W, 2).content())
        .ok()
        .expect("genesis succeeds");
    assert!(bc.is_ready());

    let one = register(2, genesis.block_one.view().hash(), 1, 0x31);
    assert_eq!(
        receive(&mut bc, &one),
        ReceiveBlockOutcome::AcceptedSilently
    );
    assert_eq!(head_of(&bc).1, one.view().hash());
    assert!(bc.node_info.is_seeded(1), "an id below the cap registers");

    let two = register(3, one.view().hash(), 2, 0x32);
    assert_eq!(
        receive(&mut bc, &two),
        ReceiveBlockOutcome::Rejected(RejectReason::InvalidEvidence)
    );
    assert_eq!(head_of(&bc).1, one.view().hash());
    assert!(!bc.node_info.is_seeded(2));
    assert_eq!(bc.node_info.max_known_node_id(), 1);

    // The contrast: the same blocks on a chain whose cap is 3 are both
    // accepted, so only the cap refused the registration above.
    let (crypto, storage, chain_config) = test_backends();
    let mut wide = new_chain(crypto, storage, chain_config, 0, 0);
    let wide_genesis = wide
        .process_genesis(CURRENCY, capped_config_builder(TEST_W, 3).content())
        .ok()
        .expect("genesis succeeds");
    let one = register(2, wide_genesis.block_one.view().hash(), 1, 0x31);
    assert_eq!(
        receive(&mut wide, &one),
        ReceiveBlockOutcome::AcceptedSilently
    );
    let two = register(3, one.view().hash(), 2, 0x32);
    assert_eq!(
        receive(&mut wide, &two),
        ReceiveBlockOutcome::AcceptedSilently
    );
    assert!(wide.node_info.is_seeded(2));
}

/// AC10: the FR3 pass applies the same rule to a registration (here the
/// fixture cap, `TEST_MAX_NODES` = 16, with the watermark at 15, so the id
/// is otherwise the expected next one).
#[test]
fn fr6_registration_at_the_node_cap_is_evidence_in_the_pass() {
    let mut bc = new_test_chain();
    let cfg_hash = admit_chain_config_anchor(&mut bc, 99, [0xAB; 32]);
    let anchor = balance_block(100, cfg_hash, &[(1, 500, 10, 0x31)], TEST_MAX_NODES - 1);
    bc.tier1_admit(&anchor.view(), &anchor.view().hash(), 0)
        .expect("anchor admitted");
    let reg = registration_block(101, anchor.view().hash(), 1, TEST_MAX_NODES, 0x43);
    let ri = bc
        .tier1_admit(&reg.view(), &reg.view().hash(), 0)
        .expect("registration admitted");
    assert_eq!(
        bc.run_processing_pass(ri).map(|_| ()),
        Err(ProcessingError::Invalid {
            block_idx: ri,
            reason: ValidationReason::NodeCountExceeded,
        })
    );
}

/// AC10: the equality the guard removal rests on — the cap equals the
/// build's `MAX_NODES` (16) — and the last id below it registers and gets
/// its slot.
#[test]
fn fr6_registration_just_below_the_node_cap_registers() {
    let mut bc = new_test_chain();
    let cfg_hash = admit_chain_config_anchor(&mut bc, 99, [0xAB; 32]);
    let anchor = balance_block(100, cfg_hash, &[(1, 500, 10, 0x31)], TEST_MAX_NODES - 2);
    bc.tier1_admit(&anchor.view(), &anchor.view().hash(), 0)
        .expect("anchor admitted");
    let reg = registration_block(101, anchor.view().hash(), 1, TEST_MAX_NODES - 1, 0x43);
    let ri = bc
        .tier1_admit(&reg.view(), &reg.view().hash(), 0)
        .expect("registration admitted");
    assert!(bc.run_processing_pass(ri).is_ok());
    assert!(bc.node_info.is_seeded(TEST_MAX_NODES - 1));
    assert_eq!(bc.node_info.max_known_node_id(), TEST_MAX_NODES - 1);
}

/// AC10: a balance block naming an id at the cap is exact evidence; one just
/// below it is not refused by the rule.
#[test]
fn fr6_balance_block_at_the_node_cap_is_evidence() {
    let mut bc = new_test_chain();
    let cfg_hash = admit_chain_config_anchor(&mut bc, 99, [0xAB; 32]);
    let over = balance_block(100, cfg_hash, &[(1, 500, 10, 0x31)], TEST_MAX_NODES);
    let oi = bc
        .tier1_admit(&over.view(), &over.view().hash(), 0)
        .expect("admitted");
    // The over-cap block is the floor of this window-anchored candidate: it
    // is condemned before it can seed the watermark.
    assert_eq!(
        bc.run_processing_pass(oi).map(|_| ()),
        Err(ProcessingError::Invalid {
            block_idx: oi,
            reason: ValidationReason::NodeCountExceeded,
        })
    );

    let mut bc = new_test_chain();
    let cfg_hash = admit_chain_config_anchor(&mut bc, 99, [0xAB; 32]);
    let at_limit = balance_block(100, cfg_hash, &[(1, 500, 10, 0x31)], TEST_MAX_NODES - 1);
    let ai = bc
        .tier1_admit(&at_limit.view(), &at_limit.view().hash(), 0)
        .expect("admitted");
    assert!(bc.run_processing_pass(ai).is_ok());
}

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

/// Whether `block` is held with its creator signature marked verified.
fn verified<S: StorageTrait>(bc: &Chain16<S>, block: &Block) -> Option<bool> {
    let view = block.view();
    bc.blocks
        .find(view.sequence(), &view.hash())
        .and_then(|idx| bc.blocks.get(idx))
        .map(|entry| entry.is_signature_verified())
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

use crate::approval::node_value;
use crate::approval::test_seams::set_grace_admits;

/// `block`'s transaction or balance payload under a new header:
/// `creator`, signed with `[key; 32]`, with the given vote fields (the
/// deviation form of [`resign`]).
fn reheader(
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
fn balance_snapshot<S: StorageTrait>(
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
fn key_of(n: u32) -> u8 {
    assert!(n < 0x44, "a fixture key byte must stay below 0x74");
    if n == 0 { 1 } else { 0x30 + n as u8 }
}

/// A node with its own key and id over `storage`, trusting node #0's key
/// as the FR69 anchor, not yet configured.
fn local_node<S: StorageTrait>(local: u32, storage: S) -> Chain16<S> {
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

fn local_storage(local: u32) -> SupportStorage {
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

type SupportChain = Chain16<SupportStorage>;

/// The Story 6.4 chain on `W = w` (configuration `extra` added): genesis
/// by node #0, then `a2` (node #0, registering nodes 1..=5), `a3` (node 1,
/// one credit for node 4), `a4` (node 4, three for node 1) and `a5` (node
/// 3, one for node 5). At #5 node 1 tops the order (`u = 1`), node 5 holds
/// 1000 and nodes 0, 2, 3 and 4 hold 0; `A = {0, 1, 3, 4}`; node 2 is
/// registered but never creates. Returns the builder `g` (node #0, local
/// id 0), the `local` node fed the same blocks over `storage`, Ready, and
/// the blocks `b0..=a5`.
fn support_chain_on<S: StorageTrait>(
    local: u32,
    storage: S,
    w: u32,
    extra: impl FnOnce(&mut ChainConfigPayloadBuilder),
) -> (SupportChain, Chain16<S>, [Block; 6]) {
    let mut g = local_node(0, local_storage(0));
    let mut config = window_config_builder(w);
    extra(&mut config);
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

fn support_chain(local: u32) -> (SupportChain, SupportChain, [Block; 6]) {
    support_chain_on(local, local_storage(local), 16, |_| {})
}

/// A deviation by `creator` on `prev` (the active head of `g`), its
/// transaction from `salt`.
fn deviation_after(g: &SupportChain, prev: &Block, creator: u32, salt: u64) -> Block {
    let seq = prev.view().sequence() + 1;
    let template = tx_block(seq, prev.view().hash(), 0, votes_for(seq, 0, 1, salt));
    deviation_on(g, &template, creator)
}

/// A normal-form block by `creator` on `prev` (the active head of `g`).
fn normal_after(g: &SupportChain, prev: &Block, creator: u32, salt: u64) -> Block {
    let seq = prev.view().sequence() + 1;
    let template = tx_block(seq, prev.view().hash(), 0, votes_for(seq, 0, 1, salt));
    real_on(g, &template, creator, key_of(creator))
}

/// The support `node` sends for `block`, if any.
fn support_for<S: StorageTrait>(node: &mut Chain16<S>, block: &Block) -> Option<SupportMessage> {
    match receive(node, block) {
        ReceiveBlockOutcome::AcceptedAndSendSupport(message) => Some(message),
        ReceiveBlockOutcome::AcceptedSilently => None,
        other => panic!("unexpected outcome {other:?}"),
    }
}

/// AC9 3c — the active set equals a window walk recomputed from storage.
fn assert_active_set_matches<
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
            let template = tx_block(seq, prev_hash, 0, votes_for(seq, 0, 1, 500 + seq as u64));
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

/// The body `message` travels as (DEC-229): its sequence, then
/// [`support_body_tail`].
fn body_of(message: &SupportMessage) -> [u8; 44 + MULTI_SIGNATURE_SIZE] {
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
fn support_by(supporter: u32, proposer: u32, p: u32, hash: [u8; 32]) -> SupportMessage {
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
fn forged(mut message: SupportMessage) -> SupportMessage {
    message.support_signature[MULTI_SIGNATURE_SIZE - 1] ^= 1;
    message
}

fn intake<S: StorageTrait>(
    node: &mut Chain16<S>,
    message: &SupportMessage,
) -> ReceiveSupportOutcome {
    let body = body_of(message);
    node.receive_support(SupportView::from_bytes(&body).expect("one body"), 0)
        .0
}

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

/// A light block by `u` (node 1) on #5: its own normal-form block at 6,
/// signed with its real key, whose hash is above every block in `beside`.
/// The equal-value siblings at 6 are retained in hash order, so a `u`-block
/// below the deviation would not be held at all. The hashes follow the
/// keys, which differ per signature scheme, so the vote's amount is
/// searched rather than fixed.
fn u_block(blocks: &[Block; 6], beside: &[&Block]) -> Block {
    (0..100_000)
        .map(|salt| {
            let template = tx_block(6, blocks[5].view().hash(), 0, votes_for(6, 0, 1, salt));
            reheader(&template, 1, 0, 1, 0, key_of(1))
        })
        .find(|u| beside.iter().all(|b| u.view().hash() > b.view().hash()))
        .expect("a u-block above its siblings")
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

// ---- Story 6.6: proposer-side accumulation and the evidence block ----

use crate::approval::test_seams::{SUBGROUP_EVALS, VERIFICATIONS, counted};
use moonblokz_crypto::{AGGREGATED_SIGNATURE_CONSTANT_SIZE, AGGREGATED_SIGNATURE_VARIABLE_SIZE};

/// The proposer `local` on Story 6.4's chain with its own deviation `d` at
/// 6 received (it becomes the active head: the direct case). Returns the
/// builder `g` (still at #5), the proposer, the blocks, `d` and its slot.
fn proposer_chain(local: u32) -> (SupportChain, SupportChain, [Block; 6], Block, u32) {
    let (g, mut l, blocks) = support_chain(local);
    let d = deviation_after(&g, &blocks[5], local, 1);
    assert_eq!(receive(&mut l, &d), ReceiveBlockOutcome::AcceptedSilently);
    assert_eq!(head_of(&l), (6, d.view().hash()), "d is active");
    let d_idx = l.blocks.find(6, &d.view().hash()).expect("d held");
    (g, l, blocks, d, d_idx)
}

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

/// Every node's accumulated vote: the engine's whole observable state.
fn engine_votes<S: StorageTrait>(bc: &Chain16<S>) -> [u32; 16] {
    core::array::from_fn(|n| bc.vote_engine.accumulated_vote_of(n as u32))
}

fn held<S: StorageTrait>(bc: &Chain16<S>) -> u8 {
    bc.approval.counts().2
}

/// The evidence payload fields a test checks: `(supporter_vote_sum,
/// deviation_sequence, m, bitmap, aggregate bytes, late entries)`.
struct Evidence {
    supporter_vote_sum: u64,
    deviation_sequence: u32,
    m: usize,
    bitmap: std::vec::Vec<u8>,
    aggregate: std::vec::Vec<u8>,
    late: std::vec::Vec<(u32, u32)>,
}

fn evidence_of(block: &Block, signers: usize) -> Evidence {
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

fn test_crypto() -> Crypto {
    Crypto::new([1u8; PRIVATE_KEY_SIZE]).ok().expect("key")
}

/// Proposer 2's deviation `d` held off the active chain: node 5's heavier
/// approval-less deviation `y@6` is the active head (DEC-200's sibling
/// case). Returns `g`, the proposer, the blocks, `d`, its slot and `y`.
fn sibling_proposer() -> (SupportChain, SupportChain, [Block; 6], Block, u32, Block) {
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
fn accumulate<S: StorageTrait>(bc: &mut Chain16<S>, d: &Block, d_idx: u32, n: usize) {
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

/// Puts `block` into `bc`'s table and storage as a retained entry with no
/// parent: a planted block (verified or not) for the evidence scans.
/// `stored == false` leaves its slot unwritten, so its read fails.
fn plant<S: StorageTrait>(bc: &mut Chain16<S>, block: &Block, verified: bool, stored: bool) {
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

type FailingSupportStorage = FailingReadStorage<{ 16 * MAX_BLOCK_SIZE + 8000 }>;

fn failing_storage(local: u32) -> FailingSupportStorage {
    FailingReadStorage {
        inner: local_storage(local),
        failing_slot: u32::MAX,
        reads_left: core::cell::Cell::new(0),
        failures_left: core::cell::Cell::new(u32::MAX),
        attempts: core::cell::Cell::new(0),
        reads: core::cell::Cell::new(0),
    }
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
/// with bytes after its last transaction, signed over all its wire bytes,
/// was accepted live and lost at restart (the restart trims it to its
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
    raw[signature_at..HEADER_SIZE].fill(0);
    let signer = Crypto::new([key_of(1); PRIVATE_KEY_SIZE])
        .ok()
        .expect("key");
    let signature = signer.sign(&raw);
    raw[signature_at..HEADER_SIZE].copy_from_slice(signature.serialize());
    let trailing = Block::from_bytes(&raw).ok().expect("parses");
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

/// [`plant`] with a parent: a retained child of `parent`.
fn plant_child<S: StorageTrait>(
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

// ---- Story 6.7: incoming approval-evidence validation ----

use crate::approval::test_seams::{AGGREGATE_VERIFICATIONS, TX_SIGNATURE_VERIFICATIONS};

/// `proposer`'s complete evidence for its own deviation `d@6` on Story
/// 6.4's chain (two supports, in rank order), with `d` and the subgroup.
fn evidence_by(proposer: u32) -> (Block, Block, std::vec::Vec<u32>) {
    let (_, mut l, _, d, d_idx) = proposer_chain(proposer);
    accumulate(&mut l, &d, d_idx, 2);
    let members = l.approval.members().to_vec();
    let e = l.build_evidence_block(d_idx, 0).expect("evidence");
    (d, e, members)
}

/// Story 6.4's builder `g` (node #0, Ready) at `proposer`'s deviation
/// `d@6`, and the evidence `proposer` built for it: a second node about to
/// judge it as a direct extension.
fn evidence_observer(proposer: u32) -> (SupportChain, Block, Block) {
    let (mut g, mut l, _, d, d_idx) = proposer_chain(proposer);
    accumulate(&mut l, &d, d_idx, 2);
    let e = l.build_evidence_block(d_idx, 0).expect("evidence");
    assert_eq!(receive(&mut g, &d), ReceiveBlockOutcome::AcceptedSilently);
    assert_eq!(head_of(&g), (6, d.view().hash()));
    (g, d, e)
}

/// An evidence block at `seq` on `prev` by `creator` in the FR27 override
/// header, its payload `ev` laid out per DEC-195, signed with the creator's
/// fixture key (so Tier 1's creator signature passes).
fn evidence_block(seq: u32, prev: [u8; 32], creator: u32, ev: &Evidence) -> Block {
    let signer = Crypto::new([key_of(creator); PRIVATE_KEY_SIZE])
        .ok()
        .expect("key");
    let header = BlockHeader {
        version: 1,
        sequence: seq,
        creator,
        mined_amount: 0,
        payload_type: PAYLOAD_TYPE_APPROVAL,
        consumed_votes: 0,
        first_voted_node: creator,
        consumed_votes_from_first_voted_node: 0,
        previous_hash: prev,
        signature: [0u8; SIGNATURE_SIZE],
    };
    let bitmap_end = APPROVAL_PREFIX_SIZE + ev.bitmap.len();
    let late_at = bitmap_end + ev.aggregate.len() + APPROVAL_LATE_COUNT_SIZE;
    let len = late_at + APPROVAL_LATE_ENTRY_SIZE * ev.late.len();
    let mut builder = BlockBuilder::new().header(header);
    let payload = builder.approval_payload_mut(len).ok().expect("room");
    payload[..APPROVAL_DEVIATION_SEQUENCE_OFFSET]
        .copy_from_slice(&ev.supporter_vote_sum.to_le_bytes());
    payload[APPROVAL_DEVIATION_SEQUENCE_OFFSET..APPROVAL_M_OFFSET]
        .copy_from_slice(&ev.deviation_sequence.to_le_bytes());
    payload[APPROVAL_M_OFFSET] = ev.m as u8;
    payload[APPROVAL_PREFIX_SIZE..bitmap_end].copy_from_slice(&ev.bitmap);
    payload[bitmap_end..bitmap_end + ev.aggregate.len()].copy_from_slice(&ev.aggregate);
    payload[late_at - APPROVAL_LATE_COUNT_SIZE..late_at]
        .copy_from_slice(&(ev.late.len() as u16).to_le_bytes());
    for (i, (id, vote)) in ev.late.iter().enumerate() {
        let at = late_at + APPROVAL_LATE_ENTRY_SIZE * i;
        payload[at..at + 4].copy_from_slice(&id.to_le_bytes());
        payload[at + 4..at + 8].copy_from_slice(&vote.to_le_bytes());
    }
    builder.build_signed(&signer).ok().expect("build signed")
}

/// `e` (with `signers` marked) under the same header, its payload
/// re-assembled after `mutate` and re-signed by its creator: one changed
/// field of a passing evidence block.
fn evidence_with(e: &Block, signers: usize, mutate: impl FnOnce(&mut Evidence)) -> Block {
    let mut ev = evidence_of(e, signers);
    mutate(&mut ev);
    let view = e.view();
    let prev: [u8; 32] = view.previous_hash().try_into().expect("32 bytes");
    evidence_block(view.sequence(), prev, view.creator(), &ev)
}

/// The serialized aggregate of `signers`' supports for `proposer`'s block
/// `hash` at `p`, in this order.
fn aggregate_by(signers: &[u32], proposer: u32, p: u32, hash: &[u8; 32]) -> std::vec::Vec<u8> {
    let message = support_message_bytes(proposer, p, hash);
    let crypto: std::vec::Vec<Crypto> = signers
        .iter()
        .map(|&n| {
            Crypto::new([key_of(n); PRIVATE_KEY_SIZE])
                .ok()
                .expect("key")
        })
        .collect();
    let signatures: std::vec::Vec<MultiSignature> =
        crypto.iter().map(|c| c.multi_sign(&message)).collect();
    let keys: std::vec::Vec<[u8; PUBLIC_KEY_SIZE]> =
        crypto.iter().map(|c| *c.public_key().serialize()).collect();
    let signature_refs: std::vec::Vec<&MultiSignature> = signatures.iter().collect();
    let key_refs: std::vec::Vec<&[u8; PUBLIC_KEY_SIZE]> = keys.iter().collect();
    let aggregate = test_crypto()
        .aggregate_signatures(&signature_refs, &key_refs, &message)
        .ok()
        .expect("aggregates");
    let mut out = std::vec![
        0u8;
        AGGREGATED_SIGNATURE_CONSTANT_SIZE
            + AGGREGATED_SIGNATURE_VARIABLE_SIZE * signers.len()
    ];
    let len = aggregate.serialize(&mut out).ok().expect("serializes");
    out.truncate(len);
    out
}

/// Ready's projection for a direct extension of `bc`'s head: the active-set
/// counter corrected from the physical tail.
fn ready_projection<S: StorageTrait>(bc: &Chain16<S>) -> Projection {
    Projection {
        counter_tail: bc.physical_counter_tail(),
        ..Projection::COMPLETE
    }
}

/// A window-anchored FR3 pass's projection with the anchor `a`: the roster
/// known and every node's vote seeded unless a test changes it.
fn window_anchored(anchor: u32) -> Projection {
    Projection {
        complete: false,
        roster_bounded: true,
        saw_balance_block: true,
        vote_seed_from: 0,
        first_segment_registration: 0,
        run_unknown_below: 0,
        counter_tail: u32::MAX,
        anchor,
    }
}

/// The evidence check's verdict on `block` as an extension of `bc`'s head
/// under `projection`, on a scratch entry removed again: `Ok`,
/// `Err(Some(reason))` (exact evidence) or `Err(None)` (a local fault).
fn judge_on<S: StorageTrait>(
    bc: &mut Chain16<S>,
    block: &Block,
    projection: &Projection,
) -> Result<(), Option<ValidationReason>> {
    let view = block.view();
    let idx = bc.blocks.next_free_index().expect("a free slot");
    let mut entry = BlockEntry::new(view.hash(), bc.active_chain_head_idx, view.sequence());
    entry.set_payload_type(view.payload_type());
    bc.blocks.insert_at(idx, entry);
    let verdict = bc.judge_evidence(&view, idx, projection);
    bc.blocks.delete(idx);
    match verdict {
        Ok(()) => Ok(()),
        Err(ProcessingError::Invalid { reason, .. }) => Err(Some(reason)),
        Err(_) => Err(None),
    }
}

/// The FR21 value of the active window, block by block from storage.
fn window_value<S: StorageTrait>(bc: &Chain16<S>) -> u64 {
    let tail = bc
        .blocks
        .get(bc.snake_chain_tail_idx)
        .expect("a tail")
        .sequence();
    let mut sum = 0;
    let mut cur = bc.active_chain_head_idx;
    loop {
        let entry = bc.blocks.get(cur).expect("on the path");
        if entry.sequence() <= tail {
            return sum;
        }
        let mut buf = [0u8; MAX_BLOCK_SIZE];
        sum += block_value::<16>(&bc.view_retained(cur, &mut buf).expect("readable"));
        cur = entry.parent_ref();
    }
}

/// A held block's `(status, on the active chain, signatures accepted
/// (bit 6), creator signature verified (bit 5))`.
fn entry_of<S: StorageTrait>(
    bc: &Chain16<S>,
    block: &Block,
) -> Option<(BlockStatus, bool, bool, bool)> {
    let view = block.view();
    bc.blocks
        .find(view.sequence(), &view.hash())
        .and_then(|idx| bc.blocks.get(idx))
        .map(|entry| {
            (
                entry.status(),
                entry.is_on_active_chain(),
                entry.is_signatures_accepted(),
                entry.is_signature_verified(),
            )
        })
}

/// The fixture's own pin: an evidence block re-assembled field by field
/// with nothing changed carries the builder's payload, and passes.
#[test]
fn a_rebuilt_evidence_is_the_built_one() {
    let (mut g, _, e) = evidence_observer(4);
    let same = evidence_with(&e, 2, |_| {});
    assert_eq!(same.view().payload(), e.view().payload());
    let ready = ready_projection(&g);
    assert_eq!(judge_on(&mut g, &same, &ready), Ok(()));
}

// -- AC4: the FR27 run rules and the FR48 clean slot --

/// Four blocks that may not extend `d`'s open run (`g` at `d`, by 4):
/// a foreign creator, the proposer in deviation form, the proposer voting
/// for another node with `consumed_votes = 0` (only `first_voted ≠
/// creator` breaks the override form), the proposer with `consumed_votes ≠
/// 0` (only `cv ≠ 0` breaks it).
fn run_violations(g: &SupportChain, d: &Block) -> [(Block, ValidationReason); 4] {
    let foreign = normal_after(g, d, 3, 71);
    let deviation = deviation_after(g, d, 4, 72);
    assert_ne!(deviation.view().first_voted_node(), 4, "deviation form");
    let other_vote = reheader(&normal_after(g, d, 4, 74), 4, 0, 3, 0, key_of(4));
    assert_eq!(other_vote.view().consumed_votes(), 0);
    let consuming = reheader(&normal_after(g, d, 4, 73), 4, 7, 4, 0, key_of(4));
    assert_eq!(d.view().creator(), 4);
    [
        (foreign, ValidationReason::RunCreator),
        (deviation, ValidationReason::RunHeader),
        (other_vote, ValidationReason::RunHeader),
        (consuming, ValidationReason::RunHeader),
    ]
}

/// AC4 rules 1–2 at intake on the direct extension of `d`: each violation
/// is exact evidence, not stored; the proposer's override replay passes.
#[test]
fn the_run_rules_refuse_a_direct_extension() {
    let (mut g, _, _, d, _) = proposer_chain(4);
    assert_eq!(receive(&mut g, &d), ReceiveBlockOutcome::AcceptedSilently);
    assert_eq!(g.active_open_run, 6);
    for (block, reason) in run_violations(&g, &d) {
        assert_eq!(step_reason(&mut g, &block), Some(reason));
        assert_eq!(
            receive(&mut g, &block),
            ReceiveBlockOutcome::Rejected(RejectReason::InvalidEvidence)
        );
        assert_eq!(entry_of(&g, &block), None, "not stored");
    }
    let replay = normal_after(&g, &d, 4, 2);
    assert_eq!(step_reason(&mut g, &replay), None);
    assert_eq!(
        receive(&mut g, &replay),
        ReceiveBlockOutcome::AcceptedSilently
    );
    assert_eq!(head_of(&g), (7, replay.view().hash()));
    assert_eq!(g.active_open_run, 6, "a replay keeps the run open");
}

/// AC4 rules 1–2 at intake on a side block (Tier 2, the header walk): `d`
/// is active below the replay head, and each violation beside the replay
/// is refused.
#[test]
fn the_run_rules_refuse_a_side_block() {
    let (mut g, _, _, d, _) = proposer_chain(4);
    assert_eq!(receive(&mut g, &d), ReceiveBlockOutcome::AcceptedSilently);
    let replay = normal_after(&g, &d, 4, 2);
    assert_eq!(
        receive(&mut g, &replay),
        ReceiveBlockOutcome::AcceptedSilently
    );
    for (block, _) in run_violations(&g, &d) {
        assert_eq!(
            receive(&mut g, &block),
            ReceiveBlockOutcome::Rejected(RejectReason::InvalidEvidence)
        );
        assert_eq!(entry_of(&g, &block), None, "not stored");
    }
    assert_eq!(head_of(&g), (7, replay.view().hash()));
}

/// AC4 at connect: a foreign block above the run that arrives before its
/// parent is judged when the parent's arrival connects it (the stored
/// child), and deleted.
#[test]
fn the_run_rules_judge_a_stored_child_at_connect() {
    let (mut g, _, _, d, _) = proposer_chain(4);
    assert_eq!(receive(&mut g, &d), ReceiveBlockOutcome::AcceptedSilently);
    let replay = normal_after(&g, &d, 4, 2);
    let foreign = normal_after(&g, &replay, 3, 3);
    assert_eq!(
        receive(&mut g, &foreign),
        ReceiveBlockOutcome::AcceptedSilently,
        "an orphan: its parent is not held"
    );
    assert!(entry_of(&g, &foreign).is_some());
    assert_eq!(
        receive(&mut g, &replay),
        ReceiveBlockOutcome::AcceptedSilently
    );
    assert_eq!(head_of(&g), (7, replay.view().hash()));
    assert_eq!(entry_of(&g, &foreign), None, "deleted at connect");
}

/// AC4 in the FR3 pass: a restart over storage holding a foreign block
/// above `d` refuses it (FR5) and goes Ready on `d`, whose open run the
/// pass derived (the Ready-entry value).
#[test]
fn the_run_rules_hold_in_the_pass() {
    let (mut g, _, _, d, _) = proposer_chain(4);
    assert_eq!(receive(&mut g, &d), ReceiveBlockOutcome::AcceptedSilently);
    let foreign = normal_after(&g, &d, 3, 2);
    let idx = g.blocks.next_free_index().expect("a free slot");
    g.storage.save_block(idx, &foreign).ok().expect("save");
    let mut restarted = local_node(0, g.storage);
    restarted.initialize_from_storage(500);
    assert!(restarted.is_ready());
    assert_eq!(head_of(&restarted), (6, d.view().hash()));
    assert_eq!(entry_of(&restarted, &foreign), None, "deleted by FR5");
    assert_eq!(restarted.active_open_run, 6, "the pass's final run state");
}

/// AC4 rule 3: a type-4 block closes an open run by its creator, naming
/// its `p`: another `p`, another creator, and no open run (after the run
/// closed) are exact evidence; the real one passes.
#[test]
fn an_evidence_must_close_an_open_run() {
    let (mut g, d, e) = evidence_observer(4);
    let ev = evidence_of(&e, 2);
    let wrong_p = evidence_with(&e, 2, |ev| ev.deviation_sequence = 5);
    let by_other = evidence_block(7, d.view().hash(), 3, &ev);
    for (block, reason) in [
        (wrong_p, ValidationReason::EvidencePlacement),
        (by_other, ValidationReason::RunCreator),
    ] {
        assert_eq!(step_reason(&mut g, &block), Some(reason));
        assert_eq!(
            receive(&mut g, &block),
            ReceiveBlockOutcome::Rejected(RejectReason::InvalidEvidence)
        );
    }
    assert_eq!(receive(&mut g, &e), ReceiveBlockOutcome::AcceptedSilently);
    let no_run = evidence_block(8, e.view().hash(), 4, &ev);
    assert_eq!(
        step_reason(&mut g, &no_run),
        Some(ValidationReason::EvidencePlacement)
    );
    assert_eq!(
        receive(&mut g, &no_run),
        ReceiveBlockOutcome::Rejected(RejectReason::InvalidEvidence)
    );
    assert_eq!(head_of(&g), (7, e.view().hash()));
}

/// A block by `creator` at `seq` in override form (no ancestry: the rules
/// read only its bytes and the run).
fn override_at(seq: u32, creator: u32) -> Block {
    reheader(
        &transfer(seq, [0x5A; 32], 1, 1),
        creator,
        0,
        creator,
        0,
        key_of(creator),
    )
}

/// AC4 rule 4 (D1): with `p = 6`, `H = 8`, a replay ends at `p + H − 1 =
/// 13` and the evidence at `p + H = 14`; a tentative configuration (no
/// `H`) judges no bound.
#[test]
fn the_run_bound_admits_replays_to_p_plus_h_minus_one() {
    let (_, e, _) = evidence_by(5);
    let ev = evidence_of(&e, 2);
    let run = Some((6, 5));
    let h = Some(TEST_H);
    let last = 6 + TEST_H;
    let bound = Err(ValidationReason::RunBound);
    assert_eq!(run_rules(&override_at(last - 1, 5).view(), run, h), Ok(()));
    assert_eq!(run_rules(&override_at(last, 5).view(), run, h), bound);
    let evidence_at = |seq: u32| evidence_block(seq, [0x5A; 32], 5, &ev);
    assert_eq!(run_rules(&evidence_at(last).view(), run, h), Ok(()));
    assert_eq!(run_rules(&evidence_at(last + 1).view(), run, h), bound);
    assert_eq!(
        run_rules(&override_at(last, 5).view(), run, None),
        Ok(()),
        "no locked H: no verdict"
    );
}

/// AC4 rule 5 (D8): at a slot (`s ≡ H − 1`) a node-transfer block, an
/// evidence block and a complex transaction with only a balance output
/// are clean; a registration, a UTXO output, a balance block and a
/// chain-config block are not. Off the slots (`H − 2`, `H`, genesis) all
/// pass, and without a locked `H` nothing is judged.
#[test]
fn a_slot_holds_only_clean_blocks() {
    let (_, e, _) = evidence_by(4);
    let ev = evidence_of(&e, 2);
    let h = TEST_H;
    let blocks = |seq: u32| -> [(Block, bool); 9] {
        let prev = [0x5A; 32];
        let utxo = utxo_tx(seq, &[], Some((1, 100)), &[Ok(60)]);
        let balance_only = utxo_tx(seq, &[], Some((1, 100)), &[Err((2, 100))]);
        let mixed = utxo_tx(seq, &[], Some((1, 100)), &[Err((2, 40)), Ok(60)]);
        [
            // Every transaction and every output counts (review).
            (
                complex_tx_block(seq, prev, 3, 0, &[&balance_only, &utxo]),
                false,
            ),
            (complex_tx_block(seq, prev, 3, 0, &[&mixed]), false),
            (transfer(seq, prev, 1, 1), true),
            (evidence_block(seq, prev, 4, &ev), true),
            (complex_tx_block(seq, prev, 3, 0, &[&balance_only]), true),
            (register(seq, prev, 6, key_of(6)), false),
            (complex_tx_block(seq, prev, 3, 0, &[&utxo]), false),
            (balance_block(seq, prev, &[(0, 1, 0, 1)], 5), false),
            (
                chain_config_block_from(seq, prev, &mut window_config_builder(TEST_W)),
                false,
            ),
        ]
    };
    for (block, clean) in blocks(h - 1).iter().chain(&blocks(2 * h - 1)) {
        assert_eq!(
            slot_rule(&block.view(), Some(h)).is_ok(),
            *clean,
            "at {}: type {}",
            block.view().sequence(),
            block.view().payload_type()
        );
        assert_eq!(slot_rule(&block.view(), None), Ok(()), "no locked H");
    }
    for seq in [h - 2, h, 2 * h] {
        for (block, _) in blocks(seq) {
            assert_eq!(slot_rule(&block.view(), Some(h)), Ok(()), "off the slots");
        }
    }
    let genesis = chain_config_block_from(0, [0; 32], &mut window_config_builder(TEST_W));
    assert_eq!(slot_rule(&genesis.view(), Some(h)), Ok(()), "#0 is no slot");
}

/// AC4 rule 5 end to end: on Story 6.4's chain (`H = 8`) the slot #7
/// refuses a registration at intake and admits a transfer; a registration
/// at #6, off the slot, passes the step.
#[test]
fn a_ready_node_refuses_unclean_content_at_a_slot() {
    let (mut g, _, blocks) = support_chain(3);
    let at_six = real_on(
        &g,
        &register(6, blocks[5].view().hash(), 6, key_of(6)),
        0,
        1,
    );
    assert_eq!(step_reason(&mut g, &at_six), None, "off the slot");
    let x6 = normal_after(&g, &blocks[5], 2, 61);
    assert_eq!(receive(&mut g, &x6), ReceiveBlockOutcome::AcceptedSilently);
    let at_seven = real_on(&g, &register(7, x6.view().hash(), 6, key_of(6)), 0, 1);
    assert_eq!(
        step_reason(&mut g, &at_seven),
        Some(ValidationReason::SlotNotClean)
    );
    assert_eq!(
        receive(&mut g, &at_seven),
        ReceiveBlockOutcome::Rejected(RejectReason::InvalidEvidence)
    );
    let clean = normal_after(&g, &x6, 2, 62);
    assert_eq!(
        receive(&mut g, &clean),
        ReceiveBlockOutcome::AcceptedSilently
    );
    assert_eq!(head_of(&g), (7, clean.view().hash()));
}

/// AC4 (D4): `active_open_run` after each event — a deviation's commit
/// opens it, a replay keeps it, the evidence (built over the replay:
/// the rewind over two blocks) closes it, and the FR5 recovery resets it.
#[test]
fn the_open_run_follows_the_head() {
    let (mut g, mut l, _, d, d_idx) = proposer_chain(4);
    assert_eq!(g.active_open_run, NO_OPEN_RUN);
    assert_eq!(receive(&mut g, &d), ReceiveBlockOutcome::AcceptedSilently);
    assert_eq!(g.active_open_run, 6);
    let replay = normal_after(&g, &d, 4, 2);
    for node in [&mut g, &mut l] {
        assert_eq!(
            receive(node, &replay),
            ReceiveBlockOutcome::AcceptedSilently
        );
    }
    assert_eq!(g.active_open_run, 6);
    accumulate(&mut l, &d, d_idx, 2);
    let tip = l.active_chain_head_idx;
    let e = l
        .build_evidence_block(tip, 0)
        .expect("evidence over the replay");
    assert_eq!(e.view().sequence(), 8);
    let verified = counted(&AGGREGATE_VERIFICATIONS);
    assert_eq!(receive(&mut g, &e), ReceiveBlockOutcome::AcceptedSilently);
    assert_eq!(head_of(&g), (8, e.view().hash()));
    assert_eq!(counted(&AGGREGATE_VERIFICATIONS) - verified, 1);
    assert_eq!(g.active_open_run, NO_OPEN_RUN);
    l.lifecycle_phase = LifecyclePhase::Processing;
    assert_eq!(l.active_open_run, 6);
    l.recover_from_failed_pass(ProcessingError::StorageRead, NONE_REF);
    assert_eq!(l.active_open_run, NO_OPEN_RUN, "FR5 resets it");
}

/// AC4 (D4): a window-anchored pass trusts rules 1–4 while the run state
/// is unknown — a foreign block over an open run passes — and a
/// deviation-form block or an evidence block settles it (taken as no run,
/// the evidence would be misplaced); the slot rule applies throughout.
#[test]
fn an_unknown_run_state_trusts_rules_one_to_four() {
    let (mut g, d, e) = evidence_observer(4);
    let foreign = normal_after(&g, &d, 3, 71);
    let judge = |g: &mut SupportChain, block: &Block, projection: &mut Projection| {
        let view = block.view();
        let idx = g.blocks.next_free_index().expect("a free slot");
        let mut entry = BlockEntry::new(view.hash(), g.active_chain_head_idx, view.sequence());
        entry.set_payload_type(view.payload_type());
        g.blocks.insert_at(idx, entry);
        let verdict = g.check_run_rules(&view, idx, projection);
        g.blocks.delete(idx);
        run_rule_reason(verdict)
    };
    let mut unknown = Projection {
        run_unknown_below: 100,
        ..Projection::COMPLETE
    };
    assert_eq!(judge(&mut g, &foreign, &mut unknown), Ok(()), "trusted");
    assert_eq!(
        unknown.run_unknown_below, 100,
        "a normal block settles nothing"
    );
    let unclean = real_on(
        &g,
        &register(7, d.view().hash(), 6, key_of(6)),
        3,
        key_of(3),
    );
    assert_eq!(
        judge(&mut g, &unclean, &mut unknown),
        Err(ValidationReason::SlotNotClean),
        "the slot rule still applies"
    );
    let mut settled_by_evidence = Projection {
        run_unknown_below: 100,
        ..Projection::COMPLETE
    };
    assert_eq!(judge(&mut g, &e, &mut settled_by_evidence), Ok(()));
    assert_eq!(
        settled_by_evidence.run_unknown_below, 0,
        "an evidence settles it"
    );
    let deviation = deviation_after(&g, &d, 3, 72);
    assert_eq!(judge(&mut g, &deviation, &mut unknown), Ok(()));
    assert_eq!(unknown.run_unknown_below, 0, "a deviation settles it");
    assert_eq!(
        judge(&mut g, &foreign, &mut unknown),
        Err(ValidationReason::RunCreator),
        "exact from then on"
    );
}

/// `check_run_rules` for `block` on a scratch child of the head, and the
/// storage reads it made.
fn run_rule_reads(
    bc: &mut Chain16<FailingSupportStorage>,
    block: &Block,
) -> (Result<(), ValidationReason>, u32) {
    let view = block.view();
    let idx = bc.blocks.next_free_index().expect("a free slot");
    let mut entry = BlockEntry::new(view.hash(), bc.active_chain_head_idx, view.sequence());
    entry.set_payload_type(view.payload_type());
    bc.blocks.insert_at(idx, entry);
    let mut projection = Projection::COMPLETE;
    let reads = bc.storage.reads.get();
    let verdict = bc.check_run_rules(&view, idx, &mut projection);
    let read = bc.storage.reads.get() - reads;
    bc.blocks.delete(idx);
    (run_rule_reason(verdict), read)
}

/// A `check_run_rules` verdict as its evidence reason; a local fault is not
/// expected where this is used.
fn run_rule_reason(verdict: Result<(), ProcessingError>) -> Result<(), ValidationReason> {
    verdict.map_err(|err| match err {
        ProcessingError::Invalid { reason, .. } => reason,
        _ => panic!("a local fault, not a verdict"),
    })
}

/// `deviation_run_at(idx)` and the storage reads it made.
fn walk_reads(
    bc: &Chain16<FailingSupportStorage>,
    idx: u32,
) -> (Result<Option<(u32, u32)>, ()>, u32) {
    let reads = bc.storage.reads.get();
    let run = bc.deviation_run_at(idx);
    (run, bc.storage.reads.get() - reads)
}

/// AC4 (D4) read counts: the head's rules read nothing outside a run and
/// `d`'s header once inside one; the side walk stops on a normal header
/// (one read), walks a run to its `d`, and reads nothing above a type-4
/// entry (the RAM flag).
#[test]
fn the_run_rules_read_only_inside_a_run() {
    let (_, e, _) = evidence_by(4);
    let (mut g, mut l, blocks) = support_chain_on(3, failing_storage(3), 16, |_| {});
    let x6 = normal_after(&g, &blocks[5], 2, 61);
    assert_eq!(run_rule_reads(&mut l, &x6), (Ok(()), 0), "no run: RAM only");
    let a4 = l.blocks.find(4, &blocks[4].view().hash()).expect("#4");
    assert_ne!(blocks[4].view().consumed_votes(), 0);
    assert_eq!(walk_reads(&l, a4), (Ok(None), 1), "a normal header ends it");

    let d = deviation_after(&g, &blocks[5], 4, 1);
    assert_eq!(receive(&mut g, &d), ReceiveBlockOutcome::AcceptedSilently);
    assert_eq!(receive(&mut l, &d), ReceiveBlockOutcome::AcceptedSilently);
    let d_idx = l.active_chain_head_idx;
    let replay = normal_after(&g, &d, 4, 2);
    assert_eq!(run_rule_reads(&mut l, &replay), (Ok(()), 1), "d's header");
    assert_eq!(walk_reads(&l, d_idx), (Ok(Some((6, 4))), 1));
    assert_eq!(
        receive(&mut l, &replay),
        ReceiveBlockOutcome::AcceptedSilently
    );
    assert_eq!(
        walk_reads(&l, l.active_chain_head_idx),
        (Ok(Some((6, 4))), 2),
        "the replay, then d"
    );
    plant_child(&mut l, &e, d_idx, true, true);
    let e_idx = l.blocks.find(7, &e.view().hash()).expect("planted");
    assert_eq!(
        walk_reads(&l, e_idx),
        (Ok(None), 0),
        "a closed run: no read"
    );
}

/// AC4: a failed read in the side block's header walk is no evidence:
/// the foreign block above `d` (whose header cannot be read) is admitted,
/// not refused; readable, the same block is refused.
#[test]
fn a_read_fault_in_the_walk_is_not_evidence() {
    let (_, e, _) = evidence_by(4);
    for fault in [true, false] {
        walk_fault_case(&e, fault);
    }
}

fn walk_fault_case(e: &Block, fault: bool) {
    let (mut g, mut l, blocks) = support_chain_on(3, failing_storage(3), 16, |_| {});
    let d = deviation_after(&g, &blocks[5], 4, 1);
    assert_eq!(receive(&mut g, &d), ReceiveBlockOutcome::AcceptedSilently);
    for block in [&d, e] {
        assert_eq!(
            receive(&mut l, block),
            ReceiveBlockOutcome::AcceptedSilently
        );
    }
    assert_eq!(
        head_of(&l),
        (7, e.view().hash()),
        "the run closed on the head"
    );
    let foreign = normal_after(&g, &d, 3, 71);
    if fault {
        l.storage.failing_slot = l.blocks.find(6, &d.view().hash()).expect("d");
        assert_eq!(
            receive(&mut l, &foreign),
            ReceiveBlockOutcome::AcceptedSilently,
            "no verdict"
        );
        assert!(entry_of(&l, &foreign).is_some(), "held, not deleted");
    } else {
        assert_eq!(
            receive(&mut l, &foreign),
            ReceiveBlockOutcome::Rejected(RejectReason::InvalidEvidence)
        );
    }
    assert_eq!(head_of(&l), (7, e.view().hash()));
}

/// AC4 (D4) — in Ready, a block whose held parent is only Stored (neither
/// the head nor Connected) is judged at intake too, by the header walk: a
/// foreign block above a stored deviation is refused before its write.
#[test]
fn a_block_on_a_stored_deviation_is_judged_at_intake() {
    let (mut g, mut l, blocks) = support_chain(3);
    let d = deviation_after(&g, &blocks[5], 4, 1);
    assert_eq!(receive(&mut g, &d), ReceiveBlockOutcome::AcceptedSilently);
    plant(&mut l, &d, false, true);
    let foreign = normal_after(&g, &d, 3, 71);
    assert_eq!(
        receive(&mut l, &foreign),
        ReceiveBlockOutcome::Rejected(RejectReason::InvalidEvidence)
    );
    assert!(entry_of(&l, &foreign).is_none(), "not stored");
}

/// AC4 — a failed read of `d`'s header in the per-block step gives no
/// verdict: the block above the open run is held Stored, neither refused
/// nor applied or marked, and the run state stays (local I/O is never
/// evidence and never acceptance). Regression: it used to be committed.
#[test]
fn an_unreadable_deviation_header_neither_refuses_nor_applies() {
    let (mut g, mut l, blocks) = support_chain_on(3, failing_storage(3), 16, |_| {});
    let d = deviation_after(&g, &blocks[5], 4, 1);
    assert_eq!(receive(&mut g, &d), ReceiveBlockOutcome::AcceptedSilently);
    assert_eq!(receive(&mut l, &d), ReceiveBlockOutcome::AcceptedSilently);
    assert_eq!(l.active_open_run, 6);
    let foreign = normal_after(&g, &d, 3, 71);
    l.storage.failing_slot = l.blocks.find(6, &d.view().hash()).expect("d");
    assert_eq!(
        receive(&mut l, &foreign),
        ReceiveBlockOutcome::AcceptedSilently,
        "no verdict"
    );
    assert_eq!(head_of(&l), (6, d.view().hash()), "not applied");
    let (status, on_chain, accepted, _) = entry_of(&l, &foreign).expect("held");
    assert!(status == BlockStatus::Stored && !on_chain && !accepted);
    assert_eq!(l.active_open_run, 6);
}

// -- Story 6.7 code review (production code): the regressions --

/// Review (header-walk faults) — genesis #0 is never inside a run: the
/// walk from it answers "no run", not "unknown".
#[test]
fn the_run_walk_ends_at_genesis() {
    let (_, l, blocks) = support_chain(3);
    let genesis = l.blocks.find(0, &blocks[0].view().hash()).expect("#0");
    assert_eq!(l.deviation_run_at(genesis), Ok(None));
}

/// Review (header-walk faults) — at intake an unreadable ancestry still
/// judges the slot rule, which reads the block alone: a balance block at a
/// slot above a Stored deviation whose header cannot be read is refused
/// before its write, while a clean block there gets no verdict (held).
#[test]
fn an_unreadable_ancestry_still_judges_the_slot_at_intake() {
    let (mut g, mut l, blocks) = support_chain_on(3, failing_storage(3), 16, |_| {});
    let h = l.verification_horizon().expect("locked");
    assert_eq!(7 % h, h - 1, "#7 is a slot");
    let d = deviation_after(&g, &blocks[5], 4, 1);
    assert_eq!(receive(&mut g, &d), ReceiveBlockOutcome::AcceptedSilently);
    plant(&mut l, &d, false, true);
    l.storage.failing_slot = l.blocks.find(6, &d.view().hash()).expect("d");
    let template = balance_snapshot(&g, 7, d.view().hash(), &[2]);
    let unclean = reheader(&template, 4, 0, 4, 0, key_of(4));
    assert_eq!(
        receive(&mut l, &unclean),
        ReceiveBlockOutcome::Rejected(RejectReason::InvalidEvidence)
    );
    assert!(entry_of(&l, &unclean).is_none(), "not stored");
    let clean = normal_after(&g, &d, 4, 71);
    assert_eq!(
        receive(&mut l, &clean),
        ReceiveBlockOutcome::AcceptedSilently,
        "no verdict"
    );
    let (status, on_chain, accepted, _) = entry_of(&l, &clean).expect("held");
    assert!(status == BlockStatus::Stored && !on_chain && !accepted);
}

/// Review (AC10, D3) — only the local node's own evidence above `d`
/// releases its accumulator: another creator's evidence held above `d`
/// (it can be held unjudged after a walk fault at intake; planted here)
/// does not.
#[test]
fn a_foreign_evidence_above_d_does_not_release() {
    let (_, e, _) = evidence_by(4);
    let ev = evidence_of(&e, 2);
    let (_, mut l, _, d, d_idx) = proposer_chain(5);
    assert!(l.open_approval(d_idx));
    let foreign = evidence_block(7, d.view().hash(), 3, &ev);
    plant_child(&mut l, &foreign, d_idx, true, true);
    assert!(l.approval_live(), "not the proposer's");
    let own = evidence_block(7, d.view().hash(), 5, &ev);
    plant_child(&mut l, &own, d_idx, true, true);
    assert!(!l.approval_live(), "the proposer's own releases");
}

/// Review (AC8) — outside the pass the evidence check reads the
/// active-set counter only while it is valid: an invalid counter is a
/// local fault, never an `EvidenceSubgroup` verdict.
#[test]
fn an_invalid_counter_is_a_local_fault() {
    let (mut g, _, e) = evidence_observer(4);
    let ready = ready_projection(&g);
    g.active_set.invalidate();
    assert_eq!(judge_on(&mut g, &e, &ready), Err(None));
}

/// Review (AC5 step 1) — the pass builds its own counter over the window
/// at `p − 1`; a read fault there leaves it invalid: a local fault, no
/// verdict and nothing verified. The control: the same pass without the
/// fault accepts.
#[test]
fn a_window_read_fault_in_the_pass_is_local() {
    let (d, r, e, _) = replay_evidence();
    let pass = || Projection {
        counter_tail: u32::MAX,
        ..Projection::COMPLETE
    };
    let mut l = failing_observer(&d, &r);
    assert_eq!(judge_on(&mut l, &e, &pass()), Ok(()), "the control");
    let mut l = failing_observer(&d, &r);
    l.storage.failing_slot = l
        .ancestor_at(l.active_chain_head_idx, 3)
        .ok()
        .flatten()
        .expect("#3 in the window");
    let verified = counted(&AGGREGATE_VERIFICATIONS);
    assert_eq!(judge_on(&mut l, &e, &pass()), Err(None));
    assert!(l.storage.attempts.get() > 0, "the window read was hit");
    assert_eq!(counted(&AGGREGATE_VERIFICATIONS), verified);
}

/// Review (AC8) — a failed restore inside the FR3 pass is the pass's own
/// local failure: it does not also mark the root's re-entry due (a
/// second, spurious re-entry). Every read budget of `r` is tried; at least
/// one hits the restore (the engine is left changed). The control: the
/// same fault under Ready's projection marks it.
#[test]
fn a_failed_restore_in_the_pass_marks_no_reentry() {
    let (d, r, e, _) = replay_evidence();
    for in_pass in [true, false] {
        let mut restore_failures = 0;
        for reads in 0..4 {
            let mut l = failing_observer(&d, &r);
            let projection = if in_pass {
                Projection {
                    counter_tail: u32::MAX,
                    ..Projection::COMPLETE
                }
            } else {
                ready_projection(&l)
            };
            let before = engine_votes(&l);
            l.storage.failing_slot = l.active_chain_head_idx;
            l.storage.reads_left.set(reads);
            l.storage.failures_left.set(1);
            let verdict = judge_on(&mut l, &e, &projection);
            let restore_failed = engine_votes(&l) != before;
            if restore_failed {
                restore_failures += 1;
                assert_eq!(verdict, Err(None), "reads {reads}");
            }
            assert_eq!(
                l.reentry_due,
                restore_failed && !in_pass,
                "in the pass {in_pass}, reads {reads}"
            );
        }
        assert!(restore_failures > 0, "a restore failed (pass {in_pass})");
    }
}

// -- AC5 / AC6: the Tier-3 evidence check and the accepted mark --

/// AC5 / AC6: a valid evidence admitted by a second node as a direct
/// extension is verified exactly once, marked "signatures accepted" (bit
/// 6 with bit 5), and closes the run.
#[test]
fn a_valid_evidence_is_verified_once_and_marked() {
    let (mut g, _, e) = evidence_observer(4);
    let verified = counted(&AGGREGATE_VERIFICATIONS);
    assert_eq!(receive(&mut g, &e), ReceiveBlockOutcome::AcceptedSilently);
    assert_eq!(head_of(&g), (7, e.view().hash()));
    assert_eq!(counted(&AGGREGATE_VERIFICATIONS) - verified, 1);
    let (_, active, accepted, verified) = entry_of(&g, &e).expect("held");
    assert!(active && accepted && verified);
    assert_eq!(g.active_open_run, NO_OPEN_RUN);
}

/// AC6 (D2): the one marker sets bits 6 and 5 together; an empty slot is
/// refused.
#[test]
fn the_accepted_mark_sets_both_bits() {
    let mut table = BlockTable::<4>::new();
    let idx = table
        .insert(BlockEntry::new([7; 32], NONE_REF, 3))
        .expect("a slot");
    let bits = |table: &BlockTable<4>| {
        let entry = table.get(idx).expect("held");
        (
            entry.is_signatures_accepted(),
            entry.is_signature_verified(),
        )
    };
    assert_eq!(bits(&table), (false, false));
    assert!(table.mark_signatures_accepted(idx));
    assert_eq!(bits(&table), (true, true), "bit 6 implies bit 5");
    assert!(!table.mark_signatures_accepted(idx + 1), "an empty slot");
    table.clear_signatures_accepted();
    assert_eq!(bits(&table), (false, true), "the pass clears bit 6 only");
}

/// One invalid family: `mutate` applied to `proposer`'s evidence (with
/// two signers) gives `reason` from the check, the block is refused at
/// intake and not stored, and the real evidence passes afterwards.
fn refused_evidence_case(
    proposer: u32,
    reason: ValidationReason,
    mutate: impl FnOnce(&mut Evidence),
) {
    let (mut g, _, e) = evidence_observer(proposer);
    let bad = evidence_with(&e, 2, mutate);
    let ready = ready_projection(&g);
    assert_eq!(judge_on(&mut g, &bad, &ready), Err(Some(reason)));
    assert_eq!(
        receive(&mut g, &bad),
        ReceiveBlockOutcome::Rejected(RejectReason::InvalidEvidence)
    );
    assert_eq!(entry_of(&g, &bad), None, "not stored");
    assert_eq!(head_of(&g).0, 6);
    assert_eq!(receive(&mut g, &e), ReceiveBlockOutcome::AcceptedSilently);
    assert_eq!(head_of(&g), (7, e.view().hash()), "the control");
}

/// AC5 step 2: a wrong `m`, or fewer than `r_eff` signers (one support,
/// its own valid aggregate), is `EvidenceSubgroup`.
#[test]
fn a_wrong_subgroup_is_refused() {
    refused_evidence_case(4, ValidationReason::EvidenceSubgroup, |ev| ev.m += 1);
    let (d, _, members) = evidence_by(4);
    let hash = d.view().hash();
    refused_evidence_case(4, ValidationReason::EvidenceSubgroup, |ev| {
        ev.bitmap = std::vec![0b01];
        ev.aggregate = aggregate_by(&members[..1], 4, 6, &hash);
    });
}

/// AC5 step 4: `supporter_vote_sum` one above or below `B_k − cv(d)` is
/// `EvidenceVoteSum`, before any aggregate verification.
#[test]
fn a_wrong_vote_sum_is_refused() {
    let verified = counted(&AGGREGATE_VERIFICATIONS);
    refused_evidence_case(4, ValidationReason::EvidenceVoteSum, |ev| {
        ev.supporter_vote_sum += 1
    });
    refused_evidence_case(4, ValidationReason::EvidenceVoteSum, |ev| {
        ev.supporter_vote_sum -= 1
    });
    assert_eq!(
        counted(&AGGREGATE_VERIFICATIONS) - verified,
        2,
        "only the two controls are verified"
    );
}

/// AC5 step 4: proposer 2's late list (nodes 5 and 0) dropped, extended,
/// reordered, or with a wrong value at the tip is `EvidenceLateList`.
#[test]
fn a_wrong_late_list_is_refused() {
    let (_, e, _) = evidence_by(2);
    assert_eq!(evidence_of(&e, 2).late.len(), 2, "two late entries");
    let late = ValidationReason::EvidenceLateList;
    refused_evidence_case(2, late, |ev| {
        ev.late.pop();
    });
    refused_evidence_case(2, late, |ev| ev.late.push((4, 0)));
    refused_evidence_case(2, late, |ev| ev.late.swap(0, 1));
    refused_evidence_case(2, late, |ev| ev.late[0].1 += 1);
    // Review: the right count, one listed id wrong — beyond the roster
    // (99), or a registered node that is not late at `p − 1`.
    for id in [99, 1, 2, 4] {
        refused_evidence_case(2, late, |ev| ev.late[1].0 = id);
    }
    // `u` heads the order, so in front of node 0, with its true value at
    // the tip, it keeps the order, the count of late nodes above the last
    // entry and the values: only "late" refuses it.
    let (g, d, _) = evidence_observer(2);
    let u = d.view().first_voted_node();
    let at_tip = g
        .vote_engine
        .grown(g.vote_engine.accumulated_vote_of(u))
        .expect("grown");
    refused_evidence_case(2, late, |ev| ev.late[0] = (u, at_tip));
}

/// AC5 step 5: a corrupted aggregate byte (the framing kept) is
/// `EvidenceAggregate`. Under BLS a `count` other than the population
/// also ends there; under Schnorr the framing refuses it at Tier 1, before
/// any verification. AC13.4: under Schnorr the keys enter in rank order,
/// so an aggregate over the signers in swapped order does not verify (a
/// BLS aggregate is order-free).
#[test]
fn a_wrong_aggregate_is_refused() {
    refused_evidence_case(4, ValidationReason::EvidenceAggregate, |ev| {
        let last = ev.aggregate.len() - 1;
        ev.aggregate[last] ^= 1;
    });
    #[cfg(not(feature = "schnorr"))]
    refused_evidence_case(4, ValidationReason::EvidenceAggregate, |ev| {
        ev.aggregate[1] = ev.aggregate[1].wrapping_add(1)
    });
    #[cfg(feature = "schnorr")]
    {
        let (mut g, _, e) = evidence_observer(4);
        let bad = evidence_with(&e, 2, |ev| {
            ev.aggregate[1] = ev.aggregate[1].wrapping_add(1)
        });
        let verified = counted(&AGGREGATE_VERIFICATIONS);
        assert_eq!(
            receive(&mut g, &bad),
            ReceiveBlockOutcome::Rejected(RejectReason::InvalidEvidence)
        );
        assert_eq!(counted(&AGGREGATE_VERIFICATIONS), verified, "Tier 1");
        assert_eq!(head_of(&g).0, 6);

        let (d, e, members) = evidence_by(4);
        assert_eq!(evidence_of(&e, 2).bitmap, [0b011], "ranks 0 and 1");
        let hash = d.view().hash();
        refused_evidence_case(4, ValidationReason::EvidenceAggregate, |ev| {
            ev.aggregate = aggregate_by(&[members[1], members[0]], 4, 6, &hash)
        });
    }
}

/// The other valid evidence of proposer 2's deviation: ranks 0 and 2 of
/// `m = 3` marked instead of 0 and 1 (FR27 accepts any `n ≥ r_eff`).
fn alternative_evidence(d: &Block, e: &Block, members: &[u32]) -> Block {
    let hash = d.view().hash();
    evidence_with(e, 2, |ev| {
        assert_eq!(ev.bitmap, [0b011]);
        ev.bitmap = std::vec![0b101];
        ev.aggregate = aggregate_by(&[members[0], members[2]], 2, 6, &hash);
    })
}

/// A block by node 1 on `e_alt`, which a node holding `d`, `e_alt` builds.
fn child_of_alternative(d: &Block, e_alt: &Block) -> Block {
    let (mut g, _, _) = support_chain(2);
    for block in [d, e_alt] {
        assert_eq!(
            receive(&mut g, block),
            ReceiveBlockOutcome::AcceptedSilently
        );
    }
    assert_eq!(head_of(&g), (7, e_alt.view().hash()));
    normal_after(&g, e_alt, 1, 81)
}

/// AC5 / AC6 / AC9 / AC4 — a switch over evidence on both branches: the
/// active `d, e` and the heavier `d, e', x8` (another valid evidence of
/// the same deviation, one block above it). The walk undoes `e` (the run
/// reopens at `d`: the exact inverse), applies `e'` (verified once, the
/// FR23 cross-check holds), and every value is exact.
#[test]
fn a_switch_judges_the_evidence_of_the_new_branch() {
    let (d, e, members) = evidence_by(2);
    let e_alt = alternative_evidence(&d, &e, &members);
    let x8 = child_of_alternative(&d, &e_alt);
    let (mut g, _, built) = evidence_observer(2);
    assert_eq!(built.serialized_bytes(), e.serialized_bytes());
    assert_eq!(receive(&mut g, &e), ReceiveBlockOutcome::AcceptedSilently);
    let verified = counted(&AGGREGATE_VERIFICATIONS);
    for block in [&e_alt, &x8] {
        assert_eq!(
            receive(&mut g, block),
            ReceiveBlockOutcome::AcceptedSilently
        );
    }
    assert_eq!(head_of(&g), (8, x8.view().hash()), "switched");
    assert!(entry_of(&g, &e_alt).expect("held").1);
    assert!(!entry_of(&g, &e).expect("held").1);
    assert_eq!(
        counted(&AGGREGATE_VERIFICATIONS) - verified,
        1,
        "e' once, on the walk"
    );
    assert!(entry_of(&g, &e_alt).expect("held").2);
    assert_eq!(g.active_open_run, NO_OPEN_RUN);
    assert_eq!(g.active_branch_value, window_value(&g));
}

/// AC6 — a switch to an evidence block that lies below the old head's
/// sequence: the active `x6..x8` (node 2's, worth nothing) gives way to
/// node 4's `d@6, e@7`, judged on the walk with the engine at `d`
/// below the old head #8. (The window is not full on this fixture, so the
/// counter's tail is #0 and the correction range is empty.)
#[test]
fn a_switch_to_an_evidence_below_the_old_head() {
    let (d, e, _) = evidence_by(4);
    let (mut g, _, blocks) = support_chain(3);
    let x6 = normal_after(&g, &blocks[5], 2, 61);
    assert_eq!(receive(&mut g, &x6), ReceiveBlockOutcome::AcceptedSilently);
    let x7 = normal_after(&g, &x6, 2, 62);
    assert_eq!(receive(&mut g, &x7), ReceiveBlockOutcome::AcceptedSilently);
    let x8 = normal_after(&g, &x7, 2, 63);
    assert_eq!(receive(&mut g, &x8), ReceiveBlockOutcome::AcceptedSilently);
    for x in [&x6, &x7, &x8] {
        assert_eq!(x.view().consumed_votes(), 0, "worth nothing");
    }
    assert_eq!(head_of(&g), (8, x8.view().hash()));
    let verified = counted(&AGGREGATE_VERIFICATIONS);
    for block in [&d, &e] {
        assert_eq!(
            receive(&mut g, block),
            ReceiveBlockOutcome::AcceptedSilently
        );
    }
    assert_eq!(
        head_of(&g),
        (7, e.view().hash()),
        "the lighter-by-length branch"
    );
    assert_eq!(counted(&AGGREGATE_VERIFICATIONS) - verified, 1);
    assert_eq!(g.active_open_run, NO_OPEN_RUN);
    assert_eq!(g.active_branch_value, window_value(&g));
}

/// AC6 / AC9 / AC4 — an aborted switch over a junk claim: `other`'s
/// deviation with an evidence claiming `u64::MAX` (worth
/// `value_cap::<16>()`) outweighs the active branch of `active` (its `d`
/// and evidence, or its `d` and a replay: the run left open). The walk
/// undoes the active blocks, refuses the junk at its Tier 3 (the vote
/// sum, before any aggregate verification), restores, and deletes it. The
/// restore verifies nothing again — no aggregate, and of the transaction
/// signatures only the new branch's `d` — and every value and the open run
/// are as before.
fn junk_switch_case(active: u32, other: u32, with_evidence: bool) {
    let (d_other, e_other, _) = evidence_by(other);
    let junk = evidence_with(&e_other, 2, |ev| ev.supporter_vote_sum = u64::MAX);
    assert_eq!(block_value::<16>(&junk.view()), value_cap::<16>());
    let (mut g, d, e) = evidence_observer(active);
    let top = if with_evidence {
        e
    } else {
        normal_after(&g, &d, active, 2)
    };
    assert_eq!(receive(&mut g, &top), ReceiveBlockOutcome::AcceptedSilently);
    let head = head_of(&g);
    assert_eq!(head, (7, top.view().hash()));
    let run = if with_evidence { NO_OPEN_RUN } else { 6 };
    assert_eq!(g.active_open_run, run);
    assert_eq!(
        receive(&mut g, &d_other),
        ReceiveBlockOutcome::AcceptedSilently
    );
    assert_eq!(head_of(&g), head, "d_other alone is lighter");
    let other_idx = g
        .blocks
        .find(6, &d_other.view().hash())
        .expect("a side block");
    let values = (
        g.active_branch_value,
        g.chain_heads.branch_value_of(other_idx),
    );
    assert_eq!(values.0, window_value(&g));
    let (aggregates, signatures) = (
        counted(&AGGREGATE_VERIFICATIONS),
        counted(&TX_SIGNATURE_VERIFICATIONS),
    );
    assert_eq!(
        receive(&mut g, &junk),
        ReceiveBlockOutcome::AcceptedSilently
    );
    assert_eq!(entry_of(&g, &junk), None, "deleted by the walk");
    assert_eq!(head_of(&g), head, "restored");
    assert_eq!(g.active_open_run, run, "the exact inverse");
    assert_eq!(counted(&AGGREGATE_VERIFICATIONS), aggregates);
    let other_txs = d_other.view().transactions().expect("txs").iter().count() as u32;
    assert_eq!(
        counted(&TX_SIGNATURE_VERIFICATIONS) - signatures,
        other_txs,
        "only d_other's, forward"
    );
    assert_eq!(
        (
            g.active_branch_value,
            g.chain_heads.branch_value_of(other_idx)
        ),
        values
    );
    assert_eq!(g.active_branch_value, window_value(&g));
    let (_, active, accepted, _) = entry_of(&g, &top).expect("held");
    assert!(active && accepted);
}

#[test]
fn an_aborted_switch_restores_without_judging_again() {
    junk_switch_case(4, 5, true);
}

#[test]
fn an_aborted_switch_restores_an_open_run() {
    junk_switch_case(5, 4, false);
}

/// AC6: a local fault in the step (`d`'s header unreadable from its first
/// read, the run rules') leaves the direct extension Stored, unmarked and
/// off the chain; once the read works, a later admission's continuation
/// judges it as a stored child of the head and accepts it.
#[test]
fn a_local_fault_leaves_the_evidence_unjudged() {
    let (_, e, _) = evidence_by(4);
    let (mut g, mut l, blocks) = support_chain_on(3, failing_storage(3), 16, |_| {});
    let d = deviation_after(&g, &blocks[5], 4, 1);
    assert_eq!(receive(&mut l, &d), ReceiveBlockOutcome::AcceptedSilently);
    assert_eq!(receive(&mut g, &d), ReceiveBlockOutcome::AcceptedSilently);
    let d_idx = l.active_chain_head_idx;
    l.storage.failing_slot = d_idx;
    assert_eq!(receive(&mut l, &e), ReceiveBlockOutcome::AcceptedSilently);
    let (status, _, accepted, _) = entry_of(&l, &e).expect("held");
    assert_eq!(status, BlockStatus::Stored);
    assert!(!accepted, "never marked on a local fault");
    assert_eq!(head_of(&l), (6, d.view().hash()));
    l.storage.failing_slot = NONE_REF;
    let verified = counted(&AGGREGATE_VERIFICATIONS);
    let sibling = normal_after(&g, &blocks[5], 2, 91);
    assert_eq!(
        receive(&mut l, &sibling),
        ReceiveBlockOutcome::AcceptedSilently
    );
    assert_eq!(head_of(&l), (7, e.view().hash()), "the stored child");
    assert_eq!(counted(&AGGREGATE_VERIFICATIONS) - verified, 1);
    assert!(entry_of(&l, &e).expect("held").2);
}

/// AC5 step 1 / AC6 (review): the evidence check's own read of `d`'s
/// header fails — the run rules' read before it succeeds — so the check
/// gives no verdict: the evidence is held Stored, unmarked, off the chain,
/// and nothing is verified.
#[test]
fn an_unreadable_deviation_header_in_the_evidence_check_is_local() {
    let (_, e, _) = evidence_by(4);
    let (mut g, mut l, blocks) = support_chain_on(3, failing_storage(3), 16, |_| {});
    let d = deviation_after(&g, &blocks[5], 4, 1);
    assert_eq!(receive(&mut l, &d), ReceiveBlockOutcome::AcceptedSilently);
    assert_eq!(receive(&mut g, &d), ReceiveBlockOutcome::AcceptedSilently);
    l.storage.failing_slot = l.active_chain_head_idx;
    l.storage.reads_left.set(1);
    let verified = counted(&AGGREGATE_VERIFICATIONS);
    assert_eq!(receive(&mut l, &e), ReceiveBlockOutcome::AcceptedSilently);
    assert!(
        l.storage.attempts.get() >= 2,
        "the run rules read d, then the check"
    );
    let (status, on_chain, accepted, _) = entry_of(&l, &e).expect("held");
    assert!(status == BlockStatus::Stored && !on_chain && !accepted);
    assert_eq!(counted(&AGGREGATE_VERIFICATIONS), verified);
    assert_eq!(head_of(&l), (6, d.view().hash()));
}

/// AC6: after a restart (FR59) the genesis-anchored pass judges the
/// evidence again — one verification — and accepts it.
#[test]
fn a_restart_judges_the_evidence_again() {
    let (mut g, _, e) = evidence_observer(4);
    assert_eq!(receive(&mut g, &e), ReceiveBlockOutcome::AcceptedSilently);
    let mut restarted = local_node(0, g.storage);
    let verified = counted(&AGGREGATE_VERIFICATIONS);
    let (outcome, _) = restarted.initialize_from_storage(500);
    assert_eq!(outcome, InitOutcome::ResumedReady);
    assert_eq!(head_of(&restarted), (7, e.view().hash()));
    assert_eq!(counted(&AGGREGATE_VERIFICATIONS) - verified, 1, "re-judged");
    assert!(entry_of(&restarted, &e).expect("held").2);
    assert_eq!(restarted.active_open_run, NO_OPEN_RUN);
}

// -- AC7: the FR3 pass --

/// AC7: a genesis-anchored pass checks the evidence exactly: a restart
/// over storage holding an evidence with a wrong vote sum refuses it
/// (FR5) and goes Ready on `d`.
#[test]
fn a_genesis_anchored_pass_refuses_an_invalid_evidence() {
    let (mut g, d, e) = evidence_observer(4);
    let junk = evidence_with(&e, 2, |ev| ev.supporter_vote_sum += 1);
    let idx = g.blocks.next_free_index().expect("a free slot");
    g.storage.save_block(idx, &junk).ok().expect("save");
    let mut restarted = local_node(0, g.storage);
    restarted.initialize_from_storage(500);
    assert!(restarted.is_ready());
    assert_eq!(head_of(&restarted), (6, d.view().hash()));
    assert_eq!(entry_of(&restarted, &junk), None, "deleted by FR5");
}

/// AC7 (D5) unit-level on Story 6.4's chain (`W = 16 > p`): in a
/// window-anchored pass the window at `p − 1` never lies in the segment,
/// so a junk claim is trusted; a genesis-anchored pass checks it exactly.
#[test]
fn a_window_anchored_pass_trusts_an_evidence_without_its_window() {
    let (mut g, _, e) = evidence_observer(4);
    let junk = evidence_with(&e, 2, |ev| ev.supporter_vote_sum += 1);
    let verified = counted(&AGGREGATE_VERIFICATIONS);
    assert_eq!(
        judge_on(&mut g, &junk, &window_anchored(0)),
        Ok(()),
        "trusted"
    );
    assert_eq!(
        counted(&AGGREGATE_VERIFICATIONS),
        verified,
        "nothing verified"
    );
    let genesis = Projection {
        counter_tail: u32::MAX,
        ..Projection::COMPLETE
    };
    assert_eq!(
        judge_on(&mut g, &junk, &genesis),
        Err(Some(ValidationReason::EvidenceVoteSum))
    );
    assert_eq!(judge_on(&mut g, &e, &genesis), Ok(()));
    assert_eq!(counted(&AGGREGATE_VERIFICATIONS) - verified, 1);
}

/// Story 6.4's chain on `W = 8` (`H = 4`), with node 2's clean blocks
/// `x6`, `x7` and node 5's balance deviation `d@8` (listing node 2; it drops
/// #0, node #0's seed source, as its replay): the window at `p − 1` is
/// `[0, 7]`, so `p − W = 0`, and `A' = {0, 2, 3, 4}` (`m = 4`, `r_eff = 3`).
/// Returns node #0 at `d` and node 5's evidence (built, never admitted: its
/// own drop of #1 would need a chain-config replay).
fn w8_evidence() -> (SupportChain, Block) {
    let (mut g, mut l, blocks) = support_chain_on(5, local_storage(5), 8, |_| {});
    let x6 = normal_after(&g, &blocks[5], 2, 61);
    for node in [&mut g, &mut l] {
        assert_eq!(receive(node, &x6), ReceiveBlockOutcome::AcceptedSilently);
    }
    let x7 = normal_after(&g, &x6, 2, 62);
    for node in [&mut g, &mut l] {
        assert_eq!(receive(node, &x7), ReceiveBlockOutcome::AcceptedSilently);
    }
    let top = g.vote_engine.top_creator().expect("a top");
    let snapshot = |n| vote_snapshot(g.vote_engine.accumulated_vote_of(n));
    let template = balance_snapshot(&g, 8, x7.view().hash(), &[2]);
    let d = reheader(&template, 5, snapshot(5), top, snapshot(top), key_of(5));
    for node in [&mut g, &mut l] {
        assert_eq!(receive(node, &d), ReceiveBlockOutcome::AcceptedSilently);
        assert_eq!(head_of(node), (8, d.view().hash()));
    }
    let d_idx = l.active_chain_head_idx;
    accumulate(&mut l, &d, d_idx, 3);
    let e = l.build_evidence_block(d_idx, 0).expect("evidence");
    (g, e)
}

/// Review (D5) — the window condition is judged before `d` is resolved:
/// an evidence whose `d` the pass cannot resolve (here above the tip) is
/// trusted under `p − W < a`, and a local fault only in the exact zone.
#[test]
fn the_window_condition_is_judged_before_d() {
    let (mut g, e) = w8_evidence();
    let unresolvable = evidence_with(&e, 3, |ev| ev.deviation_sequence = 100);
    assert_eq!(
        judge_on(&mut g, &unresolvable, &window_anchored(200)),
        Ok(())
    );
    assert_eq!(
        judge_on(&mut g, &unresolvable, &window_anchored(0)),
        Err(None),
        "the exact zone"
    );
}

/// AC7 (D5) — the exact zone of a window-anchored pass. Nodes from #2 on
/// count as registered inside the segment; #0 (seed source #0) and #1
/// (seed source #2) are vote-seeded through their sources, below `p`. With
/// `p − W = a` the evidence is then checked exactly (the real one
/// verifies, a junk claim is refused); trusted when each condition fails
/// alone: `p − W = a − 1`, the roster unknown, node #0's source below
/// `vote_seed_from`, and node 2 judged by its source, which is `d` itself
/// (its balance lists node 2): seeded at `p` only, so its vote at `p − 1`
/// is not known to be exact.
#[test]
fn a_window_anchored_pass_checks_its_exact_zone() {
    let (mut g, e) = w8_evidence();
    let junk = evidence_with(&e, 3, |ev| ev.supporter_vote_sum += 1);
    let base = || Projection {
        first_segment_registration: 2,
        ..window_anchored(0)
    };
    let exact = base();
    let verified = counted(&AGGREGATE_VERIFICATIONS);
    assert_eq!(judge_on(&mut g, &e, &exact), Ok(()));
    assert_eq!(counted(&AGGREGATE_VERIFICATIONS) - verified, 1, "exact");
    assert_eq!(
        judge_on(&mut g, &junk, &exact),
        Err(Some(ValidationReason::EvidenceVoteSum)),
        "every node seeded below p: exact"
    );
    for (projection, why) in [
        (
            Projection {
                anchor: 1,
                ..base()
            },
            "p − W = a − 1",
        ),
        (
            Projection {
                roster_bounded: false,
                ..base()
            },
            "the roster unknown",
        ),
        (
            Projection {
                vote_seed_from: 1,
                ..base()
            },
            "node #0 not vote-seeded",
        ),
        (
            Projection {
                first_segment_registration: 3,
                ..base()
            },
            "node 2 seeded at `p` only",
        ),
    ] {
        assert_eq!(judge_on(&mut g, &junk, &projection), Ok(()), "{why}");
    }
}

// -- AC9: the FR21 value arm --

/// AC9 (D7): an evidence block counts its claimed `supporter_vote_sum`,
/// clamped at `value_cap`: `u64::MAX` counts the cap, the cap and one below
/// count themselves.
#[test]
fn an_evidence_counts_its_claim_clamped_at_the_cap() {
    let (_, e, _) = evidence_by(4);
    let claimed = evidence_of(&e, 2).supporter_vote_sum;
    assert!(claimed > 0);
    assert_eq!(block_value::<16>(&e.view()), claimed);
    let cap = value_cap::<16>();
    for (claim, value) in [(u64::MAX, cap), (cap, cap), (cap - 1, cap - 1)] {
        let block = evidence_with(&e, 2, |ev| ev.supporter_vote_sum = claim);
        assert_eq!(block_value::<16>(&block.view()), value);
    }
}

// -- AC10: the stop on active evidence and the proposer's release --

/// AC10 (D3): the proposer's own evidence held as a side block (the
/// heavier `y@6` active) releases its accumulator, and the builder
/// refuses a tip at or above it.
#[test]
fn the_own_side_evidence_releases_the_accumulator() {
    let (_, mut l, _, d, d_idx, y) = sibling_proposer();
    accumulate(&mut l, &d, d_idx, 2);
    let e = l.build_evidence_block(d_idx, 0).expect("evidence");
    assert!(l.approval_live());
    plant_child(&mut l, &e, d_idx, true, true);
    let e_idx = l.blocks.find(7, &e.view().hash()).expect("held");
    assert!(
        !l.blocks.get(e_idx).expect("e").is_on_active_chain(),
        "a side block"
    );
    assert_eq!(head_of(&l), (6, y.view().hash()));
    assert!(!l.approval_live(), "released");
    assert!(l.build_evidence_block(d_idx, 0).is_none());
    assert!(l.build_evidence_block(e_idx, 0).is_none());
    assert_eq!(
        l.approval_step(7, Ok(TailObligation::None), 0, 0),
        ApprovalStep::Hold
    );
}

/// AC10 (D3): an evidence at `p` on another fork (its `p − 1` is not the
/// proposer's) stops nothing, even the proposer's own (review: the
/// ancestry condition of the release, not the creator's).
#[test]
fn an_evidence_on_another_fork_stops_nothing() {
    let (_, e, _) = evidence_by(4);
    let ev = evidence_of(&e, 2);
    let (g, mut l, blocks, _, d_idx) = proposer_chain(5);
    assert!(l.open_approval(d_idx));
    let x5 = normal_after(&g, &blocks[4], 2, 51);
    let x6 = normal_after(&g, &x5, 2, 52);
    for block in [&x5, &x6] {
        assert_eq!(
            receive(&mut l, block),
            ReceiveBlockOutcome::AcceptedSilently
        );
    }
    let x6_idx = l.blocks.find(6, &x6.view().hash()).expect("held");
    let other = evidence_block(7, x6.view().hash(), 5, &ev);
    assert_eq!(evidence_of(&other, 2).deviation_sequence, 6);
    plant_child(&mut l, &other, x6_idx, true, true);
    assert!(l.approval_live(), "another p − 1");
}

// -- AC13.3: AR16 replay --

/// AR16: one block stream — a deviation, an evidence with a wrong vote
/// sum, the valid one, a competing deviation and its junk claim — on two fresh modules gives identical
/// verdicts, heads, open runs and branch values.
#[test]
fn evidence_verdicts_are_replay_deterministic() {
    let (d4, e4, _) = evidence_by(4);
    let (d5, e5, _) = evidence_by(5);
    let bad_sum = evidence_with(&e4, 2, |ev| ev.supporter_vote_sum += 1);
    let junk = evidence_with(&e5, 2, |ev| ev.supporter_vote_sum = u64::MAX);
    let stream = [&d4, &bad_sum, &e4, &d5, &junk];
    let run = || {
        let (_, mut l, _) = support_chain(3);
        let outcomes: std::vec::Vec<ReceiveBlockOutcome> =
            stream.iter().map(|block| receive(&mut l, block)).collect();
        (
            outcomes,
            head_of(&l),
            l.active_open_run,
            l.active_branch_value,
            stream.map(|block| entry_of(&l, block).map(|entry| entry.0)),
        )
    };
    let first = run();
    assert_eq!(first.1, (7, e4.view().hash()));
    assert_eq!(
        first.0[1],
        ReceiveBlockOutcome::Rejected(RejectReason::InvalidEvidence)
    );
    assert_eq!(first.4[4], None, "the junk deleted");
    assert_eq!(first, run());
}

// -- Story 6.7 follow-up: the evidence check's local faults (N24a, N23),
// the tentative intake (N31), the registration signature on restore (N35b) --

/// Node 4's `d@6`, its replay `r@7`, its evidence `e@8` built over `r` (the
/// rewind reads `r`), and node 2's sibling `x@6` (a later admission).
fn replay_evidence() -> (Block, Block, Block, Block) {
    let (mut g, mut l, blocks, d, d_idx) = proposer_chain(4);
    let sibling = normal_after(&g, &blocks[5], 2, 91);
    assert_eq!(receive(&mut g, &d), ReceiveBlockOutcome::AcceptedSilently);
    let r = normal_after(&g, &d, 4, 2);
    assert_eq!(receive(&mut l, &r), ReceiveBlockOutcome::AcceptedSilently);
    accumulate(&mut l, &d, d_idx, 2);
    let tip = l.active_chain_head_idx;
    let e = l.build_evidence_block(tip, 0).expect("evidence over r");
    assert_eq!(e.view().sequence(), 8);
    (d, r, e, sibling)
}

/// Node 3 over a failing backend, Ready at `r` (`d`, `r` received).
fn failing_observer(d: &Block, r: &Block) -> Chain16<FailingSupportStorage> {
    let (_, mut l, _) = support_chain_on(3, failing_storage(3), 16, |_| {});
    for block in [d, r] {
        assert_eq!(
            receive(&mut l, block),
            ReceiveBlockOutcome::AcceptedSilently
        );
    }
    assert_eq!(head_of(&l), (7, r.view().hash()));
    l
}

/// N24a (AC5) — a refused rewind is a local fault, not evidence: with
/// `r`'s slot unreadable the projection cannot undo `r` (the run rules
/// read only `d`'s header and pass), so the evidence is admitted Stored,
/// unmarked and off the chain, the head unchanged; once the read works, a
/// later admission's continuation judges it and accepts it.
#[test]
fn an_unreadable_rewind_leaves_the_evidence_stored() {
    let (d, r, e, sibling) = replay_evidence();
    let mut l = failing_observer(&d, &r);
    l.storage.failing_slot = l.active_chain_head_idx;
    assert_eq!(receive(&mut l, &e), ReceiveBlockOutcome::AcceptedSilently);
    assert!(l.storage.attempts.get() > 0, "the rewind read r");
    let (status, active, accepted, _) = entry_of(&l, &e).expect("held, not deleted");
    assert_eq!(
        (status, active, accepted),
        (BlockStatus::Stored, false, false),
        "unjudged and unmarked"
    );
    assert_eq!(head_of(&l), (7, r.view().hash()));
    assert!(l.is_ready());
    l.storage.failing_slot = NONE_REF;
    let verified = counted(&AGGREGATE_VERIFICATIONS);
    assert_eq!(
        receive(&mut l, &sibling),
        ReceiveBlockOutcome::AcceptedSilently
    );
    assert_eq!(head_of(&l), (8, e.view().hash()), "judged and accepted");
    assert_eq!(counted(&AGGREGATE_VERIFICATIONS) - verified, 1);
    assert!(entry_of(&l, &e).expect("held").2);
}

/// N23 (AC8) — a failed restore inside the evidence check escalates at the
/// root: `r`'s first read (the rewind's undo) succeeds and its second (the
/// restore's re-apply) fails once. The check returns a local fault and
/// marks the re-entry due; the root skips the continuation, the driver and
/// the comparison while it is due (the engine is not at `r`), and
/// `receive_block` then re-enters collecting, whose spine re-derives the
/// tree and reaches Ready again at the evidence. Nothing is deleted, the
/// flag is consumed, and the engine equals a node that judged the evidence
/// without a fault.
#[test]
fn a_failed_restore_in_the_evidence_check_reenters_at_the_root() {
    let (d, r, e, _) = replay_evidence();
    let reference = {
        let mut clean = failing_observer(&d, &r);
        assert_eq!(
            receive(&mut clean, &e),
            ReceiveBlockOutcome::AcceptedSilently
        );
        assert_eq!(head_of(&clean), (8, e.view().hash()));
        engine_votes(&clean)
    };
    let mut l = failing_observer(&d, &r);
    l.storage.failing_slot = l.active_chain_head_idx;
    l.storage.reads_left.set(1);
    l.storage.failures_left.set(1);
    assert_eq!(receive(&mut l, &e), ReceiveBlockOutcome::AcceptedSilently);
    assert!(l.storage.attempts.get() >= 2, "the restore's read of r");
    assert_eq!(l.storage.failures_left.get(), 0, "the fault was hit");
    assert!(!l.reentry_due, "consumed at the root");
    assert!(l.is_ready(), "the re-entry's spine reached Ready again");
    assert_eq!(head_of(&l), (8, e.view().hash()));
    let (status, active, accepted, _) = entry_of(&l, &e).expect("not deleted");
    assert!(status == BlockStatus::Active && active && accepted);
    assert_eq!(
        engine_votes(&l),
        reference,
        "re-derived, not the broken engine"
    );
}

/// N31 (AC4, FR9) — outside Ready, intake judges rules 1–3 only until the
/// configuration is durably locked: a Collecting node holding the
/// tentative configuration of #1 (no genesis #0, so it stays Collecting)
/// admits a registration at the slot #7 (rule 5 waits for the lock), and
/// refuses a foreign creator above node 4's open run at #6
/// (`DeviationRun`).
#[test]
fn a_tentative_intake_judges_only_rules_one_to_three() {
    let (blocks, d, x6, foreign) = {
        let (mut g, _, blocks) = support_chain(3);
        let d = deviation_after(&g, &blocks[5], 4, 1);
        let x6 = normal_after(&g, &blocks[5], 2, 61);
        assert_eq!(receive(&mut g, &d), ReceiveBlockOutcome::AcceptedSilently);
        let foreign = normal_after(&g, &d, 3, 71);
        (blocks, d, x6, foreign)
    };
    let unclean = register(7, x6.view().hash(), 6, key_of(6));
    let mut c = local_node(3, local_storage(3));
    for block in blocks[1..].iter().chain([&d, &x6]) {
        assert_eq!(
            receive(&mut c, block),
            ReceiveBlockOutcome::AcceptedSilently
        );
    }
    assert_eq!(c.lifecycle_phase, LifecyclePhase::Collecting);
    assert!(c.chain_config.active_configuration().is_some(), "tentative");
    assert!(!c.chain_config.is_durable_locked());
    assert_eq!(
        slot_rule(&unclean.view(), Some(TEST_H)),
        Err(ValidationReason::SlotNotClean)
    );
    assert_eq!(
        receive(&mut c, &unclean),
        ReceiveBlockOutcome::AcceptedSilently,
        "rule 5 waits for the lock"
    );
    assert!(entry_of(&c, &unclean).is_some());
    assert_eq!(
        c.tier1_admit(&foreign.view(), &foreign.view().hash(), 0),
        Err(AdmitError::Rejected(Tier1Failure::DeviationRun))
    );
    assert_eq!(
        receive(&mut c, &foreign),
        ReceiveBlockOutcome::Rejected(RejectReason::InvalidEvidence)
    );
    assert_eq!(entry_of(&c, &foreign), None, "not stored");
}

/// N35b (AC6) — the registration signature is final with bit 6: an
/// aborted switch over junk undoes and restores node 1's registration
/// block `x6` (heavier than node 5's `d@6`) without verifying its
/// registration again; only `d`'s transaction is verified, forward.
#[test]
fn a_restore_verifies_no_registration_again() {
    let (d5, e5, _) = evidence_by(5);
    let junk = evidence_with(&e5, 2, |ev| ev.supporter_vote_sum = u64::MAX);
    let (mut g, _, blocks) = support_chain(3);
    let x6 = real_on(
        &g,
        &register(6, blocks[5].view().hash(), 6, key_of(6)),
        1,
        key_of(1),
    );
    assert!(
        x6.view().consumed_votes() > d5.view().consumed_votes(),
        "x6 is heavier"
    );
    assert_eq!(receive(&mut g, &x6), ReceiveBlockOutcome::AcceptedSilently);
    assert_eq!(receive(&mut g, &d5), ReceiveBlockOutcome::AcceptedSilently);
    assert_eq!(head_of(&g), (6, x6.view().hash()));
    let value = g.active_branch_value;
    let signatures = counted(&TX_SIGNATURE_VERIFICATIONS);
    assert_eq!(
        receive(&mut g, &junk),
        ReceiveBlockOutcome::AcceptedSilently
    );
    assert_eq!(entry_of(&g, &junk), None, "deleted by the walk");
    assert_eq!(head_of(&g), (6, x6.view().hash()), "restored");
    assert_eq!(
        g.node_info.max_known_node_id(),
        6,
        "the registration restored"
    );
    let d_txs = d5.view().transactions().expect("txs").iter().count() as u32;
    assert_eq!(counted(&TX_SIGNATURE_VERIFICATIONS) - signatures, d_txs);
    assert_eq!(g.active_branch_value, value);
}
