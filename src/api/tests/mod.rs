//! Tests of `api`: the harness (test sizes and configurations, storage and
//! crypto backends, the base constructors). Each test file holds the tests of
//! one production area of `api`; fixtures used by more than one test file,
//! the shared chain constructors among them, live in `fixtures.rs`.

use super::*;
use moonblokz_chain_types::{ChainConfigPayloadBuilder, MAX_BLOCK_SIZE, NODE_TRANSFER_SIZE};
use moonblokz_configuration::{ChainConfiguration, NoopConfigChangeSink, parameter};
use moonblokz_crypto::{
    AggregatedSignature, Crypto, CryptoError, MultiSignature, PRIVATE_KEY_SIZE, PublicKey,
    Signature, SignatureTrait,
};
use moonblokz_storage::{
    ControlPlaneData, INIT_PARAMS_SIZE, StorageError, backend_memory::MemoryBackend,
};

use crate::snake_chain::{TailBinding, TailObligation, tail_drop_binding};

use crate::approval::node_value;
use crate::approval::test_seams::set_grace_admits;

use crate::approval::test_seams::{
    BLOCK_SIGNATURE_VERIFICATIONS, SUBGROUP_EVALS, VERIFICATIONS, counted,
};
use moonblokz_crypto::{AGGREGATED_SIGNATURE_CONSTANT_SIZE, AGGREGATED_SIGNATURE_VARIABLE_SIZE};

use crate::approval::test_seams::{AGGREGATE_VERIFICATIONS, TX_SIGNATURE_VERIFICATIONS};

mod acquisition;
mod admission;
mod chain_config;
mod crediting;
mod evidence;
mod fact;
mod fixtures;
mod forward;
mod genesis;
mod intake;
mod late_hold;
mod proposer;
mod restart;
mod rules;
mod support;
mod switch;
mod twin;
mod utxo;
mod window;

use fixtures::*;

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
/// The fixtures' registration price: the registry default of ID 24 (no test
/// configuration declares it), which the per-block step checks for equality
/// (DEC-312).
const TEST_REGISTRATION_PRICE: u64 = 100;
/// The fixtures' registration fee: the FR56 minimum at the registry default
/// `tx_fee_per_byte_min = 1` (DEC-181), one per byte.
const TEST_REGISTRATION_FEE: u64 = REGISTRATION_SIZE as u64;
/// The fixtures' node-transfer fee: the FR56 minimum at the registry default.
const TEST_TRANSFER_FEE: u32 = NODE_TRANSFER_SIZE as u32;
/// The fee the fixtures' complex transactions pay (`Σ in − Σ out`): at least
/// the size of every complex transaction the tests build, on every scheme
/// (FR56 at the default minimum of 1 per byte), and within the default
/// maximum of 1 000 per byte.
const CX_FEE: u64 = 1_000;

/// The test chains' mempool: the smallest buffer the crate admits (one block,
/// `COMPACT_BYTES ≥ MAX_BLOCK_SIZE`) and 16 entries — small, so a test may
/// hold several chains on one thread.
const TEST_MEMPOOL_BYTES: usize = MAX_BLOCK_SIZE;
const TEST_MEMPOOL_ENTRIES: usize = 16;

/// The available-UTXO bitfield bytes of every test chain: the production value
/// (DEC-318), 32 outputs per block.
const TEST_UTXO_BYTES: usize = 4;

/// The base override set as a **content region**: literal entries declaring
/// `active_chain_length = TEST_W`, its horizon and the node cap. Every other
/// parameter resolves to its code-baked default — `vote_interest` to 100
/// (DEC-176, DEC-343), so the suite runs at the production rate. The last entry
/// declares the build's signature scheme ([`declare_build_scheme`]).
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
/// identically: the base entries plus a literal declaring `mining_reward`'s
/// own default 0. Used where a test needs two different chain-config contents.
const OTHER_CONFIG_CONTENT: [u8; 29] = [
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
    parameter::MINING_REWARD,
    4,
    0,
    0,
    0,
    0,
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
    TEST_UTXO_BYTES,
    TEST_MEMPOOL_BYTES,
    TEST_MEMPOOL_ENTRIES,
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
