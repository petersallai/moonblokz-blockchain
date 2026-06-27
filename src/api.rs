//! Primary public API surface for `moonblokz-blockchain` (FR66). All
//! blockchain-facing state is reachable only through types defined or
//! re-exported here; internal modules stay crate-private. The temporary
//! `chain_config` seam remains public only until the standalone
//! `moonblokz-configuration` crate exists.
//!
//! Story 1.3 scope: trait seams (`CryptoTrait`/`StorageTrait`/
//! `ChainConfigTrait`), construction-time init parameters
//! (`local_node_id`/`node_zero_public_key`/`prng_seed`), and the
//! Xoshiro-rooted replay seam. The full 18-method method set and outcome
//! enums arrive in Story 1.4+ per architecture §3.1–§3.6.
//!
//! Replay determinism — the module performs **no internal wall-clock reads
//! and no internal entropy source**. Callers supply `prng_seed: u64` at
//! construction and `now: u64` to every state-changing method (forthcoming),
//! so the same construction inputs + the same event sequence yield identical
//! state (FR62 / FR63 precondition).

use moonblokz_crypto::{CryptoTrait, PUBLIC_KEY_SIZE};
use moonblokz_storage::StorageTrait;

use crate::chain_config::ChainConfigTrait;
use crate::prng::Prng;

/// Next-call deadline carried alongside every state-changing outcome.
///
/// Single-outcome scheduling-pull pattern (architecture §3.2): each
/// state-changing call returns at most one semantic outcome plus a
/// [`NextCall`] telling the bridge layer when to call back via
/// `embassy_time::Timer::at(...)`.
// Deliberately no derives yet: in the embedded target, every generated trait impl
// must justify its code-size cost. Re-evaluate Copy/Clone/Debug only when a later
// story demonstrates a concrete API/scheduler need.
pub enum NextCall {
    /// Call back at the given absolute monotonic timestamp (ms).
    /// `At(now)` (or any past instant) means "call back as soon as possible".
    At(u64),
    /// Nothing scheduled; do not wake.
    Idle,
}

/// `(outcome, scheduling)` pair returned by every state-changing API call.
pub type CallResult<T> = (T, NextCall);

/// Authoritative-interpretation lifecycle phase (FR1–FR4).
///
/// - `Collecting`: empty chain or accumulating tree; query surfaces return
///   not-ready (FR1, FR14, FR42).
/// - `Processing`: full-chain reconstruction in progress (FR3).
/// - `Ready`: validated active chain; full intake/query surface available
///   (FR4, FR9 fully active).
// `PartialEq`/`Eq` are needed for lifecycle gate checks and phase-transition
// assertions in the planned state machine. Avoid Copy/Clone until a concrete
// later story needs value duplication beyond borrowing/matching.
#[derive(PartialEq, Eq)]
pub enum LifecyclePhase {
    Collecting,
    Processing,
    Ready,
}

/// Authoritative blockchain state for a MoonBlokz node.
///
/// Const generics define the compile-time-bounded memory model (AR9 /
/// architecture §5). No runtime allocation occurs at any point — every
/// internal buffer is sized from these parameters.
///
/// `Crypto`, `Storage`, and `Config` are the adjacent-component seams:
/// - `Crypto: CryptoTrait` — the module calls `crypto.sign` / `crypto.verify`
///   through the handle; it never holds raw signing-key bytes (FR68, AR13).
/// - `Storage: StorageTrait` — the module persists and reads state through
///   the trait; storage is a service it consumes (FR66 boundary).
/// - `Config: ChainConfigTrait` — chain-configurable parameters arrive via
///   the trait; the AR14 [`FixedChainConfig`](crate::FixedChainConfig) stub
///   satisfies it in MVP.
///
/// Defaults (architecture §5): `MAX_NODES = 1000`,
/// `SNAKE_CHAIN_LENGTH = 500`, `VERIFICATION_HORIZON = 20`,
/// `MAX_BLOCKS = 600`, `MAX_BRANCH_COUNT = 40`,
/// `MAX_BLOCK_UTXO_OUTPUT = 256`.
// Fields are consumed by the state-changing methods landing in Story 1.4+;
// silencing dead_code here keeps the scaffold clean.
#[allow(dead_code)]
pub struct Blockchain<
    Crypto: CryptoTrait,
    Storage: StorageTrait,
    Config: ChainConfigTrait,
    const MAX_NODES: usize,
    const SNAKE_CHAIN_LENGTH: usize,
    const VERIFICATION_HORIZON: usize,
    const MAX_BLOCKS: usize,
    const MAX_BRANCH_COUNT: usize,
    const MAX_BLOCK_UTXO_OUTPUT: usize,
> {
    // Adjacent-component handles (immutable construction inputs).
    crypto: Crypto,
    storage: Storage,
    chain_config: Config,

    // FR67 / FR69 / AR11 immutable construction inputs.
    local_node_id: u32,
    node_zero_public_key: [u8; PUBLIC_KEY_SIZE],
    prng: Prng,

    // Const-sized placeholders for future real bounded tables (Story 1.2).
    // `()` is zero-sized until the owning story replaces it with the real
    // entry layout (Story 4.1 / 4.4 / 7.1).
    _blocks: [(); MAX_BLOCKS],
    _chain_heads: [(); MAX_BRANCH_COUNT],
    _node_info: [(); MAX_NODES],

    // Real snake-chain state is two block-table indices, not a W-sized
    // window. `SNAKE_CHAIN_LENGTH` remains an algorithmic bound for
    // maintaining the tail index relative to the active head.
    _active_chain_head_idx: u32,
    _snake_chain_tail_idx: u32,
    //
    // Deliberately no standalone placeholders for:
    // - `VERIFICATION_HORIZON`: cheap/deep-zone algorithm boundary only.
    // - `MAX_BLOCK_UTXO_OUTPUT`: later consumed inside `BlockEntry.spent_bits`.
}

impl<
    Crypto: CryptoTrait,
    Storage: StorageTrait,
    Config: ChainConfigTrait,
    const MAX_NODES: usize,
    const SNAKE_CHAIN_LENGTH: usize,
    const VERIFICATION_HORIZON: usize,
    const MAX_BLOCKS: usize,
    const MAX_BRANCH_COUNT: usize,
    const MAX_BLOCK_UTXO_OUTPUT: usize,
>
    Blockchain<
        Crypto,
        Storage,
        Config,
        MAX_NODES,
        SNAKE_CHAIN_LENGTH,
        VERIFICATION_HORIZON,
        MAX_BLOCKS,
        MAX_BRANCH_COUNT,
        MAX_BLOCK_UTXO_OUTPUT,
    >
{
    /// Constructs a `Blockchain` with adjacent-component handles and
    /// construction-time init parameters (FR67, FR69, AR11).
    ///
    /// Parameters:
    /// - `crypto`/`storage`/`chain_config`: adjacent-component seam handles.
    ///   The module never receives raw signing-key bytes — only the `crypto`
    ///   handle (FR68 / AR13).
    /// - `local_node_id`: this node's canonical id on the active chain (FR67).
    /// - `node_zero_public_key`: node-zero trust anchor (FR69), sized via
    ///   `moonblokz_crypto::PUBLIC_KEY_SIZE` (backend-derived).
    /// - `prng_seed`: deterministic-replay PRNG root (AR11 / FR62 precondition).
    ///
    /// All init parameters are stored as immutable construction inputs; the
    /// module performs no internal wall-clock reads and no internal entropy
    /// source — callers must supply `now: u64` to every state-changing
    /// method (forthcoming in Story 1.4+).
    pub fn new(
        crypto: Crypto,
        storage: Storage,
        chain_config: Config,
        local_node_id: u32,
        node_zero_public_key: [u8; PUBLIC_KEY_SIZE],
        prng_seed: u64,
    ) -> Self {
        Self {
            crypto,
            storage,
            chain_config,
            local_node_id,
            node_zero_public_key,
            prng: Prng::new(prng_seed),
            _blocks: [(); MAX_BLOCKS],
            _chain_heads: [(); MAX_BRANCH_COUNT],
            _node_info: [(); MAX_NODES],
            _active_chain_head_idx: 0,
            _snake_chain_tail_idx: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain_config::FixedChainConfig;
    use moonblokz_chain_types::MAX_BLOCK_SIZE;
    use moonblokz_crypto::{Crypto, PRIVATE_KEY_SIZE};
    use moonblokz_storage::backend_memory::MemoryBackend;

    /// End-to-end integration smoke: constructs a real `Blockchain` with a
    /// real Schnorr (crypto-bigint) backend, a real `MemoryBackend`, and the
    /// AR14 `FixedChainConfig` stub. Proves the trait-bound seam compiles
    /// and constructs without panic or allocation.
    #[test]
    fn blockchain_new_constructs_a_real_instance() {
        let private_key = [1u8; PRIVATE_KEY_SIZE];
        // `Result::expect` requires `Debug` on the error, but `moonblokz-crypto`
        // intentionally omits derives on `CryptoError` (embedded code-size). Use
        // `.ok().expect(...)` to side-step the Debug bound while still panicking
        // cleanly on failure.
        let crypto = Crypto::new(private_key)
            .ok()
            .expect("test private key should be accepted by the backend");

        // Small in-memory storage capacity for the smoke test.
        let storage = MemoryBackend::<{ 8 * MAX_BLOCK_SIZE + 8000 }>::new();
        let chain_config = FixedChainConfig::new();
        let node_zero_public_key = [0u8; PUBLIC_KEY_SIZE];

        let _bc = Blockchain::<_, _, _, 16, 16, 4, 16, 4, 16>::new(
            crypto,
            storage,
            chain_config,
            42,
            node_zero_public_key,
            0xDEAD_BEEF_CAFE_F00D,
        );
    }
}
