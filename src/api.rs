//! Public API surface — the sole outward boundary of `moonblokz-blockchain`
//! (FR66). All blockchain-facing state is reachable only through types
//! defined or re-exported here; internal modules stay crate-private.
//!
//! Skeleton scope (Story 1.2): the [`Blockchain`] struct, const-generic
//! parameters, and the scheduling-pull primitives ([`NextCall`],
//! [`CallResult`], [`LifecyclePhase`]). The full 18-method method set,
//! trait bounds on `Crypto`/`Storage`/`Config`, outcome enums, and concrete
//! field layouts arrive in Story 1.3+ per architecture §3.1–§3.6.

use core::marker::PhantomData;

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
/// - `Crypto`: crypto backend (Story 1.3 will bound `Crypto: CryptoTrait`).
/// - `Storage`: storage backend (Story 1.3 will bound `Storage: StorageTrait`).
/// - `Config`: chain-configuration accessor (Story 1.3 will bound
///   `Config: ChainConfigTrait`).
///
/// Defaults (architecture §5): `MAX_NODES = 1000`,
/// `SNAKE_CHAIN_LENGTH = 500`, `VERIFICATION_HORIZON = 20`,
/// `MAX_BLOCKS = 600`, `MAX_BRANCH_COUNT = 40`,
/// `MAX_BLOCK_UTXO_OUTPUT = 256`.
pub struct Blockchain<
    Crypto,
    Storage,
    Config,
    const MAX_NODES: usize,
    const SNAKE_CHAIN_LENGTH: usize,
    const VERIFICATION_HORIZON: usize,
    const MAX_BLOCKS: usize,
    const MAX_BRANCH_COUNT: usize,
    const MAX_BLOCK_UTXO_OUTPUT: usize,
> {
    // Const-sized placeholders for future real bounded tables. These satisfy
    // AC3 without pretending that every const generic owns a standalone buffer.
    // `()` is zero-sized until the owning story replaces it with the real entry
    // layout.
    _blocks: [(); MAX_BLOCKS],
    _chain_heads: [(); MAX_BRANCH_COUNT],
    _node_info: [(); MAX_NODES],

    // Real snake-chain state is two block-table indices, not a W-sized window.
    // `SNAKE_CHAIN_LENGTH` remains an algorithmic bound for maintaining the
    // tail index relative to the active head.
    _active_chain_head_idx: u32,
    _snake_chain_tail_idx: u32,

    // Deliberately no standalone placeholders for:
    // - `VERIFICATION_HORIZON`: cheap/deep-zone algorithm boundary only.
    // - `MAX_BLOCK_UTXO_OUTPUT`: later consumed inside `BlockEntry.spent_bits`.
    _phantom: PhantomData<(Crypto, Storage, Config)>,
}
