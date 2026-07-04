//! Deterministic pseudo-random source (AR11 / architecture §2.3).
//!
//! [`Prng`] wraps `rand_xoshiro::Xoshiro256PlusPlus` (256-bit state, no_std,
//! PractRand >2 TB) as the root PRNG seeded from the caller-supplied
//! `prng_seed`. The blockchain hands `derive_subseed`-derived sub-seeds
//! (`"mempool"`, `"replay"`) to downstream consumers (`moonblokz-mempool`,
//! the FR50 seed-source selector) during their own initialization.
//! (`moonblokz-vote` is fully deterministic and takes no sub-seed.)
//!
//! **Algorithm choice:** Story 1.3 originally framed the root PRNG as WyRand
//! u64. The revised architecture §2.3 uses Xoshiro256PlusPlus instead — the
//! statistical quality difference (~32 GB vs >2 TB PractRand) is significant
//! enough for a long-running deterministic system where seeded PRNG outputs
//! feed mempool eviction and seed-source selection. Memory/CPU difference is
//! negligible (~72 B / RP2040 SRAM, both ~30-50 cycles per `next_u64`).
//!
//! Replay-determinism guarantee (AR11): `derive_subseed` is a **pure**
//! function of `(seed, label)` — it does not observe or mutate the inner
//! Xoshiro state. Two calls with the same label always produce the same
//! sub-seed, irrespective of how many `next_u64` calls happened on the
//! same `Prng` in between.

use rand_xoshiro::Xoshiro256PlusPlus;
use rand_xoshiro::rand_core::{RngCore, SeedableRng};

/// Root pseudo-random source.
///
/// Inner algorithm: Xoshiro256PlusPlus (Blackman & Vigna, 2018).
/// State: 32 B (4 × `u64`). Cached construction-time `seed: u64` is retained
/// so `derive_subseed` remains a pure function across the `Prng`'s lifetime.
pub(crate) struct Prng {
    inner: Xoshiro256PlusPlus,
    seed: u64,
}

impl Prng {
    /// Constructs a `Prng` seeded from `seed`.
    pub(crate) fn new(seed: u64) -> Self {
        Self {
            inner: Xoshiro256PlusPlus::seed_from_u64(seed),
            seed,
        }
    }

    /// Advances the inner state and returns the next 64-bit random value.
    #[allow(dead_code)] // consumed by Story 1.4+ when the API needs randomness
    pub(crate) fn next_u64(&mut self) -> u64 {
        self.inner.next_u64()
    }

    /// Derives a deterministic sub-seed from the construction-time seed and
    /// a label.
    ///
    /// Pure: depends only on `(self.seed, label)` and never observes or
    /// mutates `self.inner`. Two calls with the same label return identical
    /// sub-seeds for the lifetime of the `Prng` (AR11 stability guarantee).
    #[allow(dead_code)] // consumed by mempool initialization and FR50 seed-source selection
    pub(crate) fn derive_subseed(&self, label: &[u8]) -> u64 {
        // FNV-1a 64-bit hash of the label, XOR'd with the cached seed.
        const FNV_OFFSET: u64 = 0xCBF2_9CE4_8422_2325;
        const FNV_PRIME: u64 = 0x0000_0100_0000_01B3;
        let mut h = FNV_OFFSET;
        for b in label {
            h ^= *b as u64;
            h = h.wrapping_mul(FNV_PRIME);
        }
        self.seed ^ h
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derive_subseed_is_deterministic() {
        let p = Prng::new(0x1234_5678_9ABC_DEF0);
        let a = p.derive_subseed(b"mempool");
        let b = p.derive_subseed(b"mempool");
        assert_eq!(a, b);
    }

    #[test]
    fn derive_subseed_pure_no_inner_dependence() {
        // Two PRNGs seeded identically must yield identical sub-seeds for
        // the same label even after one has advanced the inner Xoshiro
        // state via next_u64 — proving derive_subseed does not depend on
        // (or mutate) the inner state.
        let mut p1 = Prng::new(0x1234);
        let _ = p1.next_u64();
        let _ = p1.next_u64();
        let _ = p1.next_u64();

        let p2 = Prng::new(0x1234);
        assert_eq!(p1.derive_subseed(b"mempool"), p2.derive_subseed(b"mempool"));
    }

    #[test]
    fn different_labels_produce_different_subseeds() {
        let p = Prng::new(0xFEED_FACE_DEAD_BEEF);
        let m = p.derive_subseed(b"mempool");
        let i = p.derive_subseed(b"intake");
        let r = p.derive_subseed(b"replay");
        assert_ne!(m, i);
        assert_ne!(i, r);
        assert_ne!(m, r);
    }

    #[test]
    fn next_u64_advances_state_and_diverges() {
        let mut p = Prng::new(0x7777);
        let a = p.next_u64();
        let b = p.next_u64();
        let c = p.next_u64();
        assert_ne!(a, b);
        assert_ne!(b, c);
        assert_ne!(a, c);
    }

    #[test]
    fn different_seeds_produce_different_streams() {
        let mut p1 = Prng::new(1);
        let mut p2 = Prng::new(2);
        assert_ne!(p1.next_u64(), p2.next_u64());
    }
}
