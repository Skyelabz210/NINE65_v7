//! Deterministic RNG - ChaCha-based test RNG
//!
//! Provides a deterministic, cryptographically strong RNG for tests and benchmarks.
//! This is NOT a substitute for OS CSPRNG in production key generation.

use rand_chacha::ChaCha20Rng;
use rand_core::{RngCore, SeedableRng};

/// Deterministic ChaCha20 RNG for tests/benchmarks.
///
/// # Security
/// - Deterministic: NOT suitable for production secrecy.
/// - Intended for reproducible tests and benchmarks only.
#[derive(Clone, Debug)]
pub struct DeterministicRng {
    rng: ChaCha20Rng,
}

impl DeterministicRng {
    /// Create a deterministic RNG from a 32-byte seed.
    pub fn from_seed(seed: [u8; 32]) -> Self {
        Self {
            rng: ChaCha20Rng::from_seed(seed),
        }
    }

    /// Create a deterministic RNG from a u64 seed.
    ///
    /// Expands the seed to 32 bytes using SplitMix64 to avoid low-entropy states.
    pub fn with_seed(seed: u64) -> Self {
        let mut state = if seed == 0 { 0xDEADBEEF_CAFEBABE } else { seed };
        let mut bytes = [0u8; 32];
        for chunk in bytes.chunks_mut(8) {
            let next = splitmix64(&mut state);
            chunk.copy_from_slice(&next.to_le_bytes());
        }
        Self::from_seed(bytes)
    }

    /// Generate next u64.
    #[inline]
    pub fn next_u64(&mut self) -> u64 {
        self.rng.next_u64()
    }

    /// Extract n bits (1-64).
    #[inline]
    pub fn extract_bits(&mut self, n: u32) -> u64 {
        if n == 0 {
            return 0;
        }
        if n >= 64 {
            return self.next_u64();
        }
        self.next_u64() & ((1u64 << n) - 1)
    }

    /// Generate uniform random in [0, bound).
    pub fn uniform(&mut self, bound: u64) -> u64 {
        if bound <= 1 {
            return 0;
        }

        // Rejection sampling for unbiased distribution
        let threshold = (u64::MAX - bound + 1) % bound;
        loop {
            let x = self.next_u64();
            if x >= threshold {
                return x % bound;
            }
        }
    }

    /// Generate ternary value in {-1, 0, 1}.
    pub fn ternary(&mut self) -> i64 {
        match self.uniform(3) {
            0 => -1,
            1 => 0,
            _ => 1,
        }
    }

    /// Generate CBD(eta) sample in range [-eta, eta].
    pub fn cbd(&mut self, eta: usize) -> i64 {
        let mut sum = 0i64;
        for _ in 0..eta {
            sum += (self.extract_bits(1) as i64) - (self.extract_bits(1) as i64);
        }
        sum
    }
}

impl Default for DeterministicRng {
    fn default() -> Self {
        Self::with_seed(0xDEADBEEF_CAFEBABE)
    }
}

// SplitMix64 for seed expansion.
fn splitmix64(state: &mut u64) -> u64 {
    let mut z = state.wrapping_add(0x9E3779B97F4A7C15);
    *state = z;
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
    z ^ (z >> 31)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deterministic() {
        let mut r1 = DeterministicRng::with_seed(42);
        let mut r2 = DeterministicRng::with_seed(42);

        for _ in 0..1000 {
            assert_eq!(r1.next_u64(), r2.next_u64());
        }
    }

    #[test]
    fn test_uniform_bounds() {
        let mut r = DeterministicRng::with_seed(123);
        for bound in [2, 10, 100, 1000] {
            for _ in 0..1000 {
                let v = r.uniform(bound);
                assert!(v < bound, "uniform({}) produced {}", bound, v);
            }
        }
    }
}
