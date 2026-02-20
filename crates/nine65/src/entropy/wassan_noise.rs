//! WASSAN Holographic Noise Field
//!
//! 144 φ-harmonic bands for O(1) noise retrieval
//!
//! This replaces expensive CSPRNG calls with pre-computed holographic reads.
//!
//! Performance:
//!   CSPRNG:  1,680 ns/sample (syscall every time)
//!   Shadow:     10 ns/sample (LFSR)
//!   WASSAN:    ~20 ns/sample (memory read, cache-bound)
//!
//! Usage:
//!   let mut field = WassanNoiseField::from_shadow_seed(42);
//!   let noise_poly = field.fhe_noise_polynomial(1024);

#[cfg(feature = "parallel")]
use rayon::prelude::*;

/// Golden ratio scaled to integer
const PHI_NUM: u64 = 1618033988749895;
const PHI_DEN: u64 = 1000000000000000;

/// Number of φ-harmonic frequency bands (F₁₂ = 144)
const NUM_BANDS: usize = 144;

/// Samples per band (power of 2 for fast modulo)
const SAMPLES_PER_BAND: usize = 4096;

/// WASSAN Holographic Noise Field
///
/// Pre-computed interference pattern across 144 φ-harmonic bands.
/// Retrieval is O(1) - just a memory read.
#[derive(Clone, Debug)]
pub struct WassanNoiseField {
    /// 144 frequency bands × 4096 samples each
    /// Total: 144 × 4096 × 8 bytes = 4.7 MB
    /// Using Vec<Vec> to avoid stack allocation before heap move
    interference_pattern: Vec<Vec<u64>>,
    /// Phase position in each band
    phase_position: [usize; NUM_BANDS],
    /// Band selector for round-robin
    current_band: usize,
}

impl WassanNoiseField {
    /// Create from Shadow Entropy seed (deterministic, reproducible)
    #[cfg(not(feature = "parallel"))]
    pub fn from_shadow_seed(seed: u64) -> Self {
        Self::from_shadow_seed_sequential(seed)
    }

    /// Create from Shadow Entropy seed with parallel band generation
    #[cfg(feature = "parallel")]
    pub fn from_shadow_seed(seed: u64) -> Self {
        Self::from_shadow_seed_parallel(seed)
    }

    /// Sequential initialization (fallback)
    #[cfg(not(feature = "parallel"))]
    fn from_shadow_seed_sequential(seed: u64) -> Self {
        let mut pattern: Vec<Vec<u64>> = (0..NUM_BANDS)
            .map(|_| vec![0u64; SAMPLES_PER_BAND])
            .collect();

        let mut state = [
            seed,
            seed.wrapping_mul(0x5DEECE66D).wrapping_add(0xB),
            seed.rotate_left(17) ^ 0xDEADBEEF,
            seed.rotate_right(23) ^ 0xCAFEBABE,
        ];

        for band in 0..NUM_BANDS {
            let phi_n = Self::phi_power(band);
            for i in 0..SAMPLES_PER_BAND {
                let t = state[0] ^ (state[0] << 11);
                state[0] = state[1];
                state[1] = state[2];
                state[2] = state[3];
                state[3] = state[3] ^ (state[3] >> 19) ^ t ^ (t >> 8);
                pattern[band][i] = state[3].wrapping_mul(phi_n);
            }
        }

        Self {
            interference_pattern: pattern,
            phase_position: [0; NUM_BANDS],
            current_band: 0,
        }
    }

    /// Parallel initialization - each band gets independent LFSR state
    #[cfg(feature = "parallel")]
    #[allow(clippy::needless_range_loop)] // Loop variable used for indexing and state updates
    fn from_shadow_seed_parallel(seed: u64) -> Self {
        // Generate all bands in parallel with independent RNG per band
        let pattern: Vec<Vec<u64>> = (0..NUM_BANDS)
            .into_par_iter()
            .map(|band| {
                // Each band gets unique seed derived from master seed
                let band_seed = seed
                    .wrapping_mul(0x5DEECE66D)
                    .wrapping_add(band as u64)
                    .wrapping_mul(0x1234567890ABCDEF);

                let mut state = [
                    band_seed,
                    band_seed.wrapping_mul(0x5DEECE66D).wrapping_add(0xB),
                    band_seed.rotate_left(17) ^ 0xDEADBEEF,
                    band_seed.rotate_right(23) ^ 0xCAFEBABE,
                ];

                let phi_n = Self::phi_power(band);
                let mut band_data = vec![0u64; SAMPLES_PER_BAND];

                for i in 0..SAMPLES_PER_BAND {
                    let t = state[0] ^ (state[0] << 11);
                    state[0] = state[1];
                    state[1] = state[2];
                    state[2] = state[3];
                    state[3] = state[3] ^ (state[3] >> 19) ^ t ^ (t >> 8);
                    band_data[i] = state[3].wrapping_mul(phi_n);
                }

                band_data
            })
            .collect();

        Self {
            interference_pattern: pattern,
            phase_position: [0; NUM_BANDS],
            current_band: 0,
        }
    }

    /// Create from OS entropy (one syscall, then infinite stream)
    ///
    /// # Panics
    /// Panics if OS CSPRNG fails. Use `try_from_os_seed()` to handle failures.
    #[cfg(feature = "secure_seed")]
    pub fn from_os_seed() -> Self {
        Self::try_from_os_seed()
            .expect("CRITICAL: OS entropy source failed - system CSPRNG unavailable")
    }

    /// Fallible OS-seeded constructor.
    #[cfg(feature = "secure_seed")]
    pub fn try_from_os_seed() -> Result<Self, getrandom::Error> {
        use getrandom::getrandom;
        let mut seed_bytes = [0u8; 8];
        getrandom(&mut seed_bytes)?;
        let seed = u64::from_le_bytes(seed_bytes);
        Ok(Self::from_shadow_seed(seed))
    }

    /// Compute φⁿ as integer (scaled)
    #[inline]
    fn phi_power(n: usize) -> u64 {
        // Use recurrence: φⁿ = φⁿ⁻¹ + φⁿ⁻²
        // Start with φ⁰ = 1, φ¹ = φ
        if n == 0 {
            return PHI_DEN;
        }
        if n == 1 {
            return PHI_NUM;
        }

        let mut a = PHI_DEN; // φ⁰
        let mut b = PHI_NUM; // φ¹

        for _ in 2..=n {
            let next = a.wrapping_add(b);
            a = b;
            b = next;
        }

        b
    }

    /// Sample single value - O(1) memory read
    #[inline]
    pub fn sample(&mut self) -> u64 {
        let band = self.current_band;
        let pos = self.phase_position[band];

        // Advance position (power of 2 mask for fast modulo)
        self.phase_position[band] = (pos + 1) & (SAMPLES_PER_BAND - 1);

        // Round-robin through bands (branch instead of division - 144 isn't power of 2)
        self.current_band = if band >= NUM_BANDS - 1 { 0 } else { band + 1 };

        self.interference_pattern[band][pos]
    }

    /// Sample from specific band
    #[inline]
    pub fn sample_band(&mut self, band: usize) -> u64 {
        let band = band % NUM_BANDS;
        let pos = self.phase_position[band];
        self.phase_position[band] = (pos + 1) & (SAMPLES_PER_BAND - 1);
        self.interference_pattern[band][pos]
    }

    /// Sample bounded value [0, bound)
    #[inline]
    pub fn sample_bounded(&mut self, bound: u64) -> u64 {
        // No rejection sampling needed - just modulo
        // (slight bias acceptable for FHE noise, not for keys)
        self.sample() % bound
    }

    /// Generate ternary value {-1, 0, 1} for secret key
    #[inline]
    pub fn ternary(&mut self) -> i64 {
        let r = self.sample() % 3;
        (r as i64) - 1
    }

    /// Generate ternary vector (for secret key generation)
    pub fn ternary_vec(&mut self, n: usize) -> Vec<i64> {
        (0..n).map(|_| self.ternary()).collect()
    }

    /// Generate FHE noise polynomial with bounded coefficients
    ///
    /// For BFV/BGV: coefficients in [0, q) representing small errors
    pub fn fhe_noise_polynomial(&mut self, n: usize, q: u64, bound: u64) -> Vec<u64> {
        (0..n)
            .map(|_| {
                // Small bounded noise
                let noise = self.sample_bounded(2 * bound + 1);
                // Center around 0: if noise > bound, it's negative mod q
                if noise > bound {
                    q - (noise - bound)
                } else {
                    noise
                }
            })
            .collect()
    }

    /// Generate discrete Gaussian-like noise via CBD (Central Binomial)
    ///
    /// Sum of η uniform bits minus η uniform bits gives approximate Gaussian
    pub fn cbd_noise(&mut self, n: usize, q: u64, eta: usize) -> Vec<u64> {
        (0..n)
            .map(|_| {
                let mut sum: i64 = 0;
                for _ in 0..eta {
                    sum += (self.sample() & 1) as i64;
                    sum -= (self.sample() & 1) as i64;
                }
                if sum >= 0 {
                    sum as u64
                } else {
                    (q as i64 + sum) as u64
                }
            })
            .collect()
    }

    /// Generate uniform polynomial [0, q)
    pub fn uniform_polynomial(&mut self, n: usize, q: u64) -> Vec<u64> {
        (0..n).map(|_| self.sample_bounded(q)).collect()
    }

    /// Reset all phase positions (for reproducibility)
    pub fn reset(&mut self) {
        self.phase_position = [0; NUM_BANDS];
        self.current_band = 0;
    }

    /// Generate multiple FHE noise polynomials in parallel
    ///
    /// Each polynomial is generated with an independent WASSAN field
    /// for maximum parallelism. Useful for batch ciphertext generation.
    #[cfg(feature = "parallel")]
    pub fn fhe_noise_batch_par(
        seed: u64,
        count: usize,
        n: usize,
        q: u64,
        bound: u64,
    ) -> Vec<Vec<u64>> {
        (0..count)
            .into_par_iter()
            .map(|i| {
                // Each polynomial gets independent field
                let poly_seed = seed.wrapping_add(i as u64).wrapping_mul(0xDEADBEEFCAFEBABE);
                let mut field = Self::from_shadow_seed(poly_seed);
                field.fhe_noise_polynomial(n, q, bound)
            })
            .collect()
    }

    /// Generate multiple ternary vectors in parallel (for key generation)
    #[cfg(feature = "parallel")]
    pub fn ternary_batch_par(seed: u64, count: usize, n: usize) -> Vec<Vec<i64>> {
        (0..count)
            .into_par_iter()
            .map(|i| {
                let poly_seed = seed.wrapping_add(i as u64).wrapping_mul(0xCAFEBABEDEADBEEF);
                let mut field = Self::from_shadow_seed(poly_seed);
                field.ternary_vec(n)
            })
            .collect()
    }

    /// Get current state for checkpointing
    pub fn checkpoint(&self) -> ([usize; NUM_BANDS], usize) {
        (self.phase_position, self.current_band)
    }

    /// Restore from checkpoint
    pub fn restore(&mut self, checkpoint: ([usize; NUM_BANDS], usize)) {
        self.phase_position = checkpoint.0;
        self.current_band = checkpoint.1;
    }
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn perf_tests_enabled() -> bool {
        std::env::var("NINE65_PERF_TESTS")
            .map(|value| value == "1" || value.eq_ignore_ascii_case("true"))
            .unwrap_or(false)
    }

    fn perf_limit_ms(default: u128, var: &str) -> u128 {
        std::env::var(var)
            .ok()
            .and_then(|value| value.parse::<u128>().ok())
            .filter(|value| *value > 0)
            .unwrap_or(default)
    }

    #[test]
    fn test_creation() {
        let field = WassanNoiseField::from_shadow_seed(42);
        assert_eq!(field.phase_position, [0; NUM_BANDS]);
    }

    #[test]
    fn test_sample_deterministic() {
        let mut field1 = WassanNoiseField::from_shadow_seed(12345);
        let mut field2 = WassanNoiseField::from_shadow_seed(12345);

        for _ in 0..1000 {
            assert_eq!(field1.sample(), field2.sample());
        }
    }

    #[test]
    fn test_ternary_distribution() {
        let mut field = WassanNoiseField::from_shadow_seed(42);
        let mut counts = [0u64; 3]; // -1, 0, 1

        for _ in 0..30000 {
            let t = field.ternary();
            counts[(t + 1) as usize] += 1;
        }

        // Should be roughly uniform
        for c in counts.iter() {
            assert!(*c > 8000 && *c < 12000, "Ternary not uniform: {:?}", counts);
        }
    }

    #[test]
    fn test_polynomial_generation() {
        let mut field = WassanNoiseField::from_shadow_seed(42);
        let q = 998244353u64;

        let poly = field.fhe_noise_polynomial(1024, q, 8);

        assert_eq!(poly.len(), 1024);
        for &coeff in &poly {
            assert!(coeff < q);
        }
    }

    #[test]
    fn test_cbd_noise() {
        let mut field = WassanNoiseField::from_shadow_seed(42);
        let q = 998244353u64;

        let noise = field.cbd_noise(1024, q, 3);

        assert_eq!(noise.len(), 1024);
        // CBD(3) gives values in [-3, 3], so mod q gives [0, 3] or [q-3, q-1]
        for &coeff in &noise {
            assert!(coeff <= 3 || coeff >= q - 3);
        }
    }

    #[test]
    fn test_benchmark_vs_shadow() {
        if !perf_tests_enabled() {
            eprintln!("skipping perf test; set NINE65_PERF_TESTS=1 to enable");
            return;
        }
        let mut field = WassanNoiseField::from_shadow_seed(42);

        let start = std::time::Instant::now();
        let mut sum = 0u64;
        for _ in 0..1_000_000 {
            sum = sum.wrapping_add(field.sample());
        }
        let elapsed = start.elapsed();

        println!("WASSAN 1M samples: {:?}", elapsed);
        println!("Per sample: {:?}", elapsed / 1_000_000);
        println!("Sum (prevent optimization): {}", sum);

        // Target: < 120ms for 1M samples (with parallel test execution overhead)
        // In isolation: ~20ns/sample. Under test load: ~100ns/sample is acceptable.
        let max_ms = perf_limit_ms(120, "NINE65_WASSAN_1M_MAX_MS");
        assert!(
            elapsed.as_millis() < max_ms,
            "WASSAN too slow: {:?}",
            elapsed
        );
    }

    #[test]
    fn test_fhe_noise_polynomial_benchmark() {
        if !perf_tests_enabled() {
            eprintln!("skipping perf test; set NINE65_PERF_TESTS=1 to enable");
            return;
        }
        let mut field = WassanNoiseField::from_shadow_seed(42);
        let q = 998244353u64;

        let start = std::time::Instant::now();
        for _ in 0..1000 {
            let _ = field.fhe_noise_polynomial(4096, q, 8);
        }
        let elapsed = start.elapsed();

        println!("WASSAN 4096-poly noise x1000: {:?}", elapsed);
        println!("Per polynomial: {:?}", elapsed / 1000);

        // Target: < 400ms for 1000 polys (4M samples + Vec allocs + modulo ops + test load)
        let max_ms = perf_limit_ms(400, "NINE65_WASSAN_POLY_MAX_MS");
        assert!(
            elapsed.as_millis() < max_ms,
            "Polynomial generation too slow: {:?}",
            elapsed
        );
    }
}
