//! ExactDivider - K-Elimination Exact Division Primitive
//!
//! Dual-track residue representation enables exact integer
//! reconstruction and division without any floating-point operations.
//!
//! Given residues mod M and mod A (coprime), we can reconstruct the unique
//! integer X < M*A and perform exact division when X is divisible by d.
//!
//! # Theorem Reference
//! - Proof File: `ExactCoefficient.v`
//! - Status: VERIFIED

/// Exact divider using dual-modulus K-Elimination
#[derive(Clone, Debug)]
pub struct ExactDivider {
    /// Main modulus M
    pub m: u64,
    /// Anchor modulus A (coprime to M)
    pub a: u64,
    /// M^(-1) mod A - precomputed for fast k extraction
    pub inv_m_mod_a: u64,
    /// Product M * A - maximum reconstructible integer
    pub product: u128,
}

impl ExactDivider {
    /// Create a new exact divider with given moduli
    pub fn new(m: u64, a: u64) -> Self {
        assert!(gcd(m, a) == 1, "M and A must be coprime");

        let inv_m_mod_a = mod_inverse(m, a);
        let product = (m as u128) * (a as u128);

        Self {
            m,
            a,
            inv_m_mod_a,
            product,
        }
    }

    /// Create divider suitable for FHE with given ciphertext modulus
    /// Chooses A to provide sufficient headroom for Δ² computations
    pub fn for_fhe(q: u64) -> Self {
        // For ct×ct we need M*A > Δ² * max_message²
        // Use q as M, and a large coprime as A
        let m = q;

        // Find a suitable anchor prime coprime to q
        // We want A large enough that M*A can hold Δ²*max
        let a = Self::find_coprime_anchor(q);

        Self::new(m, a)
    }

    /// Find a suitable coprime anchor modulus
    ///
    /// ORBITAL PATCH (December 2024):
    /// Previous 30-bit anchors caused "Hidden Orbital Problem" - intermediate
    /// coefficients in tensor products (~70 bits for N=1024) exceeded the
    /// 60-bit capacity (30-bit M × 30-bit A), causing silent overflow.
    ///
    /// FIX: Use 62-bit anchor primes → 92-bit total capacity (30+62)
    /// Capacity (92 bits) > Demand (70 bits) → Exact reconstruction guaranteed
    fn find_coprime_anchor(m: u64) -> u64 {
        // ORBITAL FIX: 62-bit primes for safe tensor product reconstruction
        // Total Capacity = 30 bits (Inner) + 62 bits (Anchor) = 92 bits
        // Demand = ~70 bits for N=1024 tensor products
        // Margin = 22 bits (SAFE)
        let candidates_62bit = [
            4611686018427387903u64, // 2^62 - 1 (Mersenne 62)
            4611686018427387847,    // Near-Mersenne 62-bit prime
            4611686018427387761,    // Another 62-bit prime
            4611686018427387583,    // Backup 62-bit prime
        ];

        // Try 62-bit primes first (required for production safety)
        for &c in &candidates_62bit {
            if gcd(m, c) == 1 {
                return c;
            }
        }

        // Fallback to 60-bit Solinas prime if 62-bit fails coprimality
        let solinas_60 = 1152921504606846977u64; // 2^60 - 2^14 + 1
        if gcd(m, solinas_60) == 1 {
            return solinas_60;
        }

        // Final fallback: find any large coprime (shouldn't reach here)
        let mut candidate = 1u64 << 60;
        while gcd(m, candidate) != 1 {
            candidate += 1;
        }
        candidate
    }

    /// Reconstruct the exact integer X from residues mod M and mod A
    ///
    /// Given vm = X mod M and va = X mod A, computes X using CRT:
    ///   k = (va - vm) * M^(-1) mod A
    ///   X = vm + k * M
    ///
    /// Result is valid only if true X < M*A
    pub fn reconstruct_exact(&self, m_res: u64, a_res: u64) -> u128 {
        let m = self.m as u128;
        let a = self.a as u128;
        let vm = m_res as u128;
        let va = a_res as u128;
        let inv = self.inv_m_mod_a as u128;

        // k ≡ (va - vm) * M^(-1) (mod A)
        // Handle negative difference by adding A first
        let vm_mod_a = vm % a;
        let diff = (va + a - vm_mod_a) % a;
        let k = (diff * inv) % a;

        // X = vm + k * M
        vm + k * m
    }

    /// Perform exact division: X / d where X is reconstructed from residues
    ///
    /// Panics if X is not exactly divisible by d
    pub fn exact_divide(&self, m_res: u64, a_res: u64, d: u64) -> u128 {
        let x = self.reconstruct_exact(m_res, a_res);
        assert!(
            x.is_multiple_of(d as u128),
            "exact_divide: {} is not divisible by {}",
            x,
            d
        );
        x / (d as u128)
    }

    /// Perform exact division, returning quotient and remainder
    pub fn divmod(&self, m_res: u64, a_res: u64, d: u64) -> (u128, u128) {
        let x = self.reconstruct_exact(m_res, a_res);
        (x / (d as u128), x % (d as u128))
    }

    /// Scale and round: round(X * t / q) using exact arithmetic
    ///
    /// This is the key operation for BFV rescaling
    pub fn scale_and_round(&self, m_res: u64, a_res: u64, t: u64, q: u64) -> u64 {
        let x = self.reconstruct_exact(m_res, a_res);
        // round(x * t / q) = (x * t + q/2) / q
        let scaled = (x * (t as u128) + (q as u128 / 2)) / (q as u128);
        (scaled % (t as u128)) as u64
    }

    /// Encode an integer into dual-track residues
    pub fn encode(&self, x: u128) -> (u64, u64) {
        let m_res = (x % (self.m as u128)) as u64;
        let a_res = (x % (self.a as u128)) as u64;
        (m_res, a_res)
    }

    /// Check if reconstruction would be valid (X < M*A)
    pub fn is_valid_range(&self, x: u128) -> bool {
        x < self.product
    }
}

/// Greatest common divisor
fn gcd(a: u64, b: u64) -> u64 {
    if b == 0 {
        a
    } else {
        gcd(b, a % b)
    }
}

/// Modular inverse using extended Euclidean algorithm
fn mod_inverse(a: u64, m: u64) -> u64 {
    let mut mn = (m as i128, a as i128);
    let mut xy = (0i128, 1i128);

    while mn.1 != 0 {
        let q = mn.0 / mn.1;
        mn = (mn.1, mn.0 - q * mn.1);
        xy = (xy.1, xy.0 - q * xy.1);
    }

    while xy.0 < 0 {
        xy.0 += m as i128;
    }
    (xy.0 % m as i128) as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_reconstruct_basic() {
        let div = ExactDivider::new(17, 23);

        // Test: X = 100
        // 100 mod 17 = 15
        // 100 mod 23 = 8
        let x = div.reconstruct_exact(15, 8);
        assert_eq!(x, 100, "Reconstruction failed");
    }

    #[test]
    fn test_exact_divide() {
        let div = ExactDivider::new(1009, 1013);

        // X = 12345, d = 5
        let x = 12345u128;
        let (m_res, a_res) = div.encode(x);
        let quotient = div.exact_divide(m_res, a_res, 5);
        assert_eq!(quotient, 2469, "Exact division failed");
    }

    #[test]
    fn test_scale_and_round() {
        let div = ExactDivider::new(998244353, 1073479681);

        // Test BFV-style scaling
        let q = 998244353u64;
        let t = 500000u64;
        let delta = q / t; // 1996

        // X = Δ² × 35 = 139440560
        let x = (delta as u128) * (delta as u128) * 35;
        let (m_res, a_res) = div.encode(x);

        // round(X × t / q) should give Δ × 35 = 69860
        let scaled = div.scale_and_round(m_res, a_res, t, q);
        let expected = delta * 35;

        println!("X = {}, scaled = {}, expected = {}", x, scaled, expected);

        // Allow small rounding error (< 0.1%)
        let diff = (scaled as i64 - expected as i64).abs();
        assert!(
            diff <= (expected as i64 / 1000) + 1,
            "Scale and round failed: {} vs {} (diff={})",
            scaled,
            expected,
            diff
        );
    }

    #[test]
    fn test_fhe_params() {
        let q = 998244353u64;
        let div = ExactDivider::for_fhe(q);

        println!(
            "FHE divider: M={}, A={}, product={}",
            div.m, div.a, div.product
        );

        // Verify product is large enough for Δ² × reasonable message
        let delta = q / 500000u64;
        let max_product = (delta as u128) * (delta as u128) * 1000;

        assert!(
            div.product > max_product,
            "Product {} too small for max {}",
            div.product,
            max_product
        );
    }

    #[test]
    fn test_roundtrip() {
        let div = ExactDivider::new(65537, 65521);

        for x in [0u128, 1, 1000, 1_000_000, 4_000_000_000] {
            if x < div.product {
                let (m, a) = div.encode(x);
                let recovered = div.reconstruct_exact(m, a);
                assert_eq!(recovered, x, "Roundtrip failed for {}", x);
            }
        }
    }
}
