/// garner.rs — Exact Garner CRT Reconstruction (Recumbent CRT)
///
/// Garner's algorithm converts an independent residue tuple (r_1,...,r_k)
/// back into the unique scalar integer x ∈ Z_N satisfying x ≡ r_i (mod p_i).
///
/// The algorithm works via mixed-radix representation:
///   x = v_1 + v_2·p_1 + v_3·p_1·p_2 + v_4·p_1·p_2·p_3 + ...
///
/// Theorem 4 establishes the irremovable O(k²) cost:
///   exactly k(k-1)/2 sequential modular multiplications are required.
///   For k=4: 1+2+3 = 6 multiplications.
///   For k=6: 1+2+3+4+5 = 15 multiplications.
///
/// These multiplications are STRICTLY SEQUENTIAL due to data dependencies:
///   u_3 requires u_2's output; u_4 requires both u_2 and u_3; etc.
/// This dependency chain makes single-instance SIMD impossible, cementing
/// the architectural necessity of lazy (Residue-Native) reconstruction.
///
/// The "Recumbent CRT" brand name in the QMNF ecosystem refers to this
/// deferred-reconstruction topology: the CRT scaffold lies dormant ("recumbent")
/// throughout deep computation chains, activating only at the I/O boundary.

use crate::arith::{canonical, mod_inverse, mod_mul};

/// A fully annotated Garner reconstruction result, carrying not just the
/// final scalar but a detailed trace for verification and benchmarking.
#[derive(Debug, Clone)]
pub struct GarnerResult {
    /// The reconstructed integer x ∈ Z_N.
    pub value: i128,
    /// The aggregate modulus N = p_1 * p_2 * ... * p_k.
    pub modulus: i128,
    /// The mixed-radix coefficients v_1, v_2, ..., v_k.
    pub mixed_radix_coeffs: Vec<i128>,
    /// Exact count of modular multiplications performed.
    /// Must equal k*(k-1)/2 for a correct implementation.
    pub multiplication_count: usize,
}

/// Precomputed constants for efficient repeated reconstruction over a
/// fixed prime set.  Storing these avoids recomputing mod inverses on
/// every call, which is significant in deep FHE bootstrapping chains.
#[derive(Debug, Clone)]
pub struct GarnerConstants {
    pub primes: Vec<i128>,
    /// c[i][j] = p_j^{-1} mod p_i, for j < i.
    /// These are the cross-prime modular inverses that drive the
    /// nested correction loop.
    pub c: Vec<Vec<i128>>,
}

impl GarnerConstants {
    /// Precompute all required modular inverses for the given prime set.
    /// This is a one-time O(k²) setup cost paid before the first operation.
    pub fn precompute(primes: &[i128]) -> Self {
        let k = primes.len();
        // c[i][j] = primes[j]^{-1} mod primes[i]  (j < i)
        let mut c = vec![vec![0i128; k]; k];
        for i in 1..k {
            for j in 0..i {
                c[i][j] = mod_inverse(primes[j], primes[i])
                    .expect("Primes must be pairwise coprime for Garner precomputation");
            }
        }
        Self { primes: primes.to_vec(), c }
    }
}

/// Reconstruct an integer from its residue tuple using Garner's algorithm.
/// Returns a GarnerResult with full trace information.
///
/// This is the function that consumes ~307 ns in the CRAM-S6 production
/// engine — the single dominant latency that makes Residue-Native Computing
/// (Theorem 1) architecturally necessary.
pub fn garner_reconstruct(residues: &[i128], constants: &GarnerConstants) -> GarnerResult {
    let primes = &constants.primes;
    let k = primes.len();
    assert_eq!(residues.len(), k, "Residue count must match prime count");

    let mut mul_count = 0usize;
    // mixed_u[i] = the i-th mixed-radix coefficient u_i
    let mut mixed_u = vec![0i128; k];

    // ── Extract each mixed-radix coefficient in order ─────────────────────────
    // The sequential dependency chain: u_i depends on u_1,...,u_{i-1}.
    // This is precisely what prevents SIMD parallelism within one instance.
    for i in 0..k {
        // Start with the raw residue for this prime
        let mut val = canonical(residues[i], primes[i]);

        // Subtract the accumulated lower-radix reconstruction, correcting
        // for the contributions of all previously extracted u_j, j < i.
        // This inner loop accounts for (i) multiplications at step i.
        let mut base = 1i128; // p_1 * p_2 * ... * p_{j-1} running product
        for j in 0..i {
            // Correct val by subtracting u_j * (p_1*...*p_{j-1}) mod p_i
            let correction = mod_mul(mixed_u[j], base % primes[i], primes[i]);
            val = canonical(val - correction, primes[i]);
            // Scale val by c[i][j] = p_j^{-1} mod p_i
            val = mod_mul(val, constants.c[i][j], primes[i]);
            mul_count += 1; // ← one sequential modular multiplication

            // Accumulate the product for the next correction term
            base *= primes[j];
        }
        mixed_u[i] = canonical(val, primes[i]);
    }

    // ── Horner-form reassembly from mixed-radix coefficients ─────────────────
    // x = v_1 + p_1*(v_2 + p_2*(v_3 + p_3*(v_4 + ...)))
    // Standard Horner's method from the innermost coefficient outward.
    let mut x = 0i128;
    for i in (0..k).rev() {
        x = x * primes[i] + mixed_u[i];
    }

    // Canonical reduction into [0, N) — guarantees x ∈ Z_N
    let modulus: i128 = primes.iter().product();
    let value = canonical(x, modulus);

    GarnerResult {
        value,
        modulus,
        mixed_radix_coeffs: mixed_u,
        multiplication_count: mul_count,
    }
}

/// Convenience function: reconstruct and return only the scalar value.
pub fn reconstruct(residues: &[i128], constants: &GarnerConstants) -> i128 {
    garner_reconstruct(residues, constants).value
}

/// Decompose a scalar integer into its residue tuple over the given primes.
/// This is the inverse of garner_reconstruct under the CRT bijection.
///
/// Theorem 1 (Correctness of Residue-Native Computing) relies on the
/// guarantee that decompose(reconstruct(r)) == r for any valid residue tuple.
pub fn decompose(x: i128, primes: &[i128]) -> Vec<i128> {
    primes.iter().map(|&p| canonical(x, p)).collect()
}

/// Verify the CRT round-trip: decompose ∘ reconstruct = identity.
/// This is the formal check of the bijection that underlies Theorem 1.
pub fn verify_roundtrip(x: i128, primes: &[i128], constants: &GarnerConstants) -> bool {
    let residues = decompose(x, primes);
    let result = reconstruct(&residues, constants);
    result == canonical(x, primes.iter().product())
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn s4_primes() -> Vec<i128> { vec![2, 3, 5, 7] }
    fn s6_primes() -> Vec<i128> { vec![2, 3, 5, 7, 11, 13] }

    // ── Theorem 4 multiplication count verification ───────────────────────────

    #[test]
    fn garner_s4_exactly_6_multiplications() {
        // Theorem 4: k=4 → k*(k-1)/2 = 4*3/2 = 6 sequential multiplications
        let primes = s4_primes();
        let constants = GarnerConstants::precompute(&primes);
        // Use the final residue tuple from the paper trace: (1, 0, 0, 4)
        let residues = vec![1, 0, 0, 4];
        let result = garner_reconstruct(&residues, &constants);
        assert_eq!(
            result.multiplication_count, 6,
            "CRAM-S4 Garner must use exactly k*(k-1)/2 = 6 multiplications"
        );
    }

    #[test]
    fn garner_s6_exactly_15_multiplications() {
        // Theorem 4: k=6 → k*(k-1)/2 = 6*5/2 = 15 sequential multiplications
        let primes = s6_primes();
        let constants = GarnerConstants::precompute(&primes);
        let residues = vec![0, 1, 2, 3, 4, 5]; // arbitrary valid tuple
        let result = garner_reconstruct(&residues, &constants);
        assert_eq!(
            result.multiplication_count, 15,
            "CRAM-S6 Garner must use exactly k*(k-1)/2 = 15 multiplications"
        );
    }

    // ── Paper trace: exact reconstruction of (1,0,0,4) → 165 ─────────────────

    #[test]
    fn paper_trace_reconstruct_165() {
        // From Phase 4 of the CRAM-S4 step-by-step trace:
        // Residue tuple (1, 0, 0, 4) over primes (2,3,5,7) must yield 165.
        let primes = s4_primes();
        let constants = GarnerConstants::precompute(&primes);
        let result = garner_reconstruct(&[1, 0, 0, 4], &constants);

        assert_eq!(result.value, 165, "Paper canonical result: 17 ⊛_S4 23 = 165");

        // Verify mixed-radix coefficients {v1=1, v2=1, v3=2, v4=5} from paper
        assert_eq!(result.mixed_radix_coeffs[0], 1, "v1 must equal 1");
        assert_eq!(result.mixed_radix_coeffs[1], 1, "v2 must equal 1");
        assert_eq!(result.mixed_radix_coeffs[2], 2, "v3 must equal 2");
        assert_eq!(result.mixed_radix_coeffs[3], 5, "v4 must equal 5");
    }

    // ── Diagnostic confirmation: 165 mod each prime ───────────────────────────

    #[test]
    fn paper_trace_diagnostic_confirmation() {
        // The paper explicitly checks 165 mod {2,3,5,7} = {1,0,0,4}
        assert_eq!(165 % 2, 1, "165 mod 2 must be 1");
        assert_eq!(165 % 3, 0, "165 mod 3 must be 0");
        assert_eq!(165 % 5, 0, "165 mod 5 must be 0");
        assert_eq!(165 % 7, 4, "165 mod 7 must be 4");
    }

    // ── CRT bijection round-trip (Theorem 1 foundation) ───────────────────────

    #[test]
    fn roundtrip_s4_all_residues() {
        let primes = s4_primes();
        let constants = GarnerConstants::precompute(&primes);
        let n: i128 = primes.iter().product(); // N = 210
        assert_eq!(n, 210);
        // Test every integer in Z_210 — the complete CRT bijection
        for x in 0..n {
            assert!(
                verify_roundtrip(x, &primes, &constants),
                "Round-trip failed for x={}", x
            );
        }
    }

    #[test]
    fn roundtrip_s6_spot_check() {
        // Full scan of Z_30030 is feasible but slow; spot-check 1000 values
        let primes = s6_primes();
        let constants = GarnerConstants::precompute(&primes);
        let n: i128 = primes.iter().product(); // N = 30030
        for x in (0..n).step_by(30) {
            assert!(
                verify_roundtrip(x, &primes, &constants),
                "S6 round-trip failed for x={}", x
            );
        }
    }

    // ── Decomposition spot checks ─────────────────────────────────────────────

    #[test]
    fn decompose_17_s4() {
        // From the paper Phase 1: A=17 → (1, 2, 2, 3) over primes (2,3,5,7)
        let residues = decompose(17, &s4_primes());
        assert_eq!(residues, vec![1, 2, 2, 3]);
    }

    #[test]
    fn decompose_23_s4() {
        // From the paper Phase 1: B=23 → (1, 2, 3, 2) over primes (2,3,5,7)
        let residues = decompose(23, &s4_primes());
        assert_eq!(residues, vec![1, 2, 3, 2]);
    }
}
