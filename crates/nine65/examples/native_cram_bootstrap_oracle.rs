//! Native CRAM Bootstrap Oracle with Auto-Certificate Assertions
//!
//! This module provides a Rust harness for the auto-certificate assertions
//! baked into the deep-dive canvas (§8). It implements oracle coverage for
//! the StarLift contraction mechanism with automatic range certification.
//!
//! # Mathematical Foundation
//!
//! For production parameters t = 65537, A = 65538, P = t^2:
//! - t^2 ≡ 1 (mod A) — self-inverse property
//! - t ≡ -1 (mod A) — subtraction collapse
//! - K = floor(w/t) ≤ 65536 < 65538 = A for all w ∈ [0, t^2) — automatic range certificate
//!
//! # Key Results
//!
//! 1. **StarLift Confirmation**: The t/(t+1) contraction IS the StarLift, scaled
//! 2. **Range Certificate**: Automatic for production parameters
//! 3. **K_EXACT_BOUNDED**: Free by construction (no separate range proof needed)
//! 4. **L9 Ladder**: Not needed (range certificate covers entire expansion)
//!
//! # Usage
//!
//! ```bash
//! cargo run -p nine65 --example native_cram_bootstrap_oracle
//! ```
//!
//! # References
//!
//! - [`docs/DEEP_DIVE_CANVAS.md`](../../../docs/DEEP_DIVE_CANVAS.md) §8
//! - [`docs/PRIME_POWER_BOOTSTRAP_CONTRACTION.md`](../../../docs/PRIME_POWER_BOOTSTRAP_CONTRACTION.md)

#![allow(dead_code)]
#![allow(clippy::excessive_precision)]

use std::fmt;

// Production Parameters

/// Production prime: t = 65537 = 2^16 + 1 (Fermat prime)
pub const PRODUCTION_T: u64 = 65537;

/// Work modulus: A = t + 1 = 65538 = 2 * 3^2 * 11 * 331
pub const WORK_MODULUS_A: u64 = 65538;

/// Expansion modulus: P = t^2 = 4295098367
pub const EXPANSION_MODULUS_P: u64 = 65537 * 65537;

/// Rounding shift: h = (t - 1) / 2 = 32768
pub const ROUNDING_SHIFT_H: u64 = 32768;

/// Maximum quotient: K_max = t - 1 = 65536
pub const MAX_QUOTIENT_K: u64 = 65536;

// K-Elimination Status

/// K-Elimination status classification for the expansion view.
///
/// The range certificate (§8.2) proves that for any w reduced mod t^2,
/// K = floor(w/t) ≤ 65536 < 65538 = A, which means:
/// - The elimination output is the **full quotient, every time, by construction**
/// - No separate range proof is required
/// - `kelim_status_t` is `K_EXACT_BOUNDED` for free
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KelimStatusT {
    /// Exact quotient with certified bounds — automatic for production parameters
    KExactBounded,
    /// Exact quotient (theoretical, not used in production with range certificate)
    KExact,
    /// Approximate result (not used in production paths)
    KApproximate,
}

impl fmt::Display for KelimStatusT {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KelimStatusT::KExactBounded => write!(f, "K_EXACT_BOUNDED"),
            KelimStatusT::KExact => write!(f, "K_EXACT"),
            KelimStatusT::KApproximate => write!(f, "K_APPROXIMATE"),
        }
    }
}

// Range Certificate

/// Range certificate for the expansion view.
///
/// For production parameters (t = 65537, A = 65538), this certificate
/// is **automatic** and always passes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RangeCertificate {
    /// The prime t = 65537
    pub t: u64,
    /// The work modulus A = t + 1 = 65538
    pub a: u64,
    /// The expansion modulus P = t^2
    pub p: u64,
    /// Maximum possible quotient K = t - 1 = 65536
    pub max_k: u64,
    /// Rounding shift h = (t - 1) / 2 = 32768
    pub h: u64,
}

impl RangeCertificate {
    /// Create a new range certificate for production parameters.
    pub const fn production() -> Self {
        Self {
            t: PRODUCTION_T,
            a: WORK_MODULUS_A,
            p: EXPANSION_MODULUS_P,
            max_k: MAX_QUOTIENT_K,
            h: ROUNDING_SHIFT_H,
        }
    }

    /// Verify that K = floor(w/t) is always <= max_k < A.
    ///
    /// This is the core of the automatic range certificate.
    /// For any w ∈ [0, t^2), we have:
    /// - 0 ≤ w < t^2
    /// - 0 ≤ w/t < t
    /// - 0 ≤ floor(w/t) ≤ t - 1 = max_k
    /// - max_k = 65536 < 65538 = A
    pub fn verify_automatic(&self) -> bool {
        // Verify algebraic identities
        assert_eq!(self.t + 1, self.a, "t + 1 must equal A");
        assert_eq!(self.t * self.t, self.p, "t^2 must equal P");
        assert_eq!(self.max_k, self.t - 1, "max_k must equal t - 1");
        assert_eq!((self.t - 1) / 2, self.h, "h must equal (t - 1) / 2");

        // Core verification: max_k < A
        self.max_k < self.a
    }

    /// Verify the self-inverse property: t^2 ≡ 1 (mod A)
    pub fn verify_self_inverse(&self) -> bool {
        let t_sq_mod_a = (self.t * self.t) % self.a;
        t_sq_mod_a == 1
    }

    /// Verify t ≡ -1 (mod A)
    pub fn verify_neg_one(&self) -> bool {
        let t_mod_a = self.t % self.a;
        let neg_one_mod_a = (-1i64 as u64).wrapping_add(self.a);
        t_mod_a == neg_one_mod_a
    }

    /// Verify subtraction collapse: t^2 - 1 ≡ 0 (mod A)
    pub fn verify_subtraction_collapse(&self) -> bool {
        let collapse = (self.t * self.t - 1) % self.a;
        collapse == 0
    }

    /// Verify all algebraic identities for the StarLift contraction.
    pub fn verify_starlift_identities(&self) -> bool {
        self.verify_self_inverse()
            && self.verify_neg_one()
            && self.verify_subtraction_collapse()
            && self.verify_automatic()
    }

    /// Compute K = floor(w / t) for a given w.
    pub fn compute_k(&self, w: u64) -> u64 {
        w / self.t
    }

    /// Compute the rounded variant: K = floor((w + h) / t)
    pub fn compute_k_rounded(&self, w: u64) -> u64 {
        let x = (w + self.h) % self.p;
        x / self.t
    }

    /// Verify that K is within the certified range for a given w.
    pub fn verify_k_in_range(&self, w: u64) -> bool {
        let k = self.compute_k(w);
        k <= self.max_k && k < self.a
    }

    /// Verify that the rounded K is within the certified range for a given w.
    pub fn verify_k_rounded_in_range(&self, w: u64) -> bool {
        let k = self.compute_k_rounded(w);
        k <= self.max_k && k < self.a
    }
}

// StarLift Contraction Oracle

/// StarLift contraction oracle with automatic range certification.
///
/// This oracle provides the mathematical foundation for the t/(t+1) contraction
/// mechanism, which is the StarLift scaled to production parameters.
#[derive(Debug, Clone)]
pub struct StarLiftContractionOracle {
    /// Range certificate for production parameters
    pub range_cert: RangeCertificate,
    /// K-Elimination status (always K_EXACT_BOUNDED for production)
    pub kelim_status: KelimStatusT,
}

impl StarLiftContractionOracle {
    /// Create a new StarLift contraction oracle with production parameters.
    pub fn new() -> Self {
        Self {
            range_cert: RangeCertificate::production(),
            kelim_status: KelimStatusT::KExactBounded,
        }
    }

    /// Verify all StarLift identities and the automatic range certificate.
    pub fn verify_all(&self) -> bool {
        self.range_cert.verify_starlift_identities()
    }

    /// Get the KelimStatusT for a given w.
    ///
    /// For production parameters, this is always K_EXACT_BOUNDED
    /// because the range certificate is automatic.
    pub fn get_kelim_status(&self, _w: u64) -> KelimStatusT {
        // The range certificate guarantees K_EXACT_BOUNDED for all w
        self.kelim_status
    }

    /// Compute the contraction: w -> d = floor((w + h) / t) mod t
    pub fn contract(&self, w: u64) -> u64 {
        let x = (w + self.range_cert.h) % self.range_cert.p;
        let d = x / self.range_cert.t;
        d % self.range_cert.t
    }

    /// Verify that the contraction output is the full quotient.
    ///
    /// For production parameters, K = floor(w/t) is always the full quotient
    /// because K <= 65536 < 65538 = A, so K mod A = K.
    pub fn verify_full_quotient(&self, w: u64) -> bool {
        let k = self.range_cert.compute_k(w);
        let k_mod_a = k % self.range_cert.a;
        // Full quotient means K mod A = K
        k == k_mod_a
    }
}

impl Default for StarLiftContractionOracle {
    fn default() -> Self {
        Self::new()
    }
}

// Bootstrap Oracle

/// Bootstrap oracle for the encrypted digit-removal circuit.
///
/// This oracle provides test-only coverage for the digit-removal circuit.
/// It decrypts a phase and encrypts its canonical low digits to exercise
/// the conditional kernel.
///
/// **WARNING**: This is a test oracle, not a public lift provider.
#[derive(Debug, Clone)]
pub struct BootstrapOracle {
    /// StarLift contraction oracle
    pub contraction: StarLiftContractionOracle,
}

impl BootstrapOracle {
    /// Create a new bootstrap oracle.
    pub fn new() -> Self {
        Self {
            contraction: StarLiftContractionOracle::new(),
        }
    }

    /// Simulate the canonical low-digit lift for a given coefficient.
    ///
    /// For a value w ∈ [0, t^2), this computes:
    /// - x = (w + h) mod t^2
    /// - r = x mod t (canonical low digit)
    /// - d = floor(x / t) (quotient)
    ///
    /// Returns (r, d) where r is the canonical low digit and d is the quotient.
    pub fn canonical_low_digit_lift(&self, w: u64) -> (u64, u64) {
        let cert = &self.contraction.range_cert;
        let x = (w + cert.h) % cert.p;
        let r = x % cert.t;
        let d = x / cert.t;
        (r, d)
    }

    /// Verify that r is canonical (in [0, t)).
    pub fn verify_canonical(&self, r: u64) -> bool {
        let cert = &self.contraction.range_cert;
        r < cert.t
    }

    /// Verify that d is within the certified range.
    pub fn verify_quotient(&self, d: u64) -> bool {
        let cert = &self.contraction.range_cert;
        d <= cert.max_k && d < cert.a
    }
}

// Gate C Assertions

/// Gate C: Range proof gate.
///
/// **Before**: Required separate range proof for K
/// **After**: Only needs proof that value was reduced mod t^2
/// **Reason**: Range certificate is automatic (see §8.2)
#[derive(Debug, Clone)]
pub struct GateC {
    /// Range certificate
    pub range_cert: RangeCertificate,
}

impl GateC {
    /// Create a new Gate C with production parameters.
    pub fn new() -> Self {
        Self {
            range_cert: RangeCertificate::production(),
        }
    }

    /// Check that a value w is reduced mod t^2.
    ///
    /// This is the ONLY check needed for Gate C, because the range certificate
    /// is automatic.
    pub fn check_reduced_mod_t2(&self, w: u64) -> bool {
        w < self.range_cert.p
    }

    /// Get the K-Elimination status for a reduced value.
    ///
    /// For any w reduced mod t^2, the status is K_EXACT_BOUNDED.
    pub fn get_kelim_status(&self, w: u64) -> KelimStatusT {
        if self.check_reduced_mod_t2(w) {
            KelimStatusT::KExactBounded
        } else {
            // Value not reduced mod t^2 — this should be a refusal
            panic!("Value not reduced mod t^2 — Gate C refuses");
        }
    }

    /// Verify that K = floor(w/t) is the full quotient.
    pub fn verify_full_quotient(&self, w: u64) -> bool {
        if !self.check_reduced_mod_t2(w) {
            return false;
        }
        let k = w / self.range_cert.t;
        let k_mod_a = k % self.range_cert.a;
        k == k_mod_a
    }
}

// Test Harness

/// Test harness for the native CRAM bootstrap oracle.
///
/// This harness verifies all the mathematical claims from the deep-dive canvas (§8).
pub struct NativeCramBootstrapOracleHarness {
    /// StarLift contraction oracle
    pub contraction: StarLiftContractionOracle,
    /// Bootstrap oracle
    pub bootstrap: BootstrapOracle,
    /// Gate C
    pub gate_c: GateC,
}

impl NativeCramBootstrapOracleHarness {
    /// Create a new test harness.
    pub fn new() -> Self {
        Self {
            contraction: StarLiftContractionOracle::new(),
            bootstrap: BootstrapOracle::new(),
            gate_c: GateC::new(),
        }
    }

    /// Run all verification checks.
    pub fn run_all_checks(&self) -> bool {
        println!("=== Native CRAM Bootstrap Oracle: All Checks ===\n");

        // §8.1: Structural Fit
        println!("Section 8.1 Structural Fit Verification:");
        let starlift_ok = self.verify_starlift_identities();
        println!("  StarLift identities: {}", if starlift_ok { "PASS" } else { "FAIL" });

        // §8.2: Range Certificate
        println!("\nSection 8.2 Range Certificate Verification:");
        let range_ok = self.verify_range_certificate();
        println!("  Automatic range certificate: {}", if range_ok { "PASS" } else { "FAIL" });

        // §8.3: Consequences
        println!("\nSection 8.3 Consequences Verification:");
        let k_exact_ok = self.verify_k_exact_bounded();
        println!("  K_EXACT_BOUNDED for free: {}", if k_exact_ok { "PASS" } else { "FAIL" });

        let full_quotient_ok = self.verify_full_quotient();
        println!("  Full quotient property: {}", if full_quotient_ok { "PASS" } else { "FAIL" });

        let a_composite_ok = self.verify_a_composite();
        println!("  A = 65538 is composite: {}", if a_composite_ok { "PASS" } else { "FAIL" });

        // §8.4: Boundary Cases
        println!("\nSection 8.4 Boundary Cases Verification:");
        let boundaries_ok = self.verify_boundary_cases();
        println!("  All boundary cases: {}", if boundaries_ok { "PASS" } else { "FAIL" });

        // §8.5: Random Sampling
        println!("\nSection 8.5 Random Sampling Verification:");
        let sampling_ok = self.verify_random_sampling(20_000);
        println!("  20,000 random samples: {}", if sampling_ok { "PASS" } else { "FAIL" });

        let all_pass = starlift_ok && range_ok && k_exact_ok && full_quotient_ok
            && a_composite_ok && boundaries_ok && sampling_ok;

        println!("\n=== Overall Result: {} ===", if all_pass { "ALL CHECKS PASS" } else { "SOME CHECKS FAILED" });

        all_pass
    }

    /// Verify StarLift algebraic identities.
    pub fn verify_starlift_identities(&self) -> bool {
        self.contraction.range_cert.verify_starlift_identities()
    }

    /// Verify the automatic range certificate.
    pub fn verify_range_certificate(&self) -> bool {
        self.contraction.range_cert.verify_automatic()
    }

    /// Verify K_EXACT_BOUNDED is free by construction.
    pub fn verify_k_exact_bounded(&self) -> bool {
        let cert = &self.contraction.range_cert;
        // For all w in [0, t^2), K = floor(w/t) <= t-1 < A
        // This means K mod A = K, so K_EXACT_BOUNDED holds
        cert.max_k < cert.a
    }

    /// Verify the full quotient property.
    pub fn verify_full_quotient(&self) -> bool {
        // For production parameters, this should hold for all w
        // We test a few representative values
        let cert = &self.contraction.range_cert;
        let test_values = [0, 1, cert.t - 1, cert.t, cert.p - cert.t, cert.p - 1];
        test_values.iter().all(|&w| self.gate_c.verify_full_quotient(w))
    }

    /// Verify that A = 65538 is composite.
    pub fn verify_a_composite(&self) -> bool {
        let a = self.contraction.range_cert.a;
        // Factorization: 65538 = 2 * 3^2 * 11 * 331
        a == 2 * 3 * 3 * 11 * 331
    }

    /// Verify all boundary cases.
    pub fn verify_boundary_cases(&self) -> bool {
        let cert = &self.contraction.range_cert;
        let boundaries = [0, cert.t - 1, cert.t, cert.p - cert.t, cert.p - 1];
        boundaries.iter().all(|&w| {
            cert.verify_k_in_range(w) && cert.verify_k_rounded_in_range(w)
        })
    }

    /// Verify random sampling.
    pub fn verify_random_sampling(&self, count: usize) -> bool {
        // Use a simple deterministic RNG for reproducibility
        let cert = &self.contraction.range_cert;
        let mut w: u64 = 12345; // Seed

        (0..count).all(|_| {
            // Simple LCG for deterministic sampling
            w = w.wrapping_mul(6364136223846793005).wrapping_add(1);
            let w_mod_p = w % cert.p;
            cert.verify_k_in_range(w_mod_p) && cert.verify_k_rounded_in_range(w_mod_p)
        })
    }

    /// Run Gate C checks.
    pub fn run_gate_c_checks(&self) -> bool {
        println!("=== Gate C Checks ===\n");

        let cert = &self.contraction.range_cert;

        // Test that reduced values pass
        let reduced_values = [0, 1, cert.t - 1, cert.t, cert.p - 1];
        let reduced_ok = reduced_values.iter().all(|&w| {
            let passes = self.gate_c.check_reduced_mod_t2(w);
            let status = self.gate_c.get_kelim_status(w);
            println!("  w = {}: reduced = {}, status = {}", w, passes, status);
            passes && status == KelimStatusT::KExactBounded
        });

        // Test that non-reduced values are refused
        let non_reduced = cert.p; // w = t^2 is not reduced mod t^2
        let non_reduced_ok = !self.gate_c.check_reduced_mod_t2(non_reduced);
        println!("  w = {}: reduced = {} (should be false)", non_reduced, self.gate_c.check_reduced_mod_t2(non_reduced));

        println!("\nGate C: {}", if reduced_ok && non_reduced_ok { "PASS" } else { "FAIL" });
        reduced_ok && non_reduced_ok
    }
}

// Main

fn main() {
    // Initialize the harness
    let harness = NativeCramBootstrapOracleHarness::new();

    // Run all checks
    let all_pass = harness.run_all_checks();

    // Run Gate C checks
    let gate_c_pass = harness.run_gate_c_checks();

    // Exit with appropriate code
    if all_pass && gate_c_pass {
        println!("\nAll verification checks passed!");
        std::process::exit(0);
    } else {
        println!("\nSome verification checks failed!");
        std::process::exit(1);
    }
}

// Tests

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_range_certificate_automatic() {
        let cert = RangeCertificate::production();
        assert!(cert.verify_automatic());
    }

    #[test]
    fn test_starlift_identities() {
        let cert = RangeCertificate::production();
        assert!(cert.verify_self_inverse());
        assert!(cert.verify_neg_one());
        assert!(cert.verify_subtraction_collapse());
        assert!(cert.verify_starlift_identities());
    }

    #[test]
    fn test_boundary_cases() {
        let harness = NativeCramBootstrapOracleHarness::new();
        assert!(harness.verify_boundary_cases());
    }

    #[test]
    fn test_random_sampling() {
        let harness = NativeCramBootstrapOracleHarness::new();
        assert!(harness.verify_random_sampling(1000));
    }

    #[test]
    fn test_gate_c() {
        let harness = NativeCramBootstrapOracleHarness::new();
        assert!(harness.run_gate_c_checks());
    }

    #[test]
    fn test_canonical_low_digit_lift() {
        let oracle = BootstrapOracle::new();
        let cert = &oracle.contraction.range_cert;

        // Test that for any w, the canonical low digit is in [0, t)
        let test_values = [0, 1, cert.t - 1, cert.t, cert.p - cert.t, cert.p - 1];
        for &w in &test_values {
            let (r, d) = oracle.canonical_low_digit_lift(w);
            assert!(oracle.verify_canonical(r), "r = {} not canonical for w = {}", r, w);
            assert!(oracle.verify_quotient(d), "d = {} not in range for w = {}", d, w);
        }
    }

    #[test]
    fn test_full_quotient_property() {
        let harness = NativeCramBootstrapOracleHarness::new();
        assert!(harness.verify_full_quotient());
    }

    #[test]
    fn test_k_exact_bounded_free() {
        let harness = NativeCramBootstrapOracleHarness::new();
        assert!(harness.verify_k_exact_bounded());
    }

    #[test]
    fn test_a_composite() {
        let harness = NativeCramBootstrapOracleHarness::new();
        assert!(harness.verify_a_composite());
    }
}
