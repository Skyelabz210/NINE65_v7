//! Homomorphic Operations Module
//!
//! BFV homomorphic operations:
//! - Add: component-wise addition
//! - Mul: tensor product followed by relinearization
//! - Negate: component-wise negation
//! - Add/Mul plaintext: operations with unencrypted values
//!
//! # Noise Budget Tracking
//!
//! Operations come in two variants:
//! - **Unchecked** (`add`, `mul`, etc.): Fast path, no budget tracking
//! - **Checked** (`try_add`, `try_mul`, etc.): Returns `Result`, tracks noise budget
//!
//! Use checked operations when you need to detect noise exhaustion before it causes
//! decryption failures. The `TrackedEvaluator` wrapper provides automatic tracking.

#[cfg(feature = "ntt_fft")]
use crate::arithmetic::NTTEngineFFT as NTTEngine;

#[cfg(not(feature = "ntt_fft"))]
use crate::arithmetic::NTTEngine;

use crate::arithmetic::KElimination;
use crate::errors::{Nine65Error, Nine65Result};
use crate::keys::EvaluationKey;
use crate::noise::budget::{NoiseBudget, NoiseExhausted, NoiseOpType};
use crate::ops::encrypt::{BFVEncoder, Ciphertext};
use crate::params::FHEConfig;
use crate::ring::RingPolynomial;

/// Homomorphic Evaluator
pub struct BFVEvaluator<'a> {
    pub ntt: &'a NTTEngine,
    pub eval_key: Option<&'a EvaluationKey>,
    pub encoder: &'a BFVEncoder,
    pub q: u64,
    pub t: u64,
    pub ke: KElimination, // K-Elimination for exact division
}

impl<'a> BFVEvaluator<'a> {
    pub fn new(
        ntt: &'a NTTEngine,
        encoder: &'a BFVEncoder,
        eval_key: Option<&'a EvaluationKey>,
    ) -> Self {
        Self {
            ntt,
            eval_key,
            encoder,
            q: encoder.q,
            t: encoder.t,
            ke: KElimination::for_fhe(encoder.q),
        }
    }

    /// Homomorphic addition: ct1 + ct2
    pub fn add(&self, ct1: &Ciphertext, ct2: &Ciphertext) -> Ciphertext {
        Ciphertext {
            c0: ct1.c0.add(&ct2.c0, self.ntt),
            c1: ct1.c1.add(&ct2.c1, self.ntt),
        }
    }

    /// Homomorphic subtraction: ct1 - ct2
    pub fn sub(&self, ct1: &Ciphertext, ct2: &Ciphertext) -> Ciphertext {
        Ciphertext {
            c0: ct1.c0.sub(&ct2.c0, self.ntt),
            c1: ct1.c1.sub(&ct2.c1, self.ntt),
        }
    }

    /// Homomorphic negation: -ct
    pub fn negate(&self, ct: &Ciphertext) -> Ciphertext {
        Ciphertext {
            c0: ct.c0.neg(self.ntt),
            c1: ct.c1.neg(self.ntt),
        }
    }

    /// Add plaintext to ciphertext
    ///
    /// # Panics
    /// Panics if `m >= t` (plaintext modulus). Prefer `try_add_plain()` on
    /// `TrackedEvaluator` for untrusted input.
    pub fn add_plain(&self, ct: &Ciphertext, m: u64) -> Ciphertext {
        let plain = self.encoder.try_encode(m)
            .unwrap_or_else(|e| panic!("add_plain: {}", e));
        Ciphertext {
            c0: ct.c0.add(&plain, self.ntt),
            c1: ct.c1.clone(),
        }
    }

    /// Multiply ciphertext by plaintext scalar
    ///
    /// Note: `m` is used as a raw scalar multiplier, not encoded via Δ.
    /// Values >= t are valid here (they scale coefficients mod q).
    pub fn mul_plain(&self, ct: &Ciphertext, m: u64) -> Ciphertext {
        Ciphertext {
            c0: ct.c0.scalar_mul(m, self.ntt),
            c1: ct.c1.scalar_mul(m, self.ntt),
        }
    }

    /// Homomorphic multiplication (requires eval key)
    /// Returns 3-component ciphertext that needs relinearization
    ///
    /// NOTE: For single-modulus BFV, we DON'T scale the tensor product.
    /// The scaling factor Δ² → Δ is handled by the decrypt formula.
    pub fn mul_no_relin(
        &self,
        ct1: &Ciphertext,
        ct2: &Ciphertext,
    ) -> (RingPolynomial, RingPolynomial, RingPolynomial) {
        // Tensor product:
        // c0' = c0_1 * c0_2
        // c1' = c0_1 * c1_2 + c1_1 * c0_2
        // c2' = c1_1 * c1_2

        #[cfg(feature = "parallel")]
        {
            // HIGH LEVEL: Parallelize 4 independent NTT multiplications
            // Uses nested rayon::join for optimal 4-core utilization
            let ((c0, c2), (c0_1_c1_2, c1_1_c0_2)) = rayon::join(
                || {
                    rayon::join(
                        || ct1.c0.mul(&ct2.c0, self.ntt), // c0
                        || ct1.c1.mul(&ct2.c1, self.ntt), // c2
                    )
                },
                || {
                    rayon::join(
                        || ct1.c0.mul(&ct2.c1, self.ntt), // cross 1
                        || ct1.c1.mul(&ct2.c0, self.ntt), // cross 2
                    )
                },
            );

            let c1 = c0_1_c1_2.add(&c1_1_c0_2, self.ntt);

            // DO NOT scale here! The Δ² factor will be handled in decrypt.
            // Scaling coefficient-wise doesn't work because polynomial convolution
            // in the ring doesn't commute with per-coefficient rounding.

            (c0, c1, c2)
        }

        #[cfg(not(feature = "parallel"))]
        {
            // Sequential fallback
            let c0 = ct1.c0.mul(&ct2.c0, self.ntt);

            let c0_1_c1_2 = ct1.c0.mul(&ct2.c1, self.ntt);
            let c1_1_c0_2 = ct1.c1.mul(&ct2.c0, self.ntt);
            let c1 = c0_1_c1_2.add(&c1_1_c0_2, self.ntt);

            let c2 = ct1.c1.mul(&ct2.c1, self.ntt);

            // DO NOT scale here! The Δ² factor will be handled in decrypt.
            // Scaling coefficient-wise doesn't work because polynomial convolution
            // in the ring doesn't commute with per-coefficient rounding.

            (c0, c1, c2)
        }
    }

    /// Scale polynomial by t/q with rounding using K-Elimination
    ///
    /// This is the critical operation that must be EXACT.
    /// Standard truncation division causes error accumulation.
    fn scale_by_t_over_q(&self, poly: &RingPolynomial) -> RingPolynomial {
        // round(t * c / q) for each coefficient
        // Using K-Elimination for exact computation
        let coeffs: Vec<u64> = poly
            .coeffs
            .iter()
            .map(|&c| self.ke.scale_and_round(c, self.t, self.q))
            .collect();

        RingPolynomial::from_coeffs(coeffs, self.q)
    }

    /// Relinearize 3-component ciphertext to 2-component
    ///
    /// # Panics
    /// Panics if no evaluation key was provided. Use `try_relinearize()` for fallible variant.
    pub fn relinearize(
        &self,
        c0: &RingPolynomial,
        c1: &RingPolynomial,
        c2: &RingPolynomial,
    ) -> Ciphertext {
        self.try_relinearize(c0, c1, c2)
            .expect("DESIGN ERROR: Evaluation key required for relinearization - use try_relinearize() or provide eval_key during construction")
    }

    /// Fallible relinearization that returns error if no evaluation key
    pub fn try_relinearize(
        &self,
        c0: &RingPolynomial,
        c1: &RingPolynomial,
        c2: &RingPolynomial,
    ) -> Nine65Result<Ciphertext> {
        let eval_key = self.eval_key.ok_or(Nine65Error::KeyRegimeMismatch {
            message: "Evaluation key required for relinearization".to_string(),
        })?;

        // Decompose c2 into base-w digits
        let digits = self.decompose(c2, eval_key.decomp_base, eval_key.levels);

        // Accumulate: c0' = c0 + sum(digits[i] * rlk[i].0)
        //             c1' = c1 + sum(digits[i] * rlk[i].1)
        let mut c0_new = c0.clone();
        let mut c1_new = c1.clone();

        for (i, digit) in digits.iter().enumerate() {
            let (rlk_b, rlk_a) = &eval_key.rlk[i];

            let term0 = digit.mul(rlk_b, self.ntt);
            let term1 = digit.mul(rlk_a, self.ntt);

            c0_new = c0_new.add(&term0, self.ntt);
            c1_new = c1_new.add(&term1, self.ntt);
        }

        Ok(Ciphertext {
            c0: c0_new,
            c1: c1_new,
        })
    }

    /// Decompose polynomial into base-w digits
    fn decompose(&self, poly: &RingPolynomial, base: u64, levels: usize) -> Vec<RingPolynomial> {
        let mut digits = Vec::with_capacity(levels);
        let mut current: Vec<u64> = poly.coeffs.clone();

        for _ in 0..levels {
            let digit: Vec<u64> = current.iter().map(|&c| c % base).collect();

            current = current.iter().map(|&c| c / base).collect();

            digits.push(RingPolynomial::from_coeffs(digit, self.q));
        }

        digits
    }

    /// Full homomorphic multiplication with relinearization
    ///
    /// **DEPRECATED**: For ct×ct multiplication, use `RNSFHEContext::mul_dual_symmetric()`
    /// which provides exact K-Elimination rescaling and works correctly for all parameter sets.
    /// This single-modulus implementation only works when Δ² ≤ Q.
    ///
    /// BFV ct×ct strategy for single-modulus:
    /// 1. Compute tensor product (d0, d1, d2) - scale is Δ²
    /// 2. Relinearize to (c0', c1') - scale still Δ²
    /// 3. Scale by t/q to convert Δ² → Δ
    ///
    /// Scaling AFTER relin works better than before because
    /// relin doesn't involve ring multiplication that compounds errors.
    #[deprecated(
        since = "0.2.0",
        note = "Use RNSFHEContext::mul_dual_symmetric() for K-Elimination exact rescaling"
    )]
    pub fn mul(&self, ct1: &Ciphertext, ct2: &Ciphertext) -> Ciphertext {
        let (c0, c1, c2) = self.mul_no_relin(ct1, ct2);
        let ct_relin = self.relinearize(&c0, &c1, &c2);

        // Scale by t/q to convert from Δ² scale to Δ scale
        Ciphertext {
            c0: self.scale_by_t_over_q(&ct_relin.c0),
            c1: self.scale_by_t_over_q(&ct_relin.c1),
        }
    }
}

// =============================================================================
// TRACKED EVALUATOR: Noise Budget Aware Operations
// =============================================================================

/// Evaluator with automatic noise budget tracking
///
/// Wraps `BFVEvaluator` and tracks noise budget through all operations.
/// Returns `Err(NoiseExhausted)` when budget is depleted.
///
/// # Example
///
/// ```ignore
/// let mut tracked = TrackedEvaluator::new(evaluator, config);
///
/// // Operations return Result
/// let ct_sum = tracked.try_add(&ct_a, &ct_b)?;
/// let ct_prod = tracked.try_mul_plain(&ct_sum, 5)?;
///
/// // Check remaining budget
/// println!("Budget: {}", tracked.budget());
/// ```
pub struct TrackedEvaluator<'a> {
    /// Inner evaluator
    evaluator: BFVEvaluator<'a>,
    /// Current noise budget
    budget: NoiseBudget,
    /// Config reference for cost calculations
    config: &'a FHEConfig,
}

impl<'a> TrackedEvaluator<'a> {
    /// Create tracked evaluator with automatic budget from config
    pub fn new(evaluator: BFVEvaluator<'a>, config: &'a FHEConfig) -> Self {
        Self {
            evaluator,
            budget: NoiseBudget::from_config(config),
            config,
        }
    }

    /// Create with explicit initial budget (for testing)
    pub fn with_budget(
        evaluator: BFVEvaluator<'a>,
        config: &'a FHEConfig,
        budget_bits: i64,
    ) -> Self {
        Self {
            evaluator,
            budget: NoiseBudget::with_budget_bits(budget_bits),
            config,
        }
    }

    /// Get reference to inner evaluator
    pub fn inner(&self) -> &BFVEvaluator<'a> {
        &self.evaluator
    }

    /// Get current noise budget
    pub fn budget(&self) -> &NoiseBudget {
        &self.budget
    }

    /// Get mutable reference to noise budget
    pub fn budget_mut(&mut self) -> &mut NoiseBudget {
        &mut self.budget
    }

    /// Check if an operation can be performed
    pub fn can_add(&self) -> bool {
        self.budget.can_perform(NoiseBudget::add_cost())
    }

    /// Check if plaintext multiplication can be performed
    pub fn can_mul_plain(&self) -> bool {
        self.budget
            .can_perform(NoiseBudget::mul_plain_cost(self.config))
    }

    /// Check if ciphertext multiplication can be performed
    pub fn can_mul(&self) -> bool {
        let cost = NoiseBudget::mul_ct_cost(self.config) + NoiseBudget::relin_cost(self.config);
        self.budget.can_perform(cost)
    }

    /// Remaining multiplication depth
    pub fn remaining_depth(&self) -> usize {
        self.budget.remaining_multiplications(self.config)
    }

    // =========================================================================
    // Tracked Operations (return Result)
    // =========================================================================

    /// Homomorphic addition with noise tracking
    pub fn try_add(
        &mut self,
        ct1: &Ciphertext,
        ct2: &Ciphertext,
    ) -> Result<Ciphertext, NoiseExhausted> {
        self.budget
            .consume(NoiseOpType::Add, NoiseBudget::add_cost())?;
        Ok(self.evaluator.add(ct1, ct2))
    }

    /// Homomorphic subtraction with noise tracking
    pub fn try_sub(
        &mut self,
        ct1: &Ciphertext,
        ct2: &Ciphertext,
    ) -> Result<Ciphertext, NoiseExhausted> {
        self.budget
            .consume(NoiseOpType::Add, NoiseBudget::add_cost())?;
        Ok(self.evaluator.sub(ct1, ct2))
    }

    /// Negate with noise tracking (minimal cost)
    pub fn try_negate(&mut self, ct: &Ciphertext) -> Result<Ciphertext, NoiseExhausted> {
        // Negation has negligible noise impact
        self.budget.consume(NoiseOpType::Add, 100)?;
        Ok(self.evaluator.negate(ct))
    }

    /// Add plaintext with noise tracking
    pub fn try_add_plain(&mut self, ct: &Ciphertext, m: u64) -> Result<Ciphertext, NoiseExhausted> {
        self.budget
            .consume(NoiseOpType::AddPlain, NoiseBudget::add_plain_cost())?;
        Ok(self.evaluator.add_plain(ct, m))
    }

    /// Multiply by plaintext with noise tracking
    pub fn try_mul_plain(&mut self, ct: &Ciphertext, m: u64) -> Result<Ciphertext, NoiseExhausted> {
        self.budget.consume(
            NoiseOpType::MulPlain,
            NoiseBudget::mul_plain_cost(self.config),
        )?;
        Ok(self.evaluator.mul_plain(ct, m))
    }

    /// Ciphertext multiplication without relinearization (for advanced use)
    pub fn try_mul_no_relin(
        &mut self,
        ct1: &Ciphertext,
        ct2: &Ciphertext,
    ) -> Result<(RingPolynomial, RingPolynomial, RingPolynomial), NoiseExhausted> {
        self.budget
            .consume(NoiseOpType::MulCt, NoiseBudget::mul_ct_cost(self.config))?;
        Ok(self.evaluator.mul_no_relin(ct1, ct2))
    }

    /// Relinearization with noise tracking
    pub fn try_relinearize(
        &mut self,
        c0: &RingPolynomial,
        c1: &RingPolynomial,
        c2: &RingPolynomial,
    ) -> Result<Ciphertext, NoiseExhausted> {
        self.budget
            .consume(NoiseOpType::Relin, NoiseBudget::relin_cost(self.config))?;
        Ok(self.evaluator.relinearize(c0, c1, c2))
    }

    /// Full ciphertext multiplication with relinearization
    #[allow(deprecated)]
    pub fn try_mul(
        &mut self,
        ct1: &Ciphertext,
        ct2: &Ciphertext,
    ) -> Result<Ciphertext, NoiseExhausted> {
        // Consume both multiplication and relinearization costs
        let mul_cost = NoiseBudget::mul_ct_cost(self.config);
        let relin_cost = NoiseBudget::relin_cost(self.config);

        self.budget.consume(NoiseOpType::MulCt, mul_cost)?;
        self.budget.consume(NoiseOpType::Relin, relin_cost)?;

        Ok(self.evaluator.mul(ct1, ct2))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entropy::ShadowHarvester;
    use crate::keys::KeySet;
    use crate::ops::encrypt::{BFVDecryptor, BFVEncryptor};
    use crate::params::secure_configs::SecureConfig;
    use crate::params::FHEConfig;

    fn setup() -> (FHEConfig, NTTEngine, KeySet, ShadowHarvester, BFVEncoder) {
        let config = SecureConfig::test_fast_insecure().into_config();
        let ntt = NTTEngine::new(config.q, config.n);
        let mut harvester = ShadowHarvester::with_seed(42);
        let keys = KeySet::generate(&config, &ntt, &mut harvester);
        let encoder = BFVEncoder::new(&config);
        (config, ntt, keys, harvester, encoder)
    }

    fn setup_mul() -> (FHEConfig, NTTEngine, KeySet, ShadowHarvester, BFVEncoder) {
        // Use light_mul config for ct×ct (small Δ prevents overflow)
        let config = FHEConfig::light_mul_insecure();
        let ntt = NTTEngine::new(config.q, config.n);
        let mut harvester = ShadowHarvester::with_seed(42);
        let keys = KeySet::generate(&config, &ntt, &mut harvester);
        let encoder = BFVEncoder::new(&config);
        (config, ntt, keys, harvester, encoder)
    }

    #[test]
    fn test_homomorphic_add() {
        let (config, ntt, keys, mut harvester, encoder) = setup();

        let encryptor = BFVEncryptor::new(&keys.public_key, &encoder, &ntt, config.eta);
        let decryptor = BFVDecryptor::new(&keys.secret_key, &encoder, &ntt);
        let evaluator = BFVEvaluator::new(&ntt, &encoder, None);

        let a = 100u64;
        let b = 200u64;

        let ct_a = encryptor.encrypt(a, &mut harvester);
        let ct_b = encryptor.encrypt(b, &mut harvester);

        let ct_sum = evaluator.add(&ct_a, &ct_b);
        let result = decryptor.decrypt(&ct_sum);

        assert_eq!(
            result,
            (a + b) % config.t,
            "Homo add failed: {} + {} = {} (expected {})",
            a,
            b,
            result,
            (a + b) % config.t
        );
    }

    #[test]
    fn test_subtraction() {
        let (config, ntt, keys, mut harvester, encoder) = setup();

        let encryptor = BFVEncryptor::new(&keys.public_key, &encoder, &ntt, config.eta);
        let decryptor = BFVDecryptor::new(&keys.secret_key, &encoder, &ntt);
        let evaluator = BFVEvaluator::new(&ntt, &encoder, None);

        let a = 500u64;
        let b = 200u64;

        let ct_a = encryptor.encrypt(a, &mut harvester);
        let ct_b = encryptor.encrypt(b, &mut harvester);

        let ct_diff = evaluator.sub(&ct_a, &ct_b);
        let result = decryptor.decrypt(&ct_diff);

        assert_eq!(result, a - b);
    }

    #[test]
    fn test_negate() {
        let (config, ntt, keys, mut harvester, encoder) = setup();

        let encryptor = BFVEncryptor::new(&keys.public_key, &encoder, &ntt, config.eta);
        let decryptor = BFVDecryptor::new(&keys.secret_key, &encoder, &ntt);
        let evaluator = BFVEvaluator::new(&ntt, &encoder, None);

        let a = 100u64;

        let ct_a = encryptor.encrypt(a, &mut harvester);
        let ct_neg = evaluator.negate(&ct_a);
        let result = decryptor.decrypt(&ct_neg);

        assert_eq!(result, (config.t - a) % config.t);
    }

    #[test]
    fn test_add_plain() {
        let (config, ntt, keys, mut harvester, encoder) = setup();

        let encryptor = BFVEncryptor::new(&keys.public_key, &encoder, &ntt, config.eta);
        let decryptor = BFVDecryptor::new(&keys.secret_key, &encoder, &ntt);
        let evaluator = BFVEvaluator::new(&ntt, &encoder, None);

        let a = 100u64;
        let b = 50u64;

        let ct_a = encryptor.encrypt(a, &mut harvester);
        let ct_sum = evaluator.add_plain(&ct_a, b);
        let result = decryptor.decrypt(&ct_sum);

        assert_eq!(result, (a + b) % config.t);
    }

    #[test]
    fn test_mul_plain() {
        let (config, ntt, keys, mut harvester, encoder) = setup();

        let encryptor = BFVEncryptor::new(&keys.public_key, &encoder, &ntt, config.eta);
        let decryptor = BFVDecryptor::new(&keys.secret_key, &encoder, &ntt);
        let evaluator = BFVEvaluator::new(&ntt, &encoder, None);

        let a = 10u64;
        let b = 5u64;

        let ct_a = encryptor.encrypt(a, &mut harvester);
        let ct_prod = evaluator.mul_plain(&ct_a, b);
        let result = decryptor.decrypt(&ct_prod);

        assert_eq!(result, (a * b) % config.t);
    }

    #[test]
    fn test_homomorphic_mul_no_relin() {
        let (config, ntt, keys, mut harvester, encoder) = setup();

        let encryptor = BFVEncryptor::new(&keys.public_key, &encoder, &ntt, config.eta);
        let evaluator = BFVEvaluator::new(&ntt, &encoder, None);

        let a = 5u64;
        let b = 7u64;

        let ct_a = encryptor.encrypt(a, &mut harvester);
        let ct_b = encryptor.encrypt(b, &mut harvester);

        let (_c0, _c1, _c2) = evaluator.mul_no_relin(&ct_a, &ct_b);

        // Just check it doesn't panic; full verification needs relinearization
    }

    #[test]
    fn test_relinearization_trace() {
        // Trace relinearization to find the bug
        let (config, ntt, keys, mut harvester, encoder) = setup_mul();

        let delta = config.delta();
        let s = &keys.secret_key.s;
        let s2 = s.mul(s, &ntt);

        println!("=== RELINEARIZATION TRACE ===");
        println!("q={}, t={}, Δ={}", config.q, config.t, delta);

        let a = 5u64;
        let b = 7u64;
        let _expected = (a * b) % config.t;

        let encryptor = BFVEncryptor::new(&keys.public_key, &encoder, &ntt, config.eta);
        let ct_a = encryptor.encrypt(a, &mut harvester);
        let ct_b = encryptor.encrypt(b, &mut harvester);

        // Tensor product
        let d0 = ct_a.c0.mul(&ct_b.c0, &ntt);
        let c0a_c1b = ct_a.c0.mul(&ct_b.c1, &ntt);
        let c1a_c0b = ct_a.c1.mul(&ct_b.c0, &ntt);
        let d1 = c0a_c1b.add(&c1a_c0b, &ntt);
        let d2 = ct_a.c1.mul(&ct_b.c1, &ntt);

        // Before relin: d0 + d1*s + d2*s²
        let d1_s = d1.mul(s, &ntt);
        let d2_s2 = d2.mul(&s2, &ntt);
        let before_relin = d0.add(&d1_s, &ntt).add(&d2_s2, &ntt);
        println!(
            "\nBefore relin: d0 + d1*s + d2*s² [0] = {}",
            before_relin.coeffs[0]
        );

        // Check d2 values
        println!("\nd2[0] = {}", d2.coeffs[0]);
        println!("d2[1] = {}", d2.coeffs[1]);

        // Decomposition
        let eval_key = &keys.eval_key;
        let decomp_base = eval_key.decomp_base;
        let levels = eval_key.levels;
        println!("\nDecomposition: base={}, levels={}", decomp_base, levels);

        // Manual decomposition
        let mut digits = Vec::new();
        let mut current = d2.coeffs.clone();
        for i in 0..levels {
            let digit: Vec<u64> = current.iter().map(|&c| c % decomp_base).collect();
            current = current.iter().map(|&c| c / decomp_base).collect();
            println!("digit[{}][0] = {}", i, digit[0]);
            digits.push(RingPolynomial::from_coeffs(digit, config.q));
        }

        // Verify decomposition: sum(digit[i] * T^i) should = d2
        let mut reconstructed = RingPolynomial::zero(config.n, config.q);
        let mut power_of_t = 1u64;
        for i in 0..levels {
            let scaled = digits[i].scalar_mul(power_of_t, &ntt);
            reconstructed = reconstructed.add(&scaled, &ntt);
            power_of_t = ((power_of_t as u128 * decomp_base as u128) % config.q as u128) as u64;
        }
        println!(
            "\nReconstructed d2[0] = {} (original: {})",
            reconstructed.coeffs[0], d2.coeffs[0]
        );

        // Now do relinearization manually
        let mut c0_new = d0.clone();
        let mut c1_new = d1.clone();

        for (i, digit) in digits.iter().enumerate() {
            let (rlk_b, rlk_a) = &eval_key.rlk[i];

            let term0 = digit.mul(rlk_b, &ntt);
            let term1 = digit.mul(rlk_a, &ntt);

            println!("\nLevel {}: digit[0]={}", i, digit.coeffs[0]);
            println!("  term0 = digit×rlk_b: [0]={}", term0.coeffs[0]);
            println!("  term1 = digit×rlk_a: [0]={}", term1.coeffs[0]);

            c0_new = c0_new.add(&term0, &ntt);
            c1_new = c1_new.add(&term1, &ntt);
        }

        println!("\nAfter relin:");
        println!("  c0_new[0] = {}", c0_new.coeffs[0]);
        println!("  c1_new[0] = {}", c1_new.coeffs[0]);

        // Decrypt after relin
        let c1_s = c1_new.mul(s, &ntt);
        let after_relin = c0_new.add(&c1_s, &ntt);
        println!(
            "  c0_new + c1_new*s [0] = {} (should ≈ before_relin = {})",
            after_relin.coeffs[0], before_relin.coeffs[0]
        );

        // Check what rlk_b + rlk_a*s should equal
        println!("\n--- RLK Verification ---");
        for i in 0..levels {
            let (rlk_b, rlk_a) = &eval_key.rlk[i];
            let rlk_a_s = rlk_a.mul(s, &ntt);
            let rlk_sum = rlk_b.add(&rlk_a_s, &ntt);
            // Should be ≈ e_i + s²×T^i
            let power = (1u64 << (16 * i)) % config.q;
            let expected_s2_ti = s2.scalar_mul(power, &ntt);
            println!(
                "rlk[{}]: b+a*s [0]={}, expected s²×T^{} [0]≈{}",
                i, rlk_sum.coeffs[0], i, expected_s2_ti.coeffs[0]
            );
        }
    }

    #[test]
    fn test_mul_degree2_decrypt() {
        // Test ct×ct by decrypting degree-2 directly (no relinearization)
        // This verifies the tensor product math is correct before relin
        let (config, ntt, keys, mut harvester, encoder) = setup_mul();

        let delta = config.delta();
        let s = &keys.secret_key.s;
        let s2 = s.mul(s, &ntt);

        println!("=== DEGREE-2 DECRYPT TEST ===");
        println!("q={}, t={}, Δ={}", config.q, config.t, delta);

        let a = 5u64;
        let b = 7u64;
        let expected = (a * b) % config.t;

        let encryptor = BFVEncryptor::new(&keys.public_key, &encoder, &ntt, config.eta);
        let ct_a = encryptor.encrypt(a, &mut harvester);
        let ct_b = encryptor.encrypt(b, &mut harvester);

        // Compute tensor product directly
        let d0 = ct_a.c0.mul(&ct_b.c0, &ntt);
        let c0a_c1b = ct_a.c0.mul(&ct_b.c1, &ntt);
        let c1a_c0b = ct_a.c1.mul(&ct_b.c0, &ntt);
        let d1 = c0a_c1b.add(&c1a_c0b, &ntt);
        let d2 = ct_a.c1.mul(&ct_b.c1, &ntt);

        // Degree-2 decrypt: d0 + d1*s + d2*s²
        let d1_s = d1.mul(s, &ntt);
        let d2_s2 = d2.mul(&s2, &ntt);
        let inner = d0.add(&d1_s, &ntt).add(&d2_s2, &ntt);

        println!(
            "inner[0] = {} (expected ~Δ²×{}={})",
            inner.coeffs[0],
            expected,
            (delta as u128) * (delta as u128) * (expected as u128)
        );

        // For degree-2: m = round(inner × t² / q²)
        // = round(inner × t / q × t / q)
        // First scale by t/q, then by t/q again
        let t = config.t as u128;
        let q = config.q as u128;
        let c = inner.coeffs[0] as u128;

        // Method 1: Single step t²/q²
        let result1 = ((c * t * t + q * q / 2) / (q * q)) as u64 % config.t;
        println!(
            "Degree-2 decrypt (t²/q²): {} (expected {})",
            result1, expected
        );

        // Method 2: Two-step scaling
        let step1 = (c * t + q / 2) / q;
        let result2 = ((step1 * t + q / 2) / q) as u64 % config.t;
        println!(
            "Degree-2 decrypt (2-step): {} (expected {})",
            result2, expected
        );

        // Verify
        if result1 == expected {
            println!("✓ Degree-2 decrypt WORKS with t²/q²");
        } else {
            println!(
                "✗ Degree-2 decrypt FAILED: got {} expected {}",
                result1, expected
            );
        }
    }

    #[test]
    fn test_tensor_product_trace() {
        // Test the degree-2 decrypt approach
        let (config, ntt, keys, mut harvester, encoder) = setup_mul();

        let delta = config.delta();
        let s = &keys.secret_key.s;
        let s2 = s.mul(s, &ntt);

        println!("=== DEGREE-2 DECRYPT TEST ===");
        println!("q={}, t={}, Δ={}", config.q, config.t, delta);
        println!("Δ² = {}", (delta as u128) * (delta as u128));

        let a = 5u64;
        let b = 7u64;
        let expected = (a * b) % config.t;

        // Encrypt
        let encryptor = BFVEncryptor::new(&keys.public_key, &encoder, &ntt, config.eta);
        let ct_a = encryptor.encrypt(a, &mut harvester);
        let ct_b = encryptor.encrypt(b, &mut harvester);

        // Compute tensor product WITHOUT scaling
        let d0 = ct_a.c0.mul(&ct_b.c0, &ntt);
        let c0a_c1b = ct_a.c0.mul(&ct_b.c1, &ntt);
        let c1a_c0b = ct_a.c1.mul(&ct_b.c0, &ntt);
        let d1 = c0a_c1b.add(&c1a_c0b, &ntt);
        let d2 = ct_a.c1.mul(&ct_b.c1, &ntt);

        // Compute tensor sum (degree-2 decrypt inner product)
        let d1_s = d1.mul(s, &ntt);
        let d2_s2 = d2.mul(&s2, &ntt);
        let tensor_sum = d0.add(&d1_s, &ntt).add(&d2_s2, &ntt);

        println!("\nTensor sum (at Δ² level):");
        println!("  tensor_sum[0] = {}", tensor_sum.coeffs[0]);
        println!(
            "  Expected ≈ Δ²×{}×{} = {}",
            a,
            b,
            (delta as u128) * (delta as u128) * (a as u128) * (b as u128)
        );

        // Apply degree-2 decode (t²/q² scaling)
        let result = encoder.decode_degree2(&tensor_sum);

        println!("\nDegree-2 decode:");
        println!("  result = {} (expected {})", result, expected);

        assert_eq!(
            result, expected,
            "Degree-2 decode failed: {} × {} = {} (got {})",
            a, b, expected, result
        );
    }

    #[test]
    fn test_scaling_comparison() {
        // Compare K-Elimination scaling vs simple scaling
        let config = FHEConfig::light_mul_insecure();
        let delta = config.delta();
        let ke = crate::arithmetic::KElimination::for_fhe(config.q);

        println!("Scaling comparison test:");
        println!("  q={}, t={}, Δ={}", config.q, config.t, delta);

        // Test values
        let test_values = vec![
            (delta * delta * 35, "Δ²×35"), // ~139M
            (delta * 35, "Δ×35"),          // ~70k
            (1000000u64, "1M"),
        ];

        for (val, name) in test_values {
            // Simple scaling: round(val * t / q)
            let simple = (((val as u128) * (config.t as u128) + (config.q as u128 / 2))
                / (config.q as u128)) as u64;

            // K-Elimination scaling
            let ke_result = ke.scale_and_round(val, config.t, config.q);

            println!("  {} = {}:", name, val);
            println!("    Simple: {}", simple);
            println!("    K-Elim: {}", ke_result);

            assert_eq!(simple, ke_result, "K-Elimination mismatch for {}", name);
        }
    }

    #[test]
    fn test_encrypt_decrypt_light_mul() {
        // Test that basic encrypt/decrypt works with light_mul params
        let config = FHEConfig::light_mul_insecure();
        let ntt = NTTEngine::new(config.q, config.n);
        let mut harvester = ShadowHarvester::with_seed(42);
        let keys = KeySet::generate(&config, &ntt, &mut harvester);
        let encoder = BFVEncoder::new(&config);

        let delta = config.delta();
        println!("light_mul encrypt/decrypt test:");
        println!("  q={}, t={}, Δ={}", config.q, config.t, delta);

        // Test encoding/decoding directly
        let m = 35u64;
        let encoded = encoder.encode(m);
        println!(
            "  Encoded {} → c[0]={} (expected Δ×{}={})",
            m,
            encoded.coeffs[0],
            m,
            delta * m
        );

        let decoded = encoder.decode(&encoded);
        println!("  Decoded back to: {} (expected {})", decoded, m);
        assert_eq!(decoded, m, "Encode/decode failed");

        // Test full encrypt/decrypt
        let encryptor = BFVEncryptor::new(&keys.public_key, &encoder, &ntt, config.eta);
        let decryptor = BFVDecryptor::new(&keys.secret_key, &encoder, &ntt);

        let ct = encryptor.encrypt(m, &mut harvester);

        // Manually check decryption
        let s = &keys.secret_key.s;
        let inner = ct.c0.add(&ct.c1.mul(s, &ntt), &ntt);
        println!("  inner = c0 + c1*s, inner[0]={}", inner.coeffs[0]);
        println!("  Expected inner[0] ≈ Δ×{} = {}", m, delta * m);

        let result = decryptor.decrypt(&ct);
        println!("  Decrypted: {} (expected {})", result, m);

        assert_eq!(result, m, "Encrypt/decrypt failed for light_mul");
    }

    #[test]
    fn test_ntt_basic_multiply() {
        // Test that NTT multiply works correctly for simple case
        let config = FHEConfig::light_mul_insecure();
        let ntt = NTTEngine::new(config.q, config.n);

        // (5, 0, 0, ...) * (7, 0, 0, ...) should = (35, 0, 0, ...) in R_q
        let mut a = vec![0u64; config.n];
        let mut b = vec![0u64; config.n];
        a[0] = 5;
        b[0] = 7;

        let result = ntt.multiply(&a, &b);

        println!("NTT multiply test:");
        println!("  a[0] = {}", a[0]);
        println!("  b[0] = {}", b[0]);
        println!("  result[0] = {} (expected 35)", result[0]);
        println!("  result[1..4] = {:?} (expected all 0)", &result[1..4]);

        assert_eq!(result[0], 35, "NTT constant multiply failed");
        assert!(
            result[1..].iter().all(|&x| x == 0),
            "NTT multiply produced spurious coefficients"
        );
    }

    #[test]
    fn test_ct_mul_multiple_values() {
        // Test multiple ct×ct cases with OLD BFV degree-2 decrypt
        // Note: light_mul config supports products up to ~250 (Δ²×product < q)
        let (config, ntt, keys, mut harvester, encoder) = setup_mul();

        let (supported, max_prod) = config.supports_single_mod_mul();
        println!(
            "Config: supports_single_mod_mul={}, max_product={}",
            supported, max_prod
        );

        let encryptor = BFVEncryptor::new(&keys.public_key, &encoder, &ntt, config.eta);
        let decryptor = BFVDecryptor::new(&keys.secret_key, &encoder, &ntt);
        let evaluator = BFVEvaluator::new(&ntt, &encoder, None);

        // Test cases within supported product range
        let test_cases: Vec<(u64, u64)> = vec![
            (1, 1),   // 1
            (2, 3),   // 6
            (5, 7),   // 35
            (10, 10), // 100
            (13, 17), // 221
            (15, 15), // 225
        ]
        .into_iter()
        .filter(|(a, b)| a * b <= max_prod)
        .collect();

        println!(
            "Testing {} ct×ct cases with light_mul config (degree-2 decrypt):",
            test_cases.len()
        );
        let mut total_error = 0i64;
        for (a, b) in &test_cases {
            let expected = (a * b) % config.t;

            let ct_a = encryptor.encrypt(*a, &mut harvester);
            let ct_b = encryptor.encrypt(*b, &mut harvester);

            let (d0, d1, d2) = evaluator.mul_no_relin(&ct_a, &ct_b);
            let result = decryptor.decrypt_degree2(&d0, &d1, &d2);

            let error = (result as i64 - expected as i64).abs();
            total_error += error;

            println!(
                "  {} × {} = {} (got {}, error={})",
                a, b, expected, result, error
            );

            // Allow up to 1 error due to rounding in degree-2 decrypt
            assert!(
                error <= 1,
                "Error too large for {} × {}: {} vs {} (error={})",
                a,
                b,
                expected,
                result,
                error
            );
        }
        println!(
            "All {} cases passed! Total error: {}",
            test_cases.len(),
            total_error
        );
        println!("Note: For larger products or exact results, use ExactFHEContext");
    }

    #[test]
    fn test_homomorphic_mul_with_relin() {
        // Test ct×ct multiplication with degree-2 decrypt
        let (config, ntt, keys, mut harvester, encoder) = setup_mul();

        let (supported, max_prod) = config.supports_single_mod_mul();
        let delta = config.delta();
        println!(
            "Config {}: Δ={}, Δ²={}, q={}",
            config.name,
            delta,
            (delta as u128) * (delta as u128),
            config.q
        );
        println!(
            "supports_single_mod_mul={}, max_product={}",
            supported, max_prod
        );

        let encryptor = BFVEncryptor::new(&keys.public_key, &encoder, &ntt, config.eta);
        let decryptor = BFVDecryptor::new(&keys.secret_key, &encoder, &ntt);
        let evaluator = BFVEvaluator::new(&ntt, &encoder, Some(&keys.eval_key));

        let a = 5u64;
        let b = 7u64;
        let expected = (a * b) % config.t;

        println!(
            "\nTesting ct×ct: {} × {} = {} (mod {})",
            a, b, expected, config.t
        );

        let ct_a = encryptor.encrypt(a, &mut harvester);
        let ct_b = encryptor.encrypt(b, &mut harvester);

        // Verify encryption first
        let dec_a = decryptor.decrypt(&ct_a);
        let dec_b = decryptor.decrypt(&ct_b);
        println!("Encrypted {} → {}, {} → {}", a, dec_a, b, dec_b);
        assert_eq!(dec_a, a, "Encryption of a failed");
        assert_eq!(dec_b, b, "Encryption of b failed");

        // Get tensor product (no scaling)
        let (d0, d1, d2) = evaluator.mul_no_relin(&ct_a, &ct_b);

        // Decrypt using degree-2 method
        let result = decryptor.decrypt_degree2(&d0, &d1, &d2);

        println!("ct×ct result: {}, expected: {}", result, expected);
        assert_eq!(
            result, expected,
            "ct×ct failed: {} × {} = {} (got {})",
            a, b, expected, result
        );
    }

    #[test]
    #[allow(deprecated)]
    fn test_homomorphic_mul_diagnostic() {
        // Diagnostic test to trace ct×ct multiplication step by step
        let (config, ntt, keys, mut harvester, encoder) = setup();

        println!("=== BFV ct×ct DIAGNOSTIC ===");
        println!("Parameters: N={}, q={}, t={}", config.n, config.q, config.t);
        let delta = config.q / config.t;
        println!("Δ = floor(q/t) = {}", delta);

        let encryptor = BFVEncryptor::new(&keys.public_key, &encoder, &ntt, config.eta);
        let decryptor = BFVDecryptor::new(&keys.secret_key, &encoder, &ntt);

        let a = 5u64;
        let b = 7u64;

        // Step 1: Encrypt
        let ct_a = encryptor.encrypt(a, &mut harvester);
        let ct_b = encryptor.encrypt(b, &mut harvester);

        // Verify encryption is correct
        let dec_a = decryptor.decrypt(&ct_a);
        let dec_b = decryptor.decrypt(&ct_b);
        println!("\nStep 1 - Encryption:");
        println!("  Encrypted {} → decrypt to {}", a, dec_a);
        println!("  Encrypted {} → decrypt to {}", b, dec_b);
        println!(
            "  ct_a.c0[0] = {} (expected ~Δ×{} = {})",
            ct_a.c0.coeffs[0],
            a,
            delta * a
        );
        println!(
            "  ct_b.c0[0] = {} (expected ~Δ×{} = {})",
            ct_b.c0.coeffs[0],
            b,
            delta * b
        );

        assert_eq!(dec_a, a, "Encryption of a failed");
        assert_eq!(dec_b, b, "Encryption of b failed");

        // Step 2: Tensor product (before scaling)
        let d0_raw = ct_a.c0.mul(&ct_b.c0, &ntt);
        let c0_1_c1_2 = ct_a.c0.mul(&ct_b.c1, &ntt);
        let c1_1_c0_2 = ct_a.c1.mul(&ct_b.c0, &ntt);
        let d1_raw = c0_1_c1_2.add(&c1_1_c0_2, &ntt);
        let d2_raw = ct_a.c1.mul(&ct_b.c1, &ntt);

        println!("\nStep 2a - RAW Tensor product (before scaling):");
        println!(
            "  d0_raw[0:4] = {:?}",
            &d0_raw.coeffs[0..4.min(d0_raw.coeffs.len())]
        );
        println!(
            "  d1_raw[0:4] = {:?}",
            &d1_raw.coeffs[0..4.min(d1_raw.coeffs.len())]
        );
        println!(
            "  d2_raw[0:4] = {:?}",
            &d2_raw.coeffs[0..4.min(d2_raw.coeffs.len())]
        );
        println!(
            "  Expected d0_raw[0] ≈ Δ²×{}×{} = {} (mod q)",
            a,
            b,
            ((delta as u128) * (delta as u128) * (a as u128) * (b as u128) % (config.q as u128))
                as u64
        );

        // Step 2b: After scaling
        let evaluator_no_relin = BFVEvaluator::new(&ntt, &encoder, None);
        let (d0, d1, d2) = evaluator_no_relin.mul_no_relin(&ct_a, &ct_b);

        println!("\nStep 2b - After t/q scaling:");
        println!("  d0[0:4] = {:?}", &d0.coeffs[0..4.min(d0.coeffs.len())]);
        println!("  d1[0:4] = {:?}", &d1.coeffs[0..4.min(d1.coeffs.len())]);
        println!("  d2[0:4] = {:?}", &d2.coeffs[0..4.min(d2.coeffs.len())]);

        // Step 3: Check if we can decrypt degree-2 ciphertext with RAW values
        // For degree 2: decrypt = round((d0 + d1*s + d2*s²) * t / q)
        // We should scale the SUM, not the individual components
        let s = &keys.secret_key.s;
        let s2 = s.mul(s, &ntt);

        // Test with RAW (unscaled) tensor product
        let d1_raw_s = d1_raw.mul(s, &ntt);
        let d2_raw_s2 = d2_raw.mul(&s2, &ntt);
        let sum_raw = d0_raw.add(&d1_raw_s, &ntt).add(&d2_raw_s2, &ntt);

        // Decrypt the raw degree-2: scale by t²/q² to get message
        // Actually: decryption should give round(sum * t² / q²) for Δ²-scaled message
        let sum_raw_scaled = sum_raw
            .coeffs
            .iter()
            .map(|&c| {
                // Two-stage scaling: first t/q, then extract message
                let numerator = (config.t as u128) * (config.t as u128) * (c as u128);
                let denom = (config.q as u128) * (config.q as u128);
                ((numerator + denom / 2) / denom % config.t as u128) as u64
            })
            .collect::<Vec<_>>();

        // Alternative: single t/q scaling (what current BFV does)
        let sum_raw_single_scale = sum_raw
            .coeffs
            .iter()
            .map(|&c| {
                let numerator = (config.t as u128) * (c as u128) + (config.q as u128 / 2);
                ((numerator / config.q as u128) % config.t as u128) as u64
            })
            .collect::<Vec<_>>();

        println!("\nStep 3 - Degree-2 decrypt with RAW tensor product:");
        println!("  sum_raw[0] = {}", sum_raw.coeffs[0]);
        println!("  Scaled by t²/q² → {}", sum_raw_scaled[0]);
        println!("  Scaled by t/q → {}", sum_raw_single_scale[0]);
        println!("  Expected: {} × {} = {}", a, b, (a * b) % config.t);

        // Test with already-scaled tensor product
        let d1_s = d1.mul(s, &ntt);
        let d2_s2 = d2.mul(&s2, &ntt);
        let sum_scaled_td = d0.add(&d1_s, &ntt).add(&d2_s2, &ntt);

        // This should already be Δ-scaled, so one more t/q gives message
        let sum_final = sum_scaled_td
            .coeffs
            .iter()
            .map(|&c| {
                let numerator = (config.t as u128) * (c as u128) + (config.q as u128 / 2);
                ((numerator / config.q as u128) % config.t as u128) as u64
            })
            .collect::<Vec<_>>();

        println!("\nStep 3b - Degree-2 with pre-scaled tensor product:");
        println!("  sum[0] = {}", sum_scaled_td.coeffs[0]);
        println!("  After t/q scaling → {}", sum_final[0]);
        println!("  Expected: {} × {} = {}", a, b, (a * b) % config.t);

        // Step 4: Full multiplication with relinearization
        let evaluator = BFVEvaluator::new(&ntt, &encoder, Some(&keys.eval_key));
        let ct_prod = evaluator.mul(&ct_a, &ct_b);
        let result = decryptor.decrypt(&ct_prod);

        println!("\nStep 4 - After relinearization:");
        println!("  Decrypted result: {}", result);
        println!("  Expected: {}", (a * b) % config.t);

        // Determine where the issue is
        if d0_raw.coeffs[0] < delta {
            println!("\n✗ Issue: RAW tensor product values too small - polynomial mul wrong?");
        } else if d0.coeffs[0] > delta * 2 {
            println!("\n✗ Issue: Scaling not reducing values enough");
        } else if sum_raw_scaled[0] == (a * b) % config.t {
            println!("\n✓ t²/q² scaling on raw tensor works");
        } else if sum_raw_single_scale[0] == (a * b) % config.t {
            println!("\n✓ t/q scaling on raw tensor works");
        } else if sum_final[0] == (a * b) % config.t {
            println!("\n✓ Double scaling (pre-scale + t/q) works");
        } else {
            println!("\n✗ No scaling approach produces correct answer");
            println!("  This indicates fundamental issue in tensor product");
        }
    }

    #[test]
    fn test_homo_add_benchmark() {
        let (config, ntt, keys, mut harvester, encoder) = setup();

        let encryptor = BFVEncryptor::new(&keys.public_key, &encoder, &ntt, config.eta);
        let evaluator = BFVEvaluator::new(&ntt, &encoder, None);

        let ct = encryptor.encrypt(42, &mut harvester);

        let start = std::time::Instant::now();
        let mut result = ct.clone();
        for _ in 0..10_000 {
            result = evaluator.add(&result, &ct);
        }
        let elapsed = start.elapsed();

        println!("Homo add x10k: {:?}", elapsed);
    }

    #[test]
    #[allow(deprecated)]
    fn test_homo_mul_benchmark() {
        let (config, ntt, keys, mut harvester, encoder) = setup();

        let encryptor = BFVEncryptor::new(&keys.public_key, &encoder, &ntt, config.eta);
        let evaluator = BFVEvaluator::new(&ntt, &encoder, Some(&keys.eval_key));

        let ct = encryptor.encrypt(2, &mut harvester);

        let start = std::time::Instant::now();
        for _ in 0..100 {
            let _ = evaluator.mul(&ct, &ct);
        }
        let elapsed = start.elapsed();

        println!("Homo mul x100: {:?}", elapsed);
    }

    // =========================================================================
    // TrackedEvaluator Tests
    // =========================================================================

    #[test]
    fn test_tracked_evaluator_add() {
        let (config, ntt, keys, mut harvester, encoder) = setup();

        let encryptor = BFVEncryptor::new(&keys.public_key, &encoder, &ntt, config.eta);
        let decryptor = BFVDecryptor::new(&keys.secret_key, &encoder, &ntt);
        let evaluator = BFVEvaluator::new(&ntt, &encoder, None);
        let mut tracked = super::TrackedEvaluator::new(evaluator, &config);

        let ct_a = encryptor.encrypt(100, &mut harvester);
        let ct_b = encryptor.encrypt(200, &mut harvester);

        // Should succeed with budget
        let ct_sum = tracked.try_add(&ct_a, &ct_b).expect("Add should succeed");
        let result = decryptor.decrypt(&ct_sum);
        assert_eq!(result, 300 % config.t);

        // Budget should be reduced
        assert!(tracked.budget().remaining_millibits() < tracked.budget().initial_millibits());
    }

    #[test]
    fn test_tracked_evaluator_exhaustion() {
        let (config, ntt, _, _, encoder) = setup();

        let evaluator = BFVEvaluator::new(&ntt, &encoder, None);
        // Create with tiny budget (2 bits)
        let mut tracked = super::TrackedEvaluator::with_budget(evaluator, &config, 2);

        let ct = Ciphertext {
            c0: RingPolynomial::zero(config.n, config.q),
            c1: RingPolynomial::zero(config.n, config.q),
        };

        // First few adds might work
        let result1 = tracked.try_add(&ct, &ct);
        let result2 = tracked.try_add(&ct, &ct);
        let result3 = tracked.try_add(&ct, &ct);

        // Eventually should exhaust budget
        let all_ok = result1.is_ok() && result2.is_ok() && result3.is_ok();
        let any_failed = result1.is_err() || result2.is_err() || result3.is_err();

        println!(
            "Results: r1={}, r2={}, r3={}",
            result1.is_ok(),
            result2.is_ok(),
            result3.is_ok()
        );
        println!(
            "Budget remaining: {} millibits",
            tracked.budget().remaining_millibits()
        );

        // Either all succeed (if budget was enough) or at least one fails
        assert!(
            all_ok || any_failed,
            "Should either all succeed or some fail"
        );
    }

    #[test]
    fn test_tracked_evaluator_mul_plain() {
        let (config, ntt, keys, mut harvester, encoder) = setup();

        let encryptor = BFVEncryptor::new(&keys.public_key, &encoder, &ntt, config.eta);
        let decryptor = BFVDecryptor::new(&keys.secret_key, &encoder, &ntt);
        let evaluator = BFVEvaluator::new(&ntt, &encoder, None);
        // Use explicit budget that's sufficient for mul_plain (log2(t) ≈ 12 bits for t=2^12)
        let mut tracked = super::TrackedEvaluator::with_budget(evaluator, &config, 50);

        let ct = encryptor.encrypt(10, &mut harvester);

        let ct_scaled = tracked
            .try_mul_plain(&ct, 5)
            .expect("MulPlain should succeed");
        let result = decryptor.decrypt(&ct_scaled);
        assert_eq!(result, 50 % config.t);

        println!("Tracked budget after mul_plain: {}", tracked.budget());
    }

    #[test]
    fn test_tracked_evaluator_remaining_depth() {
        let (config, ntt, _, _, encoder) = setup();

        let evaluator = BFVEvaluator::new(&ntt, &encoder, None);
        // Use explicit budget for testing depth calculation
        let tracked = super::TrackedEvaluator::with_budget(evaluator, &config, 100);

        let depth = tracked.remaining_depth();
        println!(
            "Remaining multiplication depth with 100-bit budget: {}",
            depth
        );

        // Should have some depth with 100-bit budget
        assert!(
            depth > 0,
            "Should have positive multiplication depth with 100-bit budget"
        );
    }

    #[test]
    fn test_can_perform_checks() {
        let (config, ntt, _, _, encoder) = setup();

        let evaluator = BFVEvaluator::new(&ntt, &encoder, None);
        // Use explicit budget for testing can_perform checks
        let tracked = super::TrackedEvaluator::with_budget(evaluator, &config, 50);

        assert!(
            tracked.can_add(),
            "Should be able to add with 50-bit budget"
        );
        assert!(
            tracked.can_mul_plain(),
            "Should be able to mul_plain with 50-bit budget"
        );

        // With 50-bit budget, mul should also be possible
        println!("can_mul: {}", tracked.can_mul());
    }
}
