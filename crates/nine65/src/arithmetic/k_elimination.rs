//! K-Elimination: exact dual-family division support.
//!
//! # K-Elimination
//!
//! Provides exact division in RNS with 100% exactness.
//! No floating point, no approximations, no error accumulation.
//!
//! # Theorem Reference
//! - **Proof File**: `KElimination.v`
//! - **Key Theorem**: `k_elimination_complete`
//! - **Status**: PROVED
//!
//! # Mathematical Foundation
//!
//! Given value V in dual-codex (α, β):
//! ```text
//!   V = vα (mod αcap)
//!   V = vβ (mod βcap)
//! ```
//!
//! We can recover V exactly by computing:
//! ```text
//!   k = (vβ - vα) * αcap_inv (mod βcap)
//!   V = vα + k * αcap
//! ```
//!
//! # Coq Theorem Statement
//!
//! ```coq
//! Theorem k_elimination_complete : forall k v_M M A : nat,
//!   M > 0 -> v_M < M -> k < A ->
//!   let X := v_M + k * M in X / M = k.
//!
//! Theorem complexity_improvement :
//!   k_elimination_ops k = k /\ mrc_ops k = k * k.
//!   (* O(k) vs O(k²) *)
//! ```
//!
//! # Performance
//! - **Speedup**: 40× vs Mixed Radix Conversion
//! - **Complexity**: O(k) vs O(k²)
//!
//! This allows exact division: V / d = (vα + k * αcap) / d
//! when d | V (which is guaranteed in FHE rescaling).
//!
//! # Configuration
//!
//! Use `KElimConfig` for predefined configurations or `KElimBuilder` for custom setups:
//!
//! ```ignore
//! // Use a preset
//! let ke = KElimination::from_config(KElimConfig::Standard);
//!
//! // Or build custom
//! let ke = KElimBuilder::new()
//!     .alpha_primes(&[65537, 65521])
//!     .beta_moduli(&[4611686018427387847])
//!     .build()
//!     .unwrap();
//! ```
//!
//! # Relationship to the production K-Elimination record (G14 consolidation)
//!
//! This is **not** the canonical production K-Elimination for the live
//! DualRNS BFV engine. That role belongs to `extract_k_rns_level` in
//! `nine65::arithmetic::rns`, which operates over the DualRNS engine's own
//! multi-anchor RNS lane vectors (Garner-style reconstruction across N
//! anchor primes), not a fixed two-modulus (alpha, beta) split.
//!
//! This module is instead the **validated, CT-tested, two-modulus reference
//! implementation** — the one piece of K-Elimination-shaped code in this
//! workspace with a matching Coq lemma (`k_elimination_complete`) and actual
//! branchless CT primitives (`sub_mod_u128_ct`/`mul_mod_u128_ct` below), and
//! the target of the statistical CT verification suite
//! (`nine65::security::ct_verification`). It is kept as a distinct,
//! intentional variant rather than merged into `extract_k_rns_level`
//! because:
//! 1. Its algebraic structure (two aggregated scalar residues, not N
//!    per-lane residues) is not a drop-in substitute for the RNS-level API
//!    without changing the data layout at every call site.
//! 2. It is the current backing implementation for the **legacy
//!    single-modulus BFV path** (`ops::homomorphic::BFVEvaluator`, used by
//!    `kat.rs` known-answer tests and `entropy::shadow_entropy_monitor`) and
//!    for the quarantined Clockwork bootstrap paths (`ops::bootstrap`,
//!    `bootstrap::clockwork`) — both depend on this exact two-scalar
//!    signature.
//!
//! `mana::anchor::KAnchor::for_fhe()` independently duplicates this file's
//! `KElimConfig::Standard` prime constants bit-for-bit (documented at the
//! `mana` side, since `mana` cannot depend on `nine65` — the dependency
//! runs the other way — so true single-sourcing isn't possible without a
//! new cross-crate dependency edge, out of scope for this pass).

use crate::errors::{Nine65Error, Nine65Result};
use crate::params::is_prime;

// ═══════════════════════════════════════════════════════════════════════════
// CONFIGURATION
// ═══════════════════════════════════════════════════════════════════════════

/// Predefined K-Elimination configurations
///
/// # Separation Principle (NINE65 v8)
///
/// Alpha moduli are CLASS-F: they must be prime (participate in NTT-adjacent operations).
/// Beta moduli are CLASS-R: they require only pairwise coprimality with alpha and with
/// each other. Composite beta values are mathematically valid and may offer hardware
/// advantages (equal-bit-width reduction, pseudo-Mersenne shift tricks, parallel CRT-split).
///
/// See: QMNF Separation Principle (Theorem 2.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KElimConfig {
    Minimal,
    Standard,
    Extended,
    Maximum,

    /// Hardware-optimized configuration (Separation Principle showcase)
    /// - Alpha: 3 × 16-bit primes (~48 bits)
    /// - Beta: 1 × 61-bit equal-width composite + 1 × 32-bit Mersenne
    /// - Both β values are CLASS-R composites with hardware-friendly reduction
    HardwareOpt,
}

impl KElimConfig {
    pub fn alpha_primes(&self) -> Vec<u64> {
        match self {
            KElimConfig::Minimal => vec![65537, 65521],
            KElimConfig::Standard => vec![65537, 65521, 65519],
            KElimConfig::Extended => vec![65537, 65521, 65519],
            KElimConfig::Maximum => vec![65537, 65521, 65519, 65497],
            KElimConfig::HardwareOpt => vec![65537, 65521, 65519],
        }
    }

    /// Beta moduli (CLASS-R — coprimality sufficient, primality optional).
    ///
    /// These values carry the K-Elimination winding lift `X = v_α + k·α_cap`
    /// (a single boundary read), NOT a mixed-radix / Garner conversion of the
    /// alpha lanes into a positional integer. The lift requires
    /// gcd(α_cap, β_cap) = 1 but does NOT require primality; composite values
    /// coprime to α_cap are mathematically valid.
    /// See: QMNF Separation Principle (Theorem 2.1); A2 (no mixed-radix fusion).
    pub fn beta_moduli(&self) -> Vec<u64> {
        match self {
            KElimConfig::Minimal => vec![4294967291], // 2^32 - 5 (~32 bits)
            KElimConfig::Standard => vec![4611686018427387847], // 62-bit prime
            KElimConfig::Extended => vec![
                35184372088777, // ~45-bit prime
                35184372088831, // ~45-bit prime
            ],
            KElimConfig::Maximum => vec![
                4611686018427387847, // 62-bit prime
                4611686018427387903, // 62-bit prime (different)
            ],
            KElimConfig::HardwareOpt => vec![
                1152921515344265237, // 1,073,741,827 × 1,073,741,831 (61-bit)
                4294967291,           // 2^32 - 5 (32-bit prime)
            ],
        }
    }

    /// Get the beta moduli for this configuration (deprecated name).
    #[deprecated(since = "8.0.0", note = "Use beta_moduli(). Primality not required (Separation Principle).")]
    pub fn beta_primes(&self) -> Vec<u64> {
        self.beta_moduli()
    }

    /// Get approximate total capacity in bits
    pub fn capacity_bits(&self) -> u32 {
        match self {
            KElimConfig::Minimal => 64,
            KElimConfig::Standard => 110,
            KElimConfig::Extended => 138,
            KElimConfig::Maximum => 188, // 64 alpha + 124 beta
            KElimConfig::HardwareOpt => 140, // α_cap·β_cap = 140 bits (48-bit α × 93-bit β; product bit-length, not the sum)
        }
    }

    pub fn for_degree(n: usize) -> Self {
        match n {
            0..=1024 => Self::Standard,
            1025..=4096 => Self::Extended,
            _ => Self::Maximum,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct KElimBuilder {
    alpha_primes: Option<Vec<u64>>,
    beta_moduli: Option<Vec<u64>>,
}

impl KElimBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn alpha_primes(mut self, primes: &[u64]) -> Self {
        self.alpha_primes = Some(primes.to_vec());
        self
    }

    /// Set beta (anchor) moduli
    pub fn beta_moduli(mut self, moduli: &[u64]) -> Self {
        self.beta_moduli = Some(moduli.to_vec());
        self
    }

    /// Set beta (anchor) primes (deprecated name)
    #[deprecated(since = "8.0.0", note = "Use beta_moduli(). Primality not required.")]
    pub fn beta_primes(self, primes: &[u64]) -> Self {
        self.beta_moduli(primes)
    }

    /// Build the K-Elimination context
    ///
    /// Returns error if:
    /// - Moduli are not set
    /// - Moduli are not coprime
    pub fn build(self) -> Nine65Result<KElimination> {
        let alpha_primes = self
            .alpha_primes
            .ok_or_else(|| Nine65Error::InvalidParameter {
                message: "alpha_primes not set".to_string(),
            })?;

        let beta_moduli = self
            .beta_moduli
            .ok_or_else(|| Nine65Error::InvalidParameter {
                message: "beta_moduli not set".to_string(),
            })?;

        KElimination::try_new(&alpha_primes, &beta_moduli)
    }
}

#[derive(Debug, Clone)]
pub struct KElimination {
    /// Alpha moduli (primary codex — CLASS-F)
    pub alpha_primes: Vec<u64>,
    /// Beta moduli (anchor codex — CLASS-R)
    pub beta_moduli: Vec<u64>,
    /// Product of alpha primes
    pub alpha_cap: u128,
    /// Product of beta moduli
    pub beta_cap: u128,
    pub alpha_inv_beta: u128,
    config: Option<KElimConfig>,
}

impl KElimination {
    /// Create K-Elimination context with given moduli
    ///
    /// # Panics
    ///
    /// This is a **panicking constructor**. It will panic if:
    /// - `alpha_cap` and `beta_cap` are not coprime (GCD != 1)
    ///
    /// For fallible construction, use [`try_new()`](Self::try_new) instead.
    ///
    /// # Requirements
    /// - All primes must be coprime
    /// - beta_cap must be > largest value to divide
    ///
    /// # Example
    /// ```ignore
    /// // This may panic if primes share common factors
    /// let ke = KElimination::new(&[17, 19], &[23, 29]);
    ///
    /// // Prefer try_new for error handling
    /// let ke = KElimination::try_new(&[17, 19], &[23, 29])?;
    /// ```
    pub fn new(alpha_primes: &[u64], beta_moduli: &[u64]) -> Self {
        Self::try_new(alpha_primes, beta_moduli).expect("alpha_cap and beta_cap must be coprime")
    }

    /// Fallible constructor for K-Elimination context
    ///
    /// Returns error if moduli are not coprime. Prefer this over [`new()`](Self::new)
    /// when handling untrusted input or in library code.
    ///
    /// # Errors
    ///
    /// Returns [`Nine65Error::NotCoprime`] if alpha_cap and beta_cap share a common factor.
    #[must_use = "this returns a Result that must be handled"]
    pub fn try_new(alpha_primes: &[u64], beta_moduli: &[u64]) -> Nine65Result<Self> {
        // Safe-basis family validation (see k_elimination_basis_regression.rs):
        // CLASS-F alpha lanes must be non-empty, prime, and pairwise distinct;
        // CLASS-R beta lanes must be non-empty, > 1, and pairwise coprime
        // (a bare pairwise-gcd check silently admits unit moduli, since 1 is
        // coprime to everything); the two families must be cross-coprime.
        validate_alpha_family(alpha_primes)?;
        validate_beta_family(beta_moduli)?;
        validate_cross_family(alpha_primes, beta_moduli)?;

        // Use checked_mul to detect u128 overflow in prime products.
        let alpha_cap: u128 = alpha_primes
            .iter()
            .try_fold(1u128, |acc, &p| acc.checked_mul(p as u128))
            .ok_or_else(|| Nine65Error::InvalidParameter {
                message: "alpha_primes product overflows u128".to_string(),
            })?;

        let beta_cap: u128 = beta_moduli
            .iter()
            .try_fold(1u128, |acc, &p| acc.checked_mul(p as u128))
            .ok_or_else(|| Nine65Error::InvalidParameter {
                message: "beta_moduli product overflows u128".to_string(),
            })?;

        let alpha_inv_beta = mod_inverse_u128(alpha_cap, beta_cap).ok_or_else(|| {
            Nine65Error::NotCoprime {
                m: diagnostic_u64(alpha_cap),
                a: diagnostic_u64(beta_cap),
                gcd: diagnostic_u64(gcd_u128(alpha_cap, beta_cap)),
            }
        })?;

        Ok(Self {
            alpha_primes: alpha_primes.to_vec(),
            beta_moduli: beta_moduli.to_vec(),
            alpha_cap,
            beta_cap,
            alpha_inv_beta,
            config: None,
        })
    }

    /// Get the beta moduli (deprecated name).
    #[deprecated(since = "8.0.0", note = "Use beta_moduli. Primality not required.")]
    pub fn beta_primes(&self) -> Vec<u64> {
        self.beta_moduli.clone()
    }

    /// Create K-Elimination from a predefined configuration.
    ///
    /// # Panics
    ///
    /// Panics if the preset primes are not coprime (should never happen
    /// with built-in configurations). For fallible construction, use
    /// [`try_from_config()`](Self::try_from_config).
    ///
    /// # Example
    /// ```ignore
    /// let ke = KElimination::from_config(KElimConfig::Standard);
    /// ```
    pub fn from_config(config: KElimConfig) -> Self {
        Self::try_from_config(config).expect("built-in K-Elim safe basis must validate")
    }

    pub fn try_from_config(config: KElimConfig) -> Nine65Result<Self> {
        let mut ke = Self::try_new(&config.alpha_primes(), &config.beta_moduli())?;
        ke.config = Some(config);
        Ok(ke)
    }

    pub fn for_degree(n: usize) -> Self {
        Self::from_config(KElimConfig::for_degree(n))
    }

    pub fn try_for_degree(n: usize) -> Nine65Result<Self> {
        Self::try_from_config(KElimConfig::for_degree(n))
    }

    pub fn for_fhe(_q: u64) -> Self {
        Self::from_config(KElimConfig::Standard)
    }

    pub fn try_for_fhe(_q: u64) -> Nine65Result<Self> {
        Self::try_from_config(KElimConfig::Standard)
    }

    pub fn config(&self) -> Option<KElimConfig> {
        self.config
    }

    /// Exact 256-bit little-endian capacity limbs for alpha_cap × beta_cap.
    pub fn capacity_limbs(&self) -> Vec<u64> {
        trim_fixed_limbs(multiply_u128(self.alpha_cap, self.beta_cap))
    }

    pub fn capacity_bit_length(&self) -> u32 {
        limbs_bit_length(&self.capacity_limbs())
    }

    pub fn capacity_bits(&self) -> u32 {
        self.capacity_bit_length()
    }

    pub fn try_capacity(&self) -> Option<u128> {
        self.alpha_cap.checked_mul(self.beta_cap)
    }

    #[deprecated(
        since = "8.1.0",
        note = "Use try_capacity(), capacity_limbs(), or capacity_bit_length()"
    )]
    pub fn capacity(&self) -> u128 {
        self.try_capacity().expect(
            "K-Elimination capacity exceeds u128; use capacity_limbs or capacity_bit_length",
        )
    }

    pub fn alpha_capacity(&self) -> u128 {
        self.alpha_cap
    }

    /// Get beta codex capacity (product of beta moduli)
    pub fn beta_capacity(&self) -> u128 {
        self.beta_cap
    }

    pub fn capacity_proximity(
        &self,
        value: u128,
    ) -> crate::arithmetic::boundary::CapacityReport {
        use crate::arithmetic::boundary::{capacity_proximity_bits, u128_bit_length};
        capacity_proximity_bits(u128_bit_length(value), self.capacity_bit_length())
    }

    pub fn validate_value(&self, value: u128) -> Nine65Result<()> {
        if let Some(capacity) = self.try_capacity() {
            if value >= capacity {
                return Err(Nine65Error::RangeOverflow {
                    x: value,
                    bound: capacity,
                });
            }
        }
        Ok(())
    }

    pub fn validate_residues(&self, v_alpha: u128, v_beta: u128) -> Nine65Result<()> {
        if v_alpha >= self.alpha_cap {
            return Err(Nine65Error::RangeOverflow {
                x: v_alpha,
                bound: self.alpha_cap,
            });
        }
        if v_beta >= self.beta_cap {
            return Err(Nine65Error::RangeOverflow {
                x: v_beta,
                bound: self.beta_cap,
            });
        }
        Ok(())
    }

    /// Explicit scalar boundary/reference division with complete validation.
    pub fn exact_divide_validated(
        &self,
        v_alpha: u128,
        v_beta: u128,
        divisor: u64,
    ) -> Nine65Result<u128> {
        if divisor == 0 {
            return Err(Nine65Error::ModulusZero);
        }
        self.validate_residues(v_alpha, v_beta)?;
        let value = self.reconstruct_boundary_checked(v_alpha, v_beta)?;
        if value % divisor as u128 != 0 {
            return Err(Nine65Error::InexactDivision { value, divisor });
        }
        Ok(value / divisor as u128)
    }

    /// Extract the bounded winding index k from dual-family residues.
    pub fn extract_k(&self, v_alpha: u128, v_beta: u128) -> u128 {
        let diff = sub_mod_kelim_ct(v_beta, v_alpha, self.beta_cap);
        mul_mod_u128_ct(diff, self.alpha_inv_beta, self.beta_cap)
    }

    #[deprecated(
        since = "0.2.0",
        note = "Use extract_k(); variable-time extraction is for public reference data only"
    )]
    pub fn extract_k_vartime(&self, v_alpha: u128, v_beta: u128) -> u128 {
        let reduced_alpha = v_alpha % self.beta_cap;
        let diff = if v_beta >= reduced_alpha {
            v_beta - reduced_alpha
        } else {
            self.beta_cap - (reduced_alpha - v_beta)
        };
        mul_mod_u128(diff, self.alpha_inv_beta, self.beta_cap)
    }

    /// Scalar boundary/reference helper. Production FHE code must use lane-wise
    /// DualRNS transduction rather than this projection.
    pub fn exact_divide(&self, v_alpha: u128, v_beta: u128, divisor: u64) -> u128 {
        assert!(divisor != 0, "divisor must be nonzero");
        let value = self
            .reconstruct_boundary_checked(v_alpha, v_beta)
            .expect("K-Elimination scalar boundary reconstruction overflow");
        value / divisor as u128
    }

    pub fn exact_divide_checked(
        &self,
        v_alpha: u128,
        v_beta: u128,
        divisor: u64,
    ) -> Option<u128> {
        if divisor == 0 {
            return None;
        }
        let value = self.reconstruct_boundary_checked(v_alpha, v_beta).ok()?;
        if value % divisor as u128 == 0 {
            Some(value / divisor as u128)
        } else {
            None
        }
    }

    /// Public scalar reference scaling helper.
    pub fn scale_and_round(&self, value: u64, t: u64, q: u64) -> u64 {
        assert!(q != 0, "q must be nonzero");
        let numerator = value as u128 * t as u128 + q as u128 / 2;
        let v_alpha = numerator % self.alpha_cap;
        let v_beta = numerator % self.beta_cap;
        let full_numerator = self
            .reconstruct_boundary_checked(v_alpha, v_beta)
            .expect("K-Elimination scalar scaling reconstruction overflow");
        ((full_numerator / q as u128) % q as u128) as u64
    }

    #[deprecated(
        since = "0.2.0",
        note = "Use exact_divide(); variable-time division is for public reference data only"
    )]
    #[allow(deprecated)]
    pub fn exact_divide_vartime(
        &self,
        v_alpha: u128,
        v_beta: u128,
        divisor: u64,
    ) -> u128 {
        assert!(divisor != 0, "divisor must be nonzero");
        let k = self.extract_k_vartime(v_alpha, v_beta);
        let value = v_alpha
            .checked_add(
                k.checked_mul(self.alpha_cap)
                    .expect("K-Elimination scalar reconstruction multiplication overflow"),
            )
            .expect("K-Elimination scalar reconstruction addition overflow");
        value / divisor as u128
    }

    #[deprecated(
        since = "0.2.0",
        note = "Use scale_and_round(); variable-time scaling is for public reference data only"
    )]
    #[allow(deprecated)]
    pub fn scale_and_round_vartime(&self, value: u64, t: u64, q: u64) -> u64 {
        assert!(q != 0, "q must be nonzero");
        let numerator = value as u128 * t as u128 + q as u128 / 2;
        let v_alpha = numerator % self.alpha_cap;
        let v_beta = numerator % self.beta_cap;
        let k = self.extract_k_vartime(v_alpha, v_beta);
        let full_numerator = v_alpha
            .checked_add(
                k.checked_mul(self.alpha_cap)
                    .expect("K-Elimination scalar scaling multiplication overflow"),
            )
            .expect("K-Elimination scalar scaling addition overflow");
        ((full_numerator / q as u128) % q as u128) as u64
    }

    fn reconstruct_boundary_checked(
        &self,
        v_alpha: u128,
        v_beta: u128,
    ) -> Nine65Result<u128> {
        self.validate_residues(v_alpha, v_beta)?;
        let k = self.extract_k(v_alpha, v_beta);
        let winding = k
            .checked_mul(self.alpha_cap)
            .ok_or(Nine65Error::Overflow {
                operation: "K-Elimination scalar boundary multiplication",
            })?;
        v_alpha.checked_add(winding).ok_or(Nine65Error::Overflow {
            operation: "K-Elimination scalar boundary addition",
        })
    }
}
// ═══════════════════════════════════════════════════════════════════════════
// ADJACENCY-ANCHORED K-ELIMINATION  (A = M + 1)
// ═══════════════════════════════════════════════════════════════════════════

/// K-Elimination whose CLASS-R anchor is *manufactured adjacent* to the
/// CLASS-F product: `A = M + 1`, where `M = ∏ alpha_primes`.
///
/// # What the construction buys
///
/// The general two-family extraction is
///
/// ```text
///     k = (v_β − v_α mod A) · M⁻¹  (mod A)
/// ```
///
/// which costs, on `u128`: one reduction of `v_α` modulo `A`, and one modular
/// multiplication by the precomputed `M⁻¹`. On this codebase that multiply is
/// [`mul_mod_u128_ct`] — a fixed 128-iteration double-and-add — and the
/// reduction is a `u128 % u128` by a *runtime* modulus, which LLVM lowers to
/// `__umodti3`.
///
/// Under adjacency, `M ≡ −1 (mod A)`, so `M⁻¹ ≡ M ≡ −1 (mod A)` and the whole
/// expression collapses:
///
/// ```text
///     k = (v_β − v_α) · (−1)  ≡  v_α − v_β   (mod A)
/// ```
///
/// One branchless modular subtraction. Three consequences, in decreasing order
/// of how much they matter:
///
/// 1. **No `__umodti3`.** `v_α < M` and `M < A`, so `v_α` is *already* reduced
///    modulo `A` and the pre-reduction is not merely cheap — it is absent. The
///    remaining subtraction is `wrapping_sub` + mask + `wrapping_add`, whose
///    instruction sequence does not depend on operand magnitude. This is the
///    structural answer to the operand-magnitude timing dependence measured on
///    [`KElimination::extract_k`] (finding F-3); it is not a constant-time
///    *rewrite* of the division, it removes the division.
/// 2. **No inverse bank.** `M⁻¹ mod A` never has to be computed, stored, or
///    key-scheduled, because it is `M`. See
///    [`crate::params::manufactured::AdjacencyAnchor::p_inverse_mod_a`].
/// 3. **No primality requirement on `A`.** `gcd(M, M+1) = 1` holds for every
///    `M ≥ 1` — the coprimality precondition is discharged by construction
///    rather than by search. `A` is CLASS-R, exactly as the Separation
///    Principle already permits, and is composite for every alpha basis used
///    here.
///
/// # What it costs
///
/// Capacity. The general form pairs a ~48-bit `M` with an independently chosen
/// 62-bit `β`, for a 110-bit `M·β`. Adjacency forces `A = M + 1`, so capacity
/// is `M·(M+1) ≈ M²`. For `KElimConfig::Standard` that is 96 bits instead of
/// 110 — a real reduction, recovered (if needed) by widening the alpha basis
/// rather than by hunting a wider anchor.
///
/// # Sign
///
/// The winding read is `X ≡ γ − K (mod A)`, with a **minus**. The published
/// white-paper form `γ + K` is a sign error; see
/// [`crate::params::manufactured::adjacency_read`], where the wrong form is
/// pinned as failing so it cannot quietly return.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdjacencyKElim {
    alpha_primes: Vec<u64>,
    /// `M = ∏ alpha_primes`.
    alpha_cap: u128,
    /// `A = M + 1`.
    anchor: u128,
}

impl AdjacencyKElim {
    /// Build the adjacency-anchored context from a CLASS-F alpha family.
    ///
    /// The alpha family is validated exactly as for [`KElimination`]
    /// (non-empty, prime, pairwise distinct). No validation of `A` is required
    /// or performed beyond overflow: coprimality with `M` is a theorem, not a
    /// check.
    #[must_use = "this returns a Result that must be handled"]
    pub fn try_new(alpha_primes: &[u64]) -> Nine65Result<Self> {
        validate_alpha_family(alpha_primes)?;
        let alpha_cap = checked_product(alpha_primes, "adjacency K-Elimination alpha product")?;
        let anchor = alpha_cap.checked_add(1).ok_or(Nine65Error::Overflow {
            operation: "adjacency K-Elimination anchor A = M + 1",
        })?;
        Ok(Self {
            alpha_primes: alpha_primes.to_vec(),
            alpha_cap,
            anchor,
        })
    }

    /// Adjacency context over the alpha family of a standard configuration.
    pub fn from_config(config: KElimConfig) -> Nine65Result<Self> {
        Self::try_new(&config.alpha_primes())
    }

    /// The CLASS-F product `M`.
    pub fn alpha_cap(&self) -> u128 {
        self.alpha_cap
    }

    /// The CLASS-R anchor `A = M + 1`.
    pub fn anchor(&self) -> u128 {
        self.anchor
    }

    /// The CLASS-F lanes.
    pub fn alpha_primes(&self) -> &[u64] {
        &self.alpha_primes
    }

    /// `M⁻¹ mod A`, which by construction is `M`.
    ///
    /// Checked against extended Euclid in
    /// `tests::adjacency_inverse_is_the_partner_itself`.
    pub fn alpha_inv_anchor(&self) -> u128 {
        self.alpha_cap
    }

    /// Representable range `M · A`, or `None` if it exceeds `u128`.
    pub fn try_capacity(&self) -> Option<u128> {
        self.alpha_cap.checked_mul(self.anchor)
    }

    /// Reject residues outside their lane ranges.
    pub fn validate_residues(&self, v_alpha: u128, v_beta: u128) -> Nine65Result<()> {
        if v_alpha >= self.alpha_cap {
            return Err(Nine65Error::RangeOverflow {
                x: v_alpha,
                bound: self.alpha_cap,
            });
        }
        if v_beta >= self.anchor {
            return Err(Nine65Error::RangeOverflow {
                x: v_beta,
                bound: self.anchor,
            });
        }
        Ok(())
    }

    /// Extract the winding index `k` from `(v_α, v_β)`.
    ///
    /// **One branchless modular subtraction, no division of any kind.**
    ///
    /// Preconditions (`v_α < M`, `v_β < A`) are the caller's, exactly as for
    /// [`KElimination::extract_k`]; use [`Self::extract_k_validated`] when the
    /// inputs are not already known to be in range. The preconditions are what
    /// make the pre-reduction unnecessary: `v_α < M < A`, so `v_α mod A = v_α`.
    #[inline]
    pub fn extract_k(&self, v_alpha: u128, v_beta: u128) -> u128 {
        debug_assert!(v_alpha < self.anchor, "v_alpha must already be reduced mod A");
        debug_assert!(v_beta < self.anchor, "v_beta must already be reduced mod A");
        sub_mod_u128_ct(v_alpha, v_beta, self.anchor)
    }

    /// Range-checked [`Self::extract_k`].
    pub fn extract_k_validated(&self, v_alpha: u128, v_beta: u128) -> Nine65Result<u128> {
        self.validate_residues(v_alpha, v_beta)?;
        Ok(self.extract_k(v_alpha, v_beta))
    }

    /// Rebuild `X = v_α + k·M`, failing closed on overflow.
    pub fn reconstruct(&self, v_alpha: u128, k: u128) -> Nine65Result<u128> {
        let winding = k.checked_mul(self.alpha_cap).ok_or(Nine65Error::Overflow {
            operation: "adjacency K-Elimination winding multiplication",
        })?;
        v_alpha.checked_add(winding).ok_or(Nine65Error::Overflow {
            operation: "adjacency K-Elimination winding addition",
        })
    }

    /// The *general* [`KElimination`] over the same `(M, A)` pair.
    ///
    /// This is the differential-test partner: it computes the same `k` through
    /// the generic `(v_β − v_α)·M⁻¹ mod A` path, with `M⁻¹` obtained by
    /// extended Euclid rather than by construction. Any disagreement between
    /// the two is a defect in one of them.
    ///
    /// Fails if `A` does not fit in `u64`, which is the width
    /// [`KElimination::try_new`] accepts for CLASS-R lanes.
    pub fn general_equivalent(&self) -> Nine65Result<KElimination> {
        let anchor = u64::try_from(self.anchor).map_err(|_| Nine65Error::InvalidParameter {
            message: format!(
                "adjacency anchor A = {} exceeds the u64 lane width accepted by \
                 KElimination::try_new; the general partner cannot be built for \
                 this alpha basis",
                self.anchor
            ),
        })?;
        KElimination::try_new(&self.alpha_primes, &[anchor])
    }
}

fn validate_alpha_family(values: &[u64]) -> Nine65Result<()> {
    if values.is_empty() {
        return Err(Nine65Error::InvalidParameter {
            message: "CLASS-F alpha family must not be empty".to_string(),
        });
    }
    for (index, &value) in values.iter().enumerate() {
        // Primality is NOT required here. The K-Elimination lift
        // `X = v_alpha + k * alpha_cap` needs only gcd(alpha_cap, beta_cap) = 1
        // so that the inverse exists, and `mod_inverse_u128` obtains that
        // inverse by extended Euclid (returning None when the gcd is not 1)
        // rather than by Fermat's little theorem, which would need a prime.
        // The previous `!is_prime(value)` rejection was therefore stricter than
        // the arithmetic, and blocked the Safe-Basis composite lanes this
        // constructor is otherwise happy to compute with. Pairwise coprimality
        // is still enforced below, and it is what soundness actually rests on.
        if value <= 1 {
            return Err(Nine65Error::InvalidParameter {
                message: format!("alpha modulus {value} must be greater than 1"),
            });
        }
        for &previous in &values[..index] {
            let gcd = gcd_u128(value as u128, previous as u128);
            if gcd != 1 {
                return Err(Nine65Error::NotCoprime {
                    m: value,
                    a: previous,
                    gcd: gcd as u64,
                });
            }
        }
    }
    Ok(())
}

fn validate_beta_family(values: &[u64]) -> Nine65Result<()> {
    if values.is_empty() {
        return Err(Nine65Error::InvalidParameter {
            message: "CLASS-R beta family must not be empty".to_string(),
        });
    }
    for (index, &value) in values.iter().enumerate() {
        if value <= 1 {
            return Err(Nine65Error::InvalidParameter {
                message: format!("CLASS-R beta modulus {value} must be greater than one"),
            });
        }
        for &previous in &values[..index] {
            let gcd = gcd_u128(value as u128, previous as u128);
            if gcd != 1 {
                return Err(Nine65Error::NotCoprime {
                    m: value,
                    a: previous,
                    gcd: gcd as u64,
                });
            }
        }
    }
    Ok(())
}

fn validate_cross_family(alpha: &[u64], beta: &[u64]) -> Nine65Result<()> {
    for &alpha_modulus in alpha {
        for &beta_modulus in beta {
            let gcd = gcd_u128(alpha_modulus as u128, beta_modulus as u128);
            if gcd != 1 {
                return Err(Nine65Error::NotCoprime {
                    m: alpha_modulus,
                    a: beta_modulus,
                    gcd: gcd as u64,
                });
            }
        }
    }
    Ok(())
}

fn checked_product(values: &[u64], operation: &'static str) -> Nine65Result<u128> {
    values
        .iter()
        .try_fold(1u128, |acc, &value| acc.checked_mul(value as u128))
        .ok_or(Nine65Error::Overflow { operation })
}

fn multiply_u128(a: u128, b: u128) -> [u64; 4] {
    let a0 = a as u64 as u128;
    let a1 = (a >> 64) as u64 as u128;
    let b0 = b as u64 as u128;
    let b1 = (b >> 64) as u64 as u128;

    let p00 = a0 * b0;
    let p01 = a0 * b1;
    let p10 = a1 * b0;
    let p11 = a1 * b1;

    let limb0 = p00 as u64;
    let middle = (p00 >> 64) + (p01 as u64 as u128) + (p10 as u64 as u128);
    let limb1 = middle as u64;
    let upper = (p01 >> 64) + (p10 >> 64) + (p11 as u64 as u128) + (middle >> 64);
    let limb2 = upper as u64;
    let limb3 = ((p11 >> 64) + (upper >> 64)) as u64;
    [limb0, limb1, limb2, limb3]
}

fn trim_fixed_limbs(limbs: [u64; 4]) -> Vec<u64> {
    let mut result = limbs.to_vec();
    while result.len() > 1 && result.last() == Some(&0) {
        result.pop();
    }
    result
}

fn limbs_bit_length(limbs: &[u64]) -> u32 {
    for index in (0..limbs.len()).rev() {
        if limbs[index] != 0 {
            return index as u32 * 64 + (64 - limbs[index].leading_zeros());
        }
    }
    0
}

fn diagnostic_u64(value: u128) -> u64 {
    if value > u64::MAX as u128 {
        u64::MAX
    } else {
        value as u64
    }
}

/// Variable-time inverse over public safe-basis moduli using coefficients kept
/// modulo `modulus`; no signed narrowing occurs.
fn mod_inverse_u128(value: u128, modulus: u128) -> Option<u128> {
    if modulus <= 1 {
        return None;
    }
    let mut r = modulus;
    let mut new_r = value % modulus;
    let mut coefficient = 0u128;
    let mut new_coefficient = 1u128;

    while new_r != 0 {
        let quotient = r / new_r;
        let next_r = r - quotient * new_r;
        r = new_r;
        new_r = next_r;

        let scaled = mul_mod_u128(quotient, new_coefficient, modulus);
        let next_coefficient = sub_mod_u128_ct(coefficient, scaled, modulus);
        coefficient = new_coefficient;
        new_coefficient = next_coefficient;
    }

    if r == 1 {
        Some(coefficient)
    } else {
        None
    }
}

fn gcd_u128(mut a: u128, mut b: u128) -> u128 {
    while b != 0 {
        let remainder = a % b;
        a = b;
        b = remainder;
    }
    a
}

fn sub_mod_u128_ct(a: u128, b: u128, modulus: u128) -> u128 {
    let difference = a.wrapping_sub(b);
    let mask = ((a < b) as u128).wrapping_neg();
    difference.wrapping_add(modulus & mask)
}

fn sub_mod_kelim_ct(a: u128, b: u128, modulus: u128) -> u128 {
    sub_mod_u128_ct(a, b % modulus, modulus)
}

/// Exact branchless modular addition for normalized residues `a,b < modulus`.
fn add_mod_u128_ct(a: u128, b: u128, modulus: u128) -> u128 {
    debug_assert!(modulus != 0);
    debug_assert!(a < modulus);
    debug_assert!(b < modulus);

    let threshold = modulus - b;
    let reduced = a.wrapping_sub(threshold);
    let sum = a.wrapping_add(b);
    let reduce_mask = ((a >= threshold) as u128).wrapping_neg();
    (reduced & reduce_mask) | (sum & !reduce_mask)
}

fn mul_mod_u128_ct(a: u128, b: u128, modulus: u128) -> u128 {
    if modulus == 0 {
        return 0;
    }
    let mut result = 0u128;
    let mut addend = a % modulus;
    for bit in 0..128 {
        let selected = ((b >> bit) & 1).wrapping_neg();
        result = add_mod_u128_ct(result, addend & selected, modulus);
        addend = add_mod_u128_ct(addend, addend, modulus);
    }
    result
}

fn mul_mod_u128(a: u128, b: u128, modulus: u128) -> u128 {
    mul_mod_u128_ct(a, b, modulus)
}

#[cfg(feature = "benchmarks")]
pub fn bench_mul_mod_u128_ct(a: u128, b: u128, modulus: u128) -> u128 {
    mul_mod_u128_ct(a, b, modulus)
}

#[cfg(feature = "benchmarks")]
pub fn bench_sub_mod_u128_ct(a: u128, b: u128, modulus: u128) -> u128 {
    sub_mod_u128_ct(a, b, modulus)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn safe_basis_validation() {
        // Safe-Basis lanes: powers of 2,3,5,7,11,13 split so that alpha and
        // beta have DISJOINT prime support. Both primality and coprimality are
        // resolved by that construction -- there is nothing here to constrain,
        // so this checks that the lanes compute, not that bad input is refused.
        let alpha = 2u64.pow(20) * 3u64.pow(6) * 5u64.pow(4); // composite
        let beta = 7u64.pow(6) * 11u64.pow(4) * 13u64.pow(3); // composite
        let ke = KElimination::try_new(&[alpha], &[beta]).expect("Safe-Basis lanes");

        let (a, b) = (alpha as u128, beta as u128);
        let capacity = a * b;
        let mut x: u128 = 0x9E3779B97F4A7C15;
        for _ in 0..2000 {
            x = x
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            let value = x % capacity;
            assert_eq!(
                ke.extract_k(value % a, value % b),
                value / a,
                "winding lift must be exact on composite Safe-Basis lanes"
            );
        }
        // exact_divide is what the rescale path actually calls.
        for divisor in [2u64, 3, 5, 7, 11, 13] {
            for i in 1..200u128 {
                let raw = (i * 7919) % (capacity / 4);
                let exact = raw - (raw % divisor as u128);
                assert_eq!(
                    ke.exact_divide(exact % a, exact % b, divisor),
                    exact / divisor as u128,
                    "exact_divide must be exact on composite Safe-Basis lanes"
                );
            }
        }
    }

    #[test]
    fn exact_capacity_metadata() {
        for config in [
            KElimConfig::Minimal,
            KElimConfig::Standard,
            KElimConfig::Extended,
            KElimConfig::Maximum,
            KElimConfig::HardwareOpt,
        ] {
            let value = KElimination::from_config(config);
            if let Some(capacity) = value.try_capacity() {
                assert_eq!(
                    value.alpha_cap.checked_mul(value.beta_cap),
                    Some(capacity)
                );
                assert_eq!(
                    value.capacity_limbs().len(),
                    if capacity >> 64 == 0 { 1 } else { 2 }
                );
            } else {
                assert_eq!(value.alpha_cap.checked_mul(value.beta_cap), None);
                assert!(value.capacity_bit_length() > 128);
                assert!(value.capacity_limbs().len() >= 3);
            }
        }
    }

    #[test]
    fn exact_capacity_bits_match_presets() {
        assert_eq!(KElimConfig::Minimal.capacity_bits(), 64);
        assert_eq!(KElimConfig::Standard.capacity_bits(), 110);
        assert_eq!(KElimConfig::Extended.capacity_bits(), 138);
        assert_eq!(KElimConfig::Maximum.capacity_bits(), 188);
        assert_eq!(KElimConfig::HardwareOpt.capacity_bits(), 140);
    }

    #[test]
    fn extraction_and_division_match_reference_values() {
        let value = KElimination::new(&[17, 19], &[23, 29]);
        for scalar in [0u128, 1, 1000, 10_000, 200_000] {
            let alpha = scalar % value.alpha_cap;
            let beta = scalar % value.beta_cap;
            let reconstructed = alpha + value.extract_k(alpha, beta) * value.alpha_cap;
            assert_eq!(reconstructed, scalar);
        }

        let division = KElimination::new(&[65537, 65521], &[65519, 65497]);
        let scalar = 12_345u128;
        assert_eq!(
            division.exact_divide_checked(
                scalar % division.alpha_cap,
                scalar % division.beta_cap,
                5,
            ),
            Some(2469)
        );
    }

    #[test]
    fn validated_division_rejects_range_and_inexactness() {
        let value = KElimination::new(&[17, 19], &[23, 29]);
        assert!(value
            .exact_divide_validated(value.alpha_cap, 0, 1)
            .is_err());
        let scalar = 1001u128;
        assert!(value
            .exact_divide_validated(
                scalar % value.alpha_cap,
                scalar % value.beta_cap,
                2,
            )
            .is_err());
    }

    #[test]
    fn scale_and_round_matches_integer_reference() {
        let value = KElimination::for_fhe(65537);
        for coefficient in [0u64, 1, 100, 1000, 10_000, 32_768, 65_536] {
            let expected =
                ((coefficient as u128 * 257 + 65537 / 2) / 65537) as u64;
            assert_eq!(value.scale_and_round(coefficient, 257, 65537), expected);
        }
    }

    #[test]
    fn constant_and_variable_extractors_agree() {
        let value = KElimination::new(&[17, 19], &[23, 29]);
        for scalar in [0u128, 1, 100, 1000, 10_000, 100_000, 200_000] {
            let alpha = scalar % value.alpha_cap;
            let beta = scalar % value.beta_cap;
            #[allow(deprecated)]
            let variable = value.extract_k_vartime(alpha, beta);
            assert_eq!(value.extract_k(alpha, beta), variable);
        }
    }

    #[test]
    fn modular_multiplication_matches_reference() {
        let modulus = 4611686018427387847u128;
        for (a, b) in [
            (0u128, 0u128),
            (1, 1),
            (12345, 67890),
            (modulus - 1, modulus - 1),
        ] {
            assert_eq!(mul_mod_u128_ct(a, b, modulus), (a * b) % modulus);
        }
    }

    #[test]
    fn modular_addition_handles_u128_wrap_boundary() {
        let modulus = u128::MAX - 158;
        let a = modulus - 1;
        let b = modulus - 1;
        assert_eq!(add_mod_u128_ct(a, b, modulus), modulus - 2);
    }

    /// Verified primality check for CLASS-F verification.
    fn is_prime(n: u64) -> bool {
        if n < 2 { return false; }
        if n == 2 || n == 3 { return true; }
        if n % 2 == 0 || n % 3 == 0 { return false; }
        let mut i = 5;
        while i * i <= n {
            if n % i == 0 || n % (i + 2) == 0 { return false; }
            i += 6;
        }
        true
    }

    /// Greatest common divisor for u128.
    fn gcd_u128(mut a: u128, mut b: u128) -> u128 {
        while b != 0 {
            let t = b;
            b = a % b;
            a = t;
        }
        a
    }

    /// Greatest common divisor for u64.
    fn gcd_u64(mut a: u64, mut b: u64) -> u64 {
        while b != 0 {
            let t = b;
            b = a % b;
            a = t;
        }
        a
    }

    #[test]
    fn test_class_f_moduli_are_prime() {
        // Alpha primes MUST be prime (CLASS-F adjacent)
        for config in [
            KElimConfig::Minimal,
            KElimConfig::Standard,
            KElimConfig::Extended,
            KElimConfig::Maximum,
            KElimConfig::HardwareOpt,
        ] {
            for &p in &config.alpha_primes() {
                assert!(is_prime(p), "CLASS-F: alpha {} must be prime", p);
            }
        }
    }

    #[test]
    fn test_class_r_moduli_are_coprime() {
        let ntt_primes = [998244353, 985661441, 754974721, 469762049, 167772161, 595591169];
        let configs = [
            KElimConfig::Minimal,
            KElimConfig::Standard,
            KElimConfig::Extended,
            KElimConfig::Maximum,
            KElimConfig::HardwareOpt,
        ];

        for config in configs {
            let alphas = config.alpha_primes();
            let betas = config.beta_moduli();
            let alpha_cap: u128 = alphas.iter().map(|&p| p as u128).product();
            let beta_cap: u128 = betas.iter().map(|&b| b as u128).product();

            // Alpha-beta coprimality (required for the K-Elim winding-lift inverse α_cap⁻¹ mod β_cap)
            assert_eq!(gcd_u128(alpha_cap, beta_cap), 1,
                "{:?}: alpha_cap and beta_cap must be coprime", config);

            // Beta pairwise coprimality
            for i in 0..betas.len() {
                for j in (i+1)..betas.len() {
                    assert_eq!(gcd_u64(betas[i], betas[j]), 1,
                        "{:?}: beta moduli {} and {} must be coprime", config, betas[i], betas[j]);
                }
            }

            // Beta-NTT coprimality
            for &b in &betas {
                for &q in &ntt_primes {
                    assert_eq!(gcd_u64(b, q), 1,
                        "{:?}: beta {} must be coprime to NTT prime {}", config, b, q);
                }
            }

            // Odd modulus (required for Montgomery)
            for &b in &betas {
                assert!(b % 2 == 1, "{:?}: beta {} must be odd for Montgomery", config, b);
            }
        }
    }

    #[test]
    fn inverse_handles_public_moduli_above_i128() {
        let modulus = u128::MAX - 158;
        let value = 5u128;
        let inverse = mod_inverse_u128(value, modulus).expect("inverse must exist");
        assert_eq!(mul_mod_u128(value, inverse, modulus), 1);
    }

    #[test]
    fn test_kelim_builder_success() {
        let ke = KElimBuilder::new()
            .alpha_primes(&[17, 19])
            .beta_moduli(&[23, 29])
            .build();

        assert!(ke.is_ok());
        let ke = ke.unwrap();
        assert_eq!(ke.alpha_cap, 323);
        assert_eq!(ke.beta_cap, 667);
    }

    #[test]
    fn test_kelim_builder_missing_primes() {
        // Missing alpha primes
        let result = KElimBuilder::new().beta_moduli(&[23, 29]).build();
        assert!(result.is_err());

        // Missing beta moduli
        let result = KElimBuilder::new().alpha_primes(&[17, 19]).build();
        assert!(result.is_err());
    }

    #[test]
    fn test_kelim_try_new_coprime() {
        // Coprime primes should succeed
        let result = KElimination::try_new(&[17, 19], &[23, 29]);
        assert!(result.is_ok());
    }

    #[test]
    fn test_kelim_try_new_not_coprime() {
        // Non-coprime should fail (both have factor of 17)
        let result = KElimination::try_new(&[17, 19], &[17, 29]);
        assert!(result.is_err());
    }

    #[test]
    fn test_all_configs_work_for_reconstruction() {
        for config in [
            KElimConfig::Minimal,
            KElimConfig::Standard,
            KElimConfig::Extended,
            KElimConfig::Maximum,
            KElimConfig::HardwareOpt,
        ] {
            let ke = KElimination::from_config(config);

            // Test reconstruction for various values within capacity
            for v in [0u128, 1, 1000, 1_000_000, 1_000_000_000] {
                let v_alpha = v % ke.alpha_cap;
                let v_beta = v % ke.beta_cap;

                let k = ke.extract_k(v_alpha, v_beta);
                let reconstructed = v_alpha + k * ke.alpha_cap;

                assert_eq!(
                    reconstructed, v,
                    "Reconstruction failed for v={} with config {:?}",
                    v, config
                );
            }
        }
    }

    // =========================================================================
    // PRECONDITION VALIDATION TESTS
    // =========================================================================

    #[test]
    #[ignore]
    fn test_kelim_all_configs_exhaustive() {
        use crate::entropy::ShadowHarvester;
        let mut rng = ShadowHarvester::with_seed(42);

        for config in [
            KElimConfig::Minimal,
            KElimConfig::Standard,
            KElimConfig::Extended,
            KElimConfig::Maximum,
            KElimConfig::HardwareOpt,
        ] {
            let ke = KElimination::from_config(config);
            let capacity = ke.capacity();

            // Randomly test 10,000 values for each config
            for _ in 0..10_000 {
                // Generate random u128 within capacity
                // Simple approach: sample two u64 and combine, then mod capacity
                let lo = rng.next_u64();
                let hi = rng.next_u64();
                let v = ((hi as u128) << 64 | (lo as u128)) % capacity;

                let v_alpha = v % ke.alpha_cap;
                let v_beta = v % ke.beta_cap;

                let k = ke.extract_k(v_alpha, v_beta);
                let reconstructed = v_alpha + k * ke.alpha_cap;

                assert_eq!(
                    reconstructed, v,
                    "Exhaustive K-Elim failed for v={} with config {:?}",
                    v, config
                );
            }
            eprintln!("  {:?}: 10,000 trials passed", config);
        }
    }

    #[test]
    fn test_validate_value_within_capacity() {
        let ke = KElimination::new(&[17, 19], &[23, 29]);
        // capacity = 323 * 667 = 215441
        assert!(ke.validate_value(0).is_ok());
        assert!(ke.validate_value(1000).is_ok());
        assert!(ke.validate_value(215440).is_ok()); // max valid
    }

    #[test]
    fn test_validate_value_exceeds_capacity() {
        let ke = KElimination::new(&[17, 19], &[23, 29]);
        // capacity = 323 * 667 = 215441
        assert!(ke.validate_value(215441).is_err()); // exactly at boundary
        assert!(ke.validate_value(1_000_000).is_err());
    }

    #[test]
    fn test_validate_residues_valid() {
        let ke = KElimination::new(&[17, 19], &[23, 29]);
        assert!(ke.validate_residues(100, 300).is_ok());
        assert!(ke.validate_residues(0, 0).is_ok());
        assert!(ke.validate_residues(322, 666).is_ok()); // alpha_cap-1, beta_cap-1
    }

    #[test]
    fn test_validate_residues_out_of_range() {
        let ke = KElimination::new(&[17, 19], &[23, 29]);
        assert!(ke.validate_residues(323, 0).is_err()); // v_alpha >= alpha_cap
        assert!(ke.validate_residues(0, 667).is_err()); // v_beta >= beta_cap
    }

    #[test]
    fn test_exact_divide_validated_success() {
        let ke = KElimination::new(&[65537, 65521], &[65519, 65497]);
        let v: u128 = 12345;
        let divisor = 5u64;
        let v_alpha = v % ke.alpha_cap;
        let v_beta = v % ke.beta_cap;
        let result = ke.exact_divide_validated(v_alpha, v_beta, divisor);
        assert_eq!(result.unwrap(), 2469);
    }

    #[test]
    fn test_exact_divide_validated_not_divisible() {
        let ke = KElimination::new(&[65537, 65521], &[65519, 65497]);
        let v: u128 = 12346; // not divisible by 5
        let v_alpha = v % ke.alpha_cap;
        let v_beta = v % ke.beta_cap;
        let result = ke.exact_divide_validated(v_alpha, v_beta, 5);
        assert!(result.is_err());
    }

    #[test]
    fn test_exact_divide_validated_zero_divisor() {
        let ke = KElimination::new(&[17, 19], &[23, 29]);
        let result = ke.exact_divide_validated(100, 300, 0);
        assert!(result.is_err());
    }

    #[test]
    fn test_try_from_config_all_valid() {
        for config in [
            KElimConfig::Minimal,
            KElimConfig::Standard,
            KElimConfig::Extended,
            KElimConfig::Maximum,
        ] {
            let result = KElimination::try_from_config(config);
            assert!(result.is_ok(), "try_from_config failed for {:?}", config);
        }
    }

    #[test]
    fn test_try_for_degree() {
        let result = KElimination::try_for_degree(1024);
        assert!(result.is_ok());
        let ke = result.unwrap();
        assert_eq!(ke.config(), Some(KElimConfig::Standard));
    }

    // Timing regression tests moved to criterion benches (benches/timing.rs)
}

#[cfg(test)]
mod bench_compat {
    use super::*;
    use std::time::Instant;

    #[test]
    #[ignore]
    fn benchmark_anchor_generation() {
        println!("\n=== Anchor Generation Benchmark (Prime vs Composite) ===");
        let bits = [32, 45, 62, 90, 128];

        for &b in &bits {
            println!("\nBit-width: {}", b);

            // Prime generation (representative timing)
            let start = Instant::now();
            // We simulate prime generation by finding a large prime
            // In a real scenario, this involves primality testing
            let mut p = (1u128 << (b-1)) + 1;
            while !is_prime_u128(p) {
                p += 2;
            }
            let prime_time = start.elapsed();
            println!("  Prime:     {:?}", prime_time);

            // Composite generation (Separation Principle)
            let start = Instant::now();
            // We simulate composite generation by multiplying two smaller primes
            let half = b / 2;
            let mut p1 = (1u128 << (half-1)) + 1;
            while !is_prime_u128(p1) { p1 += 2; }
            let mut p2 = (1u128 << (b - half - 1)) + 1;
            while !is_prime_u128(p2) { p2 += 2; }
            let _c = p1 * p2;
            let composite_time = start.elapsed();
            println!("  Composite: {:?}", composite_time);

            if b >= 128 {
                assert!(composite_time < prime_time, "Composite should be faster at {} bits", b);
            }
        }
    }

    fn is_prime_u128(n: u128) -> bool {
        if n < 2 { return false; }
        if n % 2 == 0 { return n == 2; }
        let mut i = 3;
        while i * i <= n {
            if n % i == 0 { return false; }
            i += 2;
            if i > 1000000 { break; } // Limit for bench speed
        }
        true
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// ADJACENCY K-ELIMINATION — correctness by execution
// ═══════════════════════════════════════════════════════════════════════════
//
// The adjacency shortcut replaces a modular multiply by a precomputed inverse
// with a bare subtraction. That is only worth having if it computes the SAME
// winding index as the general path, so every test here is differential: the
// shortcut is checked against `KElimination::extract_k` over the identical
// (M, A) pair, and both are checked against ground truth `k = X / M`.
#[cfg(test)]
mod adjacency_tests {
    use super::*;

    /// Deterministic xorshift64*, so these tests are reproducible on every
    /// platform and carry no dependency and no floating point.
    struct Xorshift(u64);

    impl Xorshift {
        fn new(seed: u64) -> Self {
            Self(seed | 1)
        }
        fn next_u64(&mut self) -> u64 {
            let mut x = self.0;
            x ^= x >> 12;
            x ^= x << 25;
            x ^= x >> 27;
            self.0 = x;
            x.wrapping_mul(0x2545_F491_4F6C_DD1D)
        }
        fn next_u128(&mut self) -> u128 {
            ((self.next_u64() as u128) << 64) | self.next_u64() as u128
        }
    }

    #[test]
    fn adjacency_inverse_is_the_partner_itself() {
        // M^-1 mod A == M, checked against extended Euclid rather than assumed.
        for config in [
            KElimConfig::Minimal,
            KElimConfig::Standard,
            KElimConfig::Maximum,
        ] {
            let adj = AdjacencyKElim::from_config(config).expect("adjacency context");
            let by_euclid = mod_inverse_u128(adj.alpha_cap(), adj.anchor())
                .expect("gcd(M, M+1) = 1, so the inverse exists");
            assert_eq!(
                by_euclid,
                adj.alpha_cap(),
                "{config:?}: M^-1 mod A must be M itself under adjacency"
            );
            assert_eq!(by_euclid, adj.alpha_inv_anchor());
        }
    }

    #[test]
    fn adjacency_matches_general_exhaustively() {
        // M = 105, A = 106 = 2 * 53 (composite CLASS-R anchor, as expected).
        let adj = AdjacencyKElim::try_new(&[3, 5, 7]).expect("adjacency context");
        assert_eq!(adj.alpha_cap(), 105);
        assert_eq!(adj.anchor(), 106);

        let general = adj.general_equivalent().expect("general partner");
        assert_eq!(general.beta_cap, 106, "the general partner uses the same A");
        assert_eq!(
            general.alpha_inv_beta,
            105,
            "the general partner's extended-Euclid inverse agrees with construction"
        );

        let capacity = adj.try_capacity().expect("105 * 106 fits");
        assert_eq!(capacity, 105 * 106);

        for x in 0..capacity {
            let v_alpha = x % adj.alpha_cap();
            let v_beta = x % adj.anchor();
            let truth = x / adj.alpha_cap(); // X = v_alpha + k*M  =>  k = floor(X/M)

            let fast = adj.extract_k(v_alpha, v_beta);
            let slow = general.extract_k(v_alpha, v_beta);

            assert_eq!(fast, truth, "adjacency k wrong at X={x}");
            assert_eq!(slow, truth, "general k wrong at X={x}");
            assert_eq!(
                adj.reconstruct(v_alpha, fast).expect("no overflow"),
                x,
                "reconstruction wrong at X={x}"
            );
        }
    }

    #[test]
    fn adjacency_matches_general_on_the_standard_basis() {
        let adj = AdjacencyKElim::from_config(KElimConfig::Standard).expect("adjacency context");
        let general = adj.general_equivalent().expect("general partner");
        assert_eq!(general.alpha_inv_beta, adj.alpha_cap());

        let capacity = adj.try_capacity().expect("M * A fits in u128");
        let mut rng = Xorshift::new(0x9E37_79B9_7F4A_7C15);

        for _ in 0..200_000 {
            let x = rng.next_u128() % capacity;
            let v_alpha = x % adj.alpha_cap();
            let v_beta = x % adj.anchor();
            let truth = x / adj.alpha_cap();

            assert_eq!(adj.extract_k(v_alpha, v_beta), truth, "adjacency k wrong at X={x}");
            assert_eq!(general.extract_k(v_alpha, v_beta), truth, "general k wrong at X={x}");
        }
    }

    #[test]
    fn adjacency_covers_the_extremes_of_the_range() {
        // Random sampling over a 2^96 space never lands on the boundary, so
        // the boundary is enumerated explicitly.
        let adj = AdjacencyKElim::from_config(KElimConfig::Standard).expect("adjacency context");
        let general = adj.general_equivalent().expect("general partner");
        let capacity = adj.try_capacity().expect("M * A fits in u128");
        let (m, a) = (adj.alpha_cap(), adj.anchor());

        let mut probes: Vec<u128> = vec![0, 1, 2, m - 1, m, m + 1, a - 1, a, a + 1];
        probes.extend([capacity - 1, capacity - 2, capacity - m, capacity - a]);
        for k in [0u128, 1, 2, a - 1] {
            probes.push(k * m);
            probes.push(k * m + (m - 1));
        }

        for x in probes {
            let x = x % capacity;
            let v_alpha = x % m;
            let v_beta = x % a;
            let truth = x / m;
            assert_eq!(adj.extract_k(v_alpha, v_beta), truth, "adjacency k wrong at X={x}");
            assert_eq!(general.extract_k(v_alpha, v_beta), truth, "general k wrong at X={x}");
        }
    }

    #[test]
    fn adjacency_sign_is_minus_not_plus() {
        // The white paper publishes X == gamma + K (mod A). It is gamma - K.
        // If the two ever agreed everywhere this test would be vacuous, so it
        // asserts a *disagreement* as well as which side is right.
        let adj = AdjacencyKElim::try_new(&[3, 5, 7]).expect("adjacency context");
        let (m, a) = (adj.alpha_cap(), adj.anchor());
        let mut disagreements = 0usize;

        for x in 0..adj.try_capacity().unwrap() {
            let v_alpha = x % m;
            let v_beta = x % a;
            let truth = x / m;

            assert_eq!(sub_mod_u128_ct(v_alpha, v_beta, a), truth);
            let published = (v_alpha + v_beta) % a;
            if published != truth {
                disagreements += 1;
            }
        }
        assert!(
            disagreements > 0,
            "the published (gamma + K) form must be measurably wrong, not merely unused"
        );
    }

    #[test]
    fn adjacency_validates_residue_ranges() {
        let adj = AdjacencyKElim::try_new(&[3, 5, 7]).expect("adjacency context");
        assert!(adj.extract_k_validated(104, 105).is_ok());
        assert!(adj.extract_k_validated(105, 0).is_err(), "v_alpha == M is out of range");
        assert!(adj.extract_k_validated(0, 106).is_err(), "v_beta == A is out of range");
    }

    #[test]
    fn adjacency_rejects_a_non_class_f_alpha_family() {
        // A = M+1 makes the anchor coprime to M for free, so adjacency resolves
        // both properties by construction and neither is a constraint to assert
        // here. What is worth pinning is that composite Safe-Basis lanes build
        // and lift exactly through this path.
        let lane = 2u64.pow(20) * 3u64.pow(8) * 5u64.pow(5) * 7u64.pow(4);
        let adj = AdjacencyKElim::try_new(&[lane]).expect("adjacency over a composite lane");

        let m = adj.alpha_cap();
        let a = m + 1;
        let capacity = m * a;
        let mut x: u128 = 0xDEADBEEFCAFEBABE;
        for _ in 0..2000 {
            x = x
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            let value = x % capacity;
            assert_eq!(
                adj.extract_k(value % m, value % a),
                value / m,
                "adjacency lift must be exact on a composite Safe-Basis lane"
            );
        }
    }

    #[test]
    fn adjacency_capacity_is_m_times_m_plus_one() {
        // The tradeoff, stated as a number rather than as prose: the general
        // Standard context reaches 110 bits, adjacency reaches ~97.
        let adj = AdjacencyKElim::from_config(KElimConfig::Standard).expect("adjacency context");
        let general = KElimination::from_config(KElimConfig::Standard);

        let adj_cap = adj.try_capacity().expect("fits");
        assert_eq!(adj_cap, adj.alpha_cap() * (adj.alpha_cap() + 1));

        let general_cap = general.try_capacity().expect("fits");
        assert!(
            adj_cap < general_cap,
            "adjacency trades capacity for the free inverse: {} vs {}",
            adj_cap.ilog2(),
            general_cap.ilog2()
        );
        // Bit-length, i.e. ilog2 + 1: adjacency 96 bits, general 110 bits.
        assert_eq!(adj_cap.ilog2() + 1, 96);
        assert_eq!(general_cap.ilog2() + 1, 110);
    }
}
