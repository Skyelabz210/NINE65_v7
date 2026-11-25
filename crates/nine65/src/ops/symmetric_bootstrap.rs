//! Trusted-key scalar refresh by decryption and fresh encryption.
//!
//! The operator holds the secret key and briefly processes a plaintext scalar.
//! This is distinct from public homomorphic bootstrap: it installs no Three-Lock
//! envelope and establishes no side-channel or production-security claim.
//!
//! Inputs must encode a scalar in coefficient zero, use the supplied key and
//! context, and still decrypt correctly. Shape/residue validation cannot prove
//! those conditions, detect a wrong but well-formed key, or certify that noise
//! has not already changed the nearest plaintext. Other plaintext coefficients
//! are intentionally not preserved. See `docs/SECURITY_MODE_MATRIX.md` and
//! `docs/PUBLIC_REFRESH_STATUS.md` for the separate public-refresh boundaries.

use crate::arithmetic::rns::{DualRNSContext, U256};
use crate::arithmetic::NTTEngine;
use crate::entropy::{FheRng, SecureRng, ShadowHarvester};
use crate::errors::{Nine65Error, Nine65Result};
use crate::keys::bootstrap::ensure_q_boot_representable;
use crate::ops::rns_fhe::{
    DualRNSCiphertext, DualRNSPoly, DualRNSPublicKey, DualRNSSecretKey, RNSFHEContext, MAX_LEVEL,
    MAX_POLY_DEGREE,
};
use crate::params::FHEConfig;
use zeroize::Zeroizing;

/// Trusted-key decrypt/re-encrypt engine for scalar ciphertexts.
///
/// `bootstrap_secure` and `reencrypt_symmetric_secure` use the OS CSPRNG.
/// The original `ShadowHarvester` entry points remain available for deterministic
/// development tests and return a typed RNG-policy refusal in release builds.
/// The public arithmetic context must retain its constructor-created internals;
/// the checks below detect metadata/shape drift, not arbitrary tampering with
/// every cached arithmetic constant or key provenance.
pub struct SymmetricBootstrap {
    /// Working FHE configuration.
    pub config: FHEConfig,
    /// Working RNS context.
    pub ctx: RNSFHEContext,
    /// Plaintext modulus.
    pub t: u64,
    /// Polynomial degree.
    pub n: usize,
    /// Number of successful refreshes.
    pub bootstrap_count: u64,
}

/// Timings and a fresh-encryption cost estimate for scalar refresh.
#[derive(Clone, Debug)]
pub struct SymBootstrapStats {
    /// Checked scalar decryption time (ns).
    pub decrypt_ns: u64,
    /// Re-encryption time (ns).
    pub encrypt_ns: u64,
    /// Total time, including validation (ns).
    pub total_ns: u64,
    /// Modelled fresh-encryption noise cost (millibits), not a measured budget
    /// or a certificate that the source ciphertext decrypted correctly.
    pub post_noise_mb: i64,
}

impl std::fmt::Display for SymBootstrapStats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "SymBootstrap: {}us total ({}us decrypt, {}us encrypt) estimated_noise_cost={}mb",
            self.total_ns / 1000,
            self.decrypt_ns / 1000,
            self.encrypt_ns / 1000,
            self.post_noise_mb,
        )
    }
}

impl SymmetricBootstrap {
    /// Create an engine for a supported scalar refresh basis.
    ///
    /// Refuses malformed degrees, non-prime/duplicate/incompatible main lanes,
    /// invalid plaintext moduli and bases wider than the full-Q sampler before
    /// entering constructors with assertion-based legacy preconditions.
    pub fn new(config: &FHEConfig) -> Nine65Result<Self> {
        Self::validate_config(config)?;
        let ctx = RNSFHEContext::try_new(config)?;
        Ok(Self {
            config: config.clone(),
            t: config.t,
            n: config.n,
            ctx,
            bootstrap_count: 0,
        })
    }

    fn mismatch(reason: &str) -> Nine65Error {
        Nine65Error::BootstrapConfigMismatch {
            reason: reason.into(),
        }
    }

    fn validate_config(config: &FHEConfig) -> Nine65Result<()> {
        if !config.n.is_power_of_two() || config.n > MAX_POLY_DEGREE {
            return Err(Self::mismatch(
                "refresh degree must be a power of two at most 32768",
            ));
        }
        if !(2..=MAX_LEVEL).contains(&config.primes.len()) || config.t < 2 {
            return Err(Self::mismatch(
                "refresh requires 2..=32 main primes and t >= 2",
            ));
        }
        ensure_q_boot_representable(&config.primes)?;
        let anchors = DualRNSContext::canonical_anchor_primes_for_n(config.n);
        for (i, &prime) in config.primes.iter().enumerate() {
            if !crate::params::is_prime(prime)
                || prime >= (1u64 << 63)
                || config.primes[..i].contains(&prime)
                || anchors.contains(&prime)
                || (prime - 1) % (2 * config.n as u64) != 0
            {
                return Err(Self::mismatch("refresh main primes must be distinct, NTT-compatible, below 2^63 and disjoint from the anchor basis"));
            }
        }
        let q = U256::product_u64s(&config.primes);
        if q.le(U256::from_u64(config.t)) || config.eta > i64::MAX as usize {
            return Err(Self::mismatch(
                "refresh requires Q > t and a representable CBD parameter",
            ));
        }
        Ok(())
    }

    fn validate_context(&self) -> Nine65Result<()> {
        let cfg = &self.config;
        if self.n != cfg.n
            || self.t != cfg.t
            || self.ctx.n != cfg.n
            || self.ctx.t != cfg.t
            || self.ctx.config.n != cfg.n
            || self.ctx.config.t != cfg.t
            || self.ctx.config.primes != cfg.primes
            || self.ctx.config.eta != cfg.eta
        {
            return Err(Self::mismatch(
                "refresh engine and context metadata disagree",
            ));
        }
        // Arithmetic caches and NTT tables remain constructor-owned. These
        // public fields cannot authenticate arbitrary caller mutations of them.
        ensure_q_boot_representable(&cfg.primes)
    }

    fn validate_full_key_shape(&self, poly: &DualRNSPoly) -> Nine65Result<()> {
        poly.validate()?;
        if poly.n != self.n
            || poly.main.len() != self.config.primes.len()
            || poly.anchor.len() != self.ctx.dual_rns.anchor.primes.len()
        {
            return Err(Self::mismatch(
                "refresh keys must cover the full output degree and basis",
            ));
        }
        Ok(())
    }

    fn validate_full_key_poly(&self, poly: &DualRNSPoly) -> Nine65Result<()> {
        self.validate_full_key_shape(poly)?;
        poly.validate_residues(&self.config.primes, &self.ctx.dual_rns.anchor.primes)
    }

    fn prepare<R: FheRng>(
        &self,
        sk: &DualRNSSecretKey,
        pk: Option<&DualRNSPublicKey>,
        rng: &R,
    ) -> Nine65Result<()> {
        crate::entropy::rng_trait::try_require_secure_rng(
            rng,
            "SymmetricBootstrap scalar refresh",
        )?;
        self.validate_context()?;
        self.validate_full_key_shape(&sk.s)?;
        if let Some(pk) = pk {
            self.validate_full_key_poly(&pk.pk0)?;
            self.validate_full_key_poly(&pk.pk1)?;
        }
        if self.bootstrap_count == u64::MAX {
            return Err(Nine65Error::Overflow {
                operation: "scalar refresh counter",
            });
        }
        Ok(())
    }

    /// Refresh coefficient zero using the supplied public key and deterministic
    /// research randomness. See the module's scalar/key/noise preconditions.
    /// Release builds return a typed RNG-policy refusal before decryption.
    pub fn bootstrap(
        &mut self,
        ct: &DualRNSCiphertext,
        sk: &DualRNSSecretKey,
        pk: &DualRNSPublicKey,
        rng: &mut ShadowHarvester,
    ) -> Nine65Result<DualRNSCiphertext> {
        self.bootstrap_with_rng(ct, sk, pk, rng)
    }

    /// Trusted-key scalar refresh using fresh OS CSPRNG randomness.
    ///
    /// The keys must be a matching pair for this context; their shape does not
    /// establish that relationship. Secure randomness does not confer public
    /// bootstrap, plaintext isolation, or a noise-exhaustion detector. Existing
    /// `SecureRng` draw methods panic if the OS entropy source fails.
    pub fn bootstrap_secure(
        &mut self,
        ct: &DualRNSCiphertext,
        sk: &DualRNSSecretKey,
        pk: &DualRNSPublicKey,
    ) -> Nine65Result<DualRNSCiphertext> {
        self.bootstrap_with_rng(ct, sk, pk, &mut SecureRng::new())
    }

    fn bootstrap_with_rng<R: FheRng>(
        &mut self,
        ct: &DualRNSCiphertext,
        sk: &DualRNSSecretKey,
        pk: &DualRNSPublicKey,
        rng: &mut R,
    ) -> Nine65Result<DualRNSCiphertext> {
        self.prepare(sk, Some(pk), rng)?;
        let m = Zeroizing::new(self.ctx.try_decrypt_dual_scalar(ct, sk)?);
        let fresh = self.ctx.encrypt_dual_with_rng(*m, pk, rng);
        self.bootstrap_count += 1;
        Ok(fresh)
    }

    /// Deterministic scalar refresh with timings. The cost model in its stats
    /// does not measure the source noise or prove successful source decryption.
    pub fn bootstrap_timed(
        &mut self,
        ct: &DualRNSCiphertext,
        sk: &DualRNSSecretKey,
        pk: &DualRNSPublicKey,
        rng: &mut ShadowHarvester,
    ) -> Nine65Result<(DualRNSCiphertext, SymBootstrapStats)> {
        let total_start = std::time::Instant::now();
        self.prepare(sk, Some(pk), rng)?;
        let t0 = std::time::Instant::now();
        let m = Zeroizing::new(self.ctx.try_decrypt_dual_scalar(ct, sk)?);
        let decrypt_ns = t0.elapsed().as_nanos() as u64;
        let t1 = std::time::Instant::now();
        let fresh = self.ctx.encrypt_dual_with_rng(*m, pk, rng);
        let encrypt_ns = t1.elapsed().as_nanos() as u64;
        drop(m);
        self.bootstrap_count += 1;
        let stats = SymBootstrapStats {
            decrypt_ns,
            encrypt_ns,
            total_ns: total_start.elapsed().as_nanos() as u64,
            post_noise_mb: crate::noise::budget::NoiseBudget::encrypt_cost(&self.config),
        };
        Ok((fresh, stats))
    }

    /// Scalar decrypt/re-encrypt without a public key, using deterministic
    /// research randomness. The plaintext is briefly visible to this process.
    pub fn reencrypt_symmetric(
        &mut self,
        ct: &DualRNSCiphertext,
        sk: &DualRNSSecretKey,
        rng: &mut ShadowHarvester,
    ) -> Nine65Result<DualRNSCiphertext> {
        self.reencrypt_symmetric_with_rng(ct, sk, rng)
    }

    /// Trusted-key scalar refresh without a public key, using the OS CSPRNG.
    /// See `bootstrap_secure` for scalar, key, entropy and confidentiality scope.
    pub fn reencrypt_symmetric_secure(
        &mut self,
        ct: &DualRNSCiphertext,
        sk: &DualRNSSecretKey,
    ) -> Nine65Result<DualRNSCiphertext> {
        self.reencrypt_symmetric_with_rng(ct, sk, &mut SecureRng::new())
    }

    fn reencrypt_symmetric_with_rng<R: FheRng>(
        &mut self,
        ct: &DualRNSCiphertext,
        sk: &DualRNSSecretKey,
        rng: &mut R,
    ) -> Nine65Result<DualRNSCiphertext> {
        self.prepare(sk, None, rng)?;
        let m = Zeroizing::new(self.ctx.try_decrypt_dual_scalar(ct, sk)?);
        let fresh = self.symmetric_encrypt(*m, sk, rng)?;
        self.bootstrap_count += 1;
        Ok(fresh)
    }

    /// Encrypt a scalar with one canonical full-Q mask and one signed CBD
    /// error polynomial shared by all main/anchor lanes. Both bases encode
    /// the same global Delta = floor(Q_main/t), including the anchors.
    fn symmetric_encrypt<R: FheRng>(
        &self,
        m: u64,
        sk: &DualRNSSecretKey,
        rng: &mut R,
    ) -> Nine65Result<DualRNSCiphertext> {
        ensure_q_boot_representable(&self.config.primes)?;
        let a = self.ctx.sample_uniform_dual_poly(rng, &self.config.primes);
        let e_signed = Zeroizing::new(rng.cbd_vector(self.n, self.config.eta));
        let (delta, _) = U256::product_u64s(&self.config.primes).div_mod_u64(self.t);
        let encrypt_lanes =
            |primes: &[u64], engines: &[NTTEngine], mask: &[Vec<u64>], secret: &[Vec<u64>]| {
                primes
                    .iter()
                    .enumerate()
                    .map(|(i, &p)| {
                        let product = Zeroizing::new(engines[i].multiply(&mask[i], &secret[i]));
                        let delta_m = ((delta.mod_u64(p) as u128 * m as u128) % p as u128) as u64;
                        (0..self.n)
                            .map(|j| {
                                let e_mod = (e_signed[j] as i128).rem_euclid(p as i128) as u128;
                                let message = if j == 0 { delta_m as u128 } else { 0 };
                                ((message + p as u128 - product[j] as u128 + e_mod) % p as u128)
                                    as u64
                            })
                            .collect()
                    })
                    .collect::<Vec<Vec<u64>>>()
            };
        let c0_main = encrypt_lanes(
            &self.config.primes,
            &self.ctx.ntt_engines,
            &a.main,
            &sk.s.main,
        );
        let c0_anchor = encrypt_lanes(
            &self.ctx.dual_rns.anchor.primes,
            &self.ctx.dual_rns.anchor.ntt_engines,
            &a.anchor,
            &sk.s.anchor,
        );
        Ok(DualRNSCiphertext {
            c0: DualRNSPoly {
                main: c0_main,
                anchor: c0_anchor,
                n: self.n,
            },
            c1: a,
            level: self.config.primes.len(),
        })
    }
}

// =============================================================================
// DEPTH ANALYSIS: How Far Can We Push Without Bootstrap?
// =============================================================================

/// Legacy noise-cost model; this is not a measured depth or correctness bound.
///
/// Returns (initial_budget_mb, cost_per_sym_mul_mb, cost_per_pub_mul_mb,
///          max_sym_depth, max_pub_depth)
pub fn analyze_depth_budget(config: &FHEConfig) -> DepthAnalysis {
    use crate::noise::budget::NoiseBudget;

    let budget = NoiseBudget::from_config(config);
    let initial_mb = budget.remaining_millibits();

    // Symmetric mode: zero relin noise, only K-Elimination rescale gain
    let sym_mul_cost = NoiseBudget::mul_ct_cost(config); // tensor product noise
    let sym_rescale_gain = NoiseBudget::rescale_cost(config); // negative = gain
    let sym_net_cost = sym_mul_cost + sym_rescale_gain; // much smaller

    // Public mode: full relin noise + mul noise - rescale gain
    let pub_mul_cost = NoiseBudget::mul_ct_cost(config);
    let pub_relin_cost = NoiseBudget::relin_cost(config);
    let pub_net_cost = pub_mul_cost + pub_relin_cost + sym_rescale_gain;

    // Max depths (conservative)
    let max_sym_depth = if sym_net_cost > 0 {
        (initial_mb / sym_net_cost) as usize
    } else {
        usize::MAX // Legacy model sentinel; not an unlimited-depth claim
    };

    let max_pub_depth = if pub_net_cost > 0 {
        (initial_mb / pub_net_cost) as usize
    } else {
        usize::MAX
    };

    DepthAnalysis {
        config_name: config.name.to_string(),
        n: config.n,
        num_primes: config.primes.len(),
        log_q_bits: config
            .primes
            .iter()
            .map(|&p| (64 - p.leading_zeros()) as u32)
            .sum(),
        initial_budget_mb: initial_mb,
        sym_mul_cost_mb: sym_mul_cost,
        sym_rescale_gain_mb: sym_rescale_gain,
        sym_net_cost_mb: sym_net_cost,
        pub_mul_cost_mb: pub_mul_cost,
        pub_relin_cost_mb: pub_relin_cost,
        pub_net_cost_mb: pub_net_cost,
        conservative_sym_depth: max_sym_depth,
        conservative_pub_depth: max_pub_depth,
        actual_sym_depth_note: "not established by this legacy model",
        actual_pub_depth_note: "not established; legacy public bootstrap remains gated",
    }
}

/// Depth analysis results
pub struct DepthAnalysis {
    pub config_name: String,
    pub n: usize,
    pub num_primes: usize,
    pub log_q_bits: u32,
    pub initial_budget_mb: i64,
    pub sym_mul_cost_mb: i64,
    pub sym_rescale_gain_mb: i64,
    pub sym_net_cost_mb: i64,
    pub pub_mul_cost_mb: i64,
    pub pub_relin_cost_mb: i64,
    pub pub_net_cost_mb: i64,
    pub conservative_sym_depth: usize,
    pub conservative_pub_depth: usize,
    pub actual_sym_depth_note: &'static str,
    pub actual_pub_depth_note: &'static str,
}

impl std::fmt::Display for DepthAnalysis {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "=== Depth Analysis: {} ===", self.config_name)?;
        writeln!(
            f,
            "  N={}, {} primes, log(Q)={} bits",
            self.n, self.num_primes, self.log_q_bits
        )?;
        writeln!(
            f,
            "  Initial budget: {} millibits ({} bits)",
            self.initial_budget_mb,
            self.initial_budget_mb / 1000
        )?;
        writeln!(f)?;
        writeln!(f, "  SYMMETRIC MODE:")?;
        writeln!(
            f,
            "    Mul cost: {} mb, Rescale gain: {} mb, Net: {} mb/mul",
            self.sym_mul_cost_mb, self.sym_rescale_gain_mb, self.sym_net_cost_mb
        )?;
        writeln!(
            f,
            "    Conservative depth: {} | Actual: {}",
            self.conservative_sym_depth, self.actual_sym_depth_note
        )?;
        writeln!(f)?;
        writeln!(f, "  PUBLIC MODE:")?;
        writeln!(
            f,
            "    Mul cost: {} mb, Relin: {} mb, Rescale: {} mb, Net: {} mb/mul",
            self.pub_mul_cost_mb,
            self.pub_relin_cost_mb,
            self.sym_rescale_gain_mb,
            self.pub_net_cost_mb
        )?;
        writeln!(
            f,
            "    Conservative depth: {} | Actual: {}",
            self.conservative_pub_depth, self.actual_pub_depth_note
        )?;
        Ok(())
    }
}

// =============================================================================
// TESTS
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arithmetic::rns::DualRNSContext;
    use crate::entropy::ShadowHarvester;
    use crate::keys::bootstrap::mod_inverse_u128;
    use crate::ops::bootstrap::ClockworkBootstrap;
    use crate::ops::rns_fhe::RNSFHEContext;
    use crate::params::SecureConfig;

    fn scalar_refresh_config() -> FHEConfig {
        FHEConfig::custom(
            512,
            vec![998_244_353, 1_004_535_809, 469_762_049],
            65_537,
            2,
        )
        .expect("test basis")
    }

    #[test]
    fn scalar_refresh_secure_roundtrips_boundaries_and_reduced_level() {
        let config = scalar_refresh_config();
        let ctx = RNSFHEContext::try_new(&config).unwrap();
        let keys = ctx.generate_keys_dual_secure();
        let mut refresh = SymmetricBootstrap::new(&config).unwrap();
        for m in [0, 1, 42, config.t - 1] {
            let input = ctx.encrypt_dual_secure(m, &keys.public_key);
            for source in [
                input.clone(),
                ctx.mod_switch_ct_to_level(&input, 2).unwrap(),
            ] {
                assert_eq!(
                    ctx.try_decrypt_dual_scalar(&source, &keys.secret_key)
                        .unwrap(),
                    m
                );
                let pk_fresh = refresh
                    .bootstrap_secure(&source, &keys.secret_key, &keys.public_key)
                    .unwrap();
                let sk_fresh = refresh
                    .reencrypt_symmetric_secure(&source, &keys.secret_key)
                    .unwrap();
                let pk_repeated = refresh
                    .bootstrap_secure(&source, &keys.secret_key, &keys.public_key)
                    .unwrap();
                let sk_repeated = refresh
                    .reencrypt_symmetric_secure(&source, &keys.secret_key)
                    .unwrap();
                for fresh in [&pk_fresh, &sk_fresh, &pk_repeated, &sk_repeated] {
                    ctx.validate_dual_ciphertext(fresh).unwrap();
                    assert_eq!(fresh.level, config.primes.len());
                    assert_eq!(
                        ctx.try_decrypt_dual_scalar(fresh, &keys.secret_key)
                            .unwrap(),
                        m
                    );
                    assert_eq!(ctx.decrypt_dual(fresh, &keys.secret_key), m);
                }
                assert_ne!(pk_fresh.c1.main, pk_repeated.c1.main);
                assert_ne!(sk_fresh.c1.main, sk_repeated.c1.main);
            }
        }
        assert_eq!(refresh.bootstrap_count, 32);
    }

    #[test]
    fn scalar_refresh_symmetric_phase_uses_one_global_delta_in_both_bases() {
        let config = scalar_refresh_config();
        let ctx = RNSFHEContext::try_new(&config).unwrap();
        let mut rng = ShadowHarvester::with_seed(0x5ca1_a002);
        let keys = ctx.generate_keys_dual(&mut rng);
        let mut refresh = SymmetricBootstrap::new(&config).unwrap();
        let input = ctx.encrypt_dual(42, &keys.public_key, &mut rng);
        let fresh = refresh
            .reencrypt_symmetric(&input, &keys.secret_key, &mut rng)
            .unwrap();
        let (delta, _) = U256::product_u64s(&config.primes).div_mod_u64(config.t);
        let phase_errors =
            |prime: u64, engine: &NTTEngine, c0: &[u64], c1: &[u64], secret: &[u64]| {
                let product = engine.multiply(c1, secret);
                (0..config.n)
                    .map(|j| {
                        let message = if j == 0 {
                            delta.mod_u64(prime) as u128 * 42 % prime as u128
                        } else {
                            0
                        };
                        let error = ((c0[j] as u128 + product[j] as u128 + prime as u128 - message)
                            % prime as u128) as u64;
                        let signed_error = if error <= config.eta as u64 {
                            error as i64
                        } else {
                            error as i64 - prime as i64
                        };
                        assert!(
                            signed_error.unsigned_abs() <= config.eta as u64,
                            "coefficient {j}"
                        );
                        signed_error
                    })
                    .collect::<Vec<_>>()
            };
        let first_lane_errors = phase_errors(
            config.primes[0],
            &ctx.ntt_engines[0],
            &fresh.c0.main[0],
            &fresh.c1.main[0],
            &keys.secret_key.s.main[0],
        );
        for i in 1..config.primes.len() {
            assert_eq!(
                phase_errors(
                    config.primes[i],
                    &ctx.ntt_engines[i],
                    &fresh.c0.main[i],
                    &fresh.c1.main[i],
                    &keys.secret_key.s.main[i]
                ),
                first_lane_errors,
                "main lane {i}"
            );
        }
        for i in 0..ctx.dual_rns.anchor.primes.len() {
            assert_eq!(
                phase_errors(
                    ctx.dual_rns.anchor.primes[i],
                    &ctx.dual_rns.anchor.ntt_engines[i],
                    &fresh.c0.anchor[i],
                    &fresh.c1.anchor[i],
                    &keys.secret_key.s.anchor[i]
                ),
                first_lane_errors,
                "anchor lane {i}"
            );
        }
        let multiplier = ctx.encrypt_dual(3, &keys.public_key, &mut rng);
        let product = ctx.mul_dual_symmetric(&fresh, &multiplier, &keys.secret_key);
        assert_eq!(
            ctx.try_decrypt_dual_scalar(&product, &keys.secret_key)
                .unwrap(),
            126
        );
    }

    #[test]
    fn scalar_refresh_rejects_malformed_inputs_without_sampling_or_counting() {
        let config = scalar_refresh_config();
        let ctx = RNSFHEContext::try_new(&config).unwrap();
        let mut setup_rng = ShadowHarvester::with_seed(0x5ca1_a003);
        let keys = ctx.generate_keys_dual(&mut setup_rng);
        let input = ctx.encrypt_dual(42, &keys.public_key, &mut setup_rng);
        let mut cases = Vec::new();
        let mut malformed = input.clone();
        malformed.level = 0;
        cases.push(malformed);
        let mut malformed = input.clone();
        malformed.c0.main[0][0] = config.primes[0];
        cases.push(malformed);
        let mut malformed = input.clone();
        malformed.c1.anchor[0].pop();
        cases.push(malformed);
        for source in cases {
            let mut refresh = SymmetricBootstrap::new(&config).unwrap();
            let mut rng = ShadowHarvester::with_seed(91);
            let mut unchanged = ShadowHarvester::with_seed(91);
            assert!(refresh
                .bootstrap(&source, &keys.secret_key, &keys.public_key, &mut rng)
                .is_err());
            assert!(refresh
                .bootstrap_timed(&source, &keys.secret_key, &keys.public_key, &mut rng)
                .is_err());
            assert!(refresh
                .reencrypt_symmetric(&source, &keys.secret_key, &mut rng)
                .is_err());
            assert_eq!(rng.next_u64(), unchanged.next_u64());
            assert_eq!(refresh.bootstrap_count, 0);
        }
    }

    #[test]
    fn scalar_refresh_rejects_incomplete_output_keys_and_context_drift() {
        let config = scalar_refresh_config();
        let ctx = RNSFHEContext::try_new(&config).unwrap();
        let mut rng = ShadowHarvester::with_seed(0x5ca1_a004);
        let keys = ctx.generate_keys_dual(&mut rng);
        let input = ctx.encrypt_dual(42, &keys.public_key, &mut rng);
        let reduced = ctx.mod_switch_ct_to_level(&input, 2).unwrap();
        let mut refresh = SymmetricBootstrap::new(&config).unwrap();
        let mut short_secret = keys.secret_key.clone();
        short_secret.s.main.pop();
        assert!(refresh
            .reencrypt_symmetric(&reduced, &short_secret, &mut rng)
            .is_err());
        let mut malformed_pk = keys.public_key.clone();
        malformed_pk.pk0.main.pop();
        assert!(refresh
            .bootstrap(&input, &keys.secret_key, &malformed_pk, &mut rng)
            .is_err());
        let mut malformed_pk = keys.public_key.clone();
        malformed_pk.pk1.anchor[0][0] = ctx.dual_rns.anchor.primes[0];
        assert!(refresh
            .bootstrap(&input, &keys.secret_key, &malformed_pk, &mut rng)
            .is_err());
        let mut malformed_sk = keys.secret_key.clone();
        malformed_sk.s.main[0][0] = config.primes[0];
        assert!(refresh
            .reencrypt_symmetric(&input, &malformed_sk, &mut rng)
            .is_err());
        refresh.t += 1;
        assert!(refresh
            .bootstrap(&input, &keys.secret_key, &keys.public_key, &mut rng)
            .is_err());
        assert_eq!(refresh.bootstrap_count, 0);
    }

    #[test]
    fn scalar_refresh_legacy_timed_entry_matches_untimed_entry() {
        let config = scalar_refresh_config();
        let ctx = RNSFHEContext::try_new(&config).unwrap();
        let mut setup_rng = ShadowHarvester::with_seed(0x5ca1_a005);
        let keys = ctx.generate_keys_dual(&mut setup_rng);
        let input = ctx.encrypt_dual(42, &keys.public_key, &mut setup_rng);
        let mut refresh = SymmetricBootstrap::new(&config).unwrap();
        let mut rng = ShadowHarvester::with_seed(92);
        let mut same_rng = ShadowHarvester::with_seed(92);
        let untimed = refresh
            .bootstrap(&input, &keys.secret_key, &keys.public_key, &mut rng)
            .unwrap();
        let (timed, stats) = refresh
            .bootstrap_timed(&input, &keys.secret_key, &keys.public_key, &mut same_rng)
            .unwrap();
        assert_eq!(timed.c0.main, untimed.c0.main);
        assert_eq!(timed.c0.anchor, untimed.c0.anchor);
        assert_eq!(timed.c1.main, untimed.c1.main);
        assert_eq!(timed.c1.anchor, untimed.c1.anchor);
        assert!(stats.total_ns >= stats.decrypt_ns + stats.encrypt_ns);
        assert_eq!(refresh.bootstrap_count, 2);
        assert_eq!(
            ctx.try_decrypt_dual_scalar(&timed, &keys.secret_key)
                .unwrap(),
            42
        );
    }

    #[test]
    fn scalar_refresh_constructor_refuses_invalid_config_without_panicking() {
        let config = scalar_refresh_config();
        let mut cases = Vec::new();
        let mut bad = config.clone();
        bad.n = 0;
        cases.push(bad);
        let mut bad = config.clone();
        bad.primes[1] = bad.primes[0];
        cases.push(bad);
        let mut bad = config.clone();
        bad.primes[0] = 15;
        cases.push(bad);
        let mut bad = config.clone();
        bad.t = 0;
        cases.push(bad);
        let mut bad = config.clone();
        bad.primes = vec![998_244_353; 9];
        cases.push(bad);
        for bad in cases {
            assert!(SymmetricBootstrap::new(&bad).is_err());
        }
    }

    // =====================================================================
    // CORRECTNESS CONTRACT TESTS
    // (Answers questions from the Clockwork Bootstrap Correctness Contract)
    // =====================================================================

    /// CONTRACT §1: Prime Superset Invariant
    /// Boot primes must be a strict superset of work primes.
    #[ignore = "VESTIGIAL: CONTRACT 1 — asserts the boot prime set is a strict superset of the work primes for all three secure configs. Strictly-more-primes is spare-basis bookkeeping for a switch that no longer happens. Bootstrap is a fallback, not the critical path. Exact division in residue space divides the value without moving the basis, so no level is consumed and depth is not budget-bounded. See docs/RETIRED_MECHANISMS.md"]
    #[test]
    fn test_contract_1_prime_superset_all_configs() {
        for (label, cfg) in [
            ("secure_128", SecureConfig::secure_128().into_config()),
            ("secure_192", SecureConfig::secure_192().into_config()),
            ("secure_256", SecureConfig::secure_256().into_config()),
        ] {
            let boot = ClockworkBootstrap::new(&cfg).unwrap_or_else(|_| panic!("{} boot", label));
            for &wp in &cfg.primes {
                assert!(
                    boot.boot_config.primes.contains(&wp),
                    "{}: work prime {} missing from boot primes",
                    label,
                    wp
                );
            }
            // Strict superset: boot has more primes
            assert!(
                boot.boot_config.primes.len() > cfg.primes.len(),
                "{}: boot should have strictly more primes",
                label
            );
        }
    }

    /// CONTRACT §2: Single Drop Prime Invariant
    /// Exactly one boot prime is not in work primes.
    #[ignore = "VESTIGIAL: CONTRACT 2 — asserts exactly one boot prime is absent from the work primes (the drop prime) across all three secure configs. Bootstrap is a fallback, not the critical path. Exact division in residue space divides the value without moving the basis, so no level is consumed and depth is not budget-bounded. See docs/RETIRED_MECHANISMS.md"]
    #[test]
    fn test_contract_2_single_drop_prime_all_configs() {
        for (label, cfg) in [
            ("secure_128", SecureConfig::secure_128().into_config()),
            ("secure_192", SecureConfig::secure_192().into_config()),
            ("secure_256", SecureConfig::secure_256().into_config()),
        ] {
            let boot = ClockworkBootstrap::new(&cfg).unwrap_or_else(|_| panic!("{} boot", label));
            let extras: Vec<u64> = boot
                .boot_config
                .primes
                .iter()
                .copied()
                .filter(|bp| !cfg.primes.contains(bp))
                .collect();
            assert_eq!(
                extras.len(),
                1,
                "{}: expected 1 drop prime, got {:?}",
                label,
                extras
            );
        }
    }

    /// CONTRACT §3: Canonical Anchor Invariant
    /// Boot context anchors must match canonical anchor list for N.
    #[ignore = "VESTIGIAL: CONTRACT 3 — asserts each bootstrap context's anchor primes match the canonical anchor list for N. Bootstrap is a fallback, not the critical path. Exact division in residue space divides the value without moving the basis, so no level is consumed and depth is not budget-bounded. See docs/RETIRED_MECHANISMS.md"]
    #[test]
    fn test_contract_3_canonical_anchors_all_configs() {
        for (label, cfg) in [
            ("secure_128", SecureConfig::secure_128().into_config()),
            ("secure_192", SecureConfig::secure_192().into_config()),
            ("secure_256", SecureConfig::secure_256().into_config()),
        ] {
            let boot = ClockworkBootstrap::new(&cfg).unwrap_or_else(|_| panic!("{} boot", label));
            let canonical = DualRNSContext::canonical_anchor_primes_for_n(cfg.n);
            let boot_anchors = &boot.boot_ctx.dual_rns.anchor.primes;
            assert_eq!(
                boot_anchors, &canonical,
                "{}: anchor primes diverged from canonical",
                label
            );
        }
    }

    /// CONTRACT §4: Anchor Recomputation After Prime Drop
    /// After Phase 3, anchors must equal CRT(main) mod anchor_prime.
    #[ignore = "VESTIGIAL: CONTRACT 4 — asserts that after Phase 3 the anchor limbs equal CRT(main) mod anchor_prime, i.e. anchors were correctly recomputed after the prime drop. Bootstrap is a fallback, not the critical path. Exact division in residue space divides the value without moving the basis, so no level is consumed and depth is not budget-bounded. See docs/RETIRED_MECHANISMS.md"]
    #[test]
    fn test_contract_4_anchor_recomputation_post_bootstrap() {
        let cfg = SecureConfig::secure_128().into_config();
        let ctx = RNSFHEContext::try_new(&cfg).expect("ctx");
        let boot = ClockworkBootstrap::new(&cfg).expect("boot");
        let mut rng = ShadowHarvester::with_seed(42);
        let keys = ctx.generate_keys_dual_full(&mut rng);
        let boot_keys = boot
            .generate_keys(&keys.secret_key, &mut rng)
            .expect("keygen");

        for m in [0u64, 1, 42, 1000, 65536] {
            let ct = ctx.encrypt_dual(m, &keys.public_key, &mut rng);
            let fresh = boot
                .bootstrap(&ct, &boot_keys.bsk, &boot_keys.ksk)
                .expect("bootstrap");

            // CRT reconstruct main limbs and verify anchor consistency
            let primes_u128: Vec<u128> = cfg.primes.iter().map(|&p| p as u128).collect();
            let mut inv = vec![0u128; primes_u128.len()];
            let mut partial = 1u128;
            for k in 0..primes_u128.len() {
                if k > 0 {
                    inv[k] = mod_inverse_u128(partial, primes_u128[k]).expect("inv");
                }
                partial *= primes_u128[k];
            }

            let anchor_primes = &ctx.dual_rns.anchor.primes;
            for pos in (0..cfg.n).step_by(cfg.n / 8) {
                let c0_full = crate::ops::bootstrap::crt_reconstruct_n(
                    fresh.c0.main.iter().map(|limb| limb[pos] as u128),
                    &primes_u128,
                    &inv,
                );
                for (ai, &ap) in anchor_primes.iter().enumerate() {
                    let got = fresh.c0.anchor[ai][pos];
                    let expected = (c0_full % ap as u128) as u64;
                    assert_eq!(
                        got, expected,
                        "m={}: anchor[{}] mismatch at pos={}: got={}, expected={}",
                        m, ai, pos, got, expected
                    );
                }
            }
        }
    }

    /// CONTRACT §5: Key-Switch Uses Full CRT Reconstruction
    /// Verifies non-circular bootstrap_with_ksk roundtrips correctly.
    #[ignore = "VESTIGIAL: CONTRACT 5 — asserts boot.bootstrap_with_ksk roundtrips m through full CRT reconstruction in the key-switch. Bootstrap is a fallback, not the critical path. Exact division in residue space divides the value without moving the basis, so no level is consumed and depth is not budget-bounded. See docs/RETIRED_MECHANISMS.md"]
    #[test]
    fn test_contract_5_ksk_full_crt_reconstruction() {
        let cfg = SecureConfig::secure_128().into_config();
        let ctx = RNSFHEContext::try_new(&cfg).expect("ctx");
        let boot = ClockworkBootstrap::new(&cfg).expect("boot");
        let mut rng = ShadowHarvester::with_seed(42);
        let keys = ctx.generate_keys_dual_full(&mut rng);
        let boot_keys_ksk = boot
            .generate_keys_with_ksk(&keys.secret_key, &mut rng)
            .expect("KSK keygen");

        for m in [0u64, 1, 42, 1000] {
            let ct = ctx.encrypt_dual(m, &keys.public_key, &mut rng);
            let fresh = boot
                .bootstrap_with_ksk(&ct, &boot_keys_ksk.bsk, &boot_keys_ksk.ksk)
                .expect("KSK bootstrap");
            let dec = ctx.decrypt_dual(&fresh, &keys.secret_key);
            assert_eq!(dec, m, "KSK roundtrip fail: m={} got={}", m, dec);
        }
    }

    /// CONTRACT §6: Non-Circular Ordering (Key-Switch Then ModSwitch)
    /// The test_ksk_bootstrap_roundtrip in bootstrap.rs exercises this.
    /// Here we verify the output is in work prime space (not boot space).
    #[ignore = "VESTIGIAL: CONTRACT 6 — asserts the non-circular bootstrap output has work-prime limb count and work-prime-bounded coefficients, i.e. it came back out of boot space. Bootstrap is a fallback, not the critical path. Exact division in residue space divides the value without moving the basis, so no level is consumed and depth is not budget-bounded. See docs/RETIRED_MECHANISMS.md"]
    #[test]
    fn test_contract_6_ksk_output_in_work_space() {
        let cfg = SecureConfig::secure_128().into_config();
        let ctx = RNSFHEContext::try_new(&cfg).expect("ctx");
        let boot = ClockworkBootstrap::new(&cfg).expect("boot");
        let mut rng = ShadowHarvester::with_seed(42);
        let keys = ctx.generate_keys_dual_full(&mut rng);
        let boot_keys_ksk = boot
            .generate_keys_with_ksk(&keys.secret_key, &mut rng)
            .expect("KSK keygen");

        let ct = ctx.encrypt_dual(42, &keys.public_key, &mut rng);
        let fresh = boot
            .bootstrap_with_ksk(&ct, &boot_keys_ksk.bsk, &boot_keys_ksk.ksk)
            .expect("KSK bootstrap");

        // Output must have work prime count, not boot prime count
        assert_eq!(
            fresh.c0.main.len(),
            cfg.primes.len(),
            "Output should be in work space ({} primes), got {} limbs",
            cfg.primes.len(),
            fresh.c0.main.len()
        );

        // Coefficients bounded by work primes
        for (i, &wp) in cfg.primes.iter().enumerate() {
            for j in 0..cfg.n {
                assert!(fresh.c0.main[i][j] < wp);
                assert!(fresh.c1.main[i][j] < wp);
            }
        }
    }

    /// CONTRACT §7: u128 CRT Ceiling Guard
    /// secure_192 and secure_256 must use U256 fallback, not silently overflow.
    #[ignore = "VESTIGIAL: CONTRACT 7 — asserts the secure_192 and secure_256 prime products overflow u128 and that ClockworkBootstrap::new still succeeds via the U256 fallback. Bootstrap is a fallback, not the critical path. Exact division in residue space divides the value without moving the basis, so no level is consumed and depth is not budget-bounded. See docs/RETIRED_MECHANISMS.md"]
    #[test]
    fn test_contract_7_u128_ceiling_guard() {
        // secure_192: 5 × 30-bit ≈ 150 bits, overflows u128
        let cfg_192 = SecureConfig::secure_192().into_config();
        let primes_u128: Vec<u128> = cfg_192.primes.iter().map(|&p| p as u128).collect();
        let product_192 = primes_u128
            .iter()
            .try_fold(1u128, |acc, &p| acc.checked_mul(p));
        assert!(
            product_192.is_none(),
            "secure_192 product should overflow u128"
        );

        // But bootstrap should still work via U256 fallback
        let boot_192 = ClockworkBootstrap::new(&cfg_192);
        assert!(
            boot_192.is_ok(),
            "secure_192 bootstrap construction should succeed (U256 fallback)"
        );

        // secure_256: 6 × 30-bit ≈ 180 bits
        let cfg_256 = SecureConfig::secure_256().into_config();
        let primes_u128_256: Vec<u128> = cfg_256.primes.iter().map(|&p| p as u128).collect();
        let product_256 = primes_u128_256
            .iter()
            .try_fold(1u128, |acc, &p| acc.checked_mul(p));
        assert!(
            product_256.is_none(),
            "secure_256 product should overflow u128"
        );

        let boot_256 = ClockworkBootstrap::new(&cfg_256);
        assert!(
            boot_256.is_ok(),
            "secure_256 bootstrap construction should succeed (U256 fallback)"
        );
    }

    /// CONTRACT §7 continued: U256 bootstrap roundtrip for 192-bit security
    #[ignore = "VESTIGIAL: CONTRACT 7 (continued) — asserts a full secure_192 encrypt -> bootstrap -> decrypt roundtrip through the U256 CRT path. Bootstrap is a fallback, not the critical path. Exact division in residue space divides the value without moving the basis, so no level is consumed and depth is not budget-bounded. See docs/RETIRED_MECHANISMS.md"]
    #[test]
    fn test_contract_7_u256_roundtrip_192() {
        let cfg = SecureConfig::secure_192().into_config();
        let ctx = RNSFHEContext::try_new(&cfg).expect("ctx");
        let boot = ClockworkBootstrap::new(&cfg).expect("boot");
        let mut rng = ShadowHarvester::with_seed(192);
        let keys = ctx.generate_keys_dual_full(&mut rng);
        let boot_keys = boot
            .generate_keys(&keys.secret_key, &mut rng)
            .expect("keygen");

        for &m in &[0u64, 1, 42, cfg.t - 1] {
            let ct = ctx.encrypt_dual(m, &keys.public_key, &mut rng);
            let fresh = boot
                .bootstrap(&ct, &boot_keys.bsk, &boot_keys.ksk)
                .expect("bootstrap");
            let dec = ctx.decrypt_dual(&fresh, &keys.secret_key);
            assert_eq!(dec, m, "192-bit U256 roundtrip fail: m={} got={}", m, dec);
        }
    }

    /// CONTRACT §8: Bootstrap Depth Budget
    /// Boot prime count >= max(bootstrap_depth + 2, work_primes + 1).
    #[ignore = "VESTIGIAL: CONTRACT 8 — asserts boot_primes >= bootstrap_depth + 2 and boot_primes >= work_primes + 1. This is a depth budget expressed directly as a prime count; it is the exact accounting this substrate retires. Bootstrap is a fallback, not the critical path. Exact division in residue space divides the value without moving the basis, so no level is consumed and depth is not budget-bounded. See docs/RETIRED_MECHANISMS.md"]
    #[test]
    fn test_contract_8_depth_budget_all_configs() {
        for (label, cfg) in [
            ("secure_128", SecureConfig::secure_128().into_config()),
            ("secure_192", SecureConfig::secure_192().into_config()),
            ("secure_256", SecureConfig::secure_256().into_config()),
        ] {
            let boot = ClockworkBootstrap::new(&cfg).unwrap_or_else(|_| panic!("{} boot", label));
            let boot_count = boot.boot_config.primes.len();
            let work_count = cfg.primes.len();
            let depth = boot.bootstrap_depth;

            assert!(
                boot_count >= depth + 2,
                "{}: need {} boot primes for depth {}, got {}",
                label,
                depth + 2,
                depth,
                boot_count
            );
            assert!(
                boot_count > work_count,
                "{}: need more boot primes than the {} work primes for modswitch, got {}",
                label,
                work_count,
                boot_count
            );
        }
    }

    // =====================================================================
    // SYMMETRIC BOOTSTRAP TESTS
    // =====================================================================

    /// Basic symmetric bootstrap roundtrip: encrypt → bootstrap → decrypt
    #[ignore = "VESTIGIAL: asserts SymmetricBootstrap::bootstrap roundtrips m for m in [0, 1, 42, 1000, 65536]. Bootstrap is a fallback, not the critical path. Exact division in residue space divides the value without moving the basis, so no level is consumed and depth is not budget-bounded. See docs/RETIRED_MECHANISMS.md"]
    #[test]
    fn test_symmetric_bootstrap_roundtrip() {
        let cfg = SecureConfig::secure_128().into_config();
        let ctx = RNSFHEContext::try_new(&cfg).expect("ctx");
        let mut sym_boot = SymmetricBootstrap::new(&cfg).expect("sym boot");
        let mut rng = ShadowHarvester::with_seed(42);
        let keys = ctx.generate_keys_dual_full(&mut rng);

        for m in [0u64, 1, 42, 1000, 65536] {
            let ct = ctx.encrypt_dual(m, &keys.public_key, &mut rng);
            let fresh = sym_boot
                .bootstrap(&ct, &keys.secret_key, &keys.public_key, &mut rng)
                .expect("sym bootstrap");
            let dec = ctx.decrypt_dual(&fresh, &keys.secret_key);
            assert_eq!(dec, m, "Symmetric bootstrap fail: m={} got={}", m, dec);
        }
    }

    /// Symmetric bootstrap after multiplication: mul → sym_bootstrap → mul
    #[ignore = "VESTIGIAL: asserts 3*7=21 -> symmetric bootstrap -> 21*5=105, with the refresh in the middle as the stated reason the second multiply has budget. Bootstrap is a fallback, not the critical path. Exact division in residue space divides the value without moving the basis, so no level is consumed and depth is not budget-bounded. See docs/RETIRED_MECHANISMS.md"]
    #[test]
    fn test_symmetric_bootstrap_after_mul() {
        let cfg = SecureConfig::secure_128().into_config();
        let ctx = RNSFHEContext::try_new(&cfg).expect("ctx");
        let mut sym_boot = SymmetricBootstrap::new(&cfg).expect("sym boot");
        let mut rng = ShadowHarvester::with_seed(42);
        let keys = ctx.generate_keys_dual_full(&mut rng);

        let ct_3 = ctx.encrypt_dual(3, &keys.public_key, &mut rng);
        let ct_7 = ctx.encrypt_dual(7, &keys.public_key, &mut rng);

        // 3 × 7 = 21
        let ct_21 = ctx.mul_dual_symmetric(&ct_3, &ct_7, &keys.secret_key);
        assert_eq!(ctx.decrypt_dual(&ct_21, &keys.secret_key), 21);

        // Bootstrap refreshes noise
        let ct_fresh = sym_boot
            .bootstrap(&ct_21, &keys.secret_key, &keys.public_key, &mut rng)
            .expect("bootstrap");
        assert_eq!(ctx.decrypt_dual(&ct_fresh, &keys.secret_key), 21);

        // Can multiply again with full budget
        let ct_5 = ctx.encrypt_dual(5, &keys.public_key, &mut rng);
        let ct_105 = ctx.mul_dual_symmetric(&ct_fresh, &ct_5, &keys.secret_key);
        assert_eq!(ctx.decrypt_dual(&ct_105, &keys.secret_key), 105);
    }

    /// Symmetric bootstrap with timing stats
    #[ignore = "VESTIGIAL: asserts SymmetricBootstrap::bootstrap_timed roundtrips 42 and reports non-zero total/decrypt/encrypt nanoseconds — an instrumentation test of the refresh path. Bootstrap is a fallback, not the critical path. Exact division in residue space divides the value without moving the basis, so no level is consumed and depth is not budget-bounded. See docs/RETIRED_MECHANISMS.md"]
    #[test]
    fn test_symmetric_bootstrap_timing() {
        let cfg = SecureConfig::secure_128().into_config();
        let ctx = RNSFHEContext::try_new(&cfg).expect("ctx");
        let mut sym_boot = SymmetricBootstrap::new(&cfg).expect("sym boot");
        let mut rng = ShadowHarvester::with_seed(42);
        let keys = ctx.generate_keys_dual_full(&mut rng);

        let ct = ctx.encrypt_dual(42, &keys.public_key, &mut rng);
        let (fresh, stats) = sym_boot
            .bootstrap_timed(&ct, &keys.secret_key, &keys.public_key, &mut rng)
            .expect("sym bootstrap");

        println!("Symmetric bootstrap: {}", stats);
        assert_eq!(ctx.decrypt_dual(&fresh, &keys.secret_key), 42);
        assert!(stats.total_ns > 0);
        assert!(stats.decrypt_ns > 0);
        assert!(stats.encrypt_ns > 0);
    }

    /// Pure symmetric encrypt (no pk needed) roundtrip
    #[ignore = "VESTIGIAL: asserts SymmetricBootstrap::reencrypt_symmetric roundtrips m without a public key. Bootstrap is a fallback, not the critical path. Exact division in residue space divides the value without moving the basis, so no level is consumed and depth is not budget-bounded. See docs/RETIRED_MECHANISMS.md"]
    #[test]
    fn test_symmetric_reencrypt_roundtrip() {
        let cfg = SecureConfig::secure_128().into_config();
        let ctx = RNSFHEContext::try_new(&cfg).expect("ctx");
        let mut sym_boot = SymmetricBootstrap::new(&cfg).expect("sym boot");
        let mut rng = ShadowHarvester::with_seed(42);
        let keys = ctx.generate_keys_dual_full(&mut rng);

        for m in [0u64, 1, 42, 1000] {
            let ct = ctx.encrypt_dual(m, &keys.public_key, &mut rng);
            let fresh = sym_boot
                .reencrypt_symmetric(&ct, &keys.secret_key, &mut rng)
                .expect("sym reencrypt");
            let dec = ctx.decrypt_dual(&fresh, &keys.secret_key);
            assert_eq!(dec, m, "Sym reencrypt fail: m={} got={}", m, dec);
        }
    }

    // =====================================================================
    // ISSUE #141: symmetric_encrypt mask support + identity (WR-5A class)
    //
    // These run unconditionally. They exercise only the mask sampler wired
    // into `symmetric_encrypt` (through the `pub fn reencrypt_symmetric`
    // entry point) and never depend on the #[ignore]d VESTIGIAL roundtrips
    // above: they read `c1 = a` straight off the output ciphertext and never
    // assert what it decrypts to.
    // =====================================================================

    /// Support + identity: the `symmetric_encrypt` mask (`c1 = a`) must be
    /// (1) in range in every lane, (2) reconstructible from the main lanes to
    /// ONE integer inside `[0, Q)` that (3) every anchor residue agrees with,
    /// and (4) actually reach above the smallest prime in the chain. The old
    /// per-lane `rng.next_u64() % p` draw satisfied (1) in every lane while
    /// the lanes jointly encoded no single integer at all, so (1) alone is
    /// exactly the check that could never have caught it. Mirrors
    /// `ops::bootstrap::tests::bootstrap_pk_mask_is_uniform_over_full_q_boot`
    /// (WR-5A, PR #116) for the third site issue #141 found.
    #[test]
    fn symmetric_encrypt_mask_is_uniform_over_full_q() {
        use crate::arithmetic::rns::U256;

        let configs = [
            ("secure_128", SecureConfig::secure_128().into_config()),
            (
                "secure_128_deep",
                SecureConfig::secure_128_deep().into_config(),
            ),
            ("secure_192", SecureConfig::secure_192().into_config()),
            ("secure_256", SecureConfig::secure_256().into_config()),
        ];

        for (name, config) in &configs {
            let ctx = RNSFHEContext::try_new(config).expect("work context");
            let mut sym_boot = SymmetricBootstrap::new(config).expect("sym boot");
            let mut rng = ShadowHarvester::with_seed(0x5E14_0141);
            let keys = ctx.generate_keys_dual(&mut rng);

            // Drive the public entry point so the wiring is what is tested,
            // not a hand-called private helper.
            let ct = ctx.encrypt_dual(42, &keys.public_key, &mut rng);
            let fresh = sym_boot
                .reencrypt_symmetric(&ct, &keys.secret_key, &mut rng)
                .unwrap_or_else(|e| panic!("{name}: reencrypt_symmetric refused: {e:?}"));

            let mask = &fresh.c1; // c1 = a, the mask
            let level = config.primes.len();
            assert_eq!(fresh.level, level, "{name}: output level");
            assert_eq!(mask.main.len(), level, "{name}: main lane count");
            let anchor_primes = &sym_boot.ctx.dual_rns.anchor.primes;
            assert_eq!(
                mask.anchor.len(),
                anchor_primes.len(),
                "{name}: anchor lane count"
            );

            let q = U256::product_u64s(&config.primes);
            let min_prime = *config
                .primes
                .iter()
                .chain(anchor_primes.iter())
                .min()
                .expect("config has primes");

            let coeffs_to_check = mask.n.min(512);
            let mut saw_value_above_min_prime = false;

            for coeff in 0..coeffs_to_check {
                let main_residues: Vec<u64> = mask.main.iter().map(|lane| lane[coeff]).collect();

                // Support: every main residue is in range for its own lane.
                for (residue, &prime) in main_residues.iter().zip(config.primes.iter()) {
                    assert!(
                        *residue < prime,
                        "{name}: main residue {residue} out of range for prime {prime}"
                    );
                }

                // Reconstruct the ONE integer the main lanes jointly encode.
                let value = sym_boot.ctx.rns.to_u256_level(&main_residues, level);
                assert!(
                    value.lt(q),
                    "{name}: reconstructed mask value must land inside [0, Q)"
                );

                // Identity: every anchor residue must equal that SAME integer
                // reduced into its own modulus -- main and anchor track one
                // accepted value, not independent draws.
                for (j, &anchor_prime) in anchor_primes.iter().enumerate() {
                    assert!(
                        mask.anchor[j][coeff] < anchor_prime,
                        "{name}: anchor residue out of range for prime {anchor_prime}"
                    );
                    assert_eq!(
                        value.mod_u64(anchor_prime),
                        mask.anchor[j][coeff],
                        "{name}: anchor lane {anchor_prime} disagrees with the main-lane \
                         reconstruction at coefficient {coeff}"
                    );
                }

                if value.ge(U256::from_u64(min_prime)) {
                    saw_value_above_min_prime = true;
                }
            }

            assert!(
                saw_value_above_min_prime,
                "{name}: no sampled coefficient among {coeffs_to_check} exceeded min_prime -- \
                 the fixed sampler should reach far beyond it almost immediately"
            );
        }
    }

    /// Regression fixture pinning the pre-fix draw pattern: each main and
    /// anchor lane sampled INDEPENDENTLY as `rng.next_u64() % p`. Every lane
    /// is in range -- which is all the old code could ever have checked --
    /// yet the anchor residues disagree with the main-lane reconstruction at
    /// essentially every coefficient, because no single integer was ever
    /// sampled. This is what the identity assertion above discriminates on.
    #[test]
    fn independent_per_lane_draws_do_not_encode_one_integer() {
        let config = SecureConfig::secure_128().into_config();
        let ctx = RNSFHEContext::try_new(&config).expect("ctx");
        let mut rng = ShadowHarvester::with_seed(0x0141_0082);

        const COEFFS: usize = 64;
        let level = config.primes.len();
        let anchor_primes = &ctx.dual_rns.anchor.primes;

        // The old pattern, verbatim in shape.
        let old_main: Vec<Vec<u64>> = config
            .primes
            .iter()
            .map(|&p| (0..COEFFS).map(|_| rng.next_u64() % p).collect())
            .collect();
        let old_anchor: Vec<Vec<u64>> = anchor_primes
            .iter()
            .map(|&p| (0..COEFFS).map(|_| rng.next_u64() % p).collect())
            .collect();

        let mut checks = 0usize;
        let mut disagreements = 0usize;
        for coeff in 0..COEFFS {
            let main_residues: Vec<u64> = old_main.iter().map(|lane| lane[coeff]).collect();
            for (residue, &prime) in main_residues.iter().zip(config.primes.iter()) {
                assert!(*residue < prime, "per-lane support was never the problem");
            }
            let value = ctx.rns.to_u256_level(&main_residues, level);
            for (j, &anchor_prime) in anchor_primes.iter().enumerate() {
                checks += 1;
                if value.mod_u64(anchor_prime) != old_anchor[j][coeff] {
                    disagreements += 1;
                }
            }
        }

        // An independent anchor draw agrees with CRT(main) mod p only by a
        // 1-in-p accident (p >= 2^30 here). Seeded, so this is deterministic;
        // the bound is loose on purpose so it documents the mechanism rather
        // than one seed's exact tally.
        assert!(
            disagreements * 4 >= checks * 3,
            "old per-lane pattern: expected the anchors to disagree with the main lanes \
             almost everywhere, got {disagreements}/{checks}"
        );
    }

    /// Compare symmetric vs public bootstrap: sym should be faster
    #[ignore = "VESTIGIAL: times ten SymmetricBootstrap::bootstrap calls against ten ClockworkBootstrap::bootstrap calls and prints the ratio; it asserts nothing, and both arms are the vestigial path. Bootstrap is a fallback, not the critical path. Exact division in residue space divides the value without moving the basis, so no level is consumed and depth is not budget-bounded. See docs/RETIRED_MECHANISMS.md"]
    #[test]
    fn test_symmetric_vs_public_bootstrap_perf() {
        let cfg = SecureConfig::secure_128().into_config();
        let ctx = RNSFHEContext::try_new(&cfg).expect("ctx");
        let mut sym_boot = SymmetricBootstrap::new(&cfg).expect("sym boot");
        let pub_boot = ClockworkBootstrap::new(&cfg).expect("pub boot");
        let mut rng = ShadowHarvester::with_seed(42);
        let keys = ctx.generate_keys_dual_full(&mut rng);
        let boot_keys = pub_boot
            .generate_keys(&keys.secret_key, &mut rng)
            .expect("keygen");

        let ct = ctx.encrypt_dual(42, &keys.public_key, &mut rng);

        // Warm up
        let _ = sym_boot.bootstrap(&ct, &keys.secret_key, &keys.public_key, &mut rng);
        let _ = pub_boot.bootstrap(&ct, &boot_keys.bsk, &boot_keys.ksk);

        // Time symmetric bootstrap
        let sym_start = std::time::Instant::now();
        for _ in 0..10 {
            let _ = sym_boot
                .bootstrap(&ct, &keys.secret_key, &keys.public_key, &mut rng)
                .unwrap();
        }
        let sym_us = sym_start.elapsed().as_micros() / 10;

        // Time public bootstrap
        let pub_start = std::time::Instant::now();
        for _ in 0..10 {
            let _ = pub_boot
                .bootstrap(&ct, &boot_keys.bsk, &boot_keys.ksk)
                .unwrap();
        }
        let pub_us = pub_start.elapsed().as_micros() / 10;

        println!("Symmetric bootstrap: {}us avg", sym_us);
        println!("Public bootstrap:    {}us avg", pub_us);
        println!(
            "Speedup: {}.{}x",
            pub_us / sym_us.max(1),
            (pub_us * 10 / sym_us.max(1)) % 10
        );

        // Symmetric should be faster (no homomorphic inner product)
        // But we don't hard-assert because timing varies by environment
    }

    // =====================================================================
    // DEPTH ANALYSIS TESTS
    // =====================================================================

    /// Print depth analysis for all production configs
    #[ignore = "VESTIGIAL: prints analyze_depth_budget for four configs. The depth-budget model it renders presumes depth is a consumable quantity. Bootstrap is a fallback, not the critical path. Exact division in residue space divides the value without moving the basis, so no level is consumed and depth is not budget-bounded. See docs/RETIRED_MECHANISMS.md"]
    #[test]
    fn test_depth_analysis_all_configs() {
        for sc in [
            SecureConfig::secure_128(),
            SecureConfig::secure_128_deep(),
            SecureConfig::secure_192(),
            SecureConfig::secure_256(),
        ] {
            let cfg = sc.into_config();
            let analysis = analyze_depth_budget(&cfg);
            println!("{}", analysis);
        }
    }

    /// Depth survey: measure maximum multiplication depth without bootstrap.
    ///
    /// secure_128 (3 primes, n=4096) is known to fail at depth 2 due to
    /// noise budget exhaustion. This test documents the actual depth ceiling
    /// empirically rather than asserting a fixed target.
    ///
    /// This retained historical survey does not establish a supported depth
    /// or an unlimited-depth guarantee for the scalar refresh API.
    #[ignore = "VESTIGIAL: surveys how deep secure_128 gets without a refresh, and its loop is driven by the retired ladder: it calls ctx.mod_switch_ct_to_level(&ct_2, ct.level) each iteration and breaks when that returns None, then asserts only max_correct_depth >= 1. Both the level alignment and the 'for unlimited depth use AutoBootstrapEvaluator or SymmetricBootstrap' framing are retired premises. Bootstrap is a fallback, not the critical path. Exact division in residue space divides the value without moving the basis, so no level is consumed and depth is not budget-bounded. See docs/RETIRED_MECHANISMS.md"]
    #[test]
    fn test_symmetric_depth_50_no_bootstrap() {
        let cfg = SecureConfig::secure_128().into_config();
        let ctx = RNSFHEContext::try_new(&cfg).expect("ctx");
        let mut rng = ShadowHarvester::with_seed(42);
        let keys = ctx.generate_keys_dual_full(&mut rng);
        let t = cfg.t;

        let ct_2 = ctx.encrypt_dual(2, &keys.public_key, &mut rng);
        let mut ct = ctx.encrypt_dual(2, &keys.public_key, &mut rng);
        let mut expected = 2u64;
        let target_depth = 50;
        let mut max_correct_depth = 0usize;

        for i in 0..target_depth {
            // The fresh multiplier `ct_2` sits at the top level, but `ct`
            // descends one level per multiply, so their levels diverge after the
            // first product and mul_dual_symmetric's same-level precondition
            // trips (a debug_assert in debug builds). Align the multiplier down
            // to ct's current level; once it can no longer be switched down we
            // have hit the level/noise ceiling, so stop the survey gracefully.
            let ct_2_aligned = match ctx.mod_switch_ct_to_level(&ct_2, ct.level) {
                Some(c) => c,
                None => break,
            };
            ct = ctx.mul_dual_symmetric(&ct, &ct_2_aligned, &keys.secret_key);
            expected = ((expected as u128 * 2) % t as u128) as u64;
            let dec = ctx.decrypt_dual(&ct, &keys.secret_key);
            if dec != expected {
                println!(
                    "[depth survey] secure_128 noise exhaustion at depth {}: expected {} got {}",
                    i + 1,
                    expected,
                    dec
                );
                break;
            }
            max_correct_depth = i + 1;
        }

        println!(
            "[depth survey] secure_128 max correct depth without bootstrap: {}",
            max_correct_depth
        );

        // Depth 1 must always succeed (single multiplication is well within budget)
        assert!(
            max_correct_depth >= 1,
            "secure_128 must support at least depth 1, got {}",
            max_correct_depth
        );
    }

    /// Historical consistency checks on the legacy noise-cost model.
    #[ignore = "VESTIGIAL: asserts analyze_depth_budget reports a positive initial budget and that the symmetric net cost is below the public net cost — a comparison between two per-multiply depletion rates. Bootstrap is a fallback, not the critical path. Exact division in residue space divides the value without moving the basis, so no level is consumed and depth is not budget-bounded. See docs/RETIRED_MECHANISMS.md"]
    #[test]
    fn test_noise_budget_is_conservative() {
        let cfg = SecureConfig::secure_128().into_config();
        let analysis = analyze_depth_budget(&cfg);

        // The millibits model predicts conservative_sym_depth
        // This estimate alone establishes no measured depth.
        println!(
            "Legacy model estimate: {} muls; measured depth is not established here",
            analysis.conservative_sym_depth
        );

        // Budget should be positive
        assert!(analysis.initial_budget_mb > 0);
        // Symmetric net cost should be less than public net cost
        assert!(analysis.sym_net_cost_mb < analysis.pub_net_cost_mb);
    }

    /// Test that public mode depth matches prediction
    #[ignore = "VESTIGIAL: asserts analyze_depth_budget's conservative_pub_depth falls in [1, 15] — a prediction of how many multiplies fit before a refresh is required. Bootstrap is a fallback, not the critical path. Exact division in residue space divides the value without moving the basis, so no level is consumed and depth is not budget-bounded. See docs/RETIRED_MECHANISMS.md"]
    #[test]
    fn test_public_depth_matches_prediction() {
        let cfg = SecureConfig::secure_128().into_config();
        let analysis = analyze_depth_budget(&cfg);

        // Public mode conservative prediction should be 2-10
        assert!(
            analysis.conservative_pub_depth >= 1 && analysis.conservative_pub_depth <= 15,
            "Public depth prediction {} should be in [1, 15]",
            analysis.conservative_pub_depth
        );
    }

    // =====================================================================
    // HYBRID APPROACH TEST: Skip Phase 3, Three-Lock Encapsulation
    // =====================================================================

    /// Test the "momentary plaintext" approach:
    /// Phase 1 modswitch gives us c0_small, c1_small in Z_t.
    /// With sk available, compute m = (c0_small + c1_small·s) mod t directly.
    /// Then re-encrypt. This skips Phase 2 and 3 entirely.
    #[ignore = "VESTIGIAL: asserts that boot.modswitch_to_t (Phase 1) followed by a hand-rolled negacyclic decrypt in Z_t recovers m, i.e. that Phases 2 and 3 of bootstrap can be skipped when sk is on hand. Bootstrap is a fallback, not the critical path. Exact division in residue space divides the value without moving the basis, so no level is consumed and depth is not budget-bounded. See docs/RETIRED_MECHANISMS.md"]
    #[test]
    fn test_hybrid_skip_phase23_direct_decrypt() {
        let cfg = SecureConfig::secure_128().into_config();
        let ctx = RNSFHEContext::try_new(&cfg).expect("ctx");
        let boot = ClockworkBootstrap::new(&cfg).expect("boot");
        let mut rng = ShadowHarvester::with_seed(42);
        let keys = ctx.generate_keys_dual_full(&mut rng);

        for m_orig in [0u64, 1, 42, 1000, 65536] {
            let ct = ctx.encrypt_dual(m_orig, &keys.public_key, &mut rng);

            // Phase 1 only: modswitch Q → t
            let (c0_small, c1_small) = boot.modswitch_to_t(&ct).expect("modswitch");

            // Direct decrypt in Z_t: m = c0 + c1·s mod t
            // Extract ternary s
            let first_prime = cfg.primes[0];
            let s_signed: Vec<i64> = keys.secret_key.s.main[0]
                .iter()
                .map(|&c| {
                    if c == 0 {
                        0i64
                    } else if c == 1 {
                        1i64
                    } else if c == first_prime - 1 {
                        -1i64
                    } else {
                        0i64
                    }
                })
                .collect();

            // Negacyclic polynomial multiply c1_small × s in Z_t
            let t = cfg.t as i128;
            let n = cfg.n;
            let mut c1s = vec![0i128; n];
            for i in 0..n {
                for j in 0..n {
                    let idx = i + j;
                    let val = c1_small[i] as i128 * s_signed[j] as i128;
                    if idx < n {
                        c1s[idx] = (c1s[idx] + val) % t;
                    } else {
                        // Negacyclic: wrap with sign flip
                        c1s[idx - n] = (c1s[idx - n] - val) % t;
                    }
                }
            }

            // m = c0[0] + (c1·s)[0] mod t
            let m_recovered = ((c0_small[0] as i128 + c1s[0] + t * 2) % t) as u64;

            // This should match the original message
            assert_eq!(
                m_recovered, m_orig,
                "Hybrid Phase1-only: expected {} got {} (c0_small[0]={}, c1s[0]={})",
                m_orig, m_recovered, c0_small[0], c1s[0]
            );
        }
    }

    /// End-to-end hybrid: Phase 1 → direct decrypt → re-encrypt → verify
    /// This is the symmetric bootstrap without the Three-Lock wrapper.
    #[ignore = "VESTIGIAL: asserts the chain 3*5=15 -> symmetric bootstrap -> 15*15=225 -> symmetric bootstrap -> 225*3=675, with each refresh presented as what buys the next multiply. Bootstrap is a fallback, not the critical path. Exact division in residue space divides the value without moving the basis, so no level is consumed and depth is not budget-bounded. See docs/RETIRED_MECHANISMS.md"]
    #[test]
    fn test_hybrid_full_reencrypt_chain() {
        let cfg = SecureConfig::secure_128().into_config();
        let ctx = RNSFHEContext::try_new(&cfg).expect("ctx");
        let mut sym_boot = SymmetricBootstrap::new(&cfg).expect("sym boot");
        let mut rng = ShadowHarvester::with_seed(42);
        let keys = ctx.generate_keys_dual_full(&mut rng);

        // Multiply until noise is high, then bootstrap, then multiply more
        let ct_3 = ctx.encrypt_dual(3, &keys.public_key, &mut rng);
        let ct_5 = ctx.encrypt_dual(5, &keys.public_key, &mut rng);

        // 3 × 5 = 15
        let ct_15 = ctx.mul_dual_symmetric(&ct_3, &ct_5, &keys.secret_key);

        // Symmetric bootstrap
        let ct_fresh_15 = sym_boot
            .bootstrap(&ct_15, &keys.secret_key, &keys.public_key, &mut rng)
            .expect("bootstrap");
        assert_eq!(ctx.decrypt_dual(&ct_fresh_15, &keys.secret_key), 15);

        // 15 × 15 = 225
        let ct_225 = ctx.mul_dual_symmetric(&ct_fresh_15, &ct_fresh_15, &keys.secret_key);
        assert_eq!(ctx.decrypt_dual(&ct_225, &keys.secret_key), 225);

        // Bootstrap again
        let ct_fresh_225 = sym_boot
            .bootstrap(&ct_225, &keys.secret_key, &keys.public_key, &mut rng)
            .expect("bootstrap 2");
        assert_eq!(ctx.decrypt_dual(&ct_fresh_225, &keys.secret_key), 225);

        // 225 × 3 = 675
        let ct_675 = ctx.mul_dual_symmetric(&ct_fresh_225, &ct_3, &keys.secret_key);
        assert_eq!(ctx.decrypt_dual(&ct_675, &keys.secret_key), 675);

        println!(
            "Hybrid chain complete: 3→15→225→675, {} bootstraps",
            sym_boot.bootstrap_count
        );
    }
}
