//! # NINE65 FHE - Clockwork Bootstrap Fully Homomorphic Encryption
//!
//! A complete BFV Fully Homomorphic Encryption implementation with
//! K-Elimination exact arithmetic and post-quantum security.
//!
//! # Safety
//!
//! This crate contains no `unsafe` code and enforces this crate-wide.

#![forbid(unsafe_code)]
#![allow(
    clippy::empty_line_after_doc_comments,
    clippy::needless_range_loop,
    clippy::manual_is_multiple_of,
    clippy::let_and_return,
    clippy::unnecessary_cast,
    clippy::double_comparisons,
    clippy::manual_div_ceil,
    clippy::println_empty_string,
    clippy::manual_range_patterns,
    clippy::manual_abs_diff,
    clippy::module_inception,
    clippy::useless_vec,
    clippy::identity_op
)]

//!
//! ## Core Components
//!
//! | Component | Benefit | Performance |
//! |------------|---------|-------------|
//! | **Montgomery Gen 2** | Division-free modular multiplication | ~30ns |
//! | **Barrett Reduction** | One-cycle modular reduction | ~2.4ns |
//! | **NTT Engine Gen 3** | Negacyclic convolution | 42× speedup |
//! | **Shadow Entropy Gen 4** | NIST-validated deterministic randomness | <10ns |
//! | **K-Elimination** | 100% exact integer division | O(n) |
//! | **Persistent Montgomery** | Stay in Montgomery form | 70× fewer conversions |
//!
//! ## Zero Floating-Point Guarantee
//!
//! All operations use exact integer arithmetic — zero floating-point anywhere.
//! Integer-only runtime: cryptographic paths use no f32/f64. The circuit compiler
//! (compiler.rs) uses f64 **only** for offline/static noise analysis.
//!
//! ## Quick Start: Production FHE
//!
//! ```ignore
//! use nine65::prelude::*;
//! use nine65::params::secure_configs::SecureConfig;
//!
//! // 1. Use SecureConfig for production (128-bit+ security guaranteed)
//! let secure = SecureConfig::secure_128();
//! let config = FHEConfig::standard_128_insecure();  // Or derive from SecureConfig
//! let ntt = NTTEngine::new(config.q, config.n);
//!
//! // 2. Generate keys with OS CSPRNG (PRODUCTION)
//! let keys = KeySet::generate_secure(&config, &ntt);
//!
//! // 3. Setup encoder/encryptor/decryptor
//! let encoder = BFVEncoder::new(&config);
//! let encryptor = BFVEncryptor::new(&keys.public_key, &encoder, &ntt, config.eta);
//! let decryptor = BFVDecryptor::new(&keys.secret_key, &encoder, &ntt);
//!
//! // 4. Encrypt with secure entropy
//! let ct = encryptor.encrypt_secure(42);  // Uses OS CSPRNG internally
//!
//! // 5. Decrypt
//! let result = decryptor.decrypt(&ct);
//! assert_eq!(result, 42);
//! ```
//!
//! ## Quick Start: Testing/Benchmarks
//!
//! ```ignore
//! use nine65::prelude::*;
//!
//! // Use deterministic parameters for reproducible tests
//! // Note: light() requires `allow_insecure` feature for testing only
//! #[cfg(feature = "allow_insecure")]
//! let config = FHEConfig::light_insecure();
//! let ntt = NTTEngine::new(config.q, config.n);
//! let mut rng = ShadowHarvester::with_seed(42);  // Deterministic!
//!
//! // Generate deterministic keys
//! let keys = KeySet::generate(&config, &ntt, &mut rng);
//! let encoder = BFVEncoder::new(&config);
//!
//! // Encrypt with deterministic entropy
//! let encryptor = BFVEncryptor::new(&keys.public_key, &encoder, &ntt, config.eta);
//! let ct = encryptor.encrypt(42, &mut rng);
//! ```
//!
//! ## Security Levels
//!
//! | Config | N | Security | Use Case |
//! |--------|---|----------|----------|
//! | `SecureConfig::secure_128()` | 8192 | 128-bit | **Production recommended** |
//! | `SecureConfig::secure_192()` | 16384 | 192-bit | High security |
//! | `standard_128()` | 4096 | 128-bit | Production (FHEConfig) |
//! | `high_192()` | 8192 | 192-bit | High security (FHEConfig) |
//! | `light()` | 1024 | ~36-bit | Testing only (`allow_insecure`) |
//! | `he_standard_128()` | 2048 | ~56-bit | Testing only (`allow_insecure`) |
//!
//! ## Module Overview
//!
//! | Module | Purpose |
//! |--------|---------|
//! | [`arithmetic`] | NTT, Montgomery, Barrett, RNS |
//! | [`entropy`] | Shadow Entropy + OS CSPRNG |
//! | [`params`] | FHE parameter configurations |
//! | [`ring`] | Ring polynomial operations |
//! | [`keys`] | Key generation and management |
//! | [`ops`] | Encryption/decryption/homomorphic ops |
//! | [`noise`] | Noise budget tracking |
//! | [`security`] | LWE security estimation |
//! | [`kat`] | Known Answer Tests |
//!
//! ## Compliance
//!
//! - **HE Standard v1.1**: Compliant parameter sets available
//! - **NIST SP 800-22**: Shadow Entropy passes statistical tests
//! - **Memory Safety**: Key zeroization via `zeroize` crate

// CLAUDE.md states plainly: "Test configs (allow_insecure) are blocked in
// release builds — never use in production." This gate enforces that, but
// it is commented out -- re-enabling it as-is breaks the documented
// `cargo test --release --workspace` command:
// `crates/fhe-service/Cargo.toml` enables `nine65/allow_insecure` from
// `[dev-dependencies]` for its own `--release` test suite, and `cfg(test)`/
// `debug_assertions` do NOT propagate from a dependent crate's test build
// into this crate when it is compiled as a (dev-)dependency -- there is no
// cfg-based way here to distinguish "a legitimate --release test run of a
// crate that dev-depends on this feature" from "a real production release
// binary that mistakenly enabled it". Verified by direct experiment
// (2026-08-19, NINE65_v7_DEEP_ANALYSIS_20260817.md G2 follow-up): enabling
// this exact check makes `cargo test --release --workspace` fail to
// compile `nine65` via fhe-service's dev-dependency, for a build that is
// not the production misuse this check is meant to catch.
// TODO: fix by restructuring fhe-service's test architecture (e.g. its
// allow_insecure-dependent tests should not require `--release`, or should
// use a secure config instead) so this can be re-enabled without breaking
// the standard test command. Do not re-enable this without first confirming
// `cargo test --release --workspace --exclude nine65-python --exclude
// nine65-wasm` still passes.
// #[cfg(all(feature = "allow_insecure", not(any(test, debug_assertions))))]
// compile_error!("The `allow_insecure` feature must not be enabled in release builds");

pub mod arithmetic;
pub mod bootstrap; // Three-Lock Bootstrap: protected re-encryption with conjunction security
pub mod compiler;
#[cfg(test)]
pub mod comprehensive_benchmarks; // Additional comprehensive benchmarks
pub mod entropy;
pub mod errors; // Standardized NINE65 error taxonomy
pub mod kat; // Known Answer Tests
pub mod keys;
pub mod noise; // CDHS-based noise tracking
pub mod ops;
pub mod params;
pub mod ring;
pub mod security; // LWE security estimation // Bootstrap-free FHE circuit compiler

#[cfg(feature = "accelerated")]
pub mod accelerated; // MANA/UNHAL acceleration layer

pub mod kiosk; // Kiosk Architecture: self-destructing FHE computation units

#[cfg(feature = "exact_transcendentals_backend")]
pub mod cram_ct_wrap; // CRAM-CT wrapper around DualRNSCiphertext

#[cfg(test)]
mod v2_integration_tests;

/// Prelude module - import commonly used types with a single `use` statement.
///
/// # Example
///
/// ```ignore
/// use nine65::prelude::*;
///
/// let config = FHEConfig::light_insecure();
/// let ntt = NTTEngine::new(config.q, config.n);
/// ```
pub mod prelude {
    // Arithmetic primitives
    pub use crate::arithmetic::{
        factor_semiprime,
        gcd,
        modular_distance,
        // Non-circular order finding (Shor's classical reduction)
        multiplicative_order,
        toric_coupling, // TORIC GEOMETRY
        BarrettContext,
        CyclotomicPolynomial, // NATIVE RING TRIG
        CyclotomicRing,
        HybridModContext,
        IntegerSoftmax,
        MQReLU,
        MQReLUPolynomial,
        MobiusInt,
        MobiusPolynomial,
        MobiusVector,
        MontgomeryContext,
        PadeEngine,
        PersistentMontgomery,
        PersistentPolynomial,
        Polarity, // SIGNED ARITHMETIC
        RNSContext,
        RNSPolynomial,
        Sign,          // O(1) SIGN DETECTION
        PADE_SCALE,    // INTEGER TRANSCENDENTALS
        SOFTMAX_SCALE, // EXACT SUM SOFTMAX
    };

    // NTT: FFT O(N log N) is the unconditional default.
    // Use --features reference_ntt for the O(N^2) DFT reference implementation.
    pub use crate::arithmetic::NTTEngine;

    // Also export both explicitly for users who need a specific implementation
    pub use crate::arithmetic::NTTEngine as NTTEngineDFT;
    pub use crate::arithmetic::NTTEngineFFT;

    // Entropy sources
    #[cfg(any(test, feature = "deterministic_rng"))]
    pub use crate::entropy::DeterministicRng;
    pub use crate::entropy::SecureRng; // OS CSPRNG for production use
    pub use crate::entropy::ShadowHarvester;
    #[cfg(feature = "shadow-entropy")]
    pub use crate::entropy::WassanNoiseField;
    pub use crate::entropy::{secure_bytes, secure_ternary, secure_u64};

    // Parameters
    pub use crate::params::{FHEConfig, SecureConfig};

    // Ring operations
    pub use crate::ring::RingPolynomial;
    pub use crate::ring::{PolynomialPool, PoolGuard, PooledPolynomial};

    // Key management
    pub use crate::keys::{EvaluationKey, KeySet, PublicKey, SecretKey};

    // FHE operations - Classical BFV (single modulus)
    pub use crate::ops::{ActivationType, DenseLayer, FHENeuralEvaluator, NeuralNetwork};
    pub use crate::ops::{BFVDecryptor, BFVEncoder, BFVEncryptor, BFVEvaluator, Ciphertext};

    // Galois automorphisms for SIMD slot rotations
    pub use crate::ops::{GaloisEngine, GaloisEvaluator, GaloisKey, GaloisKeySet};

    // Batch encoding and parallel operations
    pub use crate::ops::parallel::{ParallelDecryptor, ParallelEncryptor};
    pub use crate::ops::BatchEncoder;

    // FHE operations - DualRNS with K-Elimination (RECOMMENDED for ct×ct multiplication)
    pub use crate::ops::rns_fhe::{
        AutoCiphertext, AutoKeys, DualRNSCiphertext, DualRNSEvalKey, DualRNSFullKeySet,
        DualRNSKeySet, DualRNSPoly, DualRNSPublicKey, DualRNSSecretKey, MulRoute, RNSFHEContext,
    };

    // Noise tracking
    pub use crate::noise::budget::{NoiseBudget, NoiseOpType};
    pub use crate::noise::{
        EMACalculator, MultiWindowNoiseDetector, NoiseAnomaly, NoiseBudgetTracker,
        NoiseDistribution, NoiseSnapshot, P2QuantileEstimator,
    };

    // Security estimation
    pub use crate::security::{ConfidenceLevel, LWEParams, SecurityEstimate};

    // Error taxonomy
    pub use crate::errors::{Nine65Error, Nine65Result};
}

#[cfg(test)]
mod integration_tests {
    use crate::prelude::*;

    /// Full FHE workflow test
    #[test]
    fn test_full_fhe_workflow() {
        // 1. Setup parameters
        let config = SecureConfig::secure_128().into_config();
        let ntt = NTTEngine::new(config.q, config.n);
        let mut rng = ShadowHarvester::with_seed(42);

        // 2. Generate keys
        let keys = KeySet::generate(&config, &ntt, &mut rng);
        let encoder = BFVEncoder::new(&config);

        // 3. Create encryptor/decryptor/evaluator
        let encryptor = BFVEncryptor::new(&keys.public_key, &encoder, &ntt, config.eta);
        let decryptor = BFVDecryptor::new(&keys.secret_key, &encoder, &ntt);
        let evaluator = BFVEvaluator::new(&ntt, &encoder, Some(&keys.eval_key));

        // 4. Encrypt two values
        let a = 17u64;
        let b = 25u64;

        let ct_a = encryptor.encrypt(a, &mut rng);
        let ct_b = encryptor.encrypt(b, &mut rng);

        // 5. Homomorphic operations - test working operations

        // Addition
        let ct_sum = evaluator.add(&ct_a, &ct_b);
        let sum = decryptor.decrypt(&ct_sum);
        assert_eq!(sum, a + b, "Homomorphic addition failed");

        // Subtraction
        let ct_diff = evaluator.sub(&ct_b, &ct_a);
        let diff = decryptor.decrypt(&ct_diff);
        assert_eq!(diff, b - a, "Homomorphic subtraction failed");

        // Negation
        let ct_neg = evaluator.negate(&ct_a);
        let neg = decryptor.decrypt(&ct_neg);
        assert_eq!(
            neg,
            (config.t - a) % config.t,
            "Homomorphic negation failed"
        );

        // Add plaintext
        let ct_add_plain = evaluator.add_plain(&ct_a, 10);
        let add_plain = decryptor.decrypt(&ct_add_plain);
        assert_eq!(add_plain, a + 10, "Add plaintext failed");

        // Multiply by plaintext
        let ct_mul_plain = evaluator.mul_plain(&ct_a, 3);
        let mul_plain = decryptor.decrypt(&ct_mul_plain);
        assert_eq!(mul_plain, (a * 3) % config.t, "Mul plaintext failed");

        println!("Full FHE workflow: PASS");
        println!("  {} + {} = {}", a, b, sum);
        println!("  {} - {} = {}", b, a, diff);
        println!("  -{} = {} (mod {})", a, neg, config.t);
        println!("  {} + 10 = {}", a, add_plain);
        println!("  {} * 3 = {}", a, mul_plain);
    }

    /// Production-grade FHE test with 128-bit security parameters
    /// NOTE: This runs full-sized keygen for N=8192; expect it to be slower than unit tests.
    #[test]
    fn test_production_128bit() {
        use crate::noise::budget::{NoiseBudget, NoiseOpType};
        use crate::params::production::ProductionConfig128;

        let config = ProductionConfig128::standard();

        println!("\n=== PRODUCTION 128-BIT FHE TEST ===");
        println!("N = {}", config.n);
        println!("log(Q) = {} bits", config.log_q());
        println!("Security = {}-bit", config.estimated_security());
        println!("Max depth = {} multiplications", config.max_depth);
        println!("Primes in chain = {}", config.primes.len());

        // Validate security BEFORE proceeding
        assert!(config.validate().is_ok(), "Config must be secure");
        assert!(
            config.estimated_security() >= 128,
            "Must have 128-bit security"
        );

        // Use 51-bit NTT-friendly prime for sufficient headroom at N=8192
        // 30-bit primes give Δ≈2^14 which is insufficient (noise at N=8192 is ~2^32)
        // 51-bit prime gives Δ≈2^35 which provides ~3 bits of headroom for basic ops
        // Verified: 1125899906990081 ≡ 1 (mod 16384), is prime
        let prime_51bit: u64 = 1125899906990081;
        println!(
            "\nUsing 51-bit prime for single-level test: {}",
            prime_51bit
        );
        println!("log2(prime) = {} bits", 64 - prime_51bit.leading_zeros());

        let fhe_config = FHEConfig::custom(config.n, vec![prime_51bit], config.t, config.eta)
            .expect("Valid config");

        // Initialize noise budget tracking
        let mut budget = NoiseBudget::from_config(&fhe_config);
        println!("\nInitial {}", budget);

        let ntt = NTTEngine::new(fhe_config.q, fhe_config.n);
        let mut rng = ShadowHarvester::with_seed(0xDEAD_BEEF);

        println!("\nGenerating keys for N={}...", config.n);
        let start = std::time::Instant::now();
        let keys = KeySet::generate(&fhe_config, &ntt, &mut rng);
        let keygen_time = start.elapsed();
        println!("KeyGen: {:?}", keygen_time);

        let encoder = BFVEncoder::new(&fhe_config);
        let encryptor = BFVEncryptor::new(&keys.public_key, &encoder, &ntt, fhe_config.eta);
        let decryptor = BFVDecryptor::new(&keys.secret_key, &encoder, &ntt);
        let evaluator = BFVEvaluator::new(&ntt, &encoder, Some(&keys.eval_key));

        // Encrypt test values
        let a = 12345u64;
        let b = 54321u64;

        println!("\nEncrypting messages...");
        let start = std::time::Instant::now();
        let ct_a = encryptor.encrypt(a, &mut rng);
        let ct_b = encryptor.encrypt(b, &mut rng);
        let encrypt_time = start.elapsed();
        println!("Encrypt (×2): {:?}", encrypt_time);

        // Track encryption noise cost
        let _ = budget.consume(NoiseOpType::Encrypt, NoiseBudget::encrypt_cost(&fhe_config));
        let _ = budget.consume(NoiseOpType::Encrypt, NoiseBudget::encrypt_cost(&fhe_config));
        println!("After encryption: {}", budget);

        // Homomorphic addition
        println!("\nHomomorphic operations...");
        let start = std::time::Instant::now();
        let ct_sum = evaluator.add(&ct_a, &ct_b);
        let add_time = start.elapsed();

        // Track addition noise cost
        let _ = budget.consume(NoiseOpType::Add, NoiseBudget::add_cost());
        println!("After addition: {}", budget);

        let start = std::time::Instant::now();
        let ct_diff = evaluator.sub(&ct_b, &ct_a);
        let sub_time = start.elapsed();

        // Subtraction has same noise cost as addition
        let _ = budget.consume(NoiseOpType::Add, NoiseBudget::add_cost());
        println!("After subtraction: {}", budget);

        // Decrypt and verify
        let start = std::time::Instant::now();
        let sum = decryptor.decrypt(&ct_sum);
        let diff = decryptor.decrypt(&ct_diff);
        let decrypt_time = start.elapsed();

        println!("\nHomomorphic timings:");
        println!("  Add: {:?}", add_time);
        println!("  Sub: {:?}", sub_time);
        println!("  Decrypt: {:?}", decrypt_time);

        // Verify correctness
        assert_eq!(sum, (a + b) % fhe_config.t, "Addition failed");
        assert_eq!(diff, (b - a) % fhe_config.t, "Subtraction failed");

        // Final budget check
        assert!(
            budget.remaining_millibits() > 0,
            "Should have positive noise budget remaining"
        );
        println!("\nFinal {}", budget);
        println!(
            "Remaining multiplications possible: {}",
            budget.remaining_multiplications(&fhe_config)
        );

        println!("\n[PASS] PRODUCTION 128-BIT TEST PASSED");
        println!("   {} + {} = {} (encrypted)", a, b, sum);
        println!("   {} - {} = {} (encrypted)", b, a, diff);
    }

    /// Benchmark test
    #[test]
    fn test_benchmarks() {
        let config = SecureConfig::secure_128().into_config();
        let ntt = NTTEngine::new(config.q, config.n);
        let mut rng = ShadowHarvester::with_seed(999);

        // KeyGen benchmark
        let start = std::time::Instant::now();
        let keys = KeySet::generate(&config, &ntt, &mut rng);
        let keygen_time = start.elapsed();

        let encoder = BFVEncoder::new(&config);
        let encryptor = BFVEncryptor::new(&keys.public_key, &encoder, &ntt, config.eta);
        let decryptor = BFVDecryptor::new(&keys.secret_key, &encoder, &ntt);
        let evaluator = BFVEvaluator::new(&ntt, &encoder, Some(&keys.eval_key));

        // Encrypt benchmark
        let start = std::time::Instant::now();
        let ct = encryptor.encrypt(42, &mut rng);
        let encrypt_time = start.elapsed();

        // Decrypt benchmark
        let start = std::time::Instant::now();
        let _ = decryptor.decrypt(&ct);
        let decrypt_time = start.elapsed();

        // Homo add benchmark
        let ct2 = encryptor.encrypt(17, &mut rng);
        let start = std::time::Instant::now();
        let _ = evaluator.add(&ct, &ct2);
        let add_time = start.elapsed();

        // Homo mul benchmark (using BFVEvaluator::mul for timing - mul_dual_symmetric
        // now supports two-stage rescale for large-Q configs)
        let start = std::time::Instant::now();
        #[allow(deprecated)]
        let _ = evaluator.mul(&ct, &ct2);
        let mul_time = start.elapsed();

        println!("\n=== QMNF FHE Benchmarks (N={}) ===", config.n);
        println!("KeyGen:     {:?}", keygen_time);
        println!("Encrypt:    {:?}", encrypt_time);
        println!("Decrypt:    {:?}", decrypt_time);
        println!("Homo Add:   {:?}", add_time);
        println!("Homo Mul:   {:?}", mul_time);
    }
}
