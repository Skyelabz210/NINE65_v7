//! Known Answer Tests (KAT) for QMNF FHE
//!
//! Provides deterministic test vectors for verifying correctness
//! across versions and platforms.
//!
//! # Purpose
//!
//! - Regression testing: Ensure updates don't break existing functionality
//! - Cross-platform: Verify identical results on different systems
//! - Compliance: Support certification requirements
//!
//! # Usage
//!
//! ```ignore
//! use qmnf_fhe::kat::{run_all_kats, KATResult};
//!
//! let results = run_all_kats();
//! assert!(results.all_passed());
//! ```

#[cfg(feature = "ntt_fft")]
use crate::arithmetic::NTTEngineFFT as NTTEngine;

#[cfg(not(feature = "ntt_fft"))]
use crate::arithmetic::NTTEngine;
use crate::entropy::ShadowHarvester;
use crate::keys::KeySet;
use crate::ops::encrypt::{BFVDecryptor, BFVEncoder, BFVEncryptor};
use crate::params::FHEConfig;
use sha2::{Digest, Sha256};

/// Known Answer Test vector
#[derive(Debug, Clone)]
pub struct KATVector {
    /// Test name
    pub name: &'static str,
    /// Seed for deterministic generation
    pub seed: u64,
    /// Ring dimension
    pub n: usize,
    /// Ciphertext modulus
    pub q: u64,
    /// Plaintext modulus
    pub t: u64,
    /// Input plaintext
    pub plaintext: u64,
    /// Expected decrypted result
    pub expected_result: u64,
    /// Operation type
    pub operation: KATOperation,
}

/// Type of KAT operation
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KATOperation {
    /// Encrypt then decrypt
    EncryptDecrypt,
    /// Encrypt, add, decrypt
    HomomorphicAdd { addend: u64 },
    /// Encrypt, multiply by plain, decrypt
    MulPlain { multiplier: u64 },
    /// Encrypt two values, add ciphertexts, decrypt
    CtCtAdd { other: u64 },
}

/// Result of a KAT run
#[derive(Debug)]
pub struct KATResult {
    pub name: String,
    pub passed: bool,
    pub expected: u64,
    pub actual: u64,
    pub ct_hash: Option<[u8; 32]>,
}

/// Standard KAT vectors for QMNF FHE
pub const STANDARD_KATS: &[KATVector] = &[
    // Basic encrypt/decrypt
    KATVector {
        name: "encrypt_decrypt_zero",
        seed: 0xDEADBEEF,
        n: 1024,
        q: 998244353,
        t: 2053,
        plaintext: 0,
        expected_result: 0,
        operation: KATOperation::EncryptDecrypt,
    },
    KATVector {
        name: "encrypt_decrypt_one",
        seed: 0xDEADBEEF,
        n: 1024,
        q: 998244353,
        t: 2053,
        plaintext: 1,
        expected_result: 1,
        operation: KATOperation::EncryptDecrypt,
    },
    KATVector {
        name: "encrypt_decrypt_42",
        seed: 0xDEADBEEF,
        n: 1024,
        q: 998244353,
        t: 2053,
        plaintext: 42,
        expected_result: 42,
        operation: KATOperation::EncryptDecrypt,
    },
    KATVector {
        name: "encrypt_decrypt_max",
        seed: 0xDEADBEEF,
        n: 1024,
        q: 998244353,
        t: 2053,
        plaintext: 2052, // t - 1
        expected_result: 2052,
        operation: KATOperation::EncryptDecrypt,
    },
    // Homomorphic addition with plaintext
    KATVector {
        name: "add_plain_100_plus_50",
        seed: 0x12345678,
        n: 1024,
        q: 998244353,
        t: 2053,
        plaintext: 100,
        expected_result: 150,
        operation: KATOperation::HomomorphicAdd { addend: 50 },
    },
    // Multiply by plaintext
    KATVector {
        name: "mul_plain_17_times_3",
        seed: 0x87654321,
        n: 1024,
        q: 998244353,
        t: 2053,
        plaintext: 17,
        expected_result: 51,
        operation: KATOperation::MulPlain { multiplier: 3 },
    },
    // Ciphertext-ciphertext addition
    KATVector {
        name: "ct_ct_add_25_plus_75",
        seed: 0xCAFEBABE,
        n: 1024,
        q: 998244353,
        t: 2053,
        plaintext: 25,
        expected_result: 100,
        operation: KATOperation::CtCtAdd { other: 75 },
    },
    // Different seed (should still work)
    KATVector {
        name: "encrypt_decrypt_different_seed",
        seed: 0x11111111,
        n: 1024,
        q: 998244353,
        t: 2053,
        plaintext: 123,
        expected_result: 123,
        operation: KATOperation::EncryptDecrypt,
    },
];

/// Run a single KAT vector
pub fn run_kat(kat: &KATVector) -> KATResult {
    // Create deterministic config
    let config = FHEConfig::custom(
        kat.n,
        vec![kat.q],
        kat.t,
        2, // eta
    )
    .expect("Invalid KAT config");

    let ntt = NTTEngine::new(config.q, config.n);
    let mut harvester = ShadowHarvester::with_seed(kat.seed);

    // Generate keys
    let keys = KeySet::generate(&config, &ntt, &mut harvester);

    // Setup encoder/encryptor/decryptor
    let encoder = BFVEncoder::new(&config);
    let encryptor = BFVEncryptor::new(&keys.public_key, &encoder, &ntt, config.eta);
    let decryptor = BFVDecryptor::new(&keys.secret_key, &encoder, &ntt);

    // Fresh harvester for encryption
    let mut enc_harvester = ShadowHarvester::with_seed(kat.seed.wrapping_add(1));

    // Execute operation
    let (actual, ct_hash) = match kat.operation {
        KATOperation::EncryptDecrypt => {
            let ct = encryptor.encrypt(kat.plaintext, &mut enc_harvester);
            let hash = hash_ciphertext(&ct.c0.coeffs);
            let result = decryptor.decrypt(&ct);
            (result, Some(hash))
        }
        KATOperation::HomomorphicAdd { addend } => {
            use crate::ops::homomorphic::BFVEvaluator;
            let evaluator = BFVEvaluator::new(&ntt, &encoder, Some(&keys.eval_key));

            let ct = encryptor.encrypt(kat.plaintext, &mut enc_harvester);
            let ct_sum = evaluator.add_plain(&ct, addend);
            let result = decryptor.decrypt(&ct_sum);
            (result, None)
        }
        KATOperation::MulPlain { multiplier } => {
            use crate::ops::homomorphic::BFVEvaluator;
            let evaluator = BFVEvaluator::new(&ntt, &encoder, Some(&keys.eval_key));

            let ct = encryptor.encrypt(kat.plaintext, &mut enc_harvester);
            let ct_prod = evaluator.mul_plain(&ct, multiplier);
            let result = decryptor.decrypt(&ct_prod);
            (result, None)
        }
        KATOperation::CtCtAdd { other } => {
            use crate::ops::homomorphic::BFVEvaluator;
            let evaluator = BFVEvaluator::new(&ntt, &encoder, Some(&keys.eval_key));

            let ct1 = encryptor.encrypt(kat.plaintext, &mut enc_harvester);
            let ct2 = encryptor.encrypt(other, &mut enc_harvester);
            let ct_sum = evaluator.add(&ct1, &ct2);
            let result = decryptor.decrypt(&ct_sum);
            (result, None)
        }
    };

    KATResult {
        name: kat.name.to_string(),
        passed: actual == kat.expected_result,
        expected: kat.expected_result,
        actual,
        ct_hash,
    }
}

/// Run all standard KAT vectors
pub fn run_all_kats() -> Vec<KATResult> {
    STANDARD_KATS.iter().map(run_kat).collect()
}

/// Check if all KATs passed
pub fn all_kats_passed() -> bool {
    run_all_kats().iter().all(|r| r.passed)
}

/// Hash ciphertext coefficients for fingerprinting
fn hash_ciphertext(coeffs: &[u64]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    for &c in coeffs {
        hasher.update(c.to_le_bytes());
    }
    hasher.finalize().into()
}

/// Print KAT results
pub fn print_kat_results(results: &[KATResult]) {
    println!("╔═══════════════════════════════════════════════════════════════╗");
    println!("║                    QMNF FHE Known Answer Tests                ║");
    println!("╠═══════════════════════════════════════════════════════════════╣");

    let mut passed = 0;
    let mut failed = 0;

    for result in results {
        let status = if result.passed {
            "✓ PASS"
        } else {
            "✗ FAIL"
        };
        let status_color = if result.passed { "" } else { " <!>" };

        println!("║ {:6} │ {:<40}{}", status, result.name, status_color);

        if !result.passed {
            println!(
                "║        │   Expected: {}, Got: {}",
                result.expected, result.actual
            );
            failed += 1;
        } else {
            passed += 1;
        }
    }

    println!("╠═══════════════════════════════════════════════════════════════╣");
    println!(
        "║ Results: {} passed, {} failed                                  ║",
        passed, failed
    );
    println!("╚═══════════════════════════════════════════════════════════════╝");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_all_kats() {
        let results = run_all_kats();
        print_kat_results(&results);

        let failed: Vec<_> = results.iter().filter(|r| !r.passed).collect();
        assert!(
            failed.is_empty(),
            "KATs failed: {:?}",
            failed.iter().map(|r| &r.name).collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_kat_deterministic() {
        // Run same KAT twice, verify identical results
        let kat = &STANDARD_KATS[0];

        let result1 = run_kat(kat);
        let result2 = run_kat(kat);

        assert_eq!(
            result1.actual, result2.actual,
            "KATs should be deterministic"
        );
        assert_eq!(
            result1.ct_hash, result2.ct_hash,
            "Ciphertext hashes should match"
        );
    }

    #[test]
    fn test_kat_encrypt_decrypt() {
        for kat in STANDARD_KATS
            .iter()
            .filter(|k| matches!(k.operation, KATOperation::EncryptDecrypt))
        {
            let result = run_kat(kat);
            assert!(
                result.passed,
                "KAT {} failed: expected {}, got {}",
                kat.name, kat.expected_result, result.actual
            );
        }
    }

    #[test]
    fn test_kat_homomorphic_ops() {
        for kat in STANDARD_KATS
            .iter()
            .filter(|k| !matches!(k.operation, KATOperation::EncryptDecrypt))
        {
            let result = run_kat(kat);
            assert!(
                result.passed,
                "KAT {} failed: expected {}, got {}",
                kat.name, kat.expected_result, result.actual
            );
        }
    }
}
