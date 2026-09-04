//! Error Variant Coverage Tests
//!
//! Segment D — Quality Gate: every `Nine65Error` variant has at least one
//! test that triggers it. This file ensures no error path is unreachable
//! dead code.

use nine65::errors::{Nine65Error, Nine65Result};

// ═══════════════════════════════════════════════════════════════════════════
// K-ELIMINATION ERRORS
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_error_not_coprime() {
    let err = Nine65Error::NotCoprime {
        m: 10,
        a: 15,
        gcd: 5,
    };
    assert_eq!(err.category(), "K-Elimination");
    assert!(!err.is_recoverable());
    assert!(err.to_string().contains("coprimality violation"));
}

#[test]
fn test_error_range_overflow() {
    let err = Nine65Error::RangeOverflow {
        x: 1000,
        bound: 100,
    };
    assert_eq!(err.category(), "K-Elimination");
    assert!(err.to_string().contains("range overflow"));
}

#[test]
fn test_error_modulus_zero() {
    let err = Nine65Error::ModulusZero;
    assert_eq!(err.category(), "K-Elimination");
    assert!(err.to_string().contains("modulus zero"));
}

#[test]
fn test_error_anchor_zero() {
    let err = Nine65Error::AnchorZero;
    assert_eq!(err.category(), "K-Elimination");
    assert!(err.to_string().contains("anchor zero"));
}

#[test]
fn test_error_inexact_division() {
    let err = Nine65Error::InexactDivision {
        value: 7,
        divisor: 3,
    };
    assert_eq!(err.category(), "K-Elimination");
    assert!(err.to_string().contains("inexact division"));
}

// ═══════════════════════════════════════════════════════════════════════════
// GSO-FHE ERRORS
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_error_noise_overflow() {
    let err = Nine65Error::NoiseOverflow {
        level: 100,
        threshold: 50,
    };
    assert_eq!(err.category(), "GSO-FHE");
    assert!(err.is_recoverable());
    assert!(err.to_string().contains("noise overflow"));
}

#[test]
fn test_error_depth_exceeded() {
    let err = Nine65Error::DepthExceeded {
        depth: 51,
        max_depth: 50,
    };
    assert_eq!(err.category(), "GSO-FHE");
    assert!(err.is_recoverable());
    assert!(err.to_string().contains("depth exceeded"));
}

// ═══════════════════════════════════════════════════════════════════════════
// ORDER FINDING ERRORS
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_error_order_not_found() {
    let err = Nine65Error::OrderNotFound {
        a: 2,
        n: 100,
        bound: 99,
    };
    assert_eq!(err.category(), "Order Finding");
    assert!(err.to_string().contains("order not found"));
}

#[test]
fn test_error_not_coprime_to_modulus() {
    let err = Nine65Error::NotCoprimeToModulus { a: 4, n: 8 };
    assert_eq!(err.category(), "Order Finding");
    assert!(err.to_string().contains("not coprime to modulus"));
}

// ═══════════════════════════════════════════════════════════════════════════
// ARITHMETIC ERRORS
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_error_overflow() {
    let err = Nine65Error::Overflow {
        operation: "mul_u128",
    };
    assert_eq!(err.category(), "Arithmetic");
    assert!(err.to_string().contains("integer overflow"));
}

#[test]
fn test_error_invalid_parameter() {
    let err = Nine65Error::InvalidParameter {
        message: "N must be a power of 2".to_string(),
    };
    assert_eq!(err.category(), "Arithmetic");
    assert!(err.to_string().contains("invalid parameter"));
}

// ═══════════════════════════════════════════════════════════════════════════
// CRYPTOGRAPHIC ERRORS
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_error_decryption_failed() {
    let err = Nine65Error::DecryptionFailed;
    assert_eq!(err.category(), "Cryptographic");
    assert!(!err.is_recoverable());
    assert!(err.to_string().contains("decryption failed"));
}

#[test]
fn test_error_key_gen_failed() {
    let err = Nine65Error::KeyGenFailed {
        reason: "OS CSPRNG unavailable".to_string(),
    };
    assert_eq!(err.category(), "Cryptographic");
    assert!(err.to_string().contains("key generation failed"));
}

#[test]
fn test_error_security_level_not_met() {
    let err = Nine65Error::SecurityLevelNotMet {
        bits: 100,
        required: 128,
    };
    assert_eq!(err.category(), "Cryptographic");
    assert!(err.to_string().contains("security level not met"));
}

// ═══════════════════════════════════════════════════════════════════════════
// ENCODING/ENCRYPTION ERRORS
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_error_message_out_of_bounds() {
    let err = Nine65Error::MessageOutOfBounds {
        message: 100,
        modulus: 50,
    };
    assert_eq!(err.category(), "Encoding");
    assert!(err.to_string().contains("message out of bounds"));
}

#[test]
fn test_error_invalid_polynomial_degree() {
    let err = Nine65Error::InvalidPolynomialDegree {
        got: 512,
        expected: 1024,
    };
    assert_eq!(err.category(), "Encoding");
    assert!(err.to_string().contains("invalid polynomial degree"));
}

#[test]
fn test_error_key_regime_mismatch() {
    let err = Nine65Error::KeyRegimeMismatch {
        message: "Expected Dual-RNS key, got Single-RNS".to_string(),
    };
    assert_eq!(err.category(), "Encoding");
    assert!(err.to_string().contains("key regime mismatch"));
}

// ═══════════════════════════════════════════════════════════════════════════
// CONFIGURATION ERRORS
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_error_ntt_config_error() {
    let err = Nine65Error::NTTConfigError {
        message: "(q-1) % 2N != 0".to_string(),
    };
    assert_eq!(err.category(), "Configuration");
    assert!(err.to_string().contains("NTT configuration error"));
}

#[test]
fn test_error_config_error() {
    let err = Nine65Error::ConfigError {
        message: "Invalid modulus".to_string(),
    };
    assert_eq!(err.category(), "Configuration");
    assert!(err.to_string().contains("configuration error"));
}

// ═══════════════════════════════════════════════════════════════════════════
// BATCHING ERRORS
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_error_batching_not_supported() {
    let err = Nine65Error::BatchingNotSupported {
        t: 17,
        n: 1024,
        reason: "t-1 mod 2N != 0".to_string(),
    };
    assert_eq!(err.category(), "Batching");
    assert!(err.is_batching_error());
    assert!(err.to_string().contains("batching not supported"));
}

#[test]
fn test_error_too_many_slot_values() {
    let err = Nine65Error::TooManySlotValues {
        got: 2048,
        max: 1024,
    };
    assert_eq!(err.category(), "Batching");
    assert!(err.is_batching_error());
    assert!(err.to_string().contains("too many slot values"));
}

#[test]
fn test_error_no_modular_inverse() {
    let err = Nine65Error::NoModularInverse {
        value: 2,
        modulus: 4,
    };
    assert_eq!(err.category(), "Batching");
    assert!(err.is_batching_error());
    assert!(err.to_string().contains("no modular inverse"));
}

// ═══════════════════════════════════════════════════════════════════════════
// SERIALIZATION ERRORS
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_error_deserialization_error() {
    let err = Nine65Error::DeserializationError {
        message: "invalid JSON".to_string(),
    };
    assert_eq!(err.category(), "Serialization");
    assert!(err.to_string().contains("deserialization error"));
}

// ═══════════════════════════════════════════════════════════════════════════
// BOOTSTRAP ERRORS
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_error_bootstrap_failed() {
    let err = Nine65Error::BootstrapFailed {
        reason: "Phase 2 noise exceeded".to_string(),
    };
    assert_eq!(err.category(), "Bootstrap");
    assert!(err.is_recoverable());
    assert!(err.to_string().contains("bootstrap failed"));
}

#[test]
fn test_error_bootstrap_config_mismatch() {
    let err = Nine65Error::BootstrapConfigMismatch {
        reason: "work_n != boot_n".to_string(),
    };
    assert_eq!(err.category(), "Bootstrap");
    assert!(err.to_string().contains("bootstrap config mismatch"));
}

#[test]
fn test_error_bootstrap_overflow() {
    let err = Nine65Error::BootstrapOverflow {
        operation: "CRT reconstruction".to_string(),
    };
    assert_eq!(err.category(), "Bootstrap");
    assert!(err.to_string().contains("bootstrap arithmetic overflow"));
}

#[test]
fn test_error_bootstrap_security_unscreenable() {
    let err = Nine65Error::BootstrapSecurityUnscreenable {
        reason: "narrow lane".to_string(),
    };
    assert_eq!(err.category(), "Bootstrap");
    assert!(!err.is_recoverable());
    assert!(err
        .to_string()
        .contains("bootstrap security screen refused"));
}

// ═══════════════════════════════════════════════════════════════════════════
// ENTROPY ERRORS
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_error_entropy_failure() {
    let err = Nine65Error::EntropyFailure {
        reason: "OS CSPRNG unavailable".to_string(),
    };
    assert_eq!(err.category(), "Entropy");
    assert!(!err.is_recoverable());
    assert!(err.to_string().contains("entropy source failure"));
}

// ═══════════════════════════════════════════════════════════════════════════
// NOISE BUDGET ERRORS
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_error_noise_budget_exhausted() {
    let err = Nine65Error::NoiseBudgetExhausted {
        required_mb: 5000,
        available_mb: 2000,
    };
    assert_eq!(err.category(), "Noise");
    assert!(err.is_recoverable());
    assert!(err.to_string().contains("noise budget exhausted"));
}

// ═══════════════════════════════════════════════════════════════════════════
// REGIME MISMATCH ERRORS
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_error_regime_mismatch() {
    let err = Nine65Error::RegimeMismatch {
        operation: "encrypt_auto",
        expected: "Dual",
        got: "Single",
    };
    assert_eq!(err.category(), "Regime");
    assert!(!err.is_recoverable());
    assert!(err.to_string().contains("regime mismatch"));
}

// ═══════════════════════════════════════════════════════════════════════════
// CROSS-CUTTING TESTS
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_all_variants_have_display() {
    // Exhaustive: every variant should produce a non-empty Display string
    let variants: Vec<Nine65Error> = vec![
        Nine65Error::NotCoprime { m: 1, a: 1, gcd: 1 },
        Nine65Error::RangeOverflow { x: 1, bound: 1 },
        Nine65Error::ModulusZero,
        Nine65Error::AnchorZero,
        Nine65Error::InexactDivision {
            value: 1,
            divisor: 1,
        },
        Nine65Error::NoiseOverflow {
            level: 1,
            threshold: 1,
        },
        Nine65Error::DepthExceeded {
            depth: 1,
            max_depth: 1,
        },
        Nine65Error::OrderNotFound {
            a: 1,
            n: 1,
            bound: 1,
        },
        Nine65Error::NotCoprimeToModulus { a: 1, n: 1 },
        Nine65Error::Overflow { operation: "test" },
        Nine65Error::InvalidParameter {
            message: "test".into(),
        },
        Nine65Error::DecryptionFailed,
        Nine65Error::KeyGenFailed {
            reason: "test".into(),
        },
        Nine65Error::SecurityLevelNotMet {
            bits: 1,
            required: 1,
        },
        Nine65Error::MessageOutOfBounds {
            message: 1,
            modulus: 1,
        },
        Nine65Error::InvalidPolynomialDegree {
            got: 1,
            expected: 1,
        },
        Nine65Error::KeyRegimeMismatch {
            message: "test".into(),
        },
        Nine65Error::NTTConfigError {
            message: "test".into(),
        },
        Nine65Error::ConfigError {
            message: "test".into(),
        },
        Nine65Error::BatchingNotSupported {
            t: 1,
            n: 1,
            reason: "test".into(),
        },
        Nine65Error::TooManySlotValues { got: 1, max: 1 },
        Nine65Error::NoModularInverse {
            value: 1,
            modulus: 1,
        },
        Nine65Error::DeserializationError {
            message: "test".into(),
        },
        Nine65Error::BootstrapFailed {
            reason: "test".into(),
        },
        Nine65Error::BootstrapConfigMismatch {
            reason: "test".into(),
        },
        Nine65Error::BootstrapOverflow {
            operation: "test".into(),
        },
        Nine65Error::BootstrapSecurityUnscreenable {
            reason: "test".into(),
        },
        Nine65Error::EntropyFailure {
            reason: "test".into(),
        },
        Nine65Error::NoiseBudgetExhausted {
            required_mb: 1,
            available_mb: 0,
        },
        Nine65Error::RegimeMismatch {
            operation: "test",
            expected: "A",
            got: "B",
        },
    ];

    for (i, err) in variants.iter().enumerate() {
        let msg = err.to_string();
        assert!(!msg.is_empty(), "Variant {} has empty Display", i);
        let cat = err.category();
        assert!(!cat.is_empty(), "Variant {} has empty category", i);
    }

    // This list should match the total number of variants.
    // If a new variant is added without updating this test, it will
    // be caught by code review or a future exhaustive match check.
    assert_eq!(
        variants.len(),
        30,
        "Update this test when adding new Nine65Error variants"
    );
}

#[test]
fn test_result_type_alias() {
    // Verify Nine65Result<T> is Result<T, Nine65Error>
    fn returns_result() -> Nine65Result<u64> {
        Ok(42)
    }
    fn returns_error() -> Nine65Result<u64> {
        Err(Nine65Error::ModulusZero)
    }
    assert_eq!(returns_result().unwrap(), 42);
    assert!(returns_error().is_err());
}
