//! Regression gates for the 2026-07-13 physical audit.

use nine65::params::secure_configs::{verify_production_safety, SecureConfig};

#[test]
fn secure_128_uses_the_audited_dimension_floor() {
    let secure = SecureConfig::secure_128();
    assert_eq!(secure.claimed_security, 128);
    assert_eq!(secure.config.n, 8192);
    assert!(secure.is_production_safe());
    assert!(verify_production_safety(&secure).is_ok());
}

#[test]
fn every_named_production_config_satisfies_its_complete_claim() {
    for secure in [
        SecureConfig::secure_128(),
        SecureConfig::secure_128_deep(),
        SecureConfig::secure_192(),
        SecureConfig::secure_256(),
    ] {
        assert!(
            secure.hybrid_security >= secure.claimed_security,
            "{} screens at {} bits below its {}-bit claim",
            secure.config.name,
            secure.hybrid_security,
            secure.claimed_security,
        );
        assert!(secure.he_standard_compliant, "{}", secure.config.name);
        assert!(secure.config.n >= 8192, "{}", secure.config.name);
    }
}

#[test]
fn audited_benchmark_contains_no_float_or_simulated_refresh_path() {
    let source = include_str!("../src/bin/nine65_bench.rs");
    for forbidden in ["f32", "f64", "SIMULATED REFRESH", "simulated refresh"] {
        assert!(
            !source.contains(forbidden),
            "audited benchmark contains forbidden token: {forbidden}"
        );
    }
    assert!(source.contains("not ciphertext-ciphertext multiplicative depth"));
    assert!(source.contains("real bootstrap"));
}

#[test]
fn secure_128_ntt_lanes_match_the_new_ring_dimension() {
    let secure = SecureConfig::secure_128();
    let two_n = 2u64 * secure.config.n as u64;
    for prime in secure.config.primes {
        assert_eq!((prime - 1) % two_n, 0, "prime {prime}");
    }
}
