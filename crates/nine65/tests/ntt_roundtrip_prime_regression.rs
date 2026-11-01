//! Round trips on the actual named-profile and dimension-specific anchor bases.
use nine65::arithmetic::{DualRNSContext, NTTEngineFFT};
use nine65::params::secure_configs::SecureConfig;
use std::collections::BTreeSet;

#[test]
fn both_fallible_backends_reject_invalid_or_unsupported_modulus_ranges() {
    // The Goldilocks prime supports a 16th root but exceeds this Montgomery
    // implementation's range; the fallible constructor must not panic.
    for prime in [0, 1, 18_446_744_069_414_584_321] {
        assert!(NTTEngineFFT::try_new(prime, 8).is_err());
        assert!(nine65::arithmetic::ntt::NTTEngine::try_new(prime, 8).is_err());
    }
}

#[test]
fn named_profile_and_anchor_primes_round_trip_at_their_runtime_degrees() {
    let mut pairs = BTreeSet::new();
    for profile in [
        SecureConfig::secure_128(),
        SecureConfig::secure_192(),
        SecureConfig::secure_256(),
    ] {
        let config = profile.into_config();
        for prime in config
            .primes
            .into_iter()
            .chain(DualRNSContext::canonical_anchor_primes_for_n(config.n))
        {
            pairs.insert((config.n, prime));
        }
    }
    // The native refresh embedding has a distinct anchor catalogue.
    for prime in DualRNSContext::canonical_anchor_primes_for_n(32_768) {
        pairs.insert((32_768, prime));
    }
    assert_eq!(pairs.len(), 37, "profile/basis inventory changed");
    for (degree, prime) in pairs {
        let engine = NTTEngineFFT::try_new(prime, degree).unwrap();
        let input: Vec<_> = (0..degree)
            .map(|i| match i % 4 {
                0 => 0,
                1 => prime - 1,
                2 => prime / 2,
                _ => ((i as u128 * 7_919 + 104_729) % prime as u128) as u64,
            })
            .collect();
        assert_eq!(
            engine.intt(&engine.ntt(&input)),
            input,
            "round trip failed for N={degree}, q={prime}"
        );
    }
}
