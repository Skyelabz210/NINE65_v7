//! Differential correctness for the trusted coefficient-zero decode boundary.

use super::*;

fn small_context(mut config: FHEConfig) -> RNSFHEContext {
    config.n = 64;
    config.security_bits = 0;
    config.name = "scalar decode arithmetic test; no security claim";
    RNSFHEContext::new(&config)
}

fn zero_poly(ctx: &RNSFHEContext, level: usize) -> DualRNSPoly {
    DualRNSPoly {
        main: vec![vec![0; ctx.n]; level],
        anchor: vec![vec![0; ctx.n]; ctx.dual_rns.anchor.primes.len()],
        n: ctx.n,
    }
}

#[test]
fn scalar_decrypt_matches_full_phase_at_every_supported_named_profile_level() {
    // Small N keeps this differential test cheap; these are arithmetic tests
    // of the named prime chains, not executions of their security tuples.
    let configs = [
        SecureConfig::secure_128().into_config(),
        SecureConfig::secure_192().into_config(),
        SecureConfig::secure_256().into_config(),
    ];
    let mut narrow = 0;
    let mut wide_qt = 0;
    let mut wide_q = 0;
    for (profile, config) in configs.into_iter().enumerate() {
        let ctx = small_context(config);
        let mut rng = ShadowHarvester::with_seed(0x5ca1_a000 + profile as u64);
        let keys = ctx.generate_keys_dual(&mut rng);
        for value in [0, 1, 42, ctx.t / 2 - 1, ctx.t / 2, ctx.t - 1] {
            let fresh = ctx.encrypt_dual(value, &keys.public_key, &mut rng);
            for level in 2..=ctx.config.primes.len() {
                let ct = ctx.mod_switch_ct_to_level(&fresh, level).unwrap();
                let (decoded, margin) = ctx.decrypt_dual_with_diagnostics(&ct, &keys.secret_key);
                assert_eq!(decoded, value, "profile {profile}, level {level}");
                assert!(margin >= 0, "profile {profile}, level {level}");
                assert_eq!(
                    ctx.try_decrypt_dual_scalar(&ct, &keys.secret_key).unwrap(),
                    decoded,
                    "profile {profile}, level {level}, m={value}"
                );
                // A projected secret is also sufficient for the active level.
                let projected = DualRNSSecretKey {
                    s: ctx.project_poly_to_level(&keys.secret_key.s, level),
                };
                assert_eq!(ctx.try_decrypt_dual_scalar(&ct, &projected).unwrap(), value);
                let q = U256::product_u64s(&ctx.config.primes[..level]);
                if q.hi != 0 {
                    wide_q += 1;
                } else if q.lo.checked_mul(ctx.t as u128).is_none() {
                    wide_qt += 1;
                } else {
                    narrow += 1;
                }
            }
        }
    }
    assert!(narrow > 0 && wide_qt > 0 && wide_q > 0);
}

#[test]
fn scalar_decrypt_checks_only_coefficient_zero_plaintext() {
    let ctx = small_context(SecureConfig::secure_128().into_config());
    let mut rng = ShadowHarvester::with_seed(0x5ca1_a001);
    let keys = ctx.generate_keys_dual(&mut rng);
    let mut ct = ctx.encrypt_dual(ctx.t - 1, &keys.public_key, &mut rng);
    // Nonconstant c0 coefficients do not affect coefficient zero of the phase.
    // This pins the deliberately scalar scope instead of asserting that this
    // API validates constant-polynomial plaintext packing.
    for (lane, &q) in ctx.config.primes.iter().enumerate() {
        for index in 1..ctx.n {
            ct.c0.main[lane][index] = q - index as u64;
        }
    }
    assert_eq!(ctx.decrypt_dual(&ct, &keys.secret_key), ctx.t - 1);
    assert_eq!(
        ctx.try_decrypt_dual_scalar(&ct, &keys.secret_key).unwrap(),
        ctx.t - 1
    );
}

#[test]
fn scalar_decrypt_odd_modulus_boundaries_and_negative_margin_match_full_decode() {
    let ctx = RNSFHEContext::new(&FHEConfig {
        n: 4,
        q: 17 * 41,
        primes: vec![17, 41],
        t: 19,
        eta: 2,
        security_bits: 0,
        name: "exhaustive scalar decode; no security claim",
    });
    let sk = DualRNSSecretKey {
        s: zero_poly(&ctx, 2),
    };
    let mut ct = DualRNSCiphertext {
        c0: zero_poly(&ctx, 2),
        c1: zero_poly(&ctx, 2),
        level: 2,
    };
    let q = 17 * 41;
    let mut refusals = 0;
    // Exhausts both sides of every rounding cell for odd Q, including the
    // upper-half transition and values with a negative floored-Delta margin.
    for value in 0..q {
        let residues: Vec<_> = ctx.config.primes.iter().map(|p| value % p).collect();
        for (lane, &residue) in residues.iter().enumerate() {
            ct.c0.main[lane][0] = residue;
        }
        let narrow = ctx.decrypt_dual_with_diagnostics(&ct, &sk);
        let wide = ctx.decrypt_dual_u256(&ct.c0, 2);
        // Independent canonical BFV rounding oracle; Q is odd, so these
        // integer sample points cannot tie at Q/2.
        let expected = (value * ctx.t + q / 2) / q % ctx.t;
        assert_eq!(narrow.0, expected, "independent BFV decode at {value}");
        assert_eq!(narrow, wide, "odd modulus value {value}");
        if narrow.1 < 0 {
            assert!(matches!(
                ctx.try_decrypt_dual_scalar(&ct, &sk),
                Err(Nine65Error::DecryptionFailed)
            ));
            refusals += 1;
        } else {
            assert_eq!(ctx.try_decrypt_dual_scalar(&ct, &sk).unwrap(), narrow.0);
        }
    }
    assert!(refusals > 0);
}

#[test]
fn scalar_decrypt_rejects_malformed_ciphertexts_and_secrets_without_panics() {
    let ctx = small_context(SecureConfig::secure_128().into_config());
    let mut rng = ShadowHarvester::with_seed(0x5ca1_a002);
    let keys = ctx.generate_keys_dual(&mut rng);
    let ct = ctx.encrypt_dual(42, &keys.public_key, &mut rng);
    let mut malformed = Vec::new();
    let mut bad = ct.clone();
    bad.level -= 1;
    malformed.push(bad);
    let mut bad = ct.clone();
    bad.c1.main[0].pop();
    malformed.push(bad);
    let mut bad = ct.clone();
    bad.c0.main[0][0] = ctx.config.primes[0];
    malformed.push(bad);
    let mut bad = ct.clone();
    bad.c1.main[1][ctx.n - 1] = u64::MAX;
    malformed.push(bad);
    let mut bad = ct.clone();
    bad.c0.anchor.pop();
    bad.c1.anchor.pop();
    malformed.push(bad);
    for level in [0, 1] {
        let mut bad = ct.clone();
        bad.level = level;
        bad.c0.main.truncate(level);
        bad.c1.main.truncate(level);
        malformed.push(bad);
    }
    for bad in malformed {
        assert!(ctx.try_decrypt_dual_scalar(&bad, &keys.secret_key).is_err());
    }
    for field in 0..4 {
        let mut bad = keys.secret_key.clone();
        match field {
            0 => bad.s.main.pop().map(|_| ()).unwrap(),
            1 => bad.s.main[0][0] = ctx.config.primes[0],
            2 => bad.s.anchor[0][0] = ctx.dual_rns.anchor.primes[0],
            _ => bad.s.n /= 2,
        }
        assert!(ctx.try_decrypt_dual_scalar(&ct, &bad).is_err());
    }
}

#[test]
fn scalar_decrypt_refuses_unsupported_fixed_width_capacity() {
    let config = FHEConfig {
        n: 64,
        q: 998244353,
        primes: vec![
            998244353,
            985661441,
            754974721,
            469762049,
            576460752301785089,
            576460752301391873,
            576460752300015617,
        ],
        t: 65537,
        eta: 2,
        security_bits: 0,
        name: "unsupported scalar decode width; no security claim",
    };
    let ctx = RNSFHEContext::new(&config);
    let sk = DualRNSSecretKey {
        s: zero_poly(&ctx, config.primes.len()),
    };
    let ct = DualRNSCiphertext {
        c0: zero_poly(&ctx, config.primes.len()),
        c1: zero_poly(&ctx, config.primes.len()),
        level: config.primes.len(),
    };
    assert!(matches!(
        ctx.try_decrypt_dual_scalar(&ct, &sk),
        Err(Nine65Error::Overflow { .. })
    ));
}

#[test]
fn scalar_decrypt_unit_and_max_plaintext_moduli_preserve_canonical_decode() {
    for t in [1, u64::MAX] {
        let mut config = SecureConfig::secure_128().into_config();
        config.t = t;
        let ctx = small_context(config);
        let level = ctx.config.primes.len();
        let q = U256::product_u64s(&ctx.config.primes);
        let sk = DualRNSSecretKey {
            s: zero_poly(&ctx, level),
        };
        let mut ct = DualRNSCiphertext {
            c0: zero_poly(&ctx, level),
            c1: zero_poly(&ctx, level),
            level,
        };
        for value in [0, q.lo / 3, q.lo / 2, q.lo - 1] {
            for (lane, prime) in ctx.config.primes.iter().enumerate() {
                ct.c0.main[lane][0] = (value % *prime as u128) as u64;
            }
            // General U256 division is independent of the small-quotient
            // binary search used by the wide decoder, including t=u64::MAX.
            let numerator = U256::from_u128(value).mul_u64(t).add(q.shr1());
            let expected = (numerator.div_mod_u256(q).0.lo % t as u128) as u64;
            let full = ctx.decrypt_dual_with_diagnostics(&ct, &sk);
            assert_eq!(full.0, expected, "t={t}, value={value}");
            assert!(full.0 < t);
            let scalar = ctx.try_decrypt_dual_scalar(&ct, &sk);
            if full.1 < 0 {
                assert!(matches!(scalar, Err(Nine65Error::DecryptionFailed)));
            } else {
                assert_eq!(scalar.unwrap(), expected);
            }
        }
    }
}
