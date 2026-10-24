//! Research: a public, bounded dense-work to sparse-source transform. The
//! source exists only at a smaller modulus; dense work encryption is retained.

use super::*;

#[path = "batched_lift_phase.rs"]
mod batched_lift_phase;

fn balanced_source(n: usize, weight: usize, rng: &mut ShadowHarvester) -> Vec<i8> {
    assert!(weight > 0 && weight <= n && weight % 2 == 0 && n.is_power_of_two());
    let mut selected = BTreeSet::new();
    let mut out = vec![0; n];
    while selected.len() < weight {
        let j = rng.next_u64() as usize % n;
        if selected.insert(j) {
            // Assign signs in DRAW order, not sorted support order. Each
            // balanced support/sign assignment has the same multiplicity.
            out[j] = if selected.len() <= weight / 2 { 1 } else { -1 };
        }
    }
    out
}

struct PublicSourceTransform<'a> {
    work: &'a RNSFHEContext,
    source: &'a RNSFHEContext,
    drops: Vec<RNSFHEContext>,
    switch: RawKey,
}

struct PreparedSource {
    dropped: RNSCiphertext,
    ciphertext: RNSCiphertext,
    bound: u128,
}

impl PublicSourceTransform<'_> {
    fn apply(&self, input: &RNSCiphertext, bound: u128) -> PreparedSource {
        assert_eq!(self.work.n, self.source.n);
        assert_eq!(self.work.t, self.source.t);
        assert_eq!(input.num_primes, self.work.config.primes.len());
        let mut ct = input.clone();
        let mut v = U512::from_u128(bound);
        let mut previous = self.work;
        assert!(words(v.mul_u128(2)) < words(U512::product_u64s(&previous.config.primes)));
        for next in &self.drops {
            let special = *previous.config.primes.last().unwrap();
            ct = drop_special(next, previous, &ct);
            // This is the ORIGINAL DENSE working key throughout the drops.
            v = v
                .add(U512::from_u64(special - 1))
                .div_u64(special)
                .add(U512::from_u128(
                    (self.work.t as u128 * (self.work.n + 1) as u128).div_ceil(2),
                ));
            assert!(words(v.mul_u128(2)) < words(U512::product_u64s(&next.config.primes)));
            previous = next;
        }
        assert_eq!(previous.config.primes, self.source.config.primes);
        let engine = Engine {
            ctx: self.source,
            switches: Cell::new(0),
        };
        let switched = engine.switch(&ct.c1, &self.switch);
        let ciphertext = RNSCiphertext {
            c0: ct.c0.add(&switched.c0, &self.source.rns),
            c1: switched.c1,
            num_primes: self.source.config.primes.len(),
        };
        let bound = narrow(v)
            + self.source.t as u128
                * self.source.n as u128
                * self.switch.shape.digit_sum
                * self.switch.beta;
        assert!(
            words(U512::from_u128(bound).mul_u128(2))
                < words(U512::product_u64s(&self.source.config.primes))
        );
        assert_eq!(engine.switches.get(), 1);
        PreparedSource {
            dropped: ct,
            ciphertext,
            bound,
        }
    }
}

// KEY HOLDER only: no source-key samples are made at the working Q119.
fn make_source_transform<'a>(
    work: &'a RNSFHEContext,
    source: &'a RNSFHEContext,
    work_keys: &RNSKeySet,
    source_keys: &RNSKeySet,
    rng: &mut ShadowHarvester,
) -> PublicSourceTransform<'a> {
    assert_eq!(
        &work.config.primes[..source.config.primes.len()],
        &source.config.primes
    );
    let mut target = work_keys.secret_key.s.clone();
    target.limbs.truncate(source.config.primes.len());
    let shape = Shape::new(source, 10);
    let rows = raw_rows(source, &shape, &target, source_keys, rng);
    let engine = Engine {
        ctx: source,
        switches: Cell::new(0),
    };
    let switch = engine.cache(&shape, &rows, source.config.eta as u128);
    let mut config = work.config.clone();
    let mut drops = Vec::new();
    while config.primes.len() > source.config.primes.len() {
        config.primes.pop();
        drops.push(RNSFHEContext::try_new(&config).unwrap());
    }
    PublicSourceTransform {
        work,
        source,
        drops,
        switch,
    }
}

fn keys_on_prefix(keys: &RNSKeySet, ctx: &RNSFHEContext) -> RNSKeySet {
    let mut secret = keys.secret_key.clone();
    secret.s.limbs.truncate(ctx.config.primes.len());
    // Observer only: no mismatched public key or stale relinearization key.
    RNSKeySet {
        secret_key: secret,
        public_key: RNSPublicKey {
            pk0: RNSPolynomial::zero(&ctx.rns),
            pk1: RNSPolynomial::zero(&ctx.rns),
        },
        eval_key: RNSEvalKey {
            rlk: Vec::new(),
            decomp_base: 1 << 16,
        },
    }
}

#[test]
fn sparse_source_sampler_and_actual_source_period_are_explicit() {
    let mut rng = ShadowHarvester::with_seed(0x4241_4c41_4e43_4544);
    let source = balanced_source(8192, 96, &mut rng);
    assert_eq!(source.iter().filter(|&&s| s == 1).count(), 48);
    assert_eq!(source.iter().filter(|&&s| s == -1).count(), 48);
    let q = 998244353u128 * 985661441;
    assert_eq!(phase_window2_for_q(16384, 96, 99, q / 16, q), 13699);
    assert!(phase_window2_for_q(16384, 8192, 99, q / 16, q) > 16384);
    // A Q119 denominator would understate the source's phase allowance.
    assert_ne!(phase_window2(16384, 96, 99, q / 16), 13699);
}

// Independent CLIENT geometry oracle. It deliberately owns the source
// secret and clear clock sums; none of those values feed the public path.
#[allow(clippy::too_many_arguments)]
fn client_check_source_clock(
    source: &RNSFHEContext,
    outer: &RNSFHEContext,
    input: &RNSCiphertext,
    trits: &[i8],
    expected: &[u64],
    bound: u128,
    coordinate: usize,
    cap: u128,
) -> BTreeSet<i128> {
    let q: u128 = source.config.primes.iter().map(|&v| v as u128).product();
    let h = trits.iter().map(|s| s.unsigned_abs() as usize).sum();
    let window = phase_window2_for_q(outer.n, h, coordinate, cap, q);
    assert!(window < outer.n as u128);
    let public0 = preprocess_for_clock(source, &input.c0, coordinate, outer.n);
    let public1 = preprocess_for_clock(source, &input.c1, coordinate, outer.n);
    let client_residuals = |p: &RNSPolynomial| {
        let values = ordinary(source, p);
        let round = RoundProjection::new(&source.config.primes, source.t);
        (0..source.n)
            .map(|j| {
                let r: Vec<_> = values.iter().map(|lane| lane[j]).collect();
                let a = round.round(&r);
                let scaled = client_crt(source, &r).mul_u128(source.t as u128);
                let qa = U512::from_u128(q).mul_u128(a as u128);
                let d = abs_diff(scaled, qa);
                assert_eq!((d.d3, d.d2, d.d1), (0, 0, 0));
                if words(scaled) < words(qa) {
                    -(d.d0 as i128)
                } else {
                    d.d0 as i128
                }
            })
            .collect::<Vec<_>>()
    };
    let r0 = client_residuals(&input.c0);
    let r1 = client_residuals(&input.c1);
    let lookup = ordinary(outer, &clock_lut(outer, coordinate, window as i64).c0);
    let decode = CanonicalScaleRound::new(&outer.config.primes, outer.t).unwrap();
    let lookup_values: Vec<_> = (0..outer.n)
        .map(|j| {
            decode
                .scale_round(&lookup.iter().map(|lane| lane[j]).collect::<Vec<_>>())
                .unwrap()
        })
        .collect();
    let support: Vec<_> = trits.iter().enumerate().filter(|(_, s)| **s != 0).collect();
    let mut sheets = BTreeSet::new();
    for j in 0..source.n {
        let (mut sum, mut z, mut affine) = (r0[j], public0.clock[j], public0.a[j] as i128);
        for &(i, &s) in &support {
            let k = (j + source.n - i) % source.n;
            let sign = s as i128 * if i > j { -1 } else { 1 };
            sum += sign * r1[k];
            z += sign as i64 * public1.clock[k];
            affine += sign * public1.a[k] as i128;
        }
        let k = (sum + q as i128 / 2).div_euclid(q as i128);
        assert!((sum - q as i128 * k).unsigned_abs() <= bound);
        assert!(k.unsigned_abs() <= h.div_ceil(2) as u128);
        assert_eq!(
            (affine + k).rem_euclid(source.t as i128) as u64,
            expected[j]
        );
        let r = z.rem_euclid((2 * outer.n) as i64) as usize;
        let (index, sign) = if r == 0 {
            (0, 1i128)
        } else if r <= outer.n {
            (outer.n - r, -1)
        } else {
            (2 * outer.n - r, 1)
        };
        let value =
            (sign * lookup_values[index] as i128 * outer.n as i128).rem_euclid(source.t as i128);
        assert_eq!(value, k.rem_euclid(source.t as i128));
        sheets.insert(k);
    }
    sheets
}

#[test]
#[ignore = "opt-in native dense working-key to sparse low-Q source; no native encrypted clock"]
fn sparse_source_native_transform_preserves_dense_work_polynomial_and_clock_geometry() {
    let mut config = SecureConfig::secure_128().into_config();
    config.security_bits = 0;
    config.name = "UNADMITTED native source assessment probe";
    let work = RNSFHEContext::try_new(&config).unwrap();
    let mut source_config = config.clone();
    source_config.primes.truncate(2);
    let source = RNSFHEContext::try_new(&source_config).unwrap();
    let q: u128 = source.config.primes.iter().map(|&v| v as u128).product();
    let mut outer_config = config.clone();
    outer_config.n *= 2;
    outer_config.primes.extend(EXTRA);
    let outer = RNSFHEContext::try_new(&outer_config).unwrap();
    let mut rng = ShadowHarvester::with_seed(0x4e41_5449_5645_454e);
    let work_keys = work.generate_keys(&mut rng);
    let original_norm = ordinary(&work, &work_keys.secret_key.s)[0]
        .iter()
        .filter(|&&s| s != 0)
        .count();
    assert!(original_norm > 4096);
    let trits = balanced_source(source.n, 96, &mut rng);
    let source_keys = sparse_keys(&source, &trits, &mut rng);
    let transform = make_source_transform(&work, &source, &work_keys, &source_keys, &mut rng);
    let message: Vec<_> = (0..work.n)
        .map(|j| if j % 2 == 0 { 1 } else { work.t - 1 })
        .collect();
    let exact = work.try_exact_evaluator().unwrap();
    let relin = exact.generate_hybrid_gadget_key_with_rng(&work_keys.secret_key, &mut rng);
    let encrypted = encrypt_polynomial(&work, &work_keys, &message, &mut rng);
    let mut input = exact.try_mul_exact(&encrypted, &encrypted, &relin).unwrap();
    let expected: Vec<_> = (0..work.n)
        .map(|j| {
            let c = (2 * j + 2) as i64 - work.n as i64;
            (if j % 2 == 0 { c } else { -c }).rem_euclid(work.t as i64) as u64
        })
        .collect();
    // Stress a substantial fraction of the source Q/16 phase allowance.
    let load = Q_SOURCE as u128 / (20 * work.t as u128);
    let extra = montgomery(
        &work,
        config
            .primes
            .iter()
            .map(|&p| {
                (0..work.n)
                    .map(|j| {
                        let x = (load % p as u128) as u64;
                        if j % 2 == 0 || x == 0 {
                            x
                        } else {
                            p - x
                        }
                    })
                    .collect()
            })
            .collect(),
    );
    input.c0 = input.c0.add(&extra, &work.rns);
    let original_v = observe_polynomial(&work, &input, &work_keys, &expected);
    let fresh = work.t as u128 * (2 * work.n + 1) as u128 * config.eta as u128
        + (Q_SOURCE as u128 % work.t as u128) * (work.t - 1) as u128;
    let bound = square_history_bound(&work, fresh) + load * work.t as u128;
    assert!(original_v <= bound);
    let prepared = transform.apply(&input, bound);
    observe_polynomial(
        &source,
        &prepared.dropped,
        &keys_on_prefix(&work_keys, &source),
        &expected,
    );
    let measured = observe_polynomial(&source, &prepared.ciphertext, &source_keys, &expected);
    assert!(measured <= prepared.bound && prepared.bound < q / 16);
    assert_ne!(
        decrypt_coefficients(&source, &prepared.dropped, &source_keys),
        expected
    );
    let sheets = client_check_source_clock(
        &source,
        &outer,
        &prepared.ciphertext,
        &trits,
        &expected,
        prepared.bound,
        99,
        q / 16,
    );
    assert!(sheets.iter().any(|&k| k != 0));
    eprintln!("native dense-work/source transform: N8192 workQ119/sourceQ60, original ternary norm={original_norm}, balanced sourceH96, actual public encryption/dense square/modulus drops/key switch, all8192 messages correct; original Vbits={}, source observed/bound={}/{}, composite99 window=13699, sheets={sheets:?}; geometry checked by CLIENT only, no native encrypted clock; source security/admission FALSE",bits(original_v),bits(measured),bits(prepared.bound));
}

#[test]
#[ignore = "opt-in INSECURE dense-work/sparse-source/outer refresh and repeat integration"]
fn sparse_source_public_transform_closes_two_dense_work_refresh_cycles() {
    let mut config = SecureConfig::secure_128().into_config();
    config.n = 16;
    config.security_bits = 0;
    config.name = "INSECURE dense-work/source encapsulation research";
    let work = RNSFHEContext::try_new(&config).unwrap();
    let mut source_config = config.clone();
    source_config.primes.truncate(2);
    let source = RNSFHEContext::try_new(&source_config).unwrap();
    let source_q: u128 = source.config.primes.iter().map(|&q| q as u128).product();
    let mut outer_config = config.clone();
    outer_config.n *= 2;
    outer_config.primes.extend(EXTRA);
    let outer = RNSFHEContext::try_new(&outer_config).unwrap();
    let mut rng = ShadowHarvester::with_seed(0x4445_4e53_4553_5243);
    let work_keys = work.generate_keys(&mut rng);
    let dense_norm = ordinary(&work, &work_keys.secret_key.s)[0]
        .iter()
        .filter(|&&s| s != 0)
        .count();
    assert!(dense_norm > 2);
    let source_trits = balanced_source(source.n, 2, &mut rng);
    let source_keys = sparse_keys(&source, &source_trits, &mut rng);
    let transform = make_source_transform(&work, &source, &work_keys, &source_keys, &mut rng);
    assert_eq!(transform.switch.primes, source.config.primes);
    let outer_keys = outer.generate_keys(&mut rng);
    let engine = Engine {
        ctx: &outer,
        switches: Cell::new(0),
    };
    let packed = setup(&engine, &outer_keys, &source_trits, 8, 10, 10, &mut rng);
    let source_message: Vec<_> = source_trits
        .iter()
        .map(|&s| (s as i64).rem_euclid(source.t as i64) as u64)
        .collect();
    let linear_source =
        encrypt_polynomial(&outer, &outer_keys, &embedded(&source_message), &mut rng);
    let mut drop_config = outer_config;
    let mut drops = Vec::new();
    while drop_config.primes.len() > config.primes.len() {
        drop_config.primes.pop();
        drops.push(RNSFHEContext::try_new(&drop_config).unwrap());
    }
    let mut at_work = outer_keys.secret_key.s.clone();
    at_work.limbs.truncate(config.primes.len());
    let shape = Shape::new(&work, 10);
    let even = raw_rows(
        &work,
        &shape,
        &split(&work, &at_work, 0),
        &work_keys,
        &mut rng,
    );
    let odd = raw_rows(
        &work,
        &shape,
        &split(&work, &at_work, 1),
        &work_keys,
        &mut rng,
    );
    let returns = Engine {
        ctx: &work,
        switches: Cell::new(0),
    };
    let pipeline = PublicOuterReturn {
        work: &work,
        source: &source,
        outer: engine,
        packed,
        linear_source,
        drop_contexts: drops,
        return_even: returns.cache(&shape, &even, config.eta as u128),
        return_odd: returns.cache(&shape, &odd, config.eta as u128),
        source_norm: 2,
        coordinate: 9,
        phase_cap: source_q / 128,
        output_batch: 4,
    };
    let exact = work.try_exact_evaluator().unwrap();
    let relin = exact.generate_hybrid_gadget_key_with_rng(&work_keys.secret_key, &mut rng);
    let mut message: Vec<_> = (0..work.n).map(|j| ((j * 3 + 7) % 11) as u64).collect();
    message[work.n - 1] = work.t - 2;
    let mut current = encrypt_polynomial(&work, &work_keys, &message, &mut rng);
    let mut bound = work.t as u128 * (2 * work.n + 1) as u128 * config.eta as u128
        + (Q_SOURCE as u128 % work.t as u128) * (work.t - 1) as u128;
    let mut omissions = 0;
    for cycle in 0..2 {
        current = exact.try_mul_exact(&current, &current, &relin).unwrap();
        bound = square_history_bound(&work, bound);
        message = square_plain(&message, work.t);
        let load = Q_SOURCE as u128 / (512 * work.t as u128);
        let added = montgomery(
            &work,
            config
                .primes
                .iter()
                .map(|&q| {
                    (0..work.n)
                        .map(|j| {
                            let e = (load % q as u128) as u64;
                            if j % 2 == 0 || e == 0 {
                                e
                            } else {
                                q - e
                            }
                        })
                        .collect()
                })
                .collect(),
        );
        current.c0 = current.c0.add(&added, &work.rns);
        bound += load * work.t as u128;
        let incoming = observe_polynomial(&work, &current, &work_keys, &message);
        assert!(incoming <= bound);
        let prepared = transform.apply(&current, bound);
        observe_polynomial(
            &source,
            &prepared.dropped,
            &keys_on_prefix(&work_keys, &source),
            &message,
        );
        let source_v = observe_polynomial(&source, &prepared.ciphertext, &source_keys, &message);
        assert!(source_v <= prepared.bound && prepared.bound <= pipeline.phase_cap);
        assert_ne!(
            decrypt_coefficients(&source, &prepared.dropped, &source_keys),
            message
        );
        let refreshed = pipeline.apply(&prepared.ciphertext, prepared.bound);
        let outer_v =
            observe_polynomial(&outer, &refreshed.outer, &outer_keys, &embedded(&message));
        assert!(words(U512::from_u128(outer_v)) <= words(refreshed.outer_bound));
        let returned_v = observe_polynomial(&work, &refreshed.returned, &work_keys, &message);
        assert!(returned_v <= refreshed.returned_bound && returned_v < incoming);
        omissions += decrypt_coefficients(&outer, &refreshed.without_carry, &outer_keys)
            .iter()
            .zip(embedded(&message))
            .filter(|(a, b)| **a != *b)
            .count();
        bound = refreshed.returned_bound;
        current = refreshed.returned;
        assert!(2 * square_history_bound(&work, bound) < Q_SOURCE as u128);
        eprintln!("dense-work source encapsulation: cycle={cycle}, INSECURE workN16/outerN32, workQ119/sourceQ60/outerQ241, actual original key norm={dense_norm}, source norm2; incoming Vbits={}, prepared source observed/bound={}/{}, returned observed/bound={}/{}, all16 coefficients correct, no source-key samples at Q119",bits(incoming),bits(source_v),bits(prepared.bound),bits(returned_v),bits(bound));
    }
    let next = exact.try_mul_exact(&current, &current, &relin).unwrap();
    observe_polynomial(&work, &next, &work_keys, &square_plain(&message, work.t));
    assert!(omissions > 0);
    eprintln!("dense-work source encapsulation: same complete precharge reused for two cycles and final square; carry omission corrupts {omissions} coefficients; source security/native bootstrap admission remain FALSE");
}
