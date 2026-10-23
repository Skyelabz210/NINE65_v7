//! Nonlinear 11-adic ring section on a coherent auxiliary chart view.
//! Phi(x)=sigma_(11^-1)(x^11) mod121 is a section of reduction mod11,
//! with derivative zero mod11. It is NOT a coefficientwise canonical lift.
//! Public research producer only; no native public refresh admission.

use super::*;

const LOW_BASE: u64 = 11;
const HIGH_PLAIN: u64 = 121;
const POWER_NODES: [(usize, usize, usize); 5] =
    [(2, 1, 1), (3, 1, 2), (5, 2, 3), (6, 3, 3), (11, 5, 6)];

fn wide_bits(x: U512) -> u32 {
    for (offset, limb) in [(384, x.d3), (256, x.d2), (128, x.d1), (0, x.d0)] {
        if limb != 0 {
            return offset + 128 - limb.leading_zeros();
        }
    }
    0
}

// CLIENT only: supports errors wider than u128, unlike the early probes.
fn observe_wide(
    ctx: &RNSFHEContext,
    ct: &RNSCiphertext,
    keys: &RNSKeySet,
    expected: &[u64],
) -> U512 {
    assert_eq!(decrypt_coefficients(ctx, ct, keys), expected);
    let phases = decrypted_phase_residues(ctx, ct, keys);
    let q = U512::product_u64s(&ctx.config.primes);
    let period = q.mul_u128(ctx.t as u128);
    let mut maximum = U512::zero();
    for (j, &m) in expected.iter().enumerate() {
        let r: Vec<_> = phases.iter().map(|lane| lane[j]).collect();
        let difference = abs_diff(
            client_crt(ctx, &r).mul_u128(ctx.t as u128),
            q.mul_u128(m as u128),
        );
        let difference = if words(difference) > words(period.div_u64(2)) {
            period.sub(difference)
        } else {
            difference
        };
        assert!(words(difference.mul_u128(2)) < words(q));
        if words(difference) > words(maximum) {
            maximum = difference;
        }
    }
    maximum
}

fn plain_product(ctx: &RNSFHEContext, a: &[u64], b: &[u64]) -> Vec<u64> {
    let prime = ctx.config.primes[0];
    assert!((2 * ctx.n as u128 * (ctx.t - 1) as u128 * (ctx.t - 1) as u128) < prime as u128);
    ctx.ntt_engines[0]
        .multiply(a, b)
        .into_iter()
        .map(|v| {
            (if v > prime / 2 {
                v as i128 - prime as i128
            } else {
                v as i128
            })
            .rem_euclid(ctx.t as i128) as u64
        })
        .collect()
}

fn plain_power11(ctx: &RNSFHEContext, input: &[u64]) -> Vec<u64> {
    let mut powers = BTreeMap::from([(1, input.to_vec())]);
    for (e, a, b) in POWER_NODES {
        powers.insert(e, plain_product(ctx, &powers[&a], &powers[&b]));
    }
    powers.remove(&11).unwrap()
}

fn plain_sigma(input: &[u64], exponent: usize, t: u64) -> Vec<u64> {
    let n = input.len();
    let mut output = vec![0; n];
    for (i, &v) in input.iter().enumerate() {
        let target = i * exponent % (2 * n);
        output[target % n] = if target < n || v == 0 { v } else { t - v };
    }
    output
}

fn plain_section(ctx: &RNSFHEContext, input: &[u64]) -> Vec<u64> {
    plain_sigma(
        &plain_power11(ctx, input),
        inverse(LOW_BASE, (2 * ctx.n) as u64) as usize,
        HIGH_PLAIN,
    )
}

struct SectionOutput {
    section: RNSCiphertext,
    quotient: RNSCiphertext,
    section_bound: U512,
    quotient_bound: U512,
}

struct FrobeniusSection<'a> {
    ctx: &'a RNSFHEContext,
    exact: ExactMulEvaluator<'a>,
    relin: RNSHybridGadgetKey,
    galois: BTreeMap<usize, RawKey>,
    exponent: usize,
    switch_v: u128,
    galois_v: u128,
}

impl<'a> FrobeniusSection<'a> {
    // KEY HOLDER setup. Only public contexts and evaluation keys survive.
    fn setup(ctx: &'a RNSFHEContext, keys: &RNSKeySet, rng: &mut ShadowHarvester) -> Self {
        assert_eq!(ctx.t, HIGH_PLAIN);
        let exact = ctx.try_exact_evaluator().unwrap();
        let relin = exact.generate_hybrid_gadget_key_with_rng(&keys.secret_key, rng);
        let switch_v = ctx.t as u128
            * ctx.n as u128
            * ctx.config.eta as u128
            * ((1u128 << relin.base_bits) - 1)
            * relin.digits_per_lane.iter().sum::<usize>() as u128;
        let exponent = inverse(LOW_BASE, (2 * ctx.n) as u64) as usize;
        let target = sigma(
            ctx,
            &RNSCiphertext {
                c0: keys.secret_key.s.clone(),
                c1: RNSPolynomial::zero(&ctx.rns),
                num_primes: ctx.config.primes.len(),
            },
            exponent,
        )
        .c0;
        let shape = Shape::new(ctx, 10);
        let rows = raw_rows(ctx, &shape, &target, keys, rng);
        let galois_v = ctx.t as u128 * ctx.n as u128 * shape.digit_sum * ctx.config.eta as u128;
        let engine = Engine {
            ctx,
            switches: Cell::new(0),
        };
        let key = engine.cache(&shape, &rows, ctx.config.eta as u128);
        Self {
            ctx,
            exact,
            relin,
            galois: BTreeMap::from([(exponent, key)]),
            exponent,
            switch_v,
            galois_v,
        }
    }

    fn multiply_bound(&self, a: U512, b: U512) -> Result<U512, &'static str> {
        let q = U512::product_u64s(&self.ctx.config.primes);
        if words(a.mul_u128(2)) >= words(q) || words(b.mul_u128(2)) >= words(q) {
            return Err("Frobenius input error exceeds decoding envelope");
        }
        let n = self.ctx.n as u128;
        let t = self.ctx.t as u128;
        let factor = n * ((t - 1) / 2) + t * n * (n / 2 + 1);
        let maximum = if words(a) >= words(b) { a } else { b };
        let rounding = (t * (1 + n + n * n)).div_ceil(2);
        let bound = a
            .add(b)
            .mul_u128(factor)
            .add(maximum.mul_u128(n / 2))
            .add(U512::from_u128(rounding + self.switch_v));
        if words(bound.mul_u128(2)) >= words(q) {
            Err("Frobenius polynomial node exceeds public error budget")
        } else {
            Ok(bound)
        }
    }

    fn plan(&self, input: U512) -> Result<BTreeMap<usize, U512>, &'static str> {
        let mut bounds = BTreeMap::from([(1, input)]);
        for (e, a, b) in POWER_NODES {
            bounds.insert(e, self.multiply_bound(bounds[&a], bounds[&b])?);
        }
        let result = bounds[&11].add(U512::from_u128(self.galois_v));
        if words(result.mul_u128(2)) >= words(U512::product_u64s(&self.ctx.config.primes)) {
            return Err("Frobenius Galois return exceeds public error budget");
        }
        bounds.insert(12, result);
        Ok(bounds)
    }

    // Public nonlinear evaluator: no client key, clear digits, coefficient
    // projections, slot map, source support or phase oracle is accepted.
    fn apply(&self, input: &RNSCiphertext, input_bound: U512) -> SectionOutput {
        assert_eq!(input.num_primes, self.ctx.config.primes.len());
        let bounds = self.plan(input_bound).unwrap(); // Preflight ALL nodes.
        let mut powers = BTreeMap::from([(1, input.clone())]);
        for (e, a, b) in POWER_NODES {
            powers.insert(
                e,
                self.exact
                    .try_mul_exact(&powers[&a], &powers[&b], &self.relin)
                    .unwrap(),
            );
        }
        let engine = Engine {
            ctx: self.ctx,
            switches: Cell::new(0),
        };
        let section = engine.galois(&powers[&11], self.exponent, &self.galois);
        assert_eq!(engine.switches.get(), 1);
        let quotient = self.ctx.sub(input, &section);
        // Phi(x)=x mod11 as a ring polynomial. Hence x-Phi(x) is divisible
        // by11 coefficientwise modulo121. SAME ciphertext components are
        // Enc_11((x-Phi(x))/11), under the same key/Q, with V divided by11.
        let quotient_bound = input_bound
            .add(bounds[&12])
            .add(U512::from_u64(10))
            .div_u64(11);
        SectionOutput {
            section,
            quotient,
            section_bound: bounds[&12],
            quotient_bound,
        }
    }
}

// Coherent low-plaintext RESIDUE view, not an integer representative. It is
// independently produced from the same public source components and source
// precharge; no conversion from a p65537 ciphertext is asserted.
fn public_residue_linear(
    source: &RNSFHEContext,
    low: &RNSFHEContext,
    input: &RNSCiphertext,
    source_norm: usize,
    cap: u128,
    input_v: u128,
    precharge: &RNSCiphertext,
    precharge_v: u128,
    coefficients: [i64; 2],
) -> (RNSCiphertext, U512) {
    assert!(low.t == HIGH_PLAIN || low.t == LOW_BASE);
    assert_eq!(low.n % source.n, 0);
    let stride = low.n / source.n;
    assert!(stride >= 2 && stride.is_power_of_two());
    assert!(input_v <= cap);
    let q: u128 = source.config.primes.iter().map(|&q| q as u128).product();
    let mut inputs = Vec::new();
    for m in [99, 121] {
        assert!(phase_window2_for_q(low.n, source_norm, m, cap, q) < low.n as u128);
        inputs.push((
            preprocess_for_clock(source, &input.c0, m, low.n),
            preprocess_for_clock(source, &input.c1, m, low.n),
        ));
    }
    let mut w0 = vec![0; low.n];
    let mut w1 = w0.clone();
    for j in 0..source.n {
        w0[stride * j] =
            coefficients[0] * inputs[0].0.clock[j] + coefficients[1] * inputs[1].0.clock[j];
        w1[stride * j] =
            coefficients[0] * inputs[0].1.clock[j] + coefficients[1] * inputs[1].1.clock[j];
        // This is an explicitly residue-valued frame. Reducing a PUBLIC
        // constant is valid; no canonical lift of an encrypted value occurs.
        let residue = w0[stride * j].rem_euclid(low.t as i64);
        w0[stride * j] = if residue > low.t as i64 / 2 {
            residue - low.t as i64
        } else {
            residue
        };
    }
    let l1 = w1.iter().map(|v| v.unsigned_abs() as u128).sum::<u128>();
    let constant = w0.iter().map(|v| v.unsigned_abs() as u128).max().unwrap();
    let remainder = U512::product_u64s(&low.config.primes).mod_u64(low.t) as u128;
    let bound = U512::from_u128(precharge_v * l1 + remainder * constant);
    (
        add(
            low,
            &multiply_signed_plain(low, precharge, &w1),
            &public_plain(low, &w0),
        ),
        bound,
    )
}

// CLIENT/setup prefix keys. Unlike observer-only keys_on_prefix, the public
// key is genuinely truncated too, so fresh coherent low-view precharges can
// use the same RLWE key at the smaller public level. Legacy relin is empty.
fn prefix_setup_keys(keys: &RNSKeySet, ctx: &RNSFHEContext) -> RNSKeySet {
    let trim = |p: &RNSPolynomial| {
        let mut out = p.clone();
        out.limbs.truncate(ctx.config.primes.len());
        out
    };
    RNSKeySet {
        secret_key: RNSSecretKey {
            s: trim(&keys.secret_key.s),
        },
        public_key: RNSPublicKey {
            pk0: trim(&keys.public_key.pk0),
            pk1: trim(&keys.public_key.pk1),
        },
        eval_key: RNSEvalKey {
            rlk: Vec::new(),
            decomp_base: 1 << 16,
        },
    }
}

fn drop_view_bound(bound: U512, prime: u64, t: u64, n: usize) -> U512 {
    bound
        .add(U512::from_u64(prime - 1))
        .div_u64(prime)
        .add(U512::from_u128((t as u128 * (n + 1) as u128).div_ceil(2)))
}

fn check_section(source_n: usize, h: usize) {
    use std::time::Instant;
    // The native chart needs its native clock degree even in the smaller
    // source fixture. The encrypted tiny test below uses sourceN128/H2.
    let outer_n = if source_n == 8192 { 16384 } else { 2048 };
    let mut source_config = SecureConfig::secure_128().into_config();
    source_config.n = source_n;
    source_config.primes.truncate(2);
    source_config.security_bits = 0;
    source_config.name = "UNADMITTED coherent source/11-adic section probe";
    let source = RNSFHEContext::try_new(&source_config).unwrap();
    let mut outer_config = SecureConfig::secure_128().into_config();
    outer_config.n = outer_n;
    // The small degree's canonical transient pool has only220 bits. Keep
    // its explicitly insecure fixture at Q180; native N16384 uses the
    // existing315-bit pool and unchanged Q241. No catalog/gate is changed.
    outer_config.primes.extend(if source_n == 8192 {
        &EXTRA[..]
    } else {
        &EXTRA[..2]
    });
    outer_config.security_bits = 0;
    let outer = RNSFHEContext::try_new(&outer_config).unwrap();
    let mut full_high_config = outer_config.clone();
    full_high_config.t = HIGH_PLAIN;
    let full_high = RNSFHEContext::try_new(&full_high_config).unwrap();
    let mut high_config = full_high_config.clone();
    if source_n == 8192 {
        high_config.primes.pop();
    }
    let high = RNSFHEContext::try_new(&high_config).unwrap();
    let mut low_config = high_config;
    low_config.t = LOW_BASE;
    let low = RNSFHEContext::try_new(&low_config).unwrap();
    let mut rng = ShadowHarvester::with_seed(0x4652_4f42_454e_4955 + source_n as u64);
    let trits = balanced_source(source_n, h, &mut rng);
    let source_keys = sparse_keys(&source, &trits, &mut rng);
    let full_boot_keys = outer.generate_keys(&mut rng);
    let boot_keys = prefix_setup_keys(&full_boot_keys, &high);
    let message: Vec<_> = (0..source_n)
        .map(|j| if j % 2 == 0 { 1 } else { source.t - 1 })
        .collect();
    let input = encrypt_polynomial(&source, &source_keys, &message, &mut rng);
    let q: u128 = source.config.primes.iter().map(|&q| q as u128).product();
    let input_v = source.t as u128 * (2 * source_n + 1) as u128 * source.config.eta as u128
        + (q % source.t as u128) * (source.t - 1) as u128;
    assert!(
        observe_polynomial(&source, &input, &source_keys, &message) <= input_v && input_v < q / 64
    );
    let stride = outer_n / source_n;
    let mut source_plain = vec![0; outer_n];
    for (i, &s) in trits.iter().enumerate() {
        source_plain[stride * i] = (s as i64).rem_euclid(HIGH_PLAIN as i64) as u64;
    }
    let full_precharge = encrypt_polynomial(&full_high, &full_boot_keys, &source_plain, &mut rng);
    let full_remainder = U512::product_u64s(&full_high.config.primes).mod_u64(full_high.t) as u128;
    let full_precharge_v =
        full_high.t as u128 * (2 * outer_n + 1) as u128 * full_high.config.eta as u128
            + full_remainder * (full_high.t - 1) as u128;
    let (full_d, full_d_bound) = public_residue_linear(
        &source,
        &full_high,
        &input,
        h,
        q / 64,
        input_v,
        &full_precharge,
        full_precharge_v,
        [9, -11],
    );
    let (precharge, precharge_v, d, d_bound) = if source_n == 8192 {
        let refusal = match full_high.try_exact_evaluator() {
            Err(error) => error,
            Ok(_) => panic!("Q241 should retain its exact rank-capacity refusal"),
        };
        assert!(format!("{refusal:?}").contains("FallbackAccumulatorOverCapacity"));
        let special = *full_high.config.primes.last().unwrap();
        let precharge = drop_special(&high, &full_high, &full_precharge);
        let precharge_v = narrow(drop_view_bound(
            U512::from_u128(full_precharge_v),
            special,
            high.t,
            high.n,
        ));
        let d = drop_special(&high, &full_high, &full_d);
        let d_bound = drop_view_bound(full_d_bound, special, high.t, high.n);
        eprintln!("native section capacity: Q241 exact plan retains typed refusal {refusal:?}; PUBLIC same-key modulus drop to Q{} reduces D certificate bits {}->{}, existing rank/auxiliary guards unchanged",wide_bits(U512::product_u64s(&high.config.primes)),wide_bits(full_d_bound),wide_bits(d_bound));
        (precharge, precharge_v, d, d_bound)
    } else {
        (full_precharge, full_precharge_v, full_d, full_d_bound)
    };
    let remainder = U512::product_u64s(&high.config.primes).mod_u64(high.t) as u128;
    let d_plain = decrypt_coefficients(&high, &d, &boot_keys);
    let d_observed = observe_wide(&high, &d, &boot_keys, &d_plain);
    assert!(words(d_observed) <= words(d_bound));
    // Separate CLIENT oracle obtains the signed original integer D directly
    // from the public components and source trits, not from the evaluator.
    let views: Vec<_> = [99, 121]
        .into_iter()
        .map(|m| {
            (
                preprocess_for_clock(&source, &input.c0, m, outer_n),
                preprocess_for_clock(&source, &input.c1, m, outer_n),
            )
        })
        .collect();
    let mut expected_d = vec![0; outer_n];
    let mut expected_z99 = vec![0; outer_n];
    let mut expected_u11 = vec![0; outer_n];
    for j in 0..source_n {
        let mut z = [views[0].0.clock[j] as i128, views[1].0.clock[j] as i128];
        for (i, &s) in trits.iter().enumerate().filter(|(_, s)| **s != 0) {
            let k = (j + source_n - i) % source_n;
            let sign = s as i128 * if i > j { -1 } else { 1 };
            for a in 0..2 {
                z[a] += sign * views[a].1.clock[k] as i128;
            }
        }
        expected_d[stride * j] = (9 * z[0] - 11 * z[1]).rem_euclid(HIGH_PLAIN as i128) as u64;
        expected_z99[stride * j] = z[0].rem_euclid(HIGH_PLAIN as i128) as u64;
        expected_u11[stride * j] = (-4 * z[0] + 5 * z[1]).rem_euclid(LOW_BASE as i128) as u64;
    }
    assert_eq!(d_plain, expected_d);
    let perturb: Vec<_> = (0..outer_n)
        .map(|i| 11 * ((i * 7 + 3) % 11) as i64)
        .collect();
    let signed_perturb: Vec<_> = perturb
        .iter()
        .map(|&v| if v > 60 { v - 121 } else { v })
        .collect();
    let shifted = add(&high, &d, &public_plain(&high, &signed_perturb));
    let shifted_bound = d_bound.add(U512::from_u128(remainder * 55));
    let expected_shifted: Vec<_> = d_plain
        .iter()
        .zip(&perturb)
        .map(|(&d, &p)| (d + p as u64) % 121)
        .collect();
    assert_eq!(
        decrypt_coefficients(&high, &shifted, &boot_keys),
        expected_shifted
    );
    let evaluator = FrobeniusSection::setup(&high, &boot_keys, &mut rng);
    let expected = plain_section(&high, &d_plain);
    assert_eq!(plain_section(&high, &expected_shifted), expected);
    assert_eq!(plain_section(&high, &expected), expected);
    assert!(expected.iter().zip(&d_plain).all(|(a, b)| a % 11 == b % 11));
    assert_ne!(
        expected,
        d_plain.iter().map(|v| v % 11).collect::<Vec<_>>(),
        "ring section is not the coefficientwise canonical integer lift"
    );
    assert_ne!(
        plain_power11(&high, &d_plain),
        expected,
        "the inverse Galois permutation is essential"
    );
    let start = Instant::now();
    let a = evaluator.apply(&d, d_bound);
    let seconds = start.elapsed().as_secs_f64();
    let b = evaluator.apply(&shifted, shifted_bound);
    let a_observed = observe_wide(&high, &a.section, &boot_keys, &expected);
    let b_observed = observe_wide(&high, &b.section, &boot_keys, &expected);
    assert!(
        words(a_observed) <= words(a.section_bound) && words(b_observed) <= words(b.section_bound)
    );
    let quotient: Vec<_> = d_plain
        .iter()
        .zip(&expected)
        .map(|(&x, &y)| ((x + 121 - y) % 121) / 11)
        .collect();
    let quotient_shifted: Vec<_> = quotient
        .iter()
        .zip(&perturb)
        .map(|(&q, &p)| (q + p as u64 / 11) % 11)
        .collect();
    let qa = observe_wide(&low, &a.quotient, &boot_keys, &quotient);
    let qb = observe_wide(&low, &b.quotient, &boot_keys, &quotient_shifted);
    assert!(words(qa) <= words(a.quotient_bound) && words(qb) <= words(b.quotient_bound));
    assert_ne!(
        decrypt_coefficients(&low, &d, &boot_keys),
        quotient,
        "relabeling the original encoding cannot replace the nonlinear section"
    );
    assert!(
        evaluator.plan(a.section_bound).is_err(),
        "reapplying the section requires a fresh public budget; it cannot reset its certificate"
    );
    // Connect the nonlinear section to the actual integer chart relation
    // Z99=11U+5D. Phi is multiplicative and ignores11U, hence
    // Phi(Z99)=5^11*Phi(D), and its Witt quotient obeys the public identity
    // W(Z99)=U+5W(D)+((5-5^11)/11)*D mod11.
    let (z99, z99_bound) = public_residue_linear(
        &source,
        &high,
        &input,
        h,
        q / 64,
        input_v,
        &precharge,
        precharge_v,
        [1, 0],
    );
    assert_eq!(decrypt_coefficients(&high, &z99, &boot_keys), expected_z99);
    let phi5 = mod_pow(5, 11, 121);
    let phi5_centered = if phi5 > 60 {
        phi5 as i64 - 121
    } else {
        phi5 as i64
    };
    let phi_z99 = signed_scale(&high, &a.section, phi5_centered);
    let expected_phi_z99 = plain_section(&high, &expected_z99);
    assert_eq!(
        decrypt_coefficients(&high, &phi_z99, &boot_keys),
        expected_phi_z99
    );
    let from_high = high.sub(&z99, &phi_z99);
    let from_high_bound = z99_bound
        .add(
            a.section_bound
                .mul_u128(phi5_centered.unsigned_abs() as u128),
        )
        .add(U512::from_u64(10))
        .div_u64(11);
    let expected_wz: Vec<_> = expected_z99
        .iter()
        .zip(&expected_phi_z99)
        .map(|(&x, &y)| ((x + 121 - y) % 121) / 11)
        .collect();
    let source_low: Vec<_> = source_plain.iter().map(|v| v % 11).collect();
    let low_precharge = encrypt_polynomial(&low, &boot_keys, &source_low, &mut rng);
    let low_remainder = U512::product_u64s(&low.config.primes).mod_u64(low.t) as u128;
    let low_precharge_v = low.t as u128 * (2 * outer_n + 1) as u128 * low.config.eta as u128
        + low_remainder * (low.t - 1) as u128;
    let (u11, u11_bound) = public_residue_linear(
        &source,
        &low,
        &input,
        h,
        q / 64,
        input_v,
        &low_precharge,
        low_precharge_v,
        [-4, 5],
    );
    let (d11, d11_bound) = public_residue_linear(
        &source,
        &low,
        &input,
        h,
        q / 64,
        input_v,
        &low_precharge,
        low_precharge_v,
        [9, -11],
    );
    assert_eq!(decrypt_coefficients(&low, &u11, &boot_keys), expected_u11);
    assert_eq!(
        decrypt_coefficients(&low, &d11, &boot_keys),
        expected_d.iter().map(|v| v % 11).collect::<Vec<_>>()
    );
    let scalar = (5 - phi5 as i64) / 11;
    let scalar = scalar.rem_euclid(11);
    let scalar = if scalar > 5 { scalar - 11 } else { scalar };
    let from_chart = add(
        &low,
        &add(&low, &u11, &signed_scale(&low, &a.quotient, 5)),
        &signed_scale(&low, &d11, scalar),
    );
    let from_chart_bound = u11_bound
        .add(a.quotient_bound.mul_u128(5))
        .add(d11_bound.mul_u128(scalar.unsigned_abs() as u128));
    let wz_high = observe_wide(&low, &from_high, &boot_keys, &expected_wz);
    let wz_chart = observe_wide(&low, &from_chart, &boot_keys, &expected_wz);
    assert!(words(wz_high) <= words(from_high_bound) && words(wz_chart) <= words(from_chart_bound));
    eprintln!("11-adic chart compatibility: sourceN{source_n}, all{outer_n} coefficients of W(Z99) agree through high121 difference and U+5W(D)+{scalar}D mod11; independent coherent low11 precharge, no encrypted value converted by relabeling; observed/bound bits via high={}/{}, via chart={}/{}; ring Witt digit only, canonical integer K and p65537 return remain OPEN",wide_bits(wz_high),wide_bits(from_high_bound),wide_bits(wz_chart),wide_bits(from_chart_bound));
    eprintln!("11-adic ring section: sourceN{source_n}/outerN{outer_n}, Qbits={}, sourceH{h}, coherent D mod121; all{outer_n} coefficients correct, Phi=sigma_{}(D^11), FIVE exact products+ONE raw Galois switch, depth4, no coefficient/slot map; dense +11H perturb has IDENTICAL section message, quotient changes by H mod11; V input observed/bound={}/{}, section observed/bound={}/{}, quotient observed/bound={}/{}, second perturb output observed bits={}, public section time={seconds:.6}s; direct reinterpretation and missing-Galois controls fail, encrypted repeat preflight REFUSED; ring section is NOT canonical integer K, native public bootstrap admission remains FALSE",wide_bits(U512::product_u64s(&high.config.primes)),evaluator.exponent,wide_bits(d_observed),wide_bits(d_bound),wide_bits(a_observed),wide_bits(a.section_bound),wide_bits(qa),wide_bits(a.quotient_bound),wide_bits(b_observed));
}

#[test]
#[ignore = "opt-in small-source encrypted ring section; outerN2048 is explicitly insecure"]
fn frobenius_chart_section_small_source_preserves_low_residue_and_extracts_witt_digit() {
    check_section(128, 2);
}

#[test]
#[ignore = "opt-in full native ringwise nonlinear 11-adic section; NOT a public-bootstrap admission"]
fn frobenius_chart_section_native_contracts_coherent_residue_and_tracks_quotient() {
    check_section(8192, 96);
}
