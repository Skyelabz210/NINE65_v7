//! Research: reduce the modulus under the outer key BEFORE exposing return
//! keys at the work modulus. Recover an even polynomial in a doubled ring.

use super::*;

#[path = "sparse_source_encapsulation.rs"]
mod sparse_source_encapsulation;

const EXTRA: [u64; 4] = [1811939329, 2113929217, 2130706433, 1107296257];

fn wide_bits(x: U512) -> u32 {
    for (shift, limb) in [(384, x.d3), (256, x.d2), (128, x.d1), (0, x.d0)] {
        if limb != 0 {
            return shift + bits(limb);
        }
    }
    0
}

fn narrow(x: U512) -> u128 {
    assert_eq!(
        (x.d3, x.d2, x.d1),
        (0, 0, 0),
        "work-domain bound exceeds u128"
    );
    x.d0
}

fn split(ctx: &RNSFHEContext, p: &RNSPolynomial, parity: usize) -> RNSPolynomial {
    assert!(parity < 2);
    assert_eq!(p.n, 2 * ctx.n);
    assert_eq!(p.limbs.len(), ctx.config.primes.len());
    // Both contexts have the same main primes and Montgomery constants.
    RNSPolynomial {
        n: ctx.n,
        limbs: p
            .limbs
            .iter()
            .map(|v| v.iter().skip(parity).step_by(2).copied().collect())
            .collect(),
    }
}

fn times_x(ctx: &RNSFHEContext, p: &RNSPolynomial) -> RNSPolynomial {
    rotate(
        ctx,
        &RNSCiphertext {
            c0: p.clone(),
            c1: RNSPolynomial::zero(&ctx.rns),
            num_primes: ctx.config.primes.len(),
        },
        1,
    )
    .c0
}

// Process one polarity at a time to halve the expansion stack. Traversal
// and output batching use public indices, never private zero support.
#[allow(clippy::too_many_arguments)]
fn visit_column(
    engine: &Engine<'_>,
    packed: &Packed,
    rows: Vec<RNSCiphertext>,
    degree: usize,
    stride: usize,
    index: usize,
    step: usize,
    polarity: usize,
    consume: &mut impl FnMut(usize, usize, Multiplier),
) {
    if degree == 1 {
        consume(index, polarity, finish_column(engine, packed, &rows));
        return;
    }
    let mut even = Vec::new();
    let mut odd = Vec::new();
    for row in rows {
        let conjugate = engine.galois(&row, degree + 1, &packed.galois);
        even.push(add(engine.ctx, &row, &conjugate));
        odd.push(rotate(
            engine.ctx,
            &engine.ctx.sub(&row, &conjugate),
            -(stride as i64),
        ));
    }
    visit_column(
        engine,
        packed,
        even,
        degree / 2,
        stride * 2,
        index,
        step * 2,
        polarity,
        consume,
    );
    visit_column(
        engine,
        packed,
        odd,
        degree / 2,
        stride * 2,
        index + step,
        step * 2,
        polarity,
        consume,
    );
}

fn visit_by_polarity(
    engine: &Engine<'_>,
    packed: &Packed,
    consume: &mut impl FnMut(usize, usize, Multiplier),
) {
    for (block, columns) in packed.columns.iter().enumerate() {
        for (polarity, column) in columns.iter().enumerate() {
            visit_column(
                engine,
                packed,
                column.clone(),
                packed.block,
                engine.ctx.n / packed.block,
                block * packed.block,
                1,
                polarity,
                consume,
            );
        }
    }
}

struct PublicOuterReturn<'a> {
    work: &'a RNSFHEContext,
    source: &'a RNSFHEContext,
    outer: Engine<'a>,
    packed: Packed,
    // One ordinary BFV precharge of s_work(Y^2). No clear secret in evaluator.
    linear_source: RNSCiphertext,
    drop_contexts: Vec<RNSFHEContext>,
    return_even: RawKey,
    return_odd: RawKey,
    source_norm: usize,
    coordinate: usize,
    phase_cap: u128,
    output_batch: usize,
}

struct RingOutput {
    outer: RNSCiphertext,
    reduced: RNSCiphertext,
    returned: RNSCiphertext,
    without_carry: RNSCiphertext,
    outer_bound: U512,
    reduced_bound: u128,
    returned_bound: u128,
}

fn outer_noise_bound(
    ctx: &RNSFHEContext,
    source_n: usize,
    coordinate: usize,
    external_bound: u128,
    galois_bound: u128,
) -> U512 {
    let rem = U512::product_u64s(&ctx.config.primes).mod_u64(ctx.t) as u128;
    let lookup_norm = (ctx.t - 1) as u128 / ctx.n as u128 * (coordinate / 2) as u128;
    let carry = U512::from_u128(rem * lookup_norm)
        .add(U512::from_u128(external_bound).mul_u128(ctx.t as u128 * 2 * source_n as u128))
        .mul_u128(ctx.n as u128)
        .add(U512::from_u128(
            ctx.t as u128 * (ctx.n - 1) as u128 * galois_bound,
        ));
    let linear_fresh_v = ctx.t as u128 * (2 * ctx.n + 1) as u128 * ctx.config.eta as u128
        + rem * (ctx.t - 1) as u128;
    let affine_v =
        linear_fresh_v * source_n as u128 * (ctx.t - 1) as u128 + rem * (ctx.t / 2) as u128;
    carry
        .mul_u128(source_n as u128)
        .add(U512::from_u128(affine_v))
}

impl PublicOuterReturn<'_> {
    fn apply(&self, input: &RNSCiphertext, input_bound: u128) -> RingOutput {
        let ctx = self.outer.ctx;
        let source_n = self.source.n;
        assert_eq!(source_n, self.work.n);
        assert_eq!(self.source.t, self.work.t);
        assert_eq!(ctx.n, 2 * source_n);
        assert_eq!(self.packed.source_len, source_n);
        assert_eq!(
            self.work
                .config
                .primes
                .iter()
                .map(|&q| q as u128)
                .product::<u128>(),
            Q_SOURCE as u128
        );
        assert_eq!(input.num_primes, self.source.config.primes.len());
        assert_eq!(
            &self.work.config.primes[..self.source.config.primes.len()],
            &self.source.config.primes
        );
        assert!(input_bound <= self.phase_cap);
        assert_eq!(
            &ctx.config.primes[..self.work.config.primes.len()],
            &self.work.config.primes
        );
        let source_q = self
            .source
            .config
            .primes
            .iter()
            .map(|&q| q as u128)
            .product();
        let window2 = phase_window2_for_q(
            ctx.n,
            self.source_norm,
            self.coordinate,
            self.phase_cap,
            source_q,
        );
        assert!(window2 < ctx.n as u128);
        assert!(self.coordinate > 2 * self.source_norm.div_ceil(2));
        assert!(self.output_batch > 0 && self.output_batch <= source_n);
        let c0 = preprocess_for_clock(self.source, &input.c0, self.coordinate, ctx.n);
        let c1 = preprocess_for_clock(self.source, &input.c1, self.coordinate, ctx.n);
        let lookup = clock_lut(ctx, self.coordinate, window2 as i64);
        let mut carry = zero(ctx);
        let mut external_bound = None;
        for start in (0..source_n).step_by(self.output_batch) {
            let end = (start + self.output_batch).min(source_n);
            let mut clocks: Vec<_> = c0.clock[start..end]
                .iter()
                .map(|&b| rotate(ctx, &lookup, b))
                .collect();
            let mut seen = BTreeSet::new();
            visit_by_polarity(&self.outer, &self.packed, &mut |i, polarity, key| {
                assert!(seen.insert((i, polarity)));
                for (offset, clock) in clocks.iter_mut().enumerate() {
                    let j = start + offset;
                    let k = (j + source_n - i) % source_n;
                    let sign = if (i > j) ^ (polarity == 0) { -1 } else { 1 };
                    *clock = self.outer.cmux(clock, sign * c1.clock[k], &key);
                }
                external_bound = Some(self.outer.external_error(&key));
            });
            assert_eq!(seen.len(), 2 * source_n);
            for (offset, clock) in clocks.into_iter().enumerate() {
                let j = start + offset;
                carry = add(
                    ctx,
                    &carry,
                    &rotate(
                        ctx,
                        &self.outer.trace(clock, ctx.n, &self.packed.galois),
                        (2 * j) as i64,
                    ),
                );
            }
        }

        // The ENTIRE affine polynomial is linear. One encrypted source
        // polynomial times PUBLIC A1 replaces per-coefficient bit products.
        let mut a1 = vec![0; ctx.n];
        let mut a0 = vec![0; ctx.n];
        for j in 0..source_n {
            a1[2 * j] = c1.a[j];
            a0[2 * j] = if c0.a[j] > ctx.t / 2 {
                c0.a[j] as i64 - ctx.t as i64
            } else {
                c0.a[j] as i64
            };
        }
        let affine = add(
            ctx,
            &multiply_plain(ctx, &self.linear_source, &a1),
            &public_plain(ctx, &a0),
        );
        let output = add(ctx, &affine, &carry);
        let gal = self.packed.galois.values().next().unwrap();
        let eg = ctx.n as u128 * gal.shape.digit_sum * gal.beta;
        // U512 is required: native large-radix assembly exceeds 128 bits.
        let outer_bound =
            outer_noise_bound(ctx, source_n, self.coordinate, external_bound.unwrap(), eg);
        assert!(words(outer_bound.mul_u128(2)) < words(U512::product_u64s(&ctx.config.primes)));

        // No work-key ciphertext is ever published at the larger modulus.
        let mut reduced = output.clone();
        let mut previous = ctx;
        let mut reduced_v = outer_bound;
        for next in &self.drop_contexts {
            assert_eq!(next.n, ctx.n);
            let special = *previous.config.primes.last().unwrap();
            reduced = drop_special(next, previous, &reduced);
            reduced_v = reduced_v
                .add(U512::from_u64(special - 1))
                .div_u64(special)
                .add(U512::from_u128(
                    (ctx.t as u128 * (ctx.n + 1) as u128).div_ceil(2),
                ));
            assert!(words(reduced_v.mul_u128(2)) < words(U512::product_u64s(&next.config.primes)));
            previous = next;
        }
        assert_eq!(previous.config.primes, self.work.config.primes);
        let return_engine = Engine {
            ctx: self.work,
            switches: Cell::new(0),
        };
        // s_outer(Y)=se(X)+Y*so(X), X=Y^2. The even phase is
        // c0e+c1e*se+X*c1o*so, over X^N+1. No dense ring trace.
        let even = return_engine.switch(&split(self.work, &reduced.c1, 0), &self.return_even);
        let odd = return_engine.switch(
            &times_x(self.work, &split(self.work, &reduced.c1, 1)),
            &self.return_odd,
        );
        let returned = add(self.work, &even, &odd);
        let returned = RNSCiphertext {
            c0: returned
                .c0
                .add(&split(self.work, &reduced.c0, 0), &self.work.rns),
            ..returned
        };
        assert_eq!(return_engine.switches.get(), 2);
        let reduced_bound = narrow(reduced_v);
        let switch_v = self.work.t as u128
            * source_n as u128
            * (self.return_even.shape.digit_sum * self.return_even.beta
                + self.return_odd.shape.digit_sum * self.return_odd.beta);
        RingOutput {
            outer: output,
            reduced,
            returned,
            without_carry: affine,
            outer_bound,
            reduced_bound,
            returned_bound: reduced_bound + switch_v,
        }
    }
}

fn embedded(message: &[u64]) -> Vec<u64> {
    let mut out = vec![0; 2 * message.len()];
    for (j, &m) in message.iter().enumerate() {
        out[2 * j] = m;
    }
    out
}

#[test]
fn outer_ring_return_requires_larger_dimension_for_published_outer_tuple() {
    let mut primes = SecureConfig::secure_128().into_config().primes;
    primes.extend(EXTRA);
    assert!(SecureConfig::custom_screened(8192, primes.clone(), 65537, 3, 128).is_err());
    assert!(SecureConfig::custom_screened(16384, primes, 65537, 3, 128).is_ok());
}

#[test]
fn outer_ring_even_phase_identity_includes_cross_term_and_negacyclic_wrap() {
    let mut config = SecureConfig::secure_128().into_config();
    config.n = 16;
    config.security_bits = 0;
    let work = RNSFHEContext::try_new(&config).unwrap();
    config.n *= 2;
    let outer = RNSFHEContext::try_new(&config).unwrap();
    for (lane, &q) in work.config.primes.iter().enumerate() {
        let a: Vec<_> = (0..outer.n).map(|j| ((j * 7 + 3) as u64) % q).collect();
        let b: Vec<_> = (0..outer.n).map(|j| ((j * 11 + 5) as u64) % q).collect();
        let full = outer.ntt_engines[lane].multiply(&a, &b);
        let parity = |v: &[u64], p| v.iter().skip(p).step_by(2).copied().collect::<Vec<_>>();
        let ee = work.ntt_engines[lane].multiply(&parity(&a, 0), &parity(&b, 0));
        let oo = work.ntt_engines[lane].multiply(&parity(&a, 1), &parity(&b, 1));
        let mut xoo = vec![0; work.n];
        xoo[0] = if oo[work.n - 1] == 0 {
            0
        } else {
            q - oo[work.n - 1]
        };
        xoo[1..].copy_from_slice(&oo[..work.n - 1]);
        let result: Vec<_> = ee.iter().zip(&xoo).map(|(&x, &y)| (x + y) % q).collect();
        assert_eq!(result, parity(&full, 0));
        assert_ne!(ee, result, "fixture must reject omitting X*c1o*so");
    }
}

#[test]
#[ignore = "opt-in native input/preprocessing geometry check; NOT encrypted native bootstrap"]
fn outer_ring_native_preprocessing_covers_all_real_source_coefficients() {
    let mut config = SecureConfig::secure_128().into_config();
    // The dimension/modulus are native. Weight32 is research-only: the
    // repository's dense-key security screen does not certify this source.
    config.security_bits = 0;
    config.name = "UNADMITTED sparse32 native input geometry";
    let work = RNSFHEContext::try_new(&config).unwrap();
    let mut outer_config = config.clone();
    outer_config.n *= 2;
    outer_config.primes.extend(EXTRA);
    let outer = RNSFHEContext::try_new(&outer_config).unwrap();
    let mut rng = ShadowHarvester::with_seed(0x4e41_5449_5645_5143);
    let mut source = vec![0i8; work.n];
    let mut support = BTreeSet::new();
    while support.len() < 32 {
        let j = rng.next_u64() as usize % work.n;
        if support.insert(j) {
            source[j] = if rng.next_u64() & 1 == 0 { 1 } else { -1 };
        }
    }
    let keys = sparse_keys(&work, &source, &mut rng);
    let message: Vec<_> = (0..work.n)
        .map(|j| if j % 2 == 0 { 1 } else { work.t - 1 })
        .collect();
    let exact = work.try_exact_evaluator().unwrap();
    let relin = exact.generate_hybrid_gadget_key_with_rng(&keys.secret_key, &mut rng);
    let encrypted = encrypt_polynomial(&work, &keys, &message, &mut rng);
    let mut input = exact.try_mul_exact(&encrypted, &encrypted, &relin).unwrap();
    // Independent closed-form negacyclic square of sum_j (-X)^j.
    let expected: Vec<_> = (0..work.n)
        .map(|j| {
            let coefficient = (2 * j + 2) as i64 - work.n as i64;
            (if j % 2 == 0 {
                coefficient
            } else {
                -coefficient
            })
            .rem_euclid(work.t as i64) as u64
        })
        .collect();
    let load = Q_SOURCE as u128 / (512 * work.t as u128);
    let loaded = montgomery(
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
    input.c0 = input.c0.add(&loaded, &work.rns);
    let observed = observe_polynomial(&work, &input, &keys, &expected);
    let fresh = work.t as u128 * (2 * work.n + 1) as u128 * config.eta as u128
        + (Q_SOURCE as u128 % work.t as u128) * (work.t - 1) as u128;
    let producer_bound = square_history_bound(&work, fresh) + load * work.t as u128;
    let cap = Q_SOURCE as u128 / 8;
    assert!(observed <= producer_bound && producer_bound < cap);
    let coordinate = 33;
    let public0 = preprocess_for_clock(&work, &input.c0, coordinate, outer.n);
    let public1 = preprocess_for_clock(&work, &input.c1, coordinate, outer.n);
    let window = phase_window2(outer.n, 32, coordinate, cap);
    assert!(window < outer.n as u128);
    let lookup = clock_lut(&outer, coordinate, window as i64);
    let decode = CanonicalScaleRound::new(&outer.config.primes, outer.t).unwrap();
    let public_lookup = ordinary(&outer, &lookup.c0);
    let lookup_values: Vec<_> = (0..outer.n)
        .map(|j| {
            decode
                .scale_round(&public_lookup.iter().map(|lane| lane[j]).collect::<Vec<_>>())
                .unwrap()
        })
        .collect();
    // From here on: CLIENT-ONLY reconstruction of the true hidden sheet and
    // clear clock sum. None of these values enter any public evaluator.
    let components = |p: &RNSPolynomial| {
        let raw = ordinary(&work, p);
        let round = RoundProjection::new(&config.primes, work.t);
        (0..work.n)
            .map(|j| {
                let residues: Vec<_> = raw.iter().map(|lane| lane[j]).collect();
                let a = round.round(&residues);
                let scaled = client_crt(&work, &residues).mul_u128(work.t as u128);
                let qa = U512::from_u128(Q_SOURCE as u128).mul_u128(a as u128);
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
    let r0 = components(&input.c0);
    let r1 = components(&input.c1);
    let mut sheets = BTreeSet::new();
    for j in 0..work.n {
        let mut s = r0[j];
        let mut z = public0.clock[j];
        let mut affine = public0.a[j] as i128;
        for &i in &support {
            let k = (j + work.n - i) % work.n;
            let sign = source[i] as i128 * if i > j { -1 } else { 1 };
            s += sign * r1[k];
            z += sign as i64 * public1.clock[k];
            affine += sign * public1.a[k] as i128;
        }
        let k = (s + Q_SOURCE / 2).div_euclid(Q_SOURCE);
        let g = s - Q_SOURCE * k;
        assert!(g.unsigned_abs() <= producer_bound);
        assert!(k.abs() <= 16);
        sheets.insert(k);
        assert_eq!((affine + k).rem_euclid(work.t as i128) as u64, expected[j]);
        let rotation = z.rem_euclid((2 * outer.n) as i64) as usize;
        let (index, sign) = if rotation == 0 {
            (0, 1i128)
        } else if rotation <= outer.n {
            (outer.n - rotation, -1)
        } else {
            (2 * outer.n - rotation, 1)
        };
        let readout =
            (sign * lookup_values[index] as i128 * outer.n as i128).rem_euclid(work.t as i128);
        assert_eq!(
            readout,
            k.rem_euclid(work.t as i128),
            "native coefficient {j}"
        );
    }
    assert!(sheets.iter().any(|&k| k != 0));
    // Exercise the REAL Rust bound routine above 128 bits, independently
    // cross-checked with the Python arbitrary-integer ledger. No keys allocated.
    let shape = Shape::new(&outer, 10);
    let eg = outer.n as u128 * shape.digit_sum * outer.config.eta as u128;
    let beta = work.n as u128 * outer.config.eta as u128 + (work.n - 1) as u128 * eg;
    let beta_secret = outer.n as u128 * beta + 2 * eg;
    let ext = outer.n as u128 * shape.digit_sum * (beta + beta_secret);
    let native_bound = outer_noise_bound(&outer, work.n, coordinate, ext, eg);
    assert_eq!(
        words(native_bound),
        (0, 0, 25330, 170661182008973428005919132679417298944)
    );
    assert_eq!(wide_bits(native_bound), 143);
    eprintln!("native input/clock geometry: workN8192, clockN16384, actual full-mask public encryption and exact dense polynomial square, all8192 coefficient messages and hidden-sheet windows agree, source H32 UNADMITTED, incoming Vbits={}, producer bound bits={}, window={window}, sheets={sheets:?}; CLIENT semantic oracle only, no native encrypted clock/bootstrap execution", bits(observed),bits(producer_bound));
}

#[test]
#[ignore = "opt-in INSECURE N16/N32 doubled-ring public refresh/return/repeat probe"]
fn outer_ring_reduce_before_switch_recovers_full_polynomial_and_repeats() {
    let mut config = SecureConfig::secure_128().into_config();
    config.n = 16;
    config.security_bits = 0;
    config.name = "INSECURE doubled-ring public return research";
    let work = RNSFHEContext::try_new(&config).unwrap();
    let mut outer_config = config.clone();
    outer_config.n *= 2;
    outer_config.primes.extend(EXTRA);
    let outer = RNSFHEContext::try_new(&outer_config).unwrap();
    let engine = Engine {
        ctx: &outer,
        switches: Cell::new(0),
    };
    let mut rng = ShadowHarvester::with_seed(0x4f55_5445_5252_4554);
    let mut source = vec![0i8; work.n];
    source[3] = 1;
    source[13] = -1;
    let work_keys = sparse_keys(&work, &source, &mut rng);
    let outer_keys = outer.generate_keys(&mut rng);
    let packed = setup(&engine, &outer_keys, &source, 8, 10, 10, &mut rng);
    let source_message: Vec<_> = source
        .iter()
        .map(|&s| (s as i64).rem_euclid(work.t as i64) as u64)
        .collect();
    let linear_source =
        encrypt_polynomial(&outer, &outer_keys, &embedded(&source_message), &mut rng);
    let mut drop_contexts = Vec::new();
    let mut drop_config = outer_config;
    while drop_config.primes.len() > config.primes.len() {
        drop_config.primes.pop();
        drop_contexts.push(RNSFHEContext::try_new(&drop_config).unwrap());
    }
    // Secret-holder setup at WORK Q only. The outer secret's parity parts
    // already have the same Montgomery residues on the working prime prefix.
    let mut at_work = outer_keys.secret_key.s.clone();
    at_work.limbs.truncate(config.primes.len());
    let return_shape = Shape::new(&work, 10);
    let even_rows = raw_rows(
        &work,
        &return_shape,
        &split(&work, &at_work, 0),
        &work_keys,
        &mut rng,
    );
    let odd_rows = raw_rows(
        &work,
        &return_shape,
        &split(&work, &at_work, 1),
        &work_keys,
        &mut rng,
    );
    let return_engine = Engine {
        ctx: &work,
        switches: Cell::new(0),
    };
    let pipeline = PublicOuterReturn {
        work: &work,
        source: &work,
        outer: engine,
        packed,
        linear_source,
        drop_contexts,
        return_even: return_engine.cache(&return_shape, &even_rows, config.eta as u128),
        return_odd: return_engine.cache(&return_shape, &odd_rows, config.eta as u128),
        source_norm: 2,
        coordinate: 9,
        phase_cap: Q_SOURCE as u128 / 128,
        output_batch: 4,
    };
    let exact = work.try_exact_evaluator().unwrap();
    let relin = exact.generate_hybrid_gadget_key_with_rng(&work_keys.secret_key, &mut rng);
    let mut message: Vec<_> = (0..work.n).map(|j| (5 * j + 7) as u64).collect();
    message[work.n - 1] = work.t - 3;
    let mut current = encrypt_polynomial(&work, &work_keys, &message, &mut rng);
    let mut bound = work.t as u128 * (2 * work.n + 1) as u128 * config.eta as u128
        + (Q_SOURCE as u128 % work.t as u128) * (work.t - 1) as u128;
    let mut omissions = 0;
    for cycle in 0..2 {
        current = exact.try_mul_exact(&current, &current, &relin).unwrap();
        bound = square_history_bound(&work, bound);
        message = square_plain(&message, work.t);
        let load = Q_SOURCE as u128 / (512 * work.t as u128);
        let error = montgomery(
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
        current.c0 = current.c0.add(&error, &work.rns);
        bound += load * work.t as u128;
        let incoming = observe_polynomial(&work, &current, &work_keys, &message);
        assert!(incoming <= bound);
        let out = pipeline.apply(&current, bound);
        let expected_outer = embedded(&message);
        let observed_outer = observe_polynomial(&outer, &out.outer, &outer_keys, &expected_outer);
        assert!(words(U512::from_u128(observed_outer)) <= words(out.outer_bound));
        // Observe the reduced ciphertext under the SAME dense outer secret.
        let reduced_ctx = pipeline.drop_contexts.last().unwrap();
        let mut reduced_key = outer_keys.secret_key.clone();
        reduced_key.s.limbs.truncate(config.primes.len());
        let reduced_keys = RNSKeySet {
            secret_key: reduced_key,
            public_key: outer_keys.public_key.clone(),
            eval_key: RNSEvalKey {
                rlk: Vec::new(),
                decomp_base: 1 << 16,
            },
        };
        let observed_reduced =
            observe_polynomial(reduced_ctx, &out.reduced, &reduced_keys, &expected_outer);
        assert!(observed_reduced <= out.reduced_bound);
        let observed_returned = observe_polynomial(&work, &out.returned, &work_keys, &message);
        assert!(observed_returned <= out.returned_bound);
        assert!(observed_returned < incoming);
        let affine = decrypt_coefficients(&outer, &out.without_carry, &outer_keys);
        omissions += affine
            .iter()
            .zip(&expected_outer)
            .filter(|(a, b)| a != b)
            .count();
        // Wrong-key and missing-odd-branch controls are independent failures.
        let wrong = RNSCiphertext {
            c0: split(&work, &out.reduced.c0, 0),
            c1: split(&work, &out.reduced.c1, 0),
            num_primes: config.primes.len(),
        };
        assert_ne!(decrypt_coefficients(&work, &wrong, &work_keys), message);
        let one_branch =
            return_engine.switch(&split(&work, &out.reduced.c1, 0), &pipeline.return_even);
        let one_branch = RNSCiphertext {
            c0: one_branch
                .c0
                .add(&split(&work, &out.reduced.c0, 0), &work.rns),
            ..one_branch
        };
        assert_ne!(
            decrypt_coefficients(&work, &one_branch, &work_keys),
            message
        );
        bound = out.returned_bound;
        current = out.returned;
        let next_bound = square_history_bound(&work, bound);
        assert!(next_bound < pipeline.phase_cap);
        eprintln!("outer ring public return: cycle={cycle}, INSECURE workN16/outerN32, Q119/Q241, source weight2, all16 coefficients/positions; incoming Vbits={}, outer observed/bound={}/{}, reduced={}/{}, returned={}/{}, following polynomial square bound={}; no return key above work Q",bits(incoming),bits(observed_outer),wide_bits(out.outer_bound),bits(observed_reduced),bits(out.reduced_bound),bits(observed_returned),bits(out.returned_bound),bits(next_bound));
    }
    let next = exact.try_mul_exact(&current, &current, &relin).unwrap();
    observe_polynomial(&work, &next, &work_keys, &square_plain(&message, work.t));
    assert!(omissions > 0);
    let d: usize = pipeline.packed.shape.digits.iter().sum();
    let expansion =
        2 * (work.n / pipeline.packed.block) * d * (pipeline.packed.block - 1) + 4 * work.n * d;
    let expected_outer_switches = 2
        * (work.n.div_ceil(pipeline.output_batch) * expansion
            + 4 * work.n * work.n
            + work.n * outer.n.ilog2() as usize);
    assert_eq!(pipeline.outer.switches.get(), expected_outer_switches);
    eprintln!("outer ring public return: same precharge reused twice, batch={}, outer raw switches={}, return raw switches=4, carry omission corrupts {omissions} coefficients; wrong-key and omitted cross-term controls fail; full native admission remains FALSE", pipeline.output_batch, expected_outer_switches);
}
