//! Research-only full-polynomial integration. No production admission token.
//! Evaluation owns public contexts and precharged ciphertexts, never either key.

use super::*;
use nine65::arithmetic::main_only_base_ext::MainOnlyBaseExt;
use nine65::ops::rns_fhe::{RNSEvalKey, RNSPublicKey, RNSSecretKey};

const SPECIAL: u64 = 1_811_939_329;

// Unlike CanonicalScaleRound, this local prototype supports an EVEN target.
// Q is odd, so floor(Q/2) mod T = ((Q mod 2T)-1)/2. No inverse of 2
// modulo T is used. Only the public rank projector's bounded comparisons
// are needed; a canonical wide ciphertext coefficient is never materialized.
struct RoundProjection {
    main: Vec<u64>,
    target: u64,
    projector: MainOnlyBaseExt,
    half: u64,
    q_inverse: u64,
}

impl RoundProjection {
    fn new(main: &[u64], target: u64) -> Self {
        assert!(target >= 2 && target <= i64::MAX as u64 / 2);
        assert!(main.iter().all(|q| q % 2 == 1));
        let twice = 2 * target;
        let q_mod = main
            .iter()
            .fold(1u64, |a, &q| (a as u128 * q as u128 % twice as u128) as u64);
        Self {
            main: main.to_vec(),
            target,
            projector: MainOnlyBaseExt::new(main, &[target]).unwrap(),
            half: (q_mod - 1) / 2,
            q_inverse: inverse(q_mod % target, target),
        }
    }

    // Unwrap the endpoint T, which is otherwise returned as zero. Its
    // ambiguity is resolved by the PUBLIC canonical coefficient's half.
    fn round(&self, input: &[u64]) -> u64 {
        assert_eq!(input.len(), self.main.len());
        let remainder: Vec<_> = input
            .iter()
            .zip(&self.main)
            .map(|(&x, &q)| {
                assert!(x < q);
                ((x as u128 * self.target as u128 + (q - 1) as u128 / 2) % q as u128) as u64
            })
            .collect();
        let mut out = [0];
        self.projector.project(&remainder, &mut out).unwrap();
        let y = ((self.half as u128 + self.target as u128 - out[0] as u128)
            * self.q_inverse as u128
            % self.target as u128) as u64;
        if y == 0 {
            let (_, upper) = self.projector.project_centered(input, &mut out).unwrap();
            if upper {
                return self.target;
            }
        }
        y
    }
}

struct Components {
    a: Vec<u64>,
    clock: Vec<i64>,
}

fn preprocess(ctx: &RNSFHEContext, p: &RNSPolynomial, coordinate: usize) -> Components {
    assert!(coordinate >= 3 && coordinate % 2 == 1);
    let size = 2 * ctx.n as u64;
    let coarse = RoundProjection::new(&ctx.config.primes, ctx.t);
    let fine = RoundProjection::new(&ctx.config.primes, size * ctx.t);
    let input = ordinary(ctx, p);
    let mut a = Vec::with_capacity(ctx.n);
    let mut clock = Vec::with_capacity(ctx.n);
    for j in 0..ctx.n {
        let residues: Vec<_> = input.iter().map(|lane| lane[j]).collect();
        let ai = coarse.round(&residues);
        let u = fine.round(&residues) as i64 - size as i64 * ai as i64;
        // For ODD m, round(round(x)/m)=round(x/m), including the negative
        // half convention. Thus no extra double-rounding error is charged.
        clock.push((u + coordinate as i64 / 2).div_euclid(coordinate as i64));
        a.push(ai % ctx.t);
    }
    Components { a, clock }
}

// Secret-dependent setup ONLY. The legacy key is deliberately empty:
// exact multiplication uses its separately generated hybrid gadget key.
fn sparse_keys(ctx: &RNSFHEContext, source: &[i8], rng: &mut ShadowHarvester) -> RNSKeySet {
    assert_eq!(source.len(), ctx.n);
    let mut keys = RNSKeySet {
        secret_key: RNSSecretKey {
            s: montgomery(
                ctx,
                ctx.config
                    .primes
                    .iter()
                    .map(|&q| {
                        source
                            .iter()
                            .map(|&s| (s as i128).rem_euclid(q as i128) as u64)
                            .collect()
                    })
                    .collect(),
            ),
        },
        public_key: RNSPublicKey {
            pk0: RNSPolynomial::zero(&ctx.rns),
            pk1: RNSPolynomial::zero(&ctx.rns),
        },
        eval_key: RNSEvalKey {
            rlk: Vec::new(),
            decomp_base: 1 << 16,
        },
    };
    let mut rows = raw_rows(
        ctx,
        &Shape::new(ctx, 10),
        &RNSPolynomial::zero(&ctx.rns),
        &keys,
        rng,
    );
    let row = rows.swap_remove(0);
    keys.public_key = RNSPublicKey {
        pk0: row.c0,
        pk1: row.c1,
    };
    keys
}

// Public return kernel. For Q_boot=P*Q_work and r=center_P(C),
// round(C/P) mod q_i = (C_i-r)*P^{-1} mod q_i. Apply independently
// to the two components; retain the SAME work secret. No large CRT/division.
fn drop_special(work: &RNSFHEContext, boot: &RNSFHEContext, ct: &RNSCiphertext) -> RNSCiphertext {
    assert_eq!(work.n, boot.n);
    assert_eq!(work.t, boot.t);
    assert_eq!(boot.config.primes.len(), work.config.primes.len() + 1);
    assert_eq!(
        &boot.config.primes[..work.config.primes.len()],
        &work.config.primes
    );
    assert_eq!(ct.num_primes, boot.config.primes.len());
    let special = *boot.config.primes.last().unwrap();
    let apply = |p: &RNSPolynomial| {
        let input = ordinary(boot, p);
        let last = input.last().unwrap();
        montgomery(
            work,
            work.config
                .primes
                .iter()
                .enumerate()
                .map(|(lane, &q)| {
                    let inv = inverse(special % q, q);
                    input[lane]
                        .iter()
                        .zip(last)
                        .map(|(&x, &r)| {
                            let r = if r > special / 2 {
                                r as i128 - special as i128
                            } else {
                                r as i128
                            };
                            ((x as i128 - r).rem_euclid(q as i128) as u128 * inv as u128
                                % q as u128) as u64
                        })
                        .collect()
                })
                .collect(),
        )
    };
    RNSCiphertext {
        c0: apply(&ct.c0),
        c1: apply(&ct.c1),
        num_primes: work.config.primes.len(),
    }
}

// There is intentionally no secret, expected message, decrypted phase, or
// client noise measurement in this evaluator or its apply() arguments.
struct PublicPipeline<'a> {
    work: &'a RNSFHEContext,
    boot: Engine<'a>,
    packed: Packed,
    return_key: RawKey,
    coordinate: usize,
    source_norm: usize,
    phase_cap: u128,
}

struct Output {
    outer: RNSCiphertext,
    switched: RNSCiphertext,
    returned: RNSCiphertext,
    without_carry: RNSCiphertext,
    outer_v_bound: u128,
    returned_v_bound: u128,
}

impl PublicPipeline<'_> {
    // The bound here is a research producer ledger, not an authenticated
    // production ciphertext/history type. Reject before processing if its
    // declared bound cannot enter the clock window.
    fn apply(&self, input: &RNSCiphertext, input_v_bound: u128) -> Output {
        let ctx = self.boot.ctx;
        assert_eq!(input.num_primes, self.work.config.primes.len());
        assert_eq!(
            self.work
                .config
                .primes
                .iter()
                .map(|&q| q as u128)
                .product::<u128>(),
            Q_SOURCE as u128
        );
        assert_eq!(self.work.n, ctx.n);
        assert_eq!(self.packed.source_len, self.work.n);
        assert!(
            input_v_bound <= self.phase_cap,
            "producer bound cannot enter the clock window"
        );
        let size = 2 * ctx.n;
        let q = Q_SOURCE as u128;
        let window2 = (2 * size as u128 * self.phase_cap).div_ceil(q)
            + self.coordinate as u128 * (self.source_norm + 1) as u128;
        assert!(
            window2 < ctx.n as u128,
            "phase window refuses this source norm/radius"
        );
        assert!(
            self.coordinate > 2 * self.source_norm.div_ceil(2),
            "integer carry does not fit"
        );
        let c0 = preprocess(self.work, &input.c0, self.coordinate);
        let c1 = preprocess(self.work, &input.c1, self.coordinate);
        let lookup = clock_lut(ctx, self.coordinate, window2 as i64);
        let mut clocks: Vec<_> = c0.clock.iter().map(|&b| rotate(ctx, &lookup, b)).collect();
        let mut affine: Vec<_> = c0.a.iter().map(|&a| scalar(ctx, a)).collect();
        let mut visited = BTreeSet::new();
        let mut ext_error = None;
        visit_all(&self.boot, &self.packed, &mut |i, polarity, key| {
            assert!(visited.insert((i, polarity)));
            for j in 0..ctx.n {
                // Coefficient j of c1*s: sign flips for wrapped indices.
                let k = (j + ctx.n - i) % ctx.n;
                let negative = (i > j) ^ (polarity == 0);
                let sign = if negative { -1 } else { 1 };
                clocks[j] = self.boot.cmux(&clocks[j], sign * c1.clock[k], &key);
                let term = self.boot.external(&scalar(ctx, c1.a[k]), &key);
                affine[j] = if negative {
                    ctx.sub(&affine[j], &term)
                } else {
                    add(ctx, &affine[j], &term)
                };
            }
            ext_error = Some(self.boot.external_error(&key));
        });
        assert_eq!(visited.len(), 2 * ctx.n);
        let mut outer = zero(ctx);
        let mut without_carry = zero(ctx);
        for (j, (clock, a)) in clocks.into_iter().zip(affine).enumerate() {
            let carry = self.boot.trace(clock, ctx.n, &self.packed.galois);
            let recovered = add(ctx, &a, &carry);
            outer = add(ctx, &outer, &rotate(ctx, &recovered, j as i64));
            without_carry = add(ctx, &without_carry, &rotate(ctx, &a, j as i64));
        }
        let gal = self.packed.galois.values().next().unwrap();
        let eg = ctx.n as u128 * gal.shape.digit_sum * gal.beta;
        let rem = U512::product_u64s(&ctx.config.primes).mod_u64(ctx.t) as u128;
        let lookup_norm = (ctx.t - 1) as u128 / ctx.n as u128 * (self.coordinate / 2) as u128;
        let carry_v = ctx.n as u128
            * (rem * lookup_norm + ctx.t as u128 * 2 * ctx.n as u128 * ext_error.unwrap())
            + ctx.t as u128 * (ctx.n - 1) as u128 * eg;
        let affine_norm = (ctx.n + 1) as u128 * (ctx.t / 2) as u128;
        let per_coefficient_v =
            carry_v + rem * affine_norm + ctx.t as u128 * 2 * ctx.n as u128 * ext_error.unwrap();
        // Each extracted ciphertext has errors in ALL coefficients. Assembly
        // must charge N copies; they cannot be treated as disjoint scalars.
        let outer_v_bound = ctx.n as u128 * per_coefficient_v;
        let switched_part = self.boot.switch(&outer.c1, &self.return_key);
        let switched = RNSCiphertext {
            c0: outer.c0.add(&switched_part.c0, &ctx.rns),
            c1: switched_part.c1,
            num_primes: outer.num_primes,
        };
        let returned = drop_special(self.work, ctx, &switched);
        let switch_v =
            ctx.t as u128 * ctx.n as u128 * self.return_key.shape.digit_sum * self.return_key.beta;
        let special = *ctx.config.primes.last().unwrap() as u128;
        let returned_v_bound = (outer_v_bound + switch_v).div_ceil(special)
            + (ctx.t as u128 * (self.source_norm + 1) as u128).div_ceil(2);
        Output {
            outer,
            switched,
            returned,
            without_carry,
            outer_v_bound,
            returned_v_bound,
        }
    }
}

// CLIENT instrumentation only. Never feeds a radius/message into apply().
fn observe_polynomial(
    ctx: &RNSFHEContext,
    ct: &RNSCiphertext,
    keys: &RNSKeySet,
    message: &[u64],
) -> u128 {
    assert_eq!(message.len(), ctx.n);
    assert_eq!(decrypt_coefficients(ctx, ct, keys), message);
    let phases = decrypted_phase_residues(ctx, ct, keys);
    let q = U512::product_u64s(&ctx.config.primes);
    let period = q.mul_u128(ctx.t as u128);
    let mut maximum = 0;
    for j in 0..ctx.n {
        let residues: Vec<_> = phases.iter().map(|lane| lane[j]).collect();
        let difference = abs_diff(
            client_crt(ctx, &residues).mul_u128(ctx.t as u128),
            q.mul_u128(message[j] as u128),
        );
        let difference = if words(difference) > words(period.div_u64(2)) {
            period.sub(difference)
        } else {
            difference
        };
        assert!(words(difference.mul_u128(2)) < words(q));
        assert_eq!((difference.d3, difference.d2, difference.d1), (0, 0, 0));
        maximum = maximum.max(difference.d0);
    }
    maximum
}

fn square_plain(message: &[u64], p: u64) -> Vec<u64> {
    let mut out = vec![0i128; message.len()];
    for (i, &a) in message.iter().enumerate() {
        for (j, &b) in message.iter().enumerate() {
            let sign = if i + j < message.len() { 1 } else { -1 };
            out[(i + j) % message.len()] += sign * a as i128 * b as i128;
        }
    }
    out.into_iter()
        .map(|v| v.rem_euclid(p as i128) as u64)
        .collect()
}

// Public FULL-POLYNOMIAL bound, not the scalar envelope. Centered message
// l1 norm is at most N*(t-1)/2; component winding l1 norm at most
// N*(N/2+1). Since 2V<Q, N*V^2/Q <= (N/2)*V. Round each tensor
// component before combining with 1,s,s^2, then charge hybrid key error.
fn square_history_bound(ctx: &RNSFHEContext, v: u128) -> u128 {
    assert!(2 * v < Q_SOURCE as u128);
    let n = ctx.n as u128;
    let t = ctx.t as u128;
    let factor = n * (t - 1) / 2 + n * t * (n / 2 + 1);
    let digits: u128 = ctx
        .config
        .primes
        .iter()
        .map(|q| (q.ilog2() as u128 + 1).div_ceil(10))
        .sum();
    let switch_error = n * ctx.config.eta as u128 * 1023 * digits;
    2 * factor * v + n / 2 * v + (t * (1 + n + n * n)).div_ceil(2) + t * switch_error
}

fn floor_ratio(numerator: U512, denominator: U512, upper: u64) -> u64 {
    let (mut lo, mut hi) = (0, upper + 1);
    while hi - lo > 1 {
        let mid = (lo + hi) / 2;
        if words(denominator.mul_u128(mid as u128)) <= words(numerator) {
            lo = mid;
        } else {
            hi = mid;
        }
    }
    lo
}

#[test]
fn phase_clock_residue_preprocessing_matches_wide_client_at_endpoints_and_boundaries() {
    // Exhaustive small-Q control, including even targets and endpoints.
    for target in [2, 3, 9, 64, 257, 576] {
        let projection = RoundProjection::new(&[17, 19], target);
        for x in 0..323u64 {
            assert_eq!(
                projection.round(&[x % 17, x % 19]),
                (target * x + 161) / 323
            );
        }
    }
    let mut config = SecureConfig::secure_128().into_config();
    config.n = 32;
    config.security_bits = 0;
    let ctx = RNSFHEContext::try_new(&config).unwrap();
    let q = Q_SOURCE as u128;
    let mut samples = vec![0, 1, q / 2, q / 2 + 1, q - 2, q - 1];
    for a in [0, 1, 2, 32768, 65535, 65536] {
        let boundary = q / (2 * ctx.t as u128) * (2 * a + 1);
        for offset in [-1, 0, 1] {
            samples.push((boundary as i128 + offset) as u128);
        }
    }
    let mut rng = ShadowHarvester::with_seed(0x5052_4550_524f_4345);
    for _ in 0..512 {
        samples.push((((rng.next_u64() as u128) << 64) | rng.next_u64() as u128) % q);
    }
    for chunk in samples.chunks(ctx.n) {
        let values: Vec<_> = (0..ctx.n).map(|j| chunk[j % chunk.len()]).collect();
        let poly = montgomery(
            &ctx,
            ctx.config
                .primes
                .iter()
                .map(|&prime| values.iter().map(|v| (v % prime as u128) as u64).collect())
                .collect(),
        );
        let result = preprocess(&ctx, &poly, 9);
        for (j, x) in values.into_iter().enumerate() {
            let px = U512::from_u128(x).mul_u128(ctx.t as u128);
            let a = floor_ratio(px.add(U512::from_u128(q / 2)), U512::from_u128(q), ctx.t);
            assert_eq!(result.a[j], a % ctx.t);
            let qa = U512::from_u128(q).mul_u128(a as u128);
            let negative = words(px) < words(qa);
            let magnitude = abs_diff(px, qa);
            let denominator = U512::from_u128(q).mul_u128(9);
            let b = floor_ratio(
                magnitude
                    .mul_u128(2 * ctx.n as u128)
                    .add(denominator.div_u64(2)),
                denominator,
                2 * ctx.n as u64,
            );
            assert_eq!(
                result.clock[j],
                if negative { -(b as i64) } else { b as i64 }
            );
        }
    }
}

#[test]
fn phase_clock_prefix_outer_tuple_clears_existing_dense_parameter_screen() {
    let mut primes = SecureConfig::secure_128().into_config().primes;
    primes.push(SPECIAL);
    // A screen of the dense OUTER tuple, not certification of sparse source
    // keys, shared secret multipliers, return cycles or the tiny test below.
    let screened = SecureConfig::custom_screened(8192, primes, 65537, 3, 128);
    assert!(screened.is_ok(), "outer tuple refused: {screened:?}");
}

#[test]
fn phase_clock_public_modulus_drop_matches_wide_client_rounding() {
    let mut config = SecureConfig::secure_128().into_config();
    config.n = 32;
    config.security_bits = 0;
    let work = RNSFHEContext::try_new(&config).unwrap();
    config.primes.push(SPECIAL);
    let boot = RNSFHEContext::try_new(&config).unwrap();
    let q = U512::product_u64s(&config.primes);
    let mut values = vec![U512::zero(), U512::from_u64(1), q.sub(U512::from_u64(1))];
    for center in [SPECIAL / 2, SPECIAL, SPECIAL + SPECIAL / 2] {
        for offset in [-1i64, 0, 1] {
            values.push(U512::from_u64((center as i64 + offset) as u64));
            values.push(q.sub(U512::from_u64((center as i64 + offset) as u64)));
        }
    }
    let mut rng = ShadowHarvester::with_seed(0x4452_4f50_524f_554e);
    for _ in 0..512 {
        // Uniform work-period-sized term times an independent special digit.
        let x = (((rng.next_u64() as u128) << 64) | rng.next_u64() as u128) % Q_SOURCE as u128;
        values.push(U512::from_u128(x).mul_u128((rng.next_u64() % SPECIAL) as u128));
    }
    let mut truncation_disagrees = false;
    for chunk in values.chunks(work.n) {
        let encode = |reverse: bool| {
            montgomery(
                &boot,
                config
                    .primes
                    .iter()
                    .map(|&prime| {
                        (0..work.n)
                            .map(|j| {
                                let index = if reverse { work.n - 1 - j } else { j };
                                chunk[index % chunk.len()].mod_u64(prime)
                            })
                            .collect()
                    })
                    .collect(),
            )
        };
        let input = RNSCiphertext {
            c0: encode(false),
            c1: encode(true),
            num_primes: config.primes.len(),
        };
        let dropped = drop_special(&work, &boot, &input);
        for (reverse, output) in [(false, &dropped.c0), (true, &dropped.c1)] {
            let ordinary = ordinary(&work, output);
            for j in 0..work.n {
                let index = if reverse { work.n - 1 - j } else { j };
                let value = chunk[index % chunk.len()];
                let rounded = value.add(U512::from_u64(SPECIAL / 2)).div_u64(SPECIAL);
                let truncated = value.div_u64(SPECIAL);
                for (lane, &prime) in work.config.primes.iter().enumerate() {
                    assert_eq!(ordinary[lane][j], rounded.mod_u64(prime));
                    truncation_disagrees |= rounded.mod_u64(prime) != truncated.mod_u64(prime);
                }
            }
        }
    }
    assert!(
        truncation_disagrees,
        "fixture must detect dropping the rounding correction"
    );
}

#[test]
#[ignore = "opt-in slow INSECURE N32 full-polynomial return/repeat research probe"]
fn phase_clock_full_polynomial_public_return_and_two_dependent_refresh_cycles() {
    let mut config = SecureConfig::secure_128().into_config();
    config.n = 32;
    config.security_bits = 0;
    config.name = "INSECURE full-polynomial public bootstrap integration";
    let work = RNSFHEContext::try_new(&config).unwrap();
    assert_eq!(
        config.primes.iter().map(|&q| q as u128).product::<u128>(),
        Q_SOURCE as u128
    );
    let mut outer_config = config.clone();
    outer_config.primes.push(SPECIAL);
    let boot = RNSFHEContext::try_new(&outer_config).unwrap();
    let engine = Engine {
        ctx: &boot,
        switches: Cell::new(0),
    };
    let mut rng = ShadowHarvester::with_seed(0x4655_4c4c_5245_5045);
    let mut source = vec![0i8; work.n];
    source[5] = 1;
    source[23] = -1;
    let work_keys = sparse_keys(&work, &source, &mut rng);
    let outer_keys = boot.generate_keys(&mut rng);
    let packed = setup(&engine, &outer_keys, &source, 8, 2, 2, &mut rng);
    // Setup a switch FROM the independent dense boot key TO the working
    // sparse key, at the OUTER modulus, before the public modulus drop.
    let work_at_outer = sparse_keys(&boot, &source, &mut rng);
    let return_shape = Shape::new(&boot, 2);
    let return_rows = raw_rows(
        &boot,
        &return_shape,
        &outer_keys.secret_key.s,
        &work_at_outer,
        &mut rng,
    );
    let return_key = engine.cache(&return_shape, &return_rows, config.eta as u128);
    let pipeline = PublicPipeline {
        work: &work,
        boot: engine,
        packed,
        return_key,
        coordinate: 9,
        source_norm: 2,
        phase_cap: Q_SOURCE as u128 / 128,
    };
    let exact = work.try_exact_evaluator().unwrap();
    let relin = exact.generate_hybrid_gadget_key_with_rng(&work_keys.secret_key, &mut rng);
    // Dense nonconstant input, both signs and nonzero coefficients at the
    // wrap boundary. Plaintext multiplication is checked by schoolbook math.
    let mut message: Vec<_> = (0..work.n).map(|j| ((j * 13 + 7) % 17) as u64).collect();
    message[31] = work.t - 3;
    let encrypted = encrypt_polynomial(&work, &work_keys, &message, &mut rng);
    observe_polynomial(&work, &encrypted, &work_keys, &message);
    let fresh_bound = work.t as u128 * (2 * work.n + 1) as u128 * config.eta as u128
        + (Q_SOURCE as u128 % work.t as u128) * (work.t - 1) as u128;
    let mut current = exact.try_mul_exact(&encrypted, &encrypted, &relin).unwrap();
    let mut current_bound = square_history_bound(&work, fresh_bound);
    message = square_plain(&message, work.t);
    observe_polynomial(&work, &current, &work_keys, &message);
    let mut carried_coefficients = 0;
    for cycle in 0..2 {
        // Public, plaintext-preserving phase load. This stresses actual
        // encrypted input, rather than supplying a chosen hidden residual.
        let load = Q_SOURCE as u128 / (512 * work.t as u128);
        let added = montgomery(
            &work,
            work.config
                .primes
                .iter()
                .map(|&q| {
                    (0..work.n)
                        .map(|j| {
                            let x = (load % q as u128) as u64;
                            if j % 2 == 0 || x == 0 {
                                x
                            } else {
                                q - x
                            }
                        })
                        .collect()
                })
                .collect(),
        );
        current.c0 = current.c0.add(&added, &work.rns);
        current_bound += load * work.t as u128;
        let incoming = observe_polynomial(&work, &current, &work_keys, &message);
        assert!(incoming <= current_bound);
        let output = pipeline.apply(&current, current_bound);
        let outer_v = observe_polynomial(&boot, &output.outer, &outer_keys, &message);
        assert!(outer_v <= output.outer_v_bound);
        observe_polynomial(&boot, &output.switched, &work_at_outer, &message);
        let returned_v = observe_polynomial(&work, &output.returned, &work_keys, &message);
        assert!(returned_v <= output.returned_v_bound);
        assert!(
            returned_v < incoming,
            "return did not refresh the input phase"
        );
        let omitted = decrypt_coefficients(&boot, &output.without_carry, &outer_keys);
        carried_coefficients += omitted.iter().zip(&message).filter(|(a, b)| a != b).count();
        // A key-domain negative control: dropping without returning the key
        // must fail. It also detects accidental reuse of the source key.
        let wrong_key = drop_special(&work, &boot, &output.outer);
        assert_ne!(decrypt_coefficients(&work, &wrong_key, &work_keys), message);
        current = exact
            .try_mul_exact(&output.returned, &output.returned, &relin)
            .unwrap();
        current_bound = square_history_bound(&work, output.returned_v_bound);
        message = square_plain(&message, work.t);
        let squared_v = observe_polynomial(&work, &current, &work_keys, &message);
        assert!(squared_v <= current_bound);
        assert!(
            current_bound < pipeline.phase_cap,
            "public next-product bound cannot reenter the clock window"
        );
        eprintln!("full polynomial pipeline: cycle={cycle}, N=32 INSECURE, all32 coefficients/all32 hidden selector positions, incoming Vbits={}, outer observed/bound={}/{}, returned observed/bound={}/{}, following product observed/bound={}/{}, source-key return and polynomial square correct", bits(incoming),bits(outer_v),bits(output.outer_v_bound),bits(returned_v),bits(output.returned_v_bound),bits(squared_v),bits(current_bound));
    }
    assert!(
        carried_coefficients > 0,
        "fixture failed to exercise a nonzero hidden sheet"
    );
    eprintln!("full polynomial pipeline: same precharge reused for 2 dependent cycles, carry omission corrupts {carried_coefficients} coefficients, wrong-key return refused by client, {} raw switches; native public refresh admission remains FALSE", pipeline.boot.switches.get());
}
