//! Native-Q covering-sheet selection using a small encrypted phase clock.
//! Research only. This reuses exact native RNS gadget switching, not an
//! external bootstrap backend. Full dense-source refresh is NOT admitted.

use super::*;
use crate::arithmetic::canonical_scale_round::CanonicalScaleRound;
use crate::keys::bootstrap::screen_bootstrap_security;
use crate::ops::rns_fhe::exact_mul::{ExactMulEvaluator, ExactTensor3, RNSHybridGadgetKey};
use crate::ops::rns_galois::{shift, RNSGaloisEvaluator, RNSGaloisKey};

const SOURCE_Q: i128 = 348_959_453_350_711_275_087_786_864_768_188_417;
const ROOT_PRODUCT: i128 = 9_699_690;
const BOOT: [u64; 5] = [1811939329, 2113929217, 2130706433, 1107296257, 1711276033];

#[derive(Debug, PartialEq, Eq)]
enum Refusal {
    Domain,
    Window,
    ConflictingLut,
    NonCentered,
}

fn ceil_div(a: U256, b: U256) -> U256 {
    let (q, r) = a.div_mod_u256(b);
    if r.is_zero() {
        q
    } else {
        q.add(U256::from_u64(1))
    }
}

// PUBLIC source-component quantization. The native-width product is formed
// only from a public centered residual and a public clock size, never S or g.
fn quantize(residual: i128, q: i128, coordinate: usize, size: usize) -> Result<i64, Refusal> {
    if q < 3 || q % 2 == 0 || coordinate < 2 || size == 0 {
        return Err(Refusal::Domain);
    }
    if residual.unsigned_abs() > q as u128 / 2 {
        return Err(Refusal::NonCentered);
    }
    let denominator = U256::from_u128(q as u128).mul_u64(coordinate as u64);
    let numerator = U256::from_u128(residual.unsigned_abs()).mul_u64(size as u64);
    let rounded = numerator
        .add(denominator.shr1())
        .div_mod_u256(denominator)
        .0;
    assert_eq!(rounded.hi, 0);
    let value = i64::try_from(rounded.lo).unwrap();
    Ok(if residual < 0 { -value } else { value })
}

struct ClockPlan {
    n: usize,
    source_period: i128,
    coordinate: usize,
    twice_window: u64,
    values: Vec<i64>, // full 2N anti-periodic lookup function
}

impl ClockPlan {
    fn new(
        n: usize,
        coordinate: usize,
        q: i128,
        source_v: u128,
        active_weight: usize,
    ) -> Result<Self, Refusal> {
        if !n.is_power_of_two()
            || n < 2
            || coordinate < 2
            || (coordinate != 2 && coordinate % 2 == 0)
            || coordinate > 1023
            || q < 3
            || q % 2 == 0
            || source_v > q as u128 / 2
        {
            return Err(Refusal::Domain);
        }
        let size = 2 * n;
        // |2*m*rotation - 2*M*K| <= ceil(2*M*V/Q) + m*(H+1).
        // H is bounded by BOTH source secret weight and public nonzero terms.
        let phase = ceil_div(
            U256::from_u128(source_v).mul_u64((2 * size) as u64),
            U256::from_u128(q as u128),
        );
        if phase.hi != 0 || phase.lo > u64::MAX as u128 {
            return Err(Refusal::Window);
        }
        let twice_window = (phase.lo as u64)
            .checked_add(
                (coordinate as u64)
                    .checked_mul(active_weight as u64 + 1)
                    .ok_or(Refusal::Window)?,
            )
            .ok_or(Refusal::Window)?;
        // For odd coordinates, valid windows and their negacyclic mirrors
        // must be disjoint. This sufficient condition also works for parity.
        if twice_window >= n as u64 {
            return Err(Refusal::Window);
        }
        let mut values = vec![None; size];
        let mut deposit = |rotation: usize, value: i64| -> Result<(), Refusal> {
            for (index, signed) in [(rotation, value), ((rotation + n) % size, -value)] {
                if values[index].is_some_and(|previous| previous != signed) {
                    return Err(Refusal::ConflictingLut);
                }
                values[index] = Some(signed);
            }
            Ok(())
        };
        let period = (coordinate * size) as i64;
        for k in 0..coordinate {
            let output = if coordinate == 2 {
                if k == 0 {
                    1
                } else {
                    -1
                }
            } else if k > coordinate / 2 {
                k as i64 - coordinate as i64
            } else {
                k as i64
            };
            for rotation in 0..size {
                let distance = (coordinate as i64 * rotation as i64 - size as i64 * k as i64)
                    .rem_euclid(period);
                let distance = distance.min(period - distance);
                if 2 * distance <= twice_window as i64 {
                    deposit(rotation, output)?;
                }
            }
        }
        Ok(Self {
            n,
            source_period: q,
            coordinate,
            twice_window,
            values: values.into_iter().map(|v| v.unwrap_or(0)).collect(),
        })
    }

    fn lookup(&self, rotation: i64) -> i64 {
        self.values[rotation.rem_euclid((2 * self.n) as i64) as usize]
    }

    // Encoded directly with the trace preconditioner at setup of this public
    // accumulator. Do NOT multiply an existing noisy ciphertext by N^-1.
    fn accumulator(&self, ctx: &RNSFHEContext) -> (RNSCiphertext, u128) {
        assert_eq!(ctx.n, self.n);
        let inverse_n = mod_inverse(ctx.n as u64, ctx.t);
        let preconditioner = if inverse_n > ctx.t / 2 {
            inverse_n as i64 - ctx.t as i64
        } else {
            inverse_n as i64
        };
        let mut message = vec![0i64; ctx.n];
        message[0] = preconditioner * self.values[0];
        // const(X^r * P) = -P[N-r] for 1<=r<N.
        for r in 1..ctx.n {
            message[ctx.n - r] = -preconditioner * self.values[r];
        }
        assert!(message.iter().all(|v| v.unsigned_abs() <= ctx.t / 2));
        let max_message = message.iter().map(|v| v.unsigned_abs()).max().unwrap();
        let zero = RNSPolynomial::zero(&ctx.rns);
        let ct = RNSCiphertext {
            c0: ctx.to_montgomery_form(&RNSPolynomial {
                limbs: ctx
                    .config
                    .primes
                    .iter()
                    .enumerate()
                    .map(|(lane, &p)| {
                        message
                            .iter()
                            .map(|&m| {
                                (m as i128 * ctx.delta_rns[lane] as i128).rem_euclid(p as i128)
                                    as u64
                            })
                            .collect()
                    })
                    .collect(),
                n: ctx.n,
            }),
            c1: zero,
            num_primes: ctx.config.primes.len(),
        };
        let q = U256::product_u64s(&ctx.config.primes);
        (ct, q.mod_u64(ctx.t) as u128 * max_message as u128)
    }
}

// Opaque, test-only RGSW-style bit precharge: two exact native hybrid target
// columns. Both columns use fresh full-width masks and the existing bounded
// sampler. The evaluator has neither bit nor outer secret.
struct BitKey {
    constant: RNSHybridGadgetKey,
    secret: RNSHybridGadgetKey,
}

fn precharge_bit(
    exact: &ExactMulEvaluator<'_>,
    ctx: &RNSFHEContext,
    sk: &RNSSecretKey,
    bit: bool,
    rng: &mut ShadowHarvester,
) -> BitKey {
    let mut constant = RNSPolynomial::zero(&ctx.rns);
    if bit {
        for lane in 0..ctx.config.primes.len() {
            constant.limbs[lane][0] = ctx.rns.mont_contexts[lane].to_montgomery(1);
        }
    }
    let secret = if bit {
        sk.s.clone()
    } else {
        RNSPolynomial::zero(&ctx.rns)
    };
    BitKey {
        constant: exact.generate_hybrid_target_key(sk, &constant, rng),
        secret: exact.generate_hybrid_target_key(sk, &secret, rng),
    }
}

fn standard(ctx: &RNSFHEContext, p: &RNSPolynomial) -> RNSPolynomial {
    RNSPolynomial {
        limbs: p
            .limbs
            .iter()
            .enumerate()
            .map(|(lane, values)| {
                values
                    .iter()
                    .map(|&v| ctx.rns.mont_contexts[lane].from_montgomery(v))
                    .collect()
            })
            .collect(),
        n: ctx.n,
    }
}

fn external_product(
    exact: &ExactMulEvaluator<'_>,
    ctx: &RNSFHEContext,
    ct: &RNSCiphertext,
    key: &BitKey,
) -> RNSCiphertext {
    // relinearize_tensor is also the repository's typed Galois switch path.
    // No tensor multiplication or BFV scale/round occurs in this operation.
    let switch = |component: &RNSPolynomial, target: &RNSHybridGadgetKey| {
        exact
            .relinearize_tensor(
                &ExactTensor3 {
                    e0: RNSPolynomial::zero(&ctx.rns),
                    e1: RNSPolynomial::zero(&ctx.rns),
                    e2: standard(ctx, component),
                    num_primes: ctx.config.primes.len(),
                },
                target,
            )
            .unwrap()
    };
    ctx.add(&switch(&ct.c0, &key.constant), &switch(&ct.c1, &key.secret))
}

fn cmux_rotate(
    exact: &ExactMulEvaluator<'_>,
    ctx: &RNSFHEContext,
    ct: &RNSCiphertext,
    rotation: i64,
    key: &BitKey,
) -> RNSCiphertext {
    let rotation = rotation.rem_euclid((2 * ctx.n) as i64) as usize;
    let difference = ctx.sub(&shift(ctx, ct, rotation), ct);
    ctx.add(ct, &external_product(exact, ctx, &difference, key))
}

struct TritKey {
    minus: BitKey,
    plus: BitKey,
}

#[allow(clippy::too_many_arguments)]
fn evaluate_clock(
    ctx: &RNSFHEContext,
    exact: &ExactMulEvaluator<'_>,
    plan: &ClockPlan,
    q: i128,
    r0: i128,
    weights: &[i128],
    keys: &[TritKey],
    trace: &[RNSGaloisKey],
) -> (RNSCiphertext, u128) {
    assert_eq!(weights.len(), keys.len());
    assert_eq!(q, plan.source_period, "cannot retag a source-period plan");
    let (accumulator, initial_v) = plan.accumulator(ctx);
    let initial_rotation = quantize(r0, q, plan.coordinate, 2 * ctx.n).unwrap();
    let mut acc = shift(
        ctx,
        &accumulator,
        initial_rotation.rem_euclid((2 * ctx.n) as i64) as usize,
    );
    for (&weight, key) in weights.iter().zip(keys) {
        let rotation = quantize(weight, q, plan.coordinate, 2 * ctx.n).unwrap();
        acc = cmux_rotate(exact, ctx, &acc, rotation, &key.plus);
        acc = cmux_rotate(exact, ctx, &acc, -rotation, &key.minus);
    }
    let galois = RNSGaloisEvaluator::new(ctx).unwrap();
    for key in trace {
        acc = ctx.add(&acc, &galois.apply(&acc, key).unwrap());
    }

    // Bit CMUX selects one signed permutation of the OLD error. Its bound
    // is E_old+E_external, not 3*E_old: the reused errors cancel exactly.
    let c = exact.plan().certificate();
    let switch_e = ctx.n as u128
        * ctx.config.eta as u128
        * ((1u128 << c.base_bits) - 1)
        * c.digits_per_lane.iter().sum::<usize>() as u128;
    let clock_v = initial_v + ctx.t as u128 * 2 * switch_e * (2 * weights.len()) as u128;
    let mut v = ctx.n as u128 * clock_v + ctx.t as u128 * (ctx.n - 1) as u128 * switch_e;
    if plan.coordinate == 2 {
        // Convert (-1)^K to K mod2. The inverse's noise cost is NOT free.
        let (mut one, _) = plan.accumulator(ctx);
        one.c0 = RNSPolynomial::zero(&ctx.rns);
        for lane in 0..ctx.config.primes.len() {
            one.c0.limbs[lane][0] = ctx.rns.mont_contexts[lane].to_montgomery(ctx.delta_rns[lane]);
        }
        let difference = ctx.sub(&one, &acc);
        let magnitude = (ctx.t - 1) / 2; // inverse2 == -magnitude mod t
        let scale = |poly: &RNSPolynomial| RNSPolynomial {
            limbs: poly
                .limbs
                .iter()
                .zip(&ctx.config.primes)
                .map(|(lane, &p)| {
                    lane.iter()
                        .map(|&value| {
                            ((p as u128 - magnitude as u128 % p as u128) * value as u128
                                % p as u128) as u64
                        })
                        .collect()
                })
                .collect(),
            n: ctx.n,
        };
        acc = RNSCiphertext {
            c0: scale(&difference.c0),
            c1: scale(&difference.c1),
            num_primes: difference.num_primes,
        };
        v = magnitude as u128 * (v + U256::product_u64s(&ctx.config.primes).mod_u64(ctx.t) as u128);
    }
    (acc, v)
}

fn public_constant(ctx: &RNSFHEContext, value: i64) -> RNSCiphertext {
    let value = value.rem_euclid(ctx.t as i64);
    let value = if value > ctx.t as i64 / 2 {
        value - ctx.t as i64
    } else {
        value
    };
    let mut c0 = RNSPolynomial::zero(&ctx.rns);
    for (lane, &p) in ctx.config.primes.iter().enumerate() {
        let encoded = (value as i128 * ctx.delta_rns[lane] as i128).rem_euclid(p as i128) as u64;
        c0.limbs[lane][0] = ctx.rns.mont_contexts[lane].to_montgomery(encoded);
    }
    RNSCiphertext {
        c0,
        c1: RNSPolynomial::zero(&ctx.rns),
        num_primes: ctx.config.primes.len(),
    }
}

// PUBLIC inverse construction for a residual r in [0,Q/2]. Find C and A
// satisfying p*C=Q*A+r, 0<=C<Q. All wide products here are public only.
fn component_with_residual(r: i128, q: i128, p: u64) -> (u128, u64) {
    assert!((0..=q / 2).contains(&r));
    let inverse_q = mod_inverse((q % p as i128) as u64, p);
    let a = (((p - (r % p as i128) as u64) as u128 * inverse_q as u128) % p as u128) as u64;
    let numerator = U256::from_u128(q as u128)
        .mul_u64(a)
        .add(U256::from_u128(r as u128));
    let (component, remainder) = numerator.div_mod_u64(p);
    assert_eq!(remainder, 0);
    assert_eq!(component.hi, 0);
    assert!(component.lo < q as u128);
    (component.lo, a)
}

fn affine_message(
    ctx: &RNSFHEContext,
    exact: &ExactMulEvaluator<'_>,
    a0: u64,
    a1: &[u64],
    keys: &[TritKey],
) -> (RNSCiphertext, u128) {
    assert_eq!(a1.len(), keys.len());
    let mut output = public_constant(ctx, a0 as i64);
    let centered_abs = |a: u64| {
        let a = a % ctx.t;
        a.min(ctx.t - a) as u128
    };
    let mut norm = centered_abs(a0);
    for (&a, key) in a1.iter().zip(keys) {
        let message = public_constant(ctx, a as i64);
        let plus = external_product(exact, ctx, &message, &key.plus);
        let minus = external_product(exact, ctx, &message, &key.minus);
        output = ctx.add(&output, &ctx.sub(&plus, &minus));
        norm += centered_abs(a);
    }
    let c = exact.plan().certificate();
    let switch_e = ctx.n as u128
        * ctx.config.eta as u128
        * ((1u128 << c.base_bits) - 1)
        * c.digits_per_lane.iter().sum::<usize>() as u128;
    let remainder = U256::product_u64s(&ctx.config.primes).mod_u64(ctx.t) as u128;
    (
        output,
        remainder * norm + ctx.t as u128 * 4 * switch_e * a1.len() as u128,
    )
}

// Client-only BFV decoding of the selected SOURCE coefficient, independent
// of A0+A1*s+K. This never supplies plaintexts or errors to the producer.
fn source_coefficient_oracle(c0: u128, c1: u128, trit: i8, p: u64) -> (i64, u128) {
    let phase = (c0 as i128 + 2 * c1 as i128 * trit as i128).rem_euclid(SOURCE_Q) as u128;
    let q = U256::from_u128(SOURCE_Q as u128);
    let scaled = U256::from_u128(phase).mul_u64(p);
    let message = scaled.add(q.shr1()).div_mod_u256(q).0.mod_u64(p);
    let residual = scaled.rem_u256(q);
    let residual = if residual.gt(q.shr1()) {
        q.sub(residual)
    } else {
        residual
    };
    assert_eq!(residual.hi, 0);
    (message as i64, residual.lo)
}

// Independent secret-key observation, OUTSIDE the evaluator. Native Q154
// requires the existing U256 client CRT oracle, not the old u128 decoder.
fn observe(
    ctx: &RNSFHEContext,
    ct: &RNSCiphertext,
    sk: &RNSSecretKey,
    intended_constant: i64,
) -> u128 {
    let phase = ctx.rns_poly_mul(&ct.c1, &sk.s).add(&ct.c0, &ctx.rns);
    let phase = standard(ctx, &phase);
    let decoder = CanonicalScaleRound::new(&ctx.config.primes, ctx.t).unwrap();
    let q = U256::product_u64s(&ctx.config.primes);
    let period = q.mul_u64(ctx.t);
    let mut maximum = 0;
    for coefficient in 0..ctx.n {
        let residues: Vec<_> = phase.limbs.iter().map(|lane| lane[coefficient]).collect();
        let intended = if coefficient == 0 {
            intended_constant.rem_euclid(ctx.t as i64) as u64
        } else {
            0
        };
        assert_eq!(
            decoder.scale_round(&residues).unwrap(),
            intended,
            "coefficient {coefficient}"
        );
        let value = ctx
            .rns
            .to_u256_level(&residues, residues.len())
            .mul_u64(ctx.t);
        let ideal = q.mul_u64(intended);
        let difference = if value.ge(ideal) {
            value.sub(ideal)
        } else {
            ideal.sub(value)
        };
        let difference = if difference.gt(period.shr1()) {
            period.sub(difference)
        } else {
            difference
        };
        assert!(difference.mul_u64(2).lt(q));
        assert_eq!(difference.hi, 0);
        maximum = maximum.max(difference.lo);
    }
    maximum
}

#[test]
fn phase_clock_windows_composite_budget_and_dense_refusal() {
    for m in [2, 3, 5, 7, 11, 13, 17, 19, 33] {
        let plan = ClockPlan::new(8192, m, SOURCE_Q, SOURCE_Q as u128 / 8, 32).unwrap();
        assert!(plan.twice_window < 8192);
        assert!(matches!(
            ClockPlan::new(8192, m, SOURCE_Q, SOURCE_Q as u128 / 8, 8192),
            Err(Refusal::Window)
        ));
    }
    assert!(ClockPlan::new(8192, 65, SOURCE_Q, SOURCE_Q as u128 / 8, 64).is_err());
    assert!(ClockPlan::new(8192, 65, SOURCE_Q, SOURCE_Q as u128 / 16, 64).is_ok());
    assert!(matches!(
        quantize(SOURCE_Q, SOURCE_Q, 33, 16384),
        Err(Refusal::NonCentered)
    ));
    // All admissible integer rotations in the native signed carry corridor.
    let plan = ClockPlan::new(8192, 33, SOURCE_Q, SOURCE_Q as u128 / 8, 32).unwrap();
    let mut checked = 0;
    for k in -16i64..=16 {
        for rotation in 0..16384i64 {
            let period = 33 * 16384i64;
            let d = (33 * rotation - 16384 * k).rem_euclid(period);
            if 2 * d.min(period - d) <= plan.twice_window as i64 {
                assert_eq!(plan.lookup(rotation), k);
                checked += 1;
            }
        }
    }
    eprintln!("native clock windows: signed composite33 carry [-16,16], {checked} exact plateau checks; sparse32 passes at V/Q<=1/8; dense8192 refused; composite65 requires tighter V/Q<=1/16 for weight64");
}

#[test]
fn phase_clock_sparse96_fits_doubled_outer_ring() {
    // The live sparse-source lift uses Q60, H=96 and V<=Q/16. The batched
    // chart already moves this source into an outer ring of degree 2*8192.
    // At that degree, the direct ultradiscrete 99-clock has disjoint lookup
    // windows and emits the signed carry itself; this is a geometric gate,
    // not yet a selector-key/noise or return certificate.
    let q = 998_244_353_i128 * 985_661_441_i128;
    let n = 16_384;
    let source_v = q as u128 / 16;
    let plan = ClockPlan::new(n, 99, q, source_v, 96).unwrap();
    assert_eq!(plan.twice_window, 13_699);
    assert!(plan.twice_window < n as u64);

    // |S| < 97Q/2 from H=96 centered source terms plus R0. If |K|=49,
    // then |S| >= 49Q - V, which is strictly larger than 97Q/2 at V<=Q/16.
    // This proves the admitted signed carry support is exactly [-48,48].
    assert!(2 * (49 * q as u128 - source_v) > 97 * q as u128);
    // Exhaust every output rotation and every admitted signed carry. Every
    // rotation in a carry's certified error window must decode to that same
    // carry; no client-side centering or polynomial quotient is involved.
    let size = (2 * n) as i64;
    let period = 99 * size;
    let mut checked = 0;
    let mut checks_per_carry = [0usize; 97];
    for k in -48_i64..=48 {
        for rotation in 0..size {
            let distance = (99 * rotation - size * k).rem_euclid(period);
            let distance = distance.min(period - distance);
            if 2 * distance <= plan.twice_window as i64 {
                assert_eq!(plan.lookup(rotation), k, "carry={k}, rotation={rotation}");
                checked += 1;
                checks_per_carry[(k + 48) as usize] += 1;
            }
        }
    }
    assert!(checks_per_carry.iter().all(|&count| count > 0));
    assert!(matches!(
        ClockPlan::new(n, 99, q, source_v, 8_192),
        Err(Refusal::Window)
    ));
    eprintln!("sparse96 doubled-ring clock: Q60, V/Q<=1/16, degree{n}, coordinate99, window2={}, all 97 carry plateaus verified across {checked} rotations; dense-source window refused; selector-key, encrypted full-ring noise, return and admission gates remain open", plan.twice_window);
}

#[test]
fn phase_clock_public_quantization_distinguishes_native_alias() {
    let step = SOURCE_Q / (13 * ROOT_PRODUCT) * (13 * ROOT_PRODUCT);
    let weight = step / 2;
    assert_eq!((step - SOURCE_Q).abs(), 52_966_817);
    for n in [256, 8192] {
        for m in [2, 11, 33] {
            let plan = ClockPlan::new(n, m, SOURCE_Q, SOURCE_Q as u128 / 16, 2).unwrap();
            let b = quantize(weight, SOURCE_Q, m, 2 * n).unwrap();
            for trit in -1i64..=1 {
                let expected = if m == 2 {
                    if trit == 0 {
                        1
                    } else {
                        -1
                    }
                } else {
                    trit
                };
                assert_eq!(plan.lookup(2 * b * trit), expected);
            }
        }
    }
    // The native period remains Q119. It has NOT been replaced by a local13.
    eprintln!("native-Q alias: phase clocks distinguish sheets -1,0,1 at N256 and N8192, same public weights, without supplying centered phases");
}

fn encrypted_probe(n: usize, profiles: &[i8]) {
    let mut config = SecureConfig::secure_128().into_config();
    config.n = n;
    config.primes = BOOT.to_vec();
    config.t = 65537;
    if n != 8192 {
        config.security_bits = 0;
        config.name = "INSECURE small-ring native-Q phase clock";
    }
    if n == 8192 {
        assert!(
            screen_bootstrap_security(&config.primes, n, 128)
                .unwrap()
                .meets_claim_under_both
        );
    }
    let ctx = RNSFHEContext::try_new(&config).unwrap();
    let exact = ctx.try_exact_evaluator().unwrap();
    let mut rng = ShadowHarvester::with_seed(0x5048_4153_4543_4c4b ^ n as u64);
    let outer = ctx.generate_keys(&mut rng);
    let relin = exact.generate_hybrid_gadget_key_with_rng(&outer.secret_key, &mut rng);
    let galois = RNSGaloisEvaluator::new(&ctx).unwrap();
    let trace: Vec<_> = (0..n.ilog2())
        .map(|j| {
            galois
                .generate_key_with_rng(&outer.secret_key, (n >> j) as u64 + 1, &mut rng)
                .unwrap()
        })
        .collect();
    let step = SOURCE_Q / (13 * ROOT_PRODUCT) * (13 * ROOT_PRODUCT);
    let weights = [step / 2; 2];
    let q_boot = U256::product_u64s(&config.primes);
    let mut observed = [0u128; 2];
    let mut issued = [0u128; 2];
    let mut squares = 0;
    let mut recovered = 0;
    for &trit in profiles {
        // Key-holder boundary. Only the source selectors and outer secret are
        // used here; live public weights and source phases are NOT inputs.
        let keys: Vec<_> = (0..2)
            .map(|_| TritKey {
                minus: precharge_bit(&exact, &ctx, &outer.secret_key, trit == -1, &mut rng),
                plus: precharge_bit(&exact, &ctx, &outer.secret_key, trit == 1, &mut rng),
            })
            .collect();
        for (index, m) in [2, 33].into_iter().enumerate() {
            let plan = ClockPlan::new(n, m, SOURCE_Q, SOURCE_Q as u128 / 16, 2).unwrap();
            eprintln!(
                "clock evaluation: N={n}, coordinate={m}, source trit profile={trit}, window2={}",
                plan.twice_window
            );
            let (output, v) =
                evaluate_clock(&ctx, &exact, &plan, SOURCE_Q, 0, &weights, &keys, &trace);
            assert!(U256::from_u128(v).mul_u64(2).lt(q_boot));
            // Test oracle only, after encrypted cell selection. For this
            // two-term fixture K=trit; the evaluator does not receive it.
            let intended = if m == 2 {
                i64::from(trit != 0)
            } else {
                trit as i64
            };
            let measured = observe(&ctx, &output, &outer.secret_key, intended);
            assert!(measured <= v);
            observed[index] = observed[index].max(measured);
            issued[index] = issued[index].max(v);
            let square = exact.try_mul_exact(&output, &output, &relin).unwrap();
            observe(&ctx, &square, &outer.secret_key, intended * intended);
            squares += 1;
        }
        if n != 8192 || trit == 1 {
            // Outcome-dependent follow-up: a high-noise SOURCE coefficient,
            // not just a carry output. R0 is public and satisfies V/Q<1/16.
            // The original source phase error is about Q/128 (112 bits).
            let r0 = SOURCE_Q / 128;
            let (c0, a0) = component_with_residual(r0, SOURCE_Q, ctx.t);
            let (c1, a1) = component_with_residual(weights[0], SOURCE_Q, ctx.t);
            let plan = ClockPlan::new(n, 33, SOURCE_Q, SOURCE_Q as u128 / 16, 2).unwrap();
            let (carry, carry_v) =
                evaluate_clock(&ctx, &exact, &plan, SOURCE_Q, r0, &weights, &keys, &trace);
            let (affine, affine_v) = affine_message(&ctx, &exact, a0, &[a1; 2], &keys);
            let refreshed = ctx.add(&affine, &carry);
            let bound = affine_v + carry_v;
            let (message, input_v) = source_coefficient_oracle(c0, c1, trit, ctx.t);
            assert!(input_v <= SOURCE_Q as u128 / 16);
            let measured = observe(&ctx, &refreshed, &outer.secret_key, message);
            assert!(measured <= bound);
            // Compare dimensionless V/Q with wide TEST arithmetic. The
            // output bound is independent of the incoming measured V.
            use crate::arithmetic::rns::U512;
            let before = U512::from_u256(q_boot).mul_u128(input_v);
            let after = U512::from_u128(bound).mul_u128(SOURCE_Q as u128);
            assert!(
                (after.d3, after.d2, after.d1, after.d0)
                    < (before.d3, before.d2, before.d1, before.d0)
            );
            let square = exact.try_mul_exact(&refreshed, &refreshed, &relin).unwrap();
            observe(
                &ctx,
                &square,
                &outer.secret_key,
                (message * message).rem_euclid(ctx.t as i64),
            );
            squares += 1;
            recovered += 1;
            eprintln!("coefficient recovery: N={n}, source trit={trit}, input Vbits={}, output observed Vbits={}, output bound Vbits={}, message={message}, following message square correct", 128-input_v.leading_zeros(), 128-measured.leading_zeros(), 128-bound.leading_zeros());
        }
    }
    eprintln!("encrypted native-Q clock: N={n}, source_Qbits=119, outer_Qbits={}, profiles={profiles:?}, root2/composite33 observed V bits={:?}, conservative V bits={:?}, recovered coefficients={recovered}, dependent squares={squares}", q_boot.bitlen(), observed.map(|v| 128-v.leading_zeros()), issued.map(|v| 128-v.leading_zeros()));
}

#[test]
fn phase_clock_encrypted_native_q_without_chart_or_winding_oracle() {
    encrypted_probe(256, &[-1, 0, 1]);
}

fn phase_clock_many_term_probe(trits: &[i8], max_source_weight: usize) {
    use crate::arithmetic::rns::U512;

    const N: usize = 1024;
    assert!(trits.iter().all(|&trit| (-1..=1).contains(&trit)));
    assert!(trits.iter().filter(|&&trit| trit != 0).count() <= max_source_weight);
    assert!(max_source_weight <= trits.len());
    let mut config = SecureConfig::secure_128().into_config();
    config.n = N;
    config.primes = BOOT.to_vec();
    config.t = 65_537;
    config.security_bits = 0;
    config.name = "INSECURE multi-term phase-clock research fixture";
    let ctx = RNSFHEContext::try_new(&config).unwrap();
    let exact = ctx.try_exact_evaluator().unwrap();
    let mut rng = ShadowHarvester::with_seed(0x5048_4153_4538_5452);
    let outer = ctx.generate_keys(&mut rng);
    let relin = exact.generate_hybrid_gadget_key_with_rng(&outer.secret_key, &mut rng);
    let galois = RNSGaloisEvaluator::new(&ctx).unwrap();
    let trace: Vec<_> = (0..N.ilog2())
        .map(|j| {
            galois
                .generate_key_with_rng(&outer.secret_key, (N >> j) as u64 + 1, &mut rng)
                .unwrap()
        })
        .collect();
    let selectors: Vec<_> = trits
        .iter()
        .map(|&trit| TritKey {
            minus: precharge_bit(&exact, &ctx, &outer.secret_key, trit == -1, &mut rng),
            plus: precharge_bit(&exact, &ctx, &outer.secret_key, trit == 1, &mut rng),
        })
        .collect();
    let step = SOURCE_Q / (13 * ROOT_PRODUCT) * (13 * ROOT_PRODUCT);
    let weight = step / 2;
    let r0 = SOURCE_Q / 128;
    let weights = vec![weight; trits.len()];
    let (c0, a0) = component_with_residual(r0, SOURCE_Q, ctx.t);
    let (c1, a1) = component_with_residual(weight, SOURCE_Q, ctx.t);
    let plan = ClockPlan::new(N, 33, SOURCE_Q, SOURCE_Q as u128 / 16, max_source_weight).unwrap();
    let (carry, carry_v) = evaluate_clock(
        &ctx, &exact, &plan, SOURCE_Q, r0, &weights, &selectors, &trace,
    );
    let q_boot = U256::product_u64s(&config.primes);
    assert!(U256::from_u128(carry_v).mul_u64(2).lt(q_boot));
    // Test observer only. The public evaluator above receives neither trits
    // nor this quotient; it sees public residuals and opaque selector keys.
    let trit_sum: i128 = trits.iter().map(|&trit| trit as i128).sum();
    let source_sum = r0 + weight * trit_sum;
    let k = (source_sum + SOURCE_Q / 2).div_euclid(SOURCE_Q);
    let carry_measured = observe(&ctx, &carry, &outer.secret_key, k as i64);
    assert!(carry_measured <= carry_v);
    let (affine, affine_v) = affine_message(&ctx, &exact, a0, &vec![a1; trits.len()], &selectors);
    let refreshed = ctx.add(&affine, &carry);
    let phase = (c0 as i128 + c1 as i128 * trit_sum).rem_euclid(SOURCE_Q) as u128;
    let q_source = U256::from_u128(SOURCE_Q as u128);
    let scaled = U256::from_u128(phase).mul_u64(ctx.t);
    let message = scaled
        .add(q_source.shr1())
        .div_mod_u256(q_source)
        .0
        .mod_u64(ctx.t) as i64;
    let residual = scaled.rem_u256(q_source);
    let input_v = if residual.gt(q_source.shr1()) {
        q_source.sub(residual)
    } else {
        residual
    };
    assert_eq!(input_v.hi, 0);
    assert!(input_v.lo <= SOURCE_Q as u128 / 16);
    let output_v = observe(&ctx, &refreshed, &outer.secret_key, message);
    let bound = affine_v + carry_v;
    assert!(output_v <= bound);
    let before = U512::from_u256(q_boot).mul_u128(input_v.lo);
    let after = U512::from_u128(bound).mul_u128(SOURCE_Q as u128);
    assert!(
        (after.d3, after.d2, after.d1, after.d0) < (before.d3, before.d2, before.d1, before.d0)
    );
    let square = exact.try_mul_exact(&refreshed, &refreshed, &relin).unwrap();
    observe(
        &ctx,
        &square,
        &outer.secret_key,
        (message * message).rem_euclid(ctx.t as i64),
    );
    eprintln!(
        "many-term public clock: N={N}, H<={}, K={k}, selector keys={}, source V={} bits, refreshed V={} bits (bound {}), dependent square exact",
        max_source_weight,
        selectors.len(),
        128 - input_v.lo.leading_zeros(),
        128 - output_v.leading_zeros(),
        128 - bound.leading_zeros(),
    );
}

#[test]
fn phase_clock_resets_eight_term_source_without_word_enumeration() {
    phase_clock_many_term_probe(&[-1, -1, -1, -1, -1, -1, 1, 1], 8);
}

#[test]
fn phase_clock_resets_sixteen_term_source_without_word_enumeration() {
    phase_clock_many_term_probe(&[1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, -1, -1, -1, -1], 16);
}

#[test]
fn phase_clock_decoy_cover_preserves_sparse_window_and_resets_noise() {
    phase_clock_many_term_probe(&[0, -1, 0, -1, -1, 1, -1, 0, -1, 1, 0, -1], 8);
}

#[test]
fn phase_clock_refreshes_two_coefficients_of_a_live_sparse_source() {
    use crate::arithmetic::rns::U512;

    const N: usize = 512;
    const COVER: [usize; 12] = [0, 17, 23, 45, 88, 103, 211, 250, 300, 377, 400, 511];
    const TRITS: [i8; 12] = [-1, -1, 0, -1, 0, -1, -1, 0, -1, 0, 1, 1];
    let mut source_config = SecureConfig::secure_128().into_config();
    source_config.n = N;
    source_config.security_bits = 0;
    source_config.name = "INSECURE live sparse-source research fixture";
    let source = RNSFHEContext::try_new(&source_config).unwrap();
    let mut boot_config = source_config.clone();
    boot_config.primes = BOOT.to_vec();
    let boot = RNSFHEContext::try_new(&boot_config).unwrap();
    let exact = boot.try_exact_evaluator().unwrap();
    let p = source.t;
    let source_q = U256::product_u64s(&source_config.primes);
    assert_eq!(source_q, U256::from_u128(SOURCE_Q as u128));
    let boot_q = U256::product_u64s(&boot_config.primes);
    let mut rng = ShadowHarvester::with_seed(0x4c49_5645_434c_4f43);
    let mut secret_limbs = vec![vec![0u64; N]; source_config.primes.len()];
    for (lane, &prime) in source_config.primes.iter().enumerate() {
        for (&position, &trit) in COVER.iter().zip(&TRITS) {
            secret_limbs[lane][position] = match trit {
                -1 => prime - 1,
                0 => 0,
                1 => 1,
                _ => unreachable!(),
            };
        }
    }
    let source_sk = RNSSecretKey {
        s: source.to_montgomery_form(&RNSPolynomial {
            limbs: secret_limbs,
            n: N,
        }),
    };
    let a = source.to_montgomery_form(&source.sample_uniform_main_poly(&mut rng));
    let as_product = source.rns_poly_mul(&a, &source_sk.s);
    let stress = SOURCE_Q / (128 * p as i128);
    let mut added_limbs = vec![vec![0u64; N]; source_config.primes.len()];
    for (lane, &prime) in source_config.primes.iter().enumerate() {
        for (position, message, error) in [(0, 7i128, stress), (N - 1, -3, -stress)] {
            let value = message * source.delta_rns[lane] as i128 + error;
            added_limbs[lane][position] = value.rem_euclid(prime as i128) as u64;
        }
    }
    let added = source.to_montgomery_form(&RNSPolynomial {
        limbs: added_limbs,
        n: N,
    });
    let input = RNSCiphertext {
        c0: added.sub(&as_product, &source.rns),
        c1: a,
        num_primes: source_config.primes.len(),
    };
    let source_phase = standard(
        &source,
        &source
            .rns_poly_mul(&input.c1, &source_sk.s)
            .add(&input.c0, &source.rns),
    );
    let decoder = CanonicalScaleRound::new(&source_config.primes, p).unwrap();
    for j in 0..N {
        let residues: Vec<_> = source_phase.limbs.iter().map(|lane| lane[j]).collect();
        let expected = match j {
            0 => 7,
            k if k == N - 1 => p - 3,
            _ => 0,
        };
        assert_eq!(
            decoder.scale_round(&residues).unwrap(),
            expected,
            "source slot {j}"
        );
    }

    // These quotients and residuals depend only on public source components.
    let split = |poly: &RNSPolynomial| -> Vec<(u64, i128)> {
        let poly = standard(&source, poly);
        (0..N)
            .map(|j| {
                let residues: Vec<_> = poly.limbs.iter().map(|lane| lane[j]).collect();
                let scaled = source
                    .rns
                    .to_u256_level(&residues, residues.len())
                    .mul_u64(p);
                let (whole, remainder) = scaled.div_mod_u256(source_q);
                assert_eq!(whole.hi, 0);
                assert_eq!(remainder.hi, 0);
                if remainder.gt(source_q.shr1()) {
                    (whole.lo as u64 + 1, remainder.lo as i128 - SOURCE_Q)
                } else {
                    (whole.lo as u64, remainder.lo as i128)
                }
            })
            .collect()
    };
    let c0 = split(&input.c0);
    let c1 = split(&input.c1);

    let outer = boot.generate_keys(&mut rng);
    let relin = exact.generate_hybrid_gadget_key_with_rng(&outer.secret_key, &mut rng);
    let selectors: Vec<_> = TRITS
        .iter()
        .map(|&trit| TritKey {
            minus: precharge_bit(&exact, &boot, &outer.secret_key, trit == -1, &mut rng),
            plus: precharge_bit(&exact, &boot, &outer.secret_key, trit == 1, &mut rng),
        })
        .collect();
    let galois = RNSGaloisEvaluator::new(&boot).unwrap();
    let trace: Vec<_> = (0..N.ilog2())
        .map(|j| {
            galois
                .generate_key_with_rng(&outer.secret_key, (N >> j) as u64 + 1, &mut rng)
                .unwrap()
        })
        .collect();
    let plan = ClockPlan::new(N, 33, SOURCE_Q, SOURCE_Q as u128 / 16, 8).unwrap();
    let mut nonzero_carries = 0;
    for j in [0, N - 1] {
        let mut weights = Vec::with_capacity(COVER.len());
        let mut affine = Vec::with_capacity(COVER.len());
        for &position in &COVER {
            let (index, sign) = if position <= j {
                (j - position, 1i128)
            } else {
                (N + j - position, -1i128)
            };
            weights.push(sign * c1[index].1);
            affine.push((sign * c1[index].0 as i128).rem_euclid(p as i128) as u64);
        }
        let source_sum = c0[j].1
            + weights
                .iter()
                .zip(&TRITS)
                .map(|(&weight, &trit)| weight * trit as i128)
                .sum::<i128>();
        let k = (source_sum + SOURCE_Q / 2).div_euclid(SOURCE_Q);
        let input_v = (source_sum - SOURCE_Q * k).unsigned_abs();
        assert!(input_v <= SOURCE_Q as u128 / 16);
        nonzero_carries += usize::from(k != 0);
        let (carry, carry_v) = evaluate_clock(
            &boot, &exact, &plan, SOURCE_Q, c0[j].1, &weights, &selectors, &trace,
        );
        assert!(U256::from_u128(carry_v).mul_u64(2).lt(boot_q));
        assert!(observe(&boot, &carry, &outer.secret_key, k as i64) <= carry_v);
        let (affine_ct, affine_v) = affine_message(&boot, &exact, c0[j].0, &affine, &selectors);
        let refreshed = boot.add(&affine_ct, &carry);
        let expected = if j == 0 { 7 } else { p as i64 - 3 };
        let output_v = observe(&boot, &refreshed, &outer.secret_key, expected);
        let bound = affine_v + carry_v;
        assert!(output_v <= bound);
        let before = U512::from_u256(boot_q).mul_u128(input_v);
        let after = U512::from_u128(bound).mul_u128(SOURCE_Q as u128);
        assert!(
            (after.d3, after.d2, after.d1, after.d0) < (before.d3, before.d2, before.d1, before.d0)
        );
        let square = exact.try_mul_exact(&refreshed, &refreshed, &relin).unwrap();
        observe(
            &boot,
            &square,
            &outer.secret_key,
            expected * expected % p as i64,
        );
        eprintln!("live sparse-source slot {j}: K={k}, source Vbits={}, refreshed Vbits={}, bound Vbits={}, square exact", 128-input_v.leading_zeros(), 128-output_v.leading_zeros(), 128-bound.leading_zeros());
    }
    assert!(nonzero_carries > 0);
}

#[test]
#[ignore = "opt-in native N8192 two-term source probe; not full dense-source refresh"]
fn phase_clock_native_8192_alias_and_dependent_squares() {
    encrypted_probe(8192, &[0, 1]);
}
