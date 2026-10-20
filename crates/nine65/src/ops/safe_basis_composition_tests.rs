//! Bounded encrypted-remainder composition. Research-only native-ring runtime.
//! Public support rows describe POSSIBLE (remainder,winding) pairs; encrypted
//! one-hot weights hide the selected pair. No scalar hidden carry is cached.

use super::evaluate_centered_components;
use super::safe_basis_precharge_tests::{inverse, precharge};
use crate::arithmetic::canonical_scale_round::CanonicalScaleRound;
use crate::arithmetic::rns::{U256, U512};
use crate::arithmetic::RNSPolynomial;
use crate::entropy::ShadowHarvester;
use crate::keys::bootstrap::{screen_bootstrap_security, validate_bootstrap_primes};
use crate::ops::rns_fhe::exact_mul::{ExactMulEvaluator, ExactMulPlan, RNSHybridGadgetKey};
use crate::ops::rns_fhe::{DualRNSSecretKey, RNSCiphertext, RNSFHEContext, RNSSecretKey};
use crate::ops::rns_galois::{shift, RNSGaloisEvaluator, RNSGaloisKey};
use crate::params::{is_prime, FHEConfig, SecureConfig};
use std::cell::Cell;
use std::collections::BTreeMap;

const ROOT: [u64; 8] = [2, 3, 5, 7, 11, 13, 17, 19];
const BOOT: [u64; 6] = [
    1811939329, 2113929217, 2130706433, 1107296257, 1711276033, 1224736769,
];

fn words(x: U512) -> (u128, u128, u128, u128) {
    (x.d3, x.d2, x.d1, x.d0)
}
fn bits(x: U512) -> u32 {
    for (offset, limb) in [(384, x.d3), (256, x.d2), (128, x.d1), (0, x.d0)] {
        if limb != 0 {
            return offset + 128 - limb.leading_zeros();
        }
    }
    0
}
fn pow2(exponent: u32) -> U512 {
    assert!(exponent < 512);
    let mut x = U512::zero();
    let limb = match exponent / 128 {
        0 => &mut x.d0,
        1 => &mut x.d1,
        2 => &mut x.d2,
        _ => &mut x.d3,
    };
    *limb = 1u128 << (exponent % 128);
    x
}

#[derive(Debug, PartialEq, Eq)]
enum Refusal {
    Regime,
    NonCentered,
    StateLimit {
        needed: usize,
        limit: usize,
    },
    Noise {
        stage: &'static str,
        error_bits: u32,
        half_bits: u32,
    },
}

struct Noise {
    n: u128,
    t: u64,
    q_bits: u32,
    half: U512,
    switch: U512,
    projected: U512,
    key_words: u128,
}

impl Noise {
    fn new(config: &FHEConfig) -> Self {
        let arithmetic = ExactMulPlan::new(&config.primes, config.n, config.t).unwrap();
        let c = arithmetic.certificate();
        let n = config.n as u128;
        let q = U512::product_u64s(&config.primes);
        let switch = U512::from_u128(
            n * config.eta as u128
                * ((1u128 << c.base_bits) - 1)
                * c.digits_per_lane.iter().sum::<usize>() as u128,
        );
        // Directly preconditioned selector polynomials encode -8*delta;
        // N*(-8)=1 mod 65537. No ciphertext post-scaling is assumed free.
        assert_eq!(config.n as u64 * 8 + 1, config.t);
        let input = U512::from_u128(config.eta as u128 * (2 * n + 1) + 8);
        let projected = input.mul_u128(n).add(switch.mul_u128(n - 1));
        let key_words = (config.n.ilog2() as u128 + 1)
            * c.digits_per_lane.iter().sum::<usize>() as u128
            * 2
            * config.primes.len() as u128
            * n;
        Self {
            n,
            t: config.t,
            q_bits: bits(q),
            half: q.div_u64(config.t).div_u64(2),
            switch,
            projected,
            key_words,
        }
    }
    fn admit(&self, value: U512, stage: &'static str) -> Result<U512, Refusal> {
        if words(value) >= words(self.half) {
            Err(Refusal::Noise {
                stage,
                error_bits: bits(value),
                half_bits: bits(self.half),
            })
        } else {
            Ok(value)
        }
    }
    fn multiply(&self, a: U512, b: U512) -> Result<U512, Refusal> {
        let np = self.n * self.t as u128;
        let factor = np * (self.n / 2 + 1) + (self.t - 1) as u128 / 2;
        let exponent =
            (bits(a) + bits(b) + (128 - np.leading_zeros())).saturating_sub(self.q_bits - 1);
        let quadratic = if a == U512::zero() || b == U512::zero() {
            U512::zero()
        } else {
            pow2(exponent)
        };
        let rounding = (self.n * self.n + self.n + 1).div_ceil(2);
        self.admit(
            a.add(b)
                .mul_u128(factor)
                .add(quadratic)
                .add(U512::from_u128(rounding))
                .add(self.switch),
            "selector multiply",
        )
    }
}

#[derive(Clone)]
struct Trit {
    encrypted: [RNSCiphertext; 3],
    bound: U512,
    family: [u64; 2],
    coefficient: usize,
}
#[derive(Clone)]
struct Row {
    remainder: i128,
    winding: i64,
    selector: Option<RNSCiphertext>, // None is the initial PUBLIC one.
    bound: U512,
}
#[derive(Clone)]
struct State {
    rows: Vec<Row>,
    family: [u64; 2],
    source_q: i128,
    coefficients: Vec<usize>,
}
struct Projection {
    ciphertext: RNSCiphertext,
    bound: U512,
}
struct CarryRuntime<'a> {
    ctx: &'a RNSFHEContext,
    exact: ExactMulEvaluator<'a>,
    noise: Noise,
    source_q: i128,
    family: [u64; 2],
    max_states: usize,
    multiplications: Cell<usize>,
}

impl<'a> CarryRuntime<'a> {
    fn new(ctx: &'a RNSFHEContext, source_q: i128, family: [u64; 2], max_states: usize) -> Self {
        assert!(source_q >= 3 && source_q % 2 == 1);
        Self {
            ctx,
            exact: ctx.try_exact_evaluator().unwrap(),
            noise: Noise::new(&ctx.config),
            source_q,
            family,
            max_states,
            multiplications: Cell::new(0),
        }
    }
    fn initial(&self, remainder: i128) -> Result<State, Refusal> {
        if remainder.abs() > self.source_q / 2 {
            return Err(Refusal::NonCentered);
        }
        Ok(State {
            rows: vec![Row {
                remainder,
                winding: 0,
                selector: None,
                bound: U512::zero(),
            }],
            family: self.family,
            source_q: self.source_q,
            coefficients: vec![],
        })
    }
    fn root_value(&self, row: &Row, p: u64) -> i64 {
        // Project S=g+Q*K on demand; never form a wide hidden scalar S.
        ((row.remainder.rem_euclid(p as i128)
            + (row.winding as i128).rem_euclid(p as i128) * self.source_q.rem_euclid(p as i128))
            % p as i128) as i64
    }
    fn projection_bound(&self, state: &State, value: impl Fn(&Row) -> i64) -> U512 {
        state.rows.iter().fold(U512::zero(), |sum, row| {
            let bound = if row.bound == U512::zero() {
                U512::from_u64(1)
            } else {
                row.bound
            };
            sum.add(bound.mul_u128(value(row).unsigned_abs() as u128))
        })
    }
    fn advance(
        &self,
        state: &State,
        term: i128,
        trit: &Trit,
        relin: &RNSHybridGadgetKey,
    ) -> Result<State, Refusal> {
        if state.family != self.family
            || trit.family != self.family
            || state.source_q != self.source_q
        {
            return Err(Refusal::Regime);
        }
        if term.abs() > self.source_q / 2 {
            return Err(Refusal::NonCentered);
        }
        let right = State {
            rows: (0..3)
                .map(|branch| Row {
                    remainder: term * (branch as i128 - 1),
                    winding: 0,
                    selector: Some(trit.encrypted[branch].clone()),
                    bound: trit.bound,
                })
                .collect(),
            family: trit.family,
            source_q: self.source_q,
            coefficients: vec![trit.coefficient],
        };
        self.compose(state, &right, relin)
    }
    fn compose(
        &self,
        left: &State,
        right: &State,
        relin: &RNSHybridGadgetKey,
    ) -> Result<State, Refusal> {
        if left.family != self.family
            || right.family != self.family
            || left.source_q != self.source_q
            || right.source_q != self.source_q
        {
            return Err(Refusal::Regime);
        }
        let mut destinations = BTreeMap::new();
        let mut rows: Vec<Row> = Vec::new();
        let mut edges = Vec::new();
        // Plan every public transition, capacity and error BEFORE any multiply.
        for (source, row) in left.rows.iter().enumerate() {
            for (branch, other) in right.rows.iter().enumerate() {
                let sum = row.remainder + other.remainder;
                let increment = (sum + self.source_q / 2).div_euclid(self.source_q);
                let destination = (
                    sum - self.source_q * increment,
                    row.winding + other.winding + increment as i64,
                );
                let bound = if row.selector.is_none() {
                    self.noise.admit(other.bound, "input selector")?
                } else if other.selector.is_none() {
                    self.noise.admit(row.bound, "input selector")?
                } else {
                    self.noise.multiply(row.bound, other.bound)?
                };
                let index = if let Some(&index) = destinations.get(&destination) {
                    index
                } else {
                    let index = rows.len();
                    if index >= self.max_states {
                        return Err(Refusal::StateLimit {
                            needed: index + 1,
                            limit: self.max_states,
                        });
                    }
                    destinations.insert(destination, index);
                    rows.push(Row {
                        remainder: destination.0,
                        winding: destination.1,
                        selector: None,
                        bound: U512::zero(),
                    });
                    index
                };
                rows[index].bound = rows[index].bound.add(bound);
                self.noise.admit(rows[index].bound, "merged selector")?;
                edges.push((source, branch, index));
            }
        }
        let mut result = State {
            rows,
            family: left.family,
            source_q: left.source_q,
            coefficients: left
                .coefficients
                .iter()
                .chain(&right.coefficients)
                .copied()
                .collect(),
        };
        self.noise.admit(
            self.projection_bound(&result, |row| row.winding),
            "carry projection",
        )?;
        for p in ROOT {
            self.noise.admit(
                self.projection_bound(&result, |row| self.root_value(row, p)),
                "Safe Basis projection",
            )?;
        }
        for (source, branch, destination) in edges {
            let output = match (&left.rows[source].selector, &right.rows[branch].selector) {
                (None, None) => None,
                (None, Some(input)) | (Some(input), None) => Some(input.clone()),
                (Some(input), Some(other)) => {
                    self.multiplications.set(self.multiplications.get() + 1);
                    Some(self.exact.try_mul_exact(input, other, relin).unwrap())
                }
            };
            if let Some(output) = output {
                result.rows[destination].selector =
                    Some(match result.rows[destination].selector.take() {
                        None => output,
                        Some(previous) => self.ctx.add(&previous, &output),
                    });
            }
        }
        Ok(result)
    }
    fn project(&self, state: &State, value: impl Fn(&Row) -> i64) -> Projection {
        let bound = self.projection_bound(state, &value);
        self.noise.admit(bound, "output projection").unwrap();
        let mut output = zero(self.ctx);
        for row in &state.rows {
            let coefficient = value(row);
            if let Some(input) = &row.selector {
                add_scaled(self.ctx, &mut output, input, coefficient);
            } else {
                for (lane, &q) in self.ctx.config.primes.iter().enumerate() {
                    let value = ((coefficient as i128).rem_euclid(q as i128) as u128
                        * self.ctx.delta_rns[lane] as u128
                        % q as u128) as u64;
                    let encoded = self.ctx.rns.mont_contexts[lane].to_montgomery(value);
                    output.c0.limbs[lane][0] =
                        ((output.c0.limbs[lane][0] as u128 + encoded as u128) % q as u128) as u64;
                }
            }
        }
        Projection {
            ciphertext: output,
            bound,
        }
    }
}

fn zero(ctx: &RNSFHEContext) -> RNSCiphertext {
    RNSCiphertext {
        c0: RNSPolynomial {
            limbs: vec![vec![0; ctx.n]; ctx.config.primes.len()],
            n: ctx.n,
        },
        c1: RNSPolynomial {
            limbs: vec![vec![0; ctx.n]; ctx.config.primes.len()],
            n: ctx.n,
        },
        num_primes: ctx.config.primes.len(),
    }
}
fn add_scaled(ctx: &RNSFHEContext, dst: &mut RNSCiphertext, src: &RNSCiphertext, coefficient: i64) {
    for (a, b) in [(&mut dst.c0, &src.c0), (&mut dst.c1, &src.c1)] {
        for (lane, &q) in ctx.config.primes.iter().enumerate() {
            let c = (coefficient as i128).rem_euclid(q as i128) as u128;
            for (value, &term) in a.limbs[lane].iter_mut().zip(&b.limbs[lane]) {
                *value = ((*value as u128 + c * term as u128) % q as u128) as u64;
            }
        }
    }
}

fn project_trit(
    ctx: &RNSFHEContext,
    packed: &[RNSCiphertext; 3],
    trace: &[RNSGaloisKey],
    coefficient: usize,
    family: [u64; 2],
    bound: U512,
) -> Trit {
    assert!(coefficient < ctx.n);
    let galois = RNSGaloisEvaluator::new(ctx).unwrap();
    let encrypted = core::array::from_fn(|label| {
        let mut output = shift(
            ctx,
            &packed[label],
            if coefficient == 0 {
                0
            } else {
                2 * ctx.n - coefficient
            },
        );
        for key in trace {
            output = ctx.add(&output, &galois.apply(&output, key).unwrap());
        }
        output
    });
    Trit {
        encrypted,
        bound,
        family,
        coefficient,
    }
}

// Independent secret-holder oracle: full-width Q and bounds also support
// the five-prime boot chain. No oracle is called by advance/project_trit.
fn decode(ctx: &RNSFHEContext, ct: &RNSCiphertext, sk: &DualRNSSecretKey, bound: U512) -> Vec<u64> {
    decode_at(ctx, ct, sk, bound, [0, 1, ctx.n / 2, ctx.n - 1])
}

fn decode_at(
    ctx: &RNSFHEContext,
    ct: &RNSCiphertext,
    sk: &DualRNSSecretKey,
    bound: U512,
    indices: impl IntoIterator<Item = usize>,
) -> Vec<u64> {
    let phases: Vec<Vec<u64>> = ctx
        .config
        .primes
        .iter()
        .enumerate()
        .map(|(lane, &p)| {
            let mont = &ctx.rns.mont_contexts[lane];
            let c1: Vec<_> = ct.c1.limbs[lane]
                .iter()
                .map(|&x| mont.from_montgomery(x))
                .collect();
            let product = ctx.ntt_engines[lane].multiply(&c1, &sk.s.main[lane]);
            ct.c0.limbs[lane]
                .iter()
                .zip(product)
                .map(|(&x, y)| ((mont.from_montgomery(x) as u128 + y as u128) % p as u128) as u64)
                .collect()
        })
        .collect();
    let q = U256::product_u64s(&ctx.config.primes);
    let limit = bound.mul_u128(ctx.t as u128);
    assert_eq!((limit.d3, limit.d2), (0, 0));
    let limit = U256 {
        lo: limit.d0,
        hi: limit.d1,
    };
    indices
        .into_iter()
        .map(|j| {
            let phase = ctx.rns.to_u256_level(
                &phases.iter().map(|lane| lane[j]).collect::<Vec<_>>(),
                phases.len(),
            );
            let scaled = phase.mul_u64(ctx.t);
            let (rounded, _) = scaled.add(q.shr1()).div_mod_u256(q);
            assert_eq!(rounded.hi, 0);
            let value = (rounded.lo % ctx.t as u128) as u64;
            let ideal = q.mul_u64(value);
            let mut difference = if scaled.ge(ideal) {
                scaled.sub(ideal)
            } else {
                ideal.sub(scaled)
            };
            let period = q.mul_u64(ctx.t);
            if difference.ge(period.shr1()) {
                difference = period.sub(difference);
            }
            assert!(
                limit.ge(difference),
                "composition exact-grid error at j={j}"
            );
            value
        })
        .collect()
}

fn config_with(count: usize) -> FHEConfig {
    let mut config = SecureConfig::secure_128().into_config();
    config.primes = BOOT[..count].to_vec();
    config.q = BOOT[0];
    config
}

fn sparse_components(
    work: &FHEConfig,
    initial: i128,
    first: i128,
    second: i128,
) -> [Vec<Vec<u64>>; 2] {
    let mut components = [
        vec![vec![0; work.n]; work.primes.len()],
        vec![vec![0; work.n]; work.primes.len()],
    ];
    for (lane, &q) in work.primes.iter().enumerate() {
        let inverse_t = inverse(work.t % q, q) as u128;
        let encode = |r: i128| (r.rem_euclid(q as i128) as u128 * inverse_t % q as u128) as u64;
        // Target coefficient j=1 has S=R0[1]+R1[1]*s[0]+R1[0]*s[1].
        components[0][lane][1] = encode(initial);
        components[1][lane][1] = encode(first);
        components[1][lane][0] = encode(second);
    }
    components
}

// Evaluator-side coefficient refresh. The sparse-domain carry is already
// admitted and bound to the same source in this private test fixture. No
// source or boot secret, phase oracle, or decrypted noise appears here.
fn refresh_coefficient(
    runtime: &CarryRuntime<'_>,
    work: &FHEConfig,
    components: &[Vec<Vec<u64>>; 2],
    encrypted_source: &RNSCiphertext,
    trace: &[RNSGaloisKey],
    carry: &Projection,
) -> (Projection, Projection) {
    let q = U512::product_u64s(&runtime.ctx.config.primes);
    let n = runtime.ctx.n as u128;
    let t = runtime.ctx.t;
    let remainder = q.mod_u64(t) as u128;
    let beta = runtime.ctx.config.eta as u128 * (2 * n + 1);
    let inner_error =
        U512::from_u128(beta * n * (t / 2) as u128 + (n + 1) * remainder + remainder.div_ceil(2));
    let affine_error = inner_error
        .mul_u128(n)
        .add(runtime.noise.switch.mul_u128(n - 1));
    let output_error = runtime
        .noise
        .admit(affine_error.add(carry.bound), "bounded coefficient refresh")
        .unwrap();
    let scaler = CanonicalScaleRound::new(&work.primes, work.t).unwrap();
    let prepared = components.each_ref().map(|component| {
        (0..work.n)
            .map(|j| {
                let residues: Vec<_> = component.iter().map(|lane| lane[j]).collect();
                let a = scaler.scale_round(&residues).unwrap();
                (a as u128 * (t - 8) as u128 % t as u128) as u64
            })
            .collect::<Vec<_>>()
    });
    let phase =
        evaluate_centered_components(runtime.ctx, &prepared[0], &prepared[1], encrypted_source);
    let galois = RNSGaloisEvaluator::new(runtime.ctx).unwrap();
    let mut affine = shift(runtime.ctx, &phase, 2 * runtime.ctx.n - 1);
    for key in trace {
        affine = runtime
            .ctx
            .add(&affine, &galois.apply(&affine, key).unwrap());
    }
    let refreshed = runtime.ctx.add(&affine, &carry.ciphertext);
    (
        Projection {
            ciphertext: affine,
            bound: affine_error,
        },
        Projection {
            ciphertext: refreshed,
            bound: output_error,
        },
    )
}

fn source_decode_oracle(
    work: &RNSFHEContext,
    components: &[Vec<Vec<u64>>; 2],
    source: &[i8],
) -> (u64, U256) {
    let residues: Vec<_> = work
        .config
        .primes
        .iter()
        .enumerate()
        .map(|(lane, &q)| {
            let secret: Vec<_> = source
                .iter()
                .map(|&x| (x as i128).rem_euclid(q as i128) as u64)
                .collect();
            let product = work.ntt_engines[lane].multiply(&components[1][lane], &secret);
            ((components[0][lane][1] as u128 + product[1] as u128) % q as u128) as u64
        })
        .collect();
    let message = CanonicalScaleRound::new(&work.config.primes, work.t)
        .unwrap()
        .scale_round(&residues)
        .unwrap();
    let phase = work.rns.to_u256_level(&residues, residues.len());
    let q = U256::product_u64s(&work.config.primes);
    let scaled = phase.mul_u64(work.t);
    let ideal = q.mul_u64(message);
    let mut distance = if scaled.ge(ideal) {
        scaled.sub(ideal)
    } else {
        ideal.sub(scaled)
    };
    let period = q.mul_u64(work.t);
    if distance.ge(period.shr1()) {
        distance = period.sub(distance);
    }
    (message, distance)
}

#[test]
fn precharged_composition_profiles_check_security_and_noise_before_keys() {
    for count in [4, 5, 6] {
        let config = config_with(count);
        assert!(config.primes.iter().all(|&p| is_prime(p)));
        validate_bootstrap_primes(&config.primes, config.n).unwrap();
        let screen = screen_bootstrap_security(&config.primes, config.n, 128).unwrap();
        let noise = Noise::new(&config);
        let first = noise.projected;
        let second = noise.multiply(first, first).unwrap();
        let third = noise.multiply(second, first);
        eprintln!("composition profile: primes={count}, Qbits={}, security=({},{}) pass={}, projection_bits={}, two-term_bits={}, third={third:?}, half_bits={}, evaluation_key_bytes={}",
            noise.q_bits, screen.core_svp_bits, screen.matzov_bits, screen.meets_claim_under_both, bits(first), bits(second), bits(noise.half), noise.key_words*8);
        if count == 4 {
            assert!(matches!(third, Err(Refusal::Noise { .. })));
        }
        if count == 5 {
            assert!(screen.meets_claim_under_both);
            let third = third.unwrap();
            assert!(noise.multiply(third, first).is_err());
        }
        if count == 6 {
            assert!(
                !screen.meets_claim_under_both,
                "do not fund depth with an underscreened native chain"
            );
        }
    }
}

#[test]
#[cfg_attr(
    not(feature = "slow_tests"),
    ignore = "expensive native research probe; enable slow_tests or run this filter with --include-ignored"
)]
fn precharged_composition_uses_packed_selectors_and_updated_encrypted_remainder() {
    let work = SecureConfig::secure_128().into_config();
    let source_q = work.primes.iter().map(|&p| p as u128).product::<u128>() as i128;
    let config = config_with(5);
    validate_bootstrap_primes(&config.primes, config.n).unwrap();
    assert!(
        screen_bootstrap_security(&config.primes, config.n, 128)
            .unwrap()
            .meets_claim_under_both
    );
    let ctx = RNSFHEContext::try_new(&config).unwrap();
    let family = [0x434f_4d50_4f53_45, 1];
    let runtime = CarryRuntime::new(&ctx, source_q, family, 27);
    let mut rng = ShadowHarvester::with_seed(0x434f_4d50_4f53_45);
    let keys = ctx.generate_keys_dual(&mut rng);
    let native = RNSSecretKey {
        s: RNSPolynomial {
            n: ctx.n,
            limbs: ctx
                .rns
                .mont_contexts
                .iter()
                .zip(&keys.secret_key.s.main)
                .map(|(mont, lane)| lane.iter().map(|&x| mont.to_montgomery(x)).collect())
                .collect(),
        },
    };
    let galois = RNSGaloisEvaluator::new(&ctx).unwrap();
    let mut trace = Vec::new();
    let mut stride = ctx.n;
    eprintln!("composition: generating 13 native trace keys and one relinearization key");
    while stride > 1 {
        trace.push(
            galois
                .generate_key_with_rng(&native, stride as u64 + 1, &mut rng)
                .unwrap(),
        );
        stride /= 2;
    }
    let relin = runtime
        .exact
        .generate_hybrid_gadget_key_with_rng(&native, &mut rng);
    // Chosen public test source polynomial, independent of the boot secret.
    // Three packed ciphertexts contain indicators for ALL 8192 coefficients.
    let source: Vec<i8> = (0..ctx.n).map(|j| [1, -1, 0][j % 3]).collect();
    let encrypted_source = precharge(&ctx, &keys, &source, &mut rng);
    let work_ctx = RNSFHEContext::try_new(&work).unwrap();
    let packed = core::array::from_fn(|label| {
        let values: Vec<i8> = source
            .iter()
            .map(|&u| if u == label as i8 - 1 { -8 } else { 0 })
            .collect();
        precharge(&ctx, &keys, &values, &mut rng)
    });
    let mut trits = Vec::new();
    for coefficient in 0..4 {
        eprintln!("composition: projecting selector coefficient {coefficient}");
        let trit = project_trit(
            &ctx,
            &packed,
            &trace,
            coefficient,
            family,
            runtime.noise.projected,
        );
        for label in 0..3 {
            let decoded = decode(&ctx, &trit.encrypted[label], &keys.secret_key, trit.bound);
            assert_eq!(
                decoded[0],
                u64::from(source[coefficient] == label as i8 - 1)
            );
            assert!(decoded[1..].iter().all(|&x| x == 0));
        }
        trits.push(trit);
    }
    let h = source_q / 2;
    let mut checked = 48; // 4 coefficients * 3 labels * 4 decoded positions.
    for sign in [1i128, -1] {
        let initial = sign * h;
        let terms = [sign * h, -sign * h, sign * h];
        let mut state = runtime.initial(initial).unwrap();
        let mut exact_sum = initial;
        let mut left_pair = None;
        for step in 0..3 {
            state = runtime
                .advance(&state, terms[step], &trits[step], &relin)
                .unwrap();
            if step == 1 {
                left_pair = Some(state.clone());
            }
            exact_sum += terms[step] * source[step] as i128;
            let expected_carry = (exact_sum + h).div_euclid(source_q);
            let expected_remainder = exact_sum - source_q * expected_carry;
            assert!(state
                .rows
                .iter()
                .any(|r| r.remainder == expected_remainder && r.winding as i128 == expected_carry));
            let carry = runtime.project(&state, |r| r.winding);
            let decoded = decode(&ctx, &carry.ciphertext, &keys.secret_key, carry.bound);
            assert_eq!(decoded[0] as i128, expected_carry.rem_euclid(ctx.t as i128));
            assert!(decoded[1..].iter().all(|&x| x == 0));
            checked += 4;
            for p in ROOT {
                let view = runtime.project(&state, |r| runtime.root_value(r, p));
                let decoded = decode(&ctx, &view.ciphertext, &keys.secret_key, view.bound);
                assert_eq!(decoded[0] as i128, exact_sum.rem_euclid(p as i128));
                assert!(decoded[1..].iter().all(|&x| x == 0));
                checked += 4;
            }
            eprintln!(
                "composition: sign={sign}, terms={}, public_rows={}, carry_error_bits={}",
                step + 1,
                state.rows.len(),
                bits(carry.bound)
            );
        }
        // Wrong-reset regression: two H terms cross once, not twice.
        assert_eq!(
            ((initial + terms[0] * source[0] as i128 + h).div_euclid(source_q)
                + (initial + terms[1] * source[1] as i128 + h).div_euclid(source_q)),
            2 * sign
        );
        assert_eq!((exact_sum + h).div_euclid(source_q), sign);
        let before = runtime.multiplications.get();
        let refusal = runtime.advance(&state, h, &trits[0], &relin).err().unwrap();
        assert!(matches!(refusal, Refusal::Noise { .. }));
        assert_eq!(
            runtime.multiplications.get(),
            before,
            "refuse before any extra multiplication"
        );
        let mut wrong_family = trits[0].clone();
        wrong_family.family[1] += 1;
        assert!(matches!(
            runtime.advance(&state, h, &wrong_family, &relin),
            Err(Refusal::Regime)
        ));
        assert!(matches!(
            runtime.advance(&state, h + 1, &trits[0], &relin),
            Err(Refusal::NonCentered)
        ));
        eprintln!("composition: fourth term refused before execution: {refusal:?}");
        // Balanced block composition uses two multiplication levels rather
        // than the sequential fourth term's three. Both inputs are encrypted
        // remainder/winding states from distinct source coefficient blocks.
        let right_one = runtime
            .advance(&runtime.initial(0).unwrap(), sign * h, &trits[2], &relin)
            .unwrap();
        let right_pair = runtime
            .advance(&right_one, sign * h, &trits[3], &relin)
            .unwrap();
        let balanced = runtime
            .compose(left_pair.as_ref().unwrap(), &right_pair, &relin)
            .unwrap();
        assert_eq!(balanced.coefficients, vec![0, 1, 2, 3]);
        let total = initial
            + terms[0] * source[0] as i128
            + terms[1] * source[1] as i128
            + sign * h * (source[2] as i128 + source[3] as i128);
        let carry = runtime.project(&balanced, |row| row.winding);
        let actual = decode(&ctx, &carry.ciphertext, &keys.secret_key, carry.bound);
        assert_eq!(
            actual[0] as i128,
            ((total + h).div_euclid(source_q)).rem_euclid(ctx.t as i128)
        );
        assert!(actual[1..].iter().all(|&x| x == 0));
        checked += 4;
        let mut root_bits = 0;
        for p in ROOT {
            let view = runtime.project(&balanced, |row| runtime.root_value(row, p));
            let actual = decode(&ctx, &view.ciphertext, &keys.secret_key, view.bound);
            assert_eq!(actual[0] as i128, total.rem_euclid(p as i128));
            assert!(actual[1..].iter().all(|&x| x == 0));
            root_bits = root_bits.max(bits(view.bound));
            checked += 4;
        }
        assert_eq!(balanced.rows.len(), 9);
        let before = runtime.multiplications.get();
        assert!(matches!(
            runtime.compose(&balanced, &right_pair, &relin),
            Err(Refusal::Noise { .. })
        ));
        assert_eq!(runtime.multiplications.get(), before);
        eprintln!("composition: balanced four terms, sign={sign}, rows={}, carry_error_bits={}, largest_root_error_bits={root_bits}",balanced.rows.len(),bits(carry.bound));
        // End-to-end follow-up on an actual sparse work-domain ciphertext.
        // Its target coefficient sits one integer grid unit from the cut.
        let components = sparse_components(&work, initial, terms[0], terms[1]);
        let pair_carry = runtime.project(left_pair.as_ref().unwrap(), |row| row.winding);
        let (affine, refreshed) = refresh_coefficient(
            &runtime,
            &work,
            &components,
            &encrypted_source,
            &trace,
            &pair_carry,
        );
        let (message, old_grid_error) = source_decode_oracle(&work_ctx, &components, &source);
        assert_eq!(old_grid_error, U256::from_u128((h - 1) as u128));
        let uncorrected = decode_at(
            &ctx,
            &affine.ciphertext,
            &keys.secret_key,
            affine.bound,
            0..ctx.n,
        );
        assert_ne!(
            uncorrected[0], message,
            "original affine Phase 1 misses the carry"
        );
        assert!(uncorrected[1..].iter().all(|&x| x == 0));
        let actual = decode_at(
            &ctx,
            &refreshed.ciphertext,
            &keys.secret_key,
            refreshed.bound,
            0..ctx.n,
        );
        assert_eq!(actual[0], message);
        assert!(actual[1..].iter().all(|&x| x == 0));
        let post_bound = runtime
            .noise
            .multiply(refreshed.bound, refreshed.bound)
            .unwrap();
        let squared = runtime
            .exact
            .try_mul_exact(&refreshed.ciphertext, &refreshed.ciphertext, &relin)
            .unwrap();
        let actual = decode_at(&ctx, &squared, &keys.secret_key, post_bound, 0..ctx.n);
        assert_eq!(
            actual[0],
            (message as u128 * message as u128 % ctx.t as u128) as u64
        );
        assert!(actual[1..].iter().all(|&x| x == 0));
        checked += 3 * ctx.n;
        eprintln!("composition: sparse coefficient refresh sign={sign}, fresh_error_bits={}, post_multiply_error_bits={}, half_bits={}",bits(refreshed.bound),bits(post_bound),bits(runtime.noise.half));
    }
    // Resource failure is public, reproducible, and leaves the source state.
    let limited = CarryRuntime::new(&ctx, source_q, family, 1);
    let initial = limited.initial(0).unwrap();
    assert!(matches!(
        limited.advance(&initial, h, &trits[0], &relin),
        Err(Refusal::StateLimit { .. })
    ));
    assert_eq!(limited.multiplications.get(), 0);
    assert_eq!(checked, 336 + 6 * ctx.n);
    eprintln!("composition: {checked} encrypted coefficient/noise checks; compact precharge; both carry signs; all eight root views; three sequential or four balanced terms; selector multiplications={}; not full refresh", runtime.multiplications.get());
}
