//! A centered remainder partition and ONE winding coordinate close under
//! the tropical carry cocycle. The partition-of-unity invariant avoids
//! multiplying conditional winding moments by the other state's selectors.
//!
//! Research only: the bounded period below is 13, NOT native Q_work.
//! Constant-polynomial selectors need no plaintext roots or slot transform.

use super::*;
use nine65::ops::rns_fhe::cram_precharge::CramPrechargedSecret;
use std::cell::Cell;

trait Ring {
    type Value: Clone;
    fn add(&self, a: &Self::Value, b: &Self::Value) -> Self::Value;
    fn mul(&self, a: &Self::Value, b: &Self::Value) -> Self::Value;
    fn scale(&self, a: &Self::Value, scalar: i64) -> Self::Value;
}

fn accumulate<R: Ring>(ring: &R, slot: &mut Option<R::Value>, value: R::Value) {
    *slot = Some(match slot.take() {
        None => value,
        Some(previous) => ring.add(&previous, &value),
    });
}

#[derive(Clone)]
struct State<V> {
    period: usize,
    // Plaintexts 1[g=r]. Support is PUBLIC; None is structural zero, never
    // a branch determined by a decrypted selector. Their plaintext sum is 1.
    channels: Vec<Option<V>>,
    winding: Option<V>,
    inputs: BTreeSet<usize>,
    depth: usize,
}

#[derive(Debug, PartialEq, Eq)]
enum Refusal {
    Period,
    Capacity,
    NonCentered,
    InputOverlap,
    Domain,
}

fn validate_period(period: u128, max_channels: usize) -> Result<usize, Refusal> {
    if period < 3 || period % 2 == 0 {
        return Err(Refusal::Period);
    }
    if period > max_channels as u128 {
        return Err(Refusal::Capacity);
    }
    Ok(period as usize)
}

fn centered(sum: i64, period: usize) -> (usize, i64) {
    let h = period as i64 / 2;
    let carry = (sum + h).div_euclid(period as i64);
    ((sum - carry * period as i64 + h) as usize, carry)
}

fn leaf<R: Ring>(
    ring: &R,
    period: usize,
    weight: i64,
    input: usize,
    selectors: &[R::Value; 3],
) -> Result<State<R::Value>, Refusal> {
    if weight.unsigned_abs() > period as u64 / 2 {
        return Err(Refusal::NonCentered);
    }
    let mut channels = vec![None; period];
    for (branch, selector) in selectors.iter().enumerate() {
        let (index, carry) = centered(weight * (branch as i64 - 1), period);
        assert_eq!(carry, 0);
        accumulate(ring, &mut channels[index], selector.clone());
    }
    Ok(State {
        period,
        channels,
        winding: None,
        inputs: BTreeSet::from([input]),
        depth: 0,
    })
}

fn compose<R: Ring>(
    ring: &R,
    left: &State<R::Value>,
    right: &State<R::Value>,
    omit_cocycle: bool,
) -> Result<State<R::Value>, Refusal> {
    if left.period != right.period {
        return Err(Refusal::Domain);
    }
    if !left.inputs.is_disjoint(&right.inputs) {
        return Err(Refusal::InputOverlap);
    }
    let period = left.period;
    let h = period as i64 / 2;
    let mut channels = vec![None; period];
    let mut winding = left.winding.clone();
    if let Some(k) = &right.winding {
        accumulate(ring, &mut winding, k.clone());
    }
    for (i, a) in left.channels.iter().enumerate() {
        let Some(pa) = a else { continue };
        for (j, b) in right.channels.iter().enumerate() {
            let Some(pb) = b else { continue };
            let (destination, carry) = centered(i as i64 + j as i64 - 2 * h, period);
            let product = ring.mul(pa, pb);
            if carry != 0 && !omit_cocycle {
                accumulate(ring, &mut winding, ring.scale(&product, carry));
            }
            accumulate(ring, &mut channels[destination], product);
        }
    }
    Ok(State {
        period,
        channels,
        winding,
        inputs: left.inputs.union(&right.inputs).copied().collect(),
        depth: left.depth.max(right.depth) + 1,
    })
}

// A public centered initial R0 is a permutation plus a cocycle deposit.
// It is NOT an initial chart for R0+R1*s, which is still hidden.
fn shift<R: Ring>(ring: &R, state: &State<R::Value>, r0: i64) -> State<R::Value> {
    assert!(r0.unsigned_abs() <= state.period as u64 / 2);
    let mut output = state.clone();
    output.channels.fill(None);
    for (index, channel) in state.channels.iter().enumerate() {
        let (destination, carry) =
            centered(index as i64 - state.period as i64 / 2 + r0, state.period);
        output.channels[destination] = channel.clone();
        if carry != 0 {
            if let Some(p) = channel {
                accumulate(ring, &mut output.winding, ring.scale(p, carry));
            }
        }
    }
    output
}

fn project<R: Ring>(ring: &R, state: &State<R::Value>, chart: bool) -> R::Value {
    let mut output = if chart { None } else { state.winding.clone() };
    if chart {
        for (index, value) in state.channels.iter().enumerate() {
            if let Some(value) = value {
                let factor = index as i64 - state.period as i64 / 2;
                if factor != 0 {
                    accumulate(ring, &mut output, ring.scale(value, factor));
                }
            }
        }
    }
    output.unwrap_or_else(|| {
        let selector = state
            .channels
            .iter()
            .find_map(|c| c.as_ref())
            .expect("nonempty public support");
        ring.scale(selector, 0)
    })
}

fn build<R: Ring>(
    ring: &R,
    period: usize,
    weights: &[i64],
    selectors: &[[R::Value; 3]],
    omit_cocycle: bool,
) -> State<R::Value> {
    assert_eq!(weights.len(), selectors.len());
    let mut forest: Vec<_> = weights
        .iter()
        .enumerate()
        .map(|(input, &weight)| leaf(ring, period, weight, input, &selectors[input]).unwrap())
        .collect();
    while forest.len() > 1 {
        let mut next = Vec::new();
        let mut iter = forest.into_iter();
        while let Some(left) = iter.next() {
            next.push(if let Some(right) = iter.next() {
                compose(ring, &left, &right, omit_cocycle).unwrap()
            } else {
                left
            });
        }
        forest = next;
    }
    forest.pop().unwrap()
}

struct ClearRing {
    modulus: i64,
}
impl Ring for ClearRing {
    type Value = i64;
    fn add(&self, a: &i64, b: &i64) -> i64 {
        (a + b).rem_euclid(self.modulus)
    }
    fn mul(&self, a: &i64, b: &i64) -> i64 {
        (a * b).rem_euclid(self.modulus)
    }
    fn scale(&self, a: &i64, scalar: i64) -> i64 {
        (a * scalar).rem_euclid(self.modulus)
    }
}

struct CipherRing<'a> {
    ctx: &'a RNSFHEContext,
    relin: &'a RNSHybridGadgetKey,
    multiplications: Cell<usize>,
}
impl Ring for CipherRing<'_> {
    type Value = RNSCiphertext;
    fn add(&self, a: &RNSCiphertext, b: &RNSCiphertext) -> RNSCiphertext {
        add(self.ctx, a, b)
    }
    fn mul(&self, a: &RNSCiphertext, b: &RNSCiphertext) -> RNSCiphertext {
        self.multiplications.set(self.multiplications.get() + 1);
        self.ctx
            .try_exact_evaluator()
            .unwrap()
            .try_mul_exact(a, b, self.relin)
            .unwrap()
    }
    fn scale(&self, a: &RNSCiphertext, scalar: i64) -> RNSCiphertext {
        let mut polynomial = vec![0; self.ctx.n];
        polynomial[0] = scalar.unsigned_abs();
        let output = multiply_plain(self.ctx, a, &polynomial);
        if scalar < 0 {
            self.ctx.sub(&self.ctx.sub(a, a), &output)
        } else {
            output
        }
    }
}

#[test]
fn lifted_remainder_cocycle_initializes_chart_and_preserves_associativity() {
    let period = validate_period(13, 32).unwrap();
    let weights = [1, 3, 4, 6, -5, 2];
    let mut checked = 0;
    for modulus in [2, 11, 22, 121, 289] {
        let ring = ClearRing { modulus };
        for assignment in 0..3usize.pow(weights.len() as u32) {
            let mut code = assignment;
            let mut secret = Vec::new();
            let selectors: Vec<_> = weights
                .iter()
                .map(|_| {
                    let branch = code % 3;
                    code /= 3;
                    secret.push(branch as i64 - 1);
                    core::array::from_fn(|label| i64::from(branch == label))
                })
                .collect();
            let state = shift(&ring, &build(&ring, period, &weights, &selectors, false), 6);
            let source = 6 + weights
                .iter()
                .zip(&secret)
                .map(|(&w, &s)| w * s)
                .sum::<i64>();
            let (_, k) = centered(source, period);
            assert_eq!(
                project(&ring, &state, true),
                (source - period as i64 * k).rem_euclid(modulus)
            );
            assert_eq!(project(&ring, &state, false), k.rem_euclid(modulus));
            assert!(state.channels.len() <= 13);
            assert_eq!(state.channels.iter().filter(|p| **p == Some(1)).count(), 1);
            assert!(state
                .channels
                .iter()
                .all(|p| matches!(p, None | Some(0) | Some(1))));
            let mut sequential = leaf(&ring, period, weights[0], 0, &selectors[0]).unwrap();
            for input in 1..weights.len() {
                let right = leaf(&ring, period, weights[input], input, &selectors[input]).unwrap();
                sequential = compose(&ring, &sequential, &right, false).unwrap();
            }
            let sequential = shift(&ring, &sequential, 6);
            for (a, b) in state.channels.iter().zip(&sequential.channels) {
                assert_eq!(a.unwrap_or(0), b.unwrap_or(0));
            }
            assert_eq!(state.winding.unwrap_or(0), sequential.winding.unwrap_or(0));
            checked += 1;
        }
    }
    assert_eq!(checked, 3645);

    // Omitting the tropical cocycle keeps the torus point, loses its lift.
    let ring = ClearRing { modulus: 289 };
    let selectors = [[0, 0, 1]; 4];
    let bad = build(&ring, period, &[6; 4], &selectors, true);
    let good = build(&ring, period, &[6; 4], &selectors, false);
    assert_eq!(project(&ring, &bad, true), project(&ring, &good, true));
    assert_eq!(project(&ring, &bad, false), 0);
    assert_eq!(project(&ring, &good, false), 2);

    // The earlier single-coordinate polynomial collision is not a limit of
    // this richer state: -9 and 8 retain different source-selector histories.
    let minus = build(&ring, period, &[3, 3, 3], &[[1, 0, 0]; 3], false);
    let plus = build(&ring, period, &[3, 3, 2], &[[0, 0, 1]; 3], false);
    assert_eq!((-9i64).rem_euclid(17), 8);
    assert_eq!(project(&ring, &minus, false), 288);
    assert_eq!(project(&ring, &plus, false), 1);
    assert!(matches!(
        compose(&ring, &good, &good, false),
        Err(Refusal::InputOverlap)
    ));
    assert!(matches!(
        leaf(&ring, period, 7, 0, &[0, 1, 0]),
        Err(Refusal::NonCentered)
    ));
    eprintln!("cocycle state: {checked} clear assignments, five payload rings, balanced/sequential agreement, <=13 remainder channels");
}

fn constant_message(ctx: &RNSFHEContext, value: i64) -> Vec<u64> {
    let mut message = vec![0; ctx.n];
    message[0] = value.rem_euclid(ctx.t as i64) as u64;
    message
}

// Independent CLIENT oracle for the even-plaintext probe. The production
// CanonicalScaleRound contract is odd-target-only; do not relax it here or
// quietly claim an admitted even-target decoder. Reconstruction is confined
// to this small-Q secret-key test oracle, never the public lifted evaluator.
fn client_decode_small_q(ctx: &RNSFHEContext, ct: &RNSCiphertext, keys: &RNSKeySet) -> Vec<u64> {
    let phases = decrypted_phase_residues(ctx, ct, keys);
    let q: u128 = ctx.config.primes.iter().map(|&p| p as u128).product();
    assert!(q.checked_mul(ctx.t as u128 + 1).is_some());
    (0..ctx.n)
        .map(|coefficient| {
            let (mut phase, mut product) = (0u128, 1u128);
            for (lane, &prime) in ctx.config.primes.iter().enumerate() {
                let p = prime as u128;
                let difference = (phases[lane][coefficient] as u128 + p - phase % p) % p;
                let digit = difference * inverse((product % p) as u64, prime) as u128 % p;
                phase += product * digit;
                product *= p;
            }
            (((ctx.t as u128 * phase + q / 2) / q) % ctx.t as u128) as u64
        })
        .collect()
}

// Public source coefficients for (R1*s)_j in Z[X]/(X^N+1).
fn convolution_weights(r1: &[i64], target: usize) -> Vec<i64> {
    (0..r1.len())
        .map(|input| {
            if input <= target {
                r1[target - input]
            } else {
                -r1[r1.len() + target - input]
            }
        })
        .collect()
}

#[test]
fn encrypted_cocycle_state_builds_weighted_source_chart_without_chart_oracle() {
    let mut config = SecureConfig::secure_128().into_config();
    config.n = 8;
    config.t = 289;
    config.security_bits = 0;
    config.name = "INSECURE tropical cocycle source-initialization toy";
    let ctx = RNSFHEContext::try_new(&config).unwrap();
    let mut rng = ShadowHarvester::with_seed(0x434f_4359_434c_4531);
    let keys = ctx.generate_keys(&mut rng);
    let exact = ctx.try_exact_evaluator().unwrap();
    let relin = exact.generate_hybrid_gadget_key_with_rng(&keys.secret_key, &mut rng);
    let ring = CipherRing {
        ctx: &ctx,
        relin: &relin,
        multiplications: Cell::new(0),
    };
    let period = validate_period(13, 32).unwrap();
    let q: u128 = config.primes.iter().map(|&p| p as u128).product();
    let mut max_v = [0u128; 4];
    let mut checked = 0;
    let mut nonzero = 0;
    let mut max_channels = 0;
    let mut full_sources = 0;
    for source_secret in [[1i8; 8], [-1, 0, 1, 1, 0, -1, 1, -1]] {
        // Setup depends ONLY on secret trits, before choosing live R0/R1.
        // Use the real eta-bounded precharge, independent uniform masks.
        let selectors: Vec<[RNSCiphertext; 3]> = source_secret
            .iter()
            .map(|&trit| {
                core::array::from_fn(|branch| {
                    let mut source = vec![0i8; ctx.n];
                    source[0] = i8::from(trit == branch as i8 - 1);
                    CramPrechargedSecret::generate_with_rng(
                        &ctx,
                        &source,
                        &keys.secret_key,
                        &mut rng,
                    )
                    .unwrap()
                    .encrypted_secret()
                    .clone()
                })
            })
            .collect();
        let encrypted_trits: Vec<_> = selectors.iter().map(|s| ctx.sub(&s[2], &s[0])).collect();
        for (profile, r1) in [[6, 5, -4, 3, -6, 2, 1, -5], [1, 3, -2, 6, 4, -5, 3, -6]]
            .iter()
            .enumerate()
        {
            // The first live polynomial checks every convolution coefficient;
            // the second reuses setup and checks two further coefficients.
            let targets: Vec<_> = if profile == 0 {
                (0..ctx.n).collect()
            } else {
                vec![0, 7]
            };
            let mut oracle = [0i64; 8];
            for (i, &residual) in r1.iter().enumerate() {
                for (j, &secret) in source_secret.iter().enumerate() {
                    oracle[(i + j) % ctx.n] += if i + j < ctx.n {
                        residual * secret as i64
                    } else {
                        -residual * secret as i64
                    };
                }
            }
            for target in targets {
                let r0 = [-6, -5, -1, 0, 1, 4, 5, 6][target];
                let weights = convolution_weights(r1, target);
                // Evaluator receives no source_secret, source S, chart g or K.
                let state = shift(
                    &ring,
                    &build(&ring, period, &weights, &selectors, false),
                    r0,
                );
                assert_eq!(state.depth, 3);
                max_channels =
                    max_channels.max(state.channels.iter().filter(|c| c.is_some()).count());
                let g = project(&ring, &state, true);
                let k = project(&ring, &state, false);
                let mut s = ctx.sub(&selectors[0][0], &selectors[0][0]);
                s = add_plain_constant(&ctx, &s, r0.rem_euclid(ctx.t as i64) as u64);
                for (&weight, trit) in weights.iter().zip(&encrypted_trits) {
                    s = ring.add(&s, &ring.scale(trit, weight));
                }
                let paired = tropical_winding_from_paired_coordinates(&ctx, period as u64, &s, &g);
                let square = ring.mul(&k, &k);

                // Independent client oracle ONLY AFTER all evaluator outputs.
                let source = r0 + oracle[target];
                let expected_k = (source + period as i64 / 2).div_euclid(period as i64);
                let expected_g = source - period as i64 * expected_k;
                assert_eq!(
                    decrypt_coefficients(&ctx, &s, &keys),
                    constant_message(&ctx, source)
                );
                for (index, ciphertext, expected) in [
                    (0, &g, expected_g),
                    (1, &k, expected_k),
                    (2, &paired, expected_k),
                    (3, &square, expected_k * expected_k),
                ] {
                    let intended = constant_message(&ctx, expected);
                    assert_eq!(
                        decrypt_coefficients(&ctx, ciphertext, &keys),
                        intended,
                        "profile={profile}, target={target}, output={index}"
                    );
                    let v = super::tropical_chart_transition::observed_scaled_error(
                        &ctx, ciphertext, &keys, &intended,
                    );
                    assert!(2 * v < q);
                    max_v[index] = max_v[index].max(v);
                }
                checked += 1;
                nonzero += usize::from(expected_k != 0);
            }
            full_sources += usize::from(profile == 0);
        }
    }
    assert_eq!((checked, full_sources, max_channels), (20, 2, 13));
    assert!(nonzero > 0);
    eprintln!("encrypted source initialization: {checked} coefficients, {full_sources} full negacyclic sources, nonzero sheets={nonzero}, <=13 remainder channels + one winding, depth=3, products={}", ring.multiplications.get());
    eprintln!(
        "observed V bits [chart,winding,paired winding,dependent square]={:?}, Qbits={}",
        max_v.map(|v| 128 - v.leading_zeros()),
        128 - q.leading_zeros()
    );
}

#[test]
fn encrypted_cocycle_works_over_composite_two_eleven_without_plaintext_roots() {
    let mut config = SecureConfig::secure_128().into_config();
    config.n = 8;
    config.t = 22;
    config.security_bits = 0;
    config.name = "INSECURE constant-coordinate 2/11 cocycle toy";
    assert!(matches!(
        CanonicalScaleRound::new(&config.primes, 22),
        Err(
            nine65::arithmetic::canonical_scale_round::CanonicalScaleRoundError::InvalidTarget {
                target: 22
            }
        )
    ));
    // No primitive 16th root exists in Z/22. This path only multiplies
    // constant plaintext polynomials; it does not run a slot transform.
    assert!(!(1..22).any(|a| mod_pow(a, 8, 22) == 21));
    let ctx = RNSFHEContext::try_new(&config).unwrap();
    let mut rng = ShadowHarvester::with_seed(0x5457_4f45_4c45_564e);
    let keys = ctx.generate_keys(&mut rng);
    let relin = ctx
        .try_exact_evaluator()
        .unwrap()
        .generate_hybrid_gadget_key_with_rng(&keys.secret_key, &mut rng);
    let ring = CipherRing {
        ctx: &ctx,
        relin: &relin,
        multiplications: Cell::new(0),
    };
    for (trit, weights, expected_s, expected_g, expected_k) in
        [(-1i8, [3, 3, 3], -9, 4, -1), (1i8, [3, 3, 2], 8, -5, 1)]
    {
        let selectors: Vec<[RNSCiphertext; 3]> = (0..3)
            .map(|_| {
                core::array::from_fn(|branch| {
                    let mut source = vec![0i8; ctx.n];
                    source[0] = i8::from(trit == branch as i8 - 1);
                    CramPrechargedSecret::generate_with_rng(
                        &ctx,
                        &source,
                        &keys.secret_key,
                        &mut rng,
                    )
                    .unwrap()
                    .encrypted_secret()
                    .clone()
                })
            })
            .collect();
        let state = build(&ring, 13, &weights, &selectors, false);
        let g = project(&ring, &state, true);
        let k = project(&ring, &state, false);
        let mut s = ctx.sub(&selectors[0][0], &selectors[0][0]);
        for (&w, selector) in weights.iter().zip(&selectors) {
            s = ring.add(&s, &ring.scale(&ctx.sub(&selector[2], &selector[0]), w));
        }
        let paired = tropical_winding_from_paired_coordinates(&ctx, 13, &s, &g);
        let square = ring.mul(&k, &k);
        for (ct, expected) in [
            (&s, expected_s),
            (&g, expected_g),
            (&k, expected_k),
            (&paired, expected_k),
            (&square, 1),
        ] {
            assert_eq!(
                client_decode_small_q(&ctx, ct, &keys),
                constant_message(&ctx, expected)
            );
            let v = super::tropical_chart_transition::observed_scaled_error(
                &ctx,
                ct,
                &keys,
                &constant_message(&ctx, expected),
            );
            let q: u128 = config.primes.iter().map(|&p| p as u128).product();
            assert!(2 * v < q);
        }
    }
    eprintln!("composite 2/11: both encrypted collision histories and dependent squares pass at t=22, without plaintext roots or factorial inverses");
}

#[test]
fn fixed_remainder_state_refuses_native_period_before_keys_or_ciphertext_work() {
    let q_work = 348_959_453_350_711_275_087_786_864_768_188_417u128;
    assert_eq!(validate_period(q_work, 4096), Err(Refusal::Capacity));
    assert_eq!(validate_period(2, 4096), Err(Refusal::Period));
    assert_eq!(validate_period(13, 13), Ok(13));
    // Removing winding rows changes O(Q*H) to O(Q), NOT O(log Q).
    // The native source period cannot be replaced by the small coordinate
    // payload modulus; they are different variables in the cocycle.
    let s = 20i128;
    assert_eq!((s + 6).div_euclid(13), 2);
    assert_eq!((s + q_work as i128 / 2).div_euclid(q_work as i128), 0);

    // A small local chart plus every intact-root payload coordinate does NOT
    // supply native centering. Two valid source histories with the SAME
    // public R0/R1 collapse to the same period-13 state modulo the S8 product,
    // but lie on opposite sides of the native Q cell wall. This concerns the
    // projected state, not all information in the original trit ciphertexts.
    let a = 9_699_690i128;
    let local_period = 13i128;
    let joint_period = local_period * a;
    let source_step = q_work as i128 / joint_period * joint_period;
    let public_weight = source_step / 2;
    let local = |source: i128| {
        let k = (source + local_period / 2).div_euclid(local_period);
        (
            source - local_period * k,
            k.rem_euclid(a),
            source.rem_euclid(a),
        )
    };
    assert!(public_weight <= q_work as i128 / 2);
    assert_eq!(local(0), local(source_step));
    let native_k = |source: i128| (source + q_work as i128 / 2).div_euclid(q_work as i128);
    assert_eq!((native_k(0), native_k(source_step)), (0, 1));
    let native_phase = source_step - q_work as i128;
    assert!(native_phase.abs() < joint_period);
    eprintln!("native state preflight: period {q_work} exceeds 4096 channels; no native initializer admitted");
    eprintln!("small-chart alias: identical period-13/S8 state, native sheets 0 and 1; two public weights={public_weight}, hidden trits (0,0) versus (1,1), centered native phases 0 versus {native_phase}");
}
