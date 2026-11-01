//! Encrypted displaced carry `K_j` for a DENSE ternary source (research, test-only).
//!
//! Phase 1 of a public refresh returns `a0 + a1*s + K_j (mod t)` for source
//! coefficient `j`, where `K_j = round((R0 + sum_i s_i*w_i)/Q)` is the carry the
//! component switch displaces (`docs/OPEN_WORK_2026-08-26.md`, issue #95; the
//! diagnostic `diag_refresh_error_is_exactly_the_displaced_phase1_carry` measures
//! this `K_0` as the whole refresh error). The phase clock in the parent module
//! computes `K` under encryption but only certifies SPARSE sources, because its
//! window charges every possible term the worst quantization error.
//!
//! This module adds three things, all integer-only (no floats anywhere):
//!
//! 1. A per-ciphertext PUBLIC window certificate. The quantization residuals of
//!    the public weights are known exactly, so the window is `sum |r_i|` instead
//!    of `(H+1)*coordinate/2`. The evaluator refuses (typed `Refusal::Window`)
//!    when its own certificate fails; it never guesses.
//! 2. A DENSE live source (every source secret coefficient has a selector key).
//! 3. A Safe-Basis lane read of `K` on the number line: on the bounded carry
//!    window, `K = d + sum_p h_p(K mod p)` for per-lane lookup tables `h_p`
//!    (a linear solve mod `t`). One clock per Safe-Basis lane, each in a ring
//!    sized by its own small coordinate `p`; the lane outputs are summed. No
//!    Garner, no mixed radix, no recombination step. The window this can read
//!    is exactly `sum(p-1)+1`: 35 values for {2,3,5,7,11,13}, 69 with 17 and 19.
//!    This construction is Claude's, not a CRAM axiom.
//!
//! Scope: each `K_j` is produced as an encrypted CONSTANT in the outer ring.
//! Repacking slots into one refreshed ciphertext, the return key switch, and
//! the production gate are NOT done here.

use super::*;

fn ceil_div(a: U256, b: U256) -> U256 {
    let (q, r) = a.div_mod_u256(b);
    if r.is_zero() {
        q
    } else {
        q.add(U256::from_u64(1))
    }
}

const T_PRIMES_S6: [u64; 6] = [2, 3, 5, 7, 11, 13];
const T_PRIMES_S8: [u64; 8] = [2, 3, 5, 7, 11, 13, 17, 19];

/// Tiny deterministic integer PRNG for test fixtures (xorshift64*).
struct Xs(u64);
impl Xs {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
}

fn centered(value: i128, t: u64) -> i64 {
    let t = t as i128;
    let r = value.rem_euclid(t);
    (if r > t / 2 { r - t } else { r }) as i64
}

fn pow_mod(mut base: u64, mut exp: u64, m: u64) -> u64 {
    let mut acc = 1u64;
    base %= m;
    while exp > 0 {
        if exp & 1 == 1 {
            acc = (acc as u128 * base as u128 % m as u128) as u64;
        }
        base = (base as u128 * base as u128 % m as u128) as u64;
        exp >>= 1;
    }
    acc
}

// ---------------------------------------------------------------------------
// Lane-sum read: K = d + sum_p h_p(K mod p) on |K| <= kmax, solved mod t.
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
struct LaneSolution {
    primes: Vec<u64>,
    /// `outputs[lane][residue]`, centered mod t. Lane p=2 is `[c, -c]` (the only
    /// shape an antiperiodic negacyclic table can hold); odd lanes are arbitrary.
    outputs: Vec<Vec<i64>>,
    constant: i64,
    kmax: i64,
}

fn column(primes: &[u64], lane: usize, residue: usize) -> usize {
    // column 0 = constant; lane p=2 owns one column (the sign); odd p own p.
    let mut c = 1;
    for (i, &p) in primes.iter().enumerate() {
        if i == lane {
            return if p == 2 { c } else { c + residue };
        }
        c += if p == 2 { 1 } else { p as usize };
    }
    unreachable!()
}

fn lane_solution(primes: &[u64], kmax: i64, t: u64) -> Option<LaneSolution> {
    assert!(primes.contains(&2), "the Safe Basis must stay unbroken");
    let cols: usize = 1 + primes
        .iter()
        .map(|&p| if p == 2 { 1 } else { p as usize })
        .sum::<usize>();
    let rows = (2 * kmax + 1) as usize;
    let mut a = vec![vec![0u64; cols + 1]; rows];
    for (r, k) in (-kmax..=kmax).enumerate() {
        a[r][0] = 1;
        for (lane, &p) in primes.iter().enumerate() {
            if p == 2 {
                a[r][column(primes, lane, 0)] = if k.rem_euclid(2) == 0 { 1 } else { t - 1 };
            } else {
                a[r][column(primes, lane, k.rem_euclid(p as i64) as usize)] = 1;
            }
        }
        a[r][cols] = k.rem_euclid(t as i64) as u64;
    }
    // Gauss-Jordan over GF(t); free variables stay 0.
    let mut pivots = Vec::new();
    let mut row = 0;
    for c in 0..cols {
        let Some(p) = (row..rows).find(|&i| a[i][c] != 0) else {
            continue;
        };
        a.swap(row, p);
        let inv = pow_mod(a[row][c], t - 2, t);
        for x in a[row].iter_mut() {
            *x = (*x as u128 * inv as u128 % t as u128) as u64;
        }
        for i in 0..rows {
            if i != row && a[i][c] != 0 {
                let f = a[i][c];
                for k in 0..=cols {
                    let sub = (f as u128 * a[row][k] as u128 % t as u128) as u64;
                    a[i][k] = (a[i][k] + t - sub) % t;
                }
            }
        }
        pivots.push(c);
        row += 1;
        if row == rows {
            break;
        }
    }
    if (row..rows).any(|i| a[i][cols] != 0) {
        return None;
    }
    let mut x = vec![0u64; cols];
    for (i, &c) in pivots.iter().enumerate() {
        x[c] = a[i][cols];
    }
    let mut outputs = Vec::new();
    for (lane, &p) in primes.iter().enumerate() {
        if p == 2 {
            let c = centered(x[column(primes, lane, 0)] as i128, t);
            outputs.push(vec![c, -c]);
        } else {
            outputs.push(
                (0..p as usize)
                    .map(|r| centered(x[column(primes, lane, r)] as i128, t))
                    .collect(),
            );
        }
    }
    let solution = LaneSolution {
        primes: primes.to_vec(),
        outputs,
        constant: centered(x[0] as i128, t),
        kmax,
    };
    // Independent re-check of the identity on the whole window.
    for k in -kmax..=kmax {
        assert_eq!(solution.read(k, t), k.rem_euclid(t as i64) as u64);
    }
    Some(solution)
}

impl LaneSolution {
    /// Plain-integer evaluation of the identity (the oracle for the encrypted sum).
    fn read(&self, k: i64, t: u64) -> u64 {
        let mut sum = self.constant as i128;
        for (lane, &p) in self.primes.iter().enumerate() {
            sum += self.outputs[lane][k.rem_euclid(p as i64) as usize] as i128;
        }
        sum.rem_euclid(t as i128) as u64
    }
}

// ---------------------------------------------------------------------------
// Exact public window certificate.
// ---------------------------------------------------------------------------

/// `|w*size - round(w*size/(q*c)) * q*c|`, i.e. `q*c*|e|` for the rotation
/// error `e` (cells) of one quantized public weight. Integer-only.
fn quantization_residual(q: i128, coordinate: usize, size: usize, w: i128) -> U256 {
    let den = U256::from_u128(q as u128).mul_u64(coordinate as u64);
    let num = U256::from_u128(w.unsigned_abs()).mul_u64(size as u64);
    let rounded = num.add(den.shr1()).div_mod_u256(den).0;
    assert_eq!(rounded.hi, 0);
    let product = den.mul_u64(rounded.lo as u64);
    if num.ge(product) {
        num.sub(product)
    } else {
        product.sub(num)
    }
}

/// Window half-width (doubled, in clock distance units) that is SUFFICIENT for
/// this exact public input. `phase` covers the source decode error `v`; `extra`
/// is `ceil(2*sum|r_i|/Q)` over `r0` and every public weight, i.e. what the
/// parent module bounds by `coordinate*(H+1)`. Refuses when it does not fit.
fn certified_twice_window(
    n: usize,
    coordinate: usize,
    q: i128,
    v: u128,
    r0: i128,
    weights: &[i128],
) -> Result<u64, Refusal> {
    if !n.is_power_of_two()
        || n < 2
        || coordinate < 2
        || (coordinate != 2 && coordinate % 2 == 0)
        || coordinate > 1023
        || q < 3
        || q % 2 == 0
        || v > q as u128 / 2
    {
        return Err(Refusal::Domain);
    }
    let size = 2 * n;
    let q_u = U256::from_u128(q as u128);
    let phase = ceil_div(U256::from_u128(v).mul_u64((2 * size) as u64), q_u);
    let mut slack = quantization_residual(q, coordinate, size, r0);
    for &w in weights {
        slack = slack.add(quantization_residual(q, coordinate, size, w));
    }
    let extra = ceil_div(slack.mul_u64(2), q_u);
    let total = phase.add(extra);
    if total.hi != 0 || total.lo >= n as u128 {
        return Err(Refusal::Window);
    }
    Ok(total.lo as u64)
}

/// Worst-case doubled window for ANY public weights: no per-input knowledge.
fn worst_twice_window(n: usize, coordinate: usize, q: i128, v: u128, terms: usize) -> Option<u64> {
    let size = 2 * n;
    let phase = ceil_div(
        U256::from_u128(v).mul_u64((2 * size) as u64),
        U256::from_u128(q as u128),
    );
    if phase.hi != 0 {
        return None;
    }
    let total = phase.lo + (coordinate as u128) * (terms as u128 + 1);
    (total < n as u128).then_some(total as u64)
}

/// Smallest power-of-two outer ring whose worst-case window fits.
fn min_ring_worst(coordinate: usize, q: i128, v: u128, terms: usize) -> usize {
    let mut n = 2usize;
    loop {
        if worst_twice_window(n, coordinate, q, v, terms).is_some() {
            return n;
        }
        n *= 2;
        assert!(n < (1 << 40));
    }
}

// ---------------------------------------------------------------------------
// A lookup clock with arbitrary per-residue outputs (centered mod t).
// ---------------------------------------------------------------------------

struct LaneClock {
    n: usize,
    coordinate: usize,
    lut: Vec<i64>, // full 2N anti-periodic function
}

impl LaneClock {
    fn new(
        n: usize,
        coordinate: usize,
        twice_window: u64,
        outputs: &[i64],
    ) -> Result<Self, Refusal> {
        if !n.is_power_of_two()
            || coordinate < 2
            || (coordinate != 2 && coordinate % 2 == 0)
            || outputs.len() != coordinate
            || twice_window >= n as u64
        {
            return Err(Refusal::Domain);
        }
        let size = 2 * n;
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
        for (k, &output) in outputs.iter().enumerate() {
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
            coordinate,
            lut: values.into_iter().map(|v| v.unwrap_or(0)).collect(),
        })
    }

    fn lookup(&self, rotation: i64) -> i64 {
        self.lut[rotation.rem_euclid((2 * self.n) as i64) as usize]
    }

    /// Public accumulator with the trace preconditioner folded in, values
    /// reduced centered mod t (the parent's version asserts small integers).
    fn accumulator(&self, ctx: &RNSFHEContext) -> (RNSCiphertext, u128) {
        assert_eq!(ctx.n, self.n);
        let t = ctx.t;
        let inverse_n = mod_inverse(ctx.n as u64, t);
        let pre = inverse_n as i128;
        let mut message = vec![0i64; ctx.n];
        message[0] = centered(pre * self.lut[0] as i128, t);
        for r in 1..ctx.n {
            message[ctx.n - r] = centered(-pre * self.lut[r] as i128, t);
        }
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
        (ct, q.mod_u64(t) as u128 * max_message as u128)
    }
}

/// One encrypted blind rotation: `LUT(sum_i s_i*w_i + r0)` read at the constant
/// coefficient. Same selector-key CMUX chain and trace as the parent clock.
#[allow(clippy::too_many_arguments)]
fn run_clock(
    ctx: &RNSFHEContext,
    exact: &ExactMulEvaluator<'_>,
    clock: &LaneClock,
    q: i128,
    r0: i128,
    weights: &[i128],
    keys: &[TritKey],
    trace: &[RNSGaloisKey],
) -> (RNSCiphertext, u128) {
    assert_eq!(weights.len(), keys.len());
    let (accumulator, initial_v) = clock.accumulator(ctx);
    let initial_rotation = quantize(r0, q, clock.coordinate, 2 * ctx.n).unwrap();
    let mut acc = shift(
        ctx,
        &accumulator,
        initial_rotation.rem_euclid((2 * ctx.n) as i64) as usize,
    );
    for (&weight, key) in weights.iter().zip(keys) {
        let rotation = quantize(weight, q, clock.coordinate, 2 * ctx.n).unwrap();
        acc = cmux_rotate(exact, ctx, &acc, rotation, &key.plus);
        acc = cmux_rotate(exact, ctx, &acc, -rotation, &key.minus);
    }
    let galois = RNSGaloisEvaluator::new(ctx).unwrap();
    for key in trace {
        acc = ctx.add(&acc, &galois.apply(&acc, key).unwrap());
    }
    let c = exact.plan().certificate();
    let switch_e = ctx.n as u128
        * ctx.config.eta as u128
        * ((1u128 << c.base_bits) - 1)
        * c.digits_per_lane.iter().sum::<usize>() as u128;
    let clock_v = initial_v + ctx.t as u128 * 2 * switch_e * (2 * weights.len()) as u128;
    let v = ctx.n as u128 * clock_v + ctx.t as u128 * (ctx.n - 1) as u128 * switch_e;
    (acc, v)
}

// ---------------------------------------------------------------------------
// Encrypted K for one source slot: direct composite clock, or Safe-Basis lanes.
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug)]
enum Mode<'a> {
    /// One clock, coordinate `m` (odd, `m >= 2*kmax+1`), emits the signed carry.
    Direct { coordinate: usize },
    /// One clock per Safe-Basis prime; outputs summed with the solved constant.
    Lanes(&'a LaneSolution),
}

struct Evaluated {
    ct: RNSCiphertext,
    bound: u128,
    /// largest certified doubled window over the clocks used
    window: u64,
    clocks: usize,
}

#[allow(clippy::too_many_arguments)]
fn encrypted_k(
    ctx: &RNSFHEContext,
    exact: &ExactMulEvaluator<'_>,
    mode: Mode<'_>,
    kmax: i64,
    q: i128,
    v: u128,
    r0: i128,
    weights: &[i128],
    keys: &[TritKey],
    trace: &[RNSGaloisKey],
) -> Result<Evaluated, Refusal> {
    match mode {
        Mode::Direct { coordinate } => {
            if (coordinate as i64) < 2 * kmax + 1 {
                return Err(Refusal::Domain);
            }
            let window = certified_twice_window(ctx.n, coordinate, q, v, r0, weights)?;
            let outputs: Vec<i64> = (0..coordinate as i64)
                .map(|k| if k > coordinate as i64 / 2 { k - coordinate as i64 } else { k })
                .collect();
            let clock = LaneClock::new(ctx.n, coordinate, window, &outputs)?;
            let (ct, bound) = run_clock(ctx, exact, &clock, q, r0, weights, keys, trace);
            Ok(Evaluated { ct, bound, window, clocks: 1 })
        }
        Mode::Lanes(solution) => {
            assert_eq!(solution.kmax, kmax);
            // Certify EVERY lane before spending any encrypted work.
            let mut clocks = Vec::new();
            let mut worst = 0;
            for (lane, &p) in solution.primes.iter().enumerate() {
                let window = certified_twice_window(ctx.n, p as usize, q, v, r0, weights)?;
                worst = worst.max(window);
                clocks.push(LaneClock::new(ctx.n, p as usize, window, &solution.outputs[lane])?);
            }
            let mut total = public_constant(ctx, solution.constant);
            let mut bound = solution.constant.unsigned_abs() as u128
                * U256::product_u64s(&ctx.config.primes).mod_u64(ctx.t) as u128;
            for clock in &clocks {
                let (ct, b) = run_clock(ctx, exact, clock, q, r0, weights, keys, trace);
                total = ctx.add(&total, &ct);
                bound += b;
            }
            Ok(Evaluated { ct: total, bound, window: worst, clocks: clocks.len() })
        }
    }
}

// ---------------------------------------------------------------------------
// Dense live source.
// ---------------------------------------------------------------------------

struct DenseSource {
    n: usize,
    trits: Vec<i8>,
    messages: Vec<u64>,
    c0: Vec<(u64, i128)>,
    c1: Vec<(u64, i128)>,
    p: u64,
}

fn dense_source(n: usize, seed: u64, full_weight: bool) -> DenseSource {
    let mut source_config = SecureConfig::secure_128().into_config();
    source_config.n = n;
    source_config.security_bits = 0;
    source_config.name = "INSECURE dense live source research fixture";
    let source = RNSFHEContext::try_new(&source_config).unwrap();
    let p = source.t;
    let source_q = U256::product_u64s(&source_config.primes);
    assert_eq!(source_q, U256::from_u128(SOURCE_Q as u128));
    let mut prng = Xs(seed | 1);
    let mut rng = ShadowHarvester::with_seed(seed);

    let trits: Vec<i8> = (0..n)
        .map(|_| match (full_weight, prng.next() % 3) {
            (true, r) => {
                if r == 0 {
                    -1
                } else {
                    1
                }
            }
            (false, 0) => -1,
            (false, 1) => 0,
            (false, _) => 1,
        })
        .collect();
    let mut secret_limbs = vec![vec![0u64; n]; source_config.primes.len()];
    for (lane, &prime) in source_config.primes.iter().enumerate() {
        for (i, &trit) in trits.iter().enumerate() {
            secret_limbs[lane][i] = match trit {
                -1 => prime - 1,
                0 => 0,
                _ => 1,
            };
        }
    }
    let sk = RNSSecretKey {
        s: source.to_montgomery_form(&RNSPolynomial { limbs: secret_limbs, n }),
    };
    let a = source.to_montgomery_form(&source.sample_uniform_main_poly(&mut rng));
    let as_product = source.rns_poly_mul(&a, &sk.s);

    // Every slot carries a random message and a +-Q/(128 t) error (V = Q/128).
    let stress = SOURCE_Q / (128 * p as i128);
    let messages: Vec<u64> = (0..n).map(|_| prng.next() % p).collect();
    let errors: Vec<i128> = (0..n)
        .map(|_| if prng.next() & 1 == 0 { stress } else { -stress })
        .collect();
    let mut added_limbs = vec![vec![0u64; n]; source_config.primes.len()];
    for (lane, &prime) in source_config.primes.iter().enumerate() {
        for position in 0..n {
            let value = messages[position] as i128 * source.delta_rns[lane] as i128
                + errors[position];
            added_limbs[lane][position] = value.rem_euclid(prime as i128) as u64;
        }
    }
    let added = source.to_montgomery_form(&RNSPolynomial { limbs: added_limbs, n });
    let input = RNSCiphertext {
        c0: added.sub(&as_product, &source.rns),
        c1: a,
        num_primes: source_config.primes.len(),
    };
    let phase = standard(
        &source,
        &source.rns_poly_mul(&input.c1, &sk.s).add(&input.c0, &source.rns),
    );
    let decoder = CanonicalScaleRound::new(&source_config.primes, p).unwrap();
    for j in 0..n {
        let residues: Vec<_> = phase.limbs.iter().map(|lane| lane[j]).collect();
        assert_eq!(decoder.scale_round(&residues).unwrap(), messages[j], "slot {j}");
    }
    let split = |poly: &RNSPolynomial| -> Vec<(u64, i128)> {
        let poly = standard(&source, poly);
        (0..n)
            .map(|j| {
                let residues: Vec<_> = poly.limbs.iter().map(|lane| lane[j]).collect();
                let scaled = source.rns.to_u256_level(&residues, residues.len()).mul_u64(p);
                let (whole, remainder) = scaled.div_mod_u256(source_q);
                assert_eq!((whole.hi, remainder.hi), (0, 0));
                if remainder.gt(source_q.shr1()) {
                    (whole.lo as u64 + 1, remainder.lo as i128 - SOURCE_Q)
                } else {
                    (whole.lo as u64, remainder.lo as i128)
                }
            })
            .collect()
    };
    DenseSource {
        n,
        trits,
        messages,
        c0: split(&input.c0),
        c1: split(&input.c1),
        p,
    }
}

struct Slot {
    r0: i128,
    a0: u64,
    weights: Vec<i128>,
    affine: Vec<u64>,
    /// clear-text oracle, client side only
    k: i64,
}

fn slot(source: &DenseSource, j: usize) -> Slot {
    let n = source.n;
    let p = source.p;
    let mut weights = Vec::with_capacity(n);
    let mut affine = Vec::with_capacity(n);
    for position in 0..n {
        let (index, sign) = if position <= j {
            (j - position, 1i128)
        } else {
            (n + j - position, -1i128)
        };
        weights.push(sign * source.c1[index].1);
        affine.push((sign * source.c1[index].0 as i128).rem_euclid(p as i128) as u64);
    }
    let sum = source.c0[j].1
        + weights
            .iter()
            .zip(&source.trits)
            .map(|(&w, &t)| w * t as i128)
            .sum::<i128>();
    let k = (sum + SOURCE_Q / 2).div_euclid(SOURCE_Q);
    let v = (sum - SOURCE_Q * k).unsigned_abs();
    assert!(v <= SOURCE_Q as u128 / 16, "decode error must be <= Q/16");
    Slot {
        r0: source.c0[j].1,
        a0: source.c0[j].0,
        weights,
        affine,
        k: k as i64,
    }
}

// ---------------------------------------------------------------------------
// Encrypted outer context (shared by every clock and slot).
// ---------------------------------------------------------------------------

struct Outer {
    ctx: RNSFHEContext,
    sk: RNSSecretKey,
    keys: Vec<TritKey>,
    trace: Vec<RNSGaloisKey>,
    relin: RNSHybridGadgetKey,
}

fn outer_context(n_out: usize, trits: &[i8], seed: u64) -> Outer {
    let mut config = SecureConfig::secure_128().into_config();
    config.n = n_out;
    config.primes = BOOT.to_vec();
    config.t = 65537;
    if n_out != 8192 {
        config.security_bits = 0;
        config.name = "INSECURE dense K0 outer ring";
    }
    let ctx = RNSFHEContext::try_new(&config).unwrap();
    let exact = ctx.try_exact_evaluator().unwrap();
    let mut rng = ShadowHarvester::with_seed(seed);
    let outer = ctx.generate_keys(&mut rng);
    let relin = exact.generate_hybrid_gadget_key_with_rng(&outer.secret_key, &mut rng);
    let galois = RNSGaloisEvaluator::new(&ctx).unwrap();
    let trace: Vec<_> = (0..n_out.ilog2())
        .map(|j| {
            galois
                .generate_key_with_rng(&outer.secret_key, (n_out >> j) as u64 + 1, &mut rng)
                .unwrap()
        })
        .collect();
    // Key-holder boundary: selector keys are the only place the source secret enters.
    let keys: Vec<_> = trits
        .iter()
        .map(|&trit| TritKey {
            minus: precharge_bit(&exact, &ctx, &outer.secret_key, trit == -1, &mut rng),
            plus: precharge_bit(&exact, &ctx, &outer.secret_key, trit == 1, &mut rng),
        })
        .collect();
    Outer { ctx, sk: outer.secret_key, keys, trace, relin }
}

fn bits(v: u128) -> u32 {
    128 - v.leading_zeros()
}

/// Encrypted K plus the full coefficient refresh for slot `j`, checked against
/// the clear-text oracle. Returns (certified window, K bound bits).
fn check_slot(outer: &Outer, source: &DenseSource, j: usize, mode: Mode<'_>, kmax: i64) -> (u64, u32) {
    let ctx = &outer.ctx;
    let exact = ctx.try_exact_evaluator().unwrap();
    let s = slot(source, j);
    let evaluated = encrypted_k(
        ctx, &exact, mode, kmax, SOURCE_Q, SOURCE_Q as u128 / 16, s.r0, &s.weights,
        &outer.keys, &outer.trace,
    )
    .unwrap_or_else(|r| panic!("slot {j}: certificate refused {r:?}"));
    let q_boot = U256::product_u64s(&ctx.config.primes);
    assert!(U256::from_u128(evaluated.bound).mul_u64(2).lt(q_boot));
    let measured = observe(ctx, &evaluated.ct, &outer.sk, s.k);
    assert!(measured <= evaluated.bound, "slot {j}: K noise over bound");

    let (affine, affine_v) = affine_message(ctx, &exact, s.a0, &s.affine, &outer.keys);
    let refreshed = ctx.add(&affine, &evaluated.ct);
    let bound = affine_v + evaluated.bound;
    let message = source.messages[j] as i64;
    let out_v = observe(ctx, &refreshed, &outer.sk, message);
    assert!(out_v <= bound, "slot {j}: refreshed noise over bound");
    // The legacy affine Phase 1 alone must be wrong exactly when K != 0.
    let uncorrected = observe_value(ctx, &affine, &outer.sk);
    assert_eq!(
        uncorrected,
        (message - s.k).rem_euclid(ctx.t as i64) as u64,
        "slot {j}: affine part must decode to m-K"
    );
    let square = exact.try_mul_exact(&refreshed, &refreshed, &outer.relin).unwrap();
    observe(
        ctx,
        &square,
        &outer.sk,
        (message * message).rem_euclid(ctx.t as i64),
    );
    let _ = out_v;
    (evaluated.window, bits(bound))
}

/// Decode the constant coefficient of a ciphertext whose slots 1.. are zero,
/// without asserting the value (client-side oracle for the uncorrected affine).
fn observe_value(ctx: &RNSFHEContext, ct: &RNSCiphertext, sk: &RNSSecretKey) -> u64 {
    let phase = ctx.rns_poly_mul(&ct.c1, &sk.s).add(&ct.c0, &ctx.rns);
    let phase = standard(ctx, &phase);
    let decoder = CanonicalScaleRound::new(&ctx.config.primes, ctx.t).unwrap();
    let residues: Vec<_> = phase.limbs.iter().map(|lane| lane[0]).collect();
    decoder.scale_round(&residues).unwrap()
}

// ===========================================================================
// Tests
// ===========================================================================

#[test]
fn k0_lane_sum_identity_is_exact_up_to_the_capacity_bound() {
    let t = 65537;
    // Capacity of a lane set is sum(p-1)+1 values; the solve must hit it exactly.
    for (primes, capacity) in [(&T_PRIMES_S6[..], 35i64), (&T_PRIMES_S8[..], 69i64)] {
        assert_eq!(
            primes.iter().map(|&p| p as i64 - 1).sum::<i64>() + 1,
            capacity + 1
        );
        let mut solved = 0;
        for half in 1..=(capacity - 1) / 2 {
            let solution = lane_solution(primes, half, t)
                .unwrap_or_else(|| panic!("{primes:?}: no solution at kmax={half}"));
            for k in -half..=half {
                assert_eq!(solution.read(k, t), k.rem_euclid(t as i64) as u64);
            }
            solved += 1;
        }
        // One past capacity has no solution at all: rank is exhausted.
        assert!(lane_solution(primes, (capacity + 1) / 2, t).is_none());
        eprintln!(
            "lane-sum identity: lanes={primes:?}, every kmax in 1..={} solved and re-verified \
             on all {} carries; kmax={} refused (capacity {capacity})",
            (capacity - 1) / 2,
            capacity,
            (capacity + 1) / 2
        );
        assert_eq!(solved, (capacity - 1) / 2);
    }
}

#[test]
fn k0_window_certificate_and_dense_scaling_table() {
    let q = SOURCE_Q;
    let v = SOURCE_Q as u128 / 16;
    eprintln!("dense worst-case outer ring needed (V<=Q/16, H=N terms), power of two:");
    eprintln!("{:>6} {:>8} {:>14} {:>9} {:>14}", "N_src", "kmax", "direct(m)", "lanes", "lane ring");
    for ns in [16usize, 32, 34, 64, 68, 128, 8192] {
        let kmax = ns / 2;
        let direct = ns + 1; // odd, >= 2*kmax+1
        let direct_ring = if direct > 1023 {
            "m>1023 refused".to_string()
        } else {
            min_ring_worst(direct, q, v, ns).to_string()
        };
        let lanes: &[u64] = if 2 * kmax as i64 + 1 <= 35 {
            &T_PRIMES_S6
        } else if 2 * kmax as i64 + 1 <= 69 {
            &T_PRIMES_S8
        } else {
            &[]
        };
        let (lane_name, lane_ring) = if lanes.is_empty() {
            ("beyond S8".to_string(), "-".to_string())
        } else {
            let pmax = *lanes.last().unwrap() as usize;
            (
                format!("S{}", lanes.len()),
                min_ring_worst(pmax, q, v, ns).to_string(),
            )
        };
        eprintln!("{ns:>6} {kmax:>8} {:>6}->{direct_ring:>7} {lane_name:>9} {lane_ring:>14}", direct);
    }
    // Pinned numbers (worst case, no per-input knowledge):
    assert_eq!(min_ring_worst(33, q, v, 32), 2048); // direct, N=32
    assert_eq!(min_ring_worst(13, q, v, 32), 1024); // S6 lanes, N=32
    assert_eq!(min_ring_worst(65, q, v, 64), 8192); // direct, N=64
    assert_eq!(min_ring_worst(19, q, v, 64), 2048); // S8 lanes, N=64

    // The per-input certificate is tighter than the worst case and refuses honestly.
    let source = dense_source(16, 0xD15E_0001, false);
    let s = slot(&source, 0);
    let w_worst = worst_twice_window(512, 17, q, v, 16).unwrap();
    let w_cert = certified_twice_window(512, 17, q, v, s.r0, &s.weights).unwrap();
    eprintln!("N=16 direct m=17 @ring512: worst-case window2={w_worst}, certified window2={w_cert}");
    assert!(w_cert < w_worst);
    assert_eq!(
        certified_twice_window(32, 17, q, SOURCE_Q as u128 / 128, s.r0, &s.weights),
        Err(Refusal::Window)
    );
}

#[test]
fn k0_lane_plateaus_exhaustive() {
    let t = 65537;
    let q = SOURCE_Q;
    let v = SOURCE_Q as u128 / 16;
    for (primes, ns, n_out) in [(&T_PRIMES_S6[..], 32usize, 1024usize), (&T_PRIMES_S8[..], 64, 2048)] {
        let kmax = (ns / 2) as i64;
        let solution = lane_solution(primes, kmax, t).unwrap();
        let mut checked = 0u64;
        for (lane, &p) in primes.iter().enumerate() {
            let window = worst_twice_window(n_out, p as usize, q, v, ns).unwrap();
            let clock = LaneClock::new(n_out, p as usize, window, &solution.outputs[lane]).unwrap();
            let size = (2 * n_out) as i64;
            let period = p as i64 * size;
            for k in -kmax..=kmax {
                for rotation in 0..size {
                    let d = (p as i64 * rotation - size * k).rem_euclid(period);
                    if 2 * d.min(period - d) <= window as i64 {
                        assert_eq!(
                            clock.lookup(rotation),
                            solution.outputs[lane][k.rem_euclid(p as i64) as usize]
                        );
                        checked += 1;
                    }
                }
            }
        }
        eprintln!("lane plateaus: lanes={primes:?} N={ns} ring={n_out}: {checked} exact plateau checks over all {} carries", 2 * kmax + 1);
    }
}

#[test]
fn k0_dense_source_all_slots_direct_and_safe_basis_lanes_n16() {
    let ns = 16;
    let kmax = (ns / 2) as i64;
    let source = dense_source(ns, 0xD15E_0016, false);
    let nonzero = source.trits.iter().filter(|&&x| x != 0).count();
    let n_out = 512;
    let outer = outer_context(n_out, &source.trits, 0x4B30_0016);
    let solution = lane_solution(&T_PRIMES_S6, kmax, 65537).unwrap();
    let (mut ks, mut windows) = (Vec::new(), Vec::new());
    for j in 0..ns {
        let k = slot(&source, j).k;
        ks.push(k);
        let (w_direct, _) = check_slot(&outer, &source, j, Mode::Direct { coordinate: ns + 1 }, kmax);
        let (w_lanes, b) = check_slot(&outer, &source, j, Mode::Lanes(&solution), kmax);
        windows.push((w_direct, w_lanes));
        if j < 3 {
            eprintln!("slot {j}: K={k}, direct window2={w_direct}, S6 lanes window2={w_lanes}, refreshed bound {b} bits");
        }
    }
    eprintln!(
        "dense N={ns} (weight {nonzero}/{ns}), outer ring {n_out}: all {ns} slots exact, direct m={} and S6 lanes, carries {:?}, every slot's refresh + dependent square exact",
        ns + 1, ks
    );
}

/// Carries pushed to both extremes: every secret term aligned so `|K| = N/2`.
fn extreme_carry(ns: usize, n_out: usize, lanes: &[u64], with_direct: bool, seed: u64) {
    let t = 65537u64;
    let kmax = (ns / 2) as i64;
    let mut prng = Xs(seed | 1);
    let trits: Vec<i8> = (0..ns).map(|_| if prng.next() & 1 == 0 { -1 } else { 1 }).collect();
    let outer = outer_context(n_out, &trits, seed);
    let exact = outer.ctx.try_exact_evaluator().unwrap();
    let solution = lane_solution(lanes, kmax, t).unwrap();
    let direct = ns + 1;
    // Pick the near-Q/2 weight magnitude whose quantization residual is smallest
    // for every coordinate that will be used (public search over delta).
    let coords: Vec<usize> = lanes
        .iter()
        .map(|&p| p as usize)
        .chain(with_direct.then_some(direct))
        .collect();
    let h_max = SOURCE_Q / 2;
    let mut best = (U256::from_u128(u128::MAX), 0i128);
    for delta in 0..8192i128 {
        let h = h_max - delta;
        let mut cost = U256::zero();
        for &m in &coords {
            cost = cost.add(quantization_residual(SOURCE_Q, m, 2 * n_out, h));
        }
        if cost.lt(best.0) {
            best = (cost, delta);
        }
    }
    let h = h_max - best.1;
    let r0 = SOURCE_Q / 128;
    let (c0, a0) = component_with_residual(r0, SOURCE_Q, t);
    for sign in [1i128, -1] {
        // s_i * w_i = sign * h for every i, so S = r0 + sign*N*h and |K| = N/2.
        let weights: Vec<i128> = trits.iter().map(|&s| sign * s as i128 * h).collect();
        let mut comps = Vec::new();
        let mut affine = Vec::new();
        for &w in &weights {
            let (c, a) = component_with_residual(h, SOURCE_Q, t);
            if w >= 0 {
                comps.push(c as i128);
                affine.push(a);
            } else {
                comps.push(SOURCE_Q - c as i128);
                affine.push(t - a);
            }
        }
        let sum = r0 + weights.iter().zip(&trits).map(|(&w, &s)| w * s as i128).sum::<i128>();
        let k = (sum + SOURCE_Q / 2).div_euclid(SOURCE_Q);
        assert_eq!(k.unsigned_abs() as usize, ns / 2, "extreme carry reached");
        let v = (sum - SOURCE_Q * k).unsigned_abs();
        assert!(v <= SOURCE_Q as u128 / 16);
        // Independent source decode from canonical components.
        let phase = (c0 as i128
            + comps.iter().zip(&trits).map(|(&c, &s)| c * s as i128).sum::<i128>())
        .rem_euclid(SOURCE_Q) as u128;
        let q_source = U256::from_u128(SOURCE_Q as u128);
        let message = U256::from_u128(phase)
            .mul_u64(t)
            .add(q_source.shr1())
            .div_mod_u256(q_source)
            .0
            .mod_u64(t) as i64;
        let mut modes = vec![Mode::Lanes(&solution)];
        if with_direct {
            modes.push(Mode::Direct { coordinate: direct });
        }
        for mode in modes {
            let evaluated = encrypted_k(
                &outer.ctx, &exact, mode, kmax, SOURCE_Q, SOURCE_Q as u128 / 16, r0,
                &weights, &outer.keys, &outer.trace,
            )
            .unwrap_or_else(|r| panic!("extreme sign={sign} {mode:?}: refused {r:?}"));
            let measured = observe(&outer.ctx, &evaluated.ct, &outer.sk, k as i64);
            assert!(measured <= evaluated.bound);
            let (affine_ct, affine_v) = affine_message(&outer.ctx, &exact, a0, &affine, &outer.keys);
            let refreshed = outer.ctx.add(&affine_ct, &evaluated.ct);
            let out = observe(&outer.ctx, &refreshed, &outer.sk, message);
            assert!(out <= affine_v + evaluated.bound);
            let square = exact.try_mul_exact(&refreshed, &refreshed, &outer.relin).unwrap();
            observe(&outer.ctx, &square, &outer.sk, (message * message).rem_euclid(t as i64));
            eprintln!(
                "extreme carry N={ns} ring={n_out} sign={sign:+}: K={k} (kmax {kmax}), {} clock(s), window2={}, exact + refreshed message {message} + dependent square exact",
                evaluated.clocks, evaluated.window
            );
        }
    }
}

#[test]
fn k0_extreme_carries_both_signs_n16() {
    extreme_carry(16, 512, &T_PRIMES_S6, true, 0x4558_5431_36);
}

#[test]
fn k0_refuses_when_its_own_certificate_fails() {
    // Ring far too small for a dense N=32 source: typed refusal, no encrypted work.
    let source = dense_source(32, 0xD15E_0032, false);
    let s = slot(&source, 0);
    for ring in [64usize, 128, 256] {
        assert_eq!(
            certified_twice_window(ring, 33, SOURCE_Q, SOURCE_Q as u128 / 16, s.r0, &s.weights),
            Err(Refusal::Window),
            "direct m=33 at ring {ring}"
        );
    }
    // Same source, same error bound V, both readers: smallest certified ring.
    // Measured, not assumed: at N=32 the two coincide; the lane reader's gain
    // is confined to the worst-case (input-blind) table above.
    for (label, v) in [("V=Q/128 (live stress)", SOURCE_Q as u128 / 128), ("V=Q/16 (admission)", SOURCE_Q as u128 / 16)] {
        let direct = (1..=14).map(|e| 1usize << e).find(|&n| {
            certified_twice_window(n, 33, SOURCE_Q, v, s.r0, &s.weights).is_ok()
        });
        let lanes = (1..=14).map(|e| 1usize << e).find(|&n| {
            T_PRIMES_S6.iter().all(|&p| {
                certified_twice_window(n, p as usize, SOURCE_Q, v, s.r0, &s.weights).is_ok()
            })
        });
        let worst_direct = (1..=14).map(|e| 1usize << e).find(|&n| worst_twice_window(n, 33, SOURCE_Q, v, 32).is_some());
        eprintln!("dense N=32 slot 0, {label}: smallest ring certified per-input: direct m=33 -> {direct:?}, S6 lanes -> {lanes:?}; input-blind worst case direct -> {worst_direct:?}");
        assert!(lanes.unwrap() <= direct.unwrap());
        assert!(direct.unwrap() <= worst_direct.unwrap());
    }
}

#[test]
#[ignore = "opt-in: dense N=32, outer ring 1024, 32 slots, direct m=33 and S6 lanes"]
fn k0_dense_source_all_slots_n32() {
    let ns = 32;
    let kmax = (ns / 2) as i64;
    let source = dense_source(ns, 0xD15E_0032, false);
    let outer = outer_context(1024, &source.trits, 0x4B30_0032);
    let solution = lane_solution(&T_PRIMES_S6, kmax, 65537).unwrap();
    let mut ks = Vec::new();
    for j in 0..ns {
        ks.push(slot(&source, j).k);
        check_slot(&outer, &source, j, Mode::Direct { coordinate: ns + 1 }, kmax);
        check_slot(&outer, &source, j, Mode::Lanes(&solution), kmax);
    }
    eprintln!("dense N=32 ring 1024: all 32 slots exact, direct m=33 and S6 lanes, carries {ks:?}");
}

#[test]
#[ignore = "opt-in: dense N=64, S8 lanes only (direct m=65 needs ring 8192), outer ring 1024"]
fn k0_dense_source_n64_s8_lanes() {
    let ns = 64;
    let kmax = (ns / 2) as i64;
    let source = dense_source(ns, 0xD15E_0064, false);
    let outer = outer_context(2048, &source.trits, 0x4B30_0064);
    let solution = lane_solution(&T_PRIMES_S8, kmax, 65537).unwrap();
    for j in [0usize, 63] {
        let (w, b) = check_slot(&outer, &source, j, Mode::Lanes(&solution), kmax);
        eprintln!("dense N=64 S8 lanes slot {j}: K={}, window2={w}, refreshed bound {b} bits", slot(&source, j).k);
    }
}

#[test]
#[ignore = "opt-in: extreme carries at N=32 (ring 1024) and N=64 S8 lanes (ring 2048)"]
fn k0_extreme_carries_larger() {
    extreme_carry(32, 1024, &T_PRIMES_S6, true, 0x4558_5431_3332);
    extreme_carry(64, 2048, &T_PRIMES_S8, false, 0x4558_5431_3634);
}
