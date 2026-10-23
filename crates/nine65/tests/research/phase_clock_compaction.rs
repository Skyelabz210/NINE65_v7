//! Compact source-selector precharge. Research-only integration prototype.
//! Packed raw columns are coefficient-extracted publicly; a shared native
//! raw multiplier supplies the second column. Derived errors are NOT eta.

use super::*;
use nine65::arithmetic::rns::U512;
use std::cell::Cell;

#[path = "public_bootstrap_pipeline.rs"]
mod public_bootstrap_pipeline;

#[path = "small_digit_convolution.rs"]
mod small_digit_convolution;

const Q_SOURCE: i128 = 348_959_453_350_711_275_087_786_864_768_188_417;
const BOOT: [u64; 5] = [1811939329, 2113929217, 2130706433, 1107296257, 1711276033];

fn words(x: U512) -> (u128, u128, u128, u128) {
    (x.d3, x.d2, x.d1, x.d0)
}
fn abs_diff(a: U512, b: U512) -> U512 {
    if words(a) >= words(b) {
        a.sub(b)
    } else {
        b.sub(a)
    }
}
fn bits(x: u128) -> u32 {
    128 - x.leading_zeros()
}

fn ordinary(ctx: &RNSFHEContext, p: &RNSPolynomial) -> Vec<Vec<u64>> {
    p.limbs
        .iter()
        .enumerate()
        .map(|(lane, values)| {
            values
                .iter()
                .map(|&v| ctx.rns.mont_contexts[lane].from_montgomery(v))
                .collect()
        })
        .collect()
}

// The engine's public ntt/intt are CYCLIC transforms. multiply() applies
// the negacyclic psi twist internally; cached pointwise products must do so
// explicitly, in both the FFT and reference engines.
fn forward(ctx: &RNSFHEContext, lane: usize, values: &[u64]) -> Vec<u64> {
    let engine = &ctx.ntt_engines[lane];
    let q = ctx.config.primes[lane];
    assert!(
        q <= 1u64 << 31,
        "cached research kernel is limited to 31-bit main primes"
    );
    let twisted: Vec<_> = values
        .iter()
        .zip(&engine.psi_powers)
        .map(|(&v, &psi)| v * psi % q)
        .collect();
    engine.ntt(&twisted)
}

fn backward(ctx: &RNSFHEContext, lane: usize, values: &[u64]) -> Vec<u64> {
    let engine = &ctx.ntt_engines[lane];
    let q = ctx.config.primes[lane];
    assert!(q <= 1u64 << 31);
    engine
        .intt(values)
        .iter()
        .zip(&engine.psi_inv_powers)
        .map(|(&v, &psi)| v * psi % q)
        .collect()
}

fn montgomery(ctx: &RNSFHEContext, p: Vec<Vec<u64>>) -> RNSPolynomial {
    RNSPolynomial {
        n: ctx.n,
        limbs: p
            .into_iter()
            .enumerate()
            .map(|(lane, values)| {
                values
                    .into_iter()
                    .map(|v| ctx.rns.mont_contexts[lane].to_montgomery(v))
                    .collect()
            })
            .collect(),
    }
}

fn zero(ctx: &RNSFHEContext) -> RNSCiphertext {
    RNSCiphertext {
        c0: RNSPolynomial::zero(&ctx.rns),
        c1: RNSPolynomial::zero(&ctx.rns),
        num_primes: ctx.config.primes.len(),
    }
}

fn permutation(
    ctx: &RNSFHEContext,
    ct: &RNSCiphertext,
    map: impl Fn(usize) -> usize,
) -> RNSCiphertext {
    let apply = |p: &RNSPolynomial| RNSPolynomial {
        n: ctx.n,
        limbs: p
            .limbs
            .iter()
            .zip(&ctx.config.primes)
            .map(|(values, &q)| {
                let mut out = vec![0; ctx.n];
                for (j, &v) in values.iter().enumerate() {
                    let target = map(j) % (2 * ctx.n);
                    out[target % ctx.n] = if target < ctx.n || v == 0 { v } else { q - v };
                }
                out
            })
            .collect(),
    };
    RNSCiphertext {
        c0: apply(&ct.c0),
        c1: apply(&ct.c1),
        num_primes: ct.num_primes,
    }
}

fn rotate(ctx: &RNSFHEContext, ct: &RNSCiphertext, amount: i64) -> RNSCiphertext {
    let amount = amount.rem_euclid((2 * ctx.n) as i64) as usize;
    permutation(ctx, ct, |j| j + amount)
}

fn sigma(ctx: &RNSFHEContext, ct: &RNSCiphertext, exponent: usize) -> RNSCiphertext {
    assert!(exponent % 2 == 1 && exponent < 2 * ctx.n);
    permutation(ctx, ct, |j| j * exponent)
}

// Scalar CRT only in CLIENT observation. Never called by the raw evaluator.
fn client_crt(ctx: &RNSFHEContext, residues: &[u64]) -> U512 {
    let (mut x, mut product) = (U512::zero(), U512::from_u64(1));
    for (&value, &q) in residues.iter().zip(&ctx.config.primes) {
        let digit = ((value as u128 + q as u128 - x.mod_u64(q) as u128)
            * inverse(product.mod_u64(q), q) as u128
            % q as u128) as u64;
        x = x.add(product.mul_u128(digit as u128));
        product = product.mul_u128(q as u128);
    }
    x
}

#[derive(Clone)]
struct Shape {
    base_bits: u32,
    digits: Vec<usize>,
    digit_sum: u128,
}
impl Shape {
    fn new(ctx: &RNSFHEContext, base_bits: u32) -> Self {
        assert!((1..=10).contains(&base_bits));
        let digits: Vec<_> = ctx
            .config
            .primes
            .iter()
            .map(|q| (q.ilog2() as usize + 1).div_ceil(base_bits as usize))
            .collect();
        let mask = (1u64 << base_bits) - 1;
        let digit_sum = ctx
            .config
            .primes
            .iter()
            .zip(&digits)
            .map(|(&q, &d)| {
                (0..d)
                    .map(|j| mask.min((q - 1) >> (j as u32 * base_bits)) as u128)
                    .sum::<u128>()
            })
            .sum();
        Self {
            base_bits,
            digits,
            digit_sum,
        }
    }
}

// Distinct type: cached STANDARD-domain negacyclic NTT rows, not a native
// coefficient-domain ciphertext. No such rows cross a production API.
struct NttRow {
    c0: Vec<Vec<u64>>,
    c1: Vec<Vec<u64>>,
}
enum CachedRows {
    MainPrime(Vec<NttRow>),
    SmallDigit {
        plan: std::sync::Arc<small_digit_convolution::Plan>,
        rows: Vec<small_digit_convolution::AuxiliaryRow>,
        integer_bound: u128,
    },
}
impl CachedRows {
    fn len(&self) -> usize {
        match self {
            Self::MainPrime(rows) => rows.len(),
            Self::SmallDigit { rows, .. } => rows.len(),
        }
    }
}
struct RawKey {
    shape: Shape,
    rows: CachedRows,
    n: usize,
    primes: Vec<u64>,
    beta: u128,
}
impl RawKey {
    fn coefficient_row(&self, ctx: &RNSFHEContext, index: usize) -> RNSCiphertext {
        let decode = |values: &Vec<Vec<u64>>| {
            montgomery(
                ctx,
                values
                    .iter()
                    .enumerate()
                    .map(|(lane, v)| match &self.rows {
                        CachedRows::MainPrime(_) => backward(ctx, lane, v),
                        CachedRows::SmallDigit { plan, .. } => {
                            let out = plan.backward(v);
                            assert!(out.iter().all(|&x| x < self.primes[lane]));
                            out
                        }
                    })
                    .collect(),
            )
        };
        let (c0, c1) = match &self.rows {
            CachedRows::MainPrime(rows) => (&rows[index].c0, &rows[index].c1),
            CachedRows::SmallDigit { rows, .. } => (&rows[index].c0, &rows[index].c1),
        };
        RNSCiphertext {
            c0: decode(c0),
            c1: decode(c1),
            num_primes: self.primes.len(),
        }
    }
}
struct Multiplier {
    constant: RawKey,
    secret: RawKey,
}

struct Engine<'a> {
    ctx: &'a RNSFHEContext,
    switches: Cell<usize>,
}
impl<'a> Engine<'a> {
    fn cache(&self, shape: &Shape, rows: &[RNSCiphertext], beta: u128) -> RawKey {
        let Some(integer_bound) = small_digit_convolution::integer_bound(
            self.ctx.n,
            shape.digit_sum,
            &self.ctx.config.primes,
        ) else {
            return self.cache_main_prime(shape, rows, beta);
        };
        assert_eq!(rows.len(), shape.digits.iter().sum::<usize>());
        let plan = small_digit_convolution::Plan::shared(self.ctx.n);
        let encode = |p: &RNSPolynomial| {
            ordinary(self.ctx, p)
                .iter()
                .map(|v| plan.forward(v))
                .collect()
        };
        RawKey {
            shape: shape.clone(),
            rows: CachedRows::SmallDigit {
                rows: rows
                    .iter()
                    .map(|ct| small_digit_convolution::AuxiliaryRow {
                        c0: encode(&ct.c0),
                        c1: encode(&ct.c1),
                    })
                    .collect(),
                plan,
                integer_bound,
            },
            n: self.ctx.n,
            primes: self.ctx.config.primes.clone(),
            beta,
        }
    }

    fn cache_main_prime(&self, shape: &Shape, rows: &[RNSCiphertext], beta: u128) -> RawKey {
        assert_eq!(rows.len(), shape.digits.iter().sum::<usize>());
        let encode = |p: &RNSPolynomial| {
            ordinary(self.ctx, p)
                .iter()
                .enumerate()
                .map(|(lane, v)| forward(self.ctx, lane, v))
                .collect()
        };
        RawKey {
            shape: shape.clone(),
            rows: CachedRows::MainPrime(
                rows.iter()
                    .map(|ct| NttRow {
                        c0: encode(&ct.c0),
                        c1: encode(&ct.c1),
                    })
                    .collect(),
            ),
            n: self.ctx.n,
            primes: self.ctx.config.primes.clone(),
            beta,
        }
    }

    fn switch(&self, component: &RNSPolynomial, key: &RawKey) -> RNSCiphertext {
        assert_eq!(key.n, self.ctx.n);
        assert_eq!(key.primes, self.ctx.config.primes);
        self.switches.set(self.switches.get() + 1);
        if let CachedRows::SmallDigit {
            plan,
            rows,
            integer_bound,
        } = &key.rows
        {
            let plain = ordinary(self.ctx, component);
            let mut out0 = vec![vec![0; self.ctx.n]; key.primes.len()];
            let mut out1 = out0.clone();
            let mask = (1u64 << key.shape.base_bits) - 1;
            let mut row_index = 0;
            for (source_lane, &digits) in key.shape.digits.iter().enumerate() {
                for j in 0..digits {
                    let digit: Vec<_> = plain[source_lane]
                        .iter()
                        .map(|v| (v >> (j as u32 * key.shape.base_bits)) & mask)
                        .collect();
                    let transformed = plan.forward(&digit);
                    let row = &rows[row_index];
                    row_index += 1;
                    for lane in 0..key.primes.len() {
                        small_digit_convolution::accumulate(
                            &mut out0[lane],
                            &transformed,
                            &row.c0[lane],
                        );
                        small_digit_convolution::accumulate(
                            &mut out1[lane],
                            &transformed,
                            &row.c1[lane],
                        );
                    }
                }
            }
            let inverse = |values: Vec<Vec<u64>>| {
                montgomery(
                    self.ctx,
                    values
                        .iter()
                        .zip(&key.primes)
                        .map(|(lane, &q)| {
                            plan.backward(lane)
                                .iter()
                                .map(|&value| {
                                    small_digit_convolution::reduce_signed(value, q, *integer_bound)
                                })
                                .collect()
                        })
                        .collect(),
                )
            };
            return RNSCiphertext {
                c0: inverse(out0),
                c1: inverse(out1),
                num_primes: key.primes.len(),
            };
        }
        let CachedRows::MainPrime(rows) = &key.rows else {
            unreachable!()
        };
        let plain = ordinary(self.ctx, component);
        let mut out0 = vec![vec![0u64; self.ctx.n]; key.primes.len()];
        let mut out1 = out0.clone();
        let mask = (1u64 << key.shape.base_bits) - 1;
        let mut row_index = 0;
        for (source_lane, &d) in key.shape.digits.iter().enumerate() {
            for j in 0..d {
                let digit: Vec<_> = plain[source_lane]
                    .iter()
                    .map(|v| (v >> (j as u32 * key.shape.base_bits)) & mask)
                    .collect();
                let row = &rows[row_index];
                row_index += 1;
                for (lane, &q) in key.primes.iter().enumerate() {
                    assert!(q <= 1u64 << 31);
                    let transformed = forward(self.ctx, lane, &digit);
                    for k in 0..self.ctx.n {
                        // Canonical inputs and q<=2^31 give q^2-q<2^62.
                        out0[lane][k] = (out0[lane][k] + transformed[k] * row.c0[lane][k]) % q;
                        out1[lane][k] = (out1[lane][k] + transformed[k] * row.c1[lane][k]) % q;
                    }
                }
            }
        }
        let inverse = |p: Vec<Vec<u64>>| {
            montgomery(
                self.ctx,
                p.iter()
                    .enumerate()
                    .map(|(lane, v)| backward(self.ctx, lane, v))
                    .collect(),
            )
        };
        RNSCiphertext {
            c0: inverse(out0),
            c1: inverse(out1),
            num_primes: key.primes.len(),
        }
    }

    fn external(&self, ct: &RNSCiphertext, key: &Multiplier) -> RNSCiphertext {
        add(
            self.ctx,
            &self.switch(&ct.c0, &key.constant),
            &self.switch(&ct.c1, &key.secret),
        )
    }

    fn external_error(&self, key: &Multiplier) -> u128 {
        self.ctx.n as u128 * key.constant.shape.digit_sum * (key.constant.beta + key.secret.beta)
    }

    fn galois(
        &self,
        ct: &RNSCiphertext,
        exponent: usize,
        keys: &BTreeMap<usize, RawKey>,
    ) -> RNSCiphertext {
        let input = sigma(self.ctx, ct, exponent);
        let switched = self.switch(&input.c1, &keys[&exponent]);
        RNSCiphertext {
            c0: input.c0.add(&switched.c0, &self.ctx.rns),
            c1: switched.c1,
            num_primes: input.num_primes,
        }
    }

    fn trace(
        &self,
        mut ct: RNSCiphertext,
        degree: usize,
        keys: &BTreeMap<usize, RawKey>,
    ) -> RNSCiphertext {
        for j in 0..degree.ilog2() {
            let other = self.galois(&ct, (degree >> j) + 1, keys);
            ct = add(self.ctx, &ct, &other);
        }
        ct
    }

    fn cmux(&self, ct: &RNSCiphertext, rotation: i64, key: &Multiplier) -> RNSCiphertext {
        let difference = self.ctx.sub(&rotate(self.ctx, ct, rotation), ct);
        add(self.ctx, ct, &self.external(&difference, key))
    }
}

// KEY-HOLDER only. Independent per-lane uniform masks are uniform over the
// CRT product. One signed CBD error vector is shared consistently by lanes.
fn raw_rows(
    ctx: &RNSFHEContext,
    shape: &Shape,
    target: &RNSPolynomial,
    keys: &RNSKeySet,
    rng: &mut ShadowHarvester,
) -> Vec<RNSCiphertext> {
    let target = ordinary(ctx, target);
    let secret = ordinary(ctx, &keys.secret_key.s);
    let mut rows = Vec::new();
    for (source_lane, (&prime, &digits)) in ctx.config.primes.iter().zip(&shape.digits).enumerate()
    {
        let mut power = 1u64;
        for _ in 0..digits {
            let error: Vec<_> = (0..ctx.n)
                .map(|_| {
                    (0..ctx.config.eta)
                        .map(|_| (rng.next_u64() & 1) as i64 - (rng.next_u64() & 1) as i64)
                        .sum::<i64>()
                })
                .collect();
            let mut c0 = Vec::new();
            let mut c1 = Vec::new();
            for (lane, &q) in ctx.config.primes.iter().enumerate() {
                let mask = (1u64 << (q.ilog2() + 1)) - 1;
                let a: Vec<_> = (0..ctx.n)
                    .map(|_| loop {
                        let v = rng.next_u64() & mask;
                        if v < q {
                            break v;
                        }
                    })
                    .collect();
                let product = ctx.ntt_engines[lane].multiply(&a, &secret[lane]);
                let values = product
                    .iter()
                    .enumerate()
                    .map(|(k, &value)| {
                        let msg = if lane == source_lane {
                            target[lane][k] as u128 * power as u128 % q as u128
                        } else {
                            0
                        };
                        (msg as i128 - value as i128 - error[k] as i128).rem_euclid(q as i128)
                            as u64
                    })
                    .collect();
                c0.push(values);
                c1.push(a);
            }
            rows.push(RNSCiphertext {
                c0: montgomery(ctx, c0),
                c1: montgomery(ctx, c1),
                num_primes: ctx.config.primes.len(),
            });
            power = (power as u128 * (1u64 << shape.base_bits) as u128 % prime as u128) as u64;
        }
    }
    rows
}

struct Packed {
    block: usize,
    shape: Shape,
    columns: Vec<[Vec<RNSCiphertext>; 2]>,
    outer_secret: Multiplier,
    galois: BTreeMap<usize, RawKey>,
    source_len: usize,
}

fn setup(
    engine: &Engine<'_>,
    keys: &RNSKeySet,
    source: &[i8],
    block: usize,
    bits: u32,
    galois_bits: u32,
    rng: &mut ShadowHarvester,
) -> Packed {
    let ctx = engine.ctx;
    assert!(source.iter().all(|s| (-1..=1).contains(s)));
    assert!(block.is_power_of_two() && block <= source.len() && source.len() <= ctx.n);
    assert_eq!(
        source.len() % block,
        0,
        "public source length must fill packed blocks"
    );
    let shape = Shape::new(ctx, bits);
    let gal_shape = Shape::new(ctx, galois_bits);
    let mut galois = BTreeMap::new();
    for j in 0..ctx.n.ilog2() {
        let exponent = (ctx.n >> j) + 1;
        let secret_ct = RNSCiphertext {
            c0: keys.secret_key.s.clone(),
            c1: RNSPolynomial::zero(&ctx.rns),
            num_primes: ctx.config.primes.len(),
        };
        let target = sigma(ctx, &secret_ct, exponent).c0;
        let rows = raw_rows(ctx, &gal_shape, &target, keys, rng);
        galois.insert(
            exponent,
            engine.cache(&gal_shape, &rows, ctx.config.eta as u128),
        );
    }
    let secret = ordinary(ctx, &keys.secret_key.s);
    let squared = montgomery(
        ctx,
        secret
            .iter()
            .enumerate()
            .map(|(lane, s)| ctx.ntt_engines[lane].multiply(s, s))
            .collect(),
    );
    let rows0 = raw_rows(ctx, &shape, &keys.secret_key.s, keys, rng);
    let rows1 = raw_rows(ctx, &shape, &squared, keys, rng);
    let outer_secret = Multiplier {
        constant: engine.cache(&shape, &rows0, ctx.config.eta as u128),
        secret: engine.cache(&shape, &rows1, ctx.config.eta as u128),
    };
    let mut columns = Vec::new();
    for chunk in source.chunks(block) {
        let pair = core::array::from_fn(|polarity| {
            let target = montgomery(
                ctx,
                ctx.config
                    .primes
                    .iter()
                    .map(|&q| {
                        let inv_block = inverse(block as u64, q);
                        let mut p = vec![0; ctx.n];
                        for (index, &s) in chunk.iter().enumerate() {
                            if s == if polarity == 0 { -1 } else { 1 } {
                                p[index * (ctx.n / block)] = inv_block;
                            }
                        }
                        p
                    })
                    .collect(),
            );
            raw_rows(ctx, &shape, &target, keys, rng)
        });
        columns.push(pair);
    }
    Packed {
        block,
        shape,
        columns,
        outer_secret,
        galois,
        source_len: source.len(),
    }
}

fn derive(engine: &Engine<'_>, packed: &Packed, index: usize, polarity: usize) -> Multiplier {
    assert!(index < packed.source_len && polarity < 2);
    let ctx = engine.ctx;
    let column = &packed.columns[index / packed.block][polarity];
    let mut scalar = Vec::new();
    for row in column {
        let aligned = rotate(
            ctx,
            row,
            -(((index % packed.block) * (ctx.n / packed.block)) as i64),
        );
        let extracted = engine.trace(aligned, packed.block, &packed.galois);
        scalar.push(extracted);
    }
    finish_column(engine, packed, &scalar)
}

fn finish_column(engine: &Engine<'_>, packed: &Packed, scalar: &[RNSCiphertext]) -> Multiplier {
    let ctx = engine.ctx;
    let times_secret: Vec<_> = scalar
        .iter()
        .map(|row| engine.external(row, &packed.outer_secret))
        .collect();
    let gal = packed.galois.values().next().unwrap();
    let eg = ctx.n as u128 * gal.shape.digit_sum * gal.beta;
    let beta = packed.block as u128 * ctx.config.eta as u128 + (packed.block - 1) as u128 * eg;
    let beta_secret = ctx.n as u128 * beta + engine.external_error(&packed.outer_secret);
    Multiplier {
        constant: engine.cache(&packed.shape, scalar, beta),
        secret: engine.cache(&packed.shape, &times_secret, beta_secret),
    }
}

// Batch expansion shares each public Galois step between the even and odd
// children. It is O(G) switches per packed column, not G*log2(G). Traversal
// order is fixed by public indices; encrypted zero controls are not skipped.
fn visit_expanded(
    engine: &Engine<'_>,
    packed: &Packed,
    columns: [Vec<RNSCiphertext>; 2],
    degree: usize,
    stride: usize,
    index: usize,
    index_step: usize,
    consume: &mut impl FnMut(usize, usize, Multiplier),
) {
    if degree == 1 {
        for (polarity, column) in columns.iter().enumerate() {
            consume(index, polarity, finish_column(engine, packed, column));
        }
        return;
    }
    let mut even: [Vec<_>; 2] = core::array::from_fn(|_| Vec::new());
    let mut odd: [Vec<_>; 2] = core::array::from_fn(|_| Vec::new());
    for (polarity, column) in columns.into_iter().enumerate() {
        for row in column {
            let conjugate = engine.galois(&row, degree + 1, &packed.galois);
            even[polarity].push(add(engine.ctx, &row, &conjugate));
            odd[polarity].push(rotate(
                engine.ctx,
                &engine.ctx.sub(&row, &conjugate),
                -(stride as i64),
            ));
        }
    }
    visit_expanded(
        engine,
        packed,
        even,
        degree / 2,
        stride * 2,
        index,
        index_step * 2,
        consume,
    );
    visit_expanded(
        engine,
        packed,
        odd,
        degree / 2,
        stride * 2,
        index + index_step,
        index_step * 2,
        consume,
    );
}

fn visit_all(
    engine: &Engine<'_>,
    packed: &Packed,
    consume: &mut impl FnMut(usize, usize, Multiplier),
) {
    for (block, columns) in packed.columns.iter().enumerate() {
        visit_expanded(
            engine,
            packed,
            columns.clone(),
            packed.block,
            engine.ctx.n / packed.block,
            block * packed.block,
            1,
            consume,
        );
    }
}

fn public_plain(ctx: &RNSFHEContext, coefs: &[i64]) -> RNSCiphertext {
    assert_eq!(coefs.len(), ctx.n);
    assert!(coefs.iter().all(|c| c.unsigned_abs() <= ctx.t / 2));
    let mut out = zero(ctx);
    out.c0 = montgomery(
        ctx,
        ctx.config
            .primes
            .iter()
            .enumerate()
            .map(|(lane, &q)| {
                coefs
                    .iter()
                    .map(|&c| {
                        (c as i128 * ctx.delta_rns[lane] as i128).rem_euclid(q as i128) as u64
                    })
                    .collect()
            })
            .collect(),
    );
    out
}

fn scalar(ctx: &RNSFHEContext, value: u64) -> RNSCiphertext {
    let v = value % ctx.t;
    let v = if v > ctx.t / 2 {
        v as i64 - ctx.t as i64
    } else {
        v as i64
    };
    let mut coefs = vec![0; ctx.n];
    coefs[0] = v;
    public_plain(ctx, &coefs)
}

fn observe(ctx: &RNSFHEContext, ct: &RNSCiphertext, keys: &RNSKeySet, expected: u64) -> u128 {
    let phases = decrypted_phase_residues(ctx, ct, keys);
    let q = U512::product_u64s(&ctx.config.primes);
    let period = q.mul_u128(ctx.t as u128);
    let decode = CanonicalScaleRound::new(&ctx.config.primes, ctx.t).unwrap();
    let mut maximum = 0;
    for j in 0..ctx.n {
        let residues: Vec<_> = phases.iter().map(|lane| lane[j]).collect();
        let intended = if j == 0 { expected } else { 0 };
        assert_eq!(
            decode.scale_round(&residues).unwrap(),
            intended,
            "coefficient {j}"
        );
        let difference = abs_diff(
            client_crt(ctx, &residues).mul_u128(ctx.t as u128),
            q.mul_u128(intended as u128),
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

// Independent CLIENT check of EVERY raw derived gadget row. These are not
// Delta-scaled ciphertexts, so ordinary BFV decoding would be the wrong test.
fn observe_raw_column(
    ctx: &RNSFHEContext,
    key: &RawKey,
    keys: &RNSKeySet,
    selected: bool,
    times_secret: bool,
) {
    let q = U512::product_u64s(&ctx.config.primes);
    let secret = ordinary(ctx, &keys.secret_key.s);
    let mut index = 0;
    for (source_lane, &d) in key.shape.digits.iter().enumerate() {
        for digit in 0..d {
            let ct = key.coefficient_row(ctx, index);
            index += 1;
            let phase = decrypted_phase_residues(ctx, &ct, keys);
            let power = mod_pow(
                2,
                (digit as u32 * key.shape.base_bits) as u64,
                ctx.config.primes[source_lane],
            );
            for coefficient in 0..ctx.n {
                let errors: Vec<_> = ctx
                    .config
                    .primes
                    .iter()
                    .enumerate()
                    .map(|(lane, &p)| {
                        let target = if selected && lane == source_lane {
                            let value = if times_secret {
                                secret[lane][coefficient]
                            } else {
                                u64::from(coefficient == 0)
                            };
                            (value as u128 * power as u128 % p as u128) as u64
                        } else {
                            0
                        };
                        ((phase[lane][coefficient] as u128 + p as u128 - target as u128)
                            % p as u128) as u64
                    })
                    .collect();
                let error = client_crt(ctx, &errors);
                let error = if words(error) > words(q.div_u64(2)) {
                    q.sub(error)
                } else {
                    error
                };
                assert!(
                    words(error) <= words(U512::from_u128(key.beta)),
                    "derived raw row {index}, coefficient {coefficient}"
                );
            }
        }
    }
}

fn source_component(r: i128, p: u64) -> (i128, u64) {
    if r < 0 {
        let (component, a) = source_component(-r, p);
        return (Q_SOURCE - component, (p - a) % p);
    }
    let a = ((p as u128 - r.rem_euclid(p as i128) as u128)
        * inverse((Q_SOURCE % p as i128) as u64, p) as u128
        % p as u128) as u64;
    let x = U512::from_u128(Q_SOURCE as u128)
        .mul_u128(a as u128)
        .add(U512::from_u128(r as u128))
        .div_u64(p);
    assert_eq!((x.d3, x.d2, x.d1), (0, 0, 0));
    (x.d0 as i128, a)
}

fn clock_lut(ctx: &RNSFHEContext, m: usize, window2: i64) -> RNSCiphertext {
    let size = 2 * ctx.n;
    let mut values = vec![None; size];
    for k in 0..m {
        let value = if k > m / 2 {
            k as i64 - m as i64
        } else {
            k as i64
        };
        for rotation in 0..size {
            let period = (m * size) as i64;
            let d = (m as i64 * rotation as i64 - size as i64 * k as i64).rem_euclid(period);
            if 2 * d.min(period - d) <= window2 {
                for (i, v) in [(rotation, value), ((rotation + ctx.n) % size, -value)] {
                    assert!(values[i].is_none_or(|old| old == v));
                    values[i] = Some(v);
                }
            }
        }
    }
    let inv = inverse(ctx.n as u64, ctx.t) as i64 - ctx.t as i64;
    assert!(inv.unsigned_abs() <= ctx.t / 2);
    let mut coefs = vec![0; ctx.n];
    coefs[0] = inv * values[0].unwrap_or(0);
    for r in 1..ctx.n {
        coefs[ctx.n - r] = -inv * values[r].unwrap_or(0);
    }
    public_plain(ctx, &coefs)
}

#[test]
fn phase_clock_compact_cached_transform_is_negacyclic_not_cyclic() {
    let mut config = SecureConfig::secure_128().into_config();
    config.n = 16;
    config.security_bits = 0;
    let ctx = RNSFHEContext::try_new(&config).unwrap();
    for (lane, &q) in ctx.config.primes.iter().enumerate() {
        let mut a = vec![0; ctx.n];
        let mut b = a.clone();
        a[ctx.n - 1] = 1;
        b[1] = 1;
        let product = |x: Vec<u64>, y: Vec<u64>| {
            x.iter()
                .zip(y)
                .map(|(&a, b)| (a as u128 * b as u128 % q as u128) as u64)
                .collect::<Vec<_>>()
        };
        let cached = backward(
            &ctx,
            lane,
            &product(forward(&ctx, lane, &a), forward(&ctx, lane, &b)),
        );
        assert_eq!(cached, ctx.ntt_engines[lane].multiply(&a, &b));
        assert_eq!(cached[0], q - 1);
        let cyclic = ctx.ntt_engines[lane].intt(&product(
            ctx.ntt_engines[lane].ntt(&a),
            ctx.ntt_engines[lane].ntt(&b),
        ));
        assert_eq!(cyclic[0], 1);
        assert_ne!(cached, cyclic);
    }
}

#[test]
fn phase_clock_compact_raw_columns_preserve_boolean_controls_and_charge_derived_error() {
    let mut config = SecureConfig::secure_128().into_config();
    config.n = 16;
    config.t = 65537;
    config.primes = BOOT.to_vec();
    config.security_bits = 0;
    config.name = "INSECURE compact raw-column derivation test";
    let ctx = RNSFHEContext::try_new(&config).unwrap();
    let engine = Engine {
        ctx: &ctx,
        switches: Cell::new(0),
    };
    let mut rng = ShadowHarvester::with_seed(0x5041_434b_5241_5731);
    let keys = ctx.generate_keys(&mut rng);
    let source = [-1, 0, 1, 0, 1, 0, -1, 0, 0, 1, 0, -1, 1, 0, -1, 0];
    let packed = setup(&engine, &keys, &source, 4, 8, 8, &mut rng);
    let mut values = vec![0i64; ctx.n];
    values[0] = 7;
    values[3] = -2;
    values[11] = 5;
    let input = public_plain(&ctx, &values);
    let q = U512::product_u64s(&config.primes);
    for index in [0, 1, 2, 6, 9, 11, 15] {
        for polarity in 0..2 {
            let key = derive(&engine, &packed, index, polarity);
            assert!(key.constant.beta > 3 && key.secret.beta > key.constant.beta);
            let selected = source[index] == if polarity == 0 { -1 } else { 1 };
            observe_raw_column(&ctx, &key.constant, &keys, selected, false);
            observe_raw_column(&ctx, &key.secret, &keys, selected, true);
            let output = engine.external(&input, &key);
            let decoded = decrypt_coefficients(&ctx, &output, &keys);
            assert_eq!(
                decoded,
                values
                    .iter()
                    .map(|&v| if selected {
                        v.rem_euclid(ctx.t as i64) as u64
                    } else {
                        0
                    })
                    .collect::<Vec<_>>()
            );
            assert!(
                words(U512::from_u128(ctx.t as u128 * engine.external_error(&key)).mul_u128(2))
                    < words(q)
            );
        }
    }
    eprintln!("compact raw selector: 14 derived boolean controls, positive/negative/zero positions and full-polynomial payloads correct; both derived-column errors charged");
}

#[test]
#[ignore = "opt-in slow full-position packed-key research probe; use package optimization2"]
fn phase_clock_compact_full_position_source_recovers_message_and_following_square() {
    let mut config = SecureConfig::secure_128().into_config();
    config.n = 64;
    config.t = 65537;
    config.primes = BOOT.to_vec();
    config.security_bits = 0;
    config.name = "INSECURE compact full-position phase-clock test";
    let ctx = RNSFHEContext::try_new(&config).unwrap();
    let engine = Engine {
        ctx: &ctx,
        switches: Cell::new(0),
    };
    let mut rng = ShadowHarvester::with_seed(0x434f_4d50_4143_5431);
    let keys = ctx.generate_keys(&mut rng);
    let mut source = vec![0i8; ctx.n];
    source[5] = 1;
    source[42] = 1;
    let packed = setup(&engine, &keys, &source, 16, 2, 2, &mut rng);
    let exact = ctx.try_exact_evaluator().unwrap();
    let relin = exact.generate_hybrid_gadget_key_with_rng(&keys.secret_key, &mut rng);
    let step = Q_SOURCE / (13 * 9_699_690) * (13 * 9_699_690);
    let m = 9usize;
    let size = 2 * ctx.n;
    let quantize = |r: i128| {
        let magnitude = ((r.abs().checked_mul(size as i128).unwrap() + m as i128 * Q_SOURCE / 2)
            / (m as i128 * Q_SOURCE)) as i64;
        if r < 0 {
            -magnitude
        } else {
            magnitude
        }
    };
    let window2 = size as i64 / 8 + m as i64 * 3;
    assert!(window2 < ctx.n as i64);
    struct Frame {
        r0: i128,
        weights: Vec<i128>,
        c0: i128,
        components: Vec<i128>,
        a0: u64,
        a: Vec<u64>,
        clock: RNSCiphertext,
        affine: RNSCiphertext,
    }
    // Same compact precharge, two DIFFERENT public dense residual inputs.
    // They select different native sheets; no new source keys are supplied.
    let lookup = clock_lut(&ctx, m, window2);
    let mut frames: Vec<_> = [
        (Q_SOURCE / 128, vec![step / 2; ctx.n]),
        (
            Q_SOURCE / 256,
            (0..ctx.n)
                .map(|i| if i % 2 == 0 { step / 2 } else { -step / 2 })
                .collect(),
        ),
    ]
    .into_iter()
    .map(|(r0, weights)| {
        let (c0, a0) = source_component(r0, ctx.t);
        let (components, a) = weights.iter().map(|&w| source_component(w, ctx.t)).unzip();
        Frame {
            r0,
            weights,
            c0,
            components,
            a0,
            a,
            clock: rotate(&ctx, &lookup, quantize(r0)),
            affine: scalar(&ctx, a0),
        }
    })
    .collect();
    let mut visited = BTreeSet::new();
    let mut ext_error = None;
    visit_all(&engine, &packed, &mut |index, polarity, key| {
        // EVERY public position is processed, including encrypted zeros.
        // No selector or secret support is read on this evaluation path.
        for frame in &mut frames {
            let rotation = quantize(frame.weights[index]);
            frame.clock = engine.cmux(
                &frame.clock,
                if polarity == 0 { -rotation } else { rotation },
                &key,
            );
            let term = engine.external(&scalar(&ctx, frame.a[index]), &key);
            frame.affine = if polarity == 0 {
                ctx.sub(&frame.affine, &term)
            } else {
                add(&ctx, &frame.affine, &term)
            };
        }
        ext_error = Some(engine.external_error(&key));
        if polarity == 1 {
            assert!(visited.insert(index));
        }
    });
    let gal = packed.galois.values().next().unwrap();
    let eg = ctx.n as u128 * gal.shape.digit_sum * gal.beta;
    let rem = U512::product_u64s(&config.primes).mod_u64(ctx.t) as u128;
    let lookup_norm = ((ctx.t - 1) / (ctx.n as u64)) as u128 * (m / 2) as u128;
    let carry_bound = ctx.n as u128
        * (rem * lookup_norm + ctx.t as u128 * 2 * ctx.n as u128 * ext_error.unwrap())
        + ctx.t as u128 * (ctx.n - 1) as u128 * eg;
    assert_eq!(visited.len(), ctx.n);
    let visited = visited.len();
    let mut recovered_sheets = Vec::new();
    for (frame_index, frame) in frames.into_iter().enumerate() {
        let carry = engine.trace(frame.clock, ctx.n, &packed.galois);
        let recovered = add(&ctx, &frame.affine, &carry);
        // A conservative affine allowance charges both raw columns even though
        // its public input has c1=0; no eta=3 bound is reused for derived keys.
        let norm = frame.a0.min(ctx.t - frame.a0) as u128
            + frame
                .a
                .iter()
                .map(|&a| a.min(ctx.t - a) as u128)
                .sum::<u128>();
        let bound =
            carry_bound + rem * norm + ctx.t as u128 * 2 * ctx.n as u128 * ext_error.unwrap();
        // All remaining clear-source arithmetic is an independent CLIENT oracle.
        let sum = frame.r0
            + frame
                .weights
                .iter()
                .zip(&source)
                .map(|(&w, &s)| w * s as i128)
                .sum::<i128>();
        let k = (sum + Q_SOURCE / 2).div_euclid(Q_SOURCE);
        let g = sum - Q_SOURCE * k;
        assert!(g.unsigned_abs() <= Q_SOURCE as u128 / 16);
        recovered_sheets.push(k);
        let source_phase = (frame.c0
            + frame
                .components
                .iter()
                .zip(&source)
                .map(|(&c, &s)| c * s as i128)
                .sum::<i128>())
        .rem_euclid(Q_SOURCE) as u128;
        let scaled = U512::from_u128(source_phase)
            .mul_u128(ctx.t as u128)
            .add(U512::from_u128(Q_SOURCE as u128 / 2));
        // Independent client rounding: the quotient is tiny, so binary search
        // does not need a hidden integer division primitive in the evaluator.
        let (mut low, mut high) = (0u64, ctx.t + 1);
        while high - low > 1 {
            let mid = (low + high) / 2;
            if words(U512::from_u128(Q_SOURCE as u128).mul_u128(mid as u128)) <= words(scaled) {
                low = mid
            } else {
                high = mid
            }
        }
        let message = low % ctx.t;
        let measured = observe(&ctx, &recovered, &keys, message);
        assert!(measured <= bound);
        observe(&ctx, &carry, &keys, k.rem_euclid(ctx.t as i128) as u64);
        let square = exact.try_mul_exact(&recovered, &recovered, &relin).unwrap();
        observe(&ctx, &square, &keys, message * message % ctx.t);
        eprintln!("compact full-position clock: N=64, frame={frame_index}, all {visited} public nonzero weights processed, private source weight2, block16, raw/galois radix2bits, native-Q119 sheet={k}, message={message}, observed Vbits={}, bound Vbits={}, following message square correct",bits(measured),bits(bound));
    }
    assert_eq!(recovered_sheets, vec![1, 0]);
    let packed_rows: usize = packed.columns.iter().map(|p| p[0].len() + p[1].len()).sum();
    let rows = packed_rows
        + packed.outer_secret.constant.rows.len()
        + packed.outer_secret.secret.rows.len()
        + packed.galois.values().map(|k| k.rows.len()).sum::<usize>();
    let stored_bytes = rows * 2 * ctx.n * ctx.config.primes.len() * 8;
    assert_eq!(stored_bytes, 6_553_600);
    assert_eq!(engine.switches.get(), 31116);
    eprintln!("compact key reuse: stored polynomial words={stored_bytes} bytes, 2 message recoveries and 2 dependent squares, raw switches={}",engine.switches.get());
}
