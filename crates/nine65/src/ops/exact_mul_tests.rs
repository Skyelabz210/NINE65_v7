//! WR-1 §G acceptance gates for the derived-transient exact evaluator.
//!
//! # The oracle
//!
//! Every differential gate here compares against [`BigOracle`], a
//! from-scratch arbitrary-precision signed-integer implementation of BFV
//! multiplication that shares **no code and no state** with the route under
//! test. It has its own limb type, its own schoolbook multiply/divide, its own
//! `O(N^2)` negacyclic convolution and its own rounding. It never calls
//! `MainOnlyBaseExt`, `ExactScaleRound`, `RNSContext`, `NTTEngine`, `U256` or
//! `U512`. That independence is the point: an oracle that reused the kernel
//! would agree with a shared bug.
//!
//! The oracle works on *centered* integer coefficients throughout, which is
//! also how it independently re-derives the WR-1 invariant-5 requirement: if
//! the route were fed residues of the wrapped tensor instead of the centered
//! one, `oracle_rejects_the_wrapped_tensor_shortcut` shows the answers diverge.
//!
//! # Ring degree
//!
//! The oracle is `O(N^2)` in software bigints, so the coefficientwise gates run
//! on a reduced ring degree with the **production main primes and production
//! plaintext modulus**. `production_configs_end_to_end_*` then runs the real
//! `secure_*` configurations at their real `N` against a plaintext oracle.
//! The auxiliary-basis certificates are checked at production `N` in both.

use super::*;
use crate::arithmetic::RNSContext;
use crate::entropy::ShadowHarvester;
use crate::params::secure_configs::SecureConfig;
use crate::params::FHEConfig;

// ===========================================================================
// Independent arbitrary-precision signed integer (no crate types reused)
// ===========================================================================

/// Sign-magnitude bigint over base 2^32 limbs. Deliberately simple and
/// deliberately unrelated to `U256`/`U512`.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Big {
    neg: bool,
    /// Little-endian base-2^32 limbs, no trailing zeros; empty == zero.
    mag: Vec<u32>,
}

impl Big {
    fn zero() -> Self {
        Big {
            neg: false,
            mag: vec![],
        }
    }

    fn from_i128(mut v: i128) -> Self {
        let neg = v < 0;
        if neg {
            v = -v;
        }
        let mut mag = vec![];
        let mut u = v as u128;
        while u > 0 {
            mag.push((u & 0xFFFF_FFFF) as u32);
            u >>= 32;
        }
        Big { neg, mag }
    }

    fn from_u64(v: u64) -> Self {
        Big::from_i128(v as i128)
    }

    fn is_zero(&self) -> bool {
        self.mag.is_empty()
    }

    fn trim(mut mag: Vec<u32>) -> Vec<u32> {
        while mag.last() == Some(&0) {
            mag.pop();
        }
        mag
    }

    /// Compare magnitudes only.
    fn cmp_mag(a: &[u32], b: &[u32]) -> std::cmp::Ordering {
        if a.len() != b.len() {
            return a.len().cmp(&b.len());
        }
        for i in (0..a.len()).rev() {
            if a[i] != b[i] {
                return a[i].cmp(&b[i]);
            }
        }
        std::cmp::Ordering::Equal
    }

    fn add_mag(a: &[u32], b: &[u32]) -> Vec<u32> {
        let mut out = Vec::with_capacity(a.len().max(b.len()) + 1);
        let mut carry: u64 = 0;
        for i in 0..a.len().max(b.len()) {
            let s = carry + *a.get(i).unwrap_or(&0) as u64 + *b.get(i).unwrap_or(&0) as u64;
            out.push((s & 0xFFFF_FFFF) as u32);
            carry = s >> 32;
        }
        if carry > 0 {
            out.push(carry as u32);
        }
        Big::trim(out)
    }

    /// `a - b`, requires `a >= b` by magnitude.
    fn sub_mag(a: &[u32], b: &[u32]) -> Vec<u32> {
        let mut out = Vec::with_capacity(a.len());
        let mut borrow: i64 = 0;
        for i in 0..a.len() {
            let mut d = a[i] as i64 - *b.get(i).unwrap_or(&0) as i64 - borrow;
            if d < 0 {
                d += 1i64 << 32;
                borrow = 1;
            } else {
                borrow = 0;
            }
            out.push(d as u32);
        }
        assert_eq!(borrow, 0, "sub_mag underflow");
        Big::trim(out)
    }

    fn add(&self, other: &Big) -> Big {
        if self.neg == other.neg {
            Big {
                neg: self.neg,
                mag: Big::add_mag(&self.mag, &other.mag),
            }
        } else {
            match Big::cmp_mag(&self.mag, &other.mag) {
                std::cmp::Ordering::Equal => Big::zero(),
                std::cmp::Ordering::Greater => Big {
                    neg: self.neg,
                    mag: Big::sub_mag(&self.mag, &other.mag),
                },
                std::cmp::Ordering::Less => Big {
                    neg: other.neg,
                    mag: Big::sub_mag(&other.mag, &self.mag),
                },
            }
        }
    }

    fn negate(&self) -> Big {
        if self.is_zero() {
            Big::zero()
        } else {
            Big {
                neg: !self.neg,
                mag: self.mag.clone(),
            }
        }
    }

    fn sub(&self, other: &Big) -> Big {
        self.add(&other.negate())
    }

    fn mul(&self, other: &Big) -> Big {
        if self.is_zero() || other.is_zero() {
            return Big::zero();
        }
        let mut out = vec![0u32; self.mag.len() + other.mag.len()];
        for (i, &x) in self.mag.iter().enumerate() {
            let mut carry: u64 = 0;
            for (j, &y) in other.mag.iter().enumerate() {
                let cur = out[i + j] as u64 + x as u64 * y as u64 + carry;
                out[i + j] = (cur & 0xFFFF_FFFF) as u32;
                carry = cur >> 32;
            }
            let mut k = i + other.mag.len();
            while carry > 0 {
                let cur = out[k] as u64 + carry;
                out[k] = (cur & 0xFFFF_FFFF) as u32;
                carry = cur >> 32;
                k += 1;
            }
        }
        Big {
            neg: self.neg != other.neg,
            mag: Big::trim(out),
        }
    }

    /// Magnitude division by a small `u64` divisor (< 2^32 assumed for the
    /// remainder path; used only with 32-bit primes).
    fn divmod_small_mag(mag: &[u32], d: u32) -> (Vec<u32>, u32) {
        let mut out = vec![0u32; mag.len()];
        let mut rem: u64 = 0;
        for i in (0..mag.len()).rev() {
            let cur = (rem << 32) | mag[i] as u64;
            out[i] = (cur / d as u64) as u32;
            rem = cur % d as u64;
        }
        (Big::trim(out), rem as u32)
    }

    /// Euclidean remainder `self mod m` in `[0, m)` for a 32-bit modulus.
    fn rem_u32(&self, m: u32) -> u32 {
        let (_, r) = Big::divmod_small_mag(&self.mag, m);
        if self.neg && r != 0 {
            m - r
        } else {
            r
        }
    }

    /// Exact `floor(self / d)` for a positive small `d`, on the magnitude only.
    fn div_small_mag_exact(&self, d: u32) -> Big {
        let (q, _) = Big::divmod_small_mag(&self.mag, d);
        Big {
            neg: self.neg,
            mag: q,
        }
    }

    /// `floor(self / D)` where `D = prod(divisors)`, all positive.
    ///
    /// Successive division by each factor equals division by the product for
    /// non-negative values. For negative values it is done on the magnitude and
    /// corrected to a true floor.
    fn floor_div_product(&self, divisors: &[u64]) -> Big {
        if !self.neg {
            let mut acc = self.clone();
            for &d in divisors {
                acc = acc.div_small_mag_exact(d as u32);
            }
            return acc;
        }
        // floor(-a/D) = -ceil(a/D) = -(floor((a + D - 1)/D)).
        let d_big = divisors
            .iter()
            .fold(Big::from_u64(1), |acc, &d| acc.mul(&Big::from_u64(d)));
        let a = Big {
            neg: false,
            mag: self.mag.clone(),
        };
        let numerator = a.add(&d_big).sub(&Big::from_u64(1));
        let mut acc = numerator;
        for &d in divisors {
            acc = acc.div_small_mag_exact(d as u32);
        }
        acc.negate()
    }

    fn bit_length(&self) -> usize {
        match self.mag.last() {
            None => 0,
            Some(&top) => (self.mag.len() - 1) * 32 + (32 - top.leading_zeros() as usize),
        }
    }
}

// ===========================================================================
// Independent BFV oracle
// ===========================================================================

/// Exact BFV reference over `Z[X]/(X^N+1)`, integer-only, sign-aware.
struct BigOracle {
    n: usize,
    t: u64,
    primes: Vec<u64>,
    q: Big,
}

impl BigOracle {
    fn new(primes: &[u64], n: usize, t: u64) -> Self {
        let q = primes
            .iter()
            .fold(Big::from_u64(1), |acc, &p| acc.mul(&Big::from_u64(p)));
        BigOracle {
            n,
            t,
            primes: primes.to_vec(),
            q,
        }
    }

    /// `x mod Q` in `[0, Q)`, for an `x` of ANY magnitude and either sign.
    ///
    /// Computed as `x - Q * floor(x/Q)` with the floor taken by exact
    /// successive division by `Q`'s prime factors. Repeated add/subtract would
    /// not do: tensor coefficients here reach `~N*(Q/2)^2`, about `2^248`
    /// against a `2^119` modulus, so a subtract loop would run `~2^129` times.
    fn reduce(&self, x: &Big) -> Big {
        let quotient = x.floor_div_product(&self.primes);
        let r = x.sub(&quotient.mul(&self.q));
        debug_assert!(!r.neg && Big::cmp_mag(&r.mag, &self.q.mag) == std::cmp::Ordering::Less);
        r
    }

    /// Centered lift of a canonical value in `[0, Q)`.
    fn center(&self, x: &Big) -> Big {
        // upper half iff 2x >= Q  (Q odd, so equality is impossible)
        let two_x = x.add(x);
        if Big::cmp_mag(&two_x.mag, &self.q.mag) != std::cmp::Ordering::Less {
            x.sub(&self.q)
        } else {
            x.clone()
        }
    }

    /// Read one polynomial's coefficients out of standard-domain canonical main
    /// residues, as centered integers. CRT reconstruction lives ONLY here.
    fn from_residues_centered(&self, limbs: &[Vec<u64>]) -> Vec<Big> {
        (0..self.n)
            .map(|k| {
                let residues: Vec<u64> = limbs.iter().map(|l| l[k]).collect();
                self.center(&self.crt(&residues))
            })
            .collect()
    }

    /// Textbook CRT with an independent modular inverse. Not used anywhere in
    /// the production route — the whole point of WR-1 is that the route does
    /// not need it.
    fn crt(&self, residues: &[u64]) -> Big {
        let mut acc = Big::zero();
        for (i, (&r, &p)) in residues.iter().zip(self.primes.iter()).enumerate() {
            // M_i = prod_{j != i} p_j, built by INDEX (a duplicated prime value
            // would otherwise drop the wrong factor).
            let mi = self
                .primes
                .iter()
                .enumerate()
                .filter(|&(j, _)| j != i)
                .fold(Big::from_u64(1), |a, (_, &pj)| a.mul(&Big::from_u64(pj)));
            let mi_mod_p = mi.rem_u32(p as u32) as u64;
            let inv = mod_inv_u64(mi_mod_p, p);
            let coeff = (r as u128 * inv as u128 % p as u128) as u64;
            acc = acc.add(&mi.mul(&Big::from_u64(coeff)));
        }
        // `acc < k*Q` here (k = lane count), so a bounded subtract loop is
        // exact and cheap; `reduce` is not used to keep `crt` free of any
        // dependency on the divisor machinery it is cross-checking.
        let mut steps = 0usize;
        while Big::cmp_mag(&acc.mag, &self.q.mag) != std::cmp::Ordering::Less {
            acc = acc.sub(&self.q);
            steps += 1;
            assert!(steps <= self.primes.len(), "CRT sum exceeded k*Q");
        }
        acc
    }

    /// Negacyclic convolution over the integers, `O(N^2)`.
    fn negacyclic(&self, a: &[Big], b: &[Big]) -> Vec<Big> {
        let mut out = vec![Big::zero(); self.n];
        for (i, x) in a.iter().enumerate() {
            for (j, y) in b.iter().enumerate() {
                let term = x.mul(y);
                let idx = i + j;
                if idx < self.n {
                    out[idx] = out[idx].add(&term);
                } else {
                    out[idx - self.n] = out[idx - self.n].sub(&term);
                }
            }
        }
        out
    }

    /// `round(x * t / Q)` with the half-up rule BFV specifies, exactly.
    fn scale_round(&self, x: &Big) -> Big {
        let half_q = self.q.div_small_mag_exact(2); // Q odd -> floor(Q/2)
        let z = x.mul(&Big::from_u64(self.t)).add(&half_q);
        z.floor_div_product(&self.primes)
    }

    fn residues(&self, x: &Big) -> Vec<u64> {
        self.primes
            .iter()
            .map(|&p| x.rem_u32(p as u32) as u64)
            .collect()
    }
}

fn mod_inv_u64(a: u64, m: u64) -> u64 {
    let (mut t, mut newt): (i128, i128) = (0, 1);
    let (mut r, mut newr): (i128, i128) = (m as i128, (a % m) as i128);
    while newr != 0 {
        let q = r / newr;
        (t, newt) = (newt, t - q * newt);
        (r, newr) = (newr, r - q * newr);
    }
    ((t % m as i128 + m as i128) % m as i128) as u64
}

// ===========================================================================
// Test scaffolding
// ===========================================================================

/// Deterministic LCG, so every failure is reproducible.
struct Lcg(u64);
impl Lcg {
    fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        self.0
    }
}

/// Production main primes at a reduced ring degree, so the `O(N^2)` bigint
/// oracle stays runnable while the arithmetic stays production-shaped.
fn small_ring_config(primes: Vec<u64>, n: usize) -> FHEConfig {
    let q = primes[0];
    FHEConfig {
        n,
        primes,
        q,
        t: 65537,
        eta: 3,
        security_bits: 80,
        name: "wr1_exact_mul_oracle_ring",
    }
}

/// Build an `RNSCiphertext` directly from chosen centered integer
/// coefficients, bypassing encryption. Used by the tensor gates so the operand
/// corners (zero, one, +-1, half-Q neighbours, extremes) are reachable exactly.
fn ciphertext_from_centered(
    ctx: &RNSFHEContext,
    c0: &[Big],
    c1: &[Big],
    oracle: &BigOracle,
) -> RNSCiphertext {
    let build = |coeffs: &[Big]| {
        let limbs: Vec<Vec<u64>> = ctx
            .config
            .primes
            .iter()
            .map(|&p| coeffs.iter().map(|c| c.rem_u32(p as u32) as u64).collect())
            .collect();
        ctx.to_montgomery_form(&RNSPolynomial { limbs, n: ctx.n })
    };
    let _ = oracle;
    RNSCiphertext {
        c0: build(c0),
        c1: build(c1),
        num_primes: ctx.config.primes.len(),
    }
}

/// The four named production chains (`secure_128` and `secure_128_deep` are the
/// same tuple since the 2026-08-26 re-cut, and both are listed on purpose so a
/// future divergence is caught).
fn named_configs() -> Vec<(&'static str, FHEConfig)> {
    vec![
        ("secure_128", SecureConfig::secure_128().into_config()),
        (
            "secure_128_deep",
            SecureConfig::secure_128_deep().into_config(),
        ),
        ("secure_192", SecureConfig::secure_192().into_config()),
        ("secure_256", SecureConfig::secure_256().into_config()),
    ]
}

// ===========================================================================
// G2/§B — plan and certificates
// ===========================================================================

/// The plan's auxiliary-lane selection must reproduce the integer oracle's
/// certified minimums (`scripts/verify_wr1_transient_exact.py`), and must do so
/// by recomputing the certificate from the live config, not by consulting a
/// table.
///
/// This is also where the `N/4` -> `N/2` operand-bound deviation is pinned: the
/// stricter bound costs one required bit and **zero** extra lanes.
#[test]
fn aux_lane_counts_match_the_integer_oracle() {
    // (config, aux lanes the oracle certifies for the tuple actually shipped)
    // The oracle's own `secure_128` row uses the retired 3-prime chain; the
    // shipped `secure_128` is the 4-prime tuple, i.e. the oracle's
    // `secure_128_deep` row.
    let expected: Vec<(&str, usize, u32)> = vec![
        ("secure_128", 5, 157),
        ("secure_128_deep", 5, 157),
        ("secure_192", 6, 188),
        ("secure_256", 7, 220),
    ];
    for ((name, cfg), (ename, lanes, aux_bits)) in named_configs().into_iter().zip(expected) {
        assert_eq!(name, ename);
        let plan = ExactMulPlan::new(&cfg.primes, cfg.n, cfg.t).expect("plan");
        let cert = plan.certificate();
        assert_eq!(cert.aux_lanes, lanes, "{name}: auxiliary lane count");
        assert_eq!(cert.aux_bits, aux_bits, "{name}: A bit length");
        assert!(
            cert.aux_bits > cert.required_bits,
            "{name}: A ({}) must exceed 2*s_mult*Q ({})",
            cert.aux_bits,
            cert.required_bits
        );
        assert_eq!(cert.x_bound_over_q_sq, cfg.n as u64 / 2);

        // The N/4 bound the doc states selects the same lanes, one bit lower.
        let n4 = ExactMulPlan::with_operand_bound(&cfg.primes, cfg.n, cfg.t, cfg.n as u64 / 4)
            .expect("N/4 plan");
        assert_eq!(
            n4.certificate().aux_lanes,
            cert.aux_lanes,
            "{name}: the N/2 bound must not cost an auxiliary lane"
        );
        assert_eq!(
            n4.certificate().required_bits + 1,
            cert.required_bits,
            "{name}: N/2 must be exactly one bit above N/4"
        );

        println!(
            "{name}: N={} mainlanes={} log2(Q)={} auxlanes={} log2(A)={} required={} \
             s_mult={} base_bits={} digits={:?}",
            cert.ring_degree,
            cfg.primes.len(),
            cert.q_bits,
            cert.aux_lanes,
            cert.aux_bits,
            cert.required_bits,
            cert.shift_multiplier,
            cert.base_bits,
            cert.digits_per_lane
        );
    }
}

/// Every selected auxiliary lane must be coprime to every main lane and
/// negacyclic-NTT compatible at the config's `N`, and none of them may divide
/// `Q`.
#[test]
fn auxiliary_basis_certificates_hold_for_named_configs() {
    for (name, cfg) in named_configs() {
        let plan = ExactMulPlan::new(&cfg.primes, cfg.n, cfg.t).expect("plan");
        let two_n = 2 * cfg.n as u64;
        for &a in plan.auxiliary_basis() {
            assert_eq!((a - 1) % two_n, 0, "{name}: aux {a} not NTT-compatible");
            for &q in &cfg.primes {
                let mut x = a;
                let mut y = q;
                while y != 0 {
                    let r = x % y;
                    x = y;
                    y = r;
                }
                assert_eq!(x, 1, "{name}: aux {a} shares a factor with main {q}");
            }
        }
    }
}

/// A capacity shortfall must be a typed refusal, never a silently-wrong
/// kernel.
///
/// Non-vacuous by construction: the only difference between the refused call
/// and the accepted one is four extra main primes, so what is being refused is
/// the capacity certificate and not some unrelated validation firing first.
#[test]
fn insufficient_auxiliary_capacity_is_a_typed_refusal() {
    let cfg = SecureConfig::secure_256().into_config();

    // The shipped chain is satisfiable by the 10-prime pool.
    let ok = ExactMulPlan::new(&cfg.primes, cfg.n, cfg.t).expect("real chain is satisfiable");
    assert_eq!(ok.certificate().aux_lanes, 7);

    // Four more distinct primes, coprime to the pool, push log2(Q) from 175 to
    // ~294; with s_mult ~ 2^29 the requirement passes the pool's ~315 bits.
    let mut wider = cfg.primes.clone();
    wider.extend_from_slice(&[1004535809, 1224736769, 377487361, 645922817]);
    match ExactMulPlan::new(&wider, cfg.n, cfg.t) {
        Err(ExactMulError::AuxiliaryBasisUnavailable {
            required_bits,
            pool_bits,
            pool_lanes,
        }) => {
            assert!(
                pool_bits <= required_bits,
                "refusal must report a genuine shortfall: {pool_bits} vs {required_bits}"
            );
            assert_eq!(pool_lanes, 10);
        }
        other => panic!("expected AuxiliaryBasisUnavailable, got {other:?}"),
    }

    // An operand bound that cannot even be expressed is its own typed refusal.
    match ExactMulPlan::with_operand_bound(&cfg.primes, cfg.n, cfg.t, u64::MAX) {
        Err(ExactMulError::OperandBoundOverflow { .. }) => {}
        other => panic!("expected OperandBoundOverflow, got {other:?}"),
    }
}

// ===========================================================================
// G3 — exact `mul_no_relin` against the bigint oracle
// ===========================================================================

/// Structural operand corners for the tensor gate: zero, one, minus one,
/// half-`Q` neighbours, and both extremes of the centered range.
fn corner_coefficients(oracle: &BigOracle, n: usize) -> Vec<Vec<Big>> {
    let q = &oracle.q;
    let half = q.div_small_mag_exact(2); // (Q-1)/2, Q odd
    let one = Big::from_u64(1);
    let singles = vec![
        Big::zero(),
        one.clone(),
        one.negate(),
        half.clone(),
        half.negate(),
        half.sub(&one),
        half.sub(&one).negate(),
    ];
    let mut out = Vec::new();
    // Each corner as a constant polynomial.
    for s in &singles {
        out.push(vec![s.clone(); n]);
    }
    // A polynomial that mixes every corner, so cross terms are exercised.
    let mixed: Vec<Big> = (0..n).map(|k| singles[k % singles.len()].clone()).collect();
    out.push(mixed);
    // All-zero except the top coefficient, to exercise the negacyclic fold.
    let mut top = vec![Big::zero(); n];
    top[n - 1] = half.clone();
    out.push(top);
    out
}

/// **G3.** The degree-2 exact route must be bit-identical to the independent
/// bigint oracle on every one of `e0`, `e1`, `e2`, for every main lane and
/// every coefficient.
///
/// Covers `Delta^2 > Q` (every chain here has it), negative centered tensor
/// coefficients, rounding neighbourhoods and the largest declared operands.
#[test]
fn exact_tensor_is_bit_identical_to_the_bigint_oracle() {
    let ring_n = 16;
    let chains: Vec<Vec<u64>> = vec![
        vec![998244353, 985661441, 754974721, 469762049],
        vec![998244353, 985661441, 754974721, 469762049, 167772161],
        vec![
            998244353, 985661441, 754974721, 469762049, 167772161, 595591169,
        ],
    ];

    let mut total_checks = 0usize;
    let mut tally = RankPathTally::default();

    for primes in chains {
        let cfg = small_ring_config(primes.clone(), ring_n);
        let ctx = RNSFHEContext::new(&cfg);
        // Delta^2 > Q is the regime the legacy limb-local rescale cannot serve.
        assert_eq!(ctx.mul_route(), MulRoute::KElimDual);
        let ev = ctx.try_exact_evaluator().expect("evaluator");
        let oracle = BigOracle::new(&primes, ring_n, cfg.t);

        let corners = corner_coefficients(&oracle, ring_n);
        let mut cases: Vec<(Vec<Big>, Vec<Big>, Vec<Big>, Vec<Big>)> = Vec::new();
        // Structural corner pairs.
        for a0 in &corners {
            for b0 in corners.iter().take(4) {
                cases.push((a0.clone(), b0.clone(), b0.clone(), a0.clone()));
            }
        }
        // Seeded random full-range centered draws.
        let mut rng = Lcg(0x5EED_0F00 ^ primes.len() as u64);
        let mut draw = |rng: &mut Lcg| -> Vec<Big> {
            (0..ring_n)
                .map(|_| {
                    // Uniform in [0, Q) built limb by limb, then centered.
                    let residues: Vec<u64> = primes.iter().map(|&p| rng.next() % p).collect();
                    oracle.center(&oracle.crt(&residues))
                })
                .collect()
        };
        for _ in 0..24 {
            let a0 = draw(&mut rng);
            let a1 = draw(&mut rng);
            let b0 = draw(&mut rng);
            let b1 = draw(&mut rng);
            cases.push((a0, a1, b0, b1));
        }

        for (a0, a1, b0, b1) in cases {
            let ct_a = ciphertext_from_centered(&ctx, &a0, &a1, &oracle);
            let ct_b = ciphertext_from_centered(&ctx, &b0, &b1, &oracle);
            let (got, t) = ev
                .try_mul_no_relin_exact_observed(&ct_a, &ct_b)
                .expect("exact tensor");
            tally.certified += t.certified;
            tally.fallback += t.fallback;

            // Oracle: integer tensor of the centered lifts, then exact rescale.
            let d0 = oracle.negacyclic(&a0, &b0);
            let d1: Vec<Big> = oracle
                .negacyclic(&a0, &b1)
                .iter()
                .zip(oracle.negacyclic(&a1, &b0).iter())
                .map(|(x, y)| x.add(y))
                .collect();
            let d2 = oracle.negacyclic(&a1, &b1);

            for (component, (want_d, got_poly)) in [(d0, &got.e0), (d1, &got.e1), (d2, &got.e2)]
                .into_iter()
                .enumerate()
            {
                for (k, x) in want_d.iter().enumerate() {
                    // The declared operand bound must actually hold, checked
                    // exactly in integers: |Xc| <= (N/2) * Q^2.
                    let declared = Big::from_u64(ring_n as u64 / 2)
                        .mul(&oracle.q)
                        .mul(&oracle.q);
                    assert!(
                        Big::cmp_mag(&x.mag, &declared.mag) != std::cmp::Ordering::Greater,
                        "component {component} coeff {k}: |Xc| is {} bits, beyond \
                         the declared (N/2)*Q^2 = {} bits",
                        x.bit_length(),
                        declared.bit_length()
                    );
                    let want = oracle.residues(&oracle.scale_round(x));
                    let have: Vec<u64> = got_poly.limbs.iter().map(|l| l[k]).collect();
                    assert_eq!(
                        have, want,
                        "component {component}, coefficient {k}, chain {primes:?}"
                    );
                    total_checks += 1;
                }
            }
        }
    }

    assert!(total_checks > 5000, "gate ran only {total_checks} checks");
    assert!(
        tally.certified > 0,
        "certified fixed-point rank path never executed in the evaluator"
    );
    assert!(
        tally.fallback > 0,
        "exact fallback rank path never executed in the evaluator"
    );
    println!(
        "G3: {total_checks} exact coefficient/lane checks; rank paths \
         certified={} fallback={}",
        tally.certified, tally.fallback
    );
}

/// **G3, rounding ties.** `round(Xc * t / Q)` must use the half-up rule BFV
/// specifies, exactly, at the points where the choice is visible.
///
/// The tie points are reachable through the real evaluator, not just through
/// the kernel: with `ct_a = (x, 0)` and `ct_b = (1, 0)` the degree-2 tensor has
/// `d0[0] = x` exactly, so `x` can be placed on `Q*(2j+1)/(2t)` — where
/// `Xc*t/Q` is exactly `j + 1/2` — and on both of its neighbours.
#[test]
fn exact_rounding_ties_follow_the_bfv_half_up_rule() {
    let ring_n = 16;
    for primes in [
        vec![998244353u64, 985661441, 754974721, 469762049],
        vec![
            998244353u64,
            985661441,
            754974721,
            469762049,
            167772161,
            595591169,
        ],
    ] {
        let cfg = small_ring_config(primes.clone(), ring_n);
        let ctx = RNSFHEContext::new(&cfg);
        let ev = ctx.try_exact_evaluator().expect("evaluator");
        let oracle = BigOracle::new(&primes, ring_n, cfg.t);

        let t_big = Big::from_u64(cfg.t);
        let two_t = t_big.add(&t_big);
        let mut targets: Vec<Big> = Vec::new();
        for j in -6i128..=6 {
            // x = floor(Q*(2j+1) / (2t)) -- the exact half-way point.
            let numerator = oracle.q.mul(&Big::from_i128(2 * j + 1));
            // floor division by 2t, sign-aware.
            let base = {
                let a = Big {
                    neg: false,
                    mag: numerator.mag.clone(),
                };
                let (q_mag, _) = Big::divmod_small_mag(&a.mag, 2);
                let mut acc = Big {
                    neg: false,
                    mag: q_mag,
                };
                let (q2, _) = Big::divmod_small_mag(&acc.mag, cfg.t as u32);
                acc = Big {
                    neg: false,
                    mag: q2,
                };
                if numerator.neg {
                    acc.negate()
                } else {
                    acc
                }
            };
            let _ = &two_t;
            for delta in [-1i128, 0, 1] {
                targets.push(base.add(&Big::from_i128(delta)));
            }
        }

        let one = vec![
            Big::from_u64(1),
            Big::zero(),
            Big::zero(),
            Big::zero(),
            Big::zero(),
            Big::zero(),
            Big::zero(),
            Big::zero(),
            Big::zero(),
            Big::zero(),
            Big::zero(),
            Big::zero(),
            Big::zero(),
            Big::zero(),
            Big::zero(),
            Big::zero(),
        ];
        let zeros = vec![Big::zero(); ring_n];

        let mut checked = 0usize;
        for x in &targets {
            let mut a0 = vec![Big::zero(); ring_n];
            a0[0] = x.clone();
            let ct_a = ciphertext_from_centered(&ctx, &a0, &zeros, &oracle);
            let ct_b = ciphertext_from_centered(&ctx, &one, &zeros, &oracle);
            let got = ev.try_mul_no_relin_exact(&ct_a, &ct_b).expect("tensor");

            // d0[0] == x exactly, so e0[0] == round(x*t/Q).
            let want = oracle.residues(&oracle.scale_round(x));
            let have: Vec<u64> = got.e0.limbs.iter().map(|l| l[0]).collect();
            assert_eq!(have, want, "tie neighbourhood at x with chain {primes:?}");
            checked += 1;
        }
        assert_eq!(checked, targets.len());
        println!(
            "G3 ties: {} tie/neighbour points exact on a {}-lane chain",
            checked,
            primes.len()
        );
    }
}

/// Invariant 5, made non-vacuous. If the auxiliary residues were derived from
/// the *wrapped* mod-`Q` tensor instead of the centered inputs — the shortcut
/// this route deliberately does not take — the answers would differ. This test
/// computes both in the oracle and shows they disagree, so the centered lift is
/// load-bearing and not ceremony.
#[test]
fn oracle_rejects_the_wrapped_tensor_shortcut() {
    let ring_n = 8;
    let primes = vec![998244353u64, 985661441, 754974721, 469762049];
    let cfg = small_ring_config(primes.clone(), ring_n);
    let oracle = BigOracle::new(&primes, ring_n, cfg.t);

    let mut rng = Lcg(0xC0FFEE);
    let draw = |rng: &mut Lcg| -> Vec<Big> {
        (0..ring_n)
            .map(|_| {
                let residues: Vec<u64> = primes.iter().map(|&p| rng.next() % p).collect();
                oracle.center(&oracle.crt(&residues))
            })
            .collect()
    };
    let a = draw(&mut rng);
    let b = draw(&mut rng);
    let exact = oracle.negacyclic(&a, &b);

    let mut disagreements = 0usize;
    for x in &exact {
        // What the shortcut would feed the kernel: the tensor coefficient
        // already reduced into [0, Q), i.e. with its true magnitude discarded.
        let wrapped = oracle.reduce(x);
        if oracle.residues(&oracle.scale_round(x)) != oracle.residues(&oracle.scale_round(&wrapped))
        {
            disagreements += 1;
        }
    }
    assert!(
        disagreements * 2 > ring_n,
        "the wrapped-tensor shortcut must disagree with the exact rescale on \
         most coefficients, got {disagreements}/{ring_n}"
    );
}

// ===========================================================================
// G4 — hybrid relinearization
// ===========================================================================

/// **G4.** The gadget key's message must be exactly `g_i * B^j * s^2` in RNS
/// form: `B^j * s^2` in lane `i`, zero everywhere else — verified against an
/// independently reconstructed CRT idempotent.
#[test]
fn hybrid_gadget_key_messages_are_the_crt_idempotent_images() {
    let ring_n = 16;
    let primes = vec![998244353u64, 985661441, 754974721, 469762049];
    let cfg = small_ring_config(primes.clone(), ring_n);
    let ctx = RNSFHEContext::new(&cfg);
    let ev = ctx.try_exact_evaluator().expect("evaluator");
    let mut rng = ShadowHarvester::with_seed(0x9E1_0001);
    let keys = ctx.generate_keys(&mut rng);
    let key = ev.generate_hybrid_gadget_key_with_rng(&keys.secret_key, &mut rng);

    // Recover the message as `rlk0 + rlk1 * s`, which equals
    // `g_i * B^j * s^2 - e`; the error is tiny, so lanes where the message must
    // be zero stay tiny and the target lane must match up to that error.
    let s2 = ctx.rns_poly_mul(&keys.secret_key.s, &keys.secret_key.s);
    let s2_std = ctx.convert_from_montgomery_form(&s2);
    let base = 1u64 << key.base_bits;

    for (i, &q_i) in primes.iter().enumerate() {
        let mut power = 1u64 % q_i;
        for j in 0..key.digits_per_lane[i] {
            let (rlk0, rlk1) = &key.rlk[i][j];
            let recovered = ctx.convert_from_montgomery_form(
                &rlk0.add(&ctx.rns_poly_mul(rlk1, &keys.secret_key.s), &ctx.rns),
            );
            for (h, &q_h) in primes.iter().enumerate() {
                for k in 0..ring_n {
                    let want = if h == i {
                        ((s2_std.limbs[i][k] as u128 * power as u128) % q_i as u128) as u64
                    } else {
                        0
                    };
                    // recovered = want - e, with |e| <= eta.
                    let diff = (recovered.limbs[h][k] + q_h - want % q_h) % q_h;
                    let centered = if diff > q_h / 2 { q_h - diff } else { diff };
                    assert!(
                        centered <= cfg.eta as u64,
                        "lane {i} digit {j} target lane {h} coeff {k}: message \
                         off by {centered}, more than the CBD error bound {}",
                        cfg.eta
                    );
                }
            }
            power = ((power as u128 * base as u128) % q_i as u128) as u64;
        }
    }
}

/// **G4.** Relinearization must reproduce `e2 * s^2` up to a small error, and
/// the folded degree-1 ciphertext must decrypt to the same inner value as the
/// degree-2 one. Checked against the bigint oracle, not against another
/// implementation of the same gadget.
#[test]
fn hybrid_relinearization_matches_the_bigint_oracle() {
    let ring_n = 16;
    let primes = vec![998244353u64, 985661441, 754974721, 469762049];
    let cfg = small_ring_config(primes.clone(), ring_n);
    let ctx = RNSFHEContext::new(&cfg);
    let ev = ctx.try_exact_evaluator().expect("evaluator");
    let oracle = BigOracle::new(&primes, ring_n, cfg.t);
    let mut rng = ShadowHarvester::with_seed(0x9E1_0002);
    let keys = ctx.generate_keys(&mut rng);
    let key = ev.generate_hybrid_gadget_key_with_rng(&keys.secret_key, &mut rng);

    // A random degree-2 component in the main base.
    let mut lcg = Lcg(0xABCD_1234);
    let e2_limbs: Vec<Vec<u64>> = primes
        .iter()
        .map(|&p| (0..ring_n).map(|_| lcg.next() % p).collect())
        .collect();
    let e2 = RNSPolynomial {
        limbs: e2_limbs,
        n: ring_n,
    };
    let tensor = ExactTensor3 {
        e0: RNSPolynomial::zero(&ctx.rns),
        e1: RNSPolynomial::zero(&ctx.rns),
        e2: e2.clone(),
        num_primes: primes.len(),
    };
    let folded = ev.relinearize_tensor(&tensor, &key).expect("relin");

    // Oracle: r0 + r1*s must equal e2*s^2 mod Q, up to the gadget error.
    let inner = ctx.convert_from_montgomery_form(
        &folded
            .c0
            .add(&ctx.rns_poly_mul(&folded.c1, &keys.secret_key.s), &ctx.rns),
    );
    let s_std = ctx.convert_from_montgomery_form(&keys.secret_key.s);
    let s_coeffs = oracle.from_residues_centered(&s_std.limbs);
    let e2_coeffs = oracle.from_residues_centered(&e2.limbs);
    let s2 = oracle.negacyclic(&s_coeffs, &s_coeffs);
    let want = oracle.negacyclic(&e2_coeffs, &s2);
    let got = oracle.from_residues_centered(&inner.limbs);

    // Gadget error bound: sum over (lane, digit) of N * (B-1) * eta.
    let terms: usize = key.digits_per_lane.iter().sum();
    let bound = Big::from_i128(
        terms as i128 * ring_n as i128 * ((1i128 << key.base_bits) - 1) * cfg.eta as i128,
    );
    for (k, (g, w)) in got.iter().zip(want.iter()).enumerate() {
        // (g - w) mod Q, centered. `w` is a double convolution and reaches
        // ~N^2 * Q^3, so this must be a real reduction, not a subtract loop.
        let diff = oracle.reduce(&g.sub(w));
        let centered = oracle.center(&diff);
        let mag = Big {
            neg: false,
            mag: centered.mag.clone(),
        };
        assert!(
            Big::cmp_mag(&mag.mag, &bound.mag) != std::cmp::Ordering::Greater,
            "coefficient {k}: relinearization error {} bits exceeds the gadget \
             bound {} bits",
            mag.bit_length(),
            bound.bit_length()
        );
    }
}

/// Malformed gadget-key shapes are typed refusals, never silent truncation.
#[test]
fn malformed_gadget_key_shapes_are_refused() {
    let ring_n = 16;
    let primes = vec![998244353u64, 985661441, 754974721, 469762049];
    let cfg = small_ring_config(primes.clone(), ring_n);
    let ctx = RNSFHEContext::new(&cfg);
    let ev = ctx.try_exact_evaluator().expect("evaluator");
    let mut rng = ShadowHarvester::with_seed(0x9E1_0003);
    let keys = ctx.generate_keys(&mut rng);
    let good = ev.generate_hybrid_gadget_key_with_rng(&keys.secret_key, &mut rng);

    let tensor = ExactTensor3 {
        e0: RNSPolynomial::zero(&ctx.rns),
        e1: RNSPolynomial::zero(&ctx.rns),
        e2: RNSPolynomial::zero(&ctx.rns),
        num_primes: primes.len(),
    };
    ev.relinearize_tensor(&tensor, &good).expect("good key");

    let mut wrong_base = good.clone();
    wrong_base.base_bits = 16;
    assert!(matches!(
        ev.relinearize_tensor(&tensor, &wrong_base),
        Err(ExactMulError::GadgetKeyShape {
            what: "base_bits",
            ..
        })
    ));

    let mut dropped_lane = good.clone();
    dropped_lane.rlk.pop();
    assert!(matches!(
        ev.relinearize_tensor(&tensor, &dropped_lane),
        Err(ExactMulError::GadgetKeyShape {
            what: "lane count",
            ..
        })
    ));

    let mut dropped_digit = good.clone();
    dropped_digit.rlk[0].pop();
    assert!(matches!(
        ev.relinearize_tensor(&tensor, &dropped_digit),
        Err(ExactMulError::GadgetKeyShape {
            what: "digits in lane",
            ..
        })
    ));
}

// ===========================================================================
// G5 — end-to-end public multiply on the named production configurations
// ===========================================================================

fn end_to_end_case(cfg: &FHEConfig, label: &str, pairs: &[(u64, u64)]) {
    let ctx = RNSFHEContext::new(cfg);
    let ev = ctx.try_exact_evaluator().expect("evaluator");
    let mut rng = ShadowHarvester::with_seed(0x11_0000 ^ cfg.primes.len() as u64);
    let keys = ctx.generate_keys(&mut rng);
    let key = ev.generate_hybrid_gadget_key_with_rng(&keys.secret_key, &mut rng);

    for &(a, b) in pairs {
        let ct_a = ctx.encrypt(a, &keys.public_key, &mut rng);
        let ct_b = ctx.encrypt(b, &keys.public_key, &mut rng);

        // Round-trip first, so a decrypt failure is attributed correctly.
        assert_eq!(
            ev.try_decrypt_exact(&ct_a, &keys.secret_key)
                .expect("dec a"),
            a,
            "{label}: fresh ciphertext round-trip failed for {a}"
        );

        let prod = ev.try_mul_exact(&ct_a, &ct_b, &key).expect("exact mul");
        assert_eq!(prod.num_primes, cfg.primes.len());
        let got = ev.try_decrypt_exact(&prod, &keys.secret_key).expect("dec");
        let want = (a as u128 * b as u128 % cfg.t as u128) as u64;
        assert_eq!(got, want, "{label}: {a} * {b} mod t");
    }
}

/// **G5.** `keygen -> encrypt -> try_mul_exact -> decrypt` against exact
/// plaintext multiplication mod `t`, on the real named configurations at their
/// real `N`. No bootstrap or refresh anywhere (invariant 10).
#[test]
fn production_configs_end_to_end_secure_128() {
    let cfg = SecureConfig::secure_128().into_config();
    end_to_end_case(
        &cfg,
        "secure_128",
        &[(0, 0), (0, 5), (1, 1), (7, 7), (3, 5), (12345, 6789)],
    );
}

#[test]
fn production_configs_end_to_end_secure_128_deep() {
    let cfg = SecureConfig::secure_128_deep().into_config();
    end_to_end_case(&cfg, "secure_128_deep", &[(1, 1), (7, 7), (65536, 2)]);
}

#[test]
fn production_configs_end_to_end_secure_192() {
    let cfg = SecureConfig::secure_192().into_config();
    end_to_end_case(&cfg, "secure_192", &[(1, 1), (7, 7), (4321, 8765)]);
}

#[test]
fn production_configs_end_to_end_secure_256() {
    let cfg = SecureConfig::secure_256().into_config();
    end_to_end_case(&cfg, "secure_256", &[(1, 1), (7, 7), (4321, 8765)]);
}

/// Negative/centered plaintexts: `m > t/2` decodes to `m - t`, and the product
/// must still be exact mod `t`. This is the half of the BFV rule that a naive
/// implementation gets wrong.
#[test]
fn end_to_end_centered_plaintexts_secure_128() {
    let cfg = SecureConfig::secure_128().into_config();
    let t = cfg.t;
    end_to_end_case(
        &cfg,
        "secure_128 centered",
        &[
            (t - 1, t - 1),
            (t - 1, 2),
            (t - 2, t - 3),
            (t / 2 + 1, 2),
            (t / 2, 2),
        ],
    );
}

/// Seeded random plaintext pairs on the shipped `secure_128` chain.
#[test]
fn end_to_end_seeded_random_pairs_secure_128() {
    let cfg = SecureConfig::secure_128().into_config();
    let mut lcg = Lcg(0xD00D_5EED);
    let pairs: Vec<(u64, u64)> = (0..8)
        .map(|_| (lcg.next() % cfg.t, lcg.next() % cfg.t))
        .collect();
    end_to_end_case(&cfg, "secure_128 random", &pairs);
}

/// The exact decrypt must agree with the production single-RNS `decrypt` on a
/// chain where the latter is defined (`Q < 2^128`). This cross-checks the
/// small-value recovery against the existing reconstruction-based decoder.
#[test]
fn exact_decrypt_agrees_with_production_decrypt() {
    let cfg = FHEConfig::light_rns_insecure();
    let ctx = RNSFHEContext::new(&cfg);
    let ev = ctx.try_exact_evaluator().expect("evaluator");
    let mut rng = ShadowHarvester::with_seed(0x7115_9001);
    let keys = ctx.generate_keys(&mut rng);
    for m in [0u64, 1, 2, 7, 100, 1000, 65535, cfg.t - 1] {
        if m >= cfg.t {
            continue;
        }
        let ct = ctx.encrypt(m, &keys.public_key, &mut rng);
        let legacy = ctx.decrypt(&ct, &keys.secret_key);
        let exact = ev.try_decrypt_exact(&ct, &keys.secret_key).expect("exact");
        assert_eq!(legacy, m, "legacy decrypt round-trip");
        assert_eq!(exact, m, "exact decrypt round-trip");
        assert_eq!(legacy, exact, "the two decoders must agree");
    }
}

// ===========================================================================
// G6 — repeated multiplication to the noise limit
// ===========================================================================

/// **G6.** Measure the exact repeated-square depth with no refresh. A wrong
/// plaintext *before* the reported boundary would be a WR-1 failure; this test
/// asserts depth 1 unconditionally and reports where correctness actually ends.
#[test]
fn repeated_squaring_depth_is_measured_not_assumed() {
    for (name, cfg) in named_configs() {
        if name == "secure_128_deep" {
            continue; // same tuple as secure_128
        }
        let ctx = RNSFHEContext::new(&cfg);
        let ev = ctx.try_exact_evaluator().expect("evaluator");
        let mut rng = ShadowHarvester::with_seed(0x5EED_D3B7);
        let keys = ctx.generate_keys(&mut rng);
        let key = ev.generate_hybrid_gadget_key_with_rng(&keys.secret_key, &mut rng);

        const MAX_ROUNDS: usize = 12;
        let start = 3u64;
        let mut ct = ctx.encrypt(start, &keys.public_key, &mut rng);
        let mut want = start;
        let mut depth = 0usize;
        let mut stop = "reached the round cap";
        for _ in 0..MAX_ROUNDS {
            let next = match ev.try_mul_exact(&ct, &ct, &key) {
                Ok(c) => c,
                Err(_) => {
                    stop = "route refused (typed error)";
                    break;
                }
            };
            want = (want as u128 * want as u128 % cfg.t as u128) as u64;
            match ev.try_decrypt_exact(&next, &keys.secret_key) {
                Ok(got) if got == want => {
                    depth += 1;
                    ct = next;
                }
                Ok(_) => {
                    stop = "wrong plaintext (noise limit)";
                    break;
                }
                Err(_) => {
                    stop = "decrypt refused (typed error)";
                    break;
                }
            }
        }
        println!("G6 {name}: exact repeated-square depth without refresh = {depth} ({stop})");
        assert!(
            depth >= 1,
            "{name}: the exact route must reach at least depth 1, got {depth}"
        );
    }
}

/// Depth comparison between the WR-1 exact route and the existing production
/// `mul_dual_public`, on the same configurations and the same starting value.
///
/// `#[ignore]`d, and **assertion-free about the dual route**: it reads
/// `mul_dual_public` only to produce a comparable number for the PR evidence
/// section. WR-1 does not modify that path, and a regression there must not
/// fail a WR-1 gate. Run explicitly:
///
/// ```text
/// cargo test -p nine65 --lib --release -- \
///     exact_vs_dual_public_repeated_square_depth --ignored --nocapture
/// ```
#[test]
#[ignore = "DIAGNOSTIC: prints a depth comparison for the WR-1 evidence section; asserts nothing about the dual-RNS route"]
fn exact_vs_dual_public_repeated_square_depth() {
    const MAX_ROUNDS: usize = 12;
    for (name, cfg) in named_configs() {
        if name == "secure_128_deep" {
            continue; // same tuple as secure_128
        }
        let ctx = RNSFHEContext::new(&cfg);

        // WR-1 exact route, main-Q only.
        let ev = ctx.try_exact_evaluator().expect("evaluator");
        let mut rng = ShadowHarvester::with_seed(0x00C0_1234);
        let keys = ctx.generate_keys(&mut rng);
        let gkey = ev.generate_hybrid_gadget_key_with_rng(&keys.secret_key, &mut rng);
        let mut ct = ctx.encrypt(3, &keys.public_key, &mut rng);
        let mut want = 3u64;
        let mut exact_depth = 0usize;
        for _ in 0..MAX_ROUNDS {
            let Ok(next) = ev.try_mul_exact(&ct, &ct, &gkey) else {
                break;
            };
            want = (want as u128 * want as u128 % cfg.t as u128) as u64;
            match ev.try_decrypt_exact(&next, &keys.secret_key) {
                Ok(got) if got == want => {
                    exact_depth += 1;
                    ct = next;
                }
                _ => break,
            }
        }

        // Existing dual-RNS public multiply, same start value and round cap.
        let mut rng = ShadowHarvester::with_seed(0x00C0_1234);
        let dual_keys = ctx.generate_keys_dual_full(&mut rng);
        let mut dct = ctx.encrypt_dual(3, &dual_keys.public_key, &mut rng);
        let mut dwant = 3u64;
        let mut dual_depth = 0usize;
        for _ in 0..MAX_ROUNDS {
            let Ok(next) = ctx.mul_dual_public(&dct, &dct, &dual_keys.eval_key) else {
                break;
            };
            dwant = (dwant as u128 * dwant as u128 % cfg.t as u128) as u64;
            match ctx.try_decrypt_dual(&next, &dual_keys.secret_key) {
                Ok(got) if got == dwant => {
                    dual_depth += 1;
                    dct = next;
                }
                _ => break,
            }
        }

        println!(
            "DEPTH {name}: WR-1 exact (main-Q only) = {exact_depth}; \
             existing mul_dual_public (main + serialized anchor) = {dual_depth}"
        );
    }
}

// ===========================================================================
// G7 — WIRE-Q
// ===========================================================================

/// **G7.** The exact route's output has exactly the shape `encrypt` produces:
/// same lane count, same ring degree, same limb lengths, canonical residues in
/// the published main lanes only. There is no auxiliary field to inspect
/// because there is no auxiliary field at all.
#[test]
fn wire_q_output_shape_is_identical_to_a_fresh_ciphertext() {
    let cfg = SecureConfig::secure_128().into_config();
    let ctx = RNSFHEContext::new(&cfg);
    let ev = ctx.try_exact_evaluator().expect("evaluator");
    let mut rng = ShadowHarvester::with_seed(0x717E_0001);
    let keys = ctx.generate_keys(&mut rng);
    let key = ev.generate_hybrid_gadget_key_with_rng(&keys.secret_key, &mut rng);

    let fresh = ctx.encrypt(7, &keys.public_key, &mut rng);
    let ct_b = ctx.encrypt(6, &keys.public_key, &mut rng);
    let prod = ev.try_mul_exact(&fresh, &ct_b, &key).expect("exact mul");

    assert_eq!(prod.num_primes, fresh.num_primes);
    assert_eq!(prod.c0.limbs.len(), fresh.c0.limbs.len());
    assert_eq!(prod.c1.limbs.len(), fresh.c1.limbs.len());
    assert_eq!(prod.c0.n, fresh.c0.n);
    assert_eq!(prod.c1.n, fresh.c1.n);
    for poly in [&prod.c0, &prod.c1] {
        assert_eq!(poly.limbs.len(), cfg.primes.len());
        for (limb, &q) in poly.limbs.iter().zip(cfg.primes.iter()) {
            assert_eq!(limb.len(), cfg.n);
            assert!(limb.iter().all(|&r| r < q), "residue outside its lane");
        }
    }

    // The output ciphertext validates against the ordinary contract.
    prod.validate(cfg.n, cfg.primes.len()).expect("valid ct");

    // Every published lane divides Q; none of the transient auxiliary lanes
    // appears anywhere in the emitted artifact.
    let aux = ev.plan().auxiliary_basis().to_vec();
    for &a in &aux {
        assert!(
            !cfg.primes.contains(&a),
            "auxiliary lane {a} must not be a published main lane"
        );
    }
    assert_eq!(prod.c0.limbs.len(), cfg.primes.len());
}

/// **G7.** The hybrid gadget key is main-`Q` only: one `RNSPolynomial` pair per
/// (lane, digit), each with exactly the published lane count, canonical
/// residues, and no auxiliary field.
#[test]
fn wire_q_gadget_key_carries_only_main_lanes() {
    let ring_n = 16;
    let primes = vec![998244353u64, 985661441, 754974721, 469762049];
    let cfg = small_ring_config(primes.clone(), ring_n);
    let ctx = RNSFHEContext::new(&cfg);
    let ev = ctx.try_exact_evaluator().expect("evaluator");
    let mut rng = ShadowHarvester::with_seed(0x717E_0002);
    let keys = ctx.generate_keys(&mut rng);
    let key = ev.generate_hybrid_gadget_key_with_rng(&keys.secret_key, &mut rng);

    assert_eq!(key.rlk.len(), primes.len());
    for per_lane in &key.rlk {
        for (rlk0, rlk1) in per_lane {
            for poly in [rlk0, rlk1] {
                assert_eq!(poly.limbs.len(), primes.len());
                assert_eq!(poly.n, ring_n);
                for (limb, &q) in poly.limbs.iter().zip(primes.iter()) {
                    assert_eq!(limb.len(), ring_n);
                    assert!(limb.iter().all(|&r| r < q));
                }
            }
        }
    }
    for &a in ev.plan().auxiliary_basis() {
        assert!(!primes.contains(&a));
    }
}

/// Structural shape refusals on the input side.
#[test]
fn malformed_ciphertext_shapes_are_refused() {
    let ring_n = 16;
    let primes = vec![998244353u64, 985661441, 754974721, 469762049];
    let cfg = small_ring_config(primes.clone(), ring_n);
    let ctx = RNSFHEContext::new(&cfg);
    let ev = ctx.try_exact_evaluator().expect("evaluator");
    let mut rng = ShadowHarvester::with_seed(0x717E_0003);
    let keys = ctx.generate_keys(&mut rng);
    let good = ctx.encrypt(3, &keys.public_key, &mut rng);

    let mut bad = good.clone();
    bad.num_primes = primes.len() - 1;
    assert!(matches!(
        ev.try_mul_no_relin_exact(&bad, &good),
        Err(ExactMulError::CiphertextShape {
            what: "num_primes",
            ..
        })
    ));

    let mut bad = good.clone();
    bad.c0.limbs.pop();
    assert!(matches!(
        ev.try_mul_no_relin_exact(&bad, &good),
        Err(ExactMulError::CiphertextShape {
            what: "limb count",
            ..
        })
    ));

    let mut bad = good.clone();
    bad.c0.limbs[0][0] = primes[0]; // not canonical
    assert!(matches!(
        ev.try_mul_no_relin_exact(&bad, &good),
        Err(ExactMulError::NonCanonicalMainResidue { lane: 0, .. })
    ));
}

/// The legacy fail-closed guard on `RNSFHEContext::mul` is untouched
/// (invariant 9): the exact route did not make the approximate one reachable.
#[test]
#[should_panic(expected = "RNSFHEContext::mul is unavailable")]
fn legacy_mul_guard_is_still_fail_closed() {
    let cfg = FHEConfig::light_rns_insecure();
    let ctx = RNSFHEContext::new(&cfg);
    assert_eq!(ctx.mul_route(), MulRoute::KElimDual);
    let mut rng = ShadowHarvester::with_seed(0x7115_0002);
    let keys = ctx.generate_keys(&mut rng);
    let a = ctx.encrypt(1, &keys.public_key, &mut rng);
    let b = ctx.encrypt(1, &keys.public_key, &mut rng);
    let _ = ctx.mul(&a, &b, &keys.eval_key);
}

/// `mul_route()` must not start returning the exact route: WR-1 is explicitly
/// constructed, never auto-selected.
#[test]
fn exact_route_is_never_auto_selected() {
    for (_, cfg) in named_configs() {
        let ctx = RNSFHEContext::new(&cfg);
        assert_ne!(ctx.mul_route(), MulRoute::DerivedTransientExact);
        assert_eq!(
            ctx.try_exact_evaluator().expect("evaluator").route(),
            MulRoute::DerivedTransientExact
        );
    }
    let ctx = RNSFHEContext::new(&FHEConfig::light_rns_insecure());
    assert_ne!(ctx.mul_route(), MulRoute::DerivedTransientExact);
}

// ===========================================================================
// Security prerequisite — full-width uniform key sampling
// ===========================================================================

/// The single-RNS `a` sampler must range over `[0, Q)`, not over `[0, 2^64)`
/// reduced into every lane.
///
/// Non-vacuous by construction: with a one-`u64`-per-coefficient draw, every
/// lane's residue is a function of the SAME 64-bit value, so across `n`
/// coefficients the pairs `(r_0, r_1)` would lie on at most `2^64` points and,
/// far more visibly, `r_i = v mod q_i` with `v < 2^64` would make the top lane
/// residues collide with a detectable pattern. The direct check below is
/// stronger and simpler: reconstruct the sampled integer from two lanes and
/// confirm it exceeds `2^64`, which a `u64` draw can never do.
#[test]
fn single_rns_uniform_sampler_covers_the_whole_main_modulus() {
    let cfg = SecureConfig::secure_128().into_config();
    let ctx = RNSFHEContext::new(&cfg);
    let mut rng = ShadowHarvester::with_seed(0x5A11_0001);
    let poly = ctx.sample_uniform_main_poly(&mut rng);
    let oracle = BigOracle::new(&cfg.primes, cfg.n, cfg.t);

    let mut wide = 0usize;
    for k in 0..cfg.n {
        let residues: Vec<u64> = poly.limbs.iter().map(|l| l[k]).collect();
        for (&r, &q) in residues.iter().zip(cfg.primes.iter()) {
            assert!(r < q, "sampler produced a non-canonical residue");
        }
        if oracle.crt(&residues).bit_length() > 64 {
            wide += 1;
        }
    }
    // A u64-reduced draw gives ZERO coefficients above 64 bits. Uniform over
    // [0, Q) with log2(Q) = 119 gives essentially all of them.
    assert!(
        wide * 100 > cfg.n * 99,
        "only {wide}/{} coefficients exceeded 2^64; the sampler is not \
         uniform over [0, Q)",
        cfg.n
    );
}
