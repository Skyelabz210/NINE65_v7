//! Exact integer convolution for small gadget digits. This auxiliary field
//! is a transient computational representation, never a ciphertext lane or
//! an additional independent root. Public integer bounds prevent aliasing.

use super::*;
use std::sync::{Arc, Mutex, OnceLock};

const AUX: u64 = 0xffff_ffff_0000_0001;
const EPSILON: u64 = 0xffff_ffff;

#[inline]
fn mul(a: u64, b: u64) -> u64 {
    let product = a as u128 * b as u128;
    let high = (product >> 64) as u64;
    // 2^64 = 2^32-1 mod AUX, and (2^32-1)*2^32 = -1.
    // Canonical inputs give 0 <= r < 3*AUX; no hot-path division.
    let mut r = product as u64 as u128 + ((high & EPSILON) * EPSILON) as u128 + AUX as u128
        - (high >> 32) as u128;
    if r >= AUX as u128 {
        r -= AUX as u128;
    }
    if r >= AUX as u128 {
        r -= AUX as u128;
    }
    r as u64
}

#[inline]
fn plus(a: u64, b: u64) -> u64 {
    let sum = a as u128 + b as u128;
    if sum >= AUX as u128 {
        (sum - AUX as u128) as u64
    } else {
        sum as u64
    }
}

#[inline]
fn minus(a: u64, b: u64) -> u64 {
    if a >= b {
        a - b
    } else {
        AUX - (b - a)
    }
}

fn certify_field() {
    static CERTIFICATE: OnceLock<()> = OnceLock::new();
    CERTIFICATE.get_or_init(|| {
        let factors = [2u64, 3, 5, 17, 257, 65537];
        assert_eq!(
            (1u128 << 32) * factors[1..].iter().map(|&r| r as u128).product::<u128>(),
            AUX as u128 - 1
        );
        for &r in &factors {
            assert!((2..).take_while(|&d| d * d <= r).all(|d| r % d != 0));
        }
        let gcd = |mut a: u64, mut b: u64| {
            while b != 0 {
                (a, b) = (b, a % b);
            }
            a
        };
        assert_eq!(mod_pow(7, AUX - 1, AUX), 1);
        for r in factors {
            assert_eq!(gcd(mod_pow(7, (AUX - 1) / r, AUX) - 1, AUX), 1);
        }
        // Fully factored AUX-1 and this Lucas witness certify primality
        // and the order of 7. No probabilistic primality assumption.
    });
}

pub(super) struct Plan {
    n: usize,
    reversed: Vec<usize>,
    twist: Vec<u64>,
    inverse_twist_scaled: Vec<u64>,
    forward_roots: Vec<Vec<u64>>,
    inverse_roots: Vec<Vec<u64>>,
}

impl Plan {
    fn new(n: usize) -> Self {
        certify_field();
        assert!(n >= 2 && n.is_power_of_two() && n <= 1usize << 31);
        let psi = mod_pow(7, (AUX - 1) / (2 * n) as u64, AUX);
        assert_eq!(mod_pow(psi, n as u64, AUX), AUX - 1);
        let inverse_psi = mod_pow(psi, AUX - 2, AUX);
        let inverse_n = mod_pow(n as u64, AUX - 2, AUX);
        let powers = |value, initial, count| {
            let mut x = initial;
            (0..count)
                .map(|_| {
                    let old = x;
                    x = mul(x, value);
                    old
                })
                .collect::<Vec<_>>()
        };
        let omega = mul(psi, psi);
        let inverse_omega = mul(inverse_psi, inverse_psi);
        let stages = |root| {
            (1..=n.ilog2())
                .map(|stage| {
                    let len = 1usize << stage;
                    powers(mod_pow(root, (n / len) as u64, AUX), 1, len / 2)
                })
                .collect()
        };
        Self {
            n,
            reversed: (0..n)
                .map(|i| i.reverse_bits() >> (usize::BITS - n.ilog2()))
                .collect(),
            twist: powers(psi, 1, n),
            inverse_twist_scaled: powers(inverse_psi, inverse_n, n),
            forward_roots: stages(omega),
            inverse_roots: stages(inverse_omega),
        }
    }

    fn cyclic(&self, values: &mut [u64], roots: &[Vec<u64>]) {
        assert_eq!(values.len(), self.n);
        for (i, &j) in self.reversed.iter().enumerate() {
            if i < j {
                values.swap(i, j);
            }
        }
        for roots in roots {
            let half = roots.len();
            for block in values.chunks_exact_mut(2 * half) {
                let (left, right) = block.split_at_mut(half);
                for ((a, b), &root) in left.iter_mut().zip(right).zip(roots) {
                    let u = *a;
                    let v = mul(*b, root);
                    *a = plus(u, v);
                    *b = minus(u, v);
                }
            }
        }
    }

    pub(super) fn forward(&self, values: &[u64]) -> Vec<u64> {
        assert_eq!(values.len(), self.n);
        assert!(values.iter().all(|&v| v < AUX));
        let mut out: Vec<_> = values
            .iter()
            .zip(&self.twist)
            .map(|(&v, &t)| mul(v, t))
            .collect();
        self.cyclic(&mut out, &self.forward_roots);
        out
    }

    pub(super) fn backward(&self, values: &[u64]) -> Vec<u64> {
        let mut out = values.to_vec();
        self.cyclic(&mut out, &self.inverse_roots);
        for (v, &scale) in out.iter_mut().zip(&self.inverse_twist_scaled) {
            *v = mul(*v, scale);
        }
        out
    }

    pub(super) fn shared(n: usize) -> Arc<Self> {
        static PLANS: OnceLock<Mutex<BTreeMap<usize, Arc<Plan>>>> = OnceLock::new();
        let mut plans = PLANS
            .get_or_init(|| Mutex::new(BTreeMap::new()))
            .lock()
            .unwrap();
        plans
            .entry(n)
            .or_insert_with(|| Arc::new(Self::new(n)))
            .clone()
    }
}

// Separate representation from the main-prime NTT rows. An observer must
// inverse-transform with THIS plan before reducing back to the main lane.
pub(super) struct AuxiliaryRow {
    pub(super) c0: Vec<Vec<u64>>,
    pub(super) c1: Vec<Vec<u64>>,
}

pub(super) fn integer_bound(n: usize, digit_sum: u128, primes: &[u64]) -> Option<u128> {
    if n < 2 || !n.is_power_of_two() || n > 1usize << 31 {
        return None;
    }
    let maximum = *primes.iter().max()?;
    let bound = (n as u128)
        .checked_mul(digit_sum)?
        .checked_mul(maximum.checked_sub(1)? as u128)?;
    if bound.checked_mul(2)? < AUX as u128 {
        Some(bound)
    } else {
        None
    }
}

pub(super) fn accumulate(out: &mut [u64], digit: &[u64], row: &[u64]) {
    assert_eq!(out.len(), digit.len());
    assert_eq!(out.len(), row.len());
    for ((x, &d), &r) in out.iter_mut().zip(digit).zip(row) {
        *x = plus(*x, mul(d, r));
    }
}

pub(super) fn reduce_signed(value: u64, q: u64, bound: u128) -> u64 {
    assert!(2 * bound < AUX as u128);
    if value > AUX / 2 {
        let magnitude = AUX - value;
        assert!(
            magnitude as u128 <= bound,
            "integer convolution exceeded its public bound"
        );
        let residue = magnitude % q;
        if residue == 0 {
            0
        } else {
            q - residue
        }
    } else {
        assert!(
            value as u128 <= bound,
            "integer convolution exceeded its public bound"
        );
        value % q
    }
}

#[test]
fn auxiliary_field_certificate_and_wide_product_boundaries() {
    certify_field();
    let edges = [0, 1, 2, EPSILON, 1u64 << 32, AUX / 2, AUX - 2, AUX - 1];
    for a in edges {
        for b in edges {
            assert_eq!(mul(a, b), (a as u128 * b as u128 % AUX as u128) as u64);
            assert_eq!(plus(a, b), ((a as u128 + b as u128) % AUX as u128) as u64);
            assert_eq!(
                minus(a, b),
                (a as i128 - b as i128).rem_euclid(AUX as i128) as u64
            );
        }
    }
    let mut rng = ShadowHarvester::with_seed(0x474f_4c44_5052_4f44);
    for _ in 0..20000 {
        let a = rng.next_u64() % AUX;
        let b = rng.next_u64() % AUX;
        assert_eq!(mul(a, b), (a as u128 * b as u128 % AUX as u128) as u64);
    }
    assert!(integer_bound(16384, 30000, &[2130706433]).is_some());
    assert!(integer_bound(16384, u128::MAX, &[2130706433]).is_none());
    assert!(integer_bound(16384, 1u128 << 60, &[2130706433]).is_none());
}

#[test]
fn auxiliary_negacyclic_transform_matches_signed_schoolbook() {
    let mut rng = ShadowHarvester::with_seed(0x4e45_4741_4359_434c);
    for n in [2usize, 8, 32, 128] {
        let plan = Plan::shared(n);
        let a: Vec<_> = (0..n).map(|_| rng.next_u64() % 1024).collect();
        let b: Vec<_> = (0..n).map(|_| rng.next_u64() % 2130706433).collect();
        assert_eq!(plan.backward(&plan.forward(&a)), a);
        let mut transformed = vec![0; n];
        accumulate(&mut transformed, &plan.forward(&a), &plan.forward(&b));
        let actual = plan.backward(&transformed);
        let mut expected = vec![0i128; n];
        for (i, &x) in a.iter().enumerate() {
            for (j, &y) in b.iter().enumerate() {
                expected[(i + j) % n] += (if i + j < n { 1 } else { -1 }) * x as i128 * y as i128;
            }
        }
        for (x, e) in actual.iter().zip(expected) {
            assert_eq!(*x, e.rem_euclid(AUX as i128) as u64);
            for q in [998244353, 2130706433] {
                assert_eq!(
                    reduce_signed(*x, q, n as u128 * 1023 * 2130706432),
                    e.rem_euclid(q as i128) as u64
                );
            }
        }
    }
}

#[test]
#[ignore = "opt-in full-size exact raw-switch comparison and measured kernel cost"]
fn auxiliary_native_raw_switch_matches_all_main_prime_components() {
    use std::time::Instant;
    let mut config = SecureConfig::secure_128().into_config();
    config.n = 16384;
    config
        .primes
        .extend([1811939329, 2113929217, 2130706433, 1107296257]);
    config.security_bits = 0;
    config.name = "PUBLIC algebra-only native raw-switch benchmark";
    let ctx = RNSFHEContext::try_new(&config).unwrap();
    let engine = Engine {
        ctx: &ctx,
        switches: Cell::new(0),
    };
    let shape = Shape::new(&ctx, 10);
    let mut rng = ShadowHarvester::with_seed(0x5241_5743_4f4d_5041);
    let mut polynomial = || {
        montgomery(
            &ctx,
            config
                .primes
                .iter()
                .map(|&q| (0..ctx.n).map(|_| rng.next_u64() % q).collect())
                .collect(),
        )
    };
    let rows: Vec<_> = (0..shape.digits.iter().sum())
        .map(|_| RNSCiphertext {
            c0: polynomial(),
            c1: polynomial(),
            num_primes: config.primes.len(),
        })
        .collect();
    let component = polynomial();
    let reference = engine.cache_main_prime(&shape, &rows, 3);
    let accelerated = engine.cache(&shape, &rows, 3);
    assert!(matches!(accelerated.rows, CachedRows::SmallDigit { .. }));
    let mut reference_times = Vec::new();
    let mut accelerated_times = Vec::new();
    for _ in 0..3 {
        let start = Instant::now();
        let expected = engine.switch(&component, &reference);
        reference_times.push(start.elapsed());
        let start = Instant::now();
        let actual = engine.switch(&component, &accelerated);
        accelerated_times.push(start.elapsed());
        assert_eq!(actual.c0.limbs, expected.c0.limbs);
        assert_eq!(actual.c1.limbs, expected.c1.limbs);
    }
    reference_times.sort_unstable();
    accelerated_times.sort_unstable();
    let digits: usize = shape.digits.iter().sum();
    let ratio_milli = reference_times[1].as_nanos() * 1000 / accelerated_times[1].as_nanos().max(1);
    eprintln!("native raw-switch exact comparison: N={}, lanes={}, rows={digits}, integer bound={}, coefficient words/key={}, all components bit-identical; main-prime transforms={}, auxiliary transforms={}, main median={:?}, auxiliary median={:?}, ratio={}.{:03}x; three repetitions, public random rows only, NOT encrypted bootstrap timing",ctx.n,config.primes.len(),integer_bound(ctx.n,shape.digit_sum,&config.primes).unwrap(),2*ctx.n*config.primes.len()*digits,(digits+2)*config.primes.len(),digits+2*config.primes.len(),reference_times[1],accelerated_times[1],ratio_milli/1000,ratio_milli%1000);
}
