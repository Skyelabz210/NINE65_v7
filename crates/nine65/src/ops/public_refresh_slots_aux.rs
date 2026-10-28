//! Exact integer convolution for small gadget digits. This auxiliary field
//! is a transient computational representation, never a ciphertext lane or
//! an additional independent root. Public integer bounds prevent aliasing.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, OnceLock};

pub(super) const AUX: u64 = 0xffff_ffff_0000_0001;
const EPSILON: u64 = 0xffff_ffff;

fn mod_pow(mut a: u64, mut e: u64, q: u64) -> u64 {
    let mut out = 1u64;
    while e != 0 {
        if e & 1 != 0 {
            out = (out as u128 * a as u128 % q as u128) as u64;
        }
        a = (a as u128 * a as u128 % q as u128) as u64;
        e >>= 1;
    }
    out
}

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
    pub(super) fn new(n: usize) -> Self {
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

// Each sum is a signed INTEGER convolution, provided the public batch
// capacity is < AUX/2. This is not an additional RLWE modulus.
pub(super) fn accumulate(out: &mut [u64], left: &[u64], right: &[u64]) {
    for ((sum, &a), &b) in out.iter_mut().zip(left).zip(right) {
        *sum = plus(*sum, mul(a, b));
    }
}

pub(super) fn signed(value: u64, bound: u128) -> i128 {
    let value = if value > AUX / 2 {
        value as i128 - AUX as i128
    } else {
        value as i128
    };
    assert!(
        value.unsigned_abs() <= bound,
        "small-plaintext convolution exceeded certified integer capacity"
    );
    value
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn signed_batched_convolution_matches_schoolbook() {
        const N: usize = 32;
        let plan = Plan::new(N);
        let mut transformed = vec![0; N];
        let mut oracle = vec![0i128; N];
        for batch in 0..7 {
            let a: Vec<_> = (0..N)
                .map(|j| ((j * 991 + batch * 97) % ((1 << 24) - 1)) as u64)
                .collect();
            let b: Vec<_> = (0..N)
                .map(|j| ((j * 19 + batch * 7) % 65537) as i128 - 32768)
                .collect();
            let encoded: Vec<_> = b
                .iter()
                .map(|&x| x.rem_euclid(AUX as i128) as u64)
                .collect();
            accumulate(&mut transformed, &plan.forward(&a), &plan.forward(&encoded));
            for i in 0..N {
                for j in 0..N {
                    let sign = if i + j < N { 1 } else { -1 };
                    oracle[(i + j) % N] += sign * a[i] as i128 * b[j];
                }
            }
        }
        let bound = 7 * N as u128 * 32768 * ((1u128 << 24) - 1);
        let actual: Vec<_> = plan
            .backward(&transformed)
            .into_iter()
            .map(|v| signed(v, bound))
            .collect();
        assert_eq!(actual, oracle);
    }

    #[test]
    fn native_batch_capacity_matches_closed_form_at_extreme_words() {
        const N: usize = 32_768;
        const BATCH: u128 = 256;
        const WORD: u128 = (1 << 24) - 1;
        const PLAIN: u128 = 32_768;
        let plan = Plan::new(N);
        let left = plan.forward(&vec![WORD as u64; N]);
        let right = plan.forward(&vec![PLAIN as u64; N]);
        let mut sums = vec![0; N];
        for _ in 0..BATCH {
            accumulate(&mut sums, &left, &right);
        }
        let bound = BATCH * N as u128 * WORD * PLAIN;
        assert!(2 * bound < AUX as u128);
        for (i, value) in plan.backward(&sums).into_iter().enumerate() {
            // For constant polynomials, coefficient i has i+1 positive
            // products and N-i-1 wrapped negative products.
            let expected = (BATCH * WORD * PLAIN) as i128 * (2 * i as i128 + 2 - N as i128);
            assert_eq!(signed(value, bound), expected);
        }
    }
}

const CHUNK_BITS: usize = 24;
const CHUNK_MASK: u64 = (1u64 << CHUNK_BITS) - 1;

#[derive(Clone, Copy)]
struct ChunkSpec {
    component: usize,
    lane: usize,
    shift: usize,
}
struct CachedChunks {
    values: Vec<Vec<u64>>,
}

impl super::PublicSlotReturn<'_> {
    /// Exact shared small-plaintext transform. Each ciphertext coefficient
    /// is split into 24-bit unsigned words; all words and all main lanes
    /// reuse ONE plaintext transform. The full baby batch is certified below
    /// AUX/2 before any coefficient can be reconstructed.
    pub(super) fn apply_auxiliary(
        &self,
        input: &super::RNSCiphertext,
        keys: &super::SlotReturnKeys,
        progress: &mut dyn FnMut(&str, usize, usize),
    ) -> super::Nine65Result<super::RNSCiphertext> {
        super::validate_main(self.ctx, input)?;
        let bound = (2 * self.baby_count) as u128
            * self.ctx.n as u128
            * (self.ctx.t / 2) as u128
            * CHUNK_MASK as u128;
        if 2 * bound >= AUX as u128 {
            return Err(super::failure(
                "slot return auxiliary convolution does not fit its exact field",
            ));
        }
        let plan = Plan::shared(self.ctx.n);
        let mut specifications = Vec::new();
        for component in 0..2 {
            for (lane, &q) in self.ctx.config.primes.iter().enumerate() {
                for digit in 0..(64 - q.leading_zeros() as usize).div_ceil(CHUNK_BITS) {
                    specifications.push(ChunkSpec {
                        component,
                        lane,
                        shift: digit * CHUNK_BITS,
                    });
                }
            }
        }
        let cache = |ct: &super::RNSCiphertext| {
            let components = [&ct.c0, &ct.c1];
            CachedChunks {
                values: specifications
                    .iter()
                    .map(|spec| {
                        let mont = &self.ctx.rns.mont_contexts[spec.lane];
                        let values: Vec<_> = components[spec.component].limbs[spec.lane]
                            .iter()
                            .map(|&v| (mont.from_montgomery(v) >> spec.shift) & CHUNK_MASK)
                            .collect();
                        plan.forward(&values)
                    })
                    .collect(),
            }
        };
        let mut babies = Vec::with_capacity(2 * self.baby_count);
        for sign in 0..2 {
            let mut current = if sign == 0 {
                input.clone()
            } else {
                self.galois.apply_prepared(input, &keys.conjugate)?
            };
            for baby in 0..self.baby_count {
                if baby != 0 {
                    current = self.galois.apply_prepared(&current, &keys.baby_step)?;
                }
                babies.push(cache(&current));
                progress("inverse babies", babies.len(), 2 * self.baby_count);
            }
        }
        let mut output = None;
        let mut observed_plain_l1 = 0u128;
        let workers = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1)
            .min(8);
        for giant in (0..self.giant_count).rev() {
            let mut diagonals = Vec::with_capacity(babies.len());
            for sign in 0..2 {
                for baby in 0..self.baby_count {
                    let diagonal = self.diagonal(giant, sign, baby)?;
                    observed_plain_l1 += diagonal
                        .iter()
                        .map(|&v| v.min(self.ctx.t - v) as u128)
                        .sum::<u128>();
                    let signed: Vec<_> = diagonal
                        .into_iter()
                        .map(|v| {
                            if v <= self.ctx.t / 2 {
                                v
                            } else {
                                AUX - (self.ctx.t - v)
                            }
                        })
                        .collect();
                    diagonals.push(plan.forward(&signed));
                }
            }
            let mut sums = vec![vec![0; self.ctx.n]; specifications.len()];
            let chunk_size = sums.len().div_ceil(workers);
            std::thread::scope(|scope| {
                for (block, part) in sums.chunks_mut(chunk_size).enumerate() {
                    let babies = &babies;
                    let diagonals = &diagonals;
                    scope.spawn(move || {
                        for (offset, sum) in part.iter_mut().enumerate() {
                            for (baby, diagonal) in babies.iter().zip(diagonals) {
                                accumulate(
                                    sum,
                                    &baby.values[block * chunk_size + offset],
                                    diagonal,
                                );
                            }
                        }
                    });
                }
            });
            let zero = || vec![vec![0u64; self.ctx.n]; self.ctx.config.primes.len()];
            let mut components = [zero(), zero()];
            for (spec, sum) in specifications.iter().zip(&sums) {
                let q = self.ctx.config.primes[spec.lane];
                let scale = ((1u128 << spec.shift) % q as u128) as u64;
                let mont = &self.ctx.rns.mont_contexts[spec.lane];
                let scale = mont.to_montgomery(scale);
                for (out, value) in components[spec.component][spec.lane]
                    .iter_mut()
                    .zip(plan.backward(sum))
                {
                    let value = signed(value, bound).rem_euclid(q as i128) as u64;
                    let term = mont.montgomery_mul(value, scale);
                    let total = *out as u128 + term as u128;
                    *out = if total >= q as u128 {
                        (total - q as u128) as u64
                    } else {
                        total as u64
                    };
                }
            }
            for lanes in &mut components {
                for (lane, values) in lanes.iter_mut().enumerate() {
                    for value in values {
                        *value = self.ctx.rns.mont_contexts[lane].to_montgomery(*value);
                    }
                }
            }
            let [c0, c1] = components;
            let sum = super::RNSCiphertext {
                c0: super::RNSPolynomial {
                    limbs: c0,
                    n: self.ctx.n,
                },
                c1: super::RNSPolynomial {
                    limbs: c1,
                    n: self.ctx.n,
                },
                num_primes: self.ctx.config.primes.len(),
            };
            output = Some(match output {
                None => sum,
                Some(previous) => self.ctx.add(
                    &self.galois.apply_prepared(&previous, &keys.giant_step)?,
                    &sum,
                ),
            });
            progress("inverse giants", self.giant_count - giant, self.giant_count);
        }
        if observed_plain_l1 > self.certificate.input_error_factor {
            return Err(super::failure(
                "slot return plaintext norm exceeded its preflight certificate",
            ));
        }
        output.ok_or_else(|| super::failure("empty slot return schedule"))
    }
}
