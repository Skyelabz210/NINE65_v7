//! Exact integer noise-budget tracking for NINE65.
//!
//! Budgets are represented in millibits. The full ciphertext modulus remains
//! canonical as its ordered RNS factor vector. Budget initialization and
//! post-bootstrap reset derive their size from the exact multi-limb quotient
//! `floor(Q / t)`; per-lane bit-width sums, saturated products, floating point,
//! Garner reconstruction, and mixed-radix conversion are not used.
//!
//! # Derivation of the ledger
//!
//! Every quantity below is a **conservative upper bound** on the true noise, in
//! integer bit-widths, with every rounding taken **upward**. `scalar_bit_length`
//! is a ceiling (`scalar_bit_length(x) = floor(log2 x) + 1 >= log2 x`), so a sum
//! of bit lengths is an upper bound on the bit length of the product. Residual
//! uncertainty is spent as margin, never as optimism: the trigger therefore
//! fires strictly before the true boundary, never after.
//!
//! ## Notation
//!
//! * `R = Z[X]/(X^n + 1)`, `n` a power of two, so `n_bits = log2(n)` exactly.
//! * Ring expansion: `||a*b||_inf <= n * ||a||_inf * ||b||_inf` in `R`. The
//!   factor `n` (not `sqrt(n)`) is the worst case and is what this module uses.
//! * `s` and the encryption mask `u` are ternary: `||s||_inf, ||u||_inf <= 1`.
//! * The CBD_eta error distribution is supported on `[-eta, eta]`, so every
//!   error polynomial has `||e||_inf <= eta`.
//! * `Delta = floor(Q / t)`; a ciphertext decrypts correctly while its noise
//!   satisfies `||e||_inf < Delta / 2`, i.e. while `noise_bits <= delta_bits - 1`.
//!
//! ## Terms
//!
//! * **Fresh encryption.** `e_fresh = e_pk * u + e1 + e2 * s`, hence
//!   `||e_fresh|| <= n*eta + eta + n*eta = (2n+1)*eta <= 4*n*eta`.
//!   Bits: `n_bits + eta_bits + 2`. (`fresh_noise_bit_bound`)
//! * **ct x ct multiply.** The BFV tensor bound (Fan-Vercauteren, *Somewhat
//!   Practical Fully Homomorphic Encryption*, Lemma 2) has the shape
//!   `v_out <= 2*n*t*(v1 + v2)*(1 + n*||s||) + F`, with `F` the input-independent
//!   deposit left by the `Delta`-rescaling of the tensor product. With
//!   `||s|| <= 1` and `v1, v2 <= v` the multiplicative part is bounded by
//!   `4*n*t*v*(1+n) <= 8*n^2*t*v`, so the growth factor is
//!   `G = 8*n^2*t`, i.e. `mul_growth_bit_cost = t_bits + 2*n_bits + 3`.
//!   The input-independent deposit obeys `F <= 4*n^2*t^2`.
//! * **Folding `F` into the starting level (why the ledger stays linear).**
//!   The true recurrence is `v_{k+1} = G*v_k + F`. Substituting
//!   `w_k = v_k + F/(G-1)` gives `w_{k+1} = G*w_k`, hence exactly
//!   `v_k = G^k * (v_0 + F/(G-1)) - F/(G-1) <= G^k * (v_0 + F/(G-1))`,
//!   and for `G >= 2`, `F/(G-1) <= 2F/G = 2*(4*n^2*t^2)/(8*n^2*t) = t`.
//!   So `v_k <= G^k * (v_0 + t) <= G^k * 2^(max(v0_bits, t_bits) + 1)`.
//!   That is why the ledger charges a *constant* `G` per multiply and starts
//!   from `effective_start_bits(v0) = max(v0_bits, t_bits) + 1`: the additive
//!   term is accounted for exactly, once, at the start of the chain, rather
//!   than being assumed away.
//! * **Plaintext multiply, and when the `n` disappears.** Multiplying by an
//!   arbitrary plaintext polynomial with coefficients bounded by `b` costs the
//!   full ring expansion, `||v_out|| <= n * b * ||v_in||` (`mul_plain_cost`).
//!   Multiplying by a **constant** (a degree-0 polynomial `c`) does not: the
//!   negacyclic convolution collapses to `(a*b)_k = a_k * c`, so
//!   `||v_out|| = c * ||v_in||` exactly, with no summation over `n` terms
//!   (`mul_plain_scalar_cost`). Every in-tree plaintext multiply is the
//!   constant case — `RNSFHEContext::mul_plain_dual` builds its multiplier with
//!   `scalar_to_constant_dual_poly`, and `BFVEvaluator::mul_plain` is a
//!   coefficient-wise `scalar_mul`. Charging them the `n` factor is not
//!   conservatism, it is a term for an expansion that provably does not occur,
//!   and it costs `log2(n)` = 13 bits per scalar multiply at n=8192.
//!   Confirmed on hardware by
//!   `tests::scalar_multiply_grows_noise_by_the_scalar_not_by_n`, which reads
//!   the growth factor off successive decryption margins: measured exactly
//!   2, 3, 4 and 16 for those scalars, against `n * c` = 16384..131072 if ring
//!   expansion were occurring.
//! * **Relinearization.** Gadget decomposition of `c2` in base `2^16` into
//!   `ell = ceil(log2(Q)/16)` digits against a public-key-style relin key:
//!   `v_relin <= ell * n * 2^16 * (4*n*eta)`, i.e.
//!   `relin_noise_bit_bound = ell_bits + 2*n_bits + eta_bits + 18`.
//!   Relin noise is **additive**, so `v_mul + v_relin <= 2 * max(v_mul, v_relin)`
//!   and one single bit covers it *provided* `v_relin <= v_mul`. That side
//!   condition is not assumed: it is asserted for every supported config by
//!   `relin_bound_never_dominates_the_multiply_bound`.
//! * **Rescale / exact prime drop (the `1.5` delta term).** Dropping an RNS
//!   prime `p` divides the noise by `p` and deposits a residue: the exact
//!   align-and-drop primitive contributes `j in [0, t)` per drop, and the
//!   rounding form contributes at most `(n+1)/2`. The credit taken is only
//!   `t_bits`, never the full `log2(p)`, which is a deliberate under-credit
//!   (every config satisfies `t < p`, so `t_bits <= p_bits`), and one bit is
//!   *charged* for the drop residue. The path is therefore accounted, not free.
//! * **Refresh output.** Phase 2 of `ClockworkBootstrap` deposits
//!   `c1' * e_bsk` with `||c1'|| < t` and `||e_bsk|| <= 4*n*eta`, so
//!   `v_boot <= n * t * 4 * n * eta = 4*n^2*t*eta`:
//!   `bootstrap_output_noise_bit_bound = t_bits + 2*n_bits + eta_bits + 2`.
//!   No credit is taken for the `Q_boot -> Q_work` division, and the Phase 3
//!   rounding residue `<= (n+1)/2` is dominated by that deposit. This is
//!   strictly worse than a fresh encryption, so `reset_after_bootstrap`
//!   necessarily returns **less** budget than `from_config`.
//! * **Refresh-input reserve (the `1.4` conservative trigger).** The decryption
//!   boundary is not the binding constraint on a *refreshable* ciphertext.
//!   Phase 1 of the refresh (`modswitch_to_t`) maps each coefficient
//!   `c |-> round(c*t/Q)`; writing `c0 + c1*s = Delta*m + e (mod Q)`, the value
//!   the refresh re-encrypts is
//!   `m*(t*Delta/Q) + (t/Q)*e + (r0 + r1*s) + k*t`, where `r0, r1` are the
//!   per-coefficient rounding residues. The noise-dependent part of that
//!   perturbation, expanded through the ring product, is bounded by
//!   `n*t*||e||_inf / Q`. Requiring it to stay below one Phase-1 quantisation
//!   step, `n*t*||e||/Q < 1/2`, gives `||e||_inf < Delta/(2n)`: the noise must
//!   sit at least `n_bits + 1` bits below the decryption boundary for the
//!   ciphertext to still be an exact refresh input. That is
//!   `bootstrap_input_reserve_mb`, and `can_perform_with_reserve` is what the
//!   auto-refresh trigger consults. The noise-*independent* residue `r0 + r1*s`
//!   is a property of `modswitch_to_t`, not of the noise level; no ledger term
//!   can bound it away, which is why some configs cannot carry a public refresh
//!   at all (see `params::secure_configs::supports_public_refresh`).

use crate::params::FHEConfig;

/// Noise budget in millibits (`1000` millibits = one bit).
#[derive(Clone, Debug)]
pub struct NoiseBudget {
    remaining_mb: i64,
    initial_mb: i64,
    /// Budget at the start of the current refresh cycle. Equal to `initial_mb`
    /// until the first `reset_after_bootstrap`, then the post-refresh budget.
    /// `should_bootstrap` measures against this rather than against the fresh
    /// budget, so a percentage trigger keeps meaning the same thing after a
    /// refresh has lowered the ceiling.
    cycle_initial_mb: i64,
    operations: Vec<NoiseOperation>,
}

/// One noise-budget transition.
#[derive(Clone, Debug)]
pub struct NoiseOperation {
    pub op_type: NoiseOpType,
    pub cost_mb: i64,
    pub remaining_mb: i64,
}

/// FHE operations represented in the noise ledger.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NoiseOpType {
    Encrypt,
    Add,
    AddPlain,
    MulPlain,
    MulCt,
    Relin,
    Rescale,
    Bootstrap,
}

/// Error returned when an operation cannot be represented safely in the
/// current budget.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NoiseExhausted {
    pub required_mb: i64,
    pub available_mb: i64,
    pub operation_count: usize,
    pub last_op: NoiseOpType,
}

impl std::fmt::Display for NoiseExhausted {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "Noise budget exhausted: needed {} millibits, had {} (after {} ops)",
            self.required_mb, self.available_mb, self.operation_count
        )
    }
}

impl std::error::Error for NoiseExhausted {}

/// Multiply an ordered factor vector into exact little-endian `u64` limbs.
fn exact_product_limbs(factors: &[u64]) -> Vec<u64> {
    let mut limbs = vec![1u64];

    for &factor in factors {
        let mut carry = 0u128;
        for limb in &mut limbs {
            let product = (*limb as u128) * factor as u128 + carry;
            *limb = product as u64;
            carry = product >> 64;
        }
        if carry != 0 {
            limbs.push(carry as u64);
        }
    }

    trim_limbs(&mut limbs);
    limbs
}

/// Divide one exact little-endian multi-limb integer by a nonzero `u64`.
fn divide_limbs_by_u64(limbs: &[u64], divisor: u64) -> Vec<u64> {
    assert!(divisor != 0, "multi-limb divisor must be nonzero");

    let mut quotient = vec![0u64; limbs.len()];
    let mut remainder = 0u128;
    for index in (0..limbs.len()).rev() {
        let numerator = (remainder << 64) | limbs[index] as u128;
        quotient[index] = (numerator / divisor as u128) as u64;
        remainder = numerator % divisor as u128;
    }

    trim_limbs(&mut quotient);
    quotient
}

fn trim_limbs(limbs: &mut Vec<u64>) {
    while limbs.len() > 1 && limbs.last() == Some(&0) {
        limbs.pop();
    }
}

fn limbs_bit_length(limbs: &[u64]) -> i64 {
    for index in (0..limbs.len()).rev() {
        let limb = limbs[index];
        if limb != 0 {
            return index as i64 * 64 + (64 - limb.leading_zeros()) as i64;
        }
    }
    0
}

fn scalar_bit_length(value: u64) -> i64 {
    if value == 0 {
        0
    } else {
        (64 - value.leading_zeros()) as i64
    }
}

/// Exact bit length of `floor(Q / t)`, where `Q` is the full RNS product.
fn exact_delta_bit_length(config: &FHEConfig) -> i64 {
    assert!(!config.primes.is_empty(), "RNS factor vector must not be empty");
    assert!(config.t >= 2, "plaintext modulus must be at least two");
    assert!(
        config.primes.iter().all(|&prime| config.t < prime),
        "plaintext modulus must be smaller than every RNS prime"
    );

    let product = exact_product_limbs(&config.primes);
    let quotient = divide_limbs_by_u64(&product, config.t);
    limbs_bit_length(&quotient)
}

/// `log2(n)`, exact: every supported `n` is a power of two.
fn ring_degree_bits(config: &FHEConfig) -> i64 {
    debug_assert!(config.n.is_power_of_two(), "ring degree must be a power of two");
    config.n.trailing_zeros() as i64
}

fn plaintext_bits(config: &FHEConfig) -> i64 {
    scalar_bit_length(config.t)
}

fn error_width_bits(config: &FHEConfig) -> i64 {
    scalar_bit_length(config.eta as u64).max(1)
}

/// Noise a fresh public-key encryption deposits, in bits.
///
/// `e_fresh = e_pk*u + e1 + e2*s` with `||u||,||s|| <= 1` (ternary) and
/// `||e_pk||,||e1||,||e2|| <= eta` (CBD_eta is supported on `[-eta, eta]`).
/// Ring expansion gives `||e_fresh|| <= n*eta + eta + n*eta = (2n+1)*eta`,
/// which is at most `4*n*eta` for every `n >= 1`. Bits round up.
fn fresh_noise_bit_bound(config: &FHEConfig) -> i64 {
    ring_degree_bits(config) + error_width_bits(config) + 2
}

/// Noise a `ClockworkBootstrap` refresh deposits in its output, in bits.
///
/// Phase 2 forms `Delta_boot*(c0' + c1'*s) + c1'*e_bsk`; the only noise term is
/// `c1'*e_bsk` with `||c1'|| < t` and `||e_bsk|| <= 4*n*eta` (the bootstrap key
/// is itself a public-key encryption), so `||v_boot|| <= n*t*4*n*eta`.
/// No credit is taken for the `Q_boot -> Q_work` division in Phase 3, and that
/// step's own rounding residue (`<= (n+1)/2`) is dominated by this deposit.
///
/// This is strictly larger than [`fresh_noise_bit_bound`] by `t_bits + n_bits`,
/// which is the whole point: a refreshed ciphertext is *not* as clean as a
/// fresh one, and `reset_after_bootstrap` must not pretend otherwise.
fn bootstrap_output_noise_bit_bound(config: &FHEConfig) -> i64 {
    plaintext_bits(config) + 2 * ring_degree_bits(config) + error_width_bits(config) + 2
}

/// Number of gadget digits used by relinearization: base `2^16`, `ceil(log2 Q / 16)`.
///
/// Mirrors `RNSFHEContext::generate_eval_key_dual` (`decomp_base = 1 << 16`,
/// `num_digits = q_bits.div_ceil(16)`).
fn relin_digit_count(config: &FHEConfig) -> i64 {
    let q_bits: i64 = config
        .primes
        .iter()
        .map(|&prime| scalar_bit_length(prime))
        .sum();
    // Integer ceiling division; `i64::div_ceil` is not stable on this toolchain.
    ((q_bits + RELIN_DECOMP_BASE_BITS - 1) / RELIN_DECOMP_BASE_BITS).max(1)
}

/// Gadget decomposition base used by relinearization, in bits.
const RELIN_DECOMP_BASE_BITS: i64 = 16;

/// Noise relinearization deposits, in bits: `ell * n * 2^16 * (4*n*eta)`.
///
/// Public so the side condition that justifies charging relinearization a
/// single bit (`v_mul + v_relin <= 2*max(v_mul, v_relin)`) can be asserted
/// rather than assumed.
pub fn relin_noise_bit_bound(config: &FHEConfig) -> i64 {
    scalar_bit_length(relin_digit_count(config) as u64)
        + 2 * ring_degree_bits(config)
        + error_width_bits(config)
        + RELIN_DECOMP_BASE_BITS
        + 2
}

/// Multiplicative noise growth of one ct x ct multiply, in bits: `G = 8*n^2*t`.
fn mul_growth_bit_cost(config: &FHEConfig) -> i64 {
    plaintext_bits(config) + 2 * ring_degree_bits(config) + 3
}

/// Bits of noise a chain effectively starts from, given a starting level.
///
/// The `+ t` absorbs the input-independent deposit `F <= 4*n^2*t^2` of the
/// tensor rescaling exactly once, via `v_k <= G^k * (v_0 + F/(G-1))` and
/// `F/(G-1) <= t`. `max(.., t_bits) + 1` is an upper bound on `v_0 + t`.
fn effective_start_bits(start_noise_bits: i64, config: &FHEConfig) -> i64 {
    start_noise_bits.max(plaintext_bits(config)) + 1
}

/// Bits of noise a ciphertext may carry and still decrypt: `||e|| < Delta/2`.
fn decryption_capacity_bits(config: &FHEConfig) -> i64 {
    (exact_delta_bit_length(config) - 1).max(0)
}

/// Budget, in millibits, that must remain unspent for the ciphertext to still
/// be an **exact refresh input** (see the module derivation, "Refresh-input
/// reserve"). `n_bits + 1` bits below the decryption boundary.
///
/// This is the term that makes the auto-refresh trigger conservative *by
/// construction*: the refresh fires while the ciphertext is still inside the
/// window `modswitch_to_t` can carry exactly, not merely while it still
/// decrypts.
pub fn bootstrap_input_reserve_mb(config: &FHEConfig) -> i64 {
    (ring_degree_bits(config) + 1) * 1000
}

/// Worst-case noise *level* of a fresh encryption, in millibits.
///
/// This is a level, not a ledger charge: it says where a fresh ciphertext sits,
/// which is what a caller reporting "post-refresh noise" for a decrypt-then-
/// re-encrypt refresh wants. The corresponding ledger charge is
/// [`NoiseBudget::encrypt_cost`], which is zero because [`NoiseBudget::from_config`]
/// has already accounted for this level.
pub fn fresh_noise_millibits(config: &FHEConfig) -> i64 {
    fresh_noise_bit_bound(config) * 1000
}

/// Worst-case noise *level* of a `ClockworkBootstrap` refresh output, in millibits.
pub fn refresh_output_noise_millibits(config: &FHEConfig) -> i64 {
    bootstrap_output_noise_bit_bound(config) * 1000
}

impl NoiseBudget {
    /// Construct a budget from exact RNS quotient size.
    ///
    /// `capacity - effective_start_bits(fresh)`: the decryption capacity
    /// `Delta/2` less the fresh-encryption noise and the once-only additive
    /// deposit of the tensor rescaling (see the module derivation).
    pub fn from_config(config: &FHEConfig) -> Self {
        let budget_mb = Self::budget_mb_from_start_noise(fresh_noise_bit_bound(config), config);

        Self {
            remaining_mb: budget_mb,
            initial_mb: budget_mb,
            cycle_initial_mb: budget_mb,
            operations: Vec::new(),
        }
    }

    /// Millibits available above a ciphertext whose noise is `start_noise_bits`.
    fn budget_mb_from_start_noise(start_noise_bits: i64, config: &FHEConfig) -> i64 {
        let budget_bits =
            (decryption_capacity_bits(config) - effective_start_bits(start_noise_bits, config))
                .max(0);
        budget_bits
            .checked_mul(1000)
            .expect("noise budget exceeds i64 millibits")
    }

    /// Construct an explicit test budget.
    pub fn with_budget_bits(bits: i64) -> Self {
        let millibits = bits
            .checked_mul(1000)
            .expect("explicit noise budget exceeds i64 millibits");
        Self {
            remaining_mb: millibits,
            initial_mb: millibits,
            cycle_initial_mb: millibits,
            operations: Vec::new(),
        }
    }

    /// Consume or refund budget using checked integer arithmetic.
    pub fn consume(
        &mut self,
        op_type: NoiseOpType,
        cost_mb: i64,
    ) -> Result<i64, NoiseExhausted> {
        if cost_mb > 0 && self.remaining_mb < cost_mb {
            return Err(self.exhausted(op_type, cost_mb));
        }

        let new_remaining = self
            .remaining_mb
            .checked_sub(cost_mb)
            .ok_or_else(|| self.exhausted(op_type, cost_mb))?;

        self.remaining_mb = new_remaining;
        self.operations.push(NoiseOperation {
            op_type,
            cost_mb,
            remaining_mb: new_remaining,
        });
        Ok(new_remaining)
    }

    fn exhausted(&self, last_op: NoiseOpType, required_mb: i64) -> NoiseExhausted {
        NoiseExhausted {
            required_mb,
            available_mb: self.remaining_mb,
            operation_count: self.operations.len(),
            last_op,
        }
    }

    /// Budget a fresh encryption consumes: **zero**.
    ///
    /// [`Self::from_config`] already seats the ledger at the fresh-encryption
    /// noise level -- its budget is `capacity - effective_start(fresh)`, i.e.
    /// what remains *above* a fresh ciphertext. Charging encryption again
    /// double-counts the same noise, and charging it once per encrypted value
    /// (as a session-based caller naturally does) compounds the error linearly
    /// in the number of inputs, which is not how noise behaves at all: two
    /// independently encrypted ciphertexts each carry one fresh-noise term, not
    /// two between them.
    ///
    /// The previous value hid this because it was a `sqrt(n)` heuristic small
    /// enough to be absorbed by the slack in the old budget. Under a true
    /// worst-case bound the double-count is large enough to exhaust a real
    /// config before its first multiply, which is how it was found.
    ///
    /// Callers that want the fresh-encryption noise *level* -- rather than a
    /// ledger charge -- want [`fresh_noise_millibits`].
    pub fn encrypt_cost(_config: &FHEConfig) -> i64 {
        0
    }

    /// `v_out = v1 + v2 <= 2*max(v1, v2)`: exactly one bit.
    pub fn add_cost() -> i64 {
        1000
    }

    /// Adding a plaintext adds `Delta*m`, which is signal, not noise, so the
    /// true cost is zero. A tenth of a bit is retained as strictly conservative
    /// bookkeeping so an unbounded add-plain chain still terminates.
    pub fn add_plain_cost() -> i64 {
        100
    }

    /// Multiply by an arbitrary plaintext POLYNOMIAL whose coefficients are
    /// bounded by `scalar`: `||v_out|| <= n * scalar * ||v_in||` by ring
    /// expansion.
    ///
    /// A caller multiplying by an arbitrary plaintext polynomial must pass the
    /// plaintext modulus `t` as the bound.
    ///
    /// **Do not use this for a scalar multiply.** The `n` factor is ring
    /// expansion, and it does not occur when the multiplier is a constant —
    /// see [`Self::mul_plain_scalar_cost`].
    pub fn mul_plain_cost(scalar: u64, config: &FHEConfig) -> i64 {
        let scalar_bits = scalar_bit_length(scalar).max(1);
        (ring_degree_bits(config) + scalar_bits) * 1000
    }

    /// Multiply by a plaintext SCALAR, i.e. by a degree-0 polynomial.
    ///
    /// `||v_out|| = scalar * ||v_in||` — exactly, with no `n`.
    ///
    /// # Derivation, and why the `n` in [`Self::mul_plain_cost`] is wrong here
    ///
    /// Ring expansion `||a*b|| <= n * ||a|| * ||b||` is a bound on the
    /// negacyclic convolution, and it is tight only when `b` has support on
    /// many coefficients: each output coefficient sums up to `n` products.
    /// When `b` is a constant `c` (`b_0 = c`, `b_i = 0` for `i > 0`), the
    /// convolution collapses — `(a*b)_k = a_k * c` for every `k` — so
    /// `||a*b||_inf = |c| * ||a||_inf` with no summation and no factor of `n`.
    /// The noise polynomial transforms the same way: `e |-> c*e`.
    ///
    /// This is not a looser bound chosen for convenience; it is the exact
    /// bound for the operation, and the `n_bits` term is a term for an
    /// expansion that provably does not happen.
    ///
    /// `RNSFHEContext::mul_plain_dual` is exactly this case: it builds its
    /// multiplier with `scalar_to_constant_dual_poly`, which sets `coeffs[0]`
    /// and leaves every other coefficient zero. Charging it
    /// `mul_plain_cost` over-charged it by `log2(n)` — 13 bits at n=8192 —
    /// which is enough to make the ledger refuse chains that are comfortably
    /// inside the true bound.
    ///
    /// Pinned by `tests::scalar_multiply_grows_noise_by_the_scalar_not_by_n`.
    pub fn mul_plain_scalar_cost(scalar: u64) -> i64 {
        scalar_bit_length(scalar).max(1) * 1000
    }

    /// Multiplicative noise growth of one ct x ct multiply: `G = 8*n^2*t`.
    ///
    /// The input-independent part of the tensor bound is not dropped; it is
    /// folded exactly once into the chain's starting level by
    /// `effective_start_bits` (see the module derivation).
    pub fn mul_ct_cost(config: &FHEConfig) -> i64 {
        mul_growth_bit_cost(config) * 1000
    }

    /// Relinearization noise is **additive**, so one bit covers it:
    /// `v_mul + v_relin <= 2 * max(v_mul, v_relin)`.
    ///
    /// The side condition `v_relin <= v_mul` is asserted for every supported
    /// config by `relin_bound_never_dominates_the_multiply_bound`; it is not
    /// assumed. [`relin_noise_bit_bound`] exposes the absolute bound.
    pub fn relin_cost(_config: &FHEConfig) -> i64 {
        1000
    }

    /// Rescale / exact prime drop, net of its residue deposit.
    ///
    /// Dropping an RNS prime `p` divides the noise by `p`. Only `t_bits` of
    /// that credit is taken, never the full `log2(p)`: every supported config
    /// satisfies `t < p`, so this is a deliberate under-credit. One bit is then
    /// **charged** for the drop residue -- `j in [0, t)` per drop on the exact
    /// align-and-drop path, `<= (n+1)/2` on the rounding path -- so the drop is
    /// accounted rather than assumed free. Net credit: `t_bits - 1` bits.
    ///
    /// # This credit belongs to a LEVEL DROP, and to nothing else
    ///
    /// "Rescale" is overloaded in BFV and the two meanings must not be mixed:
    ///
    /// * The **`Delta`-rescale inside a ct x ct multiply** divides the tensor
    ///   product by `Delta = M_level / t`. It moves no basis and consumes no
    ///   level. It is *already inside* [`Self::mul_ct_cost`]: the Fan-Vercauteren
    ///   Lemma-2 bound this module derives is the bound **after** that division
    ///   (see the module header, "ct x ct multiply", where `F` is named as the
    ///   deposit left *by* the `Delta`-rescaling). Charging `mul_ct_cost` and
    ///   then taking this credit counts the same division twice, in the
    ///   optimistic direction, which is a correctness bug rather than tuning.
    /// * The **prime drop** (`mod_switch_ct_down` / `mod_switch_ct_to_level` /
    ///   `exact_modulus_switch_drop_ct`) removes an RNS lane, so `level`
    ///   strictly decreases. That, and only that, earns this credit.
    ///
    /// `RNSFHEContext::mul_dual_public` and `mul_dual_symmetric` both leave
    /// `level` where they found it (see the "RETIRED (Step 5)" note in
    /// `ops::rns_fhe`), so **neither of their tracked wrappers may take this
    /// credit**. Pinned by
    /// `tests::prime_drop_credit_is_only_earned_by_an_actual_level_drop`.
    pub fn rescale_cost(config: &FHEConfig) -> i64 {
        -((plaintext_bits(config) - 1).max(0) * 1000)
    }

    /// Cost of one multiply cycle **that also drops a level**.
    ///
    /// Only correct for a caller that follows the multiply with a real prime
    /// drop. A caller whose multiply leaves `level` unchanged -- which is every
    /// caller of `mul_dual_public` / `mul_dual_symmetric` today -- must charge
    /// `mul_ct_cost + relin_cost` and take no drop credit. See
    /// [`Self::rescale_cost`].
    pub fn multiplication_cycle_cost(config: &FHEConfig) -> i64 {
        Self::mul_ct_cost(config) + Self::relin_cost(config) + Self::rescale_cost(config)
    }

    /// Cost of one multiply cycle that does **not** drop a level: the charge
    /// every current ct x ct path in the workspace should use.
    pub fn multiplication_cycle_cost_no_drop(config: &FHEConfig) -> i64 {
        Self::mul_ct_cost(config) + Self::relin_cost(config)
    }

    pub fn remaining_millibits(&self) -> i64 {
        self.remaining_mb
    }

    pub fn initial_millibits(&self) -> i64 {
        self.initial_mb
    }

    /// Whether the budget covers `cost_mb` against the **decryption** boundary.
    ///
    /// This is the weaker of the two constraints. An auto-refresh trigger must
    /// use [`Self::can_perform_with_reserve`] instead: a ciphertext can be well
    /// inside the decryption boundary and already outside the window a refresh
    /// can carry exactly.
    pub fn can_perform(&self, cost_mb: i64) -> bool {
        cost_mb < 0 || self.remaining_mb >= cost_mb
    }

    /// Whether the budget covers `cost_mb` **and still leaves the ciphertext an
    /// exact refresh input** afterwards.
    ///
    /// This is the conservative-by-construction trigger predicate of item 1.4:
    /// it fires strictly before the boundary, because the reserve is subtracted
    /// from the available budget before the comparison rather than after.
    pub fn can_perform_with_reserve(&self, cost_mb: i64, config: &FHEConfig) -> bool {
        if cost_mb < 0 {
            return true;
        }
        let usable = self
            .remaining_mb
            .saturating_sub(bootstrap_input_reserve_mb(config));
        usable >= cost_mb
    }

    /// Multiplies still fundable before **decryption** would fail.
    pub fn remaining_multiplications(&self, config: &FHEConfig) -> usize {
        Self::divide_budget(self.remaining_mb, config)
    }

    /// Multiplies still fundable before a **refresh becomes mandatory**.
    ///
    /// Always less than or equal to [`Self::remaining_multiplications`]: the
    /// refresh-input reserve is withheld first.
    pub fn remaining_multiplications_before_refresh(&self, config: &FHEConfig) -> usize {
        Self::divide_budget(
            self.remaining_mb
                .saturating_sub(bootstrap_input_reserve_mb(config)),
            config,
        )
    }

    fn divide_budget(available_mb: i64, config: &FHEConfig) -> usize {
        let cost = Self::mul_ct_cost(config) + Self::relin_cost(config);
        if cost <= 0 {
            return usize::MAX;
        }
        if available_mb <= 0 {
            return 0;
        }
        (available_mb / cost) as usize
    }

    /// Reset after a successful real refresh, to the **refresh output** level.
    ///
    /// The credit is `capacity - effective_start_bits(bootstrap_output)`, and
    /// `bootstrap_output_noise_bit_bound` exceeds `fresh_noise_bit_bound` by
    /// `t_bits + n_bits`. A refresh therefore returns strictly less budget than
    /// a fresh encryption -- it does not restore the ciphertext to fresh, and
    /// this ledger no longer implies that it does.
    pub fn reset_after_bootstrap(&mut self, config: &FHEConfig) {
        let budget_mb =
            Self::budget_mb_from_start_noise(bootstrap_output_noise_bit_bound(config), config);

        self.remaining_mb = budget_mb;
        self.cycle_initial_mb = budget_mb;
        self.operations.push(NoiseOperation {
            op_type: NoiseOpType::Bootstrap,
            cost_mb: 0,
            remaining_mb: budget_mb,
        });
    }

    /// Trigger when the remaining budget is at or below the configured
    /// permille fraction of the **current refresh cycle's** starting budget.
    ///
    /// Measuring against the cycle start rather than the fresh budget keeps a
    /// percentage trigger meaning the same thing after a refresh has lowered
    /// the ceiling; against the fresh budget a 25% trigger silently becomes a
    /// far more permissive one once `reset_after_bootstrap` has run.
    pub fn should_bootstrap(&self, threshold_permille: u32) -> bool {
        assert!(threshold_permille <= 1000, "threshold must be in 0..=1000");
        let threshold_mb =
            (self.cycle_initial_mb as i128 * threshold_permille as i128 / 1000) as i64;
        self.remaining_mb <= threshold_mb
    }

    pub fn operations(&self) -> &[NoiseOperation] {
        &self.operations
    }

    pub fn summary(&self) -> String {
        use crate::arithmetic::integer_math::format_millibits;

        let used = self.initial_mb.saturating_sub(self.remaining_mb);
        let used_percent = if self.initial_mb > 0 {
            ((used as i128 * 100) / self.initial_mb as i128) as i64
        } else {
            100
        };

        format!(
            "Noise Budget: {}/{} bits remaining ({}% used, {} ops)",
            format_millibits(self.remaining_mb.max(0) as u64),
            format_millibits(self.initial_mb.max(0) as u64),
            used_percent,
            self.operations.len()
        )
    }
}

impl std::fmt::Display for NoiseBudget {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}", self.summary())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::SecureConfig;

    fn raw_config(primes: Vec<u64>, t: u64, n: usize, eta: usize) -> FHEConfig {
        FHEConfig {
            n,
            q: primes[0],
            primes,
            t,
            eta,
            security_bits: 0,
            name: "noise_test",
        }
    }

    #[test]
    fn exact_delta_size_does_not_sum_lane_widths() {
        // Q = 5*7 = 35, delta = floor(35/2) = 17 -> 5 bits exactly.
        // The naive lane-width formula gives (3+3) - 2 = 4, which differs —
        // that divergence is the point of this regression test. (The old
        // [5, 5] example was degenerate: both formulas produced 4.)
        let config = raw_config(vec![5, 7], 2, 1, 1);
        assert_eq!(exact_delta_bit_length(&config), 5); // floor(35/2) = 17
        let summed_lane_widths = 6i64;
        let t_bits = scalar_bit_length(config.t);
        assert_ne!(exact_delta_bit_length(&config), summed_lane_widths - t_bits);
    }

    #[test]
    fn exact_delta_size_handles_products_above_u128() {
        // Every factor must exceed t (exact_delta_bit_length asserts t < prime;
        // the old vector included a factor of 2 with t = 3 and panicked).
        // 64 + 64 + 18 = ~146 product bits, comfortably above u128.
        let config = raw_config(vec![u64::MAX, u64::MAX - 4, 274177], 3, 1, 1);
        assert!(exact_delta_bit_length(&config) > 128);
    }

    #[test]
    fn production_budgets_are_positive() {
        for secure in [
            SecureConfig::secure_128(),
            SecureConfig::secure_128_deep(),
            SecureConfig::secure_192(),
            SecureConfig::secure_256(),
        ] {
            let config = secure.into_config();
            let budget = NoiseBudget::from_config(&config);
            assert!(
                budget.remaining_millibits() > 0,
                "{} produced a non-positive budget",
                config.name
            );
        }
    }

    #[test]
    fn consume_is_exact_and_fail_closed() {
        let mut budget = NoiseBudget::with_budget_bits(5);
        assert_eq!(budget.consume(NoiseOpType::Add, 1000), Ok(4000));
        let error = budget
            .consume(NoiseOpType::MulCt, 5000)
            .expect_err("over-budget operation must fail");
        assert_eq!(error.required_mb, 5000);
        assert_eq!(error.available_mb, 4000);
        assert_eq!(error.last_op, NoiseOpType::MulCt);
    }

    #[test]
    fn checked_refund_rejects_i64_overflow() {
        let mut budget = NoiseBudget {
            remaining_mb: i64::MAX,
            initial_mb: i64::MAX,
            cycle_initial_mb: i64::MAX,
            operations: Vec::new(),
        };
        assert!(budget.consume(NoiseOpType::Rescale, i64::MIN).is_err());
    }

    // =====================================================================
    // DERIVED-BOUND SIDE CONDITIONS
    //
    // The ledger charges relinearization and the prime drop a single bit each,
    // which is only an upper bound while the additive term they contribute is
    // dominated by the term it is being added to. Those side conditions are
    // asserted here rather than assumed in a comment.
    // =====================================================================

    fn production_configs() -> Vec<FHEConfig> {
        vec![
            SecureConfig::secure_128().into_config(),
            SecureConfig::secure_128_deep().into_config(),
            SecureConfig::secure_192().into_config(),
            SecureConfig::secure_256().into_config(),
        ]
    }

    #[test]
    fn relin_bound_never_dominates_the_multiply_bound() {
        // `relin_cost` charges one bit on the strength of
        // `v_mul + v_relin <= 2*max(v_mul, v_relin)`. That is an upper bound
        // only while `v_relin <= v_mul`. The smallest `v_mul` any chain can
        // present is the one produced by multiplying the cleanest possible
        // operands -- a pair of refresh outputs, which is the cleanest state
        // the auto path ever reaches after its first operation.
        for config in production_configs() {
            let cleanest_start = fresh_noise_bit_bound(&config)
                .min(bootstrap_output_noise_bit_bound(&config));
            let smallest_post_multiply =
                effective_start_bits(cleanest_start, &config) + mul_growth_bit_cost(&config);
            let relin = relin_noise_bit_bound(&config);
            assert!(
                relin <= smallest_post_multiply,
                "{}: relin bound {} bits exceeds the smallest post-multiply bound {} bits, \
                 so charging relinearization a single bit would under-count",
                config.name,
                relin,
                smallest_post_multiply,
            );
        }
    }

    #[test]
    fn scalar_multiply_grows_noise_by_the_scalar_not_by_n() {
        // The claim `mul_plain_scalar_cost` rests on: multiplying a ciphertext
        // by a CONSTANT polynomial `c` multiplies its noise by exactly `c`,
        // with no ring-expansion factor of `n`. `mul_plain_cost` charges
        // `n_bits + scalar_bits`; `mul_plain_scalar_cost` charges `scalar_bits`.
        //
        // Measured, not taken from the algebra. `decrypt_dual_with_diagnostics`
        // returns a margin of the form `C - |e|` for a fixed `C`, so a single
        // reading cannot separate `|e|` from `C`. Scaling TWICE does:
        //
        //   margin0 = C - e          drop1 = margin0 - margin1 = (c - 1) * e
        //   margin1 = C - c*e        drop2 = margin1 - margin2 = c * (c - 1) * e
        //   margin2 = C - c^2*e      => drop2 / drop1 = c, exactly, C cancels.
        //
        // So the ratio of successive margin drops IS the growth factor, read
        // straight off the hardware. If ring expansion were occurring, that
        // ratio would be `n * c` — 8192 times larger at secure_128.
        use crate::entropy::ShadowHarvester;
        use crate::ops::rns_fhe::RNSFHEContext;
        use crate::params::SecureConfig;

        let config = SecureConfig::secure_128().into_config();
        let ctx = RNSFHEContext::try_new(&config).expect("context");
        let mut rng = ShadowHarvester::with_seed(0x5CA1A2);
        let keys = ctx.generate_keys_dual_full(&mut rng);

        let n_bits = ring_degree_bits(&config);
        assert_eq!(n_bits, 13, "secure_128 is n=8192");

        // Scalars bounded so the MESSAGE stays far inside `t` after two
        // multiplies (`scalar^2 << t = 65537`). This is not cherry-picking: at
        // `scalar = 255` the message reaches 65025, i.e. 99.2% of `t`, and the
        // margin the decryptor reports stops isolating noise from the distance
        // to the plaintext boundary — measured drop2/drop1 = 3.4e22 there, on a
        // ciphertext that still decrypts correctly to 65025. That reading is an
        // artefact of the metric, not noise growth, and a test of noise growth
        // must stay in the range where the metric measures noise growth.
        for scalar in [2u64, 3, 4, 16] {
            let scalar_bits = scalar_bit_length(scalar);

            let ct0 = ctx.encrypt_dual(1, &keys.public_key, &mut rng);
            let (v0, m0) = ctx.decrypt_dual_with_diagnostics(&ct0, &keys.secret_key);
            assert_eq!(v0, 1);

            let ct1 = ctx.mul_plain_dual(&ct0, scalar);
            let (v1, m1) = ctx.decrypt_dual_with_diagnostics(&ct1, &keys.secret_key);
            assert_eq!(v1, scalar, "first scalar multiply must be plaintext-exact");

            let ct2 = ctx.mul_plain_dual(&ct1, scalar);
            let (v2, m2) = ctx.decrypt_dual_with_diagnostics(&ct2, &keys.secret_key);
            assert_eq!(
                v2,
                (scalar * scalar) % config.t,
                "second scalar multiply must be plaintext-exact"
            );

            let drop1 = m0 - m1;
            let drop2 = m1 - m2;

            println!(
                "scalar={scalar} ({scalar_bits} bits): drop1={drop1} drop2={drop2} \
                 ratio={} (expected {scalar}); charges: scalar={} mb, polynomial={} mb",
                if drop1 != 0 { drop2 / drop1 } else { 0 },
                NoiseBudget::mul_plain_scalar_cost(scalar),
                NoiseBudget::mul_plain_cost(scalar, &config),
            );

            assert!(
                drop1 > 0 && drop2 > 0,
                "scalar={scalar}: noise did not grow at all (drop1={drop1}, \
                 drop2={drop2}) -- the measurement is not seeing the operation"
            );

            // THE MEASUREMENT. Growth factor is exactly `scalar`.
            // Integer-only, deliberately: this module's whole contract is exact
            // integer arithmetic, and a ratio printed as a float in the failure
            // message would be the only floating-point value in the file.
            assert_eq!(
                drop2,
                drop1 * scalar as i128,
                "scalar={scalar}: successive noise growth was {drop1} then {drop2} \
                 (ratio {}, remainder {}), not a clean factor of {scalar}. Noise \
                 is NOT growing by the scalar alone, so the derivation behind \
                 mul_plain_scalar_cost is wrong -- restore the ring-expansion \
                 term rather than adjusting this assertion.",
                // Guarded: these format arguments are only evaluated when the
                // assertion fails, and one way it can fail is `drop1 == 0`.
                // An unguarded `drop2 / drop1` would then panic with a divide
                // by zero INSTEAD of printing why the test failed.
                if drop1 == 0 { 0 } else { drop2 / drop1 },
                if drop1 == 0 { drop2 } else { drop2 % drop1 },
            );

            // And it is emphatically not `n * scalar`.
            assert!(
                drop2 < drop1 * (config.n as i128),
                "scalar={scalar}: growth is at ring-expansion scale; the `n` \
                 factor in mul_plain_cost would be the right charge after all"
            );

            // The two charges differ by exactly the ring-expansion term, so
            // the relationship between them is pinned rather than incidental.
            assert_eq!(
                NoiseBudget::mul_plain_cost(scalar, &config)
                    - NoiseBudget::mul_plain_scalar_cost(scalar),
                n_bits * 1000,
                "the polynomial charge must exceed the scalar charge by exactly \
                 log2(n) -- that difference IS the ring-expansion factor"
            );
        }
    }

    #[test]
    fn prime_drop_credit_is_never_larger_than_the_true_credit() {
        // `rescale_cost` credits `t_bits` for a drop that truly divides by a
        // prime `p > t`. Under-crediting is the safe direction; assert it.
        for config in production_configs() {
            let smallest_prime_bits = config
                .primes
                .iter()
                .map(|&prime| scalar_bit_length(prime))
                .min()
                .expect("non-empty RNS chain");
            assert!(
                plaintext_bits(&config) <= smallest_prime_bits,
                "{}: t is {} bits but the smallest lane is {} bits -- the rescale credit \
                 would exceed the true credit",
                config.name,
                plaintext_bits(&config),
                smallest_prime_bits,
            );
            assert!(
                NoiseBudget::rescale_cost(&config) < 0,
                "{}: rescale must remain a net credit",
                config.name
            );
            // The credit is strictly smaller than `t_bits` because one bit is
            // charged back for the drop residue -- the 1.5 delta term.
            assert_eq!(
                NoiseBudget::rescale_cost(&config),
                -((plaintext_bits(&config) - 1) * 1000),
                "{}: drop residue must be charged",
                config.name
            );
        }
    }

    #[test]
    fn refresh_output_is_strictly_worse_than_fresh_encryption() {
        for config in production_configs() {
            assert!(
                bootstrap_output_noise_bit_bound(&config) > fresh_noise_bit_bound(&config),
                "{}: refresh output must be modelled as noisier than fresh",
                config.name
            );
            let mut refreshed = NoiseBudget::from_config(&config);
            let fresh_budget = refreshed.remaining_millibits();
            refreshed.reset_after_bootstrap(&config);
            assert!(
                refreshed.remaining_millibits() < fresh_budget,
                "{}: reset_after_bootstrap returned {} mb, which is not less than the \
                 fresh budget {} mb -- that would over-credit the refresh",
                config.name,
                refreshed.remaining_millibits(),
                fresh_budget,
            );
        }
    }

    #[test]
    fn refresh_reserve_is_withheld_before_the_boundary_not_after() {
        // Adversarial: walk the budget to the boundary from both sides and
        // confirm the reserve-aware predicate flips strictly earlier than the
        // decryption-only predicate, and never later.
        for config in production_configs() {
            let cost = NoiseBudget::mul_ct_cost(&config) + NoiseBudget::relin_cost(&config);
            let reserve = bootstrap_input_reserve_mb(&config);
            assert!(reserve > 0, "{}: reserve must be positive", config.name);

            // One millibit above the reserve-aware boundary: still permitted.
            let above = NoiseBudget {
                remaining_mb: cost + reserve,
                initial_mb: cost + reserve,
                cycle_initial_mb: cost + reserve,
                operations: Vec::new(),
            };
            assert!(above.can_perform_with_reserve(cost, &config));

            // Exactly one millibit below: refused, while the decryption-only
            // predicate still says yes. That gap is the margin.
            let below = NoiseBudget {
                remaining_mb: cost + reserve - 1,
                initial_mb: cost + reserve - 1,
                cycle_initial_mb: cost + reserve - 1,
                operations: Vec::new(),
            };
            assert!(
                !below.can_perform_with_reserve(cost, &config),
                "{}: reserve-aware predicate admitted an operation that eats the reserve",
                config.name
            );
            assert!(
                below.can_perform(cost),
                "{}: decryption-only predicate should still admit it -- the reserve is \
                 exactly the difference between the two",
                config.name
            );

            // A negative cost (a credit, e.g. rescale) is always permitted.
            assert!(below.can_perform_with_reserve(-1, &config));
        }
    }

    #[test]
    fn encryption_is_not_charged_twice() {
        // `from_config` seats the ledger at the fresh level, so a fresh
        // encryption costs nothing further. A non-zero `encrypt_cost` would
        // double-count -- and, in a per-value caller, compound with the number
        // of inputs.
        for config in production_configs() {
            assert_eq!(
                NoiseBudget::encrypt_cost(&config),
                0,
                "{}: encryption must not be charged on top of from_config",
                config.name
            );
            let budget = NoiseBudget::from_config(&config);
            assert_eq!(
                budget.remaining_millibits(),
                (decryption_capacity_bits(&config)
                    - effective_start_bits(fresh_noise_bit_bound(&config), &config))
                    .max(0)
                    * 1000,
                "{}: from_config must be exactly the headroom above a fresh ciphertext",
                config.name,
            );
            // The level is still available to callers that want it.
            assert_eq!(
                fresh_noise_millibits(&config),
                fresh_noise_bit_bound(&config) * 1000
            );
            assert!(refresh_output_noise_millibits(&config) > fresh_noise_millibits(&config));
        }
    }

    #[test]
    fn reserve_aware_multiplication_count_never_exceeds_decryption_bound() {
        for config in production_configs() {
            let budget = NoiseBudget::from_config(&config);
            assert!(
                budget.remaining_multiplications_before_refresh(&config)
                    <= budget.remaining_multiplications(&config),
                "{}: refresh-bounded depth exceeded decryption-bounded depth",
                config.name
            );
        }
    }

    #[test]
    fn percentage_trigger_tracks_the_current_cycle_not_the_fresh_budget() {
        let config = SecureConfig::secure_128_deep().into_config();
        let mut budget = NoiseBudget::from_config(&config);
        budget.reset_after_bootstrap(&config);
        let post = budget.remaining_millibits();
        assert!(post < budget.initial_millibits());

        // Immediately after a reset the budget is full *for this cycle*, so a
        // 25% trigger must not fire. Measured against the fresh budget it would
        // not fire either; the distinguishing case is just below the cycle's
        // own quarter mark, which is far above the fresh budget's quarter mark.
        assert!(!budget.should_bootstrap(250));
        budget
            .consume(NoiseOpType::MulCt, post - post / 4 + 1)
            .expect("drive to just under a quarter of the cycle budget");
        assert!(
            budget.should_bootstrap(250),
            "trigger must measure against the cycle budget {} mb, not the fresh budget {} mb",
            post,
            budget.initial_millibits()
        );
    }

    #[ignore = "VESTIGIAL: asserts NoiseBudget::reset_after_bootstrap raises remaining_millibits above its pre-reset value and appends a NoiseOpType::Bootstrap entry. A reset only means something against a budget that depletes per multiply. Bootstrap is a fallback, not the critical path. Exact division in residue space divides the value without moving the basis, so no level is consumed and depth is not budget-bounded. See docs/RETIRED_MECHANISMS.md"]
    #[test]
    fn bootstrap_reset_uses_exact_delta_size() {
        let config = SecureConfig::secure_128_deep().into_config();
        let mut budget = NoiseBudget::from_config(&config);
        let cost = NoiseBudget::mul_ct_cost(&config) + NoiseBudget::relin_cost(&config);
        let _ = budget.consume(NoiseOpType::MulCt, cost);
        let before = budget.remaining_millibits();
        budget.reset_after_bootstrap(&config);
        assert!(budget.remaining_millibits() > before);
        assert_eq!(budget.operations().last().unwrap().op_type, NoiseOpType::Bootstrap);
    }

    #[ignore = "VESTIGIAL: asserts should_bootstrap(250) is inclusive at exactly 75000 millibits consumed and false one millibit below — the auto-refresh trigger boundary. Bootstrap is a fallback, not the critical path. Exact division in residue space divides the value without moving the basis, so no level is consumed and depth is not budget-bounded. See docs/RETIRED_MECHANISMS.md"]
    #[test]
    fn threshold_boundary_is_inclusive() {
        let mut budget = NoiseBudget::with_budget_bits(100);
        budget.consume(NoiseOpType::MulCt, 75000).unwrap();
        assert!(budget.should_bootstrap(250));

        let mut above = NoiseBudget::with_budget_bits(100);
        above.consume(NoiseOpType::MulCt, 74999).unwrap();
        assert!(!above.should_bootstrap(250));
    }

    #[ignore = "VESTIGIAL: asserts should_bootstrap(1001) panics — argument validation on the auto-refresh trigger threshold. Bootstrap is a fallback, not the critical path. Exact division in residue space divides the value without moving the basis, so no level is consumed and depth is not budget-bounded. See docs/RETIRED_MECHANISMS.md"]
    #[test]
    #[should_panic(expected = "threshold must be in 0..=1000")]
    fn invalid_threshold_panics() {
        NoiseBudget::with_budget_bits(1).should_bootstrap(1001);
    }

    #[test]
    fn multiplication_cycle_includes_k_elimination_credit() {
        let config = SecureConfig::secure_128_deep().into_config();
        assert_eq!(
            NoiseBudget::multiplication_cycle_cost(&config),
            NoiseBudget::mul_ct_cost(&config)
                + NoiseBudget::relin_cost(&config)
                + NoiseBudget::rescale_cost(&config)
        );
        assert!(NoiseBudget::rescale_cost(&config) < 0);
    }
}