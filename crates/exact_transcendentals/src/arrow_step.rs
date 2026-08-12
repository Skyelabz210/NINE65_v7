//! D-ARROW-c: Algebraic Time Folding for Linear PDEs.
//!
//! For a linear map F applied to a state vector, N successive applications
//! collapse to a single matrix-vector multiply via the matrix power A^N mod p.
//! The matrix power is computed by repeated squaring (binary exponentiation),
//! yielding O(n^2 * log N) cost per residue lane — compared to O(n^2 * N) for
//! naive step-by-step iteration.
//!
//! For nonlinear maps (e.g. Burgers' equation discretisation), time folding does
//! not apply directly because the state transition matrix changes at every step.
//! Instead we supply Floyd's rho algorithm for cycle detection: because the
//! state space mod p is finite, every nonlinear iteration must eventually cycle,
//! and finding the cycle lets us skip ahead without materialising every
//! intermediate state.
//!
//! All arithmetic is exact integer modular arithmetic.  Intermediate products
//! use `u128` to prevent overflow when multiplying two `u64` residues, so
//! moduli up to `u64::MAX` are safe.  No floating-point types (`f32`, `f64`)
//! appear anywhere in this module.

#[cfg(not(feature = "std"))]
use alloc::vec;
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
#[cfg(feature = "std")]
use std::vec::Vec;

// ─── modular helpers (module-local, same conventions as cram_pde) ───────────

#[inline]
fn addmod(a: u64, b: u64, m: u64) -> u64 {
    ((a as u128 + b as u128) % m as u128) as u64
}

#[inline]
fn submod(a: u64, b: u64, m: u64) -> u64 {
    ((a as u128 + m as u128 - b as u128) % m as u128) as u64
}

#[inline]
fn mulmod_u64(a: u64, b: u64, m: u64) -> u64 {
    ((a as u128 * b as u128) % m as u128) as u64
}

// ─── flat row-major n×n matrix operations, all mod p ────────────────────────

/// Multiply two n×n matrices stored in row-major order, mod p.
///
/// Uses the i-k-j loop order for better cache locality on the inner
/// (contiguous-j) sweep, with u128 intermediates for overflow safety.
pub fn mat_mul_mod(a: &[u64], b: &[u64], n: usize, p: u64) -> Vec<u64> {
    debug_assert_eq!(a.len(), n * n);
    debug_assert_eq!(b.len(), n * n);

    let mut c = vec![0u64; n * n];

    for i in 0..n {
        for k in 0..n {
            let aik = a[i * n + k];
            if aik == 0 {
                continue;
            }
            for j in 0..n {
                let prod = (aik as u128 * b[k * n + j] as u128) % p as u128;
                c[i * n + j] = ((c[i * n + j] as u128 + prod) % p as u128) as u64;
            }
        }
    }

    c
}

/// Return the n×n identity matrix in flat row-major form.
pub fn mat_identity(n: usize) -> Vec<u64> {
    let mut m = vec![0u64; n * n];
    for i in 0..n {
        m[i * n + i] = 1;
    }
    m
}

/// Compute A^exp mod p for an n×n matrix via binary repeated squaring.
pub fn mat_pow_mod(m: &[u64], exp: u64, n: usize, p: u64) -> Vec<u64> {
    debug_assert_eq!(m.len(), n * n);

    let mut result = mat_identity(n);
    let mut base = m.to_vec();
    let mut e = exp;

    while e > 0 {
        if e & 1 == 1 {
            result = mat_mul_mod(&result, &base, n, p);
        }
        e >>= 1;
        if e > 0 {
            base = mat_mul_mod(&base, &base, n, p);
        }
    }

    result
}

/// Multiply an n×n matrix by a length-n column vector, mod p.
pub fn mat_apply(m: &[u64], v: &[u64], n: usize, p: u64) -> Vec<u64> {
    debug_assert_eq!(m.len(), n * n);
    debug_assert_eq!(v.len(), n);

    let mut out = vec![0u64; n];

    for i in 0..n {
        let mut acc: u128 = 0;
        for j in 0..n {
            acc += (m[i * n + j] as u128 * v[j] as u128) % p as u128;
        }
        out[i] = (acc % p as u128) as u64;
    }

    out
}

// ─── heat stencil circulant ─────────────────────────────────────────────────

/// Build the n×n circulant matrix for the 1-D heat stencil `[b, a, b]`
/// with periodic (wrap-around) boundary conditions, reduced mod p.
///
/// Row i has `a` on the diagonal (column i), and `b` at columns
/// `(i+1) % n` and `(i+n-1) % n`.  When n == 2 those two off-diagonal
/// positions coincide, so both contributions are summed via `addmod`.
pub fn heat_circulant(dim: usize, a: u64, b: u64, p: u64) -> Vec<u64> {
    assert!(dim >= 2, "heat_circulant requires dim >= 2");

    let mut m = vec![0u64; dim * dim];
    let a_mod = a % p;
    let b_mod = b % p;

    for i in 0..dim {
        m[i * dim + i] = a_mod;

        let right = (i + 1) % dim;
        m[i * dim + right] = addmod(m[i * dim + right], b_mod, p);

        let left = (i + dim - 1) % dim;
        m[i * dim + left] = addmod(m[i * dim + left], b_mod, p);
    }

    m
}

// ─── ArrowStep: pre-computed time-folded operator ───────────────────────────

/// Pre-computed A^N mod p for every residue lane, enabling a single
/// matrix-vector multiply to replace N time steps.
pub struct ArrowStep {
    /// Pre-computed A^N mod p for each Safe Basis prime.
    pub mats: Vec<Vec<u64>>,
    /// The Safe Basis primes this was built for.
    pub primes: Vec<u64>,
    /// Grid size n.
    pub n: usize,
    /// Number of steps N.
    pub steps: u64,
}

impl ArrowStep {
    /// Construct an `ArrowStep` for the 1-D heat equation on a grid of
    /// `dim` cells with stencil coefficients `a` (diagonal) and `b`
    /// (off-diagonal), folding `steps` time steps into a single operator,
    /// independently for each prime in `basis`.
    pub fn for_heat(dim: usize, a: u64, b: u64, steps: u64, basis: &[u64]) -> Self {
        let mut mats = Vec::with_capacity(basis.len());

        for &p in basis {
            let circ = heat_circulant(dim, a, b, p);
            let powered = mat_pow_mod(&circ, steps, dim, p);
            mats.push(powered);
        }

        ArrowStep {
            mats,
            primes: basis.to_vec(),
            n: dim,
            steps,
        }
    }

    /// Apply the folded operator to per-lane state vectors.
    ///
    /// `state` is indexed as `state[lane_index][cell_index]`.  For each
    /// lane `li` the result is `A_li^N * state[li]  mod primes[li]`.
    pub fn apply(&self, state: &[Vec<u64>]) -> Vec<Vec<u64>> {
        assert_eq!(
            state.len(),
            self.primes.len(),
            "state must have one vector per lane"
        );

        let mut out = Vec::with_capacity(state.len());

        for (li, lane_state) in state.iter().enumerate() {
            debug_assert_eq!(lane_state.len(), self.n);
            let result = mat_apply(&self.mats[li], lane_state, self.n, self.primes[li]);
            out.push(result);
        }

        out
    }
}

// ─── reversibility: the arrow-emission gate ─────────────────────────────────

/// Invert an n×n matrix mod a prime p by Gauss–Jordan elimination with
/// Fermat inverses. Returns `None` when the matrix is singular mod p —
/// the lane's arrow is one-way and MUST NOT be selected for reversible
/// transport. Exact integer arithmetic throughout.
pub fn mat_inv_mod(m: &[u64], n: usize, p: u64) -> Option<Vec<u64>> {
    debug_assert_eq!(m.len(), n * n);

    let mulm = |x: u64, y: u64| ((x as u128 * y as u128) % p as u128) as u64;
    let subm = |x: u64, y: u64| ((x as u128 + p as u128 - y as u128) % p as u128) as u64;
    let pow_mod = |mut b: u64, mut e: u64| {
        let mut r = 1u64;
        b %= p;
        while e > 0 {
            if e & 1 == 1 {
                r = ((r as u128 * b as u128) % p as u128) as u64;
            }
            b = ((b as u128 * b as u128) % p as u128) as u64;
            e >>= 1;
        }
        r
    };

    let mut a: Vec<u64> = m.iter().map(|&x| x % p).collect();
    let mut inv = mat_identity(n);

    for col in 0..n {
        let piv = (col..n).find(|&r| a[r * n + col] != 0)?;
        if piv != col {
            for j in 0..n {
                a.swap(col * n + j, piv * n + j);
                inv.swap(col * n + j, piv * n + j);
            }
        }
        let pinv = pow_mod(a[col * n + col], p - 2); // Fermat: p prime
        for j in 0..n {
            a[col * n + j] = mulm(a[col * n + j], pinv);
            inv[col * n + j] = mulm(inv[col * n + j], pinv);
        }
        for r in 0..n {
            if r != col && a[r * n + col] != 0 {
                let f = a[r * n + col];
                for j in 0..n {
                    a[r * n + j] = subm(a[r * n + j], mulm(f, a[col * n + j]));
                    inv[r * n + j] = subm(inv[r * n + j], mulm(f, inv[col * n + j]));
                }
            }
        }
    }

    Some(inv)
}

impl ArrowStep {
    /// The arrow-emission gate: per-lane reversibility of the folded
    /// operator. A^N is invertible mod p iff the single-step A is, so the
    /// gate inverts the one-step stencil per lane. `true` = the lane can be
    /// run backward exactly ((A⁻¹)^N undoes A^N); `false` = the arrow is
    /// one-way on that lane (det(A) ≡ 0 mod p).
    ///
    /// Reversibility is a property of (operator, dim, prime) JOINTLY — not
    /// of the basis. Measured example: heat stencil [1,3,1] at dim=8 is
    /// singular on lanes {3, 5, 7}, two of which sit in `TRANSPORT_CORE`.
    /// Transport-lane selection must consult this gate per deployment.
    pub fn reversible_lanes(&self, a: u64, b: u64) -> Vec<bool> {
        self.primes
            .iter()
            .map(|&p| {
                let single = heat_circulant(self.n, a, b, p);
                mat_inv_mod(&single, self.n, p).is_some()
            })
            .collect()
    }

    /// Exact reverse application: undo `steps` folded time steps on every
    /// reversible lane. Returns `None` if ANY lane in the basis is singular
    /// (loud refusal — a partial unfold would silently desynchronise the
    /// lanes, which is exactly the projection non-reversibility failure
    /// T-X-PROJ forbids).
    pub fn unfold(&self, a: u64, b: u64, state: &[Vec<u64>]) -> Option<Vec<Vec<u64>>> {
        assert_eq!(state.len(), self.primes.len());

        let mut out = Vec::with_capacity(state.len());
        for (li, &p) in self.primes.iter().enumerate() {
            let single = heat_circulant(self.n, a, b, p);
            let ainv = mat_inv_mod(&single, self.n, p)?;
            let unfolded_op = mat_pow_mod(&ainv, self.steps, self.n, p);
            out.push(mat_apply(&unfolded_op, &state[li], self.n, p));
        }
        Some(out)
    }
}

// ─── Floyd's cycle detection for nonlinear PDEs ─────────────────────────────

/// One time step of the inviscid-diffusive Burgers discretisation on a
/// periodic 1-D grid, computed entirely in modular arithmetic.
///
/// ```text
/// u_new[i] = c*u[i]
///          - u[i] * (u[(i+1)%n] - u[(i+n-1)%n])
///          + d * (u[(i+1)%n] - 2*u[i] + u[(i+n-1)%n])
///     all mod p
/// ```
fn burgers_step(state: &[u64], p: u64, c: u64, d: u64) -> Vec<u64> {
    let n = state.len();
    let mut out = vec![0u64; n];

    for i in 0..n {
        let ui = state[i];
        let uright = state[(i + 1) % n];
        let uleft = state[(i + n - 1) % n];

        // convective term: u[i] * (u_right - u_left)
        let diff_conv = submod(uright, uleft, p);
        let convective = mulmod_u64(ui, diff_conv, p);

        // diffusive term: d * (u_right - 2*u[i] + u_left)
        let two_ui = addmod(ui, ui, p);
        let diff_part = addmod(submod(uright, two_ui, p), uleft, p);
        let diffusive = mulmod_u64(d, diff_part, p);

        // linear term: c * u[i]
        let linear = mulmod_u64(c, ui, p);

        // u_new = linear - convective + diffusive
        let tmp = submod(linear, convective, p);
        out[i] = addmod(tmp, diffusive, p);
    }

    out
}

/// Apply Floyd's cycle-detection algorithm to the Burgers time-stepper.
///
/// Returns `Some((mu, lambda))` where `mu` is the pre-period length and
/// `lambda` is the cycle length, or `None` if no cycle is found within
/// `max_steps` iterations.
///
/// Because the state space is finite (p^dim states), a cycle is
/// guaranteed to exist — `max_steps` is a safety bound only.
pub fn burgers_rho_on_lane(
    initial: &[u64],
    p: u64,
    c: u64,
    d: u64,
    max_steps: u64,
) -> Option<(u64, u64)> {
    // Phase 1: find a meeting point (tortoise and hare)
    let mut tortoise = burgers_step(initial, p, c, d);
    let mut hare = burgers_step(&burgers_step(initial, p, c, d), p, c, d);

    let mut steps: u64 = 0;
    while tortoise != hare {
        tortoise = burgers_step(&tortoise, p, c, d);
        hare = burgers_step(&burgers_step(&hare, p, c, d), p, c, d);
        steps += 1;
        if steps >= max_steps {
            return None;
        }
    }

    // Phase 2: find mu (pre-period length)
    let mut mu: u64 = 0;
    tortoise = initial.to_vec();
    while tortoise != hare {
        tortoise = burgers_step(&tortoise, p, c, d);
        hare = burgers_step(&hare, p, c, d);
        mu += 1;
    }

    // Phase 3: find lambda (cycle length)
    let mut lambda: u64 = 1;
    hare = burgers_step(&tortoise, p, c, d);
    while tortoise != hare {
        hare = burgers_step(&hare, p, c, d);
        lambda += 1;
    }

    Some((mu, lambda))
}

// ─── tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ------------------------------------------------------------------
    // Test 1: matrix_multiply_identity
    // ------------------------------------------------------------------
    #[test]
    fn matrix_multiply_identity() {
        let p: u64 = 97;
        let n = 3;
        // A = [[1,2,3],[4,5,6],[7,8,9]] mod 97
        let a: Vec<u64> = vec![1, 2, 3, 4, 5, 6, 7, 8, 9];
        let id = mat_identity(n);

        let ai = mat_mul_mod(&a, &id, n, p);
        let ia = mat_mul_mod(&id, &a, n, p);

        assert_eq!(ai, a, "A * I should equal A");
        assert_eq!(ia, a, "I * A should equal A");
    }

    // ------------------------------------------------------------------
    // Test 2: matrix_power_agrees_with_repeated_multiply
    // ------------------------------------------------------------------
    #[test]
    fn matrix_power_agrees_with_repeated_multiply() {
        let p: u64 = 101;
        let n = 3;
        let a: Vec<u64> = vec![2, 1, 0, 0, 3, 1, 1, 0, 2];

        // A^4 via repeated squaring
        let a4_fast = mat_pow_mod(&a, 4, n, p);

        // A^4 via 3 sequential multiplies
        let a2 = mat_mul_mod(&a, &a, n, p);
        let a3 = mat_mul_mod(&a2, &a, n, p);
        let a4_slow = mat_mul_mod(&a3, &a, n, p);

        assert_eq!(
            a4_fast, a4_slow,
            "mat_pow_mod(A, 4) should match A*A*A*A"
        );
    }

    // ------------------------------------------------------------------
    // Test 3: heat_circulant_construction
    // ------------------------------------------------------------------
    #[test]
    fn heat_circulant_construction() {
        let m = heat_circulant(4, 2, 1, 7);

        // Row 0: [2, 1, 0, 1]
        assert_eq!(m[0..4], [2, 1, 0, 1]);
        // Row 1: [1, 2, 1, 0]
        assert_eq!(m[4..8], [1, 2, 1, 0]);
        // Row 2: [0, 1, 2, 1]
        assert_eq!(m[8..12], [0, 1, 2, 1]);
        // Row 3: [1, 0, 1, 2]
        assert_eq!(m[12..16], [1, 0, 1, 2]);
    }

    // ------------------------------------------------------------------
    // Test 4: arrow_step_matches_step_by_step
    // ------------------------------------------------------------------
    #[test]
    fn arrow_step_matches_step_by_step() {
        let dim = 4;
        let a: u64 = 2;
        let b: u64 = 1;
        let steps: u64 = 5;
        let basis: Vec<u64> = vec![3, 5, 7];

        // Initial state per lane
        let initial_states: Vec<Vec<u64>> = basis
            .iter()
            .map(|&p| {
                (0..dim as u64).map(|i| (i + 1) % p).collect()
            })
            .collect();

        // ArrowStep (matrix-power path)
        let arrow = ArrowStep::for_heat(dim, a, b, steps, &basis);
        let arrow_result = arrow.apply(&initial_states);

        // Manual step-by-step: apply heat stencil N times
        for (li, &p) in basis.iter().enumerate() {
            let mut v = initial_states[li].clone();
            for _ in 0..steps {
                let mut next = vec![0u64; dim];
                for i in 0..dim {
                    let vi = v[i];
                    let vleft = v[(i + dim - 1) % dim];
                    let vright = v[(i + 1) % dim];
                    next[i] = addmod(
                        mulmod_u64(a, vi, p),
                        addmod(mulmod_u64(b, vleft, p), mulmod_u64(b, vright, p), p),
                        p,
                    );
                }
                v = next;
            }
            assert_eq!(
                arrow_result[li], v,
                "ArrowStep and step-by-step disagree on lane {} (p={})",
                li, p
            );
        }
    }

    // ------------------------------------------------------------------
    // Test 5: floyds_rho_detects_known_cycle
    // ------------------------------------------------------------------
    #[test]
    fn floyds_rho_detects_known_cycle() {
        let p: u64 = 5;
        let c: u64 = 1;
        let d: u64 = 1;
        let initial: Vec<u64> = vec![1, 2];

        let result = burgers_rho_on_lane(&initial, p, c, d, 1000);
        assert!(result.is_some(), "cycle should be detected for dim=2, p=5");

        let (mu, lambda) = result.unwrap();

        // Verify: state at step mu equals state at step mu + lambda
        let mut state = initial.clone();
        for _ in 0..mu {
            state = burgers_step(&state, p, c, d);
        }
        let state_at_mu = state.clone();

        let mut state2 = state_at_mu.clone();
        for _ in 0..lambda {
            state2 = burgers_step(&state2, p, c, d);
        }

        assert_eq!(
            state_at_mu, state2,
            "state at mu should equal state at mu+lambda"
        );
    }

    // ------------------------------------------------------------------
    // Test 6: arrow_step_apply_consistency
    //   ArrowStep(N) applied once should match ArrowStep(1) applied N times.
    // ------------------------------------------------------------------
    #[test]
    fn arrow_step_apply_consistency() {
        let dim = 3;
        let a: u64 = 3;
        let b: u64 = 1;
        let n_steps: u64 = 7;
        let basis: Vec<u64> = vec![11, 13];

        let initial: Vec<Vec<u64>> = basis
            .iter()
            .map(|&p| (0..dim as u64).map(|i| (2 * i + 1) % p).collect())
            .collect();

        // ArrowStep with N steps applied once
        let arrow_n = ArrowStep::for_heat(dim, a, b, n_steps, &basis);
        let result_n = arrow_n.apply(&initial);

        // ArrowStep with 1 step applied N times
        let arrow_1 = ArrowStep::for_heat(dim, a, b, 1, &basis);
        let mut state = initial.clone();
        for _ in 0..n_steps {
            state = arrow_1.apply(&state);
        }

        assert_eq!(
            result_n, state,
            "A^N applied once should match A^1 applied N times"
        );
    }

    // ------------------------------------------------------------------
    // Test 7: matrix_multiply_associativity
    // ------------------------------------------------------------------
    #[test]
    fn matrix_multiply_associativity() {
        let p: u64 = 53;
        let n = 3;

        let a: Vec<u64> = vec![1, 2, 3, 4, 5, 6, 7, 8, 9];
        let b: Vec<u64> = vec![9, 8, 7, 6, 5, 4, 3, 2, 1];
        let c: Vec<u64> = vec![2, 0, 1, 1, 3, 0, 0, 1, 2];

        let ab = mat_mul_mod(&a, &b, n, p);
        let bc = mat_mul_mod(&b, &c, n, p);

        let ab_c = mat_mul_mod(&ab, &c, n, p);
        let a_bc = mat_mul_mod(&a, &bc, n, p);

        assert_eq!(ab_c, a_bc, "(A*B)*C should equal A*(B*C)");
    }

    // ------------------------------------------------------------------
    // Test 8: heat_arrow_multi_step_roundtrip
    // ------------------------------------------------------------------
    #[test]
    fn heat_arrow_multi_step_roundtrip() {
        let dim = 5;
        let a: u64 = 3;
        let b: u64 = 2;
        let steps: u64 = 10;
        let basis: Vec<u64> = vec![7, 11, 13];

        let initial: Vec<Vec<u64>> = basis
            .iter()
            .map(|&p| (0..dim as u64).map(|i| (i * 3 + 1) % p).collect())
            .collect();

        // Matrix-power path
        let arrow = ArrowStep::for_heat(dim, a, b, steps, &basis);
        let arrow_result = arrow.apply(&initial);

        // Step-by-step path
        for (li, &p) in basis.iter().enumerate() {
            let mut v = initial[li].clone();
            for _ in 0..steps {
                let mut next = vec![0u64; dim];
                for i in 0..dim {
                    let vi = v[i];
                    let vleft = v[(i + dim - 1) % dim];
                    let vright = v[(i + 1) % dim];
                    next[i] = addmod(
                        mulmod_u64(a, vi, p),
                        addmod(mulmod_u64(b, vleft, p), mulmod_u64(b, vright, p), p),
                        p,
                    );
                }
                v = next;
            }
            assert_eq!(
                arrow_result[li], v,
                "10-step roundtrip disagrees on lane {} (p={})",
                li, p
            );
        }
    }
}
