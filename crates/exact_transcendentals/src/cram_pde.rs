//! CRAM-PDE: Polynomial-Nonlinear PDE Realization on the CRT Substrate.
//!
//! This module implements exact lane-parallel PDE evolution in residue space,
//! the fundamental algorithm of the Configurable Residue Arithmetic Machine
//! (CRAM) for time-stepping discrete PDEs.
//!
//! ## Core Theorems
//!
//! 1. **Exactness (D-EQI-c)**: Lane-parallel evolution agrees bit-for-bit with
//!    the integer reference at every step. Error = 0 by construction.
//!
//! 2. **p-Adic Non-Expansion (D-PADIC-c)**: For every prime p in the Safe
//!    Basis and any two states w, w': if w == w' (mod p^k) then F(w) == F(w')
//!    (mod p^k). The p-adic unit ball is invariant under F.
//!
//! 3. **Algebraic Non-Resonance (D-DKAM-c)**: If deg(F) < rho(B) = min(B),
//!    no lane can sustain resonant amplification. For the Transport Core
//!    {3,7,11,13}: rho = 3. Heat (deg=1) and Burgers (deg=2) are subcritical.
//!
//! 4. **Decidable Boundedness (Cycle-Sum Criterion)**: The winding number K
//!    is bounded on all orbits iff every reachable cycle has net winding = 0.
//!    Boundedness is a graph-theoretic property, not an analytic estimate.
//!
//! All arithmetic is exact integer. Zero floating point (A1 mandate).

#![allow(clippy::needless_range_loop)]

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
#[cfg(feature = "std")]
use std::vec::Vec;

// ============================================================================
// MODULAR HELPERS (u64-based, module-local)
// ============================================================================

/// Addition mod m using u128 to prevent overflow.
#[inline]
fn addmod(a: u64, b: u64, m: u64) -> u64 {
    ((a as u128 + b as u128) % m as u128) as u64
}

/// Subtraction mod m using u128 to prevent underflow.
#[inline]
fn submod(a: u64, b: u64, m: u64) -> u64 {
    ((a as u128 + m as u128 - b as u128) % m as u128) as u64
}

/// Multiplication mod m using u128 intermediate.
#[inline]
fn mulmod_u64(a: u64, b: u64, m: u64) -> u64 {
    ((a as u128 * b as u128) % m as u128) as u64
}

/// Modular inverse via extended Euclidean algorithm. Returns 0 if no inverse.
#[allow(dead_code)]
fn mod_inverse_u64(a: u64, m: u64) -> u64 {
    if m == 1 {
        return 0;
    }
    let (mut old_r, mut r) = (m as i128, a as i128);
    let (mut old_s, mut s) = (0i128, 1i128);

    while r != 0 {
        let q = old_r / r;
        let tmp_r = r;
        r = old_r - q * r;
        old_r = tmp_r;
        let tmp_s = s;
        s = old_s - q * s;
        old_s = tmp_s;
    }

    if old_r != 1 {
        return 0; // no inverse
    }
    ((old_s % m as i128 + m as i128) % m as i128) as u64
}

// ============================================================================
// CONSTANTS
// ============================================================================

/// Safe Basis primes: {2, 3, 5, 7, 11, 13}.
pub const SAFE_BASIS: [u64; 6] = [2, 3, 5, 7, 11, 13];

/// M = product of Safe Basis = 2 * 3 * 5 * 7 * 11 * 13 = 30030.
pub const M_SAFE: i128 = 30030;

/// Transport Core primes: the exact-div lanes carrying lineage fingerprint.
/// rho(Transport Core) = 3 (the minimum prime in this set).
pub const TRANSPORT_CORE: [u64; 4] = [3, 7, 11, 13];

// ============================================================================
// EXACT STATE
// ============================================================================

/// CRT residue state over the Safe Basis with winding field for exact recovery.
///
/// Every `ExactState` encodes an exact integer X:
///   X = garner_reconstruct(lanes) + winding * M
///
/// The lanes store X mod p for each Safe Basis prime p. The winding K records
/// how many times M has been "wound past" -- the sheet number on the CRT torus.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExactState {
    /// Residues mod each Safe Basis prime. lanes[i] = X mod SAFE_BASIS[i].
    pub lanes: [u64; 6],
    /// Winding counter K: X = garner(lanes) + K * M_SAFE.
    pub winding: i128,
}

impl ExactState {
    /// Lift any i128 into the exact CRT representation.
    pub fn from_i128(x: i128) -> Self {
        let r = x.rem_euclid(M_SAFE); // canonical residue in [0, M)
        let k = (x - r) / M_SAFE;
        let mut lanes = [0u64; 6];
        for (i, &p) in SAFE_BASIS.iter().enumerate() {
            lanes[i] = (x.rem_euclid(p as i128)) as u64;
        }
        ExactState { lanes, winding: k }
    }

    /// Reconstruct the canonical non-negative representative in [0, M).
    /// Uses Garner's algorithm via k_elim.
    pub fn to_u128(&self) -> u128 {
        let residues: Vec<(i128, i128)> = self
            .lanes
            .iter()
            .zip(SAFE_BASIS.iter())
            .map(|(&r, &p)| (r as i128, p as i128))
            .collect();
        match crate::k_elim::garner_reconstruct(&residues) {
            Some(v) => v as u128,
            None => 0, // should not happen for coprime basis
        }
    }

    /// Reconstruct the EXACT integer X = garner(lanes) + winding * M.
    pub fn to_i128_exact(&self) -> i128 {
        self.to_u128() as i128 + self.winding * M_SAFE
    }

    /// Alias for to_i128_exact.
    pub fn to_i128(&self) -> i128 {
        self.to_i128_exact()
    }

    /// Convenience: convert a slice of i128 values to ExactState vector.
    pub fn from_i128_vec(values: &[i128]) -> Vec<Self> {
        values.iter().map(|&x| Self::from_i128(x)).collect()
    }

    /// Convenience: convert a slice of ExactState to i128 vector.
    pub fn to_i128_vec(states: &[Self]) -> Vec<i128> {
        states.iter().map(|s| s.to_i128_exact()).collect()
    }
}

// ============================================================================
// POLYNOMIAL MAP TRAIT
// ============================================================================

/// A polynomial-nonlinear evolution map F: Z^n -> Z^n with integer coefficients.
///
/// The D-DKAM-c gate requires: degree() < rho(B) = min(Transport Core) = 3.
pub trait PolynomialMap {
    /// Polynomial degree of the map (1 for linear, 2 for quadratic, etc.).
    fn degree(&self) -> u32;

    /// Dimension (number of grid cells).
    fn dim(&self) -> usize;

    /// Per-lane evaluation in Z/pZ. Must agree with evaluate_i128 after
    /// CRT reconstruction (the exactness contract).
    fn evaluate_lane(&self, state_lane: &[u64], p: u64) -> Vec<u64>;

    /// Apply F mod M (integer reference with modular reduction).
    fn evaluate_i128(&self, state: &[i128]) -> Vec<i128>;

    /// Apply F WITHOUT mod-M reduction. For winding carry computation.
    /// Default: delegates to evaluate_i128.
    fn evaluate_i128_unbounded(&self, state: &[i128]) -> Vec<i128> {
        self.evaluate_i128(state)
    }

    /// For linear maps: propagate winding through the same linear stencil.
    /// Returns None for nonlinear maps.
    fn propagate_winding(&self, _windings: &[i128]) -> Option<Vec<i128>> {
        None
    }
}

// ============================================================================
// LANE-PARALLEL EVOLUTION
// ============================================================================

/// Evolve a vector of `ExactState`s by one step using map `f`, lane-parallel.
///
/// Residues are updated lane-by-lane. Winding is NOT propagated (set to 0).
/// Use `step_lane_parallel_winding` for full exact K tracking.
pub fn step_lane_parallel(states: &[ExactState], f: &dyn PolynomialMap) -> Vec<ExactState> {
    let n = states.len();
    let mut out = vec![ExactState { lanes: [0u64; 6], winding: 0 }; n];

    for (li, &p) in SAFE_BASIS.iter().enumerate() {
        let lane: Vec<u64> = states.iter().map(|s| s.lanes[li]).collect();
        let new_lane = f.evaluate_lane(&lane, p);
        for j in 0..n {
            out[j].lanes[li] = new_lane[j];
        }
    }
    out
}

/// Evolve one step with exact winding propagation.
///
/// Two paths:
/// - LINEAR (propagate_winding returns Some): garner carry + analytic propagation.
/// - NONLINEAR (propagate_winding returns None): lift to true integers, evaluate.
pub fn step_lane_parallel_winding(
    states: &[ExactState],
    f: &dyn PolynomialMap,
) -> Vec<ExactState> {
    let n = states.len();

    // Step 1: lane-parallel residue update.
    let mut out = vec![ExactState { lanes: [0u64; 6], winding: 0 }; n];
    for (li, &p) in SAFE_BASIS.iter().enumerate() {
        let lane: Vec<u64> = states.iter().map(|s| s.lanes[li]).collect();
        let new_lane = f.evaluate_lane(&lane, p);
        for j in 0..n {
            out[j].lanes[li] = new_lane[j];
        }
    }

    // new_garner[i] = garner_reconstruct(new_lanes[i])
    let new_garner: Vec<i128> = out.iter().map(|s| s.to_u128() as i128).collect();

    // Step 2: compute winding.
    let old_winding: Vec<i128> = states.iter().map(|s| s.winding).collect();

    if let Some(k_linear) = f.propagate_winding(&old_winding) {
        // LINEAR path: carry from garner + linear propagation of old K.
        let old_garner: Vec<i128> = states.iter().map(|s| s.to_u128() as i128).collect();
        let f_of_garner = f.evaluate_i128_unbounded(&old_garner);
        for i in 0..n {
            let carry = (f_of_garner[i] - new_garner[i]).div_euclid(M_SAFE);
            out[i].winding = carry + k_linear[i];
        }
    } else {
        // NONLINEAR path: reconstruct true integers, evaluate F directly.
        let true_old: Vec<i128> = states.iter().map(|s| s.to_i128_exact()).collect();
        let f_of_true = f.evaluate_i128_unbounded(&true_old);
        for i in 0..n {
            out[i].winding = (f_of_true[i] - new_garner[i]).div_euclid(M_SAFE);
        }
    }

    out
}

// ============================================================================
// HEAT EQUATION 1D — degree-1 polynomial map
// ============================================================================

/// 1D heat equation in scaled integer form (periodic boundary).
///
/// Stencil: u_new[i] = a * u[i] + b * (u[i-1] + u[i+1])
///
/// Degree 1 (linear). Always subcritical for Transport Core (rho=3).
#[derive(Clone, Debug)]
pub struct HeatEquation1D {
    /// Number of grid cells.
    pub n: usize,
    /// Coefficient on the central cell.
    pub a: i128,
    /// Coefficient on each neighbor (left and right).
    pub b: i128,
}

impl PolynomialMap for HeatEquation1D {
    fn degree(&self) -> u32 {
        1
    }

    fn dim(&self) -> usize {
        self.n
    }

    fn evaluate_i128(&self, state: &[i128]) -> Vec<i128> {
        let n = self.n;
        let m = M_SAFE;
        let a = self.a.rem_euclid(m);
        let b = self.b.rem_euclid(m);
        let mut out = vec![0i128; n];
        for i in 0..n {
            let left = state[(i + n - 1) % n].rem_euclid(m);
            let right = state[(i + 1) % n].rem_euclid(m);
            let u = state[i].rem_euclid(m);
            let center_term = (a * u).rem_euclid(m);
            let neighbor_term = (b * (left + right)).rem_euclid(m);
            out[i] = (center_term + neighbor_term).rem_euclid(m);
        }
        out
    }

    fn evaluate_i128_unbounded(&self, state: &[i128]) -> Vec<i128> {
        let n = self.n;
        let mut out = vec![0i128; n];
        for i in 0..n {
            let left = state[(i + n - 1) % n];
            let right = state[(i + 1) % n];
            out[i] = self.a * state[i] + self.b * (left + right);
        }
        out
    }

    fn propagate_winding(&self, windings: &[i128]) -> Option<Vec<i128>> {
        // Linear: same stencil applied to winding vector.
        Some(self.evaluate_i128_unbounded(windings))
    }

    fn evaluate_lane(&self, lane: &[u64], p: u64) -> Vec<u64> {
        let n = self.n;
        let a_mod = ((self.a.rem_euclid(p as i128)) as u64) % p;
        let b_mod = ((self.b.rem_euclid(p as i128)) as u64) % p;
        let mut out = vec![0u64; n];
        for i in 0..n {
            let left = lane[(i + n - 1) % n];
            let right = lane[(i + 1) % n];
            let center_term = mulmod_u64(a_mod, lane[i], p);
            let neighbor_sum = addmod(left, right, p);
            let neighbor_term = mulmod_u64(b_mod, neighbor_sum, p);
            out[i] = addmod(center_term, neighbor_term, p);
        }
        out
    }
}

// ============================================================================
// BURGERS 1D — degree-2 polynomial map
// ============================================================================

/// 1D Burgers equation in scaled integer form (periodic boundary).
///
/// Stencil:
///   u_new[i] = c * u[i]
///            - u[i] * (u[i+1] - u[i-1])        (advection, quadratic)
///            + d * (u[i+1] - 2*u[i] + u[i-1])  (diffusion, linear)
///
/// Degree 2 (quadratic). Subcritical for Transport Core (rho=3, 2 < 3).
#[derive(Clone, Debug)]
pub struct Burgers1D {
    /// Number of grid cells.
    pub n: usize,
    /// Central scaling coefficient.
    pub c: i128,
    /// Diffusion coefficient.
    pub d: i128,
}

impl PolynomialMap for Burgers1D {
    fn degree(&self) -> u32 {
        2
    }

    fn dim(&self) -> usize {
        self.n
    }

    fn evaluate_i128(&self, state: &[i128]) -> Vec<i128> {
        let n = self.n;
        let m = M_SAFE;
        let c = self.c.rem_euclid(m);
        let d = self.d.rem_euclid(m);
        let mut out = vec![0i128; n];
        for i in 0..n {
            let left = state[(i + n - 1) % n].rem_euclid(m);
            let right = state[(i + 1) % n].rem_euclid(m);
            let u = state[i].rem_euclid(m);
            let diff_rl = (right - left).rem_euclid(m);
            let advection = (u * diff_rl).rem_euclid(m);
            let two_u = (2 * u).rem_euclid(m);
            let lap = (right + left - two_u).rem_euclid(m);
            let diffusion = (d * lap).rem_euclid(m);
            out[i] = (c * u - advection + diffusion).rem_euclid(m);
        }
        out
    }

    fn evaluate_i128_unbounded(&self, state: &[i128]) -> Vec<i128> {
        let n = self.n;
        let mut out = vec![0i128; n];
        for i in 0..n {
            let left = state[(i + n - 1) % n];
            let right = state[(i + 1) % n];
            let u = state[i];
            let advection = u * (right - left);
            let diffusion = self.d * (right - 2 * u + left);
            out[i] = self.c * u - advection + diffusion;
        }
        out
    }

    // Burgers is nonlinear -- propagate_winding returns None (default).

    fn evaluate_lane(&self, lane: &[u64], p: u64) -> Vec<u64> {
        let n = self.n;
        let c_mod = ((self.c.rem_euclid(p as i128)) as u64) % p;
        let d_mod = ((self.d.rem_euclid(p as i128)) as u64) % p;
        let two = 2u64 % p;
        let mut out = vec![0u64; n];
        for i in 0..n {
            let left = lane[(i + n - 1) % n];
            let right = lane[(i + 1) % n];
            let u = lane[i];
            let diff_rl = submod(right, left, p);
            let adv = mulmod_u64(u, diff_rl, p);
            let two_u = mulmod_u64(two, u, p);
            let lap_partial = submod(addmod(right, left, p), two_u, p);
            let diff_term = mulmod_u64(d_mod, lap_partial, p);
            let cu = mulmod_u64(c_mod, u, p);
            out[i] = submod(addmod(cu, diff_term, p), adv, p);
        }
        out
    }
}

// ============================================================================
// CYCLE DETECTION — decidable boundedness criterion
// ============================================================================

/// Simple cycle-sum diagnostic: sum all residues mod p.
///
/// If the orbit of a map on a finite residue lane returns to its start with
/// zero net sum change, the orbit is bounded on that lane.
pub fn cycle_sum(residues: &[u64], p: u64) -> u64 {
    let mut sum: u128 = 0;
    for &r in residues {
        sum += r as u128;
    }
    (sum % p as u128) as u64
}

/// Detect when lane residues cycle back to their starting configuration.
///
/// Returns `Some((period, net_winding))` where:
/// - `period` is the number of steps until lanes return to start
/// - `net_winding` is the total winding drift over one cycle (sum of all cells)
///
/// Returns `None` if no cycle found within `max_period` steps.
pub fn detect_cycle(
    start: &[ExactState],
    f: &dyn PolynomialMap,
    max_period: usize,
) -> Option<(usize, i128)> {
    let start_lanes: Vec<[u64; 6]> = start.iter().map(|s| s.lanes).collect();
    let start_sum: i128 = start.iter().map(|s| s.to_i128_exact()).sum();

    let mut state = start.to_vec();

    for step in 1..=max_period {
        state = step_lane_parallel_winding(&state, f);

        let lanes_match = state
            .iter()
            .zip(start_lanes.iter())
            .all(|(s, orig)| s.lanes == *orig);

        if lanes_match {
            let current_sum: i128 = state.iter().map(|s| s.to_i128_exact()).sum();
            let net_k = (current_sum - start_sum).div_euclid(M_SAFE);
            return Some((step, net_k));
        }
    }
    None
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // ── Test 1: Heat lane-parallel agrees with i128 reference ─────────────
    #[test]
    fn heat_lane_parallel_matches_i128_reference() {
        let n = 8;
        let f = HeatEquation1D { n, a: 2, b: 1 };

        // Single bump at cell 4.
        let init: Vec<i128> = vec![0, 0, 0, 0, 4, 0, 0, 0];
        let mut ref_state = init.clone();
        let mut crt_state = ExactState::from_i128_vec(&init);

        for step in 0..10 {
            ref_state = f.evaluate_i128(&ref_state);
            crt_state = step_lane_parallel(&crt_state, &f);

            for i in 0..n {
                let ref_resid = ref_state[i].rem_euclid(M_SAFE);
                let crt_resid = crt_state[i].to_u128() as i128;
                assert_eq!(
                    ref_resid, crt_resid,
                    "heat step {} cell {}: ref={}, crt={}",
                    step, i, ref_resid, crt_resid
                );
            }
        }
    }

    // ── Test 2: Burgers lane-parallel agrees with i128 reference ──────────
    #[test]
    fn burgers_lane_parallel_matches_i128_reference() {
        let n = 8;
        let f = Burgers1D { n, c: 1, d: 1 };

        // Alternating pattern.
        let init: Vec<i128> = vec![1, 0, -1, 0, 1, 0, -1, 0];
        let mut ref_state = init.clone();
        let mut crt_state = ExactState::from_i128_vec(&init);

        for step in 0..5 {
            ref_state = f.evaluate_i128(&ref_state);
            crt_state = step_lane_parallel(&crt_state, &f);

            for i in 0..n {
                let ref_resid = ref_state[i].rem_euclid(M_SAFE);
                let crt_resid = crt_state[i].to_u128() as i128;
                assert_eq!(
                    ref_resid, crt_resid,
                    "burgers step {} cell {}: ref={}, crt={}",
                    step, i, ref_resid, crt_resid
                );
            }
        }
    }

    // ── Test 3: Winding conservation for Heat (identity stencil) ──────────
    #[test]
    fn winding_conservation_heat() {
        let n = 4;
        // Identity stencil: a=1, b=0. State unchanged each step.
        let f = HeatEquation1D { n, a: 1, b: 0 };
        let init = ExactState::from_i128_vec(&[3, 7, 11, 2]);

        let stepped = step_lane_parallel_winding(&init, &f);

        for (i, s) in stepped.iter().enumerate() {
            assert_eq!(
                s.winding, 0,
                "cell {} winding should be 0 after identity step, got {}",
                i, s.winding
            );
            assert_eq!(
                s.to_i128_exact(),
                init[i].to_i128_exact(),
                "cell {} value should be unchanged"
            , i);
        }
    }

    // ── Test 4: DKAM subcriticality check ─────────────────────────────────
    #[test]
    fn dkam_subcriticality() {
        let heat = HeatEquation1D { n: 8, a: 2, b: 1 };
        let burgers = Burgers1D { n: 8, c: 1, d: 1 };

        // rho(Transport Core) = min{3,7,11,13} = 3
        let rho: u32 = 3;

        assert!(
            heat.degree() < rho,
            "heat degree={} must be < rho={}",
            heat.degree(),
            rho
        );
        assert!(
            burgers.degree() < rho,
            "burgers degree={} must be < rho={}",
            burgers.degree(),
            rho
        );
    }

    // ── Test 5: cycle_sum basic / detect_cycle at fixed point ─────────────
    #[test]
    fn cycle_detection_fixed_point() {
        let n = 4;
        let f = HeatEquation1D { n, a: 2, b: 1 };

        // Zero is a fixed point.
        let zero_state = ExactState::from_i128_vec(&[0, 0, 0, 0]);
        let result = detect_cycle(&zero_state, &f, 10);
        assert_eq!(result, Some((1, 0)), "zero fixed point: period=1, net_k=0");

        // Basic cycle_sum.
        assert_eq!(cycle_sum(&[1, 2, 3, 4], 7), (1 + 2 + 3 + 4) % 7);
        assert_eq!(cycle_sum(&[5, 5, 5], 5), 0);
    }

    // ── Test 6: ExactState roundtrip ──────────────────────────────────────
    #[test]
    fn exact_state_roundtrip() {
        let test_values: &[i128] = &[0, 1, -1, 15015, 30030, 100_000, -100_000, 1_234_567];

        for &x in test_values {
            let s = ExactState::from_i128(x);
            let recovered = s.to_i128_exact();
            assert_eq!(recovered, x, "roundtrip failed for x={}", x);
        }

        // Verify winding for specific cases.
        let s0 = ExactState::from_i128(0);
        assert_eq!(s0.winding, 0);

        let s_neg = ExactState::from_i128(-1);
        assert_eq!(s_neg.winding, -1);

        let s_m = ExactState::from_i128(M_SAFE);
        assert_eq!(s_m.winding, 1);

        let s_2m = ExactState::from_i128(2 * M_SAFE);
        assert_eq!(s_2m.winding, 2);
    }

    // ── Test 7: Multi-step Heat evolution ─────────────────────────────────
    #[test]
    fn multi_step_heat() {
        let n = 4;
        let f = HeatEquation1D { n, a: 2, b: 1 };
        let init_vals: Vec<i128> = vec![1, 2, 3, 4];

        let mut state = ExactState::from_i128_vec(&init_vals);
        let mut true_vals = init_vals.clone();

        for _step in 0..20 {
            state = step_lane_parallel_winding(&state, &f);
            true_vals = f.evaluate_i128_unbounded(&true_vals);
        }

        for i in 0..n {
            assert_eq!(
                state[i].to_i128_exact(),
                true_vals[i],
                "cell {} multi-step heat mismatch at step 20",
                i
            );
        }
    }

    // ── Test 8: Multi-step Burgers ────────────────────────────────────────
    #[test]
    fn multi_step_burgers() {
        let n = 4;
        let f = Burgers1D { n, c: 1, d: 1 };
        let init_vals: Vec<i128> = vec![1, 0, -1, 0];

        let mut ref_state = init_vals.clone();
        let mut crt_state = ExactState::from_i128_vec(&init_vals);

        for step in 0..5 {
            ref_state = f.evaluate_i128(&ref_state);
            crt_state = step_lane_parallel(&crt_state, &f);

            for i in 0..n {
                let ref_resid = ref_state[i].rem_euclid(M_SAFE);
                let crt_resid = crt_state[i].to_u128() as i128;
                assert_eq!(
                    ref_resid, crt_resid,
                    "burgers step {} cell {} mismatch",
                    step, i
                );
            }
        }
    }

    // ── Test 9: Winding propagation for Heat ──────────────────────────────
    #[test]
    fn winding_propagation_heat() {
        let n = 4;
        let f = HeatEquation1D { n, a: 2, b: 1 };

        // Start with winding = 1 (true values ~ M + small).
        let true_values: Vec<i128> = (0..n as i128).map(|i| M_SAFE + i).collect();
        let init = ExactState::from_i128_vec(&true_values);

        // Verify initial winding.
        for (i, s) in init.iter().enumerate() {
            assert_eq!(s.winding, 1, "cell {} initial winding should be 1", i);
        }

        let stepped = step_lane_parallel_winding(&init, &f);
        let expected_true = f.evaluate_i128_unbounded(&true_values);

        for i in 0..n {
            assert_eq!(
                stepped[i].to_i128_exact(),
                expected_true[i],
                "cell {} winding propagation mismatch: got {}, expected {}",
                i,
                stepped[i].to_i128_exact(),
                expected_true[i]
            );
        }
    }

    // ── Test 10: Deep winding (many steps) ────────────────────────────────
    #[test]
    fn deep_winding() {
        let n = 4;
        let f = HeatEquation1D { n, a: 2, b: 1 };
        let init_true: Vec<i128> = vec![1, 2, 3, 4];

        let mut state = ExactState::from_i128_vec(&init_true);
        let mut true_vals = init_true.clone();

        for _step in 0..30 {
            state = step_lane_parallel_winding(&state, &f);
            true_vals = f.evaluate_i128_unbounded(&true_vals);
        }

        for i in 0..n {
            assert_eq!(
                state[i].to_i128_exact(),
                true_vals[i],
                "cell {} deep winding mismatch at step 30",
                i
            );
        }

        // Verify winding tracks magnitude correctly.
        for i in 0..n {
            let expected_k = (true_vals[i] - true_vals[i].rem_euclid(M_SAFE)) / M_SAFE;
            assert_eq!(
                state[i].winding, expected_k,
                "cell {} winding K={} should be {}",
                i, state[i].winding, expected_k
            );
        }
    }

    // ── Test 11: from_i128_vec / to_i128_vec roundtrip ────────────────────
    #[test]
    fn from_i128_vec_to_i128_vec_roundtrip() {
        let values: Vec<i128> = vec![0, 1, -1, 30030, -30030, 99999, -99999, 12345];
        let states = ExactState::from_i128_vec(&values);
        let recovered = ExactState::to_i128_vec(&states);
        assert_eq!(values, recovered);
    }

    // ── Test 12: Heat symmetry ────────────────────────────────────────────
    #[test]
    fn heat_symmetry() {
        // Symmetric initial condition on a 5-cell periodic grid.
        let n = 5;
        let f = HeatEquation1D { n, a: 2, b: 1 };
        let init: Vec<i128> = vec![1, 2, 3, 2, 1];

        let result = f.evaluate_i128_unbounded(&init);

        // Heat stencil preserves palindrome symmetry on periodic grids:
        // result[i] should equal result[n-1-i] for a symmetric init.
        // Periodic: cell 0 neighbors are cell 4 and cell 1.
        // cell 0: a*1 + b*(1 + 2) = 2 + 3 = 5
        // cell 1: a*2 + b*(1 + 3) = 4 + 4 = 8
        // cell 2: a*3 + b*(2 + 2) = 6 + 4 = 10
        // cell 3: a*2 + b*(3 + 1) = 4 + 4 = 8
        // cell 4: a*1 + b*(2 + 1) = 2 + 3 = 5
        assert_eq!(result, vec![5, 8, 10, 8, 5]);

        // Verify symmetry: result[0]==result[4], result[1]==result[3]
        assert_eq!(result[0], result[4]);
        assert_eq!(result[1], result[3]);
    }
}
