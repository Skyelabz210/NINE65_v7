//! K-Elimination Engine — exact winding recovery from coprime residues.
//!
//! The fundamental CRAM bridge operation. Given a value X living in two
//! coprime lanes (mod m) and (mod a), extracts the exact winding number:
//!
//! ```text
//!     k ≡ (s − r) · m⁻¹ (mod a)
//!     X = r + k·m     (unique for 0 ≤ X < m·a)
//! ```
//!
//! The winding number k is ALWAYS an exact integer — a topological invariant
//! counting how many times X wraps the smaller modulus.
//!
//! Also provides: Garner reconstruction as iterated K-Elimination, batch
//! winding survey, cross-lane winding matrix, p-adic digit extraction
//! (triple K-Elim), and the winding-lift phase differential (Theorem 7.3).
//!
//! Zero floating point. All arithmetic exact integer (A1).

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
#[cfg(feature = "std")]
use std::vec::Vec;

// ═══════════════════════════════════════════════════════════════════════════
// Modular arithmetic primitives
// ═══════════════════════════════════════════════════════════════════════════

/// Extended GCD: returns (gcd, x, y) where a·x + b·y = gcd.
pub fn extended_gcd(a: i128, b: i128) -> (i128, i128, i128) {
    if a == 0 {
        return (b, 0, 1);
    }
    let (g, x1, y1) = extended_gcd(b % a, a);
    (g, y1 - (b / a) * x1, x1)
}

/// Modular inverse of `a` mod `m`. Returns `None` if `gcd(a, m) != 1`.
pub fn mod_inv(a: i128, m: i128) -> Option<i128> {
    let a_mod = ((a % m) + m) % m;
    let (g, x, _) = extended_gcd(a_mod, m);
    if g != 1 {
        return None;
    }
    Some(((x % m) + m) % m)
}

/// Safe modular reduction (handles negatives correctly).
#[inline(always)]
pub fn modd(a: i128, m: i128) -> i128 {
    ((a % m) + m) % m
}

/// Modular multiplication via widening to avoid overflow.
#[inline(always)]
pub fn mulmod(a: i128, b: i128, m: i128) -> i128 {
    // For i128 inputs, the product may exceed i128 range.
    // Use the schoolbook doubling method for safety.
    let a = modd(a, m);
    let b = modd(b, m);
    // If both fit in i64, use u128 product directly.
    if a < (1i128 << 63) && b < (1i128 << 63) {
        return (a * b) % m;
    }
    // Binary-double-add method for large moduli.
    let mut result = 0i128;
    let mut base = a % m;
    let mut exp = b;
    while exp > 0 {
        if exp & 1 == 1 {
            result = (result + base) % m;
        }
        base = (base + base) % m;
        exp >>= 1;
    }
    result
}

/// Modular exponentiation.
pub fn powmod(mut base: i128, mut exp: u64, m: i128) -> i128 {
    if m == 1 {
        return 0;
    }
    let mut result = 1i128;
    base = modd(base, m);
    while exp > 0 {
        if exp & 1 == 1 {
            result = mulmod(result, base, m);
        }
        exp >>= 1;
        if exp > 0 {
            base = mulmod(base, base, m);
        }
    }
    result
}

/// GCD for i128 (absolute values).
pub fn gcd(a: i128, b: i128) -> i128 {
    let (mut a, mut b) = (a.unsigned_abs(), b.unsigned_abs());
    while b != 0 {
        let t = b;
        b = a % b;
        a = t;
    }
    a as i128
}

/// 2-adic valuation of n.
pub fn v2(n: i128) -> u32 {
    if n == 0 {
        return 128;
    }
    n.unsigned_abs().trailing_zeros()
}

// ═══════════════════════════════════════════════════════════════════════════
// K-Elimination
// ═══════════════════════════════════════════════════════════════════════════

/// Result of a K-Elimination operation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KElimResult {
    /// The winding number (always exact integer).
    pub k: i128,
    /// Reconstructed value in [0, m·a).
    pub value: i128,
    /// Modulus of the first lane.
    pub m: i128,
    /// Modulus of the second lane.
    pub a: i128,
}

/// Perform K-Elimination between two coprime lanes.
///
/// Given: X ≡ r (mod m), X ≡ s (mod a), gcd(m,a) = 1.
/// Returns: `Some(result)` with k such that X = r + k·m, k ∈ [0, a).
/// Returns `None` if the moduli are not coprime.
pub fn k_eliminate(r: i128, m: i128, s: i128, a: i128) -> Option<KElimResult> {
    let m_inv_a = mod_inv(m, a)?;
    let k = modd((s - modd(r, a)) * m_inv_a, a);
    let value = r + k * m;
    Some(KElimResult { k, value, m, a })
}

/// Multi-lane CRT reconstruction via iterated K-Elimination (Garner's algorithm).
///
/// Given residues `(r_i, m_i)` with all `m_i` pairwise coprime, reconstructs
/// the unique X in `[0, ∏m_i)`. Returns `None` if any pair is not coprime.
pub fn garner_reconstruct(residues: &[(i128, i128)]) -> Option<i128> {
    if residues.is_empty() {
        return Some(0);
    }
    let (mut value, mut modulus) = residues[0];
    value = modd(value, modulus);

    for &(r_i, m_i) in &residues[1..] {
        let result = k_eliminate(value, modulus, r_i, m_i)?;
        value = result.value;
        modulus *= m_i;
    }
    Some(value)
}

/// Batch K-Elimination: compute winding numbers between a reference
/// lane and all other lanes. Returns `Vec<(lane_modulus, winding_k)>`.
/// Returns `None` if any lane is not coprime with the reference.
pub fn k_elim_survey(
    ref_residue: i128,
    ref_mod: i128,
    lanes: &[(i128, i128)],
) -> Option<Vec<(i128, i128)>> {
    lanes
        .iter()
        .map(|&(residue, modulus)| {
            let result = k_eliminate(ref_residue, ref_mod, residue, modulus)?;
            Some((modulus, result.k))
        })
        .collect()
}

/// Cross-lane K-Elimination matrix: compute k between every pair.
/// Returns a k×k matrix where `matrix[i][j]` is the winding from lane i to lane j.
/// Returns `None` if any coprime pair fails (non-coprime pairs get 0).
pub fn k_elim_matrix(lanes: &[(i128, i128)]) -> Option<Vec<Vec<i128>>> {
    let n = lanes.len();
    let mut matrix = vec![vec![0i128; n]; n];
    for i in 0..n {
        for j in (i + 1)..n {
            let (r_i, m_i) = lanes[i];
            let (r_j, m_j) = lanes[j];
            if gcd(m_i, m_j) == 1 {
                let res_ij = k_eliminate(r_i, m_i, r_j, m_j)?;
                matrix[i][j] = res_ij.k;
                let res_ji = k_eliminate(r_j, m_j, r_i, m_i)?;
                matrix[j][i] = res_ji.k;
            }
        }
    }
    Some(matrix)
}

// ═══════════════════════════════════════════════════════════════════════════
// p-adic digit ladder (Triple K-Elimination, the 5th operator)
// ═══════════════════════════════════════════════════════════════════════════

/// Extract p-adic digits: x = κ₀ + p·κ₁ + p²·κ₂ + p³·κ₃ + O(p⁴).
/// Semantics: κ₀ position, κ₁ linear memory, κ₂ family type, κ₃ individual history.
pub fn triple_k_elim(x: i128, p: i128) -> (i128, i128, i128, i128) {
    (x % p, (x / p) % p, (x / (p * p)) % p, (x / (p * p * p)) % p)
}

/// Generalized p-adic digit ladder of arbitrary depth. Exact.
pub fn k_elim_tower(x: i128, p: i128, depth: usize) -> Vec<i128> {
    let mut digits = Vec::with_capacity(depth);
    let mut remaining = x;
    for _ in 0..depth {
        digits.push(modd(remaining, p));
        remaining /= p;
    }
    digits
}

// ═══════════════════════════════════════════════════════════════════════════
// Winding lift by phase differential (Theorem 7.3)
// ═══════════════════════════════════════════════════════════════════════════

/// Congruence class of the winding k modulo A, recovered from the phase
/// differential between two residue systems.
///
/// Given x = v_M + k·M with gcd(M,A)=1, returns k mod A.
pub fn winding_lift_phase(v_m: i128, v_a: i128, big_m: i128, a: i128) -> Option<i128> {
    if gcd(big_m, a) != 1 {
        return None;
    }
    let m_inv = mod_inv(big_m, a)?;
    Some(modd((v_a - v_m) * m_inv, a))
}

// ═══════════════════════════════════════════════════════════════════════════
// CRT utilities
// ═══════════════════════════════════════════════════════════════════════════

/// Decompose x into residues over a basis.
pub fn decompose(x: i128, basis: &[i128]) -> Vec<i128> {
    basis.iter().map(|&p| modd(x, p)).collect()
}

/// CRT reconstruction weights for a basis.
/// Returns `(weights, M)` where `X = (Σ r_i · w_i) mod M`.
pub fn crt_weights(basis: &[i128]) -> Option<(Vec<i128>, i128)> {
    let m: i128 = basis.iter().product();
    let mut weights = Vec::with_capacity(basis.len());
    for &p in basis {
        let mi = m / p;
        let inv = mod_inv(mi, p)?;
        weights.push(mi * inv);
    }
    Some((weights, m))
}

/// K-Elimination exact division: given residues of `a` and a divisor `b`
/// coprime to the basis product, returns the residues and integer value
/// of the quotient `a/b`.
///
/// Precondition: gcd(b, M) = 1 and b | a.
pub fn k_elim_divide(
    residues: &[i128],
    basis: &[i128],
    b: i128,
) -> Option<(Vec<i128>, i128)> {
    let m: i128 = basis.iter().product();
    if gcd(b, m) != 1 {
        return None;
    }
    let mut alpha = Vec::with_capacity(basis.len());
    for (&r, &p) in residues.iter().zip(basis.iter()) {
        let b_inv = mod_inv(b, p)?;
        alpha.push(modd(r * b_inv, p));
    }
    let q = garner_reconstruct(
        &alpha.iter().copied().zip(basis.iter().copied()).collect::<Vec<_>>(),
    )?;
    Some((alpha, q))
}

/// Fused Piggyback Division: exact quotient a/b when b shares a factor with M.
/// Uses an auxiliary prime coprime to both b and M for certification.
///
/// Returns `(quotient_residues, quotient, aux_prime)`.
pub fn fpd(
    a_int: i128,
    basis: &[i128],
    b: i128,
    aux_candidates: &[i128],
) -> Option<(Vec<i128>, i128, i128)> {
    let m: i128 = basis.iter().product();
    let p_aux = aux_candidates
        .iter()
        .copied()
        .find(|&c| gcd(c, b) == 1 && gcd(c, m) == 1)?;

    let (q, rem) = (a_int / b, a_int % b);
    if rem != 0 {
        return None;
    }

    // Verify through auxiliary lane.
    let r_aux = modd(a_int, p_aux);
    let b_inv_aux = mod_inv(b, p_aux)?;
    let q_aux = modd(r_aux * b_inv_aux, p_aux);
    if q_aux != modd(q, p_aux) {
        return None;
    }

    let q_residues: Vec<i128> = basis.iter().map(|&p| modd(q, p)).collect();
    Some((q_residues, q, p_aux))
}

/// Default auxiliary primes for FPD (all coprime to S8).
pub const AUX_FPD_POOL: [i128; 7] = [23, 29, 31, 37, 41, 43, 47];

// ═══════════════════════════════════════════════════════════════════════════
// Winding tower arithmetic (bounded-digit carry propagation)
// ═══════════════════════════════════════════════════════════════════════════

/// Reconstruct the winding integer K from its tower digits. Exact.
/// K = Σ_i k_i · W_i, where W_i = ∏_{j<i} μ_j.
pub fn k_from_tower(kd: &[i128], mus: &[i128]) -> i128 {
    let mut k = 0i128;
    let mut w = 1i128;
    for (i, &ki) in kd.iter().enumerate() {
        k += ki * w;
        if i < mus.len() {
            w *= mus[i];
        }
    }
    k
}

/// Express K as a depth-d winding tower: levels 0..d-2 in [0, μ_i),
/// top level absorbs overflow (signed, growable). Exact mixed-radix digits.
pub fn k_to_tower(k: i128, mus: &[i128], depth: usize) -> Vec<i128> {
    if depth == 0 {
        return Vec::new();
    }
    let mut weights = Vec::with_capacity(depth);
    weights.push(1i128);
    for i in 0..(depth - 1) {
        weights.push(weights[i] * mus[i]);
    }
    let mut digits: Vec<i128> = (0..(depth - 1))
        .map(|i| modd(k / weights[i], mus[i]))
        .collect();
    digits.push(k / weights[depth - 1]);
    digits
}

/// Add two depth-d towers with bounded-digit carry propagation.
/// Lower levels stay in [0, μ_i); the top absorbs the rest.
pub fn tower_add(a: &[i128], b: &[i128], mus: &[i128], depth: usize, c0: i128) -> Vec<i128> {
    let mut out = vec![0i128; depth];
    let mut carry = c0;
    for i in 0..depth {
        let ai = if i < a.len() { a[i] } else { 0 };
        let bi = if i < b.len() { b[i] } else { 0 };
        let s = ai + bi + carry;
        if i < depth - 1 {
            let r = modd(s, mus[i]);
            carry = (s - r) / mus[i];
            out[i] = r;
        } else {
            out[i] = s;
        }
    }
    out
}

/// Single-carry canonicalization: propagate carry through bounded-digit levels.
pub fn add_carry(kd: &mut [i128], mus: &[i128], mut c: i128) {
    let d = kd.len();
    let mut i = 0;
    while i < d - 1 && c != 0 {
        kd[i] += c;
        if kd[i] >= mus[i] {
            c = kd[i] / mus[i];
            kd[i] %= mus[i];
        } else if kd[i] < 0 {
            let borrow = (-kd[i] + mus[i] - 1) / mus[i];
            kd[i] += borrow * mus[i];
            c = -borrow;
        } else {
            c = 0;
        }
        i += 1;
    }
    if c != 0 {
        kd[d - 1] += c;
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    // --- modular arithmetic ---

    #[test]
    fn mod_inv_basic() {
        assert_eq!(mod_inv(2, 7), Some(4)); // 2·4 = 8 ≡ 1 mod 7
        assert_eq!(mod_inv(3, 7), Some(5)); // 3·5 = 15 ≡ 1 mod 7
        assert_eq!(mod_inv(2, 105).map(|inv| mulmod(inv, 2, 105)), Some(1));
    }

    #[test]
    fn mod_inv_non_coprime() {
        assert_eq!(mod_inv(6, 9), None);
        assert_eq!(mod_inv(0, 7), None);
    }

    #[test]
    fn powmod_basic() {
        assert_eq!(powmod(3, 4, 100), 81);
        assert_eq!(powmod(2, 10, 1000), 24);
        assert_eq!(powmod(7, 0, 13), 1);
    }

    // --- K-Elimination ---

    #[test]
    fn kelim_basic() {
        // X = 42: 42 mod 7 = 0, 42 mod 11 = 9
        let r = k_eliminate(0, 7, 9, 11).unwrap();
        assert_eq!(r.k, 6); // k = (9-0)·7⁻¹ mod 11 = 9·8 mod 11 = 72 mod 11 = 6
        assert_eq!(r.value, 42);
    }

    #[test]
    fn kelim_non_coprime_returns_none() {
        assert!(k_eliminate(0, 6, 3, 9).is_none());
    }

    #[test]
    fn kelim_large_value() {
        // K-Elim between two lanes reconstructs in [0, m·a).
        // X = 1049: 1049 mod 105 = 104, 1049 mod 16 = 9
        let x = 1049i128;
        let r = k_eliminate(x % 105, 105, x % 16, 16).unwrap();
        assert_eq!(r.value, x);
        // For M₈-1, use full Garner reconstruction across S8.
        let x2 = 9_699_689i128;
        let basis: Vec<i128> = vec![2, 3, 5, 7, 11, 13, 17, 19];
        let residues: Vec<(i128, i128)> =
            basis.iter().map(|&p| (x2 % p, p)).collect();
        assert_eq!(garner_reconstruct(&residues).unwrap(), x2);
    }

    // --- Garner reconstruction ---

    #[test]
    fn garner_2way() {
        let val = garner_reconstruct(&[(79, 105), (10, 16)]).unwrap();
        assert_eq!(val, 394);
    }

    #[test]
    fn garner_3way() {
        // 42 mod 3 = 0, 42 mod 5 = 2, 42 mod 7 = 0
        let val = garner_reconstruct(&[(0, 3), (2, 5), (0, 7)]).unwrap();
        assert_eq!(val, 42);
    }

    #[test]
    fn garner_s8_roundtrip() {
        let basis: Vec<i128> = vec![2, 3, 5, 7, 11, 13, 17, 19];
        let m: i128 = basis.iter().product(); // 9_699_690
        for &x in &[0, 1, 42, 1000, m / 2, m - 1] {
            let residues: Vec<(i128, i128)> =
                basis.iter().map(|&p| (x % p, p)).collect();
            let recovered = garner_reconstruct(&residues).unwrap();
            assert_eq!(recovered, x, "roundtrip failed for x={x}");
        }
    }

    // --- batch K-Elim ---

    #[test]
    fn kelim_survey_basic() {
        let survey = k_elim_survey(0, 7, &[(9, 11), (2, 5)]).unwrap();
        assert_eq!(survey[0], (11, 6)); // winding for 42 from mod-7 to mod-11
    }

    #[test]
    fn kelim_matrix_basic() {
        let lanes: Vec<(i128, i128)> = vec![(0, 3), (2, 5), (0, 7)]; // X=42
        let matrix = k_elim_matrix(&lanes).unwrap();
        // matrix[0][1] = k from lane 0 (mod 3) to lane 1 (mod 5)
        let r01 = k_eliminate(0, 3, 2, 5).unwrap();
        assert_eq!(matrix[0][1], r01.k);
    }

    // --- p-adic digits ---

    #[test]
    fn triple_kelim_basic() {
        // 42 base 5: 42 = 2 + 5·3 + 25·1 + 125·0  (digits: 2, 3, 1, 0)
        let (k0, k1, k2, k3) = triple_k_elim(42, 5);
        assert_eq!(k0, 2);
        assert_eq!(k1, 3);
        assert_eq!(k2, 1);
        assert_eq!(k3, 0);
        assert_eq!(k0 + 5 * k1 + 25 * k2 + 125 * k3, 42);
    }

    #[test]
    fn kelim_tower_roundtrip() {
        let digits = k_elim_tower(12345, 7, 6);
        let mut reconstructed = 0i128;
        let mut power = 1i128;
        for &d in &digits {
            reconstructed += d * power;
            power *= 7;
        }
        assert_eq!(reconstructed, 12345);
    }

    // --- winding lift phase ---

    #[test]
    fn winding_lift_basic() {
        // x = 394, M = 105, A = 16
        // 394 = 79 + 3·105, so K = 3
        // v_M = 79 (= 394 mod 105), v_A = 10 (= 394 mod 16)
        let k = winding_lift_phase(79, 10, 105, 16).unwrap();
        assert_eq!(k, 3);
    }

    // --- CRT utilities ---

    #[test]
    fn decompose_basic() {
        let r = decompose(42, &[3, 5, 7]);
        assert_eq!(r, vec![0, 2, 0]);
    }

    #[test]
    fn crt_weights_basic() {
        let (weights, m) = crt_weights(&[3, 5, 7]).unwrap();
        assert_eq!(m, 105);
        // Verify: each weight ≡ 1 at its own lane, 0 at others
        for (i, &w) in weights.iter().enumerate() {
            for (j, &p) in [3i128, 5, 7].iter().enumerate() {
                if i == j {
                    assert_eq!(w % p, 1, "weight {i} should be 1 mod {p}");
                } else {
                    assert_eq!(w % p, 0, "weight {i} should be 0 mod {p}");
                }
            }
        }
    }

    // --- K-Elim exact division ---

    #[test]
    fn kelim_divide_basic() {
        let basis = vec![3i128, 5, 7];
        // a = 88, b = 8. gcd(8, 105) = 1 since 105 = 3·5·7.  88/8 = 11.
        let a = 88i128;
        let b = 8i128;
        let a_res: Vec<i128> = basis.iter().map(|&p| a % p).collect();
        let (q_res, q) = k_elim_divide(&a_res, &basis, b).unwrap();
        assert_eq!(q, 11);
        assert_eq!(q_res, decompose(11, &basis));
    }

    // --- FPD ---

    #[test]
    fn fpd_basic() {
        let basis = vec![3i128, 5, 7];
        // a = 210, b = 5 (shares factor with M=105)
        let (q_res, q, p_aux) = fpd(210, &basis, 5, &AUX_FPD_POOL).unwrap();
        assert_eq!(q, 42);
        assert_eq!(q_res, decompose(42, &basis));
        assert!(gcd(p_aux, 5) == 1);
    }

    // --- winding tower ---

    #[test]
    fn tower_roundtrip() {
        let mus: Vec<i128> = vec![17, 19, 23, 29];
        let k = 12345i128;
        let tower = k_to_tower(k, &mus, 4);
        let recovered = k_from_tower(&tower, &mus);
        assert_eq!(recovered, k);
    }

    #[test]
    fn tower_add_basic() {
        let mus: Vec<i128> = vec![17, 19, 23];
        let a = k_to_tower(100, &mus, 3);
        let b = k_to_tower(200, &mus, 3);
        let sum = tower_add(&a, &b, &mus, 3, 0);
        assert_eq!(k_from_tower(&sum, &mus), 300);
    }

    #[test]
    fn tower_add_with_carry() {
        let mus: Vec<i128> = vec![17, 19, 23];
        let a = k_to_tower(100, &mus, 3);
        let b = k_to_tower(200, &mus, 3);
        // carry c0 = 1 → result should be 301
        let sum = tower_add(&a, &b, &mus, 3, 1);
        assert_eq!(k_from_tower(&sum, &mus), 301);
    }

    #[test]
    fn add_carry_propagation() {
        let mus: Vec<i128> = vec![17, 19, 23];
        // Start with a carry of 20 into level 0 (which already has 5):
        // level 0 gets 5 + 20 = 25, which exceeds μ₀=17
        // → carry 1 to level 1, level 0 = 25 - 17 = 8
        let mut kd = vec![5i128, 3, 0];
        let orig_val = k_from_tower(&kd, &mus);
        add_carry(&mut kd, &mus, 20);
        assert!(kd[0] >= 0 && kd[0] < 17, "level 0 should be in [0, 17)");
        assert_eq!(k_from_tower(&kd, &mus), orig_val + 20);
    }
}
