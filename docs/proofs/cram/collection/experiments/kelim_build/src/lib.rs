//! # K-Elimination — Universal Coprimality Invariant
//!
//! K-Elimination recovers the floor quotient `⌊X/M⌋` from the residue pair
//! `(X mod M, X mod A)` entirely within residue space. The single requirement
//! is `gcd(M, A) = 1`. Primality of M or A is neither required nor implied.
//!
//! ## Axioms
//! - **A1**: Zero floating-point operations. Every path is integer arithmetic.
//! - **A2**: No approximation. Exact integers throughout; no rounding, ever.
//!
//! ## Core operations
//! - [`k_elim`]            — general winding recovery (any coprime pair)
//! - [`k_elim_adjacent`]   — multiply-free form when A = M+1
//! - [`k_elim_dual`]       — recover `⌊X/A⌋` from the same residue pair
//! - [`k_elim_gradient`]   — partial recovery when `gcd(M,A) = d > 1`
//! - [`tower_digit`]       — one level of an n-modulus tower (in residue space)
//! - [`winding_residue`]   — read a winding's residue on a coprime lane
//! - [`rns_less_than`]     — branch-free signed comparison
//!
//! ## What is deliberately absent
//! No Garner / mixed-radix reconstruction. Assembling `X = Σ dᵢ·radixⁱ` exits
//! residue space, runs O(n²) with a cross-level subtraction cascade, and
//! couples the digits — destroying the i.i.d. carry structure. The winding is
//! carried as a *coherent residue family*, never assembled into an integer.

pub mod selector;

/// Greatest common divisor (Euclid). Exact integer.
pub const fn gcd(mut a: i128, mut b: i128) -> i128 {
    while b != 0 {
        let t = b;
        b = a % b;
        a = t;
    }
    if a < 0 { -a } else { a }
}

/// Modular inverse of `a` modulo `m`, in `[0, m)`.
/// Returns `None` iff `gcd(a, m) != 1`. Exact (extended Euclid).
pub fn mod_inv(a: i128, m: i128) -> Option<i128> {
    let (mut old_r, mut r) = (a.rem_euclid(m), m);
    let (mut old_s, mut s) = (1i128, 0i128);
    while r != 0 {
        let q = old_r / r;
        let tmp_r = old_r - q * r;
        old_r = r;
        r = tmp_r;
        let tmp_s = old_s - q * s;
        old_s = s;
        s = tmp_s;
    }
    if old_r != 1 {
        None
    } else {
        Some(old_s.rem_euclid(m))
    }
}

/// **K-Elimination** (Theorem 1). Recovers `⌊X/M⌋ mod A` from `(vM, vA)`.
///
/// Requires `gcd(M, A) = 1`. Returns the winding in `[0, A)`.
///
/// # Panics
/// Panics (debug) if `gcd(M, A) != 1`.
pub fn k_elim(v_m: i128, v_a: i128, m: i128, a: i128) -> i128 {
    let m_inv = mod_inv(m, a).expect("K-Elim requires gcd(M,A)=1");
    ((v_a - v_m).rem_euclid(a) * m_inv) % a
}

/// **Adjacent K-Elimination** (Corollary 4.4). For `A = M + 1`.
///
/// `M⁻¹ ≡ -1 (mod A)` (Lemma 4.3, holds for any M, prime or composite),
/// so the winding collapses to a subtraction: `(vM - vA) mod (M+1)`.
/// No modular inverse, no multiplication.
pub fn k_elim_adjacent(v_m: i128, v_a: i128, m: i128) -> i128 {
    (v_m - v_a).rem_euclid(m + 1)
}

/// **Dual K-Elimination** (Theorem 5.1). Recovers `⌊X/A⌋ mod M` from the
/// same residue pair `(vM, vA)`. Requires `gcd(M, A) = 1`.
pub fn k_elim_dual(v_m: i128, v_a: i128, m: i128, a: i128) -> i128 {
    let a_inv = mod_inv(a, m).expect("Dual K-Elim requires gcd(A,M)=1");
    ((v_m - v_a).rem_euclid(m) * a_inv) % m
}

/// **Resolution Gradient** (Theorem 6.1). When `gcd(M, A) = d > 1`,
/// recovers `⌊X/M⌋ mod (A/d)` — partial winding at reduced resolution.
///
/// Returns `(winding_mod_a_over_d, a_over_d)`.
///
/// # Panics
/// Panics (debug) if `d` does not divide `(vA - vM)` (should never happen
/// for residues of a common X).
pub fn k_elim_gradient(v_m: i128, v_a: i128, m: i128, a: i128) -> (i128, i128) {
    let d = gcd(m, a);
    let (md, ad) = (m / d, a / d);
    let inv_md = mod_inv(md, ad).expect("reduced moduli must be coprime");
    let diff = v_a - v_m;
    debug_assert_eq!(diff.rem_euclid(d), 0, "d must divide (vA - vM)");
    (((diff / d) * inv_md).rem_euclid(ad), ad)
}

/// **Tower digit** (Theorem 7.1). One level `i → i+1` of an n-modulus tower.
/// Returns the winding `⌊X/Mᵢ⌋ mod Mᵢ₊₁`, read in residue space by a single
/// K-Elimination on lane `(Mᵢ, Mᵢ₊₁)`. No accumulator, no cross-level
/// cascade — each level is independent, preserving i.i.d. carry structure.
/// Requires `gcd(Mᵢ, Mᵢ₊₁) = 1`.
pub fn tower_digit(v_i: i128, v_next: i128, m_i: i128, m_next: i128) -> i128 {
    k_elim(v_i, v_next, m_i, m_next)
}

/// **Winding residue** — read the residue of the winding `⌊X/M⌋` on a lane
/// `p` coprime to `M`, by a single K-Elimination. This is how the magnitude
/// axis is descended *in residue space*: the winding is never assembled into
/// an integer, only its residue on each coprime lane is read, independently.
///
/// `k mod p = ((X mod p) − (X mod M))·M⁻¹ mod p`.
///
/// Requires `gcd(M, p) = 1`. The collection of `winding_residue` over a set
/// of coprime lanes is the winding's *coherent residue family* — the substrate
/// representation of magnitude, carried without reconstruction or cascade.
pub fn winding_residue(v_m: i128, v_p: i128, m: i128, p: i128) -> i128 {
    let m_inv = mod_inv(m, p).expect("winding_residue requires gcd(M,p)=1");
    ((v_p - v_m).rem_euclid(p) * m_inv) % p
}

/// **Signed comparison** (Theorem 5.2 + signed-RNS convention).
/// Tests `X < Y` for two RNS values over the adjacent pair `(M, M+1)`.
///
/// **Precondition**: both operands lie in `[0, M(M+1)/2)` — the signed-RNS
/// operand range. The upper half of the dynamic range encodes negatives.
/// Branch-free: the result is a single comparison on the reconstructed value.
pub fn rns_less_than(x_res: (i128, i128), y_res: (i128, i128), m: i128) -> bool {
    let a = m + 1;
    let prod = m * a;
    let half = prod / 2;
    let v_m = (x_res.0 - y_res.0).rem_euclid(m);
    let v_a = (x_res.1 - y_res.1).rem_euclid(a);
    let k = (v_m - v_a).rem_euclid(a); // adjacency winding
    let delta = v_m + k * m;
    delta >= half // delta in upper half ⟺ negative ⟺ X < Y
}
