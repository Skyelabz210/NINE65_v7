//! The unit carry: shell 36, anchor 37, and the carry Markov chain.
//!
//! The forced chain `{1,2} → 3 → 6 → 36 → 37` fixes the shell modulus
//! `M = 36 = 2²·3²` and the star-prime anchor `A = 37 = S₃`
//! (`Sₙ = 6n(n−1)+1`). The hinge is
//!
//! ```text
//! 36 ≡ −1 (mod 37)
//! ```
//!
//! which is what makes the signed carry directional: `v_A = (r − K) mod A`
//! counts *down* as the hidden winding `K` counts *up*.
//!
//! # Everything here is exactly checkable
//!
//! Each invariant below has a published exact expected value, so a wrong
//! implementation cannot pass by coincidence:
//!
//! - `ΔK ∈ {0,1}`, firing only at `r = 35` — 0 exceptions under `N < 100,000`
//! - `v₃₇ = 36,35,34,33` at `N = 36,72,108,144`
//! - twin-form `(6k−1)(6k+1) ≡ 35 (mod 36)` for all `k`
//! - carry chain `P₂ = [[37/72, 35/72],[35/72, 37/72]]`, eigenvalues `{1, 1/36}`
//! - reversibility dichotomy: detailed-balance defect is exactly `0` for
//!   `n ≤ 3`, and exactly `1/384` at `(n=4, b=2)`, `99/400000` at `(n=5, b=10)`
//!
//! A1: exact rational arithmetic throughout. No floating point.

/// Shell modulus. `36 = 2²·3²`, the geometric object cast out descending the
/// star number line: `S₄ − S₃ = 73 − 37 = 36`.
pub const SHELL: i128 = 36;

/// Star-prime anchor. `37 = S₃ = 6·3·2 + 1`, adjacent to the shell.
pub const ANCHOR: i128 = 37;

/// Firing residue: the carry fires exactly at `r = M − 1`.
pub const FIRING_RESIDUE: i128 = SHELL - 1; // 35

/// `n`-th star number, `Sₙ = 6n(n−1) + 1`.
pub const fn star(n: i128) -> i128 {
    6 * n * (n - 1) + 1
}

/// The winding increment `ΔK = ⌊(N+1)/M⌋ − ⌊N/M⌋`.
///
/// Theorem 1.1 (Unit Carry): this is in `{0,1}` for every `N ≥ 0`, and equals
/// 1 exactly when `N mod M = M − 1`. It is an identity of floor division — it
/// contains no dependence on `N` beyond the residue, so it holds at every
/// scale.
pub fn winding_increment(n: i128, m: i128) -> i128 {
    (n + 1).div_euclid(m) - n.div_euclid(m)
}

/// The signed carry `v_A = (r − K) mod A`.
///
/// Theorem 2.1: with `N = M·K + r` and `A = M + 1`, we have `M ≡ −1 (mod A)`,
/// so `N ≡ r − K (mod A)`. On a closed shell (`r = 0`) the anchor counts down
/// as `K` counts up.
pub fn signed_carry(n: i128) -> i128 {
    let k = n.div_euclid(SHELL);
    let r = n.rem_euclid(SHELL);
    (r - k).rem_euclid(ANCHOR)
}

// ─── Exact rationals (A1: no floating point) ──────────────────────────────

/// A reduced rational. Kept exact; there is no float path in this module.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Frac {
    pub num: i128,
    pub den: i128,
}

const fn gcd(a: i128, b: i128) -> i128 {
    if b == 0 {
        if a < 0 {
            -a
        } else {
            a
        }
    } else {
        gcd(b, a % b)
    }
}

impl Frac {
    pub fn new(num: i128, den: i128) -> Self {
        assert!(den != 0, "zero denominator");
        let s = if den < 0 { -1 } else { 1 };
        let (num, den) = (num * s, den * s);
        let g = gcd(num, den).max(1);
        Frac {
            num: num / g,
            den: den / g,
        }
    }
    pub fn zero() -> Self {
        Frac { num: 0, den: 1 }
    }
    pub fn is_zero(&self) -> bool {
        self.num == 0
    }
    pub fn add(self, o: Self) -> Self {
        Frac::new(self.num * o.den + o.num * self.den, self.den * o.den)
    }
    pub fn sub(self, o: Self) -> Self {
        Frac::new(self.num * o.den - o.num * self.den, self.den * o.den)
    }
    pub fn mul(self, o: Self) -> Self {
        Frac::new(self.num * o.num, self.den * o.den)
    }
    pub fn abs(self) -> Self {
        Frac {
            num: self.num.abs(),
            den: self.den,
        }
    }
    /// `self > other`, by cross-multiplication (denominators are positive).
    pub fn gt(self, o: Self) -> bool {
        self.num * o.den > o.num * self.den
    }
}

// ─── Holte carry chain ────────────────────────────────────────────────────

/// Exact counts of `d₁ + … + dₙ` for digits uniform on `[0, b)`.
/// Index `s` holds the number of tuples summing to `s`.
fn sum_counts(n: usize, b: i128) -> Vec<i128> {
    let mut d = vec![1i128];
    for _ in 0..n {
        let mut nd = vec![0i128; d.len() + (b as usize) - 1];
        for (i, &c) in d.iter().enumerate() {
            for v in 0..b as usize {
                nd[i + v] += c;
            }
        }
        d = nd;
    }
    d
}

/// Holte's carry transition matrix for `n` summands in base `b`.
///
/// From carry state `c`, the next carry is `⌊(c + Σdᵢ)/b⌋`. Computed by exact
/// counting — no sampling, no approximation.
pub fn carry_matrix(n: usize, b: i128) -> Vec<Vec<Frac>> {
    let cnt = sum_counts(n, b);
    let tot = b.pow(n as u32);
    (0..n)
        .map(|c| {
            let mut row = vec![Frac::zero(); n];
            for (s, &k) in cnt.iter().enumerate() {
                let j = ((c as i128 + s as i128) / b) as usize;
                if j < n {
                    row[j] = row[j].add(Frac::new(k, tot));
                }
            }
            row
        })
        .collect()
}

/// Eulerian numbers `A(n, j)` for `j = 0..n-1`.
pub fn eulerian(n: usize) -> Vec<i128> {
    let mut a = vec![vec![0i128; n + 1]; n + 1];
    a[0][0] = 1;
    for i in 1..=n {
        for j in 0..i {
            a[i][j] = if j > 0 {
                (j as i128 + 1) * a[i - 1][j] + (i as i128 - j as i128) * a[i - 1][j - 1]
            } else {
                a[i - 1][0]
            };
        }
    }
    a[n][..n].to_vec()
}

/// The stationary law of the carry chain: `πⱼ = A(n,j)/n!`.
pub fn eulerian_stationary(n: usize) -> Vec<Frac> {
    let f: i128 = (1..=n as i128).product();
    eulerian(n).into_iter().map(|e| Frac::new(e, f)).collect()
}

/// Maximum detailed-balance defect `max |πᵢPᵢⱼ − πⱼPⱼᵢ|`.
///
/// Exactly `0` iff the chain is time-reversible.
pub fn detailed_balance_defect(n: usize, b: i128) -> Frac {
    let p = carry_matrix(n, b);
    let pi = eulerian_stationary(n);
    let mut worst = Frac::zero();
    for i in 0..n {
        for j in 0..n {
            let d = pi[i].mul(p[i][j]).sub(pi[j].mul(p[j][i])).abs();
            if d.gt(worst) {
                worst = d;
            }
        }
    }
    worst
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Theorem 1.1, exhaustively. Published: 0 exceptions under 100,000.
    #[test]
    fn unit_carry_is_zero_or_one_and_fires_only_at_the_firing_residue() {
        let mut fired = 0i128;
        let mut checked = 0i128;
        for n in 0..100_000i128 {
            let dk = winding_increment(n, SHELL);
            assert!(dk == 0 || dk == 1, "ΔK = {dk} at N = {n}, must be 0 or 1");
            let r = n.rem_euclid(SHELL);
            assert_eq!(
                dk == 1,
                r == FIRING_RESIDUE,
                "N = {n}: ΔK = {dk} but r = {r} (fires iff r = 35)"
            );
            if dk == 1 {
                fired += 1;
            }
            checked += 1;
        }
        assert_eq!(checked, 100_000, "must sweep the full range, not a sample");
        // Firings are N = 35, 71, 107, … < 100_000 — one per shell crossing.
        // Count = ⌈(L − 35)/36⌉, written in integer form.
        const L: i128 = 100_000;
        assert_eq!(
            fired,
            (L + SHELL - 1 - FIRING_RESIDUE) / SHELL,
            "unexpected firing count"
        );
        assert_eq!(fired, 2_777, "one firing per shell crossing below 100,000");
    }

    /// Theorem 2.1, exhaustively over the published range, plus the exact
    /// closed-shell descent.
    #[test]
    fn signed_carry_identity_holds_and_anchor_descends_on_closed_shells() {
        let mut checked = 0;
        for n in 0..5_000i128 {
            let k = n.div_euclid(SHELL);
            let r = n.rem_euclid(SHELL);
            assert_eq!(
                signed_carry(n),
                (r - k).rem_euclid(ANCHOR),
                "signed carry mismatch at N = {n}"
            );
            // N ≡ r − K (mod A), the identity the formula rests on.
            assert_eq!(n.rem_euclid(ANCHOR), (r - k).rem_euclid(ANCHOR), "N = {n}");
            checked += 1;
        }
        assert_eq!(checked, 5_000, "must sweep, not sample");

        // Closed shells: r = 0, so v = (−K) mod 37, counting down.
        assert_eq!(
            [36, 72, 108, 144].map(signed_carry),
            [36, 35, 34, 33],
            "the anchor must count down as the winding counts up"
        );
    }

    /// The hinge. Everything directional rests on this one congruence.
    #[test]
    fn shell_is_minus_one_mod_anchor() {
        assert_eq!(ANCHOR, SHELL + 1);
        assert_eq!(SHELL.rem_euclid(ANCHOR), ANCHOR - 1, "36 ≡ −1 (mod 37)");
        assert_eq!(star(3), ANCHOR, "37 = S₃");
        assert_eq!(star(4) - star(3), SHELL, "S₄ − S₃ = 36");
    }

    /// Theorem 5.1: every twin-prime product sits exactly on the firing
    /// boundary. Published: holds for k < 500.
    #[test]
    fn twin_form_products_land_exactly_on_the_firing_residue() {
        let mut checked = 0;
        for k in 1..500i128 {
            let prod = (6 * k - 1) * (6 * k + 1);
            assert_eq!(
                prod.rem_euclid(SHELL),
                FIRING_RESIDUE,
                "(6·{k}−1)(6·{k}+1) must be ≡ 35 (mod 36)"
            );
            assert_eq!(prod, 36 * k * k - 1, "twin-form identity");
            checked += 1;
        }
        assert_eq!(checked, 499);
    }

    /// The shell carry chain, reproduced exactly from Holte's construction by
    /// counting — matching the published matrix and eigenvalues.
    #[test]
    fn shell_carry_matrix_and_eigenvalues_reproduce_exactly() {
        let p = carry_matrix(2, SHELL);
        assert_eq!(p[0][0], Frac::new(37, 72));
        assert_eq!(p[0][1], Frac::new(35, 72));
        assert_eq!(p[1][0], Frac::new(35, 72));
        assert_eq!(p[1][1], Frac::new(37, 72));

        // 2×2: eigenvalues are 1 and trace − 1.
        let trace = p[0][0].add(p[1][1]);
        let second = trace.sub(Frac::new(1, 1));
        assert_eq!(
            second,
            Frac::new(1, 36),
            "second eigenvalue is the shell 1/36"
        );

        // Stationary law is uniform for n = 2.
        assert_eq!(
            eulerian_stationary(2),
            vec![Frac::new(1, 2), Frac::new(1, 2)]
        );
    }

    /// The Eulerian law must actually be stationary — asserted, not assumed.
    #[test]
    fn eulerian_law_is_stationary_for_every_tested_chain() {
        for n in 2..=5usize {
            for b in [2i128, 10, 36] {
                let p = carry_matrix(n, b);
                let pi = eulerian_stationary(n);
                for j in 0..n {
                    let got = (0..n).fold(Frac::zero(), |acc, i| acc.add(pi[i].mul(p[i][j])));
                    assert_eq!(got, pi[j], "πP ≠ π at n={n} b={b} j={j}");
                }
            }
        }
    }

    /// The reversibility dichotomy, with both published spot values.
    ///
    /// This is the strongest test in the module: `1/384` and `99/400000` are
    /// exact published constants, so an incorrect chain cannot match them.
    #[test]
    fn reversibility_dichotomy_is_exact_and_matches_published_values() {
        // n ≤ 3: detailed balance holds exactly, every base.
        for n in [2usize, 3] {
            for b in [2i128, 10, 36] {
                assert!(
                    detailed_balance_defect(n, b).is_zero(),
                    "n={n} b={b} must be reversible (defect exactly 0)"
                );
            }
        }

        // n ≥ 4: detailed balance fails — the negative control.
        for n in [4usize, 5] {
            for b in [2i128, 10, 36] {
                assert!(
                    !detailed_balance_defect(n, b).is_zero(),
                    "n={n} b={b} must be irreversible; if this ever passes, the \
                     dichotomy above is vacuous"
                );
            }
        }

        // Published exact values.
        assert_eq!(
            detailed_balance_defect(4, 2),
            Frac::new(1, 384),
            "n=4, b=2 defect must be exactly 1/384"
        );
        assert_eq!(
            detailed_balance_defect(5, 10),
            Frac::new(99, 400_000),
            "n=5, b=10 defect must be exactly 99/400000"
        );
    }

    /// The 36-carry sits exactly on the reversible boundary: the dynamics are
    /// time-symmetric, so the arrow is sourced by the initial condition, not by
    /// the dynamics.
    #[test]
    fn the_shell_carry_sits_on_the_reversible_boundary() {
        assert!(detailed_balance_defect(2, SHELL).is_zero());
        let p = carry_matrix(2, SHELL);
        // Time reversal P* = P for a reversible chain with uniform stationary.
        assert_eq!(p[0][1], p[1][0], "P* = P at the boundary");
    }
}
