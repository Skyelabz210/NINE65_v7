//! The adjacent anchor and the flat parallel lift.
//!
//! # The adjacency
//!
//! Pick any modulus `P ≥ 2` and take its **adjacent anchor** `A = P + 1`.
//! Consecutive integers are always coprime, so `(P, A)` is a valid CRT pair for
//! free — no search, no primality condition. The anchor is CLASS-R: it needs
//! coprimality only, never a primitive root, so composite anchors are legal.
//!
//! Adjacency buys one more thing, and it is the whole point:
//!
//! ```text
//! P ≡ −1 (mod A)   ⟹   P⁻¹ ≡ −1 (mod A)
//! ```
//!
//! so the winding of `X = r + P·k` drops out with no modular inverse at all:
//!
//! ```text
//! a ≡ X ≡ r + P·k ≡ r − k  (mod A)   ⟹   k = (r − a) mod A
//! ```
//!
//! One subtraction and one reduction. [`Anchor::winding`] is that formula, and
//! [`k_elimination_cross_check`] verifies it against
//! [`crate::k_elim::k_eliminate`], which reaches the same `k` the general way
//! through an extended-Euclid inverse. Agreement across an exhaustive sweep is
//! the evidence that the shortcut is the same object and not a lookalike.
//!
//! # The lift is flat, not a tree
//!
//! Every `k_j` is computed from its **own stored pair** `(r_j, a_j)`. No `k_j`
//! reads another, and no `a_j` is recomputed from the lanes — both components
//! are laid down once at decomposition and carried in state, because
//! recomputing `a_j` costs `O(n)` and recouples lanes that were just separated.
//!
//! The telescoping identity
//!
//! ```text
//! X = r₀ + Σⱼ kⱼ · Mⱼ
//! ```
//!
//! reads like an induction, and its proof is one. Its *evaluation* is not: each
//! `kⱼ` is a direct reduction of `X`, so all of them are available at the same
//! instant. [`AnchorFamily::windings_in_order`] exists so that can be tested
//! rather than claimed — permuting the evaluation order must leave the output
//! bit-identical, which no cascade could survive.
//!
//! # Range is a hypothesis, and it is checked
//!
//! Theorem 1 recovers `X` only for `X < P·A`. Past that the residues alias and
//! the lift returns `X mod P·A` — a wrong answer with no outward sign. Every
//! entry point here refuses out-of-range input ([`AnchorError::OutOfRange`])
//! instead of returning the alias, and [`AnchorFamily::lift_state`] decides
//! using the *winding* of an [`ExactState`], since the winding is precisely the
//! part of the magnitude a residue signature cannot see.
//!
//! A1: exact integer arithmetic throughout. No floating point.
//! A2: no Garner on any path in this module. The read here is the
//! non-destructive anchored one — it records `k` beside untouched residues.

#[cfg(not(feature = "std"))]
use alloc::{vec, vec::Vec};
#[cfg(feature = "std")]
use std::{vec, vec::Vec};

use crate::cram_pde::ExactState;

// ─── Errors ───────────────────────────────────────────────────────────────

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AnchorError {
    /// `P < 2`. `P = 1` gives the pair `(1, 2)`, which carries no information,
    /// and `P = 0` is not a modulus.
    ModulusTooSmall { p: i128 },
    /// A residue was presented outside `[0, modulus)`. Residues are canonical
    /// here; a negative or oversized one is a caller error, not something to
    /// silently normalise.
    ResidueOutOfRange { residue: i128, modulus: i128 },
    /// **Theorem 1's hypothesis violated.** `X` lies outside `[0, capacity)`, so
    /// the lift would return `X mod capacity` rather than `X`. Refused.
    OutOfRange { x: i128, capacity: i128 },
    /// `P·A`, or a tower product, exceeds `i128`. Refused rather than wrapped.
    CapacityOverflow { modulus: i128 },
    /// A family was requested with no anchors in it.
    EmptyFamily,
    /// A disjoint partition contained an empty group.
    EmptyGroup { index: usize },
    /// A pair or winding count did not match the anchor count.
    Arity { expected: usize, got: usize },
    /// An evaluation order was not a permutation of `0..n`.
    NotAPermutation,
    /// A joint integer was asked of a disjoint family, which has none — see
    /// [`AnchorFamily::groups_are_jointly_liftable`].
    NoJointValue,
}

// ─── A single adjacent anchor ─────────────────────────────────────────────

/// A modulus `P` paired with its adjacent anchor `A = P + 1`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Anchor {
    p: i128,
    a: i128,
    capacity: i128,
}

impl Anchor {
    /// Build the adjacent anchor for `p`. Coprimality is structural — `p` and
    /// `p + 1` are consecutive — so this can only fail on size.
    pub fn adjacent(p: i128) -> Result<Self, AnchorError> {
        if p < 2 {
            return Err(AnchorError::ModulusTooSmall { p });
        }
        let a = p + 1;
        let capacity = p
            .checked_mul(a)
            .ok_or(AnchorError::CapacityOverflow { modulus: p })?;
        Ok(Anchor { p, a, capacity })
    }

    /// The shell modulus `P`.
    pub fn p(&self) -> i128 {
        self.p
    }

    /// The anchor modulus `A = P + 1`.
    pub fn a(&self) -> i128 {
        self.a
    }

    /// `P·A` — the exclusive upper bound of Theorem 1's range hypothesis.
    pub fn capacity(&self) -> i128 {
        self.capacity
    }

    /// Split `x` into the pair `(x mod P, x mod A)` the state will carry.
    ///
    /// Refuses `x` outside `[0, P·A)`: past that the pair no longer determines
    /// `x`, and handing back an aliased pair is how a silent wrong answer gets
    /// manufactured.
    pub fn decompose(&self, x: i128) -> Result<(i128, i128), AnchorError> {
        if x < 0 || x >= self.capacity {
            return Err(AnchorError::OutOfRange {
                x,
                capacity: self.capacity,
            });
        }
        Ok((x % self.p, x % self.a))
    }

    /// The winding `k = (r − a) mod A`, in `O(1)` and with no modular inverse.
    ///
    /// This is the non-destructive read: `k` is produced *beside* `r` and `a`,
    /// which are taken by value and returned untouched — nothing is consumed.
    pub fn winding(&self, r: i128, a_res: i128) -> Result<i128, AnchorError> {
        if r < 0 || r >= self.p {
            return Err(AnchorError::ResidueOutOfRange {
                residue: r,
                modulus: self.p,
            });
        }
        if a_res < 0 || a_res >= self.a {
            return Err(AnchorError::ResidueOutOfRange {
                residue: a_res,
                modulus: self.a,
            });
        }
        Ok((r - a_res).rem_euclid(self.a))
    }

    /// `X = r + P·k`, the value the pair names inside `[0, P·A)`.
    pub fn lift(&self, r: i128, a_res: i128) -> Result<i128, AnchorError> {
        let k = self.winding(r, a_res)?;
        Ok(r + self.p * k)
    }
}

/// Cross-check of the adjacency shortcut against the general K-Elimination
/// step, which reaches the same `k` through an extended-Euclid inverse.
///
/// Returns `Some((fast, general))` for `x`, or `None` if `x` is out of range.
/// Exposed so the agreement is checkable from outside this module too.
pub fn k_elimination_cross_check(anchor: &Anchor, x: i128) -> Option<(i128, i128)> {
    let (r, a_res) = anchor.decompose(x).ok()?;
    let fast = anchor.winding(r, a_res).ok()?;
    let general = crate::k_elim::k_eliminate(r, anchor.p(), a_res, anchor.a())?.k;
    Some((fast, general))
}

// ─── Families ─────────────────────────────────────────────────────────────

/// How the anchors of a family relate to one another.
///
/// The two arrangements are not interchangeable, and the trade is real:
/// telescoping squares the representable range at each level but nests the
/// residues, while a disjoint partition keeps the residues independent — which
/// is what buys IID marginals and fault containment — at a fixed range.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Arrangement {
    /// `M₀` given, `A_t = M_t + 1`, `M_{t+1} = M_t·A_t`. Range grows as a
    /// tower; the residue at level `t+1` contains the one at level `t`.
    Telescoping,
    /// The basis is partitioned into groups; group `j` has `P_j = Π primes` and
    /// `A_j = P_j + 1`. The `r_j` come from disjoint prime sets, so a fault in
    /// one group cannot reach another.
    Disjoint,
}

/// A family of adjacent anchors, evaluated flat and in parallel.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AnchorFamily {
    arrangement: Arrangement,
    anchors: Vec<Anchor>,
    /// Prime groups, for [`Arrangement::Disjoint`] only.
    groups: Vec<Vec<i128>>,
}

impl AnchorFamily {
    /// Build the telescoping tower `M₀ → M₁ = M₀·A₀ → …` to `depth` levels.
    ///
    /// Refuses on `i128` overflow rather than wrapping: the tower squares, so it
    /// exhausts the type quickly, and a wrapped capacity would be a range check
    /// that passes for values it cannot represent.
    pub fn telescoping(m0: i128, depth: usize) -> Result<Self, AnchorError> {
        if depth == 0 {
            return Err(AnchorError::EmptyFamily);
        }
        let mut anchors = Vec::with_capacity(depth);
        let mut m = m0;
        for _ in 0..depth {
            let anchor = Anchor::adjacent(m)?;
            m = anchor.capacity(); // M_{t+1} = M_t · A_t
            anchors.push(anchor);
        }
        Ok(AnchorFamily {
            arrangement: Arrangement::Telescoping,
            anchors,
            groups: Vec::new(),
        })
    }

    /// Build a disjoint partition: one anchor per group of primes.
    pub fn disjoint(groups: &[&[i128]]) -> Result<Self, AnchorError> {
        if groups.is_empty() {
            return Err(AnchorError::EmptyFamily);
        }
        let mut anchors = Vec::with_capacity(groups.len());
        let mut owned = Vec::with_capacity(groups.len());
        for (index, group) in groups.iter().enumerate() {
            if group.is_empty() {
                return Err(AnchorError::EmptyGroup { index });
            }
            let mut p: i128 = 1;
            for &q in group.iter() {
                p = p
                    .checked_mul(q)
                    .ok_or(AnchorError::CapacityOverflow { modulus: q })?;
            }
            anchors.push(Anchor::adjacent(p)?);
            owned.push(group.to_vec());
        }
        Ok(AnchorFamily {
            arrangement: Arrangement::Disjoint,
            anchors,
            groups: owned,
        })
    }

    pub fn arrangement(&self) -> Arrangement {
        self.arrangement
    }

    pub fn anchors(&self) -> &[Anchor] {
        &self.anchors
    }

    pub fn groups(&self) -> &[Vec<i128>] {
        &self.groups
    }

    /// The range over which this family determines `X`.
    ///
    /// Telescoping: `M_depth`, the top of the tower. Disjoint: the **smallest**
    /// group capacity, because past that at least one group is already aliasing
    /// even though the others are not — the conservative bound is the only
    /// honest one.
    pub fn capacity(&self) -> i128 {
        match self.arrangement {
            Arrangement::Telescoping => {
                self.anchors.last().map(|a| a.capacity()).unwrap_or(0)
            }
            Arrangement::Disjoint => {
                self.anchors.iter().map(|a| a.capacity()).min().unwrap_or(0)
            }
        }
    }

    /// Lay down every `(r_j, a_j)` pair at once. This is the only place `x` is
    /// read; from here on the pairs are state and `a_j` is never recomputed.
    pub fn decompose(&self, x: i128) -> Result<Vec<(i128, i128)>, AnchorError> {
        let capacity = self.capacity();
        if x < 0 || x >= capacity {
            return Err(AnchorError::OutOfRange { x, capacity });
        }
        Ok(self
            .anchors
            .iter()
            .map(|anchor| (x % anchor.p(), x % anchor.a()))
            .collect())
    }

    /// Every `k_j`, each from its own pair.
    ///
    /// The `map` is the architecture: the closure sees `self.anchors[j]` and
    /// `pairs[j]` and has access to no other index and to no accumulator.
    pub fn windings(&self, pairs: &[(i128, i128)]) -> Result<Vec<i128>, AnchorError> {
        self.check_arity(pairs.len())?;
        self.anchors
            .iter()
            .zip(pairs.iter())
            .map(|(anchor, &(r, a_res))| anchor.winding(r, a_res))
            .collect()
    }

    /// The same windings, evaluated in a caller-supplied order, and returned
    /// **indexed by lane** rather than by evaluation position.
    ///
    /// If the lift were a cascade the result would depend on `order`. It does
    /// not, and that is the testable form of "flat, not a tree".
    pub fn windings_in_order(
        &self,
        pairs: &[(i128, i128)],
        order: &[usize],
    ) -> Result<Vec<i128>, AnchorError> {
        let n = self.anchors.len();
        self.check_arity(pairs.len())?;
        if order.len() != n {
            return Err(AnchorError::NotAPermutation);
        }
        let mut seen = vec![false; n];
        for &j in order {
            if j >= n || seen[j] {
                return Err(AnchorError::NotAPermutation);
            }
            seen[j] = true;
        }
        let mut out = vec![0i128; n];
        for &j in order {
            let (r, a_res) = pairs[j];
            out[j] = self.anchors[j].winding(r, a_res)?;
        }
        Ok(out)
    }

    /// Telescoping reconstruction: `X = r₀ + Σⱼ kⱼ·Mⱼ`.
    ///
    /// A single parallel reduction over terms that were all available at the
    /// same instant. A disjoint family has no such joint sum and returns
    /// [`AnchorError::NoJointValue`] — see [`AnchorFamily::group_values`].
    pub fn reconstruct(
        &self,
        pairs: &[(i128, i128)],
        windings: &[i128],
    ) -> Result<i128, AnchorError> {
        if self.arrangement != Arrangement::Telescoping {
            return Err(AnchorError::NoJointValue);
        }
        self.check_arity(pairs.len())?;
        self.check_arity(windings.len())?;
        let mut x = pairs[0].0; // r₀
        for (anchor, &k) in self.anchors.iter().zip(windings.iter()) {
            let term = anchor
                .p()
                .checked_mul(k)
                .ok_or(AnchorError::CapacityOverflow { modulus: anchor.p() })?;
            x = x
                .checked_add(term)
                .ok_or(AnchorError::CapacityOverflow { modulus: anchor.p() })?;
        }
        Ok(x)
    }

    /// Per-group values `X_j = r_j + P_j·k_j`.
    ///
    /// This is the disjoint family's whole output, and it is deliberately not
    /// merged into one integer: merging needs a CRT across the group moduli,
    /// which is the destructive read this module exists to avoid — and
    /// [`AnchorFamily::groups_are_jointly_liftable`] shows it is not even
    /// available once there is more than one group.
    ///
    /// Inside `[0, capacity())` every group value equals `X`, so the family is
    /// a redundant code: disagreement between groups localises a fault.
    pub fn group_values(
        &self,
        pairs: &[(i128, i128)],
        windings: &[i128],
    ) -> Result<Vec<i128>, AnchorError> {
        self.check_arity(pairs.len())?;
        self.check_arity(windings.len())?;
        Ok(self
            .anchors
            .iter()
            .zip(pairs.iter())
            .zip(windings.iter())
            .map(|((anchor, &(r, _)), &k)| r + anchor.p() * k)
            .collect())
    }

    /// Whether the group capacities `P_j·A_j` are pairwise coprime, which is
    /// what a joint CRT across groups would require.
    ///
    /// This is **always false for two or more groups**, and not by accident:
    /// `P` and `P+1` are consecutive, so exactly one of them is even and every
    /// capacity `P·(P+1)` is even. Any two capacities therefore share the
    /// factor 2. Adjacency buys a free coprime partner *within* a group at the
    /// cost of any coprimality *between* groups.
    pub fn groups_are_jointly_liftable(&self) -> bool {
        let caps: Vec<i128> = self.anchors.iter().map(|a| a.capacity()).collect();
        for i in 0..caps.len() {
            for j in (i + 1)..caps.len() {
                if crate::k_elim::gcd(caps[i], caps[j]) != 1 {
                    return false;
                }
            }
        }
        true
    }

    /// Lift straight from an [`ExactState`], using its winding to decide range.
    ///
    /// The winding is exactly the component a residue signature cannot report,
    /// so this is the range check a signature-only design structurally cannot
    /// perform.
    pub fn lift_state(&self, state: &ExactState) -> Result<i128, AnchorError> {
        let x = state.to_i128_exact();
        let pairs = self.decompose(x)?;
        let windings = self.windings(&pairs)?;
        self.reconstruct(&pairs, &windings)
    }

    fn check_arity(&self, got: usize) -> Result<(), AnchorError> {
        if got != self.anchors.len() {
            return Err(AnchorError::Arity {
                expected: self.anchors.len(),
                got,
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Adjacency is the mechanism, so assert the two facts it rests on across a
    /// spread of moduli: coprimality, and `P ≡ −1 (mod A)`.
    #[test]
    fn adjacency_gives_coprimality_and_p_congruent_to_minus_one() {
        let moduli = [2i128, 3, 6, 30, 36, 210, 1001, 2310, 30030];
        let mut checked = 0;
        for p in moduli {
            let anchor = Anchor::adjacent(p).expect("p >= 2");
            assert_eq!(crate::k_elim::gcd(anchor.p(), anchor.a()), 1, "p={p}");
            assert_eq!(
                anchor.p().rem_euclid(anchor.a()),
                anchor.a() - 1,
                "P must be −1 mod A for p={p}"
            );
            assert_eq!(anchor.capacity(), p * (p + 1), "p={p}");
            checked += 1;
        }
        assert_eq!(checked, moduli.len(), "every modulus must be checked");
    }

    /// The `O(1)` shortcut and the general inverse-based K-Elimination step must
    /// agree everywhere. Disagreement anywhere means the shortcut is a lookalike.
    #[test]
    fn winding_shortcut_agrees_with_inverse_based_k_elimination() {
        let mut checked = 0i128;
        let mut nonzero = 0i128;
        for p in [6i128, 36, 210] {
            let anchor = Anchor::adjacent(p).unwrap();
            for x in 0..anchor.capacity() {
                let (fast, general) =
                    k_elimination_cross_check(&anchor, x).expect("x in range");
                assert_eq!(fast, general, "p={p} x={x}");
                if fast != 0 {
                    nonzero += 1;
                }
                checked += 1;
            }
        }
        assert_eq!(
            checked,
            6 * 7 + 36 * 37 + 210 * 211,
            "the sweep must cover every value of every capacity"
        );
        assert!(nonzero > 0, "agreement on k = 0 alone would prove nothing");
    }

    /// C6 — exhaustive round trip on the canonical shell/anchor pair 36/37.
    #[test]
    fn single_anchor_round_trips_over_its_entire_capacity() {
        let anchor = Anchor::adjacent(36).unwrap();
        assert_eq!(anchor.capacity(), 1332);
        let mut checked = 0i128;
        for x in 0..anchor.capacity() {
            let (r, a_res) = anchor.decompose(x).unwrap();
            assert_eq!(anchor.lift(r, a_res).unwrap(), x, "x={x}");
            checked += 1;
        }
        assert_eq!(checked, 1332, "sweep must not shrink");
    }

    /// C5 — the range hypothesis. Out-of-range input is refused, and the test
    /// also exhibits the alias that would have been returned, so the refusal is
    /// shown to be necessary rather than merely defensive.
    #[test]
    fn out_of_range_is_refused_and_the_alias_it_prevents_is_real() {
        let anchor = Anchor::adjacent(36).unwrap();
        let cap = anchor.capacity();

        for over in [cap, cap + 1, cap + 7, 2 * cap, 5 * cap + 11] {
            assert_eq!(
                anchor.decompose(over),
                Err(AnchorError::OutOfRange {
                    x: over,
                    capacity: cap
                }),
                "x={over} must be refused, never wrapped"
            );
        }
        assert!(anchor.decompose(-1).is_err(), "negative must be refused");

        // What the refusal buys: reduce an out-of-range value by hand and lift
        // it. The lift is internally consistent and completely wrong.
        let x = cap + 7;
        let aliased = anchor.lift(x % anchor.p(), x % anchor.a()).unwrap();
        assert_eq!(aliased, 7, "the alias is X mod P·A");
        assert_ne!(aliased, x, "and it is not X");
    }

    /// C6 — exhaustive round trip through a telescoping family, exercising the
    /// flat sum `X = r₀ + Σ kⱼ·Mⱼ`.
    #[test]
    fn telescoping_family_reconstructs_over_its_entire_capacity() {
        let family = AnchorFamily::telescoping(6, 2).unwrap();
        // M₀ = 6, A₀ = 7, M₁ = 42, A₁ = 43, M₂ = 1806.
        assert_eq!(family.arrangement(), Arrangement::Telescoping);
        assert_eq!(
            family
                .anchors()
                .iter()
                .map(|a| (a.p(), a.a()))
                .collect::<Vec<_>>(),
            vec![(6, 7), (42, 43)]
        );
        assert_eq!(family.capacity(), 1806);

        let mut checked = 0i128;
        let mut top_level_fired = 0i128;
        for x in 0..family.capacity() {
            let pairs = family.decompose(x).unwrap();
            let ks = family.windings(&pairs).unwrap();
            assert_eq!(family.reconstruct(&pairs, &ks).unwrap(), x, "x={x}");
            if ks[1] != 0 {
                top_level_fired += 1;
            }
            checked += 1;
        }
        assert_eq!(checked, 1806, "sweep must not shrink");
        assert!(
            top_level_fired > 0,
            "the sweep must exercise the upper level, not only level 0"
        );

        assert_eq!(
            family.decompose(1806),
            Err(AnchorError::OutOfRange {
                x: 1806,
                capacity: 1806
            }),
            "the top of the tower is exclusive"
        );
    }

    /// A deeper tower, to confirm the flat sum is not an artefact of depth 2.
    #[test]
    fn telescoping_depth_three_reconstructs_including_past_the_second_level() {
        let family = AnchorFamily::telescoping(6, 3).unwrap();
        let cap = family.capacity();
        assert_eq!(cap, 1806 * 1807);

        let probes = [0i128, 1, 5, 6, 41, 42, 1805, 1806, 1807, 100_000, cap - 1];
        let mut past_level_two = 0;
        for x in probes {
            let pairs = family.decompose(x).unwrap();
            let ks = family.windings(&pairs).unwrap();
            assert_eq!(family.reconstruct(&pairs, &ks).unwrap(), x, "x={x}");
            if ks[2] != 0 {
                past_level_two += 1;
            }
        }
        assert!(
            past_level_two > 0,
            "probes must include values whose top-level winding is nonzero"
        );
    }

    /// P6 — shuffle invariance. The output is indexed by lane, so if any `kⱼ`
    /// depended on an earlier one, permuted evaluation would differ.
    #[test]
    fn windings_are_invariant_under_evaluation_order() {
        let family = AnchorFamily::disjoint(&[&[3, 5], &[7, 11], &[13, 17]]).unwrap();
        assert_eq!(family.arrangement(), Arrangement::Disjoint);
        assert_eq!(
            family
                .anchors()
                .iter()
                .map(|a| (a.p(), a.a()))
                .collect::<Vec<_>>(),
            vec![(15, 16), (77, 78), (221, 222)]
        );
        assert_eq!(family.capacity(), 15 * 16, "the smallest group bounds it");

        let orders: [[usize; 3]; 6] = [
            [0, 1, 2],
            [0, 2, 1],
            [1, 0, 2],
            [1, 2, 0],
            [2, 0, 1],
            [2, 1, 0],
        ];

        let mut checked = 0i128;
        let mut all_lanes_wound = 0i128;
        for x in 0..family.capacity() {
            let pairs = family.decompose(x).unwrap();
            let reference = family.windings(&pairs).unwrap();
            if reference.iter().all(|&k| k != 0) {
                all_lanes_wound += 1;
            }
            for order in &orders {
                assert_eq!(
                    family.windings_in_order(&pairs, order).unwrap(),
                    reference,
                    "x={x} order={order:?}"
                );
            }
            checked += 1;
        }
        assert_eq!(checked, family.capacity(), "sweep must not shrink");
        assert!(
            all_lanes_wound > 0,
            "the sweep must contain values where every lane has work to reorder"
        );

        // A non-permutation is rejected rather than quietly partially evaluated.
        let pairs = family.decompose(5).unwrap();
        assert_eq!(
            family.windings_in_order(&pairs, &[0, 0, 1]),
            Err(AnchorError::NotAPermutation)
        );
        assert_eq!(
            family.windings_in_order(&pairs, &[0, 1]),
            Err(AnchorError::NotAPermutation)
        );
    }

    /// Inside capacity the disjoint family is a redundant code: every group
    /// independently names the same integer. That agreement is what makes a
    /// single-lane fault *detectable* as well as contained.
    #[test]
    fn every_disjoint_group_independently_names_the_same_integer() {
        let family = AnchorFamily::disjoint(&[&[3, 5], &[7, 11], &[13, 17]]).unwrap();
        let mut checked = 0i128;
        for x in 0..family.capacity() {
            let pairs = family.decompose(x).unwrap();
            let ks = family.windings(&pairs).unwrap();
            for (j, v) in family.group_values(&pairs, &ks).unwrap().iter().enumerate() {
                assert_eq!(*v, x, "group {j} at x={x}");
            }
            checked += 1;
        }
        assert_eq!(checked, family.capacity(), "sweep must not shrink");
    }

    /// P7 — fault containment, with the sequential CRT as the negative control.
    ///
    /// The flat lift and Garner are handed the *same* corruption, on the *same*
    /// lane, over the *same* three moduli. One confines it to a single winding;
    /// the other carries it into every downstream partial. Without the control,
    /// "containment" would be a claim no experiment could refute.
    #[test]
    fn a_single_faulty_lane_moves_one_winding_while_garner_spreads_it() {
        let family = AnchorFamily::disjoint(&[&[3, 5], &[7, 11], &[13, 17]]).unwrap();
        let x = 200i128;
        assert!(x < family.capacity());

        let pairs = family.decompose(x).unwrap();
        let clean_k = family.windings(&pairs).unwrap();
        let clean_v = family.group_values(&pairs, &clean_k).unwrap();
        assert_eq!(clean_v, vec![x, x, x], "clean groups agree");

        let faulty = 1usize; // the {7,11} group, P = 77
        let mut corrupted = pairs.clone();
        let p = family.anchors()[faulty].p();
        corrupted[faulty].0 = (corrupted[faulty].0 + 1) % p;
        assert_ne!(
            corrupted[faulty].0, pairs[faulty].0,
            "the corruption must actually change the residue"
        );

        let dirty_k = family.windings(&corrupted).unwrap();
        let dirty_v = family.group_values(&corrupted, &dirty_k).unwrap();

        let moved_k = (0..clean_k.len()).filter(|&i| clean_k[i] != dirty_k[i]).count();
        assert_eq!(moved_k, 1, "exactly one winding moves");
        assert_ne!(clean_k[faulty], dirty_k[faulty], "and it is the faulty lane's");

        let moved_v = (0..clean_v.len()).filter(|&i| clean_v[i] != dirty_v[i]).count();
        assert_eq!(moved_v, 1, "exactly one group value moves");
        for j in 0..clean_v.len() {
            if j != faulty {
                assert_eq!(clean_v[j], dirty_v[j], "group {j} must be bit-identical");
            }
        }
        // The surviving groups still agree with each other, so the fault is not
        // just contained — it is localised to lane 1 by majority.
        assert_eq!(dirty_v[0], dirty_v[2]);
        assert_ne!(dirty_v[faulty], dirty_v[0]);

        // ── Negative control: the same fault through the sequential CRT ──
        // 15, 77 and 221 are pairwise coprime, so Garner accepts exactly these
        // three lanes. It threads one accumulator through them, so a fault at
        // lane 1 must reach every partial from lane 1 onward.
        let moduli = [15i128, 77, 221];
        let clean_res: Vec<(i128, i128)> = moduli.iter().map(|&m| (x % m, m)).collect();
        let mut dirty_res = clean_res.clone();
        dirty_res[faulty].0 = (dirty_res[faulty].0 + 1) % moduli[faulty];
        assert_eq!(
            dirty_res[faulty].0, corrupted[faulty].0,
            "control must carry the identical corruption"
        );

        let clean_partials = garner_partials(&clean_res);
        let dirty_partials = garner_partials(&dirty_res);
        let spread = (0..clean_partials.len())
            .filter(|&i| clean_partials[i] != dirty_partials[i])
            .count();
        assert_eq!(
            spread,
            moduli.len() - faulty,
            "every partial from the faulty lane onward must be damaged"
        );
        assert!(
            spread > moved_k,
            "the control must spread further than the flat lift: {spread} vs {moved_k}"
        );
        assert_ne!(
            crate::k_elim::garner_reconstruct(&clean_res),
            crate::k_elim::garner_reconstruct(&dirty_res),
            "and the reconstructed integer itself is wrong, with nothing left to compare it to"
        );
    }

    /// Sequential CRT partials, built from the library's own K-Elimination step
    /// so the control is the real mechanism and not a re-implementation of it.
    fn garner_partials(residues: &[(i128, i128)]) -> Vec<i128> {
        let (mut value, mut modulus) = residues[0];
        let mut out = vec![value];
        for &(r_i, m_i) in &residues[1..] {
            let step = crate::k_elim::k_eliminate(value, modulus, r_i, m_i).unwrap();
            value = step.value;
            modulus *= m_i;
            out.push(value);
        }
        out
    }

    /// The disjoint arrangement's structural limitation, derived rather than
    /// observed: `P` and `P+1` are consecutive, so every capacity `P·(P+1)` is
    /// even, so no two anchors in a family are ever jointly liftable.
    #[test]
    fn adjacency_forces_every_capacity_even_so_groups_never_jointly_lift() {
        let mut checked = 0;
        for p in 2i128..=2_000 {
            let cap = Anchor::adjacent(p).unwrap().capacity();
            assert_eq!(cap % 2, 0, "P·(P+1) must be even for p={p}");
            checked += 1;
        }
        assert_eq!(checked, 1_999, "sweep must not shrink");

        // A single group has nothing to be coprime *to*, so the predicate is
        // true there — it is not a constant `false`.
        let lone = AnchorFamily::disjoint(&[&[2, 3, 5, 7, 11, 13]]).unwrap();
        assert!(lone.groups_are_jointly_liftable());

        // Two or more groups never are, whatever the split.
        for split in [
            &[&[2i128, 3, 5][..], &[7, 11, 13][..]][..],
            &[&[3][..], &[5][..]][..],
            &[&[4][..], &[9][..]][..],
            &[&[13, 17][..], &[19, 23][..]][..],
        ] {
            let family = AnchorFamily::disjoint(split).unwrap();
            assert!(
                !family.groups_are_jointly_liftable(),
                "split {split:?} must not be jointly liftable"
            );
        }

        // Concretely, for the Safe Basis split {2,3,5} / {7,11,13}:
        assert_eq!(crate::k_elim::gcd(30 * 31, 1001 * 1002), 6);

        // So a disjoint family refuses a joint reconstruction outright.
        let family = AnchorFamily::disjoint(&[&[3, 5], &[7, 11]]).unwrap();
        assert_eq!(
            family.reconstruct(&[(0, 0), (0, 0)], &[0, 0]),
            Err(AnchorError::NoJointValue)
        );
    }

    /// C8 — capacity overflow refuses. The tower squares, so it exhausts `i128`
    /// after a handful of levels; a wrapped capacity would be a range check that
    /// passes for values it cannot represent.
    #[test]
    fn tower_overflow_is_refused_rather_than_wrapped() {
        let mut last_ok = 0usize;
        for depth in 1..=8 {
            match AnchorFamily::telescoping(36, depth) {
                Ok(family) => {
                    assert!(family.capacity() > 0, "capacity must not wrap negative");
                    last_ok = depth;
                }
                Err(AnchorError::CapacityOverflow { .. }) => break,
                Err(e) => panic!("unexpected error at depth {depth}: {e:?}"),
            }
        }
        assert_eq!(
            last_ok, 4,
            "the 36-tower is representable to exactly depth 4 in i128"
        );
        assert!(
            matches!(
                AnchorFamily::telescoping(36, last_ok + 1),
                Err(AnchorError::CapacityOverflow { .. })
            ),
            "the level past the last representable one must be refused"
        );
        assert_eq!(
            AnchorFamily::telescoping(36, 0),
            Err(AnchorError::EmptyFamily)
        );
        assert_eq!(Anchor::adjacent(1), Err(AnchorError::ModulusTooSmall { p: 1 }));
        assert_eq!(Anchor::adjacent(0), Err(AnchorError::ModulusTooSmall { p: 0 }));
    }

    /// The winding of an `ExactState` is what decides range. A state inside the
    /// family's capacity lifts; one the winding has carried past it is refused —
    /// and two states can share a residue signature while differing in winding,
    /// which is why a signature-only design cannot make this call.
    #[test]
    fn lift_state_uses_the_winding_to_enforce_range() {
        let family = AnchorFamily::telescoping(6, 3).unwrap();
        let cap = family.capacity();
        assert_eq!(cap, 1806 * 1807);

        for x in [0i128, 1, 30_029, 30_030, 123_456, cap - 1] {
            let state = ExactState::from_i128(x);
            assert_eq!(family.lift_state(&state).unwrap(), x, "x={x}");
        }

        for x in [cap, cap + 1, 4_123_456] {
            let state = ExactState::from_i128(x);
            assert_eq!(
                family.lift_state(&state),
                Err(AnchorError::OutOfRange { x, capacity: cap }),
                "x={x} must be refused"
            );
        }

        // The lanes cannot tell these apart; only the winding can.
        let a = ExactState::from_i128(7);
        let b = ExactState::from_i128(7 + 30_030);
        assert_eq!(a.lanes, b.lanes, "identical residue signature");
        assert_ne!(a.winding, b.winding, "distinguished only by winding");
        assert_eq!(family.lift_state(&a).unwrap(), 7);
        assert_eq!(family.lift_state(&b).unwrap(), 30_037);
    }

    /// Residues are canonical here: a caller handing in a non-canonical residue
    /// gets an error, not a silent normalisation that would hide the bug.
    #[test]
    fn non_canonical_residues_are_refused() {
        let anchor = Anchor::adjacent(36).unwrap();
        assert_eq!(
            anchor.winding(36, 0),
            Err(AnchorError::ResidueOutOfRange {
                residue: 36,
                modulus: 36
            })
        );
        assert_eq!(
            anchor.winding(-1, 0),
            Err(AnchorError::ResidueOutOfRange {
                residue: -1,
                modulus: 36
            })
        );
        assert_eq!(
            anchor.winding(0, 37),
            Err(AnchorError::ResidueOutOfRange {
                residue: 37,
                modulus: 37
            })
        );
        assert!(
            anchor.winding(35, 36).is_ok(),
            "the largest legal pair must still be accepted"
        );
    }

    /// Arity is checked; a short pair list cannot silently produce a short lift.
    #[test]
    fn arity_mismatches_are_refused() {
        let family = AnchorFamily::telescoping(6, 2).unwrap();
        assert_eq!(
            family.windings(&[(0, 0)]),
            Err(AnchorError::Arity {
                expected: 2,
                got: 1
            })
        );
        assert_eq!(
            family.reconstruct(&[(0, 0)], &[0, 0]),
            Err(AnchorError::Arity {
                expected: 2,
                got: 1
            })
        );
        assert_eq!(
            family.reconstruct(&[(0, 0), (0, 0)], &[0]),
            Err(AnchorError::Arity {
                expected: 2,
                got: 1
            })
        );
        assert_eq!(
            AnchorFamily::disjoint(&[&[2], &[]]),
            Err(AnchorError::EmptyGroup { index: 1 })
        );
        assert_eq!(AnchorFamily::disjoint(&[]), Err(AnchorError::EmptyFamily));
    }
}
