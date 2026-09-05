//! Lift-aware CRAM transduction.
//!
//! `TransductionMap::apply` intentionally names the canonical source value in
//! `[0, M_A)`.  Once the represented integer crosses that source-product
//! boundary, the source residue tray alone cannot distinguish `X` from
//! `X + M_A`.  This module supplies the missing exact term without carrying a
//! scalar winding as payload.
//!
//! If the represented integer is
//!
//! ```text
//! X = g + K*M_A,   0 <= g < M_A,
//! ```
//!
//! then on target lane `b`:
//!
//! ```text
//! X mod b = g mod b + (K mod b)*(M_A mod b) mod b.
//! ```
//!
//! The caller supplies `K mod b` per target lane.  Those residues are intended
//! to be derived on demand from the phase-lock/anchor machinery; this API does
//! not require, store, or reconstruct a scalar `K`.
//!
//! Two entry points are provided:
//!
//! - [`transduct_with_lift`] takes a pre-materialized `K mod b_j` slice, one
//!   entry per target lane. This is the original bounded primitive and its
//!   error contract is unchanged.
//! - [`transduct_with_lift_provider`] takes a typed [`LiftEvidenceProvider`]
//!   instead, so the caller's phase-lock/anchor mechanism can hand back
//!   `K mod b_j` one target lane at a time, on demand, instead of
//!   materializing the whole vector up front. Absent evidence and an invalid
//!   target contract both come back as [`LiftedTransductionError`], never a
//!   panic and never a silently wrong residue.
//!
//! Neither entry point stores, requires, or reconstructs a scalar `K`. The
//! only convenience type this module ships, [`PrecomputedLiftEvidence`], is a
//! length/range-checked *view* over a caller-owned per-lane slice — it holds
//! no scalar winding state of its own.
//!
//! A1/A2: exact integer arithmetic only; no floating point and no
//! mixed-radix/Garner reconstruction is introduced by this module.

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
#[cfg(feature = "std")]
use std::vec::Vec;

use crate::k_elim::{gcd, modd, mulmod};
use crate::transduction::TransductionMap;

/// Typed failure for lift-aware transduction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LiftedTransductionError {
    /// The source residue count does not match the source basis.
    SourceLengthMismatch { expected: usize, actual: usize },
    /// One `K mod b_j` value is required for every target lane.
    LiftLengthMismatch { expected: usize, actual: usize },
    /// Residue modulus must be strictly positive.
    InvalidTargetModulus { index: usize, modulus: i128 },
    /// A source-basis modulus must be strictly positive.
    InvalidSourceModulus { index: usize, modulus: i128 },
    /// The source basis is not pairwise coprime, so it cannot carry a CRT
    /// idempotent decomposition (the invalid-range/contract half of the
    /// typed-failure requirement: this used to be a `.expect()` panic inside
    /// `TransductionMap::new`, surfaced here instead).
    SourceBasisNotPairwiseCoprime { lane_i: usize, lane_j: usize },
    /// A [`LiftEvidenceProvider`] could not supply `K mod b_j` for the named
    /// target lane (out of range, or the provider's own derivation failed).
    EvidenceUnavailable { lane: usize },
}

/// Every source-basis modulus must be positive and pairwise coprime with
/// every other source-basis modulus, or `TransductionMap::new` has no CRT
/// idempotent to compute and would otherwise panic. Checked once, up front,
/// so both entry points below fail closed on a malformed source basis
/// instead of panicking inside the transduction primitive.
fn validate_source_basis(basis_a: &[i128]) -> Result<(), LiftedTransductionError> {
    for (i, &a_i) in basis_a.iter().enumerate() {
        if a_i <= 0 {
            return Err(LiftedTransductionError::InvalidSourceModulus {
                index: i,
                modulus: a_i,
            });
        }
    }
    for i in 0..basis_a.len() {
        for j in (i + 1)..basis_a.len() {
            if gcd(basis_a[i], basis_a[j]) != 1 {
                return Err(LiftedTransductionError::SourceBasisNotPairwiseCoprime {
                    lane_i: i,
                    lane_j: j,
                });
            }
        }
    }
    Ok(())
}

/// Overflow-safe modular addition for normalized positive modulus `m`.
#[inline]
fn addmod(a: i128, b: i128, m: i128) -> i128 {
    debug_assert!(m > 0);
    let a = modd(a, m);
    let b = modd(b, m);
    // Avoid forming a+b when it could overflow i128.
    if a >= m - b {
        a - (m - b)
    } else {
        a + b
    }
}

/// Project a canonical source residue plus a derived lift residue into one
/// target lane.
///
/// This is Universal Projection specialized to the source-product lift:
///
/// ```text
/// X = g + K*M
/// X mod b = g_b + K_b*M_b mod b.
/// ```
///
/// `k_mod_b` is an observable of the phase-locked state, not a stored scalar
/// winding requirement.
pub fn project_with_lift(
    g_mod_b: i128,
    k_mod_b: i128,
    source_product_mod_b: i128,
    target_modulus: i128,
) -> Option<i128> {
    if target_modulus <= 0 {
        return None;
    }
    let lift_term = mulmod(k_mod_b, source_product_mod_b, target_modulus);
    Some(addmod(g_mod_b, lift_term, target_modulus))
}

/// Lift-aware basis transduction.
///
/// First obtains the canonical source representative's target residues using
/// the existing bounded [`TransductionMap`].  It then adds the exact lift
/// contribution independently on every target lane.
///
/// The operation never requires full integer materialization.  `k_mod_targets`
/// must contain `K mod b_j` for each target modulus `b_j`, obtained from the
/// caller's certified phase-lock/anchor mechanism.
pub fn transduct_with_lift(
    basis_a: &[i128],
    basis_b: &[i128],
    source_residues: &[i128],
    k_mod_targets: &[i128],
) -> Result<Vec<i128>, LiftedTransductionError> {
    validate_source_basis(basis_a)?;
    if source_residues.len() != basis_a.len() {
        return Err(LiftedTransductionError::SourceLengthMismatch {
            expected: basis_a.len(),
            actual: source_residues.len(),
        });
    }
    if k_mod_targets.len() != basis_b.len() {
        return Err(LiftedTransductionError::LiftLengthMismatch {
            expected: basis_b.len(),
            actual: k_mod_targets.len(),
        });
    }
    for (j, &b) in basis_b.iter().enumerate() {
        if b <= 0 {
            return Err(LiftedTransductionError::InvalidTargetModulus {
                index: j,
                modulus: b,
            });
        }
    }

    // `apply` returns g mod b_j for the canonical g in [0,M_A).
    let map = TransductionMap::new(basis_a, basis_b);
    let canonical_targets = map.apply(source_residues);
    let m_a = map.m_a();

    let mut out = Vec::with_capacity(basis_b.len());
    for (j, &b) in basis_b.iter().enumerate() {
        let y = project_with_lift(canonical_targets[j], k_mod_targets[j], modd(m_a, b), b)
            .expect("target moduli validated positive above");
        out.push(y);
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Typed on-demand lift evidence
// ---------------------------------------------------------------------------

/// One target lane's lift evidence: `K mod target_modulus`, already reduced
/// into `[0, target_modulus)`.
///
/// This is a type-level tag, not a general-purpose integer. It exists so a
/// caller cannot hand a raw magnitude, or a stored full-precision `K`, where
/// only a single lane's reduced residue is asked for — the type only comes
/// into existence already reduced against the lane it names, via
/// [`LiftEvidence::new`] or a [`LiftEvidenceProvider`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LiftEvidence {
    lane: usize,
    target_modulus: i128,
    k_mod_target: i128,
}

impl LiftEvidence {
    /// Build lift evidence for one target lane, reducing `k` into
    /// `[0, target_modulus)`.
    ///
    /// Fails closed — rather than accepting a nonsensical modulus and
    /// silently producing a meaningless residue — when `target_modulus` is
    /// not strictly positive.
    pub fn new(
        lane: usize,
        target_modulus: i128,
        k: i128,
    ) -> Result<Self, LiftedTransductionError> {
        if target_modulus <= 0 {
            return Err(LiftedTransductionError::InvalidTargetModulus {
                index: lane,
                modulus: target_modulus,
            });
        }
        Ok(LiftEvidence {
            lane,
            target_modulus,
            k_mod_target: modd(k, target_modulus),
        })
    }

    /// The target-lane index this evidence was derived for.
    pub fn lane(&self) -> usize {
        self.lane
    }

    /// The target modulus this evidence was reduced against.
    pub fn target_modulus(&self) -> i128 {
        self.target_modulus
    }

    /// `K mod target_modulus`, already reduced into `[0, target_modulus)`.
    pub fn k_mod_target(&self) -> i128 {
        self.k_mod_target
    }
}

/// On-demand source of [`LiftEvidence`], one target lane at a time.
///
/// Implementors derive `K mod b_j` from the caller's certified
/// phase-lock/anchor mechanism (see the module docs). No implementation in
/// this crate derives a target residue from a stored scalar `K` — the trait
/// is queried per lane, and nothing requires (or permits) a caller to hand
/// this crate a full-precision winding to cache.
///
/// Absent evidence, or a target-basis/range contract the provider cannot
/// satisfy, must return `Err(LiftedTransductionError)` — never a panic, and
/// never a fabricated residue.
pub trait LiftEvidenceProvider {
    /// Supply `K mod target_modulus` for target lane `lane`.
    fn lift_evidence(
        &self,
        lane: usize,
        target_modulus: i128,
    ) -> Result<LiftEvidence, LiftedTransductionError>;
}

/// A [`LiftEvidenceProvider`] backed by an eagerly materialized per-lane
/// slice.
///
/// This is the only provider this crate ships that does not itself *derive*
/// anything: it is a length/range-checked typed *view* over a caller-owned
/// `K mod b_j` slice, equivalent in spirit to the slice [`transduct_with_lift`]
/// already accepted. It stores no scalar `K` — only a borrow of the caller's
/// own per-lane residues — and it exists so that call sites which already
/// have every lane's evidence in hand can still go through the typed
/// [`transduct_with_lift_provider`] entry point.
pub struct PrecomputedLiftEvidence<'a> {
    k_mod_targets: &'a [i128],
}

impl<'a> PrecomputedLiftEvidence<'a> {
    /// Wrap a caller-owned `K mod b_j` slice, one entry per target lane.
    pub fn new(k_mod_targets: &'a [i128]) -> Self {
        PrecomputedLiftEvidence { k_mod_targets }
    }
}

impl LiftEvidenceProvider for PrecomputedLiftEvidence<'_> {
    fn lift_evidence(
        &self,
        lane: usize,
        target_modulus: i128,
    ) -> Result<LiftEvidence, LiftedTransductionError> {
        let raw = self
            .k_mod_targets
            .get(lane)
            .copied()
            .ok_or(LiftedTransductionError::EvidenceUnavailable { lane })?;
        LiftEvidence::new(lane, target_modulus, raw)
    }
}

/// Any `Fn(lane, target_modulus) -> Result<i128, LiftedTransductionError>`
/// closure is itself a [`LiftEvidenceProvider`].
///
/// This is the genuinely on-demand shape the phase-lock/anchor machinery is
/// expected to use in practice: each call derives one lane's `K mod b_j`
/// fresh, with no vector of every lane's evidence ever materialized.
impl<F> LiftEvidenceProvider for F
where
    F: Fn(usize, i128) -> Result<i128, LiftedTransductionError>,
{
    fn lift_evidence(
        &self,
        lane: usize,
        target_modulus: i128,
    ) -> Result<LiftEvidence, LiftedTransductionError> {
        let raw = self(lane, target_modulus)?;
        LiftEvidence::new(lane, target_modulus, raw)
    }
}

/// Typed, on-demand lift-aware basis transduction.
///
/// Identical in exact-integer semantics to [`transduct_with_lift`], except
/// that `K mod b_j` for each target lane is requested one at a time from a
/// [`LiftEvidenceProvider`] instead of being supplied as a pre-materialized
/// slice. This is the typed entry point WR-4 promotes: absent evidence and
/// an invalid target-basis/range contract both come back as a typed
/// [`LiftedTransductionError`] — never a panic, never a silently truncated
/// or wrong residue.
///
/// The operation never requires full integer materialization, and — like
/// [`transduct_with_lift`] — introduces no Garner/mixed-radix cascade.
pub fn transduct_with_lift_provider<P>(
    basis_a: &[i128],
    basis_b: &[i128],
    source_residues: &[i128],
    lift: &P,
) -> Result<Vec<i128>, LiftedTransductionError>
where
    P: LiftEvidenceProvider + ?Sized,
{
    validate_source_basis(basis_a)?;
    if source_residues.len() != basis_a.len() {
        return Err(LiftedTransductionError::SourceLengthMismatch {
            expected: basis_a.len(),
            actual: source_residues.len(),
        });
    }
    for (j, &b) in basis_b.iter().enumerate() {
        if b <= 0 {
            return Err(LiftedTransductionError::InvalidTargetModulus {
                index: j,
                modulus: b,
            });
        }
    }

    // `apply` returns g mod b_j for the canonical g in [0,M_A).
    let map = TransductionMap::new(basis_a, basis_b);
    let canonical_targets = map.apply(source_residues);
    let m_a = map.m_a();

    let mut out = Vec::with_capacity(basis_b.len());
    for (j, &b) in basis_b.iter().enumerate() {
        let evidence = lift.lift_evidence(j, b)?;
        if evidence.target_modulus() != b {
            return Err(LiftedTransductionError::InvalidTargetModulus {
                index: j,
                modulus: evidence.target_modulus(),
            });
        }
        let y = project_with_lift(
            canonical_targets[j],
            evidence.k_mod_target(),
            modd(m_a, b),
            b,
        )
        .expect("target moduli validated positive above");
        out.push(y);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transduction::{S6_BASIS, S8_BASIS};

    fn residues(x: i128, basis: &[i128]) -> Vec<i128> {
        basis.iter().map(|&m| modd(x, m)).collect()
    }

    #[test]
    fn universal_projection_matches_direct_mod_for_shared_factor_targets() {
        let m = 30_030i128;
        let g = 29i128;
        let k = 17i128;
        let x = g + k * m;
        for b in [1i128, 4, 6, 9, 12, 18, 35, 77, 143, 256] {
            let got = project_with_lift(modd(g, b), modd(k, b), modd(m, b), b).unwrap();
            assert_eq!(got, modd(x, b), "target={b}");
        }
    }

    #[test]
    fn first_s6_wrap_projects_to_correct_s8_extension_lanes() {
        let x = 30_030i128;
        let source = residues(x, &S6_BASIS); // same tray as zero
        assert_eq!(source, residues(0, &S6_BASIS));

        // K=1 is derived by the phase-lock layer.  This test feeds only its
        // target residues, never a scalar winding field into the API.
        let k_mod_targets: Vec<i128> = S8_BASIS.iter().map(|&b| 1 % b).collect();
        let out = transduct_with_lift(&S6_BASIS, &S8_BASIS, &source, &k_mod_targets).unwrap();

        assert_eq!(out[6], 8); // 30030 mod 17
        assert_eq!(out[7], 10); // 30030 mod 19
        assert_eq!(out, residues(x, &S8_BASIS));
    }

    #[test]
    fn zero_lift_is_identical_to_bounded_transduction() {
        let x = 12_345i128;
        let source = residues(x, &S6_BASIS);
        let zero_k = vec![0i128; S8_BASIS.len()];
        let lifted = transduct_with_lift(&S6_BASIS, &S8_BASIS, &source, &zero_k).unwrap();
        let bounded = TransductionMap::new(&S6_BASIS, &S8_BASIS).apply(&source);
        assert_eq!(lifted, bounded);
    }

    #[test]
    fn bad_lengths_fail_closed() {
        let err = transduct_with_lift(&S6_BASIS, &S8_BASIS, &[0], &[0; 8]).unwrap_err();
        assert!(matches!(
            err,
            LiftedTransductionError::SourceLengthMismatch { .. }
        ));

        let source = vec![0i128; S6_BASIS.len()];
        let err = transduct_with_lift(&S6_BASIS, &S8_BASIS, &source, &[0]).unwrap_err();
        assert!(matches!(
            err,
            LiftedTransductionError::LiftLengthMismatch { .. }
        ));
    }

    #[test]
    fn provider_backed_precomputed_evidence_matches_the_slice_api() {
        let x = 30_030i128;
        let source = residues(x, &S6_BASIS);
        let k_mod_targets: Vec<i128> = S8_BASIS.iter().map(|&b| 1 % b).collect();

        let via_slice = transduct_with_lift(&S6_BASIS, &S8_BASIS, &source, &k_mod_targets).unwrap();

        let provider = PrecomputedLiftEvidence::new(&k_mod_targets);
        let via_provider =
            transduct_with_lift_provider(&S6_BASIS, &S8_BASIS, &source, &provider).unwrap();

        assert_eq!(via_slice, via_provider);
        assert_eq!((via_provider[6], via_provider[7]), (8, 10));
    }

    #[test]
    fn closure_provider_derives_k_on_demand_with_no_materialized_vector() {
        // The first wrapped S6 sheet: K=1, derived here per-lane by a closure
        // that never builds a Vec<i128> of every lane's evidence at once —
        // this is the genuinely on-demand shape a phase-lock/anchor caller
        // would use.
        let x = 30_030i128;
        let source = residues(x, &S6_BASIS);
        let k = 1i128;
        let provider =
            |_lane: usize, target_modulus: i128| -> Result<i128, LiftedTransductionError> {
                Ok(modd(k, target_modulus))
            };

        let out = transduct_with_lift_provider(&S6_BASIS, &S8_BASIS, &source, &provider).unwrap();
        assert_eq!(out, residues(x, &S8_BASIS));
        assert_eq!((out[6], out[7]), (8, 10));
    }

    #[test]
    fn absent_evidence_fails_closed_never_a_panic() {
        let source = vec![0i128; S6_BASIS.len()];
        // Only 2 of 8 target lanes have evidence: PrecomputedLiftEvidence must
        // report the gap by lane index rather than panicking on the missing
        // entries or silently treating them as zero.
        let short_evidence = [0i128, 0];
        let provider = PrecomputedLiftEvidence::new(&short_evidence);

        let err =
            transduct_with_lift_provider(&S6_BASIS, &S8_BASIS, &source, &provider).unwrap_err();
        assert_eq!(
            err,
            LiftedTransductionError::EvidenceUnavailable { lane: 2 }
        );
    }

    #[test]
    fn provider_returning_the_wrong_lane_modulus_is_rejected() {
        let source = vec![0i128; S6_BASIS.len()];
        // A provider that always constructs its evidence against modulus 5,
        // regardless of the target modulus it was actually asked about — the
        // mismatch must be caught as an invalid target contract, not
        // silently accepted.
        struct WrongModulus;
        impl LiftEvidenceProvider for WrongModulus {
            fn lift_evidence(
                &self,
                lane: usize,
                _target_modulus: i128,
            ) -> Result<LiftEvidence, LiftedTransductionError> {
                LiftEvidence::new(lane, 5, 3)
            }
        }
        let err =
            transduct_with_lift_provider(&S6_BASIS, &S8_BASIS, &source, &WrongModulus).unwrap_err();
        assert!(matches!(
            err,
            LiftedTransductionError::InvalidTargetModulus { .. }
        ));
    }

    #[test]
    fn zero_or_negative_source_modulus_fails_closed_never_a_panic() {
        let bad_basis = [2i128, 0, 5];
        let source = vec![0i128; 3];
        let k_mod_targets = vec![0i128; S8_BASIS.len()];

        let err = transduct_with_lift(&bad_basis, &S8_BASIS, &source, &k_mod_targets).unwrap_err();
        assert_eq!(
            err,
            LiftedTransductionError::InvalidSourceModulus {
                index: 1,
                modulus: 0
            }
        );

        let provider = PrecomputedLiftEvidence::new(&k_mod_targets);
        let err =
            transduct_with_lift_provider(&bad_basis, &S8_BASIS, &source, &provider).unwrap_err();
        assert_eq!(
            err,
            LiftedTransductionError::InvalidSourceModulus {
                index: 1,
                modulus: 0
            }
        );
    }

    #[test]
    fn non_pairwise_coprime_source_basis_fails_closed_never_a_panic() {
        // 6 and 9 share a factor of 3: no CRT idempotent exists, and the
        // underlying TransductionMap::new would otherwise panic.
        let bad_basis = [6i128, 9, 5];
        let source = vec![0i128; 3];
        let k_mod_targets = vec![0i128; S8_BASIS.len()];

        let err = transduct_with_lift(&bad_basis, &S8_BASIS, &source, &k_mod_targets).unwrap_err();
        assert_eq!(
            err,
            LiftedTransductionError::SourceBasisNotPairwiseCoprime {
                lane_i: 0,
                lane_j: 1
            }
        );
    }

    #[test]
    fn lift_evidence_rejects_nonpositive_target_modulus() {
        assert_eq!(
            LiftEvidence::new(0, 0, 5).unwrap_err(),
            LiftedTransductionError::InvalidTargetModulus {
                index: 0,
                modulus: 0
            }
        );
        assert_eq!(
            LiftEvidence::new(0, -3, 5).unwrap_err(),
            LiftedTransductionError::InvalidTargetModulus {
                index: 0,
                modulus: -3
            }
        );
        let ev = LiftEvidence::new(2, 7, 30).unwrap();
        assert_eq!(ev.lane(), 2);
        assert_eq!(ev.target_modulus(), 7);
        assert_eq!(ev.k_mod_target(), 2); // 30 mod 7
    }
}
