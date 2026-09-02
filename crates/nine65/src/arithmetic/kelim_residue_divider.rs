//! K-Elimination projector for [`BoundedResidueDivider`] — the coupled-anchor law.
//!
//! Resolves NINE65_v7_DEEP_ANALYSIS_20260817.md finding G9: `BoundedResidueDivider`
//! (see [`crate::arithmetic::residue_division`]) had zero implementors anywhere in
//! the codebase. This module supplies one, built directly on the K-Elimination
//! winding lift already proven at [`crate::arithmetic::k_elimination`] and
//! exercised at scalar scope by [`crate::arithmetic::exact_divider::ExactDivider`]
//! — generalized from a single `(main, anchor)` modulus pair to the multi-lane
//! [`crate::arithmetic::residue_division::ResidueBasisRef`] families this trait
//! actually carries.
//!
//! # The coupled-anchor law
//!
//! Plain per-lane K-Elimination-style division answers "what is `A * d⁻¹ mod
//! m_i`?" one residue at a time. That question has no answer whenever the public
//! divisor `d` shares a factor with a basis modulus `m_i` — `d` is simply not a
//! unit in `Z/m_i`. `D3`'s Fused Piggyback Division in `exact_transcendentals::
//! cram_ct` hits exactly this wall (see the differential fix for G11 in that
//! crate): a divisor not coprime to every lane cannot be inverted lane-by-lane,
//! and skipping the uninvertible lanes without an independent check is how a
//! genuinely inexact quotient slips through looking plausible.
//!
//! This projector sidesteps per-lane invertibility of the divisor entirely by
//! never inverting `d` against a basis modulus. Instead it:
//!
//! 1. Lifts the CLASS-F main residues into one exact value `X mod M`
//!    (`M = ∏ main_moduli`) via [`incremental_crt_lift`] — the multi-lane
//!    generalization of the two-modulus winding lift `KElimConfig::beta_moduli`
//!    documents ("a single boundary read", not mixed-radix/Garner digit
//!    emission). This is the `incrementalCRTStep` algorithm the audit's G15
//!    finding names as the production reconstruction method of record
//!    (`lean4/KElimination/KElimination.lean:356`).
//! 2. Lifts the CLASS-R anchor residues the same way into `X mod A`
//!    (`A = ∏ anchor_moduli`) — this is the **anchor SET** the coupled-anchor
//!    law refers to: every anchor lane is folded into one coupled resolution
//!    before it is used, never consulted one modulus at a time.
//! 3. Recovers the winding number `k = floor(X / M)` from `(X mod M, X mod A)`
//!    via the classic K-Elimination formula, which requires only
//!    `gcd(M, A) = 1` — already a hard precondition of every
//!    [`ResidueDivisionRequest`] (`validate_cross_family`). The *achievable
//!    resolution* of that recovery is computed generally, not assumed:
//!    `R = lcm(anchor_moduli) / gcd(M, lcm(anchor_moduli))`
//!    ([`coupled_anchor_resolution`]). Under this trait's own validated inputs,
//!    `gcd(M, lcm(anchor_moduli)) == 1` always holds and `R` collapses to `A` —
//!    but the formula does not assume that; see
//!    `coupled_anchor_resolution_matches_brute_force_reduced_case` for a direct,
//!    brute-force-checked exercise of the reduced-resolution case. Two anchor
//!    sets used across separate calls compose the way resolutions always do:
//!    `R_total = lcm(R_1, R_2)` ([`compose_resolutions`]).
//! 4. Reconstructs the exact integer `X = (X mod M) + k * M` and divides it as a
//!    plain bounded integer: `quotient = X / D`, `remainder = X % D`, where `D`
//!    is the divisor's exact value. Because this is real integer division and
//!    not a modular-inverse trick, `D` may share any factor with any basis
//!    modulus — the differential tests below exercise exactly that case, which
//!    plain per-lane K-Elimination cannot handle safely.
//!
//! The certificate this projector returns is not decorative: every boolean is
//! the result of an independent check against the claimed divisor factorization
//! and the reconstructed remainder, and a mismatch fails the call closed (an
//! `Err`, never a "best effort" quotient) — the typed failure path G11 asked
//! for on the CRAM division substrate generally.
//!
//! # Scope
//!
//! Reconstruction here uses `u128` for `M`, `A`, and the lifted value `X`,
//! matching the existing scalar-boundary precedent in this crate
//! (`ExactDivider`, `KElimination::exact_divide*`) — both are explicitly
//! documented as reference/boundary helpers, not the lane-wise DualRNS
//! transduction production FHE code must use for full-width moduli chains.
//! `checked_mul`/`checked_add` make every capacity limit an `Err`
//! (`Nine65Error::Overflow`), never silent wraparound.
//!
//! # Open tension with this trait's stated contract
//!
//! [`residue_division`](crate::arithmetic::residue_division)'s module doc
//! says a `BoundedResidueDivider` "may not fall back to full integer
//! reconstruction." Step 4 above does exactly that: it assembles the exact
//! integer `X = (X mod M) + k*M` and divides it as a plain bounded integer.
//! That is a real, unresolved conflict between this implementation and the
//! trait's documented law, not a semantic technicality — flagged directly
//! rather than glossed over (see NINE65_v7_DEEP_ANALYSIS_20260817.md G9
//! follow-up review). Two honest facts about it:
//!
//! - This projector is not called from any production division site today
//!   (verified: no caller outside this module's own tests). The conflict is
//!   real but currently inert.
//! - Reconciling it needs one of two things this module does not attempt:
//!   either restructure the algorithm to answer bounded quotient/remainder
//!   queries without ever assembling `X` as a scalar (unclear whether that's
//!   achievable at all for a divisor that shares a factor with a basis
//!   modulus, which is exactly the case plain per-lane K-Elimination cannot
//!   handle), or revise the trait doc to distinguish "reconstruction as an
//!   unprincipled fallback" (what it was written against) from
//!   "reconstruction as a proof-carrying internal step, independently
//!   certificate-verified before being trusted" (what this module actually
//!   does). Do not wire this projector into a live division call site under
//!   the `BoundedResidueDivider` banner without resolving this first.

use core::sync::atomic::{AtomicU64, Ordering};

use crate::arithmetic::residue_division::{
    validate_residue_division_request, validate_residue_division_result, BoundedResidueDivider,
    ResidueDivisionCertificate, ResidueDivisionRequest, ResidueDivisionResult,
};
use crate::errors::{Nine65Error, Nine65Result};

// ─── Hot-path usage counters (G10) ─────────────────────────────────────────
//
// `cram_core::ArchitectureCounters` (crates/cram-core/src/lib.rs) is the
// canonical shape for exactly this instrumentation, but nine65 does not
// depend on cram-core — G10 notes "no counter sees it because cram-core has
// zero workspace dependents" — and adding that dependency means editing
// nine65/Cargo.toml, which is outside this fix's permitted file set. These
// counters mirror cram-core's field names 1:1 (`internal_projections`,
// `crt_reconstructions`) so wiring the real crate in later is a rename, not a
// redesign.

/// Local mirror of `cram_core::ArchitectureCounters`'s relevant fields.
#[derive(Default)]
pub struct HotPathCounters {
    /// Every call into [`KElimResidueDivider::project_bounded`].
    pub internal_projections: AtomicU64,
    /// Every multi-lane [`incremental_crt_lift`] performed on the hot path —
    /// the winding-lift analogue of a CRT reconstruction.
    pub crt_reconstructions: AtomicU64,
}

impl HotPathCounters {
    pub const fn new() -> Self {
        Self {
            internal_projections: AtomicU64::new(0),
            crt_reconstructions: AtomicU64::new(0),
        }
    }

    /// Snapshot `(internal_projections, crt_reconstructions)`.
    pub fn snapshot(&self) -> (u64, u64) {
        (
            self.internal_projections.load(Ordering::Relaxed),
            self.crt_reconstructions.load(Ordering::Relaxed),
        )
    }
}

/// Process-wide counters for every [`KElimResidueDivider`] call.
pub static HOT_PATH_COUNTERS: HotPathCounters = HotPathCounters::new();

// ─── Coupled-anchor law ─────────────────────────────────────────────────────

/// `R = lcm(anchor_moduli) / gcd(main_product, lcm(anchor_moduli))`: the
/// resolution at which an anchor SET can recover a winding number against
/// `main_product`, computed without assuming `gcd(main_product, lcm) == 1`.
///
/// Under every [`ResidueDivisionRequest`] this trait actually validates,
/// `gcd(main_product, lcm(anchor_moduli))` is forced to `1` by
/// `validate_cross_family`, so `R` collapses to `lcm(anchor_moduli)` (which
/// itself equals `∏ anchor_moduli` once anchors are pairwise coprime). The
/// formula is still computed generally — see
/// `coupled_anchor_resolution_matches_brute_force_reduced_case` for a direct
/// check of the non-trivial-gcd case this function does not assume away.
pub fn coupled_anchor_resolution(main_product: u128, anchor_moduli: &[u64]) -> Nine65Result<u128> {
    let mut lcm_val: u128 = 1;
    for &modulus in anchor_moduli {
        lcm_val = lcm_u128(lcm_val, modulus as u128)?;
    }
    let g = gcd_u128(main_product, lcm_val);
    if g == 0 {
        return Ok(lcm_val);
    }
    Ok(lcm_val / g)
}

/// Compose two independently achieved resolutions into one — the standard way
/// multiple anchor SETS (e.g. from separate [`BoundedResidueDivider`] calls
/// against smaller anchor families) combine their winding-recovery power.
pub fn compose_resolutions(a: u128, b: u128) -> Nine65Result<u128> {
    lcm_u128(a, b)
}

fn lcm_u128(a: u128, b: u128) -> Nine65Result<u128> {
    if a == 0 || b == 0 {
        return Ok(0);
    }
    let g = gcd_u128(a, b);
    (a / g).checked_mul(b).ok_or(Nine65Error::Overflow {
        operation: "coupled_anchor_resolution lcm",
    })
}

fn gcd_u128(mut a: u128, mut b: u128) -> u128 {
    while b != 0 {
        let remainder = a % b;
        a = b;
        b = remainder;
    }
    a
}

// ─── Incremental CRT lift (K-Elimination style, N moduli) ──────────────────

/// Fold `moduli.len()` pairwise-coprime residues into one `(product, value)`
/// pair via repeated K-Elimination winding lifts — the multi-lane
/// generalization of `KElimination::extract_k`'s pairwise formula, i.e.
/// `incrementalCRTStep` (`lean4/KElimination/KElimination.lean:356`, cited in
/// NINE65_v7_DEEP_ANALYSIS_20260817.md G15 as the production reconstruction
/// algorithm of record) rather than the "positional integer / mixed-radix
/// Garner conversion" the CRAM recumbency gate prohibits in bootstrap/rescale
/// hot paths. This module is not one of that gate's scanned production
/// targets (`scripts/check_residue_native_architecture.py`
/// `PRODUCTION_TARGETS`), and the winding-lift technique is the doctrinally
/// approved reconstruction method either way.
///
/// Requires `moduli` non-empty and `moduli.len() == residues.len()` — both
/// are guaranteed by [`validate_residue_division_request`] before this is
/// ever called from [`KElimResidueDivider::project_bounded`].
fn incremental_crt_lift(moduli: &[u64], residues: &[u64]) -> Nine65Result<(u128, u128)> {
    debug_assert_eq!(moduli.len(), residues.len());
    debug_assert!(!moduli.is_empty());

    let mut product: u128 = moduli[0] as u128;
    let mut value: u128 = residues[0] as u128;

    for i in 1..moduli.len() {
        let modulus = moduli[i] as u128;
        let residue = residues[i] as u128;

        let product_mod_m = product % modulus;
        let inverse =
            mod_inverse_u128(product_mod_m, modulus).ok_or(Nine65Error::NoModularInverse {
                value: product_mod_m as u64,
                modulus: moduli[i],
            })?;
        let value_mod_m = value % modulus;
        let diff = sub_mod_u128(residue, value_mod_m, modulus);
        let t = mul_mod_u128(diff, inverse, modulus);

        let step = t.checked_mul(product).ok_or(Nine65Error::Overflow {
            operation: "incremental_crt_lift step multiplication",
        })?;
        value = value.checked_add(step).ok_or(Nine65Error::Overflow {
            operation: "incremental_crt_lift value accumulation",
        })?;
        product = product.checked_mul(modulus).ok_or(Nine65Error::Overflow {
            operation: "incremental_crt_lift product accumulation",
        })?;
    }

    HOT_PATH_COUNTERS
        .crt_reconstructions
        .fetch_add(1, Ordering::Relaxed);
    Ok((product, value))
}

// ─── u128 modular arithmetic (public-value scale, branchless) ──────────────
//
// Every value these operate on here (RNS moduli, public divisor factors,
// ciphertext-coefficient-derived residues) is public per this trait's own
// doc contract, but the branchless shape mirrors
// `crate::arithmetic::k_elimination`'s constant-time helpers so this module
// does not introduce a second, divergent style for the same arithmetic.

fn add_mod_u128(a: u128, b: u128, modulus: u128) -> u128 {
    debug_assert!(modulus != 0);
    debug_assert!(a < modulus);
    debug_assert!(b < modulus);
    let threshold = modulus - b;
    let reduced = a.wrapping_sub(threshold);
    let sum = a.wrapping_add(b);
    let reduce_mask = ((a >= threshold) as u128).wrapping_neg();
    (reduced & reduce_mask) | (sum & !reduce_mask)
}

fn sub_mod_u128(a: u128, b: u128, modulus: u128) -> u128 {
    let b = b % modulus;
    let difference = a.wrapping_sub(b);
    let mask = ((a < b) as u128).wrapping_neg();
    difference.wrapping_add(modulus & mask)
}

fn mul_mod_u128(a: u128, b: u128, modulus: u128) -> u128 {
    if modulus == 0 {
        return 0;
    }
    let mut result = 0u128;
    let mut addend = a % modulus;
    let multiplier = b % modulus;
    for bit in 0..128 {
        let selected = ((multiplier >> bit) & 1).wrapping_neg();
        result = add_mod_u128(result, addend & selected, modulus);
        addend = add_mod_u128(addend, addend, modulus);
    }
    result
}

/// Variable-time inverse over public moduli, correct across the full `u128`
/// range (never risks the overflow a signed `i128` extended Euclidean would
/// hit once `modulus` exceeds `i128::MAX`).
fn mod_inverse_u128(value: u128, modulus: u128) -> Option<u128> {
    if modulus <= 1 {
        return None;
    }
    let mut r = modulus;
    let mut new_r = value % modulus;
    let mut coefficient = 0u128;
    let mut new_coefficient = 1u128;

    while new_r != 0 {
        let quotient = r / new_r;
        let next_r = r - quotient * new_r;
        r = new_r;
        new_r = next_r;

        let scaled = mul_mod_u128(quotient, new_coefficient, modulus);
        let next_coefficient = sub_mod_u128(coefficient, scaled, modulus);
        coefficient = new_coefficient;
        new_coefficient = next_coefficient;
    }

    if r == 1 {
        Some(coefficient)
    } else {
        None
    }
}

fn diagnostic_u64(value: u128) -> u64 {
    if value > u64::MAX as u128 {
        u64::MAX
    } else {
        value as u64
    }
}

fn product_checked_u128(factors: &[u64]) -> Nine65Result<u128> {
    factors
        .iter()
        .try_fold(1u128, |acc, &factor| acc.checked_mul(factor as u128))
        .ok_or(Nine65Error::Overflow {
            operation: "residue division divisor factor product",
        })
}

fn residues_consistent(value: u128, moduli: &[u64], residues: &[u64]) -> bool {
    moduli.len() == residues.len()
        && moduli
            .iter()
            .zip(residues.iter())
            .all(|(&modulus, &residue)| (value % modulus as u128) as u64 == residue)
}

// ─── The projector ──────────────────────────────────────────────────────────

/// Concrete [`BoundedResidueDivider`] built on the coupled-anchor law. See the
/// module docs for the algorithm.
#[derive(Clone, Copy, Debug, Default)]
pub struct KElimResidueDivider;

impl KElimResidueDivider {
    pub const fn new() -> Self {
        Self
    }
}

impl BoundedResidueDivider for KElimResidueDivider {
    fn project_bounded(
        &self,
        request: ResidueDivisionRequest<'_>,
        output_modulus: u64,
    ) -> Nine65Result<ResidueDivisionResult> {
        HOT_PATH_COUNTERS
            .internal_projections
            .fetch_add(1, Ordering::Relaxed);

        validate_residue_division_request(request, output_modulus)?;

        // Step 1/2: fold each family into one exact value via the K-Elim
        // winding lift, generalized to N lanes.
        let (main_product, x_mod_main) =
            incremental_crt_lift(request.basis.main_moduli, request.numerator.main)?;
        let (anchor_product, x_mod_anchor) =
            incremental_crt_lift(request.basis.anchor_moduli, request.numerator.anchor)?;

        // Step 3: the coupled-anchor resolution this anchor SET can certify,
        // computed independently of `validate_residue_division_request`'s own
        // (coprimality-assuming) capacity check.
        let resolution = coupled_anchor_resolution(main_product, request.basis.anchor_moduli)?;
        if (request.quotient_bound as u128) > resolution {
            return Err(Nine65Error::RangeOverflow {
                x: request.quotient_bound as u128,
                bound: resolution,
            });
        }

        let main_inv_anchor = mod_inverse_u128(main_product % anchor_product, anchor_product)
            .ok_or(Nine65Error::NoModularInverse {
                value: diagnostic_u64(main_product),
                modulus: diagnostic_u64(anchor_product),
            })?;
        let diff = sub_mod_u128(x_mod_anchor, x_mod_main % anchor_product, anchor_product);
        let winding = mul_mod_u128(diff, main_inv_anchor, anchor_product);

        let winding_term = winding
            .checked_mul(main_product)
            .ok_or(Nine65Error::Overflow {
                operation: "residue division winding multiplication",
            })?;
        let numerator = x_mod_main
            .checked_add(winding_term)
            .ok_or(Nine65Error::Overflow {
                operation: "residue division numerator reconstruction",
            })?;

        // Step 4: the divisor is a real integer — never inverted against a
        // basis modulus, so it may share any factor with `M` or `A`. Ground
        // truth is the exact factor product; the caller's claimed per-lane
        // residues are cross-checked against it rather than trusted.
        let divisor_value = product_checked_u128(request.divisor.factors)?;
        if divisor_value == 0 {
            return Err(Nine65Error::ModulusZero);
        }

        let main_equations_verified = residues_consistent(
            divisor_value,
            request.basis.main_moduli,
            request.divisor.main_residues,
        );
        let anchor_equations_verified = residues_consistent(
            divisor_value,
            request.basis.anchor_moduli,
            request.divisor.anchor_residues,
        );
        if !main_equations_verified || !anchor_equations_verified {
            // The real, typed failure path G11 asked for: a divisor whose
            // claimed residues disagree with its claimed factorization never
            // produces a "best effort" quotient.
            return Err(Nine65Error::InvalidParameter {
                message: "divisor residues do not match the claimed factor product".to_string(),
            });
        }

        let quotient = numerator / divisor_value;
        let remainder = numerator % divisor_value;

        if quotient >= request.quotient_bound as u128 {
            return Err(Nine65Error::RangeOverflow {
                x: quotient,
                bound: request.quotient_bound as u128,
            });
        }

        let quotient_mod_output = (quotient % output_modulus as u128) as u64;

        let remainder_main: Vec<u64> = request
            .basis
            .main_moduli
            .iter()
            .map(|&m| (remainder % m as u128) as u64)
            .collect();
        let remainder_anchor: Vec<u64> = request
            .basis
            .anchor_moduli
            .iter()
            .map(|&m| (remainder % m as u128) as u64)
            .collect();

        let reconstructed = quotient
            .checked_mul(divisor_value)
            .and_then(|scaled| scaled.checked_add(remainder));
        let remainder_in_range = remainder < divisor_value && reconstructed == Some(numerator);

        let certificate = ResidueDivisionCertificate {
            quotient_bound: request.quotient_bound,
            main_equations_verified,
            anchor_equations_verified,
            remainder_in_range,
            quotient_unique_in_anchor_basis: (request.quotient_bound as u128) <= resolution,
        };

        let result = ResidueDivisionResult {
            quotient_mod_output,
            remainder_main,
            remainder_anchor,
            certificate,
        };

        // Belt-and-suspenders: re-run the trait's own contract check before
        // handing back a result claiming a complete certificate.
        validate_residue_division_result(request, output_modulus, &result)?;

        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arithmetic::residue_division::{
        ResidueBasisRef, ResidueDivisorRef, ResidueStateRef,
    };

    fn request<'a>(
        main_moduli: &'a [u64],
        anchor_moduli: &'a [u64],
        numerator_main: &'a [u64],
        numerator_anchor: &'a [u64],
        divisor_factors: &'a [u64],
        divisor_main: &'a [u64],
        divisor_anchor: &'a [u64],
        quotient_bound: u64,
    ) -> ResidueDivisionRequest<'a> {
        ResidueDivisionRequest {
            basis: ResidueBasisRef {
                main_moduli,
                anchor_moduli,
            },
            numerator: ResidueStateRef {
                main: numerator_main,
                anchor: numerator_anchor,
            },
            divisor: ResidueDivisorRef {
                factors: divisor_factors,
                main_residues: divisor_main,
                anchor_residues: divisor_anchor,
            },
            quotient_bound,
        }
    }

    fn residues(value: u128, moduli: &[u64]) -> Vec<u64> {
        moduli.iter().map(|&m| (value % m as u128) as u64).collect()
    }

    // ── Coupled-anchor law: direct formula checks ──────────────────────────

    #[test]
    fn resolution_collapses_to_anchor_product_when_coprime() {
        // 17*19 = 323 (main), 23*29 = 667 (anchor) — cross-coprime, so the
        // general formula must collapse to the plain anchor product, exactly
        // as every live call through this trait's validator guarantees.
        let resolution = coupled_anchor_resolution(323, &[23, 29]).unwrap();
        assert_eq!(resolution, 667);
    }

    #[test]
    fn coupled_anchor_resolution_matches_brute_force_reduced_case() {
        // main_product = 6, anchors {4, 9} -> lcm = 36, gcd(6, 36) = 6.
        // Formula: R = 36 / 6 = 6.
        let main_product: u128 = 6;
        let anchor_moduli = [4u64, 9u64];
        let resolution = coupled_anchor_resolution(main_product, &anchor_moduli).unwrap();
        assert_eq!(resolution, 6);

        // Brute-force cross-check: R is the size of the image of the
        // multiplication-by-main_product map on Z/lcm — a standard fact
        // (image size = lcm / gcd(main_product, lcm)) verified here by
        // direct enumeration rather than assumed.
        let lcm_val: u128 = 36;
        let mut seen = std::collections::BTreeSet::new();
        for k in 0..lcm_val {
            seen.insert((k * main_product) % lcm_val);
        }
        assert_eq!(seen.len() as u128, resolution);
    }

    #[test]
    fn resolutions_compose_by_lcm() {
        assert_eq!(compose_resolutions(6, 10).unwrap(), 30);
        assert_eq!(compose_resolutions(7, 7).unwrap(), 7);
        assert_eq!(compose_resolutions(0, 5).unwrap(), 0);
    }

    // ── Differential test vs direct integer division ───────────────────────

    /// Exhaustive differential test across the divider's full representable
    /// range for several divisors, INCLUDING divisors that share a factor
    /// with a main modulus and/or an anchor modulus — exactly the case plain
    /// per-lane K-Elimination division cannot handle (no modular inverse of
    /// the divisor exists against that lane).
    #[test]
    fn exhaustive_matches_direct_integer_division_including_non_coprime_divisors() {
        let main_moduli = [5u64, 7u64]; // M = 35 (both prime, CLASS-F)
        let anchor_moduli = [11u64, 13u64]; // A = 143 (CLASS-R)
        let capacity: u128 = 35 * 143; // 5005 — full reconstructible range
        let quotient_bound: u64 = 143; // == resolution (tightest legal bound)

        let divisor_cases: [&[u64]; 5] = [
            &[3],     // coprime to every basis modulus (baseline)
            &[5],     // shares a factor with main modulus 5
            &[11],    // shares a factor with anchor modulus 11
            &[5, 11], // shares factors with a main AND an anchor modulus
            &[7, 13], // shares factors with the OTHER main/anchor pair
        ];

        let divider = KElimResidueDivider::new();

        for factors in divisor_cases {
            let divisor_value: u128 = factors.iter().map(|&f| f as u128).product();
            let divisor_main = residues(divisor_value, &main_moduli);
            let divisor_anchor = residues(divisor_value, &anchor_moduli);

            // Plain per-lane K-Elimination-style division would need
            // `divisor_value^{-1} mod m_i` for every lane; demonstrate that
            // at least one lane has none whenever the divisor is
            // non-coprime with the basis, while this projector still
            // succeeds below.
            let mut any_lane_uninvertible = false;
            for &m in main_moduli.iter().chain(anchor_moduli.iter()) {
                if mod_inverse_u128(divisor_value % m as u128, m as u128).is_none() {
                    any_lane_uninvertible = true;
                }
            }
            if factors != [3u64].as_slice() {
                assert!(
                    any_lane_uninvertible,
                    "test setup: divisor {:?} was expected to be non-coprime with a lane",
                    factors
                );
            }

            for x in 0..capacity {
                let numerator_main = residues(x, &main_moduli);
                let numerator_anchor = residues(x, &anchor_moduli);
                let req = request(
                    &main_moduli,
                    &anchor_moduli,
                    &numerator_main,
                    &numerator_anchor,
                    factors,
                    &divisor_main,
                    &divisor_anchor,
                    quotient_bound,
                );

                let expected_quotient = x / divisor_value;
                let expected_remainder = x % divisor_value;

                let outcome = divider.project_bounded(req, 1_000_000);
                if expected_quotient >= quotient_bound as u128 {
                    assert!(
                        outcome.is_err(),
                        "expected fail-closed for x={x} d={divisor_value:?} q={expected_quotient} \
                         (>= bound {quotient_bound}), got {outcome:?}"
                    );
                    continue;
                }

                let result = outcome.unwrap_or_else(|e| {
                    panic!("x={x} divisor={factors:?} unexpectedly failed: {e:?}")
                });
                assert!(result.certificate.is_complete());
                assert_eq!(
                    result.quotient_mod_output as u128,
                    expected_quotient % 1_000_000,
                    "quotient mismatch for x={x} divisor={factors:?}"
                );
                for (i, &m) in main_moduli.iter().enumerate() {
                    assert_eq!(
                        result.remainder_main[i] as u128,
                        expected_remainder % m as u128,
                        "main remainder mismatch lane {i} x={x} divisor={factors:?}"
                    );
                }
                for (i, &m) in anchor_moduli.iter().enumerate() {
                    assert_eq!(
                        result.remainder_anchor[i] as u128,
                        expected_remainder % m as u128,
                        "anchor remainder mismatch lane {i} x={x} divisor={factors:?}"
                    );
                }
            }
        }
    }

    #[test]
    fn plain_per_lane_inverse_fails_where_this_divider_succeeds() {
        // Divisor 5 shares a factor with main modulus 5: the operation a
        // naive per-lane scheme (D3-style FPD without the bad-lane check,
        // or "plain K-Elimination" division-by-inverse) would need —
        // `5^{-1} mod 5` — provably does not exist.
        assert!(mod_inverse_u128(5 % 5, 5).is_none());

        // This projector still recovers the exact quotient by never
        // inverting the divisor against a basis modulus at all.
        let main_moduli = [5u64, 7u64];
        let anchor_moduli = [11u64, 13u64];
        let x: u128 = 5 * 37; // 185
        let divisor_value: u128 = 5;
        let numerator_main = residues(x, &main_moduli);
        let numerator_anchor = residues(x, &anchor_moduli);
        let divisor_main = residues(divisor_value, &main_moduli);
        let divisor_anchor = residues(divisor_value, &anchor_moduli);
        let req = request(
            &main_moduli,
            &anchor_moduli,
            &numerator_main,
            &numerator_anchor,
            &[5],
            &divisor_main,
            &divisor_anchor,
            143,
        );
        let result = KElimResidueDivider::new()
            .project_bounded(req, 1_000_000)
            .unwrap();
        assert_eq!(result.quotient_mod_output, 37);
    }

    #[test]
    fn rejects_divisor_whose_claimed_residues_disagree_with_its_factors() {
        let main_moduli = [17u64, 19u64];
        let anchor_moduli = [23u64, 29u64];
        let x: u128 = 100;
        // Claim divisor factor 5, but hand in residues for divisor 6 — a
        // real, typed failure path, not a silent pass-through.
        let numerator_main = residues(x, &main_moduli);
        let numerator_anchor = residues(x, &anchor_moduli);
        let divisor_main = residues(6, &main_moduli);
        let divisor_anchor = residues(6, &anchor_moduli);
        let req = request(
            &main_moduli,
            &anchor_moduli,
            &numerator_main,
            &numerator_anchor,
            &[5],
            &divisor_main,
            &divisor_anchor,
            31,
        );
        let outcome = KElimResidueDivider::new().project_bounded(req, 1_000);
        assert!(matches!(outcome, Err(Nine65Error::InvalidParameter { .. })));
    }

    #[test]
    fn rejects_quotient_bound_exceeding_coupled_anchor_resolution() {
        let main_moduli = [17u64, 19u64];
        let anchor_moduli = [23u64];
        // Anchor capacity is 23; ask for a bound of 1000 — must fail
        // closed, not silently truncate.
        let x: u128 = 5;
        let numerator_main = residues(x, &main_moduli);
        let numerator_anchor = residues(x, &anchor_moduli);
        let divisor_main = residues(1, &main_moduli);
        let divisor_anchor = residues(1, &anchor_moduli);
        let req = request(
            &main_moduli,
            &anchor_moduli,
            &numerator_main,
            &numerator_anchor,
            &[1_000_000_000], // impossible anchor capacity check happens first
            &divisor_main,
            &divisor_anchor,
            1000,
        );
        let outcome = KElimResidueDivider::new().project_bounded(req, 1_000);
        assert!(outcome.is_err());
    }

    #[test]
    fn hot_path_counters_increment_on_successful_projection() {
        let before = HOT_PATH_COUNTERS.snapshot();
        let main_moduli = [17u64, 19u64];
        let anchor_moduli = [23u64, 29u64];
        let x: u128 = 42;
        let numerator_main = residues(x, &main_moduli);
        let numerator_anchor = residues(x, &anchor_moduli);
        let divisor_main = residues(6, &main_moduli);
        let divisor_anchor = residues(6, &anchor_moduli);
        let req = request(
            &main_moduli,
            &anchor_moduli,
            &numerator_main,
            &numerator_anchor,
            &[6],
            &divisor_main,
            &divisor_anchor,
            31,
        );
        KElimResidueDivider::new()
            .project_bounded(req, 1_000)
            .unwrap();
        let after = HOT_PATH_COUNTERS.snapshot();
        assert!(after.0 > before.0, "internal_projections must increase");
        assert!(after.1 > before.1, "crt_reconstructions must increase");
    }
}
