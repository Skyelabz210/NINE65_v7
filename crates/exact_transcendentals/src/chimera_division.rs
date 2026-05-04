//! Four-Division Chimera — vocabulary scaffold (CRAM Division Substrate v1.0).
//!
//! This module formalizes the *types* used by the Four-Division Chimera so the
//! rest of the workspace can speak its grammar — division intents, lane enums,
//! certificate fields, status codes, and resolver structures. Computations
//! themselves (the four lanes D0/D1/D2/D3 and their resolvers) live in later
//! phases that depend on a concrete CRT substrate.
//!
//! The scaffold lets callers (notably SBNI's lane-count contract and any
//! upcoming CRAM-CT division routes) declare intent, attach certificates,
//! and refuse "naked" quotients without requiring the full implementation
//! to be in place.

use crate::Vec;

// ─── Division Intent ─────────────────────────────────────────────────────

/// Every division request carries an explicit intent. The resolver may not
/// emit a quotient without a certificate that satisfies the intent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DivisionIntent {
    /// Return q ≡ A·d⁻¹ (mod M_act). No integer quotient is claimed.
    ModularSolve,
    /// Return q = A/d, requiring d | A.
    ExactIntegerQuotient,
    /// Return q = trunc(A/d) with certified remainder.
    TruncatingQuotient,
    /// Return a quotient representative with a certified bound.
    CertifiedBounded,
}

// ─── Division Status ─────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DivStatus {
    ModularInverseExact,
    KElimExact,
    KElimTrunc,
    DivExact,
    FusedExact,
    FusedBounded,
    InvalidDivisor,
    MissingWitness,
    BoundInsufficient,
    LaneDisagreement,
    Invalid,
}

impl DivStatus {
    pub const fn is_exact_quotient(self) -> bool {
        matches!(
            self,
            Self::ModularInverseExact
                | Self::KElimExact
                | Self::KElimTrunc
                | Self::DivExact
                | Self::FusedExact
        )
    }

    pub const fn is_failure(self) -> bool {
        matches!(
            self,
            Self::InvalidDivisor
                | Self::MissingWitness
                | Self::BoundInsufficient
                | Self::LaneDisagreement
                | Self::Invalid
        )
    }
}

// ─── Certificate Authentication ──────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CertificateAuth {
    None,
    HashOnly { digest: [u8; 32] },
    HmacInternal { hmac: [u8; 32] },
    PublicKeySigned { sig: [u8; 64] },
}

impl CertificateAuth {
    pub fn is_publishable(&self) -> bool {
        matches!(self, Self::PublicKeySigned { .. })
    }

    pub fn is_production_acceptable(&self) -> bool {
        !matches!(self, Self::None)
    }
}

// ─── Chimera Lanes ───────────────────────────────────────────────────────

/// The four division lanes evaluated before resolution.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChimeraLane {
    /// D0: q_i ≡ a_i·d⁻¹ (mod m_i) — modular solve.
    ModularInverse,
    /// D1: K-Elimination winding lift.
    KElim,
    /// D2: absorbent quotient-basis division.
    DivExact,
    /// D3: Fused Piggyback Division (universal anchor fusion).
    FusedPiggyback,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct LaneMask {
    pub modular_inverse: bool,
    pub kelim: bool,
    pub div_exact: bool,
    pub fused_piggyback: bool,
}

impl LaneMask {
    pub fn count(&self) -> u32 {
        (self.modular_inverse as u32)
            + (self.kelim as u32)
            + (self.div_exact as u32)
            + (self.fused_piggyback as u32)
    }

    pub fn set(&mut self, lane: ChimeraLane, value: bool) {
        match lane {
            ChimeraLane::ModularInverse => self.modular_inverse = value,
            ChimeraLane::KElim => self.kelim = value,
            ChimeraLane::DivExact => self.div_exact = value,
            ChimeraLane::FusedPiggyback => self.fused_piggyback = value,
        }
    }

    pub fn get(&self, lane: ChimeraLane) -> bool {
        match lane {
            ChimeraLane::ModularInverse => self.modular_inverse,
            ChimeraLane::KElim => self.kelim,
            ChimeraLane::DivExact => self.div_exact,
            ChimeraLane::FusedPiggyback => self.fused_piggyback,
        }
    }
}

// ─── Division Certificate ────────────────────────────────────────────────

/// A single lane's certificate. `N` is an exact-natural type (typically
/// `u128` for small substrates, `CRTBigInt` for large ones).
#[derive(Debug, Clone)]
pub struct DivisionCertificate<N> {
    pub status: DivStatus,
    pub intent: DivisionIntent,

    pub target_modulus: N,
    pub quotient_modulus: N,
    pub quotient_bound: Option<N>,

    /// 0 iff the quotient is exact, else the certified ambiguity width.
    pub quotient_error_bound: N,
    /// gcd(P, M_act) for FPD — separate from quotient exactness.
    pub projection_ambiguity: N,

    pub exact_flag: bool,

    pub anchors: Vec<N>,
    pub fusion_product: N,
    pub anchor_factors: Vec<(N, N)>,

    pub remainder_bound_checked: bool,
    pub quotient_bound_checked: bool,

    pub absorbed_prime_support: Vec<N>,

    pub auth: CertificateAuth,
}

impl<N: Default + Clone> DivisionCertificate<N> {
    /// Skeleton certificate for an unattempted lane.
    pub fn pending(intent: DivisionIntent) -> Self {
        Self {
            status: DivStatus::Invalid,
            intent,
            target_modulus: N::default(),
            quotient_modulus: N::default(),
            quotient_bound: None,
            quotient_error_bound: N::default(),
            projection_ambiguity: N::default(),
            exact_flag: false,
            anchors: Vec::new(),
            fusion_product: N::default(),
            anchor_factors: Vec::new(),
            remainder_bound_checked: false,
            quotient_bound_checked: false,
            absorbed_prime_support: Vec::new(),
            auth: CertificateAuth::None,
        }
    }
}

/// Resolver certificate emitted by the chimera operator.
#[derive(Debug, Clone)]
pub struct ChimeraResolverCertificate<N> {
    pub intent: DivisionIntent,

    pub selected_lane: Option<ChimeraLane>,

    pub evaluated_lanes: LaneMask,
    pub valid_lanes: LaneMask,
    pub rejected_lanes: LaneMask,

    pub agreement_mask: LaneMask,
    pub disagreement_mask: LaneMask,

    pub strongest_quotient_error_bound: N,
    pub selected_quotient_error_bound: N,
    pub selected_projection_ambiguity: N,

    pub lane_certificate_hashes: Vec<[u8; 32]>,
    pub proof_hash: [u8; 32],

    pub auth: CertificateAuth,
}

// ─── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_statuses_classified_correctly() {
        for s in [
            DivStatus::ModularInverseExact,
            DivStatus::KElimExact,
            DivStatus::KElimTrunc,
            DivStatus::DivExact,
            DivStatus::FusedExact,
        ] {
            assert!(s.is_exact_quotient(), "{:?} should be exact", s);
            assert!(!s.is_failure());
        }
    }

    #[test]
    fn failure_statuses_classified_correctly() {
        for s in [
            DivStatus::InvalidDivisor,
            DivStatus::MissingWitness,
            DivStatus::BoundInsufficient,
            DivStatus::LaneDisagreement,
            DivStatus::Invalid,
        ] {
            assert!(s.is_failure(), "{:?} should be failure", s);
            assert!(!s.is_exact_quotient());
        }
    }

    #[test]
    fn fused_bounded_is_neither_exact_nor_failure() {
        // FusedBounded carries a certified ambiguity width — it is neither
        // a clean exact win nor an explicit failure. Callers that want
        // exactness must reject it; callers that accept bounded results
        // must read the quotient_error_bound field.
        let s = DivStatus::FusedBounded;
        assert!(!s.is_exact_quotient());
        assert!(!s.is_failure());
    }

    #[test]
    fn lane_mask_count_and_round_trip() {
        let mut m = LaneMask::default();
        assert_eq!(m.count(), 0);
        m.set(ChimeraLane::KElim, true);
        m.set(ChimeraLane::FusedPiggyback, true);
        assert_eq!(m.count(), 2);
        assert!(m.get(ChimeraLane::KElim));
        assert!(m.get(ChimeraLane::FusedPiggyback));
        assert!(!m.get(ChimeraLane::ModularInverse));
        assert!(!m.get(ChimeraLane::DivExact));
    }

    #[test]
    fn certificate_auth_policy() {
        assert!(!CertificateAuth::None.is_production_acceptable());
        assert!(CertificateAuth::HashOnly { digest: [0; 32] }.is_production_acceptable());
        assert!(CertificateAuth::HmacInternal { hmac: [0; 32] }.is_production_acceptable());
        assert!(CertificateAuth::PublicKeySigned { sig: [0; 64] }.is_publishable());
        assert!(!CertificateAuth::HashOnly { digest: [0; 32] }.is_publishable());
    }

    #[test]
    fn pending_certificate_is_invalid_until_resolved() {
        let c: DivisionCertificate<u128> =
            DivisionCertificate::pending(DivisionIntent::ExactIntegerQuotient);
        assert_eq!(c.status, DivStatus::Invalid);
        assert!(!c.exact_flag);
        assert!(c.status.is_failure());
        assert!(matches!(c.auth, CertificateAuth::None));
    }
}
