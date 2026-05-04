//! CRAM-CT Phase-0 Scaffold — Heterogeneous Polyunitary Phase-Locked Lane Fabric.
//!
//! This module implements the **data-structure layer** of the CRAM Ciphertext
//! specification (Heterogeneous Polyunitary Phase-Locked Ciphertext). It
//! defines the typed vocabulary needed by every later phase:
//!
//! 1. [`SafeBasis`] — S6 / S8 prime-basis profile.
//! 2. [`LaneFunction`] — the operational role each lane plays in a topology
//!    (integrity, modular inverse, K-Elim main / anchor, shadow / DIV_EXACT,
//!    FPD boundary, priority encoder, signature lane).
//! 3. [`RootOperator`] — the primitive operator the lane applies before its
//!    [`PostProcessor`] runs.
//! 4. [`LaneSpec`] / [`CramTopology`] — typed description of an entire eight-
//!    lane operator fabric, plus the canonical default `S8_CHIMERA_V1`.
//! 5. [`LockType`] / [`PhaseLock`] / [`PhaseLockGraph`] — cross-lane coherence
//!    constraints (anchor / agreement / shadow / boundary / multiplicative /
//!    signature) referenced from the spec.
//!
//! Phase 0 is intentionally **proof-free and data-only**: encryption, lane
//! projection of polynomial coefficients, lock verification, and bootstrap
//! all live in later phases that touch the `nine65` ciphertext path. This
//! module exists so the rest of the workspace can speak the spec's
//! vocabulary today, with the topology table validated by tests.

use crate::chimera::{family_for, LaneRole};
use crate::Vec;

// ─── Safe Basis ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SafeBasis {
    S6,
    S8,
}

impl SafeBasis {
    pub fn moduli(&self) -> &'static [u32] {
        match self {
            SafeBasis::S6 => &[2, 3, 5, 7, 11, 13],
            SafeBasis::S8 => &[2, 3, 5, 7, 11, 13, 17, 19],
        }
    }

    pub fn product(&self) -> u64 {
        self.moduli().iter().map(|&p| p as u64).product()
    }
}

// ─── Lane Function (operational role) ────────────────────────────────────

/// Operational role of a lane inside a CRAM topology — orthogonal to the
/// architectural [`LaneRole`] in `chimera`. The architectural role describes
/// what the prime *is*; the lane function describes what the prime *does* in
/// a specific eight-lane operator fabric.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LaneFunction {
    IntegrityWitness,
    ModularInverse,
    KElimMain,
    KElimAnchor,
    ShadowDivExact,
    FpdBoundary,
    PriorityEncoder,
    SignatureLane,
}

impl LaneFunction {
    pub const fn name(self) -> &'static str {
        match self {
            Self::IntegrityWitness => "integrity_witness",
            Self::ModularInverse => "modular_inverse",
            Self::KElimMain => "k_elim_main",
            Self::KElimAnchor => "k_elim_anchor",
            Self::ShadowDivExact => "shadow_div_exact",
            Self::FpdBoundary => "fpd_boundary",
            Self::PriorityEncoder => "priority_encoder",
            Self::SignatureLane => "signature_lane",
        }
    }
}

// ─── Root Operators and Post-Processors ──────────────────────────────────

/// Primitive operator a lane applies. Mirrors the spec's per-lane root.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RootOperator {
    AddParity,
    InvMul,
    KElimMain,
    KElimAnchor,
    DivExact,
    FpdDiv,
    Compare,
    HashSign,
}

/// Post-processor applied to a lane's primitive output before the lane
/// reports its observable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PostProcessor {
    CarryTrack,
    NormReduce,
    RoundTrunc,
    PhaseLock,
    ShadowUpdate,
    RemainderCheck,
    SelectValid,
    CertPackage,
}

/// What an outside observer sees from a lane after the post-processor runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LaneObservable {
    /// Plain residue mod p_i.
    Residue,
    /// Norm-reduced unit residue.
    NormReducedResidue,
    /// Quotient with rounding flag.
    Quotient,
    /// Shadow-disambiguator status.
    ShadowStatus,
    /// Boundary remainder check.
    BoundaryStatus,
    /// Selected-lane index.
    Selection,
    /// Certificate hash output.
    CertificateHash,
}

// ─── Lane Specification ──────────────────────────────────────────────────

#[derive(Debug, Clone, Copy)]
pub struct LaneSpec {
    pub modulus: u32,
    pub function: LaneFunction,
    pub root: RootOperator,
    pub post: PostProcessor,
    pub observable: LaneObservable,
}

// ─── Topology ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TopologyId(pub &'static str);

#[derive(Debug, Clone)]
pub struct CramTopology {
    pub id: TopologyId,
    pub basis: SafeBasis,
    pub lanes: &'static [LaneSpec],
}

impl CramTopology {
    /// Find the lane spec assigned to a given prime modulus.
    pub fn lane_for(&self, p: u32) -> Option<&LaneSpec> {
        self.lanes.iter().find(|l| l.modulus == p)
    }

    /// True iff every modulus in the basis has exactly one lane spec and the
    /// lane primes match the basis primes.
    pub fn is_well_formed(&self) -> bool {
        let basis = self.basis.moduli();
        if self.lanes.len() != basis.len() {
            return false;
        }
        let mut seen: Vec<u32> = Vec::with_capacity(basis.len());
        for lane in self.lanes {
            if !basis.contains(&lane.modulus) {
                return false;
            }
            if seen.contains(&lane.modulus) {
                return false;
            }
            seen.push(lane.modulus);
        }
        true
    }
}

/// Default S8 lane fabric — the Four-Division Chimera role map from the
/// CRAM-CT specification.
pub const S8_CHIMERA_V1_LANES: [LaneSpec; 8] = [
    LaneSpec {
        modulus: 2,
        function: LaneFunction::IntegrityWitness,
        root: RootOperator::AddParity,
        post: PostProcessor::CarryTrack,
        observable: LaneObservable::Residue,
    },
    LaneSpec {
        modulus: 3,
        function: LaneFunction::ModularInverse,
        root: RootOperator::InvMul,
        post: PostProcessor::NormReduce,
        observable: LaneObservable::NormReducedResidue,
    },
    LaneSpec {
        modulus: 5,
        function: LaneFunction::KElimMain,
        root: RootOperator::KElimMain,
        post: PostProcessor::RoundTrunc,
        observable: LaneObservable::Quotient,
    },
    LaneSpec {
        modulus: 7,
        function: LaneFunction::KElimAnchor,
        root: RootOperator::KElimAnchor,
        post: PostProcessor::PhaseLock,
        observable: LaneObservable::Quotient,
    },
    LaneSpec {
        modulus: 11,
        function: LaneFunction::ShadowDivExact,
        root: RootOperator::DivExact,
        post: PostProcessor::ShadowUpdate,
        observable: LaneObservable::ShadowStatus,
    },
    LaneSpec {
        modulus: 13,
        function: LaneFunction::FpdBoundary,
        root: RootOperator::FpdDiv,
        post: PostProcessor::RemainderCheck,
        observable: LaneObservable::BoundaryStatus,
    },
    LaneSpec {
        modulus: 17,
        function: LaneFunction::PriorityEncoder,
        root: RootOperator::Compare,
        post: PostProcessor::SelectValid,
        observable: LaneObservable::Selection,
    },
    LaneSpec {
        modulus: 19,
        function: LaneFunction::SignatureLane,
        root: RootOperator::HashSign,
        post: PostProcessor::CertPackage,
        observable: LaneObservable::CertificateHash,
    },
];

pub const S8_CHIMERA_V1: CramTopology = CramTopology {
    id: TopologyId("S8_CHIMERA_V1"),
    basis: SafeBasis::S8,
    lanes: &S8_CHIMERA_V1_LANES,
};

// ─── Phase-Lock Graph ────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockType {
    Anchor,
    Agreement,
    Shadow,
    Boundary,
    Multiplicative,
    Signature,
}

#[derive(Debug, Clone, Copy)]
pub struct PhaseLock {
    pub source: u32,
    pub target: u32,
    pub kind: LockType,
}

#[derive(Debug, Clone, Default)]
pub struct PhaseLockGraph {
    pub locks: Vec<PhaseLock>,
}

impl PhaseLockGraph {
    pub fn new() -> Self {
        Self { locks: Vec::new() }
    }

    pub fn add(&mut self, source: u32, target: u32, kind: LockType) {
        self.locks.push(PhaseLock {
            source,
            target,
            kind,
        });
    }

    pub fn len(&self) -> usize {
        self.locks.len()
    }

    pub fn is_empty(&self) -> bool {
        self.locks.is_empty()
    }

    /// True iff every lock's source and target prime appears in the topology.
    pub fn references_only(&self, topology: &CramTopology) -> bool {
        let basis = topology.basis.moduli();
        self.locks
            .iter()
            .all(|l| basis.contains(&l.source) && basis.contains(&l.target))
    }
}

/// Default phase-lock graph for [`S8_CHIMERA_V1`]: anchor 5↔7, agreement
/// 11↔17, shadow 2↔11, boundary 13↔17, signature 19→19.
pub fn default_phase_locks() -> PhaseLockGraph {
    let mut g = PhaseLockGraph::new();
    g.add(5, 7, LockType::Anchor);
    g.add(11, 17, LockType::Agreement);
    g.add(2, 11, LockType::Shadow);
    g.add(13, 17, LockType::Boundary);
    g.add(19, 19, LockType::Signature);
    g
}

// ─── Cross-Module Sanity ──────────────────────────────────────────────────

/// Map a [`LaneRole`] (architectural) to the [`LaneFunction`] (operational)
/// assigned by `S8_CHIMERA_V1`. The two role systems coexist: the
/// architectural role is a property of the prime; the lane function is a
/// property of the topology slot the prime occupies.
pub fn lane_function_in_default_topology(p: u32) -> Option<LaneFunction> {
    S8_CHIMERA_V1.lane_for(p).map(|s| s.function)
}

/// Look up the architectural role of the prime in lane slot `p`.
pub fn lane_role_in_default_topology(p: u32) -> Option<LaneRole> {
    family_for(p).map(|f| f.role)
}

// ─── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::triad::S8;

    #[test]
    fn safe_bases_have_expected_products() {
        assert_eq!(SafeBasis::S6.product(), 30_030);
        assert_eq!(SafeBasis::S8.product(), 9_699_690);
    }

    #[test]
    fn s8_chimera_v1_is_well_formed() {
        assert!(S8_CHIMERA_V1.is_well_formed());
    }

    #[test]
    fn s8_chimera_v1_covers_all_s8_primes() {
        for &p in &S8 {
            assert!(
                S8_CHIMERA_V1.lane_for(p).is_some(),
                "S8_CHIMERA_V1 missing lane for {p}"
            );
        }
    }

    #[test]
    fn s8_chimera_v1_assigns_each_function_exactly_once() {
        let funcs: Vec<LaneFunction> = S8_CHIMERA_V1.lanes.iter().map(|l| l.function).collect();
        for (i, a) in funcs.iter().enumerate() {
            for b in &funcs[i + 1..] {
                assert_ne!(a, b, "duplicate lane function {:?}", a);
            }
        }
    }

    #[test]
    fn lane_function_matches_spec_role_map() {
        // Spec § 4 lane role map.
        let expected: &[(u32, LaneFunction)] = &[
            (2, LaneFunction::IntegrityWitness),
            (3, LaneFunction::ModularInverse),
            (5, LaneFunction::KElimMain),
            (7, LaneFunction::KElimAnchor),
            (11, LaneFunction::ShadowDivExact),
            (13, LaneFunction::FpdBoundary),
            (17, LaneFunction::PriorityEncoder),
            (19, LaneFunction::SignatureLane),
        ];
        for &(p, f) in expected {
            assert_eq!(
                lane_function_in_default_topology(p),
                Some(f),
                "spec role mismatch on lane {p}"
            );
        }
    }

    #[test]
    fn default_phase_locks_reference_only_s8() {
        let g = default_phase_locks();
        assert!(g.references_only(&S8_CHIMERA_V1));
    }

    #[test]
    fn default_phase_locks_have_one_of_each_directional_kind() {
        let g = default_phase_locks();
        for kind in &[
            LockType::Anchor,
            LockType::Agreement,
            LockType::Shadow,
            LockType::Boundary,
            LockType::Signature,
        ] {
            assert!(
                g.locks.iter().any(|l| l.kind == *kind),
                "default phase locks missing {:?}",
                kind
            );
        }
    }

    #[test]
    fn architectural_and_operational_roles_coexist() {
        // Lane 11: architectural role = Shadow, operational function =
        // ShadowDivExact. The two systems agree but are not the same enum.
        assert_eq!(lane_role_in_default_topology(11), Some(LaneRole::Shadow));
        assert_eq!(
            lane_function_in_default_topology(11),
            Some(LaneFunction::ShadowDivExact)
        );
    }

    #[test]
    fn ill_formed_topology_is_rejected() {
        let bad = CramTopology {
            id: TopologyId("BAD"),
            basis: SafeBasis::S8,
            // Only one lane — does not cover S8.
            lanes: &S8_CHIMERA_V1_LANES[..1],
        };
        assert!(!bad.is_well_formed());
    }
}
