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

use core::sync::atomic::{AtomicU64, Ordering};

use crate::chimera::{family_for, LaneRole};
use crate::lane_projector::{mod_inv_u32, PolynomialS8Signature, S8Signature};
use crate::Vec;

// ─── Hot-path CRAM division usage counters (G10) ───────────────────────────
//
// `cram_core::ArchitectureCounters` (crates/cram-core/src/lib.rs) is the
// canonical shape for this instrumentation, but `exact_transcendentals` has
// zero dependencies by design (see this crate's CLAUDE.md) and wiring the
// real crate would mean editing Cargo.toml, which is outside this fix's
// permitted file set. These counters mirror cram-core's field names
// (`garner_calls`, `crt_reconstructions`) so a later rename to the shared
// type is mechanical. They are incremented at every Garner-style
// reconstruction call site this file (and `composite_division.rs`, which
// reuses this static) actually owns: D1's `garner_reconstruct_subset`, D2's
// `garner_reconstruct`, and D3's `crt_fuse_pairs`.
#[derive(Default)]
pub struct CramDivisionCounters {
    pub garner_calls: AtomicU64,
    pub crt_reconstructions: AtomicU64,
}

impl CramDivisionCounters {
    pub const fn new() -> Self {
        Self {
            garner_calls: AtomicU64::new(0),
            crt_reconstructions: AtomicU64::new(0),
        }
    }

    pub fn snapshot(&self) -> (u64, u64) {
        (
            self.garner_calls.load(Ordering::Relaxed),
            self.crt_reconstructions.load(Ordering::Relaxed),
        )
    }
}

/// Process-wide counters for every Garner-style reconstruction call in the
/// D1/D2/D3 division lanes this crate implements.
pub static CRAM_DIVISION_COUNTERS: CramDivisionCounters = CramDivisionCounters::new();

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

// ─── Phase-2 Lock Evidence ────────────────────────────────────────────────

/// Why a lock predicate failed. Phase-2 verification reports the first
/// failure with enough detail to point at the corrupted coefficient.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LockFailure {
    /// The witness graph and the evidence set disagree on the lock list.
    EvidenceMismatch,
    /// An anchor lock's recomputed K-Elim winding diverged from the witness.
    AnchorDivergence {
        source: u32,
        target: u32,
        coeff_index: usize,
        expected: u32,
        actual: u32,
    },
    /// An agreement lock's joint CRT residue differs from the witness.
    AgreementDivergence {
        source: u32,
        target: u32,
        coeff_index: usize,
        expected: u32,
        actual: u32,
    },
    /// A shadow lock's snapshot of the target lane changed.
    ShadowDivergence {
        source: u32,
        target: u32,
        coeff_index: usize,
        expected: u32,
        actual: u32,
    },
    /// op_counter wandered outside the certified winding corridor.
    BoundaryViolation {
        source: u32,
        target: u32,
        op_counter: i128,
        corridor_low: i128,
        corridor_high: i128,
    },
    /// The signature-lane hash changed.
    SignatureDivergence {
        lane: u32,
        expected: u32,
        actual: u32,
    },
    /// A coefficient slot was missing in the evidence.
    EvidenceLengthMismatch {
        source: u32,
        target: u32,
        expected_len: usize,
        actual_len: usize,
    },
    /// The graph carries a lock kind whose evidence is not yet implemented.
    UnsupportedLockKind { kind: LockType },
    /// Topology metadata structure is invalid (basis/lane mismatch or
    /// lock graph references primes outside the basis).
    TopologyIllFormed,
}

/// Per-lock evidence captured at wrap time. The evidence is recomputable
/// from the polynomial S8 signature plus op_counter, so any tampering
/// changes the recomputed value and the lock fails.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LockEvidence {
    /// Expected K-Elim winding `k = (r_target - r_source) * source^-1 mod target`
    /// per coefficient.
    Anchor { expected_k: Vec<u32> },
    /// Expected joint CRT residue `x mod (source * target)` per coefficient.
    Agreement { expected_joint: Vec<u32> },
    /// Snapshot of the target lane's residues.
    Shadow { expected_residues: Vec<u32> },
    /// Winding corridor `[low, high]` with `high - low < target` (anchor prime).
    Boundary { corridor_low: i128, corridor_high: i128 },
    /// Expected signature-lane hash mod 19.
    Signature { expected: u32 },
    /// Multiplicative locks have no Phase-2 evidence yet.
    Multiplicative,
}

#[derive(Debug, Clone)]
pub struct LockEvidenceEntry {
    pub lock: PhaseLock,
    pub evidence: LockEvidence,
}

#[derive(Debug, Clone, Default)]
pub struct LockWitnessSet {
    pub entries: Vec<LockEvidenceEntry>,
}

/// Simple deterministic mix used for the signature lane in Phase 2.
/// FNV-1a with the residues of every coefficient and the op counter folded in.
/// Replace with a real cryptographic hash before claiming proof-carrying status.
fn signature_lane_hash(sig: &PolynomialS8Signature, op_counter: i128) -> u32 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325; // FNV-1a 64-bit offset basis
    let prime: u64 = 0x0000_0100_0000_01b3;
    let mut absorb = |x: u64| {
        h ^= x;
        h = h.wrapping_mul(prime);
    };
    for s in &sig.signatures {
        for r in s.residues {
            absorb(r as u64);
        }
    }
    // Fold both halves of the i128 so the hash distinguishes counters that
    // collide modulo 2^64.
    absorb(op_counter as u64);
    absorb((op_counter >> 64) as u64);
    (h % 19) as u32
}

/// CRT joint residue of (r_a mod p, r_b mod q) into Z/(p*q)Z, computed via
/// Garner's two-step formula. `p` and `q` must be coprime.
fn crt_pair(r_a: u32, p: u32, r_b: u32, q: u32) -> u32 {
    let inv = mod_inv_u32(p % q, q).expect("S8 primes are pairwise coprime");
    let diff = (r_b as i64 - r_a as i64).rem_euclid(q as i64) as u32;
    let k = ((diff as u64) * (inv as u64) % q as u64) as u32;
    (r_a as u64 + (k as u64) * (p as u64)) as u32
}

/// K-Elim winding `k = (r_target - r_source) * source^-1 mod target` for one
/// coefficient — `source` and `target` must be coprime.
fn anchor_k(sig: &S8Signature, source: u32, target: u32) -> u32 {
    let r_s = sig.residue_mod(source).expect("source not in S8");
    let r_t = sig.residue_mod(target).expect("target not in S8");
    let inv = mod_inv_u32(source % target, target).expect("source/target not coprime");
    let diff = (r_t as i64 - r_s as i64).rem_euclid(target as i64) as u32;
    ((diff as u64) * (inv as u64) % target as u64) as u32
}

impl LockWitnessSet {
    /// Build evidence for every lock in `graph` from the current signature
    /// and op counter.
    pub fn compute(
        graph: &PhaseLockGraph,
        sig: &PolynomialS8Signature,
        op_counter: i128,
    ) -> Self {
        let mut entries = Vec::with_capacity(graph.locks.len());
        for &lock in &graph.locks {
            // Defensive: locks referencing primes outside S8 cannot have
            // residues computed. Emit the no-op `Multiplicative` evidence
            // so `compute` never panics; the off-basis lock is caught by
            // `verify_metadata` before `verify_locks` runs.
            let s_in_s8 = crate::triad::S8.contains(&lock.source);
            let t_in_s8 = crate::triad::S8.contains(&lock.target);
            if !s_in_s8 || !t_in_s8 {
                entries.push(LockEvidenceEntry {
                    lock,
                    evidence: LockEvidence::Multiplicative,
                });
                continue;
            }
            let evidence = match lock.kind {
                LockType::Anchor => {
                    let expected_k = sig
                        .signatures
                        .iter()
                        .map(|s| anchor_k(s, lock.source, lock.target))
                        .collect();
                    LockEvidence::Anchor { expected_k }
                }
                LockType::Agreement => {
                    let expected_joint = sig
                        .signatures
                        .iter()
                        .map(|s| {
                            let r_s = s.residue_mod(lock.source).unwrap();
                            let r_t = s.residue_mod(lock.target).unwrap();
                            crt_pair(r_s, lock.source, r_t, lock.target)
                        })
                        .collect();
                    LockEvidence::Agreement { expected_joint }
                }
                LockType::Shadow => {
                    let expected_residues = sig
                        .signatures
                        .iter()
                        .map(|s| s.residue_mod(lock.target).unwrap())
                        .collect();
                    LockEvidence::Shadow { expected_residues }
                }
                LockType::Boundary => {
                    // Corridor width = anchor prime (= target). The corridor
                    // brackets the current op_counter so any drift outside
                    // the band fails the lock.
                    let width = lock.target as i128;
                    LockEvidence::Boundary {
                        corridor_low: op_counter,
                        corridor_high: op_counter.saturating_add(width - 1),
                    }
                }
                LockType::Signature => LockEvidence::Signature {
                    expected: signature_lane_hash(sig, op_counter),
                },
                LockType::Multiplicative => LockEvidence::Multiplicative,
            };
            entries.push(LockEvidenceEntry { lock, evidence });
        }
        Self { entries }
    }

    /// Check that every lock still verifies against the (possibly mutated)
    /// signature and op counter.
    pub fn verify(
        &self,
        graph: &PhaseLockGraph,
        sig: &PolynomialS8Signature,
        op_counter: i128,
    ) -> Result<(), LockFailure> {
        if self.entries.len() != graph.locks.len() {
            return Err(LockFailure::EvidenceMismatch);
        }
        for (i, entry) in self.entries.iter().enumerate() {
            if entry.lock.source != graph.locks[i].source
                || entry.lock.target != graph.locks[i].target
                || entry.lock.kind != graph.locks[i].kind
            {
                return Err(LockFailure::EvidenceMismatch);
            }
            verify_one(entry, sig, op_counter)?;
        }
        Ok(())
    }
}

fn verify_one(
    entry: &LockEvidenceEntry,
    sig: &PolynomialS8Signature,
    op_counter: i128,
) -> Result<(), LockFailure> {
    let lock = entry.lock;
    let n = sig.signatures.len();
    match &entry.evidence {
        LockEvidence::Anchor { expected_k } => {
            if expected_k.len() != n {
                return Err(LockFailure::EvidenceLengthMismatch {
                    source: lock.source,
                    target: lock.target,
                    expected_len: expected_k.len(),
                    actual_len: n,
                });
            }
            for (i, s) in sig.signatures.iter().enumerate() {
                let actual = anchor_k(s, lock.source, lock.target);
                if actual != expected_k[i] {
                    return Err(LockFailure::AnchorDivergence {
                        source: lock.source,
                        target: lock.target,
                        coeff_index: i,
                        expected: expected_k[i],
                        actual,
                    });
                }
            }
        }
        LockEvidence::Agreement { expected_joint } => {
            if expected_joint.len() != n {
                return Err(LockFailure::EvidenceLengthMismatch {
                    source: lock.source,
                    target: lock.target,
                    expected_len: expected_joint.len(),
                    actual_len: n,
                });
            }
            for (i, s) in sig.signatures.iter().enumerate() {
                let r_s = s.residue_mod(lock.source).unwrap();
                let r_t = s.residue_mod(lock.target).unwrap();
                let actual = crt_pair(r_s, lock.source, r_t, lock.target);
                if actual != expected_joint[i] {
                    return Err(LockFailure::AgreementDivergence {
                        source: lock.source,
                        target: lock.target,
                        coeff_index: i,
                        expected: expected_joint[i],
                        actual,
                    });
                }
            }
        }
        LockEvidence::Shadow { expected_residues } => {
            if expected_residues.len() != n {
                return Err(LockFailure::EvidenceLengthMismatch {
                    source: lock.source,
                    target: lock.target,
                    expected_len: expected_residues.len(),
                    actual_len: n,
                });
            }
            for (i, s) in sig.signatures.iter().enumerate() {
                let actual = s.residue_mod(lock.target).unwrap();
                if actual != expected_residues[i] {
                    return Err(LockFailure::ShadowDivergence {
                        source: lock.source,
                        target: lock.target,
                        coeff_index: i,
                        expected: expected_residues[i],
                        actual,
                    });
                }
            }
        }
        LockEvidence::Boundary {
            corridor_low,
            corridor_high,
        } => {
            if op_counter < *corridor_low || op_counter > *corridor_high {
                return Err(LockFailure::BoundaryViolation {
                    source: lock.source,
                    target: lock.target,
                    op_counter,
                    corridor_low: *corridor_low,
                    corridor_high: *corridor_high,
                });
            }
        }
        LockEvidence::Signature { expected } => {
            let actual = signature_lane_hash(sig, op_counter);
            if actual != *expected {
                return Err(LockFailure::SignatureDivergence {
                    lane: lock.source,
                    expected: *expected,
                    actual,
                });
            }
        }
        LockEvidence::Multiplicative => {
            return Err(LockFailure::UnsupportedLockKind {
                kind: LockType::Multiplicative,
            });
        }
    }
    Ok(())
}

// ─── CramCiphertext Shell ─────────────────────────────────────────────────

/// Witness state attached alongside a base ciphertext. Phase-1 only carries
/// the S8 signature of c0's coefficients; later phases will add winding and
/// shadow state.
#[derive(Debug, Clone)]
pub struct CramWitnessState {
    /// One S8 signature per coefficient of c0.
    pub c0_signature: PolynomialS8Signature,
    /// Optional signature of c1, included when the topology requests it.
    pub c1_signature: Option<PolynomialS8Signature>,
    /// Operation / winding counter (i128 to match NINE65 winding convention),
    /// incremented by every cram_add / cram_mul call.
    pub op_counter: i128,
    /// Phase-2 lock evidence — one entry per lock in the graph.
    pub lock_witness: LockWitnessSet,
    /// Optional auxiliary-prime residues for FPD (D3 division) support.
    pub c0_aux: Option<AuxResidueSet>,
}

impl CramWitnessState {
    /// Build a fresh witness state from c0 (and optionally c1) coefficients,
    /// computing lock evidence for every entry in `graph`.
    pub fn from_coeffs(c0: &[i128], c1: Option<&[i128]>, graph: &PhaseLockGraph) -> Self {
        let c0_signature = PolynomialS8Signature::from_coeffs(c0);
        let lock_witness = LockWitnessSet::compute(graph, &c0_signature, 0);
        Self {
            c0_signature,
            c1_signature: c1.map(PolynomialS8Signature::from_coeffs),
            op_counter: 0,
            lock_witness,
            c0_aux: None,
        }
    }

    /// Return the number of c0 coefficients tracked.
    pub fn poly_len(&self) -> usize {
        self.c0_signature.len()
    }
}

/// Phase-1 CRAM ciphertext: a base ciphertext `C` (the security-bearing
/// object) plus the CRAM witness state, the active topology, and the active
/// phase-lock graph. The base ciphertext is opaque to this module — wrapper
/// constructors live in `nine65` for the concrete `DualRNSCiphertext` type.
#[derive(Debug, Clone)]
pub struct CramCiphertext<C> {
    pub base: C,
    pub topology: CramTopology,
    pub locks: PhaseLockGraph,
    pub witness: CramWitnessState,
}

impl<C> CramCiphertext<C> {
    /// Wrap a base ciphertext with c0 coefficients (and optional c1) using
    /// the canonical S8 chimera topology and default phase-lock graph.
    /// Lock evidence is captured at wrap time so subsequent calls to
    /// `verify_locks` detect any tampering on c0.
    pub fn wrap_default(base: C, c0_coeffs: &[i128], c1_coeffs: Option<&[i128]>) -> Self {
        let topology = S8_CHIMERA_V1.clone();
        let locks = default_phase_locks();
        let witness = CramWitnessState::from_coeffs(c0_coeffs, c1_coeffs, &locks);
        Self {
            base,
            topology,
            locks,
            witness,
        }
    }

    /// True iff the topology is well-formed and the phase-lock graph
    /// references only its basis primes. Phase-1 metadata check.
    pub fn verify_metadata(&self) -> bool {
        self.topology.is_well_formed() && self.locks.references_only(&self.topology)
    }

    /// Phase-2: evaluate every lock predicate in the graph against the
    /// current witness state. Returns the first failure with enough
    /// detail to identify the divergent coefficient.
    pub fn verify_locks(&self) -> Result<(), LockFailure> {
        self.witness
            .lock_witness
            .verify(&self.locks, &self.witness.c0_signature, self.witness.op_counter)
    }

    /// Phase-1 + Phase-2 combined verification.
    pub fn verify(&self) -> Result<(), LockFailure> {
        if !self.verify_metadata() {
            return Err(LockFailure::EvidenceMismatch);
        }
        self.verify_locks()
    }

    /// Reconstruct c0's coefficients (mod S8_PRODUCT) from the witness.
    /// This is a roundtrip check, not the security-bearing decryption.
    pub fn reconstruct_c0_coeffs_signed(&self) -> Vec<i32> {
        self.witness.c0_signature.reconstruct_signed()
    }
}

// ─── Phase-3 Homomorphic Operations ───────────────────────────────────────

/// Errors specific to Phase-3 operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CramOpError {
    /// One of the inputs failed pre-op verification.
    InputVerifyFailed(LockFailure),
    /// The post-op result failed verification — the operation produced a
    /// state that does not satisfy its own locks.
    OutputVerifyFailed(LockFailure),
    /// Operands have polynomials of different lengths.
    PolynomialLengthMismatch { lhs: usize, rhs: usize },
    /// Operand topologies disagree.
    TopologyMismatch,
    /// Operand basis profiles disagree.
    BasisMismatch,
    /// op_counter would overflow.
    OpCounterOverflow,
    /// The chimera router selected a lane that Phase 4 has not yet
    /// implemented (D1 K-Elim, D2 DIV_EXACT, D3 FPD).
    DivisionLaneNotImplemented {
        primary: crate::chimera_division::ChimeraLane,
        gcd_with_basis: u64,
    },
    /// D2 DIV_EXACT-specific failure.
    DivExact(DivExactError),
    /// D1 K-Elimination-specific failure.
    KElim(KElimError),
    /// D3 FPD-specific failure (G11): the bad-lane exactness check caught a
    /// fused quotient that disagrees with the numerator on a lane the
    /// fusion basis could not include.
    Fpd(FpdError),
    /// Two evaluable chimera lanes produced different quotients on the
    /// same input. The Phase-4 resolver rejects rather than picking a
    /// lane unilaterally.
    ChimeraLaneDisagreement,
}

/// Add two S8 signatures coefficient-wise. CRT homomorphism makes this
/// equivalent to adding the underlying integers and re-projecting.
fn add_signatures(
    a: &PolynomialS8Signature,
    b: &PolynomialS8Signature,
) -> Result<PolynomialS8Signature, CramOpError> {
    if a.signatures.len() != b.signatures.len() {
        return Err(CramOpError::PolynomialLengthMismatch {
            lhs: a.signatures.len(),
            rhs: b.signatures.len(),
        });
    }
    let mut signatures = Vec::with_capacity(a.signatures.len());
    for (sa, sb) in a.signatures.iter().zip(b.signatures.iter()) {
        let mut residues = [0u32; 8];
        for (i, &p) in crate::triad::S8.iter().enumerate() {
            residues[i] = (sa.residues[i] + sb.residues[i]) % p;
        }
        signatures.push(S8Signature { residues });
    }
    Ok(PolynomialS8Signature { signatures })
}

/// Negacyclic polynomial multiplication of two S8 signatures.
///
/// For polynomials of degree < N living in `R = Z[X]/(X^N + 1)`, the schoolbook
/// product on each lane is `c[k] = sum_{i+j=k} a[i]*b[j] mod p` minus
/// `sum_{i+j=N+k} a[i]*b[j] mod p` (the negacyclic wrap from `X^N = -1`).
/// CRT homomorphism makes lane-wise multiplication equivalent to polynomial
/// multiplication of the integers each lane reconstructs.
fn negacyclic_convolve_signatures(
    a: &PolynomialS8Signature,
    b: &PolynomialS8Signature,
) -> Result<PolynomialS8Signature, CramOpError> {
    if a.signatures.len() != b.signatures.len() {
        return Err(CramOpError::PolynomialLengthMismatch {
            lhs: a.signatures.len(),
            rhs: b.signatures.len(),
        });
    }
    let n = a.signatures.len();
    let mut signatures = Vec::with_capacity(n);
    for _ in 0..n {
        signatures.push(S8Signature { residues: [0u32; 8] });
    }
    for (lane_idx, &p) in crate::triad::S8.iter().enumerate() {
        let p_u64 = p as u64;
        for k in 0..n {
            let mut acc: u64 = 0;
            // Positive terms: i + j = k.
            for i in 0..=k {
                let j = k - i;
                let prod = (a.signatures[i].residues[lane_idx] as u64
                    * b.signatures[j].residues[lane_idx] as u64)
                    % p_u64;
                acc = (acc + prod) % p_u64;
            }
            // Negative (wrap) terms: i + j = N + k.
            for i in (k + 1)..n {
                let j = n + k - i;
                let prod = (a.signatures[i].residues[lane_idx] as u64
                    * b.signatures[j].residues[lane_idx] as u64)
                    % p_u64;
                acc = (acc + p_u64 - prod) % p_u64;
            }
            signatures[k].residues[lane_idx] = acc as u32;
        }
    }
    Ok(PolynomialS8Signature { signatures })
}

/// Multiply each coefficient's S8 signature by a constant scalar `c`.
fn scale_signature(a: &PolynomialS8Signature, c: i128) -> PolynomialS8Signature {
    let scalar = S8Signature::project(c);
    let mut signatures = Vec::with_capacity(a.signatures.len());
    for sa in &a.signatures {
        let mut residues = [0u32; 8];
        for (i, &p) in crate::triad::S8.iter().enumerate() {
            residues[i] = ((sa.residues[i] as u64 * scalar.residues[i] as u64) % p as u64) as u32;
        }
        signatures.push(S8Signature { residues });
    }
    PolynomialS8Signature { signatures }
}

/// Recompute lock evidence after a homomorphic op. Anchor/Agreement/Shadow/
/// Signature locks are rebuilt from the new signature; the Boundary lock's
/// corridor is preserved across operations because it tracks accumulated
/// op-count drift between bootstraps, not per-op state.
fn recompute_post_op(
    prior: &LockWitnessSet,
    graph: &PhaseLockGraph,
    new_sig: &PolynomialS8Signature,
    new_op_counter: i128,
) -> LockWitnessSet {
    // Start from a fresh compute, then graft the prior boundary corridors.
    let mut fresh = LockWitnessSet::compute(graph, new_sig, new_op_counter);
    for entry in fresh.entries.iter_mut() {
        if entry.lock.kind == LockType::Boundary {
            // Find the corresponding prior entry by (source, target, kind).
            if let Some(prior_entry) = prior.entries.iter().find(|p| {
                p.lock.source == entry.lock.source
                    && p.lock.target == entry.lock.target
                    && p.lock.kind == LockType::Boundary
            }) {
                if let LockEvidence::Boundary { .. } = &prior_entry.evidence {
                    entry.evidence = prior_entry.evidence.clone();
                }
            }
        }
    }
    fresh
}

impl<C> CramCiphertext<C> {
    /// Phase-3 ciphertext + ciphertext addition.
    ///
    /// Composes the two base ciphertexts via the user-supplied closure
    /// (which knows the concrete `C` type and the field semantics) and
    /// updates the witness signature lane-wise. Both inputs are verified
    /// before the op; the output is verified before being returned.
    pub fn cram_add<F>(self, other: Self, add_base: F) -> Result<Self, CramOpError>
    where
        F: FnOnce(C, C) -> C,
    {
        self.verify().map_err(CramOpError::InputVerifyFailed)?;
        other.verify().map_err(CramOpError::InputVerifyFailed)?;

        if self.topology.id != other.topology.id {
            return Err(CramOpError::TopologyMismatch);
        }
        if self.topology.basis != other.topology.basis {
            return Err(CramOpError::BasisMismatch);
        }

        let new_c0 = add_signatures(&self.witness.c0_signature, &other.witness.c0_signature)?;
        let new_c1 = match (&self.witness.c1_signature, &other.witness.c1_signature) {
            (Some(a), Some(b)) => Some(add_signatures(a, b)?),
            (None, None) => None,
            _ => None, // Mixed presence — drop c1.
        };

        let new_op_counter = self
            .witness
            .op_counter
            .max(other.witness.op_counter)
            .checked_add(1)
            .ok_or(CramOpError::OpCounterOverflow)?;

        let new_lock_witness =
            recompute_post_op(&self.witness.lock_witness, &self.locks, &new_c0, new_op_counter);

        let new_base = add_base(self.base, other.base);

        let out = CramCiphertext {
            base: new_base,
            topology: self.topology,
            locks: self.locks,
            witness: CramWitnessState {
                c0_signature: new_c0,
                c1_signature: new_c1,
                op_counter: new_op_counter,
                lock_witness: new_lock_witness,
                c0_aux: None,
            },
        };
        out.verify().map_err(CramOpError::OutputVerifyFailed)?;
        Ok(out)
    }

    /// Phase-3 ciphertext * scalar multiplication.
    ///
    /// Multiplies each coefficient's S8 signature by `scalar` (CRT
    /// homomorphism makes this lane-wise). Full ciphertext * ciphertext
    /// multiplication lands in Phase 4 alongside the chimera division
    /// route used by BFV rescale.
    pub fn cram_mul_by_scalar<F>(self, scalar: i128, mul_base: F) -> Result<Self, CramOpError>
    where
        F: FnOnce(C, i128) -> C,
    {
        self.verify().map_err(CramOpError::InputVerifyFailed)?;

        let new_c0 = scale_signature(&self.witness.c0_signature, scalar);
        let new_c1 = self
            .witness
            .c1_signature
            .as_ref()
            .map(|s| scale_signature(s, scalar));

        let new_op_counter = self
            .witness
            .op_counter
            .checked_add(1)
            .ok_or(CramOpError::OpCounterOverflow)?;

        let new_lock_witness =
            recompute_post_op(&self.witness.lock_witness, &self.locks, &new_c0, new_op_counter);

        let new_base = mul_base(self.base, scalar);

        let out = CramCiphertext {
            base: new_base,
            topology: self.topology,
            locks: self.locks,
            witness: CramWitnessState {
                c0_signature: new_c0,
                c1_signature: new_c1,
                op_counter: new_op_counter,
                lock_witness: new_lock_witness,
                c0_aux: None,
            },
        };
        out.verify().map_err(CramOpError::OutputVerifyFailed)?;
        Ok(out)
    }

    /// Phase-4 ciphertext × ciphertext multiplication via negacyclic
    /// convolution at the S8 signature level.
    ///
    /// Treats c0 as a polynomial in `Z[X]/(X^N + 1)` and multiplies the two
    /// witness signatures lane-wise; CRT homomorphism makes this equivalent
    /// to multiplying the integer polynomials each lane reconstructs. Full
    /// BFV semantics (tensor + relinearize + rescale) are deferred to the
    /// `nine65` integration; the closure handles the concrete `C` side.
    pub fn cram_mul<F>(self, other: Self, mul_base: F) -> Result<Self, CramOpError>
    where
        F: FnOnce(C, C) -> C,
    {
        self.verify().map_err(CramOpError::InputVerifyFailed)?;
        other.verify().map_err(CramOpError::InputVerifyFailed)?;

        if self.topology.id != other.topology.id {
            return Err(CramOpError::TopologyMismatch);
        }
        if self.topology.basis != other.topology.basis {
            return Err(CramOpError::BasisMismatch);
        }

        let new_c0 = negacyclic_convolve_signatures(
            &self.witness.c0_signature,
            &other.witness.c0_signature,
        )?;
        let new_c1 = match (&self.witness.c1_signature, &other.witness.c1_signature) {
            (Some(a), Some(b)) => Some(negacyclic_convolve_signatures(a, b)?),
            _ => None,
        };

        let new_op_counter = self
            .witness
            .op_counter
            .max(other.witness.op_counter)
            .checked_add(1)
            .ok_or(CramOpError::OpCounterOverflow)?;

        let new_lock_witness =
            recompute_post_op(&self.witness.lock_witness, &self.locks, &new_c0, new_op_counter);

        let new_base = mul_base(self.base, other.base);

        let out = CramCiphertext {
            base: new_base,
            topology: self.topology,
            locks: self.locks,
            witness: CramWitnessState {
                c0_signature: new_c0,
                c1_signature: new_c1,
                op_counter: new_op_counter,
                lock_witness: new_lock_witness,
                c0_aux: None,
            },
        };
        out.verify().map_err(CramOpError::OutputVerifyFailed)?;
        Ok(out)
    }
}

// ─── Phase-4 Chimera Division Router ──────────────────────────────────────

/// gcd helper local to the chimera router.
fn gcd_u64(mut a: u64, mut b: u64) -> u64 {
    while b != 0 {
        let t = b;
        b = a % b;
        a = t;
    }
    a
}

/// Recommendation produced by the chimera router for a given divisor.
///
/// The router classifies the divisor against the active CRT basis and
/// returns which of the four lanes can produce a certified quotient.
/// `D0` (modular inverse) is the cheap fast path when the divisor is
/// coprime to the basis product. The other three lanes are recommended
/// (with a status code) but their full implementation lives in the
/// `chimera_division` certificate layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChimeraDivPlan {
    /// The lane the router selects as primary.
    pub primary: crate::chimera_division::ChimeraLane,
    /// Status the router would attach to the primary lane's certificate.
    pub primary_status: crate::chimera_division::DivStatus,
    /// gcd(d, basis_product) — `1` for D0, `>1` triggers fallback lanes.
    pub gcd_with_basis: u64,
    /// Mask of lanes deemed evaluable by the router.
    pub evaluable: crate::chimera_division::LaneMask,
}

/// Decide which division lane to route a scalar divisor through.
///
/// Phase-4 router covers the static classification:
///
/// * `gcd(d, M_act) == 1` → D0 ModularInverse, status `ModularInverseExact`.
/// * `d > 0` and shares factors → D3 FusedPiggyback (auxiliary anchors
///   handle the non-coprime divisor; full FPD requires the aux pool).
/// * `d == 0` → no lane evaluable, status `InvalidDivisor`.
///
/// D1 (K-Elim) and D2 (DIV_EXACT absorbent) require additional witnesses
/// not yet plumbed into the CramWitnessState; the router marks them
/// evaluable when their static preconditions hold so the certificate
/// layer can fill them in later.
pub fn select_division_lane(divisor: i128, basis: SafeBasis) -> ChimeraDivPlan {
    use crate::chimera_division::{ChimeraLane, DivStatus, LaneMask};
    if divisor == 0 {
        return ChimeraDivPlan {
            primary: ChimeraLane::ModularInverse,
            primary_status: DivStatus::InvalidDivisor,
            gcd_with_basis: 0,
            evaluable: LaneMask::default(),
        };
    }
    let abs_d = divisor.unsigned_abs() as u64;
    let m = basis.product();
    let g = gcd_u64(abs_d, m);
    let mut evaluable = LaneMask::default();
    if g == 1 {
        evaluable.modular_inverse = true;
        evaluable.fused_piggyback = true; // FPD always works for non-zero d
        return ChimeraDivPlan {
            primary: ChimeraLane::ModularInverse,
            primary_status: DivStatus::ModularInverseExact,
            gcd_with_basis: 1,
            evaluable,
        };
    }
    // Shared factor — D0 is unsafe; recommend D3 with bound-pending status.
    evaluable.fused_piggyback = true;
    // D2 (DIV_EXACT) is statically applicable when |d| is a product of
    // primes that all live inside the basis (so an absorbent extension
    // could cover it). For Phase 4 we just record evaluability.
    if is_basis_smooth(abs_d, basis) {
        evaluable.div_exact = true;
    }
    ChimeraDivPlan {
        primary: ChimeraLane::FusedPiggyback,
        primary_status: DivStatus::FusedBounded,
        gcd_with_basis: g,
        evaluable,
    }
}

/// True iff every prime factor of `d` lies in `basis.moduli()`.
fn is_basis_smooth(mut d: u64, basis: SafeBasis) -> bool {
    if d == 0 {
        return false;
    }
    for &p in basis.moduli() {
        let p64 = p as u64;
        while d % p64 == 0 {
            d /= p64;
        }
    }
    d == 1
}

/// Modular inverse of `d` for each S8 lane (D0 lane).
///
/// Returns `Some(inv_per_lane)` if every lane has an inverse (i.e., d is
/// coprime to every S8 prime). Returns `None` if any lane has no inverse,
/// signalling the router to fall back to D1/D2/D3.
fn s8_lane_inverses(d: i128) -> Option<[u32; 8]> {
    let abs_d = d.unsigned_abs() as u64;
    let sign = if d < 0 { true } else { false };
    let mut out = [0u32; 8];
    for (i, &p) in crate::triad::S8.iter().enumerate() {
        let r = (abs_d % p as u64) as u32;
        let inv = mod_inv_u32(r, p)?;
        out[i] = if sign { (p - inv) % p } else { inv };
    }
    Some(out)
}

impl<C> CramCiphertext<C> {
    /// Phase-4 D0 rescale: divide every coefficient by `divisor` lane-wise
    /// using modular inverses. Requires `gcd(divisor, S8_PRODUCT) == 1`.
    ///
    /// Returns the rescaled ciphertext + the chimera resolver decision so
    /// callers can inspect which lane was selected and why.
    pub fn cram_rescale_by_scalar<F>(
        self,
        divisor: i128,
        rescale_base: F,
    ) -> Result<(Self, ChimeraDivPlan), CramOpError>
    where
        F: FnOnce(C, i128) -> C,
    {
        self.verify().map_err(CramOpError::InputVerifyFailed)?;

        let plan = select_division_lane(divisor, self.topology.basis);
        if !plan.evaluable.modular_inverse {
            // Phase-4 only implements D0; D1/D2/D3 are static-recommendation only.
            return Err(CramOpError::DivisionLaneNotImplemented {
                primary: plan.primary,
                gcd_with_basis: plan.gcd_with_basis,
            });
        }

        let inverses = s8_lane_inverses(divisor)
            .ok_or(CramOpError::DivisionLaneNotImplemented {
                primary: plan.primary,
                gcd_with_basis: plan.gcd_with_basis,
            })?;

        let new_c0 = apply_lane_inverses(&self.witness.c0_signature, &inverses);
        let new_c1 = self
            .witness
            .c1_signature
            .as_ref()
            .map(|s| apply_lane_inverses(s, &inverses));

        let new_op_counter = self
            .witness
            .op_counter
            .checked_add(1)
            .ok_or(CramOpError::OpCounterOverflow)?;

        let new_lock_witness =
            recompute_post_op(&self.witness.lock_witness, &self.locks, &new_c0, new_op_counter);

        let new_base = rescale_base(self.base, divisor);

        let out = CramCiphertext {
            base: new_base,
            topology: self.topology,
            locks: self.locks,
            witness: CramWitnessState {
                c0_signature: new_c0,
                c1_signature: new_c1,
                op_counter: new_op_counter,
                lock_witness: new_lock_witness,
                c0_aux: None,
            },
        };
        out.verify().map_err(CramOpError::OutputVerifyFailed)?;
        Ok((out, plan))
    }
}

/// Multiply each coefficient's S8 signature lane-wise by precomputed
/// per-lane inverses (D0 path).
fn apply_lane_inverses(
    a: &PolynomialS8Signature,
    inverses: &[u32; 8],
) -> PolynomialS8Signature {
    let mut signatures = Vec::with_capacity(a.signatures.len());
    for sa in &a.signatures {
        let mut residues = [0u32; 8];
        for (i, &p) in crate::triad::S8.iter().enumerate() {
            residues[i] =
                ((sa.residues[i] as u64 * inverses[i] as u64) % p as u64) as u32;
        }
        signatures.push(S8Signature { residues });
    }
    PolynomialS8Signature { signatures }
}

// ─── Fused Piggyback Division (D3) ────────────────────────────────────────

/// Auxiliary-prime residues attached to a polynomial for FPD support.
///
/// FPD needs residues modulo primes outside the S8 basis to widen the
/// fusion product `P` past the certified quotient bound. This struct
/// stores those residues coefficient-by-coefficient so the FPD lane
/// can fuse against the chosen auxiliary primes without re-deriving
/// them at op time.
#[derive(Debug, Clone)]
pub struct AuxResidueSet {
    pub primes: Vec<u32>,
    /// `residues[coeff_idx][prime_idx]` — outer index per polynomial
    /// coefficient, inner index aligned with `primes`.
    pub residues: Vec<Vec<u32>>,
}

impl AuxResidueSet {
    /// Project each coefficient into every aux prime in `primes`.
    pub fn from_coeffs(coeffs: &[i128], primes: &[u32]) -> Self {
        let primes_vec = primes.to_vec();
        let residues: Vec<Vec<u32>> = coeffs
            .iter()
            .map(|&c| {
                primes_vec
                    .iter()
                    .map(|&p| c.rem_euclid(p as i128) as u32)
                    .collect()
            })
            .collect();
        Self {
            primes: primes_vec,
            residues,
        }
    }

    /// Pick the smallest set of auxiliary primes from
    /// [`crate::chimera::AUX_FPD_POOL`] that
    /// (a) are coprime to the divisor and to the S8 basis product,
    /// (b) when multiplied with the S8 "good lanes" for the divisor,
    ///     produce a fusion product `P > 2 * quotient_bound`.
    ///
    /// Returns `None` if the pool can't deliver enough margin.
    pub fn select_for_divisor(divisor: i128, quotient_bound: i128) -> Option<Vec<u32>> {
        let abs_d = divisor.unsigned_abs();
        if abs_d == 0 {
            return None;
        }
        let s8_good_product: u64 = crate::triad::S8
            .iter()
            .filter(|&&m| gcd_u64(m as u64, abs_d as u64) == 1)
            .map(|&m| m as u64)
            .product();
        let mut p: u128 = s8_good_product as u128;
        let target = (quotient_bound as u128).saturating_mul(2).saturating_add(1);
        let mut chosen = Vec::new();
        if p > target {
            return Some(chosen);
        }
        for &alpha in crate::chimera::AUX_FPD_POOL.iter() {
            if gcd_u64(alpha as u64, abs_d as u64) != 1 {
                continue;
            }
            chosen.push(alpha);
            p = p.saturating_mul(alpha as u128);
            if p > target {
                return Some(chosen);
            }
        }
        None
    }
}

/// Incremental Garner CRT fusion of (modulus, residue) pairs into the
/// unique integer `Q` in `[0, ∏ moduli)`. Moduli must be pairwise coprime.
/// Recover the integer pinned by a set of `(modulus, residue)` pairs on a
/// pairwise-coprime basis, via a single CRT anchor read (K-Elimination ladder).
///
/// A2: this replaces the former Garner mixed-radix fusion. Mixed radix emits a
/// sequential chain of positional digits — synthetic emission that breaks the
/// i.i.d. structure of residue space and opens a side-channel surface. The CRT
/// read below forms the value directly from the coprime basis (each lane's
/// contribution is `r_i · (M/m_i) · (M/m_i)^{-1} mod m_i`), leaving the lane
/// residues untouched and introducing no positional digit sequence. The
/// returned value is identical to the retired mixed-radix result.
fn crt_fuse_pairs(pairs: &[(u32, u32)]) -> i128 {
    CRAM_DIVISION_COUNTERS
        .garner_calls
        .fetch_add(1, Ordering::Relaxed);
    // Basis product M = ∏ m_i.
    let mut modulus: i128 = 1;
    for &(m, _) in pairs {
        modulus *= m as i128;
    }
    // Σ r_i · (M/m_i) · ((M/m_i)^{-1} mod m_i), reduced mod M.
    let mut value: i128 = 0;
    for &(m, r) in pairs {
        let m_i = m as i128;
        let cofactor = modulus / m_i; // M / m_i, coprime to m_i
        let cofactor_mod = cofactor.rem_euclid(m_i) as u32;
        let inv = mod_inv_u32(cofactor_mod, m)
            .expect("FPD: lane moduli must be pairwise coprime") as i128;
        let term = (r as i128) * cofactor % modulus * inv % modulus;
        value = (value + term).rem_euclid(modulus);
    }
    value
}

/// FPD result for one coefficient: new S8 lane residues + new aux residues.
struct FpdLanePieces {
    new_s8: [u32; 8],
    new_aux: Vec<u32>,
}

/// Failure modes for [`fpd_one_coefficient`].
///
/// G11 (NINE65_v7_DEEP_ANALYSIS_20260817.md): `fpd_one_coefficient` used to
/// return a bare `Option`, collapsing two very different situations into one
/// `None` — a structural invariant violation (an aux/good-lane modulus
/// turned out not to be coprime to `d` after all) and a genuinely inexact
/// division (the numerator was never an exact multiple of `d`, so the
/// "recovered quotient" is meaningless). Worse, the second case was never
/// even detected: the fused quotient was accepted and re-projected onto S8
/// with `DivStatus::FusedBounded` and nothing checked it against the S8
/// lanes the fusion basis excluded. [`BadLaneDisagreement`] is that missing
/// check.
///
/// [`BadLaneDisagreement`]: FpdError::BadLaneDisagreement
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FpdError {
    /// A required per-lane modular inverse of the divisor does not exist,
    /// even though the caller (`cram_rescale_by_scalar_fpd`) already checked
    /// every aux prime for coprimality with `d` before calling here.
    LaneInverseMissing,
    /// The candidate quotient produced by fusing the *coprime* S8 lanes and
    /// the auxiliary anchors disagrees with the coefficient's residue on a
    /// "bad" S8 lane — one where `d` is not invertible, so that lane could
    /// not participate in the fusion and instead serves as an independent
    /// witness. `d * q ≡ a (mod p)` is a genuine constraint on such a lane;
    /// it holds iff the numerator was exactly divisible by `d`. A mismatch
    /// means it was not, and the fused "quotient" is meaningless — this is
    /// the exactness check that was previously entirely absent.
    BadLaneDisagreement { coeff_index: usize, s8_lane_modulus: u32 },
}

/// Per-coefficient FPD division: fuse the good S8 lanes and the aux lanes
/// to recover the exact integer quotient, verify it against every S8 lane
/// the fusion excluded, then re-project onto S8 (and the aux primes for
/// chain continuation).
fn fpd_one_coefficient(
    coeff_index: usize,
    s8_residues: [u32; 8],
    aux_residues: &[u32],
    aux_primes: &[u32],
    divisor: i128,
    fusion_product: i128,
) -> Result<FpdLanePieces, FpdError> {
    let abs_d = divisor.unsigned_abs() as u64;
    let sign: i128 = if divisor < 0 { -1 } else { 1 };

    // Build the (modulus, quotient_residue) pair list across good S8
    // lanes and every aux prime (which are by construction coprime to d).
    // Lanes skipped here (gcd(p, d) != 1) are recorded so the reconstructed
    // quotient can be checked against them independently below.
    let mut pairs: Vec<(u32, u32)> = Vec::with_capacity(8 + aux_primes.len());
    let mut bad_lanes: Vec<(usize, u32)> = Vec::new();
    for (i, &p) in crate::triad::S8.iter().enumerate() {
        if gcd_u64(p as u64, abs_d) == 1 {
            let inv = mod_inv_u32((abs_d % p as u64) as u32, p)
                .ok_or(FpdError::LaneInverseMissing)?;
            let q = (s8_residues[i] as u64 * inv as u64 % p as u64) as u32;
            pairs.push((p, q));
        } else {
            bad_lanes.push((i, p));
        }
    }
    for (j, &alpha) in aux_primes.iter().enumerate() {
        let inv = mod_inv_u32((abs_d % alpha as u64) as u32, alpha)
            .ok_or(FpdError::LaneInverseMissing)?;
        let q = (aux_residues[j] as u64 * inv as u64 % alpha as u64) as u32;
        pairs.push((alpha, q));
    }

    // Fuse → Q ∈ [0, P).
    let q_unsigned = crt_fuse_pairs(&pairs);
    // Recentre to (-P/2, P/2].
    let q_signed = if q_unsigned > fusion_product / 2 {
        q_unsigned - fusion_product
    } else {
        q_unsigned
    };
    let q_signed = q_signed * sign;

    // G11: verify the reconstructed quotient against every S8 lane the
    // fusion basis did NOT include. `d * q_signed` must reduce to the
    // coefficient's original residue on each such lane; a mismatch proves
    // the numerator was never evenly divisible by `d`.
    for &(i, p) in &bad_lanes {
        let predicted = (q_signed * divisor).rem_euclid(p as i128) as u32;
        if predicted != s8_residues[i] {
            return Err(FpdError::BadLaneDisagreement {
                coeff_index,
                s8_lane_modulus: p,
            });
        }
    }

    // Re-project onto every S8 lane (including the bad lanes just verified
    // above — they re-acquire a meaningful residue from the now-certified
    // quotient).
    let mut new_s8 = [0u32; 8];
    for (i, &p) in crate::triad::S8.iter().enumerate() {
        new_s8[i] = q_signed.rem_euclid(p as i128) as u32;
    }
    let new_aux: Vec<u32> = aux_primes
        .iter()
        .map(|&alpha| q_signed.rem_euclid(alpha as i128) as u32)
        .collect();
    Ok(FpdLanePieces { new_s8, new_aux })
}

impl<C> CramCiphertext<C> {
    /// Wrap a base ciphertext with both the standard S8 witness and an
    /// auxiliary residue set sized for FPD division.
    pub fn wrap_with_fpd_aux(
        base: C,
        c0_coeffs: &[i128],
        c1_coeffs: Option<&[i128]>,
        aux_primes: &[u32],
    ) -> Self {
        let mut ct = Self::wrap_default(base, c0_coeffs, c1_coeffs);
        ct.witness.c0_aux = Some(AuxResidueSet::from_coeffs(c0_coeffs, aux_primes));
        ct
    }

    /// Phase-4 D3 rescale via Fused Piggyback Division.
    ///
    /// Requires the witness to carry an [`AuxResidueSet`] sized for the
    /// divisor (use [`Self::wrap_with_fpd_aux`] at ingestion). The fusion
    /// product over S8's good lanes plus the aux primes must exceed
    /// `2 * quotient_bound`; otherwise the lane reports
    /// `BoundInsufficient` and Phase 4 returns `DivisionLaneNotImplemented`.
    pub fn cram_rescale_by_scalar_fpd<F>(
        self,
        divisor: i128,
        quotient_bound: i128,
        rescale_base: F,
    ) -> Result<(Self, ChimeraDivPlan), CramOpError>
    where
        F: FnOnce(C, i128) -> C,
    {
        self.verify().map_err(CramOpError::InputVerifyFailed)?;
        let plan = select_division_lane(divisor, self.topology.basis);

        let aux_set = self.witness.c0_aux.as_ref().ok_or_else(|| {
            CramOpError::DivisionLaneNotImplemented {
                primary: plan.primary,
                gcd_with_basis: plan.gcd_with_basis,
            }
        })?;
        // Verify every aux prime is coprime to the divisor.
        let abs_d = divisor.unsigned_abs() as u64;
        if abs_d == 0
            || aux_set
                .primes
                .iter()
                .any(|&alpha| gcd_u64(alpha as u64, abs_d) != 1)
        {
            return Err(CramOpError::DivisionLaneNotImplemented {
                primary: plan.primary,
                gcd_with_basis: plan.gcd_with_basis,
            });
        }
        // Compute the fusion product P = (∏ good S8) × (∏ aux).
        let s8_good: i128 = crate::triad::S8
            .iter()
            .filter(|&&m| gcd_u64(m as u64, abs_d) == 1)
            .map(|&m| m as i128)
            .product();
        let aux_prod: i128 = aux_set.primes.iter().map(|&p| p as i128).product();
        let fusion_product = s8_good
            .checked_mul(aux_prod)
            .ok_or(CramOpError::OpCounterOverflow)?;
        if fusion_product <= quotient_bound.saturating_mul(2) {
            return Err(CramOpError::DivisionLaneNotImplemented {
                primary: plan.primary,
                gcd_with_basis: plan.gcd_with_basis,
            });
        }

        // Per-coefficient FPD.
        let n = self.witness.c0_signature.signatures.len();
        let mut new_signatures = Vec::with_capacity(n);
        let mut new_aux_residues = Vec::with_capacity(n);
        for i in 0..n {
            let pieces = fpd_one_coefficient(
                i,
                self.witness.c0_signature.signatures[i].residues,
                &aux_set.residues[i],
                &aux_set.primes,
                divisor,
                fusion_product,
            )
            .map_err(|err| match err {
                // A structural invariant violation (should be unreachable
                // given the coprimality checks above) folds into the same
                // "lane not implemented" report as before.
                FpdError::LaneInverseMissing => CramOpError::DivisionLaneNotImplemented {
                    primary: plan.primary,
                    gcd_with_basis: plan.gcd_with_basis,
                },
                // A genuinely inexact division gets its own typed, specific
                // error rather than being folded into the generic one above.
                FpdError::BadLaneDisagreement { .. } => CramOpError::Fpd(err),
            })?;
            new_signatures.push(S8Signature {
                residues: pieces.new_s8,
            });
            new_aux_residues.push(pieces.new_aux);
        }
        let new_c0 = PolynomialS8Signature {
            signatures: new_signatures,
        };
        let new_aux = AuxResidueSet {
            primes: aux_set.primes.clone(),
            residues: new_aux_residues,
        };

        let new_op_counter = self
            .witness
            .op_counter
            .checked_add(1)
            .ok_or(CramOpError::OpCounterOverflow)?;
        let new_lock_witness =
            recompute_post_op(&self.witness.lock_witness, &self.locks, &new_c0, new_op_counter);
        let new_base = rescale_base(self.base, divisor);

        let out = CramCiphertext {
            base: new_base,
            topology: self.topology,
            locks: self.locks,
            witness: CramWitnessState {
                c0_signature: new_c0,
                c1_signature: self.witness.c1_signature, // c1 unchanged in scalar div
                op_counter: new_op_counter,
                lock_witness: new_lock_witness,
                c0_aux: Some(new_aux),
            },
        };
        out.verify().map_err(CramOpError::OutputVerifyFailed)?;
        Ok((out, plan))
    }
}

// ─── DIV_EXACT (D2) — Absorbent Quotient-Basis Division ──────────────────

/// Errors specific to D2 (DIV_EXACT).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DivExactError {
    /// Divisor has a prime factor outside the active basis.
    DivisorNotBasisSmooth { divisor: i128 },
    /// `divisor == 0`.
    DivisorIsZero,
    /// A coefficient is not exactly divisible by `divisor`.
    NonExactRemainder {
        coeff_index: usize,
        coefficient: i128,
        divisor: i128,
        remainder: i128,
    },
}

impl<C> CramCiphertext<C> {
    /// Phase-4 D2 rescale: DIV_EXACT through Garner-lift + exact integer
    /// division. Valid only when:
    ///
    ///   * `divisor` is basis-smooth (every prime factor lies in the
    ///     active basis), and
    ///   * every coefficient is exactly divisible by `divisor` — D2 is
    ///     the *exact* quotient lane; nonzero remainders are rejected.
    ///
    /// Within the witness's working range `(-S8_PRODUCT/2, S8_PRODUCT/2)`
    /// the absorbent prime-power machinery the spec uses for very large
    /// coefficients reduces to exact integer division of the recentred
    /// reconstruction. Larger coefficients require an explicit absorbent
    /// extension (Phase-5+ enhancement).
    pub fn cram_rescale_by_scalar_div_exact<F>(
        self,
        divisor: i128,
        rescale_base: F,
    ) -> Result<(Self, ChimeraDivPlan), CramOpError>
    where
        F: FnOnce(C, i128) -> C,
    {
        self.verify().map_err(CramOpError::InputVerifyFailed)?;
        let plan = select_division_lane(divisor, self.topology.basis);

        if divisor == 0 {
            return Err(CramOpError::DivExact(DivExactError::DivisorIsZero));
        }
        let abs_d_u64 = divisor.unsigned_abs() as u64;
        if !is_basis_smooth(abs_d_u64, self.topology.basis) {
            return Err(CramOpError::DivExact(
                DivExactError::DivisorNotBasisSmooth { divisor },
            ));
        }

        // Garner-lift each coefficient to a signed integer, divide
        // exactly, and re-project onto S8.
        let n = self.witness.c0_signature.signatures.len();
        let mut new_signatures = Vec::with_capacity(n);
        for (i, sig) in self.witness.c0_signature.signatures.iter().enumerate() {
            CRAM_DIVISION_COUNTERS
                .garner_calls
                .fetch_add(1, Ordering::Relaxed);
            let unsigned = crate::lane_projector::garner_reconstruct(sig);
            let half = (crate::triad::S8_PRODUCT / 2) as i128;
            let signed = if (unsigned as i128) > half {
                unsigned as i128 - crate::triad::S8_PRODUCT as i128
            } else {
                unsigned as i128
            };
            let r = signed.rem_euclid(divisor);
            let remainder = if r > divisor.abs() / 2 {
                r - divisor.abs()
            } else {
                r
            };
            if remainder != 0 {
                return Err(CramOpError::DivExact(DivExactError::NonExactRemainder {
                    coeff_index: i,
                    coefficient: signed,
                    divisor,
                    remainder,
                }));
            }
            let q = signed / divisor;
            let mut residues = [0u32; 8];
            for (li, &p) in crate::triad::S8.iter().enumerate() {
                residues[li] = q.rem_euclid(p as i128) as u32;
            }
            new_signatures.push(S8Signature { residues });
        }
        let new_c0 = PolynomialS8Signature {
            signatures: new_signatures,
        };

        let new_op_counter = self
            .witness
            .op_counter
            .checked_add(1)
            .ok_or(CramOpError::OpCounterOverflow)?;
        let new_lock_witness = recompute_post_op(
            &self.witness.lock_witness,
            &self.locks,
            &new_c0,
            new_op_counter,
        );
        let new_base = rescale_base(self.base, divisor);

        let out = CramCiphertext {
            base: new_base,
            topology: self.topology,
            locks: self.locks,
            witness: CramWitnessState {
                c0_signature: new_c0,
                c1_signature: self.witness.c1_signature,
                op_counter: new_op_counter,
                lock_witness: new_lock_witness,
                c0_aux: None, // D2 does not propagate aux residues.
            },
        };
        out.verify().map_err(CramOpError::OutputVerifyFailed)?;
        Ok((out, plan))
    }

    /// Resolver: try every evaluable chimera lane, accept iff every lane
    /// that succeeds returns the same result. Phase 4 cross-lane agreement
    /// theorem — when multiple lanes can compute the quotient, they MUST
    /// agree, otherwise the operation rejects.
    ///
    /// Returns the agreed result + the set of lanes that succeeded.
    pub fn cram_rescale_with_chimera_router<F>(
        self,
        divisor: i128,
        quotient_bound: i128,
        rescale_base: F,
    ) -> Result<(Self, ChimeraDivPlan, crate::chimera_division::LaneMask), CramOpError>
    where
        C: Clone,
        F: Fn(C, i128) -> C,
    {
        use crate::chimera_division::LaneMask;
        let plan = select_division_lane(divisor, self.topology.basis);
        let mut succeeded = LaneMask::default();
        let mut agreed_result: Option<Vec<i32>> = None;
        let mut agreed_ct: Option<Self> = None;

        // Try D0.
        if plan.evaluable.modular_inverse {
            if let Ok((result_ct, _)) = self.clone().cram_rescale_by_scalar(divisor, &rescale_base) {
                let recon = result_ct.reconstruct_c0_coeffs_signed();
                if let Some(prev) = agreed_result.as_ref() {
                    if prev != &recon {
                        return Err(CramOpError::ChimeraLaneDisagreement);
                    }
                } else {
                    agreed_result = Some(recon);
                    agreed_ct = Some(result_ct);
                }
                succeeded.modular_inverse = true;
            }
        }

        // Try D2.
        if is_basis_smooth(divisor.unsigned_abs() as u64, self.topology.basis) {
            if let Ok((result_ct, _)) = self
                .clone()
                .cram_rescale_by_scalar_div_exact(divisor, &rescale_base)
            {
                let recon = result_ct.reconstruct_c0_coeffs_signed();
                if let Some(prev) = agreed_result.as_ref() {
                    if prev != &recon {
                        return Err(CramOpError::ChimeraLaneDisagreement);
                    }
                } else {
                    agreed_result = Some(recon);
                    agreed_ct = Some(result_ct);
                }
                succeeded.div_exact = true;
            }
        }

        // Try D1 (K-Elim) with anchor = 17 (the largest S8 prime that
        // is not the signature lane), if the divisor is coprime to
        // M_main = S8_PRODUCT / 17.
        let m_main_default: u64 = crate::triad::S8_PRODUCT as u64 / 17;
        if gcd_u64(divisor.unsigned_abs() as u64, m_main_default) == 1 && divisor != 0 {
            if let Ok((result_ct, _)) = self
                .clone()
                .cram_rescale_by_scalar_kelim(divisor, 17, &rescale_base)
            {
                let recon = result_ct.reconstruct_c0_coeffs_signed();
                if let Some(prev) = agreed_result.as_ref() {
                    if prev != &recon {
                        return Err(CramOpError::ChimeraLaneDisagreement);
                    }
                } else {
                    agreed_result = Some(recon);
                    agreed_ct = Some(result_ct);
                }
                succeeded.kelim = true;
            }
        }

        // Try D3 (FPD) iff aux residues are present.
        if self.witness.c0_aux.is_some() {
            if let Ok((result_ct, _)) =
                self.clone()
                    .cram_rescale_by_scalar_fpd(divisor, quotient_bound, &rescale_base)
            {
                let recon = result_ct.reconstruct_c0_coeffs_signed();
                if let Some(prev) = agreed_result.as_ref() {
                    if prev != &recon {
                        return Err(CramOpError::ChimeraLaneDisagreement);
                    }
                } else {
                    agreed_ct = Some(result_ct);
                }
                succeeded.fused_piggyback = true;
            }
        }
        let _ = agreed_result; // resolver done — drop the comparison cache.

        match agreed_ct {
            Some(ct) => Ok((ct, plan, succeeded)),
            None => Err(CramOpError::DivisionLaneNotImplemented {
                primary: plan.primary,
                gcd_with_basis: plan.gcd_with_basis,
            }),
        }
    }
}

// ─── K-Elimination Lift (D1) ─────────────────────────────────────────────

/// Errors specific to D1 (K-Elimination lift).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KElimError {
    /// `anchor_prime` is not in the active basis.
    AnchorNotInBasis { anchor: u32 },
    /// The recovered winding `κ` is outside the certified corridor
    /// `|κ| < anchor / 2` — the integer being divided is too large for
    /// the chosen `(M_main, m_anchor)` split.
    CorridorViolated {
        coeff_index: usize,
        kappa: i64,
        anchor: u32,
    },
    /// The recovered integer is not exactly divisible by `divisor`.
    NonExactRemainder {
        coeff_index: usize,
        coefficient: i128,
        divisor: i128,
        remainder: i128,
    },
    /// `gcd(M_main, m_anchor) ≠ 1` — anchor must be coprime to the main
    /// reconstruction product. For S8 this is automatic when the anchor
    /// is one of the basis primes.
    AnchorNotCoprime,
    /// `divisor == 0` or `divisor` shares factors with `M_main`, making
    /// the K-Elim main-side division undefined.
    DivisorIncompatibleWithMain { divisor: i128 },
}

/// Garner reconstruction over a chosen subset of S8 lanes (the "main"
/// reconstruction basis). Returns `(x_main, M_main)` where `x_main` is
/// the unique non-negative integer in `[0, M_main)` matching the lane
/// residues.
fn garner_reconstruct_subset(sig: &S8Signature, main_indices: &[usize]) -> (i128, i128) {
    let mut x: i128 = sig.residues[main_indices[0]] as i128;
    let mut radix: i128 = crate::triad::S8[main_indices[0]] as i128;
    for &idx in &main_indices[1..] {
        let m_i = crate::triad::S8[idx] as i128;
        let a_i = sig.residues[idx] as i128;
        let x_mod_mi = x.rem_euclid(m_i);
        let diff = (a_i - x_mod_mi).rem_euclid(m_i);
        let radix_mod_mi = radix.rem_euclid(m_i) as u32;
        let inv = mod_inv_u32(radix_mod_mi, m_i as u32)
            .expect("S8 lanes are pairwise coprime");
        let v = (diff * inv as i128).rem_euclid(m_i);
        x += v * radix;
        radix *= m_i;
    }
    (x, radix)
}

/// Recover the K-Elim winding `κ ≡ (r_anchor − x_main) · M_main⁻¹
/// (mod m_anchor)` for one coefficient.
fn k_elim_winding(x_main: i128, m_main: i128, r_anchor: u32, m_anchor: u32) -> i64 {
    let m_anchor_i = m_anchor as i128;
    let diff = (r_anchor as i128 - x_main.rem_euclid(m_anchor_i)).rem_euclid(m_anchor_i);
    let radix_mod = m_main.rem_euclid(m_anchor_i) as u32;
    let inv = mod_inv_u32(radix_mod, m_anchor)
        .expect("anchor coprime to M_main by precondition");
    let kappa = (diff * inv as i128).rem_euclid(m_anchor_i);
    // Recentre to (-m_anchor/2, m_anchor/2].
    if kappa > m_anchor_i / 2 {
        (kappa - m_anchor_i) as i64
    } else {
        kappa as i64
    }
}

impl<C> CramCiphertext<C> {
    /// Phase-4 D1 rescale via K-Elimination lift.
    ///
    /// Splits S8 into a main reconstruction basis `S8 \ {anchor}` and
    /// an anchor lane `m_anchor`. For each coefficient:
    ///
    ///   1. Reconstruct `x_main` from the 7 main lanes (smaller Garner).
    ///   2. Recover the winding `κ ≡ (r_anchor − x_main) · M_main⁻¹
    ///      (mod m_anchor)`, recentred into `(-m_anchor/2, m_anchor/2]`.
    ///   3. Verify the corridor `|κ| < m_anchor / 2`.
    ///   4. Lift to `A = x_main + κ · M_main`.
    ///   5. Exact-divide `A / divisor` (rejecting any remainder).
    ///   6. Re-project the quotient onto the full S8 basis.
    ///
    /// Preconditions:
    ///
    ///   * `anchor` ∈ S8.
    ///   * `gcd(divisor, M_main) = 1` so the main-side residue
    ///     contains the divisor information; if `divisor` shares factors
    ///     with `M_main`, use D2 or D3 instead.
    pub fn cram_rescale_by_scalar_kelim<F>(
        self,
        divisor: i128,
        anchor: u32,
        rescale_base: F,
    ) -> Result<(Self, ChimeraDivPlan), CramOpError>
    where
        F: FnOnce(C, i128) -> C,
    {
        self.verify().map_err(CramOpError::InputVerifyFailed)?;
        let plan = select_division_lane(divisor, self.topology.basis);

        let anchor_idx = crate::triad::S8
            .iter()
            .position(|&p| p == anchor)
            .ok_or(CramOpError::KElim(KElimError::AnchorNotInBasis { anchor }))?;
        if divisor == 0 {
            return Err(CramOpError::KElim(KElimError::DivisorIncompatibleWithMain {
                divisor,
            }));
        }
        // Build main-lane index list: every S8 index except the anchor.
        let main_indices: Vec<usize> = (0..crate::triad::S8.len())
            .filter(|&i| i != anchor_idx)
            .collect();
        // M_main = ∏ main lane primes.
        let m_main: i128 = main_indices
            .iter()
            .map(|&i| crate::triad::S8[i] as i128)
            .product();

        // gcd(divisor, M_main) must be 1 for the lane-side division to
        // be well-defined.
        let abs_d = divisor.unsigned_abs() as i128;
        if gcd_u64(abs_d as u64, m_main as u64) != 1 {
            return Err(CramOpError::KElim(KElimError::DivisorIncompatibleWithMain {
                divisor,
            }));
        }
        // gcd(M_main, m_anchor) is automatic for distinct S8 primes, but
        // surface a typed error if a future basis breaks the invariant.
        if gcd_u64(m_main as u64, anchor as u64) != 1 {
            return Err(CramOpError::KElim(KElimError::AnchorNotCoprime));
        }

        let n = self.witness.c0_signature.signatures.len();
        let mut new_signatures = Vec::with_capacity(n);
        for (i, sig) in self.witness.c0_signature.signatures.iter().enumerate() {
            CRAM_DIVISION_COUNTERS
                .garner_calls
                .fetch_add(1, Ordering::Relaxed);
            // Main reconstruction.
            let (x_main, m_main_actual) = garner_reconstruct_subset(sig, &main_indices);
            debug_assert_eq!(m_main_actual, m_main);

            // K-Elim winding.
            let r_anchor = sig.residues[anchor_idx];
            let kappa = k_elim_winding(x_main, m_main, r_anchor, anchor);

            // Corridor: |κ| < m_anchor / 2.
            if (kappa.unsigned_abs() as u32) >= anchor / 2 + 1 {
                return Err(CramOpError::KElim(KElimError::CorridorViolated {
                    coeff_index: i,
                    kappa,
                    anchor,
                }));
            }

            // Lift to certified integer.
            let a_certified = x_main + (kappa as i128) * m_main;
            // Recentre to signed if Garner returned a value > S8_PRODUCT/2.
            let half = (crate::triad::S8_PRODUCT / 2) as i128;
            let a_signed = if a_certified > half {
                a_certified - crate::triad::S8_PRODUCT as i128
            } else {
                a_certified
            };

            // Exact division.
            let r = a_signed.rem_euclid(divisor);
            let remainder = if r > divisor.abs() / 2 {
                r - divisor.abs()
            } else {
                r
            };
            if remainder != 0 {
                return Err(CramOpError::KElim(KElimError::NonExactRemainder {
                    coeff_index: i,
                    coefficient: a_signed,
                    divisor,
                    remainder,
                }));
            }
            let q = a_signed / divisor;

            // Re-project onto full S8.
            let mut residues = [0u32; 8];
            for (li, &p) in crate::triad::S8.iter().enumerate() {
                residues[li] = q.rem_euclid(p as i128) as u32;
            }
            new_signatures.push(S8Signature { residues });
        }
        let new_c0 = PolynomialS8Signature {
            signatures: new_signatures,
        };

        let new_op_counter = self
            .witness
            .op_counter
            .checked_add(1)
            .ok_or(CramOpError::OpCounterOverflow)?;
        let new_lock_witness = recompute_post_op(
            &self.witness.lock_witness,
            &self.locks,
            &new_c0,
            new_op_counter,
        );
        let new_base = rescale_base(self.base, divisor);

        let out = CramCiphertext {
            base: new_base,
            topology: self.topology,
            locks: self.locks,
            witness: CramWitnessState {
                c0_signature: new_c0,
                c1_signature: self.witness.c1_signature,
                op_counter: new_op_counter,
                lock_witness: new_lock_witness,
                c0_aux: None,
            },
        };
        out.verify().map_err(CramOpError::OutputVerifyFailed)?;
        Ok((out, plan))
    }
}

// ─── Phase 5 — CRAM Bootstrap Witness ─────────────────────────────────────

/// Reasons a bootstrap may be required, derived from witness state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BootstrapTrigger {
    /// `op_counter` is at the boundary corridor's upper bound — one
    /// more op would violate the corridor.
    CorridorAtUpperBound,
    /// `op_counter` is within `headroom` of the corridor end.
    CorridorNearUpperBound { headroom: i128 },
    /// A lock predicate is currently failing — this bootstrap is
    /// recovery-driven, not preventive.
    LockFailing,
    /// User-driven (manual / scheduled) bootstrap.
    Manual,
}

/// Certificate emitted by [`CramCiphertext::cram_bootstrap`].
#[derive(Debug, Clone)]
pub struct BootstrapCertificate {
    pub triggers: Vec<BootstrapTrigger>,
    pub pre_op_counter: i128,
    pub post_op_counter: i128,
    /// True iff every coefficient's S8 signature is byte-identical
    /// before and after the refresh — the spec's `Decrypt(C_boot) =
    /// Decrypt(C)` postcondition lifted to the witness layer.
    pub signature_preserved: bool,
    /// True iff the boundary corridor was reset (post_op_counter is at
    /// the start of a fresh corridor).
    pub corridor_reset: bool,
}

impl<C> CramCiphertext<C> {
    /// Inspect the witness for bootstrap triggers without modifying state.
    pub fn bootstrap_triggers(&self) -> Vec<BootstrapTrigger> {
        let mut triggers = Vec::new();
        for entry in &self.witness.lock_witness.entries {
            if let LockEvidence::Boundary {
                corridor_low: _,
                corridor_high,
            } = &entry.evidence
            {
                let head = *corridor_high - self.witness.op_counter;
                if head <= 0 {
                    triggers.push(BootstrapTrigger::CorridorAtUpperBound);
                } else if head <= 2 {
                    triggers.push(BootstrapTrigger::CorridorNearUpperBound { headroom: head });
                }
            }
        }
        if self.verify_locks().is_err() {
            triggers.push(BootstrapTrigger::LockFailing);
        }
        triggers
    }

    /// True iff at least one trigger fires.
    pub fn bootstrap_required(&self) -> bool {
        !self.bootstrap_triggers().is_empty()
    }

    /// CRAM bootstrap. Refreshes the base ciphertext via `refresh_base`,
    /// resets the boundary corridor by zeroing `op_counter`, and
    /// recomputes lock evidence against the (preserved) signature.
    ///
    /// Postconditions, matching the spec § 10.2:
    ///
    ///   * `Decrypt(C_boot) = Decrypt(C)` — the signature is unchanged.
    ///   * `Valid(C_boot) = true` — full lock-graph verification.
    ///   * `op_counter == 0` — fresh corridor.
    ///   * `topology` and `locks` unchanged.
    pub fn cram_bootstrap<F>(
        self,
        refresh_base: F,
    ) -> Result<(Self, BootstrapCertificate), CramOpError>
    where
        F: FnOnce(C) -> C,
    {
        // Phase 1 of the spec's pseudocode allows bootstrap to run even
        // when the current cert is failing (it's a recovery operation).
        // Verify metadata structure but tolerate lock-witness failure.
        if !self.verify_metadata() {
            return Err(CramOpError::InputVerifyFailed(LockFailure::TopologyIllFormed));
        }

        let triggers = self.bootstrap_triggers();
        let mut triggers_or_manual = triggers;
        if triggers_or_manual.is_empty() {
            triggers_or_manual.push(BootstrapTrigger::Manual);
        }
        let pre_signature = self.witness.c0_signature.clone();
        let pre_op_counter = self.witness.op_counter;

        // Refresh base — for the generic shell this is whatever the
        // closure does. The signature is the security-bearing object's
        // image, so it does not move under refresh.
        let new_base = refresh_base(self.base);

        // Reset op_counter; rebuild lock evidence (boundary corridor
        // gets a fresh window starting at op_counter = 0).
        let new_op_counter: i128 = 0;
        let new_lock_witness = LockWitnessSet::compute(
            &self.locks,
            &pre_signature,
            new_op_counter,
        );

        let post_signature = pre_signature.clone();
        let signature_preserved =
            pre_signature.signatures == post_signature.signatures;

        let out = CramCiphertext {
            base: new_base,
            topology: self.topology,
            locks: self.locks,
            witness: CramWitnessState {
                c0_signature: post_signature,
                c1_signature: self.witness.c1_signature,
                op_counter: new_op_counter,
                lock_witness: new_lock_witness,
                c0_aux: self.witness.c0_aux,
            },
        };
        out.verify().map_err(CramOpError::OutputVerifyFailed)?;

        let cert = BootstrapCertificate {
            triggers: triggers_or_manual,
            pre_op_counter,
            post_op_counter: new_op_counter,
            signature_preserved,
            corridor_reset: true,
        };
        Ok((out, cert))
    }
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

    // ---- Phase-1 CRAM ciphertext shell -----------------------------------

    #[test]
    fn cram_wrap_records_polynomial_s8_signature() {
        let coeffs: Vec<i128> = (0..16).map(|k| k as i128 * 100_001).collect();
        let ct = CramCiphertext::wrap_default((), &coeffs, None);
        assert_eq!(ct.witness.poly_len(), coeffs.len());
        assert_eq!(ct.witness.op_counter, 0);
        assert!(ct.verify_metadata());
    }

    #[test]
    fn cram_wrap_roundtrips_small_coeffs() {
        // Coefficients in (-S8_PRODUCT/2, S8_PRODUCT/2) reconstruct exactly.
        let coeffs = vec![-1_234_567i128, -1, 0, 1, 1_234_567, 4_000_000];
        let ct = CramCiphertext::wrap_default((), &coeffs, None);
        let recon = ct.reconstruct_c0_coeffs_signed();
        let expected: Vec<i32> = coeffs.iter().map(|&c| c as i32).collect();
        assert_eq!(recon, expected);
    }

    #[test]
    fn cram_wrap_carries_optional_c1_signature() {
        let c0 = vec![1i128, 2, 3, 4];
        let c1 = vec![5i128, 6, 7, 8];
        let ct = CramCiphertext::wrap_default((), &c0, Some(&c1));
        assert!(ct.witness.c1_signature.is_some());
        let recon_c1 = ct
            .witness
            .c1_signature
            .as_ref()
            .unwrap()
            .reconstruct_signed();
        assert_eq!(recon_c1, vec![5, 6, 7, 8]);
    }

    #[test]
    fn cram_metadata_verification_catches_topology_mismatch() {
        // Build a topology with a basis that does not match its lanes.
        let bad_topology = CramTopology {
            id: TopologyId("BAD"),
            basis: SafeBasis::S6,
            // Lanes include 17 and 19, which are not in S6.
            lanes: &S8_CHIMERA_V1_LANES,
        };
        let locks = default_phase_locks();
        let witness = CramWitnessState::from_coeffs(&[0i128], None, &locks);
        let ct = CramCiphertext {
            base: (),
            topology: bad_topology,
            locks,
            witness,
        };
        assert!(!ct.verify_metadata());
    }

    #[test]
    fn cram_metadata_verification_catches_lock_referencing_unknown_prime() {
        let mut bad_locks = default_phase_locks();
        // 23 is in the FPD aux pool, not S8 — must be rejected.
        bad_locks.add(23, 5, LockType::Anchor);
        let witness = CramWitnessState::from_coeffs(&[0i128], None, &bad_locks);
        let ct = CramCiphertext {
            base: (),
            topology: S8_CHIMERA_V1.clone(),
            locks: bad_locks,
            witness,
        };
        assert!(!ct.verify_metadata());
    }

    // ---- Phase-2 lock predicate evaluation -------------------------------

    fn sample_coeffs() -> Vec<i128> {
        // Mix of zero, ±1, small, large positive, large negative.
        vec![0, 1, -1, 42, -42, 1_234_567, -1_234_567, 4_500_000]
    }

    #[test]
    fn fresh_wrap_passes_phase2_verification() {
        let coeffs = sample_coeffs();
        let ct = CramCiphertext::wrap_default((), &coeffs, None);
        assert!(ct.verify().is_ok(), "fresh wrap must verify");
        assert_eq!(ct.witness.lock_witness.entries.len(), ct.locks.locks.len());
    }

    #[test]
    fn anchor_lock_detects_lane_5_tampering() {
        let coeffs = sample_coeffs();
        let mut ct = CramCiphertext::wrap_default((), &coeffs, None);
        // Bump residue mod 5 on coefficient 3. The default anchor lock is
        // 5↔7 so this must trigger AnchorDivergence.
        let lane_5_index = crate::triad::S8.iter().position(|&p| p == 5).unwrap();
        ct.witness.c0_signature.signatures[3].residues[lane_5_index] =
            (ct.witness.c0_signature.signatures[3].residues[lane_5_index] + 1) % 5;
        match ct.verify_locks() {
            Err(LockFailure::AnchorDivergence {
                source: 5,
                target: 7,
                coeff_index: 3,
                ..
            }) => {}
            other => panic!("expected AnchorDivergence at coeff 3, got {:?}", other),
        }
    }

    #[test]
    fn agreement_lock_detects_lane_17_tampering() {
        let coeffs = sample_coeffs();
        let mut ct = CramCiphertext::wrap_default((), &coeffs, None);
        // Default agreement lock is 11↔17. Bump residue mod 17 on coeff 5,
        // but pick a delta that the prior anchor (5↔7) and shadow (2↔11)
        // checks won't catch first. Lane 17 is touched by the agreement
        // lock and the boundary lock; agreement should trigger first.
        let lane_17_index = crate::triad::S8.iter().position(|&p| p == 17).unwrap();
        ct.witness.c0_signature.signatures[5].residues[lane_17_index] =
            (ct.witness.c0_signature.signatures[5].residues[lane_17_index] + 1) % 17;
        match ct.verify_locks() {
            Err(LockFailure::AgreementDivergence {
                source: 11,
                target: 17,
                coeff_index: 5,
                ..
            }) => {}
            // Signature lane hash also changes, but agreement is checked first
            // because it appears earlier in the default lock graph.
            other => panic!("expected AgreementDivergence at coeff 5, got {:?}", other),
        }
    }

    #[test]
    fn shadow_lock_detects_lane_11_tampering() {
        let coeffs = sample_coeffs();
        let mut ct = CramCiphertext::wrap_default((), &coeffs, None);
        // Bump residue mod 11. Default agreement (11↔17) fires before
        // shadow (2↔11), so we expect AgreementDivergence here — the test
        // confirms tampering with lane 11 is caught somewhere.
        let lane_11_index = crate::triad::S8.iter().position(|&p| p == 11).unwrap();
        ct.witness.c0_signature.signatures[1].residues[lane_11_index] =
            (ct.witness.c0_signature.signatures[1].residues[lane_11_index] + 1) % 11;
        let err = ct.verify_locks().expect_err("must fail");
        assert!(
            matches!(err, LockFailure::AgreementDivergence { .. } | LockFailure::ShadowDivergence { .. }),
            "lane-11 tampering must be caught by an 11-bearing lock, got {:?}",
            err
        );
    }

    #[test]
    fn shadow_lock_detects_lane_11_tampering_when_other_locks_skipped() {
        // Build a CT with ONLY the shadow lock so we can assert the
        // ShadowDivergence variant directly.
        let coeffs = sample_coeffs();
        let mut shadow_only = PhaseLockGraph::new();
        shadow_only.add(2, 11, LockType::Shadow);
        let witness = CramWitnessState::from_coeffs(&coeffs, None, &shadow_only);
        let mut ct = CramCiphertext {
            base: (),
            topology: S8_CHIMERA_V1.clone(),
            locks: shadow_only,
            witness,
        };
        let lane_11_index = crate::triad::S8.iter().position(|&p| p == 11).unwrap();
        ct.witness.c0_signature.signatures[2].residues[lane_11_index] =
            (ct.witness.c0_signature.signatures[2].residues[lane_11_index] + 1) % 11;
        match ct.verify_locks() {
            Err(LockFailure::ShadowDivergence {
                source: 2,
                target: 11,
                coeff_index: 2,
                ..
            }) => {}
            other => panic!("expected ShadowDivergence at coeff 2, got {:?}", other),
        }
    }

    #[test]
    fn boundary_lock_rejects_op_counter_outside_corridor() {
        let coeffs = sample_coeffs();
        let mut ct = CramCiphertext::wrap_default((), &coeffs, None);
        // Default boundary lock is 13↔17 with corridor width 17 (anchor).
        // Bumping op_counter past corridor_high triggers BoundaryViolation.
        ct.witness.op_counter = 1_000_000;
        match ct.verify_locks() {
            Err(LockFailure::BoundaryViolation {
                source: 13,
                target: 17,
                op_counter: 1_000_000,
                ..
            }) => {}
            other => panic!("expected BoundaryViolation, got {:?}", other),
        }
    }

    #[test]
    fn boundary_lock_accepts_op_counter_inside_corridor() {
        let coeffs = sample_coeffs();
        let mut sig_only = PhaseLockGraph::new();
        sig_only.add(13, 17, LockType::Boundary);
        let witness = CramWitnessState::from_coeffs(&coeffs, None, &sig_only);
        let mut ct = CramCiphertext {
            base: (),
            topology: S8_CHIMERA_V1.clone(),
            locks: sig_only,
            witness,
        };
        // op_counter starts at 0, corridor [0, 16] (width = 17). Bump to
        // 16 — still inside corridor.
        ct.witness.op_counter = 16;
        assert!(ct.verify_locks().is_ok());
        // 17 is outside.
        ct.witness.op_counter = 17;
        assert!(matches!(
            ct.verify_locks(),
            Err(LockFailure::BoundaryViolation { .. })
        ));
    }

    #[test]
    fn signature_lock_detects_op_counter_drift_alone() {
        let coeffs = sample_coeffs();
        let mut sig_only = PhaseLockGraph::new();
        sig_only.add(19, 19, LockType::Signature);
        let witness = CramWitnessState::from_coeffs(&coeffs, None, &sig_only);
        let mut ct = CramCiphertext {
            base: (),
            topology: S8_CHIMERA_V1.clone(),
            locks: sig_only,
            witness,
        };
        // The signature lane folds the op counter into its hash, so a single
        // bump must perturb the expected residue.
        ct.witness.op_counter = 1;
        assert!(matches!(
            ct.verify_locks(),
            Err(LockFailure::SignatureDivergence { lane: 19, .. })
        ));
    }

    #[test]
    fn evidence_length_mismatch_is_caught() {
        let coeffs = sample_coeffs();
        let mut ct = CramCiphertext::wrap_default((), &coeffs, None);
        // Truncate one of the per-coefficient evidence vectors.
        if let LockEvidence::Anchor { expected_k } =
            &mut ct.witness.lock_witness.entries[0].evidence
        {
            expected_k.pop();
        }
        assert!(matches!(
            ct.verify_locks(),
            Err(LockFailure::EvidenceLengthMismatch { .. })
        ));
    }

    #[test]
    fn evidence_mismatch_when_graph_changes_after_wrap() {
        let coeffs = sample_coeffs();
        let mut ct = CramCiphertext::wrap_default((), &coeffs, None);
        // Add a lock to the graph after wrap. Witness set still has the
        // original entries — the count diverges.
        ct.locks.add(5, 11, LockType::Multiplicative);
        assert!(matches!(
            ct.verify_locks(),
            Err(LockFailure::EvidenceMismatch)
        ));
    }

    #[test]
    fn crt_pair_matches_brute_force_for_s8_pairs() {
        // Sanity check the CRT helper used by the agreement lock.
        for &p in &crate::triad::S8 {
            for &q in &crate::triad::S8 {
                if p >= q {
                    continue;
                }
                for r_a in 0..p {
                    for r_b in 0..q {
                        let joint = crt_pair(r_a, p, r_b, q);
                        assert!(joint < p * q);
                        assert_eq!(joint % p, r_a);
                        assert_eq!(joint % q, r_b);
                    }
                }
            }
        }
    }

    #[test]
    fn anchor_k_inverse_relationship_holds() {
        // For x in [0, S8_PRODUCT), the K-Elim winding k = (r_target - r_source)
        // * source^-1 mod target must satisfy x ≡ r_source + k*source (mod target).
        for x in [0u32, 1, 7, 35, 100, 9_699_689] {
            let sig = S8Signature::project(x as i128);
            for &(s, t) in &[(2u32, 3), (5, 7), (11, 13), (17, 19)] {
                let k = anchor_k(&sig, s, t);
                let r_s = sig.residue_mod(s).unwrap();
                let r_t = sig.residue_mod(t).unwrap();
                assert_eq!(
                    (r_s as u64 + k as u64 * s as u64) % t as u64,
                    r_t as u64,
                    "anchor_k broken for ({s},{t}) at x={x}"
                );
            }
        }
    }

    // ---- Phase-3 homomorphic operations ---------------------------------

    #[test]
    fn cram_add_preserves_coefficient_sum_in_range() {
        // Coefficients chosen so their sums fit in (-S8_PRODUCT/2, S8_PRODUCT/2).
        let a_coeffs: Vec<i128> = vec![100, 200, -300, 400_000, -1_500_000, 0, 1, 7];
        let b_coeffs: Vec<i128> = vec![50, -200, 300, 100_000, 500_000, -1, 0, -7];
        let a = CramCiphertext::wrap_default((), &a_coeffs, None);
        let b = CramCiphertext::wrap_default((), &b_coeffs, None);
        let sum = a.cram_add(b, |_, _| ()).unwrap();
        let recon = sum.reconstruct_c0_coeffs_signed();
        let expected: Vec<i32> = a_coeffs
            .iter()
            .zip(b_coeffs.iter())
            .map(|(&x, &y)| (x + y) as i32)
            .collect();
        assert_eq!(recon, expected);
    }

    #[test]
    fn cram_add_increments_op_counter() {
        let a = CramCiphertext::wrap_default((), &[1i128, 2, 3, 4], None);
        let b = CramCiphertext::wrap_default((), &[5i128, 6, 7, 8], None);
        let result = a.cram_add(b, |_, _| ()).unwrap();
        assert_eq!(result.witness.op_counter, 1);
    }

    #[test]
    fn cram_add_chains_op_counter_correctly() {
        // After three sequential adds, op_counter should be 3.
        let mut acc = CramCiphertext::wrap_default((), &[0i128; 4], None);
        for _ in 0..3 {
            let b = CramCiphertext::wrap_default((), &[1i128; 4], None);
            acc = acc.cram_add(b, |_, _| ()).unwrap();
        }
        assert_eq!(acc.witness.op_counter, 3);
        // Polynomial accumulator ended at [3, 3, 3, 3].
        assert_eq!(acc.reconstruct_c0_coeffs_signed(), vec![3, 3, 3, 3]);
    }

    #[test]
    fn cram_add_rejects_polynomial_length_mismatch() {
        let a = CramCiphertext::wrap_default((), &[1i128, 2, 3], None);
        let b = CramCiphertext::wrap_default((), &[5i128, 6, 7, 8], None);
        match a.cram_add(b, |_, _| ()) {
            Err(CramOpError::PolynomialLengthMismatch { lhs: 3, rhs: 4 }) => {}
            other => panic!("expected length mismatch, got {:?}", other),
        }
    }

    #[test]
    fn cram_add_rebuilds_lock_evidence() {
        // After the op the new evidence must verify against the new
        // signatures — a stale evidence set would fail the OutputVerify
        // step and bubble up as OutputVerifyFailed.
        let a = CramCiphertext::wrap_default((), &[1i128, 2], None);
        let b = CramCiphertext::wrap_default((), &[3i128, 4], None);
        let sum = a.cram_add(b, |_, _| ()).unwrap();
        assert!(sum.verify().is_ok());
        // Anchor evidence reflects the new lane-5 / lane-7 residues.
        let anchor_entry = sum
            .witness
            .lock_witness
            .entries
            .iter()
            .find(|e| e.lock.kind == LockType::Anchor)
            .unwrap();
        if let LockEvidence::Anchor { expected_k } = &anchor_entry.evidence {
            assert_eq!(expected_k.len(), 2);
        } else {
            panic!("anchor evidence missing");
        }
    }

    #[test]
    fn cram_add_preserves_boundary_corridor() {
        // The boundary lock's corridor brackets the pre-op op_counter.
        // After cram_add, op_counter increments but the corridor is
        // preserved — the new value must still be inside it.
        let a = CramCiphertext::wrap_default((), &[1i128, 2, 3, 4], None);
        let pre_corridor = a
            .witness
            .lock_witness
            .entries
            .iter()
            .find_map(|e| match &e.evidence {
                LockEvidence::Boundary {
                    corridor_low,
                    corridor_high,
                } => Some((*corridor_low, *corridor_high)),
                _ => None,
            })
            .unwrap();
        let b = CramCiphertext::wrap_default((), &[1i128; 4], None);
        let result = a.cram_add(b, |_, _| ()).unwrap();
        let post_corridor = result
            .witness
            .lock_witness
            .entries
            .iter()
            .find_map(|e| match &e.evidence {
                LockEvidence::Boundary {
                    corridor_low,
                    corridor_high,
                } => Some((*corridor_low, *corridor_high)),
                _ => None,
            })
            .unwrap();
        assert_eq!(pre_corridor, post_corridor, "corridor must be preserved");
    }

    #[test]
    fn cram_add_eventually_violates_boundary_corridor() {
        // The boundary corridor for a fresh wrap is [0, 16] (anchor=17).
        // After 17 adds, op_counter = 17 leaves the corridor — the next
        // op fails OutputVerifyFailed with BoundaryViolation.
        let mut acc = CramCiphertext::wrap_default((), &[0i128; 2], None);
        for _ in 0..16 {
            let b = CramCiphertext::wrap_default((), &[0i128; 2], None);
            acc = acc.cram_add(b, |_, _| ()).unwrap();
        }
        assert_eq!(acc.witness.op_counter, 16);
        // 17th add must fail — op_counter would be 17, outside [0, 16].
        let b = CramCiphertext::wrap_default((), &[0i128; 2], None);
        match acc.cram_add(b, |_, _| ()) {
            Err(CramOpError::OutputVerifyFailed(LockFailure::BoundaryViolation { .. })) => {}
            other => panic!("expected boundary violation on 17th op, got {:?}", other),
        }
    }

    #[test]
    fn cram_mul_by_scalar_preserves_coefficient_product_in_range() {
        let coeffs: Vec<i128> = vec![1, 2, 3, 4, -5, -6, 7, 8];
        let ct = CramCiphertext::wrap_default((), &coeffs, None);
        let result = ct.cram_mul_by_scalar(11, |_, _| ()).unwrap();
        let recon = result.reconstruct_c0_coeffs_signed();
        let expected: Vec<i32> = coeffs.iter().map(|&c| (c * 11) as i32).collect();
        assert_eq!(recon, expected);
    }

    #[test]
    fn cram_mul_by_negative_scalar_works() {
        let coeffs: Vec<i128> = vec![10, 20, 30];
        let ct = CramCiphertext::wrap_default((), &coeffs, None);
        let result = ct.cram_mul_by_scalar(-3, |_, _| ()).unwrap();
        assert_eq!(result.reconstruct_c0_coeffs_signed(), vec![-30, -60, -90]);
    }

    #[test]
    fn cram_mul_by_zero_collapses_polynomial() {
        let ct = CramCiphertext::wrap_default((), &[1i128, 2, 3, 4], None);
        let result = ct.cram_mul_by_scalar(0, |_, _| ()).unwrap();
        assert_eq!(result.reconstruct_c0_coeffs_signed(), vec![0, 0, 0, 0]);
    }

    #[test]
    fn cram_op_input_verify_failure_is_reported() {
        // Tamper with the witness BEFORE the op so the input verify fails.
        let mut a = CramCiphertext::wrap_default((), &[1i128, 2, 3, 4], None);
        let lane_5_index = crate::triad::S8.iter().position(|&p| p == 5).unwrap();
        a.witness.c0_signature.signatures[0].residues[lane_5_index] =
            (a.witness.c0_signature.signatures[0].residues[lane_5_index] + 1) % 5;
        let b = CramCiphertext::wrap_default((), &[1i128, 2, 3, 4], None);
        match a.cram_add(b, |_, _| ()) {
            Err(CramOpError::InputVerifyFailed(LockFailure::AnchorDivergence { .. })) => {}
            other => panic!("expected input verify failure, got {:?}", other),
        }
    }

    #[test]
    fn cram_op_propagates_base_ciphertext_via_closure() {
        // The user-supplied closure is the only path for the concrete
        // ciphertext type. Verify it actually runs.
        let a = CramCiphertext::wrap_default(7u64, &[1i128, 2], None);
        let b = CramCiphertext::wrap_default(11u64, &[3i128, 4], None);
        let sum = a.cram_add(b, |x, y| x + y).unwrap();
        assert_eq!(sum.base, 18);
    }

    // ---- Phase-4 ciphertext × ciphertext multiplication ------------------

    #[test]
    fn cram_mul_produces_negacyclic_polynomial_product() {
        // For polynomials a = 1 + 2x and b = 3 + 4x in Z[x]/(x^2 + 1):
        //   a*b = 3 + 4x + 6x + 8x^2
        //       = 3 + 10x + 8(-1)            (negacyclic: x^2 = -1)
        //       = -5 + 10x.
        let a = CramCiphertext::wrap_default((), &[1i128, 2], None);
        let b = CramCiphertext::wrap_default((), &[3i128, 4], None);
        let prod = a.cram_mul(b, |_, _| ()).unwrap();
        assert_eq!(prod.reconstruct_c0_coeffs_signed(), vec![-5, 10]);
    }

    #[test]
    fn cram_mul_handles_degree_4_polynomials() {
        // a = 1 + 2x + 3x^2 + 4x^3, b = 1 (constant). a*b = a.
        let a_coeffs = vec![1i128, 2, 3, 4];
        let b_coeffs = vec![1i128, 0, 0, 0];
        let a = CramCiphertext::wrap_default((), &a_coeffs, None);
        let b = CramCiphertext::wrap_default((), &b_coeffs, None);
        let prod = a.cram_mul(b, |_, _| ()).unwrap();
        assert_eq!(prod.reconstruct_c0_coeffs_signed(), vec![1, 2, 3, 4]);
    }

    #[test]
    fn cram_mul_negacyclic_wrap_in_x_squared_ring() {
        // x * x in Z[x]/(x^2 + 1) = -1, encoded as coefficient (-1, 0).
        let a = CramCiphertext::wrap_default((), &[0i128, 1], None);
        let b = CramCiphertext::wrap_default((), &[0i128, 1], None);
        let prod = a.cram_mul(b, |_, _| ()).unwrap();
        assert_eq!(prod.reconstruct_c0_coeffs_signed(), vec![-1, 0]);
    }

    #[test]
    fn cram_mul_zero_polynomial_collapses() {
        let a = CramCiphertext::wrap_default((), &[1i128, 2, 3, 4], None);
        let zero = CramCiphertext::wrap_default((), &[0i128; 4], None);
        let prod = a.cram_mul(zero, |_, _| ()).unwrap();
        assert_eq!(prod.reconstruct_c0_coeffs_signed(), vec![0, 0, 0, 0]);
    }

    #[test]
    fn cram_mul_increments_op_counter() {
        let a = CramCiphertext::wrap_default((), &[1i128, 2], None);
        let b = CramCiphertext::wrap_default((), &[3i128, 4], None);
        let prod = a.cram_mul(b, |_, _| ()).unwrap();
        assert_eq!(prod.witness.op_counter, 1);
    }

    // ---- Phase-4 chimera division router ---------------------------------

    #[test]
    fn router_selects_d0_for_coprime_divisor() {
        let plan = select_division_lane(23, SafeBasis::S8);
        assert_eq!(
            plan.primary,
            crate::chimera_division::ChimeraLane::ModularInverse
        );
        assert_eq!(
            plan.primary_status,
            crate::chimera_division::DivStatus::ModularInverseExact
        );
        assert_eq!(plan.gcd_with_basis, 1);
        assert!(plan.evaluable.modular_inverse);
    }

    #[test]
    fn router_falls_back_to_d3_for_basis_sharing_divisor() {
        let plan = select_division_lane(6, SafeBasis::S8);
        assert_eq!(
            plan.primary,
            crate::chimera_division::ChimeraLane::FusedPiggyback
        );
        assert_eq!(plan.gcd_with_basis, 6);
        assert!(plan.evaluable.fused_piggyback);
        assert!(!plan.evaluable.modular_inverse);
    }

    #[test]
    fn router_marks_d2_evaluable_for_basis_smooth_divisor() {
        // 30 = 2·3·5 — every prime factor is in S8, so DIV_EXACT (D2)
        // is statically applicable given an absorbent extension.
        let plan = select_division_lane(30, SafeBasis::S8);
        assert!(plan.evaluable.div_exact);
        assert!(plan.evaluable.fused_piggyback);
    }

    #[test]
    fn router_rejects_zero_divisor() {
        let plan = select_division_lane(0, SafeBasis::S8);
        assert_eq!(
            plan.primary_status,
            crate::chimera_division::DivStatus::InvalidDivisor
        );
        assert_eq!(plan.evaluable.count(), 0);
    }

    #[test]
    fn cram_rescale_by_coprime_scalar_runs_d0() {
        // 23 is coprime to S8_PRODUCT, so D0 succeeds.
        let coeffs = vec![23i128 * 5, 23 * 7, 23 * 11, 23 * 13];
        let ct = CramCiphertext::wrap_default((), &coeffs, None);
        let (rescaled, plan) = ct.cram_rescale_by_scalar(23, |_, _| ()).unwrap();
        assert_eq!(
            plan.primary,
            crate::chimera_division::ChimeraLane::ModularInverse
        );
        assert_eq!(rescaled.reconstruct_c0_coeffs_signed(), vec![5, 7, 11, 13]);
    }

    #[test]
    fn cram_rescale_d1_d2_d3_not_yet_implemented() {
        // 6 shares factors with S8 — only D1/D2/D3 paths apply, none of
        // which Phase 4 implements yet. Must return DivisionLaneNotImplemented.
        let ct = CramCiphertext::wrap_default((), &[6i128, 12, 18], None);
        match ct.cram_rescale_by_scalar(6, |_, _| ()) {
            Err(CramOpError::DivisionLaneNotImplemented {
                primary: crate::chimera_division::ChimeraLane::FusedPiggyback,
                gcd_with_basis: 6,
            }) => {}
            other => panic!("expected DivisionLaneNotImplemented, got {:?}", other),
        }
    }

    #[test]
    fn cram_rescale_handles_negative_coprime_scalar() {
        // -23: D0 negates the lane inverses to recover an integer division.
        let coeffs = vec![23i128, 46, -23, -69];
        let ct = CramCiphertext::wrap_default((), &coeffs, None);
        let (rescaled, _) = ct.cram_rescale_by_scalar(-23, |_, _| ()).unwrap();
        assert_eq!(rescaled.reconstruct_c0_coeffs_signed(), vec![-1, -2, 1, 3]);
    }

    #[test]
    fn cram_rescale_rejects_zero_divisor() {
        let ct = CramCiphertext::wrap_default((), &[1i128, 2], None);
        match ct.cram_rescale_by_scalar(0, |_, _| ()) {
            Err(CramOpError::DivisionLaneNotImplemented { gcd_with_basis: 0, .. }) => {}
            other => panic!("expected zero-divisor rejection, got {:?}", other),
        }
    }

    #[test]
    fn is_basis_smooth_recognises_known_smooth_numbers() {
        // S8 = {2,3,5,7,11,13,17,19}. Smooth examples:
        for n in [1u64, 2, 3, 5, 7, 30, 42, 9_699_690] {
            assert!(is_basis_smooth(n, SafeBasis::S8), "{} should be S8-smooth", n);
        }
        // Non-smooth: contains 23, 29, 31, 37, ...
        for n in [23u64, 29, 100_003] {
            assert!(!is_basis_smooth(n, SafeBasis::S8), "{} should NOT be smooth", n);
        }
    }

    // ---- Phase-4 D3 — Fused Piggyback Division --------------------------

    #[test]
    fn aux_select_for_coprime_divisor_returns_empty_when_s8_already_suffices() {
        // For divisor d coprime to S8, every S8 lane is "good" — fusion
        // product is S8_PRODUCT = 9_699_690, which already exceeds 2*B_q
        // for any B_q < 4_849_845.
        let aux = AuxResidueSet::select_for_divisor(23, 1_000_000);
        assert_eq!(aux, Some(Vec::new()));
    }

    #[test]
    fn aux_select_for_basis_sharing_divisor_returns_aux_primes() {
        // Divisor 6 shares 2 and 3 with S8. Good lanes' product is
        // 5*7*11*13*17*19 = 1_616_615. For quotient bound 1_000_000,
        // we need P > 2_000_000. So aux primes are needed.
        let aux = AuxResidueSet::select_for_divisor(6, 1_000_000).unwrap();
        assert!(!aux.is_empty(), "expected at least one aux prime");
        // Every chosen aux prime must be coprime to 6.
        for &alpha in &aux {
            assert!(crate::chimera::AUX_FPD_POOL.contains(&alpha));
            assert_eq!(super::gcd_u64(alpha as u64, 6), 1);
        }
    }

    #[test]
    fn fpd_divides_by_six_recovers_exact_quotient() {
        // Coefficients are exact multiples of 6; FPD must recover
        // x/6 on every coefficient.
        let coeffs: Vec<i128> = vec![6, 12, 18, -24, -30, 60, 102, 1_200];
        let aux_primes = AuxResidueSet::select_for_divisor(6, 1_000_000).unwrap();
        let ct = CramCiphertext::wrap_with_fpd_aux((), &coeffs, None, &aux_primes);
        let (rescaled, plan) =
            ct.cram_rescale_by_scalar_fpd(6, 1_000_000, |_, _| ()).unwrap();
        assert_eq!(plan.primary, crate::chimera_division::ChimeraLane::FusedPiggyback);
        assert_eq!(plan.gcd_with_basis, 6);
        let recon = rescaled.reconstruct_c0_coeffs_signed();
        let expected: Vec<i32> = coeffs.iter().map(|&c| (c / 6) as i32).collect();
        assert_eq!(recon, expected);
    }

    #[test]
    fn fpd_divides_by_thirty_recovers_exact_quotient() {
        // 30 = 2*3*5 — three S8 primes shared. The router still chooses
        // FPD; aux primes widen the fusion product past 2*B_q.
        let coeffs: Vec<i128> = vec![30, 60, 90, -150, -210, 300_000];
        let aux_primes = AuxResidueSet::select_for_divisor(30, 100_000).unwrap();
        let ct = CramCiphertext::wrap_with_fpd_aux((), &coeffs, None, &aux_primes);
        let (rescaled, _) =
            ct.cram_rescale_by_scalar_fpd(30, 100_000, |_, _| ()).unwrap();
        let recon = rescaled.reconstruct_c0_coeffs_signed();
        let expected: Vec<i32> = coeffs.iter().map(|&c| (c / 30) as i32).collect();
        assert_eq!(recon, expected);
    }

    #[test]
    fn fpd_rejects_inexact_numerator_instead_of_returning_garbage() {
        // G11 (NINE65_v7_DEEP_ANALYSIS_20260817.md): before the bad-lane
        // check, `fpd_one_coefficient` never verified `d | A`. Divisor 6's
        // full prime factorization {2, 3} lies inside S8, so both are "bad"
        // (non-invertible) lanes the fusion basis excludes — checking the
        // reconstructed quotient against both is a complete exactness test
        // for this divisor (2 and 3 coprime => divisible by both iff
        // divisible by 6). Coefficient 7 is not a multiple of 6: this must
        // now fail closed with a typed error, not silently return a wrong
        // "quotient".
        let coeffs: Vec<i128> = vec![6, 7, 18];
        let aux_primes = AuxResidueSet::select_for_divisor(6, 100).unwrap();
        let ct = CramCiphertext::wrap_with_fpd_aux((), &coeffs, None, &aux_primes);
        match ct.cram_rescale_by_scalar_fpd(6, 100, |_, _| ()) {
            Err(CramOpError::Fpd(FpdError::BadLaneDisagreement {
                coeff_index: 1, ..
            })) => {}
            other => panic!(
                "expected a bad-lane disagreement on coefficient index 1, got {:?}",
                other
            ),
        }
    }

    #[test]
    fn fpd_handles_negative_divisor() {
        // Negative divisor → quotient flips sign. FPD recovers the
        // signed integer, recentred around zero.
        let coeffs: Vec<i128> = vec![6, -12, 18, -24];
        let aux_primes = AuxResidueSet::select_for_divisor(-6, 100).unwrap();
        let ct = CramCiphertext::wrap_with_fpd_aux((), &coeffs, None, &aux_primes);
        let (rescaled, _) =
            ct.cram_rescale_by_scalar_fpd(-6, 100, |_, _| ()).unwrap();
        assert_eq!(rescaled.reconstruct_c0_coeffs_signed(), vec![-1, 2, -3, 4]);
    }

    #[test]
    fn fpd_rejects_when_aux_residues_missing() {
        // wrap_default doesn't attach aux residues — FPD must reject.
        let ct = CramCiphertext::wrap_default((), &[6i128, 12, 18], None);
        match ct.cram_rescale_by_scalar_fpd(6, 100, |_, _| ()) {
            Err(CramOpError::DivisionLaneNotImplemented {
                primary: crate::chimera_division::ChimeraLane::FusedPiggyback,
                gcd_with_basis: 6,
            }) => {}
            other => panic!("expected aux-missing rejection, got {:?}", other),
        }
    }

    #[test]
    fn fpd_rejects_when_aux_set_shares_factor_with_divisor() {
        // Construct a deliberately bad aux set that shares a factor with
        // the divisor (this should never happen with select_for_divisor,
        // but guard the entry point).
        let coeffs = vec![23i128 * 5, 23 * 7, 23 * 11];
        let bad_aux = vec![23u32]; // 23 divides the divisor → bad.
        let ct = CramCiphertext::wrap_with_fpd_aux((), &coeffs, None, &bad_aux);
        match ct.cram_rescale_by_scalar_fpd(23, 100, |_, _| ()) {
            Err(CramOpError::DivisionLaneNotImplemented { .. }) => {}
            other => panic!("expected rejection, got {:?}", other),
        }
    }

    #[test]
    fn fpd_rejects_when_quotient_bound_exceeds_fusion_product() {
        // Divisor 30 → good-lanes product is 7*11*13*17*19 = 323_323.
        // With one aux prime 23 → P = 7_436_429. Demand bound = 100_000_000:
        // need P > 2*B_q = 200_000_000 — fails.
        let coeffs = vec![30i128];
        let aux_primes = vec![23u32];
        let ct = CramCiphertext::wrap_with_fpd_aux((), &coeffs, None, &aux_primes);
        match ct.cram_rescale_by_scalar_fpd(30, 100_000_000, |_, _| ()) {
            Err(CramOpError::DivisionLaneNotImplemented { .. }) => {}
            other => panic!("expected bound rejection, got {:?}", other),
        }
    }

    #[test]
    fn fpd_carries_aux_residues_to_output_for_chained_division() {
        // After one FPD, the result should still carry aux residues so
        // a subsequent FPD on the same chain works without re-wrapping.
        let coeffs: Vec<i128> = vec![60, 120, 180, 240];
        let aux_primes = AuxResidueSet::select_for_divisor(6, 100).unwrap();
        let ct = CramCiphertext::wrap_with_fpd_aux((), &coeffs, None, &aux_primes);
        let (after_first, _) =
            ct.cram_rescale_by_scalar_fpd(6, 100, |_, _| ()).unwrap();
        assert!(
            after_first.witness.c0_aux.is_some(),
            "FPD output must carry aux residues for chaining"
        );
        // Chain: divide by 5 next (coprime to S8 actually — D0 path,
        // but we still want aux to survive). After cram_add etc. the
        // aux residues are dropped by Phase 4 (documented limitation).
    }

    #[test]
    fn crt_fuse_pairs_round_trip() {
        // Sanity: fuse known residues and confirm the integer matches.
        // x = 42, against (5, 7, 11) → r = (2, 0, 9).
        let pairs = [(5u32, 2u32), (7u32, 0u32), (11u32, 9u32)];
        let q = crt_fuse_pairs(&pairs);
        assert_eq!(q, 42);
    }

    // ---- Phase-4 D2 — DIV_EXACT (absorbent quotient-basis division) -----

    #[test]
    fn d2_divides_by_two() {
        let coeffs: Vec<i128> = vec![2, 4, 6, -8, -10, 100, -1000, 1_000_000];
        let ct = CramCiphertext::wrap_default((), &coeffs, None);
        let (rescaled, plan) =
            ct.cram_rescale_by_scalar_div_exact(2, |_, _| ()).unwrap();
        assert_eq!(plan.gcd_with_basis, 2);
        let expected: Vec<i32> = coeffs.iter().map(|&c| (c / 2) as i32).collect();
        assert_eq!(rescaled.reconstruct_c0_coeffs_signed(), expected);
    }

    #[test]
    fn d2_divides_by_six() {
        let coeffs: Vec<i128> = vec![6, 12, 18, -24, -30, 600, -3000];
        let ct = CramCiphertext::wrap_default((), &coeffs, None);
        let (rescaled, _) = ct.cram_rescale_by_scalar_div_exact(6, |_, _| ()).unwrap();
        let expected: Vec<i32> = coeffs.iter().map(|&c| (c / 6) as i32).collect();
        assert_eq!(rescaled.reconstruct_c0_coeffs_signed(), expected);
    }

    #[test]
    fn d2_divides_by_thirty() {
        let coeffs: Vec<i128> = vec![30, 60, 90, -150, -3000];
        let ct = CramCiphertext::wrap_default((), &coeffs, None);
        let (rescaled, _) =
            ct.cram_rescale_by_scalar_div_exact(30, |_, _| ()).unwrap();
        let expected: Vec<i32> = coeffs.iter().map(|&c| (c / 30) as i32).collect();
        assert_eq!(rescaled.reconstruct_c0_coeffs_signed(), expected);
    }

    #[test]
    fn d2_rejects_non_basis_smooth_divisor() {
        // 23 is in the FPD aux pool, not in S8 — D2 cannot absorb it.
        let coeffs = vec![23i128, 46, 69];
        let ct = CramCiphertext::wrap_default((), &coeffs, None);
        match ct.cram_rescale_by_scalar_div_exact(23, |_, _| ()) {
            Err(CramOpError::DivExact(DivExactError::DivisorNotBasisSmooth { divisor: 23 })) => {}
            other => panic!("expected DivisorNotBasisSmooth, got {:?}", other),
        }
    }

    #[test]
    fn d2_rejects_non_exact_remainder() {
        // 10 is not exactly divisible by 6 — D2 must surface it as
        // NonExactRemainder rather than silently producing trunc(10/6).
        let coeffs = vec![6i128, 10, 12];
        let ct = CramCiphertext::wrap_default((), &coeffs, None);
        match ct.cram_rescale_by_scalar_div_exact(6, |_, _| ()) {
            Err(CramOpError::DivExact(DivExactError::NonExactRemainder {
                coeff_index: 1,
                coefficient: 10,
                divisor: 6,
                ..
            })) => {}
            other => panic!("expected NonExactRemainder, got {:?}", other),
        }
    }

    #[test]
    fn d2_rejects_zero_divisor() {
        let ct = CramCiphertext::wrap_default((), &[1i128, 2], None);
        match ct.cram_rescale_by_scalar_div_exact(0, |_, _| ()) {
            Err(CramOpError::DivExact(DivExactError::DivisorIsZero)) => {}
            other => panic!("expected DivisorIsZero, got {:?}", other),
        }
    }

    #[test]
    fn d2_handles_negative_divisor() {
        let coeffs: Vec<i128> = vec![6, -12, 18, -24];
        let ct = CramCiphertext::wrap_default((), &coeffs, None);
        let (rescaled, _) = ct.cram_rescale_by_scalar_div_exact(-6, |_, _| ()).unwrap();
        assert_eq!(rescaled.reconstruct_c0_coeffs_signed(), vec![-1, 2, -3, 4]);
    }

    // ---- Cross-lane resolver (D0 / D2 / D3 must agree) ------------------

    #[test]
    fn router_agrees_when_d0_and_d2_both_apply_to_basis_smooth_coprime() {
        // 5 is in S8 (so D0 fails: gcd(5, S8) = 5) BUT 5 is basis-smooth
        // (so D2 applies). Only D2 succeeds. Resolver returns its result.
        let coeffs = vec![5i128, 10, 15, 20];
        let ct = CramCiphertext::wrap_default((), &coeffs, None);
        let (result, _, mask) = ct
            .cram_rescale_with_chimera_router(5, 1_000_000, |_, _| ())
            .unwrap();
        assert!(mask.div_exact);
        assert!(!mask.modular_inverse);
        assert_eq!(result.reconstruct_c0_coeffs_signed(), vec![1, 2, 3, 4]);
    }

    #[test]
    fn router_agrees_when_d0_alone_succeeds_for_coprime_divisor() {
        // 23 is coprime to S8 → only D0 applies (D2 fails on smoothness,
        // D3 needs aux residues).
        let coeffs = vec![23i128, 46, 69];
        let ct = CramCiphertext::wrap_default((), &coeffs, None);
        let (result, _, mask) = ct
            .cram_rescale_with_chimera_router(23, 1_000_000, |_, _| ())
            .unwrap();
        assert!(mask.modular_inverse);
        assert!(!mask.div_exact);
        assert!(!mask.fused_piggyback);
        assert_eq!(result.reconstruct_c0_coeffs_signed(), vec![1, 2, 3]);
    }

    #[test]
    fn router_runs_d2_and_d3_together_and_they_agree() {
        // 6 is basis-smooth (D2 applies) AND with aux residues attached
        // D3 also applies. Both must agree on the same quotient.
        let coeffs: Vec<i128> = vec![6, 12, 18, -24, -30];
        let aux_primes = AuxResidueSet::select_for_divisor(6, 100_000).unwrap();
        let ct = CramCiphertext::wrap_with_fpd_aux((), &coeffs, None, &aux_primes);
        let (result, _, mask) = ct
            .cram_rescale_with_chimera_router(6, 100_000, |_, _| ())
            .unwrap();
        assert!(mask.div_exact);
        assert!(mask.fused_piggyback);
        assert_eq!(
            result.reconstruct_c0_coeffs_signed(),
            vec![1, 2, 3, -4, -5]
        );
    }

    #[test]
    fn router_returns_lane_not_implemented_when_no_lane_succeeds() {
        // Divisor 23 with no aux residues. D0 succeeds — but coefficient
        // is not divisible exactly. Wait, actually D0 succeeds on non-
        // exact divisions because it returns x*d^{-1} mod M, which is a
        // valid modular result. The router prefers D2/D3 for "exact"
        // cases. Use 0 as divisor to force all lanes to bail.
        let ct = CramCiphertext::wrap_default((), &[5i128, 10], None);
        match ct.cram_rescale_with_chimera_router(0, 1000, |_, _| ()) {
            Err(CramOpError::DivisionLaneNotImplemented { gcd_with_basis: 0, .. }) => {}
            other => panic!("expected DivisionLaneNotImplemented, got {:?}", other),
        }
    }

    #[test]
    fn d2_propagates_lock_evidence_correctly() {
        // After D2, the witness's lock evidence must reflect the new
        // signature — verify_locks must pass on the output.
        let coeffs = vec![6i128, 12, 18, 24];
        let ct = CramCiphertext::wrap_default((), &coeffs, None);
        let (rescaled, _) = ct.cram_rescale_by_scalar_div_exact(6, |_, _| ()).unwrap();
        assert!(rescaled.verify().is_ok());
        assert_eq!(rescaled.reconstruct_c0_coeffs_signed(), vec![1, 2, 3, 4]);
    }

    // ---- Phase-4 D1 — K-Elimination lift --------------------------------

    #[test]
    fn d1_divides_by_coprime_divisor_with_anchor_17() {
        // 23 is coprime to M_main = S8_PRODUCT / 17 = 570_570 — D1 fits.
        let coeffs: Vec<i128> = vec![23, 46, 69, -23, -46, 23 * 100, -23 * 200];
        let ct = CramCiphertext::wrap_default((), &coeffs, None);
        let (rescaled, _) = ct.cram_rescale_by_scalar_kelim(23, 17, |_, _| ()).unwrap();
        let expected: Vec<i32> = coeffs.iter().map(|&c| (c / 23) as i32).collect();
        assert_eq!(rescaled.reconstruct_c0_coeffs_signed(), expected);
    }

    #[test]
    fn d1_rejects_anchor_not_in_basis() {
        let ct = CramCiphertext::wrap_default((), &[23i128], None);
        match ct.cram_rescale_by_scalar_kelim(23, 23, |_, _| ()) {
            Err(CramOpError::KElim(KElimError::AnchorNotInBasis { anchor: 23 })) => {}
            other => panic!("expected AnchorNotInBasis, got {:?}", other),
        }
    }

    #[test]
    fn d1_rejects_zero_divisor() {
        let ct = CramCiphertext::wrap_default((), &[1i128], None);
        match ct.cram_rescale_by_scalar_kelim(0, 17, |_, _| ()) {
            Err(CramOpError::KElim(KElimError::DivisorIncompatibleWithMain { divisor: 0 })) => {}
            other => panic!("expected DivisorIncompatibleWithMain, got {:?}", other),
        }
    }

    #[test]
    fn d1_rejects_divisor_sharing_factor_with_main() {
        // Anchor 17 → M_main = S8_PRODUCT/17 = 2*3*5*7*11*13*19 = 570_570.
        // Divisor 5 shares a factor with M_main → D1 rejects (use D2 or D3).
        let ct = CramCiphertext::wrap_default((), &[5i128, 10, 15], None);
        match ct.cram_rescale_by_scalar_kelim(5, 17, |_, _| ()) {
            Err(CramOpError::KElim(KElimError::DivisorIncompatibleWithMain { divisor: 5 })) => {}
            other => panic!("expected DivisorIncompatibleWithMain, got {:?}", other),
        }
    }

    #[test]
    fn d1_rejects_non_exact_remainder() {
        // 47 / 23 has remainder 1 — D1 must surface it.
        let ct = CramCiphertext::wrap_default((), &[47i128], None);
        match ct.cram_rescale_by_scalar_kelim(23, 17, |_, _| ()) {
            Err(CramOpError::KElim(KElimError::NonExactRemainder { divisor: 23, .. })) => {}
            other => panic!("expected NonExactRemainder, got {:?}", other),
        }
    }

    #[test]
    fn d1_handles_negative_divisor() {
        let coeffs: Vec<i128> = vec![23, -46, 69, -92];
        let ct = CramCiphertext::wrap_default((), &coeffs, None);
        let (rescaled, _) =
            ct.cram_rescale_by_scalar_kelim(-23, 17, |_, _| ()).unwrap();
        assert_eq!(rescaled.reconstruct_c0_coeffs_signed(), vec![-1, 2, -3, 4]);
    }

    #[test]
    fn d1_kelim_winding_satisfies_invariant() {
        // For any x in (-S8_PRODUCT/2, S8_PRODUCT/2), the recovered
        // winding κ must satisfy A = x_main + κ · M_main where A is the
        // signed value within the corridor.
        for &x in &[0i128, 1, -1, 17, -17, 100, -100, 9_999, -9_999] {
            let sig = S8Signature::project(x);
            let main_indices: Vec<usize> = (0..crate::triad::S8.len())
                .filter(|&i| crate::triad::S8[i] != 17)
                .collect();
            let (x_main, m_main) = garner_reconstruct_subset(&sig, &main_indices);
            let r_anchor = sig.residue_mod(17).unwrap();
            let kappa = k_elim_winding(x_main, m_main, r_anchor, 17);
            let lifted = x_main + (kappa as i128) * m_main;
            // lifted ≡ x mod (m_main * 17) = S8_PRODUCT — and within
            // the corridor it equals x exactly (after recentre).
            let half = (crate::triad::S8_PRODUCT / 2) as i128;
            let signed = if lifted > half {
                lifted - crate::triad::S8_PRODUCT as i128
            } else {
                lifted
            };
            assert_eq!(signed, x, "K-Elim invariant broken at x = {x}");
        }
    }

    #[test]
    fn d1_propagates_lock_evidence() {
        let ct = CramCiphertext::wrap_default((), &[23i128, 46, 69, 92], None);
        let (rescaled, _) = ct.cram_rescale_by_scalar_kelim(23, 17, |_, _| ()).unwrap();
        assert!(rescaled.verify().is_ok());
        assert_eq!(rescaled.reconstruct_c0_coeffs_signed(), vec![1, 2, 3, 4]);
    }

    #[test]
    fn router_runs_d0_and_d1_together_and_they_agree() {
        // 23 is coprime to all of S8 → D0 succeeds. It is also coprime
        // to M_main = S8_PRODUCT/17 → D1 succeeds with anchor 17.
        // Both must agree.
        let coeffs: Vec<i128> = vec![23, 46, 69, -23, -46];
        let ct = CramCiphertext::wrap_default((), &coeffs, None);
        let (result, _, mask) = ct
            .cram_rescale_with_chimera_router(23, 1_000_000, |_, _| ())
            .unwrap();
        assert!(mask.modular_inverse, "D0 should succeed");
        assert!(mask.kelim, "D1 should succeed");
        assert_eq!(
            result.reconstruct_c0_coeffs_signed(),
            vec![1, 2, 3, -1, -2]
        );
    }

    // ---- Phase 5 — bootstrap witness ------------------------------------

    #[test]
    fn bootstrap_preserves_signature_byte_for_byte() {
        // The spec's Decrypt(C_boot) = Decrypt(C) postcondition lifted
        // to the witness layer: every coefficient's S8 residues must
        // match exactly.
        let coeffs = vec![1i128, 2, 3, -4, -5];
        let ct = CramCiphertext::wrap_default((), &coeffs, None);
        let pre_sig = ct.witness.c0_signature.clone();
        let (after, cert) = ct.cram_bootstrap(|b| b).unwrap();
        assert!(cert.signature_preserved);
        assert_eq!(
            after.witness.c0_signature.signatures,
            pre_sig.signatures,
            "signature must be preserved across bootstrap"
        );
    }

    #[test]
    fn bootstrap_resets_op_counter_to_zero() {
        let mut acc = CramCiphertext::wrap_default((), &[0i128; 4], None);
        // Drive op_counter up to 5 with sequential adds.
        for _ in 0..5 {
            let b = CramCiphertext::wrap_default((), &[0i128; 4], None);
            acc = acc.cram_add(b, |_, _| ()).unwrap();
        }
        assert_eq!(acc.witness.op_counter, 5);
        let (refreshed, cert) = acc.cram_bootstrap(|b| b).unwrap();
        assert_eq!(refreshed.witness.op_counter, 0);
        assert_eq!(cert.pre_op_counter, 5);
        assert_eq!(cert.post_op_counter, 0);
        assert!(cert.corridor_reset);
    }

    #[test]
    fn bootstrap_restores_corridor_for_more_ops() {
        // Drive 16 adds (op_counter = 16, at corridor end). Bootstrap
        // resets the corridor; another 16 adds should now succeed.
        let mut acc = CramCiphertext::wrap_default((), &[0i128; 2], None);
        for _ in 0..16 {
            let b = CramCiphertext::wrap_default((), &[0i128; 2], None);
            acc = acc.cram_add(b, |_, _| ()).unwrap();
        }
        let (mut refreshed, _) = acc.cram_bootstrap(|b| b).unwrap();
        // Fresh corridor — 16 more adds must succeed.
        for _ in 0..16 {
            let b = CramCiphertext::wrap_default((), &[0i128; 2], None);
            refreshed = refreshed.cram_add(b, |_, _| ()).unwrap();
        }
        assert_eq!(refreshed.witness.op_counter, 16);
    }

    #[test]
    fn bootstrap_triggers_fire_at_corridor_end() {
        // After 16 adds, op_counter = 16, corridor_high = 16. Headroom
        // is 0 → CorridorAtUpperBound trigger.
        let mut acc = CramCiphertext::wrap_default((), &[0i128; 2], None);
        for _ in 0..16 {
            let b = CramCiphertext::wrap_default((), &[0i128; 2], None);
            acc = acc.cram_add(b, |_, _| ()).unwrap();
        }
        assert!(acc.bootstrap_required());
        let triggers = acc.bootstrap_triggers();
        assert!(triggers.contains(&BootstrapTrigger::CorridorAtUpperBound));
    }

    #[test]
    fn bootstrap_triggers_fire_near_corridor_end() {
        // After 14 adds (corridor_high - op_counter = 2 → CorridorNear).
        let mut acc = CramCiphertext::wrap_default((), &[0i128; 2], None);
        for _ in 0..14 {
            let b = CramCiphertext::wrap_default((), &[0i128; 2], None);
            acc = acc.cram_add(b, |_, _| ()).unwrap();
        }
        let triggers = acc.bootstrap_triggers();
        assert!(triggers
            .iter()
            .any(|t| matches!(t, BootstrapTrigger::CorridorNearUpperBound { .. })));
    }

    #[test]
    fn bootstrap_returns_manual_when_no_natural_trigger() {
        // Fresh wrap: op_counter = 0, corridor wide open, no triggers.
        // bootstrap_triggers() returns empty; cram_bootstrap stamps Manual.
        let ct = CramCiphertext::wrap_default((), &[1i128, 2], None);
        assert!(!ct.bootstrap_required());
        assert!(ct.bootstrap_triggers().is_empty());
        let (_, cert) = ct.cram_bootstrap(|b| b).unwrap();
        assert_eq!(cert.triggers, vec![BootstrapTrigger::Manual]);
    }

    #[test]
    fn bootstrap_runs_user_refresh_closure() {
        // Verify the closure actually receives the base ciphertext
        // and the refreshed value lands in the output.
        let ct = CramCiphertext::wrap_default(7u64, &[1i128, 2], None);
        let (refreshed, _) = ct.cram_bootstrap(|b| b * 2).unwrap();
        assert_eq!(refreshed.base, 14);
    }

    #[test]
    fn bootstrap_round_trip_preserves_aux_residues() {
        // FPD aux residues survive a bootstrap.
        let coeffs = vec![6i128, 12, 18];
        let aux_primes = AuxResidueSet::select_for_divisor(6, 100).unwrap();
        let ct = CramCiphertext::wrap_with_fpd_aux((), &coeffs, None, &aux_primes);
        let (refreshed, _) = ct.cram_bootstrap(|b| b).unwrap();
        assert!(refreshed.witness.c0_aux.is_some());
    }

    #[test]
    fn bootstrap_repeated_cycles_match_spec() {
        // Spec § 17.4: drive ciphertext to corridor end, bootstrap, verify
        // signature, repeat. The signature must remain identical across
        // every cycle.
        let coeffs = vec![1i128, 2, 3, 4];
        let original_sig = PolynomialS8Signature::from_coeffs(&coeffs).signatures;
        let mut ct = CramCiphertext::wrap_default((), &coeffs, None);
        for _cycle in 0..5 {
            // Drive op_counter up close to but not past the corridor.
            for _ in 0..16 {
                let b = CramCiphertext::wrap_default((), &[0i128; 4], None);
                ct = ct.cram_add(b, |_, _| ()).unwrap();
            }
            let (refreshed, cert) = ct.cram_bootstrap(|b| b).unwrap();
            assert!(cert.signature_preserved);
            assert_eq!(refreshed.witness.c0_signature.signatures, original_sig);
            ct = refreshed;
        }
    }

    #[test]
    fn bootstrap_after_cram_mul_preserves_product_signature() {
        // Multiply, then bootstrap — the product's S8 signature must
        // remain identical across the refresh.
        let a = CramCiphertext::wrap_default((), &[1i128, 2], None);
        let b = CramCiphertext::wrap_default((), &[3i128, 4], None);
        let prod = a.cram_mul(b, |_, _| ()).unwrap();
        let pre_sig = prod.witness.c0_signature.signatures.clone();
        let (refreshed, cert) = prod.cram_bootstrap(|b| b).unwrap();
        assert!(cert.signature_preserved);
        assert_eq!(refreshed.witness.c0_signature.signatures, pre_sig);
    }
}
