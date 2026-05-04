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
use crate::lane_projector::{mod_inv_u32, PolynomialS8Signature, S8Signature};
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
            },
        };
        out.verify().map_err(CramOpError::OutputVerifyFailed)?;
        Ok(out)
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
}
