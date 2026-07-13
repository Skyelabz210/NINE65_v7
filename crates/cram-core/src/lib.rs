#![forbid(unsafe_code)]
#![deny(clippy::float_arithmetic)]
#![deny(clippy::float_cmp)]

//! Canonical residue-native CRAM state and architectural instrumentation.
//!
//! Production execution must remain in residue space. Number-line projection is
//! restricted to explicit user/protocol output. Garner, mixed-radix digits,
//! internal CRT reconstruction, and hidden scalar state are prohibited.

use core::fmt;
use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct FrameId(pub u64);

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct LaneId(pub u16);

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct LineageDigest(pub [u8; 32]);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DomainState {
    Coefficient,
    Ntt,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProjectionCapability {
    UserOutput,
    ProtocolOutput,
    TestOracle,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CramError {
    EmptyBasis,
    InvalidModulus { index: usize, modulus: u64 },
    DuplicateOrNonCoprimeModuli { left: usize, right: usize },
    LaneCountMismatch { expected: usize, actual: usize },
    NonCanonicalResidue { lane: usize, residue: u64, modulus: u64 },
    TopologyLaneMismatch,
    UnauthorizedProjection,
}

impl fmt::Display for CramError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for CramError {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BasisFrame {
    moduli: Box<[u64]>,
}

impl BasisFrame {
    pub fn try_new(moduli: Vec<u64>) -> Result<Self, CramError> {
        if moduli.is_empty() {
            return Err(CramError::EmptyBasis);
        }
        for (index, &modulus) in moduli.iter().enumerate() {
            if modulus < 2 {
                return Err(CramError::InvalidModulus { index, modulus });
            }
        }
        for left in 0..moduli.len() {
            for right in (left + 1)..moduli.len() {
                if gcd(moduli[left], moduli[right]) != 1 {
                    return Err(CramError::DuplicateOrNonCoprimeModuli { left, right });
                }
            }
        }
        Ok(Self { moduli: moduli.into_boxed_slice() })
    }

    pub fn moduli(&self) -> &[u64] {
        &self.moduli
    }

    pub fn lane_count(&self) -> usize {
        self.moduli.len()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResidueLane {
    pub lane_id: LaneId,
    pub modulus: u64,
    pub residue: u64,
}

impl ResidueLane {
    pub fn try_new(lane_id: LaneId, modulus: u64, residue: u64) -> Result<Self, CramError> {
        if modulus < 2 {
            return Err(CramError::InvalidModulus { index: lane_id.0 as usize, modulus });
        }
        if residue >= modulus {
            return Err(CramError::NonCanonicalResidue {
                lane: lane_id.0 as usize,
                residue,
                modulus,
            });
        }
        Ok(Self { lane_id, modulus, residue })
    }

    pub fn add(self, rhs: Self) -> Result<Self, CramError> {
        self.compatible(rhs)?;
        let sum = self.residue as u128 + rhs.residue as u128;
        Ok(Self { residue: (sum % self.modulus as u128) as u64, ..self })
    }

    pub fn sub(self, rhs: Self) -> Result<Self, CramError> {
        self.compatible(rhs)?;
        let residue = if self.residue >= rhs.residue {
            self.residue - rhs.residue
        } else {
            self.modulus - (rhs.residue - self.residue)
        };
        Ok(Self { residue, ..self })
    }

    pub fn mul(self, rhs: Self) -> Result<Self, CramError> {
        self.compatible(rhs)?;
        let product = self.residue as u128 * rhs.residue as u128;
        Ok(Self { residue: (product % self.modulus as u128) as u64, ..self })
    }

    fn compatible(self, rhs: Self) -> Result<(), CramError> {
        if self.lane_id != rhs.lane_id || self.modulus != rhs.modulus {
            return Err(CramError::TopologyLaneMismatch);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LaneOperator {
    Add,
    Sub,
    Mul,
    Div,
    Sqr,
    Neg,
    Inv,
    Identity,
    Transduce(u32),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OperatorTopology {
    assignments: Box<[(LaneId, LaneOperator)]>,
}

impl OperatorTopology {
    pub fn try_new(assignments: Vec<(LaneId, LaneOperator)>, lane_count: usize) -> Result<Self, CramError> {
        if assignments.len() != lane_count {
            return Err(CramError::TopologyLaneMismatch);
        }
        let mut seen = vec![false; lane_count];
        for (lane, _) in &assignments {
            let index = lane.0 as usize;
            if index >= lane_count || seen[index] {
                return Err(CramError::TopologyLaneMismatch);
            }
            seen[index] = true;
        }
        Ok(Self { assignments: assignments.into_boxed_slice() })
    }

    pub fn assignments(&self) -> &[(LaneId, LaneOperator)] {
        &self.assignments
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WindingState {
    /// Finite active support only. Each cell remains exact integer state.
    pub cells: Box<[i128]>,
    pub generation: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ShadowState {
    pub residues: Box<[u64]>,
    pub integrity_epoch: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BoundCertificate {
    pub height_bits: u32,
    pub guard_bits: u32,
}

impl BoundCertificate {
    pub fn for_add(left: Self, right: Self) -> Self {
        Self {
            height_bits: left.height_bits.max(right.height_bits).saturating_add(1),
            guard_bits: left.guard_bits.max(right.guard_bits),
        }
    }

    pub fn for_mul(left: Self, right: Self) -> Self {
        Self {
            height_bits: left.height_bits.saturating_add(right.height_bits),
            guard_bits: left.guard_bits.max(right.guard_bits),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CramState {
    pub basis: BasisFrame,
    pub lanes: Box<[ResidueLane]>,
    pub winding: WindingState,
    pub shadow: ShadowState,
    pub bounds: BoundCertificate,
    pub topology: OperatorTopology,
    pub frame: FrameId,
    pub lineage: LineageDigest,
    pub domain: DomainState,
}

impl CramState {
    #[allow(clippy::too_many_arguments)]
    pub fn try_new(
        basis: BasisFrame,
        lanes: Vec<ResidueLane>,
        winding: WindingState,
        shadow: ShadowState,
        bounds: BoundCertificate,
        topology: OperatorTopology,
        frame: FrameId,
        lineage: LineageDigest,
        domain: DomainState,
    ) -> Result<Self, CramError> {
        if lanes.len() != basis.lane_count() {
            return Err(CramError::LaneCountMismatch { expected: basis.lane_count(), actual: lanes.len() });
        }
        for (index, lane) in lanes.iter().enumerate() {
            if lane.lane_id.0 as usize != index || lane.modulus != basis.moduli()[index] {
                return Err(CramError::TopologyLaneMismatch);
            }
            if lane.residue >= lane.modulus {
                return Err(CramError::NonCanonicalResidue {
                    lane: index,
                    residue: lane.residue,
                    modulus: lane.modulus,
                });
            }
        }
        if topology.assignments().len() != basis.lane_count() {
            return Err(CramError::TopologyLaneMismatch);
        }
        Ok(Self {
            basis,
            lanes: lanes.into_boxed_slice(),
            winding,
            shadow,
            bounds,
            topology,
            frame,
            lineage,
            domain,
        })
    }
}

#[derive(Default)]
pub struct ArchitectureCounters {
    pub internal_projections: AtomicU64,
    pub crt_reconstructions: AtomicU64,
    pub scalar_materializations: AtomicU64,
    pub garner_calls: AtomicU64,
    pub mixed_radix_calls: AtomicU64,
    pub transductions: AtomicU64,
    pub user_io_projections: AtomicU64,
    pub oracle_projections: AtomicU64,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ArchitectureSnapshot {
    pub internal_projections: u64,
    pub crt_reconstructions: u64,
    pub scalar_materializations: u64,
    pub garner_calls: u64,
    pub mixed_radix_calls: u64,
    pub transductions: u64,
    pub user_io_projections: u64,
    pub oracle_projections: u64,
}

impl ArchitectureCounters {
    pub fn snapshot(&self) -> ArchitectureSnapshot {
        ArchitectureSnapshot {
            internal_projections: self.internal_projections.load(Ordering::Relaxed),
            crt_reconstructions: self.crt_reconstructions.load(Ordering::Relaxed),
            scalar_materializations: self.scalar_materializations.load(Ordering::Relaxed),
            garner_calls: self.garner_calls.load(Ordering::Relaxed),
            mixed_radix_calls: self.mixed_radix_calls.load(Ordering::Relaxed),
            transductions: self.transductions.load(Ordering::Relaxed),
            user_io_projections: self.user_io_projections.load(Ordering::Relaxed),
            oracle_projections: self.oracle_projections.load(Ordering::Relaxed),
        }
    }

    pub fn assert_production_clean(&self) -> Result<(), ArchitectureSnapshot> {
        let snapshot = self.snapshot();
        if snapshot.internal_projections == 0
            && snapshot.crt_reconstructions == 0
            && snapshot.scalar_materializations == 0
            && snapshot.garner_calls == 0
            && snapshot.mixed_radix_calls == 0
        {
            Ok(())
        } else {
            Err(snapshot)
        }
    }

    pub fn record_projection(&self, capability: ProjectionCapability) {
        match capability {
            ProjectionCapability::UserOutput | ProjectionCapability::ProtocolOutput => {
                self.user_io_projections.fetch_add(1, Ordering::Relaxed);
            }
            ProjectionCapability::TestOracle => {
                self.oracle_projections.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}

pub const fn gcd(mut left: u64, mut right: u64) -> u64 {
    while right != 0 {
        let remainder = left % right;
        left = right;
        right = remainder;
    }
    left
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basis_rejects_non_coprime_moduli() {
        assert!(matches!(
            BasisFrame::try_new(vec![6, 9]),
            Err(CramError::DuplicateOrNonCoprimeModuli { .. })
        ));
    }

    #[test]
    fn lane_arithmetic_is_exact_and_canonical() {
        let left = ResidueLane::try_new(LaneId(0), 13, 12).unwrap();
        let right = ResidueLane::try_new(LaneId(0), 13, 5).unwrap();
        assert_eq!(left.add(right).unwrap().residue, 4);
        assert_eq!(left.sub(right).unwrap().residue, 7);
        assert_eq!(left.mul(right).unwrap().residue, 8);
    }

    #[test]
    fn architecture_gate_detects_prohibited_activity() {
        let counters = ArchitectureCounters::default();
        assert!(counters.assert_production_clean().is_ok());
        counters.internal_projections.fetch_add(1, Ordering::Relaxed);
        assert!(counters.assert_production_clean().is_err());
    }

    #[test]
    fn authorized_projection_does_not_mark_internal_projection() {
        let counters = ArchitectureCounters::default();
        counters.record_projection(ProjectionCapability::UserOutput);
        assert_eq!(counters.snapshot().user_io_projections, 1);
        assert!(counters.assert_production_clean().is_ok());
    }
}
