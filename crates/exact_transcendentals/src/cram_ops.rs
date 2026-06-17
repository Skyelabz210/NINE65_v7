//! CRAM Operators — the eight algebraic atoms and the Schema engine.
//!
//! Each residue lane in a CRAM topology carries one of eight operators,
//! applied independently and in parallel. A Schema assigns one operator
//! per lane and is validated at construction time: `deg(Σ) < ρ(B)` (D-002).
//!
//! This is Axis A of CRAM: the configurable distortion that breaks the CRT
//! homomorphism deliberately and exactly.
//!
//! Zero floating point. All arithmetic exact integer (A1).

#[cfg(not(feature = "std"))]
use alloc::{string::String, vec::Vec};
#[cfg(feature = "std")]
use std::{string::String, vec::Vec};

use core::fmt;

use crate::k_elim;

// ═══════════════════════════════════════════════════════════════════════════
// Error types (D-006, D-007, D-002, D-004)
// ═══════════════════════════════════════════════════════════════════════════

/// CRAM operation errors — never silently swallowed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CramOpError {
    /// D-006: Division by non-invertible element.
    DivByNonInvertible {
        a: u64,
        b: u64,
        modulus: u64,
        gcd: u64,
    },
    /// D-007: Inverse of non-invertible element.
    InvNonInvertible {
        a: u64,
        modulus: u64,
        gcd: u64,
    },
    /// D-002: Schema degree exceeds resonance order.
    DegreeViolation {
        max_degree: u32,
        rho: u64,
        schema: String,
    },
    /// D-004: Non-coprime moduli in basis.
    NonCoprimeBasis {
        m1: u64,
        m2: u64,
        gcd: u64,
    },
}

impl fmt::Display for CramOpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DivByNonInvertible { a, b, modulus, gcd } => write!(
                f,
                "D-006: Div({a}, {b}, mod {modulus}) failed: gcd(b,p)={gcd}"
            ),
            Self::InvNonInvertible { a, modulus, gcd } => {
                write!(f, "D-007: Inv({a}, mod {modulus}) failed: gcd(a,p)={gcd}")
            }
            Self::DegreeViolation {
                max_degree,
                rho,
                schema,
            } => write!(
                f,
                "D-002: Schema '{schema}' has max degree {max_degree} >= rho = {rho}"
            ),
            Self::NonCoprimeBasis { m1, m2, gcd } => {
                write!(f, "D-004: Moduli {m1} and {m2} share factor {gcd}")
            }
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// The eight operators
// ═══════════════════════════════════════════════════════════════════════════

/// The 8 CRAM root operators (Def 2.1 of the formal specification).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CramOp {
    Add, // (a + b) mod p       deg 1, binary
    Sub, // (a - b) mod p       deg 1, binary
    Mul, // (a * b) mod p       deg 2, binary
    Div, // a * b^{-1} mod p    deg 2, binary (D-006)
    Sqr, // a^2 mod p           deg 2, unary
    Neg, // (p - a) mod p       deg 1, unary (involution)
    Inv, // a^{-1} mod p        deg 2*, unary (D-007)
    Id,  // a                   deg 1, unary
}

impl CramOp {
    /// Algebraic degree of the operator (DKAM-effective).
    /// Inv has Fermat degree p-2 but effective DKAM degree is capped at 2.
    pub fn degree(self) -> u32 {
        match self {
            Self::Add | Self::Sub | Self::Neg | Self::Id => 1,
            Self::Mul | Self::Div | Self::Sqr | Self::Inv => 2,
        }
    }

    /// Whether this operator uses the second input b.
    pub fn is_binary(self) -> bool {
        matches!(self, Self::Add | Self::Sub | Self::Mul | Self::Div)
    }

    /// Whether this operator is an involution (applying twice = identity).
    pub fn is_involution(self) -> bool {
        matches!(self, Self::Neg | Self::Inv)
    }

    /// Single-character code for schema notation.
    pub fn code(self) -> char {
        match self {
            Self::Add => 'A',
            Self::Sub => 'S',
            Self::Mul => 'M',
            Self::Div => 'D',
            Self::Sqr => 'Q',
            Self::Neg => 'N',
            Self::Inv => 'I',
            Self::Id => '_',
        }
    }

    /// Parse a single operator code character.
    pub fn from_code(c: char) -> Option<Self> {
        match c {
            'A' => Some(Self::Add),
            'S' => Some(Self::Sub),
            'M' => Some(Self::Mul),
            'D' => Some(Self::Div),
            'Q' => Some(Self::Sqr),
            'N' => Some(Self::Neg),
            'I' => Some(Self::Inv),
            '_' => Some(Self::Id),
            _ => None,
        }
    }

    /// Apply operator to inputs (a, b) mod p.
    /// Returns `Ok(result)` or `Err(CramOpError)` for non-invertible cases.
    /// NEVER silently passes through (D-006, D-007).
    pub fn apply(self, a: u64, b: u64, p: u64) -> Result<u64, CramOpError> {
        match self {
            Self::Add => Ok(((a as u128 + b as u128) % p as u128) as u64),
            Self::Sub => Ok(((a as u128 + p as u128 - b as u128) % p as u128) as u64),
            Self::Mul => Ok(((a as u128 * b as u128) % p as u128) as u64),
            Self::Div => {
                if b == 0 {
                    return Err(CramOpError::DivByNonInvertible {
                        a,
                        b,
                        modulus: p,
                        gcd: p,
                    });
                }
                let g = gcd_u64(b, p);
                if g != 1 {
                    return Err(CramOpError::DivByNonInvertible {
                        a,
                        b,
                        modulus: p,
                        gcd: g,
                    });
                }
                let b_inv = mod_pow_u64(b, p - 2, p);
                Ok(((a as u128 * b_inv as u128) % p as u128) as u64)
            }
            Self::Sqr => Ok(((a as u128 * a as u128) % p as u128) as u64),
            Self::Neg => Ok((p - a) % p),
            Self::Inv => {
                if a == 0 {
                    return Err(CramOpError::InvNonInvertible {
                        a,
                        modulus: p,
                        gcd: p,
                    });
                }
                let g = gcd_u64(a, p);
                if g != 1 {
                    return Err(CramOpError::InvNonInvertible {
                        a,
                        modulus: p,
                        gcd: g,
                    });
                }
                Ok(mod_pow_u64(a, p - 2, p))
            }
            Self::Id => Ok(a),
        }
    }
}

impl fmt::Display for CramOp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.code())
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Schema — Per-Lane Operator Assignment (D-002)
// ═══════════════════════════════════════════════════════════════════════════

/// A CRAM schema: one operator per lane.
/// Validated at construction: `max_degree < ρ(basis)`.
#[derive(Debug, Clone)]
pub struct Schema {
    ops: Vec<CramOp>,
    moduli: Vec<u64>,
    max_degree: u32,
    rho: u64,
}

impl Schema {
    /// Construct a schema with degree validation (D-002).
    /// Returns `Err` if `max(deg(op_i)) >= ρ(basis)` or moduli are not coprime.
    pub fn new(ops: &[CramOp], moduli: &[u64]) -> Result<Self, CramOpError> {
        assert_eq!(ops.len(), moduli.len(), "One operator per lane");

        // D-004: Check pairwise coprimality.
        for i in 0..moduli.len() {
            for j in (i + 1)..moduli.len() {
                let g = gcd_u64(moduli[i], moduli[j]);
                if g > 1 {
                    return Err(CramOpError::NonCoprimeBasis {
                        m1: moduli[i],
                        m2: moduli[j],
                        gcd: g,
                    });
                }
            }
        }

        let rho = *moduli.iter().min().unwrap_or(&0);
        let max_degree = ops.iter().map(|op| op.degree()).max().unwrap_or(0);

        // D-002: Degree validation.
        if max_degree as u64 >= rho {
            let schema_str: String = ops.iter().map(|op| op.code()).collect();
            return Err(CramOpError::DegreeViolation {
                max_degree,
                rho,
                schema: schema_str,
            });
        }

        Ok(Schema {
            ops: ops.to_vec(),
            moduli: moduli.to_vec(),
            max_degree,
            rho,
        })
    }

    /// Apply schema to inputs (a, b) across all lanes.
    /// Returns the residue vector or the FIRST error encountered.
    pub fn apply(&self, a: &[u64], b: &[u64]) -> Result<Vec<u64>, CramOpError> {
        assert_eq!(a.len(), self.ops.len());
        assert_eq!(b.len(), self.ops.len());

        let mut result = Vec::with_capacity(self.ops.len());
        for i in 0..self.ops.len() {
            result.push(self.ops[i].apply(a[i], b[i], self.moduli[i])?);
        }
        Ok(result)
    }

    /// Schema notation string (e.g., "AAMM_").
    pub fn notation(&self) -> String {
        self.ops.iter().map(|op| op.code()).collect()
    }

    /// Number of lanes.
    pub fn lanes(&self) -> usize {
        self.ops.len()
    }

    /// Maximum operator degree in this schema.
    pub fn max_deg(&self) -> u32 {
        self.max_degree
    }

    /// Resonance order of the basis.
    pub fn rho(&self) -> u64 {
        self.rho
    }

    /// The operators in this schema.
    pub fn ops(&self) -> &[CramOp] {
        &self.ops
    }

    /// The moduli of this schema's basis.
    pub fn moduli(&self) -> &[u64] {
        &self.moduli
    }

    /// Reconstruct the result of `apply()` to an integer via Garner.
    pub fn apply_and_reconstruct(
        &self,
        a: &[u64],
        b: &[u64],
    ) -> Result<i128, CramOpError> {
        let residues = self.apply(a, b)?;
        let pairs: Vec<(i128, i128)> = residues
            .iter()
            .zip(self.moduli.iter())
            .map(|(&r, &m)| (r as i128, m as i128))
            .collect();
        Ok(k_elim::garner_reconstruct(&pairs).unwrap_or(0))
    }
}

impl fmt::Display for Schema {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Schema[{}] deg={} rho={}",
            self.notation(),
            self.max_degree,
            self.rho
        )
    }
}

/// Parse a schema from a notation string (e.g., "AAMM_") and moduli.
pub fn parse_schema(notation: &str, moduli: &[u64]) -> Result<Schema, CramOpError> {
    let ops: Vec<CramOp> = notation
        .chars()
        .map(|c| CramOp::from_code(c).unwrap_or_else(|| panic!("Unknown operator code: {c}")))
        .collect();
    Schema::new(&ops, moduli)
}

// ═══════════════════════════════════════════════════════════════════════════
// Carry pattern extraction
// ═══════════════════════════════════════════════════════════════════════════

/// Extract the Sqr carry signature on discriminating lanes {7, 11, 13}.
/// Returns `(carry_7, carry_11, carry_13)` where carry = 1 if `a² >= p`.
pub fn sqr_carry_signature(value: u64) -> (u8, u8, u8) {
    let r7 = value % 7;
    let r11 = value % 11;
    let r13 = value % 13;
    (
        if r7 * r7 >= 7 { 1 } else { 0 },
        if r11 * r11 >= 11 { 1 } else { 0 },
        if r13 * r13 >= 13 { 1 } else { 0 },
    )
}

/// Lane validity: for a Div/Inv lane mod p, the fraction of defined inputs
/// is `(p-1)/p`. Returns `(numerator, denominator)`.
pub fn lane_validity(p: u64) -> (u64, u64) {
    (p - 1, p)
}

/// Global validity product for a schema: ∏_{div/inv lanes} (p_i - 1)/p_i.
/// Returns `(numerator, denominator)` in unreduced form.
pub fn schema_validity(schema: &Schema) -> (u64, u64) {
    let mut num = 1u64;
    let mut den = 1u64;
    for (op, &p) in schema.ops().iter().zip(schema.moduli().iter()) {
        if matches!(op, CramOp::Div | CramOp::Inv) {
            num *= p - 1;
            den *= p;
        }
    }
    (num, den)
}

// ═══════════════════════════════════════════════════════════════════════════
// Utility functions (u64-domain, self-contained)
// ═══════════════════════════════════════════════════════════════════════════

fn gcd_u64(a: u64, b: u64) -> u64 {
    let (mut a, mut b) = (a, b);
    while b != 0 {
        let t = b;
        b = a % b;
        a = t;
    }
    a
}

fn mod_pow_u64(mut base: u64, mut exp: u64, modulus: u64) -> u64 {
    if modulus == 1 {
        return 0;
    }
    let mut result: u128 = 1;
    let m = modulus as u128;
    base %= modulus;
    let mut b = base as u128;
    while exp > 0 {
        if exp % 2 == 1 {
            result = result * b % m;
        }
        exp >>= 1;
        if exp > 0 {
            b = b * b % m;
        }
    }
    result as u64
}

// ═══════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    const SAFE_BASIS_5: [u64; 5] = [3, 5, 7, 11, 13];
    const S8: [u64; 8] = [2, 3, 5, 7, 11, 13, 17, 19];

    // --- Operator basics ---

    #[test]
    fn op_add() {
        assert_eq!(CramOp::Add.apply(3, 4, 7).unwrap(), 0); // 3+4=7≡0
    }

    #[test]
    fn op_sub() {
        assert_eq!(CramOp::Sub.apply(3, 5, 7).unwrap(), 5); // 3-5≡-2≡5
    }

    #[test]
    fn op_mul() {
        assert_eq!(CramOp::Mul.apply(3, 4, 7).unwrap(), 5); // 12≡5
    }

    #[test]
    fn op_sqr() {
        assert_eq!(CramOp::Sqr.apply(5, 0, 7).unwrap(), 4); // 25≡4
    }

    #[test]
    fn op_neg() {
        assert_eq!(CramOp::Neg.apply(3, 0, 7).unwrap(), 4); // 7-3=4
    }

    #[test]
    fn op_id() {
        assert_eq!(CramOp::Id.apply(42, 99, 101).unwrap(), 42);
    }

    #[test]
    fn op_div_exact() {
        // 3 / 4 mod 7: 4^{-1} mod 7 = 2 (4·2=8≡1), so 3·2=6
        assert_eq!(CramOp::Div.apply(3, 4, 7).unwrap(), 6);
    }

    #[test]
    fn op_inv_exact() {
        assert_eq!(CramOp::Inv.apply(4, 0, 7).unwrap(), 2); // 4^{-1}≡2
    }

    // --- D-006: Div error handling ---

    #[test]
    fn div_by_zero_returns_error() {
        let err = CramOp::Div.apply(5, 0, 7);
        assert!(err.is_err());
        match err.unwrap_err() {
            CramOpError::DivByNonInvertible { b: 0, .. } => {}
            e => panic!("Expected DivByNonInvertible, got {e:?}"),
        }
    }

    #[test]
    fn div_non_invertible() {
        // b=3, p=6 → gcd(3,6)=3
        let err = CramOp::Div.apply(1, 3, 6);
        assert!(err.is_err());
    }

    // --- D-007: Inv error handling ---

    #[test]
    fn inv_zero_returns_error() {
        let err = CramOp::Inv.apply(0, 0, 7);
        assert!(err.is_err());
    }

    // --- Operator properties ---

    #[test]
    fn degrees_correct() {
        assert_eq!(CramOp::Add.degree(), 1);
        assert_eq!(CramOp::Mul.degree(), 2);
        assert_eq!(CramOp::Inv.degree(), 2); // effective DKAM cap
        assert_eq!(CramOp::Id.degree(), 1);
    }

    #[test]
    fn involution_property() {
        // Neg is an involution: Neg(Neg(x)) = x
        for x in 0..7u64 {
            let y = CramOp::Neg.apply(x, 0, 7).unwrap();
            assert_eq!(CramOp::Neg.apply(y, 0, 7).unwrap(), x);
        }
    }

    #[test]
    fn code_roundtrip() {
        for op in [
            CramOp::Add,
            CramOp::Sub,
            CramOp::Mul,
            CramOp::Div,
            CramOp::Sqr,
            CramOp::Neg,
            CramOp::Inv,
            CramOp::Id,
        ] {
            assert_eq!(CramOp::from_code(op.code()), Some(op));
        }
    }

    // --- Schema construction ---

    #[test]
    fn schema_valid_transport_core() {
        // Transport Core {3,7,11,13}: ρ=3, all ops have deg≤2 → valid
        let ops = [CramOp::Mul, CramOp::Mul, CramOp::Sqr, CramOp::Id];
        let moduli = [3u64, 7, 11, 13];
        let schema = Schema::new(&ops, &moduli).unwrap();
        assert_eq!(schema.max_deg(), 2);
        assert_eq!(schema.rho(), 3);
        assert_eq!(schema.notation(), "MMQ_");
    }

    #[test]
    fn schema_d002_violation() {
        // Basis {2,3}: ρ=2, Mul has deg 2 → deg >= ρ → rejected
        let err = Schema::new(&[CramOp::Mul, CramOp::Add], &[2, 3]);
        assert!(err.is_err());
        match err.unwrap_err() {
            CramOpError::DegreeViolation { max_degree: 2, rho: 2, .. } => {}
            e => panic!("Expected DegreeViolation, got {e:?}"),
        }
    }

    #[test]
    fn schema_d004_non_coprime() {
        let err = Schema::new(&[CramOp::Add, CramOp::Add], &[6, 9]);
        assert!(err.is_err());
        match err.unwrap_err() {
            CramOpError::NonCoprimeBasis { gcd: 3, .. } => {}
            e => panic!("Expected NonCoprimeBasis, got {e:?}"),
        }
    }

    // --- Schema execution ---

    #[test]
    fn schema_apply_homogeneous_add() {
        let ops = [CramOp::Add; 5];
        let schema = Schema::new(&ops, &SAFE_BASIS_5).unwrap();
        let a = [1u64, 2, 3, 4, 5];
        let b = [2u64, 3, 4, 5, 6];
        let result = schema.apply(&a, &b).unwrap();
        // Homogeneous Add: each lane is (a+b) mod p
        assert_eq!(result, vec![0, 0, 0, 9, 11]); // 3%3=0, 5%5=0, 7%7=0, 9, 11
    }

    #[test]
    fn schema_apply_heterogeneous() {
        // Heterogeneous: Add on lane 0, Mul on lane 1
        let ops = [CramOp::Add, CramOp::Mul, CramOp::Id];
        let moduli = [3u64, 7, 11];
        let schema = Schema::new(&ops, &moduli).unwrap();
        let a = [2u64, 3, 5];
        let b = [1u64, 4, 0];
        let result = schema.apply(&a, &b).unwrap();
        assert_eq!(result[0], 0); // (2+1) % 3 = 0
        assert_eq!(result[1], 5); // (3*4) % 7 = 12 % 7 = 5
        assert_eq!(result[2], 5); // Id(5) = 5
    }

    #[test]
    fn schema_apply_and_reconstruct() {
        let ops = [CramOp::Add; 5];
        let schema = Schema::new(&ops, &SAFE_BASIS_5).unwrap();
        let x = 42u64;
        let y = 58u64;
        let a: Vec<u64> = SAFE_BASIS_5.iter().map(|&p| x % p).collect();
        let b: Vec<u64> = SAFE_BASIS_5.iter().map(|&p| y % p).collect();
        let result = schema.apply_and_reconstruct(&a, &b).unwrap();
        assert_eq!(result, 100); // 42 + 58 = 100
    }

    // --- parse_schema ---

    #[test]
    fn parse_schema_basic() {
        let schema = parse_schema("AA_", &[3, 5, 7]).unwrap();
        assert_eq!(schema.notation(), "AA_");
        assert_eq!(schema.max_deg(), 1);
    }

    // --- DKAM subcriticality: deg(stretching) = 2 < ρ = 3 ---

    #[test]
    fn dkam_subcriticality() {
        let transport_core = [3u64, 7, 11, 13];
        let rho = *transport_core.iter().min().unwrap();
        assert_eq!(rho, 3);
        let stretching_degree = CramOp::Mul.degree(); // quadratic
        assert_eq!(stretching_degree, 2);
        assert!(stretching_degree < rho as u32);
    }

    // --- sqr carry ---

    #[test]
    fn sqr_carry_basic() {
        let (c7, c11, c13) = sqr_carry_signature(4);
        // 4²=16: 16>=7 → carry, 16>=11 → carry, 16>=13 → carry
        assert_eq!((c7, c11, c13), (1, 1, 1));
        let (c7, c11, c13) = sqr_carry_signature(1);
        // 1²=1: no carry anywhere
        assert_eq!((c7, c11, c13), (0, 0, 0));
    }

    // --- validity ---

    #[test]
    fn validity_champion_s6() {
        // Champion S⁶: one Div lane on p=13 → V = 12/13
        let ops = [
            CramOp::Add,
            CramOp::Add,
            CramOp::Add,
            CramOp::Add,
            CramOp::Add,
            CramOp::Div,
        ];
        let moduli = [3u64, 5, 7, 11, 17, 13];
        let schema = Schema::new(&ops, &moduli).unwrap();
        let (num, den) = schema_validity(&schema);
        assert_eq!((num, den), (12, 13));
    }

    // --- S8 full topology space ---

    #[test]
    fn s8_topology_space_size() {
        // 16 atoms (8 root × 2 post), 8 lanes = 16^8
        assert_eq!(16u64.pow(8), 4_294_967_296);
    }

    #[test]
    fn schema_display() {
        let schema = Schema::new(
            &[CramOp::Mul, CramOp::Sqr, CramOp::Id],
            &[3, 7, 11],
        )
        .unwrap();
        let s = schema.to_string();
        assert!(s.contains("MQ_"));
        assert!(s.contains("deg=2"));
        assert!(s.contains("rho=3"));
    }
}
