/// operators.rs — Heterogeneous Lane Operators for CRAM
///
/// Each CRAM lane is assigned exactly two independent mathematical modifiers:
///   1. A Root Operator Φ_i  — binary, applied to the A and B residue inputs
///   2. A Unary Post-Processor Ψ_i — applied to the root output before CRT
///
/// The four-by-four operator matrix (4 roots × 4 post-processors = 16 configs
/// per lane) is the seed of the combinatorial explosion described in the paper.
/// For a k-lane topology this yields 16^k distinct global operators.

use crate::arith::{canonical, mod_add, mod_sub, mod_mul, mod_square, mod_neg, mod_inverse};

// ─── Root Operators ───────────────────────────────────────────────────────────

/// The four binary Root Operators Φ supported by the CRAM framework.
/// Each executes strictly within the finite field Z_p of its assigned lane.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RootOp {
    /// a + b mod p
    Add,
    /// a - b mod p  (canonical-positive output)
    Sub,
    /// a * b mod p
    Mul,
    /// a * b^{-1} mod p — falls into exceptional state when b ≡ 0 mod p
    Div,
}

impl RootOp {
    /// Apply the root operator.  Returns None on an exceptional state
    /// (specifically: DIV when the divisor has no modular inverse).
    pub fn apply(self, a: i128, b: i128, modulus: i128) -> Option<i128> {
        match self {
            RootOp::Add => Some(mod_add(a, b, modulus)),
            RootOp::Sub => Some(mod_sub(a, b, modulus)),
            RootOp::Mul => Some(mod_mul(a, b, modulus)),
            RootOp::Div => {
                // b must be invertible mod p — fails when gcd(b,p) > 1
                // For prime p this triggers only when b ≡ 0 mod p
                let inv_b = mod_inverse(b, modulus)?;
                Some(mod_mul(a, inv_b, modulus))
            }
        }
    }

    /// Returns the individual lane validity probability as a fraction (num, den).
    /// ADD, SUB, MUL are total functions → V_i = 1/1.
    /// DIV fails on the single zero residue → V_i = (p-1)/p.
    pub fn validity_fraction(self, modulus: i128) -> (i128, i128) {
        match self {
            RootOp::Add | RootOp::Sub | RootOp::Mul => (1, 1),
            RootOp::Div => (modulus - 1, modulus),
        }
    }

    /// Human-readable label for reports and traces.
    pub fn label(self) -> &'static str {
        match self {
            RootOp::Add => "ADD",
            RootOp::Sub => "SUB",
            RootOp::Mul => "MUL",
            RootOp::Div => "DIV",
        }
    }
}

// ─── Unary Post-Processors ────────────────────────────────────────────────────

/// The four Unary Post-Processors Ψ applied after the root operator.
/// These transform the intermediate residue before CRT reconstruction,
/// mapping outputs into controlled subsets (e.g. quadratic residues for SQR).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PostProc {
    /// x → x  (no transformation)
    Identity,
    /// x → -x ≡ p - x (mod p)
    Negate,
    /// x → x^2 mod p  — restricts output to quadratic residues of Z_p.
    /// The All-SQR champion topology uses this on every lane to guarantee
    /// pipeline stability (no downstream zero-divisor crashes).
    Square,
    /// x → x^{-1} mod p — falls into exceptional state when x = 0.
    Invert,
}

impl PostProc {
    /// Apply the post-processor.  Returns None on an exceptional state
    /// (Invert when x = 0).
    pub fn apply(self, x: i128, modulus: i128) -> Option<i128> {
        match self {
            PostProc::Identity => Some(canonical(x, modulus)),
            PostProc::Negate   => Some(mod_neg(x, modulus)),
            PostProc::Square   => Some(mod_square(x, modulus)),
            PostProc::Invert   => mod_inverse(x, modulus),
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            PostProc::Identity => "ID",
            PostProc::Negate   => "NEG",
            PostProc::Square   => "SQR",
            PostProc::Invert   => "INV",
        }
    }
}

// ─── Composite Lane Configuration ────────────────────────────────────────────

/// A fully configured CRAM lane: a prime modulus, a root operator, and
/// a unary post-processor.  This is the atomic unit of a CRAM topology.
#[derive(Debug, Clone, Copy)]
pub struct LaneConfig {
    /// The prime modulus p_i for this lane's finite field Z_{p_i}.
    pub prime: i128,
    /// The binary root operator Φ_i.
    pub root_op: RootOp,
    /// The unary post-processor Ψ_i applied after the root.
    pub post_proc: PostProc,
}

impl LaneConfig {
    pub fn new(prime: i128, root_op: RootOp, post_proc: PostProc) -> Self {
        Self { prime, root_op, post_proc }
    }

    /// Full lane evaluation: apply root then post-processor.
    /// Returns None if either stage enters an exceptional state.
    pub fn evaluate(&self, a: i128, b: i128) -> Option<i128> {
        let root_out = self.root_op.apply(a, b, self.prime)?;
        self.post_proc.apply(root_out, self.prime)
    }

    /// Lane validity fraction accounting for both operators.
    /// (For standard topologies, post-processor INV is the only one that
    /// can add additional failures on top of DIV root failures.)
    pub fn validity_fraction(&self) -> (i128, i128) {
        // For the current champion topologies (All-SQR) the post-proc
        // is always total when its input is in [0, p), so we only count
        // the root validity.  A future INV post-proc would multiply fractions.
        self.root_op.validity_fraction(self.prime)
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Phase 2 verification from the paper's CRAM-S4 numerical trace ─────────

    #[test]
    fn trace_lane1_mul_mod2() {
        // Lane 1: Φ=MUL, p=2.  Inputs a=1, b=1.  1*1 mod 2 = 1.
        let lane = LaneConfig::new(2, RootOp::Mul, PostProc::Identity);
        assert_eq!(lane.root_op.apply(1, 1, 2), Some(1));
    }

    #[test]
    fn trace_lane2_sub_mod3() {
        // Lane 2: Φ=SUB, p=3.  Inputs a=2, b=2.  2-2 mod 3 = 0.
        assert_eq!(RootOp::Sub.apply(2, 2, 3), Some(0));
    }

    #[test]
    fn trace_lane3_add_mod5() {
        // Lane 3: Φ=ADD, p=5.  Inputs a=2, b=3.  2+3=5 ≡ 0 mod 5.
        assert_eq!(RootOp::Add.apply(2, 3, 5), Some(0));
    }

    #[test]
    fn trace_lane4_div_mod7() {
        // Lane 4: Φ=DIV, p=7.  Inputs a=3, b=2.  3*(2^{-1} mod 7)=3*4=12≡5.
        // This is the key DIV example explicitly traced in the paper.
        assert_eq!(RootOp::Div.apply(3, 2, 7), Some(5));
    }

    // ── Phase 3 verification — All-SQR post-processing ────────────────────────

    #[test]
    fn trace_sqr_lane1() {
        // 1^2 mod 2 = 1
        assert_eq!(PostProc::Square.apply(1, 2), Some(1));
    }

    #[test]
    fn trace_sqr_lane2_zero() {
        // 0^2 mod 3 = 0  (SQR is total — zero is a quadratic residue)
        assert_eq!(PostProc::Square.apply(0, 3), Some(0));
    }

    #[test]
    fn trace_sqr_lane3_zero() {
        // 0^2 mod 5 = 0
        assert_eq!(PostProc::Square.apply(0, 5), Some(0));
    }

    #[test]
    fn trace_sqr_lane4() {
        // 5^2 = 25 ≡ 4 mod 7 — the critical SQR output from the paper
        assert_eq!(PostProc::Square.apply(5, 7), Some(4));
    }

    // ── Exceptional state tests ────────────────────────────────────────────────

    #[test]
    fn div_by_zero_is_exceptional() {
        // DIV with b=0 must return None — the exceptional set trigger
        assert_eq!(RootOp::Div.apply(5, 0, 7), None);
        assert_eq!(RootOp::Div.apply(5, 0, 13), None);
    }

    #[test]
    fn invert_zero_is_exceptional() {
        // INV of 0 must return None
        assert_eq!(PostProc::Invert.apply(0, 7), None);
    }

    // ── Validity fractions ────────────────────────────────────────────────────

    #[test]
    fn validity_total_ops() {
        assert_eq!(RootOp::Add.validity_fraction(7),  (1, 1));
        assert_eq!(RootOp::Sub.validity_fraction(7),  (1, 1));
        assert_eq!(RootOp::Mul.validity_fraction(7),  (1, 1));
    }

    #[test]
    fn validity_div_mod13() {
        // DIV over p=13: V = 12/13 — CRAM-S6 champion lane
        assert_eq!(RootOp::Div.validity_fraction(13), (12, 13));
    }

    #[test]
    fn validity_div_mod7() {
        // DIV over p=7: V = 6/7 — CRAM-S4 champion lane
        assert_eq!(RootOp::Div.validity_fraction(7), (6, 7));
    }
}
