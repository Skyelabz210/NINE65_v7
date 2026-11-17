//! CRAM operator selector — compile-time dispatch on the modulus pair.
//!
//! Given a pair `(M, A)`, the selector chooses the cheapest valid winding
//! operator: subtraction (adjacent), general K-Elim (coprime), or the
//! resolution gradient (non-coprime). This is a compile-time constant in a
//! real backend; here it is a runtime function returning the strategy tag
//! plus the precomputed constants the codegen would embed.

use crate::{gcd, mod_inv};

/// The winding-extraction strategy selected for a modulus pair.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Strategy {
    /// A = M+1. Winding = `(vM - vA) mod (M+1)`. No multiply, no inverse.
    AdjacentSubtraction,
    /// gcd(M,A)=1, not adjacent. Winding = `(vA - vM)*Minv mod A`.
    /// Carries the precomputed `M⁻¹ mod A`.
    GeneralKElim { m_inv: i128 },
    /// gcd(M,A)=d>1. Partial winding mod (A/d). Carries `(M/d)⁻¹ mod (A/d)`,
    /// the common factor `d`, and the reduced anchor `A/d`.
    ResolutionGradient { inv_md: i128, d: i128, a_over_d: i128 },
}

/// Select the winding strategy and precompute its constants.
pub fn select(m: i128, a: i128) -> Strategy {
    let d = gcd(m, a);
    if d == 1 {
        if a == m + 1 {
            Strategy::AdjacentSubtraction
        } else {
            Strategy::GeneralKElim {
                m_inv: mod_inv(m, a).expect("coprime ⇒ inverse exists"),
            }
        }
    } else {
        let (md, ad) = (m / d, a / d);
        Strategy::ResolutionGradient {
            inv_md: mod_inv(md, ad).expect("reduced moduli coprime"),
            d,
            a_over_d: ad,
        }
    }
}

/// Execute the selected strategy on residues. Returns `(winding, modulus)`,
/// where `modulus` is `A` for full recovery or `A/d` for the gradient.
pub fn apply(strategy: Strategy, v_m: i128, v_a: i128, _m: i128, a: i128) -> (i128, i128) {
    match strategy {
        Strategy::AdjacentSubtraction => ((v_m - v_a).rem_euclid(a), a),
        Strategy::GeneralKElim { m_inv } => {
            (((v_a - v_m).rem_euclid(a) * m_inv) % a, a)
        }
        Strategy::ResolutionGradient { inv_md, d, a_over_d } => {
            let diff = v_a - v_m;
            (((diff / d) * inv_md).rem_euclid(a_over_d), a_over_d)
        }
    }
}
