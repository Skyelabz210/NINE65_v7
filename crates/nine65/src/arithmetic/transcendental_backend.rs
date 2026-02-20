//! Feature-gated adapter for exact transcendental backends.
//!
//! The public arithmetic APIs keep the same i128 fixed-point interface.
//! When `exact_transcendentals_backend` is enabled we bridge to the
//! Q30 exact-transcendentals engine and convert back to caller scale.

/// Q30 fixed-point scale used by `exact_transcendentals`.
pub const Q30_SCALE: i128 = 1_i128 << 30;

#[cfg(feature = "exact_transcendentals_backend")]
use exact_transcendentals::cordic::{CordicEngine, HyperbolicCordic};
#[cfg(feature = "exact_transcendentals_backend")]
use std::sync::OnceLock;

#[cfg(feature = "exact_transcendentals_backend")]
#[derive(Clone, Debug)]
pub struct ExactTranscendentalBackend {
    circular: CordicEngine,
    hyperbolic: HyperbolicCordic,
}

#[cfg(feature = "exact_transcendentals_backend")]
impl Default for ExactTranscendentalBackend {
    fn default() -> Self {
        Self {
            circular: CordicEngine::default(),
            hyperbolic: HyperbolicCordic::default(),
        }
    }
}

#[cfg(feature = "exact_transcendentals_backend")]
impl ExactTranscendentalBackend {
    pub fn exp_integer(&self, x: i128, scale: i128) -> Option<i128> {
        let x_q30 = to_q30(x, scale)?;
        from_q30(self.hyperbolic.exp(x_q30), scale)
    }

    pub fn sin_integer(&self, x: i128, scale: i128) -> Option<i128> {
        // sin(0) = 0 exactly — bypass CORDIC to avoid gain-correction rounding
        if x == 0 {
            return Some(0);
        }
        let x_q30 = to_q30(x, scale)?;
        from_q30(self.circular.sin(x_q30), scale)
    }

    pub fn cos_integer(&self, x: i128, scale: i128) -> Option<i128> {
        // cos(0) = 1 exactly — bypass CORDIC to avoid gain-correction rounding
        // that can produce scale +/- 1 due to integer division truncation in from_q30
        if x == 0 {
            return Some(scale);
        }
        let x_q30 = to_q30(x, scale)?;
        from_q30(self.circular.cos(x_q30), scale)
    }

    pub fn ln_integer(&self, x: i128, scale: i128) -> Option<i128> {
        if x <= 0 {
            return Some(i128::MIN);
        }
        let x_q30 = to_q30(x, scale)?;
        if x_q30 <= 0 {
            return Some(i128::MIN);
        }
        let ln_q30 = self.hyperbolic.ln(x_q30);
        if ln_q30 == i64::MIN {
            return Some(i128::MIN);
        }
        from_q30(ln_q30, scale)
    }
}

#[cfg(feature = "exact_transcendentals_backend")]
fn to_q30(value: i128, scale: i128) -> Option<i64> {
    if scale <= 0 {
        return None;
    }
    let scaled = value.checked_mul(Q30_SCALE)?.checked_div(scale)?;
    i64::try_from(scaled).ok()
}

#[cfg(feature = "exact_transcendentals_backend")]
fn from_q30(value: i64, scale: i128) -> Option<i128> {
    if scale <= 0 {
        return None;
    }
    i128::from(value).checked_mul(scale)?.checked_div(Q30_SCALE)
}

#[cfg(feature = "exact_transcendentals_backend")]
fn exact_backend() -> &'static ExactTranscendentalBackend {
    static BACKEND: OnceLock<ExactTranscendentalBackend> = OnceLock::new();
    BACKEND.get_or_init(ExactTranscendentalBackend::default)
}

pub fn try_exp_integer_exact(x: i128, scale: i128) -> Option<i128> {
    #[cfg(feature = "exact_transcendentals_backend")]
    {
        return exact_backend().exp_integer(x, scale);
    }
    #[cfg(not(feature = "exact_transcendentals_backend"))]
    {
        let _ = (x, scale);
        None
    }
}

pub fn try_sin_integer_exact(x: i128, scale: i128) -> Option<i128> {
    #[cfg(feature = "exact_transcendentals_backend")]
    {
        return exact_backend().sin_integer(x, scale);
    }
    #[cfg(not(feature = "exact_transcendentals_backend"))]
    {
        let _ = (x, scale);
        None
    }
}

pub fn try_cos_integer_exact(x: i128, scale: i128) -> Option<i128> {
    #[cfg(feature = "exact_transcendentals_backend")]
    {
        return exact_backend().cos_integer(x, scale);
    }
    #[cfg(not(feature = "exact_transcendentals_backend"))]
    {
        let _ = (x, scale);
        None
    }
}

pub fn try_ln_integer_exact(x: i128, scale: i128) -> Option<i128> {
    #[cfg(feature = "exact_transcendentals_backend")]
    {
        return exact_backend().ln_integer(x, scale);
    }
    #[cfg(not(feature = "exact_transcendentals_backend"))]
    {
        let _ = (x, scale);
        None
    }
}

#[cfg(all(test, feature = "exact_transcendentals_backend"))]
mod tests {
    use super::*;

    #[test]
    fn test_exact_exp_at_zero() {
        let result = try_exp_integer_exact(0, 1_000_000_000).expect("conversion should succeed");
        assert!((result - 1_000_000_000).abs() < 2_000_000);
    }

    #[test]
    fn test_exact_ln_at_one() {
        let result =
            try_ln_integer_exact(1_000_000_000, 1_000_000_000).expect("conversion should succeed");
        assert!(result.abs() < 2_000_000);
    }
}
