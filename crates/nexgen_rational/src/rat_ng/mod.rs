//! NexGen Rational Number Module
//!
//! Integer-only exact rational arithmetic with adaptive normalization.

pub mod error;
pub mod normalize;
pub mod ops;
pub mod policy;
pub mod types;

pub use crate::exact_coeff::ExactCoeff;
pub use error::ArithmeticError;
pub use types::{DenState, DivOut, NexGenRat};
