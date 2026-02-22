//! Ring Module - Polynomial Arithmetic in R_q
//!
//! Provides polynomial operations for BFV FHE over the quotient ring
//! R_q = Z_q[X]/(X^N + 1).

pub mod polynomial;
pub mod pool;

pub use polynomial::{PolyDomain, RingPolynomial};
pub use pool::{PolynomialPool, PoolGuard, PooledPolynomial};
