//! # NexGen Rational
//!
//! Pure Rust implementation of exact rational number arithmetic using
//! **strictly integer operations**. Zero floating-point contamination.
//!
//! ## Design Principles
//! - Integer-only: All arithmetic uses i128 exclusively
//! - Exact: No approximation, no floating-point drift
//! - Overflow-aware: Checked arithmetic throughout
//! - Adaptive normalization: GCD reduction on-demand via bit-threshold scheduling
//! - Memory safe: No unsafe code permitted

#![forbid(unsafe_code)]

pub mod binary_gcd;
pub mod exact_coeff;
pub mod rat_ng;
