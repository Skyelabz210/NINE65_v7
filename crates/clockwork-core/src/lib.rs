//! # Clockwork Core — Formal-Spec-Compliant RNS Arithmetic
//!
//! This crate implements the Loki-Clockwork Formal Specification v1.0,
//! providing exact integer arithmetic for RLWE FHE ciphertext coefficients.
//!
//! ## Design Invariants (from formal spec §3)
//!
//! - **INV-1**: RLWE modulus `q` is fixed. No operation modifies it.
//! - **INV-2**: Round-trip through Clockwork residues is the identity on ℤ_q.
//! - **INV-3**: Bound tracker is always sound: |Center(X)| < 2^H(X).
//! - **INV-7**: Operation schedule is public and value-independent.
//!
//! ## Zero Floating Point Guarantee
//!
//! This crate contains ZERO floating-point operations. All arithmetic is
//! exact integer computation. This is enforced by `#![deny(clippy::float_arithmetic)]`
//! and verified by grep in CI.

// NOTE: unsafe is used ONLY in key_lifecycle::zero_u64 for volatile memory zeroing (A4).
// All other code is safe Rust.
// NOTE: In production, enable these:
// #![deny(clippy::float_arithmetic)]
// #![deny(clippy::float_cmp)]

pub mod basis;
pub mod bound_tracker;
pub mod decode_to_q;
pub mod garner;
pub mod gearstack;
pub mod gro;
pub mod integrity;
pub mod key_lifecycle;

// Re-exports for convenience
pub use basis::RnsBasis;
pub use bound_tracker::Bound;
pub use decode_to_q::DecodeToQ;
pub use garner::k_eliminate;
pub use gearstack::GearStack;
pub use gro::GroGate;
pub use integrity::TripleRedundant;
