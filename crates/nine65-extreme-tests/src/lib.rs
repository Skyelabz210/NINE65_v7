// NINE65 v7 Extreme Testing Harness
//
// This crate answers 20 questions the existing 1,163-test suite does not ask.
// All tests are opt-in via the `extreme-tests` feature flag to avoid slowing
// normal `cargo test` runs.
//
// Run with:
//   cargo test -p nine65-extreme-tests --features extreme-tests -- --nocapture
//
// Each module is self-contained and documents which question(s) it answers.

#[cfg(all(test, feature = "extreme-tests"))]
pub mod noise_model_validation;

#[cfg(all(test, feature = "extreme-tests"))]
pub mod k_elimination_extremes;

#[cfg(all(test, feature = "extreme-tests"))]
pub mod rns_boundary_tests;

#[cfg(all(test, feature = "extreme-tests"))]
pub mod bootstrap_adversarial;

#[cfg(all(test, feature = "extreme-tests"))]
pub mod concurrent_operations;

#[cfg(all(test, feature = "extreme-tests"))]
pub mod entropy_extremes;

#[cfg(all(test, feature = "extreme-tests"))]
pub mod montgomery_timing_audit;

#[cfg(all(test, feature = "extreme-tests"))]
pub mod ema_numerical_stability;

#[cfg(all(test, feature = "extreme-tests"))]
pub mod formal_spec_linkage;

#[cfg(all(test, feature = "extreme-tests"))]
pub mod cross_config_operations;

#[cfg(all(test, feature = "extreme-tests"))]
pub mod depth_stress_tests;

#[cfg(all(test, feature = "extreme-tests"))]
pub mod negative_plaintext_coverage;

#[cfg(all(test, feature = "extreme-tests"))]
pub mod key_serialization_roundtrip;

#[cfg(all(test, feature = "extreme-tests"))]
pub mod boundary_tests;
