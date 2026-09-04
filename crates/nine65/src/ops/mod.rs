//! Operations Module - BFV FHE Operations
//!
//! Provides:
//! - Encryption and decryption
//! - Homomorphic operations (add, mul, etc.)
//! - RNS-based multiplication for ct×ct
//! - Noise management
//! - Neural network operations
//! - Galois automorphisms for SIMD slot rotations
//! - CRT batching for SIMD packing (N/2 slots per ciphertext)
//! - Parallel encrypt/decrypt for throughput

// Public forwarding layer for the exact align-and-drop primitive, consumed by
// the arrow-emission gate matrix in tests/. `#[doc(hidden)]`: it exists only
// so an integration-test target can reach a deliberately `pub(crate)`
// primitive from outside the crate. It is reachable, but it is not part of the
// documented API surface and carries no stability promise. See the module's
// own header for the full rationale.
#[doc(hidden)]
pub mod arrow_emission_gate;
pub mod auto_bootstrap;
pub mod batch;
pub mod bootstrap;
// RETIRED: `pub mod sbni;` — shadow-butterfly noise injection, dropped per
// author decision. `src/ops/sbni.rs` was removed entirely (issue #68
// completed the retirement); it was never part of the module tree and never
// compiled into the crate. The historical record lives in
// docs/LADDER_REMOVAL.md §1 and docs/RETIRED_MECHANISMS.md.
pub mod cram_public;
pub mod encrypt;
pub mod galois;
pub mod gso_fhe;
pub mod homomorphic;
pub mod neural;
pub mod parallel;
pub mod rns_fhe;
// REMOVED (G19, legacy duplicate stack): `pub mod rns_mul;` used to define a
// second, independent RNSEvaluator/DualRNS* stack (duplicate DualRNSPoly,
// DualRNSCiphertext, DualRNSSecretKey, DualRNSPublicKey types distinct from
// the ones in `rns_fhe`) with a u128-only K-Elimination path that lacked the
// signed-k fix. It had zero callers outside its own file and tests
// (`RNSEvaluator` was only ever referenced from rns_mul.rs itself and this
// mod.rs re-export) -- the live ct×ct multiplication path is rns_fhe.rs. The
// file has been deleted outright rather than feature-gated, since deleting
// was safe (no external references) per the removal criteria this was
// reviewed against.
pub mod symmetric_bootstrap;

pub use batch::BatchEncoder;
pub use encrypt::{BFVDecryptor, BFVEncoder, BFVEncryptor, Ciphertext};
pub use galois::{GaloisEngine, GaloisEvaluator, GaloisKey, GaloisKeySet};
pub use gso_fhe::{
    AttractorBasin, GSOCiphertext, GSOFHEContext, GSOSwarm, NoiseEstimate, NoiseStats,
};
pub use homomorphic::{BFVEvaluator, TrackedEvaluator};
pub use neural::{ActivationType, DenseLayer, FHENeuralEvaluator, NeuralNetwork};
pub use parallel::{ParallelDecryptor, ParallelEncryptor};
pub use rns_fhe::{
    RNSCiphertext, RNSEvalKey, RNSFHEContext, RNSKeySet, RNSPublicKey, RNSSecretKey,
};
