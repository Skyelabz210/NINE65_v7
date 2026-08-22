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

pub mod arrow_emission_gate; // Public forwarding layer for the exact
                             // align-and-drop primitive, consumed by the
                             // arrow-emission gate matrix in tests/.
pub mod auto_bootstrap;
pub mod batch;
pub mod bootstrap;
// RETIRED: `pub mod sbni;` — shadow-butterfly noise injection, dropped per
// author decision. The file remains on disk at `src/ops/sbni.rs` for the
// record but is no longer part of the module tree and does not compile into
// the crate. See its header and docs/RETIRED_MECHANISMS.md.
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
