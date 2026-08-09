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
pub mod rns_mul;
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
pub use rns_mul::RNSEvaluator;
