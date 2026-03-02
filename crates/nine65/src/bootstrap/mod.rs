//! # Three-Lock Bootstrap — Protected Re-Encryption with Conjunction Security
//!
//! Refreshes noise-exhausted ciphertexts through protected re-encryption,
//! where the intermediate plaintext is shielded by three orthogonal
//! security layers (mask + outer RLWE + constant-time execution).
//!
//! ## Usage
//!
//! ```ignore
//! use nine65::bootstrap::*;
//!
//! let bsk = BootstrapKey::generate_with_pk(
//!     &config, &secret_key, &public_key.pk0, &public_key.pk1,
//! );
//! let mut tl = ThreeLockBootstrap::new(&config, SecurityTier::Tier2Production);
//! let refreshed = tl.bootstrap(&exhausted_ct, &bsk, &ntt);       // hot path (no syscalls)
//! let (refreshed, stats) = tl.bootstrap_timed(&exhausted_ct, &bsk, &ntt); // with timing
//! ```
//!
//! HackFate.us Research, February 2026

pub mod clockwork;
pub mod mask;
pub mod outer;
pub mod three_lock;

pub use clockwork::{BootstrapKey, BootstrapParams, ClockworkBootstrap};
pub use mask::MaskLayer;
pub use outer::{OuterCiphertext, OuterLayer};
pub use three_lock::{BootstrapStats, SecurityTier, ThreeLockBootstrap};
