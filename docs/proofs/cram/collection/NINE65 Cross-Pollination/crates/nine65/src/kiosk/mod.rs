//! # NINE65 Kiosk Architecture — Self-Destructing FHE Computation Units
//!
//! Implements the "Ammunition" model: disposable, self-destructing computation
//! units (Bullets, Capsules, Fuses) that run on client hardware and destroy
//! themselves after use, leaving no forensic trace.
//!
//! ## Architecture
//!
//! | Component | Purpose |
//! |-----------|---------|
//! | [`fold`] | Algebraic folding renders RNS state meaningless before zeroing |
//! | [`destruction`] | Atomic lifecycle: Fold + Zero + Receipt generation |
//! | [`inv8`] | INV-8 Check Lane: redundant RNS channel for DDoS detection |
//! | [`fuse`] | Shadow Entropy Fuse: countdown to self-destruction |
//! | [`receipt`] | SHA-256 receipt verification for destroyed units |
//! | [`unit`] | Kiosk unit types: Bullet (single-use), Capsule (multi-use), Fuse (time-limited) |
//!
//! ## Security Properties
//!
//! - **Self-Destruction**: Units zero all state after computation via `zeroize`
//! - **Shadow Entropy Metering**: Montgomery quotient byproducts meter usage
//! - **INV-8 Detection**: Algebraic inversion attacks detected at first operation
//! - **Tamper Detection**: Unauthorized computation produces detectable entropy

pub mod destruction;
pub mod fold;
pub mod fuse;
pub mod inv8;
pub mod receipt;
pub mod unit;

pub use destruction::{DestructionReceipt, DestructionSequence};
pub use fold::{FoldOperator, FoldState};
pub use fuse::{EntropyFuse, FuseState};
pub use inv8::{Inv8CheckLane, Inv8Verdict};
pub use receipt::{ReceiptHash, ReceiptVerifier};
pub use unit::{KioskLifecycle, KioskUnit, KioskUnitType, UnitStatus};
