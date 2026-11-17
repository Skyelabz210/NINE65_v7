/// lib.rs — CRAM: Configurable Residue Arithmetic Machine
///
/// The complete QMNF / NINE65 v7 stack in exact integer Rust.
///
/// Module Hierarchy:
///
///   arith    — Exact integer arithmetic primitives (extended GCD, mod inverse, etc.)
///   operators — Root Operators (Φ) and Unary Post-Processors (Ψ)
///   garner   — Recumbent CRT: Garner's algorithm for exact CRT reconstruction
///   topology — Champion topology definitions and Shadow Entropy analysis
///   engine   — Core CRAM execution engine (residue-native + eager modes)
///   fhe      — NINE65 v7 K-Elimination FHE with auto-bootstrapping
///   ahop     — Apollonian Hidden Orbit Problem post-quantum bridge
///
/// Philosophical constraint (QMNF): mathematical truth cannot be approximated.
/// No floating-point operations exist anywhere in this crate except in
/// display/reporting helpers.

pub mod arith;
pub mod operators;
pub mod garner;
pub mod subproduct_tree;
pub mod topology;
pub mod engine;
pub mod fhe;
pub mod ahop;

// Re-export the most commonly used public surface for ergonomics
pub use topology::{Topology, cram_s4_champion, cram_s6_champion, cram_s4_plus, cram_s3_minimal};
pub use engine::{CramEngine, CramError, CramResult, ResidueTuple};
pub use operators::{RootOp, PostProc, LaneConfig};
pub use garner::{GarnerConstants, GarnerResult, garner_reconstruct, decompose, reconstruct};
pub use subproduct_tree::{SptConstants, SptResult, spt_reconstruct, spt_decompose,
                          cross_validate_spt_garner};
pub use fhe::Nine65Engine;
pub use ahop::{reflect_cram, reflect_classical, walk_cram_orbit, AhopEngine};
