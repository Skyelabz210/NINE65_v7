//! # UNHAL - Universal Neuromorphic Hardware Abstraction Layer
//!
//! Higher-level interface over MANA for FHE acceleration.
//!
//! ## Pipeline
//!
//! The production data flow is **nine65 → UNHAL (decides) → MANA
//! (executes)**: nine65's hot loops call [`accelerator::Accelerator::run_lanes`],
//! UNHAL's `Accelerator` picks the execution strategy, and delegates to
//! MANA's dependency-free, deterministic scoped-thread lane executor
//! (`mana::executor`), which is not a SIMD engine and does not use rayon —
//! output is bit-identical regardless of thread count or scheduling order.
//! See `accelerator::Accelerator::run_lanes`'s doc comment for the full
//! contract.
//!
//! ```text
//! ┌──────────────────────────────────────────────────────┐
//! │                     UNHAL (decides)                   │
//! │  Accelerator::run_lanes — the production entry point  │
//! │  (also: legacy Pipeline / Batch / stream-level API,    │
//! │  SIMD-fallback and opt-in-rayon dispatch — see          │
//! │  accelerator.rs module docs)                            │
//! └───────────────────────┬─────────────────────────────┘
//!                         │
//! ┌───────────────────────┴─────────────────────────────┐
//! │                    MANA (executes)                    │
//! │  executor (deterministic scoped-thread lane runner —   │
//! │  the production path) · Lane · Stream (CRT) ·          │
//! │  Anchor (K-Elim) · GSO (Qbit) · parallel (opt-in rayon) │
//! └──────────────────────────────────────────────────────┘
//! ```
//!
//! ## Usage
//!
//! ```ignore
//! use unhal::prelude::*;
//!
//! // Production path: UNHAL decides, MANA executes.
//! let accel = Accelerator::auto();
//! let results = accel.run_lanes(lanes, |lane_idx| compute_lane(lane_idx));
//!
//! // Legacy stream-level API — SIMD is a no-op fallback to sequential, and
//! // the parallel path here requires the opt-in `parallel` (rayon) feature;
//! // see accelerator.rs module docs before relying on either.
//! let result = accel.add_streams(&a, &b);
//!
//! // Pipeline of operations (built on the legacy stream-level API above)
//! let pipe = Pipeline::new()
//!     .add(Stage::Add)
//!     .add(Stage::ScalarMul(2))
//!     .build();
//! let result = pipe.execute(&a, &b);
//!
//! // Bulk processing (also built on the legacy stream-level API)
//! let batch = BatchProcessor::auto();
//! let results = batch.add_batch_par(&pairs);
//! ```

pub mod accelerator;
pub mod batch;
pub mod pipeline;

pub mod prelude {
    //! Common imports
    pub use crate::accelerator::{Accelerator, AcceleratorConfig, ExecutionMode};
    pub use crate::batch::BatchProcessor;
    pub use crate::pipeline::{Pipeline, PipelineBuilder, Stage};

    // Re-export key MANA types
    pub use mana::anchor::{AnchorContext, KAnchor};
    pub use mana::lane::Lane;
    pub use mana::stream::ManaStream;
}
