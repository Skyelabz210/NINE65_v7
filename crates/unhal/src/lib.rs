//! # UNHAL - Universal Neuromorphic Hardware Abstraction Layer
//!
//! Higher-level interface over MANA for FHE acceleration.
//! Provides a unified API that abstracts over SIMD and parallel execution.
//!
//! ## Architecture
//!
//! ```text
//! ┌──────────────────────────────────────────────────────┐
//! │                     UNHAL                            │
//! │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  │
//! │  │ Accelerator │  │  Pipeline   │  │   Batch     │  │
//! │  │  (auto-     │  │  (staged    │  │  (bulk      │  │
//! │  │   detect)   │  │   compute)  │  │   process)  │  │
//! │  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘  │
//! └─────────┼────────────────┼────────────────┼─────────┘
//!           │                │                │
//!           └────────────────┴────────────────┘
//!                            │
//! ┌──────────────────────────┴───────────────────────────┐
//! │                      MANA                            │
//! │  ┌─────────┐  ┌─────────┐  ┌─────────┐  ┌─────────┐ │
//! │  │  Lane   │  │ Stream  │  │ Anchor  │  │   GSO   │ │
//! │  │ (SIMD)  │  │ (CRT)   │  │ (K-Elim)│  │ (Qbit)  │ │
//! │  └─────────┘  └─────────┘  └─────────┘  └─────────┘ │
//! └──────────────────────────────────────────────────────┘
//! ```
//!
//! ## Usage
//!
//! ```ignore
//! use unhal::prelude::*;
//!
//! // Auto-detect best execution path
//! let accel = Accelerator::auto();
//!
//! // Simple operation
//! let result = accel.add_streams(&a, &b);
//!
//! // Pipeline of operations
//! let pipe = Pipeline::new()
//!     .add(Stage::Add)
//!     .add(Stage::ScalarMul(2))
//!     .build();
//! let result = pipe.execute(&a, &b);
//!
//! // Bulk processing
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
