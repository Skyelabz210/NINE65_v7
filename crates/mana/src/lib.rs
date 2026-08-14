//! # MANA - Modular Anchored Number Arithmetic
//!
//! FHE Stream Accelerator: "A murder of FPGAs in RAM"
//!
//! ## Architecture
//!
//! MANA treats CRT prime moduli as parallel compute lanes, enabling:
//! - **Rayon**: Parallel execution across lanes (one thread per prime) - 2.78x speedup
//! - **GSO**: Glowworm Swarm Optimization with qbit-inspired operations
//! - **K-Elimination**: Exact division via anchor codex (no reconstruction cost)
//!
//! ## Zero Floating-Point Guarantee
//!
//! All operations use exact integer arithmetic. No f32, f64 anywhere.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod anchor;
pub mod executor;
pub mod gso;
pub mod lane;
pub mod stream;

#[cfg(feature = "parallel")]
pub mod parallel;

pub mod prelude {
    //! Common imports
    pub use crate::anchor::{AnchorContext, KAnchor};
    pub use crate::executor::{run_lanes, run_lanes_sequential};
    pub use crate::gso::{GsoSwarm, QbitAgent};
    pub use crate::lane::{Lane, LaneOps};
    pub use crate::stream::{ManaStream, StreamOps};

    #[cfg(feature = "parallel")]
    pub use crate::parallel::ParallelStream;
}
