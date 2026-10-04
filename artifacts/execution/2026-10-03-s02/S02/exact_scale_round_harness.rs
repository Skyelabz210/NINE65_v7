//! Build the actual BFV scaler source tests against an already built nine65
//! library without recompiling the entire library test binary.
//! This verifies the selected FPD route's existing unit tests only.

pub mod main_only_base_ext {
    pub use nine65::arithmetic::main_only_base_ext::*;
}

pub mod rns {
    pub use nine65::arithmetic::rns::*;
}

#[path = "../../../../crates/nine65/src/arithmetic/exact_scale_round.rs"]
pub mod exact_scale_round;
