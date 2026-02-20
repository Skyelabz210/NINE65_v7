//! # Pipeline - Staged Computation Graphs
//!
//! Build complex FHE operation pipelines that can be optimized as a whole.
//!
//! ## Example
//!
//! ```ignore
//! use unhal::prelude::*;
//!
//! let pipeline = Pipeline::new()
//!     .add(Stage::Add)
//!     .add(Stage::ScalarMul(3))
//!     .add(Stage::Negate)
//!     .build();
//!
//! let result = pipeline.execute(&input_a, &input_b);
//! ```

use crate::accelerator::Accelerator;
use mana::stream::{ManaStream, StreamOps};

/// Pipeline stage operations
#[derive(Clone, Debug)]
pub enum Stage {
    /// Add two streams
    Add,
    /// Subtract second from first
    Sub,
    /// Negate result
    Negate,
    /// Multiply by scalar
    ScalarMul(u64),
    /// Custom operation (name, function index)
    Custom(String, usize),
}

/// Pipeline builder
#[derive(Clone, Debug)]
pub struct PipelineBuilder {
    stages: Vec<Stage>,
}

impl PipelineBuilder {
    /// Create new empty pipeline builder
    pub fn new() -> Self {
        Self { stages: Vec::new() }
    }

    /// Add a stage
    pub fn add_stage(mut self, stage: Stage) -> Self {
        self.stages.push(stage);
        self
    }

    /// Build the pipeline
    pub fn build(self) -> Pipeline {
        Pipeline {
            stages: self.stages,
            accelerator: Accelerator::auto(),
        }
    }

    /// Build with specific accelerator
    pub fn build_with(self, accel: Accelerator) -> Pipeline {
        Pipeline {
            stages: self.stages,
            accelerator: accel,
        }
    }
}

impl Default for PipelineBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Compiled pipeline
#[derive(Clone, Debug)]
pub struct Pipeline {
    stages: Vec<Stage>,
    accelerator: Accelerator,
}

impl Pipeline {
    /// Create new pipeline builder
    pub fn builder() -> PipelineBuilder {
        PipelineBuilder::new()
    }

    /// Execute pipeline on two input streams
    pub fn execute(&self, a: &ManaStream, b: &ManaStream) -> ManaStream {
        let mut result = a.clone();
        let other = b.clone();

        for stage in &self.stages {
            result = match stage {
                Stage::Add => self.accelerator.add_streams(&result, &other),
                Stage::Sub => self.accelerator.sub_streams(&result, &other),
                Stage::Negate => result.neg(),
                Stage::ScalarMul(s) => result.scalar_mul(*s),
                Stage::Custom(_, _) => {
                    // Custom ops would need a registry - for now, pass through
                    result
                }
            };
        }

        result
    }

    /// Execute on a single stream (uses zero stream as second input)
    pub fn execute_single(&self, a: &ManaStream) -> ManaStream {
        let zero = ManaStream::new(&a.primes, a.n);
        self.execute(a, &zero)
    }

    /// Number of stages
    pub fn len(&self) -> usize {
        self.stages.len()
    }

    /// Is empty?
    pub fn is_empty(&self) -> bool {
        self.stages.is_empty()
    }

    /// Get stages
    pub fn stages(&self) -> &[Stage] {
        &self.stages
    }
}

/// Macro for building pipelines more ergonomically
#[macro_export]
macro_rules! pipeline {
    ($($stage:expr),+ $(,)?) => {
        Pipeline::builder()
            $(.add_stage($stage))+
            .build()
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    const PRIMES: [u64; 3] = [998244353, 985661441, 754974721];

    #[test]
    fn test_pipeline_add() {
        let pipeline = Pipeline::builder().add_stage(Stage::Add).build();

        let a = ManaStream::from_ints(&[1, 2, 3], &PRIMES);
        let b = ManaStream::from_ints(&[4, 5, 6], &PRIMES);

        let result = pipeline.execute(&a, &b);

        assert_eq!(result.reconstruct_at(0), 5);
        assert_eq!(result.reconstruct_at(1), 7);
        assert_eq!(result.reconstruct_at(2), 9);
    }

    #[test]
    fn test_pipeline_chain() {
        let pipeline = Pipeline::builder()
            .add_stage(Stage::Add)
            .add_stage(Stage::ScalarMul(2))
            .build();

        let a = ManaStream::from_ints(&[1, 2], &PRIMES);
        let b = ManaStream::from_ints(&[3, 4], &PRIMES);

        let result = pipeline.execute(&a, &b);

        // (1+3)*2 = 8, (2+4)*2 = 12
        assert_eq!(result.reconstruct_at(0), 8);
        assert_eq!(result.reconstruct_at(1), 12);
    }

    #[test]
    fn test_pipeline_negate() {
        let pipeline = Pipeline::builder().add_stage(Stage::Negate).build();

        let a = ManaStream::from_ints(&[1, 2], &PRIMES);
        let b = ManaStream::from_ints(&[0, 0], &PRIMES);

        let result = pipeline.execute(&a, &b);

        // After negate, reconstruct should give q - original (where q is product)
        // But since we're mod product, we check that -1 is product-1
        let product: u128 = PRIMES.iter().map(|&p| p as u128).product();
        assert_eq!(result.reconstruct_at(0), product - 1);
    }
}
