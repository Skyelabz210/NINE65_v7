//! # Batch - Bulk Stream Processing
//!
//! Process multiple streams in parallel for maximum throughput.
//! Optimal for FHE operations on vectors of ciphertexts.

use crate::accelerator::Accelerator;
use mana::stream::ManaStream;

#[cfg(feature = "parallel")]
use rayon::prelude::*;

/// Batch processor for bulk operations
#[derive(Clone, Debug)]
pub struct BatchProcessor {
    accelerator: Accelerator,
}

impl BatchProcessor {
    /// Create new batch processor
    pub fn new(accelerator: Accelerator) -> Self {
        Self { accelerator }
    }

    /// Create with auto-detected settings
    pub fn auto() -> Self {
        Self::new(Accelerator::auto())
    }

    /// Add pairs of streams in batch
    #[cfg(feature = "parallel")]
    pub fn add_batch_par(&self, pairs: &[(ManaStream, ManaStream)]) -> Vec<ManaStream> {
        pairs
            .par_iter()
            .map(|(a, b)| self.accelerator.add_streams(a, b))
            .collect()
    }

    /// Add pairs sequentially
    pub fn add_batch(&self, pairs: &[(ManaStream, ManaStream)]) -> Vec<ManaStream> {
        pairs
            .iter()
            .map(|(a, b)| self.accelerator.add_streams(a, b))
            .collect()
    }

    /// Subtract pairs in batch
    #[cfg(feature = "parallel")]
    pub fn sub_batch_par(&self, pairs: &[(ManaStream, ManaStream)]) -> Vec<ManaStream> {
        pairs
            .par_iter()
            .map(|(a, b)| self.accelerator.sub_streams(a, b))
            .collect()
    }

    /// Subtract pairs sequentially
    pub fn sub_batch(&self, pairs: &[(ManaStream, ManaStream)]) -> Vec<ManaStream> {
        pairs
            .iter()
            .map(|(a, b)| self.accelerator.sub_streams(a, b))
            .collect()
    }

    /// Multiply pairs in batch
    #[cfg(feature = "parallel")]
    pub fn mul_batch_par(&self, pairs: &[(ManaStream, ManaStream)]) -> Vec<ManaStream> {
        pairs
            .par_iter()
            .map(|(a, b)| self.accelerator.mul_streams(a, b))
            .collect()
    }

    /// Multiply pairs sequentially
    pub fn mul_batch(&self, pairs: &[(ManaStream, ManaStream)]) -> Vec<ManaStream> {
        pairs
            .iter()
            .map(|(a, b)| self.accelerator.mul_streams(a, b))
            .collect()
    }

    /// Element-wise add a single stream to all in a batch
    #[cfg(feature = "parallel")]
    pub fn broadcast_add_par(
        &self,
        streams: &[ManaStream],
        addend: &ManaStream,
    ) -> Vec<ManaStream> {
        streams
            .par_iter()
            .map(|s| self.accelerator.add_streams(s, addend))
            .collect()
    }

    /// Element-wise add sequentially
    pub fn broadcast_add(&self, streams: &[ManaStream], addend: &ManaStream) -> Vec<ManaStream> {
        streams
            .iter()
            .map(|s| self.accelerator.add_streams(s, addend))
            .collect()
    }

    /// Reduce streams by addition (parallel tree reduction)
    #[cfg(feature = "parallel")]
    pub fn reduce_add_par(&self, streams: &[ManaStream]) -> Option<ManaStream> {
        if streams.is_empty() {
            return None;
        }
        if streams.len() == 1 {
            return Some(streams[0].clone());
        }

        // Parallel tree reduction
        let mut current: Vec<ManaStream> = streams.to_vec();

        while current.len() > 1 {
            let next_len = current.len().div_ceil(2);
            let mut next = Vec::with_capacity(next_len);

            // Process pairs in parallel
            let pairs: Vec<_> = (0..current.len() / 2)
                .map(|i| (current[i * 2].clone(), current[i * 2 + 1].clone()))
                .collect();

            let sums: Vec<ManaStream> = pairs
                .par_iter()
                .map(|(a, b)| self.accelerator.add_streams(a, b))
                .collect();

            next.extend(sums);

            // Handle odd element
            if current.len() % 2 == 1 {
                next.push(current.last().unwrap().clone());
            }

            current = next;
        }

        current.pop()
    }

    /// Reduce streams by addition (sequential)
    pub fn reduce_add(&self, streams: &[ManaStream]) -> Option<ManaStream> {
        self.accelerator.sum_streams(streams)
    }
}

/// Matrix-like batch operations
impl BatchProcessor {
    /// Matrix-vector multiply (each row of matrix × vector)
    ///
    /// matrix: Vec of rows, each row is a ManaStream
    /// vector: Single ManaStream
    /// Returns: Vec of dot products (as ManaStreams)
    #[cfg(feature = "parallel")]
    pub fn matvec_par(&self, matrix: &[ManaStream], vector: &ManaStream) -> Vec<ManaStream> {
        matrix
            .par_iter()
            .map(|row| self.accelerator.mul_streams(row, vector))
            .collect()
    }

    /// Matrix-vector multiply (sequential)
    pub fn matvec(&self, matrix: &[ManaStream], vector: &ManaStream) -> Vec<ManaStream> {
        matrix
            .iter()
            .map(|row| self.accelerator.mul_streams(row, vector))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PRIMES: [u64; 3] = [998244353, 985661441, 754974721];

    #[test]
    fn test_batch_add() {
        let processor = BatchProcessor::auto();

        let pairs: Vec<(ManaStream, ManaStream)> = (0..4)
            .map(|i| {
                let a = ManaStream::from_ints(&[i * 10], &PRIMES);
                let b = ManaStream::from_ints(&[i], &PRIMES);
                (a, b)
            })
            .collect();

        let results = processor.add_batch(&pairs);

        assert_eq!(results.len(), 4);
        assert_eq!(results[0].reconstruct_at(0), 0); // 0 + 0
        assert_eq!(results[1].reconstruct_at(0), 11); // 10 + 1
        assert_eq!(results[2].reconstruct_at(0), 22); // 20 + 2
        assert_eq!(results[3].reconstruct_at(0), 33); // 30 + 3
    }

    #[test]
    fn test_reduce_add() {
        let processor = BatchProcessor::auto();

        let streams: Vec<ManaStream> = (1..=5)
            .map(|i| ManaStream::from_ints(&[i as u64], &PRIMES))
            .collect();

        let sum = processor.reduce_add(&streams).unwrap();

        // 1 + 2 + 3 + 4 + 5 = 15
        assert_eq!(sum.reconstruct_at(0), 15);
    }

    #[cfg(feature = "parallel")]
    #[test]
    fn test_reduce_add_par() {
        let processor = BatchProcessor::auto();

        let streams: Vec<ManaStream> = (1..=8)
            .map(|i| ManaStream::from_ints(&[i as u64], &PRIMES))
            .collect();

        let sum = processor.reduce_add_par(&streams).unwrap();

        // 1+2+3+4+5+6+7+8 = 36
        assert_eq!(sum.reconstruct_at(0), 36);
    }

    #[test]
    fn test_broadcast_add() {
        let processor = BatchProcessor::auto();

        let streams: Vec<ManaStream> = (0..3)
            .map(|i| ManaStream::from_ints(&[i * 10], &PRIMES))
            .collect();

        let addend = ManaStream::from_ints(&[5], &PRIMES);

        let results = processor.broadcast_add(&streams, &addend);

        assert_eq!(results[0].reconstruct_at(0), 5); // 0 + 5
        assert_eq!(results[1].reconstruct_at(0), 15); // 10 + 5
        assert_eq!(results[2].reconstruct_at(0), 25); // 20 + 5
    }
}
