//! Deterministic lane executor — the missing piece recorded as ledger entry
//! `[31]` (deterministic-lane-parallelism).
//!
//! MANA's premise is that CRT prime moduli are independent compute lanes.
//! Until now the only parallel dispatch was the rayon work-stealing pool,
//! feature-gated off by default because general-purpose work stealing is
//! neither needed nor wanted here. This module is the purpose-built
//! replacement: scoped OS threads over an indexed task list, no external
//! dependencies, no `unsafe`, and — the property that matters for this
//! project — **bit-identical output regardless of thread count or
//! scheduling order**.
//!
//! # Determinism argument
//!
//! Each lane's work is a pure function of that lane's inputs. Every lane
//! writes its result into its own pre-assigned output slot, so the output
//! vector is ordered by lane index, never by completion order. Threads
//! claim lane indices from an atomic counter; the claim order affects only
//! *which thread* computes a lane, not *what* is computed or *where* it
//! lands. Output is therefore a deterministic function of the inputs alone,
//! satisfying the workspace's bit-identical-across-platforms rule with any
//! thread count, including one.
//!
//! # Constant-time posture
//!
//! The schedule depends only on the number of lanes and the thread count —
//! both public parameters. No branch in this module inspects lane *values*.

use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::OnceLock;

/// Number of worker threads the executor will use, decided once per process.
fn worker_count() -> usize {
    static WORKERS: OnceLock<usize> = OnceLock::new();
    *WORKERS.get_or_init(|| {
        std::thread::available_parallelism()
            .map(NonZeroUsize::get)
            .unwrap_or(1)
    })
}

/// Minimum number of lanes before spawning threads is worth the overhead.
/// Below this, the sequential path runs — the *output* is identical either
/// way; this threshold affects wall-clock only.
const MIN_PARALLEL_LANES: usize = 2;

/// Run `lane_fn` for each lane index in `0..lanes`, in parallel across OS
/// threads, returning results ordered by lane index.
///
/// The closure must be a pure function of the lane index (and whatever
/// captured immutable state it reads): it is invoked exactly once per lane,
/// possibly from different threads across calls.
///
/// Output is bit-identical to `(0..lanes).map(lane_fn).collect()` for every
/// thread count. That equivalence is asserted by this module's tests and is
/// the contract callers may rely on.
pub fn run_lanes<T, F>(lanes: usize, lane_fn: F) -> Vec<T>
where
    T: Send,
    F: Fn(usize) -> T + Sync,
{
    let workers = worker_count().min(lanes);
    if lanes < MIN_PARALLEL_LANES || workers < 2 {
        return (0..lanes).map(lane_fn).collect();
    }

    // One pre-assigned slot per lane; completion order cannot reorder output.
    let mut slots: Vec<Option<T>> = Vec::with_capacity(lanes);
    slots.resize_with(lanes, || None);
    let next = AtomicUsize::new(0);

    // Hand each worker a disjoint set of slot references up front. A worker
    // may only *fill* slots for lane indices it claimed from the atomic
    // counter, so slots are partitioned dynamically — but Rust's aliasing
    // rules require the mutable borrows to be disjoint statically. The
    // simplest safe shape: give every worker its own Vec of (index, &mut
    // slot) pairs? That would be a static partition, losing dynamic
    // balancing. Instead, collect results per worker and write them back on
    // the main thread — the join order is fixed (worker 0..w), and each
    // result carries its lane index, so placement stays index-determined.
    let mut per_worker: Vec<Vec<(usize, T)>> = std::thread::scope(|scope| {
        let handles: Vec<_> = (0..workers)
            .map(|_| {
                let next = &next;
                let lane_fn = &lane_fn;
                scope.spawn(move || {
                    let mut out: Vec<(usize, T)> = Vec::new();
                    loop {
                        let i = next.fetch_add(1, Ordering::Relaxed);
                        if i >= lanes {
                            break;
                        }
                        out.push((i, lane_fn(i)));
                    }
                    out
                })
            })
            .collect();
        handles
            .into_iter()
            .map(|h| h.join().expect("lane worker panicked"))
            .collect()
    });

    for bucket in per_worker.drain(..) {
        for (i, value) in bucket {
            debug_assert!(slots[i].is_none(), "lane {i} computed twice");
            slots[i] = Some(value);
        }
    }
    slots
        .into_iter()
        .enumerate()
        .map(|(i, s)| s.unwrap_or_else(|| panic!("lane {i} never computed")))
        .collect()
}

/// Sequential reference implementation of [`run_lanes`], for A/B
/// bit-identity checks. Kept public so downstream crates can assert the
/// contract against their own lane functions.
pub fn run_lanes_sequential<T, F>(lanes: usize, lane_fn: F) -> Vec<T>
where
    F: Fn(usize) -> T,
{
    (0..lanes).map(lane_fn).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn work(i: usize) -> Vec<u64> {
        // Deterministic per-lane computation with distinct shape per lane.
        let p = [2u64, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37][i % 12];
        (0..256u64)
            .map(|x| x.wrapping_mul(p).wrapping_add(i as u64) % (p * p))
            .collect()
    }

    #[test]
    fn parallel_matches_sequential_bit_identically() {
        for lanes in [0usize, 1, 2, 3, 8, 16, 33] {
            let par = run_lanes(lanes, work);
            let seq = run_lanes_sequential(lanes, work);
            assert_eq!(par, seq, "lanes={lanes}");
        }
    }

    #[test]
    fn output_is_ordered_by_lane_index_not_completion() {
        // Lane 0 does far more work than lane N-1; if completion order
        // leaked into output order this would scramble.
        let lanes = 8;
        let out = run_lanes(lanes, |i| {
            let spin = if i == 0 { 200_000u64 } else { 10 };
            let mut acc = i as u64;
            for k in 0..spin {
                acc = acc.wrapping_mul(6364136223846793005).wrapping_add(k);
            }
            (i as u64) << 32 | (acc & 0) // value encodes only the lane index
        });
        for (i, v) in out.iter().enumerate() {
            assert_eq!(*v >> 32, i as u64);
        }
    }

    #[test]
    fn every_lane_computed_exactly_once() {
        use std::sync::atomic::AtomicU64;
        let counters: Vec<AtomicU64> = (0..24).map(|_| AtomicU64::new(0)).collect();
        let _ = run_lanes(24, |i| counters[i].fetch_add(1, Ordering::Relaxed));
        for (i, c) in counters.iter().enumerate() {
            assert_eq!(c.load(Ordering::Relaxed), 1, "lane {i}");
        }
    }
}
