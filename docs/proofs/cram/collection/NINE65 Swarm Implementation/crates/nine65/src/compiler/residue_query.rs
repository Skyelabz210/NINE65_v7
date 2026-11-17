//! Opt-in clear-residue query adapter. All scheduling choices use public query
//! counts; this module does not synthesize encrypted observations or claim the
//! variable-time quotient consumer is a ciphertext circuit.

#![deny(clippy::float_arithmetic)]

pub use cram_core::query_runtime::{
    AdjacentProducer, DemandPlan, ProducerCandidate, ProducerSelection, QueryError, QueryOutput,
    QuerySpec, SourceState,
};

/// Unrestricted-integer information planning. The live bounded runtime below
/// has a separate public interval certificate and may require less information.
pub fn plan_information(
    observed_moduli: &[u64],
    queries: &[QuerySpec],
) -> Result<DemandPlan, QueryError> {
    cram_core::query_runtime::plan_demands(observed_moduli, queries)
}

/// Select public available-producer descriptions; this does not issue readings.
pub fn choose_observation_producers(
    observed_moduli: &[u64],
    queries: &[QuerySpec],
    available: &[ProducerCandidate],
) -> Result<ProducerSelection, QueryError> {
    cram_core::query_runtime::select_producers(observed_moduli, queries, available)
}

/// Execute only after every query plan passes source/frame and public work
/// admission. Output order matches query order. `accelerated` selects the live
/// UNHAL/MANA deterministic lane runner; otherwise the same plans run serially.
/// The borrowed source cannot be updated while these queries execute.
pub fn execute_residue_queries(
    producer: &AdjacentProducer,
    state: &SourceState,
    queries: &[QuerySpec],
) -> Result<Vec<QueryOutput>, QueryError> {
    let observation = producer.observe(state)?;
    let plans = queries
        .iter()
        .map(|&query| observation.plan(query))
        .collect::<Result<Vec<_>, _>>()?;

    #[cfg(feature = "accelerated")]
    let results = unhal::accelerator::Accelerator::auto()
        .run_lanes(plans.len(), |lane| observation.execute(&plans[lane]));

    #[cfg(not(feature = "accelerated"))]
    let results: Vec<_> = plans.iter().map(|plan| observation.execute(plan)).collect();

    results.into_iter().collect()
}
