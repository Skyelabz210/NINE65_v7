//! Matched clear-workload measurements, not an FHE or RNS speedup claim.
use cram_core::query_runtime::{AdjacentProducer, QueryCost, QuerySpec};
use std::hint::black_box;
use std::time::Instant;

fn main() {
    let queries = [
        QuerySpec::LinearResidue {
            coefficient: 3,
            offset: -7,
            modulus: 19,
        },
        QuerySpec::FloorQuotient {
            divisor: 36,
            modulus: 37,
            negate: false,
        },
        QuerySpec::FloorQuotient {
            divisor: 6,
            modulus: 19,
            negate: false,
        },
    ];
    let setup = Instant::now();
    let producer = AdjacentProducer::frame_36_37(1331).unwrap();
    let setup_ns = setup.elapsed().as_nanos();
    let ingress = Instant::now();
    let states: Vec<_> = (0..1332).map(|x| producer.ingress(x).unwrap()).collect();
    let ingress_ns = ingress.elapsed().as_nanos();
    let planning = Instant::now();
    let plans: Vec<Vec<_>> = states
        .iter()
        .map(|state| {
            let view = producer.observe(state).unwrap();
            queries.iter().map(|q| view.plan(*q).unwrap()).collect()
        })
        .collect();
    let planning_ns = planning.elapsed().as_nanos();
    let oracle = |x: u64| {
        [
            ((3 * x as i128 - 7).rem_euclid(19)) as u64,
            (x / 36) % 37,
            (x / 6) % 19,
        ]
    };
    // Establish equality before taking any runtime measurements.
    for (x, (state, row)) in states.iter().zip(&plans).enumerate() {
        let view = producer.observe(state).unwrap();
        for (plan, expected) in row.iter().zip(oracle(x as u64)) {
            assert_eq!(view.execute(plan).unwrap().residue, expected);
        }
    }
    let mut rows = Vec::new();
    let mut counts = QueryCost::default();
    for run in 0..3 {
        let begin = Instant::now();
        let mut steady_checksum = 0;
        for (state, row) in states.iter().zip(&plans) {
            let view = producer.observe(black_box(state)).unwrap();
            for plan in row {
                let output = view.execute(black_box(plan)).unwrap();
                steady_checksum += black_box(output.residue);
                if run == 0 {
                    counts.modular_additions += output.cost.modular_additions;
                    counts.modular_subtractions += output.cost.modular_subtractions;
                    counts.modular_multiplications += output.cost.modular_multiplications;
                    counts.winding_readouts += output.cost.winding_readouts;
                    counts.integer_comparisons += output.cost.integer_comparisons;
                    counts.loop_iterations += output.cost.loop_iterations;
                }
            }
        }
        let steady_ns = begin.elapsed().as_nanos();
        let begin = Instant::now();
        let baseline_checksum: u64 = (0..1332)
            .map(|x| oracle(black_box(x)).into_iter().map(black_box).sum::<u64>())
            .sum();
        let baseline_ns = begin.elapsed().as_nanos();
        let begin = Instant::now();
        let mut full_checksum = 0;
        for x in 0..1332 {
            let state = producer.ingress(black_box(x)).unwrap();
            let view = producer.observe(&state).unwrap();
            for query in queries {
                let plan = view.plan(black_box(query)).unwrap();
                full_checksum += black_box(view.execute(&plan).unwrap().residue);
            }
        }
        let full_ns = begin.elapsed().as_nanos();
        assert_eq!(steady_checksum, baseline_checksum);
        assert_eq!(full_checksum, baseline_checksum);
        rows.push(format!("{{\"run\":{run},\"steady_query_ns\":{steady_ns},\"integer_boundary_baseline_ns\":{baseline_ns},\"ingress_plan_query_ns\":{full_ns},\"checksum\":{full_checksum}}}"));
    }
    println!("{{\"scope\":\"clear integer boundary baseline versus bounded residue query runtime; no speedup claim\",\"states\":1332,\"queries_per_state\":3,\"setup_ns\":{setup_ns},\"ingress_ns\":{ingress_ns},\"planning_ns\":{planning_ns},\"runs\":[{}],\"counted_modular_additions\":{},\"counted_modular_subtractions\":{},\"counted_modular_multiplications\":{},\"counted_winding_readouts\":{},\"counted_comparisons\":{},\"counted_loop_iterations\":{}}}", rows.join(","),counts.modular_additions,counts.modular_subtractions,counts.modular_multiplications,counts.winding_readouts,counts.integer_comparisons,counts.loop_iterations);
}
