//! Finite arrow-harness traces from the actual coefficient implementation.
//! Run with `cargo run -p nine65 --release --example recumbent_arrow_trace -- drop`
//! or replace `drop` with `rank`. All scalar division here is a test oracle;
//! the operation under observation is the public recumbent API.

use nine65::arithmetic::recumbent::{
    RecumbentBasis, RecumbentCoefficient, Rounding, SignedInterval,
};

const MAIN: [u64; 3] = [2, 3, 5];
const ANCHOR: [u64; 1] = [7];
const INPUT: [u64; 4] = [2, 3, 5, 7];
const SCHEDULES: [[u64; 3]; 6] = [
    [2, 3, 5],
    [2, 5, 3],
    [3, 2, 5],
    [3, 5, 2],
    [5, 2, 3],
    [5, 3, 2],
];

fn observe(x: i128, main: &[u64], rank: bool) -> (Vec<u64>, Vec<u64>) {
    let basis = RecumbentBasis::new(main.to_vec(), ANCHOR.to_vec()).unwrap();
    let coefficient =
        RecumbentCoefficient::from_coefficient(x, basis, SignedInterval::new(0, 209).unwrap())
            .unwrap();
    let divided = if rank {
        coefficient
            .divide_with_rank_projection(2, Rounding::Floor)
            .unwrap()
    } else {
        coefficient
            .drop_main(main.iter().position(|&m| m == 2).unwrap(), Rounding::Floor)
            .unwrap()
    };
    let q = divided.coefficient;
    let moduli: Vec<_> = q
        .basis()
        .main_moduli()
        .iter()
        .chain(q.basis().anchor_moduli())
        .copied()
        .collect();
    let residues: Vec<_> = q
        .primary()
        .residues()
        .iter()
        .chain(q.overflow().residues())
        .copied()
        .collect();
    let canonical_output = if rank { &INPUT[..] } else { &INPUT[1..] };
    let mut output: Vec<_> = canonical_output
        .iter()
        .map(|m| residues[moduli.iter().position(|p| p == m).unwrap()])
        .collect();
    output.push(divided.remainder as u64);
    // Reverse by the actual quotient and remainder, not by saved input X.
    let restored = INPUT
        .iter()
        .map(|&m| {
            if !rank && m == 2 {
                divided.remainder as u64
            } else {
                let digit = residues[moduli.iter().position(|&p| p == m).unwrap()];
                ((2 * digit as u128 + divided.remainder as u128) % m as u128) as u64
            }
        })
        .collect();
    (output, restored)
}

fn main() {
    let mode = std::env::args().nth(1).unwrap_or_else(|| "drop".into());
    assert!(
        mode == "drop" || mode == "rank",
        "mode must be drop or rank"
    );
    let rank = mode == "rank";
    let output_moduli = if rank {
        vec![2, 3, 5, 7, 2]
    } else {
        vec![3, 5, 7, 2]
    };
    println!(
        "{{\"name\":\"recumbent_{mode}\",\"input_moduli\":{INPUT:?},\"output_moduli\":{output_moduli:?},\"exhaustive_product\":true,\"rows\":["
    );
    for x in 0..210i128 {
        let input = INPUT.map(|m| x.rem_euclid(m as i128) as u64);
        let (output, restored) = observe(x, &MAIN, rank);
        let order_outputs: Vec<_> = SCHEDULES
            .iter()
            .map(|schedule| observe(x, schedule, rank).0)
            .collect();
        let quotient_moduli = if rank { &INPUT[..] } else { &INPUT[1..] };
        let mut expected: Vec<_> = quotient_moduli
            .iter()
            .map(|&m| (x / 2).rem_euclid(m as i128) as u64)
            .collect();
        expected.push(x.rem_euclid(2) as u64);
        let separator = if x == 209 { "" } else { "," };
        println!(
            "{{\"input\":{input:?},\"output\":{output:?},\"restored\":{restored:?},\"expected\":{expected:?},\"order_outputs\":{order_outputs:?}}}{separator}"
        );
    }
    println!("]}}");
}
