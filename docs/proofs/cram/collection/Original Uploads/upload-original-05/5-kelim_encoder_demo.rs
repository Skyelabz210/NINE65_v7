//! Multi-turn absolute encoder demonstrator (35/36 adjacent-composite gears).
//!
//! Two gears, 35 and 36 teeth, on one shaft. Each gear's tooth position is a
//! residue. Absolute shaft position over the full 1260-position supercycle is
//! recovered by a single subtraction — no inverse, no lookup, no CRT solver.
//!
//! Run: `cargo run --release --bin encoder_demo`

use kelim::k_elim_adjacent;

const M1: i128 = 35; // primary gear
const M2: i128 = 36; // adjacent anchor gear (M1 + 1)

/// Absolute position from two gear residues. Subtraction-only winding.
fn encoder_readout(sensor35: i128, sensor36: i128) -> i128 {
    let k = k_elim_adjacent(sensor35, sensor36, M1); // ⌊X/35⌋
    sensor35 + k * M1
}

fn main() {
    let supercycle = M1 * M2; // 1260

    // Exhaustive self-test
    let mut errors = 0;
    for x in 0..supercycle {
        let s35 = x % M1;
        let s36 = x % M2;
        if encoder_readout(s35, s36) != x {
            errors += 1;
        }
    }

    println!("Multi-turn absolute encoder — 35/36 adjacent-composite gears");
    println!("Supercycle: {} positions", supercycle);
    println!("Exhaustive self-test: {} errors", errors);
    println!();
    println!("  {:>5} | {:>7} {:>7} | {:>10}", "X", "gear35", "gear36", "recovered");
    for x in [0, 100, 629, 630, 1000, 1259] {
        let s35 = x % M1;
        let s36 = x % M2;
        let rec = encoder_readout(s35, s36);
        let ok = if rec == x { "OK" } else { "FAIL" };
        println!("  {:>5} | {:>7} {:>7} | {:>10}  {}", x, s35, s36, rec, ok);
    }
    println!();
    println!("Per-readout: 1 subtraction, 1 modulo, 1 multiply, 1 add.");
    assert_eq!(errors, 0, "encoder must be exact over all positions");
}
