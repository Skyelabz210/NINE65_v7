//! Compile and behavior gate for the staged lift-aware transduction module.
//!
//! The production module is intentionally staged as a sibling source file so
//! this PR can prove it before changing the crate's public API.  These shim
//! modules make its `crate::k_elim` / `crate::transduction` imports resolve in
//! the integration-test crate.  After the gate is green, the execution agent
//! may expose it from `lib.rs` with `pub mod lifted_transduction;`.

mod k_elim {
    pub use exact_transcendentals::k_elim::*;
}

mod transduction {
    pub use exact_transcendentals::transduction::*;
}

#[path = "../src/lifted_transduction.rs"]
mod lifted_transduction;

use exact_transcendentals::transduction::{S6_BASIS, S8_BASIS};
use lifted_transduction::{project_with_lift, transduct_with_lift};

fn residues(x: i128, basis: &[i128]) -> Vec<i128> {
    basis
        .iter()
        .map(|&m| exact_transcendentals::k_elim::modd(x, m))
        .collect()
}

#[test]
fn staged_module_compiles_and_resolves_first_s6_wrap() {
    let x = 30_030i128;
    let source = residues(x, &S6_BASIS);
    assert_eq!(source, residues(0, &S6_BASIS));

    // The phase-lock layer derives K=1 for the first wrapped S6 sheet.  The
    // staged transducer consumes only K modulo each target lane.
    let k_mod_targets: Vec<i128> = S8_BASIS.iter().map(|&b| 1 % b).collect();
    let out = transduct_with_lift(&S6_BASIS, &S8_BASIS, &source, &k_mod_targets)
        .expect("lift-aware transduction must accept the certified first sheet");

    assert_eq!(out, residues(x, &S8_BASIS));
    assert_eq!((out[6], out[7]), (8, 10));
}

#[test]
fn staged_projection_handles_shared_factor_composites() {
    let m = 30_030i128;
    let g = 29i128;
    let k = 17i128;
    let x = g + k * m;

    for b in [1i128, 4, 6, 9, 12, 18, 35, 77, 143, 256] {
        let got = project_with_lift(
            exact_transcendentals::k_elim::modd(g, b),
            exact_transcendentals::k_elim::modd(k, b),
            exact_transcendentals::k_elim::modd(m, b),
            b,
        )
        .expect("positive target modulus");
        assert_eq!(got, exact_transcendentals::k_elim::modd(x, b), "b={b}");
    }
}
