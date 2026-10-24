//! Research bridge: K-elimination supplies the lattice-sheet coordinate of
//! the rank-one tropical theta lift. Clear residue inputs only; this harness
//! does not implement an encrypted centered-phase producer or BFV refresh.

use exact_transcendentals::k_elim::{gcd, k_eliminate, mod_inv, modd, mulmod};
use exact_transcendentals::lifted_transduction::project_with_lift;
use exact_transcendentals::transduction::S8_BASIS;

// Derive the winding residue directly. Unlike k_eliminate's observation
// result, this does not materialize g + Q*K, which can exceed i128 at native Q.
fn winding_residue(q: i128, g: i128, s_mod_a: i128, a: i128) -> Option<i128> {
    if q < 3 || q % 2 == 0 || g.abs() > q / 2 || a < 2 {
        return None;
    }
    let inverse = mod_inv(q, a)?;
    Some(mulmod(s_mod_a - modd(g, a), inverse, a))
}

// A public corridor must come from the state's history. This read cannot
// detect a true winding displaced by a whole multiple of A (tested below).
fn signed_corridor(residue: i128, a: i128, bound: i128) -> Option<i128> {
    if bound < 0 || 2 * bound >= a || !(0..a).contains(&residue) {
        None
    } else if residue <= bound {
        Some(residue)
    } else if residue >= a - bound {
        Some(residue - a)
    } else {
        None
    }
}

// Independent finite search for twice the rank-one min-plus theta function:
// T_Q(z) = min_n [Q*n^2 + 2*n*z]. All toy minima lie within this search range.
fn theta_oracle(q: i128, z: i128, search: i128) -> (i128, Vec<i128>) {
    let values: Vec<_> = (-search..=search)
        .map(|n| (q * n * n + 2 * n * z, n))
        .collect();
    let minimum = values.iter().map(|&(value, _)| value).min().unwrap();
    let minimizers = values
        .into_iter()
        .filter_map(|(value, n)| (value == minimum).then_some(n))
        .collect();
    (minimum, minimizers)
}

#[test]
fn k_elimination_selects_the_exact_tropical_theta_sheet() {
    let mut checked = 0;
    for q in [3i128, 5, 7, 11, 17, 31] {
        let a = 2 * q + 1; // Includes composite anchors 15, 35 and 63.
        let bound = q - 1;
        for k in -bound..=bound {
            for g in -q / 2..=q / 2 {
                let s = g + q * k; // Toy oracle only.
                let residue = winding_residue(q, g, modd(s, a), a).unwrap();
                let recovered = signed_corridor(residue, a, bound).unwrap();
                let (theta, minimizers) = theta_oracle(q, s, bound + 2);
                assert_eq!(recovered, k);
                assert_eq!(minimizers, vec![-recovered]);
                assert_eq!(theta, -2 * recovered * g - q * recovered * recovered);

                // Exercise the existing general K-elimination implementation
                // as well, with its canonical (rather than centered) chart.
                let canonical = modd(s, q);
                let general = k_eliminate(canonical, q, modd(s, a), a).unwrap();
                let chart_change = i128::from(canonical > q / 2);
                assert_eq!(residue, modd(general.k + chart_change, a));
                checked += 1;
            }
        }
    }
    assert!(checked > 2500);
}

#[test]
fn lifted_theta_cocycle_composes_without_enumerating_source_assignments() {
    let q = 17;
    let cocycle = |z: i128, k: i128| -2 * k * z - q * k * k;
    for g in -q / 2..=q / 2 {
        for k in -5..=5 {
            for l in -5..=5 {
                assert_eq!(cocycle(g, k + l), cocycle(g, k) + cocycle(g + q * k, l));
                let (actual, _) = theta_oracle(q, g + q * (k + l), 12);
                assert_eq!(actual, cocycle(g, k + l));
            }
        }
    }
    // Discarding the sheet loses the theta lift even though the torus point
    // stays unchanged. This is a direct negative control for zero-winding.
    assert_eq!(modd(1, q), modd(1 + q, q));
    assert_ne!(theta_oracle(q, 1, 3).0, theta_oracle(q, 1 + q, 3).0);
}

#[test]
fn theta_difference_exposes_the_two_eleven_phase_relation_at_cell_walls() {
    let q = 17;
    for k in -12..=12 {
        for g in -q / 2..=q / 2 {
            let z = g + q * k;
            let difference = theta_oracle(q, z + 1, 15).0 - theta_oracle(q, z, 15).0;
            let boundary = i128::from(g == q / 2);
            assert_eq!(difference, -2 * k - boundary);
            let parity = modd(difference, 2);
            assert_eq!(parity, boundary);
            let k_mod_11 = modd(-(difference + parity) * 6, 11);
            assert_eq!(k_mod_11, modd(k, 11));
        }
    }
}

#[test]
fn composite_sister_differences_lift_every_native_sheet() {
    // One Safe-Basis root supplies the 2 and 11 phases. Its prime-power
    // sisters 7^2, 11^2, and 5^2 then provide enough odd CRT period to lift
    // the native |K| <= 4096 corridor without another root.
    let trays = [49i128, 121, 25];
    let mut period = 1i128;
    for tray in trays {
        assert_eq!(gcd(period, tray), 1);
        period *= tray;
    }
    assert_eq!(period, 148_225);
    assert!(2 * 4096 < period);

    for k in -4096i128..=4096 {
        for boundary in [0i128, 1] {
            // The tropical finite difference is D=-2K-b. Its 2-tray view
            // returns the wall bit, which makes (D+b) exactly even.
            let difference = -2 * k - boundary;
            let recovered_boundary = modd(difference, 2);
            assert_eq!(recovered_boundary, boundary);

            // Divide only after the phase lock has supplied b. In each odd
            // sister tray, multiplication by 2^-1 is exactly K mod tray.
            let residues: Vec<_> = trays
                .iter()
                .map(|&tray| {
                    let inverse_two = mod_inv(2, tray).unwrap();
                    modd(-(difference + recovered_boundary) * inverse_two, tray)
                })
                .collect();

            // K-Elimination/CRT combines the arbitrary sister views into the
            // unique signed sheet in the certified corridor.
            let mut value = 0i128;
            let mut accumulated = 1i128;
            for (&residue, &tray) in residues.iter().zip(&trays) {
                let delta = modd(residue - modd(value, tray), tray);
                let correction = mulmod(delta, mod_inv(accumulated, tray).unwrap(), tray);
                value += accumulated * correction;
                accumulated *= tray;
            }
            assert_eq!(accumulated, period);
            assert_eq!(signed_corridor(value, period, 4096), Some(k));
        }
    }

    // The 2/11 pair alone cannot distinguish sheets separated by 22.
    assert_eq!((modd(7, 2), modd(7, 11)), (modd(29, 2), modd(29, 11)));
}

#[test]
fn native_q_and_one_safe_root_resolve_the_full_bounded_sheet_corridor() {
    let q = 348_959_453_350_711_275_087_786_864_768_188_417i128;
    let a: i128 = S8_BASIS.iter().product();
    let bound = 4096;
    assert_eq!(a, 9_699_690);
    assert_eq!(gcd(q, a), 1);
    assert!(2 * bound < a);
    let h = q / 2;
    let sisters = [1i128, 2, 4, 6, 11, 22, 33, 77, 121, 256, 1024];
    let mut checked = 0;
    for k in -bound..=bound {
        for g in [-h, -h + 1, -1, 0, 1, h - 1, h] {
            // Construct authentic coordinates without constructing S=g+Q*K.
            let s_mod_a = modd(modd(g, a) + mulmod(q, k, a), a);
            let residue = winding_residue(q, g, s_mod_a, a).unwrap();
            let recovered = signed_corridor(residue, a, bound).unwrap();
            assert_eq!(recovered, k);
            // Strict adjacent inequalities certify the unique minimum of
            // the convex quadratic at n=-K, including both chart endpoints.
            assert!(q - 2 * g > 0 && q + 2 * g > 0);
            for b in sisters {
                let projected =
                    project_with_lift(modd(g, b), modd(recovered, b), modd(q, b), b).unwrap();
                assert_eq!(projected, modd(modd(g, b) + mulmod(q, k, b), b));
            }
            checked += 1;
        }
    }
    assert_eq!(checked, 57_351);
}

#[test]
fn missing_corridor_and_missing_lift_information_have_explicit_aliases() {
    let (q, a, g, k) = (17i128, 35i128, 1i128, 3i128);
    let coordinate = |sheet| modd(g + q * sheet, a);
    assert_eq!(coordinate(k), coordinate(k + a));
    assert_eq!(
        winding_residue(q, g, coordinate(k), a),
        winding_residue(q, g, coordinate(k + a), a)
    );
    assert_eq!(signed_corridor(3, a, 17), Some(3));
    assert_eq!(signed_corridor(3, a, 18), None);
    assert_eq!(signed_corridor(10, a, 3), None);
    // The owner's 2/11 views fix useful phases but alone have period 22.
    assert_eq!(
        (modd(k, 2), modd(k, 11)),
        (modd(k + 22, 2), modd(k + 22, 11))
    );
    assert_eq!(winding_residue(5, 0, 0, 10), None);
}

#[test]
fn even_period_theta_wall_needs_a_tie_convention() {
    assert_eq!(theta_oracle(6, 3, 3), (0, vec![-1, 0]));
    assert_eq!(winding_residue(6, 3, 0, 7), None);
}
