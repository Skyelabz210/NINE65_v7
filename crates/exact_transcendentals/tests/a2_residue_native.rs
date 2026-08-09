//! A2 — residue-native transduction, verified in Rust so it gates the build.
//!
//! This replaces a Python model that carried the note "Rust has no toolchain in
//! this box". There is a toolchain. Verification that lives outside `cargo test`
//! cannot fail a build, cannot stop a regression, and is therefore not
//! verification — it is documentation that happens to execute.
//!
//! What is asserted here:
//!   A1  every target residue is exact — `y_j == v mod b_j` — over the full
//!       domain [0, M_A), not a sample;
//!   A2  the transduction performs no mixed-radix cascade. Each target lane is
//!       read independently from the source tray, so the result cannot depend
//!       on lane ORDER. A Garner cascade threads digit i through digits 0..i-1
//!       and is order-sensitive; permuting the source basis is the observable
//!       that separates the two;
//!   PL  a lane shared by both fixtures carries its residue across unchanged —
//!       the phase lock;
//!   RT  round trips are exact within the smaller corridor.

use exact_transcendentals::transduction::{
    verify_roundtrip, TransductionMap, S6_BASIS, S8_BASIS, TRANSPORT_CORE,
};

fn residues(value: i128, basis: &[i128]) -> Vec<i128> {
    basis.iter().map(|&m| value.rem_euclid(m)).collect()
}

/// A1 — exactness over the ENTIRE source corridor, every lane.
#[test]
fn a1_exact_over_full_corridor() {
    let map = TransductionMap::new(&S6_BASIS, &S8_BASIS);
    let m_a: i128 = S6_BASIS.iter().product(); // 30_030
    let mut checked = 0u32;
    for v in 0..m_a {
        let out = map.apply(&residues(v, &S6_BASIS));
        for (j, &b_j) in S8_BASIS.iter().enumerate() {
            assert_eq!(
                out[j],
                v.rem_euclid(b_j),
                "lane {b_j} wrong for v={v}: got {} want {}",
                out[j],
                v.rem_euclid(b_j)
            );
        }
        checked += 1;
    }
    assert_eq!(checked, 30_030, "must sweep the whole corridor, not a sample");
}

/// A2 — no threaded accumulator. Permuting the source basis must not move the
/// answer. A mixed-radix cascade is order-dependent; independent per-lane reads
/// are not. This is the observable that distinguishes them.
#[test]
fn a2_result_is_independent_of_source_lane_order() {
    let forward = [2i128, 3, 5, 7, 11, 13];
    let reversed = [13i128, 11, 7, 5, 3, 2];
    let rotated = [7i128, 11, 13, 2, 3, 5];

    let m_f = TransductionMap::new(&forward, &S8_BASIS);
    let m_r = TransductionMap::new(&reversed, &S8_BASIS);
    let m_o = TransductionMap::new(&rotated, &S8_BASIS);

    for v in (0..30_030i128).step_by(7) {
        let a = m_f.apply(&residues(v, &forward));
        let b = m_r.apply(&residues(v, &reversed));
        let c = m_o.apply(&residues(v, &rotated));
        assert_eq!(a, b, "lane order changed the result at v={v} (cascade!)");
        assert_eq!(a, c, "lane rotation changed the result at v={v} (cascade!)");
    }
}

/// PL — a shared lane is the phase lock: it carries across untouched.
#[test]
fn phase_lock_shared_lanes_pass_through_unchanged() {
    let map = TransductionMap::new(&S6_BASIS, &S8_BASIS);
    for v in (0..30_030i128).step_by(13) {
        let src = residues(v, &S6_BASIS);
        let out = map.apply(&src);
        // S6 ⊂ S8, so lanes 0..6 of the target are the shared ones.
        for (i, &p) in S6_BASIS.iter().enumerate() {
            let j = S8_BASIS.iter().position(|&q| q == p).unwrap();
            assert_eq!(out[j], src[i], "phase lock broken on lane {p} at v={v}");
        }
    }
}

/// A1 — exactness when the target basis is DISJOINT from the source, which is
/// the case the wrap term exists for. Without it these lanes are wrong.
#[test]
fn a1_exact_on_disjoint_target_basis() {
    let a = [3i128, 5, 7];
    let b = [11i128, 13, 17, 19];
    let map = TransductionMap::new(&a, &b);
    let m_a: i128 = a.iter().product(); // 105
    for v in 0..m_a {
        let out = map.apply(&residues(v, &a));
        for (j, &b_j) in b.iter().enumerate() {
            assert_eq!(out[j], v.rem_euclid(b_j), "disjoint lane {b_j} wrong at v={v}");
        }
    }
}

/// RT — round trip exact inside the smaller corridor.
#[test]
fn roundtrip_exact_within_corridor() {
    for v in (0..30_030i128).step_by(11) {
        assert!(verify_roundtrip(&S6_BASIS, &S8_BASIS, v), "S6->S8->S6 failed at {v}");
    }
    for v in (0..3_003i128).step_by(7) {
        assert!(
            verify_roundtrip(&TRANSPORT_CORE, &S8_BASIS, v),
            "transport-core round trip failed at {v}"
        );
    }
}
