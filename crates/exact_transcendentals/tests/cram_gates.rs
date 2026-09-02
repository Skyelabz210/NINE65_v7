//! CRAM quality gates — correctness (C*) and posture (P*).
//!
//! # Why this file exists separately from the unit tests
//!
//! The `cram_*` modules each carry their own `#[cfg(test)]` suite. Those test
//! internals. This target tests the **public contract** — everything here goes
//! through `exact_transcendentals::…` exactly as a consumer would.
//!
//! It is the target that SHOULD be CI's required step for the public contract.
//! It is not one today: no file under `.github/workflows/` names `cram_gates`,
//! so nothing selects it beyond the blanket `cargo test --workspace` in
//! `ci.yml` — and that workflow has not completed a run since 2026-02-25.
//! Until that changes, this target is a gate only when someone runs it.
//!
//! A regression that a module's own tests would not see, because it moved a
//! boundary rather than a formula, fails here when this target is run.
//!
//! # Why gates rather than tests
//!
//! Today's audit found four mechanisms that were nominal — present, exercised,
//! green, and doing nothing. A suite passing is not evidence a mechanism works.
//! So every gate below is built to be able to fail:
//!
//! - exact equality on published constants, no tolerance anywhere
//! - exhaustive sweeps with an anti-shrink guard (`assert_eq!(checked, TOTAL)`)
//! - a negative control beside every containment or independence claim
//! - no counter-only assertions: the values produced are asserted, not the
//!   number of times something ran
//!
//! # Coverage
//!
//! Landed: C1–C6, C8, P1, P3, P6, P7, P8, P9.
//! Pending their build steps: C7 and P10 (Shared-Factor Lift), P2's runtime
//! counter (Garner retirement), P4 (five trays), P5's Σ half (Adelic tuple).
//! C9 (`nine65 --lib` baseline 648/3/103) is cross-crate and lives in the
//! verification command list, not here.

use exact_transcendentals::cram_anchor::{Anchor, AnchorError, AnchorFamily};
use exact_transcendentals::cram_carry::{
    carry_matrix, detailed_balance_defect, eulerian_stationary, signed_carry, star,
    winding_increment, Frac, ANCHOR, FIRING_RESIDUE, SHELL,
};
use exact_transcendentals::cram_machine::{
    canonical_from, Cram, CramError, Instr, Parity, ShadowStatus, Sign, WindingLoss,
    DISCRIMINATING_BASIS,
};
use exact_transcendentals::cram_pde::{ExactState, M_SAFE, SAFE_BASIS, TRANSPORT_CORE};
use exact_transcendentals::k_elim::{garner_reconstruct, gcd, k_eliminate, mod_inv};
use exact_transcendentals::safe_basis_io;

// ═══════════════════════════════════════════════════════════════════════════
// A. Correctness gates
// ═══════════════════════════════════════════════════════════════════════════

/// **C1** — the published constants of the carry chain, reproduced exactly.
///
/// Every value here is an exact rational from the literature. There is no
/// tolerance and there can be no near miss: a chain that is even slightly wrong
/// produces a different fraction, not a nearby one.
#[test]
fn c1_published_carry_constants_reproduce_exactly() {
    let p = carry_matrix(2, SHELL);
    assert_eq!(p[0][0], Frac::new(37, 72));
    assert_eq!(p[0][1], Frac::new(35, 72));
    assert_eq!(p[1][0], Frac::new(35, 72));
    assert_eq!(p[1][1], Frac::new(37, 72));

    // 2×2 stochastic: eigenvalues are 1 and trace − 1.
    let second = p[0][0].add(p[1][1]).sub(Frac::new(1, 1));
    assert_eq!(second, Frac::new(1, 36), "second eigenvalue is 1/36");

    // The Eulerian law is asserted stationary, not assumed to be.
    for n in 2..=5usize {
        for b in [2i128, 10, 36] {
            let m = carry_matrix(n, b);
            let pi = eulerian_stationary(n);
            for j in 0..n {
                let got = (0..n).fold(Frac::zero(), |acc, i| acc.add(pi[i].mul(m[i][j])));
                assert_eq!(got, pi[j], "πP ≠ π at n={n} b={b} j={j}");
            }
        }
    }

    // The reversibility dichotomy, both sides. The n ≥ 4 half is the negative
    // control: without it, "reversible for n ≤ 3" could be reported by a defect
    // function that is identically zero.
    for n in [2usize, 3] {
        for b in [2i128, 10, 36] {
            assert!(
                detailed_balance_defect(n, b).is_zero(),
                "n={n} b={b} must be exactly reversible"
            );
        }
    }
    for n in [4usize, 5] {
        for b in [2i128, 10, 36] {
            assert!(
                !detailed_balance_defect(n, b).is_zero(),
                "n={n} b={b} must be irreversible, or the n ≤ 3 half is vacuous"
            );
        }
    }
    assert_eq!(detailed_balance_defect(4, 2), Frac::new(1, 384));
    assert_eq!(detailed_balance_defect(5, 10), Frac::new(99, 400_000));
}

/// **C2** — the unit carry, exhaustive to 100,000, with the exact firing count.
#[test]
fn c2_unit_carry_is_binary_and_fires_only_at_thirty_five() {
    const L: i128 = 100_000;
    let mut fired = 0i128;
    let mut checked = 0i128;
    for n in 0..L {
        let dk = winding_increment(n, SHELL);
        assert!(dk == 0 || dk == 1, "ΔK = {dk} at N = {n}");
        assert_eq!(
            dk == 1,
            n.rem_euclid(SHELL) == FIRING_RESIDUE,
            "N = {n} must fire iff r = {FIRING_RESIDUE}"
        );
        fired += dk;
        checked += 1;
    }
    assert_eq!(checked, L, "sweep must not shrink");
    assert_eq!(fired, 2_777, "one firing per shell crossing below 100,000");

    // The hinge the whole construction rests on.
    assert_eq!(ANCHOR, SHELL + 1);
    assert_eq!(SHELL.rem_euclid(ANCHOR), ANCHOR - 1, "36 ≡ −1 (mod 37)");
    assert_eq!(star(3), ANCHOR, "37 = S₃");
    assert_eq!(star(4) - star(3), SHELL, "S₄ − S₃ = 36");
}

/// **C3** — the signed carry, exhaustive to 5,000, plus the closed-shell descent.
#[test]
fn c3_signed_carry_identity_and_closed_shell_descent() {
    let mut checked = 0i128;
    for n in 0..5_000i128 {
        let k = n.div_euclid(SHELL);
        let r = n.rem_euclid(SHELL);
        assert_eq!(signed_carry(n), (r - k).rem_euclid(ANCHOR), "N = {n}");
        assert_eq!(n.rem_euclid(ANCHOR), (r - k).rem_euclid(ANCHOR), "N = {n}");
        checked += 1;
    }
    assert_eq!(checked, 5_000, "sweep must not shrink");
    assert_eq!(
        [36, 72, 108, 144].map(signed_carry),
        [36, 35, 34, 33],
        "the anchor counts down as the winding counts up"
    );
}

/// **C4** — the twin form lands exactly on the firing residue, all `k < 500`.
#[test]
fn c4_twin_form_products_sit_on_the_firing_residue() {
    let mut checked = 0i128;
    for k in 1..500i128 {
        let prod = (6 * k - 1) * (6 * k + 1);
        assert_eq!(prod.rem_euclid(SHELL), FIRING_RESIDUE, "k = {k}");
        assert_eq!(prod, 36 * k * k - 1, "twin-form identity at k = {k}");
        checked += 1;
    }
    assert_eq!(checked, 499, "sweep must not shrink");
}

/// **C5** — the range hypothesis is enforced, and the alias it prevents is real.
///
/// This is the defect class that produced a silently wrong plaintext at depth 2:
/// a capacity bound that was never checked, so an over-range value came back
/// reduced instead of rejected. Every entry point must refuse.
#[test]
fn c5_out_of_range_is_refused_and_never_wrapped() {
    let anchor = Anchor::adjacent(36).unwrap();
    let cap = anchor.capacity();
    assert_eq!(cap, 1332);

    let mut refused = 0;
    for over in [cap, cap + 1, cap + 7, 2 * cap, 5 * cap + 11, i128::MAX / 4] {
        assert_eq!(
            anchor.decompose(over),
            Err(AnchorError::OutOfRange {
                x: over,
                capacity: cap
            }),
            "x = {over}"
        );
        refused += 1;
    }
    assert_eq!(refused, 6, "every over-range probe must be refused");
    assert!(anchor.decompose(-1).is_err(), "negative refused too");

    // The alias that refusal prevents, exhibited rather than described.
    let x = cap + 7;
    assert_eq!(
        anchor.lift(x % anchor.p(), x % anchor.a()).unwrap(),
        7,
        "hand-reducing an over-range value yields a consistent, wrong answer"
    );

    // The same bound on a family, and on the state-level entry point.
    let family = AnchorFamily::telescoping(6, 3).unwrap();
    let fcap = family.capacity();
    assert_eq!(fcap, 1806 * 1807);
    assert_eq!(
        family.decompose(fcap),
        Err(AnchorError::OutOfRange {
            x: fcap,
            capacity: fcap
        })
    );
    assert_eq!(
        family.lift_state(&ExactState::from_i128(fcap + 1)),
        Err(AnchorError::OutOfRange {
            x: fcap + 1,
            capacity: fcap
        })
    );
}

/// **C6** — round-trip exactness, exhaustive over the whole capacity.
#[test]
fn c6_every_value_in_range_reconstructs_bit_exact() {
    // Single anchor: the canonical 36/37 shell.
    let anchor = Anchor::adjacent(36).unwrap();
    let mut checked = 0i128;
    for x in 0..anchor.capacity() {
        let (r, a) = anchor.decompose(x).unwrap();
        assert_eq!(anchor.lift(r, a).unwrap(), x, "x = {x}");
        checked += 1;
    }
    assert_eq!(checked, 1332, "sweep must not shrink");

    // Telescoping family: the flat sum X = r₀ + Σ kⱼ·Mⱼ.
    let family = AnchorFamily::telescoping(6, 2).unwrap();
    let mut checked = 0i128;
    let mut upper_level_fired = 0i128;
    for x in 0..family.capacity() {
        let pairs = family.decompose(x).unwrap();
        let ks = family.windings(&pairs).unwrap();
        assert_eq!(family.reconstruct(&pairs, &ks).unwrap(), x, "x = {x}");
        if ks[1] != 0 {
            upper_level_fired += 1;
        }
        checked += 1;
    }
    assert_eq!(checked, 1806, "sweep must not shrink");
    assert!(
        upper_level_fired > 0,
        "the sweep must reach the upper level"
    );

    // Safe Basis corridor: every value, through ExactState.
    let mut checked = 0i128;
    for x in 0..M_SAFE {
        assert_eq!(ExactState::from_i128(x).to_i128_exact(), x, "x = {x}");
        checked += 1;
    }
    assert_eq!(checked, M_SAFE, "corridor sweep must not shrink");

    // The anchored read `g = (a + K) mod A`, over positive and negative
    // windings, plus the residue that can only mean a corrupt state.
    const M: i128 = 36;
    let mut checked = 0i128;
    for x in -500i128..500 {
        let (g, k) = (x.rem_euclid(M), x.div_euclid(M));
        let a = (g - k).rem_euclid(M + 1);
        assert_eq!(canonical_from(a, k, M), Ok(g), "x = {x}");
        assert_eq!(
            g + k * M,
            x,
            "the pair must name x, not merely be consistent"
        );
        checked += 1;
    }
    assert_eq!(checked, 1_000, "sweep must not shrink");
    assert_eq!(
        canonical_from(M, 0, M),
        Err(CramError::InconsistentState { g: M, m: M }),
        "g = M is unreachable and must be reported, not returned"
    );
}

/// **C8** — anything that cannot be represented exactly is refused, never wrapped.
#[test]
fn c8_overflow_refuses_rather_than_wraps() {
    // Winding overflow in the Safe Basis arithmetic path.
    let huge = ExactState::from_i128(i128::MAX / 2);
    assert!(
        safe_basis_io::mul(&huge, &huge).is_none(),
        "an unrepresentable product must be refused"
    );

    // Tower capacity overflow. The 36-tower squares, so it exhausts i128 at a
    // known depth; a wrapped capacity would be a range check that admits values
    // it cannot represent.
    let mut last_ok = 0usize;
    for depth in 1..=8 {
        match AnchorFamily::telescoping(36, depth) {
            Ok(f) => {
                assert!(f.capacity() > 0, "capacity must never wrap negative");
                last_ok = depth;
            }
            Err(AnchorError::CapacityOverflow { .. }) => break,
            Err(e) => panic!("unexpected error at depth {depth}: {e:?}"),
        }
    }
    assert_eq!(
        last_ok, 4,
        "the 36-tower is representable to exactly depth 4"
    );
    assert!(matches!(
        AnchorFamily::telescoping(36, 5),
        Err(AnchorError::CapacityOverflow { .. })
    ));

    // And a positive control: values that DO fit are not refused, so the gate
    // is not passing by refusing everything.
    assert!(safe_basis_io::mul(
        &ExactState::from_i128(100_003),
        &ExactState::from_i128(99_991)
    )
    .is_some());
}

// ═══════════════════════════════════════════════════════════════════════════
// B. Posture checks
// ═══════════════════════════════════════════════════════════════════════════

/// The production half of a module: everything before its `#[cfg(test)]` block.
///
/// Test code is deliberately excluded. A negative control has to *call* the
/// mechanism it is controlling against — P7's control calls Garner on purpose —
/// so a scan that included test code could only be satisfied by deleting the
/// control, which is the opposite of what these gates are for.
fn production_code(src: &str) -> String {
    let cut = src.find("#[cfg(test)]").unwrap_or(src.len());
    code_only(&src[..cut])
}

/// Strip `//` line comments and `/* */` blocks so a source scan reads code only.
fn code_only(src: &str) -> String {
    let mut out = String::with_capacity(src.len());
    let bytes: Vec<char> = src.chars().collect();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == '/' && i + 1 < bytes.len() && bytes[i + 1] == '/' {
            while i < bytes.len() && bytes[i] != '\n' {
                i += 1;
            }
        } else if bytes[i] == '/' && i + 1 < bytes.len() && bytes[i + 1] == '*' {
            i += 2;
            while i + 1 < bytes.len() && !(bytes[i] == '*' && bytes[i + 1] == '/') {
                i += 1;
            }
            i += 2;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    out
}

/// **P1** — A1 zero-float. No `cram_*` module may contain a floating-point type.
///
/// Comments are stripped first, because the modules discuss floats in prose
/// ("no floating point") and a raw substring scan would either false-positive on
/// that or be weakened until it could not fail. The scan is on code.
#[test]
fn p1_no_cram_module_contains_a_float() {
    let modules: [(&str, &str); 6] = [
        ("cram_anchor.rs", include_str!("../src/cram_anchor.rs")),
        ("cram_carry.rs", include_str!("../src/cram_carry.rs")),
        ("cram_machine.rs", include_str!("../src/cram_machine.rs")),
        ("cram_ops.rs", include_str!("../src/cram_ops.rs")),
        ("cram_pde.rs", include_str!("../src/cram_pde.rs")),
        ("safe_basis_io.rs", include_str!("../src/safe_basis_io.rs")),
    ];
    let mut scanned = 0;
    for (name, src) in modules {
        let code = production_code(src);
        for forbidden in ["f32", "f64", "powf", "sqrt()", "as f"] {
            assert!(
                !code.contains(forbidden),
                "{name} contains forbidden float token `{forbidden}`"
            );
        }
        scanned += 1;
    }
    assert_eq!(scanned, 6, "every cram module must be scanned");

    // The stripper must not be a function that deletes everything — a scan over
    // an empty string would pass trivially.
    let code = production_code(include_str!("../src/cram_anchor.rs"));
    assert!(
        code.contains("pub fn winding"),
        "stripper removed live code"
    );
    assert!(
        !code.contains("no floating point"),
        "stripper failed to remove comments"
    );
    assert!(
        !code.contains("mod tests"),
        "production slice must stop at the test module"
    );
    // …and it must actually catch a float when one is present.
    assert!(code_only("let x: f64 = 1.0; // comment").contains("f64"));
    assert!(!code_only("// f64 in a comment\n").contains("f64"));
}

/// **P2 (source half)** — the anchored read uses no Garner.
///
/// The runtime half — `garner_calls == 0` across an arithmetic run — needs the
/// instrumented counter that lands with step 8, when `safe_basis_io` stops
/// detecting its carry through `garner_reconstruct`. Until then this asserts
/// what is true now: the anchor module reaches its winding without it, and
/// `safe_basis_io` still does not, which is recorded here so the retirement is
/// visible as an outstanding debt rather than an assumed property.
#[test]
fn p2_anchored_read_is_garner_free_and_the_remaining_debt_is_named() {
    let anchor = production_code(include_str!("../src/cram_anchor.rs"));
    assert!(
        !anchor.contains("garner_reconstruct"),
        "the anchored lift must not reconstruct through Garner"
    );
    assert!(
        anchor.contains("rem_euclid(self.a)"),
        "…and it must still reach the winding by the adjacency formula"
    );

    // The outstanding debt, asserted so it cannot be quietly forgotten: this
    // flips when step 8 lands, and the flip must be a deliberate edit here.
    let pde = production_code(include_str!("../src/cram_pde.rs"));
    assert!(
        pde.contains("garner_reconstruct"),
        "ExactState::to_u128 still goes through Garner; when that changes, \
         update this gate to assert the absence instead"
    );
}

/// **P3** — execution never leaves residue space.
///
/// `projections()` counts exits and `exec` structurally cannot increment it.
/// The positive control — `project` does increment — is what stops this from
/// passing on a counter that is simply never wired up.
#[test]
fn p3_exec_never_leaves_residue_space_but_project_does() {
    let mut m = Cram::new(&DISCRIMINATING_BASIS, 3);
    m.exec(&[
        Instr::Load { dst: 0, value: 41 },
        Instr::Load { dst: 1, value: 17 },
        Instr::Apply {
            dst: 2,
            a: 0,
            b: 1,
            schema: "AMS__".into(),
        },
        Instr::Apply {
            dst: 2,
            a: 2,
            b: 1,
            schema: "AMS__".into(),
        },
    ])
    .unwrap();

    assert_eq!(m.ops_executed(), 2, "the program must actually have run");
    assert_eq!(m.projections(), 0, "exec must not leave residue space");

    // The register holds a real result, not zeros — otherwise "never projected"
    // would be true of a machine that did nothing.
    let lanes = m.read(2).unwrap().to_vec();
    assert!(lanes.iter().any(|&l| l != 0), "register must hold a value");
    for (lane, &p) in DISCRIMINATING_BASIS.iter().enumerate() {
        assert!(lanes[lane] < p, "lane {lane} must be canonical mod {p}");
    }

    // Positive control: the counter is live.
    m.project(2).unwrap();
    assert_eq!(
        m.projections(),
        1,
        "project must be the thing that increments"
    );
    m.project(0).unwrap();
    assert_eq!(m.projections(), 2);
}

/// **P5** — lane independence of the Property Signature Σ.
///
/// Every Σ field must read exactly one source, which is what makes the update
/// `O(1)` with no cross-lane communication. The probes are constructed so that
/// only one input differs: `+M/2` flips the 2-lane alone, `+M/11` flips the
/// 11-lane alone, `+M` flips the winding while leaving every lane bit-identical.
/// A field that quietly consulted a second lane would move when it should not.
#[test]
fn p5_each_signature_field_reads_exactly_one_source() {
    const S6: [u64; 6] = [2, 3, 5, 7, 11, 13];
    let mut m = Cram::new(&S6, 2);
    assert_eq!(m.modulus(), 30_030);
    assert_eq!(m.anchor(), 30_031);

    // 110 = 2·5·11 — even, on the shadow, winding 0.
    m.load(0, 110).unwrap();
    let base = m.signature(0).unwrap();
    assert_eq!(base.parity, Parity::Even);
    assert_eq!(base.shadow, ShadowStatus::OnShadow);
    assert_eq!(base.sign, Sign::NonNegative);
    assert_eq!(base.bounds, Some((0, 30_030)));

    let one_lane_apart = |m: &Cram, target: u64| {
        let (a, b) = (m.read(0).unwrap(), m.read(1).unwrap());
        let differing: Vec<u64> = (0..S6.len())
            .filter(|&i| a[i] != b[i])
            .map(|i| S6[i])
            .collect();
        assert_eq!(differing, vec![target], "exactly one lane may differ");
    };

    // 2-lane only.
    m.load(1, 110 + 30_030 / 2).unwrap();
    one_lane_apart(&m, 2);
    let p = m.signature(1).unwrap();
    assert_eq!(p.parity, Parity::Odd, "parity moves");
    assert_eq!(
        (p.shadow, p.sign, p.bounds),
        (base.shadow, base.sign, base.bounds),
        "nothing else may"
    );

    // 11-lane only.
    m.load(1, 110 + 30_030 / 11).unwrap();
    one_lane_apart(&m, 11);
    let s = m.signature(1).unwrap();
    assert_eq!(s.shadow, ShadowStatus::OffShadow, "shadow moves");
    assert_eq!(
        (s.parity, s.sign, s.bounds),
        (base.parity, base.sign, base.bounds),
        "nothing else may"
    );

    // Winding only — every lane bit-identical.
    m.load(1, 110 + 30_030).unwrap();
    assert_eq!(m.read(0).unwrap(), m.read(1).unwrap(), "lanes identical");
    let w = m.signature(1).unwrap();
    assert_eq!(w.bounds, Some((30_030, 60_060)), "bounds move");
    assert_eq!(
        (w.parity, w.shadow),
        (base.parity, base.shadow),
        "no lane-sourced field may move"
    );
    m.load(1, -1).unwrap();
    assert_eq!(
        m.signature(1).unwrap().sign,
        Sign::Negative,
        "sign is winding-sourced"
    );

    // A basis without those lanes declines to report, rather than
    // reconstructing across lanes to manufacture an answer.
    let mut small = Cram::new(&[3, 5, 7], 1);
    small.load(0, 8).unwrap();
    assert_eq!(small.signature(0).unwrap().parity, Parity::Unavailable);
    assert_eq!(
        small.signature(0).unwrap().shadow,
        ShadowStatus::Unavailable
    );
    assert_eq!(
        small.signature(0).unwrap().sign,
        Sign::NonNegative,
        "the winding-sourced fields still work without those lanes"
    );
}

/// **P3b** — the winding is a measurement, not a counter, and a heterogeneous
/// schema is honest about having none.
///
/// A CRAM instruction that assigns different operators to different lanes is
/// not an integer operation. The machine drops the winding and refuses to name
/// an integer, rather than reporting a number it cannot justify — and the
/// homogeneous control shows the refusal is about the schema, not a machine
/// that never names anything.
#[test]
fn p3b_the_winding_is_measured_and_absent_when_it_should_be() {
    let mut m = Cram::discriminating(3);
    m.load(0, 3).unwrap();
    let powers: [i128; 5] = [9, 81, 6_561, 43_046_721, 1_853_020_188_851_841];
    let mut windings = Vec::new();
    for want in powers {
        m.exec(&[Instr::Apply {
            dst: 0,
            a: 0,
            b: 0,
            schema: "QQQQQ".into(),
        }])
        .unwrap();
        assert_eq!(m.project_integer(0).unwrap(), want, "ground truth");
        windings.push(m.winding(0).unwrap().known().unwrap());
    }
    assert!(
        windings[3] > 0 && windings[4] > windings[3],
        "magnitude must show up in the winding: {windings:?}"
    );

    // Heterogeneous: no winding, and the machine says which schema cost it.
    m.load(0, 41).unwrap();
    m.load(1, 17).unwrap();
    m.exec(&[Instr::Apply {
        dst: 2,
        a: 0,
        b: 1,
        schema: "AMSQ_".into(),
    }])
    .unwrap();
    assert_eq!(
        m.project_integer(2),
        Err(CramError::NoWinding(WindingLoss::Heterogeneous {
            notation: "AMSQ_".into()
        }))
    );

    // Chimera 1 again, at the machine level: even a *homogeneous* Div schema
    // loses the winding, because `a·b⁻¹ mod p` is not `⌊a/b⌋`.
    m.exec(&[Instr::Apply {
        dst: 2,
        a: 0,
        b: 1,
        schema: "DDDDD".into(),
    }])
    .unwrap();
    assert_eq!(
        m.project_integer(2),
        Err(CramError::NoWinding(WindingLoss::ModularOnly { op: 'D' }))
    );

    // Control: homogeneous and integer-meaningful keeps it.
    m.exec(&[Instr::Apply {
        dst: 2,
        a: 0,
        b: 1,
        schema: "MMMMM".into(),
    }])
    .unwrap();
    assert_eq!(m.project_integer(2).unwrap(), 41 * 17);
}

/// **P6** — shuffle invariance: the lift is flat, not a cascade.
///
/// Every winding is returned indexed by lane, so if any depended on an earlier
/// one, a permuted evaluation would differ. Exhaustive over the family capacity.
#[test]
fn p6_windings_are_invariant_under_evaluation_order() {
    let family = AnchorFamily::disjoint(&[&[3, 5], &[7, 11], &[13, 17]]).unwrap();
    let orders: [[usize; 3]; 6] = [
        [0, 1, 2],
        [0, 2, 1],
        [1, 0, 2],
        [1, 2, 0],
        [2, 0, 1],
        [2, 1, 0],
    ];

    let mut checked = 0i128;
    let mut all_wound = 0i128;
    for x in 0..family.capacity() {
        let pairs = family.decompose(x).unwrap();
        let reference = family.windings(&pairs).unwrap();
        if reference.iter().all(|&k| k != 0) {
            all_wound += 1;
        }
        for order in &orders {
            assert_eq!(
                family.windings_in_order(&pairs, order).unwrap(),
                reference,
                "x = {x}, order = {order:?}"
            );
        }
        checked += 1;
    }
    assert_eq!(checked, family.capacity(), "sweep must not shrink");
    assert!(
        all_wound > 0,
        "the sweep must include values where every lane has work to reorder"
    );

    assert_eq!(
        family.windings_in_order(&family.decompose(5).unwrap(), &[0, 0, 1]),
        Err(AnchorError::NotAPermutation),
        "a non-permutation must be refused, not partially evaluated"
    );
}

/// **P7** — fault containment, with the sequential CRT as the negative control.
///
/// The same corruption, on the same lane, over the same three moduli, is put
/// through both reads. The flat lift confines it to one winding; Garner carries
/// it into every downstream partial and into the reconstructed integer. Without
/// the control, "contained" would be a claim no experiment could refute.
#[test]
fn p7_one_faulty_lane_is_contained_but_garner_spreads_it() {
    let family = AnchorFamily::disjoint(&[&[3, 5], &[7, 11], &[13, 17]]).unwrap();
    let x = 200i128;
    assert!(x < family.capacity());

    let pairs = family.decompose(x).unwrap();
    let clean_k = family.windings(&pairs).unwrap();
    let clean_v = family.group_values(&pairs, &clean_k).unwrap();
    assert_eq!(clean_v, vec![x, x, x], "clean groups all name X");

    let faulty = 1usize;
    let mut dirty_pairs = pairs.clone();
    let p = family.anchors()[faulty].p();
    dirty_pairs[faulty].0 = (dirty_pairs[faulty].0 + 1) % p;
    assert_ne!(dirty_pairs[faulty].0, pairs[faulty].0, "fault must be real");

    let dirty_k = family.windings(&dirty_pairs).unwrap();
    let dirty_v = family.group_values(&dirty_pairs, &dirty_k).unwrap();

    let moved_k = (0..clean_k.len())
        .filter(|&i| clean_k[i] != dirty_k[i])
        .count();
    assert_eq!(moved_k, 1, "exactly one winding may move");
    assert_ne!(
        clean_k[faulty], dirty_k[faulty],
        "and it is the faulty lane's"
    );
    for j in 0..clean_v.len() {
        if j != faulty {
            assert_eq!(clean_v[j], dirty_v[j], "group {j} must be bit-identical");
        }
    }
    // Survivors still agree, so the fault is localised by majority, not merely
    // walled off.
    assert_eq!(dirty_v[0], dirty_v[2]);
    assert_ne!(dirty_v[faulty], dirty_v[0]);

    // ── Negative control ──
    let moduli = [15i128, 77, 221];
    let clean_res: Vec<(i128, i128)> = moduli.iter().map(|&m| (x % m, m)).collect();
    let mut dirty_res = clean_res.clone();
    dirty_res[faulty].0 = (dirty_res[faulty].0 + 1) % moduli[faulty];
    assert_eq!(
        dirty_res[faulty].0, dirty_pairs[faulty].0,
        "the control must carry the identical corruption"
    );

    let partials = |res: &[(i128, i128)]| -> Vec<i128> {
        let (mut v, mut m) = res[0];
        let mut out = vec![v];
        for &(r, mi) in &res[1..] {
            v = k_eliminate(v, m, r, mi).unwrap().value;
            m *= mi;
            out.push(v);
        }
        out
    };
    let cp = partials(&clean_res);
    let dp = partials(&dirty_res);
    let spread = (0..cp.len()).filter(|&i| cp[i] != dp[i]).count();
    assert_eq!(
        spread,
        moduli.len() - faulty,
        "damage reaches every later partial"
    );
    assert!(
        spread > moved_k,
        "the control must spread further: {spread} vs {moved_k}"
    );
    assert_ne!(
        garner_reconstruct(&clean_res),
        garner_reconstruct(&dirty_res),
        "and the reconstructed integer is wrong, with nothing left to compare it to"
    );
}

/// **P8** — the basis registers are distinct objects and are not conflated.
///
/// The Transport Core is asserted **by its definition** — `{p ∈ S6 :
/// gcd(p, SCALE) = 1}` with `SCALE = 10⁴` — rather than by its listed value.
/// That is the check that would have caught the invented rationale that 2 is
/// excluded "because it drops ρ to 2": under the real definition 2 and 5 are
/// excluded on identical grounds, as parking lanes of the decimal scale.
#[test]
fn p8_basis_registers_are_distinct_and_derived_not_asserted() {
    const SCALE: i128 = 10_000; // 2⁴ · 5⁴

    assert_eq!(SAFE_BASIS, [2, 3, 5, 7, 11, 13], "S6");
    assert_eq!(TRANSPORT_CORE, [3, 7, 11, 13], "exact-division lanes");
    assert_eq!(DISCRIMINATING_BASIS, [3, 5, 7, 11, 13], "CRAM schema lanes");

    // Transport Core, derived.
    let derived: Vec<u64> = SAFE_BASIS
        .iter()
        .copied()
        .filter(|&p| gcd(p as i128, SCALE) == 1)
        .collect();
    assert_eq!(
        derived,
        TRANSPORT_CORE.to_vec(),
        "Transport Core is a derivation"
    );

    // 2 and 5 are excluded on identical grounds; neither exclusion is about ρ.
    assert_eq!(gcd(2, SCALE), 2);
    assert_eq!(gcd(5, SCALE), 5);
    assert_eq!(SCALE, 2i128.pow(4) * 5i128.pow(4));

    // Products and resonance orders, so the registers cannot be swapped.
    assert_eq!(SAFE_BASIS.iter().product::<u64>() as i128, M_SAFE);
    assert_eq!(M_SAFE, 30_030);
    assert_eq!(
        TRANSPORT_CORE.iter().product::<u64>(),
        3_003,
        "M_safe of the core"
    );
    assert_eq!(*TRANSPORT_CORE.iter().min().unwrap(), 3, "ρ = 3");
    assert_eq!(*DISCRIMINATING_BASIS.iter().min().unwrap(), 3, "ρ = 3");

    // They are genuinely different sets.
    assert_ne!(SAFE_BASIS.to_vec(), DISCRIMINATING_BASIS.to_vec());
    assert_ne!(TRANSPORT_CORE.to_vec(), DISCRIMINATING_BASIS.to_vec());
    assert_ne!(SAFE_BASIS.to_vec(), TRANSPORT_CORE.to_vec());

    // Each is internally pairwise coprime — the one property all of them share.
    for reg in [
        &SAFE_BASIS[..],
        &TRANSPORT_CORE[..],
        &DISCRIMINATING_BASIS[..],
    ] {
        for i in 0..reg.len() {
            for j in (i + 1)..reg.len() {
                assert_eq!(gcd(reg[i] as i128, reg[j] as i128), 1, "{reg:?}");
            }
        }
    }
}

/// **P9** — a `Div` root is modular division, **not** the integer quotient.
///
/// `a·b⁻¹ mod p` and `⌊a/b⌋` are different functions, and conflating them is a
/// silent-wrong-answer bug rather than a rounding difference. The gate exhibits
/// how far apart they are, so nothing downstream can assume they coincide.
#[test]
fn p9_div_root_is_modular_and_is_not_the_integer_quotient() {
    let mut differ = 0;
    let mut agree = 0;
    for &p in &[7i128, 11, 13] {
        for a in 0..p {
            for b in 1..p {
                let modular = (a * mod_inv(b, p).unwrap()).rem_euclid(p);
                let integer = a.div_euclid(b);
                if modular == integer {
                    agree += 1;
                } else {
                    differ += 1;
                }
            }
        }
    }
    assert!(
        differ > agree,
        "the two must differ on most inputs: {differ} vs {agree}"
    );

    // A named, checkable instance.
    let (a, b, p) = (5i128, 3i128, 7i128);
    assert_eq!(
        (a * mod_inv(b, p).unwrap()).rem_euclid(p),
        4,
        "5·3⁻¹ ≡ 4 (mod 7)"
    );
    assert_eq!(a.div_euclid(b), 1, "⌊5/3⌋ = 1");
    assert_ne!(4, 1, "and 4 is not 1");

    // Coincidence is possible, which is exactly why the distinction must be
    // enforced rather than inferred from a spot check.
    assert_eq!((6i128 * mod_inv(3, 7).unwrap()).rem_euclid(7), 2);
    assert_eq!(6i128.div_euclid(3), 2);
}
