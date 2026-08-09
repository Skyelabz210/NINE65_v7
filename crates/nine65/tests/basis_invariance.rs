//! Basis invariance under exact residue-space division.
//!
//! # The claim under test
//!
//! **Exact division reduces the VALUE without moving the BASIS.**
//!
//! Classical BFV cannot satisfy this by construction. Its `rescale` /
//! `mod_switch_down` *fuses* two operations — divide the value by `q_i`, and
//! drop `q_i` from the basis — because classical division of a ciphertext by
//! `q_i` is inexact. The only way to make the division come out clean is to
//! stop representing the residue you divided by. Hence a finite descending
//! level chain, hence a consumable noise budget, hence bootstrapping.
//!
//! NINE65 divides in residue space, exactly (K-Elimination when
//! `gcd(d, M) = 1`, Fused Piggyback Division when `gcd(d, M) > 1`). An exact
//! division needs no rounding term, and therefore needs no lane sacrificed to
//! absorb one. The two halves of `rescale` come apart: the value is divided,
//! and **the basis does not move** — same lanes, same order, same count,
//! same `Q`, same level.
//!
//! This file is therefore a *discriminator*, not a restatement: the very same
//! assertions applied to the retired `mod_switch_ct_down` path fail, and
//! `mod_switch_ladder_is_the_negative_of_this_invariant` pins that down so the
//! invariance assertions here can never be read as vacuous.
//!
//! See `docs/RETIRED_MECHANISMS.md`. The retired entry points still present in
//! the tree are `RNSFHEContext::mod_switch_ct_down`, `::mod_switch_down_dual`
//! and `::mod_switch_ct_to_level` (`crates/nine65/src/ops/rns_fhe.rs`); every
//! lane-count assertion below is the direct negative of what those do.
//!
//! # What "divide" means here, precisely
//!
//! Exact division applies to a value that is *exactly divisible*. A **fresh**
//! `Enc(M)` carries the underlying integer `Δ·M + e` with a random `e`; `d`
//! does not divide `e`, so no integer quotient exists and none is claimed.
//! The divisible object is the one the architecture actually rescales: the
//! output of a multiplication. `mul_plain_dual(Enc(m), d)` is a bona fide
//! `Enc(M)` for `M = d·m` (asserted below, not assumed) whose underlying
//! integer is exactly `d·(Δm + e)`. Dividing that by `d` in residue space
//! returns `Δm + e` — value reduced by `d`, noise scaled by `1/d`, **no
//! rounding term added at all** (see
//! `exact_division_is_bit_exact_no_rounding_term`), and the basis untouched.
//!
//! # Division primitive
//!
//! There is no `(DualRNSCiphertext, d) -> DualRNSCiphertext` entry point in the
//! workspace — `RNSFHEContext` has `add_plain_dual` and `mul_plain_dual` but no
//! `div_plain_dual`. The per-lane exact division is therefore assembled here
//! from the residue-native K-Elimination primitives in
//! `exact_transcendentals::k_elim` (`reciprocal_lanewise`, cross-checked
//! against `k_elim_divide`), applied to every main and anchor lane. That is
//! four lines and it is the whole operation: no reconstruction, no
//! cross-lane carry, no lane dropped.

use exact_transcendentals::chimera_division::{ChimeraLane, DivStatus};
use exact_transcendentals::cram_ct::{select_division_lane, CramCiphertext, SafeBasis};
use exact_transcendentals::k_elim;
use exact_transcendentals::triad::{S8, S8_PRODUCT};

use nine65::entropy::ShadowHarvester;
use nine65::ops::rns_fhe::{DualRNSCiphertext, DualRNSFullKeySet, DualRNSPoly, RNSFHEContext};
use nine65::params::secure_configs::SecureConfig;

// ============================================================================
// PARAMETER SETS AND DIVISORS
// ============================================================================

/// Named parameter sets exercised by every invariance test.
///
/// Deliberately spans 2, 3 and 4 main lanes so that "the basis did not move"
/// is asserted over chains of different lengths — a level-consuming
/// implementation would show a different failure signature on each.
fn parameter_sets() -> Vec<(&'static str, SecureConfig)> {
    vec![
        ("test_medium_insecure", SecureConfig::test_medium_insecure()),
        ("secure_128", SecureConfig::secure_128()),
        ("secure_128_deep", SecureConfig::secure_128_deep()),
    ]
}

/// Divisors used for the value-correctness sweep. Every one of these is a
/// unit on every NINE65 lane (asserted in
/// `every_admissible_divisor_is_a_unit_on_the_rns_lane_set`), so each routes
/// to the K-Elimination / modular-inverse lane.
const DIVISORS: &[u64] = &[2, 3, 5, 7, 11, 23, 97, 1009, 65521];

fn ctx_and_keys(cfg: &SecureConfig) -> (RNSFHEContext, DualRNSFullKeySet) {
    let ctx = RNSFHEContext::new(&cfg.config);
    let mut rng = ShadowHarvester::with_seed(42);
    let keys = ctx.generate_keys_dual_full(&mut rng);
    (ctx, keys)
}

// ============================================================================
// THE BASIS FINGERPRINT
// ============================================================================

/// Byte-level encoding of everything that constitutes "the basis": the
/// modulus chain (in order), the products, and the ciphertext's own occupancy
/// of that chain.
///
/// A modulus switch changes these bytes. An exact division must not.
fn basis_bytes(ctx: &RNSFHEContext, ct: &DualRNSCiphertext) -> Vec<u8> {
    let mut out = Vec::new();

    // (A) The lane set itself, in order. Order matters: a permuted chain is a
    //     different basis even if the multiset is equal.
    out.extend_from_slice(b"CFG-PRIMES");
    for &p in &ctx.config.primes {
        out.extend_from_slice(&p.to_le_bytes());
    }
    out.extend_from_slice(b"MAIN-PRIMES");
    for &p in &ctx.dual_rns.main.primes {
        out.extend_from_slice(&p.to_le_bytes());
    }
    out.extend_from_slice(b"ANCHOR-PRIMES");
    for &p in &ctx.dual_rns.anchor.primes {
        out.extend_from_slice(&p.to_le_bytes());
    }

    // (B) Q itself, and the derived widths.
    out.extend_from_slice(b"Q");
    out.extend_from_slice(&ctx.q_product.to_le_bytes());
    out.extend_from_slice(&(ctx.q_bits as u64).to_le_bytes());
    out.extend_from_slice(&ctx.dual_rns.main_product.to_le_bytes());
    out.extend_from_slice(&ctx.dual_rns.anchor_product.to_le_bytes());

    // (C) The ciphertext's occupancy of the chain. THIS is what a classical
    //     rescale decrements, and what `mod_switch_ct_down` decrements today.
    out.extend_from_slice(b"CT-LANES");
    for v in [
        ct.c0.main.len(),
        ct.c0.anchor.len(),
        ct.c1.main.len(),
        ct.c1.anchor.len(),
        ct.level,
        ct.c0.n,
        ct.c1.n,
    ] {
        out.extend_from_slice(&(v as u64).to_le_bytes());
    }

    // (D) Per-lane widths — catches a silently truncated lane that would keep
    //     the lane *count* while shrinking the representation.
    out.extend_from_slice(b"LANE-WIDTHS");
    for limb in ct
        .c0
        .main
        .iter()
        .chain(ct.c0.anchor.iter())
        .chain(ct.c1.main.iter())
        .chain(ct.c1.anchor.iter())
    {
        out.extend_from_slice(&(limb.len() as u64).to_le_bytes());
    }

    out
}

/// Human-readable form of the same thing, for failure messages.
fn basis_summary(ctx: &RNSFHEContext, ct: &DualRNSCiphertext) -> String {
    format!(
        "main={:?} anchor={:?} Q={} q_bits={} c0=({} main,{} anchor) c1=({} main,{} anchor) level={}",
        ctx.dual_rns.main.primes,
        ctx.dual_rns.anchor.primes,
        ctx.q_product,
        ctx.q_bits,
        ct.c0.main.len(),
        ct.c0.anchor.len(),
        ct.c1.main.len(),
        ct.c1.anchor.len(),
        ct.level,
    )
}

// ============================================================================
// THE DIVISION ITSELF (residue-native, basis-preserving)
// ============================================================================

/// Residue-native reciprocal of `d` on a single lane, from the K-Elimination
/// primitive layer. Pure per-lane inversion: no reconstruction, no cross-lane
/// carry, nothing left residue space.
fn lane_reciprocal(d: u64, prime: u64) -> u64 {
    let inv = k_elim::reciprocal_lanewise(&[d as i128], &[prime as i128])
        .unwrap_or_else(|| panic!("divisor {d} is not a unit on lane {prime}"));
    inv[0] as u64
}

fn divide_lane(limb: &[u64], prime: u64, d: u64) -> Vec<u64> {
    let inv = lane_reciprocal(d, prime) as u128;
    let p = prime as u128;
    limb.iter()
        .map(|&r| ((r as u128 * inv) % p) as u64)
        .collect()
}

fn exact_divide_poly(ctx: &RNSFHEContext, poly: &DualRNSPoly, d: u64) -> DualRNSPoly {
    let main = poly
        .main
        .iter()
        .enumerate()
        .map(|(i, limb)| divide_lane(limb, ctx.config.primes[i], d))
        .collect();
    let anchor = poly
        .anchor
        .iter()
        .enumerate()
        .map(|(j, limb)| divide_lane(limb, ctx.dual_rns.anchor.primes[j], d))
        .collect();
    DualRNSPoly {
        main,
        anchor,
        n: poly.n,
    }
}

/// Exact division of a dual-RNS ciphertext by `d`, in residue space.
///
/// Every lane — main *and* anchor — is divided. No lane is dropped, no
/// rounding term is introduced, `level` is **not** decremented. The output
/// occupies exactly the same chain as the input.
fn exact_divide_dual(ctx: &RNSFHEContext, ct: &DualRNSCiphertext, d: u64) -> DualRNSCiphertext {
    DualRNSCiphertext {
        c0: exact_divide_poly(ctx, &ct.c0, d),
        c1: exact_divide_poly(ctx, &ct.c1, d),
        // Not `ct.level - 1`. Nothing was spent, so nothing is decremented.
        level: ct.level,
    }
}

/// Build a ciphertext of `M = d * m` whose underlying integer is exactly
/// divisible by `d`, and assert it really is an encryption of `M`.
fn encrypt_divisible(
    ctx: &RNSFHEContext,
    keys: &DualRNSFullKeySet,
    seed: u64,
    m: u64,
    d: u64,
) -> (DualRNSCiphertext, u64) {
    assert!(
        d.checked_mul(m).map(|x| x < ctx.t).unwrap_or(false),
        "test setup: d*m must stay below t"
    );
    let mut rng = ShadowHarvester::with_seed(seed);
    let base = ctx.encrypt_dual(m, &keys.public_key, &mut rng);
    let ct_m = ctx.mul_plain_dual(&base, d);
    let big = d * m;
    assert_eq!(
        ctx.decrypt_dual(&ct_m, &keys.secret_key),
        big,
        "test setup: mul_plain_dual(Enc({m}), {d}) must be an encryption of {big}"
    );
    (ct_m, big)
}

// ============================================================================
// 1. BASIS INVARIANCE
// ============================================================================

#[test]
fn basis_is_byte_identical_before_and_after_exact_division() {
    for (name, cfg) in parameter_sets() {
        let (ctx, keys) = ctx_and_keys(&cfg);
        for (i, &d) in DIVISORS.iter().enumerate() {
            let m = (ctx.t - 1) / d;
            let m = m.min(7).max(1);
            let (ct, _big) = encrypt_divisible(&ctx, &keys, 1000 + i as u64, m, d);

            let before_bytes = basis_bytes(&ctx, &ct);
            let before_text = basis_summary(&ctx, &ct);

            let divided = exact_divide_dual(&ctx, &ct, d);

            let after_bytes = basis_bytes(&ctx, &divided);
            let after_text = basis_summary(&ctx, &divided);

            // Diagnostic record (run with `-- --nocapture`).
            if i == 0 {
                println!("[{name}] before: {before_text}");
                println!("[{name}] after/{d}: {after_text}");
            }

            assert_eq!(
                before_bytes, after_bytes,
                "[{name}] d={d}: BASIS MOVED under exact division\n  before: {before_text}\n  after:  {after_text}"
            );

            // Spelled out lane by lane as well, so a failure names the lane.
            assert_eq!(
                ctx.dual_rns.main.primes, ctx.config.primes,
                "[{name}] main lane set diverged from config chain"
            );
            assert_eq!(
                ct.c0.main.len(),
                divided.c0.main.len(),
                "[{name}] d={d}: c0 main lane COUNT changed (this is what a mod switch does)"
            );
            assert_eq!(
                ct.c0.anchor.len(),
                divided.c0.anchor.len(),
                "[{name}] d={d}: c0 anchor lane count changed"
            );
            assert_eq!(
                ct.c1.main.len(),
                divided.c1.main.len(),
                "[{name}] d={d}: c1 main lane count changed"
            );
            assert_eq!(
                ct.c1.anchor.len(),
                divided.c1.anchor.len(),
                "[{name}] d={d}: c1 anchor lane count changed"
            );
            for (lane, (a, b)) in ct.c0.main.iter().zip(divided.c0.main.iter()).enumerate() {
                assert_eq!(
                    a.len(),
                    b.len(),
                    "[{name}] d={d}: c0 main lane {lane} width changed"
                );
            }
            assert!(
                divided.validate().is_ok(),
                "[{name}] d={d}: divided ciphertext failed structural validation"
            );
        }
    }
}

// ============================================================================
// 2. VALUE CORRECTNESS
// ============================================================================

#[test]
fn exact_division_recovers_the_quotient_on_every_parameter_set() {
    for (name, cfg) in parameter_sets() {
        let (ctx, keys) = ctx_and_keys(&cfg);
        for (i, &d) in DIVISORS.iter().enumerate() {
            let m = ((ctx.t - 1) / d).min(7).max(1);
            let (ct_big, big) = encrypt_divisible(&ctx, &keys, 2000 + i as u64, m, d);
            assert_eq!(big % d, 0, "test setup: d must divide M");

            let divided = exact_divide_dual(&ctx, &ct_big, d);
            let got = ctx.decrypt_dual(&divided, &keys.secret_key);

            assert_eq!(
                got,
                big / d,
                "[{name}] decrypt(divide(Enc({big}), {d})) = {got}, expected {}",
                big / d
            );
        }
    }
}

/// The strongest form of "no rounding term added": dividing by `d` a
/// ciphertext that was just multiplied by `d` reproduces the original
/// residues **bit for bit**, on every lane, main and anchor.
///
/// Classical rescale cannot do this — it necessarily perturbs the value by the
/// rounding term it had to introduce, and it returns a ciphertext on a
/// strictly smaller chain that cannot even be compared limb-for-limb with the
/// input.
#[test]
fn exact_division_is_bit_exact_no_rounding_term() {
    for (name, cfg) in parameter_sets() {
        let (ctx, keys) = ctx_and_keys(&cfg);
        let mut rng = ShadowHarvester::with_seed(31337);
        let original = ctx.encrypt_dual(4242 % ctx.t, &keys.public_key, &mut rng);

        for &d in DIVISORS {
            let up = ctx.mul_plain_dual(&original, d);
            let down = exact_divide_dual(&ctx, &up, d);

            assert_eq!(
                original.c0.main, down.c0.main,
                "[{name}] d={d}: c0 main residues not restored exactly"
            );
            assert_eq!(
                original.c0.anchor, down.c0.anchor,
                "[{name}] d={d}: c0 anchor residues not restored exactly"
            );
            assert_eq!(
                original.c1.main, down.c1.main,
                "[{name}] d={d}: c1 main residues not restored exactly"
            );
            assert_eq!(
                original.c1.anchor, down.c1.anchor,
                "[{name}] d={d}: c1 anchor residues not restored exactly"
            );
            assert_eq!(original.level, down.level, "[{name}] d={d}: level moved");

            // And the decryption diagnostics — including the rounding margin,
            // the thing a noise budget would track — are identical, not merely
            // "still acceptable".
            let (m_before, margin_before) =
                ctx.decrypt_dual_with_diagnostics(&original, &keys.secret_key);
            let (m_after, margin_after) =
                ctx.decrypt_dual_with_diagnostics(&down, &keys.secret_key);
            assert_eq!(m_before, m_after, "[{name}] d={d}: plaintext changed");
            assert_eq!(
                margin_before, margin_after,
                "[{name}] d={d}: rounding margin moved — a budget was spent"
            );
        }
    }
}

// ============================================================================
// 2b. THE TWO ROUTER BRANCHES
// ============================================================================

/// Structural fact, asserted rather than assumed: on the NINE65 RNS lane set
/// *every* divisor admissible in the plaintext domain is a unit on every lane.
///
/// The smallest modulus in any shipped chain is far larger than `t`, and all
/// of them are prime, so `gcd(d, Q) = 1` for every `0 < d < t`. Consequence:
/// the Fused Piggyback lane is **unreachable from the plaintext-domain scalar
/// API on these parameter sets** — not because it is unimplemented, but
/// because no admissible divisor can share a factor with the chain. The FPD
/// branch is therefore exercised below on the bases that do contain small
/// primes (the S8 safe basis, and explicit small CRT bases).
#[test]
fn every_admissible_divisor_is_a_unit_on_the_rns_lane_set() {
    fn gcd(a: u64, b: u64) -> u64 {
        if b == 0 {
            a
        } else {
            gcd(b, a % b)
        }
    }

    for (name, cfg) in parameter_sets() {
        let ctx = RNSFHEContext::new(&cfg.config);
        let smallest = ctx
            .dual_rns
            .main
            .primes
            .iter()
            .chain(ctx.dual_rns.anchor.primes.iter())
            .copied()
            .min()
            .expect("chain must be non-empty");
        assert!(
            smallest > ctx.t,
            "[{name}] smallest lane {smallest} is not above t={}",
            ctx.t
        );
        for &d in DIVISORS {
            for &p in ctx
                .dual_rns
                .main
                .primes
                .iter()
                .chain(ctx.dual_rns.anchor.primes.iter())
            {
                assert_eq!(
                    gcd(d, p),
                    1,
                    "[{name}] d={d} shares a factor with lane {p} — this divisor \
                     would need the Fused Piggyback lane, not K-Elimination"
                );
            }
        }
    }
}

/// The router classifies both branches, and neither branch changes the basis
/// it is classified against.
#[test]
fn division_router_selects_kelim_and_fpd_without_touching_the_basis() {
    let basis = SafeBasis::S8;
    let moduli_before: Vec<u32> = basis.moduli().to_vec();
    let product_before = basis.product();

    // Coprime to S8 (= 2·3·5·7·11·13·17·19) → K-Elimination / modular inverse.
    for d in [23i128, 29, 31, 1009, 65521] {
        let plan = select_division_lane(d, basis);
        assert_eq!(
            plan.gcd_with_basis, 1,
            "d={d} was expected coprime to the S8 basis"
        );
        assert_eq!(plan.primary, ChimeraLane::ModularInverse, "d={d}");
        assert_eq!(plan.primary_status, DivStatus::ModularInverseExact, "d={d}");
        assert!(plan.primary_status.is_exact_quotient(), "d={d}");
    }

    // Sharing a factor with S8 → Fused Piggyback.
    for (d, expected_gcd) in [(6i128, 6u64), (10, 10), (210, 210), (4, 2), (9, 3)] {
        let plan = select_division_lane(d, basis);
        assert_eq!(plan.gcd_with_basis, expected_gcd, "d={d}");
        assert_eq!(
            plan.primary,
            ChimeraLane::FusedPiggyback,
            "d={d} shares a factor with the basis and must route to FPD"
        );
        assert!(
            plan.evaluable.fused_piggyback,
            "d={d}: FPD lane must be evaluable"
        );
    }

    assert_eq!(
        moduli_before,
        basis.moduli().to_vec(),
        "routing a divisor must not mutate the basis"
    );
    assert_eq!(product_before, basis.product());
    assert_eq!(moduli_before, S8.to_vec());
    assert_eq!(product_before, S8_PRODUCT as u64);
}

/// The Fused Piggyback lane, on a basis that genuinely contains a factor of
/// the divisor: `gcd(6, 3·5·7) = 3 > 1`.
///
/// The auxiliary prime is a *certification* lane returned alongside the
/// result; it is not spliced into the basis. Input basis and output basis are
/// the same list, same order, same length. Nothing was dropped to pay for the
/// division.
#[test]
fn fused_piggyback_divides_without_dropping_a_lane() {
    fn gcd(a: i128, b: i128) -> i128 {
        if b == 0 {
            a.abs()
        } else {
            gcd(b, a % b)
        }
    }

    let cases: &[(i128, &[i128], i128)] = &[
        (210, &[3, 5, 7], 6),
        (210, &[3, 5, 7], 30),
        (420, &[3, 5, 7], 6),
        (2310, &[3, 5, 7, 11], 210),
        (1800, &[2, 3, 5], 60),
    ];

    for &(a, basis, b) in cases {
        assert!(
            gcd(b, basis.iter().product::<i128>()) > 1,
            "case a={a} b={b}: this case is supposed to exercise the FPD branch"
        );

        let basis_before: Vec<i128> = basis.to_vec();
        let (q_res, q, aux) = k_elim::fpd(a, basis, b, &k_elim::AUX_FPD_POOL)
            .unwrap_or_else(|| panic!("FPD failed for a={a}, basis={basis:?}, b={b}"));

        // VALUE reduced, exactly.
        assert_eq!(q, a / b, "a={a} b={b}: quotient wrong");
        assert_eq!(a % b, 0, "test setup: b must divide a");

        // BASIS not moved: same length, same order, same moduli, and the
        // quotient is expressed on exactly those lanes.
        assert_eq!(
            basis_before,
            basis.to_vec(),
            "a={a} b={b}: the basis list itself changed"
        );
        assert_eq!(
            q_res.len(),
            basis.len(),
            "a={a} b={b}: FPD returned a different number of lanes — a lane was dropped"
        );
        for (r, &p) in q_res.iter().zip(basis.iter()) {
            assert_eq!(*r, q.rem_euclid(p), "a={a} b={b}: lane {p} residue wrong");
        }

        // The auxiliary prime is a certification lane, not a basis member.
        assert!(
            !basis.contains(&aux),
            "a={a} b={b}: aux prime {aux} must not be part of the basis"
        );
        assert!(k_elim::AUX_FPD_POOL.contains(&aux));
    }
}

/// The same FPD lane driven through the ciphertext shell: an S8-basis
/// `CramCiphertext` divided by `6` (`gcd(6, S8_PRODUCT) = 6 > 1`).
///
/// After the division the topology still declares the S8 basis with all eight
/// lanes present — including lanes 2 and 3, which share factors with the
/// divisor and were skipped during fusion. FPD re-projects the recovered
/// quotient onto them; it does not retire them.
#[test]
fn fpd_ciphertext_shell_keeps_all_eight_lanes() {
    let coeffs: Vec<i128> = vec![612, -3006, 4200, 0, 66, -12, 6];
    let quotient_bound = 10_000i128;
    let divisor = 6i128;

    let aux = exact_transcendentals::cram_ct::AuxResidueSet::select_for_divisor(
        divisor,
        quotient_bound,
    )
    .expect("aux pool must be able to size this divisor");

    let ct = CramCiphertext::<()>::wrap_with_fpd_aux((), &coeffs, None, &aux);
    assert!(ct.verify().is_ok(), "wrapped witness must verify");

    let basis_before = ct.topology.basis;
    let moduli_before: Vec<u32> = basis_before.moduli().to_vec();
    let lanes_before = ct.topology.lanes.len();
    let id_before = ct.topology.id;

    let (out, plan) = ct
        .cram_rescale_by_scalar_fpd(divisor, quotient_bound, |base, _| base)
        .expect("FPD rescale must succeed");

    assert_eq!(plan.primary, ChimeraLane::FusedPiggyback);
    assert_eq!(plan.gcd_with_basis, 6);

    // BASIS INVARIANCE on the witness topology.
    assert_eq!(out.topology.basis, basis_before, "safe basis changed");
    assert_eq!(
        out.topology.basis.moduli().to_vec(),
        moduli_before,
        "S8 moduli changed"
    );
    assert_eq!(
        out.topology.lanes.len(),
        lanes_before,
        "lane count changed — a lane was spent"
    );
    assert_eq!(out.topology.lanes.len(), 8);
    assert_eq!(out.topology.id, id_before, "topology identity changed");
    assert!(out.topology.is_well_formed());
    assert!(out.verify().is_ok(), "post-division witness must verify");

    // VALUE reduced.
    let got = out.reconstruct_c0_coeffs_signed();
    let expected: Vec<i32> = coeffs.iter().map(|&c| (c / divisor) as i32).collect();
    assert_eq!(
        &got[..expected.len()],
        &expected[..],
        "FPD quotient coefficients wrong"
    );
}

// ============================================================================
// 3. REPEATABILITY — THE ANTI-LADDER ASSERTION
// ============================================================================

/// Eight exact divisions **in sequence**, nothing in between.
///
/// A level-consuming implementation degrades here: with a 2-, 3- or 4-prime
/// chain it runs out on the second, third or fourth division and either
/// panics, returns `None`, or starts decrypting garbage. Here the basis is
/// byte-identical after all eight, and the plaintext tracks `d^(8-i)·m`
/// exactly at every step.
#[test]
fn eight_sequential_divisions_leave_basis_and_value_intact() {
    const ROUNDS: u32 = 8;

    for (name, cfg) in parameter_sets() {
        let (ctx, keys) = ctx_and_keys(&cfg);

        // d^ROUNDS * m must stay below t so the plaintext ladder is honest.
        for (d, m) in [(2u64, 5u64), (3u64, 2u64)] {
            let top = d.pow(ROUNDS) * m;
            assert!(top < ctx.t, "test setup: d^8*m must stay below t");

            let mut rng = ShadowHarvester::with_seed(777);
            let mut ct = ctx.encrypt_dual(m, &keys.public_key, &mut rng);
            for _ in 0..ROUNDS {
                ct = ctx.mul_plain_dual(&ct, d);
            }
            assert_eq!(
                ctx.decrypt_dual(&ct, &keys.secret_key),
                top,
                "[{name}] test setup: climbing to d^8*m failed"
            );

            let bytes_at_start = basis_bytes(&ctx, &ct);
            let level_at_start = ct.level;
            let lanes_at_start = (ct.c0.main.len(), ct.c0.anchor.len());

            let mut expected = top;
            for round in 1..=ROUNDS {
                ct = exact_divide_dual(&ctx, &ct, d);
                expected /= d;

                assert_eq!(
                    basis_bytes(&ctx, &ct),
                    bytes_at_start,
                    "[{name}] d={d}: basis moved at division #{round}\n  now: {}",
                    basis_summary(&ctx, &ct)
                );
                assert_eq!(
                    ct.level, level_at_start,
                    "[{name}] d={d}: level moved at division #{round}"
                );
                assert_eq!(
                    (ct.c0.main.len(), ct.c0.anchor.len()),
                    lanes_at_start,
                    "[{name}] d={d}: lane count moved at division #{round}"
                );
                assert!(
                    ct.validate().is_ok(),
                    "[{name}] d={d}: ciphertext invalid after division #{round}"
                );

                let got = ctx.decrypt_dual(&ct, &keys.secret_key);
                assert_eq!(
                    got, expected,
                    "[{name}] d={d}: after division #{round} decrypt = {got}, expected {expected}"
                );
            }
            assert_eq!(expected, m, "[{name}] the ladder should land back on m");
        }
    }
}

/// A longer run than the chain could ever fund: 64 divisions in sequence.
///
/// Every parameter set here has at most four main lanes. A ladder-based
/// implementation cannot survive 64 rescales without bootstrapping; this one
/// never spends anything, so there is nothing to run out of.
#[test]
fn sixty_four_divisions_still_do_not_move_the_basis() {
    const ROUNDS: usize = 64;
    let (ctx, keys) = ctx_and_keys(&SecureConfig::secure_128());
    let d = 23u64;
    let m = 1234u64 % ctx.t;

    let mut rng = ShadowHarvester::with_seed(4242);
    let mut ct = ctx.encrypt_dual(m, &keys.public_key, &mut rng);

    let bytes_at_start = basis_bytes(&ctx, &ct);
    let residues_at_start = (ct.c0.main.clone(), ct.c1.main.clone());

    for round in 1..=ROUNDS {
        // Each round: scale up by d, then divide it back out exactly. The
        // division is the operation under test; the multiply only supplies a
        // value that d divides.
        let up = ctx.mul_plain_dual(&ct, d);
        ct = exact_divide_dual(&ctx, &up, d);

        assert_eq!(
            basis_bytes(&ctx, &ct),
            bytes_at_start,
            "basis moved at division #{round}"
        );
        assert_eq!(
            ctx.decrypt_dual(&ct, &keys.secret_key),
            m,
            "value corrupted at division #{round}"
        );
    }

    // Not merely "still decrypts": the residues are the ones we started with.
    assert_eq!(
        (ct.c0.main.clone(), ct.c1.main.clone()),
        residues_at_start,
        "after {ROUNDS} divisions the residues should be exactly the originals"
    );
    assert_eq!(ct.level, 3, "level must not have moved across {ROUNDS} divisions");
}

// ============================================================================
// 4. NO LEVEL COUNTER MOVED
// ============================================================================

#[test]
fn no_level_like_counter_moves_under_exact_division() {
    for (name, cfg) in parameter_sets() {
        let (ctx, keys) = ctx_and_keys(&cfg);
        let d = 97u64;
        let (ct, _) = encrypt_divisible(&ctx, &keys, 55, 5, d);

        // Everything level-like the API exposes, sampled before.
        let ct_level = ct.level;
        let ct_main_lanes = ct.c0.main.len();
        let ct_anchor_lanes = ct.c0.anchor.len();
        let ctx_num_moduli = ctx.rns.num_primes();
        let ctx_main_moduli = ctx.dual_rns.main.primes.len();
        let ctx_anchor_moduli = ctx.dual_rns.anchor.primes.len();
        let ctx_q_bits = ctx.q_bits;
        let ctx_q_product = ctx.q_product;
        let ctx_delta_len = ctx.delta_rns.len();
        let cfg_chain_len = ctx.config.primes.len();

        let divided = exact_divide_dual(&ctx, &ct, d);

        assert_eq!(divided.level, ct_level, "[{name}] ct.level moved");
        assert_eq!(
            divided.c0.main.len(),
            ct_main_lanes,
            "[{name}] main lane count (the de-facto level) moved"
        );
        assert_eq!(
            divided.c0.anchor.len(),
            ct_anchor_lanes,
            "[{name}] anchor lane count moved"
        );
        assert_eq!(ctx.rns.num_primes(), ctx_num_moduli, "[{name}] num_moduli moved");
        assert_eq!(ctx.dual_rns.main.primes.len(), ctx_main_moduli, "[{name}]");
        assert_eq!(ctx.dual_rns.anchor.primes.len(), ctx_anchor_moduli, "[{name}]");
        assert_eq!(ctx.q_bits, ctx_q_bits, "[{name}] q_bits moved");
        assert_eq!(ctx.q_product, ctx_q_product, "[{name}] Q moved");
        assert_eq!(ctx.delta_rns.len(), ctx_delta_len, "[{name}] delta chain moved");
        assert_eq!(ctx.config.primes.len(), cfg_chain_len, "[{name}] config chain moved");

        // The level field must also still be a truthful description of the
        // ciphertext: it must not have been "kept constant" by decoupling it
        // from the lanes.
        assert_eq!(
            divided.level,
            divided.c0.main.len(),
            "[{name}] level and lane count disagree — the invariant would be cosmetic"
        );
    }
}

// ============================================================================
// FALSIFIABILITY: the retired mechanism is the exact negative of all of this
// ============================================================================

/// The discriminator. The assertions above are worthless if nothing in this
/// codebase could ever violate them — so here is something that does.
///
/// `mod_switch_ct_down` is the retired classical rescale (still present at
/// `crates/nine65/src/ops/rns_fhe.rs`, alongside `mod_switch_down_dual` and
/// `mod_switch_ct_to_level`). Applied to the same ciphertext, it drops a lane
/// and decrements the level — it *fails* every assertion in
/// `basis_is_byte_identical_before_and_after_exact_division`.
///
/// This test asserts that failure, so the invariance claim is falsifiable and
/// demonstrably non-vacuous. It must NEVER be turned into an endorsement of
/// modulus switching: it is here purely to prove the basis *can* move in this
/// type system, and that exact division is what keeps it still.
#[test]
fn mod_switch_ladder_is_the_negative_of_this_invariant() {
    let (ctx, keys) = ctx_and_keys(&SecureConfig::secure_128());
    let d = 23u64;
    let (ct, big) = encrypt_divisible(&ctx, &keys, 99, 3, d);

    let bytes_before = basis_bytes(&ctx, &ct);

    // Exact division: basis byte-identical, value divided.
    let divided = exact_divide_dual(&ctx, &ct, d);
    assert_eq!(basis_bytes(&ctx, &divided), bytes_before);
    assert_eq!(ctx.decrypt_dual(&divided, &keys.secret_key), big / d);

    // Retired classical rescale on the same input: basis MOVES.
    let switched = ctx
        .mod_switch_ct_down(&ct)
        .expect("retired path still present; this test documents what it does");

    assert_ne!(
        basis_bytes(&ctx, &switched),
        bytes_before,
        "mod_switch_ct_down was expected to move the basis; if it no longer does, \
         the falsifiability of this file must be re-established against whatever \
         does move it"
    );
    assert_eq!(
        switched.c0.main.len(),
        ct.c0.main.len() - 1,
        "the retired rescale drops exactly one main lane"
    );
    assert_eq!(
        switched.level,
        ct.level - 1,
        "the retired rescale decrements the level"
    );
    assert!(
        switched.c0.main.len() < divided.c0.main.len(),
        "the whole point: the ladder shrinks the representation, exact division does not"
    );
}

// ============================================================================
// PRIMITIVE CROSS-CHECK
// ============================================================================

/// The lane arithmetic used above is exactly what `k_elim::k_elim_divide`
/// computes — checked against the K-Elimination entry point on real ciphertext
/// residues, lane by lane.
///
/// (`k_elim_divide` forms `basis.iter().product::<i128>()` internally, which
/// overflows on a multi-lane ~31-bit chain, so it is fed one lane at a time —
/// which is also precisely how residue-native division is defined: per lane,
/// no cross-lane carry.)
#[test]
fn k_elim_divide_primitive_agrees_on_real_ciphertext_residues() {
    let (ctx, keys) = ctx_and_keys(&SecureConfig::secure_128());
    let d = 1009u64;
    let (ct, _) = encrypt_divisible(&ctx, &keys, 11, 4, d);
    let divided = exact_divide_dual(&ctx, &ct, d);

    let lanes: Vec<u64> = ctx
        .config
        .primes
        .iter()
        .chain(ctx.dual_rns.anchor.primes.iter())
        .copied()
        .collect();

    for (lane_idx, &p) in lanes.iter().enumerate() {
        let (src, out) = if lane_idx < ctx.config.primes.len() {
            (&ct.c0.main[lane_idx], &divided.c0.main[lane_idx])
        } else {
            let j = lane_idx - ctx.config.primes.len();
            (&ct.c0.anchor[j], &divided.c0.anchor[j])
        };

        for coeff in [0usize, 1, 2, 17, 100] {
            if coeff >= src.len() {
                continue;
            }
            let via_primitive = k_elim::k_elim_divide(&[src[coeff] as i128], &[p as i128], d as i128)
                .unwrap_or_else(|| panic!("k_elim_divide rejected lane {p}"));
            assert_eq!(
                via_primitive.len(),
                1,
                "k_elim_divide must return one residue per lane — no lane added or dropped"
            );
            assert_eq!(
                via_primitive[0] as u64, out[coeff],
                "lane {p} coeff {coeff}: k_elim_divide disagrees with the applied division"
            );
        }
    }
}
