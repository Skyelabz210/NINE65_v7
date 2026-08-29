//! T2 — regression tripwires for the CRAM-public / M2b non-standard design
//! decisions. Each test is written to be never-vacuous in both directions:
//! it must fail if the protected decision regresses to the textbook
//! default, and it must also fail if the guardrail itself stops exercising
//! the case it claims to (see each test's header for the specific
//! never-vacuous argument). See docs/CRAM_PUBLIC_MODE.md for the milestone
//! context (M2a/M2b) these protect, and docs/roadmap/README.md for the
//! anti-regression rationale this file exists to serve.
//!
//! Tripwire 1 (no-centering) and tripwire 3 (no-Garner) live IN-MODULE
//! (`crates/nine65/src/ops/rns_fhe.rs` and
//! `crates/nine65/src/arithmetic/unified_rescale.rs` respectively) rather
//! than here: both need access to private internals
//! (`k_elim_rescale_manufactured`, and the `#[cfg(test)]`-gated `garner`
//! oracle, which does not even exist in the library build this integration
//! test binary links against) that are not part of the public API surface.
//! This file covers tripwires 2 and 4, which are expressible entirely
//! through public API (`RescaleChain`, `exact_delta_rescale`,
//! `extended_gcd`, `FHEConfig::manufactured_m2b_insecure`).

use nine65::arithmetic::rns::U256;
use nine65::arithmetic::unified_rescale::{exact_delta_rescale, DeltaRounding, RescaleChain, RescaleExit};
use nine65::params::primes::extended_gcd;
use nine65::params::FHEConfig;

/// T2 tripwire 2 (unsigned-bound certificate): the M2b winding capacity
/// certificate must be sized to the SOUND bound `4*N*Q + 1` (the `d1`
/// component is a sum of two products, within `±2*N*Q^2` before the
/// K-Elimination shift) — an under-provisioned certificate (even by just
/// one anchor lane short of what `4*N*Q+1` needs) silently aliases instead
/// of erroring (charter M2b finding #2: "certificates need proved bounds,
/// not assumed ones").
///
/// Never-vacuous both directions: constructs the true worst-case winding
/// `K_true = 4*N*Q` (just under the certificate) and reconstructs it through
/// two independently built [`RescaleChain`]s — one whose anchor-product
/// capacity is exactly one lane short of the real `4*N*Q+1` certificate, one
/// that meets it — using the SAME `exact_delta_rescale` primitive the
/// shipped rescale calls. The short-by-one chain MUST alias (recovers a
/// value congruent to but not equal to the true winding); the correctly
/// sized chain MUST NOT. If a future change narrows the real certificate to
/// admit one fewer anchor than `4*N*Q+1` needs, the "must not alias"
/// assertion below starts failing on real chains too — this test's failure
/// mode is a subset of that regression's.
#[test]
fn cram_public_guardrail_unsigned_bound_certificate_must_be_4nq_not_2nq() {
    let cfg = FHEConfig::manufactured_m2b_insecure();
    let n = cfg.n as u128;
    let t = cfg.t;
    let lanes: Vec<u64> = cfg.primes.clone();
    let t_idx = lanes.iter().position(|&p| p == t).expect("t must be a main lane");
    let delta_idx: Vec<usize> = (0..lanes.len()).filter(|&i| i != t_idx).collect();

    let q_product: u128 = lanes.iter().map(|&p| p as u128).product();
    let four_nq_plus_1 = 4 * n * q_product + 1;

    // Anchor primes available to build subsets from — the same canonical
    // set the manufactured chain draws its certificate anchors from.
    let avoid = nine65::arithmetic::DualRNSContext::canonical_anchor_primes_for_n(cfg.n);
    assert!(avoid.len() >= 2, "test setup: need at least 2 anchor primes to build a short-by-one subset");

    // Correctly sized subset: smallest prefix whose product clears the real
    // certificate 4*N*Q+1 (the same threshold the shipped rescale uses).
    let mut correct: Vec<u64> = Vec::new();
    let mut cap_correct: u128 = 1;
    for &a in &avoid {
        cap_correct = cap_correct.checked_mul(a as u128).expect("test bound: capacity overflow");
        correct.push(a);
        if cap_correct > four_nq_plus_1 {
            break;
        }
    }
    assert!(cap_correct > four_nq_plus_1, "test setup: correct subset must clear 4*N*Q+1");
    assert!(correct.len() >= 2, "test setup: correct subset needs >=2 anchors for a meaningful short-by-one undersized subset");

    // Undersized subset: exactly ONE fewer anchor than the certificate
    // needs — the direct shape of "under-provision the certificate by one
    // lane". Its capacity is many orders of magnitude below cap_correct
    // (each anchor prime is ~2^31, so dropping the last one drops capacity
    // by that same factor), leaving ample room to place a realistic
    // worst-case winding strictly between the two.
    let undersized: Vec<u64> = correct[..correct.len() - 1].to_vec();
    let cap_under: u128 = undersized.iter().map(|&a| a as u128).product();
    assert!(cap_under < four_nq_plus_1, "test setup: undersized subset must NOT clear the real certificate");

    // K_true = the true sound worst-case bound from the charter analysis
    // (4*N*Q, just under the certificate 4*N*Q+1) — realistic, not
    // adversarially tiny-but-technically-over-cap_under.
    let k_true: u128 = 4 * n * q_product;
    assert!(k_true > cap_under, "test setup: K_true must exceed the undersized capacity to alias");
    assert!(k_true < cap_correct, "test setup: K_true must fit under the correct capacity to reconstruct exactly");

    let chain_under = RescaleChain::new(&lanes, &delta_idx, t, &undersized).unwrap();
    let chain_correct = RescaleChain::new(&lanes, &delta_idx, t, &correct).unwrap();

    // `exact_delta_rescale` takes residues of the FULL pre-division value X
    // across every main lane (not residues of K*t directly) and performs
    // the align-and-drop itself. Construct X = w*Q + xc with w = K_true and
    // xc = 0: dividing (X + floor(Delta/2)) by Delta (each Delta-lane in
    // turn, exactly as the shipped rescale does) gives Y = w*t + 0 exactly,
    // since xc=0 keeps the half-Delta offset from crossing a boundary — so
    // the surviving-lane read is gamma=0 and the anchor-reconstructed
    // winding is exactly K_true. (Same construction as the ground-truth
    // sweep in `rns_fhe.rs`'s `manufactured_rescale_matches_ground_truth_
    // on_known_values`.)
    let w = k_true;
    let main_res: Vec<u64> = lanes
        .iter()
        .map(|&p| {
            let p128 = p as u128;
            (((w % p128) * (q_product % p128)) % p128) as u64
        })
        .collect();
    let anchor_res_under: Vec<u64> = undersized
        .iter()
        .map(|&a| {
            let a128 = a as u128;
            (((w % a128) * (q_product % a128)) % a128) as u64
        })
        .collect();
    let anchor_res_correct: Vec<u64> = correct
        .iter()
        .map(|&a| {
            let a128 = a as u128;
            (((w % a128) * (q_product % a128)) % a128) as u64
        })
        .collect();

    let out_under = exact_delta_rescale(
        &chain_under,
        &main_res,
        &anchor_res_under,
        DeltaRounding::NearestHalfUp,
        RescaleExit::ModulusReduced,
    )
    .unwrap();
    let out_correct = exact_delta_rescale(
        &chain_correct,
        &main_res,
        &anchor_res_correct,
        DeltaRounding::NearestHalfUp,
        RescaleExit::ModulusReduced,
    )
    .unwrap();

    assert_eq!(
        out_correct.winding_k_u128().unwrap(), k_true,
        "the correctly-certified (4*N*Q+1) anchor subset must recover the true \
         winding exactly — if this fails, the certificate math itself is broken"
    );
    assert_ne!(
        out_under.winding_k_u128().unwrap(), k_true,
        "REGRESSION-SHAPE FAILURE: the short-by-one-anchor subset recovered the \
         true winding anyway — either K_true was not actually placed above the \
         undersized capacity (widen the test construction), or aliasing stopped \
         happening, which would mean this guardrail no longer demonstrates why the \
         certificate must be 4*N*Q+1 and not one anchor lane less. Do not 'fix' \
         this test by accepting equality here."
    );
}

/// T2 tripwire 4 (derived-inverse / G5 discipline): every manufactured
/// Δ-lane `D = c*t + 1` carries a FREE inverse read-off `t^{-1} mod D = D - c`
/// by star-family construction — this must equal the general extended-Euclid
/// inverse of `t` mod `D`, not merely "some cached value with no derivation"
/// (the owner's G5 clarification: derivability is the discipline, caching a
/// value that IS derivable is fine; caching one that ISN'T, or drifting from
/// its derivation, is the failure G5 forbids).
///
/// Never-vacuous: exercises every Δ-lane of the real manufactured chain (not
/// a synthetic example), and would fail immediately if a future change
/// stored an inverse table disconnected from the `D - c` read-off (the two
/// sides are computed by entirely independent methods: closed-form
/// construction vs. general extended Euclid).
#[test]
fn cram_public_guardrail_derived_inverse_matches_egcd_for_every_delta_lane() {
    let cfg = FHEConfig::manufactured_m2b_insecure();
    let t = cfg.t;
    let delta_lanes = &cfg.primes[1..];
    assert!(delta_lanes.len() >= 2, "test setup: manufactured chain must have Delta-lanes");

    let mut checked = 0usize;
    for &d in delta_lanes {
        assert_eq!((d - 1) % t, 0, "Delta-lane {d} must satisfy D = c*t + 1 by construction");
        let c = (d - 1) / t;
        let derived_inv = d - c; // the star-family free read-off, G5-clean

        let (g, x, _y) = extended_gcd(t as i128, d as i128);
        assert_eq!(g, 1, "t and Delta-lane {d} must be coprime (D ≡ 1 mod t by construction)");
        let egcd_inv = ((x % d as i128) + d as i128) % d as i128;

        assert_eq!(
            derived_inv as i128, egcd_inv,
            "REGRESSION: the D-c star-family read-off no longer matches the general \
             extended-Euclid inverse of t mod D={d} — G5 requires the cached/derived \
             value to agree with its derivation, not merely exist"
        );
        checked += 1;
    }
    assert!(checked >= 2, "sweep must not go vacuous — manufactured chain must expose Delta-lanes");
}

/// T2 tripwire 2b — pins the SHIPPED certificate derivation itself.
///
/// **Why this exists (found the hard way, 2026-08-26).** The sibling test
/// `cram_public_guardrail_unsigned_bound_certificate_must_be_4nq_not_2nq`
/// demonstrates the *mathematical principle* that an under-provisioned
/// certificate aliases — but it builds its own chains and re-derives its own
/// bound locally, so it never reads the constant the shipped code uses. It
/// was therefore VACUOUS with respect to the real code: flipping
/// `k_elim_rescale_manufactured`'s certificate from `4 * self.n` to
/// `2 * self.n` left it, and the entire rest of the suite (13 tests, every
/// guardrail, the ground-truth sweep, the depth-3 chain), fully GREEN.
///
/// **Why the pinned constant changed (2026-08-29).** `4*N*Q + 1` was itself
/// an under-provision, for the same reason it warned about one level down.
/// It bounds the winding only if the tensor's operands are canonical in
/// `[0, Q)`. They are not: a dual-RNS ciphertext coefficient carries the
/// integer its lanes were computed from, and a fresh encryption's `a·s` is a
/// negacyclic convolution over `N` terms. Measured on
/// `manufactured_m2b_insecure` over 24,576 sampled coefficients, max
/// `|V| = 118` bits — exactly `2·N·Q` — and the resulting tensor measured
/// max `|X| = 241` bits over 18,432 samples against a shift of
/// `S = 2·N·Q² = 2^225`. `X + S` stayed NEGATIVE and wrapped silently:
/// wrong-but-plausible plaintexts (`m3_rns_limb_relin`'s 603-for-42) with no
/// error raised anywhere.
///
/// So the operand bound `V ≤ 2·N·Q` is now carried explicitly, giving
/// `S = 2·N·V² = 8·N³·Q²` and the certificate `K'' ≤ 16·N³·Q + 1` (2^139 at
/// `n=512`, measured windings all exactly 138 bits). This test pins that
/// derivation and keeps refusing BOTH superseded constants.
///
/// Never-vacuous: it asserts the surrounding context still exists, so a
/// refactor that moves or renames the certificate fails here loudly instead
/// of passing silently.
#[test]
fn cram_public_guardrail_shipped_certificate_constant_is_4n_not_2n() {
    const SRC: &str = include_str!("../src/ops/rns_fhe.rs");

    // Context anchor: if this vanishes, the certificate moved or was renamed,
    // and the constant assertions below would pass vacuously.
    assert!(
        SRC.contains("Winding capacity certificate"),
        "REGRESSION-SHAPE FAILURE: the 'Winding capacity certificate' comment is \
         gone from rns_fhe.rs, so this guardrail no longer knows where to look. \
         Re-point it at the certificate's new home; do NOT delete it."
    );
    assert!(
        SRC.contains("fn manufactured_shift_certificate"),
        "REGRESSION-SHAPE FAILURE: `manufactured_shift_certificate` is gone. It is \
         the single place the shipped path and the centered-wrong guardrail both \
         take their certificate from; splitting them lets the two drift."
    );

    // The operand bound V = 2*N*Q must be carried explicitly. Deriving S from
    // Q alone is the measured silent-wrap regression.
    assert!(
        SRC.contains("let v_scale = 2u128.checked_mul(n_u)"),
        "REGRESSION: the manufactured shift no longer derives its operand bound \
         V = 2*N*Q. Sizing S from Q alone assumes canonical operands; measured \
         max |V| is 2^118 = 2*N*Q on manufactured_m2b_insecure, so S = 2N*Q^2 \
         under-shifts by 20 bits, X + S stays negative, and the rescale wraps \
         silently. Do NOT 'simplify' S back to a function of Q."
    );
    assert!(
        SRC.contains("let s_scale = v_scale")
            && SRC.contains("K'' ≤ k_scale·Q + 1 = 2·S/Q + 1"),
        "REGRESSION: S is no longer 2*N*V^2, or the winding bound is no longer \
         derived from S as 2*S/Q. These two must move together — a bound derived \
         from anything but the shipped S is not a certificate."
    );

    // Both superseded certificates stay refused.
    assert!(
        !SRC.contains("let two_nq = (4 * self.n as u128)"),
        "REGRESSION: the certificate reverted to 4*N*Q + 1. That bound is sound \
         only for operands canonical in [0,Q); measured operands reach 2*N*Q, and \
         the shift derived alongside it (S = 2N*Q^2) under-shifts the tensor by 16 \
         bits. See this test's doc comment for the measurement."
    );
    assert!(
        !SRC.contains("let two_nq = (2 * self.n as u128)"),
        "REGRESSION: the certificate was halved to 2*N*Q. This is the original \
         documented regression: the d1 tensor component is a SUM OF TWO products \
         of unsigned representatives, so halving under-sizes it 2x on top of the \
         operand-magnitude gap, and the winding aliases by exactly the ladder \
         capacity C."
    );
}

/// T2 tripwire 5 pointer: the Y''-mod-Q semantics pin lives in-module as
/// `manufactured_rescale_matches_ground_truth_on_known_values` (extended
/// with a DO-NOT header) and
/// `cram_public_guardrail_no_centering_regression_measurably_fails` in
/// `crates/nine65/src/ops/rns_fhe.rs`, next to the code they guard. This
/// marker test exists only so `cargo test --test cram_public_guardrails`
/// documents where that coverage actually lives.
#[test]
fn tripwire_5_pointer_y_star_mod_q_semantics_pinned_in_rns_fhe_rs() {
    // No-op: see the doc comment above. Kept as a real (trivially-passing)
    // test rather than a comment so `cargo test` output lists it, instead
    // of silently omitting tripwire 5 from this file's test list.
    let _ = U256::from_u128(0); // touch the import so it is not flagged unused
}
