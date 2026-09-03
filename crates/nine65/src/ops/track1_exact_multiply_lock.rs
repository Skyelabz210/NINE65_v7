//! Track 1 (PR #103) stage T1.1 — lock the current multiply/rescale failure
//! and pin the target semantics.
//!
//! This module is a **child** of `ops::rns_fhe` (declared there under
//! `#[cfg(test)]`) so it can reach the private `RNSFHEContext::exact_rescale`
//! without widening any production visibility.
//!
//! Per `docs/TRACK1_D3_EXACT_MULTIPLY_IMPLEMENTATION.md` T1.1, these tests
//! prove four things:
//!
//! 1. the current limb-local `exact_rescale` disagrees with the exact BFV
//!    oracle on a multi-prime chain where `Delta^2 > Q`;
//! 2. the target result is the exact rounded BFV value reduced back into the
//!    mod-`Q` lanes (pinned independently of any implementation);
//! 3. the existing [`BaseExt::project`] cannot serve the production route
//!    without a redundant residue the mod-`Q` object does not carry, while
//!    [`MainOnlyBaseExt`] reproduces it bit-for-bit from the main lanes alone;
//! 4. no auxiliary lane survives serialization.
//!
//! **Do not delete or weaken test (1) when the replacement route lands.** The
//! contract requires it to be *re-pointed* at the new route and flipped to
//! assert agreement.
//!
//! ## Why no big-integer dependency
//!
//! The oracle here is exact in `u128`, not approximate. On the chain used
//! below (`light_rns_insecure`, three ~30-bit NTT primes) `Q < 2^90` and
//! `t = 65537 < 2^17`, so the widest oracle intermediate is
//! `mag * t < 2^90 * 2^17 = 2^107`, which fits `u128` with 21 bits to spare.
//! The assertion in `oracle_intermediates_fit_u128` pins that headroom so a
//! future chain change cannot silently wrap.

use super::*;
use crate::arithmetic::base_ext::BaseExt;
use crate::arithmetic::main_only_base_ext::{MainOnlyBaseExt, RankPath};

/// Exact BFV rescale oracle: `round(centered(x) * t / Q)` reduced into
/// `[0, Q)`.
///
/// Rounding is half-away-from-zero on the centered magnitude, which is the
/// rule `exact_rescale` itself attempts per limb (`+ q_i/2` then floor). Using
/// the same rule keeps this an apples-to-apples comparison: any disagreement
/// is a defect in the *decomposition*, not a difference of rounding
/// convention.
fn exact_bfv_rescale_oracle(x: u128, t: u128, q: u128) -> u128 {
    assert!(x < q, "oracle input must be canonical in [0, Q)");
    let negative = x > q / 2;
    let magnitude = if negative { q - x } else { x };
    // Exact in u128 for this chain; see module docs.
    let scaled = (magnitude * t + q / 2) / q;
    let reduced = scaled % q;
    if negative && reduced != 0 {
        q - reduced
    } else {
        reduced
    }
}

/// Drive one coefficient through the production `exact_rescale` and read the
/// result back as an integer.
fn rescale_one_coefficient(ctx: &RNSFHEContext, x: u128) -> u128 {
    let mut limbs = vec![vec![0u64; ctx.n]; ctx.config.primes.len()];
    for (i, &p) in ctx.config.primes.iter().enumerate() {
        limbs[i][0] = (x % p as u128) as u64;
    }
    let poly = RNSPolynomial { limbs, n: ctx.n };
    let mont = ctx.to_montgomery_form(&poly);
    let out = ctx.exact_rescale(&mont);
    let coeffs: Vec<u64> = out.limbs.iter().map(|l| l[0]).collect();
    ctx.to_int_montgomery(&coeffs)
}

/// The multi-prime chain this stage is pinned against.
fn lock_context() -> RNSFHEContext {
    let config = FHEConfig::light_rns_insecure();
    RNSFHEContext::new(&config)
}

/// Sample points: the structural corners the contract names, plus seeded
/// pseudo-random draws. Deterministic — no RNG dependency.
fn sample_points(q: u128) -> Vec<u128> {
    let mut xs = vec![0, 1, 2, q / 2 - 1, q / 2, q / 2 + 1, q - 2, q - 1];
    // Deterministic LCG draws spread across [0, Q).
    let mut state: u128 = 0x9E37_79B9_7F4A_7C15;
    for _ in 0..64 {
        state = state
            .wrapping_mul(0x5851_F42D_4C95_7F2D)
            .wrapping_add(0x1405_7B7E_F767_814F);
        xs.push(state % q);
    }
    xs
}

#[test]
fn oracle_intermediates_fit_u128() {
    let ctx = lock_context();
    let q = ctx.q_product;
    let t = ctx.t as u128;
    assert!(q > 0, "this chain must not use the q_product=0 sentinel");
    // Widest intermediate is (q-1)*t + q/2. Prove it cannot wrap u128.
    let headroom = u128::MAX / t;
    assert!(
        q - 1 < headroom,
        "oracle would overflow u128 on this chain: Q={q}, t={t}"
    );
    assert!(
        u128::MAX - (q - 1) * t >= q / 2,
        "oracle rounding term would overflow u128"
    );
}

/// **T1.1 lock.** On a multi-prime chain with `Delta^2 > Q`, the limb-local
/// Bajard rescale is not the BFV rescale.
///
/// When the derived-transient route lands, re-point this test at that route
/// and flip the assertion to `disagreements == 0`. Do not delete it.
#[test]
fn bajard_rescale_disagrees_with_exact_oracle_when_delta_squared_exceeds_q() {
    let ctx = lock_context();
    let q = ctx.q_product;
    let t = ctx.t as u128;
    let delta = q / t;

    // Regime fact: this chain is outside the Bajard route's stated contract.
    assert!(
        delta.checked_mul(delta).is_none_or(|d2| d2 > q),
        "chain must satisfy Delta^2 > Q for this lock to mean anything"
    );
    assert_eq!(
        ctx.mul_route(),
        MulRoute::KElimDual,
        "router must already know the single-RNS route is invalid here"
    );
    assert!(
        ctx.config.primes.len() >= 3,
        "lock requires a genuinely multi-prime chain"
    );

    let xs = sample_points(q);
    let mut disagreements = 0usize;
    let mut worst_abs_error = 0u128;
    let mut first_witness = None;

    for &x in &xs {
        let got = rescale_one_coefficient(&ctx, x);
        let want = exact_bfv_rescale_oracle(x, t, q);
        if got != want {
            disagreements += 1;
            // Centered distance between got and want, mod Q.
            let raw = got.abs_diff(want);
            let err = raw.min(q - raw);
            if err > worst_abs_error {
                worst_abs_error = err;
            }
            if first_witness.is_none() {
                first_witness = Some((x, got, want));
            }
        }
    }

    let (x, got, want) = first_witness.expect(
        "T1.1 lock: exact_rescale unexpectedly matched the BFV oracle on every \
         sample. If the derived-transient route has landed, re-point this test \
         at it and assert agreement instead of deleting it.",
    );

    // The failure is not a rounding wobble: it is a wrong decomposition.
    assert!(
        worst_abs_error > 1,
        "disagreement of at most 1 would be a rounding-convention artifact, \
         not the structural defect this test locks (worst={worst_abs_error})"
    );
    assert!(
        disagreements * 2 > xs.len(),
        "expected the Bajard route to be wrong on most samples, not a few: \
         {disagreements}/{} (first witness x={x} got={got} want={want})",
        xs.len()
    );
}

/// **T1.1 end-to-end lock, re-pointed for the WIRE-Q fail-closed gate
/// (PR #107).** `RNSFHEContext::mul` used to be a public API with no route
/// guard, so on a `Delta^2 > Q` chain it silently returned a ciphertext that
/// decrypted to the wrong plaintext. `mul` now calls
/// `require_bajard_single_mul_route` before it touches the limb-local
/// `exact_rescale`, so the hazard this test originally pinned (wrong
/// plaintext, no error) can no longer happen: the same off-contract call now
/// panics instead. Per this module's own instruction ("re-point this test
/// rather than deleting it" once `mul()` fails closed), this locks the new
/// contract: the call must panic, not compute.
///
/// Scope note: this is a *hazard on a public entry point*, not a defect in
/// the auto-routed pipeline. Nothing here changes production behavior; T1.1 is
/// a test-only stage by contract.
#[test]
#[should_panic(
    expected = "RNSFHEContext::mul is unavailable when the configuration requires \
    K-Elimination/dual rescaling"
)]
fn public_mul_fails_closed_instead_of_returning_wrong_plaintext_off_contract() {
    let ctx = lock_context();
    assert_eq!(
        ctx.mul_route(),
        MulRoute::KElimDual,
        "router already knows the single-RNS route is invalid on this chain"
    );

    let mut rng = ShadowHarvester::with_seed(0x7115_0002);
    let keys = ctx.generate_keys(&mut rng);
    let ct_a = ctx.encrypt(1, &keys.public_key, &mut rng);
    let ct_b = ctx.encrypt(1, &keys.public_key, &mut rng);

    // Must panic before it ever computes a (wrong) plaintext.
    let _ = ctx.mul(&ct_a, &ct_b, &keys.eval_key);
}

/// **T1.1 target semantics.** The exact oracle is the BFV decode rule.
///
/// A coefficient `Delta * m` must rescale back to `m` *as a centered
/// residue*. This is the subtlety the naive reading misses: BFV plaintexts
/// live in the centered range, so for `m > t/2` the coefficient `Delta * m`
/// exceeds `Q/2` and decodes to the negative representative `m - t`, not to
/// `m`. Both halves are pinned below.
///
/// This fixes what the replacement route must produce, independently of how
/// it is implemented.
#[test]
fn exact_oracle_recovers_message_from_delta_scaled_coefficient() {
    let ctx = lock_context();
    let q = ctx.q_product;
    let t = ctx.t as u128;
    let delta = q / t;

    // Centered decode of a value in [0, Q).
    let centered = |v: u128| -> i128 {
        if v > q / 2 {
            v as i128 - q as i128
        } else {
            v as i128
        }
    };

    // The whole plaintext space, in the invariant that actually matters:
    // decode(rescale(Delta * m)) == m (mod t).
    for m in 0..t {
        let x = delta * m;
        assert!(x < q, "Delta*m must stay canonical for m < t");
        let got = exact_bfv_rescale_oracle(x, t, q);
        assert_eq!(
            centered(got).rem_euclid(t as i128),
            m as i128,
            "rescale of Delta*{m} must decode to {m} mod t"
        );
    }

    // Explicit endpoints, so the centered wrap is visible and not just implied.
    // Below the wrap the result is literally m.
    for m in [0u128, 1, 2, 7, 1000, t / 2] {
        assert_eq!(
            exact_bfv_rescale_oracle(delta * m, t, q),
            m,
            "Delta*{m} is below Q/2 and must rescale to exactly {m}"
        );
    }
    // Above the wrap it is the negative representative m - t, reduced mod Q.
    for m in [t / 2 + 1, t - 2, t - 1] {
        assert_eq!(
            exact_bfv_rescale_oracle(delta * m, t, q),
            q - (t - m),
            "Delta*{m} is above Q/2 and must rescale to the centered value {} \
             (= {m} - {t}), reduced mod Q",
            m as i128 - t as i128
        );
    }
}

/// **T1.1 blocker.** `BaseExt::project` needs `r_red = X mod m_r`, which the
/// mod-`Q` object does not carry; `MainOnlyBaseExt` derives the same
/// projection from the main lanes alone.
///
/// Both halves matter: agreement proves the new primitive is a faithful
/// replacement (the contract's required cross-check against the reference),
/// and the second half proves the redundant residue is genuinely load-bearing
/// rather than decorative — i.e. it could not simply be dropped.
#[test]
fn main_only_reproduces_base_ext_without_the_redundant_residue() {
    // Small coprime basis so every case is checkable by construction.
    let main: [u64; 3] = [97, 101, 103];
    let aux: [u64; 2] = [107, 109];
    // BaseExt requires the redundant lane to exceed the main lane count.
    let m_r: u64 = 113;

    let reference = BaseExt::new(&main, &aux, m_r);
    let derived = MainOnlyBaseExt::new(&main, &aux).expect("valid basis");

    let m_product: u128 = main.iter().map(|&p| p as u128).product();
    let mut saw_certified = false;
    let mut saw_fallback = false;

    // Exhaustive over the whole product space.
    for x in 0..m_product {
        let r: Vec<u64> = main.iter().map(|&p| (x % p as u128) as u64).collect();
        let r_red = (x % m_r as u128) as u64;

        let mut want = vec![0u64; aux.len()];
        reference.project(&r, r_red, &mut want);

        let mut got = vec![0u64; aux.len()];
        let path = derived.project(&r, &mut got).expect("canonical residues");
        match path {
            RankPath::CertifiedFixedPoint => saw_certified = true,
            RankPath::ExactFallback => saw_fallback = true,
        }

        assert_eq!(
            got, want,
            "main-only projection must equal the redundant-lane reference at x={x}"
        );

        // Ground truth, independent of both implementations.
        let truth: Vec<u64> = aux.iter().map(|&a| (x % a as u128) as u64).collect();
        assert_eq!(got, truth, "projection must be the true residues at x={x}");
    }

    assert!(
        saw_certified,
        "certified fixed-point rank path never executed"
    );
    let _ = saw_fallback; // exercised by the production-prefix tests in T1.2

    // The redundant residue is load-bearing: feeding a wrong one corrupts the
    // reference, which is precisely why it cannot be omitted from a mod-Q
    // object that does not carry it.
    let x: u128 = 123_456;
    let r: Vec<u64> = main.iter().map(|&p| (x % p as u128) as u64).collect();
    let true_r_red = (x % m_r as u128) as u64;
    let mut correct = vec![0u64; aux.len()];
    reference.project(&r, true_r_red, &mut correct);

    let mut corrupted_count = 0usize;
    for wrong in 0..m_r {
        if wrong == true_r_red {
            continue;
        }
        let mut out = vec![0u64; aux.len()];
        reference.project(&r, wrong, &mut out);
        if out != correct {
            corrupted_count += 1;
        }
    }
    assert!(
        corrupted_count > 0,
        "if no wrong r_red changed the answer, the redundant lane would be \
         inert and the architectural blocker would not exist"
    );
}

/// **T1.1 WIRE-Q lock.** The single-RNS ciphertext is wire-clean; the
/// dual-RNS ciphertext — the one the `KElimDual` route actually uses and the
/// one that has `to_bytes` — publishes anchor residues that are *coprime* to
/// `Q`.
///
/// That second half is the current-state lock, in the same spirit as the
/// Bajard lock above. `docs/TRACK1_D3_EXACT_MULTIPLY_IMPLEMENTATION.md` rule 5
/// forbids "an anchor, shadow, redundant, or auxiliary lane" in any serialized
/// artifact, and rule 4's derived-transient design exists precisely so the
/// auxiliary residues live inside one kernel call instead of on the wire.
///
/// `DualRNSPoly` carries `anchor: Vec<Vec<u64>>` beside `main`, and
/// `DualRNSCiphertext` bincode-encodes the whole struct (under the `serde`
/// feature), so those anchor limbs ship. `X mod A` for `A` coprime to `Q` is
/// strictly more information than `X mod Q`.
///
/// When the derived-transient route replaces this representation, flip the
/// `anchor_lane_count > 0` assertion to `== 0`. Do not delete it.
#[test]
fn wire_q_lock_dual_ciphertext_publishes_anchor_lanes_coprime_to_q() {
    let ctx = lock_context();
    let main_lanes = ctx.config.primes.len();

    // Single-RNS ciphertext: wire-clean, carries only Q lanes.
    let mut rng = ShadowHarvester::with_seed(0x7115_0001);
    let keys = ctx.generate_keys(&mut rng);
    let ct = ctx.encrypt(42, &keys.public_key, &mut rng);
    assert_eq!(
        ct.num_primes, main_lanes,
        "single-RNS ct must carry only Q lanes"
    );
    assert_eq!(ct.c0.limbs.len(), main_lanes);
    assert_eq!(ct.c1.limbs.len(), main_lanes);

    // Every main lane genuinely divides Q.
    for &p in &ctx.config.primes {
        assert_eq!(ctx.q_product % p as u128, 0, "main lane {p} must divide Q");
    }

    // Dual-RNS ciphertext: the serializable one. Anchor lanes are present.
    let dual_keys = ctx.generate_keys_dual(&mut rng);
    let dual_ct = ctx.encrypt_dual(42, &dual_keys.public_key, &mut rng);

    assert_eq!(
        dual_ct.c0.main.len(),
        main_lanes,
        "dual ct main track must carry exactly the Q lanes"
    );

    let anchor_lane_count = dual_ct.c0.anchor.len();
    assert!(
        anchor_lane_count > 0,
        "T1.1 WIRE-Q lock: dual ciphertext carried no anchor lanes. If the \
         derived-transient route has landed, flip this to assert == 0 rather \
         than deleting the test."
    );
    assert_eq!(
        dual_ct.c1.anchor.len(),
        anchor_lane_count,
        "both components carry the anchor track"
    );

    // The anchors are extra information: coprime to Q, not divisors of it.
    let anchors = &ctx.dual_rns.anchor.primes;
    assert_eq!(anchors.len(), anchor_lane_count);
    for &a in anchors {
        assert_ne!(
            ctx.q_product % a as u128,
            0,
            "anchor {a} must not divide Q — otherwise it would carry no \
             information beyond the main track"
        );
        for &p in &ctx.config.primes {
            assert_eq!(
                gcd_u64(a, p),
                1,
                "anchor {a} and main lane {p} must be coprime"
            );
        }
    }
}

fn gcd_u64(mut a: u64, mut b: u64) -> u64 {
    while b != 0 {
        let t = a % b;
        a = b;
        b = t;
    }
    a
}
