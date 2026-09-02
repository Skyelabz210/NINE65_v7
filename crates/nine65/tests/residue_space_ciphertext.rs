//! Can we actually run ciphertext in residue space?
//!
//! `basis_invariance.rs` answers one third of that question: exact division
//! reduces the VALUE without moving the BASIS. This file extends the probe to
//! the whole ciphertext path — `encrypt -> mul -> exact-divide -> decrypt` —
//! and asks the two further questions that "residue space" actually means.
//!
//! # The three claims, and what separates them
//!
//! **(1) The lane set never moves.** Not just across division, but across
//! ct x ct multiplication and across a multiplication *chain*. This is the
//! claim the retired modulus ladder used to falsify: `mod_switch_ct_down`
//! returns a ciphertext with one fewer main limb, so a depth-`k` circuit
//! walked the basis down `k` steps and then ran out. Verified here at every
//! step of a four-deep chain, on the fingerprint bytes, not on `.level`.
//!
//! **(2) The lanes are i.i.d.** — each lane is `x mod p` and references no
//! other lane. The observable form: perturb ONE input lane and see which
//! output lanes move. If lane `j` moves when lane `i` was perturbed, the
//! lanes are coupled, and the "attacker's trace sees independent residues"
//! story does not hold for that operation. This is the sharp discriminator,
//! and it is the one the substrate currently fails on the multiply path
//! (see `ct_multiply_is_not_lane_independent_every_lane_moves`).
//!
//! **(3) The result does not depend on lane ORDER.** A mixed-radix / Garner
//! cascade threads digit `i` through digits `0..i`, so permuting the basis is
//! the classic observable that separates a cascade from independent per-lane
//! reads (the pattern in
//! `crates/exact_transcendentals/tests/a2_residue_native.rs`).
//!
//! HONEST CAVEAT ON (3), stated here so the passing test below is not
//! over-read: order-invariance is NECESSARY for residue-nativity but it is
//! NOT SUFFICIENT. An *exact* CRT reconstruction is also order-invariant —
//! Garner's algorithm returns the same integer whichever order the moduli are
//! visited in. So (3) passing does not prove nothing was reconstructed. It
//! only rules out a *lossy* or *truncated* cascade. Claim (2) is what
//! actually discriminates, because reconstruction necessarily mixes every
//! lane into every output lane. Both are asserted; only (2) is decisive.
//!
//! # What "exact divide" is here
//!
//! Same as `basis_invariance.rs`: there is no `div_plain_dual` entry point,
//! so per-lane exact division is assembled from
//! `exact_transcendentals::k_elim::reciprocal_lanewise` and applied to every
//! main and anchor lane. Four lines, no reconstruction, no cross-lane carry,
//! no lane dropped. A fresh `Enc(m)` is not divisible by `d` (the noise `e`
//! is not), so the divisible object is built the way the architecture builds
//! it: `mul_plain_dual(ct, d)` carries the integer `d*(delta*m + e)` exactly,
//! and dividing that by `d` in residue space returns `delta*m + e`.
//!
//! # Standing finding: the sbni out-of-bounds is GONE
//!
//! The brief describes `mul_dual_public` Step 5 as still calling
//! `mod_switch_ct_down`, shortening `poly.main`, and panicking out of bounds
//! at `ops/sbni.rs:84` on the next multiply. That is no longer the state of
//! the tree. `pub mod sbni;` has been removed from `ops/mod.rs`, the Step 3.5
//! injection call is gone, and the Step-5 auto-switch is retired in both
//! `mul_dual_public` (`ops/rns_fhe.rs:2986-3003`) and `mul_dual_symmetric`
//! (`:2773-2780`); `should_two_stage_rescale` now returns a hard `false`
//! (`:3378`), which also closes the quieter ladder that
//! `k_elim_rescale_dual_two_stage` hid inside the rescale. Deep chains run
//! here without panicking, and the basis does not move. What remains is a
//! plain noise ceiling, recorded in
//! `deep_chain_never_moves_the_basis_and_reports_its_correctness_horizon`.

use exact_transcendentals::k_elim;

use nine65::entropy::ShadowHarvester;
use nine65::ops::rns_fhe::{
    DualRNSCiphertext, DualRNSEvalKey, DualRNSFullKeySet, DualRNSPoly, DualRNSPublicKey,
    DualRNSSecretKey, RNSFHEContext,
};
use nine65::params::secure_configs::SecureConfig;
use nine65::params::FHEConfig;

// ============================================================================
// THE BASIS FINGERPRINT
//
// Byte-level encoding of everything that constitutes "the basis": the modulus
// chain in order, the products, and the ciphertext's own occupancy of that
// chain. A modulus switch changes these bytes. Nothing on a residue-space
// path may.
//
// Deliberately the same shape as `basis_invariance.rs::basis_bytes` so the two
// files are comparable; this one is applied to multiply and to chains, not to
// division alone.
// ============================================================================

fn basis_bytes(ctx: &RNSFHEContext, ct: &DualRNSCiphertext) -> Vec<u8> {
    let mut out = Vec::new();

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

    out.extend_from_slice(b"Q");
    out.extend_from_slice(&ctx.q_product.to_le_bytes());
    out.extend_from_slice(&(ctx.q_bits as u64).to_le_bytes());
    out.extend_from_slice(&ctx.dual_rns.main_product.to_le_bytes());
    out.extend_from_slice(&ctx.dual_rns.anchor_product.to_le_bytes());

    // The ciphertext's occupancy of the chain. THIS is what a classical
    // rescale decrements.
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

    // Per-lane widths — catches a silently truncated lane that would keep the
    // lane COUNT while shrinking the representation.
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

fn basis_summary(ctx: &RNSFHEContext, ct: &DualRNSCiphertext) -> String {
    format!(
        "main={:?} anchor={:?} c0=({} main,{} anchor) c1=({} main,{} anchor) level={}",
        ctx.dual_rns.main.primes,
        ctx.dual_rns.anchor.primes,
        ct.c0.main.len(),
        ct.c0.anchor.len(),
        ct.c1.main.len(),
        ct.c1.anchor.len(),
        ct.level,
    )
}

/// Records the fingerprint at each named step of a chain and fails naming the
/// first step at which the basis moved.
struct BasisTrace {
    label: &'static str,
    expected: Vec<u8>,
    origin: String,
}

impl BasisTrace {
    fn start(label: &'static str, ctx: &RNSFHEContext, ct: &DualRNSCiphertext) -> Self {
        Self {
            label,
            expected: basis_bytes(ctx, ct),
            origin: basis_summary(ctx, ct),
        }
    }

    fn check(&self, step: &str, ctx: &RNSFHEContext, ct: &DualRNSCiphertext) {
        let got = basis_bytes(ctx, ct);
        assert_eq!(
            got,
            self.expected,
            "[{}] BASIS MOVED at step '{}'.\n  before: {}\n  after:  {}\n\
             The lane set must be identical at every step of the ciphertext path. \
             A shrinking main-limb count is the signature of the retired modulus \
             ladder (RNSFHEContext::mod_switch_ct_down / ::mod_switch_down_dual, \
             crates/nine65/src/ops/rns_fhe.rs). See docs/RETIRED_MECHANISMS.md.",
            self.label,
            step,
            self.origin,
            basis_summary(ctx, ct)
        );
    }
}

// ============================================================================
// RESIDUE-NATIVE EXACT DIVISION (basis-preserving, no reconstruction)
// ============================================================================

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

/// Exact division of a dual-RNS ciphertext by `d`, entirely in residue space.
/// Every lane divided, no lane dropped, `level` NOT decremented.
fn exact_divide_dual(ctx: &RNSFHEContext, ct: &DualRNSCiphertext, d: u64) -> DualRNSCiphertext {
    DualRNSCiphertext {
        c0: exact_divide_poly(ctx, &ct.c0, d),
        c1: exact_divide_poly(ctx, &ct.c1, d),
        level: ct.level,
    }
}

// ============================================================================
// FIXTURES
// ============================================================================

fn ctx_and_keys(cfg: &SecureConfig, seed: u64) -> (RNSFHEContext, DualRNSFullKeySet) {
    let ctx = RNSFHEContext::new(&cfg.config);
    let mut rng = ShadowHarvester::with_seed(seed);
    let keys = ctx.generate_keys_dual_full(&mut rng);
    (ctx, keys)
}

fn ctx_and_deep_keys(cfg: &SecureConfig, seed: u64) -> (RNSFHEContext, DualRNSFullKeySet) {
    let ctx = RNSFHEContext::new(&cfg.config);
    let mut rng = ShadowHarvester::with_seed(seed);
    let keys = ctx.generate_keys_dual_full_public_deep(&mut rng);
    (ctx, keys)
}

fn encrypt(ctx: &RNSFHEContext, keys: &DualRNSFullKeySet, m: u64, seed: u64) -> DualRNSCiphertext {
    let mut rng = ShadowHarvester::with_seed(seed);
    ctx.encrypt_dual(m, &keys.public_key, &mut rng)
}

// ============================================================================
// (1) THE LANE SET NEVER MOVES — THROUGH THE FULL CHAIN
// ============================================================================

/// `encrypt -> mul(ct x ct) -> mul_plain -> exact-divide -> decrypt`, with the
/// basis fingerprint asserted byte-identical at EVERY step.
///
/// `basis_invariance.rs` covers the division step. The step that used to break
/// this — and the reason a depth budget existed at all — is the multiply:
/// classical BFV `rescale` fuses "divide by delta" with "drop a lane", so
/// every ct x ct product returned a shorter chain. Step 4 of `mul_dual_public`
/// now divides by delta via K-Elimination and the Step-5 lane drop is retired,
/// so the product occupies the same chain as its inputs.
#[test]
fn full_chain_encrypt_mul_divide_decrypt_leaves_the_basis_byte_identical() {
    let cfg = SecureConfig::secure_128();
    let (ctx, keys) = ctx_and_keys(&cfg, 42);

    let (a, b, d) = (6u64, 7u64, 97u64);
    let ab = a * b;
    assert!(
        d * ab < ctx.t,
        "test setup: d*a*b must stay below t so the scaled ciphertext does not wrap mod Q"
    );

    let ct_a = encrypt(&ctx, &keys, a, 7);
    let ct_b = encrypt(&ctx, &keys, b, 13);

    let trace = BasisTrace::start("full_chain/secure_128", &ctx, &ct_a);
    trace.check("encrypt(a)", &ctx, &ct_a);
    trace.check("encrypt(b)", &ctx, &ct_b);

    // --- ct x ct multiply: the step that used to consume a lane ---
    let ct_ab = ctx
        .mul_dual_public(&ct_a, &ct_b, &keys.eval_key)
        .expect("mul_dual_public must succeed at depth 1");
    trace.check("mul_dual_public(a,b)", &ctx, &ct_ab);
    assert_eq!(
        ctx.decrypt_dual(&ct_ab, &keys.secret_key),
        ab,
        "the product must decrypt correctly, otherwise basis invariance is vacuous"
    );

    // --- make the value exactly divisible, in the architecture's own way ---
    let ct_scaled = ctx.mul_plain_dual(&ct_ab, d);
    trace.check("mul_plain_dual(*d)", &ctx, &ct_scaled);
    assert_eq!(
        ctx.decrypt_dual(&ct_scaled, &keys.secret_key),
        d * ab,
        "mul_plain_dual must produce Enc(d*a*b)"
    );

    // --- exact division in residue space ---
    let ct_div = exact_divide_dual(&ctx, &ct_scaled, d);
    trace.check("exact_divide_dual(/d)", &ctx, &ct_div);
    assert_eq!(
        ctx.decrypt_dual(&ct_div, &keys.secret_key),
        ab,
        "exact division must return the quotient — value reduced, basis untouched"
    );

    // --- and the decryption boundary itself changed nothing ---
    trace.check("post-decrypt", &ctx, &ct_div);

    // Level is not the fingerprint, but it is the field the retired ladder
    // decremented, so pin it explicitly too.
    assert_eq!(ct_div.level, ct_a.level, "level must not be consumed");
    assert_eq!(
        ct_div.c0.main.len(),
        ctx.config.primes.len(),
        "the ciphertext must still occupy the FULL main chain"
    );
}

/// The other half of "stays in residue space": the REPRESENTATION.
///
/// Basis invariance says the lane set does not move. This says the stored
/// object is a residue and nothing else — every limb entry is canonically
/// reduced below its own lane prime, at every step of the chain, in both
/// components and in both tracks. A step that materialised an integer and
/// wrote it back un-reduced, or that carried a value across lanes, would show
/// up here as an out-of-range residue.
///
/// This passing is necessary, not sufficient: the multiply DOES materialise a
/// 256-bit integer per coefficient internally (see
/// `ct_multiply_is_not_lane_independent_every_lane_moves`), it simply
/// re-reduces before storing. The distinction between "the stored form is
/// residues" and "the computation touched only residues" is exactly the
/// distinction this file exists to make.
#[test]
fn every_stored_limb_is_a_canonically_reduced_residue_through_the_chain() {
    let cfg = SecureConfig::secure_128();
    let (ctx, keys) = ctx_and_keys(&cfg, 42);

    let check = |step: &str, ct: &DualRNSCiphertext| {
        for (which, poly) in [("c0", &ct.c0), ("c1", &ct.c1)] {
            assert_eq!(
                poly.main.len(),
                ctx.config.primes.len(),
                "{step}/{which}: main lane count changed"
            );
            for (i, limb) in poly.main.iter().enumerate() {
                let p = ctx.config.primes[i];
                assert_eq!(
                    limb.len(),
                    ctx.n,
                    "{step}/{which}: main lane {i} wrong width"
                );
                if let Some((k, &bad)) = limb.iter().enumerate().find(|(_, &r)| r >= p) {
                    panic!(
                        "{step}/{which}: main lane {i} (p={p}) holds {bad} at coefficient {k} — \
                         not a residue mod p"
                    );
                }
            }
            for (j, limb) in poly.anchor.iter().enumerate() {
                let a = ctx.dual_rns.anchor.primes[j];
                assert_eq!(
                    limb.len(),
                    ctx.n,
                    "{step}/{which}: anchor lane {j} wrong width"
                );
                if let Some((k, &bad)) = limb.iter().enumerate().find(|(_, &r)| r >= a) {
                    panic!(
                        "{step}/{which}: anchor lane {j} (a={a}) holds {bad} at coefficient {k} — \
                         not a residue mod a"
                    );
                }
            }
        }
    };

    let ct_a = encrypt(&ctx, &keys, 6, 7);
    let ct_b = encrypt(&ctx, &keys, 7, 13);
    check("encrypt(a)", &ct_a);
    check("encrypt(b)", &ct_b);

    let ct_ab = ctx
        .mul_dual_public(&ct_a, &ct_b, &keys.eval_key)
        .expect("multiply");
    check("mul_dual_public", &ct_ab);

    let ct_sum = ctx.add_dual(&ct_ab, &ct_a);
    check("add_dual", &ct_sum);

    let ct_scaled = ctx.mul_plain_dual(&ct_ab, 97);
    check("mul_plain_dual", &ct_scaled);

    let ct_div = exact_divide_dual(&ctx, &ct_scaled, 97);
    check("exact_divide_dual", &ct_div);

    assert_eq!(
        ctx.decrypt_dual(&ct_div, &keys.secret_key),
        42,
        "chain must still be correct, else the residue check above is vacuous"
    );
}

/// The chain form of the same claim. Four chained ct x ct multiplications on
/// `secure_128_deep`; the fingerprint is asserted after each one.
///
/// A level-consuming implementation cannot reach depth 4 from a 4-prime chain:
/// it would be out of lanes. Reaching it with the fingerprint unchanged is the
/// direct evidence that depth is not budget-bounded by the modulus chain.
#[test]
fn basis_is_invariant_across_a_four_deep_multiplication_chain() {
    let cfg = SecureConfig::secure_128_deep();
    let (ctx, keys) = ctx_and_deep_keys(&cfg, 42);

    let mut acc = encrypt(&ctx, &keys, 2, 101);
    let trace = BasisTrace::start("chain/secure_128_deep", &ctx, &acc);
    let mut expected = 2u64;

    for depth in 1..=4u64 {
        let operand = encrypt(&ctx, &keys, 2, 200 + depth);
        trace.check(&format!("fresh operand at depth {depth}"), &ctx, &operand);

        acc = ctx
            .mul_dual_public(&acc, &operand, &keys.eval_key)
            .unwrap_or_else(|e| panic!("mul_dual_public failed at depth {depth}: {e:?}"));
        expected *= 2;

        trace.check(&format!("after multiply at depth {depth}"), &ctx, &acc);
        assert_eq!(
            acc.c0.main.len(),
            ctx.config.primes.len(),
            "depth {depth}: main chain shortened — the ladder is back"
        );
        assert_eq!(
            ctx.decrypt_dual(&acc, &keys.secret_key),
            expected,
            "depth {depth}: value wrong, so the invariance above would be vacuous"
        );
    }
}

/// Depth is not bounded by the BASIS, but it is still bounded by NOISE, and
/// the two are different failures. This test drives `secure_128` past its
/// correctness horizon and asserts the hard part: even past the horizon the
/// basis is byte-identical.
///
/// The horizon itself is REPORTED, not pinned to a number, and that is a
/// deliberate choice backed by measurement rather than a hedge. A 20-seed /
/// 8-seed sweep run while writing this file gives:
///
/// ```text
///   test_medium_insecure   depth 1: 15/20 correct   depth 2:  0/20
///   secure_128             depth 1:  8/8            depth 2:  2/8    depth 3: 0/8
///   secure_128 (2^10 relin) depth 1: 8/8            depth 2:  2/8    depth 3: 0/8
///   secure_128_deep (2^10) depth 1:  6/6   d2: 6/6   d3: 6/6   d4: 6/6
/// ```
///
/// So depth 2 on `secure_128` is a coin flip that depends on the encryption
/// randomness, and depth 1 on `test_medium_insecure` is only ~75% reliable.
/// Pinning "horizon >= 2" here would encode one lucky seed as a contract. The
/// non-vacuity floor asserted instead is `horizon >= 1`: if not even a single
/// ct x ct multiply decrypts correctly, the basis-invariance assertion above
/// it would be measuring nothing.
///
/// Recorded as a separate finding, visible in this test's output: at the
/// depths where the value is wrong, `try_decrypt_dual` frequently still
/// returns `Ok` (5/20 and 4/8 in the sweeps above) — the noise gate misses the
/// failure it exists to catch.
#[test]
fn deep_chain_never_moves_the_basis_and_reports_its_correctness_horizon() {
    let cfg = SecureConfig::secure_128();
    let (ctx, keys) = ctx_and_keys(&cfg, 42);

    let mut acc = encrypt(&ctx, &keys, 2, 500);
    let trace = BasisTrace::start("horizon/secure_128", &ctx, &acc);
    let mut expected = 2u64;
    let mut horizon = 0usize;
    let mut silent_corruption_at: Option<usize> = None;

    for depth in 1..=5usize {
        let operand = encrypt(&ctx, &keys, 2, 600 + depth as u64);
        acc = ctx
            .mul_dual_public(&acc, &operand, &keys.eval_key)
            .unwrap_or_else(|e| panic!("mul_dual_public returned Err at depth {depth}: {e:?}"));
        expected = expected.wrapping_mul(2) % ctx.t;

        // THE ASSERTION. Noise may ruin the value; it may not move the basis.
        trace.check(&format!("depth {depth} (past horizon is fine)"), &ctx, &acc);

        let got = ctx.decrypt_dual(&acc, &keys.secret_key);
        let checked = ctx.try_decrypt_dual(&acc, &keys.secret_key);
        if got == expected {
            horizon = depth;
        } else if silent_corruption_at.is_none() && checked.is_ok() {
            // Wrong plaintext, but the noise gate said Ok. Reported, not pinned.
            silent_corruption_at = Some(depth);
        }
        println!(
            "  secure_128 depth {depth}: lanes={} decrypt={} expected={} try_decrypt={}",
            acc.c0.main.len(),
            got,
            expected,
            if checked.is_ok() { "Ok" } else { "Err" }
        );
    }

    println!("  correctness horizon (secure_128, base 2^16 relin): depth {horizon}");
    if let Some(d) = silent_corruption_at {
        println!(
            "  FINDING: try_decrypt_dual returned Ok for a WRONG plaintext at depth {d} \
             (silent corruption; the noise gate did not fire)"
        );
    }
    assert!(
        horizon >= 1,
        "not even a depth-1 ct x ct multiply decrypted correctly on secure_128 \
         (horizon {horizon}), which would make the basis-invariance assertions in \
         this test vacuous"
    );
}

/// The seed-dependence of the horizon, measured rather than asserted from one
/// sample. Small deterministic sweep so the number in the doc comment above
/// stays honest in CI.
///
/// Hard assertion: depth 1 must be correct on EVERY seed — a single ct x ct
/// multiply is the floor the whole substrate rests on. Depth 2 is reported.
#[test]
fn ct_multiply_reliability_is_measured_not_assumed() {
    let cfg = SecureConfig::secure_128();
    let (ctx, keys) = ctx_and_keys(&cfg, 42);

    const TRIALS: u64 = 4;
    let mut ok = [0u64; 2];
    let mut silent = [0u64; 2];

    for s in 0..TRIALS {
        let mut acc = encrypt(&ctx, &keys, 2, 1000 + s * 37);
        let mut expected = 2u64;
        for d in 0..2usize {
            let operand = encrypt(&ctx, &keys, 2, 9000 + s * 37 + d as u64);
            acc = ctx
                .mul_dual_public(&acc, &operand, &keys.eval_key)
                .expect("multiply must not error");
            expected = expected.wrapping_mul(2) % ctx.t;
            let got = ctx.decrypt_dual(&acc, &keys.secret_key);
            if got == expected {
                ok[d] += 1;
            } else if ctx.try_decrypt_dual(&acc, &keys.secret_key).is_ok() {
                silent[d] += 1;
            }
        }
    }

    for d in 0..2usize {
        println!(
            "  secure_128 depth {}: correct {}/{}  wrong-but-try_decrypt-said-Ok {}",
            d + 1,
            ok[d],
            TRIALS,
            silent[d]
        );
    }

    assert_eq!(
        ok[0], TRIALS,
        "depth-1 ct x ct multiply must be correct on every seed, got {}/{}",
        ok[0], TRIALS
    );
    assert!(
        ok[1] < TRIALS || silent[1] == 0,
        "inconsistent bookkeeping in the sweep"
    );
}

// ============================================================================
// (2) LANE INDEPENDENCE — THE i.i.d. OBSERVABLE
// ============================================================================

fn changed_main_lanes(a: &DualRNSPoly, b: &DualRNSPoly) -> Vec<usize> {
    (0..a.main.len())
        .filter(|&i| a.main[i] != b.main[i])
        .collect()
}

fn changed_anchor_lanes(a: &DualRNSPoly, b: &DualRNSPoly) -> Vec<usize> {
    (0..a.anchor.len())
        .filter(|&i| a.anchor[i] != b.anchor[i])
        .collect()
}

/// Bump one residue in one main lane by +1 mod p. Nothing else moves.
fn perturb_main_lane(
    ctx: &RNSFHEContext,
    ct: &DualRNSCiphertext,
    lane: usize,
) -> DualRNSCiphertext {
    let p = ctx.config.primes[lane];
    let mut out = ct.clone();
    out.c0.main[lane][0] = (out.c0.main[lane][0] + 1) % p;
    out
}

/// The i.i.d. property, in its observable form, on the operations that are
/// genuinely lane-wise: perturbing input lane `i` moves output lane `i` and
/// NOTHING else — no other main lane, no anchor lane.
///
/// This is the positive control. It establishes that the probe below is
/// measuring a real difference between operations, not an artifact of the
/// measurement.
#[test]
fn lanewise_ops_change_only_the_perturbed_lane() {
    let cfg = SecureConfig::test_medium_insecure();
    let (ctx, keys) = ctx_and_keys(&cfg, 42);
    let num_main = ctx.config.primes.len();

    let a = encrypt(&ctx, &keys, 6, 7);
    let b = encrypt(&ctx, &keys, 7, 13);

    // (name, op) — every one of these must be lane-local.
    #[allow(clippy::type_complexity)]
    let ops: Vec<(&str, Box<dyn Fn(&DualRNSCiphertext) -> DualRNSCiphertext>)> = vec![
        (
            "add_dual",
            Box::new(|x: &DualRNSCiphertext| ctx.add_dual(x, &b)),
        ),
        (
            "add_plain_dual",
            Box::new(|x: &DualRNSCiphertext| ctx.add_plain_dual(x, 12345)),
        ),
        (
            "mul_plain_dual",
            Box::new(|x: &DualRNSCiphertext| ctx.mul_plain_dual(x, 97)),
        ),
        (
            "negate_dual",
            Box::new(|x: &DualRNSCiphertext| ctx.negate_dual(x)),
        ),
        (
            "exact_divide_dual",
            Box::new(|x: &DualRNSCiphertext| exact_divide_dual(&ctx, x, 97)),
        ),
    ];

    for (name, op) in &ops {
        let base = op(&a);
        for lane in 0..num_main {
            let perturbed = op(&perturb_main_lane(&ctx, &a, lane));

            let c0_main = changed_main_lanes(&base.c0, &perturbed.c0);
            let c0_anchor = changed_anchor_lanes(&base.c0, &perturbed.c0);
            let c1_main = changed_main_lanes(&base.c1, &perturbed.c1);
            let c1_anchor = changed_anchor_lanes(&base.c1, &perturbed.c1);

            assert_eq!(
                c0_main,
                vec![lane],
                "{name}: perturbing main lane {lane} of c0 moved c0 main lanes {c0_main:?}, \
                 expected only [{lane}]. Lanes that move together are not i.i.d."
            );
            assert!(
                c0_anchor.is_empty(),
                "{name}: perturbing main lane {lane} moved ANCHOR lanes {c0_anchor:?} of c0. \
                 A main-lane perturbation must not reach the anchor track — that is \
                 cross-track coupling."
            );
            assert!(
                c1_main.is_empty() || c1_main == vec![lane],
                "{name}: perturbing c0 main lane {lane} moved c1 main lanes {c1_main:?}"
            );
            assert!(
                c1_anchor.is_empty(),
                "{name}: perturbing c0 main lane {lane} moved c1 anchor lanes {c1_anchor:?}"
            );
        }
    }
}

/// THE DISCRIMINATOR — and it currently FALSIFIES claim (2) for ct x ct
/// multiplication.
///
/// Perturbing a single residue in a single main lane of `c0` moves EVERY main
/// lane and EVERY anchor lane of BOTH output components. The lanes of a
/// `mul_dual_public` result are not i.i.d.; each output lane is a function of
/// all input lanes.
///
/// The cause is not the tensor product (`dual_poly_mul` is per-lane NTT, and
/// `lanewise_ops_change_only_the_perturbed_lane` above shows the lane-wise
/// primitives stay local). It is the two per-coefficient CRT reconstructions
/// inside the multiply:
///
///   * `RNSFHEContext::k_elim_rescale_dual`, `ops/rns_fhe.rs:3304` —
///     `let v_m = self.rns.to_u256_level(&main_residues, ct_level);`
///     `to_u256_level` (`arithmetic/rns.rs:535`) is documented in its own body
///     as "Iterative CRT (Garner-style) in full precision (U256)". Every
///     output residue is then `scaled.mod_u64(p)` (`:3335`) taken of that one
///     materialised integer, so every output lane depends on every input lane.
///     Reached from `mul_dual_public` Step 4 (`:2971-2982`).
///   * `RNSFHEContext::extract_digit_dual`, `ops/rns_fhe.rs:3194` — same
///     reconstruction, then `let exact = v_m.add(k.mul_low(m_product_level))`
///     (`:3204`) materialises the exact 256-bit value and bit-shifts it for
///     the relinearization digits. Reached from `relinearize_dual` (`:3143`),
///     which is `mul_dual_public` Step 2 (`:2954`).
///
/// This test asserts the coupling rather than the independence, on purpose:
/// it is the negative of the claim, in the same spirit as
/// `basis_invariance.rs::mod_switch_ladder_is_the_negative_of_this_invariant`.
/// It pins the current behaviour so the finding cannot be quietly lost, and it
/// will start failing the moment the multiply becomes genuinely lane-local —
/// at which point it should be inverted, not deleted.
#[test]
fn ct_multiply_is_not_lane_independent_every_lane_moves() {
    let cfg = SecureConfig::secure_128();
    let (ctx, keys) = ctx_and_keys(&cfg, 42);
    let num_main = ctx.config.primes.len();
    let num_anchor = ctx.dual_rns.anchor.primes.len();

    let a = encrypt(&ctx, &keys, 6, 7);
    let b = encrypt(&ctx, &keys, 7, 13);
    let base = ctx
        .mul_dual_public(&a, &b, &keys.eval_key)
        .expect("baseline multiply");

    let all_main: Vec<usize> = (0..num_main).collect();
    let all_anchor: Vec<usize> = (0..num_anchor).collect();

    for lane in 0..num_main {
        let perturbed = ctx
            .mul_dual_public(&perturb_main_lane(&ctx, &a, lane), &b, &keys.eval_key)
            .expect("perturbed multiply");

        let c0_main = changed_main_lanes(&base.c0, &perturbed.c0);
        let c0_anchor = changed_anchor_lanes(&base.c0, &perturbed.c0);
        let c1_main = changed_main_lanes(&base.c1, &perturbed.c1);
        let c1_anchor = changed_anchor_lanes(&base.c1, &perturbed.c1);

        println!(
            "  perturb c0 main lane {lane}: c0 main {c0_main:?} anchor {c0_anchor:?} | \
             c1 main {c1_main:?} anchor {c1_anchor:?}"
        );

        assert_ne!(
            c0_main,
            vec![lane],
            "mul_dual_public unexpectedly became lane-local for lane {lane}. \
             If the per-coefficient CRT reconstructions at ops/rns_fhe.rs:3304 and \
             :3194 have been removed, INVERT this test into a lane-independence \
             assertion — do not delete it."
        );
        assert_eq!(
            c0_main, all_main,
            "expected the reconstruction to couple every main lane of c0"
        );
        assert_eq!(
            c0_anchor, all_anchor,
            "expected the reconstruction to couple every anchor lane of c0"
        );
        assert_eq!(
            c1_main, all_main,
            "expected the reconstruction to couple every main lane of c1"
        );
        assert_eq!(
            c1_anchor, all_anchor,
            "expected the reconstruction to couple every anchor lane of c1"
        );
    }
}

// ============================================================================
// (3) ORDER INVARIANCE
//
// Permuting the lane order must permute the answer and change nothing else.
// The whole context is rebuilt on the permuted chain and ALL key material is
// permuted with it, so the two runs differ in lane order and in nothing else.
// ============================================================================

fn perm_vec<T: Clone>(v: &[T], perm: &[usize]) -> Vec<T> {
    perm.iter().map(|&i| v[i].clone()).collect()
}

fn perm_poly(p: &DualRNSPoly, perm: &[usize]) -> DualRNSPoly {
    DualRNSPoly {
        main: perm_vec(&p.main, perm),
        anchor: p.anchor.clone(), // the anchor basis is a function of n only
        n: p.n,
    }
}

fn perm_ct(c: &DualRNSCiphertext, perm: &[usize]) -> DualRNSCiphertext {
    DualRNSCiphertext {
        c0: perm_poly(&c.c0, perm),
        c1: perm_poly(&c.c1, perm),
        level: c.level,
    }
}

fn perm_cfg(c: &FHEConfig, perm: &[usize]) -> FHEConfig {
    let primes = perm_vec(&c.primes, perm);
    let q = primes[0];
    FHEConfig {
        primes,
        q,
        ..c.clone()
    }
}

fn perm_keys(k: &DualRNSFullKeySet, perm: &[usize]) -> DualRNSFullKeySet {
    DualRNSFullKeySet {
        secret_key: DualRNSSecretKey {
            s: perm_poly(&k.secret_key.s, perm),
        },
        public_key: DualRNSPublicKey {
            pk0: perm_poly(&k.public_key.pk0, perm),
            pk1: perm_poly(&k.public_key.pk1, perm),
        },
        eval_key: DualRNSEvalKey {
            rlk: k
                .eval_key
                .rlk
                .iter()
                .map(|(x, y)| (perm_poly(x, perm), perm_poly(y, perm)))
                .collect(),
            decomp_base: k.eval_key.decomp_base,
            num_digits: k.eval_key.num_digits,
        },
    }
}

fn assert_ct_eq(label: &str, expected: &DualRNSCiphertext, got: &DualRNSCiphertext) {
    assert_eq!(
        expected.c0.main, got.c0.main,
        "{label}: c0 main residues differ under lane permutation"
    );
    assert_eq!(
        expected.c0.anchor, got.c0.anchor,
        "{label}: c0 anchor residues differ under lane permutation"
    );
    assert_eq!(
        expected.c1.main, got.c1.main,
        "{label}: c1 main residues differ under lane permutation"
    );
    assert_eq!(
        expected.c1.anchor, got.c1.anchor,
        "{label}: c1 anchor residues differ under lane permutation"
    );
    assert_eq!(expected.level, got.level, "{label}: level differs");
}

/// Positive control: the residue-native exact division commutes with a lane
/// permutation, bit for bit. Per-lane reads cannot do anything else.
#[test]
fn exact_division_is_order_equivariant() {
    let cfg = SecureConfig::secure_128().config;
    let perm: Vec<usize> = (0..cfg.primes.len()).rev().collect();
    let cfg_rev = perm_cfg(&cfg, &perm);

    let ctx_f = RNSFHEContext::new(&cfg);
    let ctx_r = RNSFHEContext::new(&cfg_rev);

    let mut rng = ShadowHarvester::with_seed(42);
    let keys_f = ctx_f.generate_keys_dual_full(&mut rng);
    let ct_f = encrypt(&ctx_f, &keys_f, 6, 7);
    let ct_r = perm_ct(&ct_f, &perm);

    for &d in &[2u64, 3, 97, 65521] {
        let out_f = exact_divide_dual(&ctx_f, &ct_f, d);
        let out_r = exact_divide_dual(&ctx_r, &ct_r, d);
        assert_ct_eq(
            &format!("exact_divide by {d}"),
            &perm_ct(&out_f, &perm),
            &out_r,
        );
    }
}

/// The A2 probe on the real ciphertext path. Both contexts hold the same
/// modulus set in different orders; the ciphertext, secret key, public key and
/// evaluation key are permuted to match. The multiply output must be the exact
/// permutation of the unpermuted output, and both must decrypt to the same
/// plaintext.
///
/// READ THIS RESULT CAREFULLY. Passing rules out an order-SENSITIVE cascade
/// (a truncated or lossy mixed-radix chain), which is what
/// `a2_residue_native.rs` was built to catch. It does NOT rule out
/// reconstruction: Garner's algorithm on a coprime basis returns the same
/// integer in any visitation order, so the exact CRT at
/// `ops/rns_fhe.rs:3304` passes this probe too. The test that actually
/// separates the two is `ct_multiply_is_not_lane_independent_every_lane_moves`.
/// `correctness_anchor` marks the cases where a depth-1 ct x ct multiply is
/// reliably correct, so `42` can be asserted as the non-vacuity guard.
/// `test_medium_insecure` is NOT such a case — its own depth-1 multiply is
/// only ~75% reliable (15/20 in the sweep recorded on
/// `deep_chain_never_moves_the_basis_and_reports_its_correctness_horizon`), so
/// asserting `== 42` there would be asserting a coin flip. It is kept in the
/// sweep because order-equivariance is a dataflow property that a noisy
/// ciphertext exercises just as well: the two runs must still agree bit for
/// bit and decrypt to the same (possibly wrong) value.
#[test]
fn ct_multiply_is_order_equivariant_bit_exact() {
    for (name, cfg_src, perm, correctness_anchor) in [
        (
            "test_medium_insecure/reverse",
            SecureConfig::test_medium_insecure().config,
            vec![1usize, 0],
            false,
        ),
        (
            "secure_128/reverse",
            SecureConfig::secure_128().config,
            vec![2usize, 1, 0],
            true,
        ),
        (
            "secure_128/rotate",
            SecureConfig::secure_128().config,
            vec![1usize, 2, 0],
            true,
        ),
        (
            "secure_128_deep/reverse",
            SecureConfig::secure_128_deep().config,
            vec![3usize, 2, 1, 0],
            true,
        ),
    ] {
        let cfg_perm = perm_cfg(&cfg_src, &perm);
        let ctx_f = RNSFHEContext::new(&cfg_src);
        let ctx_p = RNSFHEContext::new(&cfg_perm);

        let mut rng = ShadowHarvester::with_seed(42);
        let keys_f = ctx_f.generate_keys_dual_full(&mut rng);
        let keys_p = perm_keys(&keys_f, &perm);

        let a_f = encrypt(&ctx_f, &keys_f, 6, 7);
        let b_f = encrypt(&ctx_f, &keys_f, 7, 13);
        let (a_p, b_p) = (perm_ct(&a_f, &perm), perm_ct(&b_f, &perm));

        // Encryption itself must be order-equivariant, or the comparison below
        // would be measuring the encryptor rather than the multiply.
        let a_p_native = {
            let mut r = ShadowHarvester::with_seed(7);
            ctx_p.encrypt_dual(6, &keys_p.public_key, &mut r)
        };
        assert_ct_eq(&format!("{name}: encrypt"), &a_p, &a_p_native);

        let out_f = ctx_f
            .mul_dual_public(&a_f, &b_f, &keys_f.eval_key)
            .expect("forward multiply");
        let out_p = ctx_p
            .mul_dual_public(&a_p, &b_p, &keys_p.eval_key)
            .expect("permuted multiply");

        assert_ct_eq(
            &format!("{name}: mul_dual_public"),
            &perm_ct(&out_f, &perm),
            &out_p,
        );

        let dec_f = ctx_f.decrypt_dual(&out_f, &keys_f.secret_key);
        let dec_p = ctx_p.decrypt_dual(&out_p, &keys_p.secret_key);
        if correctness_anchor {
            assert_eq!(dec_f, 42, "{name}: forward product must decrypt to 42");
        } else {
            println!("  {name}: forward product decrypts to {dec_f} (noise-marginal config, not anchored)");
        }
        assert_eq!(
            dec_p, dec_f,
            "{name}: lane order changed the decrypted result (cascade!)"
        );

        // And the whole chain, not just the multiply.
        let scaled_f = ctx_f.mul_plain_dual(&out_f, 97);
        let scaled_p = ctx_p.mul_plain_dual(&out_p, 97);
        let div_f = exact_divide_dual(&ctx_f, &scaled_f, 97);
        let div_p = exact_divide_dual(&ctx_p, &scaled_p, 97);
        assert_ct_eq(
            &format!("{name}: mul_plain + exact_divide"),
            &perm_ct(&div_f, &perm),
            &div_p,
        );
        assert_eq!(
            ctx_p.decrypt_dual(&div_p, &keys_p.secret_key),
            ctx_f.decrypt_dual(&div_f, &keys_f.secret_key),
            "{name}: lane order changed the end-to-end result"
        );
    }
}
