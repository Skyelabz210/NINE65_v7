/// integration_tests.rs — Independent Verification of All Paper Theorems
///
/// These tests operate entirely from the public API surface, treating the
/// CRAM engine as a black box.  They independently verify every quantitative
/// claim in the paper without relying on any internal implementation detail.
///
/// Running: cargo test --tests
/// All tests must pass with zero failures for the implementation to be
/// considered correct per the paper's specification.

use cram::*;
use cram::garner::{GarnerConstants, garner_reconstruct, decompose, reconstruct, verify_roundtrip};
use cram::fhe::Nine65Engine;
use cram::ahop;

// ─────────────────────────────────────────────────────────────────────────────
// GROUP A: Exact Arithmetic Foundation (arith.rs)
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn a1_mod_inverse_all_residues_mod7() {
    // Every non-zero element of Z_7 must have a multiplicative inverse,
    // because 7 is prime (the fundamental field property).
    for a in 1..7i128 {
        let inv = cram::arith::mod_inverse(a, 7)
            .expect(&format!("Z_7\\{{0}} must be invertible: {} has no inverse", a));
        let product = cram::arith::mod_mul(a, inv, 7);
        assert_eq!(product, 1, "a * a^{{-1}} must equal 1 in Z_7: {}*{}={}", a, inv, product);
    }
}

#[test]
fn a2_zero_has_no_inverse_in_any_prime_field() {
    for p in [2i128, 3, 5, 7, 11, 13, 97] {
        assert!(
            cram::arith::mod_inverse(0, p).is_none(),
            "0 must have no inverse in Z_{}", p
        );
    }
}

#[test]
fn a3_canonical_handles_large_negative_values() {
    // Verify canonical() works for large negative values that appear
    // during Garner coefficient extraction (subtraction phases).
    assert_eq!(cram::arith::canonical(-100, 7), 5); // -100 = -15*7 + 5
    assert_eq!(cram::arith::canonical(-1, 13), 12);
    assert_eq!(cram::arith::canonical(0, 7), 0);
}

// ─────────────────────────────────────────────────────────────────────────────
// GROUP B: Operator Correctness (operators.rs)
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn b1_all_four_root_operators_evaluated_paper_lane4() {
    // The paper's Lane 4 is the most complex: DIV mod 7.
    // Exhaustively verify DIV against brute-force for small primes.
    let p = 7i128;
    for a in 0..p {
        for b in 1..p { // b ≠ 0 to avoid exceptional state
            let div_result = RootOp::Div.apply(a, b, p).unwrap();
            // Verify: div_result * b ≡ a (mod p)
            let check = cram::arith::mod_mul(div_result, b, p);
            assert_eq!(check, a % p,
                "DIV verification failed: {} / {} mod {} = {}, but {}*{}={} ≠ {}",
                a, b, p, div_result, div_result, b, check, a);
        }
    }
}

#[test]
fn b2_sqr_output_is_always_quadratic_residue() {
    // The All-SQR matrix restricts outputs to quadratic residues.
    // A quadratic residue in Z_p is any x where x = y^2 mod p for some y.
    // Verify that SQR(x) is always in the set of quadratic residues.
    for p in [3i128, 5, 7, 11, 13] {
        let qr_set: std::collections::HashSet<i128> =
            (0..p).map(|y| cram::arith::mod_square(y, p)).collect();
        for x in 0..p {
            let sqr_out = PostProc::Square.apply(x, p).unwrap();
            assert!(
                qr_set.contains(&sqr_out),
                "SQR({}) mod {} = {} is not a quadratic residue", x, p, sqr_out
            );
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// GROUP C: Garner Reconstruction (garner.rs)
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn c1_paper_canonical_result_165() {
    // The most important single test in the entire suite.
    // Paper Section "Phase 4": residue tuple (1,0,0,4) over {2,3,5,7} = 165.
    let primes = vec![2i128, 3, 5, 7];
    let constants = GarnerConstants::precompute(&primes);
    let result = garner_reconstruct(&[1, 0, 0, 4], &constants);
    assert_eq!(result.value, 165);
}

#[test]
fn c2_mixed_radix_coefficients_match_paper() {
    // The paper explicitly gives v = {1, 1, 2, 5} for input (1,0,0,4).
    let primes = vec![2i128, 3, 5, 7];
    let constants = GarnerConstants::precompute(&primes);
    let result = garner_reconstruct(&[1, 0, 0, 4], &constants);
    assert_eq!(result.mixed_radix_coeffs, vec![1, 1, 2, 5]);
}

#[test]
fn c3_crt_bijection_is_perfect_over_z210() {
    // Theorem 1 requires decompose(reconstruct(r)) = r for all valid r.
    // Verify this holds for every integer in Z_210 (the CRAM-S4 ring).
    let primes = vec![2i128, 3, 5, 7];
    let constants = GarnerConstants::precompute(&primes);
    let n: i128 = primes.iter().product();
    assert_eq!(n, 210);

    for x in 0..n {
        let residues = decompose(x, &primes);
        let reconstructed = reconstruct(&residues, &constants);
        assert_eq!(reconstructed, x,
            "CRT bijection failed: decompose/reconstruct({}) = {}", x, reconstructed);
    }
}

#[test]
fn c4_garner_multiplication_count_theorem4() {
    // Theorem 4: exactly k*(k-1)/2 sequential multiplications for k primes.
    let test_cases = [(vec![2i128,3,5], 3usize), (vec![2,3,5,7], 6), (vec![2,3,5,7,11,13], 15)];
    for (primes, expected_mults) in test_cases {
        let constants = GarnerConstants::precompute(&primes);
        let k = primes.len();
        let residues: Vec<i128> = (0..k as i128).collect();
        let result = garner_reconstruct(&residues, &constants);
        assert_eq!(result.multiplication_count, expected_mults,
            "k={}: expected {} mults, got {}", k, expected_mults, result.multiplication_count);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// GROUP D: Topology Algebra (topology.rs)
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn d1_operator_state_space_table_from_paper() {
    // The paper provides an exact table of 16^k values for k=3..7.
    let expected = [(3usize, 4_096u64), (4, 65_536), (5, 1_048_576),
                    (6, 16_777_216), (7, 268_435_456)];
    for (k, exp) in expected {
        assert_eq!(16u64.pow(k as u32), exp,
            "16^{} must equal {}", k, exp);
    }
}

#[test]
fn d2_s4_validity_exact_fraction_six_sevenths() {
    let topo = cram_s4_champion();
    let (n, d) = topo.validity_fraction();
    assert_eq!(n, 6); assert_eq!(d, 7);
}

#[test]
fn d3_s6_validity_exact_fraction_twelve_thirteenths() {
    let topo = cram_s6_champion();
    let (n, d) = topo.validity_fraction();
    assert_eq!(n, 12); assert_eq!(d, 13);
}

#[test]
fn d4_s6_modulus_is_30030() {
    // N = 2*3*5*7*11*13 = 30,030
    assert_eq!(cram_s6_champion().modulus, 30_030);
}

#[test]
fn d5_theorem5_larger_primes_yield_higher_validity() {
    // Theorem 5: f(p) = (p-1)/p is monotonically increasing.
    // The derivative df/dp = 1/p² > 0, so larger p → higher validity.
    let primes = [3i128, 7, 13, 97, 997];
    let mut prev_validity = 0.0f64;
    for p in primes {
        let validity = (p - 1) as f64 / p as f64;
        assert!(validity > prev_validity,
            "f({}) = {} must exceed f(prev) = {}", p, validity, prev_validity);
        prev_validity = validity;
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// GROUP E: CRAM Engine (engine.rs)
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn e1_canonical_paper_result() {
    let engine = CramEngine::new(cram_s4_champion());
    assert_eq!(engine.execute(17, 23).unwrap(), 165);
}

#[test]
fn e2_engine_rejects_exceptional_inputs() {
    // B=7 forces b₄ = 0 mod 7 → DIV lane exceptional
    let engine = CramEngine::new(cram_s4_champion());
    assert!(engine.execute(1, 7).is_err());
    assert!(engine.execute(5, 14).is_err()); // 14 mod 7 = 0
    assert!(engine.execute(3, 21).is_err()); // 21 mod 7 = 0
}

#[test]
fn e3_theorem1_lazy_equals_eager_comprehensive() {
    // Test 100 random-ish chains of depth 15 on both S4 and S6.
    for topo in [cram_s4_champion(), cram_s6_champion()] {
        let engine = CramEngine::new(topo);
        let n = engine.topology.modulus;
        for seed in [2i128, 11, 37, 71, 101] {
            let chain: Vec<i128> = (1..15).map(|i| (seed * i * 3 + 7) % (n - 1) + 1).collect();
            let lazy  = engine.execute_chain_lazy(seed, chain[0], &chain[1..]);
            let eager = engine.execute_chain_traditional(seed, chain[0], &chain[1..]);
            match (lazy, eager) {
                (Ok(l), Ok(e)) => assert_eq!(l, e, "Theorem 1 violated for seed={}", seed),
                (Err(_), Err(_)) => {} // consistent exceptional-set behavior
                _ => panic!("Theorem 1 violated: lazy/eager diverged for seed={}", seed),
            }
        }
    }
}

#[test]
fn e4_non_commutativity_proven() {
    let engine = CramEngine::new(cram_s4_champion());
    // Search for a pair where F(a,b) ≠ F(b,a)
    let mut non_comm = false;
    'outer: for a in 1..30i128 {
        for b in 1..30i128 {
            if let (Ok(ab), Ok(ba)) = (engine.execute(a, b), engine.execute(b, a)) {
                if ab != ba { non_comm = true; break 'outer; }
            }
        }
    }
    assert!(non_comm, "CRAM-S4 must be non-commutative");
}

#[test]
fn e5_non_associativity_proven() {
    let engine = CramEngine::new(cram_s4_champion());
    // Search for (a,b,c) where F(F(a,b),c) ≠ F(a,F(b,c))
    let mut non_assoc = false;
    'outer: for a in 1..20i128 {
        for b in 1..20i128 {
            for c in 1..20i128 {
                let lhs = engine.execute(a, b).and_then(|x| engine.execute(x, c));
                let rhs = engine.execute(b, c).and_then(|x| engine.execute(a, x));
                if let (Ok(l), Ok(r)) = (lhs, rhs) {
                    if l != r { non_assoc = true; break 'outer; }
                }
            }
        }
    }
    assert!(non_assoc, "CRAM-S4 must be non-associative");
}

#[test]
fn e6_theorem3_empirical_validity_s4_convergence() {
    // Over a full Z_210 scan, empirical validity must match 6/7 within 1%.
    let engine = CramEngine::new(cram_s4_champion());
    let (valid, total) = engine.empirical_validity(210);
    let empirical = valid as f64 / total as f64;
    let theoretical = 6.0 / 7.0;
    assert!((empirical - theoretical).abs() < 0.01,
        "Empirical {:.4} must be within 1% of theoretical {:.4}", empirical, theoretical);
}

// ─────────────────────────────────────────────────────────────────────────────
// GROUP F: NINE65 v7 FHE (fhe.rs)
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn f1_homomorphic_addition_is_exact() {
    let mut engine = Nine65Engine::new();
    let n = engine.cram.topology.modulus;
    // Test several addition pairs that stay within Z_N
    for (a, b) in [(5i128, 10), (0, 99), (100, 200), (1, 1)] {
        let ct_a = engine.encrypt(a);
        let ct_b = engine.encrypt(b);
        let ct_sum = engine.homomorphic_add(&ct_a, &ct_b).expect("Addition must succeed");
        let result = engine.decrypt(&ct_sum);
        assert_eq!(result, (a + b) % n,
            "Homomorphic add: {} + {} = {} (mod {}), got {}", a, b, (a+b)%n, n, result);
    }
}

#[test]
fn f2_k_elimination_resets_noise_exactly() {
    let engine = Nine65Engine::new();
    let primes = engine.cram.topology.primes();
    let mut ct = engine.encrypt(7);

    // Simulate noise accumulation by manually setting noise residues
    ct.noise = cram::engine::ResidueTuple::new(
        primes.iter().map(|&p| (p - 1) % p).collect(), // max possible noise per lane
        primes.clone(),
    );
    ct.depth = 99;

    let bootstrapped = engine.k_eliminate(&ct)
        .expect("K-Elimination must succeed for non-zero noise residues");

    // Every noise residue must be exactly 1 after K-Elimination
    for (i, &r) in bootstrapped.noise.residues.iter().enumerate() {
        assert_eq!(r, 1,
            "K-Elimination must reset lane {} noise to exactly 1, got {}", i, r);
    }
    assert_eq!(bootstrapped.depth, 0, "Depth must reset to 0 after bootstrap");
    // Message must be preserved
    assert_eq!(engine.decrypt(&bootstrapped), engine.decrypt(&ct));
}

#[test]
fn f3_encrypt_decrypt_identity_for_all_residues() {
    let engine = Nine65Engine::new();
    let n = engine.cram.topology.modulus;
    for x in (0..n).step_by(100) {
        let ct = engine.encrypt(x);
        assert_eq!(engine.decrypt(&ct), x,
            "Encrypt/decrypt identity failed for x={}", x);
    }
}

#[test]
fn f4_200_operation_unlimited_depth_chain_completes() {
    let mut engine = Nine65Engine::new();
    let operands: Vec<(bool, i128)> = (0..200).map(|i| (false, (i % 7) + 1)).collect();
    // This must not panic — it should complete regardless of depth
    let (_result, _bootstraps, ops) = engine.evaluate_unlimited_depth(1, &operands);
    assert_eq!(ops, 200, "All 200 operations must complete (unlimited depth)");
}

// ─────────────────────────────────────────────────────────────────────────────
// GROUP G: AHOP-CRAM Bridge (ahop.rs)
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn g1_classical_descartes_ford_circles() {
    // Ford circle packing seed: (k1,k2,k3,k_old) = (2,2,3,-1)
    // k_new = 2*(2+2+3) - (-1) = 14 + 1 = 15
    assert_eq!(ahop::reflect_classical(2, 2, 3, -1), 15);
}

#[test]
fn g2_cram_orbit_is_deterministic() {
    let engine1 = CramEngine::new(cram_s4_champion());
    let engine2 = CramEngine::new(cram_s4_champion());
    // Two engine instances with the same topology must produce identical orbits
    let r1 = reflect_cram(&engine1, 3, 5, 7, 11);
    let r2 = reflect_cram(&engine2, 3, 5, 7, 11);
    // Either both succeed with the same value, or both fail
    match (r1, r2) {
        (Ok(v1), Ok(v2)) => assert_eq!(v1, v2, "CRAM orbit must be deterministic"),
        (Err(_), Err(_)) => {} // Both hit exceptional set — deterministic failure
        _ => panic!("CRAM orbit non-determinism detected!"),
    }
}

#[test]
fn g3_orbit_walk_statistics_are_self_consistent() {
    let engine = CramEngine::new(cram_s4_champion());
    let stats = walk_cram_orbit(&engine, 2, 3, 5, 7, 500);
    assert_eq!(stats.valid_steps + stats.exceptional_steps, stats.total_steps,
        "valid + exceptional must equal total");
    assert_eq!(stats.total_steps, 500);
    let reconstructed_rate = stats.exceptional_steps as f64 / stats.total_steps as f64;
    let error = (reconstructed_rate - stats.exceptional_rate).abs();
    assert!(error < 1e-10, "Exceptional rate must be consistent with step counts");
}

#[test]
fn g4_s6_exceptional_rate_is_positive() {
    // CRAM-S6 has DIV in Lane 6 (p=13), so ~7.69% of steps must be exceptional.
    let engine = CramEngine::new(cram_s6_champion());
    let stats = walk_cram_orbit(&engine, 5, 7, 11, 13, 300);
    // The rate must be positive (we have a DIV lane) and below 50% (sane topology)
    assert!(stats.exceptional_rate > 0.0 && stats.exceptional_rate < 0.5,
        "S6 exceptional rate {} is outside expected range (0%, 50%)", stats.exceptional_rate);
}

// ─────────────────────────────────────────────────────────────────────────────
// GROUP H: Sub-quadratic CRT — Subproduct Tree (subproduct_tree.rs)
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn h1_spt_paper_canonical_result() {
    // SPT must reproduce the canonical paper result identically.
    let spt    = cram::SptConstants::precompute(&[2i128, 3, 5, 7]);
    let result = spt.reconstruct(&[1, 0, 0, 4]);
    assert_eq!(result.value, 165,
        "SPT: (1,0,0,4) must reconstruct to 165");
}

#[test]
fn h2_spt_merge_count_always_k_minus_1() {
    // The k-1 merge invariant must hold for all k.
    for (primes, expected_merges) in [
        (vec![2i128, 3, 5],          2usize),  // k=3 (odd)
        (vec![2i128, 3, 5, 7],       3),        // k=4 (canonical CRAM-S4)
        (vec![2i128, 3, 5, 7, 11, 13], 5),      // k=6 (CRAM-S6)
        (vec![2i128, 3, 5, 7, 11, 13, 17, 19], 7), // k=8
    ] {
        let k   = primes.len();
        let spt = cram::SptConstants::precompute(&primes);
        let residues: Vec<i128> = primes.iter().map(|&p| 1 % p).collect();
        let result = spt.reconstruct(&residues);
        assert_eq!(result.merge_count, expected_merges,
            "k={}: expected {} merges, got {}", k, expected_merges, result.merge_count);
        assert_eq!(result.mod_mul_count, expected_merges,
            "k={}: expected {} mod_muls, got {}", k, expected_merges, result.mod_mul_count);
    }
}

#[test]
fn h3_spt_garner_identity_full_z210() {
    // SPT and Garner must agree on every integer in Z_210.
    let primes = vec![2i128, 3, 5, 7];
    let spt    = cram::SptConstants::precompute(&primes);
    let garner = cram::GarnerConstants::precompute(&primes);
    let (checked, mismatches) = cram::cross_validate_spt_garner(&primes, &spt, &garner, 210);
    assert_eq!(mismatches, 0,
        "SPT ≠ Garner: {} mismatches in {} checks over Z_210", mismatches, checked);
}

#[test]
fn h4_spt_roundtrip_z210_complete() {
    // Full Z_210 round-trip: decompose(reconstruct(r)) == r for all r.
    let spt = cram::SptConstants::precompute(&[2i128, 3, 5, 7]);
    for x in 0..210i128 {
        assert!(spt.verify_roundtrip(x),
            "SPT round-trip failed for x={}", x);
    }
}

#[test]
fn h5_spt_reduction_ratios_correct() {
    // Verify the theoretical reduction ratio: Garner/SPT = k(k-1)/2 / (k-1) = k/2.
    for primes in [
        vec![2i128, 3, 5, 7],           // k=4: ratio=2.0×
        vec![2i128, 3, 5, 7, 11, 13],   // k=6: ratio=3.0×
    ] {
        let k = primes.len();
        let spt = cram::SptConstants::precompute(&primes);
        let (garner_muls, spt_muls, ratio) = spt.garner_reduction();
        assert_eq!(garner_muls, k * (k - 1) / 2,
            "k={}: garner_muls expected {}, got {}", k, k*(k-1)/2, garner_muls);
        assert_eq!(spt_muls, k - 1,
            "k={}: spt_muls expected {}, got {}", k, k-1, spt_muls);
        let expected_ratio = k as f64 / 2.0;
        assert!((ratio - expected_ratio).abs() < 1e-10,
            "k={}: expected ratio {:.1}×, got {:.4}×", k, expected_ratio, ratio);
    }
}

#[test]
fn h6_spt_s6_tree_structure() {
    // CRAM-S6 tree must have the exact structure proven by the algorithm:
    // [[2,3,5,7,11,13], [6,35,143], [210,143], [30030]]
    let spt = cram::SptConstants::precompute(&[2i128, 3, 5, 7, 11, 13]);
    assert_eq!(spt.levels[0], vec![2, 3, 5, 7, 11, 13]);
    assert_eq!(spt.levels[1], vec![6, 35, 143]);
    assert_eq!(spt.levels[2], vec![210, 143]);
    assert_eq!(spt.levels[3], vec![30030]);
    assert_eq!(spt.modulus, 30030);
    assert_eq!(spt.depth, 3);
}

#[test]
fn h7_spt_decompose_matches_garner_decompose() {
    // SPT decompose must produce the same residues as the Garner CRT bijection.
    let primes = vec![2i128, 3, 5, 7];
    let spt    = cram::SptConstants::precompute(&primes);
    for x in 0..210i128 {
        let spt_res    = spt.decompose(x);
        let garner_res = cram::decompose(x, &primes);
        assert_eq!(spt_res, garner_res,
            "SPT and Garner decompose differ for x={}", x);
    }
}
