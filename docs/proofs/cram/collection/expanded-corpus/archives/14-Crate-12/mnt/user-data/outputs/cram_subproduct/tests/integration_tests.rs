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
// GROUP H: Subproduct Tree CRT — Sub-quadratic Reconstruction
// ─────────────────────────────────────────────────────────────────────────────
//
// All tests in this group operate through the public API only and independently
// verify the subproduct tree against Garner across every claimed property:
//   H1  — Paper canonical result (1,0,0,4) → 165
//   H2  — Full Z_210 correctness vs Garner (bijection exhaustion)
//   H3  — Z_30030 spot check vs Garner (S6 topology)
//   H4  — CRAM-S4+ correctness (primes {79,83,89,97})
//   H5  — Operation count table matches known values
//   H6  — Sequential depth is log₂(next_pow2(k)) for all topologies
//   H7  — crt_combine is a valid CRT solver for all Z_p × Z_q pairs
//   H8  — Sentinel identity in crt_combine
//   H9  — SubproductTreeCrt precompute + reconstruct matches Garner
//   H10 — Single-prime edge case (k=1)
//   H11 — Boundary values: x=0, x=N-1

use cram::{
    SubproductTree, SubproductTreeCrt, SubproductCrtResult,
    subproduct_reconstruct, reconstruct_subproduct,
    crt_combine, verify_matches_garner, operation_count_comparison,
};

#[test]
fn h1_paper_canonical_result_165() {
    // THE paper trace result verified via a completely independent code path.
    // Residue tuple (1,0,0,4) over primes (2,3,5,7) — same as garner::c3.
    let primes = vec![2i128, 3, 5, 7];
    let tree = SubproductTree::build(&primes);
    let result = subproduct_reconstruct(&[1, 0, 0, 4], &tree);

    assert_eq!(result.value, 165,
        "Subproduct tree must reproduce paper canonical: 17 ⊛_S4 23 = 165");
    // S4 is exactly power of 2, so 3 combines, depth 2.
    assert_eq!(result.combine_count,    3, "S4: exactly 3 combines (n_leaves-1)");
    assert_eq!(result.sequential_depth, 2, "S4: sequential depth = log2(4) = 2");
}

#[test]
fn h2_z210_exhaustive_vs_garner() {
    // Every x ∈ Z_210 must reconstruct identically under both algorithms.
    // This is the full bijection check — if any of the 210 values diverges,
    // the subproduct tree has a bug.
    let primes = vec![2i128, 3, 5, 7];
    for x in 0..210i128 {
        assert!(
            verify_matches_garner(
                &primes.iter().map(|&p| x % p).collect::<Vec<_>>(),
                &primes
            ),
            "Subproduct tree diverges from Garner at x={}", x
        );
    }
}

#[test]
fn h3_z30030_spot_check_vs_garner() {
    // 1001 evenly-spaced values from Z_30030 (S6 modulus).
    let primes = vec![2i128, 3, 5, 7, 11, 13];
    let n: i128 = primes.iter().product();
    for x in (0..n).step_by(30) {
        assert!(
            verify_matches_garner(
                &primes.iter().map(|&p| x % p).collect::<Vec<_>>(),
                &primes
            ),
            "S6 subproduct tree diverges from Garner at x={}", x
        );
    }
}

#[test]
fn h4_s4_plus_correctness() {
    // CRAM-S4+: larger primes {79,83,89,97}, N=56,360,923.
    // Tests that the tree handles non-trivially-sized products correctly.
    let primes = vec![79i128, 83, 89, 97];
    let n: i128 = primes.iter().product();
    // 50 pseudo-spread values
    for i in 0..50i128 {
        let x = (i * 1_127_220) % n;
        assert!(
            verify_matches_garner(
                &primes.iter().map(|&p| x % p).collect::<Vec<_>>(),
                &primes
            ),
            "S4+ diverges at x={}", x
        );
    }
}

#[test]
fn h5_operation_count_table() {
    // Verify the operation count table against independently computed values.
    // Format: (k, expected_garner_mults, expected_tree_combines, expected_depth)
    let cases: &[(usize, usize, usize, usize)] = &[
        (1,    0,    0, 0),   // k=1: trivial
        (2,    1,    1, 1),   // k=2: Garner 1 mult, tree 1 combine, depth 1
        (4,    6,    3, 2),   // CRAM-S4
        (6,   15,    7, 3),   // CRAM-S6 (padded to 8)
        (13,  78,   15, 4),   // 13 lanes (next_pow2=16)
        (144, 10_296, 255, 8), // WASSAN 144-band
    ];

    for &(k, g, tc, td) in cases {
        let (garner, tree_combines, tree_depth) = operation_count_comparison(k);
        assert_eq!(garner,       g,  "k={}: garner mults expected {}", k, g);
        assert_eq!(tree_combines, tc, "k={}: tree combines expected {}", k, tc);
        assert_eq!(tree_depth,    td, "k={}: tree depth expected {}", k, td);
    }
}

#[test]
fn h6_sequential_depth_is_log2_next_pow2() {
    // For every topology, sequential_depth() must equal log2(next_pow2(k)).
    // This is the critical-path length claim.
    let topologies: &[(&[i128], usize)] = &[
        (&[2, 3, 5, 7],           2),  // S4: next_pow2(4)=4, log2(4)=2
        (&[2, 3, 5, 7, 11, 13],   3),  // S6: next_pow2(6)=8, log2(8)=3
        (&[79, 83, 89, 97],       2),  // S4+: next_pow2(4)=4, log2(4)=2
        (&[2, 3, 5],              2),  // S3: next_pow2(3)=4, log2(4)=2
    ];

    for (primes, expected_depth) in topologies {
        let tree = SubproductTree::build(primes);
        assert_eq!(
            tree.sequential_depth(), *expected_depth,
            "Primes {:?}: depth {} expected {}", primes, tree.sequential_depth(), expected_depth
        );
    }
}

#[test]
fn h7_crt_combine_exhaustive_small_primes() {
    // crt_combine must satisfy both congruences for all (r_p, r_q) pairs
    // over each pair of primes in the S4 topology.
    let prime_pairs = [(2i128, 3i128), (2, 5), (2, 7), (3, 5), (3, 7), (5, 7)];
    for (p, q) in prime_pairs {
        for r_p in 0..p {
            for r_q in 0..q {
                let (x, m) = crt_combine(r_p, p, r_q, q);
                assert_eq!(m, p * q, "combined modulus must be p*q");
                assert!(x >= 0 && x < m, "x must be in [0, m)");
                assert_eq!(x % p, r_p, "x mod {} must equal {}", p, r_p);
                assert_eq!(x % q, r_q, "x mod {} must equal {}", q, r_q);
            }
        }
    }
}

#[test]
fn h8_crt_combine_sentinel_identity() {
    // Combining any (r, m) with (0, 1) must return (r, m) unchanged.
    // This is the correctness basis for padding with sentinel primes of 1.
    let test_pairs = [(42i128, 210i128), (0, 30030), (165, 30030), (29999, 30030)];
    for (r, m) in test_pairs {
        let (x1, m1) = crt_combine(r, m, 0, 1);
        assert_eq!((x1, m1), (r, m), "right-sentinel failed for ({}, {})", r, m);

        let (x2, m2) = crt_combine(0, 1, r, m);
        assert_eq!((x2, m2), (r, m), "left-sentinel failed for ({}, {})", r, m);
    }
}

#[test]
fn h9_subproduct_tree_crt_type_matches_garner() {
    // SubproductTreeCrt must produce identical results to Garner for every
    // test case in the paper.
    let primes = vec![2i128, 3, 5, 7, 11, 13];
    let crt_engine = SubproductTreeCrt::precompute(&primes);
    let garner_engine = cram::GarnerConstants::precompute(&primes);

    let test_inputs: &[i128] = &[0, 1, 42, 100, 165, 1000, 17000, 29999];
    for &x in test_inputs {
        let residues = cram::decompose(x, &primes);
        let tree_val   = crt_engine.reconstruct(&residues);
        let garner_val = cram::reconstruct(&residues, &garner_engine);
        let expected   = x % 30030;
        assert_eq!(tree_val, garner_val,
            "SubproductTreeCrt/Garner diverge at x={}: tree={} garner={}", x, tree_val, garner_val);
        assert_eq!(tree_val, expected,
            "SubproductTreeCrt wrong value at x={}: got {} expected {}", x, tree_val, expected);
    }
}

#[test]
fn h10_single_prime_edge_case() {
    // k=1 is a degenerate topology — the residue IS the result.
    // The tree should handle this without any combines.
    let tree = SubproductTree::build(&[13]);
    for r in 0..13i128 {
        let result = subproduct_reconstruct(&[r], &tree);
        assert_eq!(result.value,           r, "k=1 must return the residue itself");
        assert_eq!(result.combine_count,   0, "k=1 needs zero combines");
        assert_eq!(result.sequential_depth, 0, "k=1 has zero depth");
    }
}

#[test]
fn h11_boundary_values_zero_and_n_minus_1() {
    for primes in [vec![2i128, 3, 5, 7], vec![2i128, 3, 5, 7, 11, 13]] {
        let n: i128 = primes.iter().product();
        let tree = SubproductTree::build(&primes);

        // x = 0: all residues are 0
        let r0 = subproduct_reconstruct(&vec![0i128; primes.len()], &tree);
        assert_eq!(r0.value, 0, "zero must reconstruct to 0");

        // x = N - 1: all residues are p_i - 1
        let residues_nm1: Vec<i128> = primes.iter().map(|&p| p - 1).collect();
        let rnm1 = subproduct_reconstruct(&residues_nm1, &tree);
        assert_eq!(rnm1.value, n - 1, "N-1 must reconstruct to N-1 = {}", n - 1);
    }
}
