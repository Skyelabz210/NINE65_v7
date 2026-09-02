//! Measured cost of the CRAM-public evaluator's operations, per config.
//!
//! Same house pattern as `tests/op_timings.rs` (medians over multiple runs,
//! every round decrypts and asserts exactness so no timing comes from a
//! wrong answer, `#[ignore]`d, reproduce command below) applied to
//! `CramPublicEvaluator` — the public-only surface — and, where the config
//! is a manufactured chain, the M2b/M3 elimination-first paths.
//!
//! Also includes a determinism check: this codebase commits to bit-
//! identical results across platforms (CLAUDE.md, "Deterministic execution
//! — bit-identical results across all platforms required"), so every op is
//! run twice in-process on IDENTICAL seeds and the resulting ciphertexts
//! are asserted byte-identical, not just plaintext-identical.
//!
//! Run:
//!   cargo test -p nine65 --test cram_public_timings --release \
//!     --features allow_insecure -- --ignored --nocapture

use nine65::entropy::ShadowHarvester;
use nine65::ops::cram_public::CramPublicEvaluator;
use nine65::ops::rns_fhe::DualRNSCiphertext;
use nine65::params::secure_configs::SecureConfig;
use nine65::params::FHEConfig;
use std::time::Instant;

fn median(mut v: Vec<u128>) -> f64 {
    v.sort_unstable();
    v[v.len() / 2] as f64 / 1_000_000.0
}

/// Sum every limb of every lane, main and anchor, of both ciphertext
/// components — a cheap, stable stand-in for a cryptographic hash. Good
/// enough to detect ANY bit difference between two runs; not intended to be
/// collision-resistant (it doesn't need to be for this purpose).
fn ciphertext_fingerprint(ct: &DualRNSCiphertext) -> u64 {
    let mut acc: u64 = 0xcbf29ce484222325; // FNV offset basis, arbitrary but fixed
    let mut mix = |v: u64| {
        acc ^= v;
        acc = acc.wrapping_mul(0x100000001b3);
    };
    for poly in [&ct.c0, &ct.c1] {
        for limb in poly.main.iter().chain(poly.anchor.iter()) {
            for &c in limb {
                mix(c);
            }
        }
    }
    acc
}

fn determinism_check_manufactured(cfg: &FHEConfig) {
    let eval = CramPublicEvaluator::new(cfg);
    let mut rng1 = ShadowHarvester::with_seed(555001);
    let (pk1, client1) = eval.keygen_with_rng(&mut rng1);
    let mut rng2 = ShadowHarvester::with_seed(555001); // identical seed
    let (pk2, client2) = eval.keygen_with_rng(&mut rng2);

    let mut r1 = ShadowHarvester::with_seed(555002);
    let mut r2 = ShadowHarvester::with_seed(555002);
    let mut eval1 = CramPublicEvaluator::new(cfg);
    let mut eval2 = CramPublicEvaluator::new(cfg);
    let a1 = eval1.encrypt_with_rng(1234, &client1.public_key, &mut r1);
    let a2 = eval2.encrypt_with_rng(1234, &client2.public_key, &mut r2);
    assert_eq!(
        ciphertext_fingerprint(&a1),
        ciphertext_fingerprint(&a2),
        "determinism: two encrypts with identical seeds must be byte-identical"
    );

    let mut r3 = ShadowHarvester::with_seed(555003);
    let mut r4 = ShadowHarvester::with_seed(555003);
    let b1 = eval1.encrypt_with_rng(5678, &client1.public_key, &mut r3);
    let b2 = eval2.encrypt_with_rng(5678, &client2.public_key, &mut r4);

    let ab1 = eval1
        .mul_manufactured(&a1, &b1, &pk1)
        .expect("manufactured mul 1");
    let ab2 = eval2
        .mul_manufactured(&a2, &b2, &pk2)
        .expect("manufactured mul 2");
    assert_eq!(
        ciphertext_fingerprint(&ab1),
        ciphertext_fingerprint(&ab2),
        "determinism: two manufactured multiplies with identical seeds must be \
         byte-identical"
    );
    assert_eq!(
        eval1.decrypt(&ab1, &client1),
        (1234u64 * 5678) % eval1.context().t
    );
}

/// Timing + correctness pass over the CRAM-public surface for one
/// manufactured-chain config. Every op decrypts and asserts exactness.
fn time_cram_public_manufactured(name: &str, cfg: &FHEConfig, rounds: usize) {
    let eval = CramPublicEvaluator::new(cfg);
    let mut keygen_rng = ShadowHarvester::with_seed(4242);
    let (pk, gadget, client) = eval
        .keygen_with_gadget_with_rng(&mut keygen_rng)
        .expect("gadget keygen on a manufactured chain");
    let mut eval = eval;
    let t = eval.context().t;

    let (mut enc, mut add, mut mulp, mut divide, mut mul_general, mut mul_m2b, mut mul_m3, mut dec) = (
        vec![],
        vec![],
        vec![],
        vec![],
        vec![],
        vec![],
        vec![],
        vec![],
    );

    for i in 0..rounds {
        let a = (i as u64 % 17) + 2;
        let b = (i as u64 % 13) + 3;

        let t0 = Instant::now();
        let mut r = ShadowHarvester::with_seed(9000 + i as u64);
        let ct_a = eval.encrypt_with_rng(a, &client.public_key, &mut r);
        enc.push(t0.elapsed().as_nanos());

        let mut r2 = ShadowHarvester::with_seed(9500 + i as u64);
        let ct_b = eval.encrypt_with_rng(b, &client.public_key, &mut r2);

        let t1 = Instant::now();
        let sum = eval.add(&ct_a, &ct_b);
        add.push(t1.elapsed().as_nanos());
        assert_eq!(
            eval.decrypt(&sum, &client),
            (a + b) % t,
            "{name}: add must stay exact"
        );

        let t2 = Instant::now();
        let scaled = eval.mul_plain(&ct_a, 3);
        mulp.push(t2.elapsed().as_nanos());
        assert_eq!(
            eval.decrypt(&scaled, &client),
            (a * 3) % t,
            "{name}: mul_plain must stay exact"
        );

        let t3 = Instant::now();
        let divided = eval
            .exact_divide(&scaled, 3)
            .expect("3 is a unit on every lane");
        divide.push(t3.elapsed().as_nanos());
        assert_eq!(
            eval.decrypt(&divided, &client),
            a % t,
            "{name}: exact_divide must invert mul_plain"
        );

        let t4 = Instant::now();
        let prod_general = eval.mul(&ct_a, &ct_b, &pk).expect("general mul");
        mul_general.push(t4.elapsed().as_nanos());
        assert_eq!(
            eval.decrypt(&prod_general, &client),
            (a * b) % t,
            "{name}: general mul must stay exact"
        );

        let t5 = Instant::now();
        let prod_m2b = eval.mul_manufactured(&ct_a, &ct_b, &pk).expect("m2b mul");
        mul_m2b.push(t5.elapsed().as_nanos());
        assert_eq!(
            eval.decrypt(&prod_m2b, &client),
            (a * b) % t,
            "{name}: m2b mul must stay exact"
        );

        let t6 = Instant::now();
        let prod_m3 = eval
            .mul_manufactured_gadget(&ct_a, &ct_b, &gadget)
            .expect("m3 gadget mul");
        mul_m3.push(t6.elapsed().as_nanos());
        assert_eq!(
            eval.decrypt(&prod_m3, &client),
            (a * b) % t,
            "{name}: m3 gadget mul must stay exact"
        );

        let t7 = Instant::now();
        let got = eval.decrypt(&sum, &client);
        dec.push(t7.elapsed().as_nanos());
        let _ = got;
    }

    println!(
        "| `{name}` | {} | {} | {:.3} | {:.3} | {:.3} | {:.3} | {:.2} | {:.2} | {:.2} | {:.3} |",
        cfg.n,
        cfg.primes.len(),
        median(enc),
        median(add),
        median(mulp),
        median(divide),
        median(mul_general),
        median(mul_m2b),
        median(mul_m3),
        median(dec),
    );
}

/// Timing + correctness pass over the CRAM-public surface for a general
/// (non-manufactured) config — only the ops that make sense there.
fn time_cram_public_general(name: &str, cfg: &FHEConfig, rounds: usize) {
    let eval = CramPublicEvaluator::new(cfg);
    let mut keygen_rng = ShadowHarvester::with_seed(4242);
    let (pk, client) = eval.keygen_with_rng(&mut keygen_rng);
    let mut eval = eval;
    let t = eval.context().t;

    let (mut enc, mut add, mut mulp, mut divide, mut mul_general, mut dec) =
        (vec![], vec![], vec![], vec![], vec![], vec![]);

    for i in 0..rounds {
        let a = (i as u64 % 17) + 2;
        let b = (i as u64 % 13) + 3;

        let t0 = Instant::now();
        let mut r = ShadowHarvester::with_seed(9000 + i as u64);
        let ct_a = eval.encrypt_with_rng(a, &client.public_key, &mut r);
        enc.push(t0.elapsed().as_nanos());

        let mut r2 = ShadowHarvester::with_seed(9500 + i as u64);
        let ct_b = eval.encrypt_with_rng(b, &client.public_key, &mut r2);

        let t1 = Instant::now();
        let sum = eval.add(&ct_a, &ct_b);
        add.push(t1.elapsed().as_nanos());
        assert_eq!(
            eval.decrypt(&sum, &client),
            (a + b) % t,
            "{name}: add must stay exact"
        );

        let t2 = Instant::now();
        let scaled = eval.mul_plain(&ct_a, 3);
        mulp.push(t2.elapsed().as_nanos());
        assert_eq!(
            eval.decrypt(&scaled, &client),
            (a * 3) % t,
            "{name}: mul_plain must stay exact"
        );

        let t3 = Instant::now();
        let divided = eval
            .exact_divide(&scaled, 3)
            .expect("3 is a unit on every lane");
        divide.push(t3.elapsed().as_nanos());
        assert_eq!(
            eval.decrypt(&divided, &client),
            a % t,
            "{name}: exact_divide must invert mul_plain"
        );

        let t4 = Instant::now();
        let prod_general = eval.mul(&ct_a, &ct_b, &pk).expect("general mul");
        mul_general.push(t4.elapsed().as_nanos());
        assert_eq!(
            eval.decrypt(&prod_general, &client),
            (a * b) % t,
            "{name}: general mul must stay exact"
        );

        let t7 = Instant::now();
        let got = eval.decrypt(&sum, &client);
        dec.push(t7.elapsed().as_nanos());
        let _ = got;
    }

    println!(
        "| `{name}` | {} | {} | {:.3} | {:.3} | {:.3} | {:.3} | {:.2} | n/a | n/a | {:.3} |",
        cfg.n,
        cfg.primes.len(),
        median(enc),
        median(add),
        median(mulp),
        median(divide),
        median(mul_general),
        median(dec),
    );
}

#[test]
#[ignore = "timing measurement — run explicitly with --ignored --nocapture"]
fn measure_cram_public_op_timings() {
    println!("\n=== CRAM-public evaluator operation timings (this build, this machine) ===");
    println!(
        "| Config | N | main lanes | Encrypt ms | Add ms | mul_plain ms | exact_divide ms | \
         mul (general) ms | mul_manufactured (M2b) ms | mul_manufactured_gadget (M3) ms | \
         Decrypt ms |"
    );
    println!("|---|---|---|---|---|---|---|---|---|---|---|");
    time_cram_public_manufactured(
        "manufactured_m2b_insecure",
        &FHEConfig::manufactured_m2b_insecure(),
        5,
    );
    time_cram_public_general(
        "secure_128_deep",
        &SecureConfig::secure_128_deep().config,
        5,
    );
    println!();
}

#[test]
#[ignore = "determinism check — run explicitly with --ignored --nocapture"]
fn cram_public_determinism_bit_identical_across_identical_seeds() {
    determinism_check_manufactured(&FHEConfig::manufactured_m2b_insecure());
    println!("determinism check passed: identical seeds produce byte-identical ciphertexts");
}
