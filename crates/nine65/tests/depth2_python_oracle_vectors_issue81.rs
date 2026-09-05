//! Dumps real ciphertext/key "public vectors" from a depth-2 DualRNS
//! multiply chain to a JSON fixture, for cross-checking by an INDEPENDENT
//! Python arbitrary-precision oracle (`scripts/depth2_issue81_python_oracle.py`)
//! that shares no code with this crate.
//!
//! # Why this exists (issue #81 acceptance criterion #5)
//!
//! Issue #81 requires "an independent Python arbitrary-precision oracle for
//! reduced small-N public vectors" that agrees with the Rust path exactly.
//! `decrypt_dual` (`ops/rns_fhe.rs`) only ever reads the MAIN-system RNS
//! residues of coefficient 0 of `c0 + c1*s` -- the anchor/K-Elimination
//! system is used internally during MULTIPLY (to compute exact rescale
//! division), but never at decode time. So an oracle that starts from a real
//! ciphertext's raw main-system residues (dumped here, "public" in the sense
//! that ciphertexts are public data even under symmetric-key evaluation) and
//! independently re-derives the decoded plaintext from scratch is a genuine,
//! meaningful cross-check of the actual data the depth-2 bug's fix touches --
//! even though it cannot re-run the multiply's *internal* rescale step from
//! outside the crate (that requires private methods; `depth2_isolation.rs`'s
//! module doc explains why an outside re-implementation of the tensor product
//! itself was tried and retired as a dead end).
//!
//! This file dumps the FULL degree-N coefficient arrays (not just
//! coefficient 0) of every ciphertext of interest, in BOTH the main and
//! anchor RNS systems, plus the secret key, so the Python oracle can:
//!
//!   1. Independently perform the negacyclic polynomial multiply
//!      `c0 + c1 (x) s` via schoolbook convolution (its own code, not NTT)
//!      per main prime, and independently CRT-reconstruct + round-divide to
//!      decode -- confirming it reaches the SAME plaintext Rust's own
//!      `decrypt_dual` reports.
//!   2. Independently CRT-reconstruct the TRUE (unbounded, signed) value of
//!      chosen ciphertext coefficients from main+anchor residues (the same
//!      `extract_k_rns_level` formula `depth2_isolation.rs` already
//!      replicated in Rust, now ported to Python as the issue literally
//!      requests), and confirm the winding stays inside the anchor
//!      capacity -- i.e. that the fix's capacity margin is real on these
//!      exact vectors, not merely asserted.
//!
//! # Why N=64, not N=8192/16384
//!
//! Dumping full N=8192-length coefficient arrays across 4-10 RNS lanes for
//! every ciphertext in a seed matrix would be tens of megabytes of JSON for
//! no added rigor -- the RNS/NTT machinery is coefficient-independent (every
//! coefficient index is an independent lane in every operation this crate
//! performs; there is no cross-coefficient mixing except inside the negacyclic
//! convolution itself, which the oracle already re-derives from scratch).
//! Reducing N shrinks the fixture without changing the arithmetic being
//! checked. The catch is that anchor/main primes must stay NTT-compatible
//! with the chosen N, so this file reuses REAL production primes -- the exact
//! four main primes secure_128/secure_128_deep ship, and the crate's own
//! `canonical_anchor_primes_for_n` for the anchor set -- at a smaller N,
//! rather than inventing toy moduli. That keeps Q (hence the real depth-2
//! capacity margin this issue is about) representative of the actual fix,
//! while N shrinks to something a from-scratch Python script can chew
//! through directly.

use nine65::entropy::ShadowHarvester;
use nine65::ops::rns_fhe::{DualRNSCiphertext, RNSFHEContext};
use nine65::params::FHEConfig;
use std::fmt::Write as _;

/// Reduced-N config carrying the REAL secure_128/secure_128_deep main-prime
/// chain (log2(Q) = 119 bits, the exact tuple this issue's fix concerns) at
/// N=64 instead of N=8192, purely to keep the dumped fixture small. All 4
/// primes satisfy `(p-1) % (2*n) == 0` for every n up to 2^22, so N=64 is
/// NTT-compatible -- `RNSFHEContext::new`'s own internal assertion enforces
/// this and would fail loudly if it were not.
fn oracle_config() -> FHEConfig {
    FHEConfig {
        n: 64,
        primes: vec![998244353, 985661441, 754974721, 469762049],
        q: 998244353,
        t: 65537,
        eta: 3,
        security_bits: 128,
        name: "depth2_oracle_reduced_n64_issue81",
    }
}

fn json_u64_array(v: &[u64]) -> String {
    let mut s = String::from("[");
    for (i, x) in v.iter().enumerate() {
        if i > 0 {
            s.push(',');
        }
        write!(s, "{x}").unwrap();
    }
    s.push(']');
    s
}

fn json_u64_matrix(v: &[Vec<u64>]) -> String {
    let mut s = String::from("[");
    for (i, row) in v.iter().enumerate() {
        if i > 0 {
            s.push(',');
        }
        s.push_str(&json_u64_array(row));
    }
    s.push(']');
    s
}

fn json_poly(main: &[Vec<u64>], anchor: &[Vec<u64>]) -> String {
    format!(
        "{{\"main\":{},\"anchor\":{}}}",
        json_u64_matrix(main),
        json_u64_matrix(anchor)
    )
}

fn json_ciphertext(ct: &DualRNSCiphertext) -> String {
    format!(
        "{{\"level\":{},\"c0\":{},\"c1\":{}}}",
        ct.level,
        json_poly(&ct.c0.main, &ct.c0.anchor),
        json_poly(&ct.c1.main, &ct.c1.anchor)
    )
}

/// One named ciphertext entry plus the Rust-computed ground truth
/// (`decrypt_dual` output and the mathematically expected plaintext) to
/// cross-check the Python oracle against.
struct DumpedOp {
    label: String,
    mode: &'static str, // "symmetric" | "public"
    ct: DualRNSCiphertext,
    rust_decrypt: u64,
    expected: u64,
}

#[test]
fn dump_depth2_oracle_vectors_and_verify_rust_ground_truth() {
    let config = oracle_config();
    let ctx = RNSFHEContext::new(&config);
    let t = ctx.t;

    // Sanity on the reduced config itself before trusting anything dumped
    // from it: same main-prime chain as secure_128/secure_128_deep, and NTT
    // compatibility held (RNSFHEContext::new would have panicked otherwise).
    assert_eq!(
        config.primes,
        vec![998244353, 985661441, 754974721, 469762049]
    );
    assert!(
        ctx.dual_rns.anchor.primes.len() >= 5,
        "reduced-N config must still get a real anchor basis, got {}",
        ctx.dual_rns.anchor.primes.len()
    );

    let seeds = [12345u64, 909_090u64];
    let mut ops: Vec<DumpedOp> = Vec::new();

    for &seed in &seeds {
        let mut rng = ShadowHarvester::with_seed(seed);
        let keys = ctx.generate_keys_dual_full(&mut rng);

        // ---- squaring chain: base=3 -> 9 -> 81 ----
        let base = 3u64;
        let ct0 = ctx.encrypt_dual(base, &keys.public_key, &mut rng);

        let sym_d1 = ctx.mul_dual_symmetric(&ct0, &ct0, &keys.secret_key);
        let sym_d2 = ctx.mul_dual_symmetric(&sym_d1, &sym_d1, &keys.secret_key);
        let pub_d1 = ctx
            .mul_dual_public(&ct0, &ct0, &keys.eval_key)
            .expect("public depth-1 squaring");
        let pub_d2 = ctx
            .mul_dual_public(&pub_d1, &pub_d1, &keys.eval_key)
            .expect("public depth-2 squaring");

        for (label, mode, ct, expected) in [
            ("square_d1", "symmetric", sym_d1.clone(), (base * base) % t),
            (
                "square_d2",
                "symmetric",
                sym_d2.clone(),
                ((base * base) % t) * ((base * base) % t) % t,
            ),
            ("square_d1", "public", pub_d1.clone(), (base * base) % t),
            (
                "square_d2",
                "public",
                pub_d2.clone(),
                ((base * base) % t) * ((base * base) % t) % t,
            ),
        ] {
            let dec = ctx.decrypt_dual(&ct, &keys.secret_key);
            assert_eq!(
                dec, expected,
                "seed={seed} {mode} {label}: RUST decrypt_dual got {dec}, want {expected} -- \
                 fixture would be built on a Rust-side failure, refusing to dump"
            );
            ops.push(DumpedOp {
                label: format!("seed{seed}_{label}"),
                mode,
                ct,
                rust_decrypt: dec,
                expected,
            });
        }

        // ---- mixed-operand, non-squaring depth-2 chain: (a*b)*(c*d) ----
        let (a, b, c, d) = (
            (seed % 11) + 2,
            (seed % 11) + 5,
            (seed % 11) + 8,
            (seed % 11) + 11,
        );
        let ct_a = ctx.encrypt_dual(a, &keys.public_key, &mut rng);
        let ct_b = ctx.encrypt_dual(b, &keys.public_key, &mut rng);
        let ct_c = ctx.encrypt_dual(c, &keys.public_key, &mut rng);
        let ct_d = ctx.encrypt_dual(d, &keys.public_key, &mut rng);

        let sym_ab = ctx.mul_dual_symmetric(&ct_a, &ct_b, &keys.secret_key);
        let sym_cd = ctx.mul_dual_symmetric(&ct_c, &ct_d, &keys.secret_key);
        let sym_abcd = ctx.mul_dual_symmetric(&sym_ab, &sym_cd, &keys.secret_key);

        let pub_ab = ctx
            .mul_dual_public(&ct_a, &ct_b, &keys.eval_key)
            .expect("public a*b");
        let pub_cd = ctx
            .mul_dual_public(&ct_c, &ct_d, &keys.eval_key)
            .expect("public c*d");
        let pub_abcd = ctx
            .mul_dual_public(&pub_ab, &pub_cd, &keys.eval_key)
            .expect("public (a*b)*(c*d)");

        let expect_ab = (a * b) % t;
        let expect_cd = (c * d) % t;
        let expect_abcd = ((expect_ab as u128 * expect_cd as u128) % t as u128) as u64;

        for (label, mode, ct, expected) in [
            ("mixed_d2_abcd", "symmetric", sym_abcd.clone(), expect_abcd),
            ("mixed_d2_abcd", "public", pub_abcd.clone(), expect_abcd),
        ] {
            let dec = ctx.decrypt_dual(&ct, &keys.secret_key);
            assert_eq!(
                dec, expected,
                "seed={seed} {mode} {label}: RUST decrypt_dual got {dec}, want {expected}"
            );
            ops.push(DumpedOp {
                label: format!("seed{seed}_{label}"),
                mode,
                ct,
                rust_decrypt: dec,
                expected,
            });
        }

        // Dump the secret key ONCE per seed (shared by every op above, since
        // generate_keys_dual_full was called once per seed). Stashed as a
        // pseudo-op ("keydump" mode) so it travels through the same JSON
        // assembly loop below, keyed to the seed so the oracle can match each
        // ciphertext op back to the key that decrypts it.
        ops.push(DumpedOp {
            label: format!("secret_key_seed{seed}"),
            mode: "keydump",
            ct: DualRNSCiphertext {
                c0: keys.secret_key.s.clone(),
                c1: keys.secret_key.s.clone(),
                level: 0,
            },
            rust_decrypt: 0,
            expected: 0,
        });
    }

    // ---- assemble JSON fixture ----
    let mut json = String::new();
    json.push_str("{\n");
    write!(json, "  \"n\": {},\n", ctx.n).unwrap();
    write!(json, "  \"t\": {},\n", ctx.t).unwrap();
    write!(
        json,
        "  \"main_primes\": {},\n",
        json_u64_array(&ctx.config.primes)
    )
    .unwrap();
    write!(
        json,
        "  \"anchor_primes\": {},\n",
        json_u64_array(&ctx.dual_rns.anchor.primes)
    )
    .unwrap();
    write!(
        json,
        "  \"k_reconstruction_anchor_count\": {},\n",
        ctx.dual_rns.anchor.primes.len().min(8)
    )
    .unwrap();
    json.push_str("  \"ops\": [\n");
    for (i, op) in ops.iter().enumerate() {
        if i > 0 {
            json.push_str(",\n");
        }
        if op.mode == "keydump" {
            write!(
                json,
                "    {{\"label\":\"{}\",\"mode\":\"secret_key\",\"s\":{}}}",
                op.label,
                json_poly(&op.ct.c0.main, &op.ct.c0.anchor)
            )
            .unwrap();
        } else {
            write!(
                json,
                "    {{\"label\":\"{}\",\"mode\":\"{}\",\"rust_decrypt\":{},\"expected\":{},\"ciphertext\":{}}}",
                op.label,
                op.mode,
                op.rust_decrypt,
                op.expected,
                json_ciphertext(&op.ct)
            )
            .unwrap();
        }
    }
    json.push_str("\n  ]\n}\n");

    let out_dir = format!("{}/tests/fixtures", env!("CARGO_MANIFEST_DIR"));
    std::fs::create_dir_all(&out_dir).expect("create fixtures dir");
    let out_path = format!("{out_dir}/depth2_oracle_vectors_issue81.json");
    std::fs::write(&out_path, &json).unwrap_or_else(|e| panic!("write {out_path}: {e}"));

    println!(
        "=== dumped {} ops ({} bytes) to {out_path} for the Python oracle cross-check ===",
        ops.len(),
        json.len()
    );
}
