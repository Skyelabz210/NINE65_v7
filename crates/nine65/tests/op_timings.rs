//! Measured cost of the core FHE operations, per config.
//!
//! Exists because the numbers in `README.md` and `CLAUDE.md` were inherited
//! rather than re-measured, and because a constant-time change landed inside
//! `BarrettContext::reduce_ct`, which `NTTEngine` calls in its pointwise
//! multiply — the innermost loop of every ciphertext multiply. A perf claim
//! that nobody re-runs is the same class of problem as a CI claim that nobody
//! checks.
//!
//! Run:
//!   cargo test -p nine65 --test op_timings --release --features allow_insecure \
//!     -- --ignored --nocapture

use nine65::entropy::ShadowHarvester;
use nine65::ops::rns_fhe::RNSFHEContext;
use nine65::params::secure_configs::SecureConfig;
use std::time::Instant;

fn median(mut v: Vec<u128>) -> f64 {
    v.sort_unstable();
    v[v.len() / 2] as f64 / 1_000_000.0
}

fn time_config(name: &str, secure: SecureConfig, rounds: usize) {
    let config = secure.config.clone();
    let ctx = RNSFHEContext::new(&config);
    let mut rng = ShadowHarvester::with_seed(4242);
    let keys = ctx.generate_keys_dual_full(&mut rng);

    let (mut enc, mut add, mut mul, mut dec, mut smul) =
        (vec![], vec![], vec![], vec![], vec![]);
    let s2 = ctx.precompute_s_squared(&keys.secret_key);

    for i in 0..rounds {
        let a = (i as u64 % 17) + 2;
        let b = (i as u64 % 13) + 3;

        let t0 = Instant::now();
        let ct_a = ctx.encrypt_dual(a, &keys.public_key, &mut rng);
        enc.push(t0.elapsed().as_nanos());

        let ct_b = ctx.encrypt_dual(b, &keys.public_key, &mut rng);

        let t1 = Instant::now();
        let sum = ctx.add_dual(&ct_a, &ct_b);
        add.push(t1.elapsed().as_nanos());

        let t2 = Instant::now();
        let prod = ctx
            .mul_dual_public(&ct_a, &ct_b, &keys.eval_key)
            .expect("mul_dual_public returned Err");
        mul.push(t2.elapsed().as_nanos());

        let t3 = Instant::now();
        let got = ctx.decrypt_dual(&sum, &keys.secret_key);
        dec.push(t3.elapsed().as_nanos());

        let t4 = Instant::now();
        let sprod = ctx.mul_dual_symmetric_with_s2(&ct_a, &ct_b, &keys.secret_key, &s2);
        smul.push(t4.elapsed().as_nanos());
        assert_eq!(
            ctx.decrypt_dual(&sprod, &keys.secret_key),
            (a * b) % config.t,
            "{name}: symmetric mul must stay exact"
        );

        assert_eq!(got, (a + b) % config.t, "{name}: add must stay exact");
        assert_eq!(
            ctx.decrypt_dual(&prod, &keys.secret_key),
            (a * b) % config.t,
            "{name}: mul must stay exact"
        );
    }

    println!(
        "| `{name}` | {} | {} | {:.2} | {:.3} | {:.2} | {:.2} | {:.2} |",
        config.n,
        config.primes.len(),
        median(enc),
        median(add),
        median(mul),
        median(smul),
        median(dec),
    );
}

#[test]
#[ignore = "timing measurement — run explicitly with --ignored --nocapture"]
fn measure_core_op_timings() {
    println!("\n=== NINE65 core operation timings (this build, this machine) ===");
    println!("| Config | N | main lanes | Encrypt ms | Add ms | Public mul ms | Symmetric mul ms | Decrypt ms |");
    println!("|---|---|---|---|---|---|---|---|");
    time_config("secure_128", SecureConfig::secure_128(), 5);
    time_config("secure_128_deep", SecureConfig::secure_128_deep(), 5);
    time_config("secure_192", SecureConfig::secure_192(), 3);
    time_config("secure_256", SecureConfig::secure_256(), 3);
    println!();
}
