// Comparison-record probe (ADDITIVE — measurement only, no algorithm touched).
//
// Purpose: produce REAL integer-nanosecond sample arrays for every operation
// that the fhe-comparison-record-v1 contract (benchmarks/comparative/README.md)
// can carry, so the performance claim is DATA rather than assertion.
//
// Run with:
//   RAYON_NUM_THREADS=1 taskset -c 0 \
//     cargo run -p nine65 --release --example comparison_record_probe
//
// This file only calls the public API. It modifies nothing, deletes nothing,
// and does not touch the constant-time arithmetic layer. It is picked up by
// cargo example autodiscovery, so crates/nine65/Cargo.toml is NOT edited.
//
// Output: a machine-readable JSON block between the markers
//   ===BEGIN_PROBE_JSON===  /  ===END_PROBE_JSON===
// containing, per operation, the raw sorted samples_ns plus exact integer
// statistics (median as numerator/denominator, nearest-rank p95). No floating
// point is used anywhere in this program.

use nine65::entropy::ShadowHarvester;
use nine65::ops::rns_fhe::RNSFHEContext;
use nine65::params::secure_configs::SecureConfig;
use nine65::params::security_estimator::{CostModel, LatticeSecurityEstimator, SecretDistribution};
use nine65::params::FHEConfig;
use std::time::Instant;

/// Exact median as (numerator, denominator). Integer only.
fn median_exact(sorted: &[u64]) -> (u128, u128) {
    let n = sorted.len();
    assert!(n > 0);
    if n % 2 == 1 {
        (sorted[n / 2] as u128, 1)
    } else {
        (sorted[n / 2 - 1] as u128 + sorted[n / 2] as u128, 2)
    }
}

/// p95 by nearest-rank: rank = ceil(95*n/100), 1-based. Integer only.
fn p95_nearest_rank(sorted: &[u64]) -> u64 {
    let n = sorted.len();
    let rank = (95 * n + 99) / 100;
    let rank = if rank == 0 { 1 } else { rank };
    sorted[rank - 1]
}

/// Emit one operation's measurement block as JSON.
fn emit_op(name: &str, api: &str, samples: &[u64], trials: u32, failures: u32, last: bool) {
    let mut s = samples.to_vec();
    s.sort_unstable();
    let (num, den) = median_exact(&s);
    let p95 = p95_nearest_rank(&s);
    println!("    \"{}\": {{", name);
    println!("      \"api\": \"{}\",", api);
    println!("      \"n_samples\": {},", s.len());
    println!("      \"min_ns\": {},", s[0]);
    println!("      \"max_ns\": {},", s[s.len() - 1]);
    println!("      \"median_ns_numerator\": {},", num);
    println!("      \"median_ns_denominator\": {},", den);
    println!("      \"median_ns_floor\": {},", num / den);
    println!("      \"p95_ns_nearest_rank\": {},", p95);
    println!("      \"correctness_trials\": {},", trials);
    println!("      \"correctness_failures\": {},", failures);
    let joined: Vec<String> = s.iter().map(|v| v.to_string()).collect();
    println!("      \"samples_ns\": [{}]", joined.join(", "));
    println!("    }}{}", if last { "" } else { "," });
}

fn main() {
    let cfg: FHEConfig = SecureConfig::secure_128().into_config();
    let n = cfg.n;
    let t = cfg.t;

    // ---- log_q_bits computed from the ACTUAL primes, not guessed ----
    let mut q_product: u128 = 1;
    for p in cfg.primes.iter() {
        q_product = q_product.checked_mul(*p as u128).expect("q overflows u128");
    }
    let log_q_bits: u32 = 128 - q_product.leading_zeros();

    // ---- in-tree screening gate (NOT an independent lattice certificate) ----
    let est = LatticeSecurityEstimator::new(CostModel::CoreSVP).dual_estimate(
        n,
        log_q_bits,
        SecretDistribution::Ternary,
        128,
    );

    let ctx = RNSFHEContext::try_new(&cfg).expect("context construction failed");
    let mut rng = ShadowHarvester::with_seed(500);
    let keys = ctx.generate_keys_dual(&mut rng);

    // Fixed operands reused across timed loops so the timed region is the
    // operation itself and nothing else.
    let ct_a = ctx.encrypt_dual(5, &keys.public_key, &mut rng);
    let ct_b = ctx.encrypt_dual(7, &keys.public_key, &mut rng);

    // =================== KEYGEN ===================
    const KEYGEN_WARMUP: usize = 5;
    const KEYGEN_SAMPLES: usize = 40;
    for _ in 0..KEYGEN_WARMUP {
        std::hint::black_box(ctx.generate_keys_dual(&mut rng));
    }
    let mut keygen_ns = Vec::with_capacity(KEYGEN_SAMPLES);
    for _ in 0..KEYGEN_SAMPLES {
        let t0 = Instant::now();
        let k = ctx.generate_keys_dual(&mut rng);
        let dt = t0.elapsed().as_nanos();
        std::hint::black_box(&k);
        keygen_ns.push(dt as u64);
    }
    // Keygen correctness: each freshly generated keyset must round-trip a value.
    let mut keygen_trials = 0u32;
    let mut keygen_failures = 0u32;
    for m in [1u64, 2, 42, 65536, t - 1] {
        let k = ctx.generate_keys_dual(&mut rng);
        let c = ctx.encrypt_dual(m, &k.public_key, &mut rng);
        let d = ctx.decrypt_dual(&c, &k.secret_key);
        keygen_trials += 1;
        if d != m {
            keygen_failures += 1;
        }
    }

    // =================== ENCRYPT ===================
    const ENC_WARMUP: usize = 5;
    const ENC_SAMPLES: usize = 40;
    for _ in 0..ENC_WARMUP {
        std::hint::black_box(ctx.encrypt_dual(5, &keys.public_key, &mut rng));
    }
    let mut enc_ns = Vec::with_capacity(ENC_SAMPLES);
    for _ in 0..ENC_SAMPLES {
        let t0 = Instant::now();
        let c = ctx.encrypt_dual(5, &keys.public_key, &mut rng);
        let dt = t0.elapsed().as_nanos();
        std::hint::black_box(&c);
        enc_ns.push(dt as u64);
    }

    // =================== DECRYPT ===================
    // Correctness for encrypt and decrypt is the same round-trip experiment;
    // it is reported on both records with that stated in the note.
    let mut rt_trials = 0u32;
    let mut rt_failures = 0u32;
    for m in [0u64, 1, 2, 5, 7, 42, 1000, 65536, t - 1] {
        let c = ctx.encrypt_dual(m, &keys.public_key, &mut rng);
        let d = ctx.decrypt_dual(&c, &keys.secret_key);
        rt_trials += 1;
        if d != m {
            rt_failures += 1;
        }
    }

    const DEC_WARMUP: usize = 5;
    const DEC_SAMPLES: usize = 40;
    for _ in 0..DEC_WARMUP {
        std::hint::black_box(ctx.decrypt_dual(&ct_a, &keys.secret_key));
    }
    let mut dec_ns = Vec::with_capacity(DEC_SAMPLES);
    for _ in 0..DEC_SAMPLES {
        let t0 = Instant::now();
        let d = ctx.decrypt_dual(&ct_a, &keys.secret_key);
        let dt = t0.elapsed().as_nanos();
        std::hint::black_box(d);
        dec_ns.push(dt as u64);
    }

    // =================== ADD ===================
    const ADD_WARMUP: usize = 10;
    const ADD_SAMPLES: usize = 100;
    for _ in 0..ADD_WARMUP {
        std::hint::black_box(ctx.add_dual(&ct_a, &ct_b));
    }
    let mut add_ns = Vec::with_capacity(ADD_SAMPLES);
    for _ in 0..ADD_SAMPLES {
        let t0 = Instant::now();
        let c = ctx.add_dual(&ct_a, &ct_b);
        let dt = t0.elapsed().as_nanos();
        std::hint::black_box(&c);
        add_ns.push(dt as u64);
    }
    let mut add_trials = 0u32;
    let mut add_failures = 0u32;
    for (a, b) in [
        (0u64, 0u64),
        (1, 1),
        (2, 3),
        (7, 11),
        (100, 200),
        (t - 1, 2),
    ] {
        let ca = ctx.encrypt_dual(a, &keys.public_key, &mut rng);
        let cb = ctx.encrypt_dual(b, &keys.public_key, &mut rng);
        let cs = ctx.add_dual(&ca, &cb);
        let got = ctx.decrypt_dual(&cs, &keys.secret_key);
        let expected = ((a as u128 + b as u128) % t as u128) as u64;
        add_trials += 1;
        if got != expected {
            add_failures += 1;
        }
    }

    // =================== MUL ===================
    const MUL_WARMUP: usize = 5;
    const MUL_SAMPLES: usize = 20;
    for _ in 0..MUL_WARMUP {
        std::hint::black_box(ctx.mul_dual_symmetric(&ct_a, &ct_b, &keys.secret_key));
    }
    let mut mul_ns = Vec::with_capacity(MUL_SAMPLES);
    for _ in 0..MUL_SAMPLES {
        let t0 = Instant::now();
        let c = ctx.mul_dual_symmetric(&ct_a, &ct_b, &keys.secret_key);
        let dt = t0.elapsed().as_nanos();
        std::hint::black_box(&c);
        mul_ns.push(dt as u64);
    }
    let mut mul_trials = 0u32;
    let mut mul_failures = 0u32;
    for (a, b) in [
        (0u64, 0u64),
        (1, 1),
        (2, 3),
        (5, 7),
        (7, 11),
        (100, 200),
        (t - 1, 2),
    ] {
        let ca = ctx.encrypt_dual(a, &keys.public_key, &mut rng);
        let cb = ctx.encrypt_dual(b, &keys.public_key, &mut rng);
        let cp = ctx.mul_dual_symmetric(&ca, &cb, &keys.secret_key);
        let got = ctx.decrypt_dual(&cp, &keys.secret_key);
        let expected = ((a as u128 * b as u128) % t as u128) as u64;
        mul_trials += 1;
        if got != expected {
            mul_failures += 1;
        }
    }

    // =================== PACKED (capability check only) ===================
    // No slot encoder exists in this workspace, so no packed ciphertext can be
    // constructed and no packed operation can be timed. Reported, never faked.
    let two_n = 2 * n;
    let packed_permitted = (t % two_n as u64) == 1;

    // =================== EMIT ===================
    println!("===BEGIN_PROBE_JSON===");
    println!("{{");
    println!("  \"config_name\": \"secure_128\",");
    println!("  \"n\": {},", n);
    println!("  \"t\": {},", t);
    let primes: Vec<String> = cfg.primes.iter().map(|p| p.to_string()).collect();
    println!("  \"primes\": [{}],", primes.join(", "));
    println!("  \"q_product\": \"{}\",", q_product);
    println!("  \"log_q_bits\": {},", log_q_bits);
    println!("  \"secret_distribution\": \"ternary\",");
    println!("  \"screening_gate\": {{");
    println!(
        "    \"name\": \"nine65-in-tree LatticeSecurityEstimator (integer-only screening gate)\","
    );
    println!(
        "    \"core_svp_effective_bits\": {},",
        est.core_svp.effective_bits
    );
    println!(
        "    \"matzov_effective_bits\": {},",
        est.matzov.effective_bits
    );
    println!("    \"binding_bits\": {},", est.binding_bits);
    println!("    \"meets_both\": {}", est.meets_both);
    println!("  }},");
    println!("  \"packed\": {{");
    println!("    \"permitted_by_parameters\": {},", packed_permitted);
    println!("    \"measured\": false,");
    println!("    \"reason\": \"no slot encoder exists; no packed ciphertext can be constructed, so no packed operation can be timed\"");
    println!("  }},");
    println!("  \"operations\": {{");
    emit_op(
        "keygen",
        "RNSFHEContext::generate_keys_dual(&mut ShadowHarvester)",
        &keygen_ns,
        keygen_trials,
        keygen_failures,
        false,
    );
    emit_op(
        "encrypt",
        "RNSFHEContext::encrypt_dual(m: u64, &pk, &mut ShadowHarvester)",
        &enc_ns,
        rt_trials,
        rt_failures,
        false,
    );
    emit_op(
        "decrypt",
        "RNSFHEContext::decrypt_dual(&ct, &sk)",
        &dec_ns,
        rt_trials,
        rt_failures,
        false,
    );
    emit_op(
        "add_ct",
        "RNSFHEContext::add_dual(&ct1, &ct2)",
        &add_ns,
        add_trials,
        add_failures,
        false,
    );
    emit_op(
        "mul_ct",
        "RNSFHEContext::mul_dual_symmetric(&ct1, &ct2, &sk)",
        &mul_ns,
        mul_trials,
        mul_failures,
        true,
    );
    println!("  }}");
    println!("}}");
    println!("===END_PROBE_JSON===");
}
