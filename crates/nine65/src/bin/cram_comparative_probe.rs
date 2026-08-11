//! Exact same-process comparison probe for NINE65 execution paths.
//!
//! The probe measures the legacy single-modulus BFV path and the DualRNS/CRAM
//! path under one parameter tuple, process, compiler build, seed, and hardware
//! environment. It emits integer nanosecond averages and explicit correctness
//! checks. It does not simulate refresh or infer security from timings.

use nine65::ops::rns_fhe::RNSFHEContext;
use nine65::prelude::*;
use serde_json::json;
use std::hint::black_box;
use std::path::PathBuf;
use std::time::{Instant, SystemTime};

#[derive(Clone, Debug)]
struct Args {
    config: String,
    iterations: u64,
    mul_iterations: u64,
    ct_mul_depth: usize,
    seed: u64,
    a: u64,
    b: u64,
    output: Option<PathBuf>,
}

impl Default for Args {
    fn default() -> Self {
        Self {
            config: "v6_compat_4096".to_string(),
            iterations: 100,
            mul_iterations: 10,
            ct_mul_depth: 8,
            seed: 42,
            a: 8,
            b: 8,
            output: None,
        }
    }
}

fn parse_args() -> Args {
    let mut parsed = Args::default();
    let mut arguments = std::env::args().skip(1);
    while let Some(argument) = arguments.next() {
        let next = |arguments: &mut std::iter::Skip<std::env::Args>, flag: &str| {
            arguments.next().unwrap_or_else(|| {
                eprintln!("missing value for {flag}");
                std::process::exit(2);
            })
        };
        match argument.as_str() {
            "--config" => parsed.config = next(&mut arguments, "--config"),
            "--iterations" => {
                parsed.iterations = next(&mut arguments, "--iterations")
                    .parse()
                    .unwrap_or_else(|_| invalid("--iterations"));
            }
            "--mul-iterations" => {
                parsed.mul_iterations = next(&mut arguments, "--mul-iterations")
                    .parse()
                    .unwrap_or_else(|_| invalid("--mul-iterations"));
            }
            "--ct-mul-depth" => {
                parsed.ct_mul_depth = next(&mut arguments, "--ct-mul-depth")
                    .parse()
                    .unwrap_or_else(|_| invalid("--ct-mul-depth"));
            }
            "--seed" => {
                parsed.seed = next(&mut arguments, "--seed")
                    .parse()
                    .unwrap_or_else(|_| invalid("--seed"));
            }
            "--a" => {
                parsed.a = next(&mut arguments, "--a")
                    .parse()
                    .unwrap_or_else(|_| invalid("--a"));
            }
            "--b" => {
                parsed.b = next(&mut arguments, "--b")
                    .parse()
                    .unwrap_or_else(|_| invalid("--b"));
            }
            "--output" | "-o" => {
                parsed.output = Some(PathBuf::from(next(&mut arguments, "--output")));
            }
            "--help" | "-h" => {
                eprintln!(
                    "cram_comparative_probe \
                     --config v6_compat_4096|secure_128|secure_128_deep|secure_192|secure_256 \
                     --iterations 100 --mul-iterations 10 --ct-mul-depth 8 \
                     --seed 42 --a 8 --b 8 --output result.json"
                );
                std::process::exit(0);
            }
            _ => {
                eprintln!("unknown argument: {argument}");
                std::process::exit(2);
            }
        }
    }
    if parsed.iterations == 0 || parsed.mul_iterations == 0 || parsed.ct_mul_depth == 0 {
        eprintln!("iteration counts and depth must be positive");
        std::process::exit(2);
    }
    parsed
}

fn invalid(flag: &str) -> ! {
    eprintln!("invalid value for {flag}");
    std::process::exit(2);
}

fn v6_compat_config() -> FHEConfig {
    FHEConfig {
        n: 4096,
        primes: vec![998_244_353, 985_661_441, 754_974_721],
        q: 998_244_353,
        t: 65_537,
        eta: 3,
        security_bits: 0,
        name: "v6_compat_4096",
    }
}

fn select_config(name: &str) -> FHEConfig {
    match name {
        "v6_compat_4096" => {
            if !cfg!(feature = "allow_insecure") {
                eprintln!(
                    "v6_compat_4096 requires --features serde,allow_insecure; it is comparison-only"
                );
                std::process::exit(2);
            }
            v6_compat_config()
        }
        "secure_128" => SecureConfig::secure_128().into_config(),
        "secure_128_deep" => SecureConfig::secure_128_deep().into_config(),
        "secure_192" => SecureConfig::secure_192().into_config(),
        "secure_256" => SecureConfig::secure_256().into_config(),
        other => {
            eprintln!("unknown configuration: {other}");
            std::process::exit(2);
        }
    }
}

fn average_ns(iterations: u64, mut operation: impl FnMut()) -> u64 {
    let started = Instant::now();
    for _ in 0..iterations {
        operation();
    }
    let elapsed = started.elapsed().as_nanos();
    (elapsed / iterations as u128).min(u64::MAX as u128) as u64
}

fn exact_product_bit_length(factors: &[u64]) -> u64 {
    let mut limbs = vec![1_u64];
    for &factor in factors {
        let mut carry = 0_u128;
        for limb in &mut limbs {
            let product = *limb as u128 * factor as u128 + carry;
            *limb = product as u64;
            carry = product >> 64;
        }
        if carry != 0 {
            limbs.push(carry as u64);
        }
    }
    while limbs.len() > 1 && limbs.last() == Some(&0) {
        limbs.pop();
    }
    match limbs.last().copied() {
        None | Some(0) => 0,
        Some(high) => (limbs.len() as u64 - 1) * 64 + u64::from(64 - high.leading_zeros()),
    }
}

fn timestamp() -> String {
    let elapsed = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default();
    format!("{}s_since_epoch", elapsed.as_secs())
}

fn main() {
    let args = parse_args();
    let config = select_config(&args.config);
    let a = args.a % config.t;
    let b = args.b % config.t;
    let mut rng = ShadowHarvester::with_seed(args.seed);

    let ntt = NTTEngine::new(config.q, config.n);
    let legacy_keygen_started = Instant::now();
    let legacy_keys = KeySet::generate(&config, &ntt, &mut rng);
    let legacy_keygen_ns = legacy_keygen_started
        .elapsed()
        .as_nanos()
        .min(u64::MAX as u128) as u64;
    let encoder = BFVEncoder::new(&config);
    let encryptor = BFVEncryptor::new(
        &legacy_keys.public_key,
        &encoder,
        &ntt,
        config.eta,
    );
    let decryptor = BFVDecryptor::new(&legacy_keys.secret_key, &encoder, &ntt);
    let evaluator = BFVEvaluator::new(&ntt, &encoder, Some(&legacy_keys.eval_key));

    let mut legacy_a = encryptor.encrypt(a, &mut rng);
    let legacy_encrypt_ns = average_ns(args.iterations, || {
        legacy_a = black_box(encryptor.encrypt(a, &mut rng));
    });
    let legacy_b = encryptor.encrypt(b, &mut rng);
    let legacy_decrypt_ns = average_ns(args.iterations, || {
        black_box(decryptor.decrypt(&legacy_a));
    });
    let legacy_add_ns = average_ns(args.iterations, || {
        black_box(evaluator.add(&legacy_a, &legacy_b));
    });
    let legacy_sub_ns = average_ns(args.iterations, || {
        black_box(evaluator.sub(&legacy_a, &legacy_b));
    });
    let legacy_negate_ns = average_ns(args.iterations, || {
        black_box(evaluator.negate(&legacy_a));
    });
    let legacy_add_plain_ns = average_ns(args.iterations, || {
        black_box(evaluator.add_plain(&legacy_a, b));
    });
    let legacy_mul_plain_ns = average_ns(args.iterations, || {
        black_box(evaluator.mul_plain(&legacy_a, b));
    });
    #[allow(deprecated)]
    let legacy_mul_ns = average_ns(args.mul_iterations, || {
        black_box(evaluator.mul(&legacy_a, &legacy_b));
    });
    #[allow(deprecated)]
    let legacy_mul_correct = decryptor.decrypt(&evaluator.mul(&legacy_a, &legacy_b))
        == (a * b) % config.t;

    let legacy_correctness = json!({
        "encrypt": decryptor.decrypt(&legacy_a) == a,
        "decrypt": decryptor.decrypt(&legacy_a) == a,
        "add_ct": decryptor.decrypt(&evaluator.add(&legacy_a, &legacy_b)) == (a + b) % config.t,
        "sub_ct": decryptor.decrypt(&evaluator.sub(&legacy_a, &legacy_b)) == (a + config.t - b) % config.t,
        "negate_ct": decryptor.decrypt(&evaluator.negate(&legacy_a)) == (config.t - a) % config.t,
        "add_plain": decryptor.decrypt(&evaluator.add_plain(&legacy_a, b)) == (a + b) % config.t,
        "mul_plain": decryptor.decrypt(&evaluator.mul_plain(&legacy_a, b)) == (a * b) % config.t,
        "mul_ct": legacy_mul_correct,
    });

    let dual = RNSFHEContext::new(&config);
    let dual_keygen_started = Instant::now();
    let dual_keys = dual.generate_keys_dual_full(&mut rng);
    let dual_keygen_ns = dual_keygen_started
        .elapsed()
        .as_nanos()
        .min(u64::MAX as u128) as u64;
    let mut dual_a = dual.encrypt_dual(a, &dual_keys.public_key, &mut rng);
    let dual_encrypt_ns = average_ns(args.iterations, || {
        dual_a = black_box(dual.encrypt_dual(a, &dual_keys.public_key, &mut rng));
    });
    let dual_b = dual.encrypt_dual(b, &dual_keys.public_key, &mut rng);
    let dual_decrypt_ns = average_ns(args.iterations, || {
        black_box(dual.decrypt_dual(&dual_a, &dual_keys.secret_key));
    });
    let dual_add_ns = average_ns(args.iterations, || {
        black_box(dual.add_dual(&dual_a, &dual_b));
    });
    let dual_add_plain_ns = average_ns(args.iterations, || {
        black_box(dual.add_plain_dual(&dual_a, b));
    });
    let dual_mul_plain_ns = average_ns(args.iterations, || {
        black_box(dual.mul_plain_dual(&dual_a, b));
    });
    let dual_mul_ns = average_ns(args.mul_iterations, || {
        black_box(
            dual.mul_dual_public(&dual_a, &dual_b, &dual_keys.eval_key)
                .expect("DualRNS multiplication failed"),
        );
    });
    let dual_mul_correct = dual
        .mul_dual_public(&dual_a, &dual_b, &dual_keys.eval_key)
        .map(|ciphertext| {
            dual.decrypt_dual(&ciphertext, &dual_keys.secret_key) == (a * b) % config.t
        })
        .unwrap_or(false);
    let dual_correctness = json!({
        "encrypt": dual.decrypt_dual(&dual_a, &dual_keys.secret_key) == a,
        "decrypt": dual.decrypt_dual(&dual_a, &dual_keys.secret_key) == a,
        "add_ct": dual.decrypt_dual(&dual.add_dual(&dual_a, &dual_b), &dual_keys.secret_key) == (a + b) % config.t,
        "add_plain": dual.decrypt_dual(&dual.add_plain_dual(&dual_a, b), &dual_keys.secret_key) == (a + b) % config.t,
        "mul_plain": dual.decrypt_dual(&dual.mul_plain_dual(&dual_a, b), &dual_keys.secret_key) == (a * b) % config.t,
        "mul_ct": dual_mul_correct,
    });

    let mut depth_ciphertext = dual.encrypt_dual(a, &dual_keys.public_key, &mut rng);
    let mut depth_expected = a;
    let mut depth_entries = Vec::with_capacity(args.ct_mul_depth);
    let mut depth_error: Option<String> = None;
    for depth in 1..=args.ct_mul_depth {
        let level_before = depth_ciphertext.level;
        let started = Instant::now();
        match dual.mul_dual_public(
            &depth_ciphertext,
            &depth_ciphertext,
            &dual_keys.eval_key,
        ) {
            Ok(next) => {
                let operation_ns = started
                    .elapsed()
                    .as_nanos()
                    .min(u64::MAX as u128) as u64;
                depth_ciphertext = next;
                depth_expected = (depth_expected * depth_expected) % config.t;
                let decrypted = dual.decrypt_dual(&depth_ciphertext, &dual_keys.secret_key);
                let correct = decrypted == depth_expected;
                depth_entries.push(json!({
                    "depth": depth,
                    "operation_ns": operation_ns,
                    "level_before": level_before,
                    "level_after": depth_ciphertext.level,
                    "expected": depth_expected,
                    "decrypted": decrypted,
                    "mismatch_delta_mod_t": (decrypted + config.t - depth_expected) % config.t,
                    "correct": correct,
                }));
                if !correct {
                    depth_error = Some(format!("correctness mismatch at depth {depth}"));
                    break;
                }
            }
            Err(error) => {
                let operation_ns = started
                    .elapsed()
                    .as_nanos()
                    .min(u64::MAX as u128) as u64;
                depth_entries.push(json!({
                    "depth": depth,
                    "operation_ns": operation_ns,
                    "level_before": level_before,
                    "operation_error": error.to_string(),
                    "correct": false,
                }));
                depth_error = Some(format!("operation error at depth {depth}: {error}"));
                break;
            }
        }
    }

    let legacy_all_correct = legacy_correctness
        .as_object()
        .into_iter()
        .flat_map(|object| object.values())
        .all(|value| value.as_bool() == Some(true));
    let dual_all_correct = dual_correctness
        .as_object()
        .into_iter()
        .flat_map(|object| object.values())
        .all(|value| value.as_bool() == Some(true));
    let depth_all_correct = depth_entries
        .iter()
        .all(|entry| entry.get("correct").and_then(serde_json::Value::as_bool) == Some(true));

    let output = json!({
        "schema": "nine65-comparative-probe-v1",
        "status": if legacy_all_correct && dual_all_correct { "PASS" } else { "FAIL" },
        "metadata": {
            "timestamp": timestamp(),
            "config": args.config,
            "n": config.n,
            "rns_primes": config.primes,
            "exact_log_q_bits": exact_product_bit_length(&config.primes),
            "plaintext_modulus": config.t,
            "eta": config.eta,
            "security_claim_bits": config.security_bits,
            "comparison_only_parameter_set": config.name == "v6_compat_4096",
            "seed": args.seed,
            "iterations": args.iterations,
            "mul_iterations": args.mul_iterations,
            "allow_insecure_feature": cfg!(feature = "allow_insecure"),
            "crate_version": env!("CARGO_PKG_VERSION"),
        },
        "keygen_ns": {
            "legacy": legacy_keygen_ns,
            "dual_rns": dual_keygen_ns,
        },
        "operations_ns": {
            "legacy": {
                "encrypt": legacy_encrypt_ns,
                "decrypt": legacy_decrypt_ns,
                "add_ct": legacy_add_ns,
                "sub_ct": legacy_sub_ns,
                "negate_ct": legacy_negate_ns,
                "add_plain": legacy_add_plain_ns,
                "mul_plain": legacy_mul_plain_ns,
                "mul_ct": legacy_mul_ns,
            },
            "dual_rns": {
                "encrypt": dual_encrypt_ns,
                "decrypt": dual_decrypt_ns,
                "add_ct": dual_add_ns,
                "add_plain": dual_add_plain_ns,
                "mul_plain": dual_mul_plain_ns,
                "mul_ct": dual_mul_ns,
            },
        },
        "correctness": {
            "legacy": legacy_correctness,
            "dual_rns": dual_correctness,
        },
        "ct_mul_depth": {
            "requested": args.ct_mul_depth,
            "completed": depth_entries.len(),
            "all_completed_entries_correct": depth_all_correct,
            "first_error": depth_error,
            "entries": depth_entries,
        },
        "key_structure": {
            "relinearization_components": dual_keys.eval_key.rlk.len(),
            "decomposition_base": dual_keys.eval_key.decomp_base,
            "decomposition_digits": dual_keys.eval_key.num_digits,
        },
    });

    let rendered = serde_json::to_string_pretty(&output).expect("serialize probe output");
    if let Some(path) = args.output {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).expect("create output directory");
        }
        std::fs::write(path, rendered.as_bytes()).expect("write probe output");
    }
    println!("{rendered}");
    if !legacy_all_correct || !dual_all_correct {
        std::process::exit(1);
    }
}
