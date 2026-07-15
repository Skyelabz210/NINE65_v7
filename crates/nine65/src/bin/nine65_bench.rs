//! NINE65 exact-integer benchmark and correctness harness.
//!
//! The mixed chain reported here is an **operation-count chain** containing
//! ciphertext-plaintext operations. It is not ciphertext-ciphertext
//! multiplicative depth. Unbootstrapped runs stop when the modeled noise budget
//! cannot fund the next operation. The harness never resets a budget without
//! performing a real ciphertext refresh.

use nine65::noise::budget::{NoiseBudget, NoiseOpType};
use nine65::ops::bootstrap::ClockworkBootstrap;
use nine65::ops::rns_fhe::RNSFHEContext;
use nine65::prelude::*;
use serde_json::{json, Value};
use std::time::{Instant, SystemTime};

fn percent_floor(remaining: i64, total: i64) -> u64 {
    if remaining <= 0 || total <= 0 {
        0
    } else {
        ((remaining as u128 * 100) / total as u128) as u64
    }
}

fn rate_per_second(count: u64, elapsed_us: u64) -> u64 {
    if elapsed_us == 0 {
        0
    } else {
        ((count as u128 * 1_000_000) / elapsed_us as u128) as u64
    }
}

fn usage() {
    eprintln!(
        "Usage: nine65_bench [OPTIONS]\n\n\
         Options:\n\
         --config <name>      secure_128 (default), secure_128_deep, secure_192, secure_256\n\
         --max-depth <n>      Requested mixed-operation count (default: 80)\n\
         --output <path>      Output JSON file (default: stdout)\n\
         --a <u64>            First operand (default: 8)\n\
         --b <u64>            Second operand (default: 8)\n\
         --with-bootstrap     Enable real Clockwork Bootstrap\n\
         --auto-bootstrap     Enable threshold-triggered real bootstrap\n\
         --statistical-test   Run 100 real-bootstrap correctness trials\n\
         --trigger-pct <n>    Refresh threshold in percent (default: 25)"
    );
}

fn select_config(name: &str) -> FHEConfig {
    match name {
        "secure_128" | "standard_128" => SecureConfig::secure_128().into_config(),
        "secure_128_deep" => SecureConfig::secure_128_deep().into_config(),
        "secure_192" | "high_192" => SecureConfig::secure_192().into_config(),
        "secure_256" => SecureConfig::secure_256().into_config(),
        other => {
            eprintln!("Unknown config: {other}");
            std::process::exit(2);
        }
    }
}

fn main() {
    let mut config_name = String::from("secure_128");
    let mut requested_operations: usize = 80;
    let mut output_path: Option<String> = None;
    let mut init_a: u64 = 8;
    let mut init_b: u64 = 8;
    let mut with_bootstrap = false;
    let mut auto_bootstrap = false;
    let mut statistical_test = false;
    let mut trigger_pct: u32 = 25;
    let seed: u64 = 42;

    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--config" => config_name = args.next().unwrap_or_default(),
            "--max-depth" => {
                requested_operations = args
                    .next()
                    .unwrap_or_default()
                    .parse()
                    .unwrap_or(80);
            }
            "--output" | "-o" => output_path = args.next(),
            "--a" => init_a = args.next().unwrap_or_default().parse().unwrap_or(8),
            "--b" => init_b = args.next().unwrap_or_default().parse().unwrap_or(8),
            "--with-bootstrap" => with_bootstrap = true,
            "--auto-bootstrap" => auto_bootstrap = true,
            "--statistical-test" => statistical_test = true,
            "--trigger-pct" => {
                trigger_pct = args.next().unwrap_or_default().parse().unwrap_or(25)
            }
            "-h" | "--help" => {
                usage();
                return;
            }
            _ => {
                eprintln!("Unknown flag: {arg}");
                usage();
                std::process::exit(2);
            }
        }
    }

    if requested_operations == 0 {
        eprintln!("--max-depth must be positive");
        std::process::exit(2);
    }
    if trigger_pct > 100 {
        eprintln!("--trigger-pct must be in 0..=100");
        std::process::exit(2);
    }

    // Statistical verification and auto mode both require actual key material
    // and actual refreshes. Neither mode is permitted to simulate a refresh.
    if auto_bootstrap || statistical_test {
        with_bootstrap = true;
    }

    let config = select_config(&config_name);
    let trigger_permille = trigger_pct * 10;

    eprintln!("NINE65 exact benchmark harness");
    eprintln!(
        "Config: {} (n={}, lanes={}, q0={}, t={})",
        config_name,
        config.n,
        config.primes.len(),
        config.q,
        config.t
    );
    eprintln!("Requested mixed operations: {requested_operations}");
    eprintln!(
        "Bootstrap: {}",
        if with_bootstrap { "real" } else { "disabled" }
    );

    let ntt = NTTEngine::new(config.q, config.n);
    let mut rng = ShadowHarvester::with_seed(seed);

    let keygen_start = Instant::now();
    let keys = KeySet::generate(&config, &ntt, &mut rng);
    let keygen_us = keygen_start.elapsed().as_micros() as u64;

    let encoder = BFVEncoder::new(&config);
    let encryptor = BFVEncryptor::new(&keys.public_key, &encoder, &ntt, config.eta);
    let decryptor = BFVDecryptor::new(&keys.secret_key, &encoder, &ntt);
    let evaluator = BFVEvaluator::new(&ntt, &encoder, Some(&keys.eval_key));

    let iterations: u64 = 100;

    let start = Instant::now();
    let mut ct_a = encryptor.encrypt(init_a % config.t, &mut rng);
    for _ in 1..iterations {
        ct_a = encryptor.encrypt(init_a % config.t, &mut rng);
    }
    let encrypt_us = start.elapsed().as_micros() as u64 / iterations;
    let ct_b = encryptor.encrypt(init_b % config.t, &mut rng);

    let start = Instant::now();
    for _ in 0..iterations {
        let _ = decryptor.decrypt(&ct_a);
    }
    let decrypt_us = start.elapsed().as_micros() as u64 / iterations;

    let start = Instant::now();
    for _ in 0..iterations {
        let _ = evaluator.add(&ct_a, &ct_b);
    }
    let add_us = start.elapsed().as_micros() as u64 / iterations;

    let start = Instant::now();
    for _ in 0..iterations {
        let _ = evaluator.sub(&ct_a, &ct_b);
    }
    let sub_us = start.elapsed().as_micros() as u64 / iterations;

    let start = Instant::now();
    for _ in 0..iterations {
        let _ = evaluator.negate(&ct_a);
    }
    let negate_us = start.elapsed().as_micros() as u64 / iterations;

    let start = Instant::now();
    for _ in 0..iterations {
        let _ = evaluator.add_plain(&ct_a, 10 % config.t);
    }
    let add_plain_us = start.elapsed().as_micros() as u64 / iterations;

    let start = Instant::now();
    for _ in 0..iterations {
        let _ = evaluator.mul_plain(&ct_a, 3);
    }
    let mul_plain_us = start.elapsed().as_micros() as u64 / iterations;

    #[allow(deprecated)]
    let mul_us = {
        let start = Instant::now();
        for _ in 0..iterations {
            let _ = evaluator.mul(&ct_a, &ct_b);
        }
        start.elapsed().as_micros() as u64 / iterations
    };

    let ctx = RNSFHEContext::new(&config);
    let dual_keys = ctx.generate_keys_dual_full(&mut rng);

    let bootstrap = if with_bootstrap {
        Some(ClockworkBootstrap::new(&config).expect("bootstrap initialization failed"))
    } else {
        None
    };
    let bootstrap_keys = if let Some(ref engine) = bootstrap {
        let started = Instant::now();
        let generated = engine
            .generate_keys(&dual_keys.secret_key, &mut rng)
            .expect("bootstrap key generation failed");
        eprintln!("Bootstrap key generation: {}us", started.elapsed().as_micros());
        Some(generated)
    } else {
        None
    };

    let chain_ops: [(&str, u64); 20] = [
        ("mul_plain", 3),
        ("add_plain", 2),
        ("mul_plain", 5),
        ("add_plain", 13),
        ("sub_plain", 7),
        ("mul_plain", 2),
        ("add_plain", 11),
        ("mul_plain", 4),
        ("add_plain", 9),
        ("sub_plain", 3),
        ("mul_plain", 7),
        ("add_plain", 17),
        ("mul_plain", 3),
        ("sub_plain", 8),
        ("add_plain", 6),
        ("mul_plain", 9),
        ("sub_plain", 1),
        ("add_plain", 23),
        ("mul_plain", 2),
        ("add_plain", 5),
    ];

    let mut budget = NoiseBudget::from_config(&config);
    let initial_budget_mb = budget.remaining_millibits();
    let mut ciphertext = ctx.encrypt_dual(init_a % config.t, &dual_keys.public_key, &mut rng);
    let _ = budget.consume(NoiseOpType::Encrypt, NoiseBudget::encrypt_cost(&config));
    let mut plaintext = init_a % config.t;
    let mut entries: Vec<Value> = Vec::with_capacity(requested_operations);
    let mut refreshes: u64 = 0;
    let chain_start = Instant::now();

    for index in 0..requested_operations {
        let (operation, operand) = if index == 0 {
            ("mul_plain", init_b % config.t)
        } else {
            chain_ops[(index - 1) % chain_ops.len()]
        };

        let (noise_type, noise_cost) = match operation {
            "mul_plain" => (
                NoiseOpType::MulPlain,
                NoiseBudget::mul_plain_cost(&config),
            ),
            _ => (NoiseOpType::Add, NoiseBudget::add_plain_cost()),
        };

        let needs_refresh = budget.remaining_millibits() < noise_cost
            || (with_bootstrap && budget.should_bootstrap(trigger_permille));

        if needs_refresh {
            if let (Some(engine), Some(keys)) = (bootstrap.as_ref(), bootstrap_keys.as_ref()) {
                ciphertext = engine
                    .bootstrap(&ciphertext, &keys.bsk, &keys.ksk)
                    .expect("real bootstrap failed");
                budget.reset_after_bootstrap(&config);
                refreshes += 1;
            } else {
                eprintln!(
                    "Stopped before operation {}: modeled noise budget cannot fund the next operation",
                    index + 1
                );
                break;
            }
        }

        let op_start = Instant::now();
        match operation {
            "mul_plain" => {
                ciphertext = ctx.mul_plain_dual(&ciphertext, operand);
                plaintext = (plaintext * operand) % config.t;
            }
            "add_plain" => {
                ciphertext = ctx.add_plain_dual(&ciphertext, operand % config.t);
                plaintext = (plaintext + operand) % config.t;
            }
            "sub_plain" => {
                let encoded_subtrahend = (config.t - (operand % config.t)) % config.t;
                ciphertext = ctx.add_plain_dual(&ciphertext, encoded_subtrahend);
                plaintext = (plaintext + encoded_subtrahend) % config.t;
            }
            _ => unreachable!(),
        }
        let elapsed_us = op_start.elapsed().as_micros() as u64;

        budget
            .consume(noise_type, noise_cost)
            .expect("preflighted noise consumption must succeed");

        entries.push(json!({
            "operation_index": index + 1,
            "operation": operation,
            "operand": operand,
            "elapsed_us": elapsed_us,
            "noise_budget_pct": percent_floor(
                budget.remaining_millibits(),
                initial_budget_mb,
            ),
            "real_refreshes_so_far": refreshes,
        }));
    }

    let chain_us = chain_start.elapsed().as_micros() as u64;
    let operations_achieved = entries.len();
    let decrypted = ctx.decrypt_dual(&ciphertext, &dual_keys.secret_key);
    let achieved_chain_correct = decrypted == plaintext;
    let completed_requested = operations_achieved == requested_operations;

    let statistical_summary = if statistical_test {
        let engine = bootstrap.as_ref().expect("statistical test bootstrap engine");
        let keys = bootstrap_keys
            .as_ref()
            .expect("statistical test bootstrap keys");
        let mut successes: u64 = 0;
        let mut statistical_refreshes: u64 = 0;

        for _ in 0..100u64 {
            let mut expected = rng.next_u64() % config.t;
            let mut ct = ctx.encrypt_dual(expected, &dual_keys.public_key, &mut rng);
            let mut trial_budget = NoiseBudget::from_config(&config);
            let _ = trial_budget.consume(
                NoiseOpType::Encrypt,
                NoiseBudget::encrypt_cost(&config),
            );

            for step in 0..80usize {
                let (_, operand) = chain_ops[step % chain_ops.len()];
                let (kind, cost) = if step % 3 == 0 {
                    (
                        NoiseOpType::MulPlain,
                        NoiseBudget::mul_plain_cost(&config),
                    )
                } else {
                    (NoiseOpType::Add, NoiseBudget::add_plain_cost())
                };

                if trial_budget.remaining_millibits() < cost
                    || trial_budget.should_bootstrap(trigger_permille)
                {
                    ct = engine
                        .bootstrap(&ct, &keys.bsk, &keys.ksk)
                        .expect("statistical bootstrap failed");
                    trial_budget.reset_after_bootstrap(&config);
                    statistical_refreshes += 1;
                }

                if step % 3 == 0 {
                    ct = ctx.mul_plain_dual(&ct, operand);
                    expected = (expected * operand) % config.t;
                } else {
                    ct = ctx.add_plain_dual(&ct, operand % config.t);
                    expected = (expected + operand) % config.t;
                }
                trial_budget
                    .consume(kind, cost)
                    .expect("preflighted statistical budget consumption");
            }

            if ctx.decrypt_dual(&ct, &dual_keys.secret_key) == expected {
                successes += 1;
            }
        }

        if successes != 100 {
            eprintln!("Statistical correctness failed: {successes}/100");
            std::process::exit(1);
        }

        json!({
            "enabled": true,
            "successes": successes,
            "trials": 100,
            "real_refreshes": statistical_refreshes,
        })
    } else {
        json!({"enabled": false})
    };

    let scale_tests = json!({
        "deep_arithmetic": run_scale_test(
            &config,
            &encryptor,
            &evaluator,
            &mut rng,
            80,
            "arithmetic",
        ),
        "statistical_pipeline": run_scale_test(
            &config,
            &encryptor,
            &evaluator,
            &mut rng,
            60,
            "statistical",
        ),
        "neural_network": run_scale_test(
            &config,
            &encryptor,
            &evaluator,
            &mut rng,
            50,
            "neural_network",
        ),
        "polynomial_eval": run_scale_test(
            &config,
            &encryptor,
            &evaluator,
            &mut rng,
            128,
            "polynomial",
        ),
    });

    let average_chain_us = if operations_achieved == 0 {
        0
    } else {
        chain_us / operations_achieved as u64
    };
    let chain_ops_per_second = rate_per_second(operations_achieved as u64, chain_us);
    let min_noise = entries
        .iter()
        .filter_map(|entry| entry.get("noise_budget_pct").and_then(Value::as_u64))
        .min()
        .unwrap_or(percent_floor(
            budget.remaining_millibits(),
            initial_budget_mb,
        ));

    let output = json!({
        "metadata": {
            "timestamp": chrono_lite(),
            "config": config_name,
            "n": config.n,
            "rns_primes": config.primes,
            "q_primary": config.q,
            "t": config.t,
            "eta": config.eta,
            "security_claim_bits": config.security_bits,
            "seed": seed,
            "requested_operation_count": requested_operations,
            "chain_semantics": "mixed ciphertext-plaintext operation count; not ciphertext-ciphertext multiplicative depth",
            "bootstrap_mode": if with_bootstrap { "real" } else { "disabled" },
            "nine65_version": env!("CARGO_PKG_VERSION"),
        },
        "keygen_us": keygen_us,
        "operations": {
            "encrypt_us": encrypt_us,
            "decrypt_us": decrypt_us,
            "add_us": add_us,
            "sub_us": sub_us,
            "negate_us": negate_us,
            "add_plain_us": add_plain_us,
            "mul_plain_us": mul_plain_us,
            "legacy_single_modulus_mul_us": mul_us,
        },
        "operation_chain": {
            "requested_operations": requested_operations,
            "operations_achieved": operations_achieved,
            "completed_requested": completed_requested,
            "achieved_chain_correct": achieved_chain_correct,
            "decrypted_result": decrypted,
            "expected_result": plaintext,
            "real_refreshes": refreshes,
            "elapsed_us": chain_us,
            "entries": entries,
        },
        "statistical_test": statistical_summary,
        "scale_tests": scale_tests,
        "speedometer_summary": {
            "average_chain_ops_per_sec": chain_ops_per_second,
            "average_chain_latency_us": average_chain_us,
            "operations_achieved": operations_achieved,
            "noise_budget_min_pct": min_noise,
            "real_refreshes": refreshes,
        },
    });

    let json_text = serde_json::to_string_pretty(&output).expect("JSON serialization failed");
    if let Some(path) = output_path {
        std::fs::write(&path, json_text).expect("failed to write benchmark output");
        eprintln!("Output written to {path}");
    } else {
        println!("{json_text}");
    }

    eprintln!(
        "Completed: achieved {operations_achieved}/{requested_operations} operations, correctness={}, real refreshes={refreshes}",
        achieved_chain_correct
    );
}

fn run_scale_test(
    config: &FHEConfig,
    encryptor: &BFVEncryptor,
    evaluator: &BFVEvaluator,
    rng: &mut ShadowHarvester,
    requested_operations: usize,
    workload: &str,
) -> Value {
    let mut budget = NoiseBudget::from_config(config);
    let initial_budget = budget.remaining_millibits();
    let mut ciphertext = encryptor.encrypt(42 % config.t, rng);
    let _ = budget.consume(NoiseOpType::Encrypt, NoiseBudget::encrypt_cost(config));
    let started = Instant::now();
    let mut achieved: u64 = 0;

    for index in 0..requested_operations {
        let (kind, cost) = match workload {
            "arithmetic" if index % 3 == 0 => (
                NoiseOpType::MulPlain,
                NoiseBudget::mul_plain_cost(config),
            ),
            "neural_network" if index % 2 == 0 => (
                NoiseOpType::MulPlain,
                NoiseBudget::mul_plain_cost(config),
            ),
            "polynomial" if index % 2 == 0 => (
                NoiseOpType::MulPlain,
                NoiseBudget::mul_plain_cost(config),
            ),
            _ => (NoiseOpType::Add, NoiseBudget::add_plain_cost()),
        };

        if budget.remaining_millibits() < cost {
            break;
        }

        ciphertext = match kind {
            NoiseOpType::MulPlain => evaluator.mul_plain(&ciphertext, 3),
            _ => evaluator.add_plain(&ciphertext, ((index as u64) + 1) % config.t),
        };
        budget
            .consume(kind, cost)
            .expect("preflighted scale-test budget consumption");
        achieved += 1;
    }

    let elapsed_us = started.elapsed().as_micros() as u64;
    json!({
        "workload": workload,
        "requested_operations": requested_operations,
        "operations_achieved": achieved,
        "completed_requested": achieved == requested_operations as u64,
        "elapsed_us": elapsed_us,
        "operations_per_sec": rate_per_second(achieved, elapsed_us),
        "simulated_refreshes": 0,
        "final_noise_pct": percent_floor(budget.remaining_millibits(), initial_budget),
    })
}

fn chrono_lite() -> String {
    use std::time::SystemTime;
    let duration = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default();
    format!("{}s_since_epoch", duration.as_secs())
}
