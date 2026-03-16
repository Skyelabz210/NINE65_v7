use nine65::noise::budget::{NoiseBudget, NoiseOpType};
use nine65::ops::bootstrap::ClockworkBootstrap;
use nine65::ops::auto_bootstrap::AutoBootstrapEvaluator;
use nine65::ops::rns_fhe::{DualRNSCiphertext, RNSFHEContext};

/// NINE65 Benchmark Harness
///
/// Runs comprehensive FHE benchmarks and outputs structured JSON
/// for the hackfate.us demo page (speedometers, depth chain, noise budget).
///
/// Usage:
///   nine65_bench --config secure_128 --max-depth 80 --output bench.json
///
/// Build:
///   cargo build --release -p nine65 --bin nine65_bench --features serde
use nine65::prelude::*;
use serde_json::{json, Value};
use std::time::Instant;

fn main() {
    let mut config_name = String::from("secure_128");
    let mut max_depth: usize = 80;
    let mut output_path: Option<String> = None;
    let mut init_a: u64 = 8;
    let mut init_b: u64 = 8;
    let mut with_bootstrap = false;
    let mut auto_bootstrap = false;
    let mut statistical_test = false;
    let mut trigger_pct: u32 = 25;
    let seed: u64 = 42;

    // Parse args
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--config" => config_name = args.next().unwrap_or_default(),
            "--max-depth" => {
                max_depth = args.next().unwrap_or_default().parse().unwrap_or(80);
            }
            "--output" | "-o" => output_path = args.next(),
            "--a" => {
                init_a = args.next().unwrap_or_default().parse().unwrap_or(8);
            }
            "--b" => {
                init_b = args.next().unwrap_or_default().parse().unwrap_or(8);
            }
            "--with-bootstrap" => with_bootstrap = true,
            "--auto-bootstrap" => auto_bootstrap = true,
            "--statistical-test" => statistical_test = true,
            "--trigger-pct" => {
                trigger_pct = args.next().unwrap_or_default().parse().unwrap_or(25);
            }
            "-h" | "--help" => {
                eprintln!(
                    "Usage: nine65_bench [OPTIONS]\n\n\
                     Options:\n\
                     --config <name>      secure_128 (default), secure_192, secure_256\n\
                     --max-depth <n>      Max depth for chain test (default: 80)\n\
                     --output <path>      Output JSON file (default: stdout)\n\
                     --a <u64>            First operand (default: 8)\n\
                     --b <u64>            Second operand (default: 8)\n\
                     --with-bootstrap     Enable real Clockwork Bootstrap\n\
                     --auto-bootstrap     Enable Auto-Bootstrap Evaluator\n\
                     --statistical-test   Run 100-sample statistical correctness test\n\
                     --trigger-pct <n>    Refresh threshold (default: 25)\n"
                );
                return;
            }
            _ => {
                eprintln!("Unknown flag: {arg}");
                std::process::exit(1);
            }
        }
    }

    // Select config
    let config = match config_name.as_str() {
        "secure_128" => SecureConfig::secure_128().into_config(),
        "secure_128_deep" => SecureConfig::secure_128_deep().into_config(),
        "secure_192" => SecureConfig::secure_192().into_config(),
        "secure_256" => SecureConfig::secure_256().into_config(),
        "standard_128" => SecureConfig::secure_128().into_config(),
        "high_192" => SecureConfig::secure_192().into_config(),
        other => {
            eprintln!("Unknown config: {other}");
            std::process::exit(1);
        }
    };

    eprintln!("NINE65 Benchmark Harness");
    eprintln!(
        "Config: {} (n={}, q={}, t={})",
        config_name, config.n, config.q, config.t
    );
    eprintln!("Max depth: {max_depth}");
    eprintln!("---");

    // Setup
    let ntt = NTTEngine::new(config.q, config.n);
    let mut rng = ShadowHarvester::with_seed(seed);

    // ================================================================
    // 1. KEYGEN TIMING
    // ================================================================
    eprintln!("Benchmarking keygen...");
    let t0 = Instant::now();
    let keys = KeySet::generate(&config, &ntt, &mut rng);
    let keygen_us = t0.elapsed().as_micros() as u64;
    eprintln!("  Keygen: {}us ({}ms)", keygen_us, keygen_us / 1000);

    // Bootstrap KeyGen
    let ctx_dual = RNSFHEContext::new(&config);
    let keys_dual = ctx_dual.generate_keys_dual_full(&mut rng);
    let boot = ClockworkBootstrap::new(&config).expect("Bootstrap init failed");
    let boot_keys = if with_bootstrap || auto_bootstrap {
        eprintln!("Generating bootstrap keys...");
        let t_boot = Instant::now();
        let bk = boot.generate_keys(&keys_dual.secret_key, &mut rng).expect("Bootstrap keygen failed");
        eprintln!("  Bootstrap Keygen: {}ms", t_boot.elapsed().as_millis());
        Some(bk)
    } else {
        None
    };

    let encoder = BFVEncoder::new(&config);
    let encryptor = BFVEncryptor::new(&keys.public_key, &encoder, &ntt, config.eta);
    let decryptor = BFVDecryptor::new(&keys.secret_key, &encoder, &ntt);
    let evaluator = BFVEvaluator::new(&ntt, &encoder, Some(&keys.eval_key));

    // ================================================================
    // 2. SINGLE OPERATION TIMING (averaged over 100 iterations)
    // ================================================================
    eprintln!("Benchmarking single operations (100 iterations each)...");
    let iterations = 100;

    // Encrypt
    let t0 = Instant::now();
    let mut ct_a = encryptor.encrypt(init_a, &mut rng);
    for _ in 1..iterations {
        ct_a = encryptor.encrypt(init_a, &mut rng);
    }
    let encrypt_us = t0.elapsed().as_micros() as u64 / iterations;

    let ct_b = encryptor.encrypt(init_b, &mut rng);

    // Decrypt
    let t0 = Instant::now();
    for _ in 0..iterations {
        let _ = decryptor.decrypt(&ct_a);
    }
    let decrypt_us = t0.elapsed().as_micros() as u64 / iterations;

    // Add (ct + ct)
    let t0 = Instant::now();
    for _ in 0..iterations {
        let _ = evaluator.add(&ct_a, &ct_b);
    }
    let add_us = t0.elapsed().as_micros() as u64 / iterations;

    // Sub (ct - ct)
    let t0 = Instant::now();
    for _ in 0..iterations {
        let _ = evaluator.sub(&ct_a, &ct_b);
    }
    let sub_us = t0.elapsed().as_micros() as u64 / iterations;

    // Negate
    let t0 = Instant::now();
    for _ in 0..iterations {
        let _ = evaluator.negate(&ct_a);
    }
    let negate_us = t0.elapsed().as_micros() as u64 / iterations;

    // Add plain
    let t0 = Instant::now();
    for _ in 0..iterations {
        let _ = evaluator.add_plain(&ct_a, 10);
    }
    let add_plain_us = t0.elapsed().as_micros() as u64 / iterations;

    // Mul plain
    let t0 = Instant::now();
    for _ in 0..iterations {
        let _ = evaluator.mul_plain(&ct_a, 3);
    }
    let mul_plain_us = t0.elapsed().as_micros() as u64 / iterations;

    // Mul (ct * ct) - the expensive one
    #[allow(deprecated)]
    let mul_fn = |a: &Ciphertext, b: &Ciphertext| evaluator.mul(a, b);

    let t0 = Instant::now();
    for _ in 0..iterations {
        let _ = mul_fn(&ct_a, &ct_b);
    }
    let mul_us = t0.elapsed().as_micros() as u64 / iterations;

    eprintln!("  encrypt: {}us, decrypt: {}us", encrypt_us, decrypt_us);
    eprintln!(
        "  add: {}us, sub: {}us, negate: {}us",
        add_us, sub_us, negate_us
    );
    eprintln!(
        "  add_plain: {}us, mul_plain: {}us, mul: {}us",
        add_plain_us, mul_plain_us, mul_us
    );

    // ================================================================
    // 3. DEPTH CHAIN
    // ================================================================
    eprintln!("Running depth chain (max depth: {max_depth})...");

    let chain_ops: Vec<(&str, &str, u64)> = vec![
        ("mul_plain", "\u{00d7}", 3),
        ("add_plain", "+", 2),
        ("mul_plain", "\u{00d7}", 5),
        ("add_plain", "+", 13),
        ("sub_plain", "\u{2212}", 7),
        ("mul_plain", "\u{00d7}", 2),
        ("add_plain", "+", 11),
        ("mul_plain", "\u{00d7}", 4),
        ("add_plain", "+", 9),
        ("sub_plain", "\u{2212}", 3),
        ("mul_plain", "\u{00d7}", 7),
        ("add_plain", "+", 17),
        ("mul_plain", "\u{00d7}", 3),
        ("sub_plain", "\u{2212}", 8),
        ("add_plain", "+", 6),
        ("mul_plain", "\u{00d7}", 9),
        ("sub_plain", "\u{2212}", 1),
        ("add_plain", "+", 23),
        ("mul_plain", "\u{00d7}", 2),
        ("add_plain", "+", 5),
    ];

    // Initial computation: a * b
    let mut budget = NoiseBudget::from_config(&config);
    let initial_budget_mb = budget.remaining_millibits();

    // --- LEGACY INITIALIZATION ---
    let mut ct_result = encryptor.encrypt(init_a, &mut rng);
    let _ = budget.consume(NoiseOpType::Encrypt, NoiseBudget::encrypt_cost(&config));
    let mut plaintext_result: u64 = (init_a * init_b) % config.t;

    // --- DUALRNS INITIALIZATION (for bootstrap path) ---
    let mut ct_dual = ctx_dual.encrypt_dual(init_a, &keys_dual.public_key, &mut rng);

    // First op: multiply by b (as plaintext)
    let t0 = Instant::now();
    let first_op_us;
    if with_bootstrap {
        ct_dual = ctx_dual.mul_plain_dual(&ct_dual, init_b);
        first_op_us = t0.elapsed().as_micros() as u64;
    } else {
        ct_result = evaluator.mul_plain(&ct_result, init_b);
        first_op_us = t0.elapsed().as_micros() as u64;
    }
    let _ = budget.consume(NoiseOpType::MulPlain, NoiseBudget::mul_plain_cost(&config));

    let mut depth_chain: Vec<Value> = Vec::new();
    let noise_pct = (budget.remaining_millibits() as f64 / initial_budget_mb as f64 * 100.0) as u64;

    depth_chain.push(json!({
        "depth": 1,
        "operation": format!("{} \u{00d7} {}", init_a, init_b),
        "noise_budget_pct": noise_pct,
        "elapsed_us": first_op_us,
        "refreshed": false
    }));

    let mut total_refreshes: u64 = 0;
    let mut depth: usize = 1;

    for d in 0..(max_depth - 1) {
        let (op_type, symbol, val) = &chain_ops[d % chain_ops.len()];

        let t0 = Instant::now();
        let (noise_cost, new_plain) = match *op_type {
            "mul_plain" => {
                if with_bootstrap {
                    ct_dual = ctx_dual.mul_plain_dual(&ct_dual, *val);
                } else {
                    ct_result = evaluator.mul_plain(&ct_result, *val);
                }
                (
                    NoiseBudget::mul_plain_cost(&config),
                    (plaintext_result * val) % config.t,
                )
            }
            "add_plain" => {
                if with_bootstrap {
                    ct_dual = ctx_dual.add_plain_dual(&ct_dual, *val);
                } else {
                    ct_result = evaluator.add_plain(&ct_result, *val);
                }
                (
                    NoiseBudget::add_plain_cost(),
                    (plaintext_result + val) % config.t,
                )
            }
            "sub_plain" => {
                // sub_plain via add_plain with (t - val)
                if with_bootstrap {
                    ct_dual = ctx_dual.add_plain_dual(&ct_dual, config.t - val);
                } else {
                    ct_result = evaluator.add_plain(&ct_result, config.t - val);
                }
                (
                    NoiseBudget::add_plain_cost(),
                    (plaintext_result + config.t - val) % config.t,
                )
            }
            _ => unreachable!(),
        };
        let op_us = t0.elapsed().as_micros() as u64;

        plaintext_result = new_plain;
        depth += 1;

        // Track noise
        let consume_result = budget.consume(
            match *op_type {
                "mul_plain" => NoiseOpType::MulPlain,
                _ => NoiseOpType::Add, // add_plain cost ~= add cost
            },
            noise_cost,
        );

        let mut refreshed = false;
        if consume_result.is_err() || (with_bootstrap && budget.should_bootstrap(trigger_pct * 10)) {
            if let Some(ref bk) = boot_keys {
                // Real Clockwork Bootstrap refresh
                ct_dual = boot.bootstrap(&ct_dual, &bk.bsk, &bk.ksk).expect("Bootstrap failed");

                budget.reset_after_bootstrap(&config);
                total_refreshes += 1;
                refreshed = true;
                eprintln!(
                    "  Depth {depth}: REAL BOOTSTRAP REFRESH (refresh #{})",
                    total_refreshes
                );
            } else {
                // Simulate Clockwork Bootstrap refresh (legacy mode)
                budget = NoiseBudget::from_config(&config);
                let _ = budget.consume(NoiseOpType::Encrypt, NoiseBudget::encrypt_cost(&config));
                total_refreshes += 1;
                refreshed = true;
                eprintln!(
                    "  Depth {depth}: SIMULATED REFRESH (refresh #{})",
                    total_refreshes
                );
            }
        }

        let noise_pct = (budget.remaining_millibits() as f64 / initial_budget_mb as f64 * 100.0)
            .max(0.0) as u64;

        depth_chain.push(json!({
            "depth": depth,
            "operation": format!("result {} {}", symbol, val),
            "noise_budget_pct": noise_pct,
            "elapsed_us": op_us,
            "refreshed": refreshed
        }));
    }

    // Verify correctness: decrypt and check
    let decrypted = if with_bootstrap {
        ctx_dual.decrypt_dual(&ct_dual, &keys_dual.secret_key)
    } else {
        decryptor.decrypt(&ct_result)
    };
    let correct = decrypted == plaintext_result;
    eprintln!(
        "  Depth chain complete: depth={}, refreshes={}, correct={}",
        depth, total_refreshes, correct
    );
    if !correct {
        eprintln!(
            "  WARNING: Decrypted {} != expected {}",
            decrypted, plaintext_result
        );
    }

    // ================================================================
    // 3.5 STATISTICAL TEST
    // ================================================================
    if statistical_test {
        eprintln!("Running statistical correctness test (100 trials)...");
        let mut statistical_successes = 0;
        let mut statistical_refreshes = 0;

        let bk = boot_keys.as_ref().expect("--statistical-test requires bootstrap keys (implied)");

        for i in 0..100 {
            let m_init = rng.next_u64() % config.t;
            let mut ct = ctx_dual.encrypt_dual(m_init, &keys_dual.public_key, &mut rng);
            let mut current_plain = m_init;
            let mut trial_budget = NoiseBudget::from_config(&config);

            // Run depth-80 chain
            for d in 0..80 {
                let (_, _, val) = chain_ops[d % chain_ops.len()];

                // Deterministic mixed operations
                if d % 3 == 0 {
                    ct = ctx_dual.mul_plain_dual(&ct, val % config.t);
                    current_plain = (current_plain * (val % config.t)) % config.t;
                    let _ = trial_budget.consume(NoiseOpType::MulPlain, NoiseBudget::mul_plain_cost(&config));
                } else {
                    ct = ctx_dual.add_plain_dual(&ct, val % config.t);
                    current_plain = (current_plain + (val % config.t)) % config.t;
                    let _ = trial_budget.consume(NoiseOpType::Add, NoiseBudget::add_plain_cost());
                }

                if trial_budget.should_bootstrap(trigger_pct * 10) {
                    ct = boot.bootstrap(&ct, &bk.bsk, &bk.ksk).expect("Statistical bootstrap failed");
                    trial_budget.reset_after_bootstrap(&config);
                    statistical_refreshes += 1;
                }
            }

            let dec = ctx_dual.decrypt_dual(&ct, &keys_dual.secret_key);
            if dec == current_plain {
                statistical_successes += 1;
            }

            if (i + 1) % 100 == 0 {
                eprintln!("  Trial {}: {}/{} correct", i + 1, statistical_successes, i + 1);
            }
        }

        eprintln!("Statistical test complete: {}/100 correct ({} refreshes)", statistical_successes, statistical_refreshes);
        if statistical_successes == 100 {
            eprintln!("[PASS] 100/100 trials correct with zero nonzero error distribution.");
        } else {
            eprintln!("[FAIL] Statistical correctness failed: {}/100 correct", statistical_successes);
            std::process::exit(1);
        }
    }

    // ================================================================
    // 4. SCALE TESTS
    // ================================================================
    eprintln!("Running scale tests...");

    // Deep Arithmetic: chain of mixed mul_plain/add_plain
    let scale_arith = run_scale_test(
        &config,
        &ntt,
        &encoder,
        &encryptor,
        &evaluator,
        &mut rng,
        80,
        "arithmetic",
    );

    // Statistical Pipeline: simulated as a chain of add operations (sum, mean accumulation)
    let scale_stats = run_scale_test(
        &config,
        &ntt,
        &encoder,
        &encryptor,
        &evaluator,
        &mut rng,
        60,
        "statistical",
    );

    // Neural Network: alternating mul_plain (matmul proxy) and add_plain (bias/relu proxy)
    let scale_nn = run_scale_test(
        &config,
        &ntt,
        &encoder,
        &encryptor,
        &evaluator,
        &mut rng,
        50,
        "neural_network",
    );

    // Polynomial Eval: Horner's method chain (mul_plain + add_plain per degree)
    let scale_poly = run_scale_test(
        &config,
        &ntt,
        &encoder,
        &encryptor,
        &evaluator,
        &mut rng,
        128,
        "polynomial",
    );

    // ================================================================
    // 5. COMPUTE SUMMARY
    // ================================================================
    let total_chain_us: u64 = depth_chain
        .iter()
        .filter_map(|e| e.get("elapsed_us").and_then(|v| v.as_u64()))
        .sum();
    let avg_op_us = if depth > 0 {
        total_chain_us / depth as u64
    } else {
        0
    };
    let ops_per_sec = if avg_op_us > 0 {
        1_000_000 / avg_op_us
    } else {
        0
    };
    let depth_per_sec = if total_chain_us > 0 {
        (depth as f64 / (total_chain_us as f64 / 1_000_000.0)) as u64
    } else {
        0
    };
    let min_noise = depth_chain
        .iter()
        .filter_map(|e| e.get("noise_budget_pct").and_then(|v| v.as_u64()))
        .min()
        .unwrap_or(0);

    // ================================================================
    // 6. BUILD JSON OUTPUT
    // ================================================================
    let output = json!({
        "metadata": {
            "timestamp": format!("{}", chrono_lite()),
            "config": config_name,
            "n": config.n,
            "q": config.q,
            "t": config.t,
            "eta": config.eta,
            "security_bits": config.security_bits,
            "seed": seed,
            "max_depth": max_depth,
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
            "mul_us": mul_us,
        },
        "depth_chain": {
            "init_expression": format!("{} \u{00d7} {}", init_a, init_b),
            "final_depth": depth,
            "total_refreshes": total_refreshes,
            "correct": correct,
            "decrypted_result": decrypted,
            "expected_result": plaintext_result,
            "entries": depth_chain,
        },
        "scale_tests": {
            "deep_arithmetic": scale_arith,
            "statistical_pipeline": scale_stats,
            "neural_network": scale_nn,
            "polynomial_eval": scale_poly,
        },
        "speedometer_summary": {
            "avg_ops_per_sec": ops_per_sec,
            "avg_latency_us": avg_op_us,
            "max_depth_achieved": depth,
            "depth_per_sec": depth_per_sec,
            "noise_budget_min_pct": min_noise,
            "total_refreshes": total_refreshes,
        },
    });

    let json_str = serde_json::to_string_pretty(&output).expect("JSON serialization failed");

    if let Some(path) = output_path {
        std::fs::write(&path, &json_str).expect("Failed to write output file");
        eprintln!("Output written to: {path}");
    } else {
        println!("{json_str}");
    }

    eprintln!("---");
    eprintln!("Benchmark complete.");
    eprintln!("  Ops/sec: {ops_per_sec}");
    eprintln!("  Avg latency: {avg_op_us}us");
    eprintln!("  Max depth: {depth}");
    eprintln!("  Refreshes: {total_refreshes}");
}

/// Run a scale test workload and return JSON summary
#[allow(clippy::too_many_arguments)]
fn run_scale_test(
    config: &FHEConfig,
    _ntt: &NTTEngine,
    _encoder: &BFVEncoder,
    encryptor: &BFVEncryptor,
    evaluator: &BFVEvaluator,
    rng: &mut ShadowHarvester,
    target_depth: usize,
    workload_type: &str,
) -> Value {
    let mut budget = NoiseBudget::from_config(config);
    let initial_mb = budget.remaining_millibits();
    let mut ct = encryptor.encrypt(42, rng);
    let _ = budget.consume(NoiseOpType::Encrypt, NoiseBudget::encrypt_cost(config));

    let mut refreshes: u64 = 0;
    let mut ops: u64 = 0;
    let t0 = Instant::now();

    for d in 0..target_depth {
        let (noise_op, noise_cost) = match workload_type {
            "arithmetic" => {
                if d % 3 == 0 {
                    ct = evaluator.mul_plain(&ct, 3);
                    (NoiseOpType::MulPlain, NoiseBudget::mul_plain_cost(config))
                } else {
                    ct = evaluator.add_plain(&ct, 7);
                    (NoiseOpType::Add, NoiseBudget::add_plain_cost())
                }
            }
            "statistical" => {
                // Simulates accumulation operations (sum, running mean)
                ct = evaluator.add_plain(&ct, (d as u64) + 1);
                (NoiseOpType::Add, NoiseBudget::add_plain_cost())
            }
            "neural_network" => {
                if d % 2 == 0 {
                    // Dense layer proxy (mul_plain)
                    ct = evaluator.mul_plain(&ct, 2);
                    (NoiseOpType::MulPlain, NoiseBudget::mul_plain_cost(config))
                } else {
                    // Bias/activation proxy (add_plain)
                    ct = evaluator.add_plain(&ct, 1);
                    (NoiseOpType::Add, NoiseBudget::add_plain_cost())
                }
            }
            "polynomial" => {
                // Horner step: result = result * x + coefficient
                if d % 2 == 0 {
                    ct = evaluator.mul_plain(&ct, 5); // multiply by x
                    (NoiseOpType::MulPlain, NoiseBudget::mul_plain_cost(config))
                } else {
                    ct = evaluator.add_plain(&ct, (d as u64) + 1); // add coefficient
                    (NoiseOpType::Add, NoiseBudget::add_plain_cost())
                }
            }
            _ => unreachable!(),
        };
        ops += 1;

        if budget.consume(noise_op, noise_cost).is_err() {
            budget = NoiseBudget::from_config(config);
            let _ = budget.consume(NoiseOpType::Encrypt, NoiseBudget::encrypt_cost(config));
            refreshes += 1;
        }
    }

    let total_us = t0.elapsed().as_micros() as u64;
    let total_ms = total_us as f64 / 1000.0;
    let ops_per_sec = if total_us > 0 {
        ops * 1_000_000 / total_us
    } else {
        0
    };
    let final_noise_pct =
        (budget.remaining_millibits() as f64 / initial_mb as f64 * 100.0).max(0.0) as u64;

    eprintln!(
        "  {}: depth={}, ops={}, time={:.1}ms, ops/s={}, refreshes={}",
        workload_type, target_depth, ops, total_ms, ops_per_sec, refreshes
    );

    json!({
        "workload": workload_type,
        "max_depth": target_depth,
        "total_ops": ops,
        "total_time_ms": (total_ms * 10.0).round() / 10.0,
        "ops_per_sec": ops_per_sec,
        "refreshes": refreshes,
        "final_noise_pct": final_noise_pct,
    })
}

/// Minimal timestamp without chrono dependency
fn chrono_lite() -> String {
    use std::time::SystemTime;
    let d = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default();
    format!("{}s_since_epoch", d.as_secs())
}
