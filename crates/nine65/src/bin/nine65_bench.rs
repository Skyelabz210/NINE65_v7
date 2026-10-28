//! NINE65 exact-integer benchmark and correctness harness.
//!
//! The mixed chain reported here is an **operation-count chain** containing
//! ciphertext-plaintext operations. It is not ciphertext-ciphertext
//! multiplicative depth. Unbootstrapped runs stop when the modeled noise budget
//! cannot fund the next operation. The harness never resets a budget without
//! performing a real ciphertext refresh.

use nine65::arithmetic::rns::{U256, U512};
use nine65::keys::bootstrap::BootstrapKeySet;
use nine65::noise::budget::refresh_output_noise_millibits;
use nine65::noise::budget::{NoiseBudget, NoiseOpType};
use nine65::ops::bootstrap::ClockworkBootstrap;
use nine65::ops::rns_fhe::{DualRNSCiphertext, DualRNSFullKeySet, DualRNSSecretKey, RNSFHEContext};
use nine65::prelude::*;
use serde_json::{json, Value};
use std::time::Instant;

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

// Client-side test observer only. None of these measurements is passed to
// the public refresh circuit or used to choose its encrypted output.
fn add_mod_observer(a: u128, b: u128, modulus: u128) -> u128 {
    if a >= modulus - b {
        a - (modulus - b)
    } else {
        a + b
    }
}

fn mul_mod_observer(mut a: u128, mut b: u128, modulus: u128) -> u128 {
    let mut out = 0;
    while b != 0 {
        if b & 1 != 0 {
            out = add_mod_observer(out, a, modulus);
        }
        a = add_mod_observer(a, a, modulus);
        b >>= 1;
    }
    out
}

fn crt_weights_observer(primes: &[u64], q: u128) -> Vec<u128> {
    primes
        .iter()
        .map(|&prime| {
            let p = prime as u128;
            let punctured = q / p;
            // Fermat inversion is used only for the public, validated prime basis.
            let mut base = punctured % p;
            let mut exponent = prime - 2;
            let mut inverse = 1u128;
            while exponent != 0 {
                if exponent & 1 != 0 {
                    inverse = inverse * base % p;
                }
                base = base * base % p;
                exponent >>= 1;
            }
            punctured * inverse // strictly below q, so this product fits u128
        })
        .collect()
}

fn scale_observer(value: u128, scalar: u64) -> U256 {
    // At most 128 + 64 bits, with no truncation of nonzero high words.
    let product = U512::from_u128(value).mul_u128(scalar as u128);
    U256 {
        lo: product.d0,
        hi: product.d1,
    }
}

fn grid_error_observer(phase: u128, expected: u64, q: u128, t: u64) -> U256 {
    let actual = scale_observer(phase, t);
    let ideal = scale_observer(q, expected);
    let gap = if (actual.hi, actual.lo) >= (ideal.hi, ideal.lo) {
        actual.sub(ideal)
    } else {
        ideal.sub(actual)
    };
    let complement = scale_observer(q, t).sub(gap);
    if (gap.hi, gap.lo) < (complement.hi, complement.lo) {
        gap
    } else {
        complement
    }
}

fn decimal_observer(mut value: U256) -> String {
    if value.hi == 0 && value.lo == 0 {
        return "0".into();
    }
    let mut digits = Vec::new();
    while value.hi != 0 || value.lo != 0 {
        let mut remainder = 0u128;
        let mut quotient = [0u64; 4];
        for (index, limb) in [
            (value.hi >> 64) as u64,
            value.hi as u64,
            (value.lo >> 64) as u64,
            value.lo as u64,
        ]
        .iter()
        .enumerate()
        {
            let numerator = (remainder << 64) | *limb as u128;
            quotient[index] = (numerator / 10) as u64;
            remainder = numerator % 10;
        }
        digits.push((b'0' + remainder as u8) as char);
        value = U256 {
            hi: ((quotient[0] as u128) << 64) | quotient[1] as u128,
            lo: ((quotient[2] as u128) << 64) | quotient[3] as u128,
        };
    }
    digits.into_iter().rev().collect()
}

fn max_grid_error_observer(
    ctx: &RNSFHEContext,
    ct: &DualRNSCiphertext,
    sk: &DualRNSSecretKey,
    message: u64,
    q: u128,
) -> U256 {
    let weights = crt_weights_observer(&ctx.config.primes, q);
    let phase_lanes: Vec<Vec<u64>> = ctx
        .config
        .primes
        .iter()
        .enumerate()
        .map(|(i, &p)| {
            let product = ctx.ntt_engines[i].multiply(&ct.c1.main[i], &sk.s.main[i]);
            ct.c0.main[i]
                .iter()
                .zip(product)
                .map(|(&a, b)| ((a as u128 + b as u128) % p as u128) as u64)
                .collect()
        })
        .collect();
    let mut maximum = U256::zero();
    for j in 0..ctx.n {
        let mut phase = 0;
        for (lane, &weight) in phase_lanes.iter().zip(&weights) {
            phase = add_mod_observer(phase, mul_mod_observer(weight, lane[j] as u128, q), q);
        }
        let error = grid_error_observer(phase, if j == 0 { message } else { 0 }, q, ctx.t);
        if (error.hi, error.lo) > (maximum.hi, maximum.lo) {
            maximum = error;
        }
    }
    maximum
}

fn renewal_witness(
    ctx: &RNSFHEContext,
    engine: &ClockworkBootstrap,
    keys: &DualRNSFullKeySet,
    boot_keys: &BootstrapKeySet,
    rng: &mut ShadowHarvester,
) -> Value {
    let config = &ctx.config;
    let Some(q) = config.try_rns_product() else {
        return json!({"enabled": true, "passed": false,
                      "reason": "renewal observer requires checked u128 Q"});
    };
    let message = 7 % config.t;
    let injected = q / (8 * config.n as u128 * config.t as u128);
    let reserve = q / (2 * config.n as u128);
    let noise_mb = refresh_output_noise_millibits(config);
    let bits = ((noise_mb + 999) / 1000) as u32;
    let Some(raw_bound) = 1u128
        .checked_shl(bits)
        .and_then(|v| v.checked_add(config.n as u128 + config.t as u128 + 1))
    else {
        return json!({"enabled": true, "passed": false,
                      "reason": "renewal bound exceeds observer capacity"});
    };
    let bound = scale_observer(raw_bound, config.t);
    let Some(doubled_raw_bound) = raw_bound.checked_mul(2) else {
        return json!({"enabled": true, "passed": false,
                      "reason": "doubled renewal bound exceeds observer capacity"});
    };
    let doubled_bound = scale_observer(doubled_raw_bound, config.t);
    let mut stressed = ctx.encrypt_dual(message, &keys.public_key, rng);
    for (lane, &p) in stressed.c0.main.iter_mut().zip(&config.primes) {
        lane[0] = ((lane[0] as u128 + injected % p as u128) % p as u128) as u64;
    }
    for (lane, &p) in stressed
        .c0
        .anchor
        .iter_mut()
        .zip(&ctx.dual_rns.anchor.primes)
    {
        lane[0] = ((lane[0] as u128 + injected % p as u128) % p as u128) as u64;
    }
    let input_decode = ctx.decrypt_dual(&stressed, &keys.secret_key);
    let input_error = max_grid_error_observer(ctx, &stressed, &keys.secret_key, message, q);
    let admitted = injected > 0
        && input_decode == message
        && (input_error.hi, input_error.lo) < (0, reserve)
        && (input_error.hi, input_error.lo) > (doubled_bound.hi, doubled_bound.lo);
    let mut result = json!({
        "enabled": true, "passed": false, "expected": message,
        "modulus_q": q.to_string(), "injected_error": injected.to_string(),
        "input_reserve_scaled": reserve.to_string(),
        "declared_refresh_noise_mb": noise_mb,
        "refresh_error_bound_scaled": decimal_observer(bound),
        "input_error_scaled": decimal_observer(input_error),
        "input_decrypted": input_decode, "input_coefficients_checked": ctx.n,
        "input_admitted": admitted, "real_refreshes": 0,
    });
    if !admitted {
        result["reason"] = json!("stressed input is outside the certified witness corridor");
        return result;
    }
    // Only public/evaluation key material enters the actual engine call.
    let refreshed = match engine.bootstrap(&stressed, &boot_keys.bsk, &boot_keys.ksk) {
        Ok(value) => value,
        Err(error) => {
            result["reason"] = json!(error.to_string());
            return result;
        }
    };
    result["real_refreshes"] = json!(1);
    let output_decode = ctx.decrypt_dual(&refreshed, &keys.secret_key);
    let output_error = max_grid_error_observer(ctx, &refreshed, &keys.secret_key, message, q);
    let passed =
        output_decode == message && (output_error.hi, output_error.lo) < (bound.hi, bound.lo);
    result["output_decrypted"] = json!(output_decode);
    result["output_coefficients_checked"] = json!(ctx.n);
    result["output_error_scaled"] = json!(decimal_observer(output_error));
    result["passed"] = json!(passed);
    result
}

fn write_json_report(output: &Value, path: Option<&str>) -> Result<(), String> {
    let encoded = serde_json::to_string_pretty(output).map_err(|error| error.to_string())?;
    if let Some(path) = path {
        std::fs::write(path, encoded).map_err(|error| error.to_string())?;
        eprintln!("Output written to {path}");
    } else {
        println!("{encoded}");
    }
    Ok(())
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
                requested_operations = args.next().unwrap_or_default().parse().unwrap_or(80);
            }
            "--output" | "-o" => output_path = args.next(),
            "--a" => init_a = args.next().unwrap_or_default().parse().unwrap_or(8),
            "--b" => init_b = args.next().unwrap_or_default().parse().unwrap_or(8),
            "--with-bootstrap" => with_bootstrap = true,
            "--auto-bootstrap" => auto_bootstrap = true,
            "--statistical-test" => statistical_test = true,
            "--trigger-pct" => trigger_pct = args.next().unwrap_or_default().parse().unwrap_or(25),
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
    let legacy_mul_status = match evaluator.mul(&ct_a, &ct_b) {
        Ok(_) => "unexpected ciphertext",
        Err(_) => "refused",
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
        eprintln!(
            "Bootstrap key generation: {}us",
            started.elapsed().as_micros()
        );
        Some(generated)
    } else {
        None
    };

    let renewal =
        if let (Some(engine), Some(boot_keys)) = (bootstrap.as_ref(), bootstrap_keys.as_ref()) {
            renewal_witness(&ctx, engine, &dual_keys, boot_keys, &mut rng)
        } else {
            json!({"enabled": false})
        };
    if with_bootstrap && renewal["passed"] != true {
        // Archive the actual failed attempt instead of hiding it in a panic
        // before the workflow can preserve the engine's refusal or bad output.
        let failed = json!({
            "schema": "nine65-real-refresh-evidence-v1", "overall_correct": false,
            "metadata": {"integer_only_reporting": true, "simulated_refreshes": 0,
                         "trigger_pct": trigger_pct, "bootstrap_mode": "real",
                         "config": config_name, "n": config.n, "t": config.t,
                         "eta": config.eta, "rns_primes": config.primes},
            "renewal_witness": renewal,
        });
        if let Err(error) = write_json_report(&failed, output_path.as_deref()) {
            eprintln!("Failed to archive renewal witness: {error}");
        }
        eprintln!("Real refresh failed the stressed-input renewal witness");
        std::process::exit(1);
    }

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
    let mut refresh_checks: Vec<Value> = Vec::new();
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
                NoiseBudget::mul_plain_scalar_cost(operand),
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
                refreshes += 1;
                // The secret is used only by this benchmark oracle, after
                // the public evaluator has returned its result.
                let refreshed = ctx.decrypt_dual(&ciphertext, &dual_keys.secret_key);
                let correct = refreshed == plaintext;
                refresh_checks.push(json!({
                    "operation_index": index + 1,
                    "expected": plaintext, "decrypted": refreshed, "correct": correct,
                }));
                if !correct {
                    eprintln!(
                        "REFRESH FAILURE before operation {}: expected {}, got {}",
                        index + 1,
                        plaintext,
                        refreshed
                    );
                    break;
                }
                budget.reset_after_bootstrap(&config);
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

        // PER-STEP CORRECTNESS CHECK
        let decrypted = ctx.decrypt_dual(&ciphertext, &dual_keys.secret_key);
        let correct = decrypted == plaintext;

        entries.push(json!({
            "operation_index": index + 1,
            "operation": operation,
            "operand": operand,
            "elapsed_us": elapsed_us,
            "noise_budget_pct": percent_floor(
                budget.remaining_millibits(),
                initial_budget_mb,
            ),
            "noise_remaining_mb": budget.remaining_millibits(),
            "expected": plaintext,
            "decrypted": decrypted,
            "correct": correct,
        }));

        if !correct {
            eprintln!(
                "CORRECTNESS FAILURE at operation {}: expected {}, got {}",
                index + 1,
                plaintext,
                decrypted
            );
            break;
        }
    }

    let chain_us = chain_start.elapsed().as_micros() as u64;
    let operations_achieved = entries.len();
    let decrypted = ctx.decrypt_dual(&ciphertext, &dual_keys.secret_key);
    let achieved_chain_correct = decrypted == plaintext;
    let completed_requested = operations_achieved == requested_operations;

    let statistical_summary = if statistical_test {
        let engine = bootstrap
            .as_ref()
            .expect("statistical test bootstrap engine");
        let keys = bootstrap_keys
            .as_ref()
            .expect("statistical test bootstrap keys");
        let mut successes: u64 = 0;
        let mut statistical_refreshes: u64 = 0;
        let mut trials: Vec<Value> = Vec::with_capacity(100);

        for trial in 0..100u64 {
            let mut expected = rng.next_u64() % config.t;
            let mut ct = ctx.encrypt_dual(expected, &dual_keys.public_key, &mut rng);
            let mut trial_budget = NoiseBudget::from_config(&config);
            let _ = trial_budget.consume(NoiseOpType::Encrypt, NoiseBudget::encrypt_cost(&config));
            let mut trial_entries: Vec<Value> = Vec::with_capacity(80);
            let mut trial_refresh_checks: Vec<Value> = Vec::new();
            let mut trial_refreshes = 0u64;

            for step in 0..80usize {
                let (_, operand) = chain_ops[step % chain_ops.len()];
                let (kind, cost) = if step % 3 == 0 {
                    (
                        NoiseOpType::MulPlain,
                        NoiseBudget::mul_plain_scalar_cost(operand),
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
                    statistical_refreshes += 1;
                    trial_refreshes += 1;
                    let decrypted = ctx.decrypt_dual(&ct, &dual_keys.secret_key);
                    let correct = decrypted == expected;
                    trial_refresh_checks.push(json!({
                        "operation_index": step + 1,
                        "expected": expected, "decrypted": decrypted, "correct": correct,
                    }));
                    if !correct {
                        eprintln!(
                            "Statistical refresh failed: trial {}, operation {}",
                            trial + 1,
                            step + 1
                        );
                        break;
                    }
                    trial_budget.reset_after_bootstrap(&config);
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
                let decrypted = ctx.decrypt_dual(&ct, &dual_keys.secret_key);
                let correct = decrypted == expected;
                trial_entries.push(json!({
                    "operation_index": step + 1,
                    "expected": expected, "decrypted": decrypted, "correct": correct,
                }));
                if !correct {
                    break;
                }
            }

            let decrypted = ctx.decrypt_dual(&ct, &dual_keys.secret_key);
            let complete = trial_entries.len() == 80;
            let correct = complete
                && decrypted == expected
                && trial_entries.iter().all(|entry| entry["correct"] == true)
                && trial_refresh_checks
                    .iter()
                    .all(|entry| entry["correct"] == true);
            if correct {
                successes += 1;
            }
            trials.push(json!({
                "trial_index": trial + 1,
                "requested_operations": 80,
                "operations_achieved": trial_entries.len(),
                "completed_requested": complete,
                "achieved_chain_correct": correct,
                "decrypted_result": decrypted,
                "expected_result": expected,
                "real_refreshes": trial_refreshes,
                "entries": trial_entries,
                "refresh_checks": trial_refresh_checks,
            }));
        }

        if successes != 100 {
            eprintln!("Statistical correctness failed: {successes}/100");
        }

        json!({
            "enabled": true,
            "successes": successes,
            "trials": 100,
            "real_refreshes": statistical_refreshes,
            "operations_per_trial": 80,
            "entries": trials,
        })
    } else {
        json!({"enabled": false})
    };

    let scale_tests = json!({
        "deep_arithmetic": run_scale_test(
            &config,
            &encryptor,
            &evaluator,
            &decryptor,
            &mut rng,
            80,
            "arithmetic",
        ),
        "statistical_pipeline": run_scale_test(
            &config,
            &encryptor,
            &evaluator,
            &decryptor,
            &mut rng,
            60,
            "statistical",
        ),
        "neural_network": run_scale_test(
            &config,
            &encryptor,
            &evaluator,
            &decryptor,
            &mut rng,
            50,
            "neural_network",
        ),
        "polynomial_eval": run_scale_test(
            &config,
            &encryptor,
            &evaluator,
            &decryptor,
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

    let statistical_correct =
        !statistical_test || statistical_summary["successes"].as_u64() == Some(100);
    let overall_correct = completed_requested && achieved_chain_correct && statistical_correct;
    let output = json!({
        "schema": "nine65-real-refresh-evidence-v1",
        "metadata": {
            "integer_only_reporting": true,
            "simulated_refreshes": 0,
            "trigger_pct": trigger_pct,
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
            "legacy_single_modulus_mul": legacy_mul_status,
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
            "refresh_checks": refresh_checks,
        },
        "renewal_witness": renewal,
        "statistical_test": statistical_summary,
        "scale_tests": scale_tests,
        "overall_correct": overall_correct,
        "speedometer_summary": {
            "average_chain_ops_per_sec": chain_ops_per_second,
            "average_chain_latency_us": average_chain_us,
            "operations_achieved": operations_achieved,
            "noise_budget_min_pct": min_noise,
            "real_refreshes": refreshes,
        },
    });

    if let Err(error) = write_json_report(&output, output_path.as_deref()) {
        eprintln!("Failed to write benchmark report: {error}");
        std::process::exit(1);
    }

    eprintln!(
        "Completed: achieved {operations_achieved}/{requested_operations} operations, correctness={}, real refreshes={refreshes}",
        achieved_chain_correct
    );
    if !overall_correct {
        std::process::exit(1);
    }
}

fn run_scale_test(
    config: &FHEConfig,
    encryptor: &BFVEncryptor,
    evaluator: &BFVEvaluator,
    decryptor: &BFVDecryptor,
    rng: &mut ShadowHarvester,
    requested_operations: usize,
    workload: &str,
) -> Value {
    // These are single-q ciphertexts, so unused RNS primes cannot fund them.
    let mut budget = NoiseBudget::from_single_modulus(config);
    let initial_budget = budget.remaining_millibits();
    let mut ciphertext = encryptor.encrypt(42 % config.t, rng);
    let _ = budget.consume(NoiseOpType::Encrypt, NoiseBudget::encrypt_cost(config));
    let started = Instant::now();
    let mut achieved: u64 = 0;
    let mut expected = 42 % config.t;
    let mut correct = true;

    for index in 0..requested_operations {
        let (kind, cost) = match workload {
            "arithmetic" if index % 3 == 0 => {
                (NoiseOpType::MulPlain, NoiseBudget::mul_plain_scalar_cost(3))
            }
            "neural_network" if index % 2 == 0 => {
                (NoiseOpType::MulPlain, NoiseBudget::mul_plain_scalar_cost(3))
            }
            "polynomial" if index % 2 == 0 => {
                (NoiseOpType::MulPlain, NoiseBudget::mul_plain_scalar_cost(3))
            }
            _ => (NoiseOpType::Add, NoiseBudget::add_plain_cost()),
        };

        if budget.remaining_millibits() < cost {
            break;
        }

        ciphertext = match kind {
            NoiseOpType::MulPlain => {
                expected = (expected * 3) % config.t;
                evaluator.mul_plain(&ciphertext, 3)
            }
            _ => {
                let operand = ((index as u64) + 1) % config.t;
                expected = (expected + operand) % config.t;
                evaluator.add_plain(&ciphertext, operand)
            }
        };
        budget
            .consume(kind, cost)
            .expect("preflighted scale-test budget consumption");
        achieved += 1;
        correct = decryptor.decrypt(&ciphertext) == expected;
        if !correct {
            break;
        }
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
        "correct": correct,
        "expected_result": expected,
        "decrypted_result": decryptor.decrypt(&ciphertext),
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

#[cfg(test)]
mod renewal_observer_tests {
    use super::*;

    #[test]
    fn direct_crt_observer_recovers_every_small_basis_state() {
        let primes = [5u64, 13, 17];
        let q = 1105u128;
        let weights = crt_weights_observer(&primes, q);
        for value in 0..q {
            let mut recovered = 0;
            for (&p, &weight) in primes.iter().zip(&weights) {
                recovered =
                    add_mod_observer(recovered, mul_mod_observer(weight, value % p as u128, q), q);
            }
            assert_eq!(recovered, value);
        }
    }

    #[test]
    fn observer_modular_products_cover_full_u128_without_overflow() {
        let q = u128::MAX - 158;
        assert_eq!(mul_mod_observer(q - 1, q - 2, q), 2);
        assert_eq!(add_mod_observer(q - 1, q - 1, q), q - 2);
        assert_eq!(mul_mod_observer(0, q - 1, q), 0);
    }

    #[test]
    fn ideal_grid_error_reads_the_nearest_circular_representative() {
        assert_eq!(grid_error_observer(43, 2, 65, 3), U256::from_u64(1));
        assert_eq!(grid_error_observer(64, 0, 65, 3), U256::from_u64(3));
        assert_eq!(grid_error_observer(0, 0, 65, 3), U256::zero());
        let wide_q = u128::MAX - 158;
        assert_eq!(
            grid_error_observer(wide_q - 1, 0, wide_q, 65_537),
            U256::from_u64(65_537)
        );
        assert_eq!(
            grid_error_observer(0, 65_536, wide_q, 65_537),
            U256::from_u128(wide_q)
        );
    }

    #[test]
    fn exact_decimal_evidence_preserves_magnitudes_above_u128() {
        assert_eq!(
            decimal_observer(U256 { hi: 1, lo: 0 }),
            "340282366920938463463374607431768211456"
        );
        assert_eq!(
            decimal_observer(U256 {
                hi: u128::MAX,
                lo: u128::MAX
            }),
            "115792089237316195423570985008687907853269984665640564039457584007913129639935"
        );
    }
}
