//! NINE65 audit and benchmark harness.
//!
//! This binary measures the production DualRNS path, separates leveled depth
//! from real Clockwork refresh, preflights every tracked operation, and reports
//! only exact integer quantities. A software noise-counter reset is never
//! reported as ciphertext bootstrap.

use nine65::entropy::ShadowHarvester;
use nine65::keys::bootstrap::{BootstrapKey, KeySwitchKey};
use nine65::noise::budget::{NoiseBudget, NoiseOpType};
use nine65::ops::auto_bootstrap::AutoBootstrapEvaluator;
use nine65::ops::bootstrap::ClockworkBootstrap;
use nine65::ops::rns_fhe::{DualRNSFullKeySet, RNSFHEContext};
use nine65::params::secure_configs::SecureConfig;
use nine65::params::FHEConfig;
use serde_json::{json, Value};
use std::time::{Instant, SystemTime};

const TIMING_ITERATIONS: u64 = 20;
const STATISTICAL_TRIALS: u64 = 100;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DepthMode {
    NoBootstrap,
    ManualBootstrap,
    AutoBootstrap,
}

impl DepthMode {
    fn label(self) -> &'static str {
        match self {
            Self::NoBootstrap => "no_bootstrap",
            Self::ManualBootstrap => "clockwork_manual",
            Self::AutoBootstrap => "clockwork_auto",
        }
    }
}

#[derive(Debug)]
struct Options {
    config_name: String,
    max_depth: usize,
    output_path: Option<String>,
    init_a: u64,
    init_b: u64,
    mode: DepthMode,
    statistical_test: bool,
    trigger_pct: u32,
}

fn main() {
    let options = match parse_options() {
        Ok(options) => options,
        Err(message) => {
            eprintln!("{message}");
            print_help();
            std::process::exit(2);
        }
    };

    let config = select_config(&options.config_name);
    eprintln!("NINE65 DualRNS benchmark");
    eprintln!(
        "config={} n={} main_primes={} t={} mode={}",
        options.config_name,
        config.n,
        config.primes.len(),
        config.t,
        options.mode.label()
    );

    let ctx = RNSFHEContext::try_new(&config).expect("DualRNS context construction failed");
    let mut rng = ShadowHarvester::with_seed(42);

    let keygen_start = Instant::now();
    let keys = ctx.generate_keys_dual_full(&mut rng);
    let keygen_us = micros_u64(keygen_start.elapsed().as_micros());

    let operations = benchmark_operations(&ctx, &keys, &mut rng, options.init_a, options.init_b);

    let (depth_chain, statistical_test) = match options.mode {
        DepthMode::NoBootstrap => (
            run_no_bootstrap_depth(
                &ctx,
                &keys,
                &mut rng,
                options.init_a,
                options.max_depth,
            ),
            Value::Null,
        ),
        DepthMode::ManualBootstrap => {
            let bootstrap =
                ClockworkBootstrap::new(&config).expect("Clockwork bootstrap init failed");
            let bootstrap_keys = bootstrap
                .generate_keys(&keys.secret_key, &mut rng)
                .expect("Clockwork bootstrap key generation failed");
            (
                run_manual_bootstrap_depth(
                    &ctx,
                    &keys,
                    &bootstrap,
                    &bootstrap_keys.bsk,
                    &bootstrap_keys.ksk,
                    &mut rng,
                    options.init_a,
                    options.max_depth,
                    options.trigger_pct,
                ),
                Value::Null,
            )
        }
        DepthMode::AutoBootstrap => {
            let bootstrap =
                ClockworkBootstrap::new(&config).expect("Clockwork bootstrap init failed");
            let bootstrap_keys = bootstrap
                .generate_keys(&keys.secret_key, &mut rng)
                .expect("Clockwork bootstrap key generation failed");
            let depth_chain = run_auto_bootstrap_depth(
                &ctx,
                &keys,
                &bootstrap,
                &bootstrap_keys.bsk,
                &bootstrap_keys.ksk,
                &mut rng,
                options.init_a,
                options.max_depth,
                options.trigger_pct,
            );
            let statistical_test = if options.statistical_test {
                run_statistical_auto_bootstrap(
                    &ctx,
                    &keys,
                    &bootstrap,
                    &bootstrap_keys.bsk,
                    &bootstrap_keys.ksk,
                    &mut rng,
                    options.max_depth,
                    options.trigger_pct,
                )
            } else {
                Value::Null
            };
            (depth_chain, statistical_test)
        }
    };

    let depth_correct = json_bool(&depth_chain, "correct");
    let statistical_correct = if options.statistical_test {
        json_bool(&statistical_test, "correct")
    } else {
        true
    };
    let overall_correct = depth_correct && statistical_correct;

    let output = json!({
        "metadata": {
            "timestamp": timestamp(),
            "config": options.config_name,
            "n": config.n,
            "main_primes": config.primes,
            "t": config.t,
            "eta": config.eta,
            "security_bits_internal": config.security_bits,
            "max_depth_requested": options.max_depth,
            "depth_mode": options.mode.label(),
            "trigger_pct": options.trigger_pct,
            "nine65_version": env!("CARGO_PKG_VERSION"),
            "integer_only_reporting": true,
            "simulated_refreshes": 0
        },
        "keygen_us": keygen_us,
        "operations": operations,
        "depth_chain": depth_chain,
        "statistical_test": statistical_test,
        "overall_correct": overall_correct
    });

    let json_text = serde_json::to_string_pretty(&output).expect("JSON serialization failed");
    if let Some(path) = options.output_path.as_deref() {
        std::fs::write(path, json_text).expect("failed to write benchmark output");
        eprintln!("output={path}");
    } else {
        println!("{json_text}");
    }

    if !overall_correct {
        if !depth_correct {
            eprintln!("depth-chain correctness gate failed");
        }
        if !statistical_correct {
            eprintln!("statistical correctness gate failed");
        }
        std::process::exit(1);
    }
}

fn json_bool(value: &Value, field: &str) -> bool {
    value.get(field).and_then(Value::as_bool).unwrap_or(false)
}

fn parse_options() -> Result<Options, String> {
    let mut config_name = String::from("secure_128_deep");
    let mut max_depth = 80usize;
    let mut output_path = None;
    let mut init_a = 8u64;
    let mut init_b = 8u64;
    let mut mode = DepthMode::NoBootstrap;
    let mut mode_selected = false;
    let mut statistical_test = false;
    let mut trigger_pct = 25u32;

    let mut args = std::env::args().skip(1);
    while let Some(argument) = args.next() {
        match argument.as_str() {
            "--config" => config_name = required_value(&mut args, "--config")?,
            "--max-depth" => {
                max_depth = parse_value(&required_value(&mut args, "--max-depth")?, "--max-depth")?
            }
            "--output" | "-o" => output_path = Some(required_value(&mut args, "--output")?),
            "--a" => init_a = parse_value(&required_value(&mut args, "--a")?, "--a")?,
            "--b" => init_b = parse_value(&required_value(&mut args, "--b")?, "--b")?,
            "--trigger-pct" => {
                trigger_pct = parse_value(
                    &required_value(&mut args, "--trigger-pct")?,
                    "--trigger-pct",
                )?
            }
            "--with-bootstrap" => {
                if mode_selected {
                    return Err("select only one bootstrap mode".to_string());
                }
                mode = DepthMode::ManualBootstrap;
                mode_selected = true;
            }
            "--auto-bootstrap" => {
                if mode_selected {
                    return Err("select only one bootstrap mode".to_string());
                }
                mode = DepthMode::AutoBootstrap;
                mode_selected = true;
            }
            "--statistical-test" => statistical_test = true,
            "-h" | "--help" => {
                print_help();
                std::process::exit(0);
            }
            other => return Err(format!("unknown option: {other}")),
        }
    }

    if max_depth == 0 {
        return Err("--max-depth must be at least 1".to_string());
    }
    if trigger_pct > 100 {
        return Err("--trigger-pct must be in 0..=100".to_string());
    }
    if statistical_test && mode != DepthMode::AutoBootstrap {
        return Err("--statistical-test requires --auto-bootstrap".to_string());
    }

    Ok(Options {
        config_name,
        max_depth,
        output_path,
        init_a,
        init_b,
        mode,
        statistical_test,
        trigger_pct,
    })
}

fn required_value(
    args: &mut impl Iterator<Item = String>,
    flag: &str,
) -> Result<String, String> {
    args.next().ok_or_else(|| format!("missing value for {flag}"))
}

fn parse_value<T: std::str::FromStr>(value: &str, flag: &str) -> Result<T, String> {
    value
        .parse()
        .map_err(|_| format!("invalid value for {flag}: {value}"))
}

fn print_help() {
    eprintln!(
        "Usage: nine65_bench [OPTIONS]\n\n\
         --config <name>       secure_128_deep (default), secure_128, secure_192, secure_256\n\
         --max-depth <n>       ct×ct multiplications to attempt (default: 80)\n\
         --output <path>       write structured JSON to a file\n\
         --a <u64>             encrypted accumulator value (default: 8)\n\
         --b <u64>             second operand for operation timing (default: 8)\n\
         --with-bootstrap      use real manual Clockwork refresh\n\
         --auto-bootstrap      use AutoBootstrapEvaluator\n\
         --statistical-test    run 100 auto-bootstrap correctness trials\n\
         --trigger-pct <n>     pre-operation refresh threshold in 0..=100 (default: 25)"
    );
}

fn select_config(name: &str) -> FHEConfig {
    match name {
        "secure_128" | "standard_128" => SecureConfig::secure_128().into_config(),
        "secure_128_deep" => SecureConfig::secure_128_deep().into_config(),
        "secure_192" | "high_192" => SecureConfig::secure_192().into_config(),
        "secure_256" => SecureConfig::secure_256().into_config(),
        other => {
            eprintln!("unknown configuration: {other}");
            std::process::exit(2);
        }
    }
}

fn benchmark_operations(
    ctx: &RNSFHEContext,
    keys: &DualRNSFullKeySet,
    rng: &mut ShadowHarvester,
    a: u64,
    b: u64,
) -> Value {
    let mut ciphertext_a = ctx.encrypt_dual(a % ctx.t, &keys.public_key, rng);

    let start = Instant::now();
    for _ in 0..TIMING_ITERATIONS {
        ciphertext_a = ctx.encrypt_dual(a % ctx.t, &keys.public_key, rng);
    }
    let encrypt_us = average_micros(start, TIMING_ITERATIONS);

    let ciphertext_b = ctx.encrypt_dual(b % ctx.t, &keys.public_key, rng);

    let start = Instant::now();
    for _ in 0..TIMING_ITERATIONS {
        let _ = ctx.decrypt_dual(&ciphertext_a, &keys.secret_key);
    }
    let decrypt_us = average_micros(start, TIMING_ITERATIONS);

    let start = Instant::now();
    for _ in 0..TIMING_ITERATIONS {
        let _ = ctx.add_dual(&ciphertext_a, &ciphertext_b);
    }
    let add_us = average_micros(start, TIMING_ITERATIONS);

    let start = Instant::now();
    for _ in 0..TIMING_ITERATIONS {
        let _ = ctx.mul_plain_dual(&ciphertext_a, b % ctx.t);
    }
    let mul_plain_us = average_micros(start, TIMING_ITERATIONS);

    let start = Instant::now();
    for _ in 0..TIMING_ITERATIONS {
        let _ = ctx
            .mul_dual_public(&ciphertext_a, &ciphertext_b, &keys.eval_key)
            .expect("DualRNS multiplication failed during timing");
    }
    let mul_dual_k_elim_us = average_micros(start, TIMING_ITERATIONS);

    json!({
        "iterations": TIMING_ITERATIONS,
        "encrypt_us": encrypt_us,
        "decrypt_us": decrypt_us,
        "add_dual_us": add_us,
        "mul_plain_dual_us": mul_plain_us,
        "mul_dual_k_elim_us": mul_dual_k_elim_us,
        "path": "DualRNS + K-Elimination"
    })
}

fn multiplication_cost(config: &FHEConfig) -> i64 {
    NoiseBudget::mul_ct_cost(config) + NoiseBudget::relin_cost(config)
}

fn run_no_bootstrap_depth(
    ctx: &RNSFHEContext,
    keys: &DualRNSFullKeySet,
    rng: &mut ShadowHarvester,
    initial: u64,
    max_depth: usize,
) -> Value {
    let expected = initial % ctx.t;
    let one = ctx.encrypt_dual(1, &keys.public_key, rng);
    let mut accumulator = ctx.encrypt_dual(expected, &keys.public_key, rng);
    let mut budget = NoiseBudget::from_config(&ctx.config);
    let initial_budget = budget.remaining_millibits();
    let operation_cost = multiplication_cost(&ctx.config);
    let mut entries = Vec::new();
    let mut failure = None;

    for depth in 1..=max_depth {
        if !budget.can_perform(operation_cost) {
            failure = Some(format!(
                "tracked noise budget cannot fund multiplication at depth {depth}"
            ));
            break;
        }

        let start = Instant::now();
        let next = match ctx.mul_dual_public(&accumulator, &one, &keys.eval_key) {
            Ok(next) => next,
            Err(error) => {
                failure = Some(format!("multiplication rejected at depth {depth}: {error}"));
                break;
            }
        };
        let elapsed_us = micros_u64(start.elapsed().as_micros());

        if let Err(error) = budget.consume(NoiseOpType::MulCt, operation_cost) {
            failure = Some(format!("noise preflight invariant failed at depth {depth}: {error}"));
            break;
        }

        let decrypted = ctx.decrypt_dual(&next, &keys.secret_key);
        let correct = decrypted == expected;
        entries.push(json!({
            "depth": depth,
            "elapsed_us": elapsed_us,
            "decrypted": decrypted,
            "expected": expected,
            "correct": correct,
            "noise_budget_pct": percent(budget.remaining_millibits(), initial_budget),
            "refreshed": false
        }));
        accumulator = next;

        if !correct {
            failure = Some(format!("decryption mismatch at depth {depth}"));
            break;
        }
    }

    summarize_depth(
        DepthMode::NoBootstrap,
        &entries,
        failure,
        0,
        ctx.decrypt_dual(&accumulator, &keys.secret_key),
        expected,
    )
}

#[allow(clippy::too_many_arguments)]
fn run_manual_bootstrap_depth(
    ctx: &RNSFHEContext,
    keys: &DualRNSFullKeySet,
    bootstrap: &ClockworkBootstrap,
    bsk: &BootstrapKey,
    ksk: &KeySwitchKey,
    rng: &mut ShadowHarvester,
    initial: u64,
    max_depth: usize,
    trigger_pct: u32,
) -> Value {
    let expected = initial % ctx.t;
    let one = ctx.encrypt_dual(1, &keys.public_key, rng);
    let mut accumulator = ctx.encrypt_dual(expected, &keys.public_key, rng);
    let mut budget = NoiseBudget::from_config(&ctx.config);
    let initial_budget = budget.remaining_millibits();
    let operation_cost = multiplication_cost(&ctx.config);
    let trigger_permille = trigger_pct * 10;
    let mut entries = Vec::new();
    let mut refreshes = 0u64;
    let mut failure = None;

    for depth in 1..=max_depth {
        let start = Instant::now();
        let mut refreshed = false;

        if !budget.can_perform(operation_cost) || budget.should_bootstrap(trigger_permille) {
            accumulator = match bootstrap.bootstrap(&accumulator, bsk, ksk) {
                Ok(fresh) => fresh,
                Err(error) => {
                    failure = Some(format!("pre-operation bootstrap failed: {error}"));
                    break;
                }
            };
            budget.reset_after_bootstrap(&ctx.config);
            refreshes += 1;
            refreshed = true;
        }

        if !budget.can_perform(operation_cost) {
            failure = Some(format!(
                "post-bootstrap budget cannot fund multiplication at depth {depth}"
            ));
            break;
        }

        let next = match ctx.mul_dual_public(&accumulator, &one, &keys.eval_key) {
            Ok(next) => next,
            Err(_) if !refreshed => {
                accumulator = match bootstrap.bootstrap(&accumulator, bsk, ksk) {
                    Ok(fresh) => fresh,
                    Err(error) => {
                        failure = Some(format!("recovery bootstrap failed: {error}"));
                        break;
                    }
                };
                budget.reset_after_bootstrap(&ctx.config);
                refreshes += 1;
                refreshed = true;
                match ctx.mul_dual_public(&accumulator, &one, &keys.eval_key) {
                    Ok(next) => next,
                    Err(error) => {
                        failure = Some(format!("multiplication failed after refresh: {error}"));
                        break;
                    }
                }
            }
            Err(error) => {
                failure = Some(format!("multiplication failed after preflight refresh: {error}"));
                break;
            }
        };

        if let Err(error) = budget.consume(NoiseOpType::MulCt, operation_cost) {
            failure = Some(format!("noise preflight invariant failed at depth {depth}: {error}"));
            break;
        }

        let elapsed_us = micros_u64(start.elapsed().as_micros());
        let decrypted = ctx.decrypt_dual(&next, &keys.secret_key);
        let correct = decrypted == expected;
        entries.push(json!({
            "depth": depth,
            "elapsed_us": elapsed_us,
            "decrypted": decrypted,
            "expected": expected,
            "correct": correct,
            "noise_budget_pct": percent(budget.remaining_millibits(), initial_budget),
            "refreshed": refreshed
        }));
        accumulator = next;

        if !correct {
            failure = Some(format!("decryption mismatch at depth {depth}"));
            break;
        }
    }

    summarize_depth(
        DepthMode::ManualBootstrap,
        &entries,
        failure,
        refreshes,
        ctx.decrypt_dual(&accumulator, &keys.secret_key),
        expected,
    )
}

#[allow(clippy::too_many_arguments)]
fn run_auto_bootstrap_depth(
    ctx: &RNSFHEContext,
    keys: &DualRNSFullKeySet,
    bootstrap: &ClockworkBootstrap,
    bsk: &BootstrapKey,
    ksk: &KeySwitchKey,
    rng: &mut ShadowHarvester,
    initial: u64,
    max_depth: usize,
    trigger_pct: u32,
) -> Value {
    let expected = initial % ctx.t;
    let one = ctx.encrypt_dual(1, &keys.public_key, rng);
    let mut accumulator = ctx.encrypt_dual(expected, &keys.public_key, rng);
    let mut evaluator = AutoBootstrapEvaluator::new(
        ctx,
        bootstrap,
        bsk,
        ksk,
        &keys.eval_key,
        &ctx.config,
    );
    evaluator.set_trigger_threshold(trigger_pct * 10);
    let initial_budget = evaluator.remaining_budget_mb();
    let mut entries = Vec::new();
    let mut failure = None;

    for depth in 1..=max_depth {
        let previous_refreshes = evaluator.bootstrap_count;
        let start = Instant::now();
        let next = match evaluator.mul_auto(&accumulator, &one) {
            Ok(next) => next,
            Err(error) => {
                failure = Some(format!("auto-bootstrap multiplication failed: {error}"));
                break;
            }
        };
        let elapsed_us = micros_u64(start.elapsed().as_micros());
        let decrypted = ctx.decrypt_dual(&next, &keys.secret_key);
        let correct = decrypted == expected;
        entries.push(json!({
            "depth": depth,
            "elapsed_us": elapsed_us,
            "decrypted": decrypted,
            "expected": expected,
            "correct": correct,
            "noise_budget_pct": percent(evaluator.remaining_budget_mb(), initial_budget),
            "bootstrap_calls": evaluator.bootstrap_count - previous_refreshes,
            "refreshed": evaluator.bootstrap_count > previous_refreshes
        }));
        accumulator = next;

        if !correct {
            failure = Some(format!("decryption mismatch at depth {depth}"));
            break;
        }
    }

    summarize_depth(
        DepthMode::AutoBootstrap,
        &entries,
        failure,
        evaluator.bootstrap_count as u64,
        ctx.decrypt_dual(&accumulator, &keys.secret_key),
        expected,
    )
}

#[allow(clippy::too_many_arguments)]
fn run_statistical_auto_bootstrap(
    ctx: &RNSFHEContext,
    keys: &DualRNSFullKeySet,
    bootstrap: &ClockworkBootstrap,
    bsk: &BootstrapKey,
    ksk: &KeySwitchKey,
    rng: &mut ShadowHarvester,
    depth: usize,
    trigger_pct: u32,
) -> Value {
    let mut successes = 0u64;
    let mut total_bootstrap_calls = 0u64;

    for _ in 0..STATISTICAL_TRIALS {
        let expected = rng.next_u64() % ctx.t;
        let one = ctx.encrypt_dual(1, &keys.public_key, rng);
        let mut accumulator = ctx.encrypt_dual(expected, &keys.public_key, rng);
        let mut evaluator = AutoBootstrapEvaluator::new(
            ctx,
            bootstrap,
            bsk,
            ksk,
            &keys.eval_key,
            &ctx.config,
        );
        evaluator.set_trigger_threshold(trigger_pct * 10);

        let mut trial_ok = true;
        for _ in 0..depth {
            accumulator = match evaluator.mul_auto(&accumulator, &one) {
                Ok(next) => next,
                Err(_) => {
                    trial_ok = false;
                    break;
                }
            };
        }

        total_bootstrap_calls += evaluator.bootstrap_count as u64;
        if trial_ok && ctx.decrypt_dual(&accumulator, &keys.secret_key) == expected {
            successes += 1;
        }
    }

    json!({
        "trials": STATISTICAL_TRIALS,
        "depth_per_trial": depth,
        "successes": successes,
        "failures": STATISTICAL_TRIALS - successes,
        "total_bootstrap_calls": total_bootstrap_calls,
        "correct": successes == STATISTICAL_TRIALS
    })
}

fn summarize_depth(
    mode: DepthMode,
    entries: &[Value],
    failure: Option<String>,
    bootstrap_calls: u64,
    decrypted: u64,
    expected: u64,
) -> Value {
    let total_us = entries
        .iter()
        .filter_map(|entry| entry.get("elapsed_us").and_then(Value::as_u64))
        .sum::<u64>();
    let depth = entries.len() as u64;
    let ops_per_sec = if total_us == 0 {
        0
    } else {
        depth.saturating_mul(1_000_000) / total_us
    };
    let correct = failure.is_none() && decrypted == expected;

    json!({
        "mode": mode.label(),
        "final_depth": depth,
        "total_bootstrap_calls": bootstrap_calls,
        "simulated_refreshes": 0,
        "total_elapsed_us": total_us,
        "ops_per_sec": ops_per_sec,
        "decrypted_result": decrypted,
        "expected_result": expected,
        "correct": correct,
        "failure": failure,
        "entries": entries
    })
}

fn average_micros(start: Instant, iterations: u64) -> u64 {
    let elapsed = micros_u64(start.elapsed().as_micros());
    if iterations == 0 {
        0
    } else {
        elapsed / iterations
    }
}

fn percent(remaining: i64, initial: i64) -> u64 {
    if remaining <= 0 || initial <= 0 {
        return 0;
    }
    ((remaining as u128 * 100u128) / initial as u128) as u64
}

fn micros_u64(value: u128) -> u64 {
    value.min(u64::MAX as u128) as u64
}

fn timestamp() -> String {
    let seconds = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    format!("{seconds}s_since_epoch")
}
