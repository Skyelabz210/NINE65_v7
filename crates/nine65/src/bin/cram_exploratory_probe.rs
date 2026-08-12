use nine65::noise::budget::{NoiseBudget, NoiseOpType};
use nine65::ops::bootstrap::ClockworkBootstrap;
use nine65::ops::rns_fhe::{DualRNSCiphertext, RNSFHEContext};
use nine65::prelude::*;
use serde_json::{json, Value};
use std::error::Error;
use std::path::PathBuf;
use std::time::Instant;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Workload {
    AddOnly,
    MulPlainOnly,
    MulCtOnly,
    Interleaved,
}

impl Workload {
    fn parse(value: &str) -> Result<Self, String> {
        match value {
            "add_only" => Ok(Self::AddOnly),
            "mul_plain_only" => Ok(Self::MulPlainOnly),
            "mul_ct_only" => Ok(Self::MulCtOnly),
            "interleaved" => Ok(Self::Interleaved),
            _ => Err(format!("unknown workload: {value}")),
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::AddOnly => "add_only",
            Self::MulPlainOnly => "mul_plain_only",
            Self::MulCtOnly => "mul_ct_only",
            Self::Interleaved => "interleaved",
        }
    }

    fn operation(self, step: usize) -> Operation {
        match self {
            Self::AddOnly => Operation::AddCt,
            Self::MulPlainOnly => Operation::MulPlain,
            Self::MulCtOnly => Operation::MulCt,
            Self::Interleaved => match step % 4 {
                0 | 3 => Operation::MulCt,
                _ => Operation::AddCt,
            },
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Operation {
    AddCt,
    MulPlain,
    MulCt,
}

impl Operation {
    fn name(self) -> &'static str {
        match self {
            Self::AddCt => "add_ct",
            Self::MulPlain => "mul_plain",
            Self::MulCt => "mul_ct",
        }
    }

    fn is_multiplication(self) -> bool {
        matches!(self, Self::MulPlain | Self::MulCt)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RefreshMode {
    None,
    Threshold,
    Exhaustion,
    CandidateWall,
}

impl RefreshMode {
    fn parse(value: &str) -> Result<Self, String> {
        match value {
            "none" => Ok(Self::None),
            "threshold" => Ok(Self::Threshold),
            "exhaustion" => Ok(Self::Exhaustion),
            "wall" => Ok(Self::CandidateWall),
            _ => Err(format!("unknown refresh mode: {value}")),
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Threshold => "threshold",
            Self::Exhaustion => "exhaustion",
            Self::CandidateWall => "wall",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RefreshTiming {
    PreOperation,
    PostOperation,
}

impl RefreshTiming {
    fn parse(value: &str) -> Result<Self, String> {
        match value {
            "pre" => Ok(Self::PreOperation),
            "post" => Ok(Self::PostOperation),
            _ => Err(format!("unknown refresh timing: {value}")),
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::PreOperation => "pre",
            Self::PostOperation => "post",
        }
    }
}

#[derive(Clone, Debug)]
struct Args {
    config_name: String,
    workload: Workload,
    depth: usize,
    seed: u64,
    initial: u64,
    rhs: u64,
    refresh_mode: RefreshMode,
    refresh_timing: RefreshTiming,
    trigger_permille: u32,
    candidate_wall: u64,
    output: Option<PathBuf>,
}

impl Default for Args {
    fn default() -> Self {
        Self {
            config_name: "secure_128".to_string(),
            workload: Workload::Interleaved,
            depth: 12,
            seed: 42,
            initial: 3,
            rhs: 2,
            refresh_mode: RefreshMode::None,
            refresh_timing: RefreshTiming::PreOperation,
            trigger_permille: 120,
            candidate_wall: 0,
            output: None,
        }
    }
}

fn parse_args() -> Result<Args, String> {
    let mut parsed = Args::default();
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        let value = |args: &mut std::iter::Skip<std::env::Args>, flag: &str| {
            args.next().ok_or_else(|| format!("missing value for {flag}"))
        };
        match arg.as_str() {
            "--config" => parsed.config_name = value(&mut args, "--config")?,
            "--workload" => parsed.workload = Workload::parse(&value(&mut args, "--workload")?)?,
            "--depth" => {
                parsed.depth = value(&mut args, "--depth")?
                    .parse()
                    .map_err(|_| "invalid --depth".to_string())?;
            }
            "--seed" => {
                parsed.seed = value(&mut args, "--seed")?
                    .parse()
                    .map_err(|_| "invalid --seed".to_string())?;
            }
            "--initial" => {
                parsed.initial = value(&mut args, "--initial")?
                    .parse()
                    .map_err(|_| "invalid --initial".to_string())?;
            }
            "--rhs" => {
                parsed.rhs = value(&mut args, "--rhs")?
                    .parse()
                    .map_err(|_| "invalid --rhs".to_string())?;
            }
            "--refresh" => {
                parsed.refresh_mode = RefreshMode::parse(&value(&mut args, "--refresh")?)?;
            }
            "--refresh-timing" => {
                parsed.refresh_timing =
                    RefreshTiming::parse(&value(&mut args, "--refresh-timing")?)?;
            }
            "--trigger-permille" => {
                parsed.trigger_permille = value(&mut args, "--trigger-permille")?
                    .parse()
                    .map_err(|_| "invalid --trigger-permille".to_string())?;
            }
            "--candidate-wall" => {
                parsed.candidate_wall = value(&mut args, "--candidate-wall")?
                    .parse()
                    .map_err(|_| "invalid --candidate-wall".to_string())?;
            }
            "--output" | "-o" => parsed.output = Some(PathBuf::from(value(&mut args, "--output")?)),
            "--help" | "-h" => {
                return Err(
                    "usage: cram_exploratory_probe --config secure_128 --workload interleaved \
                     --depth 12 --refresh none|threshold|exhaustion|wall \
                     --refresh-timing pre|post --trigger-permille 120 \
                     --candidate-wall 0 --seed 42 --initial 3 --rhs 2 --output result.json"
                        .to_string(),
                );
            }
            _ => return Err(format!("unknown argument: {arg}")),
        }
    }
    if parsed.depth == 0 {
        return Err("--depth must be positive".to_string());
    }
    if parsed.trigger_permille > 1000 {
        return Err("--trigger-permille must be <= 1000".to_string());
    }
    if parsed.refresh_mode == RefreshMode::CandidateWall && parsed.candidate_wall < 2 {
        return Err("wall refresh requires --candidate-wall >= 2".to_string());
    }
    Ok(parsed)
}

fn select_config(name: &str) -> Result<FHEConfig, String> {
    match name {
        "secure_128" => Ok(SecureConfig::secure_128().into_config()),
        "secure_128_deep" => Ok(SecureConfig::secure_128_deep().into_config()),
        "secure_192" => Ok(SecureConfig::secure_192().into_config()),
        "secure_256" => Ok(SecureConfig::secure_256().into_config()),
        _ => Err(format!("unknown configuration: {name}")),
    }
}

fn elapsed_ns(start: Instant) -> u64 {
    start.elapsed().as_nanos().min(u64::MAX as u128) as u64
}

fn budget_permille(remaining: i64, initial: i64) -> i64 {
    if initial <= 0 {
        return 0;
    }
    remaining.max(0).saturating_mul(1000) / initial
}

fn operation_cost(operation: Operation, config: &FHEConfig, rhs: u64) -> i64 {
    match operation {
        Operation::AddCt => NoiseBudget::add_cost(),
        Operation::MulPlain => NoiseBudget::mul_plain_cost(rhs, config),
        Operation::MulCt => {
            NoiseBudget::mul_ct_cost(config) + NoiseBudget::relin_cost(config)
        }
    }
}

fn alternative_cycle_cost(operation: Operation, config: &FHEConfig, rhs: u64) -> i64 {
    match operation {
        Operation::MulCt => NoiseBudget::multiplication_cycle_cost(config),
        _ => operation_cost(operation, config, rhs),
    }
}

fn should_refresh(
    mode: RefreshMode,
    budget: &NoiseBudget,
    next_cost: i64,
    multiplication_count: u64,
    next_is_multiplication: bool,
    trigger_permille: u32,
    candidate_wall: u64,
) -> bool {
    match mode {
        RefreshMode::None => false,
        RefreshMode::Threshold => budget.should_bootstrap(trigger_permille),
        RefreshMode::Exhaustion => !budget.can_perform(next_cost),
        RefreshMode::CandidateWall => {
            next_is_multiplication
                && multiplication_count.saturating_add(1) >= candidate_wall
        }
    }
}

fn perform_bootstrap(
    bootstrap: &ClockworkBootstrap,
    keys: &nine65::keys::bootstrap::BootstrapKeySet,
    ciphertext: &DualRNSCiphertext,
) -> Result<(DualRNSCiphertext, u64), Box<dyn Error>> {
    let started = Instant::now();
    let refreshed = bootstrap.bootstrap(ciphertext, &keys.bsk, &keys.ksk)?;
    Ok((refreshed, elapsed_ns(started)))
}

fn main() -> Result<(), Box<dyn Error>> {
    let args = parse_args().map_err(|message| {
        eprintln!("{message}");
        std::io::Error::new(std::io::ErrorKind::InvalidInput, message)
    })?;
    let config = select_config(&args.config_name).map_err(|message| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, message)
    })?;

    let ctx = RNSFHEContext::new(&config);
    let mut rng = ShadowHarvester::with_seed(args.seed);

    let keygen_started = Instant::now();
    let keys = ctx.generate_keys_dual_full(&mut rng);
    let keygen_ns = elapsed_ns(keygen_started);

    let bootstrap = if args.refresh_mode == RefreshMode::None {
        None
    } else {
        Some(ClockworkBootstrap::new(&config)?)
    };
    let bootstrap_keys = if let Some(ref engine) = bootstrap {
        let started = Instant::now();
        let generated = engine.generate_keys(&keys.secret_key, &mut rng)?;
        Some((generated, elapsed_ns(started)))
    } else {
        None
    };

    let initial = args.initial % config.t;
    let rhs = args.rhs % config.t;
    let mut ciphertext = ctx.encrypt_dual(initial, &keys.public_key, &mut rng);
    let rhs_ciphertext = ctx.encrypt_dual(rhs, &keys.public_key, &mut rng);
    let mut expected = initial;
    let mut budget = NoiseBudget::from_config(&config);
    let initial_budget_mb = budget.initial_millibits();
    let mut multiplication_count = 0_u64;
    let mut refresh_count = 0_u64;
    let mut traces: Vec<Value> = Vec::with_capacity(args.depth);
    let mut first_error: Option<String> = None;
    let mut all_correct = true;

    for step in 0..args.depth {
        let operation = args.workload.operation(step);
        let cost_mb = operation_cost(operation, &config, rhs);
        let cycle_cost_mb = alternative_cycle_cost(operation, &config, rhs);
        let before_budget_mb = budget.remaining_millibits();
        let before_level = ciphertext.level;
        let before_multiplications = multiplication_count;
        let mut pre_refresh_ns = 0_u64;
        let mut post_refresh_ns = 0_u64;
        let mut refreshed_pre = false;
        let mut refreshed_post = false;

        if args.refresh_timing == RefreshTiming::PreOperation
            && should_refresh(
                args.refresh_mode,
                &budget,
                cost_mb,
                multiplication_count,
                operation.is_multiplication(),
                args.trigger_permille,
                args.candidate_wall,
            )
        {
            let engine = bootstrap.as_ref().expect("refresh engine exists");
            let (ref key_set, _) = bootstrap_keys.as_ref().expect("refresh keys exist");
            let (fresh, timing) = perform_bootstrap(engine, key_set, &ciphertext)?;
            ciphertext = fresh;
            budget.reset_after_bootstrap(&config);
            refresh_count += 1;
            multiplication_count = 0;
            pre_refresh_ns = timing;
            refreshed_pre = true;
        }

        let operation_started = Instant::now();
        let operation_result: Result<DualRNSCiphertext, String> = match operation {
            Operation::AddCt => Ok(ctx.add_dual(&ciphertext, &rhs_ciphertext)),
            Operation::MulPlain => Ok(ctx.mul_plain_dual(&ciphertext, rhs)),
            Operation::MulCt => ctx
                .mul_dual_public(&ciphertext, &rhs_ciphertext, &keys.eval_key)
                .map_err(|error| error.to_string()),
        };
        let operation_ns = elapsed_ns(operation_started);

        let next_ciphertext = match operation_result {
            Ok(value) => value,
            Err(error) => {
                first_error = Some(format!("step {step} {}: {error}", operation.name()));
                traces.push(json!({
                    "step": step,
                    "operation": operation.name(),
                    "operation_ns": operation_ns,
                    "operation_error": error,
                    "budget_before_mb": before_budget_mb,
                    "candidate_multiplications_before": before_multiplications,
                    "status": "OPERATION_ERROR"
                }));
                break;
            }
        };
        ciphertext = next_ciphertext;

        expected = match operation {
            Operation::AddCt => expected.wrapping_add(rhs) % config.t,
            Operation::MulPlain | Operation::MulCt => expected.wrapping_mul(rhs) % config.t,
        };
        if operation.is_multiplication() {
            multiplication_count = multiplication_count.saturating_add(1);
        }

        let budget_result = budget.consume(
            match operation {
                Operation::AddCt => NoiseOpType::Add,
                Operation::MulPlain => NoiseOpType::MulPlain,
                Operation::MulCt => NoiseOpType::MulCt,
            },
            cost_mb,
        );
        let budget_exhausted = budget_result.is_err();

        if args.refresh_timing == RefreshTiming::PostOperation
            && (budget_exhausted
                || should_refresh(
                    args.refresh_mode,
                    &budget,
                    cost_mb,
                    multiplication_count,
                    operation.is_multiplication(),
                    args.trigger_permille,
                    args.candidate_wall,
                ))
            && args.refresh_mode != RefreshMode::None
        {
            let engine = bootstrap.as_ref().expect("refresh engine exists");
            let (ref key_set, _) = bootstrap_keys.as_ref().expect("refresh keys exist");
            let (fresh, timing) = perform_bootstrap(engine, key_set, &ciphertext)?;
            ciphertext = fresh;
            budget.reset_after_bootstrap(&config);
            refresh_count += 1;
            multiplication_count = 0;
            post_refresh_ns = timing;
            refreshed_post = true;
        }

        let decrypt_started = Instant::now();
        let decrypted = ctx.decrypt_dual(&ciphertext, &keys.secret_key);
        let decrypt_ns = elapsed_ns(decrypt_started);
        let correct = decrypted == expected;
        all_correct &= correct;
        let mismatch_delta = (decrypted + config.t - expected) % config.t;
        let remaining_mb = budget.remaining_millibits();
        let candidate_wall_remaining = if args.candidate_wall > multiplication_count {
            args.candidate_wall - multiplication_count
        } else {
            0
        };

        traces.push(json!({
            "step": step,
            "operation": operation.name(),
            "operation_ns": operation_ns,
            "decrypt_ns": decrypt_ns,
            "pre_refresh_ns": pre_refresh_ns,
            "post_refresh_ns": post_refresh_ns,
            "refreshed_pre": refreshed_pre,
            "refreshed_post": refreshed_post,
            "refresh_kind": if refreshed_pre || refreshed_post { "real_bootstrap" } else { "none" },
            "expected": expected,
            "decrypted": decrypted,
            "correct": correct,
            "mismatch_delta_mod_t": mismatch_delta,
            "level_before": before_level,
            "level_after": ciphertext.level,
            "budget_before_mb": before_budget_mb,
            "budget_after_mb": remaining_mb,
            "budget_after_permille": budget_permille(remaining_mb, initial_budget_mb),
            "accounting_cost_mb": cost_mb,
            "alternative_full_cycle_cost_mb": cycle_cost_mb,
            "budget_exhausted": budget_exhausted,
            "candidate_multiplications_before": before_multiplications,
            "candidate_multiplications_after": multiplication_count,
            "candidate_wall": args.candidate_wall,
            "candidate_wall_remaining": candidate_wall_remaining,
            "candidate_winding_is_verified": false
        }));

        if !correct {
            first_error = Some(format!(
                "step {step} {} decrypted {decrypted}, expected {expected}",
                operation.name()
            ));
            break;
        }
    }

    let final_decrypted = ctx.decrypt_dual(&ciphertext, &keys.secret_key);
    let full_log_q_bits: u64 = config
        .primes
        .iter()
        .map(|prime| u64::from(64 - prime.leading_zeros()))
        .sum();
    let bootstrap_keygen_ns = bootstrap_keys.as_ref().map(|(_, timing)| *timing);
    let status = if all_correct && first_error.is_none() {
        "PASS"
    } else {
        "FAIL"
    };

    let output = json!({
        "schema": "nine65-cram-exploratory-probe-v1",
        "status": status,
        "scope": "exploratory_hypothesis_probe",
        "metadata": {
            "config": args.config_name,
            "n": config.n,
            "q_representative": config.q,
            "plaintext_modulus": config.t,
            "eta": config.eta,
            "main_primes": config.primes,
            "full_log_q_bits_upper_sum": full_log_q_bits,
            "claimed_security_bits": config.security_bits,
            "seed": args.seed,
            "workload": args.workload.name(),
            "requested_depth": args.depth,
            "initial": initial,
            "rhs": rhs,
            "refresh_mode": args.refresh_mode.name(),
            "refresh_timing": args.refresh_timing.name(),
            "trigger_permille": args.trigger_permille,
            "candidate_wall": args.candidate_wall,
            "candidate_winding_is_verified": false,
            "noise_budget_is_accounting_model": true,
            "refresh_kind": if args.refresh_mode == RefreshMode::None { "none" } else { "real_bootstrap" }
        },
        "key_structure": {
            "keygen_ns": keygen_ns,
            "bootstrap_keygen_ns": bootstrap_keygen_ns,
            "eval_key_relinearization_components": keys.eval_key.rlk.len(),
            "eval_key_decomposition_base": keys.eval_key.decomp_base,
            "eval_key_decomposition_digits": keys.eval_key.num_digits,
            "zero_auxiliary_components_claim_supported": keys.eval_key.rlk.is_empty() && keys.eval_key.num_digits == 0
        },
        "ciphertext_structure": {
            "main_limbs": ciphertext.c0.main.len(),
            "anchor_limbs": ciphertext.c0.anchor.len(),
            "polynomial_degree": ciphertext.c0.n,
            "final_level": ciphertext.level
        },
        "budget_model": {
            "initial_mb": initial_budget_mb,
            "final_mb": budget.remaining_millibits(),
            "final_permille": budget_permille(budget.remaining_millibits(), initial_budget_mb),
            "operation_records": budget.operations().len()
        },
        "result": {
            "completed_steps": traces.len(),
            "refresh_count": refresh_count,
            "final_expected": expected,
            "final_decrypted": final_decrypted,
            "all_checked_steps_correct": all_correct,
            "first_error": first_error
        },
        "trace": traces
    });

    let rendered = serde_json::to_string_pretty(&output)?;
    if let Some(path) = args.output {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(path, rendered.as_bytes())?;
    }
    println!("{rendered}");
    if status == "PASS" {
        Ok(())
    } else {
        Err("exploratory probe recorded a failure".into())
    }
}
