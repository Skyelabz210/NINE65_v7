use nine65::params::secure_configs::SecureConfig;
use nine65::params::security_estimator::{CostModel, LatticeSecurityEstimator, SecretDistribution};
use std::env;

/// Integer log2 floor: returns the bit-width minus 1 (floor of log2)
fn log2_floor(value: u64) -> u32 {
    assert!(value > 0, "log2 of zero is undefined");
    63 - value.leading_zeros()
}

/// Sum of floor(log2(p)) for each prime -- integer approximation of log2(product)
/// Returns (integer_part, fractional_millibits) for display as "X.YY"
fn log2_product_approx(primes: &[u64]) -> (u32, u32) {
    // Sum bit-widths: each prime p contributes floor(log2(p)) bits
    // For finer granularity, compute sum of (64 - leading_zeros - 1) = floor(log2(p))
    // Plus fractional correction: for each prime, the fraction is log2(p) - floor(log2(p))
    // We approximate the fractional part using: (p - 2^floor) * 100 / 2^floor
    let mut total_bits: u32 = 0;
    let mut frac_hundredths: u32 = 0;
    for &p in primes {
        let floor = log2_floor(p);
        total_bits += floor;
        // fractional part approximation in hundredths of a bit
        let pow2 = 1u64 << floor;
        let remainder = p - pow2;
        // fraction ~ remainder / pow2, scaled to hundredths
        frac_hundredths += ((remainder * 100) / pow2) as u32;
    }
    // Carry over fractional hundredths into integer bits
    total_bits += frac_hundredths / 100;
    frac_hundredths %= 100;
    (total_bits, frac_hundredths)
}

fn log2_product_floor_bits(primes: &[u64]) -> u32 {
    primes.iter().map(|&p| 64 - p.leading_zeros()).sum()
}

fn parse_args() -> (String, CostModel) {
    let mut format = "markdown".to_string();
    let mut cost_model = CostModel::CoreSVP;

    let mut args = env::args().skip(1).peekable();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--format" => {
                if let Some(value) = args.next() {
                    format = value;
                }
            }
            "--cost-model" => {
                if let Some(value) = args.next() {
                    match value.as_str() {
                        "core" | "core-svp" => cost_model = CostModel::CoreSVP,
                        "matzov" => cost_model = CostModel::MATZOV,
                        _ => {}
                    }
                }
            }
            "--help" | "-h" => {
                println!("Usage: security_estimator_baseline [--format markdown|csv] [--cost-model core|matzov]");
                std::process::exit(0);
            }
            _ => {}
        }
    }

    (format, cost_model)
}

fn main() {
    let (format, cost_model) = parse_args();
    let estimator = LatticeSecurityEstimator::new(cost_model);

    let configs = [
        ("secure_128", SecureConfig::secure_128().into_config()),
        ("secure_192", SecureConfig::secure_192().into_config()),
        ("secure_256", SecureConfig::secure_256().into_config()),
    ];

    if format == "csv" {
        println!("config,n,log2(q),effective_bits,cost_model");
        for (name, config) in configs {
            let log_q_bits = log2_product_floor_bits(&config.primes);
            let estimate = estimator.estimate(
                config.n,
                log_q_bits,
                SecretDistribution::Ternary,
                config.security_bits as u32,
            );
            let (int_part, frac_part) = log2_product_approx(&config.primes);
            println!(
                "{},{},{}.{:02},{},{}",
                name,
                config.n,
                int_part,
                frac_part,
                estimate.effective_bits,
                match cost_model {
                    CostModel::CoreSVP => "core-svp",
                    CostModel::MATZOV => "matzov",
                }
            );
        }
        return;
    }

    println!("| SecureConfig | n | log2(q) | min attack log2(rop) | cost model |");
    println!("| --- | --- | --- | --- | --- |");
    for (name, config) in configs {
        let log_q_bits = log2_product_floor_bits(&config.primes);
        let estimate = estimator.estimate(
            config.n,
            log_q_bits,
            SecretDistribution::Ternary,
            config.security_bits as u32,
        );
        let (int_part, frac_part) = log2_product_approx(&config.primes);
        println!(
            "| {} | {} | {}.{:02} | {} | {} |",
            name,
            config.n,
            int_part,
            frac_part,
            estimate.effective_bits,
            match cost_model {
                CostModel::CoreSVP => "core-svp",
                CostModel::MATZOV => "matzov",
            }
        );
    }
}
