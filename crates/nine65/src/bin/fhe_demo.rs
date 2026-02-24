use nine65::prelude::*;
use std::time::Instant;

fn expect_eq(label: &str, got: u64, expected: u64) {
    if got != expected {
        eprintln!("{label} failed: got {got}, expected {expected}");
        std::process::exit(1);
    }
}

fn print_usage() {
    eprintln!(
        "Usage: fhe_demo [--a <u64>] [--b <u64>] [--config <name>] [--seed <u64> | --os-seed]\n\
         \n\
         Options:\n\
           --a <u64>           First plaintext (default: 17)\n\
           --b <u64>           Second plaintext (default: 25)\n\
           --config <name>     Config name (default: standard_128)\n\
                               SECURE: standard_128, high_192\n\
                               INSECURE (test only): light (~36-bit), he_standard_128 (~56-bit)\n\
           --seed <u64>        Deterministic RNG seed (default: 42)\n\
           --os-seed           Use OS entropy for RNG\n\
           -h, --help          Show this help\n"
    );
}

fn parse_u64(value: &str, flag: &str) -> u64 {
    value.parse::<u64>().unwrap_or_else(|_| {
        eprintln!("Invalid value for {flag}: {value}");
        std::process::exit(2);
    })
}

fn main() {
    let mut a = 17u64;
    let mut b = 25u64;
    let mut config_name = String::from("standard_128"); // Default to secure config
    let mut seed: Option<u64> = Some(42);
    let mut use_os_seed = false;

    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        if arg == "-h" || arg == "--help" {
            print_usage();
            return;
        }

        let (flag, value) = if let Some((left, right)) = arg.split_once('=') {
            (left, Some(right.to_string()))
        } else {
            (arg.as_str(), None)
        };

        match flag {
            "--a" => {
                let v = value.unwrap_or_else(|| args.next().unwrap_or_default());
                if v.is_empty() {
                    eprintln!("Missing value for --a");
                    std::process::exit(2);
                }
                a = parse_u64(&v, "--a");
            }
            "--b" => {
                let v = value.unwrap_or_else(|| args.next().unwrap_or_default());
                if v.is_empty() {
                    eprintln!("Missing value for --b");
                    std::process::exit(2);
                }
                b = parse_u64(&v, "--b");
            }
            "--config" => {
                let v = value.unwrap_or_else(|| args.next().unwrap_or_default());
                if v.is_empty() {
                    eprintln!("Missing value for --config");
                    std::process::exit(2);
                }
                config_name = v;
            }
            "--seed" => {
                let v = value.unwrap_or_else(|| args.next().unwrap_or_default());
                if v.is_empty() {
                    eprintln!("Missing value for --seed");
                    std::process::exit(2);
                }
                seed = Some(parse_u64(&v, "--seed"));
            }
            "--os-seed" => {
                use_os_seed = true;
            }
            _ => {
                eprintln!("Unknown option: {flag}");
                print_usage();
                std::process::exit(2);
            }
        }
    }

    if use_os_seed && seed.is_some() {
        eprintln!("Use either --seed or --os-seed, not both");
        std::process::exit(2);
    }

    let config = match config_name.as_str() {
        #[cfg(feature = "allow_insecure")]
        "light" => {
            eprintln!(
                "WARNING: 'light' config has only ~36-bit security - NOT for production use!"
            );
            #[allow(deprecated)]
            {
                FHEConfig::light_insecure()
            }
        }
        #[cfg(feature = "allow_insecure")]
        "he_standard_128" | "he-standard-128" => {
            eprintln!(
                "WARNING: 'he_standard_128' has only ~56-bit security - NOT for production use!"
            );
            #[allow(deprecated)]
            {
                FHEConfig::he_standard_128_insecure()
            }
        }
        #[cfg(not(feature = "allow_insecure"))]
        "light" | "he_standard_128" | "he-standard-128" => {
            eprintln!("ERROR: Insecure configs (light, he_standard_128) require --features allow_insecure");
            eprintln!("Build with: cargo build --release --features allow_insecure");
            std::process::exit(3);
        }
        "standard_128" | "standard-128" => FHEConfig::standard_128_insecure(),
        "high_192" | "high-192" => FHEConfig::high_192_insecure(),
        other => {
            eprintln!("Unknown config: {other}");
            print_usage();
            std::process::exit(2);
        }
    };

    if a >= config.t {
        eprintln!("ERROR: --a ({}) must be less than plaintext modulus t ({})", a, config.t);
        std::process::exit(2);
    }
    if b >= config.t {
        eprintln!("ERROR: --b ({}) must be less than plaintext modulus t ({})", b, config.t);
        std::process::exit(2);
    }

    println!("NINE65 FHE demo");
    println!("Note: demo uses deterministic Shadow Entropy unless --os-seed is set.");

    let ntt = NTTEngine::new(config.q, config.n);
    let mut rng = if use_os_seed {
        ShadowHarvester::from_os_seed()
    } else {
        ShadowHarvester::with_seed(seed.unwrap_or(42))
    };

    let start = Instant::now();
    let keys = KeySet::generate(&config, &ntt, &mut rng);
    let keygen_ms = start.elapsed().as_millis();

    let encoder = BFVEncoder::new(&config);
    let encryptor = BFVEncryptor::new(&keys.public_key, &encoder, &ntt, config.eta);
    let decryptor = BFVDecryptor::new(&keys.secret_key, &encoder, &ntt);
    let evaluator = BFVEvaluator::new(&ntt, &encoder, Some(&keys.eval_key));

    let ct_a = encryptor.encrypt(a, &mut rng);
    let ct_b = encryptor.encrypt(b, &mut rng);

    let ct_sum = evaluator.add(&ct_a, &ct_b);
    let sum = decryptor.decrypt(&ct_sum);
    expect_eq("add", sum, (a + b) % config.t);

    let ct_diff = evaluator.sub(&ct_a, &ct_b);
    let diff = decryptor.decrypt(&ct_diff);
    let expected_diff = if a >= b { a - b } else { config.t - (b - a) };
    expect_eq("sub", diff, expected_diff);

    let ct_neg = evaluator.negate(&ct_a);
    let neg = decryptor.decrypt(&ct_neg);
    expect_eq("neg", neg, (config.t - a) % config.t);

    let ct_add_plain = evaluator.add_plain(&ct_a, 10);
    let add_plain = decryptor.decrypt(&ct_add_plain);
    expect_eq("add_plain", add_plain, (a + 10) % config.t);

    let ct_mul_plain = evaluator.mul_plain(&ct_a, 3);
    let mul_plain = decryptor.decrypt(&ct_mul_plain);
    expect_eq("mul_plain", mul_plain, (a * 3) % config.t);

    println!(
        "Parameters: n={}, q={}, t={}, eta={}",
        config.n, config.q, config.t, config.eta
    );
    println!("Keygen: {} ms", keygen_ms);
    println!("Results:");
    println!("  {} + {} = {}", a, b, sum);
    println!("  {} - {} = {} (mod {})", a, b, diff, config.t);
    println!("  -{} = {} (mod {})", a, neg, config.t);
    println!("  {} + 10 = {}", a, add_plain);
    println!("  {} * 3 = {}", a, mul_plain);
    println!("Status: PASS");
}
