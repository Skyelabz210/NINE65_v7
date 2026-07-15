use nine65::prelude::NTTEngine;
use serde_json::{json, Value};
use std::error::Error;
use std::path::PathBuf;
use std::time::Instant;

#[derive(Clone, Debug)]
struct Args {
    n: usize,
    moduli: Vec<u64>,
    seed: u64,
    output: Option<PathBuf>,
}

fn parse_args() -> Result<Args, String> {
    let mut n = 256_usize;
    let mut moduli = vec![998_244_353, 1_006_632_961, 1_u64 << 32, 4_294_967_295];
    let mut seed = 0x9E37_79B9_7F4A_7C15_u64;
    let mut output = None;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--n" => {
                n = args
                    .next()
                    .ok_or("missing --n")?
                    .parse()
                    .map_err(|_| "invalid --n")?;
            }
            "--moduli" => {
                let value = args.next().ok_or("missing --moduli")?;
                moduli = value
                    .split(',')
                    .filter(|item| !item.trim().is_empty())
                    .map(|item| item.trim().parse().map_err(|_| format!("invalid modulus: {item}")))
                    .collect::<Result<Vec<u64>, String>>()?;
            }
            "--seed" => {
                seed = args
                    .next()
                    .ok_or("missing --seed")?
                    .parse()
                    .map_err(|_| "invalid --seed")?;
            }
            "--output" | "-o" => output = Some(PathBuf::from(args.next().ok_or("missing --output")?)),
            "--help" | "-h" => {
                return Err(
                    "usage: cram_modulus_probe --n 256 --moduli 998244353,1006632961 --seed 42 --output result.json"
                        .to_string(),
                );
            }
            _ => return Err(format!("unknown argument: {arg}")),
        }
    }
    if n == 0 || !n.is_power_of_two() {
        return Err("--n must be a nonzero power of two".to_string());
    }
    if n > 1024 {
        return Err("--n must be <= 1024 for the exact schoolbook differential probe".to_string());
    }
    if moduli.is_empty() {
        return Err("at least one modulus is required".to_string());
    }
    Ok(Args { n, moduli, seed, output })
}

#[derive(Clone, Copy)]
struct XorShift64(u64);

impl XorShift64 {
    fn next(&mut self) -> u64 {
        let mut value = self.0;
        value ^= value << 13;
        value ^= value >> 7;
        value ^= value << 17;
        self.0 = value;
        value
    }
}

fn mul_mod(left: u64, right: u64, modulus: u64) -> u64 {
    ((left as u128 * right as u128) % modulus as u128) as u64
}

fn pow_mod(mut base: u64, mut exponent: u64, modulus: u64) -> u64 {
    let mut result = 1_u64 % modulus;
    base %= modulus;
    while exponent > 0 {
        if exponent & 1 == 1 {
            result = mul_mod(result, base, modulus);
        }
        base = mul_mod(base, base, modulus);
        exponent >>= 1;
    }
    result
}

fn is_prime_u64(value: u64) -> bool {
    if value < 2 {
        return false;
    }
    for prime in [2_u64, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37] {
        if value == prime {
            return true;
        }
        if value % prime == 0 {
            return false;
        }
    }
    let mut d = value - 1;
    let mut s = 0_u32;
    while d & 1 == 0 {
        d >>= 1;
        s += 1;
    }
    for base in [2_u64, 325, 9_375, 28_178, 450_775, 9_780_504, 1_795_265_022] {
        let reduced = base % value;
        if reduced == 0 {
            continue;
        }
        let mut x = pow_mod(reduced, d, value);
        if x == 1 || x == value - 1 {
            continue;
        }
        let mut witnessed = true;
        for _ in 1..s {
            x = mul_mod(x, x, value);
            if x == value - 1 {
                witnessed = false;
                break;
            }
        }
        if witnessed {
            return false;
        }
    }
    true
}

fn schoolbook_negacyclic(left: &[u64], right: &[u64], modulus: u64) -> Vec<u64> {
    let n = left.len();
    let mut output = vec![0_u64; n];
    for (left_index, &left_value) in left.iter().enumerate() {
        for (right_index, &right_value) in right.iter().enumerate() {
            let product = mul_mod(left_value, right_value, modulus);
            let raw_index = left_index + right_index;
            if raw_index < n {
                output[raw_index] = ((output[raw_index] as u128 + product as u128) % modulus as u128) as u64;
            } else {
                let index = raw_index - n;
                output[index] = if output[index] >= product {
                    output[index] - product
                } else {
                    modulus - (product - output[index])
                };
            }
        }
    }
    output
}

fn elapsed_ns(start: Instant) -> u64 {
    start.elapsed().as_nanos().min(u64::MAX as u128) as u64
}

fn probe_modulus(n: usize, modulus: u64, seed: u64) -> Value {
    let two_n = (n as u64).saturating_mul(2);
    let structurally_compatible = modulus > 2 && two_n > 0 && (modulus - 1) % two_n == 0;
    let prime = is_prime_u64(modulus);
    let power_of_two = modulus.is_power_of_two();
    let engine_result = std::panic::catch_unwind(|| NTTEngine::new(modulus, n));
    let engine = match engine_result {
        Ok(engine) => engine,
        Err(_) => {
            return json!({
                "modulus": modulus,
                "n": n,
                "is_prime": prime,
                "is_composite": modulus > 1 && !prime,
                "is_power_of_two": power_of_two,
                "q_minus_one_divisible_by_2n": structurally_compatible,
                "engine_constructed": false,
                "roundtrip_correct": false,
                "convolution_correct": false,
                "status": "CONSTRUCTION_PANIC"
            });
        }
    };

    let mut rng = XorShift64(seed ^ modulus ^ n as u64);
    let input: Vec<u64> = (0..n).map(|_| rng.next() % modulus).collect();
    let right: Vec<u64> = (0..n).map(|_| rng.next() % modulus).collect();

    let mut transformed = input.clone();
    let roundtrip_started = Instant::now();
    engine.ntt_inplace(&mut transformed);
    engine.intt_inplace(&mut transformed);
    let roundtrip_ns = elapsed_ns(roundtrip_started);
    let roundtrip_correct = transformed == input;

    let multiply_started = Instant::now();
    let actual = engine.multiply(&input, &right);
    let multiply_ns = elapsed_ns(multiply_started);
    let reference_started = Instant::now();
    let expected = schoolbook_negacyclic(&input, &right, modulus);
    let reference_ns = elapsed_ns(reference_started);
    let convolution_correct = actual == expected;
    let first_mismatch = actual
        .iter()
        .zip(&expected)
        .position(|(left, right)| left != right);

    json!({
        "modulus": modulus,
        "n": n,
        "is_prime": prime,
        "is_composite": modulus > 1 && !prime,
        "is_power_of_two": power_of_two,
        "q_minus_one_divisible_by_2n": structurally_compatible,
        "engine_constructed": true,
        "roundtrip_correct": roundtrip_correct,
        "roundtrip_ns": roundtrip_ns,
        "convolution_correct": convolution_correct,
        "ntt_multiply_ns": multiply_ns,
        "schoolbook_reference_ns": reference_ns,
        "first_mismatch": first_mismatch,
        "status": if roundtrip_correct && convolution_correct { "PASS" } else { "FAIL" }
    })
}

fn main() -> Result<(), Box<dyn Error>> {
    let args = parse_args().map_err(|message| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, message)
    })?;
    let results: Vec<Value> = args
        .moduli
        .iter()
        .map(|&modulus| probe_modulus(args.n, modulus, args.seed))
        .collect();
    let passing = results
        .iter()
        .filter(|record| record.get("status").and_then(Value::as_str) == Some("PASS"))
        .count();
    let output = json!({
        "schema": "nine65-cram-modulus-probe-v1",
        "scope": "exploratory_ntt_candidate_validation",
        "n": args.n,
        "seed": args.seed,
        "candidate_count": results.len(),
        "passing_candidates": passing,
        "results": results,
        "interpretation": "Structural congruence is necessary but runtime roundtrip and convolution equality are independently checked. Security is not inferred by this probe."
    });
    let rendered = serde_json::to_string_pretty(&output)?;
    if let Some(path) = args.output {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(path, rendered.as_bytes())?;
    }
    println!("{rendered}");
    Ok(())
}
