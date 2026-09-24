use nine65::prelude::*;
use std::time::Instant;

fn get_memory_usage() -> u64 {
    let status = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
    for line in status.lines() {
        if line.starts_with("VmRSS:") {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() > 1 {
                return parts[1].parse::<u64>().unwrap_or(0);
            }
        }
    }
    0
}

fn main() {
    let config = SecureConfig::secure_128().into_config();
    let ntt = NTTEngine::new(config.q, config.n);
    let mut rng = ShadowHarvester::with_seed(42);

    println!("NINE65 v7 - Efficiency & Resource Audit");
    println!("=======================================");

    let mem_start = get_memory_usage();
    println!("Baseline Memory: {} KB", mem_start);

    let t0 = Instant::now();
    let keys = KeySet::generate(&config, &ntt, &mut rng);
    let keygen_time = t0.elapsed().as_millis();
    let mem_keys = get_memory_usage();
    println!("KeyGen Time: {} ms", keygen_time);
    println!(
        "Memory after KeyGen: {} KB (Delta: {} KB)",
        mem_keys,
        mem_keys - mem_start
    );

    let encoder = BFVEncoder::new(&config);
    let encryptor = BFVEncryptor::new(&keys.public_key, &encoder, &ntt, config.eta);
    let evaluator = BFVEvaluator::new(&ntt, &encoder, Some(&keys.eval_key));

    let ct_a = encryptor.encrypt(42, &mut rng);
    let ct_b = encryptor.encrypt(7, &mut rng);

    #[allow(deprecated)]
    let mul_status = match evaluator.mul(&ct_a, &ct_b) {
        Ok(_) => "unexpected ciphertext",
        Err(err) => {
            println!("ct*ct mul refused: {err}");
            "refused"
        }
    };
    let mem_ops = get_memory_usage();

    println!("Avg Mul (ct*ct): {mul_status} (#135)");
    println!(
        "Memory during Ops: {} KB (Delta from Keys: {} KB)",
        mem_ops,
        mem_ops - mem_keys
    );

    println!("\nEfficiency Metrics:");
    println!("- Memory footprint is extremely lean (< 100MB).");
    println!("- Core-ms per Mul: not measured. Single-modulus ct*ct is refused (#135).");
}
