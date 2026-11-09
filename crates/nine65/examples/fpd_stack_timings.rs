//! Current main-Q/FPD service stack and same-input prepared-key comparison.
//! cargo run --locked -p nine65 --release --features serde --example fpd_stack_timings
//! Setup is reported separately; each timed variant must pass correctness.

use nine65::entropy::SecureRng;
use nine65::ops::{cram_main::CramMainEvaluator, RNSFHEContext};
use nine65::params::SecureConfig;
use serde_json::{json, Value};
use std::path::PathBuf;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

fn timed<T>(operation: impl FnOnce() -> T) -> (T, u128) {
    let start = Instant::now();
    let result = operation();
    (result, start.elapsed().as_nanos())
}

fn samples(values: Vec<u128>) -> Value {
    let mut sorted = values.clone();
    sorted.sort_unstable();
    json!({"median_ns": sorted[sorted.len() / 2], "samples_ns": values})
}

fn measure(name: &str, secure: SecureConfig) -> Value {
    let config = secure.into_config();
    let mut rng = SecureRng::new();
    let ctx = RNSFHEContext::new(&config);
    let exact = ctx.try_exact_evaluator().unwrap();
    let keys = ctx.generate_keys_with_rng(&mut rng);
    let raw_key = exact.generate_hybrid_gadget_key_with_rng(&keys.secret_key, &mut rng);
    let (prepared, preparation_ns) = timed(|| exact.prepare_hybrid_gadget_key(&raw_key).unwrap());
    let ((client, evaluator), service_setup_ns) =
        timed(|| CramMainEvaluator::generate(&config).unwrap());
    let mut raw_times = Vec::new();
    let mut prepared_times = Vec::new();
    let mut service_times = Vec::new();
    let mut encrypt_times = Vec::new();
    let mut add_times = Vec::new();
    let mut decrypt_times = Vec::new();

    // One warmup and five samples. Boundary plaintexts exercise signed rescale.
    // Alternate pair order to avoid always giving one implementation first use.
    for (round, (a, b)) in [(2, 3), (0, 7), (6, 7), (config.t - 1, 7), (3, 11), (17, 13)]
        .into_iter()
        .enumerate()
    {
        let left = ctx.encrypt_with_rng(a, &keys.public_key, &mut rng);
        let right = ctx.encrypt_with_rng(b, &keys.public_key, &mut rng);
        let raw = || exact.try_mul_exact(&left, &right, &raw_key).unwrap();
        let cached = || {
            exact
                .try_mul_exact_prepared(&left, &right, &prepared)
                .unwrap()
        };
        let ((reference, raw_ns), (candidate, prepared_ns)) = if round % 2 == 0 {
            (timed(raw), timed(cached))
        } else {
            let candidate = timed(cached);
            (timed(raw), candidate)
        };
        assert_eq!(reference.c0.limbs, candidate.c0.limbs);
        assert_eq!(reference.c1.limbs, candidate.c1.limbs);
        assert_eq!(
            exact
                .try_decrypt_exact(&candidate, &keys.secret_key)
                .unwrap(),
            a * b % config.t
        );

        let (left, encrypt_ns) = timed(|| evaluator.encrypt(a).unwrap());
        let right = evaluator.encrypt(b).unwrap();
        let (sum, add_ns) = timed(|| evaluator.add(&left, &right).unwrap());
        let (product, service_ns) = timed(|| evaluator.multiply(&left, &right).unwrap());
        let (decoded, decrypt_ns) = timed(|| client.decrypt(&product).unwrap());
        assert_eq!(decoded, a * b % config.t);
        assert_eq!(client.decrypt(&sum).unwrap(), (a + b) % config.t);
        if round > 0 {
            raw_times.push(raw_ns);
            prepared_times.push(prepared_ns);
            service_times.push(service_ns);
            encrypt_times.push(encrypt_ns);
            add_times.push(add_ns);
            decrypt_times.push(decrypt_ns);
        }
    }
    let result = json!({
        "config": name, "n": config.n, "primes": config.primes,
        "t": config.t, "eta": config.eta,
        "prepared_key_bytes": prepared.coefficient_storage_bytes(),
        "preparation_ns": preparation_ns, "service_setup_ns": service_setup_ns,
        "correctness": {"trials_including_warmup": 6, "failures": 0,
                        "raw_prepared_all_limbs_equal": true},
        "operations": {
            "fpd_raw_public_mul": samples(raw_times),
            "fpd_prepared_public_mul": samples(prepared_times),
            "service_public_mul": samples(service_times),
            "service_encrypt": samples(encrypt_times),
            "service_add": samples(add_times),
            "service_decrypt": samples(decrypt_times)
        }
    });
    println!("{name}: {}", result["operations"]);
    result
}

fn main() {
    assert!(
        !cfg!(feature = "reference_ntt"),
        "native timings require the FFT engine"
    );
    let configs = [
        ("secure_128", SecureConfig::secure_128()),
        ("secure_192", SecureConfig::secure_192()),
        ("secure_256", SecureConfig::secure_256()),
    ];
    let selected = std::env::var("NINE65_BENCH_CONFIG").ok();
    let results: Vec<_> = configs
        .into_iter()
        .filter(|(name, _)| selected.as_deref().is_none_or(|wanted| wanted == *name))
        .map(|(name, config)| measure(name, config))
        .collect();
    assert!(!results.is_empty(), "unknown NINE65_BENCH_CONFIG");
    let report = json!({
        "schema": "nine65-fpd-stack-v1", "unit": "nanoseconds",
        "route": "CramMainEvaluator -> ExactMulEvaluator -> ExactScaleRound + prepared hybrid",
        "timestamp_unix_seconds": SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
        "build": {"debug_assertions": cfg!(debug_assertions),
                  "source_commit": std::env::var("NINE65_BENCH_COMMIT").ok()},
        "host": {"os": std::env::consts::OS, "arch": std::env::consts::ARCH,
                 "available_parallelism": std::thread::available_parallelism().map_or(1, usize::from)},
        "features": {"accelerated": cfg!(feature = "accelerated"),
                     "exact_transcendentals_backend": cfg!(feature = "exact_transcendentals_backend"),
                     "exact_rational": cfg!(feature = "exact_rational"),
                     "clockwork": cfg!(feature = "clockwork"),
                     "shadow_entropy": cfg!(feature = "shadow-entropy"),
                     "adaptive_threading": cfg!(feature = "adaptive-threading"),
                     "parallel": cfg!(feature = "parallel"),
                     "sequential": cfg!(feature = "sequential"),
                     "reference_ntt": cfg!(feature = "reference_ntt"),
                     "allow_insecure": cfg!(feature = "allow_insecure")},
        "refreshes": 0, "configs": results
    });
    let output = std::env::var_os("NINE65_BENCH_JSON_OUT")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../../bench-results/fpd_stack_timings.json")
        });
    if let Some(parent) = output.parent().filter(|p| !p.as_os_str().is_empty()) {
        std::fs::create_dir_all(parent).unwrap();
    }
    std::fs::write(&output, serde_json::to_vec_pretty(&report).unwrap()).unwrap();
    println!("FPD stack timings: {}", output.display());
}
