//! NOT BUILT — benchmarks a REJECTED parallelism approach (rayon).
//!
//! This bench compares generic rayon work-stealing against the adaptive/MANA
//! paths. rayon is **not** the parallelism layer for NINE65: it is measurably
//! slower for this workload, whose lanes are i.i.d. residues (x mod p, each
//! referencing no other lane) rather than the irregular task graph rayon's
//! work-stealing scheduler is built for. MANA (`crates/mana`, enabled by the
//! `accelerated` feature) is the canonical parallelism layer; the root
//! Cargo.toml annotates rayon as "Opt-in data parallelism (MANA is canonical)".
//!
//! Consequently:
//!   * rayon is NOT a dev-dependency of nine65 — it is optional, behind the
//!     `parallel` / `generic-rayon` features only.
//!   * this file has NO `[[bench]]` stanza, and `autobenches = false` is set in
//!     crates/nine65/Cargo.toml, so Cargo does not build it.
//!   * `use rayon::prelude::*` below therefore does not resolve in a default
//!     build. That is intended, not a defect to be fixed by adding rayon back.
//!
//! The source is retained for reference / provenance of the rejected approach.
//! To run it ad hoc, re-add a `[[bench]]` stanza with
//! `required-features = ["parallel"]` — do not add rayon to `[dev-dependencies]`.

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use nine65::arithmetic::NTTEngine;
use nine65::entropy::shadow_entropy_monitor::AdaptiveFHEContext;
use nine65::keys::KeySet;
use nine65::ops::encrypt::{BFVEncoder, BFVEncryptor};
use nine65::params::SecureConfig;
use rayon::prelude::*;

// ─── Helpers ──────────────────────────────────────────────────────────

fn bench_config() -> nine65::params::FHEConfig {
    SecureConfig::secure_128().into_config()
}

fn setup_context() -> (nine65::params::FHEConfig, NTTEngine, KeySet) {
    let config = bench_config();
    let ntt = NTTEngine::new(config.q, config.n);
    let mut rng = nine65::entropy::shadow::ShadowHarvester::with_seed(0xBEEF);
    let keys = KeySet::generate(&config, &ntt, &mut rng);
    (config, ntt, keys)
}

// ─── Sequential Implementation ──────────────────────────────────────────

fn sequential_encrypt(
    messages: &[u64],
    config: &nine65::params::FHEConfig,
    keys: &KeySet,
) -> Vec<nine65::ops::encrypt::Ciphertext> {
    messages
        .iter()
        .map(|&msg| {
            // Create NTT engine and encoder for each message (no caching in sequential mode)
            let ntt = NTTEngine::new(config.q, config.n);
            let encoder = BFVEncoder::new(config);
            let encryptor = BFVEncryptor::new(&keys.public_key, &encoder, &ntt, config.eta);

            let mut harvester = nine65::entropy::shadow::ShadowHarvester::with_seed(42);
            encryptor.encrypt(msg, &mut harvester)
        })
        .collect()
}

// ─── Generic Rayon Implementation ───────────────────────────────────────

fn generic_rayon_encrypt(
    messages: &[u64],
    config: &nine65::params::FHEConfig,
    keys: &KeySet,
) -> Vec<nine65::ops::encrypt::Ciphertext> {
    messages
        .par_iter()
        .map_init(
            || {
                // Initialize per-thread state (runs once per thread)
                let ntt = NTTEngine::new(config.q, config.n);
                let encoder = BFVEncoder::new(config);
                (ntt, encoder)
            },
            |(ntt, encoder), &msg| {
                // Reuse cached objects
                let encryptor = BFVEncryptor::new(&keys.public_key, encoder, ntt, config.eta);
                let mut harvester = nine65::entropy::shadow::ShadowHarvester::with_seed(42);
                encryptor.encrypt(msg, &mut harvester)
            },
        )
        .collect()
}

// ─── Benchmark: Threading Strategy Comparison ───────────────────────────

fn bench_threading_strategies(c: &mut Criterion) {
    let mut group = c.benchmark_group("threading-strategy-comparison");
    group.sample_size(10);

    let (config, ntt, keys) = setup_context();

    // Generate keys again for the adaptive context since KeySet doesn't implement Clone
    let mut rng = nine65::entropy::shadow::ShadowHarvester::with_seed(0xBEEF + 1);
    let keys_for_adaptive = KeySet::generate(&config, &ntt, &mut rng);
    let adaptive_ctx = AdaptiveFHEContext::new(config.clone(), keys_for_adaptive);

    for batch_size in [5, 20, 50, 100] {
        let messages: Vec<u64> = (0..batch_size).map(|i| i as u64).collect();

        group.throughput(Throughput::Elements(batch_size as u64));

        // Sequential Implementation
        group.bench_with_input(
            BenchmarkId::new("sequential", batch_size),
            &batch_size,
            |b, _| b.iter(|| black_box(sequential_encrypt(&messages, &config, &keys))),
        );

        // Generic Rayon Implementation
        group.bench_with_input(
            BenchmarkId::new("generic_rayon", batch_size),
            &batch_size,
            |b, _| b.iter(|| black_box(generic_rayon_encrypt(&messages, &config, &keys))),
        );

        // Adaptive System
        group.bench_with_input(
            BenchmarkId::new("adaptive_system", batch_size),
            &batch_size,
            |b, _| b.iter(|| black_box(adaptive_ctx.adaptive_encrypt(&messages, 42))),
        );
    }

    group.finish();
}

criterion_group!(threading_benches, bench_threading_strategies);
criterion_main!(threading_benches);
