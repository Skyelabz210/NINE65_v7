// NINE65 Rust vs NINE65-SEAL Performance Comparison
// Compares native Rust implementations against C++ SEAL integration

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use nine65::prelude::*;
use std::time::Duration;

// Test data sizes
const SMALL: usize = 100;
const MEDIUM: usize = 1000;
const LARGE: usize = 4096;

fn bench_montgomery_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("Persistent Montgomery");

    let modulus = 1152921504606584833u64; // 60-bit prime
    let mont = PersistentMontgomery::new(modulus);

    let a = 12345678901234u64;
    let b = 98765432109876u64;

    // Benchmark Montgomery enter
    group.bench_function("Montgomery enter", |bencher| {
        bencher.iter(|| {
            let result = mont.enter(black_box(a));
            black_box(result);
        });
    });

    // Benchmark Montgomery multiplication
    let a_mont = mont.enter(a);
    let b_mont = mont.enter(b);

    group.bench_function("Montgomery mul", |bencher| {
        bencher.iter(|| {
            let result = mont.mul(black_box(a_mont), black_box(b_mont));
            black_box(result);
        });
    });

    // Benchmark Montgomery exit
    group.bench_function("Montgomery exit", |bencher| {
        bencher.iter(|| {
            let result = mont.exit(black_box(a_mont));
            black_box(result);
        });
    });

    group.finish();
}

fn bench_order_finding(c: &mut Criterion) {
    let mut group = c.benchmark_group("Order Finding");
    group.measurement_time(Duration::from_secs(10));

    // Small cases
    group.bench_function("ord_63(2)", |bencher| {
        bencher.iter(|| {
            let order = nine65::arithmetic::multiplicative_order(black_box(2u64), black_box(63u64));
            black_box(order);
        });
    });

    group.bench_function("ord_1000(3)", |bencher| {
        bencher.iter(|| {
            let order =
                nine65::arithmetic::multiplicative_order(black_box(3u64), black_box(1000u64));
            black_box(order);
        });
    });

    // Factoring
    group.bench_function("factor_15", |bencher| {
        bencher.iter(|| {
            let factors = nine65::arithmetic::factor_semiprime(black_box(15u64), black_box(10));
            black_box(factors);
        });
    });

    group.bench_function("factor_3233", |bencher| {
        bencher.iter(|| {
            let factors = nine65::arithmetic::factor_semiprime(black_box(3233u64), black_box(20));
            black_box(factors);
        });
    });

    group.finish();
}

fn bench_polynomial_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("Polynomial Operations");

    for size in [SMALL, MEDIUM, LARGE].iter() {
        // Create test polynomials
        let coeffs: Vec<i64> = (0..*size).map(|i| (i % 100) as i64).collect();

        group.bench_with_input(
            BenchmarkId::new("Polynomial eval", size),
            size,
            |bencher, _| {
                bencher.iter(|| {
                    let x = 2i64;
                    let mut result = 0i64;
                    for (i, &coeff) in coeffs.iter().enumerate() {
                        result = result.wrapping_add(coeff.wrapping_mul(x.wrapping_pow(i as u32)));
                    }
                    black_box(result);
                });
            },
        );
    }

    group.finish();
}

fn bench_sign_detection(c: &mut Criterion) {
    let mut group = c.benchmark_group("Sign Detection (MQ-ReLU)");

    let modulus = 1152921504606584833u64;
    let relu = MQReLU::new(modulus);

    let positive = 123456u64;
    let _negative = modulus - 123456u64;

    group.bench_function("MobiusInt sign", |bencher| {
        bencher.iter(|| {
            let sign = relu.detect_sign(black_box(positive));
            black_box(sign);
        });
    });

    group.bench_function("MQ-ReLU scalar", |bencher| {
        bencher.iter(|| {
            let result = relu.apply_scalar(black_box(positive));
            black_box(result);
        });
    });

    group.finish();
}

/// Integer square root via Newton's method (local helper for bench binary)
fn integer_sqrt(n: u64) -> u64 {
    if n < 2 {
        return n;
    }
    let shift = (63 - n.leading_zeros()) / 2;
    let mut x = 1u64 << (shift + 1);
    loop {
        let y = (x + n / x) / 2;
        if y >= x {
            break;
        }
        x = y;
    }
    x
}

fn bench_quantum_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("Quantum Operations");

    // Sparse Grover simulation metrics
    for qubits in [10, 15, 20].iter() {
        let n_states = 1u64 << qubits;

        group.bench_with_input(
            BenchmarkId::new("Grover optimal iterations", qubits),
            qubits,
            |bencher, _| {
                bencher.iter(|| {
                    // Grover optimal iterations ~ (pi/4) * sqrt(N)
                    // Integer approximation: pi/4 ~ 355/(113*4) = 355/452
                    let sqrt_n = integer_sqrt(n_states);
                    let iterations = (355 * sqrt_n) / 452;
                    black_box(iterations);
                });
            },
        );
    }

    group.finish();
}

fn bench_ml_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("ML Operations");

    let softmax = IntegerSoftmax::new();

    // Softmax benchmarks (uses i128, not i64)
    for size in [10, 100, 1000].iter() {
        let logits: Vec<i128> = (0..*size).map(|i| i as i128 * 1000000).collect();

        group.bench_with_input(
            BenchmarkId::new("Integer Softmax", size),
            size,
            |bencher, _| {
                bencher.iter(|| {
                    let result = softmax.compute(black_box(&logits));
                    black_box(result);
                });
            },
        );
    }

    // MQ-ReLU benchmark for polynomial
    let modulus = 1152921504606584833u64;
    let relu = MQReLU::new(modulus);
    let activations: Vec<u64> = (0..4096).map(|i| (i * 1000) % modulus).collect();

    group.bench_function("MQ-ReLU Poly (4096)", |bencher| {
        bencher.iter(|| {
            let result = relu.apply_polynomial(black_box(&activations));
            black_box(result);
        });
    });

    group.finish();
}

fn bench_transcendentals(c: &mut Criterion) {
    let mut group = c.benchmark_group("Padé Transcendentals");

    let pade = PadeEngine::default_engine(); // PADE_SCALE is built-in

    // Scaled integer inputs (uses i128)
    let x: i128 = 1 << 19; // 0.5 in scaled form
    let _x_large: i128 = 1 << 20; // 1.0 in scaled form

    group.bench_function("Padé exp", |bencher| {
        bencher.iter(|| {
            let result = pade.exp_integer(black_box(x));
            black_box(result);
        });
    });

    group.bench_function("Padé sin", |bencher| {
        bencher.iter(|| {
            let result = pade.sin_integer(black_box(x));
            black_box(result);
        });
    });

    group.bench_function("Padé sigmoid", |bencher| {
        bencher.iter(|| {
            let result = pade.sigmoid_integer(black_box(x));
            black_box(result);
        });
    });

    group.finish();
}

fn bench_cyclotomic_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("Cyclotomic Phase");

    let n = 4096;
    let modulus = 1152921504606584833u64;
    let ring = CyclotomicRing::new(n, modulus);

    // Benchmark phase polynomial creation and rotation
    let poly = CyclotomicPolynomial::phase(17, ring.clone());

    group.bench_function("Cyclotomic rotation (4096)", |bencher| {
        bencher.iter(|| {
            let result = poly.rotate(black_box(100));
            black_box(result);
        });
    });

    group.bench_function("Extract sine/cosine (4096)", |bencher| {
        bencher.iter(|| {
            let sin_poly = poly.extract_sine();
            let cos_poly = poly.extract_cosine();
            black_box((sin_poly, cos_poly));
        });
    });

    group.finish();
}

// =============================================================================
// FHE OPERATION BENCHMARKS (DualRNS with K-Elimination)
// =============================================================================
//
// These benchmarks measure core FHE operations that would be compared to SEAL.
// SEAL comparison methodology:
// 1. Run NINE65 benchmarks (this file)
// 2. Run SEAL with equivalent parameters (see SEAL_COMPARISON.md)
// 3. Compare timings in JSON output

fn bench_fhe_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("FHE_DualRNS_K-Elimination");
    group.measurement_time(Duration::from_secs(5));

    // Setup context with light_rns_exact (3 main primes + anchors)
    let config = SecureConfig::secure_128().into_config();
    let ctx = RNSFHEContext::new(&config);
    let mut rng = ShadowHarvester::with_seed(42);
    let keys = ctx.generate_keys_dual(&mut rng);

    // Pre-encrypt ciphertexts for benchmarking
    let ct_a = ctx.encrypt_dual(5, &keys.public_key, &mut rng);
    let ct_b = ctx.encrypt_dual(7, &keys.public_key, &mut rng);

    // Benchmark encryption
    group.bench_function("encrypt", |bencher| {
        let mut rng = ShadowHarvester::with_seed(100);
        bencher.iter(|| {
            let ct = ctx.encrypt_dual(black_box(42), &keys.public_key, &mut rng);
            black_box(ct);
        });
    });

    // Benchmark decryption
    group.bench_function("decrypt", |bencher| {
        bencher.iter(|| {
            let result = ctx.decrypt_dual(black_box(&ct_a), &keys.secret_key);
            black_box(result);
        });
    });

    // Benchmark homomorphic addition
    group.bench_function("add", |bencher| {
        bencher.iter(|| {
            let ct_sum = ctx.add_dual(black_box(&ct_a), black_box(&ct_b));
            black_box(ct_sum);
        });
    });

    // Benchmark homomorphic multiplication (K-Elimination rescale)
    group.bench_function("mul_k_elim", |bencher| {
        bencher.iter(|| {
            let ct_prod =
                ctx.mul_dual_symmetric(black_box(&ct_a), black_box(&ct_b), &keys.secret_key);
            black_box(ct_prod);
        });
    });

    group.finish();
}

fn bench_fhe_key_generation(c: &mut Criterion) {
    let mut group = c.benchmark_group("FHE_KeyGen");
    group.measurement_time(Duration::from_secs(10));

    let config = SecureConfig::secure_128().into_config();
    let ctx = RNSFHEContext::new(&config);

    group.bench_function("keygen_dual", |bencher| {
        let mut rng = ShadowHarvester::with_seed(42);
        bencher.iter(|| {
            let keys = ctx.generate_keys_dual(&mut rng);
            black_box(keys);
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_montgomery_operations,
    bench_order_finding,
    bench_sign_detection,
    bench_polynomial_operations,
    bench_quantum_operations,
    bench_ml_operations,
    bench_transcendentals,
    bench_cyclotomic_operations,
    bench_fhe_operations,
    bench_fhe_key_generation
);

criterion_main!(benches);
