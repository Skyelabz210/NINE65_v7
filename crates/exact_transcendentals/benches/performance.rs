use criterion::{black_box, criterion_group, criterion_main, Criterion};
use exact_transcendentals::agm::AgmEngine;
use exact_transcendentals::binary_splitting::*;
use exact_transcendentals::continued_fraction::*;
use exact_transcendentals::cordic::CordicEngine;
use exact_transcendentals::sqrt::*;

fn bench_cordic_sincos(c: &mut Criterion) {
    let engine = CordicEngine::default();
    let angle = exact_transcendentals::cordic::HALF_PI / 4; // π/8

    c.bench_function("cordic sincos", |b| {
        b.iter(|| {
            black_box(engine.sincos(black_box(angle)));
        })
    });
}

fn bench_agm_pi(c: &mut Criterion) {
    let engine = AgmEngine::default();

    c.bench_function("agm pi computation", |b| {
        b.iter(|| {
            black_box(engine.compute_pi_scaled());
        })
    });
}

fn bench_exp_taylor(c: &mut Criterion) {
    let scale = 1i128 << 20;

    c.bench_function("exp taylor", |b| {
        b.iter(|| {
            black_box(exp_binary_split(
                black_box(scale),
                black_box(20),
                black_box(15),
            ));
        })
    });
}

fn bench_isqrt_newton(c: &mut Criterion) {
    c.bench_function("isqrt newton", |b| {
        b.iter(|| {
            black_box(isqrt_newton(black_box(1000000)));
        })
    });
}

fn bench_continued_fraction(c: &mut Criterion) {
    let cf = sqrt_cf(2);

    c.bench_function("continued fraction convergent", |b| {
        b.iter(|| {
            black_box(cf.convergent(black_box(10)));
        })
    });
}

criterion_group!(
    benches,
    bench_cordic_sincos,
    bench_agm_pi,
    bench_exp_taylor,
    bench_isqrt_newton,
    bench_continued_fraction
);
criterion_main!(benches);
