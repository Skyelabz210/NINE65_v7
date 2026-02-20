//! V2 Integration Tests
//!
//! Tests for NINE65 V2 components:
//! - NTT FFT (O(N log N))
//! - WASSAN Holographic Noise Field (requires shadow-entropy feature)
//!
//! Run with: cargo test --features v2,shadow-entropy v2_integration

#[cfg(all(test, feature = "shadow-entropy"))]
mod v2_integration_tests {
    use crate::arithmetic::ntt::NTTEngine;
    use crate::arithmetic::ntt_fft::NTTEngineFFT;
    use crate::entropy::wassan_noise::WassanNoiseField;

    const TEST_Q: u64 = 998244353;

    fn perf_tests_enabled() -> bool {
        std::env::var("NINE65_PERF_TESTS")
            .map(|value| value == "1" || value.eq_ignore_ascii_case("true"))
            .unwrap_or(false)
    }

    fn perf_limit_ms(default: u128, var: &str) -> u128 {
        std::env::var(var)
            .ok()
            .and_then(|value| value.parse::<u128>().ok())
            .filter(|value| *value > 0)
            .unwrap_or(default)
    }

    // =========================================================================
    // FFT NTT TESTS
    // =========================================================================

    #[test]
    fn test_fft_ntt_roundtrip() {
        let engine = NTTEngineFFT::new(TEST_Q, 8);
        let original: Vec<u64> = vec![1, 2, 3, 4, 5, 6, 7, 8];

        let ntt_result = engine.ntt(&original);
        let recovered = engine.intt(&ntt_result);

        assert_eq!(recovered, original, "FFT NTT roundtrip failed");
    }

    #[test]
    fn test_fft_matches_dft() {
        // Verify FFT produces same results as original DFT
        let n = 8;
        let fft = NTTEngineFFT::new(TEST_Q, n);
        let dft = NTTEngine::new(TEST_Q, n);

        let a: Vec<u64> = vec![1, 2, 3, 4, 5, 6, 7, 8];
        let b: Vec<u64> = vec![8, 7, 6, 5, 4, 3, 2, 1];

        let fft_result = fft.multiply(&a, &b);
        let dft_result = dft.multiply(&a, &b);

        assert_eq!(
            fft_result, dft_result,
            "FFT and DFT produce different results!"
        );
    }

    #[test]
    fn test_fft_negacyclic() {
        let engine = NTTEngineFFT::new(TEST_Q, 4);

        // x³ * x = x⁴ = -1 in X⁴ + 1
        let a = vec![0, 0, 0, 1]; // x³
        let b = vec![0, 1, 0, 0]; // x

        let result = engine.multiply(&a, &b);

        // Should get -1 = q-1
        assert_eq!(result, vec![TEST_Q - 1, 0, 0, 0]);
    }

    #[test]
    fn test_fft_1024_benchmark() {
        if !perf_tests_enabled() {
            eprintln!("skipping perf test; set NINE65_PERF_TESTS=1 to enable");
            return;
        }
        let engine = NTTEngineFFT::new(TEST_Q, 1024);

        let a: Vec<u64> = (0..1024).map(|i| i % TEST_Q).collect();
        let b: Vec<u64> = (0..1024).map(|i| (i * 2) % TEST_Q).collect();

        let start = std::time::Instant::now();
        for _ in 0..100 {
            let _ = engine.multiply(&a, &b);
        }
        let elapsed = start.elapsed();

        println!(
            "FFT NTT 1024 x 100: {:?} ({:?} per mul)",
            elapsed,
            elapsed / 100
        );

        // Should be < 20ms for 100 multiplies (vs 1.35s for DFT)
        let max_ms = perf_limit_ms(200, "NINE65_FFT_1024_MAX_MS");
        assert!(elapsed.as_millis() < max_ms, "FFT too slow: {:?}", elapsed);
    }

    // =========================================================================
    // WASSAN NOISE TESTS
    // =========================================================================

    #[test]
    fn test_wassan_deterministic() {
        let mut w1 = WassanNoiseField::from_shadow_seed(42);
        let mut w2 = WassanNoiseField::from_shadow_seed(42);

        for _ in 0..1000 {
            assert_eq!(w1.sample(), w2.sample(), "WASSAN not deterministic");
        }
    }

    #[test]
    fn test_wassan_ternary_distribution() {
        let mut wassan = WassanNoiseField::from_shadow_seed(42);
        let mut counts = [0u64; 3];

        for _ in 0..30000 {
            let t = wassan.ternary();
            counts[(t + 1) as usize] += 1;
        }

        // Should be roughly uniform
        for c in counts.iter() {
            assert!(*c > 8000 && *c < 12000, "Ternary not uniform: {:?}", counts);
        }
    }

    #[test]
    fn test_wassan_polynomial() {
        let mut wassan = WassanNoiseField::from_shadow_seed(42);
        let poly = wassan.fhe_noise_polynomial(1024, TEST_Q, 8);

        assert_eq!(poly.len(), 1024);
        for &coeff in &poly {
            assert!(coeff < TEST_Q);
        }
    }

    #[test]
    fn test_wassan_benchmark() {
        if !perf_tests_enabled() {
            eprintln!("skipping perf test; set NINE65_PERF_TESTS=1 to enable");
            return;
        }
        let mut wassan = WassanNoiseField::from_shadow_seed(42);

        let start = std::time::Instant::now();
        let mut sum = 0u64;
        for _ in 0..1_000_000 {
            sum = sum.wrapping_add(wassan.sample());
        }
        let elapsed = start.elapsed();

        println!(
            "WASSAN 1M samples: {:?} ({:?}/sample)",
            elapsed,
            elapsed / 1_000_000
        );
        println!("Sum (anti-optimize): {}", sum);

        // Target: < 80ms for 1M samples (~80ns/sample with parallel test overhead)
        // Note: Parallel initialization adds thread spawn cost
        let max_ms = perf_limit_ms(80, "NINE65_WASSAN_V2_MAX_MS");
        assert!(
            elapsed.as_millis() < max_ms,
            "WASSAN too slow: {:?}",
            elapsed
        );
    }

    // =========================================================================
    // SPEEDUP COMPARISON
    // =========================================================================

    #[test]
    fn test_v2_speedup_summary() {
        println!("\n===== NINE65 V2 SPEEDUP SUMMARY =====\n");

        // NTT comparison
        let dft = NTTEngine::new(TEST_Q, 256);
        let fft = NTTEngineFFT::new(TEST_Q, 256);

        let a: Vec<u64> = (0..256).map(|i| i % TEST_Q).collect();
        let b: Vec<u64> = (0..256).map(|i| (i * 2) % TEST_Q).collect();

        let start = std::time::Instant::now();
        for _ in 0..100 {
            let _ = dft.multiply(&a, &b);
        }
        let dft_time = start.elapsed();

        let start = std::time::Instant::now();
        for _ in 0..100 {
            let _ = fft.multiply(&a, &b);
        }
        let fft_time = start.elapsed();

        let speedup_tenths = (dft_time.as_nanos() * 10) / fft_time.as_nanos().max(1);

        println!("NTT 256 (x100):");
        println!("  DFT (O(N²)):    {:?}", dft_time);
        println!("  FFT (O(NlogN)): {:?}", fft_time);
        println!(
            "  Speedup:        {}.{}x",
            speedup_tenths / 10,
            speedup_tenths % 10
        );

        // Entropy comparison
        let mut wassan = WassanNoiseField::from_shadow_seed(42);

        let start = std::time::Instant::now();
        for _ in 0..10000 {
            let _ = wassan.sample();
        }
        let wassan_time = start.elapsed();

        println!("\nNoise Generation (x10000):");
        println!("  WASSAN:   {:?}", wassan_time);
        println!("  Per sample: {:?}", wassan_time / 10000);

        println!("\n=========================================\n");
    }
}
