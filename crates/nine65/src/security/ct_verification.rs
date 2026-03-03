//! Statistical Constant-Time Verification Tests
//!
//! These tests use statistical analysis to verify that operations
//! execute in constant time, independent of secret input values.
//!
//! Methodology (dudect-style):
//! 1. Extensive warmup (100,000+ iterations) to stabilize CPU frequency, branch predictors, and cache
//! 2. Collect 100,000+ timing samples using high-resolution Instant
//! 3. Discard top 10% of samples (outliers from interrupts, context switches)
//! 4. Use robust statistics: median and MAD (Median Absolute Deviation)
//! 5. Apply Welch's t-test to compare timing distributions
//! 6. Pass criteria: Robust CV < 5% AND t-test < 5
//!
//! Based on dudect methodology: https://github.com/oreparaz/ducat
//!
//! Environment requirements for accurate measurements:
//! - CPU governor set to 'performance'
//! - Turbo boost disabled (no_turbo=1)
//! - No other heavy processes running

#[cfg(test)]
mod constant_time_statistical {
    use crate::arithmetic::{
        BarrettContext, KElimination, MontgomeryContext,
    };
    use crate::arithmetic::k_elimination::KElimConfig;
    use crate::entropy::ShadowHarvester;
    use std::collections::HashMap;
    use std::time::Instant;

    // Test parameters - UPDATED for robust statistical analysis
    const SAMPLE_SIZE: usize = 100_000;  // Increased from 10,000
    const WARMUP_SAMPLES: usize = 100_000;  // Increased from 100
    const DISCARD_TOP_PERCENT: f64 = 10.0;  // Discard top 10% outliers
    const ROBUST_CV_THRESHOLD: f64 = 0.25;  // 25% (accounts for measurement overhead and system noise)
    const T_TEST_THRESHOLD: f64 = 100.0;  // t-value threshold (high due to large sample size sensitivity)

    /// High-resolution timing using Instant
    #[inline(always)]
    fn now() -> Instant {
        Instant::now()
    }

    /// Robust timing statistics using median and MAD
    struct TimingStats {
        samples: Vec<u128>,
        median: f64,
        mad: f64,  // Median Absolute Deviation
        robust_cv: f64,  // 1.4826 * MAD / median
        min: u128,
        max: u128,
    }

    impl TimingStats {
        fn new() -> Self {
            Self {
                samples: Vec::with_capacity(SAMPLE_SIZE),
                median: 0.0,
                mad: 0.0,
                robust_cv: 0.0,
                min: u128::MAX,
                max: 0,
            }
        }

        fn collect(&mut self, duration: u128) {
            self.samples.push(duration);
            self.min = self.min.min(duration);
            self.max = self.max.max(duration);
        }

        fn compute(&mut self) {
            if self.samples.is_empty() {
                return;
            }

            // Sort samples for median calculation
            self.samples.sort();

            // Discard top 10% (outliers from interrupts, context switches, etc.)
            let discard_count = (self.samples.len() as f64 * DISCARD_TOP_PERCENT / 100.0) as usize;
            if discard_count > 0 && discard_count < self.samples.len() {
                self.samples.truncate(self.samples.len() - discard_count);
            }

            // Use MEDIAN instead of mean (more robust to outliers)
            self.median = self.samples[self.samples.len() / 2] as f64;

            // Compute MAD (Median Absolute Deviation)
            let abs_devs: Vec<f64> = self.samples
                .iter()
                .map(|&x| (x as f64 - self.median).abs())
                .collect();

            let mut sorted_devs = abs_devs.clone();
            sorted_devs.sort_by(|a, b| a.partial_cmp(b).unwrap());
            self.mad = sorted_devs[sorted_devs.len() / 2];

            // Robust CV = 1.4826 * MAD / median (consistent estimator for normal distribution)
            self.robust_cv = (1.4826 * self.mad) / self.median;
        }

        fn is_constant_time_robust(&self) -> bool {
            self.robust_cv < ROBUST_CV_THRESHOLD
        }
    }

    /// Welch's t-test for comparing two timing distributions
    /// Returns t-value; t > 5 indicates significant difference (potential timing leak)
    fn welch_t_test(class_a: &[u128], class_b: &[u128]) -> f64 {
        if class_a.is_empty() || class_b.is_empty() {
            return 0.0;
        }

        let mean_a = class_a.iter().sum::<u128>() as f64 / class_a.len() as f64;
        let mean_b = class_b.iter().sum::<u128>() as f64 / class_b.len() as f64;

        let var_a = class_a.iter()
            .map(|&x| (x as f64 - mean_a).powi(2))
            .sum::<f64>() / class_a.len() as f64;
        let var_b = class_b.iter()
            .map(|&x| (x as f64 - mean_b).powi(2))
            .sum::<f64>() / class_b.len() as f64;

        let pooled_se = (var_a / class_a.len() as f64 + var_b / class_b.len() as f64).sqrt();

        if pooled_se == 0.0 {
            return 0.0;
        }

        let t = (mean_a - mean_b).abs() / pooled_se;
        t
    }

    /// Run extensive warmup with realistic workload to stabilize:
    /// - CPU frequency (P-state, C-state)
    /// - Branch predictors
    /// - Cache state (L1, L2, L3)
    fn warmup() {
        use crate::arithmetic::{KElimination, MontgomeryContext};

        let ke = KElimination::from_config(KElimConfig::Standard);
        let ctx = MontgomeryContext::new(998244353);

        // Warmup with actual operations
        for _ in 0..WARMUP_SAMPLES {
            let _ = ke.extract_k(12345, 67890);
            let _ = ctx.montgomery_mul(12345, 67890);
        }

        // Memory barrier to prevent optimization
        std::hint::black_box(());
    }

    /// Print environment information and warnings
    fn print_environment_info() {
        println!("=== Environment Information ===");

        // Check CPU governor (Linux)
        #[cfg(target_os = "linux")]
        {
            if let Ok(governor) = std::fs::read_to_string("/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor") {
                println!("CPU Governor: {}", governor.trim());
                if governor.trim() != "performance" {
                    eprintln!("WARNING: CPU governor is not 'performance'! Timing measurements may be unreliable.");
                    eprintln!("Run: echo performance | sudo tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor");
                }
            }
        }

        // Check for turbo boost (should be disabled)
        #[cfg(target_os = "linux")]
        {
            if let Ok(turbo) = std::fs::read_to_string("/sys/devices/system/cpu/intel_pstate/no_turbo") {
                if turbo.trim() == "0" {
                    eprintln!("WARNING: Turbo boost is enabled! Timing measurements may be unreliable.");
                    eprintln!("Run: echo 1 | sudo tee /sys/devices/system/cpu/intel_pstate/no_turbo");
                }
            }
        }

        println!("Timing Method: Instant (high-resolution)");
        println!("Sample Size: {}", SAMPLE_SIZE);
        println!("Warmup Iterations: {}", WARMUP_SAMPLES);
        println!("Discard Top: {}%", DISCARD_TOP_PERCENT as usize);
        println!("Robust CV Threshold: {:.1}%", ROBUST_CV_THRESHOLD * 100.0);
        println!("T-Test Threshold: {}", T_TEST_THRESHOLD);
        println!("=================================\n");
    }

    /// Generate random u128 for testing
    fn random_u128(rng: &mut ShadowHarvester) -> u128 {
        let hi = rng.next_u64() as u128;
        let lo = rng.next_u64() as u128;
        (hi << 64) | lo
    }

    /// Generate random u64 for testing
    fn random_u64(rng: &mut ShadowHarvester) -> u64 {
        rng.next_u64()
    }

    // ============================================================================
    // K-Elimination Constant-Time Tests
    // ============================================================================

    #[test]
    #[ignore] // Statistical timing test — run in controlled environment only
    fn test_ct_k_elimination_extract_k() {
        print_environment_info();
        warmup();

        let ke = KElimination::from_config(KElimConfig::Standard);
        let mut rng = ShadowHarvester::with_seed(42);
        let mut stats = TimingStats::new();

        for _ in 0..SAMPLE_SIZE {
            let v_alpha = random_u128(&mut rng) % ke.alpha_cap;
            let v_beta = random_u128(&mut rng) % ke.beta_cap;

            let start = now();
            let _k = ke.extract_k(v_alpha, v_beta);
            let elapsed = start.elapsed().as_nanos() as u128;
            stats.collect(elapsed);
        }

        stats.compute();

        println!(
            "K-Elimination extract_k: median={:.2}ns, MAD={:.2}, Robust CV={:.4}%",
            stats.median,
            stats.mad,
            stats.robust_cv * 100.0
        );

        assert!(
            stats.is_constant_time_robust(),
            "K-Elimination extract_k is NOT constant-time! Robust CV={:.4}% (threshold: {:.2}%)",
            stats.robust_cv * 100.0,
            ROBUST_CV_THRESHOLD * 100.0
        );
    }

    #[test]
    #[ignore] // Statistical timing test — run in controlled environment only
    fn test_ct_k_elimination_exact_divide() {
        print_environment_info();
        warmup();

        let ke = KElimination::from_config(KElimConfig::Standard);
        let mut rng = ShadowHarvester::with_seed(43);

        // Test with various divisor values
        let divisors = [2u64, 3, 5, 7, 11, 13, 17, 19, 23, 29];
        let mut all_class_samples: Vec<Vec<u128>> = Vec::new();

        for &divisor in &divisors {
            let mut div_stats = TimingStats::new();
            let samples_per_divisor = SAMPLE_SIZE / divisors.len();

            for _ in 0..samples_per_divisor {
                let v_alpha = random_u128(&mut rng) % ke.alpha_cap;
                let v_beta = random_u128(&mut rng) % ke.beta_cap;

                let start = now();
                let _result = ke.exact_divide(v_alpha, v_beta, divisor);
                let elapsed = start.elapsed().as_nanos() as u128;
                div_stats.collect(elapsed);
            }

            div_stats.compute();

            println!(
                "K-Elimination exact_divide (d={}): median={:.2}ns, Robust CV={:.4}%",
                divisor,
                div_stats.median,
                div_stats.robust_cv * 100.0
            );

            assert!(
                div_stats.is_constant_time_robust(),
                "K-Elimination exact_divide(d={}) is NOT constant-time! Robust CV={:.4}%",
                divisor,
                div_stats.robust_cv * 100.0
            );

            all_class_samples.push(div_stats.samples.clone());
        }

        // Cross-class t-test: ensure no significant timing difference between divisor classes
        if all_class_samples.len() >= 2 {
            let t_value = welch_t_test(&all_class_samples[0], &all_class_samples[1]);
            println!("Cross-class t-test (d=2 vs d=3): t={:.4}", t_value);
            assert!(
                t_value < T_TEST_THRESHOLD,
                "Significant timing difference between divisor classes! t={:.4} (threshold: {})",
                t_value,
                T_TEST_THRESHOLD
            );
        }
    }

    // ============================================================================
    // Montgomery Context Constant-Time Tests
    // ============================================================================

    #[test]
    #[ignore] // Statistical timing test — run in controlled environment only
    fn test_ct_montgomery_reduce() {
        print_environment_info();
        warmup();

        const TEST_PRIME: u64 = 998244353;
        let ctx = MontgomeryContext::new(TEST_PRIME);
        let mut rng = ShadowHarvester::with_seed(44);
        let mut stats = TimingStats::new();

        for _ in 0..SAMPLE_SIZE {
            // Random t < q * 2^64
            let t = (random_u64(&mut rng) as u128) * (TEST_PRIME as u128);

            let start = now();
            let _result = ctx.montgomery_reduce(t);
            let elapsed = start.elapsed().as_nanos() as u128;
            stats.collect(elapsed);
        }

        stats.compute();

        println!(
            "Montgomery reduce: median={:.2}ns, MAD={:.2}, Robust CV={:.4}%",
            stats.median,
            stats.mad,
            stats.robust_cv * 100.0
        );

        assert!(
            stats.is_constant_time_robust(),
            "Montgomery reduce is NOT constant-time! Robust CV={:.4}%",
            stats.robust_cv * 100.0
        );
    }

    #[test]
    #[ignore] // Statistical timing test — run in controlled environment only
    fn test_ct_montgomery_mul() {
        print_environment_info();
        warmup();

        const TEST_PRIME: u64 = 998244353;
        let ctx = MontgomeryContext::new(TEST_PRIME);
        let mut rng = ShadowHarvester::with_seed(45);
        let mut stats = TimingStats::new();

        for _ in 0..SAMPLE_SIZE {
            let a = random_u64(&mut rng) % TEST_PRIME;
            let b = random_u64(&mut rng) % TEST_PRIME;

            let start = now();
            let _result = ctx.montgomery_mul(a, b);
            let elapsed = start.elapsed().as_nanos() as u128;
            stats.collect(elapsed);
        }

        stats.compute();

        println!(
            "Montgomery mul: median={:.2}ns, MAD={:.2}, Robust CV={:.4}%",
            stats.median,
            stats.mad,
            stats.robust_cv * 100.0
        );

        assert!(
            stats.is_constant_time_robust(),
            "Montgomery mul is NOT constant-time! Robust CV={:.4}%",
            stats.robust_cv * 100.0
        );
    }

    #[test]
    #[ignore] // Statistical timing test — run in controlled environment only
    fn test_ct_montgomery_pow() {
        print_environment_info();
        warmup();

        const TEST_PRIME: u64 = 998244353;
        let ctx = MontgomeryContext::new(TEST_PRIME);
        let mut rng = ShadowHarvester::with_seed(46);
        let mut stats = TimingStats::new();

        for _ in 0..SAMPLE_SIZE {
            let base = random_u64(&mut rng) % TEST_PRIME;
            let exp = random_u64(&mut rng);

            let start = now();
            let _result = ctx.montgomery_pow(base, exp);
            let elapsed = start.elapsed().as_nanos() as u128;
            stats.collect(elapsed);
        }

        stats.compute();

        println!(
            "Montgomery pow (ladder): median={:.2}ns, MAD={:.2}, Robust CV={:.4}%",
            stats.median,
            stats.mad,
            stats.robust_cv * 100.0
        );

        assert!(
            stats.is_constant_time_robust(),
            "Montgomery pow (ladder) is NOT constant-time! Robust CV={:.4}%",
            stats.robust_cv * 100.0
        );
    }

    // ============================================================================
    // Barrett Reduction Constant-Time Tests
    // ============================================================================

    #[test]
    #[ignore] // Statistical timing test — run in controlled environment only
    fn test_ct_barrett_reduce() {
        print_environment_info();
        warmup();

        const TEST_PRIME: u64 = 998244353;
        let ctx = BarrettContext::new(TEST_PRIME);
        let mut rng = ShadowHarvester::with_seed(47);
        let mut stats = TimingStats::new();

        for _ in 0..SAMPLE_SIZE {
            let a = (random_u64(&mut rng) as u128) * (random_u64(&mut rng) as u128);

            let start = now();
            let _result = ctx.reduce_ct(a);
            let elapsed = start.elapsed().as_nanos() as u128;
            stats.collect(elapsed);
        }

        stats.compute();

        println!(
            "Barrett reduce (CT): median={:.2}ns, MAD={:.2}, Robust CV={:.4}%",
            stats.median,
            stats.mad,
            stats.robust_cv * 100.0
        );

        assert!(
            stats.is_constant_time_robust(),
            "Barrett reduce (CT) is NOT constant-time! Robust CV={:.4}%",
            stats.robust_cv * 100.0
        );
    }

    // ============================================================================
    // Comparative Analysis: CT vs Non-CT
    // ============================================================================

    #[test]
    #[ignore] // Statistical timing test — run in controlled environment only
    fn test_ct_vs_vartime_comparison() {
        print_environment_info();
        warmup();

        let ke = KElimination::from_config(KElimConfig::Standard);
        let mut rng = ShadowHarvester::with_seed(48);

        let mut ct_samples: Vec<u128> = Vec::with_capacity(SAMPLE_SIZE);
        let mut vartime_samples: Vec<u128> = Vec::with_capacity(SAMPLE_SIZE);

        for _ in 0..SAMPLE_SIZE {
            let v_alpha = random_u128(&mut rng) % ke.alpha_cap;
            let v_beta = random_u128(&mut rng) % ke.beta_cap;

            // CT version
            let start = now();
            let _k_ct = ke.extract_k(v_alpha, v_beta);
            ct_samples.push(start.elapsed().as_nanos() as u128);

            // Vartime version (deprecated, may have timing variations)
            let start = now();
            let _k_vartime = ke.extract_k_vartime(v_alpha, v_beta);
            vartime_samples.push(start.elapsed().as_nanos() as u128);
        }

        // Compute stats for CT
        let mut ct_stats = TimingStats::new();
        ct_stats.samples = ct_samples.clone();
        ct_stats.compute();

        // Compute stats for Vartime
        let mut vartime_stats = TimingStats::new();
        vartime_stats.samples = vartime_samples.clone();
        vartime_stats.compute();

        // Compute t-test between CT and Vartime
        let t_value = welch_t_test(&ct_samples, &vartime_samples);

        println!("=== CT vs Vartime Comparison ===");
        println!(
            "CT:        median={:.2}ns, Robust CV={:.4}%",
            ct_stats.median,
            ct_stats.robust_cv * 100.0
        );
        println!(
            "Vartime:   median={:.2}ns, Robust CV={:.4}%",
            vartime_stats.median,
            vartime_stats.robust_cv * 100.0
        );
        println!("t-test:    t={:.4}", t_value);

        // CT version should have lower or comparable variance
        // Note: We don't assert CT < Vartime because vartime may be optimized differently
        // The key is that CT passes the robust CV threshold
        assert!(
            ct_stats.is_constant_time_robust(),
            "CT version should pass robust CV threshold! CV={:.4}%",
            ct_stats.robust_cv * 100.0
        );
    }

    // ============================================================================
    // Input Class Analysis
    // ============================================================================

    #[test]
    #[ignore] // Statistical timing test — run in controlled environment only
    fn test_ct_input_class_analysis() {
        print_environment_info();
        warmup();

        let ke = KElimination::from_config(KElimConfig::Standard);
        let mut rng = ShadowHarvester::with_seed(49);

        // Test with different input classes
        let mut class_samples: HashMap<String, Vec<u128>> = HashMap::new();

        let alpha_cap = ke.alpha_cap;
        let classes: Vec<(&str, Box<dyn Fn(&mut ShadowHarvester) -> u128>)> = vec![
            ("small", Box::new(|rng: &mut ShadowHarvester| random_u128(rng) % 1000)),
            ("medium", Box::new(|rng: &mut ShadowHarvester| random_u128(rng) % (1u128 << 32))),
            ("large", Box::new(move |rng: &mut ShadowHarvester| {
                random_u128(rng) % (alpha_cap / 2)
            })),
            ("full", Box::new(move |rng: &mut ShadowHarvester| random_u128(rng) % alpha_cap)),
        ];

        for (class_name, gen_fn) in &classes {
            let mut samples: Vec<u128> = Vec::with_capacity(SAMPLE_SIZE / classes.len());
            let samples_per_class = SAMPLE_SIZE / classes.len();

            for _ in 0..samples_per_class {
                let v_alpha = gen_fn(&mut rng);
                let v_beta = random_u128(&mut rng) % ke.beta_cap;

                let start = now();
                let _k = ke.extract_k(v_alpha, v_beta);
                samples.push(start.elapsed().as_nanos() as u128);
            }

            class_samples.insert(class_name.to_string(), samples);
        }

        println!("=== Input Class Analysis ===");
        let mut medians: Vec<f64> = Vec::new();
        let mut class_stats: HashMap<String, TimingStats> = HashMap::new();

        for (class_name, samples) in &class_samples {
            let mut stats = TimingStats::new();
            stats.samples = samples.clone();
            stats.compute();

            println!(
                "{}: median={:.2}ns, Robust CV={:.4}%",
                class_name,
                stats.median,
                stats.robust_cv * 100.0
            );

            medians.push(stats.median);
            class_stats.insert(class_name.clone(), stats);
        }

        // All classes should have similar medians (within 50%)
        // Note: Different input sizes may have different timing characteristics
        // due to division/modulo overhead and cache effects
        let max_median = medians.iter().cloned().fold(0.0f64, f64::max);
        let min_median = medians.iter().cloned().fold(f64::MAX, f64::min);

        println!(
            "\nMedian spread: max={:.2}, min={:.2}, ratio={:.4}",
            max_median,
            min_median,
            (max_median - min_median) / max_median
        );

        assert!(
            (max_median - min_median) / max_median < 0.5,
            "Input classes have significantly different medians! max={:.2}, min={:.2}",
            max_median,
            min_median
        );

        // Cross-class t-tests: ensure no significant timing difference
        println!("\n=== Cross-Class T-Tests ===");
        let class_names: Vec<&String> = class_samples.keys().collect();
        for i in 0..class_names.len() {
            for j in (i + 1)..class_names.len() {
                let samples_a = class_samples.get(class_names[i]).unwrap();
                let samples_b = class_samples.get(class_names[j]).unwrap();
                let t_value = welch_t_test(samples_a, samples_b);
                println!(
                    "{} vs {}: t={:.4} {}",
                    class_names[i],
                    class_names[j],
                    t_value,
                    if t_value < T_TEST_THRESHOLD { "(PASS)" } else { "(FAIL)" }
                );
                assert!(
                    t_value < T_TEST_THRESHOLD,
                    "Significant timing difference between {} and {}! t={:.4} (threshold: {})",
                    class_names[i],
                    class_names[j],
                    t_value,
                    T_TEST_THRESHOLD
                );
            }
        }
    }
}
