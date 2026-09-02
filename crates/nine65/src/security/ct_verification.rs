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
//!
//! # Two families of test in this file — they are NOT equally strong
//!
//! **(a) Robust-CV tests** (`test_ct_*` over K-Elimination / Montgomery /
//! Barrett). These time ONE scalar operation per `Instant::now()` pair and
//! report the dispersion of that single distribution. Read the caveat before
//! trusting them: on Linux `Instant::now()` costs roughly 20-30 ns and has
//! ~1 ns granularity, while the operations under test are single-digit
//! nanoseconds. The measurement is therefore dominated by timer overhead, the
//! samples collapse onto a couple of discrete values, and the Median Absolute
//! Deviation frequently lands on exactly 0 — which makes `robust_cv` 0.0 and
//! the assertion pass *vacuously*. A low CV here is evidence that the timer
//! is coarse, not evidence that the operation is constant-time. These tests
//! are kept as regression tripwires for gross slowdowns; they are explicitly
//! NOT the constant-time argument.
//!
//! **(b) dudect two-class tests** (`test_ct_dudect_*`). These are the real
//! leak detectors. They compare two *input classes* under interleaved,
//! randomised scheduling and apply Welch's t-test to the cropped samples.
//! Crucially each run also produces a CONTROL statistic: two independent
//! sample streams drawn from the *same* class. The control measures the
//! machine's noise floor. Interpretation is then three-valued, and the
//! third value is not a failure of nerve:
//!
//! | control t | signal t | conclusion                                    |
//! |-----------|----------|-----------------------------------------------|
//! | < 5       | < 5      | constant-time at this sample size             |
//! | < 5       | >= 5     | MEASURED timing dependence on the input class |
//! | >= 5      | any      | INCONCLUSIVE — noise floor exceeds threshold  |
//!
//! Without the control arm a large t on a shared/co-tenanted machine cannot be
//! distinguished from a neighbouring workload, which is precisely why the
//! earlier version of this file could not be believed in either direction.

#[cfg(test)]
mod constant_time_statistical {
    use crate::arithmetic::k_elimination::{AdjacencyKElim, KElimConfig};
    use crate::arithmetic::{BarrettContext, KElimination, MontgomeryContext};
    use crate::entropy::ShadowHarvester;
    use crate::ops::rns_fhe::{exact_modulus_switch_drop_poly, DualRNSPoly, RNSFHEContext};
    use crate::params::SecureConfig;
    use std::collections::HashMap;
    use std::time::Instant;

    // Test parameters - UPDATED for robust statistical analysis
    const SAMPLE_SIZE: usize = 100_000; // Increased from 10,000
    const WARMUP_SAMPLES: usize = 100_000; // Increased from 100
    const DISCARD_TOP_PERCENT: f64 = 10.0; // Discard top 10% outliers

    // Thresholds. These are the values the module header has always documented
    // and they are back where they belong.
    //
    // HISTORY (do not re-loosen without evidence): these were previously
    // widened to CV < 25% and t < 100 so the suite would go green. That was
    // theatre twice over — a t-threshold of 100 does not reject any leak a
    // t-threshold of 5 would not already have caught by an order of magnitude,
    // and every test in the file was `#[ignore]`d anyway, so nothing was
    // measuring anything. The fix for an environment-sensitive test is to run
    // it on a quiesced machine and to add a control arm (see `dudect_two_class`
    // below), not to move the goalposts.
    const ROBUST_CV_THRESHOLD: f64 = 0.05; // 5% — documented value, restored
    const T_TEST_THRESHOLD: f64 = 5.0; // dudect's canonical ~4.5, rounded up

    /// Smallest median (ns) at which the robust-CV statistic can even LAND
    /// inside the pass band, given a 1 ns timer tick.
    ///
    /// MAD is quantised to whole nanoseconds, so `robust_cv = 1.4826 * MAD /
    /// median` can only take the values 0, 1.4826/median, 2*1.4826/median, ...
    /// For the 5% threshold to be a real test rather than a coin flip, the
    /// quantum must be at most half the threshold, i.e.
    ///     1.4826 / median <= ROBUST_CV_THRESHOLD / 2
    ///     median          >= 2 * 1.4826 / 0.05  ~= 59.3 ns
    ///
    /// This is not a hypothetical. Measured on this machine, `montgomery_reduce`
    /// reported CV = 0.0000% (MAD 0, median 29 ns) on one run and CV = 5.2950%
    /// (MAD 1, median 28 ns) on the next — a pass and a fail from the SAME code
    /// on the SAME box, separated by one tick of the clock. Below this median
    /// the CV number is reported but not asserted on; the operation's real
    /// constant-time evidence is its batched `test_ct_dudect_*` counterpart,
    /// which moves the timer out of the inner loop entirely.
    const CV_RESOLVABLE_MEDIAN_NS: f64 = 2.0 * 1.4826 / ROBUST_CV_THRESHOLD;

    /// High-resolution timing using Instant
    #[inline(always)]
    fn now() -> Instant {
        Instant::now()
    }

    /// Robust timing statistics using median and MAD
    struct TimingStats {
        samples: Vec<u128>,
        median: f64,
        mad: f64,       // Median Absolute Deviation
        robust_cv: f64, // 1.4826 * MAD / median
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
            let abs_devs: Vec<f64> = self
                .samples
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

        /// Whether the robust-CV statistic is resolvable at all for this
        /// distribution. See `CV_RESOLVABLE_MEDIAN_NS`.
        fn cv_is_resolvable(&self) -> bool {
            self.median >= CV_RESOLVABLE_MEDIAN_NS
        }

        /// Largest MAD, in timer ticks, that the "too coarse to resolve"
        /// explanation can actually account for.
        ///
        /// Below `CV_RESOLVABLE_MEDIAN_NS` the CV threshold is unusable because
        /// MAD is quantised to whole nanoseconds. That argument explains a MAD
        /// of 0 or 1 tick. It does NOT explain a MAD of 5 ticks on a 30 ns
        /// median — that is a genuinely spread distribution, and quantisation
        /// is no excuse for declining to fail on it.
        const MAX_UNRESOLVABLE_MAD_TICKS: f64 = 1.0;

        /// Non-panicking form of the CV check, so a test can report EVERY
        /// class it measured before failing on any of them.
        ///
        /// # Below the resolvable median this still asserts something
        ///
        /// An earlier form returned `None` unconditionally when
        /// `!cv_is_resolvable()`, which left `test_ct_montgomery_reduce`,
        /// `test_ct_montgomery_mul` and `test_ct_barrett_reduce` reporting
        /// `ok` while asserting nothing whatsoever about the operation named in
        /// the test. A gate that cannot fail is not a gate, and nothing in the
        /// test name or the CI job listing said so.
        ///
        /// The quantisation argument bounds what those tests can check; it does
        /// not reduce it to nothing. At a sub-`CV_RESOLVABLE_MEDIAN_NS` median
        /// the timer can still distinguish "MAD within one tick" from "MAD of
        /// several ticks", and the former is the claim the batched dudect
        /// counterpart is relied on to sharpen — not a claim to skip. So below
        /// the resolvable median this asserts the tick bound instead of the CV
        /// threshold, and says which one it applied.
        fn cv_failure(&self, label: &str) -> Option<String> {
            if !self.cv_is_resolvable() {
                return if self.mad <= Self::MAX_UNRESOLVABLE_MAD_TICKS {
                    None
                } else {
                    Some(format!(
                        "{label}: median {:.1}ns is below the {:.1}ns CV \
                         resolution floor, but MAD={:.2} ticks exceeds the \
                         {:.1}-tick bound that timer quantisation can explain. \
                         The distribution is genuinely spread, not merely \
                         unresolvable.",
                        self.median,
                        CV_RESOLVABLE_MEDIAN_NS,
                        self.mad,
                        Self::MAX_UNRESOLVABLE_MAD_TICKS,
                    ))
                };
            }
            if self.is_constant_time_robust() {
                None
            } else {
                Some(format!(
                    "{label}: robust CV={:.4}% >= {:.2}%",
                    self.robust_cv * 100.0,
                    ROBUST_CV_THRESHOLD * 100.0
                ))
            }
        }

        /// True when the sample distribution is too coarse for the robust-CV
        /// statistic to mean anything: a MAD of exactly zero drives `robust_cv`
        /// to 0.0 and makes `is_constant_time_robust` pass no matter what the
        /// code under test does. See the module header, family (a).
        fn cv_is_vacuous(&self) -> bool {
            self.mad == 0.0
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

        let var_a = class_a
            .iter()
            .map(|&x| (x as f64 - mean_a).powi(2))
            .sum::<f64>()
            / class_a.len() as f64;
        let var_b = class_b
            .iter()
            .map(|&x| (x as f64 - mean_b).powi(2))
            .sum::<f64>()
            / class_b.len() as f64;

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

    /// Median cost of an EMPTY measured region, i.e. `Instant::now()` +
    /// `elapsed()` and nothing else. This is the resolution floor of every
    /// single-operation measurement in family (a).
    fn timer_floor_ns() -> u128 {
        let mut samples: Vec<u128> = Vec::with_capacity(20_000);
        for _ in 0..20_000 {
            let start = now();
            std::hint::black_box(0u64);
            samples.push(start.elapsed().as_nanos());
        }
        samples.sort_unstable();
        samples[samples.len() / 2]
    }

    /// Print environment information and warnings
    fn print_environment_info() {
        println!("=== Environment Information ===");

        // Check CPU governor (Linux)
        #[cfg(target_os = "linux")]
        {
            if let Ok(governor) =
                std::fs::read_to_string("/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor")
            {
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
            if let Ok(turbo) =
                std::fs::read_to_string("/sys/devices/system/cpu/intel_pstate/no_turbo")
            {
                if turbo.trim() == "0" {
                    eprintln!(
                        "WARNING: Turbo boost is enabled! Timing measurements may be unreliable."
                    );
                    eprintln!(
                        "Run: echo 1 | sudo tee /sys/devices/system/cpu/intel_pstate/no_turbo"
                    );
                }
            }
        }

        // Measure the floor of the instrument itself. Any reported median at
        // or near this value is the cost of `Instant::now()`, not the cost of
        // the operation, and the corresponding CV number means nothing.
        let floor = timer_floor_ns();
        println!("Timer floor (empty measured region): median {floor} ns");
        println!("Timing Method: Instant (high-resolution)");
        println!("Sample Size: {}", SAMPLE_SIZE);
        println!("Warmup Iterations: {}", WARMUP_SAMPLES);
        println!("Discard Top: {}%", DISCARD_TOP_PERCENT as usize);
        println!("Robust CV Threshold: {:.1}%", ROBUST_CV_THRESHOLD * 100.0);
        println!("T-Test Threshold: {}", T_TEST_THRESHOLD);
        println!("=================================\n");
    }

    /// Emit a robust-CV line plus, when applicable, the vacuity warning that
    /// makes the number honest.
    fn report_cv(label: &str, stats: &TimingStats) {
        println!(
            "{label}: median={:.2}ns, MAD={:.2}, Robust CV={:.4}%, min={}, max={}",
            stats.median,
            stats.mad,
            stats.robust_cv * 100.0,
            stats.min,
            stats.max
        );
        if !stats.cv_is_resolvable() {
            println!(
                "  CV NOT ASSERTED (median {:.1}ns is below the {:.1}ns at which \
                 a 1ns-quantised MAD can land inside the {:.1}% band). ASSERTED \
                 INSTEAD: MAD={:.2} <= {:.1} tick — the bound quantisation can \
                 explain. The sharper constant-time evidence for this operation \
                 is its batched test_ct_dudect_* counterpart.",
                stats.median,
                CV_RESOLVABLE_MEDIAN_NS,
                ROBUST_CV_THRESHOLD * 100.0,
                stats.mad,
                TimingStats::MAX_UNRESOLVABLE_MAD_TICKS,
            );
        } else if stats.cv_is_vacuous() {
            println!(
                "  NOTE: MAD == 0 at a resolvable median — the distribution \
                 collapsed to a single value. Treat as suspicious, not as proof."
            );
        }
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
            let k = ke.extract_k(std::hint::black_box(v_alpha), std::hint::black_box(v_beta));
            std::hint::black_box(k);
            let elapsed = start.elapsed().as_nanos() as u128;
            stats.collect(elapsed);
        }

        stats.compute();

        report_cv("K-Elimination extract_k", &stats);

        assert!(
            stats.cv_failure("K-Elimination extract_k").is_none(),
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
        let mut failures: Vec<String> = Vec::new();

        for &divisor in &divisors {
            let mut div_stats = TimingStats::new();
            let samples_per_divisor = SAMPLE_SIZE / divisors.len();

            for _ in 0..samples_per_divisor {
                let v_alpha = random_u128(&mut rng) % ke.alpha_cap;
                let v_beta = random_u128(&mut rng) % ke.beta_cap;

                let start = now();
                let r = ke.exact_divide(
                    std::hint::black_box(v_alpha),
                    std::hint::black_box(v_beta),
                    std::hint::black_box(divisor),
                );
                std::hint::black_box(r);
                let elapsed = start.elapsed().as_nanos() as u128;
                div_stats.collect(elapsed);
            }

            div_stats.compute();

            println!(
                "K-Elimination exact_divide (d={}): median={:.2}ns, MAD={:.2}, Robust CV={:.4}%",
                divisor,
                div_stats.median,
                div_stats.mad,
                div_stats.robust_cv * 100.0
            );

            failures.extend(div_stats.cv_failure(&format!("exact_divide(d={divisor})")));
            all_class_samples.push(div_stats.samples.clone());
        }

        // Cross-class t-test: ensure no significant timing difference between divisor classes
        if all_class_samples.len() >= 2 {
            let t_value = welch_t_test(&all_class_samples[0], &all_class_samples[1]);
            // REPORTED, NOT ASSERTED — and this is a repair, not a relaxation.
            //
            // The d=2 samples are all collected, then all the d=3 samples: the
            // classes are separated in TIME, so clock drift between the two
            // blocks is indistinguishable from a divisor effect. Measured on
            // this machine across three consecutive runs of unchanged code the
            // statistic read t = 14.31, then 2.57, then 15.77. A gate whose
            // value swings by 6x on identical code is not measuring the code.
            //
            // The same question — does exact_divide's timing depend on the
            // divisor? — is asserted properly by
            // `test_ct_dudect_k_elim_exact_divide_divisor_classes`, which
            // randomises class order per measurement and carries a control
            // arm. On the same machine that test reads t = 2.54 / 3.24 / 4.89
            // / 4.32 with controls of 0.28-3.03. Coverage moved; it was not
            // dropped.
            println!(
                "Cross-class t-test (d=2 vs d=3), BLOCK-measured, reported only: t={t_value:.4}"
            );
        }

        // Assert last so that every divisor's numbers are always emitted, even
        // on failure. A diagnostic suite that stops printing at the first bad
        // class is useless for diagnosis.
        assert!(
            failures.is_empty(),
            "K-Elimination exact_divide is NOT constant-time: {}",
            failures.join("; ")
        );
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
            let r = ctx.montgomery_reduce(std::hint::black_box(t));
            std::hint::black_box(r);
            let elapsed = start.elapsed().as_nanos() as u128;
            stats.collect(elapsed);
        }

        stats.compute();

        report_cv("Montgomery reduce", &stats);

        assert!(
            stats.cv_failure("Montgomery reduce").is_none(),
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
            let r = ctx.montgomery_mul(std::hint::black_box(a), std::hint::black_box(b));
            std::hint::black_box(r);
            let elapsed = start.elapsed().as_nanos() as u128;
            stats.collect(elapsed);
        }

        stats.compute();

        report_cv("Montgomery mul", &stats);

        assert!(
            stats.cv_failure("Montgomery mul").is_none(),
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
            let r = ctx.montgomery_pow(std::hint::black_box(base), std::hint::black_box(exp));
            std::hint::black_box(r);
            let elapsed = start.elapsed().as_nanos() as u128;
            stats.collect(elapsed);
        }

        stats.compute();

        report_cv("Montgomery pow (ladder)", &stats);

        assert!(
            stats.cv_failure("Montgomery pow (ladder)").is_none(),
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
            let r = ctx.reduce_ct(std::hint::black_box(a));
            std::hint::black_box(r);
            let elapsed = start.elapsed().as_nanos() as u128;
            stats.collect(elapsed);
        }

        stats.compute();

        report_cv("Barrett reduce (CT)", &stats);

        assert!(
            stats.cv_failure("Barrett reduce (CT)").is_none(),
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
            let k_ct = ke.extract_k(std::hint::black_box(v_alpha), std::hint::black_box(v_beta));
            std::hint::black_box(k_ct);
            ct_samples.push(start.elapsed().as_nanos() as u128);

            // Vartime version (deprecated, may have timing variations)
            let start = now();
            let k_vt =
                ke.extract_k_vartime(std::hint::black_box(v_alpha), std::hint::black_box(v_beta));
            std::hint::black_box(k_vt);
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
            ct_stats.cv_failure("extract_k (CT)").is_none(),
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
            (
                "small",
                Box::new(|rng: &mut ShadowHarvester| random_u128(rng) % 1000),
            ),
            (
                "medium",
                Box::new(|rng: &mut ShadowHarvester| random_u128(rng) % (1u128 << 32)),
            ),
            (
                "large",
                Box::new(move |rng: &mut ShadowHarvester| random_u128(rng) % (alpha_cap / 2)),
            ),
            (
                "full",
                Box::new(move |rng: &mut ShadowHarvester| random_u128(rng) % alpha_cap),
            ),
        ];

        for (class_name, gen_fn) in &classes {
            let mut samples: Vec<u128> = Vec::with_capacity(SAMPLE_SIZE / classes.len());
            let samples_per_class = SAMPLE_SIZE / classes.len();

            for _ in 0..samples_per_class {
                let v_alpha = gen_fn(&mut rng);
                let v_beta = random_u128(&mut rng) % ke.beta_cap;

                let start = now();
                let k = ke.extract_k(std::hint::black_box(v_alpha), std::hint::black_box(v_beta));
                std::hint::black_box(k);
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

        // All classes should have similar medians (within 50%).
        //
        // READ THE THRESHOLD BEFORE READING THE VERDICT. 50% is a
        // gross-breakage tripwire, not a constant-time gate, and the gap
        // between it and reality is two orders of magnitude: the operand-
        // magnitude effect actually present in `extract_k` on this machine is
        // 0.63% (medians 2,403,289ns vs 2,388,188ns per 4096-call batch,
        // t = 25.6), measured by
        // `test_ct_dudect_k_elim_extract_k_operand_magnitude`. This test
        // reports `ok` while that leak is present, and always would.
        //
        // It cannot do better, for a reason that is structural rather than a
        // matter of threshold choice: it times ONE ~590ns call per sample
        // through a timer whose own floor is ~21ns, so per-call timer noise
        // swamps a single-digit-nanosecond class difference. Resolving that
        // effect requires moving the clock outside a batch, which is what the
        // dudect family does.
        //
        // Kept because a gross regression -- a class that suddenly costs 2x --
        // would still trip it, and that is worth having. Reported loudly so
        // nobody reads its `ok` as evidence of constant time.
        //
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

        println!(
            "  RESOLUTION: this check only fails at >=50% median spread. The real \
             operand-magnitude effect on extract_k is 0.63% (t=25.6), measured by \
             test_ct_dudect_k_elim_extract_k_operand_magnitude. An `ok` here is NOT \
             evidence of constant time."
        );
        let mut failures: Vec<String> = Vec::new();
        if (max_median - min_median) / max_median >= 0.5 {
            failures.push(format!(
                "median spread max={max_median:.2} min={min_median:.2} exceeds 50%"
            ));
        }

        // Cross-class t-tests: ensure no significant timing difference.
        //
        // CAVEAT, and it is a large one: the four classes above are measured in
        // four CONTIGUOUS blocks, not interleaved. Any drift in CPU frequency,
        // cache occupancy or co-tenant load between blocks is attributed to the
        // class rather than to the clock, so a large t here is not by itself
        // evidence of a leak. The `test_ct_dudect_*` tests below fix this by
        // randomising class order per measurement and by carrying a control arm.
        println!("\n=== Cross-Class T-Tests (block-measured; see caveat) ===");
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
                    if t_value < T_TEST_THRESHOLD {
                        "(under)"
                    } else {
                        "(over)"
                    }
                );
                // Reported, not asserted — same block-measurement defect as in
                // `test_ct_k_elimination_exact_divide`. The asserted form of
                // this question is
                // `test_ct_dudect_k_elim_extract_k_operand_magnitude`, which
                // interleaves the classes; note that it currently FAILS with a
                // measured leak that this block-measured version never saw.
            }
        }

        // Assert only after every pair has been printed.
        assert!(
            failures.is_empty(),
            "input-class timing differences detected: {}",
            failures.join("; ")
        );
    }

    // ========================================================================
    // dudect two-class harness (family (b) — see module header)
    // ========================================================================

    /// Number of measurement rounds per dudect test. Each round times THREE
    /// executions (class A, an independent second draw of class A for the
    /// control arm, and class B), so a round costs ~3 operations.
    const DUDECT_ROUNDS: usize = 3_000;

    /// Size of the pre-generated input pool per class. Inputs are built up
    /// front and only INDEXED inside the measurement loop, so allocation and
    /// RNG cost never lands inside a timed region.
    const DUDECT_POOL: usize = 24;

    /// Percentile above which samples are cropped, computed over the pooled
    /// distribution of all three streams so the crop cannot favour a class.
    const DUDECT_CROP_PERCENTILE: f64 = 90.0;

    /// Outcome of a two-class dudect measurement.
    struct DudectResult {
        /// Welch t between class A and class B — the leak statistic.
        t_signal: f64,
        /// Welch t between two independent draws of class A — the noise floor.
        /// Any |t| the machine produces here is achievable with NO class
        /// difference at all, so it bounds what `t_signal` can mean.
        t_control: f64,
        median_a: f64,
        median_b: f64,
        kept: usize,
        total: usize,
    }

    impl DudectResult {
        /// Three-valued verdict. `None` = inconclusive (noise floor too high).
        fn is_constant_time(&self) -> Option<bool> {
            if self.t_control >= T_TEST_THRESHOLD {
                None
            } else {
                Some(self.t_signal < T_TEST_THRESHOLD)
            }
        }

        fn report(&self, label: &str) {
            println!("--- dudect: {label} ---");
            println!(
                "  samples kept {}/{} after {:.0}th-percentile crop",
                self.kept, self.total, DUDECT_CROP_PERCENTILE
            );
            println!(
                "  median class A = {:.1}ns, median class B = {:.1}ns",
                self.median_a, self.median_b
            );
            println!("  t_control (A vs A', same class) = {:.4}", self.t_control);
            println!("  t_signal  (A vs B,  cross class) = {:.4}", self.t_signal);
            match self.is_constant_time() {
                None => println!(
                    "  VERDICT: INCONCLUSIVE — control t={:.4} >= {T_TEST_THRESHOLD}; \
                     this machine's noise floor already exceeds the threshold, so \
                     t_signal cannot be attributed to the input class.",
                    self.t_control
                ),
                Some(true) => println!(
                    "  VERDICT: CONSTANT-TIME at this sample size (control and \
                     signal both below {T_TEST_THRESHOLD})."
                ),
                Some(false) => println!(
                    "  VERDICT: TIMING DEPENDENCE MEASURED — control t={:.4} is \
                     below threshold but signal t={:.4} is not. The difference \
                     tracks the input class, not the machine.",
                    self.t_control, self.t_signal
                ),
            }
        }
    }

    /// Build the three measurement pools with INTERLEAVED allocation order
    /// (a[0], a2[0], b[0], a[1], a2[1], b[1], ...).
    ///
    /// This is not cosmetic. Allocating each class's pool contiguously gives
    /// the three classes systematically different heap placement — different
    /// pages, different cache sets, possibly different NUMA/THP behaviour —
    /// and placement is a per-RUN constant that interleaving the MEASUREMENTS
    /// cannot cancel. Symptom of getting this wrong: a signal t comfortably
    /// above threshold whose SIGN flips between runs, which is what an earlier
    /// revision of these tests produced for `extract_k`. `mk_a` is called twice
    /// per iteration to give two independent draws of the same class, so the
    /// control arm sees exactly the placement diversity the signal arm does.
    fn interleaved_pools<I, F, G>(
        count: usize,
        mut mk_a: F,
        mut mk_b: G,
    ) -> (Vec<I>, Vec<I>, Vec<I>)
    where
        F: FnMut() -> I,
        G: FnMut() -> I,
    {
        let mut a = Vec::with_capacity(count);
        let mut a2 = Vec::with_capacity(count);
        let mut b = Vec::with_capacity(count);
        for _ in 0..count {
            a.push(mk_a());
            a2.push(mk_a());
            b.push(mk_b());
        }
        (a, a2, b)
    }

    fn percentile(sorted: &[u64], pct: f64) -> u64 {
        if sorted.is_empty() {
            return u64::MAX;
        }
        let idx = ((sorted.len() as f64) * pct / 100.0) as usize;
        sorted[idx.min(sorted.len() - 1)]
    }

    fn mean(v: &[u64]) -> f64 {
        v.iter().map(|&x| x as f64).sum::<f64>() / v.len() as f64
    }

    fn median_of(v: &[u64]) -> f64 {
        if v.is_empty() {
            return 0.0;
        }
        let mut s = v.to_vec();
        s.sort_unstable();
        s[s.len() / 2] as f64
    }

    /// Welch's t over u64 nanosecond samples (sample variance, n-1).
    fn welch_t_u64(a: &[u64], b: &[u64]) -> f64 {
        if a.len() < 2 || b.len() < 2 {
            return 0.0;
        }
        let (ma, mb) = (mean(a), mean(b));
        let va = a.iter().map(|&x| (x as f64 - ma).powi(2)).sum::<f64>() / (a.len() - 1) as f64;
        let vb = b.iter().map(|&x| (x as f64 - mb).powi(2)).sum::<f64>() / (b.len() - 1) as f64;
        let se = (va / a.len() as f64 + vb / b.len() as f64).sqrt();
        if se == 0.0 {
            return 0.0;
        }
        (ma - mb).abs() / se
    }

    /// Interleaved two-class dudect measurement with a control arm.
    ///
    /// `pool_a` and `pool_a2` are two INDEPENDENT draws from the same input
    /// class; `pool_b` is the contrasting class. Every round measures one
    /// sample from each of the three pools in a randomised order, so machine
    /// drift is shared by all three streams instead of accruing to whichever
    /// stream happened to be measured last.
    fn dudect_two_class<I, F>(
        rng: &mut ShadowHarvester,
        pool_a: &[I],
        pool_a2: &[I],
        pool_b: &[I],
        rounds: usize,
        mut run: F,
    ) -> DudectResult
    where
        F: FnMut(&I),
    {
        let mut sa: Vec<u64> = Vec::with_capacity(rounds);
        let mut sa2: Vec<u64> = Vec::with_capacity(rounds);
        let mut sb: Vec<u64> = Vec::with_capacity(rounds);

        // Untimed warmup over both classes so first-touch page faults and
        // branch-predictor training are not charged to whichever class runs
        // first.
        for i in 0..pool_a.len().max(pool_b.len()) {
            run(&pool_a[i % pool_a.len()]);
            run(&pool_a2[i % pool_a2.len()]);
            run(&pool_b[i % pool_b.len()]);
        }

        for _ in 0..rounds {
            // Fisher-Yates on a 3-element order.
            let mut order = [0u8, 1, 2];
            for i in (1..3usize).rev() {
                let j = (rng.next_u64() as usize) % (i + 1);
                order.swap(i, j);
            }
            for &which in &order {
                let (pool, sink): (&[I], &mut Vec<u64>) = match which {
                    0 => (pool_a, &mut sa),
                    1 => (pool_a2, &mut sa2),
                    _ => (pool_b, &mut sb),
                };
                let idx = (rng.next_u64() as usize) % pool.len();
                let input = &pool[idx];
                let start = Instant::now();
                run(input);
                let dt = start.elapsed().as_nanos() as u64;
                sink.push(dt);
            }
        }

        let total = sa.len() + sa2.len() + sb.len();

        // Common crop threshold over the pooled distribution, so the crop
        // cannot be chosen per class and thereby manufacture a difference.
        //
        // Known asymmetry, and it is the safe direction: when the two classes
        // have very different medians, a pooled percentile lands inside the
        // SLOWER class, so that class loses part of its tail while the faster
        // one is untouched. That shrinks the measured gap. A positive finding
        // from this harness is therefore a lower bound on the real effect, and
        // the control arm (two streams of the same class) is unaffected because
        // both its streams sit in the same mode.
        let mut pooled: Vec<u64> = Vec::with_capacity(total);
        pooled.extend_from_slice(&sa);
        pooled.extend_from_slice(&sa2);
        pooled.extend_from_slice(&sb);
        pooled.sort_unstable();
        let cutoff = percentile(&pooled, DUDECT_CROP_PERCENTILE);

        let crop = |v: &[u64]| -> Vec<u64> { v.iter().copied().filter(|&x| x <= cutoff).collect() };
        let ca = crop(&sa);
        let ca2 = crop(&sa2);
        let cb = crop(&sb);
        let kept = ca.len() + ca2.len() + cb.len();

        DudectResult {
            t_signal: welch_t_u64(&ca, &cb),
            t_control: welch_t_u64(&ca, &ca2),
            median_a: median_of(&ca),
            median_b: median_of(&cb),
            kept,
            total,
        }
    }

    /// Turn a dudect verdict into a test outcome without ever silently
    /// swallowing a measured leak.
    ///
    /// - measured constant-time  -> pass
    /// - measured NON-constant-time -> panic, naming the statistic
    /// - inconclusive -> pass with a loud INCONCLUSIVE banner (already printed
    ///   by `report`). Failing here would make the test a coin flip on a noisy
    ///   runner; passing silently would be a lie. Printing the control t and
    ///   saying so is the only honest option, and the CI posture (scheduled,
    ///   artifact-uploaded) is built around a human reading it.
    fn assert_dudect(label: &str, r: &DudectResult) {
        r.report(label);
        if r.is_constant_time() == Some(false) {
            panic!(
                "{label}: MEASURED timing dependence on input class — \
                 t_signal={:.4} >= {T_TEST_THRESHOLD} while the same-class \
                 control t_control={:.4} stayed below it. medians: A={:.1}ns \
                 B={:.1}ns.",
                r.t_signal, r.t_control, r.median_a, r.median_b
            );
        }
    }

    // ========================================================================
    // Exact prime-drop (ops::rns_fhe::exact_modulus_switch_drop_poly)
    // ========================================================================
    //
    // This is the exact align-and-drop primitive: for each surviving lane
    //     x_i' = (x_i - r_k) * q_k^{-1}  (mod q_i)
    // It is branch-free at the source level, but every one of those steps is a
    // hardware or software DIVISION on a value derived from the ciphertext:
    // `dropped[c] % q_i`, `src[c] % q_i`, `(x + q_i - r_k) % q_i`, and
    // `(diff as u128 * inv as u128) % q_i as u128`. The last one is a 128-bit
    // remainder by a runtime modulus, which LLVM lowers to `__umodti3` — a
    // shift/subtract loop whose iteration count depends on the operand's bit
    // length. That is a data-dependent execution path, which is exactly what
    // these two tests are for.

    /// Dual-basis geometry used by the prime-drop tests. `n` is deliberately
    /// small enough that one call is tens of microseconds — far above timer
    /// noise — but large enough that the per-coefficient loop dominates the
    /// per-call setup.
    const DROP_N: usize = 1024;

    struct DropBasis {
        main: Vec<u64>,
        anchor: Vec<u64>,
    }

    fn drop_basis() -> DropBasis {
        // Real production basis: secure_128 main primes plus its anchor primes.
        let config = SecureConfig::secure_128().into_config();
        let ctx = RNSFHEContext::new(&config);
        DropBasis {
            main: ctx.config.primes.clone(),
            anchor: ctx.dual_rns.anchor.primes.clone(),
        }
    }

    /// Build a DualRNSPoly whose residues are produced by `gen(prime)`.
    fn drop_poly<G: FnMut(u64) -> u64>(basis: &DropBasis, mut gen: G) -> DualRNSPoly {
        DualRNSPoly {
            main: basis
                .main
                .iter()
                .map(|&p| (0..DROP_N).map(|_| gen(p)).collect())
                .collect(),
            anchor: basis
                .anchor
                .iter()
                .map(|&p| (0..DROP_N).map(|_| gen(p)).collect())
                .collect(),
            n: DROP_N,
        }
    }

    #[test]
    #[ignore = "Statistical timing test - run in a controlled environment only. WAS finding F-1, \
now CLOSED and kept as its regression gate: medians 110,927ns vs 110,977ns (+0.045%), t_signal 0.96 \
against control 1.16. It previously measured 128.2us vs 150.1us (+17%) at t = 71.9-129.6. The \
recorded cause was wrong: removing every division made the function 2x faster and the leak LARGER. \
The real cause was BarrettContext::sub_ct, whose ((a < b) as u64).wrapping_neg() mask compiled to a \
conditional branch whose prediction rate depends on the operands. See docs/CT_VERIFICATION_PLAN.md \
section 4.8 for the probe-by-probe localisation."]
    fn test_ct_dudect_exact_prime_drop_fixed_vs_random() {
        print_environment_info();
        warmup();

        let basis = drop_basis();
        let mut rng = ShadowHarvester::with_seed(101);

        // Class A ("fixed"): every residue is zero — the classic dudect fixed
        // vector. Class B ("random"): uniform residues.
        let mut rb = ShadowHarvester::with_seed(151);
        let (pool_a, pool_a2, pool_b) = interleaved_pools(
            DUDECT_POOL,
            || drop_poly(&basis, |_p| 0u64),
            || drop_poly(&basis, |p| rb.next_u64() % p),
        );

        let main = basis.main.clone();
        let anchor = basis.anchor.clone();
        let result = dudect_two_class(
            &mut rng,
            &pool_a,
            &pool_a2,
            &pool_b,
            DUDECT_ROUNDS,
            |poly| {
                let out =
                    exact_modulus_switch_drop_poly(std::hint::black_box(poly), &main, &anchor, 0)
                        .expect("prime drop must succeed on the secure_128 dual basis");
                std::hint::black_box(&out);
            },
        );

        assert_dudect(
            "exact_modulus_switch_drop_poly — all-zero residues vs uniform residues",
            &result,
        );
    }

    #[test]
    #[ignore = "Statistical timing test - run in a controlled environment only. WAS finding F-1's \
magnitude contrast, now CLOSED and kept as its regression gate: medians 110,782ns vs 110,798ns \
(+0.014%), t_signal 0.45 against control 0.11. It previously measured 128.4us vs 138.4us (+7.8%) at \
t = 48.4. This contrast is the one that exposed the sign flip during the fix - under the original \
divisions small residues were faster, and once division was removed branch prediction dominated and \
they became slower. See docs/CT_VERIFICATION_PLAN.md section 4.8."]
    fn test_ct_dudect_exact_prime_drop_small_vs_large_residues() {
        print_environment_info();
        warmup();

        let basis = drop_basis();
        let mut rng = ShadowHarvester::with_seed(102);

        // Magnitude contrast at equal Hamming-ish structure: residues confined
        // to the bottom 20 bits versus residues confined to the top of the lane.
        // Both classes are non-zero, so this isolates operand MAGNITUDE — the
        // thing a shift/subtract `__umodti3` and a legacy `div r64` are
        // sensitive to — rather than the trivial zero special case.
        const SMALL_MASK: u64 = (1 << 20) - 1;
        let mut r1 = ShadowHarvester::with_seed(103);
        let mut r3 = ShadowHarvester::with_seed(105);
        let (pool_a, pool_a2, pool_b) = interleaved_pools(
            DUDECT_POOL,
            || drop_poly(&basis, |_p| r1.next_u64() & SMALL_MASK),
            || drop_poly(&basis, |p| p - 1 - (r3.next_u64() & SMALL_MASK)),
        );

        let main = basis.main.clone();
        let anchor = basis.anchor.clone();
        let result = dudect_two_class(
            &mut rng,
            &pool_a,
            &pool_a2,
            &pool_b,
            DUDECT_ROUNDS,
            |poly| {
                let out =
                    exact_modulus_switch_drop_poly(std::hint::black_box(poly), &main, &anchor, 0)
                        .expect("prime drop must succeed on the secure_128 dual basis");
                std::hint::black_box(&out);
            },
        );

        assert_dudect(
            "exact_modulus_switch_drop_poly — small residues vs near-modulus residues",
            &result,
        );
    }

    // ========================================================================
    // Rescale / level-drop path (RNSFHEContext::mod_switch_down_dual)
    // ========================================================================
    //
    // `mod_switch_down_dual` reconstructs each coefficient to a centred U256,
    // divides by the dropped prime with rounding, and re-encodes. Unlike the
    // prime drop it contains EXPLICIT data-dependent branches on reconstructed
    // coefficient values:
    //
    //     if rem >= q_last_half { q_mag = q_mag.add(U256::one()); }
    //     result_main[j][i] = if v_centered.is_neg && q_mod_p != 0 { p - q_mod_p }
    //                         else { q_mod_p };
    //
    // plus `U256::div_mod_u64`, a long division whose work depends on the
    // magnitude of the dividend. The tests below target the sign branch (with
    // magnitude held constant between classes, so a difference can only come
    // from the sign) and the classic fixed-vs-random contrast.
    //
    // THREAT-MODEL NOTE, stated plainly: this path consumes ciphertext
    // residues. Against a server-side adversary who already holds the
    // ciphertext, a timing dependence on those residues leaks nothing new. It
    // matters for a co-resident attacker on the CLIENT, where the same code
    // runs over values correlated with the plaintext and the key. That is a
    // narrower threat model than "all secret data", and the docs should not
    // claim more than that.

    /// Split a u128 value into per-prime residues for a dual basis.
    fn residues_of(x: u128, primes: &[u64]) -> Vec<u64> {
        primes.iter().map(|&p| (x % p as u128) as u64).collect()
    }

    fn switch_poly(ctx: &RNSFHEContext, values: &[u128], n: usize) -> DualRNSPoly {
        let main_primes = &ctx.config.primes;
        let anchor_primes = &ctx.dual_rns.anchor.primes;
        let mut main = vec![vec![0u64; n]; main_primes.len()];
        let mut anchor = vec![vec![0u64; n]; anchor_primes.len()];
        for (i, &x) in values.iter().enumerate().take(n) {
            for (j, r) in residues_of(x, main_primes).into_iter().enumerate() {
                main[j][i] = r;
            }
            for (j, r) in residues_of(x, anchor_primes).into_iter().enumerate() {
                anchor[j][i] = r;
            }
        }
        DualRNSPoly { main, anchor, n }
    }

    #[test]
    #[ignore] // Statistical timing test — run in controlled environment only
    fn test_ct_dudect_mod_switch_rescale_sign_classes() {
        print_environment_info();
        warmup();

        let config = SecureConfig::secure_128().into_config();
        let ctx = RNSFHEContext::new(&config);
        let n = ctx.n;

        // M = product of the main primes. secure_128 is log2(q) ~= 90, so M
        // fits in u128 and the class construction below is exact.
        let m: u128 = ctx
            .config
            .primes
            .iter()
            .try_fold(1u128, |acc, &p| acc.checked_mul(p as u128))
            .expect("secure_128 main product must fit in u128 for this test");
        let m_half = m / 2;

        // Magnitude-matched sign classes. Class A draws x in [0, M/2), so the
        // centred value is +x. Class B draws x in [M/2, M), so the centred
        // value is -(M-x). |v| has the SAME distribution in both classes;
        // only the sign differs. Any timing gap therefore isolates the
        // `is_neg` branch rather than the size of the dividend.
        let one = |r: &mut ShadowHarvester, negative: bool| -> DualRNSPoly {
            let values: Vec<u128> = (0..n)
                .map(|_| {
                    let mag = (((r.next_u64() as u128) << 64) | r.next_u64() as u128) % m_half;
                    if negative {
                        m - 1 - mag
                    } else {
                        mag
                    }
                })
                .collect();
            switch_poly(&ctx, &values, n)
        };
        let mut ra = ShadowHarvester::with_seed(201);
        let mut rb = ShadowHarvester::with_seed(203);
        let (pool_a, pool_a2, pool_b) =
            interleaved_pools(DUDECT_POOL, || one(&mut ra, false), || one(&mut rb, true));

        let mut rng = ShadowHarvester::with_seed(204);
        let result = dudect_two_class(
            &mut rng,
            &pool_a,
            &pool_a2,
            &pool_b,
            // One call touches n=8192 coefficients, so far fewer rounds are
            // needed to accumulate the same amount of work.
            DUDECT_ROUNDS / 20,
            |poly| {
                let out = ctx
                    .mod_switch_down_dual(std::hint::black_box(poly))
                    .expect("secure_128 has 3 main primes, so one level drop is available");
                std::hint::black_box(&out);
            },
        );

        assert_dudect(
            "mod_switch_down_dual — positive-centred vs negative-centred coefficients              (magnitude-matched)",
            &result,
        );
    }

    #[test]
    #[ignore = "OPEN FINDING, not a flake, and the largest one in this file: \
RNSFHEContext::mod_switch_down_dual is NOT constant-time in coefficient magnitude. Measured over \
5 runs: t_signal = 701.0 / 228.9 / 202.4 / 206.6 / 210.0 against control t = 0.56-2.10, medians \
25.4ms (all-zero coefficients) vs 80.1ms (uniform coefficients) - a 3.2x, not a percentage. Cause: \
U256::div_mod_u64 is a long division over the reconstructed coefficient. Note the companion test \
test_ct_dudect_mod_switch_rescale_sign_classes PASSES, so the sign branches are not the leak - the \
dividend magnitude is. See docs/CT_VERIFICATION_PLAN.md."]
    fn test_ct_dudect_mod_switch_rescale_fixed_vs_random() {
        print_environment_info();
        warmup();

        let config = SecureConfig::secure_128().into_config();
        let ctx = RNSFHEContext::new(&config);
        let n = ctx.n;

        let m: u128 = ctx
            .config
            .primes
            .iter()
            .try_fold(1u128, |acc, &p| acc.checked_mul(p as u128))
            .expect("secure_128 main product must fit in u128 for this test");

        // Class A: the all-zero polynomial (dudect's fixed vector).
        // Class B: uniform over [0, M).
        let mut r = ShadowHarvester::with_seed(301);
        let (zero_pool, zero_pool2, rand_pool) = interleaved_pools(
            DUDECT_POOL,
            || switch_poly(&ctx, &vec![0u128; n], n),
            || {
                let values: Vec<u128> = (0..n)
                    .map(|_| (((r.next_u64() as u128) << 64) | r.next_u64() as u128) % m)
                    .collect();
                switch_poly(&ctx, &values, n)
            },
        );

        let mut rng = ShadowHarvester::with_seed(302);
        let result = dudect_two_class(
            &mut rng,
            &zero_pool,
            &zero_pool2,
            &rand_pool,
            DUDECT_ROUNDS / 20,
            |poly| {
                let out = ctx
                    .mod_switch_down_dual(std::hint::black_box(poly))
                    .expect("secure_128 has 3 main primes, so one level drop is available");
                std::hint::black_box(&out);
            },
        );

        assert_dudect(
            "mod_switch_down_dual — all-zero coefficients vs uniform coefficients",
            &result,
        );
    }

    // ========================================================================
    // Batched dudect over the scalar primitives
    // ========================================================================
    //
    // The family (a) tests cannot resolve a 1-3 ns operation through a ~20 ns
    // timer. The fix is not a bigger sample count — it is to move the timer
    // out of the inner loop. Each measured region below runs DUDECT_BATCH
    // operations, so the region is tens of microseconds and the timer's
    // contribution is under one part in a thousand. The accumulator plus
    // `black_box` on both operands and result stops LLVM from hoisting,
    // constant-folding or deleting the calls, which the original
    // `let _result = ...` form did not.

    const DUDECT_BATCH: usize = 4_096;

    /// Rounds for the batched scalar tests. Higher than `DUDECT_ROUNDS`
    /// because each measured region is cheap, and because statistical POWER is
    /// the point: a genuine class difference makes |t| grow like sqrt(rounds),
    /// while pure noise leaves it bounded. A borderline t at low round counts
    /// is therefore resolved by adding rounds, not by widening the threshold.
    const DUDECT_BATCHED_ROUNDS: usize = 2_000;

    /// Rounds for the `extract_k` operand-magnitude test specifically.
    ///
    /// This test is the subject of the scheduled INVERTED tripwire in
    /// `.github/workflows/ct_verification.yml`: that job hard-fails if the
    /// documented leak stops reproducing. A tripwire whose verdict is a coin
    /// flip is worse than no tripwire, because roughly a third of scheduled
    /// runs would raise "the leak was fixed" for an unchanged tree.
    ///
    /// At `DUDECT_BATCHED_ROUNDS` (2000) the verdict is exactly that unstable.
    /// Measured on this machine, six runs:
    ///
    /// ```text
    ///   2000 rounds:  t_signal = 4.3547 -> CONSTANT-TIME   (verdict flip)
    ///                            13.6314 -> DEPENDENCE
    ///                            10.2013 -> DEPENDENCE
    ///   8000 rounds:  t_signal = 18.4584 -> DEPENDENCE
    ///                            20.5285 -> DEPENDENCE
    ///                            29.2741 -> DEPENDENCE
    ///   controls across all six: 0.0715 .. 1.1686, never near 5.
    /// ```
    ///
    /// This is the textbook signature of a real effect measured with too little
    /// power: `|t|` grows like `sqrt(rounds)` for a genuine class difference and
    /// stays bounded for noise, and 2000 rounds simply sat on the threshold.
    /// The fix is more rounds, not a wider threshold — 6/6 runs at 8000 clear
    /// the threshold by 3.7x or better, with the control arm two orders of
    /// magnitude below it.
    ///
    /// Cost: about 40s per run, inside the scheduled job's 60-minute budget.
    const DUDECT_EXTRACT_K_ROUNDS: usize = 8_000;

    /// Rounds for the `exact_divide` divisor-class test specifically.
    ///
    /// This test was written as the interleaved replacement for the deleted
    /// block-measured `d=2 vs d=3` cross-class t-test in
    /// `test_ct_k_elimination_exact_divide`. The open question was whether it
    /// could be promoted into the blocking job. Measured on this machine:
    ///
    /// ```text
    ///    2000 rounds: t_signal = 0.76 / 2.54 / 3.24 / 4.32 / 4.89
    ///    8000 rounds: t_signal = 8.1821 / 6.7307 / 4.9425
    ///                 controls   1.2701 / 0.6210 / 0.4564   (clean)
    ///   32000 rounds: t_signal = 11.4212  control 1.1433    (clean)
    ///                            20.2218  control 11.1909   INCONCLUSIVE
    ///                            20.2598  control  9.2015   INCONCLUSIVE
    /// ```
    ///
    /// Two conclusions, and the second is why this constant is 8000 rather
    /// than higher:
    ///
    /// 1. **The effect is real.** `|t|` grows with round count (mean ~3 at
    ///    2000, ~6.6 at 8000, 11.4 at the one clean 32000 run) while the
    ///    control stays near zero, and the sign is stable across every clean
    ///    run — divisor 3 is consistently SLOWER than divisor 2 by ~1-3us per
    ///    4096-call batch. That is a genuine divisor-dependent timing
    ///    dependence, not the block-measurement artefact the deleted test was
    ///    criticised for. So this test cannot be promoted into the blocking
    ///    job as a passing gate; it is an OPEN FINDING.
    /// 2. **The verdict is not yet stable at any round count this runner can
    ///    sustain.** At 8000 it reads DEPENDENCE in 2 of 3 runs, and at 32000
    ///    the control arm itself exceeds the threshold and the harness
    ///    correctly reports INCONCLUSIVE. So it cannot go into the inverted
    ///    open-findings tripwire either, which requires a stable
    ///    "TIMING DEPENDENCE MEASURED".
    ///
    /// 8000 is the largest count at which the control arm stayed clean in
    /// every run, i.e. the most power this machine can buy without measuring
    /// its own noise instead. Settling this needs a quiesced, frequency-pinned
    /// runner; see `docs/CT_VERIFICATION_PLAN.md`.
    const DUDECT_DIVISOR_CLASS_ROUNDS: usize = 8_000;

    type OperandPair = (u128, u128);

    /// Pool count for the batched scalar tests. Each pool entry is a whole
    /// batch, so a handful is plenty.
    const DUDECT_POOLS_BATCHED: usize = 4;

    /// Uniform u128 strictly below `cap`, restricted to the low `bits` bits
    /// (small class) or to the top `bits`-wide window under `cap` (large class).
    fn windowed(rng: &mut ShadowHarvester, cap: u128, bits: u32, high: bool) -> u128 {
        let span: u128 = 1u128 << bits;
        let off = random_u128(rng) % span;
        if high {
            cap - 1 - off
        } else {
            off + 1
        }
    }

    #[test]
    #[ignore = "OPEN FINDING, and now measured with enough power to be one: KElimination::extract_k \
shows a small but reproducible operand-magnitude timing dependence, contradicting its docstring \
claim of fixed-cost, branch-free execution. Interleaved class allocation, 8000 rounds \
(DUDECT_EXTRACT_K_ROUNDS): t_signal = 18.5 / 20.5 / 29.3 over three runs, against controls of \
0.07-1.17; medians differ by ~13-15us per 4096-call batch, i.e. ~3.5ns on a ~590ns call (0.6%). \
|t| grows with round count (4.4-13.6 at 2000 rounds, 18.5-29.3 at 8000), the signature of a real \
effect rather than noise. CORRECTION to the earlier reason string: at 2000 rounds the VERDICT was \
not stable (one of three runs read 4.35 and reported CONSTANT-TIME), so 'not a flake' was not \
established until the round count was raised; and the SIGN of the median difference is not stable \
either - near-cap operands were slower in some runs and faster in others - so only the magnitude \
of the dependence is established, not its direction. Effect size is small enough that a quiesced, \
frequency-pinned machine should confirm it before any code change. \
See docs/CT_VERIFICATION_PLAN.md."]
    fn test_ct_dudect_k_elim_extract_k_operand_magnitude() {
        print_environment_info();
        warmup();

        let ke = KElimination::from_config(KElimConfig::Standard);
        let (acap, bcap) = (ke.alpha_cap, ke.beta_cap);

        let mut ra = ShadowHarvester::with_seed(401);
        let mut rb = ShadowHarvester::with_seed(403);
        let (pool_a, pool_a2, pool_b) = interleaved_pools(
            DUDECT_POOLS_BATCHED,
            || {
                (0..DUDECT_BATCH)
                    .map(|_| {
                        (
                            windowed(&mut ra, acap, 20, false),
                            windowed(&mut ra, bcap, 20, false),
                        )
                    })
                    .collect::<Vec<OperandPair>>()
            },
            || {
                (0..DUDECT_BATCH)
                    .map(|_| {
                        (
                            windowed(&mut rb, acap, 20, true),
                            windowed(&mut rb, bcap, 20, true),
                        )
                    })
                    .collect::<Vec<OperandPair>>()
            },
        );

        let mut rng = ShadowHarvester::with_seed(404);
        let result = dudect_two_class(
            &mut rng,
            &pool_a,
            &pool_a2,
            &pool_b,
            DUDECT_EXTRACT_K_ROUNDS,
            |batch| {
                let mut acc = 0u128;
                for &(a, b) in batch.iter() {
                    acc ^= ke.extract_k(std::hint::black_box(a), std::hint::black_box(b));
                }
                std::hint::black_box(acc);
            },
        );

        assert_dudect(
            "KElimination::extract_k — small operands vs near-cap operands (batched)",
            &result,
        );
    }

    // ========================================================================
    // F-3, structurally: adjacency-anchored K-Elimination
    // ========================================================================
    //
    // `KElimination::extract_k` measured a small but reproducible
    // operand-magnitude dependence (test above: t_signal = 10.5 vs control
    // 0.19). Its body is
    //
    //     diff = sub_mod_kelim_ct(v_beta, v_alpha, beta_cap)   // v_alpha % beta_cap
    //     mul_mod_u128_ct(diff, alpha_inv_beta, beta_cap)      // a % beta_cap, then 128 rounds
    //
    // Both halves contain a `u128 % u128` by a RUNTIME modulus, which LLVM
    // lowers to `__umodti3`: a shift/subtract loop whose trip count tracks the
    // operands' bit lengths. Branch-free at the source level is not
    // constant-time when the *instruction* is not.
    //
    // The adjacency construction A = M + 1 makes M ≡ −1 (mod A), so
    // M⁻¹ ≡ M and the extraction collapses to k = (v_α − v_β) mod A: one
    // `wrapping_sub`, one mask, one `wrapping_add`. There is no modulo left to
    // make constant-time. These two tests measure whether that is actually
    // true on this machine, using the SAME classes, the SAME batch size and
    // the SAME round count as the finding above, so the numbers are directly
    // comparable.

    /// Repeats of the adjacency sweep per measured region.
    ///
    /// **This constant is what makes the comparison honest.** One adjacency
    /// extraction costs ~1.7 ns against the general form's ~587 ns, so a
    /// `DUDECT_BATCH`-sized adjacency region is ~7 us where the general one is
    /// ~2.4 ms. Comparing a null result on a 7 us region against a positive on
    /// a 2.4 ms region would compare two different experiments: shorter regions
    /// carry a larger share of timer noise and less accumulated signal, so a
    /// null there is weak evidence, not strong.
    ///
    /// Sweeping the same batch `ADJ_REGION_REPEATS` times brings the adjacency
    /// region to the same ~2.4 ms, and the test below runs it at
    /// `DUDECT_EXTRACT_K_ROUNDS` — the same 8,000 rounds as the general test,
    /// not the 2,000 used elsewhere. Equal region duration, equal round count,
    /// identical operand classes, identical harness.
    ///
    /// That also supplies the positive control the null result needs: the
    /// general test demonstrates that THIS harness, at THIS region size and
    /// round count, resolves a 0.63% relative effect (t = 25.6). A t below
    /// threshold here is therefore a measurement made with proven power, not
    /// an underpowered shrug.
    const ADJ_REGION_REPEATS: usize = 340;

    /// The adjacency form under the operand classes that make the general form
    /// leak. This is the falsifiable half of the structural argument: if the
    /// construction closes F-3, this test passes where the one above fails.
    #[test]
    #[ignore] // Statistical timing test — run in controlled environment only
    fn test_ct_dudect_adjacency_k_elim_operand_magnitude() {
        print_environment_info();
        warmup();

        let adj = AdjacencyKElim::from_config(KElimConfig::Standard).expect("adjacency context");
        let (mcap, acap) = (adj.alpha_cap(), adj.anchor());

        let mut ra = ShadowHarvester::with_seed(401);
        let mut rb = ShadowHarvester::with_seed(403);
        let (pool_a, pool_a2, pool_b) = interleaved_pools(
            DUDECT_POOLS_BATCHED,
            || {
                (0..DUDECT_BATCH)
                    .map(|_| {
                        (
                            windowed(&mut ra, mcap, 20, false),
                            windowed(&mut ra, acap, 20, false),
                        )
                    })
                    .collect::<Vec<OperandPair>>()
            },
            || {
                (0..DUDECT_BATCH)
                    .map(|_| {
                        (
                            windowed(&mut rb, mcap, 20, true),
                            windowed(&mut rb, acap, 20, true),
                        )
                    })
                    .collect::<Vec<OperandPair>>()
            },
        );

        let mut rng = ShadowHarvester::with_seed(404);
        let result = dudect_two_class(
            &mut rng,
            &pool_a,
            &pool_a2,
            &pool_b,
            DUDECT_EXTRACT_K_ROUNDS,
            |batch| {
                let mut acc = 0u128;
                for _ in 0..ADJ_REGION_REPEATS {
                    for &(a, b) in batch.iter() {
                        acc ^= adj.extract_k(std::hint::black_box(a), std::hint::black_box(b));
                    }
                    std::hint::black_box(&acc);
                }
                std::hint::black_box(acc);
            },
        );

        println!(
            "  region size check: adjacency median {:.0}ns vs the general form's \
             ~2.40e6ns — these must be the same order for the comparison to hold",
            result.median_a
        );
        assert_dudect(
            "AdjacencyKElim::extract_k — small operands vs near-cap operands (batched)",
            &result,
        );
    }

    /// Operand ORDER, at identical operand magnitudes.
    ///
    /// The magnitude test above cannot see a branch. Both of its classes draw
    /// `v_α` and `v_β` independently, so `v_α < v_β` holds about half the time
    /// in *both* arms — a conditional whose taken-rate is equal across classes
    /// is invisible to a two-class test, however badly it is compiled. That is
    /// not a hypothetical: `BarrettContext::sub_ct` used the same
    /// `((a < b) as T).wrapping_neg()` mask, compiled to a real branch, and
    /// leaked 23 us at t = 442 once a class contrast could see it
    /// (`docs/CT_VERIFICATION_PLAN.md` §4.8).
    ///
    /// This test supplies that contrast. Both classes draw the same pairs and
    /// present the **identical multiset of operand values**; they differ only
    /// in which element of each pair is passed first:
    ///
    /// * class A always passes `(larger, smaller)`, so the borrow never fires
    ///   and a branch is perfectly predicted;
    /// * class B randomises the order, so a branch mispredicts about half the
    ///   time.
    ///
    /// Magnitude is therefore held constant by construction and only
    /// predictability varies. A null here is a statement about the compiled
    /// form, not just about the algebra.
    #[test]
    #[ignore] // Statistical timing test — run in controlled environment only
    fn test_ct_dudect_adjacency_k_elim_operand_order() {
        print_environment_info();
        warmup();

        let adj = AdjacencyKElim::from_config(KElimConfig::Standard).expect("adjacency context");
        let anchor = adj.anchor();

        let mut ra = ShadowHarvester::with_seed(801);
        let mut rb = ShadowHarvester::with_seed(803);

        // Sorted: v_alpha >= v_beta on every pair, so `a < b` is always false.
        let mut sorted_batch = |rng: &mut ShadowHarvester| -> Vec<OperandPair> {
            (0..DUDECT_BATCH)
                .map(|_| {
                    let x = random_u128(rng) % anchor;
                    let y = random_u128(rng) % anchor;
                    if x >= y {
                        (x, y)
                    } else {
                        (y, x)
                    }
                })
                .collect()
        };
        // Shuffled: the same construction, then each pair independently
        // swapped, so `a < b` holds about half the time. The VALUES are drawn
        // identically; only their order differs.
        let mut shuffled_batch = |rng: &mut ShadowHarvester| -> Vec<OperandPair> {
            (0..DUDECT_BATCH)
                .map(|_| {
                    let x = random_u128(rng) % anchor;
                    let y = random_u128(rng) % anchor;
                    let (hi, lo) = if x >= y { (x, y) } else { (y, x) };
                    if rng.next_u64() & 1 == 0 {
                        (hi, lo)
                    } else {
                        (lo, hi)
                    }
                })
                .collect()
        };

        let (pool_a, pool_a2, pool_b) = interleaved_pools(
            DUDECT_POOLS_BATCHED,
            || sorted_batch(&mut ra),
            || shuffled_batch(&mut rb),
        );

        let mut rng = ShadowHarvester::with_seed(804);
        let result = dudect_two_class(
            &mut rng,
            &pool_a,
            &pool_a2,
            &pool_b,
            DUDECT_EXTRACT_K_ROUNDS,
            |batch| {
                let mut acc = 0u128;
                for _ in 0..ADJ_REGION_REPEATS {
                    for &(a, b) in batch.iter() {
                        acc ^= adj.extract_k(std::hint::black_box(a), std::hint::black_box(b));
                    }
                    std::hint::black_box(&acc);
                }
                std::hint::black_box(acc);
            },
        );

        assert_dudect(
            "AdjacencyKElim::extract_k — sorted operands vs randomised order (batched)",
            &result,
        );
    }

    /// Head-to-head cost of the two extractions over identical inputs.
    ///
    /// Reports only; it asserts correctness (the two forms must agree on every
    /// sample) but never asserts a speed ratio, because a ratio measured on a
    /// shared, unpinned runner is not a number anyone should gate on. The
    /// medians are printed so a human reading CI output sees the size of the
    /// difference rather than being told about it.
    #[test]
    #[ignore] // Timing measurement — run in controlled environment only
    fn test_ct_adjacency_vs_general_k_elim_cost() {
        print_environment_info();
        warmup();

        let adj = AdjacencyKElim::from_config(KElimConfig::Standard).expect("adjacency context");
        let general = adj
            .general_equivalent()
            .expect("general partner over the same (M, A)");
        assert_eq!(
            general.alpha_inv_beta,
            adj.alpha_cap(),
            "the general partner must be extracting against the same anchor"
        );

        let mut rng = ShadowHarvester::with_seed(1201);
        let batch: Vec<OperandPair> = (0..DUDECT_BATCH)
            .map(|_| {
                let x = random_u128(&mut rng) % adj.try_capacity().expect("M * A fits");
                (x % adj.alpha_cap(), x % adj.anchor())
            })
            .collect();

        // Same (M, A), same inputs, two implementations: any disagreement here
        // would make the timing comparison meaningless.
        for &(a, b) in batch.iter() {
            assert_eq!(adj.extract_k(a, b), general.extract_k(a, b));
        }

        const COST_ROUNDS: usize = 400;
        let mut t_general: Vec<u64> = Vec::with_capacity(COST_ROUNDS);
        let mut t_adjacent: Vec<u64> = Vec::with_capacity(COST_ROUNDS);

        for _ in 0..COST_ROUNDS {
            // Alternate the order every round so drift is shared.
            let general_first = rng.next_u64() & 1 == 0;
            let mut run_general = || {
                let start = Instant::now();
                let mut acc = 0u128;
                for &(a, b) in batch.iter() {
                    acc ^= general.extract_k(std::hint::black_box(a), std::hint::black_box(b));
                }
                std::hint::black_box(acc);
                start.elapsed().as_nanos() as u64
            };
            let mut run_adjacent = || {
                let start = Instant::now();
                let mut acc = 0u128;
                for &(a, b) in batch.iter() {
                    acc ^= adj.extract_k(std::hint::black_box(a), std::hint::black_box(b));
                }
                std::hint::black_box(acc);
                start.elapsed().as_nanos() as u64
            };
            if general_first {
                t_general.push(run_general());
                t_adjacent.push(run_adjacent());
            } else {
                t_adjacent.push(run_adjacent());
                t_general.push(run_general());
            }
        }

        let (mg, ma) = (median_of(&t_general), median_of(&t_adjacent));
        // The `median=` spelling is load-bearing: the diagnostics job in
        // .github/workflows/ct_verification.yml gates on each test having
        // actually produced numbers by grepping for `median=|median class|
        // VERDICT:`. A test that emits no recognised marker is treated as not
        // having run at all, which is the correct default.
        println!("  K-Elimination extraction cost over {DUDECT_BATCH} calls, {COST_ROUNDS} rounds");
        println!("    general  (v_beta - v_alpha) * M^-1 mod A : median={mg:.0}ns per batch");
        println!("    adjacency (v_alpha - v_beta) mod A       : median={ma:.0}ns per batch");
        if ma > 0.0 {
            println!(
                "    ratio general/adjacency                  : {:.2}x",
                mg / ma
            );
        }
        println!(
            "    per call: general {:.2} ns, adjacency {:.2} ns",
            mg / DUDECT_BATCH as f64,
            ma / DUDECT_BATCH as f64
        );
    }

    #[test]
    #[ignore = "OPEN FINDING with an UNSTABLE VERDICT: KElimination::exact_divide shows a real \
divisor-dependent timing dependence (divisor 3 consistently slower than divisor 2 by ~1-3us per \
4096-call batch, sign stable across every clean run, |t| growing with round count: mean ~3 at 2000 \
rounds, ~6.6 at 8000, 11.4 at the one clean 32000-round run, against controls of 0.46-1.27). It is \
therefore NOT promotable into the dudect-blocking job as a passing gate. It is also not placeable \
in the inverted open-findings tripwire, which needs a stable DEPENDENCE verdict: at 8000 rounds it \
read DEPENDENCE in only 2 of 3 runs, and at 32000 rounds this machine's own control arm exceeded \
the threshold (9.2-11.2) so the harness correctly reported INCONCLUSIVE. Neither CI job can gate \
this deterministically today; it is collected and reported, and settling it needs a quiesced, \
frequency-pinned runner. See DUDECT_DIVISOR_CLASS_ROUNDS and docs/CT_VERIFICATION_PLAN.md."]
    fn test_ct_dudect_k_elim_exact_divide_divisor_classes() {
        print_environment_info();
        warmup();

        let ke = KElimination::from_config(KElimConfig::Standard);
        let (acap, bcap) = (ke.alpha_cap, ke.beta_cap);

        // Identical operand distribution in all three streams; only the
        // DIVISOR differs between class A and class B. This is the
        // interleaved answer to the block-measured `d=2 vs d=3` cross-class
        // t-test in `test_ct_k_elimination_exact_divide`, whose classes are
        // measured in contiguous blocks and so cannot separate a divisor
        // effect from clock drift.
        // `dudect_two_class` takes ONE run closure, so the class label (the
        // divisor) travels with the input rather than with the closure.
        let mut ra = ShadowHarvester::with_seed(501);
        let mut rb = ShadowHarvester::with_seed(503);
        let (a, a2, b) = interleaved_pools(
            DUDECT_POOLS_BATCHED,
            || {
                (
                    (0..DUDECT_BATCH / 8)
                        .map(|_| (random_u128(&mut ra) % acap, random_u128(&mut ra) % bcap))
                        .collect::<Vec<OperandPair>>(),
                    2u64,
                )
            },
            || {
                (
                    (0..DUDECT_BATCH / 8)
                        .map(|_| (random_u128(&mut rb) % acap, random_u128(&mut rb) % bcap))
                        .collect::<Vec<OperandPair>>(),
                    3u64,
                )
            },
        );

        let mut rng = ShadowHarvester::with_seed(504);
        let result = dudect_two_class(
            &mut rng,
            &a,
            &a2,
            &b,
            DUDECT_DIVISOR_CLASS_ROUNDS,
            |(batch, d)| {
                let mut acc = 0u128;
                for &(x, y) in batch.iter() {
                    acc ^= ke.exact_divide(
                        std::hint::black_box(x),
                        std::hint::black_box(y),
                        std::hint::black_box(*d),
                    );
                }
                std::hint::black_box(acc);
            },
        );

        assert_dudect(
            "KElimination::exact_divide — divisor 2 vs divisor 3, identical operands (batched)",
            &result,
        );
    }

    #[test]
    #[ignore] // Statistical timing test — run in controlled environment only
    fn test_ct_dudect_montgomery_mul_operand_magnitude() {
        print_environment_info();
        warmup();

        const TEST_PRIME: u64 = 998244353;
        let ctx = MontgomeryContext::new(TEST_PRIME);
        let cap = TEST_PRIME as u128;

        let mut ra = ShadowHarvester::with_seed(601);
        let mut rb = ShadowHarvester::with_seed(603);
        let (pool_a, pool_a2, pool_b) = interleaved_pools(
            DUDECT_POOLS_BATCHED,
            || {
                (0..DUDECT_BATCH)
                    .map(|_| {
                        (
                            windowed(&mut ra, cap, 12, false),
                            windowed(&mut ra, cap, 12, false),
                        )
                    })
                    .collect::<Vec<OperandPair>>()
            },
            || {
                (0..DUDECT_BATCH)
                    .map(|_| {
                        (
                            windowed(&mut rb, cap, 12, true),
                            windowed(&mut rb, cap, 12, true),
                        )
                    })
                    .collect::<Vec<OperandPair>>()
            },
        );

        let mut rng = ShadowHarvester::with_seed(604);
        let result = dudect_two_class(
            &mut rng,
            &pool_a,
            &pool_a2,
            &pool_b,
            DUDECT_BATCHED_ROUNDS,
            |batch| {
                let mut acc = 0u64;
                for &(a, b) in batch.iter() {
                    acc ^= ctx.montgomery_mul(
                        std::hint::black_box(a as u64),
                        std::hint::black_box(b as u64),
                    );
                }
                std::hint::black_box(acc);
            },
        );

        assert_dudect(
            "MontgomeryContext::montgomery_mul — small operands vs near-modulus operands (batched)",
            &result,
        );
    }

    #[test]
    #[ignore] // Statistical timing test — run in controlled environment only
    fn test_ct_dudect_montgomery_reduce_operand_magnitude() {
        print_environment_info();
        warmup();

        const TEST_PRIME: u64 = 998244353;
        let ctx = MontgomeryContext::new(TEST_PRIME);
        let q = TEST_PRIME as u128;

        // `montgomery_reduce` takes t < q * 2^64. Class A keeps the cofactor in
        // the low 16 bits; class B forces its top bit. Same call, same code
        // path, operands three orders of magnitude apart.
        let mut ra = ShadowHarvester::with_seed(701);
        let mut rb = ShadowHarvester::with_seed(703);
        let (pool_a, pool_a2, pool_b) = interleaved_pools(
            DUDECT_POOLS_BATCHED,
            || {
                (0..DUDECT_BATCH)
                    .map(|_| ((ra.next_u64() & 0xFFFF) as u128 * q, 0u128))
                    .collect::<Vec<OperandPair>>()
            },
            || {
                (0..DUDECT_BATCH)
                    .map(|_| ((rb.next_u64() | (1u64 << 63)) as u128 * q, 0u128))
                    .collect::<Vec<OperandPair>>()
            },
        );

        let mut rng = ShadowHarvester::with_seed(704);
        let result = dudect_two_class(
            &mut rng,
            &pool_a,
            &pool_a2,
            &pool_b,
            DUDECT_BATCHED_ROUNDS,
            |batch| {
                let mut acc = 0u64;
                for &(t, _) in batch.iter() {
                    acc ^= ctx.montgomery_reduce(std::hint::black_box(t));
                }
                std::hint::black_box(acc);
            },
        );

        assert_dudect(
            "MontgomeryContext::montgomery_reduce — small cofactor vs top-bit cofactor (batched)",
            &result,
        );
    }

    #[test]
    #[ignore] // Statistical timing test — run in controlled environment only
    fn test_ct_dudect_barrett_reduce_operand_magnitude() {
        print_environment_info();
        warmup();

        const TEST_PRIME: u64 = 998244353;
        let ctx = BarrettContext::new(TEST_PRIME);

        // Class A: 40-bit dividends. Class B: dividends with bit 127 set.
        let mut ra = ShadowHarvester::with_seed(801);
        let mut rb = ShadowHarvester::with_seed(803);
        let (pool_a, pool_a2, pool_b) = interleaved_pools(
            DUDECT_POOLS_BATCHED,
            || {
                (0..DUDECT_BATCH)
                    .map(|_| (random_u128(&mut ra) >> 88, 0u128))
                    .collect::<Vec<OperandPair>>()
            },
            || {
                (0..DUDECT_BATCH)
                    .map(|_| (random_u128(&mut rb) | (1u128 << 127), 0u128))
                    .collect::<Vec<OperandPair>>()
            },
        );

        let mut rng = ShadowHarvester::with_seed(804);
        let result = dudect_two_class(
            &mut rng,
            &pool_a,
            &pool_a2,
            &pool_b,
            DUDECT_BATCHED_ROUNDS,
            |batch| {
                let mut acc = 0u64;
                for &(a, _) in batch.iter() {
                    acc ^= ctx.reduce_ct(std::hint::black_box(a));
                }
                std::hint::black_box(acc);
            },
        );

        assert_dudect(
            "BarrettContext::reduce_ct — 40-bit dividends vs 128-bit dividends (batched)",
            &result,
        );
    }

    /// A u64 with exactly `hw` bits set, chosen uniformly at random.
    fn exp_with_hamming(rng: &mut ShadowHarvester, hw: u32) -> u64 {
        let mut e = 0u64;
        let mut set = 0u32;
        while set < hw {
            let bit = (rng.next_u64() % 64) as u32;
            if e & (1u64 << bit) == 0 {
                e |= 1u64 << bit;
                set += 1;
            }
        }
        e
    }

    #[test]
    #[ignore] // Statistical timing test — run in controlled environment only
    fn test_ct_dudect_montgomery_pow_exponent_hamming_weight() {
        print_environment_info();
        warmup();

        const TEST_PRIME: u64 = 998244353;
        let ctx = MontgomeryContext::new(TEST_PRIME);

        // THE classic modular-exponentiation side channel: a square-and-multiply
        // loop that skips the multiply on a zero exponent bit runs in time
        // proportional to the exponent's Hamming weight, whereas a Montgomery
        // ladder does not. Both classes use full 64-bit exponents (same loop
        // trip count); only the POPCOUNT differs — 8 bits set versus 56.
        // `test_ct_montgomery_pow`'s CV statistic cannot see this at all,
        // because it never varies the exponent class.
        let mut ra = ShadowHarvester::with_seed(901);
        let mut rb = ShadowHarvester::with_seed(903);
        let (pool_a, pool_a2, pool_b) = interleaved_pools(
            DUDECT_POOLS_BATCHED,
            || {
                (0..DUDECT_BATCH / 8)
                    .map(|_| {
                        (
                            (ra.next_u64() % TEST_PRIME) as u128,
                            exp_with_hamming(&mut ra, 8) as u128,
                        )
                    })
                    .collect::<Vec<OperandPair>>()
            },
            || {
                (0..DUDECT_BATCH / 8)
                    .map(|_| {
                        (
                            (rb.next_u64() % TEST_PRIME) as u128,
                            exp_with_hamming(&mut rb, 56) as u128,
                        )
                    })
                    .collect::<Vec<OperandPair>>()
            },
        );

        let mut rng = ShadowHarvester::with_seed(904);
        let result = dudect_two_class(
            &mut rng,
            &pool_a,
            &pool_a2,
            &pool_b,
            DUDECT_BATCHED_ROUNDS,
            |batch| {
                let mut acc = 0u64;
                for &(base, exp) in batch.iter() {
                    acc ^= ctx.montgomery_pow(
                        std::hint::black_box(base as u64),
                        std::hint::black_box(exp as u64),
                    );
                }
                std::hint::black_box(acc);
            },
        );

        assert_dudect(
            "MontgomeryContext::montgomery_pow — exponent Hamming weight 8 vs 56 (batched)",
            &result,
        );
    }
}

/// The CT workflow and this file must name the same tests — enforced here,
/// because CI is not enforcing it.
///
/// `.github/workflows/ct_verification.yml` names each timing test explicitly, in
/// one of three jobs (blocking, open-findings tripwire, diagnostics). Two ways
/// that correspondence rots:
///
/// * a test is **added here and named nowhere**, so it never runs in CI and
///   nobody notices — which is exactly what happened to the three tests added on
///   2026-08-22;
/// * a test is **renamed or removed here while the workflow still names it**, so
///   the job's `--exact` filter matches nothing. `cargo test` exits 0 on an empty
///   filter, so a phantom name is silent unless something checks.
///
/// This lives in the test suite rather than in a CI script deliberately. As of
/// 2026-08-22 no GitHub Actions workflow in this repository has run since
/// February, and twelve of the thirteen registered workflows have never run at
/// all — so a gate that only exists in YAML is not a gate. `cargo test` runs.
#[cfg(test)]
mod workflow_correspondence {
    use std::collections::BTreeSet;
    use std::path::PathBuf;

    fn repo_root() -> PathBuf {
        // CARGO_MANIFEST_DIR is <root>/crates/nine65
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
    }

    /// Every `test_ct_*` identifier appearing in `text`, however it appears.
    fn ct_test_names(text: &str, after: &str) -> BTreeSet<String> {
        let mut out = BTreeSet::new();
        for (idx, _) in text.match_indices(after) {
            let rest = &text[idx + after.len()..];
            let name: String = rest
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                .collect();
            if !name.is_empty() {
                out.insert(format!("{after}{name}"));
            }
        }
        out
    }

    #[test]
    fn every_ct_timing_test_is_named_by_the_workflow_and_vice_versa() {
        let workflow = repo_root()
            .join(".github")
            .join("workflows")
            .join("ct_verification.yml");

        let Ok(yaml) = std::fs::read_to_string(&workflow) else {
            // The crate can legitimately be built outside a git checkout (a
            // vendored source tarball has no .github/). Say so loudly rather
            // than passing quietly, so a real absence is never mistaken for a
            // real check.
            println!(
                "SKIPPED: {} is not present, so the workflow correspondence \
                 could not be checked from this build tree",
                workflow.display()
            );
            return;
        };

        let source = include_str!("ct_verification.rs");

        // Definitions in this file: `fn test_ct_...`.
        let defined: BTreeSet<String> = ct_test_names(source, "test_ct_")
            .into_iter()
            .filter(|n| source.contains(&format!("fn {n}(")))
            .collect();

        let named_in_yaml = ct_test_names(&yaml, "test_ct_");

        let orphans: Vec<_> = defined.difference(&named_in_yaml).cloned().collect();
        let phantoms: Vec<_> = named_in_yaml.difference(&defined).cloned().collect();

        assert!(
            defined.len() >= 15,
            "only {} timing tests were discovered in this file, which means the \
             scan is broken rather than the file being empty",
            defined.len()
        );

        assert!(
            orphans.is_empty(),
            "these timing tests exist in ct_verification.rs but are named by NO job \
             in .github/workflows/ct_verification.yml, so CI would never run them: \
             {orphans:?}. Add each to the job that matches what it measures — \
             dudect-blocking if it must stay constant-time, open-findings if it is \
             a documented leak, diagnostics if it only records numbers."
        );

        assert!(
            phantoms.is_empty(),
            "these test names appear in .github/workflows/ct_verification.yml but are \
             not defined in ct_verification.rs: {phantoms:?}. `cargo test --exact` \
             exits 0 when its filter matches nothing, so each of these is a job step \
             that silently measures nothing."
        );
    }
}
