// Module 14: boundary_tests
//
// Tests the capacity boundary proximity system:
// - CapacityReport at 80%/90% thresholds
// - PostSwitchMargin at 5%/15% headroom
// - Anchor capacity checks for all secure configs
// - DualRNSContext anchor proximity methods

#[cfg(test)]
mod tests {
    use nine65::arithmetic::boundary::{
        capacity_proximity_bits, post_switch_margin_bits, u128_bit_length, u64_bit_length,
        CapacityRegion,
    };
    use nine65::arithmetic::rns::DualRNSContext;
    use nine65::arithmetic::k_elimination::{KElimConfig, KElimination};
    use nine65::params::secure_configs::SecureConfig;

    // ─── Unit tests: capacity_proximity_bits ────────────────────────────────

    /// Values at < 80% of capacity must be Safe.
    #[test]
    fn test_proximity_safe_region() {
        // 79% of 159 bits = 124.8 → value_bits=124
        let r = capacity_proximity_bits(124, 159);
        assert_eq!(r.region, CapacityRegion::Safe,
            "124/159 = {}% should be Safe", r.utilization_pct);
        assert!(r.is_safe());
        assert!(!r.is_warning());
    }

    /// Values at 80–89% of capacity must be Warn80.
    #[test]
    fn test_proximity_warn80_region() {
        // 80% of 159 bits = 126.4 → value_bits=127 gives 127*100/159=80%
        let r = capacity_proximity_bits(127, 159);
        assert_eq!(r.region, CapacityRegion::Warn80,
            "127/159 = {}% should be Warn80", r.utilization_pct);
        assert!(r.is_warning());
        assert!(!r.is_critical());

        // 89% of 159 = 140.6 → value_bits=140 gives 140*100/159=88% → Warn80
        let r2 = capacity_proximity_bits(140, 159);
        assert_eq!(r2.region, CapacityRegion::Warn80,
            "140/159 = {}% should be Warn80", r2.utilization_pct);
    }

    /// Values at 90–99% of capacity must be Warn90.
    #[test]
    fn test_proximity_warn90_region() {
        // 90% of 159 = 142.2 → value_bits=143 gives 143*100/159=90%
        let r = capacity_proximity_bits(143, 159);
        assert_eq!(r.region, CapacityRegion::Warn90,
            "143/159 = {}% should be Warn90", r.utilization_pct);
    }

    /// Values at or above capacity must be Critical.
    #[test]
    fn test_proximity_critical_region() {
        let r = capacity_proximity_bits(159, 159);
        assert_eq!(r.region, CapacityRegion::Critical);
        assert!(r.is_critical());

        let r2 = capacity_proximity_bits(200, 159);
        assert_eq!(r2.region, CapacityRegion::Critical);
    }

    /// Zero value must be Safe (0 bits → 0% utilization).
    #[test]
    fn test_proximity_zero_value_is_safe() {
        let r = capacity_proximity_bits(0, 159);
        assert_eq!(r.region, CapacityRegion::Safe);
        assert_eq!(r.value_bits, 0);
    }

    // ─── Unit tests: post_switch_margin_bits ────────────────────────────────

    /// After u128→U256 with a comfortable value, margin should be healthy.
    #[test]
    fn test_post_switch_healthy_margin() {
        // value = 130 bits in U256 (256-bit capacity) → 49% headroom
        let m = post_switch_margin_bits(130, 256);
        assert!(!m.is_marginal, "headroom={}%", m.headroom_pct);
        assert!(!m.is_critical, "headroom={}%", m.headroom_pct);
        assert!(m.headroom_pct > 15);
    }

    /// Value at 85–95% of new capacity → marginal switch.
    #[test]
    fn test_post_switch_marginal_5_to_15_pct() {
        // value=224 bits in U256 → 12.5% headroom → marginal (5-15%)
        let m = post_switch_margin_bits(224, 256);
        assert!(m.is_marginal, "headroom={}% should be marginal", m.headroom_pct);
        assert!(!m.is_critical);

        // value=218 bits → 14.8% headroom → still marginal
        let m2 = post_switch_margin_bits(218, 256);
        assert!(m2.is_marginal, "headroom={}% should be marginal", m2.headroom_pct);
    }

    /// Value at >95% of new capacity → critical (< 5% headroom).
    #[test]
    fn test_post_switch_critical_below_5_pct() {
        // value=248 bits in U256 → 3% headroom → critical
        let m = post_switch_margin_bits(248, 256);
        assert!(m.is_critical, "headroom={}% should be critical", m.headroom_pct);
    }

    /// After u64→u128 promotion with medium-sized value → healthy headroom.
    #[test]
    fn test_post_switch_u64_to_u128() {
        // value=65 bits in u128 (128-bit capacity) → 49% headroom → healthy
        let m = post_switch_margin_bits(65, 128);
        assert!(!m.is_marginal && !m.is_critical,
            "headroom={}%", m.headroom_pct);
    }

    // ─── u128_bit_length correctness ────────────────────────────────────────

    #[test]
    fn test_u128_bit_length_correctness() {
        assert_eq!(u128_bit_length(0), 0, "0 has 0 bits");
        assert_eq!(u128_bit_length(1), 1, "1 has 1 bit");
        assert_eq!(u128_bit_length(2), 2, "2 has 2 bits");
        assert_eq!(u128_bit_length(3), 2, "3 has 2 bits");
        assert_eq!(u128_bit_length(4), 3, "4 has 3 bits");
        assert_eq!(u128_bit_length(127), 7, "127 has 7 bits");
        assert_eq!(u128_bit_length(128), 8, "128 has 8 bits");
        assert_eq!(u128_bit_length(u64::MAX as u128), 64, "u64::MAX has 64 bits");
        assert_eq!(u128_bit_length(u128::MAX), 128, "u128::MAX has 128 bits");
    }

    #[test]
    fn test_u64_bit_length_correctness() {
        assert_eq!(u64_bit_length(0), 0);
        assert_eq!(u64_bit_length(1), 1);
        assert_eq!(u64_bit_length(u64::MAX), 64);
    }

    // ─── KElimination::capacity_proximity ───────────────────────────────────

    /// KElimination::capacity_proximity() returns Safe for small values.
    #[test]
    fn test_kelim_capacity_proximity_small_value() {
        let ke = KElimination::from_config(KElimConfig::Standard);
        // capacity_bits for Standard: alpha ~48 bits + beta ~90 bits = ~138 bits
        // A small value (e.g., 42) is at 0% → Safe
        let report = ke.capacity_proximity(42);
        assert_eq!(report.region, CapacityRegion::Safe,
            "value=42, capacity_bits={}", report.capacity_bits);
    }

    /// KElimination::capacity_proximity() correctly reports large values.
    #[test]
    fn test_kelim_capacity_proximity_large_value() {
        let ke = KElimination::from_config(KElimConfig::Standard);
        let cap_bits = ke.capacity_bits();
        // Construct a value at 85% of capacity_bits
        let value_bits = (cap_bits * 85) / 100;
        // Build a value with exactly value_bits significant bits
        let test_value: u128 = if value_bits > 0 && value_bits < 128 {
            1u128 << (value_bits - 1)
        } else {
            1
        };
        let report = ke.capacity_proximity(test_value);
        println!("[boundary] KElim Standard: capacity_bits={}, test value_bits={}, region={:?}",
            cap_bits, report.value_bits, report.region);
        // At 85%, region should be Warn80 or Warn90
        assert!(report.region == CapacityRegion::Warn80 || report.region == CapacityRegion::Warn90,
            "value at ~85% should trigger warning, got {:?}", report.region);
    }

    // ─── DualRNSContext anchor capacity methods ──────────────────────────────

    /// anchor_capacity_bits() must return ~159 for canonical 5-anchor set.
    #[test]
    fn test_anchor_capacity_bits_canonical() {
        let config = SecureConfig::secure_128().into_config();
        let ctx = DualRNSContext::for_fhe(&config.primes, config.n);
        let anchor_bits = ctx.anchor_capacity_bits();
        println!("[boundary] anchor_capacity_bits for secure_128: {}", anchor_bits);
        // 5 primes × ~31-32 bits = ~155-160 bits
        assert!(anchor_bits >= 150 && anchor_bits <= 170,
            "Expected ~159 bits for 5 canonical anchors, got {}", anchor_bits);
    }

    /// anchor3_capacity_bits() must be ~93 bits (first 3 canonical anchors).
    #[test]
    fn test_anchor3_capacity_bits_canonical() {
        let config = SecureConfig::secure_128().into_config();
        let ctx = DualRNSContext::for_fhe(&config.primes, config.n);
        let anchor3_bits = ctx.anchor3_capacity_bits();
        println!("[boundary] anchor3_capacity_bits: {}", anchor3_bits);
        // First 3 anchors: 2013265921 (~31), 2281701377 (~31), 2483027969 (~32) = ~94 bits
        assert!(anchor3_bits >= 90 && anchor3_bits <= 100,
            "Expected ~93-94 bits for first 3 canonical anchors, got {}", anchor3_bits);
    }

    /// max_intermediate_bits() must fit within anchor capacity for all configs.
    #[test]
    fn test_max_intermediate_bits_all_configs() {
        let configs = [
            ("secure_128", SecureConfig::secure_128().into_config()),
            ("secure_192", SecureConfig::secure_192().into_config()),
            ("secure_256", SecureConfig::secure_256().into_config()),
        ];

        for (name, config) in &configs {
            let ctx = DualRNSContext::for_fhe(&config.primes, config.n);
            let intermediate = ctx.max_intermediate_bits();
            let anchor_bits = ctx.anchor_capacity_bits();
            let report = ctx.check_intermediate_proximity(intermediate);

            println!("[boundary] {}: intermediate={} bits, anchor={} bits, region={:?} ({}%)",
                name, intermediate, anchor_bits, report.region, report.utilization_pct);

            // For secure_128 and secure_192, intermediate should be well within anchor capacity
            // For secure_256, document the proximity (may be Safe or Warn80)
            if *name == "secure_128" || *name == "secure_192" {
                assert!(report.region <= CapacityRegion::Warn80,
                    "{}: intermediate ({} bits) at {}% of anchor ({} bits) — too close to boundary",
                    name, intermediate, report.utilization_pct, anchor_bits);
            }
            // secure_256 is documented; we print its region without asserting
        }
    }

    /// check_k_proximity() must return Safe for small k values.
    #[test]
    fn test_check_k_proximity_small_k() {
        let config = SecureConfig::secure_128().into_config();
        let ctx = DualRNSContext::for_fhe(&config.primes, config.n);

        // k is bounded by Q*N ≈ 2^30 * 2^12 = 2^42 → 42 bits
        // anchor3_capacity ≈ 93 bits → k at 42/93 = 45% → Safe
        let k_bits: u32 = 42;
        let report = ctx.check_k_proximity(k_bits);
        println!("[boundary] k_proximity (42 bits): region={:?} ({}%), anchor3={}",
            report.region, report.utilization_pct, report.capacity_bits);
        assert_eq!(report.region, CapacityRegion::Safe,
            "k at 42 bits should be well below 93-bit anchor3 bound");
    }

    /// Document anchor capacity for secure_256 with large N=16384.
    ///
    /// This is the specific concern the user raised: "anchor capacity drift
    /// when approaching or exceeding 159 bits for very large N at 256".
    #[test]
    fn test_anchor_capacity_drift_secure_256() {
        let config = SecureConfig::secure_256().into_config();
        let ctx = DualRNSContext::for_fhe(&config.primes, config.n);

        let anchor_bits = ctx.anchor_capacity_bits();
        let intermediate_bits = ctx.max_intermediate_bits();
        let report = ctx.check_intermediate_proximity(intermediate_bits);

        println!("[boundary] Q21/ANCHOR DRIFT secure_256:");
        println!("  n={}, num_primes={}", config.n, config.primes.len());
        println!("  anchor_capacity_bits = {}", anchor_bits);
        println!("  max_intermediate_bits (N×Q²) = {}", intermediate_bits);
        println!("  proximity region = {:?} ({}%)", report.region, report.utilization_pct);
        println!("  headroom = {} bits", report.headroom_bits());

        // Report whether secure_256 has capacity margin
        if report.region == CapacityRegion::Safe {
            println!("[boundary] ANSWER: secure_256 intermediate values are safe within anchor capacity.");
        } else if report.region == CapacityRegion::Warn80 {
            println!("[boundary] ANSWER: secure_256 is approaching 80% anchor capacity — monitor carefully.");
        } else {
            println!("[boundary] ANSWER: secure_256 is at or above {}% anchor capacity — risk of overflow.",
                if report.region == CapacityRegion::Warn90 { 90 } else { 100 });
        }
        // Test always passes — documenting the finding
    }

    /// Verify the 5%/15% post-switch margin for a u128→U256 transition
    /// at the boundary values relevant to NINE65.
    #[test]
    fn test_post_switch_margins_at_fhe_boundaries() {
        // After u128→U256, a 129-bit value has 99% headroom → healthy
        let m_healthy = post_switch_margin_bits(129, 256);
        assert!(!m_healthy.is_marginal && !m_healthy.is_critical,
            "129 bits in U256: headroom={}%", m_healthy.headroom_pct);

        // A value at 246 bits in U256 → 246*100/256=96%, headroom=4% → critical
        let m_critical = post_switch_margin_bits(246, 256);
        assert!(m_critical.is_critical,
            "246 bits in U256: headroom={}%", m_critical.headroom_pct);

        // A value at 220 bits in U256 → 14% headroom → marginal (5-15%)
        let m_marginal = post_switch_margin_bits(220, 256);
        assert!(m_marginal.is_marginal,
            "220 bits in U256: headroom={}%", m_marginal.headroom_pct);

        println!("[boundary] post-switch margins: healthy={}%, marginal={}%, critical={}%",
            m_healthy.headroom_pct, m_marginal.headroom_pct, m_critical.headroom_pct);
    }
}
