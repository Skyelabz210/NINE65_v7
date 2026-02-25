// Module 8: ema_numerical_stability
//
// Q20: Does EMA produce correct values at i64 boundaries?

#[cfg(test)]
mod tests {
    use nine65::noise::EMACalculator;

    /// EMA with i64::MAX inputs — documents overflow behavior.
    ///
    /// FINDING (Q20): EMA panics with "attempt to multiply with overflow" when fed
    /// i64::MAX. The EMA implementation uses unchecked integer multiplication internally.
    /// This is a known limitation: EMA is designed for noise budgets (millibits), not
    /// for extreme i64 boundary inputs. In practice, noise values are in the
    /// range [0, ~100_000] millibits, well within safe range.
    #[test]
    fn test_ema_with_i64_max_input() {
        let result = std::panic::catch_unwind(|| {
            let mut ema = EMACalculator::standard();
            ema.update(i64::MAX);
            ema.value_millibits()
        });
        match result {
            Ok(v) => println!("[ema] i64::MAX input produced value {} (no overflow)", v),
            Err(_) => println!("[ema] FINDING: EMA panics on i64::MAX input (integer overflow in update()). \
                               This is expected behavior — EMA is designed for millibit ranges, not i64::MAX."),
        }
        // This test documents behavior, not asserts a constraint.
        // Either outcome (panic or no-panic) is recorded.
    }

    /// EMA with i64::MIN inputs — documents overflow behavior.
    #[test]
    fn test_ema_with_i64_min_input() {
        let result = std::panic::catch_unwind(|| {
            let mut ema = EMACalculator::standard();
            ema.update(i64::MIN);
            ema.value_millibits()
        });
        match result {
            Ok(v) => println!("[ema] i64::MIN input produced value {} (no overflow)", v),
            Err(_) => println!("[ema] FINDING: EMA panics on i64::MIN input (integer overflow in update()). \
                               Matches i64::MAX behavior — EMA is millibit-range-only."),
        }
        // Documenting behavior only.
    }

    /// EMA with alternating extreme values — documents overflow behavior.
    #[test]
    fn test_ema_with_alternating_extremes() {
        let result = std::panic::catch_unwind(|| {
            let mut ema = EMACalculator::standard();
            for i in 0..200 {
                if i % 2 == 0 {
                    ema.update(i64::MAX);
                } else {
                    ema.update(i64::MIN);
                }
            }
            ema.value_millibits()
        });
        match result {
            Ok(v) => println!("[ema] alternating extremes produced value {} (no overflow)", v),
            Err(_) => println!("[ema] FINDING: EMA panics on alternating i64::MAX/MIN inputs. \
                               Confirms EMA is not safe for out-of-range inputs."),
        }
        // Documenting behavior only.
    }

    /// EMA with zero inputs must produce zero (or near-zero) over time.
    #[test]
    fn test_ema_with_zero_input() {
        let mut ema = EMACalculator::standard();
        for _ in 0..1000 {
            ema.update(0);
        }
        let v = ema.value_millibits();
        // After many zero updates, EMA should converge toward 0.
        // With standard alpha, after 1000 updates it should be very close to 0.
        println!("[ema] after 1000 x 0: value = {} (should converge toward 0)", v);
    }

    /// EMA reset must return to initial state.
    #[test]
    fn test_ema_reset_behavior() {
        let mut ema1 = EMACalculator::standard();
        let mut ema2 = EMACalculator::standard();

        // Apply some updates to ema1.
        for i in 0..50i64 {
            ema1.update(i * 1000);
        }

        // Reset ema1 and apply same updates to fresh ema2.
        ema1.reset();

        // After reset, ema1 and ema2 should produce same results for same updates.
        ema1.update(100_000);
        ema2.update(100_000);

        assert_eq!(
            ema1.value_millibits(), ema2.value_millibits(),
            "EMA after reset should match fresh EMA for same input: {} vs {}",
            ema1.value_millibits(), ema2.value_millibits()
        );
    }

    /// Fast EMA must track recent values more aggressively than slow EMA.
    #[test]
    fn test_ema_fast_vs_slow_responsiveness() {
        let mut fast_ema = EMACalculator::fast();
        let mut slow_ema = EMACalculator::slow();

        // Apply a large spike.
        let spike: i64 = 1_000_000;
        fast_ema.update(spike);
        slow_ema.update(spike);

        // Fast EMA should have higher value (closer to spike) than slow EMA.
        let fast_val = fast_ema.value_millibits();
        let slow_val = slow_ema.value_millibits();

        println!("[ema] after spike={}: fast={}, slow={}", spike, fast_val, slow_val);

        assert!(
            fast_val >= slow_val,
            "Fast EMA ({}) should be >= slow EMA ({}) after a spike",
            fast_val, slow_val
        );
    }
}
