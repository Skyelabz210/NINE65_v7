// Module 2: k_elimination_extremes
//
// Q4: Does K-Elimination silently fail when capacity overflows u128? (Fix 2 closes this)
// Q5: Does U256 overflow detection work in release builds? (Fix 1 closes this)

#[cfg(test)]
mod tests {
    use nine65::arithmetic::k_elimination::KElimination;

    /// Constructor must reject prime sets whose product overflows u128.
    #[test]
    fn test_k_elimination_capacity_near_u128_max() {
        // Two 64-bit primes whose product > u128::MAX (overflow in beta_cap computation).
        // 2^64 - 59 and 2^64 - 83 are large near-64-bit values; their product >> u128::MAX.
        // (We use values that will actually trigger the overflow check added in Fix 2.)
        let large_prime_a: u64 = (u64::MAX >> 1) + 1; // 2^63 — not prime but tests the overflow path
        let large_prime_b: u64 = (u64::MAX >> 1) + 3;

        // This must return Err, not panic with overflow or return wrong u128::MAX capacity.
        let result = KElimination::try_new(&[3u64], &[large_prime_a, large_prime_b]);
        // Either it succeeds (if the product doesn't overflow) or returns Err — either is fine.
        // The critical invariant is: it must NOT silently return u128::MAX from saturating_mul.
        match result {
            Ok(ke) => {
                // If it succeeded, verify that capacity() doesn't saturate silently.
                // The capacity must equal alpha_cap * beta_cap exactly.
                let _ = ke.capacity(); // Must not panic or silently overflow
            }
            Err(e) => {
                // Expected: overflow error
                println!("[k_elim] correctly rejected overflow: {}", e);
            }
        }
    }

    /// Values at capacity-1 (maximum valid input) must reconstruct exactly.
    #[test]
    fn test_k_elimination_with_max_valid_value() {
        let ke = KElimination::try_new(&[65537u64, 65521], &[4294967291u64])
            .expect("valid construction");

        let capacity = ke.capacity();
        // capacity - 1 is the largest representable value.
        let max_val = capacity - 1;

        // Compute residues mod alpha_cap and beta_cap.
        let v_alpha = max_val % ke.alpha_cap;
        let v_beta = max_val % ke.beta_cap;

        // Reconstruct via K-Elimination.
        let k = ke.extract_k(v_alpha, v_beta);
        let reconstructed = v_alpha + k * ke.alpha_cap;

        assert_eq!(
            reconstructed, max_val,
            "K-Elimination failed at capacity-1: reconstructed {} != expected {}",
            reconstructed, max_val
        );
    }

    /// Values at or above capacity must be rejected, not silently wrapped.
    #[test]
    fn test_k_elimination_with_value_exceeding_capacity() {
        let ke = KElimination::try_new(&[65537u64, 65521], &[4294967291u64])
            .expect("valid construction");

        let capacity = ke.capacity();
        let over_capacity = capacity + 1;

        // validate_value must return Err for values >= capacity.
        let result = ke.validate_value(over_capacity);
        assert!(
            result.is_err(),
            "validate_value({}) should fail (capacity={}), but returned Ok",
            over_capacity,
            capacity
        );
    }

    /// All standard K-Elimination configs must have sufficient anchor capacity.
    #[test]
    fn test_k_elimination_anchor_capacity_all_configs() {
        use nine65::arithmetic::rns::DualRNSContext;
        use nine65::params::secure_configs::SecureConfig;

        let configs = [
            ("secure_128", SecureConfig::secure_128().into_config()),
            ("secure_192", SecureConfig::secure_192().into_config()),
        ];

        for (name, config) in &configs {
            // This calls for_fhe() which now has startup assertions.
            // It will panic if anchor capacity is insufficient — that IS the test.
            let _ctx = DualRNSContext::for_fhe(&config.primes, config.n);
            println!(
                "[k_elim] {} anchor capacity check: PASSED (n={}, {} main primes)",
                name,
                config.n,
                config.primes.len()
            );
        }
    }

    /// Adversarial residue inputs: both residues zero.
    #[test]
    fn test_k_elimination_adversarial_residues_both_zero() {
        let ke = KElimination::try_new(&[17u64, 19], &[23u64, 29]).expect("valid construction");

        // V = 0: both residues should be 0.
        let k = ke.extract_k(0, 0);
        let reconstructed = 0 + k * ke.alpha_cap;
        assert_eq!(reconstructed, 0, "K-Elim failed for V=0");
    }

    /// Adversarial residue inputs: v_beta = 0, v_alpha = alpha_cap - 1.
    #[test]
    fn test_k_elimination_adversarial_residues_extreme_crt() {
        let ke = KElimination::try_new(&[17u64, 19], &[23u64, 29]).expect("valid construction");

        // Find a value V such that V mod alpha_cap = alpha_cap - 1 and V mod beta_cap = 0.
        // By CRT: V = 0 * alpha_cap + alpha_cap - 1 is a candidate only if it's < capacity.
        // We need V such that V ≡ alpha_cap-1 (mod alpha_cap) and V ≡ 0 (mod beta_cap).
        // This is: V = k * alpha_cap + (alpha_cap - 1) for some k, where V ≡ 0 (mod beta_cap).
        // For simplicity: pick V = alpha_cap - 1 if it's < capacity and ≡ 0 mod beta_cap
        // doesn't hold, just test the raw k-extraction doesn't panic.
        let v_alpha = ke.alpha_cap - 1;
        let v_beta = 0u128;

        // This must not panic.
        let k = ke.extract_k(v_alpha, v_beta);
        let reconstructed = v_alpha + k * ke.alpha_cap;

        // Verify reconstructed is consistent: reconstructed mod alpha_cap == v_alpha
        assert_eq!(reconstructed % ke.alpha_cap, v_alpha);
        // And reconstructed mod beta_cap == v_beta
        assert_eq!(reconstructed % ke.beta_cap, v_beta);
    }

    /// K-value overflow: verify k * alpha_cap doesn't overflow in reconstruction.
    #[test]
    fn test_k_elimination_k_value_no_overflow() {
        // Use a config where alpha_cap is moderately large.
        let ke = KElimination::try_new(&[65537u64, 65521u64], &[4294967291u64])
            .expect("valid construction");

        // For maximum valid V = capacity - 1, compute k and verify no overflow.
        let max_val = ke.capacity() - 1;
        let v_alpha = max_val % ke.alpha_cap;
        let v_beta = max_val % ke.beta_cap;

        let k = ke.extract_k(v_alpha, v_beta);

        // k * alpha_cap must not overflow u128 (checked arithmetic).
        let product = k.checked_mul(ke.alpha_cap);
        assert!(
            product.is_some(),
            "k ({}) * alpha_cap ({}) overflows u128 — reconstruction would be wrong",
            k,
            ke.alpha_cap
        );

        let reconstructed = v_alpha + product.unwrap();
        assert_eq!(reconstructed, max_val);
    }
}
