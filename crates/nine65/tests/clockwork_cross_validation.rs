//! Cross-validation: Clockwork Garner vs NINE65 K-Elimination
//!
//! Property-tests that Clockwork's Garner reconstruction produces
//! identical results to NINE65's K-Elimination for the same inputs.
//! This validates both implementations and provides a cross-check
//! for production use.

#[cfg(feature = "clockwork")]
mod tests {
    use clockwork_core::basis::RnsBasis;
    use clockwork_core::garner::{garner_decompose, garner_decompose_ct};
    use nine65::arithmetic::KElimination;

    /// For a 2-modulus case, NINE65's K-Elimination and Clockwork's Garner
    /// must reconstruct the same value from the same residues.
    #[test]
    fn garner_matches_kelim_2_modulus() {
        // Use two coprime moduli
        let m = 251u64;
        let a = 509u64;
        let moduli = vec![m, a];
        let basis = RnsBasis::new(moduli.clone()).unwrap();

        // NINE65 K-Elimination with same moduli
        let kelim = KElimination::new(&[m], &[a]);

        let mut rng: u64 = 0xDEAD_BEEF_CAFE_BABE;
        for _ in 0..100_000 {
            rng = rng.wrapping_mul(6364136223846793005).wrapping_add(1);
            let value = (rng as u128) % basis.capacity();

            // Compute residues
            let r_m = (value % m as u128) as u64;
            let r_a = (value % a as u128) as u64;
            let residues = vec![r_m, r_a];

            // Reconstruct via Clockwork Garner
            let garner_digits = garner_decompose(&residues, &moduli);
            let garner_result = garner_digits.reconstruct();

            // Reconstruct via NINE65 K-Elimination
            let k = kelim.extract_k(r_m as u128, r_a as u128);
            let kelim_result = r_m as u128 + k * m as u128;

            assert_eq!(
                garner_result, kelim_result,
                "Garner vs K-Elim mismatch: value={value}, r_m={r_m}, r_a={r_a}, \
                 garner={garner_result}, kelim={kelim_result}"
            );

            // Both must equal the original value
            assert_eq!(
                value, garner_result,
                "Garner reconstruction wrong for value={value}"
            );
        }
    }

    /// Multi-modulus Garner reconstruction agrees with Clockwork CRT decode.
    #[test]
    fn garner_matches_crt_decode_multi_modulus() {
        let moduli = vec![17u64, 31, 61, 127, 251];
        let basis = RnsBasis::new(moduli.clone()).unwrap();

        let mut rng: u64 = 0xCAFE_BABE_1234_5678;
        for _ in 0..100_000 {
            rng = rng.wrapping_mul(6364136223846793005).wrapping_add(1);
            let value = (rng as u128) % basis.capacity();

            let residues = basis.encode(value);

            // Reconstruct via Garner
            let garner_digits = garner_decompose(&residues, &moduli);
            let garner_result = garner_digits.reconstruct();

            // Reconstruct via CRT decode
            let crt_result = basis.decode(&residues);

            assert_eq!(
                garner_result, crt_result,
                "Garner vs CRT decode mismatch: value={value}"
            );
            assert_eq!(
                value, garner_result,
                "Reconstruction wrong for value={value}"
            );
        }
    }

    /// Constant-time Garner decomposition matches standard decomposition.
    #[test]
    fn garner_ct_matches_standard() {
        let moduli = vec![251u64, 509, 521, 1021];
        let basis = RnsBasis::new(moduli.clone()).unwrap();

        let mut rng: u64 = 0x1111_2222_3333_4444;
        for _ in 0..100_000 {
            rng = rng.wrapping_mul(6364136223846793005).wrapping_add(1);
            let value = (rng as u128) % basis.capacity();

            let residues = basis.encode(value);

            let digits_std = garner_decompose(&residues, &moduli);
            let digits_ct = garner_decompose_ct(&residues, &moduli);

            assert_eq!(
                digits_std.digits, digits_ct.digits,
                "CT vs standard Garner diverged at value={value}"
            );

            // Both must reconstruct correctly
            assert_eq!(digits_std.reconstruct(), value);
            assert_eq!(digits_ct.reconstruct(), value);
        }
    }

    /// Exhaustive test for small moduli: every value in the range
    /// must reconstruct identically through both paths.
    #[test]
    fn exhaustive_small_moduli() {
        let moduli = vec![7u64, 11, 13]; // M = 1001
        let basis = RnsBasis::new(moduli.clone()).unwrap();

        // Also set up a 2-modulus K-Elimination for (7*11, 13) = (77, 13)
        let kelim_2mod = KElimination::new(&[7, 11], &[13]);

        for value in 0..basis.capacity() {
            let residues = basis.encode(value);

            // Garner reconstruction
            let garner_digits = garner_decompose(&residues, &moduli);
            let garner_result = garner_digits.reconstruct();

            // CRT decode
            let crt_result = basis.decode(&residues);

            // K-Elimination (2-modulus: alpha={7,11}=77, beta={13})
            let v_alpha = value % 77;
            let v_beta = value % 13;
            let k = kelim_2mod.extract_k(v_alpha, v_beta);
            let kelim_result = v_alpha + k * 77;

            assert_eq!(garner_result, value, "Garner wrong at {value}");
            assert_eq!(crt_result, value, "CRT wrong at {value}");
            assert_eq!(kelim_result, value, "K-Elim wrong at {value}");
        }
    }

    /// Centered lift consistency: Clockwork's centered lift should be
    /// consistent with its decode for all values.
    #[test]
    fn centered_lift_consistency() {
        let moduli = vec![7u64, 11, 13];
        let basis = RnsBasis::new(moduli.clone()).unwrap();
        let capacity = basis.capacity(); // 1001

        for value in 0..capacity {
            let residues = basis.encode(value);
            let decoded = basis.decode(&residues);
            let centered = basis.centered_lift(decoded);

            // centered ∈ [-500, 500]
            let half = capacity as i128 / 2;
            assert!(
                centered >= -half && centered <= half,
                "Centered lift out of range: {centered} for value={value}"
            );

            // centered ≡ value (mod M)
            let c_mod = ((centered % capacity as i128) + capacity as i128) as u128 % capacity;
            assert_eq!(c_mod, value, "Centered lift not congruent at value={value}");
        }
    }
}
