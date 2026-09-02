// Module 12: negative_plaintext_coverage
//
// Q6: Are negative plaintexts handled correctly across all configs?
//
// In BFV, "negative" values are encoded as large positive values near t:
//   -1  ≡ t-1 (mod t)
//   -v  ≡ t-v (mod t) for v < t/2

#[cfg(test)]
mod tests {
    use nine65::entropy::shadow::ShadowHarvester;
    use nine65::ops::rns_fhe::RNSFHEContext;
    use nine65::params::secure_configs::SecureConfig;

    fn encode_signed(v: i64, t: u64) -> u64 {
        if v >= 0 {
            (v as u64) % t
        } else {
            let abs_v = (-v) as u64;
            t - (abs_v % t)
        }
    }

    fn decode_signed(encoded: u64, t: u64) -> i64 {
        if encoded <= t / 2 {
            encoded as i64
        } else {
            -((t - encoded) as i64)
        }
    }

    /// Q6: Negative plaintexts for secure_128.
    #[test]
    fn test_encrypt_decrypt_negative_values_secure_128() {
        let config = SecureConfig::secure_128().into_config();
        let ctx = RNSFHEContext::try_new(&config).expect("context");
        let mut rng = ShadowHarvester::with_seed(60_001);
        let keys = ctx.generate_keys_dual_secure();
        let t = config.t;

        let test_values: &[i64] = &[-1, -100, -(t as i64 / 2), (t as i64 / 2) - 1, 0, 1];

        for &v in test_values {
            let encoded = encode_signed(v, t);
            let ct = ctx.encrypt_dual_secure(encoded, &keys.public_key);
            let decrypted = ctx.decrypt_dual(&ct, &keys.secret_key);
            let decoded = decode_signed(decrypted, t);

            assert_eq!(decoded, v,
                "Negative plaintext roundtrip failed: input={}, encoded={}, decrypted={}, decoded={}",
                v, encoded, decrypted, decoded);
        }
        println!("[negative] secure_128: all signed plaintexts roundtripped correctly");
    }

    /// Q6: Negative plaintext for secure_192.
    #[test]
    fn test_encrypt_decrypt_negative_values_secure_192() {
        let config = SecureConfig::secure_192().into_config();
        let ctx = RNSFHEContext::try_new(&config).expect("context_192");
        let mut rng = ShadowHarvester::with_seed(60_002);
        let keys = ctx.generate_keys_dual_secure();
        let t = config.t;

        let test_values: &[i64] = &[-1, -50, 0, 1, (t as i64 / 2) - 1];

        for &v in test_values {
            let encoded = encode_signed(v, t);
            let ct = ctx.encrypt_dual_secure(encoded, &keys.public_key);
            let decrypted = ctx.decrypt_dual(&ct, &keys.secret_key);
            let decoded = decode_signed(decrypted, t);

            assert_eq!(
                decoded, v,
                "secure_192 negative plaintext failed: input={}, decoded={}",
                v, decoded
            );
        }
    }

    /// Homomorphic addition of negative and positive values.
    /// Enc(-5) + Enc(3) = Enc(-2)
    #[test]
    fn test_add_negative_and_positive() {
        let config = SecureConfig::secure_128().into_config();
        let ctx = RNSFHEContext::try_new(&config).expect("context");
        let mut rng = ShadowHarvester::with_seed(60_003);
        let keys = ctx.generate_keys_dual_secure();
        let t = config.t;

        let a: i64 = -5;
        let b: i64 = 3;
        let expected: i64 = a + b; // -2

        let enc_a = encode_signed(a, t);
        let enc_b = encode_signed(b, t);

        let ct_a = ctx.encrypt_dual_secure(enc_a, &keys.public_key);
        let ct_b = ctx.encrypt_dual_secure(enc_b, &keys.public_key);
        let ct_sum = ctx.add_dual(&ct_a, &ct_b);

        let decrypted = ctx.decrypt_dual(&ct_sum, &keys.secret_key);
        let decoded = decode_signed(decrypted, t);

        assert_eq!(
            decoded, expected,
            "Enc({}) + Enc({}) = {} expected {}",
            a, b, decoded, expected
        );
    }

    /// Homomorphic multiplication: Enc(-3) * Enc(2) = Enc(-6).
    #[test]
    fn test_mul_negative_by_positive() {
        let config = SecureConfig::secure_128().into_config();
        let ctx = RNSFHEContext::try_new(&config).expect("context");
        let mut rng = ShadowHarvester::with_seed(60_004);
        let keys = ctx.generate_keys_dual_secure();
        let t = config.t;

        let a: i64 = -3;
        let b: i64 = 2;
        let expected: i64 = a * b; // -6

        let enc_a = encode_signed(a, t);
        let enc_b = encode_signed(b, t);

        let ct_a = ctx.encrypt_dual_secure(enc_a, &keys.public_key);
        let ct_b = ctx.encrypt_dual_secure(enc_b, &keys.public_key);
        let ct_mul = ctx.mul_dual_symmetric(&ct_a, &ct_b, &keys.secret_key);

        let decrypted = ctx.decrypt_dual(&ct_mul, &keys.secret_key);
        let decoded = decode_signed(decrypted, t);

        assert_eq!(
            decoded, expected,
            "Enc({}) * Enc({}) = {} expected {}",
            a, b, decoded, expected
        );
    }
}
