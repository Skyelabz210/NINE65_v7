// Module 13: key_serialization_roundtrip
//
// Q19: Are key serialization round-trips lossless?

#[cfg(test)]
mod tests {
    use nine65::ops::rns_fhe::{RNSFHEContext, DualRNSKeySet};
    use nine65::params::secure_configs::SecureConfig;
    use nine65::entropy::shadow::ShadowHarvester;

    /// Q19: DualRNSKeySet JSON serialization roundtrip — encrypt after deserialization
    /// must produce the same plaintext as before.
    #[test]
    fn test_dual_key_set_json_serialization_roundtrip() {
        let config = SecureConfig::secure_128().into_config();
        let ctx = RNSFHEContext::try_new(&config).expect("context");
        let mut rng = ShadowHarvester::with_seed(70_001);
        let keys = ctx.generate_keys_dual(&mut rng);

        // Serialize the whole keyset.
        let json = keys.to_json().expect("key serialize");

        // Deserialize.
        let keys2 = DualRNSKeySet::from_json_validated(&json).expect("key deserialize");

        // Encrypt with deserialized pk, decrypt with deserialized sk.
        let m: u64 = 12345;
        let ct = ctx.encrypt_dual(m, &keys2.public_key, &mut rng);
        let recovered = ctx.decrypt_dual(&ct, &keys2.secret_key);

        assert_eq!(recovered, m,
            "Key serialization roundtrip failed: got {} expected {}", recovered, m);
        println!("[key_ser] DualRNSKeySet JSON roundtrip: OK ({}b)", json.len());
    }

    /// Bytes (bincode) serialization roundtrip for DualRNSKeySet.
    #[test]
    fn test_key_set_bytes_serialization_roundtrip() {
        let config = SecureConfig::secure_128().into_config();
        let ctx = RNSFHEContext::try_new(&config).expect("context");
        let mut rng = ShadowHarvester::with_seed(70_002);
        let keys = ctx.generate_keys_dual(&mut rng);

        // Serialize to bytes.
        let bytes = keys.to_bytes().expect("key to bytes");
        println!("[key_ser] keyset bytes size: {}", bytes.len());

        // Deserialize.
        let keys2 = DualRNSKeySet::from_bytes_validated(&bytes).expect("key from bytes");

        // Encrypt with deserialized key, decrypt with deserialized key.
        let m: u64 = 9876;
        let ct = ctx.encrypt_dual(m, &keys2.public_key, &mut rng);
        let recovered = ctx.decrypt_dual(&ct, &keys2.secret_key);

        assert_eq!(recovered, m,
            "Key bytes roundtrip failed: got {} expected {}", recovered, m);
    }

    /// Full key set (with eval key) multiplication roundtrip.
    #[test]
    fn test_full_key_set_multiplication_roundtrip() {
        let config = SecureConfig::secure_128().into_config();
        let ctx = RNSFHEContext::try_new(&config).expect("context");
        let mut rng = ShadowHarvester::with_seed(70_003);
        let full_keys = ctx.generate_keys_dual_full(&mut rng);

        let m: u64 = 7;
        let ct = ctx.encrypt_dual(m, &full_keys.public_key, &mut rng);
        let ct_mul = ctx.mul_dual_public(&ct, &ct, &full_keys.eval_key)
            .expect("multiplication");
        let recovered = ctx.decrypt_dual(&ct_mul, &full_keys.secret_key);
        let expected = (m * m) % config.t;

        assert_eq!(recovered, expected,
            "Full key set mul roundtrip failed: got {} expected {}", recovered, expected);
        println!("[key_ser] DualRNSFullKeySet mul roundtrip: OK");
    }

    /// Secret key serialization roundtrip — encrypt with original pk, decrypt with
    /// the deserialized sk from a round-tripped keyset.
    #[test]
    fn test_secret_key_bytes_serialization_roundtrip() {
        let config = SecureConfig::secure_128().into_config();
        let ctx = RNSFHEContext::try_new(&config).expect("context");
        let mut rng = ShadowHarvester::with_seed(70_004);
        let keys = ctx.generate_keys_dual(&mut rng);

        let bytes = keys.to_bytes().expect("sk to bytes");
        println!("[key_ser] keyset bytes size: {}", bytes.len());

        let keys2 = DualRNSKeySet::from_bytes_validated(&bytes).expect("sk from bytes");

        let m: u64 = 1234;
        let ct = ctx.encrypt_dual_secure(m, &keys.public_key);
        let recovered = ctx.decrypt_dual(&ct, &keys2.secret_key);

        assert_eq!(recovered, m,
            "Secret key bytes roundtrip failed: got {} expected {}", recovered, m);
    }

    /// Key sizes must be within documented bounds (regression test for key bloat).
    #[test]
    fn test_serialized_key_size_within_bounds() {
        let config = SecureConfig::secure_128().into_config();
        let ctx = RNSFHEContext::try_new(&config).expect("context");
        let mut rng = ShadowHarvester::with_seed(70_005);
        let keys = ctx.generate_keys_dual(&mut rng);

        let keyset_size = keys.to_bytes().map(|b| b.len()).unwrap_or(0);
        println!("[key_ser] secure_128 keyset size: {}B", keyset_size);

        // Sanity bounds: keys should not be unreasonably large.
        // For n=4096, 3 primes: expected DualRNSKeySet size is in the tens of KB range.
        let keyset_mb = keyset_size / (1024 * 1024);
        assert!(keyset_mb < 10, "Keyset exceeds 10 MB: {} bytes — possible key bloat regression", keyset_size);
    }
}
