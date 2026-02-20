use proptest::prelude::*;
use nine65::prelude::*;

/// Property‑based test: encryption then decryption returns the original message.
proptest! {
    #[test]
    fn prop_encrypt_decrypt(msg in 0u64..1000) {
        // Use standard 128‑bit config for reproducibility
        let config = FHEConfig::standard_128();
        let ntt = NTTEngine::new(config.q, config.n);
        let mut rng = ShadowHarvester::with_seed(42);

        // Key generation
        let keys = KeySet::generate(&config, &ntt, &mut rng);
        let encoder = BFVEncoder::new(&config);
        let encryptor = BFVEncryptor::new(&keys.public_key, &encoder, &ntt, config.eta);
        let decryptor = BFVDecryptor::new(&keys.secret_key, &encoder, &ntt);

        // Encrypt and decrypt the random message
        let ct = encryptor.encrypt(msg, &mut rng);
        let decrypted = decryptor.decrypt(&ct);

        // Assert equality modulo t (plaintext modulus)
        prop_assert_eq!(decrypted, msg);
    }
}
