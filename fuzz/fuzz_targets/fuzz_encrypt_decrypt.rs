#![no_main]

use libfuzzer_sys::fuzz_target;
use arbitrary::Arbitrary;
use nine65::prelude::*;

#[derive(Arbitrary, Debug)]
struct EncryptInput {
    plaintext: u64,
    seed: u64,
}

// Fuzz encrypt/decrypt roundtrip using the BFV API
// This verifies that for any plaintext value:
// - Encryption doesn't panic
// - Decryption correctly recovers the plaintext (mod t)
fuzz_target!(|input: EncryptInput| {
    // Use a fixed secure config to avoid parameter fuzzing overhead
    let config = FHEConfig::standard_128_insecure();

    // Bound plaintext to valid range
    let plaintext = input.plaintext % config.t;

    let ntt = NTTEngine::new(config.q, config.n);
    let mut rng = ShadowHarvester::with_seed(input.seed);

    // Generate keys using the public KeySet API
    let keys = KeySet::generate(&config, &ntt, &mut rng);

    let encoder = BFVEncoder::new(&config);
    let encryptor = BFVEncryptor::new(&keys.public_key, &encoder, &ntt, config.eta);
    let decryptor = BFVDecryptor::new(&keys.secret_key, &encoder, &ntt);

    // Encrypt
    let ct = encryptor.encrypt(plaintext, &mut rng);

    // Decrypt
    let decrypted = decryptor.decrypt(&ct);

    // Verify roundtrip correctness
    assert_eq!(
        decrypted, plaintext,
        "Roundtrip failed: encrypted {} but decrypted {}",
        plaintext, decrypted
    );
});
