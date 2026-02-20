#![no_main]

use libfuzzer_sys::fuzz_target;
use nine65::ops::rns_fhe::DualRNSCiphertext;

// Fuzz the ciphertext deserialization with arbitrary bytes
// This tests that malformed input doesn't cause:
// - Panics
// - Memory corruption
// - Excessive allocation (DoS)
fuzz_target!(|data: &[u8]| {
    // Test binary deserialization (validated path)
    let _ = DualRNSCiphertext::from_bytes_validated(data);

    // Test JSON deserialization if data looks like valid UTF-8
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = DualRNSCiphertext::from_json_validated(s);
    }
});
