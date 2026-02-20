use nine65::prelude::*;
use nine65::params::secure_configs::SecureConfig;
use nine65::ops::rns_fhe::RNSFHEContext;
use nine65::ops::gso_fhe::GSOFHEContext;
use nine65::entropy::ShadowHarvester;

/// Comprehensive Audit Test Suite for NINE65 v5
/// 
/// This test suite verifies:
/// 1. Basic FHE operations (encrypt, decrypt, add, mul)
/// 2. K-Elimination exact division functionality
/// 3. Security properties and parameter validation
/// 4. Performance characteristics
/// 5. Edge cases and error conditions
fn main() {
    println!("🧪 Starting NINE65 v5 Comprehensive Audit Test Suite...\n");

    // Test 1: Basic FHE operations with secure_128
    test_basic_fhe_operations();
    
    // Test 2: K-Elimination functionality
    test_k_elimination();
    
    // Test 3: Security parameter validation
    test_security_validation();
    
    // Test 4: Depth testing (bootstrap-free)
    test_depth_capabilities();
    
    // Test 5: Performance benchmarking
    test_performance_benchmarks();
    
    // Test 6: Edge cases and error handling
    test_edge_cases();
    
    println!("\n✅ All audit tests completed successfully!");
}

fn test_basic_fhe_operations() {
    println!("📋 Testing Basic FHE Operations...");
    
    let config = SecureConfig::secure_128().into_config();
    let inner = RNSFHEContext::new_coeff_domain(&config);
    let ctx = GSOFHEContext::new(inner);
    let keys = ctx.keygen();
    
    // Encrypt two values
    let ct_a = ctx.encrypt(42, &keys.public_key);
    let ct_b = ctx.encrypt(7, &keys.public_key);
    
    // Test addition
    let ct_sum = ctx.add(&ct_a, &ct_b);
    let result_sum = ctx.decrypt(&ct_sum, &keys.secret_key);
    assert_eq!(result_sum, 42 + 7, "Addition failed");
    println!("  ✅ Addition: 42 + 7 = {}", result_sum);
    
    // Test multiplication
    let ct_prod = ctx.mul(&ct_a, &ct_b, &keys.secret_key);
    let result_prod = ctx.decrypt(&ct_prod, &keys.secret_key);
    assert_eq!(result_prod, 42 * 7, "Multiplication failed");
    println!("  ✅ Multiplication: 42 * 7 = {}", result_prod);
    
    // Test subtraction
    let ct_diff = ctx.sub(&ct_a, &ct_b);
    let result_diff = ctx.decrypt(&ct_diff, &keys.secret_key);
    assert_eq!(result_diff, (42 - 7) % config.t, "Subtraction failed");
    println!("  ✅ Subtraction: 42 - 7 = {}", result_diff);
    
    // Test negation
    let ct_neg = ctx.negate(&ct_a);
    let result_neg = ctx.decrypt(&ct_neg, &keys.secret_key);
    let expected_neg = (config.t - 42) % config.t;
    assert_eq!(result_neg, expected_neg, "Negation failed");
    println!("  ✅ Negation: -42 = {} (mod {})", result_neg, config.t);
    
    println!("  🟢 Basic FHE operations test passed!\n");
}

fn test_k_elimination() {
    println!("🔧 Testing K-Elimination Functionality...");
    
    use nine65::arithmetic::rns::{DualRNSContext, DualRNSPolynomial};
    
    // Use small primes for testing
    let main_primes = vec![998244353, 985661441, 754974721];
    let anchor_primes = vec![2013265921, 2281701377];
    
    let ctx = DualRNSContext::new(main_primes, anchor_primes, 4);
    
    // Test exact division
    let test_val: u128 = 600;
    let divisor = 6u64;
    let expected = 100u128;
    
    let v_main = test_val % ctx.main_product;
    let v_anchor = test_val % ctx.anchor_product;
    
    let result = ctx.exact_divide(v_main, v_anchor, divisor);
    assert_eq!(result, expected, "K-Elimination exact division failed!");
    println!("  ✅ Exact division: {} / {} = {}", test_val, divisor, result);
    
    // Test K-Elimination reconstruction
    let v: u128 = 500;
    let v_main = v % ctx.main_product;
    let v_anchor = v % ctx.anchor_product;
    
    let k = ctx.extract_k(v_main, v_anchor);
    let reconstructed = ctx.reconstruct(v_main, v_anchor);
    
    assert_eq!(reconstructed, v, "K-Elimination reconstruction failed!");
    println!("  ✅ Reconstruction: {} -> k={}, reconstructed={}", v, k, reconstructed);
    
    println!("  🟢 K-Elimination functionality test passed!\n");
}

fn test_security_validation() {
    println!("🔒 Testing Security Parameter Validation...");
    
    use nine65::security::{LWEParams, SecurityEstimate, ConfidenceLevel};
    
    // Test secure_128 config
    let config = SecureConfig::secure_128().into_config();
    let params = LWEParams::from_config(&config);
    let estimate = params.he_standard_estimate();
    
    assert!(estimate.classical_bits >= 128, "Secure 128 config should provide 128-bit security");
    assert!(estimate.quantum_bits >= 85, "Should have quantum security >= 85 bits");
    assert_eq!(estimate.confidence, ConfidenceLevel::Standard, "Should use standard confidence");
    
    println!("  ✅ Secure 128: {} (classical), ~{} (quantum)", 
             estimate.classical_bits, estimate.quantum_bits);
    
    // Test secure_192 config
    let config_192 = SecureConfig::secure_192().into_config();
    let params_192 = LWEParams::from_config(&config_192);
    let estimate_192 = params_192.he_standard_estimate();
    
    assert!(estimate_192.classical_bits >= 192, "Secure 192 config should provide 192-bit security");
    assert!(estimate_192.quantum_bits >= 128, "Should have quantum security >= 128 bits");
    
    println!("  ✅ Secure 192: {} (classical), ~{} (quantum)", 
             estimate_192.classical_bits, estimate_192.quantum_bits);
    
    // Verify N/log(q) ratio meets HE Standard requirements
    assert!(params.meets_he_standard(128), "Should meet HE Standard for 128-bit security");
    assert!(params_192.meets_he_standard(192), "Should meet HE Standard for 192-bit security");
    
    println!("  🟢 Security validation test passed!\n");
}

fn test_depth_capabilities() {
    println!("📈 Testing Depth Capabilities (Bootstrap-Free)...");
    
    let config = SecureConfig::secure_128().into_config();
    let inner = RNSFHEContext::new_coeff_domain(&config);
    let ctx = GSOFHEContext::new(inner);
    let keys = ctx.keygen();
    
    // Encrypt initial values
    let mut ct_current = ctx.encrypt(2, &keys.public_key);
    
    // Perform 50 multiplications (the claimed max depth)
    let mut expected_result = 2u64; // Start with 2
    
    for i in 1..=50 {
        // Multiply by 2 each time
        let ct_two = ctx.encrypt(2, &keys.public_key);
        ct_current = ctx.mul(&ct_current, &ct_two, &keys.secret_key);
        expected_result = (expected_result * 2) % config.t;
        
        // Decrypt and verify at intervals
        if i % 10 == 0 {
            let result = ctx.decrypt(&ct_current, &keys.secret_key);
            assert_eq!(result, expected_result, 
                      "Depth {} multiplication failed: expected {}, got {}", 
                      i, expected_result, result);
            println!("    Depth {}: ✓ (result = {})", i, result);
        }
    }
    
    // Final verification
    let final_result = ctx.decrypt(&ct_current, &keys.secret_key);
    assert_eq!(final_result, expected_result, 
              "Final depth 50 multiplication failed: expected {}, got {}", 
              expected_result, final_result);
    
    println!("  ✅ Depth 50 test passed: 2^50 mod {} = {}", config.t, final_result);
    println!("  🟢 Depth capabilities test passed! (0 bootstraps required)\n");
}

fn test_performance_benchmarks() {
    println!("⏱️  Testing Performance Benchmarks...");
    
    let config = SecureConfig::secure_128().into_config();
    let inner = RNSFHEContext::new_coeff_domain(&config);
    let ctx = GSOFHEContext::new(inner);
    let keys = ctx.keygen();
    
    // Benchmark encryption
    let start = std::time::Instant::now();
    let ct = ctx.encrypt(42, &keys.public_key);
    let encrypt_time = start.elapsed();
    
    // Benchmark decryption
    let start = std::time::Instant::now();
    let _result = ctx.decrypt(&ct, &keys.secret_key);
    let decrypt_time = start.elapsed();
    
    // Benchmark addition
    let ct_a = ctx.encrypt(10, &keys.public_key);
    let ct_b = ctx.encrypt(20, &keys.public_key);
    let start = std::time::Instant::now();
    let _ct_sum = ctx.add(&ct_a, &ct_b);
    let add_time = start.elapsed();
    
    // Benchmark multiplication
    let start = std::time::Instant::now();
    let _ct_prod = ctx.mul(&ct_a, &ct_b, &keys.secret_key);
    let mul_time = start.elapsed();
    
    println!("  📊 Performance Results (secure_128):");
    println!("    Encrypt: {:?}", encrypt_time);
    println!("    Decrypt: {:?}", decrypt_time);
    println!("    Add:     {:?}", add_time);
    println!("    Mul:     {:?}", mul_time);
    
    // Verify times are reasonable (not more than 10 seconds per operation)
    assert!(encrypt_time.as_secs() < 10, "Encryption too slow");
    assert!(decrypt_time.as_secs() < 10, "Decryption too slow");
    assert!(add_time.as_secs() < 10, "Addition too slow");
    assert!(mul_time.as_secs() < 10, "Multiplication too slow");
    
    println!("  🟢 Performance benchmarks test passed!\n");
}

fn test_edge_cases() {
    println!("🔍 Testing Edge Cases and Error Handling...");
    
    let config = SecureConfig::secure_128().into_config();
    let inner = RNSFHEContext::new_coeff_domain(&config);
    let ctx = GSOFHEContext::new(inner);
    let keys = ctx.keygen();
    
    // Test with value 0
    let ct_zero = ctx.encrypt(0, &keys.public_key);
    let result_zero = ctx.decrypt(&ct_zero, &keys.secret_key);
    assert_eq!(result_zero, 0, "Zero encryption failed");
    println!("  ✅ Zero encryption/decryption: 0 -> {}", result_zero);
    
    // Test with value 1
    let ct_one = ctx.encrypt(1, &keys.public_key);
    let result_one = ctx.decrypt(&ct_one, &keys.secret_key);
    assert_eq!(result_one, 1, "One encryption failed");
    println!("  ✅ One encryption/decryption: 1 -> {}", result_one);
    
    // Test with large value (close to t)
    let large_val = config.t - 1;
    let ct_large = ctx.encrypt(large_val, &keys.public_key);
    let result_large = ctx.decrypt(&ct_large, &keys.secret_key);
    assert_eq!(result_large, large_val, "Large value encryption failed");
    println!("  ✅ Large value encryption/decryption: {} -> {}", large_val, result_large);
    
    // Test multiplication with 0
    let ct_zero_again = ctx.encrypt(0, &keys.public_key);
    let ct_any = ctx.encrypt(42, &keys.public_key);
    let ct_mult_zero = ctx.mul(&ct_zero_again, &ct_any, &keys.secret_key);
    let result_mult_zero = ctx.decrypt(&ct_mult_zero, &keys.secret_key);
    assert_eq!(result_mult_zero, 0, "Multiplication by zero failed");
    println!("  ✅ Multiplication by zero: 0 * 42 = {}", result_mult_zero);
    
    // Test multiplication with 1 (identity)
    let ct_one_again = ctx.encrypt(1, &keys.public_key);
    let ct_other = ctx.encrypt(123, &keys.public_key);
    let ct_mult_one = ctx.mul(&ct_one_again, &ct_other, &keys.secret_key);
    let result_mult_one = ctx.decrypt(&ct_mult_one, &keys.secret_key);
    assert_eq!(result_mult_one, 123, "Multiplication by one failed");
    println!("  ✅ Multiplication by one: 1 * 123 = {}", result_mult_one);
    
    println!("  🟢 Edge cases test passed!\n");
}