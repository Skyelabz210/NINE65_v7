// Module 5: concurrent_operations
//
// Q9: Is the system thread-safe under concurrent mixed operations?

#[cfg(test)]
mod tests {
    use nine65::entropy::shadow::ShadowHarvester;
    use nine65::ops::rns_fhe::RNSFHEContext;
    use nine65::params::secure_configs::SecureConfig;
    use std::sync::Arc;

    /// Q9: Parallel encryption from multiple threads sharing the same context.
    /// ShadowHarvester is NOT Sync, so each thread gets its own.
    #[test]
    fn test_parallel_encryption_same_context() {
        let config = SecureConfig::secure_128().into_config();
        let ctx = Arc::new(RNSFHEContext::try_new(&config).expect("context"));
        let t = config.t;

        // Generate shared keys (no rng needed for secure variant).
        let keys = Arc::new(ctx.generate_keys_dual_secure());

        // Spawn 4 threads, each encrypting and decrypting 25 values.
        let handles: Vec<_> = (0u64..4)
            .map(|thread_id| {
                let ctx = Arc::clone(&ctx);
                let keys = Arc::clone(&keys);
                std::thread::spawn(move || {
                    // Each thread has its own RNG.
                    let mut rng = ShadowHarvester::with_seed(thread_id * 1000 + 42);
                    let mut failures = 0usize;

                    for i in 0u64..25 {
                        let m = (thread_id * 100 + i) % t;
                        let ct = ctx.encrypt_dual(m, &keys.public_key, &mut rng);
                        let recovered = ctx.decrypt_dual(&ct, &keys.secret_key);
                        if recovered != m {
                            failures += 1;
                        }
                    }

                    (thread_id, failures)
                })
            })
            .collect();

        for handle in handles {
            let (thread_id, failures) = handle.join().expect("thread panicked");
            assert_eq!(
                failures, 0,
                "Thread {} had {} decryption failures under concurrent access",
                thread_id, failures
            );
        }
    }

    /// Parallel ciphertext addition: each thread uses its own key pair.
    #[test]
    fn test_parallel_ciphertext_addition() {
        let config = SecureConfig::secure_128().into_config();
        let ctx = Arc::new(RNSFHEContext::try_new(&config).expect("context"));
        let t = config.t;

        let handles: Vec<_> = (0u64..4)
            .map(|thread_id| {
                let ctx = Arc::clone(&ctx);
                std::thread::spawn(move || {
                    let mut rng = ShadowHarvester::with_seed(thread_id * 777);
                    let keys = ctx.generate_keys_dual(&mut rng);

                    let a: u64 = thread_id * 10 % t;
                    let b: u64 = (thread_id * 7 + 3) % t;

                    let ct_a = ctx.encrypt_dual(a, &keys.public_key, &mut rng);
                    let ct_b = ctx.encrypt_dual(b, &keys.public_key, &mut rng);

                    let ct_sum = ctx.add_dual(&ct_a, &ct_b);
                    let recovered = ctx.decrypt_dual(&ct_sum, &keys.secret_key);
                    let expected = (a + b) % t;

                    (thread_id, recovered, expected)
                })
            })
            .collect();

        for handle in handles {
            let (thread_id, recovered, expected) = handle.join().expect("thread panicked");
            assert_eq!(
                recovered, expected,
                "Thread {} addition failed: got {} expected {}",
                thread_id, recovered, expected
            );
        }
    }
}
