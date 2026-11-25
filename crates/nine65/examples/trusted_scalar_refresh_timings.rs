//! Compare trusted-key scalar refresh on matched inputs with OS randomness.
//! cargo run --locked --release -p nine65 --example trusted_scalar_refresh_timings
use nine65::ops::symmetric_bootstrap::SymmetricBootstrap;
use nine65::params::SecureConfig;
use std::time::Instant;

fn timed<T>(run: impl FnOnce() -> T) -> (T, u128) {
    let start = Instant::now();
    let output = run();
    (output, start.elapsed().as_nanos())
}

fn main() {
    let cfg = SecureConfig::secure_128().into_config();
    let mut refresh = SymmetricBootstrap::new(&cfg).expect("secure_128 context");
    let keys = refresh.ctx.generate_keys_dual_secure();
    let (sk, pk) = (&keys.secret_key, &keys.public_key);

    // Each pair uses the same fresh input. Alternate execution order after warmup.
    // The reference composes the existing full-product decoder with secure encryption.
    println!("round,message,full_decode_ns,scalar_decode_ns,full_refresh_ns,scalar_refresh_ns");
    for round in 0..=21 {
        let message = [0, 1, cfg.t / 2, cfg.t / 2 + 1, cfg.t - 1, 42][round % 6];
        let ct = refresh.ctx.encrypt_dual_secure(message, pk);
        let full_decode = || refresh.ctx.decrypt_dual(&ct, sk);
        let scalar_decode = || {
            refresh
                .ctx
                .try_decrypt_dual_scalar(&ct, sk)
                .expect("decode")
        };
        let (full, scalar) = if round % 2 == 0 {
            (timed(full_decode), timed(scalar_decode))
        } else {
            let scalar = timed(scalar_decode);
            (timed(full_decode), scalar)
        };
        assert_eq!(full.0, message);
        assert_eq!(scalar.0, message);

        let reference = |engine: &SymmetricBootstrap| {
            engine
                .ctx
                .encrypt_dual_secure(engine.ctx.decrypt_dual(&ct, sk), pk)
        };
        let (before, after) = if round % 2 == 0 {
            let before = timed(|| reference(&refresh));
            (
                before,
                timed(|| refresh.bootstrap_secure(&ct, sk, pk).expect("refresh")),
            )
        } else {
            let after = timed(|| refresh.bootstrap_secure(&ct, sk, pk).expect("refresh"));
            (timed(|| reference(&refresh)), after)
        };
        assert_eq!(refresh.ctx.decrypt_dual(&before.0, sk), message);
        assert_eq!(refresh.ctx.decrypt_dual(&after.0, sk), message);
        if round != 0 {
            println!(
                "{round},{message},{},{},{},{}",
                full.1, scalar.1, before.1, after.1
            );
        }
    }
}
