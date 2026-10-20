use super::*;
use crate::entropy::ShadowHarvester;
use crate::params::SecureConfig;

fn toy() -> FHEConfig {
    let mut config = SecureConfig::secure_128().into_config();
    config.n = 8;
    config.security_bits = 0;
    config.name = "certified_main_toy";
    config
}

fn pair(config: &FHEConfig) -> (CramMainClient, CramMainEvaluator) {
    CramMainEvaluator::generate_with_rng(config, &mut ShadowHarvester::with_seed(0xc001)).unwrap()
}

#[test]
fn certified_main_scalar_operations_and_signed_boundaries() {
    let config = toy();
    let (client, eval) = pair(&config);
    let t = config.t;
    for value in [0, 1, t / 2, t / 2 + 1, t - 1] {
        let a = eval.encrypt(value).unwrap();
        assert_eq!(client.decrypt(&a).unwrap(), value);
        assert_eq!(
            client.decrypt(&eval.negate(&a).unwrap()).unwrap(),
            (t - value) % t
        );
        for scalar in [0, 1, 2, t / 2, t - 1] {
            assert_eq!(
                client
                    .decrypt(&eval.add_plain(&a, scalar).unwrap())
                    .unwrap(),
                (value + scalar) % t
            );
            assert_eq!(
                client
                    .decrypt(&eval.mul_plain(&a, scalar).unwrap())
                    .unwrap(),
                value * scalar % t
            );
        }
    }
    let a = eval.encrypt(6).unwrap();
    let b = eval.encrypt(7).unwrap();
    assert_eq!(client.decrypt(&eval.add(&a, &b).unwrap()).unwrap(), 13);
    assert_eq!(client.decrypt(&eval.sub(&a, &b).unwrap()).unwrap(), t - 1);
    assert_eq!(client.decrypt(&eval.multiply(&a, &b).unwrap()).unwrap(), 42);
    assert!(matches!(
        eval.encrypt(t),
        Err(CramMainError::PlaintextRange)
    ));
}

#[test]
fn certified_main_depth_refuses_before_wrong_plaintext_and_preserves_branches() {
    let (client, eval) = pair(&toy());
    let original = eval.encrypt(3).unwrap();
    let original_bound = original.noise_bound().clone();
    let mut a = original.clone();
    let mut expected = 3;
    let mut count = 0;
    loop {
        match eval.multiply(&a, &a) {
            Ok(next) => {
                expected = expected * expected % eval.config().t;
                assert_eq!(
                    client.decrypt(&next).unwrap(),
                    expected,
                    "depth {}",
                    count + 1
                );
                a = next;
                count += 1;
                assert!(count < 16, "must eventually refuse");
            }
            Err(CramMainError::NoiseExhausted(_)) => break,
            Err(error) => panic!("unexpected refusal: {error}"),
        }
    }
    assert!(count >= 2);
    assert_eq!(original.noise_bound(), &original_bound);
    assert_eq!(client.decrypt(&original).unwrap(), 3);
    let joined = eval.add(&original, &a).unwrap();
    assert_eq!(
        client.decrypt(&joined).unwrap(),
        (3 + expected) % eval.config().t
    );
}

#[test]
fn certified_main_rejects_foreign_key_and_context() {
    let (client, eval) = pair(&toy());
    let (_, other) = pair(&toy());
    let a = eval.encrypt(2).unwrap();
    let b = other.encrypt(3).unwrap();
    assert!(matches!(
        eval.add(&a, &b),
        Err(CramMainError::DomainMismatch)
    ));
    assert!(matches!(
        eval.multiply(&a, &b),
        Err(CramMainError::DomainMismatch)
    ));
    assert!(matches!(
        client.decrypt(&b),
        Err(CramMainError::DomainMismatch)
    ));
    let mut reversed = toy();
    reversed.primes.reverse();
    reversed.q = reversed.primes[0];
    let (_, other) = pair(&reversed);
    assert!(matches!(
        eval.add(&a, &other.encrypt(1).unwrap()),
        Err(CramMainError::DomainMismatch)
    ));
}

#[test]
fn certified_main_wire_rejects_tampering_and_never_resets_bound() {
    let (client, eval) = pair(&toy());
    let mut transport = eval.transport(2);
    let a = eval.encrypt(7).unwrap();
    let deep = eval.multiply(&a, &a).unwrap();
    let bytes = transport.export(&deep).unwrap();
    assert_eq!(
        bytes.len(),
        84 + 2 * eval.config().n * eval.config().primes.len() * 8
    );
    let restored = transport.import(&bytes).unwrap();
    assert_eq!(restored.noise_bound(), deep.noise_bound());
    assert_eq!(client.decrypt(&restored).unwrap(), 49);
    for index in 0..bytes.len() {
        let mut altered = bytes.clone();
        altered[index] ^= 1;
        assert!(transport.import(&altered).is_err(), "changed byte {index}");
    }
    assert!(transport.import(&bytes[..bytes.len() - 1]).is_err());
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(transport.import(&trailing).is_err());
    assert!(transport.import(b"legacy dual RNS").is_err());
    assert!(
        eval.transport(2).import(&bytes).is_err(),
        "no history in fresh registry"
    );
    let (_, other) = pair(&toy());
    assert!(other.transport(2).import(&bytes).is_err());
    transport.export(&a).unwrap();
    assert!(matches!(
        transport.export(&eval.encrypt(1).unwrap()),
        Err(wire_q::WireQError::Capacity)
    ));
    assert_eq!(transport.export(&deep).unwrap(), bytes);
}

#[test]
fn certified_main_production_128_roundtrip_and_early_refusal() {
    let config = SecureConfig::secure_128().into_config();
    let (client, eval) = pair(&config);
    let a = eval.encrypt(config.t - 1).unwrap();
    let b = eval.encrypt(7).unwrap();
    let product = eval.multiply(&a, &b).unwrap();
    assert_eq!(client.decrypt(&product).unwrap(), config.t - 7);
    let square = eval.multiply(&product, &product).unwrap();
    assert_eq!(client.decrypt(&square).unwrap(), 49);
    assert!(matches!(
        eval.multiply(&square, &square),
        Err(CramMainError::NoiseExhausted(_))
    ));
}

#[test]
fn certified_main_refresh_radius_tracks_live_history_and_transport() {
    let (client, eval) = pair(&toy());
    let fresh = eval.encrypt(7).unwrap();
    let original = fresh.prime_square_residual_radius();
    assert_eq!(original, 4, "N=8 rounding dominates a fresh input");
    let mut current = fresh.clone();
    let mut increased = false;
    for _ in 0..16 {
        let next = match eval.multiply(&current, &current) {
            Ok(next) => next,
            Err(CramMainError::NoiseExhausted(_)) => break,
            Err(error) => panic!("unexpected refusal: {error}"),
        };
        assert!(next.prime_square_residual_radius() >= current.prime_square_residual_radius());
        increased |= next.prime_square_residual_radius() > original;
        current = next;
    }
    // At this tiny ring, squaring can hit the operation gate before the
    // integral radius crosses its next boundary. Additions grow the history
    // bound more gradually and must expose that boundary while still admitted.
    for _ in 0..256 {
        if increased {
            break;
        }
        let next = eval.add(&current, &current).expect("radius boundary precedes decoding exhaustion");
        assert!(next.prime_square_residual_radius() >= current.prime_square_residual_radius());
        increased = next.prime_square_residual_radius() > original;
        current = next;
    }
    assert!(increased, "radius must reflect accumulated error");
    assert_eq!(fresh.prime_square_residual_radius(), original);
    let mut transport = eval.transport(1);
    let wire = transport.export(&current).unwrap();
    let restored = transport.import(&wire).unwrap();
    assert_eq!(
        restored.prime_square_residual_radius(),
        current.prime_square_residual_radius()
    );
    assert_eq!(
        client.decrypt(&restored).unwrap(),
        client.decrypt(&current).unwrap()
    );
}
