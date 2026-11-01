//! The compatibility projection must not influence modulus routing.
use nine65::ops::rns_fhe::{MulRoute, RNSFHEContext};
use nine65::params::secure_configs::SecureConfig;

#[test]
fn routing_uses_checked_product_when_legacy_projection_is_poisoned() {
    for config in [SecureConfig::secure_128(), SecureConfig::secure_192()] {
        let mut ctx = RNSFHEContext::new(&config.into_config());
        // Force distinguishable routes for the two sizes without changing Q.
        ctx.t = u64::MAX;
        let expected = if ctx.q_product_checked.is_some() {
            MulRoute::BajardSingle
        } else {
            MulRoute::KElimDual
        };
        assert_eq!(ctx.mul_route(), expected);
        ctx.q_product = if ctx.q_product_checked.is_some() {
            0
        } else {
            1
        };
        assert_eq!(ctx.mul_route(), expected);
    }
}
