use certified_lift::{Kernel, LiftError};
use num_bigint::BigUint;
#[test]
fn foreign_frame_is_accepted_and_breaks_certificate() {
    let first = Kernel::new(36, &[37]).unwrap();
    let second = Kernel::new(35, &[37]).unwrap();
    let foreign = first.lift(1000).unwrap();
    let accepted = second.add(&foreign, &second.lift(0).unwrap()).unwrap();
    assert_eq!(accepted.bound(), &BigUint::from(1000u32));
    assert_eq!(accepted.lanes(), &[28, 1]);
    let interpreted = second.derive_k(&accepted) * 35u32 + accepted.lanes()[0];
    assert_eq!(interpreted, BigUint::from(1148u32));
    assert!(interpreted > *accepted.bound());
}
#[test]
fn foreign_short_frame_can_panic() {
    let first = Kernel::new(36, &[37]).unwrap();
    let second = Kernel::new(36, &[37, 41]).unwrap();
    let foreign = first.lift(1).unwrap();
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| second.derive_k(&foreign)));
    assert!(outcome.is_err());
}
#[test]
fn bound_is_exact_scalar_payload_on_add_mul_chains() {
    let kernel = Kernel::new(36, &[37, 41]).unwrap();
    let a = kernel.lift(100).unwrap();
    let b = kernel.lift(200).unwrap();
    let product = kernel.mul(&a, &b).unwrap();
    assert_eq!(product.bound(), &BigUint::from(20000u32));
    let sum = kernel.add(&product, &a).unwrap();
    assert_eq!(sum.bound(), &BigUint::from(20100u32));
}
#[test]
fn exact_division_is_conservative_not_general() {
    let kernel = Kernel::new(36, &[37]).unwrap();
    let a = kernel.lift(140).unwrap();
    assert_eq!(kernel.div_exact(&a, 7).unwrap_err(), LiftError::UnknownDivisor(7));
    assert_eq!(kernel.div_exact(&a, 1).unwrap_err(), LiftError::UnknownDivisor(1));
    assert_eq!(kernel.div_exact(&a, 5).unwrap_err(), LiftError::UnknownDivisor(5));
    assert_eq!(kernel.div_exact(&a, 2).unwrap_err(), LiftError::NotCoprime(2));
}
