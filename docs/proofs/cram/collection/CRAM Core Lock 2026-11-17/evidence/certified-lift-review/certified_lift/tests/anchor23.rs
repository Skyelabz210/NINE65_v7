// 23 as an anchor over the composite shell M = 2*3*5*7*13*37*73 (coprimality only; no lane is required prime).
use certified_lift::*;
use num_bigint::BigUint;
#[test]
fn anchor_23_reads_k_over_the_s0_shell() {
    let m: u64 = 2 * 3 * 5 * 7 * 13 * 37 * 73;
    assert_eq!(m, 7_373_730);
    assert!([2u64, 3, 5, 7, 13, 37, 73].iter().all(|p| 23 % p != 0));            // gcd(23, M) = 1
    let k = Kernel::new(m, &[23]).unwrap();
    assert_eq!(k.window(), &BigUint::from(m * 23));
    // every multiple of the 11960-day eclipse table inside the window, plus exhaustive sample of the window
    let mut hits = 0u64;
    let mut x = 0u64;
    while x < m * 23 { let l = k.lift(x).unwrap(); assert_eq!(k.derive_k(&l), BigUint::from(x / m)); x += 11960; hits += 1; }
    for x in (0..m * 23).step_by(1009) { let l = k.lift(x).unwrap(); assert_eq!(k.derive_k(&l), BigUint::from(x / m)); }
    assert!(hits > 10000);
    // 11960 = 2^3 * 5 * 13 * 23 : the anchor lane reads 0 exactly on multiples of 23
    assert_eq!(k.lift(11960).unwrap().lanes()[1], 0);
    // with a composite shell, 23 is also usable as an exact divisor only if it stays coprime to every lane
    let a = k.lift(11960 / 23).unwrap();
    assert_eq!(k.div_exact(&k.mul_const(&a, 11).unwrap(), 11).unwrap().lanes(), a.lanes());
}

#[test]
fn dividing_by_a_shell_factor_is_refused_not_wrong() {
    let k = Kernel::new(2 * 3 * 5 * 7 * 13 * 37 * 73, &[23]).unwrap();
    let a = k.lift(100).unwrap();
    assert_eq!(k.div_exact(&a, 5).unwrap_err(), LiftError::NotCoprime(5));
    assert_eq!(k.div_exact(&a, 23).unwrap_err(), LiftError::NotCoprime(23));
}
