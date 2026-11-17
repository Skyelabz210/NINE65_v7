// Coprimality, not primality: the addressing layer on composite lanes (cf. Coprimality-Primality Separation, Thm 1).
use certified_lift::*;
use num_bigint::BigUint;
use std::cmp::Ordering;

#[test]
fn composite_adjacent_pairs_recover_k_exhaustively() {
    // pairs from the paper's table, plus more: every state, every pair composite/composite
    for &(m, a) in &[(8u64, 9u64), (35, 36), (25, 49), (99, 100), (15, 16), (14, 15), (48, 49), (120, 121), (4, 9), (6, 25)] {
        let k = Kernel::new(m, &[a]).unwrap();
        let w = (m * a) as u64;
        for x in 0..w {
            let l = k.lift(x).unwrap();
            assert_eq!(k.derive_k(&l), BigUint::from(x / m), "({m},{a}) x={x}");
        }
        assert!(matches!(k.lift(w), Err(LiftError::Capacity { .. })));
    }
}

#[test]
fn composite_basis_order_sign_and_division() {
    // shell 36 (composite), anchors 25 and 49 (composite), 11 and 13 (prime): pairwise coprime
    let k = Kernel::new(36, &[25, 49, 11, 13]).unwrap();
    let w: u64 = 36 * 25 * 49 * 11 * 13;
    assert_eq!(k.window(), &BigUint::from(w));
    for x in (0..w / 2).step_by(997) { for y in (0..w / 2).step_by(1009) {
        assert_eq!(k.cmp(&k.lift(x).unwrap(), &k.lift(y).unwrap()), x.cmp(&y));
    } }
    for s in (-(w as i64) / 4..=(w as i64) / 4).step_by(1013) {
        let a = k.lift_signed(s).unwrap();
        assert_eq!(k.sign(&a), s.cmp(&0));
    }
    let a = k.lift(7).unwrap(); let m = k.mul_const(&a, 17).unwrap();       // 17 coprime to every lane
    assert_eq!(k.cmp(&k.div_exact(&m, 17).unwrap(), &a), Ordering::Equal);
    assert_eq!(k.div_exact(&a, 5).unwrap_err(), LiftError::NotCoprime(5)); // 5 shares a factor with lane 25
}

#[test]
fn growth_picks_coprime_composites_not_primes() {
    let mut m = Machine::new(36, &[37], 3, 12).unwrap();
    m.load(0, 30).unwrap(); m.load(1, 29).unwrap();
    for _ in 0..4 { m.mul(2, 0, 1).unwrap_or(()); m.grow().unwrap(); }
    let lanes = m.kernel().lanes().to_vec();
    for i in 0..lanes.len() { for j in 0..i {
        let (mut a, mut b) = (lanes[i], lanes[j]); while b != 0 { let t = a % b; a = b; b = t; }
        assert_eq!(a, 1, "lanes {} and {} not coprime", lanes[i], lanes[j]);
    } }
    assert!(lanes[1..].iter().any(|&p| (2..p).any(|d| d * d <= p && p % d == 0)), "expected at least one composite lane: {lanes:?}");
}
