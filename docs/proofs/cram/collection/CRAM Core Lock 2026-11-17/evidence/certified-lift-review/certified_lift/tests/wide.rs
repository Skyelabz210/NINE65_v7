use certified_lift::*;
use num_bigint::BigUint;
use num_traits::Zero;
use std::cmp::Ordering;

const SHELL: u64 = 18446744073709551557; // 2^64 - 59
const ANCH: u64 = 18446744073709551533;  // 2^64 - 83
fn inv(a: u64, p: u64) -> u64 { let (mut t, mut nt) = (0i128, 1i128); let (mut r, mut nr) = (p as i128, (a % p) as i128);
    while nr != 0 { let q = r / nr; let x = t - q * nt; t = nt; nt = x; let y = r - q * nr; r = nr; nr = y; }
    (((t % p as i128) + p as i128) % p as i128) as u64 }
fn oracle(lanes: &[u64], window: &BigUint, v: &[u64]) -> BigUint {
    let mut x = BigUint::zero();
    for (i, &p) in lanes.iter().enumerate() { let wi = window / p; let y = inv(*(&wi % p).to_u64_digits().first().unwrap_or(&0), p); x += BigUint::from(v[i]) * wi * y; }
    x % window
}
struct Rng(u64);
impl Rng { fn next(&mut self) -> u64 { let mut x = self.0; x ^= x >> 12; x ^= x << 25; x ^= x >> 27; self.0 = x; x.wrapping_mul(0x2545F4914F6CDD1D) }
           fn below(&mut self, n: u64) -> u64 { self.next() % n } }

#[test]
fn wide_anchor_window_is_128_bits_and_needs_no_combine() {
    let k = Kernel::new(SHELL, &[ANCH]).unwrap();
    assert!(k.window().bits() >= 127);
    let mut rng = Rng(77);
    for _ in 0..3000 {
        let (x, y) = (rng.next() >> 1, rng.next() >> 1);             // 63-bit operands: product < 2^126 < window
        let (a, b) = (k.lift(x).unwrap(), k.lift(y).unwrap());
        let s = k.add(&a, &b).unwrap(); let p = k.mul(&a, &b).unwrap(); // up to 128 bits
        assert_eq!(oracle(k.lanes(), k.window(), s.lanes()), BigUint::from(x) + BigUint::from(y));
        assert_eq!(oracle(k.lanes(), k.window(), p.lanes()), BigUint::from(x) * BigUint::from(y));
        assert_eq!(k.cmp(&a, &b), x.cmp(&y));
        assert_eq!(k.cmp(&p, &s), (BigUint::from(x) * BigUint::from(y)).cmp(&(BigUint::from(x) + BigUint::from(y))));
        let (sa, sb) = (k.lift_signed((x >> 1) as i64).unwrap(), k.lift_signed(-((y >> 1) as i64)).unwrap());
        assert_eq!(k.scmp(&sa, &sb), ((x >> 1) as i64).cmp(&-((y >> 1) as i64)));
        assert_eq!(k.sign(&k.ssub(&sa, &sa).unwrap()), Ordering::Equal);
    }
    assert_eq!(k.counters().1, 0, "single wide anchor must never need the combine");
    // the wall: a 128-bit product that would not fit is refused, not aliased
    let big = k.lift(u64::MAX).unwrap();
    // (2^64-1)^2 = 2^128 - 2^65 + 1 exceeds shell*anchor = (2^64-59)(2^64-83): refusing it is correct
    assert!(matches!(k.mul(&big, &big), Err(LiftError::Capacity { .. })));
    let h = k.lift(u64::MAX >> 1).unwrap(); let sq = k.mul(&h, &h).unwrap();
    assert!(matches!(k.mul(&sq, &h), Err(LiftError::Capacity { .. })));
}

#[test]
fn wide_machine_grows_exactly_and_combines_only_after_growth() {
    let mut m = Machine::new(SHELL, &[ANCH], 4, 6).unwrap();
    let mut sh: Vec<BigUint> = Vec::new();
    for i in 0..4 { let x = u64::MAX - i as u64 * 1000; m.load(i, x).unwrap(); sh.push(BigUint::from(x)); }
    m.mul(0, 0, 1).unwrap(); sh[0] = &sh[0] * &sh[1];         // ~128 bits, fits
    assert_eq!(m.growths(), 0); assert_eq!(m.kernel().counters().1, 0);
    m.mul(2, 2, 3).unwrap(); sh[2] = &sh[2] * &sh[3];
    m.mul(0, 0, 2).unwrap(); sh[0] = &sh[0] * &sh[2];         // ~256 bits: forces growth
    assert!(m.growths() >= 1);
    for i in 0..4 { assert_eq!(oracle(m.kernel().lanes(), m.kernel().window(), m.reg(i).lanes()), sh[i], "reg {i}"); }
    assert_eq!(m.cmp(0, 2), sh[0].cmp(&sh[2]));
    assert!(m.kernel().counters().1 > 0); // the combine appears only once the basis has >1 anchor
}
