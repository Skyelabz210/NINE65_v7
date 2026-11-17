use certified_lift::*;
use num_bigint::BigUint;
use num_traits::Zero;
use std::cmp::Ordering;

// ---------- ORACLE (tests only): the single place X is ever assembled ----------
fn inv(a: u64, p: u64) -> u64 { let (mut t, mut nt) = (0i128, 1i128); let (mut r, mut nr) = (p as i128, (a % p) as i128);
    while nr != 0 { let q = r / nr; let x = t - q * nt; t = nt; nt = x; let y = r - q * nr; r = nr; nr = y; }
    (((t % p as i128) + p as i128) % p as i128) as u64 }
fn oracle(lanes: &[u64], window: &BigUint, v: &[u64]) -> BigUint {
    let mut x = BigUint::zero();
    for (i, &p) in lanes.iter().enumerate() {
        let wi = window / p; let y = inv(*(&wi % p).to_u64_digits().first().unwrap_or(&0), p);
        x += BigUint::from(v[i]) * wi * y;
    }
    x % window
}
struct Rng(u64);
impl Rng { fn next(&mut self) -> u64 { let mut x = self.0; x ^= x >> 12; x ^= x << 25; x ^= x >> 27; self.0 = x; x.wrapping_mul(0x2545F4914F6CDD1D) }
           fn below(&mut self, n: u64) -> u64 { self.next() % n } }

#[test]
fn window_1332_adjacency_is_exact_and_refuses_at_the_wall() {
    let k = Kernel::new(36, &[37]).unwrap();
    assert_eq!(k.window(), &BigUint::from(1332u32));
    for x in 0..1332u64 {
        let l = k.lift(x).unwrap();
        // derived K equals floor(X/36) exactly, and equals the single subtraction r36 - r37 mod 37
        assert_eq!(k.derive_k(&l), BigUint::from(x / 36));
        assert_eq!((l.lanes()[0] + 37 - l.lanes()[1]) % 37, (x / 36) % 37);
    }
    assert!(matches!(k.lift(1332), Err(LiftError::Capacity { .. })));
    let a = k.lift(1331).unwrap(); let one = k.lift(1).unwrap();
    assert!(matches!(k.add(&a, &one), Err(LiftError::Capacity { .. })));
    let f = k.lift(36).unwrap(); assert!(k.mul(&f, &f).is_ok());              // 1296 < 1332
    let g = k.lift(40).unwrap(); assert!(matches!(k.mul(&g, &g), Err(LiftError::Capacity { .. }))); // 1600
    assert_eq!(k.counters().1, 0); // single anchor: no combine, ever
}

#[test]
fn order_is_total_and_matches_integers() {
    let k = Kernel::new(36, &[37]).unwrap();
    for x in (0..1332u64).step_by(7) { for y in (0..1332u64).step_by(11) {
        assert_eq!(k.cmp(&k.lift(x).unwrap(), &k.lift(y).unwrap()), x.cmp(&y));
    } }
}

#[test]
fn sub_underflow_and_exact_division_rules() {
    let k = Kernel::new(2147483647, &[2147483629]).unwrap();
    let (a, b) = (k.lift(10).unwrap(), k.lift(20).unwrap());
    assert_eq!(k.sub(&a, &b).unwrap_err(), LiftError::Underflow);
    let d = k.sub(&b, &a).unwrap(); assert_eq!(oracle(k.lanes(), k.window(), d.lanes()), BigUint::from(10u32));
    let m = k.mul_const(&b, 7).unwrap();                       // 140, certified divisible by 7
    let q = k.div_exact(&m, 7).unwrap(); assert_eq!(oracle(k.lanes(), k.window(), q.lanes()), BigUint::from(20u32));
    assert_eq!(k.div_exact(&b, 7).unwrap_err(), LiftError::UnknownDivisor(7));
    assert_eq!(k.div_exact(&m, 2147483647).unwrap_err(), LiftError::NotCoprime(2147483647));
}

#[test]
fn random_program_with_growth_matches_bigints() {
    const DIVS: [u64; 8] = [3, 5, 7, 11, 13, 17, 19, 23];
    for seed in [1u64, 7, 99, 0xDEADBEEF, 0x9E3779B97F4A7C15] {
        let mut m = Machine::new(2147483647, &[2147483629], 8, 40).unwrap();
        m.reserve_divisors(&DIVS).unwrap();
        let mut rng = Rng(seed);
        let mut sh: Vec<BigUint> = Vec::new();
        for i in 0..8 { let x = 1 + rng.below(1 << 20); m.load(i, x).unwrap(); sh.push(BigUint::from(x)); }
        let (mut refusals, mut compares) = (0u64, 0u64);
        for _ in 0..4000 {
            let (a, b, d) = (rng.below(8) as usize, rng.below(8) as usize, rng.below(8) as usize);
            let op = rng.below(100);
            let r = if op < 25 { let t = &sh[a] + &sh[b]; m.add(d, a, b).map(|_| t) }
                else if op < 50 { let t = &sh[a] * &sh[b]; m.mul(d, a, b).map(|_| t) }
                else if op < 62 { let t = if sh[a] >= sh[b] { &sh[a] - &sh[b] } else { BigUint::zero() };
                    match m.sub(d, a, b) { Ok(()) => Ok(t), Err(LiftError::Underflow) => { assert!(sh[a] < sh[b]); continue } Err(e) => Err(e) } }
                else if op < 80 { compares += 1; assert_eq!(m.cmp(a, b), sh[a].cmp(&sh[b])); continue }
                else if op < 90 { let c = DIVS[rng.below(8) as usize]; let t = &sh[a] * c; m.mul_const(d, a, c).map(|_| t) }
                else { let c = DIVS[rng.below(8) as usize];
                    match m.div_exact(d, a, c) { Ok(()) => { assert!(&sh[a] % c == BigUint::zero()); Ok(&sh[a] / c) }
                        Err(LiftError::UnknownDivisor(_)) => continue, Err(e) => Err(e) } };
            match r {
                Ok(t) => sh[d] = t,
                Err(LiftError::Capacity { .. }) => { refusals += 1; let x = 1 + rng.below(1 << 20); m.load(d, x).unwrap(); sh[d] = BigUint::from(x); }
                Err(e) => panic!("unexpected {e:?}"),
            }
        }
        for i in 0..8 { assert_eq!(oracle(m.kernel().lanes(), m.kernel().window(), m.reg(i).lanes()), sh[i], "seed {seed} reg {i}"); }
        assert!(m.growths() > 0 && compares > 0, "seed {seed}: growths={} refusals={refusals}", m.growths());
    }
}

#[test]
fn comparing_never_needs_x_and_ordering_survives_growth() {
    let mut m = Machine::new(2147483647, &[2147483629], 3, 10).unwrap();
    m.load(0, 2000000000).unwrap(); m.load(1, 1999999999).unwrap();
    m.mul(2, 0, 0).unwrap(); // forces growth beyond the 62-bit window
    m.mul(2, 2, 2).unwrap(); m.mul(1, 1, 1).unwrap(); m.mul(1, 1, 1).unwrap();
    assert!(m.growths() >= 1);
    assert_eq!(m.cmp(2, 1), Ordering::Greater);
}
