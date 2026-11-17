use certified_lift::*;
use num_bigint::{BigInt, BigUint};
use num_traits::Zero;
use std::cmp::Ordering;

// ---------- ORACLE (tests only) ----------
fn inv(a: u64, p: u64) -> u64 { let (mut t, mut nt) = (0i128, 1i128); let (mut r, mut nr) = (p as i128, (a % p) as i128);
    while nr != 0 { let q = r / nr; let x = t - q * nt; t = nt; nt = x; let y = r - q * nr; r = nr; nr = y; }
    (((t % p as i128) + p as i128) % p as i128) as u64 }
fn oracle(lanes: &[u64], window: &BigUint, v: &[u64]) -> BigUint {
    let mut x = BigUint::zero();
    for (i, &p) in lanes.iter().enumerate() { let wi = window / p; let y = inv(*(&wi % p).to_u64_digits().first().unwrap_or(&0), p); x += BigUint::from(v[i]) * wi * y; }
    x % window
}
fn oracle_signed(lanes: &[u64], window: &BigUint, v: &[u64]) -> BigInt {
    let x = oracle(lanes, window, v);
    if &x * 2u32 > *window { BigInt::from(x) - BigInt::from(window.clone()) } else { BigInt::from(x) }
}
struct Rng(u64);
impl Rng { fn next(&mut self) -> u64 { let mut x = self.0; x ^= x >> 12; x ^= x << 25; x ^= x >> 27; self.0 = x; x.wrapping_mul(0x2545F4914F6CDD1D) }
           fn below(&mut self, n: u64) -> u64 { self.next() % n } }

#[test]
fn signed_exhaustive_on_the_1332_window() {
    let k = Kernel::new(36, &[37]).unwrap();
    // signed capacity is 2U < 1332, so |S| <= 665
    assert!(k.lift_signed(665).is_ok() && k.lift_signed(-665).is_ok());
    assert!(matches!(k.lift_signed(666), Err(LiftError::Capacity { .. })));
    assert!(matches!(k.lift_signed(-666), Err(LiftError::Capacity { .. })));
    for s in -665i64..=665 {
        let a = k.lift_signed(s).unwrap();
        assert_eq!(k.sign(&a), s.cmp(&0), "sign of {s}");
        assert_eq!(oracle_signed(k.lanes(), k.window(), k.sneg(&a).lanes()), BigInt::from(-s));
    }
    for s in (-665i64..=665).step_by(13) { for t in (-665i64..=665).step_by(17) {
        let (a, b) = (k.lift_signed(s).unwrap(), k.lift_signed(t).unwrap());
        assert_eq!(k.scmp(&a, &b), s.cmp(&t), "cmp {s} {t}");
    } }
    assert_eq!(k.counters().1, 0); // one anchor: no combine on any sign or order reading
}

#[test]
fn signed_arithmetic_crosses_zero_exactly() {
    let k = Kernel::new(2147483647, &[2147483629]).unwrap();
    let (a, b) = (k.lift_signed(1000).unwrap(), k.lift_signed(-2500).unwrap());
    let d = k.sadd(&a, &b).unwrap();
    assert_eq!(oracle_signed(k.lanes(), k.window(), d.lanes()), BigInt::from(-1500));
    assert_eq!(k.sign(&d), Ordering::Less);
    let p = k.smul(&d, &d).unwrap(); // (-1500)^2
    assert_eq!(k.sign(&p), Ordering::Greater);
    let z = k.ssub(&a, &a).unwrap();
    assert_eq!(k.sign(&z), Ordering::Equal); // zero with a nonzero certified bound still reads as zero
    let m = k.smul_const(&b, 7).unwrap(); let q = k.sdiv_exact(&m, 7).unwrap();
    assert_eq!(oracle_signed(k.lanes(), k.window(), q.lanes()), BigInt::from(-2500));
}

#[test]
fn tighten_never_loosens_and_always_contains_the_value() {
    let k = Kernel::new(2147483647, &[2147483629, 2147483587]).unwrap();
    let mut rng = Rng(42);
    for _ in 0..2000 {
        let (x, y) = (1 + rng.below(1 << 30), 1 + rng.below(1 << 30));
        let (a, b) = (k.lift(x).unwrap(), k.lift(y).unwrap());
        let prod = k.mul(&a, &b).unwrap();                       // true value x*y, bound x*y
        let loose = k.mul_const(&prod, 23).unwrap();             // bound loosened by 23x
        let back = k.div_exact(&loose, 23).unwrap();             // true value x*y again, bound floor(23xy/23)
        let t = k.tighten(&loose);
        let truth = BigUint::from(x) * BigUint::from(y) * 23u32;
        assert!(t.bound() >= &truth && t.bound() <= loose.bound());          // sound and monotone
        assert!(t.bound() - &truth < BigUint::from(2147483647u64));          // within one shell of the truth
        let _ = back;
    }
    // a value that is exactly zero but carries a huge certified bound re-certifies to < shell
    let a = k.lift(1u64 << 30).unwrap(); let sq = k.mul(&a, &a).unwrap();
    let z = k.sub(&sq, &sq).unwrap();
    assert!(z.bound() > &BigUint::from(1u64 << 59));
    assert!(k.tighten(&z).bound() < &BigUint::from(2147483647u64));
}

#[test]
fn signed_random_program_with_growth_matches_bigints() {
    const DIVS: [u64; 8] = [3, 5, 7, 11, 13, 17, 19, 23];
    for seed in [3u64, 11, 123, 0xC0FFEE, 0x9E3779B97F4A7C15] {
        let mut m = SMachine::new(2147483647, &[2147483629], 8, 40).unwrap();
        m.reserve_divisors(&DIVS).unwrap();
        let mut rng = Rng(seed);
        let mut sh: Vec<BigInt> = Vec::new();
        let small = |rng: &mut Rng| { let x = rng.below(1 << 20) as i64; if rng.below(2) == 0 { x } else { -x } };
        for i in 0..8 { let x = small(&mut rng); m.load(i, x).unwrap(); sh.push(BigInt::from(x)); }
        let (mut signs, mut crossings) = (0u64, 0u64);
        for _ in 0..4000 {
            let (a, b, d) = (rng.below(8) as usize, rng.below(8) as usize, rng.below(8) as usize);
            let op = rng.below(100);
            let r: Result<BigInt, LiftError> =
                if op < 20 { let t = &sh[a] + &sh[b]; m.add(d, a, b).map(|_| t) }
                else if op < 36 { let t = &sh[a] - &sh[b]; m.sub(d, a, b).map(|_| t) }
                else if op < 54 { let t = &sh[a] * &sh[b]; m.mul(d, a, b).map(|_| t) }
                else if op < 60 { let t = -&sh[a]; m.neg(d, a); Ok(t) }
                else if op < 76 {
                    signs += 1; assert_eq!(m.sign(a), sh[a].cmp(&BigInt::zero()));
                    assert_eq!(m.cmp(a, b), sh[a].cmp(&sh[b])); continue }
                else if op < 88 { let c = DIVS[rng.below(8) as usize]; let t = &sh[a] * c; m.mul_const(d, a, c).map(|_| t) }
                else { let c = DIVS[rng.below(8) as usize];
                    match m.div_exact(d, a, c) { Ok(()) => { assert!((&sh[a] % c).is_zero()); Ok(&sh[a] / c) }
                        Err(LiftError::UnknownDivisor(_)) => continue, Err(e) => Err(e) } };
            match r {
                Ok(t) => { if (sh[d].sign() != t.sign()) && !t.is_zero() && !sh[d].is_zero() { crossings += 1; } sh[d] = t }
                Err(LiftError::Capacity { .. }) => { let x = small(&mut rng); m.load(d, x).unwrap(); sh[d] = BigInt::from(x); }
                Err(e) => panic!("unexpected {e:?}"),
            }
        }
        for i in 0..8 { assert_eq!(oracle_signed(m.kernel().lanes(), m.kernel().window(), m.reg(i).lanes()), sh[i], "seed {seed} reg {i}"); }
        assert!(m.growths() > 0 && signs > 0 && crossings > 0, "seed {seed}: growths={} signs={signs} crossings={crossings}", m.growths());
    }
}

fn unsigned_run(seed: u64, tighten: bool) -> (u64, u64, u64) {
    const DIVS: [u64; 8] = [3, 5, 7, 11, 13, 17, 19, 23];
    let mut m = Machine::new(2147483647, &[2147483629], 8, 64).unwrap();
        m.reserve_divisors(&DIVS).unwrap();
    m.set_tighten(tighten);
    let mut rng = Rng(seed);
    let mut sh: Vec<BigUint> = Vec::new();
    for i in 0..8 { let x = 1 + rng.below(1 << 20); m.load(i, x).unwrap(); sh.push(BigUint::from(x)); }
    let mut refusals = 0u64;
    for _ in 0..4000 {
        let (a, b, d) = (rng.below(8) as usize, rng.below(8) as usize, rng.below(8) as usize);
        let op = rng.below(100);
        let r = if op < 25 { let t = &sh[a] + &sh[b]; m.add(d, a, b).map(|_| t) }
            else if op < 50 { let t = &sh[a] * &sh[b]; m.mul(d, a, b).map(|_| t) }
            else if op < 62 { let t = if sh[a] >= sh[b] { &sh[a] - &sh[b] } else { BigUint::zero() };
                match m.sub(d, a, b) { Ok(()) => Ok(t), Err(LiftError::Underflow) => continue, Err(e) => Err(e) } }
            else if op < 80 { assert_eq!(m.cmp(a, b), sh[a].cmp(&sh[b])); continue }
            else if op < 90 { let c = DIVS[rng.below(8) as usize]; let t = &sh[a] * c; m.mul_const(d, a, c).map(|_| t) }
            else { let c = DIVS[rng.below(8) as usize];
                match m.div_exact(d, a, c) { Ok(()) => Ok(&sh[a] / c), Err(LiftError::UnknownDivisor(_)) => continue, Err(e) => Err(e) } };
        match r { Ok(t) => sh[d] = t,
            Err(LiftError::Capacity { .. }) => { refusals += 1; let x = 1 + rng.below(1 << 20); m.load(d, x).unwrap(); sh[d] = BigUint::from(x); }
            Err(e) => panic!("{e:?}") }
    }
    for i in 0..8 { assert_eq!(oracle(m.kernel().lanes(), m.kernel().window(), m.reg(i).lanes()), sh[i]); }
    (m.growths(), m.tightens(), refusals)
}

#[test]
fn tightening_reduces_growth_and_stays_exact() {
    let (mut g_off, mut g_on, mut r_off, mut r_on, mut t_on) = (0, 0, 0, 0, 0);
    for seed in [5u64, 17, 29, 101, 0xFACADE] {
        let (g0, _, r0) = unsigned_run(seed, false); let (g1, t1, r1) = unsigned_run(seed, true);
        g_off += g0; g_on += g1; r_off += r0; r_on += r1; t_on += t1;
    }
    println!("growths: pessimistic bound={g_off} tightened={g_on} | refusals: {r_off} vs {r_on} | tightenings={t_on}");
    assert!(g_on < g_off, "tightening should reduce basis growth ({g_on} vs {g_off})");
}
