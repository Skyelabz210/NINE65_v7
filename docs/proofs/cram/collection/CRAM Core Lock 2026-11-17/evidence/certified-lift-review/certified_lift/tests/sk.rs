use certified_lift::*;
use num_bigint::BigUint;
struct Rng(u64);
impl Rng { fn next(&mut self) -> u64 { let mut x = self.0; x ^= x >> 12; x ^= x << 25; x ^= x >> 27; self.0 = x; x.wrapping_mul(0x2545F4914F6CDD1D) } }

fn prime_below(mut n: u64) -> u64 { loop { n -= 1; let mut d = 2; let mut ok = n > 1; while d * d <= n { if n % d == 0 { ok = false; break; } d += 1; } if ok { return n; } } }

#[test]
fn sk_route_equals_full_combine_whenever_certified() {
    // shell 2^31-1 plus 8 anchors; values built by the kernel itself with bounds that keep K < C'
    let mut anchors = vec![]; let mut p = 2147483629u64; for _ in 0..8 { anchors.push(p); p = prime_below(p); }
    let k = Kernel::new(2147483647, &anchors).unwrap();
    let mut rng = Rng(2026);
    let (mut sk_used, mut checked) = (0u64, 0u64);
    for _ in 0..3000 {
        let a = k.lift(1 + (rng.next() >> 33)).unwrap();
        let mut v = a.clone();
        for _ in 0..(rng.next() % 5) { let b = k.lift(1 + (rng.next() >> 33)).unwrap(); v = if rng.next() % 2 == 0 { k.mul(&v, &b).unwrap() } else { k.add(&v, &b).unwrap() }; }
        let before = k.sk_reads();
        let fast = k.derive_k_bounded(&v);
        if k.sk_reads() > before { sk_used += 1; }
        assert_eq!(fast, k.derive_k_combine(&v));
        checked += 1;
    }
    assert!(sk_used > 1000, "SK path should be used for most certified values ({sk_used}/{checked})");
}

#[test]
fn sk_refuses_to_run_when_the_certificate_does_not_cover_k() {
    let k = Kernel::new(36, &[37, 41, 43]).unwrap();           // regular anchors 37,41 (C'=1517), redundant 43
    for x in 0..(36u64 * 37 * 41 * 43).min(60000) {
        let l = k.lift(x).unwrap();
        let (before, kk) = (k.sk_reads(), k.derive_k_bounded(&l));
        assert_eq!(kk, BigUint::from(x / 36), "x={x}");
        let used = k.sk_reads() > before;
        assert_eq!(used, (x / 36) < 1517, "route choice at x={x}"); // lift() bound = x
    }
}
