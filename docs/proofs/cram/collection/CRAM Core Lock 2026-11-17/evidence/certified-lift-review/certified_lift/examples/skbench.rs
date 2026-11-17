// Redundant-modulus K route vs full big-integer combine, same K, certified values. Integer-only (ns via as_nanos).
use certified_lift::*;
use std::hint::black_box;
use std::time::Instant;
fn prime_below(mut n: u64) -> u64 { loop { n -= 1; let mut d = 2; let mut ok = n > 1; while d * d <= n { if n % d == 0 { ok = false; break; } d += 1; } if ok { return n; } } }
fn main() {
    println!("{:>5} {:>14} {:>14} {:>10}", "anch", "ns/combine", "ns/SK", "ratio_x100");
    for &s in &[2usize, 4, 8, 16, 32, 64, 128] {
        let mut anchors = vec![]; let mut p = 2147483629u64; for _ in 0..s { anchors.push(p); p = prime_below(p); }
        let k = Kernel::new(2147483647, &anchors).unwrap();
        // values whose certified K is below the regular-anchor product: products of a few 30-bit numbers per anchor budget
        let mut vals = vec![]; let mut x = 0x9E3779B97F4A7C15u64;
        for _ in 0..16 {
            let mut v = k.lift(1).unwrap();
            let target_bits = 31 * (s as u64 - 1) + 20;  // stay under shell * C'
            while v.bound().bits() + 31 < target_bits { x ^= x << 13; x ^= x >> 7; x ^= x << 17; v = k.mul(&v, &k.lift(1 + (x >> 34)).unwrap()).unwrap(); }
            vals.push(v);
        }
        for v in &vals { assert_eq!(k.derive_k_bounded(v), k.derive_k_combine(v)); }
        assert!(k.sk_reads() > 0, "SK route must be taken for these values");
        let reps = 20000usize / s.max(1) + 50; let mut sink = 0u64;
        let t = Instant::now(); for r in 0..reps { sink ^= k.derive_k_combine(black_box(&vals[r % 16])).to_u64_digits().first().copied().unwrap_or(0); }
        let nc = t.elapsed().as_nanos() / reps as u128;
        let t = Instant::now(); for r in 0..reps { sink ^= k.derive_k_bounded(black_box(&vals[r % 16])).to_u64_digits().first().copied().unwrap_or(0); }
        let ns = t.elapsed().as_nanos() / reps as u128;
        black_box(sink);
        println!("{:>5} {:>14} {:>14} {:>10}", s, nc, ns, 100 * nc / ns.max(1));
    }
}
