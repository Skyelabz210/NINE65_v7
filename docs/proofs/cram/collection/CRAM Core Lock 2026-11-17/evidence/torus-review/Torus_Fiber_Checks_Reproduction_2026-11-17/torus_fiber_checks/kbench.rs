// K-readout (redundant modulus) vs Garner over k ~62-bit RNS lanes. Integer-only. std only.
// Correctness: both methods are cross-checked against each other and against an independent check modulus q2.
use std::hint::black_box;
use std::time::Instant;

#[inline(always)] fn mulmod(a: u64, b: u64, m: u64) -> u64 { ((a as u128 * b as u128) % (m as u128)) as u64 }
fn powmod(mut b: u64, mut e: u64, m: u64) -> u64 { let mut r = 1u64; b %= m; while e > 0 { if e & 1 == 1 { r = mulmod(r, b, m); } b = mulmod(b, b, m); e >>= 1; } r }
fn inv(a: u64, p: u64) -> u64 { powmod(a % p, p - 2, p) }
fn is_prime(n: u64) -> bool {
    if n < 2 { return false; }
    for &p in &[2u64, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37] { if n % p == 0 { return n == p; } }
    let (mut d, mut s) = (n - 1, 0u32); while d % 2 == 0 { d /= 2; s += 1; }
    'w: for &a in &[2u64, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37] {
        let mut x = powmod(a, d, n); if x == 1 || x == n - 1 { continue; }
        for _ in 0..s - 1 { x = mulmod(x, x, n); if x == n - 1 { continue 'w; } }
        return false;
    }
    true
}
struct Rng(u64);
impl Rng { fn next(&mut self) -> u64 { let mut x = self.0; x ^= x >> 12; x ^= x << 25; x ^= x >> 27; self.0 = x; x.wrapping_mul(0x2545F4914F6CDD1D) } }

fn mul_small_add(v: &mut Vec<u64>, m: u64, a: u64) { // v = v*m + a
    let mut carry = a as u128;
    for l in v.iter_mut() { let t = (*l as u128) * (m as u128) + carry; *l = t as u64; carry = t >> 64; }
    if carry > 0 { v.push(carry as u64); }
}
fn garner_digits(x: &[u64], p: &[u64], c: &Vec<Vec<u64>>, v: &mut [u64]) -> u64 { // returns mulmod count; c[i][j]=p_i^{-1} mod p_j
    let k = p.len(); let mut cnt = 0u64;
    v.copy_from_slice(x);
    for j in 1..k { for i in 0..j {
        let t = (v[j] + p[j] - (v[i] % p[j])) % p[j];
        v[j] = mulmod(t, c[i][j], p[j]); cnt += 1;
    } }
    cnt
}
fn sk_alpha(x: &[u64], xr: u64, p: &[u64], minv: &[u64], mi_r: &[u64], minv_r: u64, mr: u64, xi: &mut [u64]) -> (u64, u64) {
    let k = p.len(); let mut acc = 0u64; let mut cnt = 0u64;
    for i in 0..k { xi[i] = mulmod(x[i], minv[i], p[i]); acc = (acc + mulmod(xi[i] % mr, mi_r[i], mr)) % mr; cnt += 2; }
    let a = mulmod((acc + mr - xr) % mr, minv_r, mr); cnt += 1;
    (a, cnt)
}
fn mod_from_digits(v: &[u64], p: &[u64], m: u64) -> u64 {
    let k = p.len(); let mut acc = v[k - 1] % m;
    for i in (0..k - 1).rev() { acc = (mulmod(acc, p[i] % m, m) + v[i] % m) % m; }
    acc
}
fn main() {
    // primes just below 2^62
    let mut primes: Vec<u64> = Vec::new(); let mut c = (1u64 << 62) - 1;
    while primes.len() < 132 { if is_prime(c) { primes.push(c); } c -= 2; }
    let mut rng = Rng(0x9E3779B97F4A7C15);
    println!("{:>4} {:>9} {:>9} | {:>12} {:>12} {:>9} | {:>14} {:>14} {:>9} | ok", "k", "garner_mm", "sk_mm", "ns/garnerMRC", "ns/skAlpha", "ratio_x100", "ns/full(garn)", "ns/full(sk)", "ratio_x100");
    for &k in &[2usize, 4, 8, 16, 32, 64, 128] {
        let p = &primes[..k]; let mr = primes[k]; let q2 = primes[k + 1];
        // tables (setup, not timed)
        let mut ctab = vec![vec![0u64; k]; k];
        for j in 0..k { for i in 0..j { ctab[i][j] = inv(p[i] % p[j], p[j]); } }
        let mut minv = vec![0u64; k]; let mut mi_r = vec![0u64; k]; let mut mi_q = vec![0u64; k];
        for i in 0..k {
            let (mut a, mut b, mut cq) = (1u64, 1u64, 1u64);
            for l in 0..k { if l != i { a = mulmod(a, p[l] % p[i], p[i]); b = mulmod(b, p[l] % mr, mr); cq = mulmod(cq, p[l] % q2, q2); } }
            minv[i] = inv(a, p[i]); mi_r[i] = b; mi_q[i] = cq;
        }
        let (mut mm_r, mut mm_q) = (1u64, 1u64); for l in 0..k { mm_r = mulmod(mm_r, p[l] % mr, mr); mm_q = mulmod(mm_q, p[l] % q2, q2); }
        let (minv_r, minv_q) = (inv(mm_r, mr), inv(mm_q, q2));
        // big-integer limbs for full assembly
        let mut m_limbs: Vec<u64> = vec![1]; for l in 0..k { mul_small_add(&mut m_limbs, p[l], 0); }
        let mut mi_limbs: Vec<Vec<u64>> = Vec::new();
        for i in 0..k { let mut v: Vec<u64> = vec![1]; for l in 0..k { if l != i { mul_small_add(&mut v, p[l], 0); } } mi_limbs.push(v); }
        // test vectors with independently derived redundant residues
        const NV: usize = 16; let mut xs: Vec<Vec<u64>> = Vec::new(); let mut xrs: Vec<u64> = Vec::new(); let mut ok = true;
        let mut v = vec![0u64; k]; let mut xi = vec![0u64; k];
        let (mut gmm, mut smm) = (0u64, 0u64);
        for _ in 0..NV {
            let x: Vec<u64> = (0..k).map(|i| rng.next() % p[i]).collect();
            gmm = garner_digits(&x, p, &ctab, &mut v);
            let xr = mod_from_digits(&v, p, mr); let xq = mod_from_digits(&v, p, q2);
            let (a, sc) = sk_alpha(&x, xr, p, &minv, &mi_r, minv_r, mr, &mut xi); smm = sc;
            // independent check of alpha via modulus q2: alpha = (sum xi*Mi - X) * M^-1 mod q2, alpha < k < q2 so equality is exact
            let mut s = 0u64; for i in 0..k { s = (s + mulmod(xi[i] % q2, mi_q[i], q2)) % q2; }
            let a_q = mulmod((s + q2 - xq) % q2, minv_q, q2);
            if a != a_q || (a as usize) >= k { ok = false; }
            // full assembly: Garner Horner vs SK sum-minus-alpha*M
            let mut xg: Vec<u64> = vec![v[k - 1]]; for i in (0..k - 1).rev() { mul_small_add(&mut xg, p[i], v[i]); }
            let mut acc = vec![0u64; k + 3];
            for i in 0..k { let mut carry = 0u128; for (l, &ml) in mi_limbs[i].iter().enumerate() { let t = (xi[i] as u128) * (ml as u128) + acc[l] as u128 + carry; acc[l] = t as u64; carry = t >> 64; }
                let mut l = mi_limbs[i].len(); while carry > 0 { let t = acc[l] as u128 + carry; acc[l] = t as u64; carry = t >> 64; l += 1; } }
            let mut borrow = 0i128; let mut am: Vec<u64> = vec![0u64; k + 3]; { let mut carry = 0u128; for (l, &ml) in m_limbs.iter().enumerate() { let t = (a as u128) * (ml as u128) + carry; am[l] = t as u64; carry = t >> 64; } let mut l = m_limbs.len(); while carry > 0 { am[l] = carry as u64; carry >>= 64; l += 1; } }
            for l in 0..k + 3 { let t = acc[l] as i128 - am[l] as i128 - borrow; if t < 0 { acc[l] = (t + (1i128 << 64)) as u64; borrow = 1; } else { acc[l] = t as u64; borrow = 0; } }
            while acc.len() > 1 && *acc.last().unwrap() == 0 { acc.pop(); }
            while xg.len() > 1 && *xg.last().unwrap() == 0 { xg.pop(); }
            if acc != xg { ok = false; }
            xs.push(x); xrs.push(xr);
        }
        // timing
        let reps_a = std::cmp::max(1usize, 4_000_000 / (k * k / 2 + k));
        let t0 = Instant::now(); let mut sink = 0u64;
        for r in 0..reps_a { let idx = r % NV; garner_digits(black_box(&xs[idx]), p, &ctab, &mut v); sink ^= v[k - 1]; }
        let ns_g = t0.elapsed().as_nanos() / reps_a as u128;
        let reps_b = std::cmp::max(1usize, 4_000_000 / (2 * k + 1));
        let t0 = Instant::now();
        for r in 0..reps_b { let idx = r % NV; let (a, _) = sk_alpha(black_box(&xs[idx]), xrs[idx], p, &minv, &mi_r, minv_r, mr, &mut xi); sink ^= a; }
        let ns_s = t0.elapsed().as_nanos() / reps_b as u128;
        // full reconstruction timings
        let reps_c = std::cmp::max(1usize, 2_000_000 / (k * k + 1));
        let t0 = Instant::now();
        for r in 0..reps_c { let idx = r % NV; garner_digits(black_box(&xs[idx]), p, &ctab, &mut v);
            let mut xg: Vec<u64> = vec![v[k - 1]]; for i in (0..k - 1).rev() { mul_small_add(&mut xg, p[i], v[i]); } sink ^= xg[0]; }
        let ns_fg = t0.elapsed().as_nanos() / reps_c as u128;
        let t0 = Instant::now();
        for r in 0..reps_c { let idx = r % NV; let (a, _) = sk_alpha(black_box(&xs[idx]), xrs[idx], p, &minv, &mi_r, minv_r, mr, &mut xi);
            let mut acc = vec![0u64; k + 3];
            for i in 0..k { let mut carry = 0u128; for (l, &ml) in mi_limbs[i].iter().enumerate() { let t = (xi[i] as u128) * (ml as u128) + acc[l] as u128 + carry; acc[l] = t as u64; carry = t >> 64; }
                let mut l = mi_limbs[i].len(); while carry > 0 { let t = acc[l] as u128 + carry; acc[l] = t as u64; carry = t >> 64; l += 1; } }
            let mut borrow = 0i128; let mut am: Vec<u64> = vec![0u64; k + 3]; { let mut carry = 0u128; for (l, &ml) in m_limbs.iter().enumerate() { let t = (a as u128) * (ml as u128) + carry; am[l] = t as u64; carry = t >> 64; } let mut l = m_limbs.len(); while carry > 0 { am[l] = carry as u64; carry >>= 64; l += 1; } }
            for l in 0..k + 3 { let t = acc[l] as i128 - am[l] as i128 - borrow; if t < 0 { acc[l] = (t + (1i128 << 64)) as u64; borrow = 1; } else { acc[l] = t as u64; borrow = 0; } }
            sink ^= acc[0]; }
        let ns_fs = t0.elapsed().as_nanos() / reps_c as u128;
        black_box(sink);
        println!("{:>4} {:>9} {:>9} | {:>12} {:>12} {:>9} | {:>14} {:>14} {:>9} | {}", k, gmm, smm, ns_g, ns_s, 100 * ns_g / std::cmp::max(1, ns_s), ns_fg, ns_fs, 100 * ns_fg / std::cmp::max(1, ns_fs), if ok { "PASS" } else { "FAIL" });
    }
}
