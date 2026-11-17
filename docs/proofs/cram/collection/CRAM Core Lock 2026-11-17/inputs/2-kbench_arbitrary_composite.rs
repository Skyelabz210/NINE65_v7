// K-readout (redundant modulus) vs Garner over k ~62-bit RNS lanes. Integer-only. std only.
// Correctness: both methods are cross-checked against each other and against an independent check modulus q2.
use std::hint::black_box;
use std::time::Instant;
use std::collections::HashSet;
use std::env;
use std::fs;

#[inline(always)] fn mulmod(a: u64, b: u64, m: u64) -> u64 {
    assert!(m > 0, "modulus must be positive");
    ((a as u128 * b as u128) % (m as u128)) as u64
}
#[inline(always)] fn addmod(a: u64, b: u64, m: u64) -> u64 {
    assert!(m > 0, "modulus must be positive");
    let a = a % m; let b = b % m;
    if a >= m - b { a - (m - b) } else { a + b }
}
#[inline(always)] fn submod(a: u64, b: u64, m: u64) -> u64 {
    assert!(m > 0, "modulus must be positive");
    let a = a % m; let b = b % m;
    if a >= b { a - b } else { m - (b - a) }
}
fn powmod(mut b: u64, mut e: u64, m: u64) -> u64 { let mut r = 1u64; b %= m; while e > 0 { if e & 1 == 1 { r = mulmod(r, b, m); } b = mulmod(b, b, m); e >>= 1; } r }
fn inv(a: u64, m: u64) -> u64 {
    assert!(m > 1, "inverse modulus must exceed 1");
    let (mut t, mut new_t) = (0i128, 1i128);
    let (mut r, mut new_r) = (m as i128, (a % m) as i128);
    while new_r != 0 {
        let q = r / new_r;
        (t, new_t) = (new_t, t - q * new_t);
        (r, new_r) = (new_r, r - q * new_r);
    }
    assert_eq!(r, 1, "inverse requested for non-coprime values");
    let out = t.rem_euclid(m as i128) as u64;
    assert_eq!(mulmod(a % m, out, m), 1 % m, "inverse check failed");
    out
}
fn gcd(mut a: u64, mut b: u64) -> u64 {
    while b != 0 { let r = a % b; a = b; b = r; }
    a
}
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
        let t = submod(v[j], v[i], p[j]);
        v[j] = mulmod(t, c[i][j], p[j]); cnt += 1;
    } }
    cnt
}
fn sk_alpha(x: &[u64], xr: u64, p: &[u64], minv: &[u64], mi_r: &[u64], minv_r: u64, mr: u64, xi: &mut [u64]) -> (u64, u64) {
    let k = p.len(); let mut acc = 0u64; let mut cnt = 0u64;
    for i in 0..k { xi[i] = mulmod(x[i], minv[i], p[i]); acc = addmod(acc, mulmod(xi[i] % mr, mi_r[i], mr), mr); cnt += 2; }
    let a = mulmod(submod(acc, xr, mr), minv_r, mr); cnt += 1;
    (a, cnt)
}
fn mod_from_digits(v: &[u64], p: &[u64], m: u64) -> u64 {
    let k = p.len(); let mut acc = v[k - 1] % m;
    for i in (0..k - 1).rev() { acc = addmod(mulmod(acc, p[i] % m, m), v[i], m); }
    acc
}
fn take_prime(bits: u32, used: &mut HashSet<u64>) -> u64 {
    let mut n = (1u64 << bits) - 1;
    let min = 1u64 << (bits - 1);
    if n % 2 == 0 { n -= 1; }
    loop {
        assert!(n >= min, "prime pool exhausted for {}-bit factors", bits);
        if !used.contains(&n) && is_prime(n) { used.insert(n); return n; }
        n -= 2;
    }
}
fn product(factors: &[u64]) -> u64 {
    factors.iter().fold(1u64, |p, &f| p.checked_mul(f).expect("composite modulus exceeds u64"))
}
fn composite_moduli() -> Vec<u64> {
    let mut used = HashSet::new();
    let even_factor = 3_037_000_493u64;
    let check_factor_1 = 4_294_967_291u64;
    let check_factor_2 = 4_294_967_279u64;
    assert!(is_prime(even_factor) && is_prime(check_factor_1) && is_prime(check_factor_2));
    used.insert(even_factor); used.insert(check_factor_1); used.insert(check_factor_2);
    let high_even = product(&[2, even_factor, even_factor]);
    let high_odd_1 = product(&[check_factor_1, check_factor_1]);
    let high_odd_2 = product(&[check_factor_2, check_factor_2]);
    assert!(high_even > i64::MAX as u64 && high_odd_1 > i64::MAX as u64 && high_odd_2 > i64::MAX as u64);

    // 127 additional composites with several shapes: semiprimes, squares, cubes,
    // squareful products, and products of three/four distinct factors.
    let mut normal = Vec::with_capacity(127);
    for i in 0..127 {
        let m = match i % 7 {
            0 => { let a = take_prime(31, &mut used); let b = take_prime(31, &mut used); product(&[a, b]) },
            1 => { let a = take_prime(31, &mut used); product(&[a, a]) },
            2 => { let a = take_prime(21, &mut used); let b = take_prime(21, &mut used); let c = take_prime(20, &mut used); product(&[a, b, c]) },
            3 => { let a = take_prime(16, &mut used); let b = take_prime(16, &mut used); let c = take_prime(15, &mut used); let d = take_prime(15, &mut used); product(&[a, b, c, d]) },
            4 => { let a = take_prime(21, &mut used); product(&[a, a, a]) },
            5 => { let a = take_prime(16, &mut used); let b = take_prime(15, &mut used); product(&[a, a, b, b]) },
            _ => { let a = take_prime(20, &mut used); let b = take_prime(20, &mut used); let c = take_prime(20, &mut used); product(&[a, b, c]) },
        };
        normal.push(m);
    }
    let mut moduli = Vec::with_capacity(130);
    moduli.push(normal[0]);
    moduli.push(high_even); // lane 1: exercises Garner with a modulus > 2^63
    moduli.extend_from_slice(&normal[1..]); // indexes 2..127
    moduli.push(high_odd_1); // index 128: redundant modulus for k=128
    moduli.push(high_odd_2); // index 129: q2 for k=128
    assert_eq!(moduli.len(), 130);
    assert!(moduli.iter().all(|&m| m > 1));
    for i in 0..moduli.len() {
        for j in 0..i { assert_eq!(gcd(moduli[i], moduli[j]), 1, "moduli {i} and {j} are not coprime"); }
    }
    moduli
}
fn load_moduli() -> Vec<u64> {
    let mut args = env::args().skip(1);
    if let Some(path) = args.next() {
        assert!(args.next().is_none(), "provide at most one modulus-file path");
        let input = fs::read_to_string(&path).expect("could not read modulus file");
        let values: Vec<u64> = input.split(|c: char| c == ',' || c.is_whitespace())
            .filter(|s| !s.is_empty()).map(|s| s.parse().expect("invalid u64 modulus")).collect();
        assert!(values.len() >= 4, "need at least k=2 lane moduli plus two check moduli");
        values
    } else { composite_moduli() }
}
fn validate_for_k(moduli: &[u64], k: usize) {
    assert!(moduli.len() >= k + 2, "modulus file is too short for k={}", k);
    let lanes = &moduli[..k]; let mr = moduli[k]; let q2 = moduli[k + 1];
    assert!(mr > 1 && q2 > 1 && lanes.iter().all(|&m| m > 1), "all moduli must exceed 1");
    assert!(q2 >= k as u64, "q2 must be at least k to recover all alpha values");
    for i in 0..k {
        for j in 0..i { assert_eq!(gcd(lanes[i], lanes[j]), 1, "lane moduli must be pairwise coprime"); }
        assert_eq!(gcd(lanes[i], mr), 1, "anchor modulus must be coprime to every lane");
        assert_eq!(gcd(lanes[i], q2), 1, "witness modulus must be coprime to every lane");
    }
    // The anchor and witness need not be coprime to one another.
}
fn limbs_mod_le(limbs: &[u64], m: u64) -> u64 {
    assert!(m > 0);
    let radix = mulmod(1u64 << 63, 2, m); // 2^64 mod m, without representing 2^64 in u64
    let mut acc = 0u64;
    for &word in limbs.iter().rev() { acc = addmod(mulmod(acc, radix, m), word % m, m); }
    acc
}
fn checksum_limbs(limbs: &[u64], width: usize) -> u64 {
    let mut h = 0x243F6A8885A308D3u64;
    for i in 0..width {
        let word = limbs.get(i).copied().unwrap_or(0);
        h = h.rotate_left(9) ^ word.wrapping_mul(0x9E3779B97F4A7C15);
    }
    h
}
fn main() {
    let near_max = u64::MAX;
    assert_eq!(addmod(near_max - 1, near_max - 2, near_max), near_max - 3);
    assert_eq!(submod(0, near_max - 1, near_max), 1);
    assert_eq!(mulmod(near_max - 1, near_max - 1, near_max), 1);
    let moduli = load_moduli();
    let largest = *moduli.iter().max().unwrap();
    let smallest = *moduli.iter().min().unwrap();
    let even_count = moduli.iter().filter(|&&m| m % 2 == 0).count();
    println!("composite modulus set: n={}, min_bits={}, max_bits={}, even_count={}, max_modulus={}, max_above_2^63={}",
        moduli.len(), 64 - smallest.leading_zeros(), 64 - largest.leading_zeros(), even_count, largest, largest > i64::MAX as u64);
    let mut rng = Rng(0x9E3779B97F4A7C15);
    println!("{:>4} {:>9} {:>9} | {:>12} {:>12} {:>9} | {:>14} {:>14} {:>9} | ok", "k", "garner_mm", "sk_mm", "ns/garnerMRC", "ns/skAlpha", "ratio_x100", "ns/full(garn)", "ns/full(sk)", "ratio_x100");
    let sizes: Vec<usize> = [2usize, 4, 8, 16, 32, 64, 128].iter().copied().filter(|&k| moduli.len() >= k + 2).collect();
    assert!(!sizes.is_empty(), "no supported k fits this modulus list");
    for k in sizes {
        validate_for_k(&moduli, k);
        let p = &moduli[..k]; let mr = moduli[k]; let q2 = moduli[k + 1];
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
        // Deterministic boundary vectors plus pseudorandom normalized residues.
        let mut xs: Vec<Vec<u64>> = Vec::new(); let mut xrs: Vec<u64> = Vec::new(); let mut ok = true;
        let mut v = vec![0u64; k]; let mut xi = vec![0u64; k];
        let (mut gmm, mut smm) = (0u64, 0u64);
        let mut cases: Vec<(Vec<u64>, Option<u64>)> = Vec::new();
        cases.push((vec![0u64; k], Some(0)));
        let mut mi_p = vec![0u64; k];
        for i in 0..k { let mut z = 1u64; for l in 0..k { if l != i { z = mulmod(z, p[l] % p[i], p[i]); } } mi_p[i] = z; }
        let alpha_max_residues: Vec<u64> = (0..k).map(|i| mulmod(p[i] - 1, mi_p[i], p[i])).collect();
        cases.push((alpha_max_residues, Some((k - 1) as u64)));
        cases.push((p.iter().map(|&m| m - 1).collect(), None));
        for i in 0..std::cmp::min(k, 4) {
            let mut one = vec![0u64; k]; one[i] = 1; cases.push((one, None));
            let mut high = vec![0u64; k]; high[i] = p[i] - 1; cases.push((high, None));
        }
        while cases.len() < 24 { cases.push(((0..k).map(|i| rng.next() % p[i]).collect(), None)); }
        for (x, expected_alpha) in cases {
            assert!(x.iter().zip(p).all(|(&r, &m)| r < m), "lane input was not normalized");
            gmm = garner_digits(&x, p, &ctab, &mut v);
            for i in 0..k { if mod_from_digits(&v, p, p[i]) != x[i] { ok = false; } }
            let mut xg: Vec<u64> = vec![v[k - 1]]; for i in (0..k - 1).rev() { mul_small_add(&mut xg, p[i], v[i]); }
            let xr = limbs_mod_le(&xg, mr); let xq = limbs_mod_le(&xg, q2);
            let (a, sc) = sk_alpha(&x, xr, p, &minv, &mi_r, minv_r, mr, &mut xi); smm = sc;
            if let Some(want) = expected_alpha { if a != want { ok = false; } }
            if (a as usize) >= k { ok = false; }
            // q2 residue is independently reduced from the canonical Garner limb result.
            let mut s = 0u64; for i in 0..k { s = addmod(s, mulmod(xi[i] % q2, mi_q[i], q2), q2); }
            let a_q = mulmod(submod(s, xq, q2), minv_q, q2);
            if a != a_q { ok = false; }
            // Full assembly: check the canonical limbs and that every original lane residue returns.
            let mut acc = vec![0u64; k + 3];
            for i in 0..k { let mut carry = 0u128; for (l, &ml) in mi_limbs[i].iter().enumerate() { let t = (xi[i] as u128) * (ml as u128) + acc[l] as u128 + carry; acc[l] = t as u64; carry = t >> 64; }
                let mut l = mi_limbs[i].len(); while carry > 0 { let t = acc[l] as u128 + carry; acc[l] = t as u64; carry = t >> 64; l += 1; } }
            let mut borrow = 0i128; let mut am: Vec<u64> = vec![0u64; k + 3]; { let mut carry = 0u128; for (l, &ml) in m_limbs.iter().enumerate() { let t = (a as u128) * (ml as u128) + carry; am[l] = t as u64; carry = t >> 64; } let mut l = m_limbs.len(); while carry > 0 { am[l] = carry as u64; carry >>= 64; l += 1; } }
            for l in 0..k + 3 { let t = acc[l] as i128 - am[l] as i128 - borrow; if t < 0 { acc[l] = (t + (1i128 << 64)) as u64; borrow = 1; } else { acc[l] = t as u64; borrow = 0; } }
            while acc.len() > 1 && *acc.last().unwrap() == 0 { acc.pop(); }
            while xg.len() > 1 && *xg.last().unwrap() == 0 { xg.pop(); }
            if borrow != 0 || acc != xg { ok = false; }
            xs.push(x); xrs.push(xr);
        }
        assert!(ok, "correctness check failed for k={}; refusing to emit a timing row", k);
        let nv = xs.len();
        // timing
        let reps_a = std::cmp::max(1usize, 4_000_000 / (k * k / 2 + k));
        let t0 = Instant::now(); let mut sink = 0u64;
        for r in 0..reps_a { let idx = r % nv; garner_digits(black_box(&xs[idx]), p, &ctab, &mut v); sink ^= v[k - 1]; }
        let ns_g = t0.elapsed().as_nanos() / reps_a as u128;
        let reps_b = std::cmp::max(1usize, 4_000_000 / (2 * k + 1));
        let t0 = Instant::now();
        for r in 0..reps_b { let idx = r % nv; let (a, _) = sk_alpha(black_box(&xs[idx]), xrs[idx], p, &minv, &mi_r, minv_r, mr, &mut xi); sink ^= a; }
        let ns_s = t0.elapsed().as_nanos() / reps_b as u128;
        // full reconstruction timings
        let reps_c = std::cmp::max(1usize, 2_000_000 / (k * k + 1));
        let t0 = Instant::now();
        for r in 0..reps_c { let idx = r % nv; garner_digits(black_box(&xs[idx]), p, &ctab, &mut v);
            let mut xg: Vec<u64> = vec![v[k - 1]]; for i in (0..k - 1).rev() { mul_small_add(&mut xg, p[i], v[i]); } sink ^= checksum_limbs(&xg, k + 3); }
        let ns_fg = t0.elapsed().as_nanos() / reps_c as u128;
        let t0 = Instant::now();
        for r in 0..reps_c { let idx = r % nv; let (a, _) = sk_alpha(black_box(&xs[idx]), xrs[idx], p, &minv, &mi_r, minv_r, mr, &mut xi);
            let mut acc = vec![0u64; k + 3];
            for i in 0..k { let mut carry = 0u128; for (l, &ml) in mi_limbs[i].iter().enumerate() { let t = (xi[i] as u128) * (ml as u128) + acc[l] as u128 + carry; acc[l] = t as u64; carry = t >> 64; }
                let mut l = mi_limbs[i].len(); while carry > 0 { let t = acc[l] as u128 + carry; acc[l] = t as u64; carry = t >> 64; l += 1; } }
            let mut borrow = 0i128; let mut am: Vec<u64> = vec![0u64; k + 3]; { let mut carry = 0u128; for (l, &ml) in m_limbs.iter().enumerate() { let t = (a as u128) * (ml as u128) + carry; am[l] = t as u64; carry = t >> 64; } let mut l = m_limbs.len(); while carry > 0 { am[l] = carry as u64; carry >>= 64; l += 1; } }
            for l in 0..k + 3 { let t = acc[l] as i128 - am[l] as i128 - borrow; if t < 0 { acc[l] = (t + (1i128 << 64)) as u64; borrow = 1; } else { acc[l] = t as u64; borrow = 0; } }
            sink ^= checksum_limbs(&acc, k + 3); }
        let ns_fs = t0.elapsed().as_nanos() / reps_c as u128;
        black_box(sink);
        println!("{:>4} {:>9} {:>9} | {:>12} {:>12} {:>9} | {:>14} {:>14} {:>9} | {}", k, gmm, smm, ns_g, ns_s, 100 * ns_g / std::cmp::max(1, ns_s), ns_fg, ns_fs, 100 * ns_fg / std::cmp::max(1, ns_fs), if ok { "PASS" } else { "FAIL" });
    }
}
