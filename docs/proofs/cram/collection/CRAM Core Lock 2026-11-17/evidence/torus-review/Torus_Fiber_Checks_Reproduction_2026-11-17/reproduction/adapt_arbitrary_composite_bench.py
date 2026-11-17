#!/usr/bin/env python3
"""Build a generalized arbitrary-composite/u64-safe variant from the untouched source harness."""
from pathlib import Path

root = Path(__file__).resolve().parent
source = root.parent / 'torus_fiber_checks' / 'kbench.rs'
target = root / 'kbench_arbitrary_composite.rs'
text = source.read_text(encoding='utf-8')

def replace_once(old: str, new: str, label: str) -> None:
    global text
    count = text.count(old)
    if count != 1:
        raise SystemExit(f'{label}: expected one match, found {count}')
    text = text.replace(old, new, 1)

replace_once(
    'use std::time::Instant;',
    'use std::time::Instant;\nuse std::collections::HashSet;\nuse std::env;\nuse std::fs;',
    'imports',
)
replace_once(
    '#[inline(always)] fn mulmod(a: u64, b: u64, m: u64) -> u64 { ((a as u128 * b as u128) % (m as u128)) as u64 }',
    '''#[inline(always)] fn mulmod(a: u64, b: u64, m: u64) -> u64 {
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
}''',
    'overflow-safe modular primitives',
)
replace_once(
    'fn inv(a: u64, p: u64) -> u64 { powmod(a % p, p - 2, p) }',
    '''fn inv(a: u64, m: u64) -> u64 {
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
}''',
    'general modular inverse',
)
replace_once(
    'fn main() {',
    '''fn take_prime(bits: u32, used: &mut HashSet<u64>) -> u64 {
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
fn main() {''',
    'general composite modulus generator and helpers',
)

start = text.index('    // primes just below 2^62')
end = text.index('        // tables (setup, not timed)', start)
text = text[:start] + '''    let moduli = load_moduli();
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
''' + text[end:]

replace_once(
    'let t = (v[j] + p[j] - (v[i] % p[j])) % p[j];',
    'let t = submod(v[j], v[i], p[j]);',
    'Garner modular subtraction',
)
replace_once(
    'acc = (acc + mulmod(xi[i] % mr, mi_r[i], mr)) % mr;',
    'acc = addmod(acc, mulmod(xi[i] % mr, mi_r[i], mr), mr);',
    'alpha accumulator modular addition',
)
replace_once(
    'let a = mulmod((acc + mr - xr) % mr, minv_r, mr);',
    'let a = mulmod(submod(acc, xr, mr), minv_r, mr);',
    'alpha modular subtraction',
)
replace_once(
    'acc = (mulmod(acc, p[i] % m, m) + v[i] % m) % m;',
    'acc = addmod(mulmod(acc, p[i] % m, m), v[i], m);',
    'Horner modular addition',
)
replace_once(
    's = (s + mulmod(xi[i] % q2, mi_q[i], q2)) % q2;',
    's = addmod(s, mulmod(xi[i] % q2, mi_q[i], q2), q2);',
    'q2 check modular addition',
)
replace_once(
    'let a_q = mulmod((s + q2 - xq) % q2, minv_q, q2);',
    'let a_q = mulmod(submod(s, xq, q2), minv_q, q2);',
    'q2 check modular subtraction',
)

start = text.index('        // test vectors with independently derived redundant residues')
end = text.index('        // timing', start)
new_tests = '''        // Deterministic boundary vectors plus pseudorandom normalized residues.
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
'''
text = text[:start] + new_tests + text[end:]

# The timing loops now consume a checksum of every output limb rather than only the low word.
nv_count = text.count('r % NV')
if nv_count != 4:
    raise SystemExit(f'dynamic sample count: expected four loop references, found {nv_count}')
text = text.replace('r % NV', 'r % nv')
replace_once('sink ^= xg[0];', 'sink ^= checksum_limbs(&xg, k + 3);', 'Garner full-output consumption')
replace_once('sink ^= acc[0];', 'sink ^= checksum_limbs(&acc, k + 3);', 'SK full-output consumption')

# Add an explicit near-u64 modular-arithmetic smoke check at process start.
replace_once(
    'fn main() {\n    let moduli = load_moduli();',
    '''fn main() {
    let near_max = u64::MAX;
    assert_eq!(addmod(near_max - 1, near_max - 2, near_max), near_max - 3);
    assert_eq!(submod(0, near_max - 1, near_max), 1);
    assert_eq!(mulmod(near_max - 1, near_max - 1, near_max), 1);
    let moduli = load_moduli();''',
    'u64 boundary smoke checks',
)

target.write_text(text, encoding='utf-8')
print(f'wrote {target}')
