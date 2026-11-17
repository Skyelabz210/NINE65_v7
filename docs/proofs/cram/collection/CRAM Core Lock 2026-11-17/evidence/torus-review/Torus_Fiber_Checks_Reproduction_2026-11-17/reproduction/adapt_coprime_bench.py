#!/usr/bin/env python3
"""Make a separate coprime-composite variant of the supplied Rust benchmark."""
from pathlib import Path

root = Path(__file__).resolve().parent
source = root.parent / 'torus_fiber_checks' / 'kbench.rs'
target = root / 'kbench_coprime.rs'
text = source.read_text(encoding='utf-8')

old_inv = 'fn inv(a: u64, p: u64) -> u64 { powmod(a % p, p - 2, p) }'
new_inv = '''fn inv(a: u64, m: u64) -> u64 {
    // Extended Euclid: valid for every modulus m coprime to a, including composites.
    let (mut t, mut new_t) = (0i128, 1i128);
    let (mut r, mut new_r) = (m as i128, (a % m) as i128);
    while new_r != 0 {
        let q = r / new_r;
        (t, new_t) = (new_t, t - q * new_t);
        (r, new_r) = (new_r, r - q * new_r);
    }
    assert_eq!(r, 1, "inverse requested for non-coprime values");
    t.rem_euclid(m as i128) as u64
}
fn gcd(mut a: u64, mut b: u64) -> u64 {
    while b != 0 { let r = a % b; a = b; b = r; }
    a
}'''
if text.count(old_inv) != 1:
    raise SystemExit('expected exactly one prime-only inverse definition')
text = text.replace(old_inv, new_inv)

start = text.index('    // primes just below 2^62')
end = text.index('        // tables (setup, not timed)', start)
new_setup = '''    // Build 130 pairwise-coprime composite moduli from disjoint factors.
    // Miller-Rabin here only supplies convenient factors; every actual lane and
    // redundant modulus is a composite product, and pairwise gcd is checked.
    let mut factors: Vec<u64> = Vec::new();
    let mut c = (1u64 << 31) - 1;
    while factors.len() < 260 { if is_prime(c) { factors.push(c); } c -= 2; }
    let moduli: Vec<u64> = (0..130).map(|i| factors[2*i] * factors[2*i + 1]).collect();
    for i in 0..moduli.len() {
        for j in 0..i { assert_eq!(gcd(moduli[i], moduli[j]), 1, "moduli are not pairwise coprime"); }
    }
    let mut rng = Rng(0x9E3779B97F4A7C15);
    println!("composite lane/check moduli; all pairwise gcd=1; extended-Euclid inverses");
    println!("{:>4} {:>9} {:>9} | {:>12} {:>12} {:>9} | {:>14} {:>14} {:>9} | ok", "k", "garner_mm", "sk_mm", "ns/garnerMRC", "ns/skAlpha", "ratio_x100", "ns/full(garn)", "ns/full(sk)", "ratio_x100");
    for &k in &[2usize, 4, 8, 16, 32, 64, 128] {
        let p = &moduli[..k]; let mr = moduli[k]; let q2 = moduli[k + 1];
        assert!(q2 > k as u64);
'''
text = text[:start] + new_setup + text[end:]
target.write_text(text, encoding='utf-8')
print(f'wrote {target}')
