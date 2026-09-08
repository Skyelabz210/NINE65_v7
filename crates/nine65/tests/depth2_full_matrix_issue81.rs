//! Full correctness verification matrix for GitHub issue #81 ("[P0] Fix
//! fixed-basis depth-2 ct×ct correctness in symmetric and public DualRNS
//! paths").
//!
//! # Relationship to `depth2_isolation.rs`
//!
//! `crates/nine65/tests/depth2_isolation.rs` already root-caused the defect:
//! `DualRNSContext::extract_k_rns_level`'s anchor-prime selection used to pick
//! a subset of anchors sized off `ct_level` alone, and at depth-2 the true
//! signed winding `k` (152 bits for `secure_128_deep`) exceeded that subset's
//! capacity. `arithmetic/rns.rs`'s `extract_k_rns_level_cached` (as currently
//! checked in) always reconstructs from `k_reconstruction_anchor_count()` —
//! `min(anchor_count, 8)` — anchors instead, and `canonical_anchor_primes_for_n`
//! widened the anchor basis to 7 primes for `n <= 8192` and 10 for `n = 16384`.
//! That file's own module doc records this as "looks fixed as a side effect",
//! but only checked ONE config (`secure_128_deep`), ONE operand shape
//! (squaring), and ONE seed (12345).
//!
//! This file is the broader matrix issue #81's acceptance criteria actually
//! require:
//!
//!   1. All four named configs (`secure_128`, `secure_128_deep`, `secure_192`,
//!      `secure_256`), not just `secure_128_deep`.
//!   2. Mixed operands (`Enc(a) * Enc(b)`, `a != b`) and a non-squaring
//!      depth-2 chain (`(a*b) * (c*d)`), not just repeated squaring.
//!   3. A seed matrix, not one fixed seed.
//!   4. The exact capacity numbers (`extract_k_rns_level`'s operative anchor
//!      capacity) computed per config from the actual live prime lists, not
//!      guessed or hand-copied from a comment.
//!   5. Boundary/large-value vectors that push plaintext values, and hence
//!      ciphertext coefficient magnitudes, toward the extremes the scheme
//!      supports (`t-1`, `t/2`, etc.), chained to depth 2.
//!
//! Everything here uses ONLY the crate's public surface
//! (`RNSFHEContext::{encrypt_dual,decrypt_dual,mul_dual_symmetric,mul_dual_public}`,
//! `DualRNSCiphertext::{c0,c1,level}`, `DualRNSPoly::{main,anchor}`,
//! `SecureConfig::*`) plus a from-scratch bignum CRT reconstruction (no
//! floats, no threaded Garner cascade — plain schoolbook limb arithmetic),
//! exactly as `depth2_isolation.rs` already established as the pattern for
//! reaching private RNS state from outside the crate.

use nine65::entropy::ShadowHarvester;
use nine65::ops::rns_fhe::{DualRNSPoly, RNSFHEContext};
use nine65::params::secure_configs::SecureConfig;

// ============================================================================
// Minimal from-scratch signed bignum: 6 x u64 limbs (384 bits), little-endian
// magnitude. Widened from depth2_isolation.rs's 4-limb (256-bit) version
// because secure_192/secure_256 carry main-prime products (~146/175 bits) and
// anchor reconstruction products (up to 8 anchors x ~32 bits =~ 256 bits) that
// no longer both fit comfortably in 256 bits with margin to spare. Same
// schoolbook arithmetic as before: every limb of every result is a direct
// function of the corresponding input limbs plus a locally computed
// carry/borrow, not a per-digit dependency chain reading back through
// previously emitted digits of the SAME number (so this is not the
// "Garner-style cascade" A2 rules out).
// ============================================================================

const LIMBS: usize = 6;
type Mag = [u64; LIMBS];

fn mag_zero() -> Mag {
    [0u64; LIMBS]
}

fn mag_from_u128(x: u128) -> Mag {
    let mut m = mag_zero();
    m[0] = x as u64;
    m[1] = (x >> 64) as u64;
    m
}

fn add_mag(a: Mag, b: Mag) -> Mag {
    let mut r = mag_zero();
    let mut carry: u128 = 0;
    for i in 0..LIMBS {
        let s = a[i] as u128 + b[i] as u128 + carry;
        r[i] = s as u64;
        carry = s >> 64;
    }
    assert_eq!(
        carry,
        0,
        "magnitude add overflow beyond {} bits",
        LIMBS * 64
    );
    r
}

fn cmp_mag(a: Mag, b: Mag) -> std::cmp::Ordering {
    for i in (0..LIMBS).rev() {
        match a[i].cmp(&b[i]) {
            std::cmp::Ordering::Equal => continue,
            o => return o,
        }
    }
    std::cmp::Ordering::Equal
}

/// a - b, requires a >= b.
fn sub_mag(a: Mag, b: Mag) -> Mag {
    let mut r = mag_zero();
    let mut borrow: i128 = 0;
    for i in 0..LIMBS {
        let d = a[i] as i128 - b[i] as i128 - borrow;
        if d < 0 {
            r[i] = (d + (1i128 << 64)) as u64;
            borrow = 1;
        } else {
            r[i] = d as u64;
            borrow = 0;
        }
    }
    assert_eq!(borrow, 0, "sub_mag underflow -- caller must ensure a >= b");
    r
}

fn bitlen_mag(a: Mag) -> u32 {
    for i in (0..LIMBS).rev() {
        if a[i] != 0 {
            return (i as u32) * 64 + (64 - a[i].leading_zeros());
        }
    }
    0
}

/// Multiply a `Mag` by a u64, returning the low LIMBS*64 bits (exact for this
/// file's use: every magnitude here stays well under 384 bits before the
/// multiply, verified by the overflow assert below firing loudly otherwise).
fn mul_mag_u64(a: Mag, m: u64) -> Mag {
    let mut r = mag_zero();
    let mut carry: u128 = 0;
    for i in 0..LIMBS {
        let p = a[i] as u128 * m as u128 + carry;
        r[i] = p as u64;
        carry = p >> 64;
    }
    assert_eq!(carry, 0, "mul_mag_u64 overflow beyond {} bits", LIMBS * 64);
    r
}

/// value mod m, for a `Mag` and u64 modulus, via repeated double-and-reduce
/// over the limbs from the top down (schoolbook long division style, not a
/// mixed-radix digit cascade over a CRT basis).
fn mag_mod_u64(a: Mag, m: u64) -> u64 {
    let mut rem: u128 = 0;
    for i in (0..LIMBS).rev() {
        rem = ((rem << 64) | a[i] as u128) % m as u128;
    }
    rem as u64
}

/// Extended-Euclid modular inverse, written from scratch for this file (does
/// not call `nine65::params::mod_inverse` or `nine65::arithmetic`'s copy).
fn mod_inverse(a: u64, m: u64) -> u64 {
    let (mut old_r, mut r) = (m as i128, a as i128);
    let (mut old_s, mut s) = (0i128, 1i128);
    while r != 0 {
        let q = old_r / r;
        let tmp_r = old_r - q * r;
        old_r = r;
        r = tmp_r;
        let tmp_s = old_s - q * s;
        old_s = s;
        s = tmp_s;
    }
    let mut result = old_s % m as i128;
    if result < 0 {
        result += m as i128;
    }
    result as u64
}

/// Direct (non-cascaded) CRT reconstruction into `Mag`: each term
/// `residue_i * M_i * inverse(M_i mod p_i, p_i)` is computed independently of
/// every other term, then all terms are summed mod M. No digit of the result
/// is derived from a previously computed digit of the SAME reconstruction.
/// Works for ANY prime list whose product fits in `LIMBS*64` bits (main or
/// anchor system, any config) -- generalized from depth2_isolation.rs's
/// separate u128 (main) / Mag (anchor) paths because secure_192/secure_256's
/// main-prime products (146/175 bits) no longer fit in u128 either.
fn crt_reconstruct_mag(residues: &[u64], primes: &[u64]) -> Mag {
    let mut m = mag_from_u128(1);
    for &p in primes {
        m = mul_mag_u64(m, p);
    }
    let mut acc = mag_zero();
    for (i, &p) in primes.iter().enumerate() {
        // M_i = product of all OTHER primes, built directly (avoids needing
        // a general Mag/Mag divider for this file's small prime counts).
        let mut mi = mag_from_u128(1);
        for (j, &q) in primes.iter().enumerate() {
            if i != j {
                mi = mul_mag_u64(mi, q);
            }
        }
        let mi_mod_p = mag_mod_u64(mi, p);
        let mi_inv = mod_inverse(mi_mod_p, p);
        let term_scalar = (residues[i] as u128 * mi_inv as u128 % p as u128) as u64;
        let term = mul_mag_u64(mi, term_scalar);
        acc = add_mag(acc, term);
        acc = mag_mod_full(acc, m);
    }
    acc
}

fn product_mag(primes: &[u64]) -> Mag {
    let mut m = mag_from_u128(1);
    for &p in primes {
        m = mul_mag_u64(m, p);
    }
    m
}

/// acc mod m, via repeated subtraction of shifted copies of m (schoolbook
/// long-division remainder). m has at most ~256 bits in this file, so this
/// runs in at most a few hundred iterations -- not perf-sensitive here.
fn mag_mod_full(mut acc: Mag, m: Mag) -> Mag {
    if cmp_mag(acc, m) == std::cmp::Ordering::Less {
        return acc;
    }
    let acc_bits = bitlen_mag(acc);
    let m_bits = bitlen_mag(m);
    if m_bits == 0 {
        return acc;
    }
    let mut shift = acc_bits - m_bits;
    loop {
        let shifted = mag_shl(m, shift);
        if cmp_mag(shifted, acc) != std::cmp::Ordering::Greater {
            acc = sub_mag(acc, shifted);
        }
        if shift == 0 {
            break;
        }
        shift -= 1;
    }
    acc
}

fn mag_shl(a: Mag, bits: u32) -> Mag {
    if bits == 0 {
        return a;
    }
    let limb_shift = (bits / 64) as usize;
    let bit_shift = bits % 64;
    let mut r = mag_zero();
    for i in (0..LIMBS).rev() {
        if i + limb_shift >= LIMBS {
            continue;
        }
        let mut v = (a[i] as u128) << bit_shift;
        if i + limb_shift < LIMBS {
            r[i + limb_shift] |= v as u64;
            v >>= 64;
        }
        if v != 0 && i + limb_shift + 1 < LIMBS {
            r[i + limb_shift + 1] |= v as u64;
        }
    }
    r
}

fn mag_shr1(a: Mag) -> Mag {
    let mut r = mag_zero();
    let mut carry = 0u64;
    for i in (0..LIMBS).rev() {
        let new_carry = a[i] & 1;
        r[i] = (a[i] >> 1) | (carry << 63);
        carry = new_carry;
    }
    r
}

/// Reconstruct coefficient `i`'s true signed value using BOTH the main system
/// (for `v_m`) and a chosen anchor-prime subset (for `k`), replicating
/// `extract_k_rns_level`'s formula from scratch (`v_exact = v_m + k*M_level`,
/// `k` found via CRT over the anchor residues), fully generalized over prime
/// counts so it applies to every config's main/anchor basis unchanged.
/// Returns (is_negative, magnitude) using the same convention
/// `SignedK256::from_unsigned` uses: k > A/2 => negative magnitude A-k.
fn reconstruct_signed_k(
    main_residues: &[u64],
    anchor_residues: &[u64],
    main_primes: &[u64],
    anchor_primes: &[u64],
) -> (bool, Mag) {
    let v_m = crt_reconstruct_mag(main_residues, main_primes);
    let m_level = product_mag(main_primes);

    let mut k_rns = vec![0u64; anchor_primes.len()];
    for (j, &a) in anchor_primes.iter().enumerate() {
        let m_level_mod_a = mag_mod_u64(m_level, a);
        let inv = mod_inverse(m_level_mod_a, a);
        let v_m_mod_a = mag_mod_u64(v_m, a);
        let diff = (anchor_residues[j] + a - v_m_mod_a) % a;
        k_rns[j] = ((diff as u128 * inv as u128) % a as u128) as u64;
    }
    let k = crt_reconstruct_mag(&k_rns, anchor_primes);

    let a_full = product_mag(anchor_primes);
    let a_half = mag_shr1(a_full);

    if cmp_mag(k, a_half) == std::cmp::Ordering::Greater {
        (true, sub_mag(a_full, k))
    } else {
        (false, k)
    }
}

/// Max |signed k| bit length across every coefficient of `poly`, using the
/// first `k_primes` anchors -- the independent, generalized equivalent of
/// `depth2_isolation.rs`'s `max_signed_k_bits`, but parameterized so it works
/// for any config's anchor count rather than hardcoding 5.
fn max_signed_k_bits(
    poly: &DualRNSPoly,
    main_primes: &[u64],
    anchor_primes: &[u64],
    k_primes: usize,
    n: usize,
) -> u32 {
    let anchors = &anchor_primes[..k_primes];
    let mut max_bits = 0u32;
    let mut main_residues = vec![0u64; main_primes.len()];
    let mut anchor_residues = vec![0u64; k_primes];
    for i in 0..n {
        for (j, limb) in poly.main.iter().enumerate() {
            main_residues[j] = limb[i];
        }
        for (j, limb) in poly.anchor.iter().take(k_primes).enumerate() {
            anchor_residues[j] = limb[i];
        }
        let (_, mag) = reconstruct_signed_k(&main_residues, &anchor_residues, main_primes, anchors);
        max_bits = max_bits.max(bitlen_mag(mag));
    }
    max_bits
}

/// Bignum CRT machinery self-check, on small controlled test vectors (not
/// derived from any crypto data): reconstruct from residues, re-reduce mod
/// each prime, confirm the original residues come back. Guards against a
/// `crt_reconstruct_mag` bug that could round-trip against itself while still
/// being wrong relative to the real primes.
fn selftest_bignum_crt() {
    let test_primes = [
        2013265921u64,
        2281701377,
        2483027969,
        2885681153,
        3221225473,
        3221422081,
        3222306817,
    ];
    let test_cases: [[u64; 7]; 4] = [
        [0, 0, 0, 0, 0, 0, 0],
        [1, 1, 1, 1, 1, 1, 1],
        [
            123456789, 987654321, 555555555, 111111111, 999999999, 42424242, 13371337,
        ],
        [
            test_primes[0] - 1,
            test_primes[1] - 1,
            test_primes[2] - 1,
            test_primes[3] - 1,
            test_primes[4] - 1,
            test_primes[5] - 1,
            test_primes[6] - 1,
        ],
    ];
    for residues in test_cases {
        let v = crt_reconstruct_mag(&residues, &test_primes);
        for (j, &p) in test_primes.iter().enumerate() {
            let got = mag_mod_u64(v, p);
            assert_eq!(
                got, residues[j],
                "bignum CRT round-trip failed: residues={:?} prime[{}]={} got={} expected={}",
                residues, j, p, got, residues[j]
            );
        }
    }
}

// ============================================================================
// Config matrix
// ============================================================================

struct ConfigCase {
    name: &'static str,
    make: fn() -> SecureConfig,
}

const CONFIGS: &[ConfigCase] = &[
    ConfigCase {
        name: "secure_128",
        make: SecureConfig::secure_128,
    },
    ConfigCase {
        name: "secure_128_deep",
        make: SecureConfig::secure_128_deep,
    },
    ConfigCase {
        name: "secure_192",
        make: SecureConfig::secure_192,
    },
    ConfigCase {
        name: "secure_256",
        make: SecureConfig::secure_256,
    },
];

/// Reconstruction anchor cap mirrored from
/// `DualRNSContext::k_reconstruction_anchor_count`'s private
/// `K_RECONSTRUCTION_MAX_ANCHORS` constant (`arithmetic/rns.rs`). Cited, not
/// invented: production uses `min(anchor_count, 8)` anchors to reconstruct
/// `k` and treats any remaining anchors as witness lanes.
const K_RECONSTRUCTION_MAX_ANCHORS: usize = 8;

/// Deterministic seed matrix -- rules out seed 12345 (the issue's own
/// reproducer) being a lucky case. Fixed, not random, so a failure is
/// reproducible.
const SEEDS: &[u64] = &[12345, 1, 2, 999_999, 424_242];

/// Smaller seed subset for the more expensive mixed-operand / public-mode
/// cases, to keep total wall time reasonable while still ruling out a single
/// lucky seed.
const SEEDS_SUBSET: &[u64] = &[12345, 777, 55555];

// ============================================================================
// Part 1: capacity facts, per config, computed (not guessed) from the live
// prime lists via public fields -- the exact bit-length thresholds
// `extract_k_rns_level`'s capacity math actually operates against.
// ============================================================================

#[test]
fn depth2_capacity_facts_all_configs() {
    println!("\n=== depth2_capacity_facts_all_configs ===");
    println!(
        "{:<16} {:>4} {:>6} {:>10} {:>12} {:>14} {:>16}",
        "config", "n", "mains", "M_bits", "anchors", "k_primes", "A_recon_bits(-1)"
    );
    for cc in CONFIGS {
        let secure_config = (cc.make)();
        let ctx = RNSFHEContext::new(&secure_config.config);

        let m_bits: u32 = ctx
            .config
            .primes
            .iter()
            .map(|&p| 64 - p.leading_zeros())
            .sum();
        let anchor_primes = &ctx.dual_rns.anchor.primes;
        let k_primes = anchor_primes.len().min(K_RECONSTRUCTION_MAX_ANCHORS);
        let a_recon_bits: u32 = anchor_primes[..k_primes]
            .iter()
            .map(|&p| 64 - p.leading_zeros())
            .sum();

        println!(
            "{:<16} {:>4} {:>6} {:>10} {:>12} {:>14} {:>16}",
            cc.name,
            ctx.n,
            ctx.config.primes.len(),
            m_bits,
            anchor_primes.len(),
            k_primes,
            format!("{} ({})", a_recon_bits, a_recon_bits.saturating_sub(1))
        );

        // Sanity: production's own startup invariant (>= 5 anchors) and the
        // reconstruction basis must have real margin over the main-prime
        // product it needs to disambiguate winding for (M_level itself, as a
        // conservative floor -- the true k bound is scheme-specific and
        // measured directly in Part 2/4 below, not re-derived here).
        assert!(
            anchor_primes.len() >= 5,
            "{}: anchor basis must have >= 5 primes (DualRNSContext::for_fhe invariant)",
            cc.name
        );
        assert!(
            a_recon_bits > m_bits,
            "{}: reconstruction-anchor capacity ({} bits) must exceed M_level ({} bits) \
             or k could never be disambiguated even at depth 0",
            cc.name,
            a_recon_bits,
            m_bits
        );
    }
}

/// secure_128 was re-cut 2026-08-26 to the same four-prime chain as
/// secure_128_deep (CLAUDE.md, "Bootstrap Paths"). Verify this directly
/// against the live constructors rather than trusting the doc comment or
/// older issue text -- CLAUDE.md itself warns against re-deriving settled
/// facts, but a *constructor* is exactly the kind of thing that can drift
/// out from under a doc comment without anyone noticing.
#[test]
fn secure_128_is_numerically_identical_to_secure_128_deep() {
    let a = SecureConfig::secure_128();
    let b = SecureConfig::secure_128_deep();
    assert_eq!(a.config.n, b.config.n, "N differs");
    assert_eq!(a.config.primes, b.config.primes, "main prime chain differs");
    assert_eq!(a.config.t, b.config.t, "plaintext modulus differs");
    assert_eq!(
        a.config.primes.len(),
        4,
        "expected the 4-prime post-recut chain"
    );

    // And confirm the derived anchor bases (what extract_k_rns_level actually
    // uses) come out identical too, not just the FHEConfig fields.
    let ctx_a = RNSFHEContext::new(&a.config);
    let ctx_b = RNSFHEContext::new(&b.config);
    assert_eq!(
        ctx_a.dual_rns.anchor.primes, ctx_b.dual_rns.anchor.primes,
        "derived anchor bases differ between secure_128 and secure_128_deep"
    );
    println!(
        "=== secure_128 == secure_128_deep confirmed: {:?}, anchors {:?} ===",
        a.config.primes, ctx_a.dual_rns.anchor.primes
    );
}

// ============================================================================
// Part 2: squaring depth-2, seed matrix, both evaluation modes, all 4 configs.
// ============================================================================

#[test]
fn depth2_squaring_seed_matrix_symmetric_all_configs() {
    selftest_bignum_crt();
    println!("\n=== depth2_squaring_seed_matrix_symmetric_all_configs ===");
    for cc in CONFIGS {
        let secure_config = (cc.make)();
        let ctx = RNSFHEContext::new(&secure_config.config);
        let t = ctx.t;
        let anchor_primes = ctx.dual_rns.anchor.primes.clone();
        let main_primes = ctx.config.primes.clone();
        let k_primes = anchor_primes.len().min(K_RECONSTRUCTION_MAX_ANCHORS);

        for &seed in SEEDS {
            let mut rng = ShadowHarvester::with_seed(seed);
            let keys = ctx.generate_keys_dual(&mut rng);
            let base = 3u64;
            let ct0 = ctx.encrypt_dual(base, &keys.public_key, &mut rng);

            let ct1 = ctx.mul_dual_symmetric(&ct0, &ct0, &keys.secret_key);
            let dec1 = ctx.decrypt_dual(&ct1, &keys.secret_key);
            let expect1 = (base * base) % t;
            assert_eq!(
                dec1, expect1,
                "{} seed={} SYMMETRIC depth-1 squaring: got {} want {}",
                cc.name, seed, dec1, expect1
            );

            let ct2 = ctx.mul_dual_symmetric(&ct1, &ct1, &keys.secret_key);
            let dec2 = ctx.decrypt_dual(&ct2, &keys.secret_key);
            let expect2 = (expect1 * expect1) % t;
            let max_k_bits =
                max_signed_k_bits(&ct2.c0, &main_primes, &anchor_primes, k_primes, ctx.n);
            let a_recon_bits: u32 = anchor_primes[..k_primes]
                .iter()
                .map(|&p| 64 - p.leading_zeros())
                .sum();
            assert_eq!(
                dec2, expect2,
                "{} seed={} SYMMETRIC depth-2 squaring: got {} want {} \
                 (max|k| independently measured = {} bits, reconstruction capacity ~{} bits)",
                cc.name, seed, dec2, expect2, max_k_bits, a_recon_bits
            );
            assert!(
                max_k_bits + 4 < a_recon_bits,
                "{} seed={}: measured max|k|={} bits leaves < 4 bits margin under the \
                 {}-bit reconstruction capacity -- too close to the boundary to trust",
                cc.name,
                seed,
                max_k_bits,
                a_recon_bits
            );
        }
        println!(
            "  {:<16} PASSED symmetric squaring depth-2 across {} seeds",
            cc.name,
            SEEDS.len()
        );
    }
}

#[test]
fn depth2_squaring_seed_matrix_public_all_configs() {
    println!("\n=== depth2_squaring_seed_matrix_public_all_configs ===");
    for cc in CONFIGS {
        let secure_config = (cc.make)();
        let ctx = RNSFHEContext::new(&secure_config.config);
        let t = ctx.t;

        for &seed in SEEDS {
            let mut rng = ShadowHarvester::with_seed(seed);
            let keys = ctx.generate_keys_dual_full(&mut rng);
            let base = 3u64;
            let ct0 = ctx.encrypt_dual(base, &keys.public_key, &mut rng);

            let ct1 = ctx
                .mul_dual_public(&ct0, &ct0, &keys.eval_key)
                .unwrap_or_else(|e| {
                    panic!(
                        "{} seed={} PUBLIC depth-1 mul_dual_public error: {e:?}",
                        cc.name, seed
                    )
                });
            let dec1 = ctx.decrypt_dual(&ct1, &keys.secret_key);
            let expect1 = (base * base) % t;
            assert_eq!(
                dec1, expect1,
                "{} seed={} PUBLIC depth-1 squaring: got {} want {}",
                cc.name, seed, dec1, expect1
            );

            let ct2 = ctx
                .mul_dual_public(&ct1, &ct1, &keys.eval_key)
                .unwrap_or_else(|e| {
                    panic!(
                        "{} seed={} PUBLIC depth-2 mul_dual_public error: {e:?}",
                        cc.name, seed
                    )
                });
            let dec2 = ctx.decrypt_dual(&ct2, &keys.secret_key);
            let expect2 = (expect1 * expect1) % t;
            assert_eq!(
                dec2, expect2,
                "{} seed={} PUBLIC depth-2 squaring: got {} want {}",
                cc.name, seed, dec2, expect2
            );
        }
        println!(
            "  {:<16} PASSED public squaring depth-2 across {} seeds",
            cc.name,
            SEEDS.len()
        );
    }
}

// ============================================================================
// Part 3: mixed operands -- Enc(a)*Enc(b), a != b, and a non-squaring
// depth-2 chain (a*b)*(c*d). Both evaluation modes, all 4 configs.
// ============================================================================

fn mixed_case(seed: u64) -> (u64, u64, u64, u64) {
    // Four distinct small values, varied per seed so different seeds exercise
    // different plaintext magnitudes/parities, not just the same 4 numbers
    // relabeled.
    let base = (seed % 11) + 2;
    (base, base + 3, base + 5, base + 8)
}

#[test]
fn depth2_mixed_operands_symmetric_all_configs() {
    println!("\n=== depth2_mixed_operands_symmetric_all_configs ===");
    for cc in CONFIGS {
        let secure_config = (cc.make)();
        let ctx = RNSFHEContext::new(&secure_config.config);
        let t = ctx.t;

        for &seed in SEEDS_SUBSET {
            let mut rng = ShadowHarvester::with_seed(seed);
            let keys = ctx.generate_keys_dual(&mut rng);
            let (a, b, c, d) = mixed_case(seed);

            let ct_a = ctx.encrypt_dual(a, &keys.public_key, &mut rng);
            let ct_b = ctx.encrypt_dual(b, &keys.public_key, &mut rng);
            let ct_c = ctx.encrypt_dual(c, &keys.public_key, &mut rng);
            let ct_d = ctx.encrypt_dual(d, &keys.public_key, &mut rng);

            // Depth-1 mixed: Enc(a) * Enc(b), a != b.
            let ct_ab = ctx.mul_dual_symmetric(&ct_a, &ct_b, &keys.secret_key);
            let dec_ab = ctx.decrypt_dual(&ct_ab, &keys.secret_key);
            let expect_ab = (a * b) % t;
            assert_eq!(
                dec_ab, expect_ab,
                "{} seed={} SYMMETRIC depth-1 mixed a*b: {a}*{b} got {} want {}",
                cc.name, seed, dec_ab, expect_ab
            );

            // Depth-1 mixed: Enc(c) * Enc(d).
            let ct_cd = ctx.mul_dual_symmetric(&ct_c, &ct_d, &keys.secret_key);
            let dec_cd = ctx.decrypt_dual(&ct_cd, &keys.secret_key);
            let expect_cd = (c * d) % t;
            assert_eq!(
                dec_cd, expect_cd,
                "{} seed={} SYMMETRIC depth-1 mixed c*d: {c}*{d} got {} want {}",
                cc.name, seed, dec_cd, expect_cd
            );

            // Depth-2, NON-SQUARING chain: (a*b) * (c*d).
            let ct_abcd = ctx.mul_dual_symmetric(&ct_ab, &ct_cd, &keys.secret_key);
            let dec_abcd = ctx.decrypt_dual(&ct_abcd, &keys.secret_key);
            let expect_abcd = ((expect_ab as u128 * expect_cd as u128) % t as u128) as u64;
            assert_eq!(
                dec_abcd, expect_abcd,
                "{} seed={} SYMMETRIC depth-2 mixed (a*b)*(c*d): ({a}*{b})*({c}*{d}) got {} want {}",
                cc.name, seed, dec_abcd, expect_abcd
            );
        }
        println!(
            "  {:<16} PASSED symmetric mixed-operand depth-1/depth-2 across {} seeds",
            cc.name,
            SEEDS_SUBSET.len()
        );
    }
}

#[test]
fn depth2_mixed_operands_public_all_configs() {
    println!("\n=== depth2_mixed_operands_public_all_configs ===");
    for cc in CONFIGS {
        let secure_config = (cc.make)();
        let ctx = RNSFHEContext::new(&secure_config.config);
        let t = ctx.t;

        for &seed in SEEDS_SUBSET {
            let mut rng = ShadowHarvester::with_seed(seed);
            let keys = ctx.generate_keys_dual_full(&mut rng);
            let (a, b, c, d) = mixed_case(seed);

            let ct_a = ctx.encrypt_dual(a, &keys.public_key, &mut rng);
            let ct_b = ctx.encrypt_dual(b, &keys.public_key, &mut rng);
            let ct_c = ctx.encrypt_dual(c, &keys.public_key, &mut rng);
            let ct_d = ctx.encrypt_dual(d, &keys.public_key, &mut rng);

            let ct_ab = ctx
                .mul_dual_public(&ct_a, &ct_b, &keys.eval_key)
                .unwrap_or_else(|e| panic!("{} seed={} PUBLIC a*b error: {e:?}", cc.name, seed));
            let dec_ab = ctx.decrypt_dual(&ct_ab, &keys.secret_key);
            let expect_ab = (a * b) % t;
            assert_eq!(
                dec_ab, expect_ab,
                "{} seed={} PUBLIC depth-1 mixed a*b: {a}*{b} got {} want {}",
                cc.name, seed, dec_ab, expect_ab
            );

            let ct_cd = ctx
                .mul_dual_public(&ct_c, &ct_d, &keys.eval_key)
                .unwrap_or_else(|e| panic!("{} seed={} PUBLIC c*d error: {e:?}", cc.name, seed));
            let dec_cd = ctx.decrypt_dual(&ct_cd, &keys.secret_key);
            let expect_cd = (c * d) % t;
            assert_eq!(
                dec_cd, expect_cd,
                "{} seed={} PUBLIC depth-1 mixed c*d: {c}*{d} got {} want {}",
                cc.name, seed, dec_cd, expect_cd
            );

            let ct_abcd = ctx
                .mul_dual_public(&ct_ab, &ct_cd, &keys.eval_key)
                .unwrap_or_else(|e| {
                    panic!("{} seed={} PUBLIC (a*b)*(c*d) error: {e:?}", cc.name, seed)
                });
            let dec_abcd = ctx.decrypt_dual(&ct_abcd, &keys.secret_key);
            let expect_abcd = ((expect_ab as u128 * expect_cd as u128) % t as u128) as u64;
            assert_eq!(
                dec_abcd, expect_abcd,
                "{} seed={} PUBLIC depth-2 mixed (a*b)*(c*d): ({a}*{b})*({c}*{d}) got {} want {}",
                cc.name, seed, dec_abcd, expect_abcd
            );
        }
        println!(
            "  {:<16} PASSED public mixed-operand depth-1/depth-2 across {} seeds",
            cc.name,
            SEEDS_SUBSET.len()
        );
    }
}

// ============================================================================
// Part 4: boundary / large-value vectors -- plaintext values near t-1 and
// t/2, chained to depth 2 (extends the existing depth-1-only
// `test_mul_dual_symmetric_large_values_secure_128` pattern to depth-2 and to
// all 4 configs).
// ============================================================================

#[test]
fn depth2_boundary_large_values_symmetric_all_configs() {
    println!("\n=== depth2_boundary_large_values_symmetric_all_configs ===");
    for cc in CONFIGS {
        let secure_config = (cc.make)();
        let ctx = RNSFHEContext::new(&secure_config.config);
        let t = ctx.t;

        // Boundary plaintext values: max, half, and near-max-but-not-max, the
        // same corpus test_mul_dual_symmetric_large_values_secure_128 already
        // uses for depth-1, chained one multiply deeper here.
        let cases: [(u64, u64); 4] = [(t - 1, t - 1), (t - 1, 2), (t / 2, t / 2), (t - 2, t - 3)];

        for &seed in &[12345u64, 777u64] {
            let mut rng = ShadowHarvester::with_seed(seed);
            let keys = ctx.generate_keys_dual(&mut rng);

            for (a, b) in cases {
                let ct_a = ctx.encrypt_dual(a, &keys.public_key, &mut rng);
                let ct_b = ctx.encrypt_dual(b, &keys.public_key, &mut rng);

                let ct1 = ctx.mul_dual_symmetric(&ct_a, &ct_b, &keys.secret_key);
                let dec1 = ctx.decrypt_dual(&ct1, &keys.secret_key);
                let expect1 = ((a as u128 * b as u128) % t as u128) as u64;
                assert_eq!(
                    dec1, expect1,
                    "{} seed={} SYMMETRIC boundary depth-1: {a}*{b} got {} want {}",
                    cc.name, seed, dec1, expect1
                );

                // Depth-2: square the depth-1 result -- worst case, since the
                // depth-1 output already carries a near-maximal true value.
                let ct2 = ctx.mul_dual_symmetric(&ct1, &ct1, &keys.secret_key);
                let dec2 = ctx.decrypt_dual(&ct2, &keys.secret_key);
                let expect2 = ((expect1 as u128 * expect1 as u128) % t as u128) as u64;
                assert_eq!(
                    dec2, expect2,
                    "{} seed={} SYMMETRIC boundary depth-2: ({a}*{b})^2 got {} want {}",
                    cc.name, seed, dec2, expect2
                );
            }
        }
        println!(
            "  {:<16} PASSED symmetric boundary-value depth-2 chains (4 cases x 2 seeds)",
            cc.name
        );
    }
}

/// Public-mode spot-check of the same boundary corpus -- cheaper subset (one
/// seed) since public-mode multiply is materially more expensive per op, but
/// covering all 4 configs and the same near-t-1 / half-t / near-max cases.
#[test]
fn depth2_boundary_large_values_public_all_configs() {
    println!("\n=== depth2_boundary_large_values_public_all_configs ===");
    for cc in CONFIGS {
        let secure_config = (cc.make)();
        let ctx = RNSFHEContext::new(&secure_config.config);
        let t = ctx.t;
        let cases: [(u64, u64); 3] = [(t - 1, t - 1), (t / 2, t / 2), (t - 2, t - 3)];

        let mut rng = ShadowHarvester::with_seed(12345);
        let keys = ctx.generate_keys_dual_full(&mut rng);

        for (a, b) in cases {
            let ct_a = ctx.encrypt_dual(a, &keys.public_key, &mut rng);
            let ct_b = ctx.encrypt_dual(b, &keys.public_key, &mut rng);

            let ct1 = ctx
                .mul_dual_public(&ct_a, &ct_b, &keys.eval_key)
                .unwrap_or_else(|e| panic!("{} PUBLIC boundary depth-1 error: {e:?}", cc.name));
            let dec1 = ctx.decrypt_dual(&ct1, &keys.secret_key);
            let expect1 = ((a as u128 * b as u128) % t as u128) as u64;
            assert_eq!(
                dec1, expect1,
                "{} PUBLIC boundary depth-1: {a}*{b} got {} want {}",
                cc.name, dec1, expect1
            );

            let ct2 = ctx
                .mul_dual_public(&ct1, &ct1, &keys.eval_key)
                .unwrap_or_else(|e| panic!("{} PUBLIC boundary depth-2 error: {e:?}", cc.name));
            let dec2 = ctx.decrypt_dual(&ct2, &keys.secret_key);
            let expect2 = ((expect1 as u128 * expect1 as u128) % t as u128) as u64;
            assert_eq!(
                dec2, expect2,
                "{} PUBLIC boundary depth-2: ({a}*{b})^2 got {} want {}",
                cc.name, dec2, expect2
            );
        }
        println!(
            "  {:<16} PASSED public boundary-value depth-2 chains (3 cases)",
            cc.name
        );
    }
}

// ============================================================================
// Part 5: witness-lane cross-check for the 10-anchor configs (secure_192,
// secure_256). Production reconstructs k from the first 8 anchors and treats
// anchors 9-10 as witnesses that must independently agree
// (extract_k_rns_level_cached's own witness-dissent check). This
// independently re-derives that agreement from scratch on real depth-2
// output, rather than trusting the in-crate check alone.
// ============================================================================

#[test]
fn depth2_witness_anchor_agreement_secure_192_and_256() {
    println!("\n=== depth2_witness_anchor_agreement_secure_192_and_256 ===");
    for cc in CONFIGS
        .iter()
        .filter(|c| c.name == "secure_192" || c.name == "secure_256")
    {
        let secure_config = (cc.make)();
        let ctx = RNSFHEContext::new(&secure_config.config);
        let anchor_primes = ctx.dual_rns.anchor.primes.clone();
        let main_primes = ctx.config.primes.clone();
        let k_primes = anchor_primes.len().min(K_RECONSTRUCTION_MAX_ANCHORS);
        assert!(
            anchor_primes.len() > k_primes,
            "{}: expected extra witness anchors beyond the {}-anchor reconstruction basis, \
             found only {} total anchors",
            cc.name,
            k_primes,
            anchor_primes.len()
        );

        let mut rng = ShadowHarvester::with_seed(12345);
        let keys = ctx.generate_keys_dual(&mut rng);
        let base = 3u64;
        let ct0 = ctx.encrypt_dual(base, &keys.public_key, &mut rng);
        let ct1 = ctx.mul_dual_symmetric(&ct0, &ct0, &keys.secret_key);
        let ct2 = ctx.mul_dual_symmetric(&ct1, &ct1, &keys.secret_key);
        assert_eq!(ctx.decrypt_dual(&ct2, &keys.secret_key), 81);

        let mut mismatches = 0usize;
        let mut main_residues = vec![0u64; main_primes.len()];
        let mut anchor_residues = vec![0u64; k_primes];
        for i in 0..ctx.n {
            for (j, limb) in ct2.c0.main.iter().enumerate() {
                main_residues[j] = limb[i];
            }
            for (j, limb) in ct2.c0.anchor.iter().take(k_primes).enumerate() {
                anchor_residues[j] = limb[i];
            }
            let (is_neg, mag) = reconstruct_signed_k(
                &main_residues,
                &anchor_residues,
                &main_primes,
                &anchor_primes[..k_primes],
            );

            // Witness check, matching extract_k_rns_level_cached's own logic
            // EXACTLY: the comparison is between the reconstructed k's
            // residue at the witness anchor and that witness anchor's OWN
            // k_rns value (computed from ITS ciphertext residue via the same
            // per-anchor k formula) -- NOT the ciphertext's raw anchor
            // residue directly (which represents v, not k, and is a
            // different quantity entirely).
            let v_m = crt_reconstruct_mag(&main_residues, &main_primes);
            let m_level = product_mag(&main_primes);
            for (w, &aw) in anchor_primes.iter().enumerate().skip(k_primes) {
                let m_level_mod_aw = mag_mod_u64(m_level, aw);
                let inv = mod_inverse(m_level_mod_aw, aw);
                let v_m_mod_aw = mag_mod_u64(v_m, aw);
                let v_anchor_w = ct2.c0.anchor[w][i];
                let diff = (v_anchor_w + aw - v_m_mod_aw) % aw;
                let k_rns_witness = ((diff as u128 * inv as u128) % aw as u128) as u64;

                let mag_mod = mag_mod_u64(mag, aw);
                let expected = if is_neg && mag_mod != 0 {
                    aw - mag_mod
                } else {
                    mag_mod
                };
                if expected != k_rns_witness {
                    mismatches += 1;
                }
            }
        }
        assert_eq!(
            mismatches, 0,
            "{}: {} witness-anchor disagreements out of {} coefficients on the depth-2 output \
             -- k has exceeded the 8-anchor reconstruction capacity",
            cc.name, mismatches, ctx.n
        );
        println!(
            "  {:<16} PASSED: 0/{} witness disagreements on depth-2 output (anchors {}..{})",
            cc.name,
            ctx.n,
            k_primes,
            anchor_primes.len()
        );
    }
}
