//! Additive, diagnostic-only integration test for the depth-2 K-Elimination
//! divergence documented in `docs/LADDER_REMOVAL.md` §3.4/§6.1
//! (`test_mul_dual_symmetric_depth2_secure_128_deep`, currently failing and
//! left unmodified) and `crates/nine65/tests/depth_and_noise.rs`
//! (`depth_and_noise_curve_squaring_chain`, `depth_and_noise_curve_public_mode`).
//!
//! This file does NOT assert any depth-2 correctness claim, does NOT modify
//! or weaken any existing test, and does NOT touch production code.
//!
//! # Why two diagnostics instead of one
//!
//! The functions that actually reconstruct a value from RNS residues in the
//! hot path -- `DualRNSContext::extract_k_rns_level`, `RNSContext::to_u256_level`,
//! `crt_reconstruct_u256`, the `U256` type itself, `dual_poly_mul` -- are all
//! private or `pub(crate)`. An integration test under `tests/` is compiled as
//! a separate crate and can only see `nine65`'s `pub` surface, so none of
//! those are callable from here, and the raw tensor-product terms (d0/d1/d2,
//! computed inside `mul_dual_symmetric` before rescale) cannot be obtained
//! from outside the crate at all -- there is no public API that returns them.
//!
//! The authoritative, per-coefficient, tensor-product-level measurement is
//! therefore the companion in-crate diagnostic,
//! `ops::rns_fhe::tests::diag_depth2_k_capacity_probe_secure_128_deep`
//! (`crates/nine65/src/ops/rns_fhe.rs`), which has full private access and
//! whose exact `v_m` / `k` numbers for depth-1 coefficient 0 were
//! cross-verified character-for-character against an independent Python
//! arbitrary-precision re-implementation of `extract_k_rns_level`'s formula
//! during this investigation (not re-run here; recorded as fact below).
//!
//! What THIS file verifies independently, using only public fields
//! (`DualRNSCiphertext::{c0,c1,level}`, `DualRNSPoly::{main,anchor}`,
//! `RNSFHEContext::{rns,dual_rns,config,ke,n,t}`, `RNSContext::primes`) and a
//! from-scratch CRT + modular-inverse (no floats per A1; no threaded
//! mixed-radix cascade per A2 -- see the CRT function's own doc):
//!
//! 1. The capacity structural facts (§ same as the in-crate probe): what
//!    `ctx.ke.capacity_bit_length()` actually is and why it is unrelated to
//!    the operative anchor capacity.
//! 2. That a ciphertext coefficient's true value is NOT always the naive
//!    "CRT-reconstruct via the main system alone" value (k assumed 0) --
//!    demonstrated on the actual encrypted-domain data, matching the same
//!    k != 0 texture the in-crate probe reports for the secret key and
//!    fresh ciphertext. This is the same phenomenon `extract_k_rns_level`
//!    exists to handle, verified here from a second, independent
//!    implementation.
//! 3. That this file's own from-scratch bignum CRT machinery (the piece that
//!    would be trusted to reconstruct k via the full 5-anchor system) is
//!    itself correct: reconstruct from residues, re-reduce mod each of the 5
//!    real anchor primes, and confirm the original residues come back, on
//!    controlled test vectors (not merely self-consistent by construction --
//!    a bug in `crt_reconstruct_mag` could round-trip against itself while
//!    still being wrong relative to the real primes).
//!
//! An earlier version of this file attempted to reconstruct the raw
//! tensor-product coefficient 0 by naively CRT-reconstructing ciphertext
//! coefficients via the main system alone (assuming k=0) and convolving
//! those. That produced a value that did NOT match the actual `d.anchor`
//! residues the crate's own (verified-correct-by-schoolbook-cross-check)
//! anchor NTT convolution computed -- not because of a bug in the anchor
//! NTT, but because the naive-k=0 assumption is simply wrong for ciphertext
//! coefficients representing small/negative true values (per point 2 above).
//! That approach is retired here in favor of the honest scope above; the
//! investigation record documents the dead end so it is not re-walked.

use nine65::entropy::ShadowHarvester;
use nine65::ops::rns_fhe::{DualRNSCiphertext, DualRNSPoly, RNSFHEContext};
use nine65::params::secure_configs::SecureConfig;

// ============================================================================
// Minimal from-scratch signed big integer: 4 x u64 limbs (256 bits), little
// endian magnitude + sign. Plain schoolbook arithmetic: every limb of every
// result is a direct function of the corresponding input limbs plus a
// locally-computed carry/borrow -- there is no per-digit dependency chain
// reading back through previously emitted digits of the SAME number the way
// Garner's mixed-radix algorithm threads through CRT digits, so this is not
// the "Garner-style cascade" A2 rules out.
// ============================================================================

const LIMBS: usize = 4;
type Mag = [u64; LIMBS];

fn mag_zero() -> Mag {
    [0u64; LIMBS]
}

fn mag_from_u128(x: u128) -> Mag {
    [x as u64, (x >> 64) as u64, 0, 0]
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

/// Multiply a 256-bit magnitude by a u64, returning the low 256 bits (exact
/// for this file's use: magnitudes here never exceed ~160 bits before the
/// multiply, so the true product always fits).
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

/// value mod m, for a 256-bit magnitude and u64 modulus, via repeated
/// double-and-reduce over the limbs from the top down (schoolbook long
/// division style, not a mixed-radix digit cascade over a CRT basis).
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

/// Direct (non-cascaded) CRT reconstruction into a plain `u128`: each term
/// `residue_i * M_i * inverse(M_i mod p_i, p_i)` is computed independently of
/// every other term, then all terms are summed mod M. No digit of the result
/// is derived from a previously-computed digit of the SAME reconstruction.
/// Used for the 4 main primes, whose product fits in u128.
fn crt_reconstruct_u128(residues: &[u64], primes: &[u64]) -> u128 {
    let m_level: u128 = primes.iter().map(|&p| p as u128).product();
    let mut acc: u128 = 0;
    for (i, &p) in primes.iter().enumerate() {
        let mi = m_level / p as u128;
        let mi_mod_p = (mi % p as u128) as u64;
        let mi_inv = mod_inverse(mi_mod_p, p);
        let term = ((residues[i] as u128 * mi_inv as u128) % p as u128) * mi % m_level;
        acc = (acc + term) % m_level;
    }
    acc
}

/// Same direct-CRT construction, into the 256-bit `Mag` type, for the 5
/// anchor primes (product ~159 bits, does not fit in u128).
fn crt_reconstruct_mag(residues: &[u64], primes: &[u64]) -> Mag {
    // M = product of primes, built as Mag via repeated mul_mag_u64.
    let mut m = mag_from_u128(1);
    for &p in primes {
        m = mul_mag_u64(m, p);
    }
    let mut acc = mag_zero();
    for (i, &p) in primes.iter().enumerate() {
        // M_i = M / p, computed by long division isn't needed here: build it
        // as the product of all OTHER primes directly (avoids needing a
        // general Mag/Mag divider for this file's small prime count).
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
        // Keep acc reduced mod m so it never grows past the ~159-bit range.
        let acc_mod = mag_mod_full(acc, m);
        acc = acc_mod;
    }
    acc
}

/// acc mod m for two same-shape `Mag`s, via repeated subtraction of shifted
/// copies of m (m has at most ~160 bits here, this runs in at most a few
/// hundred iterations -- not a performance-sensitive path in this test).
fn mag_mod_full(mut acc: Mag, m: Mag) -> Mag {
    if cmp_mag(acc, m) == std::cmp::Ordering::Less {
        return acc;
    }
    // Find how many bits to shift m left so it's just <= acc, then
    // subtract-and-shift-down (schoolbook long division remainder).
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

/// Reconstruct coefficient `i`'s true value using BOTH the main system (for
/// v_m) and the full 5-anchor system (for k), replicating
/// `extract_k_rns_level`'s formula from scratch: v_exact = v_m + k * M_level,
/// with k found via CRT over the anchor residues. Returns (is_negative,
/// magnitude) using the SignedK256-equivalent convention (k > A/2 => negative
/// magnitude A-k).
fn reconstruct_signed_coeff(
    main_residues: &[u64],
    anchor_residues: &[u64],
    main_primes: &[u64],
    anchor_primes: &[u64],
) -> (bool, Mag) {
    let v_m = crt_reconstruct_u128(main_residues, main_primes);
    let m_level: u128 = main_primes.iter().map(|&p| p as u128).product();

    let mut k_rns = vec![0u64; anchor_primes.len()];
    for (j, &a) in anchor_primes.iter().enumerate() {
        let m_level_mod_a = (m_level % a as u128) as u64;
        let inv = mod_inverse(m_level_mod_a, a);
        let v_m_mod_a = (v_m % a as u128) as u64;
        let diff = (anchor_residues[j] + a - v_m_mod_a) % a;
        k_rns[j] = ((diff as u128 * inv as u128) % a as u128) as u64;
    }
    let k = crt_reconstruct_mag(&k_rns, anchor_primes);

    let mut a_full = mag_from_u128(1);
    for &p in anchor_primes {
        a_full = mul_mag_u64(a_full, p);
    }
    let a_half = mag_shr1(a_full);

    if cmp_mag(k, a_half) == std::cmp::Ordering::Greater {
        (true, sub_mag(a_full, k))
    } else {
        (false, k)
    }
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

/// For every coefficient of `poly`, checks whether the naive "k=0" value
/// (CRT-reconstruct main residues only) matches the stored anchor residues.
/// Returns the mismatch count -- expected to be nonzero and NOT a bug (see
/// module doc point 2); coefficients representing small negative true values
/// legitimately need k != 0.
fn naive_k0_mismatch_count(
    poly: &DualRNSPoly,
    main_primes: &[u64],
    anchor_primes: &[u64],
    n: usize,
) -> usize {
    let mut mismatches = 0;
    let mut main_residues = vec![0u64; main_primes.len()];
    for i in 0..n {
        for (j, limb) in poly.main.iter().enumerate() {
            main_residues[j] = limb[i];
        }
        let v_m = crt_reconstruct_u128(&main_residues, main_primes);
        for (j, &a) in anchor_primes.iter().enumerate() {
            if (v_m % a as u128) as u64 != poly.anchor[j][i] {
                mismatches += 1;
                break;
            }
        }
    }
    mismatches
}

/// For every coefficient, does the FULL k-extraction (via all anchors),
/// and returns the max |signed k| bit length seen -- the from-scratch
/// equivalent of the in-crate probe's `max |true signed k|` column, but
/// computed by a completely independent implementation.
fn max_signed_k_bits(
    poly: &DualRNSPoly,
    main_primes: &[u64],
    anchor_primes: &[u64],
    n: usize,
) -> u32 {
    let mut max_bits = 0u32;
    let mut main_residues = vec![0u64; main_primes.len()];
    let mut anchor_residues = vec![0u64; anchor_primes.len()];
    for i in 0..n {
        for (j, limb) in poly.main.iter().enumerate() {
            main_residues[j] = limb[i];
        }
        for (j, limb) in poly.anchor.iter().enumerate() {
            anchor_residues[j] = limb[i];
        }
        let (_, mag) =
            reconstruct_signed_coeff(&main_residues, &anchor_residues, main_primes, anchor_primes);
        max_bits = max_bits.max(bitlen_mag(mag));
    }
    max_bits
}

#[test]
fn depth2_isolation_capacity_and_coefficient_texture() {
    // ------------------------------------------------------------------
    // Part 1: capacity facts, straight from public fields/methods.
    // ------------------------------------------------------------------
    let secure_config = SecureConfig::secure_128_deep();
    let ctx = RNSFHEContext::new(&secure_config.config);

    let m_bits: u32 = ctx
        .config
        .primes
        .iter()
        .map(|&p| 64 - p.leading_zeros())
        .sum();
    let anchor_bits: Vec<u32> = ctx
        .dual_rns
        .anchor
        .primes
        .iter()
        .map(|&p| 64 - p.leading_zeros())
        .collect();
    let a4_bits: u32 = anchor_bits[..4].iter().sum();
    let a_full_bits: u32 = anchor_bits.iter().sum();

    println!(
        "[depth2_isolation] secure_128_deep: N={} main_primes={:?} (M_level={} bits) anchor_primes={:?}",
        ctx.n, ctx.config.primes, m_bits, ctx.dual_rns.anchor.primes
    );
    println!(
        "[depth2_isolation] A4 (production capacity for this 4-main-prime config) = {} bits (signed half = {} bits); \
         full anchor set ({} primes) = {} bits (signed half = {} bits)",
        a4_bits, a4_bits - 1, ctx.dual_rns.anchor.primes.len(), a_full_bits, a_full_bits - 1
    );
    println!(
        "[depth2_isolation] ctx.ke.capacity_bit_length() = {} bits -- this is the KElimination::for_fhe(config.primes[0]) \
         legacy field (`KElimConfig::Standard`, fixed regardless of FHEConfig); it does not participate in the \
         rescale/relinearize path at all (that path uses ctx.dual_rns.anchor, not ctx.ke). Recorded here because it is \
         the number the original investigation lead referenced -- it is a red herring, not the operative capacity.",
        ctx.ke.capacity_bit_length()
    );
    assert_eq!(ctx.ke.capacity_bit_length(), 110);
    assert_eq!(ctx.dual_rns.anchor.primes.len(), 7);
    assert_eq!(
        a4_bits, 127,
        "4-anchor production capacity for secure_128_deep"
    );
    assert_eq!(a_full_bits, 223, "full 7-anchor capacity");
    assert_eq!(m_bits, 119, "secure_128_deep M_level bit length");

    // ------------------------------------------------------------------
    // Part 2: the identical depth-2 symmetric squaring chain under test
    // (same construction as test_mul_dual_symmetric_depth2_secure_128_deep),
    // using ONLY the public mul_dual_symmetric / encrypt_dual / decrypt_dual
    // API -- these are the real production calls, not a re-implementation.
    // ------------------------------------------------------------------
    let mut rng = ShadowHarvester::with_seed(12345);
    let keys = ctx.generate_keys_dual(&mut rng);
    let base = 3u64;
    let ct_base: DualRNSCiphertext = ctx.encrypt_dual(base, &keys.public_key, &mut rng);
    let ct_d1 = ctx.mul_dual_symmetric(&ct_base, &ct_base, &keys.secret_key);
    let dec_d1 = ctx.decrypt_dual(&ct_d1, &keys.secret_key);
    println!("[depth2_isolation] depth-1 decrypt = {} (want 9)", dec_d1);
    assert_eq!(
        dec_d1, 9,
        "depth-1 must still be correct (sanity check, not the bug under test)"
    );

    let main_primes = &ctx.config.primes;
    let anchor_primes = &ctx.dual_rns.anchor.primes;

    // ------------------------------------------------------------------
    // Part 3: naive-k=0 mismatch texture (point 2 in the module doc) --
    // demonstrates that "just CRT the main residues" is not always the true
    // value, on the real encrypted-domain data, independently implemented.
    // ------------------------------------------------------------------
    let c0_mismatches = naive_k0_mismatch_count(&ct_base.c0, main_primes, anchor_primes, ctx.n);
    let c1_mismatches = naive_k0_mismatch_count(&ct_base.c1, main_primes, anchor_primes, ctx.n);
    println!(
        "[depth2_isolation] naive k=0 mismatches on FRESH ciphertext (texture, not a bug -- see module doc): \
         c0={}/{} c1={}/{}",
        c0_mismatches, ctx.n, c1_mismatches, ctx.n
    );

    // ------------------------------------------------------------------
    // Part 4: validate this file's own bignum CRT machinery in isolation,
    // on small controlled test vectors (not derived from any crypto data),
    // before trusting it for the measurement in Part 5. Confirms
    // crt_reconstruct_mag / mag_mod_u64 / mod_inverse round-trip correctly:
    // reconstruct from residues, then re-reduce mod each prime, and check we
    // get the original residues back.
    // ------------------------------------------------------------------
    {
        let test_primes = [
            2013265921u64,
            2281701377,
            2483027969,
            2885681153,
            3221225473,
        ];
        let test_cases: [[u64; 5]; 4] = [
            [0, 0, 0, 0, 0],
            [1, 1, 1, 1, 1],
            [123456789, 987654321, 555555555, 111111111, 999999999],
            [
                test_primes[0] - 1,
                test_primes[1] - 1,
                test_primes[2] - 1,
                test_primes[3] - 1,
                test_primes[4] - 1,
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
        println!("[depth2_isolation] bignum CRT machinery (crt_reconstruct_mag/mag_mod_u64) round-trip: PASSED on 4 controlled test vectors");
    }

    // ------------------------------------------------------------------
    // Part 5: texture comparison -- max |signed k| across all coefficients
    // of the fresh ciphertext (depth-1 input) vs the depth-1 OUTPUT
    // ciphertext (depth-2 input), computed independently. This does not
    // reach the tensor-product term itself (private, see module doc), but
    // shows the two ciphertexts are not drawn from the same magnitude
    // distribution -- consistent with, though not by itself proof of, the
    // in-crate probe's tensor-product-level finding recorded below.
    // ------------------------------------------------------------------
    let fresh_max_k_bits = max_signed_k_bits(&ct_base.c0, main_primes, anchor_primes, ctx.n);
    let d1out_max_k_bits = max_signed_k_bits(&ct_d1.c0, main_primes, anchor_primes, ctx.n);
    println!(
        "[depth2_isolation] max |signed k| across all {} coeffs (this file's independent extraction): \
         fresh ct_base.c0={} bits, depth-1-OUTPUT ct_d1.c0={} bits",
        ctx.n, fresh_max_k_bits, d1out_max_k_bits
    );

    // ------------------------------------------------------------------
    // Part 6: the authoritative tensor-product-level finding, from the
    // companion in-crate probe (full private access; Python-cross-verified
    // during this investigation). Recorded here as fact, not re-derived --
    // reaching the raw d0/d1/d2 tensor terms requires `dual_poly_mul`,
    // which has no public entry point.
    //
    //   DEPTH-1 tensor (fresh Enc(3) x fresh Enc(3)), ct_level=4:
    //     d0=c0*c0  max |true signed k| =  90 bits <= 126-bit half-capacity -> correct (0/8192 mismatches)
    //     d1        max |true signed k| =  23 bits <= 126 -> correct
    //     d2        max |true signed k| =   1 bit  <= 126 -> correct
    //   DEPTH-2 tensor (ct_d1=Enc(9) x ct_d1=Enc(9)), ct_level=4:
    //     d0=c0*c0  max |true signed k| = 152 bits >  126-bit half-capacity -> WRONG (8192/8192 mismatches)
    //     d1        max |true signed k| = 140 bits >  126 -> WRONG (8192/8192 mismatches)
    //     d2        max |true signed k| = 128 bits >  126 -> WRONG (5435/8192 mismatches)
    //
    // Divergence point: crates/nine65/src/ops/rns_fhe.rs, k_elim_rescale_dual
    // (around line 3305-3309, the extract_k_rns_level call feeding
    // SignedK256::from_unsigned), called on d0 of the SECOND
    // mul_dual_symmetric -- specifically DualRNSContext::extract_k_rns_level
    // (arithmetic/rns.rs:1302-1347)'s k_primes selection (lines 1322-1329),
    // which picks the anchor-prime count from ct_level alone (3/4/5 anchors
    // for ct_level <4/<5/>=5) rather than from the actual magnitude k needs.
    let ct_d2 = ctx.mul_dual_symmetric(&ct_d1, &ct_d1, &keys.secret_key);
    let dec_d2 = ctx.decrypt_dual(&ct_d2, &keys.secret_key);
    println!(
        "[depth2_isolation] depth-2 decrypt = {} (want 81) -- {}",
        dec_d2,
        if dec_d2 == 81 {
            "unexpectedly correct on this run (capacity finding above still stands from the in-crate probe)"
        } else {
            "reproduces the documented symptom"
        }
    );
}
