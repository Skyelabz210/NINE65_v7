//! CLIENT-generated exact witness ciphertexts for the domain of a fixed
//! coefficientwise F(U,D). They are ideal research fixtures, not encrypted
//! nonlinear-gate implementations or production ciphertext producers.

use super::*;

fn ceil_signed(a: i128, b: i128) -> i128 {
    -(-a).div_euclid(b)
}

fn witness_terms(t: i64, k: i64, q: i128, denominator: i128) -> Vec<i128> {
    assert!(t * k >= 0 && (t != 0 || k == 0));
    let mut cells = Vec::new();
    for i in 0..97 {
        let r = t.unsigned_abs() as i128 / 97 + i128::from((i as u64) < t.unsigned_abs() % 97);
        let low = [99i128, 121]
            .iter()
            .map(|&m| ceil_signed(m * q * (2 * r - 1), 65536))
            .max()
            .unwrap()
            .max(-(q / 2));
        let high = [99i128, 121]
            .iter()
            .map(|&m| ceil_signed(m * q * (2 * r + 1), 65536) - 1)
            .min()
            .unwrap()
            .min(q / 2);
        assert!(low <= high);
        cells.push((low, high));
    }
    let low: i128 = cells.iter().map(|v| v.0).sum();
    let high: i128 = cells.iter().map(|v| v.1).sum();
    let target = (q * k.unsigned_abs() as i128).clamp(low, high);
    assert!((target - q * k.unsigned_abs() as i128).abs() <= q / denominator);
    let mut extra = target - low;
    let sign = if t < 0 { -1 } else { 1 };
    let values = cells
        .iter()
        .map(|&(a, b)| {
            let add = extra.min(b - a);
            extra -= add;
            sign * (a + add)
        })
        .collect();
    assert_eq!(extra, 0);
    values
}

// CLIENT only. Set one desired phase coefficient to p^{-1}*g mod Q and
// all others to zero. Thus the entire source polynomial has V<=|g|.
fn client_fixture(
    ctx: &RNSFHEContext,
    keys: &RNSKeySet,
    trits: &[i8],
    terms: &[i128],
    k: i64,
    rng: &mut ShadowHarvester,
) -> (RNSCiphertext, i128, u64) {
    let q: i128 = ctx.config.primes.iter().map(|&q| q as i128).product();
    let g = terms.iter().sum::<i128>() - q * k as i128;
    let phase = (inverse(ctx.t, q as u64) as i128 * g).rem_euclid(q) as u64;
    let support: Vec<_> = trits.iter().enumerate().filter(|(_, s)| **s != 0).collect();
    assert_eq!(support.len(), 96);
    let mut mask: Vec<Vec<u64>> = ctx
        .config
        .primes
        .iter()
        .map(|&q| (0..ctx.n).map(|_| rng.next_u64() % q).collect())
        .collect();
    for (a, &(index, &s)) in support.iter().enumerate() {
        let coefficient = (ctx.n - index) % ctx.n;
        let sign = s as i128 * if index == 0 { 1 } else { -1 };
        for (lane, &prime) in ctx.config.primes.iter().enumerate() {
            mask[lane][coefficient] = (terms[a + 1] * sign).rem_euclid(prime as i128) as u64;
            mask[lane][coefficient] = (mask[lane][coefficient] as u128
                * inverse(ctx.t, prime) as u128
                % prime as u128) as u64;
        }
    }
    let secret = ordinary(ctx, &keys.secret_key.s);
    let c0: Vec<_> = ctx
        .config
        .primes
        .iter()
        .enumerate()
        .map(|(lane, &prime)| {
            ctx.ntt_engines[lane]
                .multiply(&mask[lane], &secret[lane])
                .iter()
                .enumerate()
                .map(|(j, &v)| {
                    (if j == 0 { phase as i128 } else { 0 } - v as i128).rem_euclid(prime as i128)
                        as u64
                })
                .collect()
        })
        .collect();
    (
        RNSCiphertext {
            c0: montgomery(ctx, c0),
            c1: montgomery(ctx, mask),
            num_primes: ctx.config.primes.len(),
        },
        g,
        phase,
    )
}

fn check_witnesses(n: usize, points: &[(i64, i64, i128)]) {
    let mut config = SecureConfig::secure_128().into_config();
    config.n = n;
    config.primes.truncate(2);
    config.security_bits = 0;
    config.name = "CLIENT ideal chart-domain witness; NOT production encryption";
    let ctx = RNSFHEContext::try_new(&config).unwrap();
    let mut rng = ShadowHarvester::with_seed(0x4741_5445_444f_4d41 + n as u64);
    let trits = balanced_source(n, 96, &mut rng);
    let keys = sparse_keys(&ctx, &trits, &mut rng);
    let q: i128 = ctx.config.primes.iter().map(|&q| q as i128).product();
    let mut maximum_g = 0;
    for &(t, k, denominator) in points {
        let terms = witness_terms(t, k, q, denominator);
        let (input, g, phase) = client_fixture(&ctx, &keys, &trits, &terms, k, &mut rng);
        assert!(g.unsigned_abs() <= q as u128 / denominator as u128);
        maximum_g = maximum_g.max(g.unsigned_abs());
        // Full ring, every lane: these CLIENT fixtures satisfy their bound
        // everywhere, not just at the coefficient used by the degree proof.
        for (lane, values) in decrypted_phase_residues(&ctx, &input, &keys)
            .iter()
            .enumerate()
        {
            for (j, &v) in values.iter().enumerate() {
                assert_eq!(
                    v,
                    if j == 0 {
                        phase % ctx.config.primes[lane]
                    } else {
                        0
                    }
                );
            }
        }
        let message = (ctx.t as i128 * phase as i128 - g) / q;
        assert_eq!(ctx.t as i128 * phase as i128 - q * message, g);
        let mut views = Vec::new();
        let mut actual_lift = None;
        for coordinate in [99, 121] {
            let c0 = preprocess_for_clock(&ctx, &input.c0, coordinate, 16384);
            let c1 = preprocess_for_clock(&ctx, &input.c1, coordinate, 16384);
            let mut z = c0.clock[0] as i128;
            let mut affine = c0.a[0] as i128;
            for (i, &s) in trits.iter().enumerate().filter(|(_, s)| **s != 0) {
                let j = (ctx.n - i) % ctx.n;
                let sign = s as i128 * if i == 0 { 1 } else { -1 };
                z += sign * c1.clock[j] as i128;
                affine += sign * c1.a[j] as i128;
            }
            assert_eq!(z, t as i128);
            assert_eq!((message - affine - k as i128).rem_euclid(ctx.t as i128), 0);
            assert_eq!(
                (coordinate as i128 * z + 16384).div_euclid(32768),
                k as i128
            );
            actual_lift = Some(k);
            views.push(z);
        }
        assert_eq!(
            (-4 * views[0] + 5 * views[1], 9 * views[0] - 11 * views[1]),
            (t as i128, -2 * t as i128)
        );
        assert_eq!(actual_lift, Some(k));
    }
    eprintln!("fixed paired-LUT native-domain witnesses: sourceN{n}, Q60, H96 balanced, {} CLIENT ideal ciphertexts; every coefficient/lane phase checked, max |g|={maximum_g}, true residue preprocessing gives Z99=Z121=t, U=t,D=-2t and exact K for every witness; input-independent polynomial restriction only, NOT an encrypted gate",points.len());
}

#[test]
fn paired_lut_valid_source_edge_fixtures_are_not_small_period_aliases() {
    check_witnesses(
        128,
        &[
            (-336, -1, 16),
            (-262, -1, 16),
            (-62, 0, 16),
            (0, 0, 16),
            (62, 0, 16),
            (262, 1, 16),
            (336, 1, 16),
            (-323, -1, 64),
            (48, 0, 64),
            (323, 1, 64),
        ],
    );
}

#[test]
#[ignore = "opt-in 464 native valid ciphertext witnesses for fixed paired-LUT degree constraints"]
fn paired_lut_native_ciphertexts_realize_both_restriction_domains() {
    let mut points = Vec::new();
    for (den, edge, low, high) in [(16, 62, 262, 336), (64, 48, 278, 323)] {
        for t in -high..=-low {
            points.push((t, -1, den));
        }
        for t in -edge..=edge {
            points.push((t, 0, den));
        }
        for t in low..=high {
            points.push((t, 1, den));
        }
    }
    assert_eq!(points.len(), 464);
    check_witnesses(8192, &points);
}
