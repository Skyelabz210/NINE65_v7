// Slot-batching probe (ADDITIVE — measures the control only).
//
// Run with:
//   RAYON_NUM_THREADS=1 cargo run -p nine65 --release --example slot_batching_probe
//
// WHAT THIS MEASURES (evidence):
//   - scalar mul_ct on secure_128 (N=8192, t=65537), slots=1, warm steady state.
//   - correctness dec(E(5)*E(7)) == 35.
//   - plaintext-value independence of mul latency (m=1 vs m=t-1), a weak but
//     real empirical check that the pipeline is data-independent.
//
// WHAT THIS DOES NOT MEASURE (and why):
//   CRT slot batching is NOT IMPLEMENTED in this workspace. There is no NTT over
//   the plaintext modulus t, no slot encoder, and no vector-shaped
//   encrypt/decrypt. encrypt_dual takes `m: u64` and hard-codes
//   `m_coeffs = vec![0u64; n]`; decrypt_dual reads `limb[0]` only. Therefore a
//   PACKED multiply cannot be timed here. The amortized per-slot figure this
//   program prints is a PROJECTION (measured scalar latency / max_slots), not a
//   measurement. It is labelled as such in the output.
//
// No existing algorithm is modified by this file. It is read-only w.r.t. the
// crate: it only calls the public API.

use nine65::entropy::ShadowHarvester;
use nine65::ops::rns_fhe::RNSFHEContext;
use nine65::ops::BatchEncoder;
use nine65::params::secure_configs::SecureConfig;
use nine65::params::FHEConfig;
use std::time::Instant;

// n=20 so that nearest-rank p95 (rank = ceil(0.95*20) = 19) is the
// second-largest sample rather than degenerating to the maximum, as it would
// at n=15 (rank = ceil(14.25) = 15 = max).
const WARMUP: usize = 5;
const SAMPLES: usize = 20;

/// Exact median as (numerator, denominator). No floats.
fn median_exact(sorted: &[u64]) -> (u128, u128) {
    let n = sorted.len();
    assert!(n > 0);
    if n % 2 == 1 {
        (sorted[n / 2] as u128, 1)
    } else {
        (sorted[n / 2 - 1] as u128 + sorted[n / 2] as u128, 2)
    }
}

/// p95 by nearest-rank: rank = ceil(95*n/100), 1-based. Integer only.
fn p95_nearest_rank(sorted: &[u64]) -> u64 {
    let n = sorted.len();
    let rank = (95 * n + 99) / 100;
    let rank = if rank == 0 { 1 } else { rank };
    sorted[rank - 1]
}

fn time_muls(
    ctx: &RNSFHEContext,
    ct_a: &nine65::ops::rns_fhe::DualRNSCiphertext,
    ct_b: &nine65::ops::rns_fhe::DualRNSCiphertext,
    sk: &nine65::ops::rns_fhe::DualRNSSecretKey,
    samples: usize,
) -> Vec<u64> {
    // Warm steady state: discard the first WARMUP iterations.
    for _ in 0..WARMUP {
        let p = ctx.mul_dual_symmetric(ct_a, ct_b, sk);
        std::hint::black_box(p);
    }
    let mut out = Vec::with_capacity(samples);
    for _ in 0..samples {
        let t0 = Instant::now();
        let p = ctx.mul_dual_symmetric(ct_a, ct_b, sk);
        let dt = t0.elapsed().as_nanos();
        std::hint::black_box(p);
        out.push(dt as u64);
    }
    out
}

fn report(label: &str, samples: &[u64]) -> (u128, u128) {
    let mut s = samples.to_vec();
    s.sort_unstable();
    let (num, den) = median_exact(&s);
    let p95 = p95_nearest_rank(&s);
    println!("  {label}");
    println!("    n_samples      : {}", s.len());
    println!("    min_ns         : {}", s[0]);
    println!("    max_ns         : {}", s[s.len() - 1]);
    println!(
        "    median_ns      : {} / {}  (exact numerator/denominator)",
        num, den
    );
    println!("    median_ns_floor: {}", num / den);
    println!("    p95_ns         : {}  (nearest-rank, integer)", p95);
    println!("    samples_ns     : {:?}", s);
    (num, den)
}

fn main() {
    println!("=== NINE65 SLOT-BATCHING PROBE ===");
    println!("Build: release. Threads: 1 (no rayon feature in default build).\n");

    let cfg: FHEConfig = SecureConfig::secure_128().into_config();
    let n = cfg.n;
    let t = cfg.t;
    let two_n = 2 * n;

    // ---------------------------------------------------------------
    // 1. CAPABILITY CHECK — is slot batching PERMITTED by the params?
    // ---------------------------------------------------------------
    println!("--- 1. PARAMETER CAPABILITY (permitted?) ---");
    println!("  config          : secure_128");
    println!("  N               : {}", n);
    println!("  2N              : {}", two_n);
    println!("  t               : {}", t);
    println!("  t mod 2N        : {}", t % two_n as u64);
    println!("  t == 1 (mod 2N) : {}", t % two_n as u64 == 1);
    println!("  primes          : {:?}", cfg.primes);
    println!(
        "  supports_simd_slots(): {}   <- predicate exists, NOTHING consumes it",
        BatchEncoder::supports_simd_slots(&cfg)
    );
    println!("  => max_slots (if implemented): {}", n);
    println!();

    // ---------------------------------------------------------------
    // 2. IMPLEMENTATION CHECK — is it actually WIRED?
    // ---------------------------------------------------------------
    println!("--- 2. IMPLEMENTATION STATUS (implemented?) ---");
    println!("  plaintext NTT over t          : ABSENT (no NTTEngine ever built over cfg.t)");
    println!("  slot encoder / decoder        : ABSENT");
    println!("  encrypt_dual signature        : (m: u64, ...)  -> scalar only");
    println!("  encrypt_dual message coeffs   : vec![0u64; N], index 0 overwritten");
    println!("  decrypt_dual coeff extraction : inner.main.iter().map(|limb| limb[0])");
    println!("  => PACKED MULTIPLY IS NOT MEASURABLE. Control only below.");
    println!();

    // ---------------------------------------------------------------
    // 3. CORRECTNESS (scalar control)
    // ---------------------------------------------------------------
    println!("--- 3. CORRECTNESS (scalar, slots=1) ---");
    let ctx = RNSFHEContext::try_new(&cfg).expect("context construction failed");
    let mut rng = ShadowHarvester::with_seed(500);
    let keys = ctx.generate_keys_dual(&mut rng);

    let ct_5 = ctx.encrypt_dual(5, &keys.public_key, &mut rng);
    let ct_7 = ctx.encrypt_dual(7, &keys.public_key, &mut rng);
    let ct_prod = ctx.mul_dual_symmetric(&ct_5, &ct_7, &keys.secret_key);
    let dec = ctx.decrypt_dual(&ct_prod, &keys.secret_key);
    let ok_5x7 = dec == 35;
    println!(
        "  dec(E(5)*E(7)) = {}  expected 35  -> {}",
        dec,
        if ok_5x7 { "PASS" } else { "FAIL" }
    );

    // Correctness trials over several pairs, integer-exact expectations.
    let pairs: [(u64, u64); 6] = [(0, 0), (1, 1), (2, 3), (7, 11), (100, 200), (t - 1, 2)];
    let mut trials: u32 = 0;
    let mut failures: u32 = 0;
    for (a, b) in pairs.iter() {
        let ca = ctx.encrypt_dual(*a, &keys.public_key, &mut rng);
        let cb = ctx.encrypt_dual(*b, &keys.public_key, &mut rng);
        let cp = ctx.mul_dual_symmetric(&ca, &cb, &keys.secret_key);
        let got = ctx.decrypt_dual(&cp, &keys.secret_key);
        let expected = ((*a as u128 * *b as u128) % t as u128) as u64;
        trials += 1;
        if got != expected {
            failures += 1;
            println!("    FAIL: {}*{} -> got {} expected {}", a, b, got, expected);
        }
    }
    println!("  correctness trials: {} failures: {}", trials, failures);
    println!();

    // ---------------------------------------------------------------
    // 4. MEASURED: scalar mul_ct
    // ---------------------------------------------------------------
    println!("--- 4. MEASURED: scalar mul_ct (slots=1) ---");
    let scalar_samples = time_muls(&ctx, &ct_5, &ct_7, &keys.secret_key, SAMPLES);
    let (med_num, med_den) = report("mul_ct scalar (m=5 x m=7)", &scalar_samples);
    let median_floor = (med_num / med_den) as u64;
    println!();

    // ---------------------------------------------------------------
    // 5. MEASURED: plaintext-value independence
    //    NOT a slot-occupancy test. It only shows latency does not track the
    //    plaintext VALUE, consistent with the constant-time arithmetic layer.
    // ---------------------------------------------------------------
    println!("--- 5. MEASURED: plaintext-value independence (NOT a packing test) ---");
    let ct_lo_a = ctx.encrypt_dual(1, &keys.public_key, &mut rng);
    let ct_lo_b = ctx.encrypt_dual(1, &keys.public_key, &mut rng);
    let ct_hi_a = ctx.encrypt_dual(t - 1, &keys.public_key, &mut rng);
    let ct_hi_b = ctx.encrypt_dual(t - 1, &keys.public_key, &mut rng);
    let lo = time_muls(&ctx, &ct_lo_a, &ct_lo_b, &keys.secret_key, SAMPLES);
    let hi = time_muls(&ctx, &ct_hi_a, &ct_hi_b, &keys.secret_key, SAMPLES);
    let (lo_num, lo_den) = report("mul_ct m=1 x m=1", &lo);
    let (hi_num, hi_den) = report("mul_ct m=(t-1) x m=(t-1)", &hi);
    // Compare medians exactly by cross-multiplication (no floats).
    let lhs = lo_num * hi_den;
    let rhs = hi_num * lo_den;
    let (bigger, smaller) = if lhs > rhs { (lhs, rhs) } else { (rhs, lhs) };
    let delta_permille = if smaller == 0 {
        0
    } else {
        (bigger - smaller) * 1000 / smaller
    };
    println!(
        "  median delta between low/high plaintext: {} per-mille",
        delta_permille
    );
    println!();

    // ---------------------------------------------------------------
    // 5b. MEASURED: operand density of the multiply.
    //     This DOES bear on the projection. The mul operands are the ciphertext
    //     polynomials c0/c1, not the plaintext. If they are already fully dense
    //     for a scalar plaintext, then packing the plaintext changes no operand
    //     shape and no loop bound, so the multiply has nothing left to get
    //     slower at. This is measurable today without any encoder.
    // ---------------------------------------------------------------
    println!("--- 5b. MEASURED: ciphertext operand density (scalar plaintext) ---");
    let count_nz = |limb: &Vec<u64>| limb.iter().filter(|&&x| x != 0).count();
    for (name, poly) in [("c0", &ct_5.c0), ("c1", &ct_5.c1)] {
        for (i, limb) in poly.main.iter().enumerate() {
            let nz = count_nz(limb);
            println!(
                "  {}.main[{}] : {} / {} coefficients nonzero  ({} per-mille)",
                name,
                i,
                nz,
                limb.len(),
                nz * 1000 / limb.len()
            );
        }
    }
    println!("  => the multiply already operates on FULLY DENSE operands with a");
    println!("     scalar plaintext. Slot occupancy changes VALUES, not SHAPES.");
    println!();

    // ---------------------------------------------------------------
    // 6. PROJECTION (NOT MEASURED)
    // ---------------------------------------------------------------
    println!("--- 6. PROJECTED amortization (THIS IS AN ARGUMENT, NOT EVIDENCE) ---");
    println!("  *** THE FOLLOWING NUMBER WAS NOT MEASURED. ***");
    println!("  *** No packed ciphertext was constructed, because no encoder exists. ***");
    let proj_num = med_num;
    let proj_den = med_den * n as u128;
    println!("  projected amortized ns/slot = median_ns / max_slots");
    println!(
        "                              = ({} / {}) / {}",
        med_num, med_den, n
    );
    println!(
        "                              = {} / {}",
        proj_num, proj_den
    );
    println!(
        "                              = {} ns/slot (floor)",
        proj_num / proj_den
    );
    println!("  ASSUMES, UNVERIFIED: a packed mul costs the same as a scalar mul,");
    println!(
        "  and that all {} slots decrypt correctly at dense-plaintext noise.",
        n
    );
    println!("  Neither assumption has been tested. B4 (dense-plaintext noise) is open.");
    println!();

    println!("=== SUMMARY ===");
    println!(
        "  MEASURED  scalar mul_ct median : {} ns (exact {}/{})",
        median_floor, med_num, med_den
    );
    println!(
        "  MEASURED  correctness          : {}/{} trials failed",
        failures, trials
    );
    println!("  NOT MEASURED packed mul_ct     : batching unimplemented");
    println!("  PROJECTED amortized ns/slot    : {}", proj_num / proj_den);
}
