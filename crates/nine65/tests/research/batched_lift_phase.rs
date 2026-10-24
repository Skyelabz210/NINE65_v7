//! Research alternative input to a batched integer-lift gate. Construct the
//! entire encrypted z polynomial with ONE public polynomial multiplication.
//! A composite plaintext scale can turn 99*z into the encrypted Phase 1 carry
//! by ordinary BFV decoding under p; this still does not admit refresh.

use super::*;

#[path = "lift_gate_domain.rs"]
mod lift_gate_domain;

#[path = "triple_lift_chart.rs"]
mod triple_lift_chart;

#[path = "power_sister_tray.rs"]
mod power_sister_tray;

fn multiply_signed_plain(
    ctx: &RNSFHEContext,
    input: &RNSCiphertext,
    weights: &[i64],
) -> RNSCiphertext {
    assert_eq!(weights.len(), ctx.n);
    let multiply = |p: &RNSPolynomial| {
        let coefficients = ordinary(ctx, p);
        montgomery(
            ctx,
            coefficients
                .iter()
                .zip(&ctx.config.primes)
                .enumerate()
                .map(|(lane, (values, &q))| {
                    let weights: Vec<_> = weights
                        .iter()
                        .map(|&w| (w as i128).rem_euclid(q as i128) as u64)
                        .collect();
                    ctx.ntt_engines[lane].multiply(values, &weights)
                })
                .collect(),
        )
    };
    RNSCiphertext {
        c0: multiply(&input.c0),
        c1: multiply(&input.c1),
        num_primes: input.num_primes,
    }
}

fn signed_scale(ctx: &RNSFHEContext, input: &RNSCiphertext, factor: i64) -> RNSCiphertext {
    let scale = |p: &RNSPolynomial| RNSPolynomial {
        n: ctx.n,
        limbs: p
            .limbs
            .iter()
            .zip(&ctx.config.primes)
            .map(|(values, &q)| {
                let factor = (factor as i128).rem_euclid(q as i128) as u128;
                values
                    .iter()
                    .map(|&v| (v as u128 * factor % q as u128) as u64)
                    .collect()
            })
            .collect(),
    };
    RNSCiphertext {
        c0: scale(&input.c0),
        c1: scale(&input.c1),
        num_primes: input.num_primes,
    }
}

fn add_mod_u128(left: u128, right: u128, modulus: u128) -> u128 {
    debug_assert!(left < modulus && right < modulus);
    if left >= modulus - right {
        left - (modulus - right)
    } else {
        left + right
    }
}

fn mul_mod_u128(mut left: u128, mut right: u128, modulus: u128) -> u128 {
    let mut product = 0;
    while right != 0 {
        if right & 1 != 0 {
            product = add_mod_u128(product, left, modulus);
        }
        right >>= 1;
        if right != 0 {
            left = add_mod_u128(left, left, modulus);
        }
    }
    product
}

// Composite BFV plaintext scale for the direct tropical quotient readout.
// T = p*A, with p=65,537 and A=32,769. The four 2N-compatible RNS primes
// are all above T, so this experiment also satisfies SecureConfig's t<q_i
// shape restriction instead of relying on a raw-context bypass.
const PHASE_P: u64 = 65_537;
const COMPOSITE_CHART_T: u64 = PHASE_P * 32_769;
const COMPOSITE_CHART_PRIMES: [u64; 4] =
    [2_148_728_833, 2_148_794_369, 2_149_810_177, 2_150_072_321];

fn centered_component_residual(
    ctx: &RNSFHEContext,
    component: &[Vec<u64>],
    coefficient: usize,
    source_q: u128,
) -> i128 {
    assert_eq!(ctx.config.primes.len(), 2);
    assert!(source_q < i128::MAX as u128);
    let p0 = ctx.config.primes[0];
    let p1 = ctx.config.primes[1];
    let r0 = component[0][coefficient];
    let r1 = component[1][coefficient];
    let delta = (r1 + p1 - r0 % p1) % p1;
    let correction = (delta as u128 * inverse(p0 % p1, p1) as u128 % p1 as u128) as u64;
    let canonical = r0 as u128 + p0 as u128 * correction as u128;
    assert!(canonical < source_q);

    // R_i = center(t*c_i mod Q). This equals t*c_i-Q*round(t*c_i/Q)
    // for odd Q and the repository's nearest-integer convention, without
    // ever materializing the wider t*c_i product.
    let residue = mul_mod_u128(canonical, ctx.t as u128, source_q);
    if residue <= source_q / 2 {
        residue as i128
    } else {
        residue as i128 - source_q as i128
    }
}

fn phase1_tropical_carry(
    residual0: &[i128],
    residual1: &[i128],
    secret: &[i8],
    source_q: u128,
    coefficient: usize,
) -> (i128, i128) {
    let n = secret.len();
    let mut source = residual0[coefficient];
    for (i, &weight) in residual1.iter().enumerate() {
        let secret_index = (coefficient + n - i) % n;
        let sign = if i + secret_index < n { 1 } else { -1 };
        source += weight * secret[secret_index] as i128 * sign;
    }
    let q = source_q as i128;
    let carry = (source + q / 2).div_euclid(q);
    (carry, source - carry * q)
}

struct BatchedPhase<'a> {
    source: &'a RNSFHEContext,
    outer: &'a RNSFHEContext,
    // KEY HOLDER setup encrypts s_source(Y^2), then retains the secrets.
    encrypted_source: RNSCiphertext,
    precharge_v: u128,
    source_norm: usize,
    coordinate: usize,
    phase_cap: u128,
}

struct BatchedPhaseOutput {
    ciphertext: RNSCiphertext,
    bound: u128,
    integer_coefficient_limit: u128,
    public_polynomial_l1: u128,
}

impl BatchedPhase<'_> {
    // Evaluator: no source support, phase measurement, clock sheet or key.
    fn apply(&self, input: &RNSCiphertext, input_v: u128) -> BatchedPhaseOutput {
        assert_eq!(self.outer.n, 2 * self.source.n);
        assert_eq!(self.outer.t % self.source.t, 0);
        assert_eq!(input.num_primes, self.source.config.primes.len());
        assert_eq!(
            self.encrypted_source.num_primes,
            self.outer.config.primes.len()
        );
        assert!(self.source_norm <= self.source.n && input_v <= self.phase_cap);
        let q: u128 = self
            .source
            .config
            .primes
            .iter()
            .map(|&q| q as u128)
            .product();
        assert!(
            phase_window2_for_q(
                self.outer.n,
                self.source_norm,
                self.coordinate,
                self.phase_cap,
                q
            ) < self.outer.n as u128
        );
        let public0 = preprocess_for_clock(self.source, &input.c0, self.coordinate, self.outer.n);
        let public1 = preprocess_for_clock(self.source, &input.c1, self.coordinate, self.outer.n);
        let maximum = public0
            .clock
            .iter()
            .chain(&public1.clock)
            .map(|b| b.unsigned_abs() as u128)
            .max()
            .unwrap();
        assert!(maximum <= (self.outer.n as u128).div_ceil(self.coordinate as u128));
        let integer_limit = (self.source_norm + 1) as u128 * maximum;
        assert!(
            2 * integer_limit < self.outer.t as u128,
            "batch phase must have an unambiguous signed integer lift"
        );
        let mut b0 = vec![0; self.outer.n];
        let mut b1 = vec![0; self.outer.n];
        for j in 0..self.source.n {
            b0[2 * j] = public0.clock[j];
            b1[2 * j] = public1.clock[j];
        }
        let ciphertext = add(
            self.outer,
            &multiply_signed_plain(self.outer, &self.encrypted_source, &b1),
            &public_plain(self.outer, &b0),
        );
        let l1 = b1.iter().map(|b| b.unsigned_abs() as u128).sum::<u128>();
        let remainder = U512::product_u64s(&self.outer.config.primes).mod_u64(self.outer.t) as u128;
        let bound = self.precharge_v * l1 + remainder * maximum;
        assert!(
            words(U512::from_u128(bound).mul_u128(2))
                < words(U512::product_u64s(&self.outer.config.primes))
        );
        BatchedPhaseOutput {
            ciphertext,
            bound,
            integer_coefficient_limit: integer_limit,
            public_polynomial_l1: l1,
        }
    }
}

fn check_batched_phase(
    n: usize,
    weight: usize,
    coordinate: usize,
    phase_denominator: u128,
    chart_t: u64,
) {
    use std::time::Instant;
    let mut config = SecureConfig::secure_128().into_config();
    config.n = n;
    config.security_bits = 0;
    config.name = "UNADMITTED encrypted batch lift phase, NOT bootstrap";
    let mut source_config = config.clone();
    source_config.primes.truncate(2);
    let source = RNSFHEContext::try_new(&source_config).unwrap();
    let mut outer_config = config;
    outer_config.n = 2 * n;
    outer_config.primes = COMPOSITE_CHART_PRIMES.to_vec();
    outer_config.t = chart_t;
    let outer = RNSFHEContext::try_new(&outer_config).unwrap();
    let source_q: u128 = source.config.primes.iter().map(|&q| q as u128).product();
    let mut rng = ShadowHarvester::with_seed(0x4241_5443_4850_4841 + n as u64);
    let trits = balanced_source(n, weight, &mut rng);
    let source_keys = sparse_keys(&source, &trits, &mut rng);
    let outer_keys = outer.generate_keys(&mut rng);
    let message: Vec<_> = (0..n)
        .map(|j| if j % 2 == 0 { 1 } else { source.t - 1 })
        .collect();
    let mut input = encrypt_polynomial(&source, &source_keys, &message, &mut rng);
    let load = source_q / ((phase_denominator + 4) * source.t as u128);
    input.c0 = input.c0.add(
        &montgomery(
            &source,
            source
                .config
                .primes
                .iter()
                .map(|&q| {
                    (0..n)
                        .map(|j| {
                            let v = (load % q as u128) as u64;
                            if j % 2 == 0 || v == 0 {
                                v
                            } else {
                                q - v
                            }
                        })
                        .collect()
                })
                .collect(),
        ),
        &source.rns,
    );
    let source_fresh_v = source.t as u128 * (2 * n + 1) as u128 * source.config.eta as u128
        + (source_q % source.t as u128) * (source.t - 1) as u128;
    let input_v = source_fresh_v + load * source.t as u128;
    assert!(observe_polynomial(&source, &input, &source_keys, &message) <= input_v);

    // Independent clear oracle for the exact Phase 1 residual polynomial.
    // Keep the same source ciphertext, secret history, component-rounding
    // residuals and Q that feed the encrypted chart producer below.
    let source_q = source_q as u128;
    let source_components = [ordinary(&source, &input.c0), ordinary(&source, &input.c1)];
    let residual0: Vec<_> = (0..n)
        .map(|j| centered_component_residual(&source, &source_components[0], j, source_q))
        .collect();
    let residual1: Vec<_> = (0..n)
        .map(|j| centered_component_residual(&source, &source_components[1], j, source_q))
        .collect();
    let phase1: Vec<_> = (0..n)
        .map(|j| phase1_tropical_carry(&residual0, &residual1, &trits, source_q, j))
        .collect();
    let carry_radius = (weight / 2) as i128;
    assert!(phase1.iter().all(|(k, _)| k.abs() <= carry_radius));
    let encrypted_source = encrypt_polynomial(
        &outer,
        &outer_keys,
        &embedded(
            &trits
                .iter()
                .map(|&s| (s as i64).rem_euclid(outer.t as i64) as u64)
                .collect::<Vec<_>>(),
        ),
        &mut rng,
    );
    let remainder = U512::product_u64s(&outer.config.primes).mod_u64(outer.t) as u128;
    let precharge_v = outer.t as u128 * (2 * outer.n + 1) as u128 * outer.config.eta as u128
        + remainder * (outer.t - 1) as u128;
    let mut evaluator = BatchedPhase {
        source: &source,
        outer: &outer,
        encrypted_source,
        precharge_v,
        source_norm: weight,
        coordinate,
        phase_cap: source_q / phase_denominator,
    };
    let coordinates = [coordinate, if coordinate == 99 { 121 } else { 7 }];
    let mut views = Vec::new();
    for coordinate in coordinates {
        evaluator.coordinate = coordinate;
        let start = Instant::now();
        let output = evaluator.apply(&input, input_v);
        let seconds = start.elapsed().as_secs_f64();
        // Independent CLIENT oracle. The clear weighted sums are only assertions.
        let public0 = preprocess_for_clock(&source, &input.c0, coordinate, outer.n);
        let public1 = preprocess_for_clock(&source, &input.c1, coordinate, outer.n);
        let support: Vec<_> = trits.iter().enumerate().filter(|(_, s)| **s != 0).collect();
        let mut expected = vec![0; outer.n];
        let mut sheets = BTreeSet::new();
        let mut wrong_cyclic = 0;
        let mut maximum = 0;
        for j in 0..n {
            let mut z = public0.clock[j] as i128;
            let mut cyclic = z;
            let mut affine = public0.a[j] as i128;
            for &(i, &s) in &support {
                let k = (j + n - i) % n;
                let sign = s as i128 * if i > j { -1 } else { 1 };
                z += sign * public1.clock[k] as i128;
                cyclic += s as i128 * public1.clock[k] as i128;
                affine += sign * public1.a[k] as i128;
            }
            let residue = (message[j] as i128 - affine).rem_euclid(source.t as i128);
            let sheet = if residue > source.t as i128 / 2 {
                residue - source.t as i128
            } else {
                residue
            };
            assert!(sheet.unsigned_abs() <= weight.div_ceil(2) as u128);
            assert_eq!(
                (coordinate as i128 * z + outer.n as i128).div_euclid((2 * outer.n) as i128),
                sheet
            );
            expected[2 * j] = z.rem_euclid(outer.t as i128) as u64;
            sheets.insert(sheet);
            maximum = maximum.max(z.unsigned_abs());
            wrong_cyclic += usize::from(cyclic != z);
        }
        assert!(
            maximum <= output.integer_coefficient_limit
                && wrong_cyclic > 0
                && sheets.iter().any(|&k| k != 0)
        );
        let observed = observe_polynomial(&outer, &output.ciphertext, &outer_keys, &expected);
        assert!(observed <= output.bound);
        if coordinate == 99 {
            let mut chart_checked = 0;
            for j in 0..n {
                let chart_z_residue = expected[2 * j] as i128;
                let chart_z = if chart_z_residue > outer.t as i128 / 2 {
                    chart_z_residue - outer.t as i128
                } else {
                    chart_z_residue
                };
                let chart_carry =
                    (99 * chart_z + outer.n as i128).div_euclid((2 * outer.n) as i128);
                let (phase_carry, centered_phase) = phase1[j];
                assert_eq!(chart_carry, phase_carry, "K99 / K_phase at j={j}");
                assert!(centered_phase.unsigned_abs() <= (source_q / 2) as u128);
                chart_checked += 1;
            }
            assert_eq!(chart_checked, n);
            eprintln!("tropical chart bridge: sourceN{n}, H={weight}, all {chart_checked} coefficients satisfy K99=round((R0+R1*s)/Q)=K_phase; |K|<={carry_radius}, g=center_Q(S); same live source ciphertext and residual history");

            if chart_t != source.t {
                let quotient_scale = 2 * outer.n as u64 + 1;
                assert_eq!(chart_t, PHASE_P * quotient_scale);
                let reader_config = nine65::params::FHEConfig {
                    t: source.t,
                    ..outer.config.clone()
                };
                let reader = RNSFHEContext::try_new(&reader_config).unwrap();
                let scaled = signed_scale(&outer, &output.ciphertext, coordinate as i64);
                let mut expected_scaled = vec![0; outer.n];
                let mut expected_carry = vec![0; outer.n];
                let mut affine_weights = vec![0i64; outer.n];
                let mut affine_constant = vec![0i64; outer.n];
                let mut expected_affine_t = vec![0; outer.n];
                let mut expected_affine_p = vec![0; outer.n];
                let mut expected_corrected = vec![0; outer.n];
                let mut expected_chart_residual = vec![0; outer.n];
                let mut max_residual = 0u128;
                for j in 0..n {
                    let z = expected[2 * j] as i128;
                    let z = if z > chart_t as i128 / 2 {
                        z - chart_t as i128
                    } else {
                        z
                    };
                    let x = coordinate as i128 * z;
                    let (k, _) = phase1[j];
                    let residual = x - quotient_scale as i128 * k;
                    max_residual = max_residual.max(residual.unsigned_abs());
                    assert!(2 * residual.unsigned_abs() + 1 < quotient_scale as u128);
                    assert!(x.unsigned_abs() * 2 < chart_t as u128);
                    expected_scaled[2 * j] = x.rem_euclid(chart_t as i128) as u64;
                    expected_carry[2 * j] = k.rem_euclid(source.t as i128) as u64;
                    expected_chart_residual[2 * j] = residual.rem_euclid(chart_t as i128) as u64;
                    let center_t = |value: u128| {
                        let residue = (value % chart_t as u128) as i128;
                        if residue > chart_t as i128 / 2 {
                            residue - chart_t as i128
                        } else {
                            residue
                        }
                    };
                    affine_constant[2 * j] =
                        center_t(quotient_scale as u128 * public0.a[j] as u128) as i64;
                    affine_weights[2 * j] =
                        center_t(quotient_scale as u128 * public1.a[j] as u128) as i64;
                    let affine = (public0.a[j] as i128
                        + trits
                            .iter()
                            .enumerate()
                            .map(|(i, &secret_digit)| {
                                let source_index = (j + n - i) % n;
                                let sign = if i > j { -1i128 } else { 1i128 };
                                sign * public1.a[source_index] as i128 * secret_digit as i128
                            })
                            .sum::<i128>())
                    .rem_euclid(source.t as i128);
                    expected_affine_p[2 * j] = affine as u64;
                    expected_affine_t[2 * j] =
                        (quotient_scale as u128 * affine as u128 % chart_t as u128) as u64;
                    expected_corrected[2 * j] = message[j];
                }
                let scaled_bound = output.bound * coordinate as u128;
                let q_outer = U512::product_u64s(&outer.config.primes);
                assert!(words(U512::from_u128(scaled_bound).mul_u128(2)) < words(q_outer));
                let observed_t = observe_polynomial(&outer, &scaled, &outer_keys, &expected_scaled);
                assert!(observed_t <= scaled_bound);
                let observed_p = decrypt_coefficients(&reader, &scaled, &outer_keys);
                assert_eq!(observed_p, expected_carry);

                // Scale the affine componentwise Phase 1 result by A in the
                // same T ciphertext space. Interpreting both it and 99*Z99
                // under p makes their sum affine+K, the original plaintext.
                let affine_ciphertext = add(
                    &outer,
                    &multiply_signed_plain(&outer, &evaluator.encrypted_source, &affine_weights),
                    &public_plain(&outer, &affine_constant),
                );
                let affine_l1 = affine_weights
                    .iter()
                    .map(|weight| weight.unsigned_abs() as u128)
                    .sum::<u128>();
                let affine_b0_max = affine_constant
                    .iter()
                    .map(|weight| weight.unsigned_abs() as u128)
                    .max()
                    .unwrap();
                let remainder_t = U512::product_u64s(&outer.config.primes).mod_u64(chart_t) as u128;
                let affine_bound = precharge_v * affine_l1 + remainder_t * affine_b0_max;
                assert!(words(U512::from_u128(affine_bound).mul_u128(2)) < words(q_outer));
                let affine_observed =
                    observe_polynomial(&outer, &affine_ciphertext, &outer_keys, &expected_affine_t);
                assert!(affine_observed <= affine_bound);
                assert_eq!(
                    decrypt_coefficients(&reader, &affine_ciphertext, &outer_keys),
                    expected_affine_p
                );

                let corrected = add(&outer, &affine_ciphertext, &scaled);
                let corrected_bound = affine_bound + scaled_bound;
                assert!(words(U512::from_u128(corrected_bound).mul_u128(2)) < words(q_outer));
                let corrected_p = decrypt_coefficients(&reader, &corrected, &outer_keys);
                assert_eq!(corrected_p, expected_corrected);
                let corrected_p_noise =
                    observe_polynomial(&reader, &corrected, &outer_keys, &expected_corrected);
                let chart_modulus = (2 * outer.n) as u128;
                let twice_chart_residual_bound = coordinate as u128 * (weight as u128 + 1)
                    + 2 * chart_modulus / phase_denominator;
                let chart_residual_bound = (twice_chart_residual_bound - 1) / 2;
                let corrected_residual_bound = chart_residual_bound + weight.div_ceil(2) as u128;
                assert!(max_residual <= corrected_residual_bound);
                let corrected_p_noise_bound = q_outer
                    .mul_u128(corrected_residual_bound)
                    .add(U512::from_u128(corrected_bound))
                    .add(U512::from_u64(quotient_scale as u64 - 1))
                    .div_u64(quotient_scale as u64);
                assert_eq!(
                    (
                        corrected_p_noise_bound.d3,
                        corrected_p_noise_bound.d2,
                        corrected_p_noise_bound.d1
                    ),
                    (0, 0, 0),
                    "p-view phase bound must fit u128 for this screened chain"
                );
                assert!(corrected_p_noise <= corrected_p_noise_bound.d0);
                let q_outer_u128 = q_outer.d0;
                assert_eq!((q_outer.d3, q_outer.d2, q_outer.d1), (0, 0, 0));
                eprintln!("composite scale-locked Phase 1: T={chart_t}=p*A, p={}, A={}, same RNS basis/key/history; all {} doubled-ring coefficients including odd zeros decode as K and affine+K recovers the original plaintext; max |99*z-A*K|={}, p-view phase noise observed/bound bits={}/{}, Q_outer bits={}, source input V/Q bits={}/{}, p-output V/Q bits={}/{}, source-certified |r|<={}; evaluator adds/scales ciphertexts only",source.t,quotient_scale,outer.n,max_residual,bits(corrected_p_noise),bits(corrected_p_noise_bound.d0),bits(q_outer_u128),bits(input_v),bits(source_q),bits(corrected_p_noise),bits(q_outer_u128),corrected_residual_bound);

                // Isolation control for the open high-encoding carry producer.
                // The key holder supplies the paired residues S mod T and
                // g mod T; the evaluator uses the actual K-elimination kernel
                // to produce K mod T. This tests the consumer/noise path, but
                // the encrypted centered-g producer is still a client oracle.
                if n <= 1024 {
                    let mut expected_source_t = vec![0; outer.n];
                    let mut expected_centered_t = vec![0; outer.n];
                    let mut expected_carry_t = vec![0; outer.n];
                    for (j, &(k, g)) in phase1.iter().enumerate() {
                        let source_phase = source_q as i128 * k + g;
                        expected_source_t[2 * j] = source_phase.rem_euclid(chart_t as i128) as u64;
                        expected_centered_t[2 * j] = g.rem_euclid(chart_t as i128) as u64;
                        expected_carry_t[2 * j] = k.rem_euclid(chart_t as i128) as u64;
                    }
                    let encrypted_source_t =
                        encrypt_polynomial(&outer, &outer_keys, &expected_source_t, &mut rng);
                    let encrypted_centered_t =
                        encrypt_polynomial(&outer, &outer_keys, &expected_centered_t, &mut rng);
                    assert!(
                        observe_polynomial(
                            &outer,
                            &encrypted_source_t,
                            &outer_keys,
                            &expected_source_t,
                        ) <= precharge_v
                    );
                    assert!(
                        observe_polynomial(
                            &outer,
                            &encrypted_centered_t,
                            &outer_keys,
                            &expected_centered_t,
                        ) <= precharge_v
                    );
                    let inverse_period = inverse(source_q as u64 % chart_t, chart_t) as u128;
                    let carry_t_bound = 2 * inverse_period * precharge_v;
                    assert!(words(U512::from_u128(carry_t_bound).mul_u128(2)) < words(q_outer));
                    let carry_t = tropical_winding_from_paired_coordinates(
                        &outer,
                        source_q as u64,
                        &encrypted_source_t,
                        &encrypted_centered_t,
                    );
                    let carry_t_observed =
                        observe_polynomial(&outer, &carry_t, &outer_keys, &expected_carry_t);
                    assert!(carry_t_observed <= carry_t_bound);
                    let carry_t_scaled = signed_scale(&outer, &carry_t, quotient_scale as i64);
                    let residual_t =
                        add(&outer, &scaled, &signed_scale(&outer, &carry_t_scaled, -1));
                    let residual_t_bound = scaled_bound + quotient_scale as u128 * carry_t_bound;
                    assert!(words(U512::from_u128(residual_t_bound).mul_u128(2)) < words(q_outer));
                    let residual_t_observed = observe_polynomial(
                        &outer,
                        &residual_t,
                        &outer_keys,
                        &expected_chart_residual,
                    );
                    assert!(residual_t_observed <= residual_t_bound);

                    // Removing the independently encrypted residual cancels
                    // the original chart ciphertext exactly, leaving only the
                    // affine term and A*Enc_T(K). Thus its p-view error is
                    // bounded by (V_affine + A*V_carry)/A.
                    let repaired = add(&outer, &corrected, &signed_scale(&outer, &residual_t, -1));
                    let expected_repaired_t: Vec<_> = expected_corrected
                        .iter()
                        .map(|&m| (quotient_scale as u128 * m as u128 % chart_t as u128) as u64)
                        .collect();
                    let repaired_t_observed =
                        observe_polynomial(&outer, &repaired, &outer_keys, &expected_repaired_t);
                    let repaired_t_bound = affine_bound + quotient_scale as u128 * carry_t_bound;
                    assert!(repaired_t_observed <= repaired_t_bound);
                    let repaired_p = decrypt_coefficients(&reader, &repaired, &outer_keys);
                    assert_eq!(repaired_p, expected_corrected);
                    let repaired_p_observed =
                        observe_polynomial(&reader, &repaired, &outer_keys, &expected_corrected);
                    let repaired_p_bound = repaired_t_bound.div_ceil(quotient_scale as u128);
                    assert!(repaired_p_observed <= repaired_p_bound);
                    assert!(
                        words(U512::from_u128(repaired_p_observed).mul_u128(source_q))
                            < words(U512::from_u128(input_v).mul_u128(q_outer_u128))
                    );

                    // Follow the repaired result through two dependent dense
                    // products under the p plaintext view. Schoolbook negacyclic
                    // multiplication supplies only the client-side oracle.
                    let exact = reader.try_exact_evaluator().unwrap();
                    let relin =
                        exact.generate_hybrid_gadget_key_with_rng(&outer_keys.secret_key, &mut rng);
                    let schoolbook = |left: &[u64], right: &[u64]| {
                        let mut accum = vec![0i128; outer.n];
                        for (i, &a) in left.iter().enumerate() {
                            let a = if a > source.t / 2 {
                                a as i128 - source.t as i128
                            } else {
                                a as i128
                            };
                            for (j, &b) in right.iter().enumerate() {
                                let b = if b > source.t / 2 {
                                    b as i128 - source.t as i128
                                } else {
                                    b as i128
                                };
                                let index = i + j;
                                if index < outer.n {
                                    accum[index] += a * b;
                                } else {
                                    accum[index - outer.n] -= a * b;
                                }
                            }
                        }
                        accum
                            .into_iter()
                            .map(|v| v.rem_euclid(source.t as i128) as u64)
                            .collect::<Vec<_>>()
                    };
                    let square_expected = schoolbook(&expected_corrected, &expected_corrected);
                    let square = exact.try_mul_exact(&repaired, &repaired, &relin).unwrap();
                    assert_eq!(
                        decrypt_coefficients(&reader, &square, &outer_keys),
                        square_expected
                    );
                    let cube_expected = schoolbook(&square_expected, &expected_corrected);
                    let cube = exact.try_mul_exact(&square, &repaired, &relin).unwrap();
                    let cube_decoded = decrypt_coefficients(&reader, &cube, &outer_keys);
                    let cube_matches = cube_decoded == cube_expected;
                    if n == 512 {
                        assert!(cube_matches, "small-corridor cubic control");
                    } else {
                        assert!(
                            !cube_matches,
                            "larger-corridor cubic must expose the next refresh gate"
                        );
                    }
                    let carry_values: BTreeSet<_> = phase1.iter().map(|(k, _)| *k).collect();
                    let cube_mismatches = cube_decoded
                        .iter()
                        .zip(&cube_expected)
                        .filter(|(actual, expected)| actual != expected)
                        .count();
                    eprintln!("K-elimination residual ablation: sourceN{n}/outerN{}, K values={carry_values:?}, inverse(Q_s mod T)={inverse_period}; paired encrypted (S,g) residues yield Enc_T(K), observed/bound V bits={}/{}, subtracting A*K removes chart residual and gives p-view V bits observed/bound={}/{}, source input V/Q bits={}/{}, first dense square passes; second dependent product mismatches {cube_mismatches}/{} coefficients at this larger stress point; centered-g producer and repeat-refresh gate remain open",outer.n,bits(carry_t_observed),bits(carry_t_bound),bits(repaired_p_observed),bits(repaired_p_bound),bits(input_v),bits(source_q),outer.n);

                    // Join the K-Elimination consumer to the actual encrypted
                    // chart. Only the low M tray is supplied by the client
                    // oracle here; X_T is derived from the live chart output.
                    // X=99*Z99+M/2=M*K+r_M, so one same-encoding tray gives
                    // Enc_T(K)=(Enc_T(X)-Enc_T(r_M))*M^(-1) mod T without a
                    // signed lift or a centered-g input.
                    let low_modulus = 2 * outer.n as u64;
                    let mut expected_x_t = expected_scaled.clone();
                    let mut expected_low_tray_t = vec![0; outer.n];
                    let half = outer.n as u64;
                    for (x, low) in expected_x_t.iter_mut().zip(&mut expected_low_tray_t) {
                        let signed_x = if *x > chart_t / 2 {
                            *x as i128 - chart_t as i128
                        } else {
                            *x as i128
                        };
                        let chart_x_with_half = signed_x + half as i128;
                        *x = chart_x_with_half.rem_euclid(chart_t as i128) as u64;
                        *low = chart_x_with_half.rem_euclid(low_modulus as i128) as u64;
                    }
                    let encrypted_low_tray =
                        encrypt_polynomial(&outer, &outer_keys, &expected_low_tray_t, &mut rng);
                    let low_tray_observed = observe_polynomial(
                        &outer,
                        &encrypted_low_tray,
                        &outer_keys,
                        &expected_low_tray_t,
                    );
                    assert!(low_tray_observed <= precharge_v);
                    let high_chart_x = add(
                        &outer,
                        &scaled,
                        &public_plain(&outer, &vec![half as i64; outer.n]),
                    );
                    let inverse_low_modulus = inverse(low_modulus % chart_t, chart_t) as i128;
                    let centered_inverse = if inverse_low_modulus > chart_t as i128 / 2 {
                        inverse_low_modulus - chart_t as i128
                    } else {
                        inverse_low_modulus
                    };
                    let low_carry_bound =
                        centered_inverse.unsigned_abs() * (scaled_bound + precharge_v);
                    assert!(words(U512::from_u128(low_carry_bound).mul_u128(2)) < words(q_outer));
                    let low_carry = signed_scale(
                        &outer,
                        &add(
                            &outer,
                            &high_chart_x,
                            &signed_scale(&outer, &encrypted_low_tray, -1),
                        ),
                        centered_inverse as i64,
                    );
                    let low_carry_observed =
                        observe_polynomial(&outer, &low_carry, &outer_keys, &expected_carry_t);
                    assert!(low_carry_observed <= low_carry_bound);
                    let low_residual = add(
                        &outer,
                        &scaled,
                        &signed_scale(&outer, &low_carry, -(quotient_scale as i64)),
                    );
                    let low_residual_bound =
                        scaled_bound + quotient_scale as u128 * low_carry_bound;
                    assert!(
                        words(U512::from_u128(low_residual_bound).mul_u128(2)) < words(q_outer)
                    );
                    let low_residual_observed = observe_polynomial(
                        &outer,
                        &low_residual,
                        &outer_keys,
                        &expected_chart_residual,
                    );
                    assert!(low_residual_observed <= low_residual_bound);
                    let low_repaired =
                        add(&outer, &corrected, &signed_scale(&outer, &low_residual, -1));
                    assert_eq!(
                        decrypt_coefficients(&reader, &low_repaired, &outer_keys),
                        expected_corrected,
                        "live-chart low-tray K-Elimination return"
                    );
                    let low_repaired_observed = observe_polynomial(
                        &reader,
                        &low_repaired,
                        &outer_keys,
                        &expected_corrected,
                    );
                    let low_repaired_bound = (affine_bound
                        + quotient_scale as u128 * low_carry_bound)
                        .div_ceil(quotient_scale as u128);
                    assert!(low_repaired_observed <= low_repaired_bound);
                    eprintln!("live-chart M-tray K-Elimination ablation: M={low_modulus}, same T/key and actual X_T chart; only Enc_T(r_M) is oracle supplied, inverse(M mod T)={inverse_low_modulus} (centered {centered_inverse}); carry V observed/bound={}/{}, residual V observed/bound={}/{}, repaired p-view observed/bound={}/{}, low-tray producer still open",bits(low_carry_observed),bits(low_carry_bound),bits(low_residual_observed),bits(low_residual_bound),bits(low_repaired_observed),bits(low_repaired_bound));

                    // Continue the same low-tray return through dependent
                    // products. This separates a correct one-shot carry
                    // cancellation from an output with enough remaining
                    // phase budget for useful work.
                    let low_square_expected = schoolbook(&expected_corrected, &expected_corrected);
                    let low_square = exact
                        .try_mul_exact(&low_repaired, &low_repaired, &relin)
                        .unwrap();
                    assert_eq!(
                        decrypt_coefficients(&reader, &low_square, &outer_keys),
                        low_square_expected,
                        "live-chart low-tray corrected square"
                    );
                    let low_cube_expected = schoolbook(&low_square_expected, &expected_corrected);
                    let low_cube = exact
                        .try_mul_exact(&low_square, &low_repaired, &relin)
                        .unwrap();
                    let low_cube_decoded = decrypt_coefficients(&reader, &low_cube, &outer_keys);
                    let low_cube_mismatches = low_cube_decoded
                        .iter()
                        .zip(&low_cube_expected)
                        .filter(|(actual, expected)| actual != expected)
                        .count();
                    eprintln!("live-chart M-tray dependent-product follow-up: square exact; second product mismatches {low_cube_mismatches}/{} coefficients, isolating the carry-consumer return from the still-open noise-reset gate", outer.n);
                }

                // Run the low-tray consumer once at native N=8192 as well.
                // Keep the expensive paired-(S,g) oracle/product ablation
                // limited to the small fixtures; this branch tests whether
                // the same live-chart K-Elimination arithmetic and bound
                // survive the admitted native source envelope.
                if n == 8192 {
                    let low_modulus = 2 * outer.n as u64;
                    let half = outer.n as u64;
                    let mut expected_x_t = expected_scaled.clone();
                    let mut expected_low_tray_t = vec![0; outer.n];
                    let mut expected_native_carry = vec![0; outer.n];
                    for (j, &(k, _)) in phase1.iter().enumerate() {
                        expected_native_carry[2 * j] = k.rem_euclid(chart_t as i128) as u64;
                    }
                    for (x, low) in expected_x_t.iter_mut().zip(&mut expected_low_tray_t) {
                        let signed_x = if *x > chart_t / 2 {
                            *x as i128 - chart_t as i128
                        } else {
                            *x as i128
                        };
                        let chart_x_with_half = signed_x + half as i128;
                        *x = chart_x_with_half.rem_euclid(chart_t as i128) as u64;
                        *low = chart_x_with_half.rem_euclid(low_modulus as i128) as u64;
                    }
                    let encrypted_low_tray =
                        encrypt_polynomial(&outer, &outer_keys, &expected_low_tray_t, &mut rng);
                    let low_tray_observed = observe_polynomial(
                        &outer,
                        &encrypted_low_tray,
                        &outer_keys,
                        &expected_low_tray_t,
                    );
                    assert!(low_tray_observed <= precharge_v);
                    let high_chart_x = add(
                        &outer,
                        &scaled,
                        &public_plain(&outer, &vec![half as i64; outer.n]),
                    );
                    let inverse_low_modulus = inverse(low_modulus % chart_t, chart_t) as i128;
                    let centered_inverse = if inverse_low_modulus > chart_t as i128 / 2 {
                        inverse_low_modulus - chart_t as i128
                    } else {
                        inverse_low_modulus
                    };
                    let low_carry_bound =
                        centered_inverse.unsigned_abs() * (scaled_bound + precharge_v);
                    assert!(words(U512::from_u128(low_carry_bound).mul_u128(2)) < words(q_outer));
                    let low_carry = signed_scale(
                        &outer,
                        &add(
                            &outer,
                            &high_chart_x,
                            &signed_scale(&outer, &encrypted_low_tray, -1),
                        ),
                        centered_inverse as i64,
                    );
                    let low_carry_observed =
                        observe_polynomial(&outer, &low_carry, &outer_keys, &expected_native_carry);
                    assert!(low_carry_observed <= low_carry_bound);
                    let low_residual = add(
                        &outer,
                        &scaled,
                        &signed_scale(&outer, &low_carry, -(quotient_scale as i64)),
                    );
                    let low_residual_bound =
                        scaled_bound + quotient_scale as u128 * low_carry_bound;
                    assert!(
                        words(U512::from_u128(low_residual_bound).mul_u128(2)) < words(q_outer)
                    );
                    let low_residual_observed = observe_polynomial(
                        &outer,
                        &low_residual,
                        &outer_keys,
                        &expected_chart_residual,
                    );
                    assert!(low_residual_observed <= low_residual_bound);
                    let low_repaired =
                        add(&outer, &corrected, &signed_scale(&outer, &low_residual, -1));
                    assert_eq!(
                        decrypt_coefficients(&reader, &low_repaired, &outer_keys),
                        expected_corrected,
                        "native live-chart low-tray K-Elimination return"
                    );
                    let low_repaired_observed = observe_polynomial(
                        &reader,
                        &low_repaired,
                        &outer_keys,
                        &expected_corrected,
                    );
                    let low_repaired_bound = (affine_bound
                        + quotient_scale as u128 * low_carry_bound)
                        .div_ceil(quotient_scale as u128);
                    assert!(low_repaired_observed <= low_repaired_bound);
                    eprintln!("native N8192 live-chart M-tray K-Elimination: M={low_modulus}, A={quotient_scale}, centered inverse={centered_inverse}, all {} doubled-ring coefficients return exactly; carry V observed/bound bits={}/{}, repaired p-view V observed/bound bits={}/{}, low-tray producer remains oracle supplied",outer.n,bits(low_carry_observed),bits(low_carry_bound),bits(low_repaired_observed),bits(low_repaired_bound));

                    // Check the first native dependent operation too. The
                    // source occupies even coefficients in the doubled ring,
                    // so compute the oracle product at source degree n and
                    // embed it back into the even lanes.
                    let exact = reader.try_exact_evaluator().unwrap();
                    let relin =
                        exact.generate_hybrid_gadget_key_with_rng(&outer_keys.secret_key, &mut rng);
                    let mut source_square = vec![0i128; n];
                    for (i, &left) in expected_corrected.iter().step_by(2).enumerate() {
                        let left = if left > source.t / 2 {
                            left as i128 - source.t as i128
                        } else {
                            left as i128
                        };
                        for (j, &right) in expected_corrected.iter().step_by(2).enumerate() {
                            let right = if right > source.t / 2 {
                                right as i128 - source.t as i128
                            } else {
                                right as i128
                            };
                            let index = i + j;
                            if index < n {
                                source_square[index] += left * right;
                            } else {
                                source_square[index - n] -= left * right;
                            }
                        }
                    }
                    let mut expected_native_square = vec![0; outer.n];
                    for (index, value) in source_square.into_iter().enumerate() {
                        expected_native_square[2 * index] =
                            value.rem_euclid(source.t as i128) as u64;
                    }
                    let native_square = exact
                        .try_mul_exact(&low_repaired, &low_repaired, &relin)
                        .unwrap();
                    let native_square_decoded =
                        decrypt_coefficients(&reader, &native_square, &outer_keys);
                    let native_square_mismatches = native_square_decoded
                        .iter()
                        .zip(&expected_native_square)
                        .filter(|(actual, expected)| actual != expected)
                        .count();
                    let native_square_odd_mismatches = native_square_decoded
                        .iter()
                        .zip(&expected_native_square)
                        .enumerate()
                        .filter(|(index, (actual, expected))| index % 2 == 1 && actual != expected)
                        .count();
                    let native_square_examples: Vec<_> = native_square_decoded
                        .iter()
                        .zip(&expected_native_square)
                        .enumerate()
                        .filter(|(_, (actual, expected))| actual != expected)
                        .take(8)
                        .map(|(index, (actual, expected))| (index, *actual, *expected))
                        .collect();
                    let native_square_observed_bits = if native_square_mismatches == 0 {
                        Some(bits(observe_polynomial(
                            &reader,
                            &native_square,
                            &outer_keys,
                            &expected_native_square,
                        )))
                    } else {
                        None
                    };
                    eprintln!("native N8192 low-tray follow-up: first dense square mismatches {native_square_mismatches}/{}, odd-lane mismatches {native_square_odd_mismatches}, observed phase V bits={native_square_observed_bits:?}, first mismatches={native_square_examples:?}",outer.n);
                }
            }
        }
        let readout_status = if coordinate == 99 && chart_t != source.t {
            "scale-locked K and corrected Phase 1 readout passed"
        } else {
            "encrypted K readout not evaluated for this chart"
        };
        eprintln!("encrypted batch lift phase: sourceN{n}/outerN{}, sourceH{weight}, composite{coordinate}; ONE signed public polynomial multiplication, all{n} z coefficients and all{n} odd zeros correct, source support hidden from evaluator, signed |z| observed/bound={maximum}/{}, V observed/bound={}/{}, public weight l1={}, native evaluator time={seconds:.6}s, sheets={sheets:?}, cyclic-wrap omission corrupts {wrong_cyclic} z values; {readout_status}",outer.n,output.integer_coefficient_limit,bits(observed),bits(output.bound),output.public_polynomial_l1);
        views.push((output, expected, public0, public1));
    }
    // The 99/121 views share factor11. 9*z99-11*z121 cancels
    // M*(K+g/Q)/11 exactly, leaving only component-rounding residuals.
    // Both views use the SAME precharge, so their encryption errors are
    // correlated; combine public weights first to charge the actual error.
    let mut gcd = coordinates[0];
    let mut other = coordinates[1];
    while other != 0 {
        (gcd, other) = (other, gcd % other);
    }
    let a = (coordinates[0] / gcd) as i64;
    let b = (coordinates[1] / gcd) as i64;
    let mut d0 = vec![0; outer.n];
    let mut d1 = vec![0; outer.n];
    for j in 0..n {
        d0[2 * j] = a * views[0].2.clock[j] - b * views[1].2.clock[j];
        d1[2 * j] = a * views[0].3.clock[j] - b * views[1].3.clock[j];
    }
    let rounding_limit = ((a + b) as u128).div_ceil(2);
    assert!(d0
        .iter()
        .chain(&d1)
        .all(|d| d.unsigned_abs() as u128 <= rounding_limit));
    let integer_limit = (weight + 1) as u128 * rounding_limit;
    assert!(2 * integer_limit < outer.t as u128);
    let start = Instant::now();
    let direct = add(
        &outer,
        &multiply_signed_plain(&outer, &evaluator.encrypted_source, &d1),
        &public_plain(&outer, &d0),
    );
    let seconds = start.elapsed().as_secs_f64();
    let combined = add(
        &outer,
        &signed_scale(&outer, &views[0].0.ciphertext, a),
        &signed_scale(&outer, &views[1].0.ciphertext, -b),
    );
    assert_eq!(direct.c0.limbs, combined.c0.limbs);
    assert_eq!(direct.c1.limbs, combined.c1.limbs);
    let maximum_public = d0.iter().map(|d| d.unsigned_abs() as u128).max().unwrap();
    let l1 = d1.iter().map(|d| d.unsigned_abs() as u128).sum::<u128>();
    let bound = precharge_v * l1 + remainder * maximum_public;
    let triangle = a as u128 * views[0].0.bound + b as u128 * views[1].0.bound;
    assert!(bound < triangle);
    let expected: Vec<_> = views[0]
        .1
        .iter()
        .zip(&views[1].1)
        .map(|(&x, &y)| {
            (a as i128 * x as i128 - b as i128 * y as i128).rem_euclid(outer.t as i128) as u64
        })
        .collect();
    let maximum = expected
        .iter()
        .map(|&v| v.min(outer.t - v) as u128)
        .max()
        .unwrap();
    assert!(maximum <= integer_limit);
    let observed = observe_polynomial(&outer, &direct, &outer_keys, &expected);
    assert!(observed <= bound);
    let mut residual_sheets = BTreeMap::new();
    let mut collisions = 0;
    for j in 0..n {
        let z = views[0].1[2 * j] as i128;
        let z = if z > outer.t as i128 / 2 {
            z - outer.t as i128
        } else {
            z
        };
        let k = (coordinates[0] as i128 * z + outer.n as i128).div_euclid((2 * outer.n) as i128);
        if let Some(previous) = residual_sheets.insert(expected[2 * j], k) {
            collisions += usize::from(previous != k);
        }
    }
    if n == 8192 {
        assert!(
            collisions > 0,
            "a K-eliminated residual must not be confused with K itself"
        );
    }
    eprintln!("encrypted paired K-elimination: sourceN{n}, coordinates={coordinates:?}, common factor={gcd}, {a}*Z0-{b}*Z1 cancels both ideal K and fractional g/Q; all{n} coefficients/odd zeros correct, direct public-weight construction BIT-IDENTICAL to correlated encrypted difference; |D| observed/bound={maximum}/{integer_limit}, residual weight l1={l1}, V observed/direct/triangle bits={}/{}/{}, direct evaluator time={seconds:.6}s; same residual/different K controls={collisions}, bounded PAIRED state initialized, encrypted integer K extraction/refresh NOT implemented",bits(observed),bits(bound),bits(triangle));
    // Complete the residual to a unimodular INTEGER chart. This retains
    // both original views, and is invertible modulo2, modulo11 and every
    // dependent composite. Native coefficients: U=-4*Z99+5*Z121.
    let mut u0 = inverse(b as u64, a as u64) as i64;
    if u0 > a / 2 {
        u0 -= a;
    }
    let u1 = (1 - b * u0) / a;
    assert_eq!(b * u0 + a * u1, 1);
    let mut w0 = vec![0; outer.n];
    let mut w1 = vec![0; outer.n];
    for j in 0..n {
        w0[2 * j] = u0 * views[0].2.clock[j] + u1 * views[1].2.clock[j];
        w1[2 * j] = u0 * views[0].3.clock[j] + u1 * views[1].3.clock[j];
    }
    let u_maximum = w0
        .iter()
        .chain(&w1)
        .map(|v| v.unsigned_abs() as u128)
        .max()
        .unwrap();
    let u_limit = (weight + 1) as u128 * u_maximum;
    assert!(2 * u_limit < outer.t as u128);
    let start = Instant::now();
    let u = add(
        &outer,
        &multiply_signed_plain(&outer, &evaluator.encrypted_source, &w1),
        &public_plain(&outer, &w0),
    );
    let u_seconds = start.elapsed().as_secs_f64();
    let weighted = add(
        &outer,
        &signed_scale(&outer, &views[0].0.ciphertext, u0),
        &signed_scale(&outer, &views[1].0.ciphertext, u1),
    );
    assert_eq!(u.c0.limbs, weighted.c0.limbs);
    assert_eq!(u.c1.limbs, weighted.c1.limbs);
    for (index, up, dp) in [(0, b, u1), (1, a, -u0)] {
        let restored = add(
            &outer,
            &signed_scale(&outer, &u, up),
            &signed_scale(&outer, &direct, dp),
        );
        assert_eq!(restored.c0.limbs, views[index].0.ciphertext.c0.limbs);
        assert_eq!(restored.c1.limbs, views[index].0.ciphertext.c1.limbs);
    }
    let u_l1 = w1.iter().map(|v| v.unsigned_abs() as u128).sum::<u128>();
    let u_bound =
        precharge_v * u_l1 + remainder * w0.iter().map(|v| v.unsigned_abs() as u128).max().unwrap();
    let u_expected: Vec<_> = views[0]
        .1
        .iter()
        .zip(&views[1].1)
        .map(|(&x, &y)| {
            (u0 as i128 * x as i128 + u1 as i128 * y as i128).rem_euclid(outer.t as i128) as u64
        })
        .collect();
    let u_observed = observe_polynomial(&outer, &u, &outer_keys, &u_expected);
    assert!(u_observed <= u_bound);
    let u_max = u_expected
        .iter()
        .map(|&v| v.min(outer.t - v) as u128)
        .max()
        .unwrap();
    assert!(u_max <= u_limit);
    eprintln!("encrypted unimodular lift chart: sourceN{n}, U={u0}*Z0+{u1}*Z1, D={a}*Z0-{b}*Z1, determinant=-1; BOTH original ciphertexts recovered BIT-IDENTICALLY, no division or extra Safe Basis; U ideal scale M/{}, |U| observed/bound={u_max}/{u_limit}, U weight l1={u_l1}, V observed/bound={}/{}, direct U evaluator time={u_seconds:.6}s; two signed public polynomial products construct (U,D), corrected return and native repeated refresh remain OPEN",gcd*a as usize*b as usize,bits(u_observed),bits(u_bound));
}

#[test]
fn batched_lift_phase_is_negacyclic_and_has_an_unambiguous_integer_domain() {
    check_batched_phase(16, 2, 9, 128, PHASE_P);
}

#[test]
fn composite_scale_locked_tropical_chart_decodes_the_encrypted_carry() {
    check_batched_phase(512, 2, 99, 128, PHASE_P * (4 * 512 + 1));
}

#[test]
fn composite_scale_locked_residual_correction_survives_a_larger_carry_corridor() {
    check_batched_phase(1024, 8, 99, 16, PHASE_P * (4 * 1024 + 1));
}

#[test]
fn composite_chart_outer_chain_passes_the_128_bit_screen() {
    let screened = SecureConfig::custom_screened(
        16_384,
        COMPOSITE_CHART_PRIMES.to_vec(),
        COMPOSITE_CHART_T,
        3,
        128,
    )
    .expect("composite chart scale must retain a screened 128-bit outer chain");
    assert!(screened.is_production_safe_under_all_models());
}

#[test]
#[ignore = "opt-in native encrypted batch PHASE construction; nonlinear lift gate remains open"]
fn batched_lift_phase_native_constructs_all_source_coefficients_together() {
    check_batched_phase(8192, 96, 99, 16, COMPOSITE_CHART_T);
}
