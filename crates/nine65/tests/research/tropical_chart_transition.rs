//! Endogenous local cell crossing, using the existing encrypted toy backend.
//! Initial chart/source coordinates are supplied once. Every crossing below
//! is evaluated publicly from encrypted chart and increment, with no new
//! chart or crossing oracle at the transition boundary.

use super::*;

#[derive(Debug, PartialEq, Eq)]
enum PlanError {
    Period,
    NonUnitFactor(u64),
}

struct LocalChart {
    period: u64,
    inverse_factorial: u64,
}

impl LocalChart {
    fn new(period: u64, modulus: u64) -> Result<Self, PlanError> {
        if period < 3 || period % 2 == 0 || period > 63 || modulus < 2 {
            return Err(PlanError::Period);
        }
        let mut factorial = 1u128;
        for factor in 1..=period {
            let (mut a, mut b) = (factor, modulus);
            while b != 0 {
                (a, b) = (b, a % b);
            }
            if a != 1 {
                return Err(PlanError::NonUnitFactor(factor));
            }
            factorial = factorial * factor as u128 % modulus as u128;
        }
        Ok(Self {
            period,
            inverse_factorial: inverse(factorial as u64, modulus),
        })
    }

    // C(z)=prod_(r=-h..h)(z-r)/Q!, h=(Q-1)/2. On [-h-1,h+1]
    // this is -1, 0 or +1, exactly the carry after a ternary increment.
    fn crossing_slots(
        &self,
        ctx: &RNSFHEContext,
        z: &RNSCiphertext,
        relin: &RNSHybridGadgetKey,
    ) -> RNSCiphertext {
        let h = self.period as i64 / 2;
        let mut factors: Vec<_> = (-h..=h)
            .map(|r| add_plain_constant(ctx, z, (-r).rem_euclid(ctx.t as i64) as u64))
            .collect();
        let exact = ctx.try_exact_evaluator().unwrap();
        while factors.len() > 1 {
            let mut next = Vec::new();
            let mut iter = factors.into_iter();
            while let Some(left) = iter.next() {
                next.push(if let Some(right) = iter.next() {
                    exact.try_mul_exact(&left, &right, relin).unwrap()
                } else {
                    left
                });
            }
            factors = next;
        }
        scale(ctx, &factors.pop().unwrap(), self.inverse_factorial)
    }

    fn two_trit_quadratic(&self, modulus: u64) -> Result<(u64, u64), PlanError> {
        LocalChart::new(self.period + 2, modulus)?;
        let m = modulus as u128;
        let c = self.inverse_factorial as u128;
        let upper = self.period.div_ceil(2);
        let a = (m - self.period as u128 * c % m)
            * inverse((self.period + 1) * (self.period + 2) % modulus, modulus) as u128
            % m;
        let b = (c + m - a * upper as u128 * upper as u128 % m) % m;
        Ok((a as u64, b as u64))
    }

    // For |z|<=h+2, C2(z)=G(z)*(a*z^2+b). At the two positive
    // outer points G(h+1)=Q!, G(h+2)=(Q+1)*Q!, so the public quadratic
    // normalizes both to one. Oddness gives the two negative crossings.
    fn two_trit_crossing_slots(
        &self,
        ctx: &RNSFHEContext,
        z: &RNSCiphertext,
        relin: &RNSHybridGadgetKey,
    ) -> Result<RNSCiphertext, PlanError> {
        let (a, b) = self.two_trit_quadratic(ctx.t)?;
        let exact = ctx.try_exact_evaluator().unwrap();
        let square = exact.try_mul_exact(z, z, relin).unwrap();
        let quadratic = if a > ctx.t / 2 {
            let zero = ctx.sub(&square, &square);
            add_plain_constant(ctx, &ctx.sub(&zero, &scale(ctx, &square, ctx.t - a)), b)
        } else {
            add_plain_constant(ctx, &scale(ctx, &square, a), b)
        };
        let h = self.period as i64 / 2;
        let mut forest: Vec<_> = (-h..=h)
            .map(|r| {
                (
                    add_plain_constant(ctx, z, (-r).rem_euclid(ctx.t as i64) as u64),
                    0usize,
                )
            })
            .collect();
        forest.push((quadratic, 1));
        // Charge the quadratic's existing multiplication layer. Combining
        // shallowest factors first keeps the period-13 circuit at depth four.
        while forest.len() > 1 {
            forest.sort_by_key(|(_, depth)| *depth);
            let (left, dl) = forest.remove(0);
            let (right, dr) = forest.remove(0);
            forest.push((
                exact.try_mul_exact(&left, &right, relin).unwrap(),
                dl.max(dr) + 1,
            ));
        }
        let (result, depth) = forest.pop().unwrap();
        if self.period == 13 {
            assert_eq!(depth, 4);
        }
        Ok(result)
    }
}

fn scale(ctx: &RNSFHEContext, ct: &RNSCiphertext, scalar: u64) -> RNSCiphertext {
    let mut polynomial = vec![0; ctx.n];
    polynomial[0] = scalar;
    multiply_plain(ctx, ct, &polynomial)
}

// Secret-key observation only. Exact ideal-grid error V, with correctness
// condition 2*V<Q; never used by the public evaluator or as an issued bound.
pub(super) fn observed_scaled_error(
    ctx: &RNSFHEContext,
    ct: &RNSCiphertext,
    keys: &RNSKeySet,
    intended: &[u64],
) -> u128 {
    let phases = decrypted_phase_residues(ctx, ct, keys);
    let q: u128 = ctx.config.primes.iter().map(|&p| p as u128).product();
    let t = ctx.t as u128;
    let period = t.checked_mul(q).unwrap();
    (0..ctx.n)
        .map(|j| {
            let residues: Vec<_> = phases.iter().map(|lane| lane[j]).collect();
            // Independent client/oracle CRT. This observation is outside
            // every evaluator function and is bounded by this toy's u128 Q.
            let (mut phase, mut product) = (0u128, 1u128);
            for (&residue, &prime) in residues.iter().zip(&ctx.config.primes) {
                let p = prime as u128;
                let difference = (residue as u128 + p - phase % p) % p;
                let digit = difference * inverse((product % p) as u64, prime) as u128 % p;
                phase += product * digit;
                product *= p;
            }
            let a = t * phase;
            let b = q * intended[j] as u128;
            let difference = a.abs_diff(b);
            difference.min(period - difference)
        })
        .max()
        .unwrap()
}

#[test]
fn composite_chart_checks_units_and_exhausts_the_local_boundary_map() {
    let (period, modulus) = (13u64, 289u64);
    let plan = LocalChart::new(period, modulus).unwrap();
    let h = period as i64 / 2;
    let mut count = 0;
    for g in -h..=h {
        for trit in -1..=1 {
            let z = g + trit;
            let product = (-h..=h).fold(1u128, |value, r| {
                value * (z - r).rem_euclid(modulus as i64) as u128 % modulus as u128
            });
            let crossing = product * plan.inverse_factorial as u128 % modulus as u128;
            let expected = (z + h).div_euclid(period as i64);
            assert_eq!(crossing, expected.rem_euclid(modulus as i64) as u128);
            assert!((-h..=h).contains(&(z - period as i64 * expected)));
            count += 1;
        }
    }
    assert_eq!(count, 39);
    let (a, b) = plan.two_trit_quadratic(modulus).unwrap();
    let mut two_trit_count = 0;
    for g in -h..=h {
        for u in -1..=1 {
            for v in -1..=1 {
                let z = g + u + v;
                let product = (-h..=h).fold(1u128, |value, r| {
                    value * (z - r).rem_euclid(modulus as i64) as u128 % modulus as u128
                });
                let quadratic = (a as i128 * z as i128 * z as i128 + b as i128)
                    .rem_euclid(modulus as i128) as u128;
                assert_eq!(
                    product * quadratic % modulus as u128,
                    (z + h).div_euclid(period as i64).rem_euclid(modulus as i64) as u128
                );
                two_trit_count += 1;
            }
        }
    }
    assert_eq!(two_trit_count, 117);
    assert_eq!(
        LocalChart::new(15, 289)
            .unwrap()
            .two_trit_quadratic(289)
            .err(),
        Some(PlanError::NonUnitFactor(17))
    );
    // A third trit widens support to [-9,9]. Here -9 and 8 collide mod17,
    // while the desired carries are -1 and +1, ruling out a polynomial
    // of ANY degree in this one prime-power coordinate ring.
    assert_eq!((-9i64).rem_euclid(17), 8i64.rem_euclid(17));
    assert_ne!(
        (-9i64 + h).div_euclid(13).rem_euclid(17),
        (8i64 + h).div_euclid(13).rem_euclid(17)
    );
    assert_eq!(
        LocalChart::new(31, 289).err(),
        Some(PlanError::NonUnitFactor(17))
    );
    assert_eq!(
        LocalChart::new(13, 22).err(),
        Some(PlanError::NonUnitFactor(2))
    );
    // The first refusal is structural: 15 == -2 mod17, but the desired
    // period-31 endpoint indicator differs on those two chart points.
    assert_eq!(15i64.rem_euclid(17), (-2i64).rem_euclid(17));
}

#[test]
fn local_composite_chart_does_not_supply_native_dense_slot_geometry() {
    // Units modulo 17^2 have order dividing 17*16, so the toy supports
    // primitive 16th roots but cannot provide primitive 16384th roots.
    assert!((2..289).any(|r| mod_pow(r, 8, 289) == 288));
    assert!(!(2..289).any(|r| mod_pow(r, 8192, 289) == 288));
    // The work plaintext does have the required native root geometry; its
    // larger plaintext scale has a different circuit-noise contract.
    assert_eq!(mod_pow(81, 8192, 65537), 65536);
}

#[test]
fn encrypted_chart_updates_compose_two_hidden_trit_increments() {
    let mut config = SecureConfig::secure_128().into_config();
    config.n = 8;
    config.t = 289;
    config.security_bits = 0;
    config.name = "INSECURE tropical local chart transition toy";
    let ctx = RNSFHEContext::try_new(&config).unwrap();
    let plan = LocalChart::new(13, ctx.t).unwrap();
    let h = plan.period as i64 / 2;
    let mut rng = ShadowHarvester::with_seed(0x4348_4152_5453_5445);
    let keys = ctx.generate_keys(&mut rng);
    let exact = ctx.try_exact_evaluator().unwrap();
    let relin = exact.generate_hybrid_gadget_key_with_rng(&keys.secret_key, &mut rng);
    let galois = RNSGaloisEvaluator::new(&ctx).unwrap();
    let (baby, giant) = automorphism_factor_sets(ctx.n);
    let mut galois_keys = BTreeMap::new();
    for exponent in required_galois_exponents(&baby, &giant) {
        galois_keys.insert(
            exponent,
            galois
                .generate_key_with_rng(&keys.secret_key, exponent, &mut rng)
                .unwrap(),
        );
    }
    let root_values = roots(ctx.n, ctx.t);
    let (to_slots, to_coefficients) = coefficient_matrices(ctx.n, ctx.t, &root_values);
    let map = |ct: &RNSCiphertext, matrix: &[Vec<u64>]| {
        linear_map_from_slots_bsgs(
            &ctx,
            ct,
            matrix,
            &root_values,
            &galois,
            &galois_keys,
            &baby,
            &giant,
        )
    };
    let reduce = |x: i64| x.rem_euclid(ctx.t as i64) as u64;
    let cases: Vec<_> = (-h..=h)
        .flat_map(|g| (-1..=1).map(move |u| (g, u)))
        .collect();
    let mut checked = 0;
    let mut walls = 0;
    let mut combined_walls = 0;
    let mut max_v = [0u128; 8];
    let q: u128 = ctx.config.primes.iter().map(|&p| p as u128).product();
    for v_value in -1i64..=1 {
        for batch in 0..cases.len().div_ceil(ctx.n) {
            let input: Vec<_> = (0..ctx.n)
                .map(|j| cases[(batch * ctx.n + j) % cases.len()])
                .collect();
            let sheet: Vec<_> = (0..ctx.n).map(|j| j as i64 * 5 - 17).collect();
            let g_plain: Vec<_> = input.iter().map(|&(g, _)| reduce(g)).collect();
            let u_plain: Vec<_> = input.iter().map(|&(_, u)| reduce(u)).collect();
            let s_plain: Vec<_> = input
                .iter()
                .zip(&sheet)
                .map(|(&(g, _), &k)| reduce(g + plan.period as i64 * k))
                .collect();
            // Setup supplies initial coordinates and encrypted source trits.
            let g = encrypt_polynomial(&ctx, &keys, &g_plain, &mut rng);
            let u = encrypt_polynomial(&ctx, &keys, &u_plain, &mut rng);
            let s = encrypt_polynomial(&ctx, &keys, &s_plain, &mut rng);
            let v = encrypt_polynomial(&ctx, &keys, &vec![reduce(v_value); ctx.n], &mut rng);
            let k = tropical_winding_from_paired_coordinates(&ctx, plan.period, &s, &g);

            // Public evaluator: first form encrypted z=g+u, then produce the
            // crossing and update all three coordinates from the same state.
            let z = add(&ctx, &g, &u);
            let crossing_slots = plan.crossing_slots(&ctx, &map(&z, &to_coefficients), &relin);
            let crossing = map(&crossing_slots, &to_slots);
            let next_g = ctx.sub(&z, &scale(&ctx, &crossing, plan.period));
            let next_s = add(&ctx, &s, &u);
            let next_k = add(&ctx, &k, &crossing);
            let paired_k =
                tropical_winding_from_paired_coordinates(&ctx, plan.period, &next_s, &next_g);

            let expected_c: Vec<_> = input
                .iter()
                .map(|&(g, u)| (g + u + h).div_euclid(plan.period as i64))
                .collect();
            let expected_g: Vec<_> = input
                .iter()
                .zip(&expected_c)
                .map(|(&(g, u), &c)| reduce(g + u - plan.period as i64 * c))
                .collect();
            let expected_k: Vec<_> = sheet
                .iter()
                .zip(&expected_c)
                .map(|(&k, &c)| k + c)
                .collect();
            assert_eq!(
                decrypt_coefficients(&ctx, &crossing, &keys),
                expected_c.iter().map(|&c| reduce(c)).collect::<Vec<_>>()
            );
            assert_eq!(decrypt_coefficients(&ctx, &next_g, &keys), expected_g);
            assert_eq!(
                decrypt_coefficients(&ctx, &next_s, &keys),
                input
                    .iter()
                    .zip(&sheet)
                    .map(|(&(g, u), &k)| reduce(g + u + plan.period as i64 * k))
                    .collect::<Vec<_>>()
            );
            assert_eq!(
                decrypt_coefficients(&ctx, &next_k, &keys),
                expected_k.iter().map(|&k| reduce(k)).collect::<Vec<_>>()
            );
            assert_eq!(
                decrypt_coefficients(&ctx, &paired_k, &keys),
                expected_k.iter().map(|&k| reduce(k)).collect::<Vec<_>>()
            );

            let square = exact.try_mul_exact(&next_k, &next_k, &relin).unwrap();
            let mut expected_square = vec![0i64; ctx.n];
            for (i, &a) in expected_k.iter().enumerate() {
                for (j, &b) in expected_k.iter().enumerate() {
                    expected_square[(i + j) % ctx.n] += if i + j < ctx.n { a * b } else { -a * b };
                }
            }
            let expected_square_mod: Vec<_> = expected_square.into_iter().map(reduce).collect();
            assert_eq!(
                decrypt_coefficients(&ctx, &square, &keys),
                expected_square_mod
            );
            for (index, ct, intended) in [
                (
                    0,
                    &crossing,
                    expected_c.iter().map(|&c| reduce(c)).collect::<Vec<_>>(),
                ),
                (1, &next_g, expected_g.clone()),
                (
                    2,
                    &next_k,
                    expected_k.iter().map(|&k| reduce(k)).collect::<Vec<_>>(),
                ),
                (3, &square, expected_square_mod),
            ] {
                let observed = observed_scaled_error(&ctx, ct, &keys, &intended);
                assert!(2 * observed < q);
                max_v[index] = max_v[index].max(observed);
            }

            // Outcome-dependent follow-up: evaluate the next crossing on the
            // updated chart ciphertext itself, preserving its accumulated error.
            if v_value == -1 && batch == 0 {
                let z_second = add(&ctx, &next_g, &v);
                let c_second_slots =
                    plan.crossing_slots(&ctx, &map(&z_second, &to_coefficients), &relin);
                let c_second = map(&c_second_slots, &to_slots);
                let expected_c_second: Vec<_> = input
                    .iter()
                    .zip(&expected_c)
                    .map(|(&(g, u), &c)| {
                        (g + u + v_value - plan.period as i64 * c + h)
                            .div_euclid(plan.period as i64)
                    })
                    .map(reduce)
                    .collect();
                let second_v = observed_scaled_error(&ctx, &c_second, &keys, &expected_c_second);
                eprintln!(
            "sequential re-evaluation negative control: second crossing ideal-grid error={} bits, Q={} bits",
            128 - second_v.leading_zeros(),
            128 - q.leading_zeros()
        );
                assert!(2 * second_v >= q);
                assert_ne!(
                    decrypt_coefficients(&ctx, &c_second, &keys),
                    expected_c_second
                );
            }

            // Compose both encrypted increments from the initial chart. The
            // boundary decision is still computed here, without supplying it or
            // a new chart. The degree-15 gate uses four multiplication layers.
            let z_combined = add(&ctx, &z, &v);
            let combined_slots = plan
                .two_trit_crossing_slots(&ctx, &map(&z_combined, &to_coefficients), &relin)
                .unwrap();
            let combined = map(&combined_slots, &to_slots);
            let combined_g = ctx.sub(&z_combined, &scale(&ctx, &combined, plan.period));
            let combined_s = add(&ctx, &next_s, &v);
            let combined_k = add(&ctx, &k, &combined);
            let combined_paired = tropical_winding_from_paired_coordinates(
                &ctx,
                plan.period,
                &combined_s,
                &combined_g,
            );
            let expected_combined: Vec<_> = input
                .iter()
                .map(|&(g, u)| (g + u + v_value + h).div_euclid(plan.period as i64))
                .collect();
            let expected_combined_g: Vec<_> = input
                .iter()
                .zip(&expected_combined)
                .map(|(&(g, u), &c)| reduce(g + u + v_value - plan.period as i64 * c))
                .collect();
            let expected_combined_k: Vec<_> = sheet
                .iter()
                .zip(&expected_combined)
                .map(|(&k, &c)| k + c)
                .collect();
            assert_eq!(
                decrypt_coefficients(&ctx, &combined, &keys),
                expected_combined
                    .iter()
                    .map(|&c| reduce(c))
                    .collect::<Vec<_>>()
            );
            assert_eq!(
                decrypt_coefficients(&ctx, &combined_g, &keys),
                expected_combined_g
            );
            assert_eq!(
                decrypt_coefficients(&ctx, &combined_s, &keys),
                input
                    .iter()
                    .zip(&sheet)
                    .map(|(&(g, u), &k)| reduce(g + u + v_value + plan.period as i64 * k))
                    .collect::<Vec<_>>()
            );
            assert_eq!(
                decrypt_coefficients(&ctx, &combined_k, &keys),
                expected_combined_k
                    .iter()
                    .map(|&k| reduce(k))
                    .collect::<Vec<_>>()
            );
            assert_eq!(
                decrypt_coefficients(&ctx, &combined_paired, &keys),
                expected_combined_k
                    .iter()
                    .map(|&k| reduce(k))
                    .collect::<Vec<_>>()
            );
            let combined_square = exact
                .try_mul_exact(&combined_k, &combined_k, &relin)
                .unwrap();
            let mut expected_combined_square = vec![0i64; ctx.n];
            for (i, &a) in expected_combined_k.iter().enumerate() {
                for (j, &b) in expected_combined_k.iter().enumerate() {
                    expected_combined_square[(i + j) % ctx.n] +=
                        if i + j < ctx.n { a * b } else { -a * b };
                }
            }
            let expected_combined_square: Vec<_> =
                expected_combined_square.into_iter().map(reduce).collect();
            assert_eq!(
                decrypt_coefficients(&ctx, &combined_square, &keys),
                expected_combined_square
            );
            for (index, ct, intended) in [
                (
                    4,
                    &combined,
                    expected_combined
                        .iter()
                        .map(|&c| reduce(c))
                        .collect::<Vec<_>>(),
                ),
                (5, &combined_g, expected_combined_g),
                (
                    6,
                    &combined_k,
                    expected_combined_k
                        .iter()
                        .map(|&k| reduce(k))
                        .collect::<Vec<_>>(),
                ),
                (7, &combined_square, expected_combined_square),
            ] {
                let observed = observed_scaled_error(&ctx, ct, &keys, &intended);
                assert!(2 * observed < q);
                max_v[index] = max_v[index].max(observed);
            }
            if expected_c.iter().any(|&c| c != 0) {
                // Omitting the computed crossing leaves the old sheet and fails
                // exactly on wall transitions; no fresh chart is injected.
                let omitted =
                    tropical_winding_from_paired_coordinates(&ctx, plan.period, &next_s, &z);
                assert_ne!(
                    decrypt_coefficients(&ctx, &omitted, &keys),
                    expected_k.iter().map(|&k| reduce(k)).collect::<Vec<_>>()
                );
            }
            for (j, &c) in expected_c.iter().enumerate() {
                if batch * ctx.n + j < cases.len() {
                    checked += 1;
                    walls += usize::from(c != 0);
                    combined_walls += usize::from(expected_combined[j] != 0);
                }
            }
        }
    }
    assert_eq!((checked, walls, combined_walls), (117, 6, 8));
    eprintln!("tropical chart transitions: all 117 chart/two-trit states; single-step crossings={walls}, two-step crossings={combined_walls}; 30 dependent squares; observed scaled-error bits [C1,g1,K1,square1,C2,g2,K2,square2]={:?}, Q={} bits; insecure N=8 period-13 toy", max_v.map(|v| 128-v.leading_zeros()), 128-q.leading_zeros());
}
