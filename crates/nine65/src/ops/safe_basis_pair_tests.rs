//! Pair indicators prepared by the source key holder, independent of the
//! later public residual coefficients. Bounded research; one S8 root.

use super::*;
use crate::ops::rns_fhe::DualRNSKeySet;

#[path = "safe_basis_terminal_tests.rs"]
mod terminal;

struct PackedPairs {
    indicators: [RNSCiphertext; 9],
    family: [u64; 2],
    pairs: usize,
}

// Key-holder-only producer: slot j describes source coefficients 2j,2j+1.
// Nine independent encryptions; no product of noisy single-trit ciphertexts.
fn precharge_pairs(
    ctx: &RNSFHEContext,
    keys: &DualRNSKeySet,
    source: &[i8],
    family: [u64; 2],
    rng: &mut ShadowHarvester,
) -> PackedPairs {
    assert_eq!(source.len(), ctx.n);
    assert!(source.iter().all(|u| (-1..=1).contains(u)));
    let indicators = core::array::from_fn(|pattern| {
        let mut values = vec![0i8; ctx.n];
        for (j, pair) in source.chunks_exact(2).enumerate() {
            if (pair[0] + 1) as usize * 3 + (pair[1] + 1) as usize == pattern {
                values[j] = -8;
            }
        }
        precharge(ctx, keys, &values, rng)
    });
    PackedPairs {
        indicators,
        family,
        pairs: source.len() / 2,
    }
}

// Public metadata only. No source trits, selected carry, or decryption.
// Selector=None denotes unexecuted planned rows here, never evaluator inputs.
fn plan_pair(
    runtime: &CarryRuntime<'_>,
    pair: usize,
    terms: [i128; 2],
    initial: i128,
) -> Result<(State, [usize; 9]), Refusal> {
    if pair >= runtime.ctx.n / 2 {
        return Err(Refusal::Regime);
    }
    if terms
        .into_iter()
        .chain([initial])
        .any(|x| x.unsigned_abs() > runtime.source_q as u128 / 2)
    {
        return Err(Refusal::NonCentered);
    }
    let mut destinations = BTreeMap::new();
    let mut rows: Vec<Row> = Vec::new();
    let mut edges = [0; 9];
    for (pattern, edge) in edges.iter_mut().enumerate() {
        let sum =
            initial + terms[0] * (pattern as i128 / 3 - 1) + terms[1] * (pattern as i128 % 3 - 1);
        let winding = (sum + runtime.source_q / 2).div_euclid(runtime.source_q);
        let label = (sum - runtime.source_q * winding, winding as i64);
        let next = rows.len();
        let index = *destinations.entry(label).or_insert(next);
        if index == rows.len() {
            if index >= runtime.max_states {
                return Err(Refusal::StateLimit {
                    needed: index + 1,
                    limit: runtime.max_states,
                });
            }
            rows.push(Row {
                remainder: label.0,
                winding: label.1,
                selector: None,
                bound: U512::zero(),
            });
        }
        rows[index].bound = runtime.noise.admit(
            rows[index].bound.add(runtime.noise.projected),
            "merged pair selector",
        )?;
        *edge = index;
    }
    let state = State {
        rows,
        family: runtime.family,
        source_q: runtime.source_q,
        coefficients: vec![2 * pair, 2 * pair + 1],
    };
    runtime.noise.admit(
        runtime.projection_bound(&state, |r| r.winding),
        "pair carry",
    )?;
    for p in ROOT {
        runtime.noise.admit(
            runtime.projection_bound(&state, |r| runtime.root_value(r, p)),
            "pair root",
        )?;
    }
    Ok((state, edges))
}

fn project_pair(
    runtime: &CarryRuntime<'_>,
    packed: &PackedPairs,
    trace: &[RNSGaloisKey],
    pair: usize,
    terms: [i128; 2],
    initial: i128,
) -> Result<State, Refusal> {
    if packed.family != runtime.family || pair >= packed.pairs {
        return Err(Refusal::Regime);
    }
    // Refuse the complete public plan before trace/key-switch work.
    let (mut state, edges) = plan_pair(runtime, pair, terms, initial)?;
    let ctx = runtime.ctx;
    let galois = RNSGaloisEvaluator::new(ctx).unwrap();
    for (pattern, destination) in edges.into_iter().enumerate() {
        let mut output = shift(
            ctx,
            &packed.indicators[pattern],
            if pair == 0 { 0 } else { 2 * ctx.n - pair },
        );
        for key in trace {
            output = ctx.add(&output, &galois.apply(&output, key).unwrap());
        }
        state.rows[destination].selector = Some(match state.rows[destination].selector.take() {
            None => output,
            Some(previous) => ctx.add(&previous, &output),
        });
    }
    Ok(state)
}

#[test]
fn precharged_pairs_public_support_covers_arbitrary_centered_terms() {
    let config = config_with(5);
    let ctx = RNSFHEContext::try_new(&config).unwrap();
    let family = [0x50414952, 1];
    let mut cases = 0;
    for q in [5i128, 17, 31] {
        let runtime = CarryRuntime::new(&ctx, q, family, 9);
        let h = q / 2;
        for initial in [-h, 0, h] {
            for a in -h..=h {
                for b in -h..=h {
                    let (state, edges) = plan_pair(&runtime, 0, [a, b], initial).unwrap();
                    assert_eq!(state.coefficients, vec![0, 1]);
                    assert_eq!(
                        state.rows.iter().fold(U512::zero(), |s, r| s.add(r.bound)),
                        runtime.noise.projected.mul_u128(9),
                    );
                    for (pattern, &destination) in edges.iter().enumerate() {
                        let sum =
                            initial + a * (pattern as i128 / 3 - 1) + b * (pattern as i128 % 3 - 1);
                        let row = &state.rows[destination];
                        assert_eq!(row.winding as i128, (sum + h).div_euclid(q));
                        assert_eq!(row.remainder + q * row.winding as i128, sum);
                        for p in ROOT {
                            assert_eq!(
                                runtime.root_value(row, p) as i128,
                                sum.rem_euclid(p as i128)
                            );
                        }
                        cases += 1;
                    }
                }
            }
        }
        assert!(matches!(
            plan_pair(&runtime, 0, [h + 1, 0], 0),
            Err(Refusal::NonCentered)
        ));
        assert!(matches!(
            plan_pair(&runtime, ctx.n / 2, [0, 0], 0),
            Err(Refusal::Regime)
        ));
        let limited = CarryRuntime::new(&ctx, q, family, 1);
        assert!(matches!(
            plan_pair(&limited, 0, [h, h], 0),
            Err(Refusal::StateLimit { .. })
        ));
        let mut dummy = PackedPairs {
            indicators: core::array::from_fn(|_| zero(&ctx)),
            family: [0x50414952, 2],
            pairs: ctx.n / 2,
        };
        assert!(matches!(
            project_pair(&runtime, &dummy, &[], 0, [0, 0], 0),
            Err(Refusal::Regime)
        ));
        dummy.family = family;
        assert!(matches!(
            project_pair(&runtime, &dummy, &[], dummy.pairs, [0, 0], 0),
            Err(Refusal::Regime)
        ));
        assert!(matches!(
            project_pair(&runtime, &dummy, &[], 0, [i128::MIN, 0], 0),
            Err(Refusal::NonCentered)
        ));
        assert!(matches!(
            project_pair(&limited, &dummy, &[], 0, [h, h], 0),
            Err(Refusal::StateLimit { .. })
        ));
        assert_eq!(runtime.multiplications.get(), 0);
    }
    assert_eq!(cases, 34425);
    eprintln!(
        "pair precharge: {cases} public assignments, arbitrary small centered terms, all S8 views"
    );
}

fn assert_state(
    runtime: &CarryRuntime<'_>,
    state: &State,
    source_sum: i128,
    sk: &DualRNSSecretKey,
) -> usize {
    let mut checks = 0;
    let mut projections = vec![(
        runtime.project(state, |r| r.winding),
        (source_sum + runtime.source_q / 2)
            .div_euclid(runtime.source_q)
            .rem_euclid(runtime.ctx.t as i128) as u64,
    )];
    for p in ROOT.into_iter().chain([6, 10, 15, 21, 1, 8, 9, 11, 22, 6]) {
        projections.push((
            runtime.project(state, |r| runtime.root_value(r, p)),
            source_sum.rem_euclid(p as i128) as u64,
        ));
    }
    projections.push((
        runtime.project(state, |r| {
            ((runtime.root_value(r, 11) - runtime.root_value(r, 2)) * 6).rem_euclid(11)
        }),
        source_sum.div_euclid(2).rem_euclid(11) as u64,
    ));
    for (projection, expected) in projections {
        let values = decode_at(
            runtime.ctx,
            &projection.ciphertext,
            sk,
            projection.bound,
            0..runtime.ctx.n,
        );
        assert_eq!(values[0], expected);
        assert!(values[1..].iter().all(|&x| x == 0));
        checks += runtime.ctx.n;
    }
    checks
}

#[test]
#[cfg_attr(
    not(feature = "slow_tests"),
    ignore = "expensive native pair-precharge research probe; enable slow_tests or use --include-ignored"
)]
fn precharged_pairs_extend_carry_and_refresh_four_term_coefficient() {
    let work = SecureConfig::secure_128().into_config();
    let q = work.primes.iter().map(|&p| p as u128).product::<u128>() as i128;
    let h = q / 2;
    let config = config_with(5);
    validate_bootstrap_primes(&config.primes, config.n).unwrap();
    assert!(
        screen_bootstrap_security(&config.primes, config.n, 128)
            .unwrap()
            .meets_claim_under_both
    );
    let ctx = RNSFHEContext::try_new(&config).unwrap();
    let work_ctx = RNSFHEContext::try_new(&work).unwrap();
    let family = [0x50414952, 1];
    let runtime = CarryRuntime::new(&ctx, q, family, 27);
    let mut rng = ShadowHarvester::with_seed(0x50414952);
    let keys = ctx.generate_keys_dual(&mut rng);
    let native = RNSSecretKey {
        s: RNSPolynomial {
            n: ctx.n,
            limbs: ctx
                .rns
                .mont_contexts
                .iter()
                .zip(&keys.secret_key.s.main)
                .map(|(mont, lane)| lane.iter().map(|&x| mont.to_montgomery(x)).collect())
                .collect(),
        },
    };
    let galois = RNSGaloisEvaluator::new(&ctx).unwrap();
    let mut trace = Vec::new();
    let mut stride = ctx.n;
    eprintln!("pair precharge: generating shared trace/relinearization keys");
    while stride > 1 {
        trace.push(
            galois
                .generate_key_with_rng(&native, stride as u64 + 1, &mut rng)
                .unwrap(),
        );
        stride /= 2;
    }
    let relin = runtime
        .exact
        .generate_hybrid_gadget_key_with_rng(&native, &mut rng);
    // All nine pair patterns occur across the packed source. First four pairs
    // select different patterns, including zero and opposite signs.
    let patterns = [
        [1, -1],
        [-1, 1],
        [-1, 0],
        [1, 1],
        [-1, -1],
        [0, 1],
        [0, -1],
        [0, 0],
        [1, 0],
    ];
    let source: Vec<i8> = (0..ctx.n).map(|j| patterns[(j / 2) % 9][j % 2]).collect();
    let encrypted_source = precharge(&ctx, &keys, &source, &mut rng);
    let packed = precharge_pairs(&ctx, &keys, &source, family, &mut rng);
    let mut checks = 0;
    // Check every packed pattern and slot, including unused upper-half slots.
    let fresh_bound = U512::from_u128(config.eta as u128 * (2 * ctx.n as u128 + 1) + 8);
    for pattern in 0..9 {
        let values = decode_at(
            &ctx,
            &packed.indicators[pattern],
            &keys.secret_key,
            fresh_bound,
            0..ctx.n,
        );
        for (j, &value) in values.iter().enumerate() {
            let selected = j < packed.pairs
                && (source[2 * j] + 1) as usize * 3 + (source[2 * j + 1] + 1) as usize == pattern;
            assert_eq!(value, if selected { ctx.t - 8 } else { 0 });
        }
        checks += ctx.n;
    }
    for sign in [1i128, -1] {
        let terms = [
            sign * h,
            -sign * h,
            sign * h,
            sign * h,
            sign * h,
            sign * h,
            sign * h,
            sign * h,
        ];
        let mut blocks = Vec::new();
        for pair in 0..4 {
            eprintln!("pair precharge: sign={sign}, projecting pair={pair}");
            let block = project_pair(
                &runtime,
                &packed,
                &trace,
                pair,
                [terms[2 * pair], terms[2 * pair + 1]],
                if pair == 0 { sign * h } else { 0 },
            )
            .unwrap();
            let selected_sum = (if pair == 0 { sign * h } else { 0 })
                + terms[2 * pair] * source[2 * pair] as i128
                + terms[2 * pair + 1] * source[2 * pair + 1] as i128;
            for row in &block.rows {
                let values = decode_at(
                    &ctx,
                    row.selector.as_ref().unwrap(),
                    &keys.secret_key,
                    row.bound,
                    0..ctx.n,
                );
                assert_eq!(
                    values[0],
                    u64::from(row.remainder + q * row.winding as i128 == selected_sum)
                );
                assert!(values[1..].iter().all(|&x| x == 0));
                checks += ctx.n;
            }
            blocks.push(block);
        }
        let before = runtime.multiplications.get();
        let four = runtime.compose(&blocks[0], &blocks[1], &relin).unwrap();
        assert_eq!(runtime.multiplications.get() - before, 25);
        let six = runtime.compose(&four, &blocks[2], &relin).unwrap();
        assert_eq!(runtime.multiplications.get() - before, 70);
        assert_eq!(four.coefficients, (0..4).collect::<Vec<_>>());
        assert_eq!(six.coefficients, (0..6).collect::<Vec<_>>());
        for (length, state) in [(4, &four), (6, &six)] {
            let sum = sign * h
                + (0..length)
                    .map(|j| terms[j] * source[j] as i128)
                    .sum::<i128>();
            checks += assert_state(&runtime, state, sum, &keys.secret_key);
            eprintln!("pair precharge: sign={sign}, terms={length}, rows={}, carry_bits={}, max_root_bits={}",
                state.rows.len(), bits(runtime.projection_bound(state, |r| r.winding)),
                ROOT.into_iter().map(|p| bits(runtime.projection_bound(state, |r| runtime.root_value(r,p)))).max().unwrap());
        }
        // Outcome-dependent attempt: balanced eight terms, then sequential.
        let right_four = runtime.compose(&blocks[2], &blocks[3], &relin).unwrap();
        let before_refusal = runtime.multiplications.get();
        for (left, right) in [(&four, &right_four), (&six, &blocks[3])] {
            let refusal = runtime.compose(left, right, &relin).err().unwrap();
            assert!(matches!(refusal, Refusal::Noise { .. }));
            assert_eq!(runtime.multiplications.get(), before_refusal);
            eprintln!("pair precharge: sign={sign}, following merge refused before multiplication: {refusal:?}");
        }
        // Actual four-term work-domain coefficient at j=3. All source secret
        // coordinates are encrypted; only the public sparse residual is chosen.
        let mut components = [
            vec![vec![0; work.n]; work.primes.len()],
            vec![vec![0; work.n]; work.primes.len()],
        ];
        for (lane, &p) in work.primes.iter().enumerate() {
            let inv = inverse(work.t % p, p) as u128;
            let encode = |r: i128| (r.rem_euclid(p as i128) as u128 * inv % p as u128) as u64;
            components[0][lane][3] = encode(sign * h);
            for j in 0..4 {
                components[1][lane][3 - j] = encode(terms[j]);
            }
        }
        let carry = runtime.project(&four, |r| r.winding);
        let (affine, refreshed) = refresh_coefficient_at(
            &runtime,
            &work,
            &components,
            &encrypted_source,
            &trace,
            &carry,
            3,
        );
        let (message, old_grid_error) = source_decode_oracle_at(&work_ctx, &components, &source, 3);
        // All four selected trits are nonzero. S=+/-3H has carry +/-1,
        // with the old phase one integer grid unit from the decoding cut.
        assert_eq!(old_grid_error, U256::from_u128((h - 1) as u128));
        for (output, expected) in [(&affine, None), (&refreshed, Some(message))] {
            let values = decode_at(
                &ctx,
                &output.ciphertext,
                &keys.secret_key,
                output.bound,
                0..ctx.n,
            );
            if let Some(value) = expected {
                assert_eq!(values[0], value);
            } else {
                assert_ne!(values[0], message);
            }
            assert!(values[1..].iter().all(|&x| x == 0));
            checks += ctx.n;
        }
        let square_bound = runtime
            .noise
            .multiply(refreshed.bound, refreshed.bound)
            .unwrap();
        let square = runtime
            .exact
            .try_mul_exact(&refreshed.ciphertext, &refreshed.ciphertext, &relin)
            .unwrap();
        let values = decode_at(&ctx, &square, &keys.secret_key, square_bound, 0..ctx.n);
        assert_eq!(
            values[0],
            (message as u128 * message as u128 % ctx.t as u128) as u64
        );
        assert!(values[1..].iter().all(|&x| x == 0));
        checks += ctx.n;
        eprintln!("pair precharge: four-term coefficient refresh sign={sign}, old_grid_distance=H-1, output_bits={}, square_bits={}",
            bits(refreshed.bound), bits(square_bound));
    }
    assert_eq!(checks, 135 * ctx.n);
    assert_eq!(runtime.multiplications.get(), 190);
    let ct_bytes = 2 * ctx.config.primes.len() * ctx.n * 8;
    eprintln!("pair precharge: {checks} coefficient/error checks, packed_bytes={}, shared_key_bytes={}, selector_products=190; full refresh remains unadmitted",
        9 * ct_bytes, runtime.noise.key_words * 8);
}
