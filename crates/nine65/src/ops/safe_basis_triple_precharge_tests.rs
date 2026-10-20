//! One-level terminal readout from two key-holder-precharged three-trit blocks.
//! The evaluator combines two 27-row public supports, but never emits their
//! 729-row product as a reusable State.

use super::*;
use std::collections::BTreeMap;

const TRIPLE_TRAYS: [u64; 11] = [6, 10, 77, 221, 1, 8, 27, 121, 4199, 65537, 20_000];

struct PackedTriples {
    indicators: [RNSCiphertext; 27],
    family: [u64; 2],
    triples: usize,
}

// Key-holder-only precharge. Pattern slots encode three source trits directly
// as independent encryptions; the evaluator never multiplies raw trit inputs.
fn precharge_triples(
    ctx: &RNSFHEContext,
    keys: &super::super::DualRNSKeySet,
    source: &[i8],
    family: [u64; 2],
    rng: &mut ShadowHarvester,
) -> PackedTriples {
    assert_eq!(source.len(), ctx.n);
    assert!(source.iter().all(|u| (-1..=1).contains(u)));
    let indicators = core::array::from_fn(|pattern| {
        let mut values = vec![0i8; ctx.n];
        for (j, triple) in source.chunks_exact(3).enumerate() {
            let encoded = (triple[0] + 1) as usize * 9
                + (triple[1] + 1) as usize * 3
                + (triple[2] + 1) as usize;
            if encoded == pattern {
                values[j] = -8;
            }
        }
        super::super::precharge(ctx, keys, &values, rng)
    });
    PackedTriples {
        indicators,
        family,
        triples: source.len() / 3,
    }
}

fn plan_triple(
    runtime: &CarryRuntime<'_>,
    triple: usize,
    terms: [i128; 3],
    initial: i128,
) -> Result<(State, [usize; 27]), Refusal> {
    if triple >= runtime.ctx.n / 3 {
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
    let mut edges = [0; 27];
    for (pattern, edge) in edges.iter_mut().enumerate() {
        let trits = [
            pattern as i128 / 9 - 1,
            (pattern as i128 / 3) % 3 - 1,
            pattern as i128 % 3 - 1,
        ];
        let sum = initial
            + terms
                .iter()
                .zip(trits)
                .map(|(&term, trit)| term * trit)
                .sum::<i128>();
        let winding = (sum + runtime.source_q / 2).div_euclid(runtime.source_q);
        if winding.unsigned_abs() > 1 {
            return Err(Refusal::Regime);
        }
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
            "merged triple selector",
        )?;
        *edge = index;
    }
    let state = State {
        rows,
        family: runtime.family,
        source_q: runtime.source_q,
        coefficients: vec![3 * triple, 3 * triple + 1, 3 * triple + 2],
    };
    runtime.noise.admit(
        runtime.projection_bound(&state, |r| r.winding),
        "triple carry",
    )?;
    for p in ROOT {
        runtime.noise.admit(
            runtime.projection_bound(&state, |r| runtime.root_value(r, p)),
            "triple root",
        )?;
    }
    Ok((state, edges))
}

fn project_triple(
    runtime: &CarryRuntime<'_>,
    packed: &PackedTriples,
    trace: &[RNSGaloisKey],
    triple: usize,
    terms: [i128; 3],
    initial: i128,
) -> Result<State, Refusal> {
    if packed.family != runtime.family || triple >= packed.triples {
        return Err(Refusal::Regime);
    }
    // Refuse before any shift/trace/key-switch work.
    let (mut state, edges) = plan_triple(runtime, triple, terms, initial)?;
    let ctx = runtime.ctx;
    let galois = RNSGaloisEvaluator::new(ctx).unwrap();
    for (pattern, destination) in edges.into_iter().enumerate() {
        let mut output = shift(
            ctx,
            &packed.indicators[pattern],
            if triple == 0 { 0 } else { 2 * ctx.n - triple },
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

fn test_triple_rows(q: i128, terms: [i128; 3]) -> Vec<Row> {
    let mut rows = Vec::with_capacity(27);
    for pattern in 0..27 {
        let trits = [
            pattern as i128 / 9 - 1,
            (pattern as i128 / 3) % 3 - 1,
            pattern as i128 % 3 - 1,
        ];
        let raw = terms
            .iter()
            .zip(trits)
            .map(|(&term, trit)| term * trit)
            .sum::<i128>();
        let winding = (raw + q / 2).div_euclid(q);
        let label = (raw - winding * q, winding as i64);
        rows.push(Row {
            remainder: label.0,
            winding: label.1,
            selector: None,
            bound: U512::zero(),
        });
    }
    rows
}

fn direct_readout(q: i128, a: &Row, b: &Row, query: &Query, output: Readout) -> i64 {
    let raw =
        query.initial + a.remainder + q * a.winding as i128 + b.remainder + q * b.winding as i128;
    let signed = query.sign as i128 * raw;
    match output {
        Readout::Carry => ((signed + q / 2).div_euclid(q)) as i64,
        Readout::Residue(m) => signed.rem_euclid(m as i128) as i64,
        Readout::Phase211 => signed.div_euclid(2).rem_euclid(11) as i64,
    }
}

#[test]
fn triple_precharge_bivariate_readouts_match_every_small_assignment() {
    let terms = [[14, 12, 10], [8, 6, 4]];
    let left = test_triple_rows(31, terms[0]);
    let right = test_triple_rows(31, terms[1]);
    assert_eq!((left.len(), right.len()), (27, 27));
    let mut checked = 0;
    let mut mixed_needed = 0;
    for initial in [-15, 0, 15] {
        for sign in [-1, 1] {
            let query = Query {
                initial,
                sign,
                moduli: TRIPLE_TRAYS.to_vec(),
            };
            for output in readouts(&query) {
                let table: Vec<Vec<_>> = left
                    .iter()
                    .map(|a| {
                        right
                            .iter()
                            .map(|b| direct_readout(31, a, b, &query, output))
                            .collect()
                    })
                    .collect();
                let diff = Differences::new(&table);
                for (i, row) in table.iter().enumerate() {
                    for (j, &expected) in row.iter().enumerate() {
                        assert_eq!(diff.at(i, j), expected);
                        if i > 0
                            && j > 0
                            && diff.base + diff.left[i - 1] + diff.right[j - 1] != expected
                        {
                            mixed_needed += 1;
                        }
                        checked += 1;
                    }
                }
            }
        }
    }
    assert_eq!(checked, 91_854);
    assert!(mixed_needed > 0, "linear-only negative control must fail");
    eprintln!("triple precharge exact table: {checked} assignment/output checks; linear-only failures={mixed_needed}");
}

fn native_queries(h: i128) -> Vec<Query> {
    [h, -h + 40]
        .into_iter()
        .flat_map(|initial| {
            [1, -1].into_iter().map(move |sign| Query {
                initial,
                sign,
                moduli: TRIPLE_TRAYS.to_vec(),
            })
        })
        .collect()
}

#[test]
fn triple_precharge_terminal_plan_preflights_all_views_and_limits() {
    let ctx = RNSFHEContext::try_new(&config_with(5)).unwrap();
    let work = SecureConfig::secure_128().into_config();
    let q = work.primes.iter().map(|&p| p as u128).product::<u128>() as i128;
    let h = q / 2;
    let runtime = CarryRuntime::new(&ctx, q, [0x54524950, 1], 27);
    let weights = [h - 1, h - 3, h - 9, h - 27, h - 81, h - 243];
    let mut states = Vec::new();
    for triple in 0..2 {
        let terms = [
            weights[triple * 3],
            weights[triple * 3 + 1],
            weights[triple * 3 + 2],
        ];
        let (mut state, _) = plan_triple(&runtime, triple, terms, 0).unwrap();
        assert_eq!(state.rows.len(), 27);
        for row in &mut state.rows {
            row.selector = Some(zero(&ctx));
        }
        states.push(state);
    }
    let queries = native_queries(h);
    let plan = plan_terminal(&runtime, &states[0], &states[1], &queries, 676, 84).unwrap();
    assert_eq!(plan.products.len(), 676);
    assert_eq!(plan.frames.len(), 4);
    let carry_bits: Vec<_> = plan
        .frames
        .iter()
        .map(|f| bits(f.outputs[0].bound))
        .collect();
    let max_view_bits = plan
        .frames
        .iter()
        .flat_map(|f| f.outputs.iter().map(|o| bits(o.bound)))
        .max()
        .unwrap();
    assert!(carry_bits.iter().all(|&b| b < 100), "{carry_bits:?}");
    assert!(max_view_bits < 110, "{max_view_bits}");
    drop(plan);
    assert!(matches!(
        plan_terminal(&runtime, &states[0], &states[1], &queries, 675, 84),
        Err(TerminalRefusal::WorkLimit {
            needed: 676,
            limit: 675
        })
    ));
    assert!(matches!(
        plan_terminal(&runtime, &states[0], &states[1], &queries, 676, 83),
        Err(TerminalRefusal::OutputLimit {
            needed: 84,
            limit: 83
        })
    ));
    let mut nonadjacent = states[1].clone();
    nonadjacent.coefficients[0] += 3;
    nonadjacent.coefficients[1] += 3;
    nonadjacent.coefficients[2] += 3;
    assert!(matches!(
        plan_terminal(&runtime, &states[0], &nonadjacent, &queries, 676, 84),
        Err(TerminalRefusal::Regime)
    ));
    assert_eq!(runtime.multiplications.get(), 0);
    eprintln!("triple precharge preflight: carry bits={carry_bits:?}, maximum view bits={max_view_bits}, products=676, outputs=84; 675-product and 83-output plans refused before multiplication");
}

#[test]
#[cfg_attr(
    not(feature = "slow_tests"),
    ignore = "expensive native triple-precharge terminal readout and refresh; enable slow_tests or use --include-ignored"
)]
fn triple_precharge_native_readouts_refresh_and_square() {
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
    let family = [0x54524950, 1];
    let runtime = CarryRuntime::new(&ctx, q, family, 27);
    let mut rng = ShadowHarvester::with_seed(0x54524950);
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
    eprintln!("triple precharge native: preparing shared trace/relinearization keys");
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
    let source = vec![1i8; ctx.n];
    let encrypted_source = precharge(&ctx, &keys, &source, &mut rng);
    eprintln!("triple precharge native: encrypting 27 direct pattern indicators");
    let packed = precharge_triples(&ctx, &keys, &source, family, &mut rng);
    let weights = [h - 1, h - 3, h - 9, h - 27, h - 81, h - 243];
    let mut states = Vec::new();
    let mut checks = 0usize;
    for triple in 0..2 {
        eprintln!("triple precharge native: projecting block {triple}");
        let terms = [
            weights[triple * 3],
            weights[triple * 3 + 1],
            weights[triple * 3 + 2],
        ];
        let state = project_triple(&runtime, &packed, &trace, triple, terms, 0).unwrap();
        assert_eq!(state.rows.len(), 27);
        let selected_sum = terms.into_iter().sum::<i128>();
        for row in &state.rows {
            let actual = decode_at(
                &ctx,
                row.selector.as_ref().unwrap(),
                &keys.secret_key,
                row.bound,
                0..ctx.n,
            );
            assert_eq!(
                actual[0],
                u64::from(row.remainder + q * row.winding as i128 == selected_sum)
            );
            assert!(actual[1..].iter().all(|&x| x == 0));
            checks += ctx.n;
        }
        states.push(state);
    }
    assert!(matches!(
        runtime.plan_compose(&states[0], &states[1]),
        Err(Refusal::StateLimit {
            needed: 28,
            limit: 27
        })
    ));
    assert_eq!(runtime.multiplications.get(), 0);

    let queries = native_queries(h);
    let plan = plan_terminal(&runtime, &states[0], &states[1], &queries, 676, 84).unwrap();
    assert_eq!(plan.products.len(), 676);
    let bounds: Vec<Vec<_>> = plan
        .frames
        .iter()
        .map(|f| f.outputs.iter().map(|o| o.bound).collect())
        .collect();
    eprintln!(
        "triple precharge native: executing 676 shared selector products for 84 dependent views"
    );
    let frames = plan.execute(&relin);
    assert_eq!(runtime.multiplications.get(), 676);
    for (frame_index, frame) in frames.iter().enumerate() {
        let query = &frame.query;
        let signed = query.sign as i128 * (query.initial + weights.iter().sum::<i128>());
        let expected_carry = (signed + q / 2).div_euclid(q);
        for ((view, output), bound) in frame
            .views
            .iter()
            .zip(readouts(query))
            .zip(&bounds[frame_index])
        {
            assert_eq!(view.bound, *bound, "commit must preserve planned bound");
            let expected = match output {
                Readout::Carry => expected_carry.rem_euclid(ctx.t as i128) as u64,
                Readout::Residue(m) => signed.rem_euclid(m as i128) as u64,
                Readout::Phase211 => signed.div_euclid(2).rem_euclid(11) as u64,
            };
            let actual = decode_at(
                &ctx,
                &view.ciphertext,
                &keys.secret_key,
                view.bound,
                0..ctx.n,
            );
            assert_eq!(
                actual[0], expected,
                "frame={frame_index}, output={output:?}"
            );
            assert!(actual[1..].iter().all(|&x| x == 0));
            checks += ctx.n;
        }
        // Check the dependent phase against its 2- and 11-residue sister views.
        let phase = decode_at(
            &ctx,
            &frame.views[9].ciphertext,
            &keys.secret_key,
            frame.views[9].bound,
            0..ctx.n,
        );
        let parity = decode_at(
            &ctx,
            &frame.views[1].ciphertext,
            &keys.secret_key,
            frame.views[1].bound,
            0..ctx.n,
        );
        let root11 = decode_at(
            &ctx,
            &frame.views[5].ciphertext,
            &keys.secret_key,
            frame.views[5].bound,
            0..ctx.n,
        );
        assert_eq!((2 * phase[0] + parity[0]) % 11, root11[0] % 11);
    }

    // The first frame is H,+: its hidden winding repairs the sparse six-term
    // source coefficient, and the newly bounded result must survive a square.
    let mut components = [
        vec![vec![0; work.n]; work.primes.len()],
        vec![vec![0; work.n]; work.primes.len()],
    ];
    for (lane, &prime) in work.primes.iter().enumerate() {
        let inverse_t = inverse(work.t % prime, prime) as u128;
        let encode = |value: i128| {
            (value.rem_euclid(prime as i128) as u128 * inverse_t % prime as u128) as u64
        };
        components[0][lane][5] = encode(h);
        for (index, &weight) in weights.iter().enumerate() {
            components[1][lane][5 - index] = encode(weight);
        }
    }
    let carry = Projection {
        ciphertext: frames[0].views[0].ciphertext.clone(),
        bound: frames[0].views[0].bound,
    };
    let (affine, refreshed) = refresh_coefficient_at(
        &runtime,
        &work,
        &components,
        &encrypted_source,
        &trace,
        &carry,
        5,
    );
    let (message, grid_distance) = source_decode_oracle_at(&work_ctx, &components, &source, 5);
    assert_ne!(grid_distance, U256::zero());
    let affine_values = decode_at(
        &ctx,
        &affine.ciphertext,
        &keys.secret_key,
        affine.bound,
        0..ctx.n,
    );
    assert_ne!(affine_values[0], message, "the hidden carry is necessary");
    assert!(affine_values[1..].iter().all(|&x| x == 0));
    let refreshed_values = decode_at(
        &ctx,
        &refreshed.ciphertext,
        &keys.secret_key,
        refreshed.bound,
        0..ctx.n,
    );
    assert_eq!(refreshed_values[0], message);
    assert!(refreshed_values[1..].iter().all(|&x| x == 0));
    checks += 2 * ctx.n;

    let square_bound = runtime
        .noise
        .multiply(refreshed.bound, refreshed.bound)
        .expect("triple-precharged refresh square should pass before execution");
    assert!(bits(square_bound) < bits(runtime.noise.half));
    let square = runtime
        .exact
        .try_mul_exact(&refreshed.ciphertext, &refreshed.ciphertext, &relin)
        .unwrap();
    runtime
        .multiplications
        .set(runtime.multiplications.get() + 1);
    let square_values = decode_at(&ctx, &square, &keys.secret_key, square_bound, 0..ctx.n);
    assert_eq!(
        square_values[0],
        (message as u128 * message as u128 % ctx.t as u128) as u64
    );
    assert!(square_values[1..].iter().all(|&x| x == 0));
    checks += ctx.n;
    assert_eq!(checks, 141 * ctx.n);
    assert_eq!(runtime.multiplications.get(), 677);
    eprintln!("triple precharge native: {checks} coefficient/error checks, 27 precharged patterns, 54 projected selectors, 84 root/tray/phase/carry views; refreshed output bits={}, square bits={}, selector products=676+1; all 19 sister moduli admitted", bits(refreshed.bound), bits(square_bound));
}
