//! Terminal readouts of two pair states. No combined one-hot State is emitted.
//! Public lookup differences share selector products across all requested views.

use super::*;

const TRAYS: [u64; 10] = [6, 10, 77, 221, 1, 8, 27, 121, 4199, 65537];

#[derive(Clone)]
struct Query {
    initial: i128,
    sign: i64,
    moduli: Vec<u64>,
}

#[derive(Clone, Copy)]
enum Readout {
    Carry,
    Residue(u64),
    Phase211,
}

fn readouts(query: &Query) -> Vec<Readout> {
    std::iter::once(Readout::Carry)
        .chain(ROOT.into_iter().map(Readout::Residue))
        .chain(std::iter::once(Readout::Phase211))
        .chain(query.moduli.iter().copied().map(Readout::Residue))
        .collect()
}

fn label(q: i128, left: &Row, right: &Row, query: &Query) -> Row {
    let z = query.sign as i128 * (query.initial + left.remainder + right.remainder);
    let crossing = (z + q / 2).div_euclid(q);
    Row {
        remainder: z - q * crossing,
        winding: query.sign * (left.winding + right.winding) + crossing as i64,
        selector: None,
        bound: U512::zero(),
    }
}

fn value(q: i128, row: &Row, output: Readout) -> i64 {
    let residue = |m: u64| {
        ((row.remainder.rem_euclid(m as i128)
            + (row.winding as i128).rem_euclid(m as i128) * q.rem_euclid(m as i128))
            % m as i128) as i64
    };
    match output {
        Readout::Carry => row.winding,
        Readout::Residue(m) => residue(m),
        Readout::Phase211 => ((residue(11) - residue(2)) * 6).rem_euclid(11),
    }
}

struct Differences {
    base: i64,
    left: Vec<i64>,
    right: Vec<i64>,
    mixed: Vec<i64>,
}

impl Differences {
    fn new(table: &[Vec<i64>]) -> Self {
        let base = table[0][0];
        Self {
            base,
            left: table[1..].iter().map(|row| row[0] - base).collect(),
            right: table[0][1..].iter().map(|&v| v - base).collect(),
            mixed: table[1..]
                .iter()
                .flat_map(|row| (1..row.len()).map(move |j| row[j] - row[0] - table[0][j] + base))
                .collect(),
        }
    }
    fn at(&self, i: usize, j: usize) -> i64 {
        self.base
            + if i == 0 { 0 } else { self.left[i - 1] }
            + if j == 0 { 0 } else { self.right[j - 1] }
            + if i == 0 || j == 0 {
                0
            } else {
                self.mixed[(i - 1) * self.right.len() + j - 1]
            }
    }
}

#[derive(Debug, PartialEq, Eq)]
enum TerminalRefusal {
    Regime,
    InvalidQuery,
    WorkLimit { needed: usize, limit: usize },
    OutputLimit { needed: usize, limit: usize },
    Noise(Refusal),
}

struct OutputPlan {
    difference: Differences,
    bound: U512,
}
struct FramePlan {
    query: Query,
    outputs: Vec<OutputPlan>,
}
struct TerminalPlan<'r, 'c> {
    runtime: &'r CarryRuntime<'c>,
    left: &'r State,
    right: &'r State,
    products: Vec<(usize, usize, U512)>,
    frames: Vec<FramePlan>,
}

// A readout frame deliberately is NOT a State and cannot be fed to compose.
// One root's carry/eight lanes/phase and its dependent views share one query.
struct TerminalFrame {
    query: Query,
    views: Vec<Projection>,
}

fn plan_terminal<'r, 'c>(
    runtime: &'r CarryRuntime<'c>,
    left: &'r State,
    right: &'r State,
    queries: &[Query],
    max_products: usize,
    max_outputs: usize,
) -> Result<TerminalPlan<'r, 'c>, TerminalRefusal> {
    let q = runtime.source_q;
    // This private route accepts two actual adjacent-pair states, with no
    // public-unit placeholders or caller-supplied combined-state certificate.
    if q > i128::MAX / 4
        || [left, right].iter().any(|s| {
            s.family != runtime.family
                || s.source_q != q
                || s.rows.is_empty()
                || s.rows.len() > 9
                || s.coefficients.len() != 2
                || s.coefficients[0] % 2 != 0
                || s.coefficients[1] >= runtime.ctx.n
                || s.coefficients[0].checked_add(1) != Some(s.coefficients[1])
                || s.rows.iter().any(|r| {
                    r.selector.is_none()
                        || r.remainder.unsigned_abs() > q as u128 / 2
                        || r.winding.unsigned_abs() > 1
                })
        })
        || left
            .coefficients
            .iter()
            .any(|j| right.coefficients.contains(j))
    {
        return Err(TerminalRefusal::Regime);
    }
    if queries.is_empty()
        || queries.iter().any(|query| {
            ![-1, 1].contains(&query.sign)
                || query.initial.unsigned_abs() > q as u128 / 2
                || query.moduli.iter().any(|&m| m == 0 || m > runtime.ctx.t)
        })
    {
        return Err(TerminalRefusal::InvalidQuery);
    }
    let needed = (left.rows.len() - 1) * (right.rows.len() - 1);
    if needed > max_products {
        return Err(TerminalRefusal::WorkLimit {
            needed,
            limit: max_products,
        });
    }
    let outputs = queries
        .iter()
        .try_fold(0usize, |n, query| {
            query
                .moduli
                .len()
                .checked_add(10)
                .and_then(|count| n.checked_add(count))
        })
        .ok_or(TerminalRefusal::InvalidQuery)?;
    if outputs > max_outputs {
        return Err(TerminalRefusal::OutputLimit {
            needed: outputs,
            limit: max_outputs,
        });
    }
    for row in left.rows.iter().chain(&right.rows) {
        runtime
            .noise
            .admit(row.bound, "terminal input")
            .map_err(TerminalRefusal::Noise)?;
    }
    let mut products = Vec::new();
    for i in 1..left.rows.len() {
        for j in 1..right.rows.len() {
            products.push((
                i,
                j,
                runtime
                    .noise
                    .multiply(left.rows[i].bound, right.rows[j].bound)
                    .map_err(TerminalRefusal::Noise)?,
            ));
        }
    }
    let mut frames = Vec::new();
    for query in queries {
        let mut outputs = Vec::new();
        for output in readouts(query) {
            let table: Vec<Vec<_>> = left
                .rows
                .iter()
                .map(|a| {
                    right
                        .rows
                        .iter()
                        .map(|b| value(q, &label(q, a, b, query), output))
                        .collect()
                })
                .collect();
            let difference = Differences::new(&table);
            // A public delta*base has at most |base| exact-grid error. All
            // selector and product errors, including negative coefficients,
            // are charged in absolute value. No one-hot error cancellation
            // or free noise reset is assumed by this algebraic identity.
            let mut bound = U512::from_u64(difference.base.unsigned_abs());
            for (row, &c) in left.rows[1..]
                .iter()
                .zip(&difference.left)
                .chain(right.rows[1..].iter().zip(&difference.right))
            {
                bound = bound.add(row.bound.mul_u128(c.unsigned_abs() as u128));
            }
            for ((_, _, error), &c) in products.iter().zip(&difference.mixed) {
                bound = bound.add(error.mul_u128(c.unsigned_abs() as u128));
            }
            runtime
                .noise
                .admit(bound, "terminal output")
                .map_err(TerminalRefusal::Noise)?;
            outputs.push(OutputPlan { difference, bound });
        }
        frames.push(FramePlan {
            query: query.clone(),
            outputs,
        });
    }
    Ok(TerminalPlan {
        runtime,
        left,
        right,
        products,
        frames,
    })
}

fn public_constant(ctx: &RNSFHEContext, coefficient: i64) -> RNSCiphertext {
    let mut output = zero(ctx);
    for (lane, &q) in ctx.config.primes.iter().enumerate() {
        let v = ((coefficient as i128).rem_euclid(q as i128) as u128 * ctx.delta_rns[lane] as u128
            % q as u128) as u64;
        output.c0.limbs[lane][0] = ctx.rns.mont_contexts[lane].to_montgomery(v);
    }
    output
}

impl TerminalPlan<'_, '_> {
    fn execute(self, relin: &RNSHybridGadgetKey) -> Vec<TerminalFrame> {
        let ctx = self.runtime.ctx;
        let mut frames: Vec<_> = self
            .frames
            .iter()
            .map(|frame| {
                let views = frame
                    .outputs
                    .iter()
                    .map(|p| {
                        let mut ciphertext = public_constant(ctx, p.difference.base);
                        for (row, &c) in self.left.rows[1..]
                            .iter()
                            .zip(&p.difference.left)
                            .chain(self.right.rows[1..].iter().zip(&p.difference.right))
                        {
                            if c != 0 {
                                add_scaled(ctx, &mut ciphertext, row.selector.as_ref().unwrap(), c);
                            }
                        }
                        Projection {
                            ciphertext,
                            bound: p.bound,
                        }
                    })
                    .collect();
                TerminalFrame {
                    query: frame.query.clone(),
                    views,
                }
            })
            .collect();
        for (index, &(i, j, _)) in self.products.iter().enumerate() {
            let product = self
                .runtime
                .exact
                .try_mul_exact(
                    self.left.rows[i].selector.as_ref().unwrap(),
                    self.right.rows[j].selector.as_ref().unwrap(),
                    relin,
                )
                .unwrap();
            self.runtime
                .multiplications
                .set(self.runtime.multiplications.get() + 1);
            for (frame, planned) in frames.iter_mut().zip(&self.frames) {
                for (view, p) in frame.views.iter_mut().zip(&planned.outputs) {
                    let c = p.difference.mixed[index];
                    if c != 0 {
                        add_scaled(ctx, &mut view.ciphertext, &product, c);
                    }
                }
            }
            // Only this joint ciphertext is live; no 81-row combined state.
        }
        frames
    }
}

fn queries(h: i128) -> Vec<Query> {
    [h, -h + 40]
        .into_iter()
        .flat_map(|initial| {
            [1, -1].into_iter().map(move |sign| Query {
                initial,
                sign,
                moduli: TRAYS.to_vec(),
            })
        })
        .collect()
}

#[test]
fn terminal_readout_mixed_differences_recover_every_small_assignment() {
    let mut checked = 0;
    let mut mixed_needed = 0;
    for q in [5i128, 17, 31] {
        let h = q / 2;
        for initial in [-h, 0, h] {
            for a in [-h, 0, h] {
                for b in [-h, 0, h] {
                    for c in [-h, 0, h] {
                        for d in [-h, 0, h] {
                            let pair_sums = |a, b| {
                                (-1..=1)
                                    .flat_map(move |u| (-1..=1).map(move |v| a * u + b * v))
                                    .collect::<Vec<i128>>()
                            };
                            let left = pair_sums(a, b);
                            let right = pair_sums(c, d);
                            let query = Query {
                                initial,
                                sign: 1,
                                moduli: TRAYS.to_vec(),
                            };
                            for output in readouts(&query) {
                                let table: Vec<Vec<_>> = left
                                    .iter()
                                    .map(|&x| {
                                        right
                                            .iter()
                                            .map(|&y| {
                                                let s = initial + x + y;
                                                let k = (s + h).div_euclid(q);
                                                let r = Row {
                                                    remainder: s - q * k,
                                                    winding: k as i64,
                                                    selector: None,
                                                    bound: U512::zero(),
                                                };
                                                let got = value(q, &r, output);
                                                let expected = match output {
                                                    Readout::Carry => k as i64,
                                                    Readout::Residue(p) => {
                                                        s.rem_euclid(p as i128) as i64
                                                    }
                                                    Readout::Phase211 => {
                                                        s.div_euclid(2).rem_euclid(11) as i64
                                                    }
                                                };
                                                assert_eq!(got, expected);
                                                got
                                            })
                                            .collect()
                                    })
                                    .collect();
                                let diff = Differences::new(&table);
                                for (i, row) in table.iter().enumerate() {
                                    for (j, &expected) in row.iter().enumerate() {
                                        assert_eq!(diff.at(i, j), expected);
                                        if i > 0
                                            && j > 0
                                            && diff.base + diff.left[i - 1] + diff.right[j - 1]
                                                != expected
                                        {
                                            mixed_needed += 1;
                                        }
                                        checked += 1;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    assert_eq!(checked, 1180980);
    assert!(mixed_needed > 0, "linear-only negative control must fail");
    eprintln!("terminal readout: {checked} exact lookup/difference checks, linear-only failures={mixed_needed}");
}

#[test]
fn terminal_readout_plans_without_joint_state_and_refuses_before_execution() {
    let ctx = RNSFHEContext::try_new(&config_with(5)).unwrap();
    let work = SecureConfig::secure_128().into_config();
    let q = work.primes.iter().map(|&p| p as u128).product::<u128>() as i128;
    let h = q / 2;
    let runtime = CarryRuntime::new(&ctx, q, [0x5445524d, 1], 27);
    let mock = |pair, terms| {
        let (mut s, _) = plan_pair(&runtime, pair, terms, 0).unwrap();
        // Public dummy ciphertexts are only for testing plan rejection;
        // this test never executes or claims they are encrypted one-hot data.
        for row in &mut s.rows {
            row.selector = Some(zero(&ctx));
        }
        s
    };
    let left = mock(0, [h - 1, h - 3]);
    let right = mock(1, [h - 9, h - 27]);
    assert_eq!(left.rows.len() * right.rows.len(), 81);
    assert!(matches!(
        runtime.plan_compose(&left, &right),
        Err(Refusal::StateLimit {
            needed: 28,
            limit: 27
        })
    ));
    let qs = queries(h);
    let plan = plan_terminal(&runtime, &left, &right, &qs, 64, 80).unwrap();
    assert_eq!(plan.products.len(), 64);
    assert_eq!(plan.frames.len(), 4);
    drop(plan);
    assert!(matches!(
        plan_terminal(&runtime, &left, &right, &qs, 63, 80),
        Err(TerminalRefusal::WorkLimit {
            needed: 64,
            limit: 63
        })
    ));
    assert!(matches!(
        plan_terminal(&runtime, &left, &right, &qs, 64, 79),
        Err(TerminalRefusal::OutputLimit {
            needed: 80,
            limit: 79
        })
    ));
    for bad in [
        Query {
            initial: h + 1,
            sign: 1,
            moduli: vec![],
        },
        Query {
            initial: 0,
            sign: 0,
            moduli: vec![],
        },
        Query {
            initial: 0,
            sign: 1,
            moduli: vec![0],
        },
        Query {
            initial: 0,
            sign: 1,
            moduli: vec![ctx.t + 1],
        },
    ] {
        assert!(matches!(
            plan_terminal(&runtime, &left, &right, &[bad], 64, 80),
            Err(TerminalRefusal::InvalidQuery)
        ));
    }
    assert!(matches!(
        plan_terminal(&runtime, &left, &left, &qs, 64, 80),
        Err(TerminalRefusal::Regime)
    ));
    let mut bad = right.clone();
    bad.family[1] += 1;
    assert!(matches!(
        plan_terminal(&runtime, &left, &bad, &qs, 64, 80),
        Err(TerminalRefusal::Regime)
    ));
    let mut bad = right.clone();
    bad.rows[0].selector = None;
    assert!(matches!(
        plan_terminal(&runtime, &left, &bad, &qs, 64, 80),
        Err(TerminalRefusal::Regime)
    ));
    let mut bad = right.clone();
    bad.rows[0].bound = runtime.noise.half;
    assert!(matches!(
        plan_terminal(&runtime, &left, &bad, &qs, 64, 80),
        Err(TerminalRefusal::Noise(_))
    ));
    let mut bad = right.clone();
    for row in &mut bad.rows {
        row.bound = pow2(80);
    }
    assert!(matches!(
        plan_terminal(&runtime, &left, &bad, &qs, 64, 80),
        Err(TerminalRefusal::Noise(Refusal::Noise {
            stage: "terminal output",
            ..
        }))
    ));
    assert_eq!(runtime.multiplications.get(), 0);
}

#[test]
#[cfg_attr(
    not(feature = "slow_tests"),
    ignore = "expensive native terminal readout probe; enable slow_tests or use --include-ignored"
)]
fn terminal_readout_native_refreshes_non_cancelling_four_term_sources() {
    let work = SecureConfig::secure_128().into_config();
    let q = work.primes.iter().map(|&p| p as u128).product::<u128>() as i128;
    let h = q / 2;
    let terms = [h - 1, h - 3, h - 9, h - 27];
    let config = config_with(5);
    validate_bootstrap_primes(&config.primes, config.n).unwrap();
    assert!(
        screen_bootstrap_security(&config.primes, config.n, 128)
            .unwrap()
            .meets_claim_under_both
    );
    let ctx = RNSFHEContext::try_new(&config).unwrap();
    let work_ctx = RNSFHEContext::try_new(&work).unwrap();
    let family = [0x5445524d, 1];
    let runtime = CarryRuntime::new(&ctx, q, family, 27);
    let mut rng = ShadowHarvester::with_seed(0x5445524d);
    let keys = ctx.generate_keys_dual(&mut rng);
    let native = RNSSecretKey {
        s: RNSPolynomial {
            n: ctx.n,
            limbs: ctx
                .rns
                .mont_contexts
                .iter()
                .zip(&keys.secret_key.s.main)
                .map(|(m, l)| l.iter().map(|&x| m.to_montgomery(x)).collect())
                .collect(),
        },
    };
    let galois = RNSGaloisEvaluator::new(&ctx).unwrap();
    let mut trace = Vec::new();
    let mut stride = ctx.n;
    eprintln!("terminal native: preparing shared trace/relinearization keys");
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
    let mut source: Vec<i8> = (0..ctx.n)
        .map(|j| {
            let pattern = (j / 2) % 9;
            if j % 2 == 0 {
                (pattern / 3) as i8 - 1
            } else {
                (pattern % 3) as i8 - 1
            }
        })
        .collect();
    source[..4].fill(1);
    let encrypted_source = precharge(&ctx, &keys, &source, &mut rng);
    let packed = precharge_pairs(&ctx, &keys, &source, family, &mut rng);
    let mut states = Vec::new();
    let mut checked = 0;
    for pair in 0..2 {
        eprintln!("terminal native: extracting pair {pair}");
        let state = project_pair(
            &runtime,
            &packed,
            &trace,
            pair,
            [terms[2 * pair], terms[2 * pair + 1]],
            0,
        )
        .unwrap();
        assert_eq!(state.rows.len(), 9);
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
                u64::from(
                    row.remainder + q * row.winding as i128
                        == terms[2 * pair] + terms[2 * pair + 1]
                )
            );
            assert!(actual[1..].iter().all(|&x| x == 0));
            checked += ctx.n;
        }
        states.push(state);
    }
    assert!(matches!(
        runtime.compose(&states[0], &states[1], &relin),
        Err(Refusal::StateLimit {
            needed: 28,
            limit: 27
        })
    ));
    assert_eq!(runtime.multiplications.get(), 0);
    let qs = queries(h);
    let plan = plan_terminal(&runtime, &states[0], &states[1], &qs, 64, 80).unwrap();
    let bounds: Vec<Vec<_>> = plan
        .frames
        .iter()
        .map(|f| f.outputs.iter().map(|o| o.bound).collect())
        .collect();
    eprintln!("terminal native: executing 64 shared selector products for four query frames");
    let frames = plan.execute(&relin);
    assert_eq!(runtime.multiplications.get(), 64);
    for (index, frame) in frames.into_iter().enumerate() {
        let query = frame.query;
        let s = query.sign as i128 * (query.initial + terms.iter().sum::<i128>());
        let carry_value = (s + h).div_euclid(q);
        assert_eq!(
            carry_value,
            query.sign as i128 * if query.initial == h { 2 } else { 1 }
        );
        for ((view, output), bound) in frame.views.iter().zip(readouts(&query)).zip(&bounds[index])
        {
            assert_eq!(view.bound, *bound, "commit must preserve the planned bound");
            let expected = match output {
                Readout::Carry => carry_value.rem_euclid(ctx.t as i128) as u64,
                Readout::Residue(p) => s.rem_euclid(p as i128) as u64,
                Readout::Phase211 => s.div_euclid(2).rem_euclid(11) as u64,
            };
            let actual = decode_at(
                &ctx,
                &view.ciphertext,
                &keys.secret_key,
                view.bound,
                0..ctx.n,
            );
            assert_eq!(actual[0], expected);
            assert!(actual[1..].iter().all(|&x| x == 0));
            checked += ctx.n;
        }
        let mut components = [
            vec![vec![0; work.n]; work.primes.len()],
            vec![vec![0; work.n]; work.primes.len()],
        ];
        for (lane, &p) in work.primes.iter().enumerate() {
            let inv = inverse(work.t % p, p) as u128;
            let encode = |x: i128| (x.rem_euclid(p as i128) as u128 * inv % p as u128) as u64;
            components[0][lane][3] = encode(query.sign as i128 * query.initial);
            for j in 0..4 {
                components[1][lane][3 - j] = encode(query.sign as i128 * terms[j]);
            }
        }
        let (affine, refreshed) = refresh_coefficient_at(
            &runtime,
            &work,
            &components,
            &encrypted_source,
            &trace,
            &frame.views[0],
            3,
        );
        let (message, distance) = source_decode_oracle_at(&work_ctx, &components, &source, 3);
        let cut_offset = if query.initial == h { 42 } else { 1 };
        assert_eq!(distance, U256::from_u128((h - cut_offset) as u128));
        for (view, correct) in [(&affine, false), (&refreshed, true)] {
            let actual = decode_at(
                &ctx,
                &view.ciphertext,
                &keys.secret_key,
                view.bound,
                0..ctx.n,
            );
            if correct {
                assert_eq!(actual[0], message);
            } else {
                assert_ne!(actual[0], message);
            }
            assert!(actual[1..].iter().all(|&x| x == 0));
            checked += ctx.n;
        }
        let square_bound = runtime
            .noise
            .multiply(refreshed.bound, refreshed.bound)
            .unwrap();
        let square = runtime
            .exact
            .try_mul_exact(&refreshed.ciphertext, &refreshed.ciphertext, &relin)
            .unwrap();
        let actual = decode_at(&ctx, &square, &keys.secret_key, square_bound, 0..ctx.n);
        assert_eq!(
            actual[0],
            (message as u128 * message as u128 % ctx.t as u128) as u64
        );
        assert!(actual[1..].iter().all(|&x| x == 0));
        checked += ctx.n;
        eprintln!("terminal native: query={index}, carry={carry_value}, old_grid_distance=H-{cut_offset}, carry_bits={}, max_view_bits={}, square_bits={}",
            bits(frame.views[0].bound),frame.views.iter().map(|v|bits(v.bound)).max().unwrap(),bits(square_bound));
    }
    assert_eq!(checked, 110 * ctx.n);
    assert_eq!(runtime.multiplications.get(), 64);
    eprintln!("terminal native: {checked} coefficient/error checks, 81 possible sums, 64 shared products, four source/sign queries; no combined state or full refresh admission");
}
