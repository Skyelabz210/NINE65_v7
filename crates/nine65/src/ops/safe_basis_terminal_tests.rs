//! Terminal readouts of two adjacent precharged blocks. No combined one-hot State is emitted.
//! Public lookup differences share selector products across all requested views.

use super::*;

#[path = "safe_basis_triple_precharge_tests.rs"]
mod triple_precharge;

const TRAYS: [u64; 10] = [6, 10, 77, 221, 1, 8, 27, 121, 4199, 65537];

#[derive(Clone)]
struct Query {
    initial: i128,
    sign: i64,
    moduli: Vec<u64>,
}

#[derive(Clone, Copy, Debug)]
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

// Three precharged pair states use a multilinear expansion on their 9x9x9
// public labels. This keeps a terminal readout from materializing the 729-row
// combined State. The 8x8x8 top-order coefficients are genuine mixed
// differences and are charged as such by the planner below.
struct CubeDifferences {
    base: i64,
    a: Vec<i64>,
    b: Vec<i64>,
    c: Vec<i64>,
    ab: Vec<i64>,
    ac: Vec<i64>,
    bc: Vec<i64>,
    abc: Vec<i64>,
}

impl CubeDifferences {
    fn new(table: &[Vec<Vec<i64>>]) -> Self {
        assert_eq!(table.len(), 9);
        assert!(table.iter().all(|plane| plane.len() == 9));
        assert!(table.iter().flatten().all(|row| row.len() == 9));
        let base = table[0][0][0];
        let a = (1..9).map(|i| table[i][0][0] - base).collect();
        let b = (1..9).map(|j| table[0][j][0] - base).collect();
        let c = (1..9).map(|k| table[0][0][k] - base).collect();
        let ab = (1..9)
            .flat_map(|i| {
                (1..9).map(move |j| table[i][j][0] - table[i][0][0] - table[0][j][0] + base)
            })
            .collect();
        let ac = (1..9)
            .flat_map(|i| {
                (1..9).map(move |k| table[i][0][k] - table[i][0][0] - table[0][0][k] + base)
            })
            .collect();
        let bc = (1..9)
            .flat_map(|j| {
                (1..9).map(move |k| table[0][j][k] - table[0][j][0] - table[0][0][k] + base)
            })
            .collect();
        let abc = (1..9)
            .flat_map(|i| {
                (1..9).flat_map(move |j| {
                    (1..9).map(move |k| {
                        table[i][j][k] - table[i][j][0] - table[i][0][k] - table[0][j][k]
                            + table[i][0][0]
                            + table[0][j][0]
                            + table[0][0][k]
                            - base
                    })
                })
            })
            .collect();
        Self {
            base,
            a,
            b,
            c,
            ab,
            ac,
            bc,
            abc,
        }
    }

    fn at(&self, i: usize, j: usize, k: usize) -> i64 {
        let mut out = self.base;
        if i > 0 {
            out += self.a[i - 1];
        }
        if j > 0 {
            out += self.b[j - 1];
        }
        if k > 0 {
            out += self.c[k - 1];
        }
        if i > 0 && j > 0 {
            out += self.ab[(i - 1) * 8 + j - 1];
        }
        if i > 0 && k > 0 {
            out += self.ac[(i - 1) * 8 + k - 1];
        }
        if j > 0 && k > 0 {
            out += self.bc[(j - 1) * 8 + k - 1];
        }
        if i > 0 && j > 0 && k > 0 {
            out += self.abc[((i - 1) * 8 + j - 1) * 8 + k - 1];
        }
        out
    }

    fn nonzero(&self) -> (usize, usize, usize) {
        (
            self.ab.iter().filter(|&&x| x != 0).count()
                + self.ac.iter().filter(|&&x| x != 0).count()
                + self.bc.iter().filter(|&&x| x != 0).count(),
            self.abc.iter().filter(|&&x| x != 0).count(),
            self.abc.len(),
        )
    }
}

fn three_pair_carry(q: i128, initial: i128, sign: i64, rows: [&Row; 3]) -> i64 {
    let raw = initial
        + rows
            .into_iter()
            .map(|row| row.remainder + q * row.winding as i128)
            .sum::<i128>();
    (sign as i128 * raw + q / 2).div_euclid(q) as i64
}

fn three_pair_readout(q: i128, initial: i128, sign: i64, rows: [&Row; 3], output: Readout) -> i64 {
    let raw = initial
        + rows
            .into_iter()
            .map(|row| row.remainder + q * row.winding as i128)
            .sum::<i128>();
    let signed = sign as i128 * raw;
    match output {
        Readout::Carry => ((signed + q / 2).div_euclid(q)) as i64,
        Readout::Residue(modulus) => signed.rem_euclid(modulus as i128) as i64,
        Readout::Phase211 => signed.div_euclid(2).rem_euclid(11) as i64,
    }
}

fn cube_table(
    runtime: &CarryRuntime<'_>,
    states: [&State; 3],
    initial: i128,
    sign: i64,
    output: Readout,
) -> Vec<Vec<Vec<i64>>> {
    states[0]
        .rows
        .iter()
        .map(|a| {
            states[1]
                .rows
                .iter()
                .map(|b| {
                    states[2]
                        .rows
                        .iter()
                        .map(|c| {
                            three_pair_readout(runtime.source_q, initial, sign, [a, b, c], output)
                        })
                        .collect()
                })
                .collect()
        })
        .collect()
}

fn cube_error_bound(
    runtime: &CarryRuntime<'_>,
    states: [&State; 3],
    diff: &CubeDifferences,
) -> Result<U512, Refusal> {
    let mut ab = vec![U512::zero(); 64];
    let mut ac = vec![U512::zero(); 64];
    let mut bc = vec![U512::zero(); 64];
    for i in 1..9 {
        for j in 1..9 {
            let index = (i - 1) * 8 + j - 1;
            ab[index] = runtime
                .noise
                .multiply(states[0].rows[i].bound, states[1].rows[j].bound)?;
            ac[index] = runtime
                .noise
                .multiply(states[0].rows[i].bound, states[2].rows[j].bound)?;
            bc[index] = runtime
                .noise
                .multiply(states[1].rows[i].bound, states[2].rows[j].bound)?;
        }
    }
    let mut bound = U512::from_u64(diff.base.unsigned_abs());
    for (rows, coefficients) in [
        (&states[0].rows, &diff.a),
        (&states[1].rows, &diff.b),
        (&states[2].rows, &diff.c),
    ] {
        for (row, coefficient) in rows[1..].iter().zip(coefficients) {
            bound = bound.add(row.bound.mul_u128(coefficient.unsigned_abs() as u128));
        }
    }
    for (coefficients, errors) in [(&diff.ab, &ab), (&diff.ac, &ac), (&diff.bc, &bc)] {
        for (coefficient, error) in coefficients.iter().zip(errors) {
            bound = bound.add(error.mul_u128(coefficient.unsigned_abs() as u128));
        }
    }
    for i in 1..9 {
        for j in 1..9 {
            for k in 1..9 {
                let coefficient = diff.abc[((i - 1) * 8 + j - 1) * 8 + k - 1];
                if coefficient != 0 {
                    let triple = runtime
                        .noise
                        .multiply(ab[(i - 1) * 8 + j - 1], states[2].rows[k].bound)?;
                    bound = bound.add(triple.mul_u128(coefficient.unsigned_abs() as u128));
                }
            }
        }
    }
    runtime.noise.admit(bound, "three-pair terminal output")
}

fn execute_cube_batch(
    runtime: &CarryRuntime<'_>,
    states: [&State; 3],
    differences: &[CubeDifferences],
    relin: &RNSHybridGadgetKey,
) -> Vec<RNSCiphertext> {
    for difference in differences {
        cube_error_bound(runtime, states, difference).unwrap();
    }
    let ctx = runtime.ctx;
    let mut outputs: Vec<_> = differences
        .iter()
        .map(|diff| {
            let mut output = public_constant(ctx, diff.base);
            for (row, &coefficient) in states[0].rows[1..].iter().zip(&diff.a) {
                add_scaled(
                    ctx,
                    &mut output,
                    row.selector.as_ref().unwrap(),
                    coefficient,
                );
            }
            for (row, &coefficient) in states[1].rows[1..].iter().zip(&diff.b) {
                add_scaled(
                    ctx,
                    &mut output,
                    row.selector.as_ref().unwrap(),
                    coefficient,
                );
            }
            for (row, &coefficient) in states[2].rows[1..].iter().zip(&diff.c) {
                add_scaled(
                    ctx,
                    &mut output,
                    row.selector.as_ref().unwrap(),
                    coefficient,
                );
            }
            output
        })
        .collect();

    for i in 1..9 {
        for j in 1..9 {
            let needs_ab = differences.iter().any(|diff| {
                diff.ab[(i - 1) * 8 + j - 1] != 0
                    || (1..9).any(|k| diff.abc[((i - 1) * 8 + j - 1) * 8 + k - 1] != 0)
            });
            if !needs_ab {
                continue;
            }
            let xy = runtime
                .exact
                .try_mul_exact(
                    states[0].rows[i].selector.as_ref().unwrap(),
                    states[1].rows[j].selector.as_ref().unwrap(),
                    relin,
                )
                .unwrap();
            runtime
                .multiplications
                .set(runtime.multiplications.get() + 1);
            for (output, diff) in outputs.iter_mut().zip(differences) {
                let coefficient = diff.ab[(i - 1) * 8 + j - 1];
                if coefficient != 0 {
                    add_scaled(ctx, output, &xy, coefficient);
                }
            }
            for k in 1..9 {
                if !differences
                    .iter()
                    .any(|diff| diff.abc[((i - 1) * 8 + j - 1) * 8 + k - 1] != 0)
                {
                    continue;
                }
                let xyz = runtime
                    .exact
                    .try_mul_exact(&xy, states[2].rows[k].selector.as_ref().unwrap(), relin)
                    .unwrap();
                runtime
                    .multiplications
                    .set(runtime.multiplications.get() + 1);
                for (output, diff) in outputs.iter_mut().zip(differences) {
                    let coefficient = diff.abc[((i - 1) * 8 + j - 1) * 8 + k - 1];
                    if coefficient != 0 {
                        add_scaled(ctx, output, &xyz, coefficient);
                    }
                }
            }
        }
    }
    for (left, right, surface) in [(0, 2, 1), (1, 2, 2)] {
        for i in 1..9 {
            for j in 1..9 {
                let needs_product = differences.iter().any(|diff| {
                    let coefficients = match surface {
                        1 => &diff.ac,
                        _ => &diff.bc,
                    };
                    coefficients[(i - 1) * 8 + j - 1] != 0
                });
                if !needs_product {
                    continue;
                }
                let product = runtime
                    .exact
                    .try_mul_exact(
                        states[left].rows[i].selector.as_ref().unwrap(),
                        states[right].rows[j].selector.as_ref().unwrap(),
                        relin,
                    )
                    .unwrap();
                runtime
                    .multiplications
                    .set(runtime.multiplications.get() + 1);
                for (output, diff) in outputs.iter_mut().zip(differences) {
                    let coefficient = match surface {
                        1 => diff.ac[(i - 1) * 8 + j - 1],
                        _ => diff.bc[(i - 1) * 8 + j - 1],
                    };
                    if coefficient != 0 {
                        add_scaled(ctx, output, &product, coefficient);
                    }
                }
            }
        }
    }
    outputs
}

enum ResiduePlanKind {
    Linear(Vec<Projection>),
    Cube(CubeDifferences),
}

struct ResiduePlan {
    kind: ResiduePlanKind,
    offset: i64,
    bound: U512,
}

fn plan_three_pair_residue(
    runtime: &CarryRuntime<'_>,
    states: [&State; 3],
    initial: i128,
    sign: i64,
    modulus: u64,
) -> Result<ResiduePlan, TerminalRefusal> {
    if modulus == 0 || modulus > runtime.ctx.t {
        return Err(TerminalRefusal::InvalidQuery);
    }
    let m = modulus as i128;
    let offset = (sign as i128 * initial).rem_euclid(m) as i64;
    if modulus == runtime.ctx.t || 4u128 * ((modulus - 1) as u128) < runtime.ctx.t as u128 {
        let mut bound = U512::from_u64(offset.unsigned_abs());
        let mut components = Vec::new();
        for state in states {
            let projection = runtime.project(state, |row| {
                (sign as i128 * (row.remainder + runtime.source_q * row.winding as i128))
                    .rem_euclid(m) as i64
            });
            bound = bound.add(projection.bound);
            components.push(projection);
        }
        runtime
            .noise
            .admit(bound, "three-pair additive residue")
            .map_err(TerminalRefusal::Noise)?;
        Ok(ResiduePlan {
            kind: ResiduePlanKind::Linear(components),
            offset,
            bound,
        })
    } else {
        let diff = CubeDifferences::new(&cube_table(
            runtime,
            states,
            initial,
            sign,
            Readout::Residue(modulus),
        ));
        let bound = cube_error_bound(runtime, states, &diff).map_err(TerminalRefusal::Noise)?;
        Ok(ResiduePlan {
            kind: ResiduePlanKind::Cube(diff),
            offset,
            bound,
        })
    }
}

fn execute_three_pair_residue(
    runtime: &CarryRuntime<'_>,
    states: [&State; 3],
    plan: ResiduePlan,
    relin: &RNSHybridGadgetKey,
) -> Projection {
    let ciphertext = match plan.kind {
        ResiduePlanKind::Linear(components) => components.into_iter().fold(
            public_constant(runtime.ctx, plan.offset),
            |sum, component| runtime.ctx.add(&sum, &component.ciphertext),
        ),
        ResiduePlanKind::Cube(diff) => execute_cube_batch(runtime, states, &[diff], relin)
            .into_iter()
            .next()
            .unwrap(),
    };
    Projection {
        ciphertext,
        bound: plan.bound,
    }
}

struct Phase211Plan {
    phase: Vec<Projection>,
    parity: Vec<Projection>,
    offset_phase: i64,
    offset_parity: i64,
    bound: U512,
}

fn plan_three_pair_phase211(
    runtime: &CarryRuntime<'_>,
    states: [&State; 3],
    initial: i128,
    sign: i64,
) -> Result<Phase211Plan, TerminalRefusal> {
    let offset = sign as i128 * initial;
    let offset_phase = offset.div_euclid(2).rem_euclid(11) as i64;
    let offset_parity = offset.rem_euclid(2) as i64;
    let phase = states
        .iter()
        .map(|state| {
            runtime.project(*state, |row| {
                let signed =
                    sign as i128 * (row.remainder + runtime.source_q * row.winding as i128);
                signed.div_euclid(2).rem_euclid(11) as i64
            })
        })
        .collect::<Vec<_>>();
    let parity = states
        .iter()
        .map(|state| runtime.project(*state, |row| runtime.root_value(row, 2)))
        .collect::<Vec<_>>();
    let pair_bounds = [
        runtime.noise.multiply(parity[0].bound, parity[1].bound),
        runtime.noise.multiply(parity[0].bound, parity[2].bound),
        runtime.noise.multiply(parity[1].bound, parity[2].bound),
    ]
    .into_iter()
    .collect::<Result<Vec<_>, _>>()
    .map_err(TerminalRefusal::Noise)?;
    let triple_bound = runtime
        .noise
        .multiply(pair_bounds[0], parity[2].bound)
        .map_err(TerminalRefusal::Noise)?;
    let mut bound = U512::from_u64(offset_phase.unsigned_abs());
    for projection in &phase {
        bound = bound.add(projection.bound);
    }
    if offset_parity != 0 {
        for projection in &parity {
            bound = bound.add(projection.bound);
        }
    }
    for error in pair_bounds {
        bound = bound.add(error);
    }
    bound = bound.add(triple_bound.mul_u128(2));
    runtime
        .noise
        .admit(bound, "three-pair 2/11 phase")
        .map_err(TerminalRefusal::Noise)?;
    Ok(Phase211Plan {
        phase,
        parity,
        offset_phase,
        offset_parity,
        bound,
    })
}

fn execute_three_pair_phase211(
    runtime: &CarryRuntime<'_>,
    plan: Phase211Plan,
    relin: &RNSHybridGadgetKey,
) -> Projection {
    let mut ciphertext = public_constant(runtime.ctx, plan.offset_phase);
    for projection in &plan.phase {
        ciphertext = runtime.ctx.add(&ciphertext, &projection.ciphertext);
    }
    if plan.offset_parity != 0 {
        for projection in &plan.parity {
            ciphertext = runtime.ctx.add(&ciphertext, &projection.ciphertext);
        }
    }
    let coefficient = if plan.offset_parity == 0 { 1 } else { -1 };
    let p12 = runtime
        .exact
        .try_mul_exact(
            &plan.parity[0].ciphertext,
            &plan.parity[1].ciphertext,
            relin,
        )
        .unwrap();
    let p13 = runtime
        .exact
        .try_mul_exact(
            &plan.parity[0].ciphertext,
            &plan.parity[2].ciphertext,
            relin,
        )
        .unwrap();
    let p23 = runtime
        .exact
        .try_mul_exact(
            &plan.parity[1].ciphertext,
            &plan.parity[2].ciphertext,
            relin,
        )
        .unwrap();
    let p123 = runtime
        .exact
        .try_mul_exact(&p12, &plan.parity[2].ciphertext, relin)
        .unwrap();
    for product in [&p12, &p13, &p23] {
        add_scaled(runtime.ctx, &mut ciphertext, product, coefficient);
    }
    add_scaled(
        runtime.ctx,
        &mut ciphertext,
        &p123,
        if plan.offset_parity == 0 { -2 } else { 2 },
    );
    runtime
        .multiplications
        .set(runtime.multiplications.get() + 4);
    Projection {
        ciphertext,
        bound: plan.bound,
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
    // This private route accepts two actual adjacent precharged blocks (two
    // or three trits each), with no public-unit placeholders or caller-
    // supplied combined-state certificate.
    let block_width = left.coefficients.len();
    if q > i128::MAX / 4
        || ![2, 3].contains(&block_width)
        || right.coefficients.len() != block_width
        || [left, right].iter().any(|s| {
            s.family != runtime.family
                || s.source_q != q
                || s.rows.is_empty()
                || s.rows.len() > 3usize.pow(block_width as u32)
                || s.coefficients.len() != block_width
                || s.coefficients[0] % block_width != 0
                || s.coefficients
                    .windows(2)
                    .any(|w| w[0].checked_add(1) != Some(w[1]))
                || s.coefficients.last().copied().unwrap_or(runtime.ctx.n) >= runtime.ctx.n
                || s.rows.iter().any(|r| {
                    r.selector.is_none()
                        || r.remainder.unsigned_abs() > q as u128 / 2
                        || r.winding.unsigned_abs() > 1
                })
        })
        || left.coefficients.last().and_then(|j| j.checked_add(1))
            != right.coefficients.first().copied()
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
fn terminal_three_pair_carry_and_additive_211_phase_are_exact() {
    let q = 31i128;
    let h = q / 2;
    let weights = [14, 12, 10, 8, 6, 4];
    let pair_rows = |a: i128, b: i128| {
        (-1..=1)
            .flat_map(move |x| {
                (-1..=1).map(move |y| {
                    let raw = a * x + b * y;
                    let winding = (raw + h).div_euclid(q);
                    Row {
                        remainder: raw - q * winding,
                        winding: winding as i64,
                        selector: None,
                        bound: U512::zero(),
                    }
                })
            })
            .collect::<Vec<_>>()
    };
    let a = pair_rows(weights[0], weights[1]);
    let b = pair_rows(weights[2], weights[3]);
    let c = pair_rows(weights[4], weights[5]);
    let mut assignments = 0;
    let mut carry_cubic_terms = 0;
    let mut linear_pair_failures = 0;
    for initial in [-h, h] {
        for sign in [-1, 1] {
            let table: Vec<Vec<Vec<_>>> = a
                .iter()
                .map(|ra| {
                    b.iter()
                        .map(|rb| {
                            c.iter()
                                .map(|rc| three_pair_carry(q, initial, sign, [ra, rb, rc]))
                                .collect()
                        })
                        .collect()
                })
                .collect();
            let differences = CubeDifferences::new(&table);
            carry_cubic_terms += differences
                .abc
                .iter()
                .filter(|&&coefficient| coefficient != 0)
                .count();
            for (i, row) in table.iter().enumerate() {
                for (j, column) in row.iter().enumerate() {
                    for (k, &expected) in column.iter().enumerate() {
                        assert_eq!(differences.at(i, j, k), expected);
                        let linear_pair_only = differences.base
                            + if i == 0 { 0 } else { differences.a[i - 1] }
                            + if j == 0 { 0 } else { differences.b[j - 1] }
                            + if k == 0 { 0 } else { differences.c[k - 1] }
                            + if i == 0 || j == 0 {
                                0
                            } else {
                                differences.ab[(i - 1) * 8 + j - 1]
                            }
                            + if i == 0 || k == 0 {
                                0
                            } else {
                                differences.ac[(i - 1) * 8 + k - 1]
                            }
                            + if j == 0 || k == 0 {
                                0
                            } else {
                                differences.bc[(j - 1) * 8 + k - 1]
                            };
                        linear_pair_failures += usize::from(linear_pair_only != expected);

                        let parts = [
                            sign as i128 * (initial + a[i].remainder + q * a[i].winding as i128),
                            sign as i128 * (b[j].remainder + q * b[j].winding as i128),
                            sign as i128 * (c[k].remainder + q * c[k].winding as i128),
                        ];
                        let parities = parts.map(|part| part.rem_euclid(2));
                        let phase_parts = parts.map(|part| part.div_euclid(2).rem_euclid(11));
                        let phase = (phase_parts.into_iter().sum::<i128>()
                            + (parities.into_iter().sum::<i128>() / 2))
                            .rem_euclid(11);
                        let signed_total = sign as i128
                            * (initial
                                + a[i].remainder
                                + q * a[i].winding as i128
                                + b[j].remainder
                                + q * b[j].winding as i128
                                + c[k].remainder
                                + q * c[k].winding as i128);
                        assert_eq!(phase, signed_total.div_euclid(2).rem_euclid(11));
                        for modulus in [2i128, 6, 11, 77, 221, 4199] {
                            assert_eq!(
                                signed_total.rem_euclid(modulus),
                                parts
                                    .into_iter()
                                    .map(|part| part.rem_euclid(modulus))
                                    .sum::<i128>()
                                    .rem_euclid(modulus)
                            );
                        }
                        assignments += 1;
                    }
                }
            }
        }
    }
    assert_eq!(assignments, 2 * 2 * 9usize.pow(3));
    assert!(carry_cubic_terms > 0);
    assert!(linear_pair_failures > 0);
    eprintln!(
        "three-pair terminal: {assignments} label assignments; cubic carry terms={carry_cubic_terms}; linear/pair-only failures={linear_pair_failures}"
    );
}

#[test]
fn terminal_three_pair_carry_and_phase_bounds_preflight() {
    let ctx = RNSFHEContext::try_new(&config_with(5)).unwrap();
    let work = SecureConfig::secure_128().into_config();
    let q = work.primes.iter().map(|&p| p as u128).product::<u128>() as i128;
    let h = q / 2;
    let family = [0x43554245, 1];
    let runtime = CarryRuntime::new(&ctx, q, family, 27);
    let weights = [h - 1, h - 3, h - 9, h - 27, h - 81, h - 243];
    let mut states = Vec::new();
    for pair in 0..3 {
        let (mut state, _) = plan_pair(
            &runtime,
            pair,
            [weights[pair * 2], weights[pair * 2 + 1]],
            0,
        )
        .unwrap();
        for row in &mut state.rows {
            row.selector = Some(zero(&ctx));
        }
        states.push(state);
    }

    let mut carry_bound_bits = Vec::new();
    let mut carry_cubic_terms = Vec::new();
    let states_ref = [&states[0], &states[1], &states[2]];
    let mut phase_bound_bits = Vec::new();
    for (initial, sign) in [(h, 1), (h, -1), (-h + 40, 1), (-h + 40, -1)] {
        let diff = CubeDifferences::new(&cube_table(
            &runtime,
            states_ref,
            initial,
            sign,
            Readout::Carry,
        ));
        let bound = cube_error_bound(&runtime, states_ref, &diff).unwrap();
        carry_bound_bits.push(bits(bound));
        carry_cubic_terms.push(diff.nonzero().1);
        let phase = plan_three_pair_phase211(&runtime, states_ref, initial, sign).unwrap();
        phase_bound_bits.push(bits(phase.bound));
    }

    let layouts: Vec<u64> = ROOT.into_iter().chain(TRAYS).collect();
    let mut residue_bound_bits = Vec::new();
    for modulus in layouts {
        let plan = plan_three_pair_residue(&runtime, states_ref, h, 1, modulus).unwrap();
        residue_bound_bits.push(bits(plan.bound));
        assert!(matches!(plan.kind, ResiduePlanKind::Linear(_)));
    }
    let large_modulus = plan_three_pair_residue(&runtime, states_ref, h, 1, 20_000);
    assert!(matches!(large_modulus, Err(TerminalRefusal::Noise(_))));
    assert_eq!(runtime.multiplications.get(), 0);
    eprintln!(
        "three-pair preflight: carry bits={carry_bound_bits:?}, cubic terms={carry_cubic_terms:?}, phase211 bits={phase_bound_bits:?}, residue-view bits={residue_bound_bits:?}; modulus 20000 refused without products"
    );
}

#[test]
#[cfg_attr(
    not(feature = "slow_tests"),
    ignore = "expensive native three-pair terminal readout; enable slow_tests or use --include-ignored"
)]
fn terminal_three_pair_native_carry_phase_and_sister_views() {
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
    let family = [0x43554245, 1];
    let runtime = CarryRuntime::new(&ctx, q, family, 27);
    let mut rng = ShadowHarvester::with_seed(0x43554245);
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
    let packed = precharge_pairs(&ctx, &keys, &source, family, &mut rng);
    let encrypted_source = precharge(&ctx, &keys, &source, &mut rng);
    let weights = [h - 1, h - 3, h - 9, h - 27, h - 81, h - 243];
    let mut states = Vec::new();
    let mut checks = 0usize;
    for pair in 0..3 {
        let state = project_pair(
            &runtime,
            &packed,
            &trace,
            pair,
            [weights[pair * 2], weights[pair * 2 + 1]],
            0,
        )
        .unwrap();
        let selected_sum = weights[pair * 2] + weights[pair * 2 + 1];
        for row in &state.rows {
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
        states.push(state);
    }
    let states_ref = [&states[0], &states[1], &states[2]];

    // Plan the entire legal frame before multiplication: two carry offsets,
    // one intact S8 root, the configured dependent trays and 2/11 phase.
    let carry_differences = [(h, 1), (-h + 40, 1)]
        .into_iter()
        .map(|(initial, sign)| {
            CubeDifferences::new(&cube_table(
                &runtime,
                states_ref,
                initial,
                sign,
                Readout::Carry,
            ))
        })
        .collect::<Vec<_>>();
    let carry_bounds = carry_differences
        .iter()
        .map(|diff| cube_error_bound(&runtime, states_ref, diff).unwrap())
        .collect::<Vec<_>>();
    assert!(carry_bounds
        .iter()
        .all(|bound| bits(*bound) < bits(runtime.noise.half)));
    let phase_plan = plan_three_pair_phase211(&runtime, states_ref, h, 1).unwrap();
    let moduli: Vec<_> = ROOT.into_iter().chain(TRAYS).collect();
    let residue_plans = moduli
        .iter()
        .map(|&modulus| plan_three_pair_residue(&runtime, states_ref, h, 1, modulus).unwrap())
        .collect::<Vec<_>>();
    let before_refusal = runtime.multiplications.get();
    let oversized = plan_three_pair_residue(&runtime, states_ref, h, 1, 20_000);
    assert!(matches!(oversized, Err(TerminalRefusal::Noise(_))));
    assert_eq!(runtime.multiplications.get(), before_refusal);

    let carry_outputs = execute_cube_batch(&runtime, states_ref, &carry_differences, &relin);
    let carry_products = runtime.multiplications.get();
    let carry_refresh = Projection {
        ciphertext: carry_outputs[0].clone(),
        bound: carry_bounds[0],
    };
    let mut negative_carries = Vec::new();
    for output in &carry_outputs {
        let mut negative = zero(&ctx);
        add_scaled(&ctx, &mut negative, output, -1);
        negative_carries.push(negative);
    }
    let phase_output = execute_three_pair_phase211(&runtime, phase_plan, &relin);
    let phase_products = runtime.multiplications.get() - carry_products;
    let residue_outputs = residue_plans
        .into_iter()
        .map(|plan| execute_three_pair_residue(&runtime, states_ref, plan, &relin))
        .collect::<Vec<_>>();

    let total = h + weights.into_iter().sum::<i128>();
    let expected_carries = [
        (total + q / 2).div_euclid(q),
        (-h + 40 + weights.into_iter().sum::<i128>() + q / 2).div_euclid(q),
    ];
    for ((output, expected), bound) in carry_outputs
        .into_iter()
        .zip(expected_carries)
        .zip(carry_bounds.iter().copied())
    {
        let values = decode_at(&ctx, &output, &keys.secret_key, bound, 0..ctx.n);
        assert_eq!(values[0], expected.rem_euclid(ctx.t as i128) as u64);
        assert!(values[1..].iter().all(|&x| x == 0));
        checks += ctx.n;
    }
    for ((output, expected), bound) in negative_carries
        .iter()
        .zip(expected_carries.into_iter().map(|k| -k))
        .zip(carry_bounds.iter().copied())
    {
        let values = decode_at(&ctx, output, &keys.secret_key, bound, 0..ctx.n);
        assert_eq!(values[0], expected.rem_euclid(ctx.t as i128) as u64);
        assert!(values[1..].iter().all(|&x| x == 0));
        checks += ctx.n;
    }
    let expected_phase = total.div_euclid(2).rem_euclid(11) as u64;
    let phase_values = decode_at(
        &ctx,
        &phase_output.ciphertext,
        &keys.secret_key,
        phase_output.bound,
        0..ctx.n,
    );
    assert_eq!(phase_values[0] % 11, expected_phase);
    assert!(phase_values[1..].iter().all(|&x| x == 0));
    checks += ctx.n;
    for (&modulus, output) in moduli.iter().zip(&residue_outputs) {
        let values = decode_at(
            &ctx,
            &output.ciphertext,
            &keys.secret_key,
            output.bound,
            0..ctx.n,
        );
        assert_eq!(
            values[0] % modulus,
            total.rem_euclid(modulus as i128) as u64
        );
        assert!(values[1..].iter().all(|&x| x == 0));
        checks += ctx.n;
    }
    let phase_parity = total.rem_euclid(2) as u64;
    let root11_index = moduli.iter().position(|&m| m == 11).unwrap();
    let root11_values = decode_at(
        &ctx,
        &residue_outputs[root11_index].ciphertext,
        &keys.secret_key,
        residue_outputs[root11_index].bound,
        0..ctx.n,
    );
    assert_eq!(
        (2 * phase_values[0] + phase_parity) % 11,
        root11_values[0] % 11
    );

    // Feed the recovered six-term winding into a real sparse BFV coefficient
    // refresh, then test whether its certified output can support a square.
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
    let (affine, refreshed) = refresh_coefficient_at(
        &runtime,
        &work,
        &components,
        &encrypted_source,
        &trace,
        &carry_refresh,
        5,
    );
    let (message, old_grid_distance) = source_decode_oracle_at(&work_ctx, &components, &source, 5);
    assert_ne!(old_grid_distance, U256::zero());
    let affine_values = decode_at(
        &ctx,
        &affine.ciphertext,
        &keys.secret_key,
        affine.bound,
        0..ctx.n,
    );
    assert_ne!(affine_values[0], message);
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
    match runtime.noise.multiply(refreshed.bound, refreshed.bound) {
        Ok(square_bound) => {
            let ciphertext = runtime
                .exact
                .try_mul_exact(&refreshed.ciphertext, &refreshed.ciphertext, &relin)
                .unwrap();
            let values = decode_at(&ctx, &ciphertext, &keys.secret_key, square_bound, 0..ctx.n);
            assert_eq!(
                values[0],
                (message as u128 * message as u128 % ctx.t as u128) as u64
            );
            assert!(values[1..].iter().all(|&x| x == 0));
            checks += ctx.n;
            eprintln!(
                "three-pair follow-up square admitted at {} bits",
                bits(square_bound)
            );
        }
        Err(Refusal::Noise {
            stage,
            error_bits,
            half_bits,
        }) => {
            assert_eq!(stage, "selector multiply");
            eprintln!(
                "three-pair follow-up square refused before multiplication: {error_bits} error bits >= {half_bits}-bit half-scale"
            );
        }
        Err(other) => panic!("unexpected follow-up square refusal: {other:?}"),
    }

    assert!(carry_products > 0);
    assert_eq!(phase_products, 4);
    assert_eq!(runtime.multiplications.get(), carry_products + 4);
    eprintln!(
        "three-pair native: {checks} coefficient/error checks, carry bounds={:?}, carry selector products={carry_products}, 2/11 phase products={phase_products}, tray moduli={moduli:?}; modulus 20000 preflight refused",
        carry_bounds.iter().map(|bound| bits(*bound)).collect::<Vec<_>>()
    );
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
