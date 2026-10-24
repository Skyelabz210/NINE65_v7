//! One S8 root, dependent arbitrary-modulus trays, and a bounded 2/11 phase
//! relation. Private research capability; not a production phase authenticator.

use super::*;
use crate::arithmetic::main_only_base_ext::MainOnlyBaseExt;
use exact_transcendentals::chimera::{chimera_by_name, S8_FAMILIES};

#[derive(Debug, PartialEq, Eq)]
enum TrayRefusal {
    ForeignRoot,
    Regime,
    InvalidModulus,
    EncodingCapacity,
    PeriodCapacity,
    Noise(Refusal),
    Transition(Refusal),
    PhaseTransition,
    InvalidCompositeBudget,
    NoCompositeFits,
    InvalidLiftBound,
}

// A per-output error cap, NOT a pool of BFV headroom and not a new Q lane.
// The modulus must also separate every admitted public support row. A large
// modulus/LCM alone would not exclude a constant, information-losing view.
#[derive(Clone, Copy)]
struct CompositeBudget {
    min_modulus: u64,
    max_modulus: u64,
    max_view_error: U512,
}

#[derive(Debug, PartialEq, Eq)]
struct CompositeChoice {
    modulus: u64,
    error_bound: U512,
    distinct_support: usize,
}

fn choose_composite(
    runtime: &CarryRuntime<'_>,
    state: &State,
    budget: CompositeBudget,
) -> Result<CompositeChoice, TrayRefusal> {
    Root211::preflight_root(runtime, state)?;
    if budget.min_modulus < 4
        || budget.min_modulus > budget.max_modulus
        || budget.max_modulus > runtime.ctx.t
        || words(budget.max_view_error) >= words(runtime.noise.half())
    {
        return Err(TrayRefusal::InvalidCompositeBudget);
    }
    // Projection error need NOT increase with m: residues wrap. Exhaust the
    // declared finite range in descending order, rather than binary-searching
    // a false monotonic predicate or choosing from decrypted samples.
    for modulus in (budget.min_modulus..=budget.max_modulus).rev() {
        if is_prime(modulus) {
            continue;
        }
        let mut values: Vec<_> = state
            .rows
            .iter()
            .map(|row| runtime.root_value(row, modulus))
            .collect();
        values.sort_unstable();
        values.dedup();
        if values.len() != state.rows.len() {
            continue;
        }
        let error_bound = runtime.projection_bound(state, |row| runtime.root_value(row, modulus));
        if words(error_bound) <= words(budget.max_view_error) {
            return Ok(CompositeChoice {
                modulus,
                error_bound,
                distinct_support: values.len(),
            });
        }
    }
    Err(TrayRefusal::NoCompositeFits)
}

// If X=b+2*j, b=X mod 2, then j mod 11 is derived from BOTH root roles.
// The inverse is a verified PUBLIC constant, not an inverse of a hidden value.
fn phase_211(runtime: &CarryRuntime<'_>, row: &Row) -> i64 {
    ((runtime.root_value(row, 11) - runtime.root_value(row, 2)) * 6).rem_euclid(11)
}

fn gcd(mut a: u128, mut b: u128) -> u128 {
    while b != 0 {
        (a, b) = (b, a % b);
    }
    a
}

fn period(moduli: &[u64]) -> Result<u128, TrayRefusal> {
    moduli.iter().try_fold(1u128, |p, &m| {
        if m == 0 {
            return Err(TrayRefusal::InvalidModulus);
        }
        (p / gcd(p, m as u128))
            .checked_mul(m as u128)
            .ok_or(TrayRefusal::PeriodCapacity)
    })
}

// This root borrows ONE immutable encrypted source state. There is no API
// accepting caller-supplied phase snapshots or retagged sister ciphertexts.
// Source admission remains the private parent's research fixture contract.
struct Root211<'a> {
    runtime: &'a CarryRuntime<'a>,
    state: &'a State,
    lanes: [Projection; 8],
    shadow_index: Projection,
    evaluated_views: Cell<usize>,
}

struct SisterTray<'a, 'b> {
    root: &'b Root211<'a>,
    moduli: Vec<u64>,
    views: Vec<Projection>,
    period: u128,
}

// A prepared update borrows the exact parent capability. Its owned right
// input, transition edges, support and bounds cannot be swapped at commit.
struct PreparedStep<'a, 'b> {
    parent: &'b Root211<'a>,
    advance: AdvancePlan<'b, 'a>,
    layouts: Vec<Vec<u64>>,
}
impl PreparedStep<'_, '_> {
    fn validate_parent(&self, parent: &Root211<'_>) -> Result<(), TrayRefusal> {
        if !std::ptr::eq(self.parent, parent) {
            return Err(TrayRefusal::ForeignRoot);
        }
        Ok(())
    }
    fn commit(self, relin: &RNSHybridGadgetKey) -> (State, Vec<Vec<u64>>) {
        (self.advance.commit(relin), self.layouts)
    }
}

fn verify_phase_edges(
    runtime: &CarryRuntime<'_>,
    advance: &AdvancePlan<'_, '_>,
) -> Result<(), TrayRefusal> {
    for &(left, right, destination) in &advance.composition.edges {
        let l = &advance.left.rows[left];
        let r = &advance.right.rows[right];
        let out = &advance.composition.result.rows[destination];
        let binary_sum = runtime.root_value(l, 2) + runtime.root_value(r, 2);
        if runtime.root_value(out, 2) != binary_sum % 2
            || phase_211(runtime, out)
                != (phase_211(runtime, l) + phase_211(runtime, r) + binary_sum / 2) % 11
        {
            return Err(TrayRefusal::PhaseTransition);
        }
    }
    Ok(())
}

impl<'a> Root211<'a> {
    fn new(runtime: &'a CarryRuntime<'a>, state: &'a State) -> Result<Self, TrayRefusal> {
        Self::preflight_root(runtime, state)?;
        let lanes = ROOT.map(|p| runtime.project(state, |r| runtime.root_value(r, p)));
        let shadow_index = runtime.project(state, |r| phase_211(runtime, r));
        Ok(Self {
            runtime,
            state,
            lanes,
            shadow_index,
            evaluated_views: Cell::new(9),
        })
    }

    fn preflight_root(runtime: &CarryRuntime<'_>, state: &State) -> Result<(), TrayRefusal> {
        if state.family != runtime.family || state.source_q != runtime.source_q {
            return Err(TrayRefusal::Regime);
        }
        assert_eq!(S8_FAMILIES.map(|f| f.p as u64), ROOT);
        assert_eq!(2 * 6 % 11, 1);
        // Preflight the whole root/phase bundle before producing a ciphertext.
        for p in ROOT {
            runtime
                .noise
                .admit(
                    runtime.projection_bound(state, |r| runtime.root_value(r, p)),
                    "preserved root",
                )
                .map_err(TrayRefusal::Noise)?;
        }
        runtime
            .noise
            .admit(
                runtime.projection_bound(state, |r| phase_211(runtime, r)),
                "2/11 phase",
            )
            .map_err(TrayRefusal::Noise)?;
        Ok(())
    }

    fn preflight_layout(
        runtime: &CarryRuntime<'_>,
        state: &State,
        moduli: &[u64],
    ) -> Result<u128, TrayRefusal> {
        // Arbitrary positive target moduli, NOT another coprime source basis.
        // Shared factors, repeats, prime powers, and modulus 1 are valid.
        for &m in moduli {
            if m == 0 {
                return Err(TrayRefusal::InvalidModulus);
            }
            if m > runtime.ctx.t {
                return Err(TrayRefusal::EncodingCapacity);
            }
            runtime
                .noise
                .admit(
                    runtime.projection_bound(state, |r| runtime.root_value(r, m)),
                    "dependent sister view",
                )
                .map_err(TrayRefusal::Noise)?;
        }
        period(moduli)
    }

    fn attach<'b>(&'b self, moduli: &[u64]) -> Result<SisterTray<'a, 'b>, TrayRefusal> {
        let period = Self::preflight_layout(self.runtime, self.state, moduli)?;
        let views = moduli
            .iter()
            .map(|&m| {
                let view = self
                    .runtime
                    .project(self.state, |r| self.runtime.root_value(r, m));
                self.evaluated_views.set(self.evaluated_views.get() + 1);
                view
            })
            .collect();
        Ok(SisterTray {
            root: self,
            moduli: moduli.to_vec(),
            views,
            period,
        })
    }

    // Research bounded lift: the tray must be attached to this exact root,
    // its odd period must identify the centered remainder, and the root
    // projects that remainder into the common plaintext encoding. Production
    // history/certificate binding is deliberately outside this test module.
    fn project_bounded_remainder(
        &self,
        tray: &SisterTray<'_, '_>,
        period: u64,
        bound: u64,
        target: u64,
    ) -> Result<Projection, TrayRefusal> {
        self.project_bounded_scaled_remainder(tray, period, bound, 1, target)
    }

    fn project_bounded_scaled_remainder(
        &self,
        tray: &SisterTray<'_, '_>,
        period: u64,
        bound: u64,
        scale: i64,
        target: u64,
    ) -> Result<Projection, TrayRefusal> {
        self.validate(tray)?;
        if period < 3
            || (period as u128) <= 2 * bound as u128
            || scale == 0
            || target != self.runtime.ctx.t
            || !tray.moduli.contains(&period)
            || self.state.rows.iter().any(|row| {
                row.remainder.unsigned_abs() > bound as u128
                    || self.runtime.root_value(row, period)
                        != row.remainder.rem_euclid(period as i128) as i64
                    || row
                        .remainder
                        .checked_mul(scale as i128)
                        .and_then(|value| i64::try_from(value).ok())
                        .is_none()
            })
        {
            return Err(TrayRefusal::InvalidLiftBound);
        }
        let projection = self
            .runtime
            .project(self.state, |row| (row.remainder * scale as i128) as i64);
        self.evaluated_views.set(self.evaluated_views.get() + 1);
        Ok(projection)
    }

    // Project a bounded affine expression of the root's centered remainder
    // and winding into the common plaintext encoding. The tray period proves
    // that this expression is the same signed residue as the attached view.
    fn project_bounded_affine_sheet(
        &self,
        tray: &SisterTray<'_, '_>,
        period: u64,
        bound: u64,
        remainder_scale: i64,
        winding_scale: i64,
        target: u64,
    ) -> Result<Projection, TrayRefusal> {
        self.validate(tray)?;
        let value = |row: &Row| {
            row.remainder
                .checked_mul(remainder_scale as i128)?
                .checked_add((row.winding as i128).checked_mul(winding_scale as i128)?)
        };
        if period < 3
            || (period as u128) <= 2 * bound as u128
            || (remainder_scale == 0 && winding_scale == 0)
            || target != self.runtime.ctx.t
            || !tray.moduli.contains(&period)
            || self.state.rows.iter().any(|row| {
                value(row).map_or(true, |value| {
                    value.unsigned_abs() > bound as u128
                        || i64::try_from(value).is_err()
                        || self.runtime.root_value(row, period)
                            != value.rem_euclid(period as i128) as i64
                })
            })
        {
            return Err(TrayRefusal::InvalidLiftBound);
        }
        let projection = self
            .runtime
            .project(self.state, |row| value(row).unwrap() as i64);
        self.evaluated_views.set(self.evaluated_views.get() + 1);
        Ok(projection)
    }

    fn validate(&self, tray: &SisterTray<'_, '_>) -> Result<(), TrayRefusal> {
        if !std::ptr::eq(self, tray.root) {
            return Err(TrayRefusal::ForeignRoot);
        }
        Ok(())
    }

    fn prepare_advance<'b>(
        &'b self,
        term: i128,
        trit: &Trit,
        layouts: &[Vec<u64>],
    ) -> Result<PreparedStep<'a, 'b>, TrayRefusal> {
        let advance = self
            .runtime
            .plan_advance(self.state, term, trit)
            .map_err(TrayRefusal::Transition)?;
        let proposed = &advance.composition.result;
        Self::preflight_root(self.runtime, proposed)?;
        // Check the actual planned transition edges, including the binary
        // crossing, rather than trusting post-operation snapshot equality.
        verify_phase_edges(self.runtime, &advance)?;
        for layout in layouts {
            Self::preflight_layout(self.runtime, proposed, layout)?;
        }
        Ok(PreparedStep {
            parent: self,
            advance,
            layouts: layouts.to_vec(),
        })
    }

    fn prepare_composite_advance<'b>(
        &'b self,
        term: i128,
        trit: &Trit,
        retained_layouts: &[Vec<u64>],
        budget: CompositeBudget,
    ) -> Result<(PreparedStep<'a, 'b>, CompositeChoice), TrayRefusal> {
        // Bind to the exact proposed state/history, not the cheaper old state.
        // Retained views cannot be silently removed to make the new one fit.
        let mut prepared = self.prepare_advance(term, trit, retained_layouts)?;
        let choice = choose_composite(self.runtime, &prepared.advance.composition.result, budget)?;
        prepared.layouts.push(vec![choice.modulus]);
        Ok((prepared, choice))
    }
}

#[test]
fn sister_tray_composite_budget_is_exact_nonmonotone_and_preserves_support() {
    let ctx = RNSFHEContext::try_new(&config_with(5)).unwrap();
    let runtime = CarryRuntime::new(&ctx, 101, [211, 3], 27);
    // Public bound-only support fixture, not an encrypted execution claim.
    let mut state = runtime.initial(1).unwrap();
    state.rows.push(row_for(11, 101));
    let budget = CompositeBudget {
        min_modulus: 4,
        max_modulus: 12,
        max_view_error: U512::from_u64(4),
    };
    let choice = choose_composite(&runtime, &state, budget).unwrap();
    assert_eq!(choice.modulus, 9);
    assert_eq!(choice.error_bound, U512::from_u64(3));
    assert_eq!(choice.distinct_support, 2);
    // 6 costs 6, but 8 costs 4 and 9 costs 3: no monotonic modulus shortcut.
    for (m, expected) in [(6, 6), (8, 4), (9, 3)] {
        assert_eq!(
            runtime.projection_bound(&state, |row| runtime.root_value(row, m)),
            U512::from_u64(expected)
        );
    }
    let exact = CompositeBudget {
        min_modulus: 9,
        max_modulus: 9,
        max_view_error: choice.error_bound,
    };
    assert_eq!(choose_composite(&runtime, &state, exact).unwrap(), choice);
    assert_eq!(
        choose_composite(
            &runtime,
            &state,
            CompositeBudget {
                max_view_error: U512::from_u64(2),
                ..exact
            }
        ),
        Err(TrayRefusal::NoCompositeFits)
    );
    // Modulo 10 both rows become 1. Its lower error does not excuse aliasing.
    assert_eq!(
        choose_composite(
            &runtime,
            &state,
            CompositeBudget {
                min_modulus: 10,
                max_modulus: 10,
                ..budget
            }
        ),
        Err(TrayRefusal::NoCompositeFits)
    );
    for invalid in [
        CompositeBudget {
            min_modulus: 3,
            ..budget
        },
        CompositeBudget {
            min_modulus: 13,
            ..budget
        },
        CompositeBudget {
            max_modulus: ctx.t + 1,
            ..budget
        },
        CompositeBudget {
            max_view_error: runtime.noise.half(),
            ..budget
        },
    ] {
        assert_eq!(
            choose_composite(&runtime, &state, invalid),
            Err(TrayRefusal::InvalidCompositeBudget)
        );
    }
    assert_eq!(
        choose_composite(
            &runtime,
            &state,
            CompositeBudget {
                min_modulus: 11,
                max_modulus: 11,
                ..budget
            }
        ),
        Err(TrayRefusal::NoCompositeFits)
    );
    assert_eq!(runtime.multiplications.get(), 0);
    assert_eq!(state.rows[0].bound, U512::zero());
}

fn row_for(value: i128, q: i128) -> Row {
    let winding = (value + q / 2).div_euclid(q);
    Row {
        remainder: value - q * winding,
        winding: winding.try_into().unwrap(),
        selector: None,
        bound: U512::zero(),
    }
}

fn public_constant(ctx: &RNSFHEContext, value: i64) -> RNSCiphertext {
    let mut ciphertext = zero(ctx);
    for (lane, &prime) in ctx.config.primes.iter().enumerate() {
        let value = (value as i128).rem_euclid(ctx.t as i128) as u128;
        let encoded = (value * ctx.delta_rns[lane] as u128 % prime as u128) as u64;
        ciphertext.c0.limbs[lane][0] = ctx.rns.mont_contexts[lane].to_montgomery(encoded);
    }
    ciphertext
}

fn check_transition(runtime: &CarryRuntime<'_>, x: i128, y: i128) {
    let left = row_for(x, runtime.source_q);
    let right = row_for(y, runtime.source_q);
    let crossing =
        (left.remainder + right.remainder + runtime.source_q / 2).div_euclid(runtime.source_q);
    let out = Row {
        remainder: left.remainder + right.remainder - runtime.source_q * crossing,
        winding: left.winding + right.winding + crossing as i64,
        selector: None,
        bound: U512::zero(),
    };
    let b_left = runtime.root_value(&left, 2);
    let b_right = runtime.root_value(&right, 2);
    let parity_crossing = (b_left + b_right) / 2;
    assert_eq!(runtime.root_value(&out, 2), (b_left + b_right) % 2);
    assert_eq!(
        phase_211(runtime, &out),
        (phase_211(runtime, &left) + phase_211(runtime, &right) + parity_crossing) % 11
    );
    assert_eq!(
        phase_211(runtime, &out) as i128,
        (x + y).div_euclid(2).rem_euclid(11)
    );
    assert_eq!(
        runtime.root_value(&out, 11),
        (runtime.root_value(&out, 2) + 2 * phase_211(runtime, &out)) % 11
    );
    for m in [1, 6, 10, 22, 27, 77, 121, 221, 385, 4199, 65537] {
        assert_eq!(
            runtime.root_value(&out, m) as i128,
            (x + y).rem_euclid(m as i128)
        );
    }
}

#[test]
fn sister_tray_211_phase_transition_carries_the_parity_crossing() {
    let ctx = RNSFHEContext::try_new(&config_with(5)).unwrap();
    let mut checked = 0;
    for q in [5, 17, 31] {
        let runtime = CarryRuntime::new(&ctx, q, [211, 1], 27);
        for x in -64..=64 {
            for y in -64..=64 {
                check_transition(&runtime, x, y);
                checked += 1;
            }
        }
    }
    let work = SecureConfig::secure_128().into_config();
    let q = work.primes.iter().map(|&p| p as i128).product::<i128>();
    let runtime = CarryRuntime::new(&ctx, q, [211, 1], 27);
    let h = q / 2;
    for x in [-2 * q, -q, -h, -1, 0, 1, h, q, 2 * q] {
        for y in [-2 * q, -q, -h, -1, 0, 1, h, q, 2 * q] {
            check_transition(&runtime, x, y);
            checked += 1;
        }
    }
    assert_eq!(checked, 50_004);
    // Dropping the binary crossing makes the 1+1 transition wrong.
    assert_eq!((1i128 + 1).div_euclid(2) % 11, 1);
    assert_eq!(1i128.div_euclid(2) + 1i128.div_euclid(2), 0);
    eprintln!("sister tray: {checked} exact 2/11 transitions with arbitrary target views");
}

#[test]
fn sister_tray_one_root_accepts_arbitrary_views_and_refuses_snapshot_rebinding() {
    let ctx = RNSFHEContext::try_new(&config_with(5)).unwrap();
    let runtime = CarryRuntime::new(&ctx, 101, [211, 1], 27);
    let zero_state = runtime.initial(0).unwrap();
    let next_state = runtime.initial(22).unwrap();
    let root = Root211::new(&runtime, &zero_state).unwrap();
    let next = Root211::new(&runtime, &next_state).unwrap();
    let first = root.attach(&[6, 10, 6, 1]).unwrap();
    let second = root.attach(&[11, 121, 5]).unwrap();
    let power = root.attach(&[65_536, 65_537]).unwrap();
    assert_eq!(first.period, 30);
    assert_eq!(second.period, 605);
    assert_eq!(power.moduli, vec![65_536, 65_537]);
    assert_eq!(root.lanes.len(), 8);
    assert!(std::ptr::eq(first.root, second.root));
    assert!(std::ptr::eq(first.root, power.root));
    root.validate(&first).unwrap();
    root.validate(&second).unwrap();
    root.validate(&power).unwrap();
    // X and X+22 share the two snapshots AND the derived 2/11 index.
    // They do not name the same source value. Only the factory capability
    // may attach a tray; agreeing public tags/snapshots cannot rebind it.
    for index in [0, 4] {
        assert_eq!(
            root.lanes[index].ciphertext.c0.limbs,
            next.lanes[index].ciphertext.c0.limbs
        );
    }
    assert_eq!(
        root.shadow_index.ciphertext.c0.limbs,
        next.shadow_index.ciphertext.c0.limbs
    );
    assert_eq!(next.validate(&first), Err(TrayRefusal::ForeignRoot));
    assert_ne!(
        runtime.root_value(&zero_state.rows[0], 5),
        runtime.root_value(&next_state.rows[0], 5)
    );
    let before = root.evaluated_views.get();
    assert!(matches!(
        root.attach(&[6, 0]),
        Err(TrayRefusal::InvalidModulus)
    ));
    assert!(matches!(
        root.attach(&[6, ctx.t + 1]),
        Err(TrayRefusal::EncodingCapacity)
    ));
    assert_eq!(root.evaluated_views.get(), before);
    let mut foreign = zero_state.clone();
    foreign.family[1] += 1;
    assert!(matches!(
        Root211::new(&runtime, &foreign),
        Err(TrayRefusal::Regime)
    ));
    assert_eq!(period(&[6, 10]), Ok(30));
    assert_eq!(period(&[11, 121, 121, 1]), Ok(121));
    assert!(matches!(
        period(&[u64::MAX, u64::MAX - 1, u64::MAX - 2]),
        Err(TrayRefusal::PeriodCapacity)
    ));
    assert_eq!(runtime.multiplications.get(), 0);
}

#[test]
fn paired_chart_k_elimination_uses_one_root_and_common_encoding() {
    const M: i128 = 32_768;
    const ADJACENT: i128 = M + 1;
    const Z99_VALUES: [i128; 5] = [-15_887, -330, 50, 330, 15_887];
    const CARRIES: [i128; 5] = [-48, -1, 0, 1, 48];

    let ctx = RNSFHEContext::try_new(&config_with(6)).unwrap();
    assert_eq!(ctx.t, 65_537);
    let mut rng = ShadowHarvester::with_seed(0x5041_4952_4b45_4c49);
    let keys = ctx.generate_keys_dual(&mut rng);
    let runtime = CarryRuntime::new(&ctx, 5_000_003, [211, 2], 27);
    let mut chart_rows = Vec::new();

    for (&z99, &expected_k) in Z99_VALUES.iter().zip(&CARRIES) {
        let chart_residual = 99 * z99 - M * expected_k;
        assert!(chart_residual.abs() <= 5_313);
        assert_eq!((99 * z99 + M / 2).div_euclid(M), expected_k);
        let x = 99 * z99 + M / 2;
        let mut row = row_for(x, runtime.source_q);
        assert_eq!(row.remainder, x);
        assert_eq!(row.winding, 0);

        // The key holder precharges a one-hot chart-row selector. The
        // evaluator only receives the encrypted selectors and public rows.
        row.bound = runtime.noise.projected;
        chart_rows.push(row);
    }

    // Precharge encrypted one-hot indicators for the public support. Each
    // follow-up changes only which hidden row is selected.
    let mut one_message = vec![0i8; ctx.n];
    one_message[0] = 1;
    let selected_one = precharge(&ctx, &keys, &one_message, &mut rng);
    let selected_zero = precharge(&ctx, &keys, &vec![0i8; ctx.n], &mut rng);
    let family = runtime.family;
    let relin = relin_key(&runtime, &keys, &mut rng);
    for selected_index in 0..chart_rows.len() {
        for (index, row) in chart_rows.iter_mut().enumerate() {
            row.selector = Some(if index == selected_index {
                selected_one.clone()
            } else {
                selected_zero.clone()
            });
        }
        let state = State {
            rows: chart_rows.clone(),
            family,
            source_q: runtime.source_q,
            coefficients: vec![0],
        };
        let root = Root211::new(&runtime, &state).unwrap();
        let tray = root.attach(&[M as u64, ctx.t, 98]).unwrap();
        root.validate(&tray).unwrap();
        assert_eq!(root.lanes.len(), 8);
        assert_eq!(tray.moduli, vec![M as u64, ctx.t, 98]);

        // X_p and r=X mod M are both p-encoded projections of one root.
        // Since p=2*M+1, K = 2*(r-X_p) mod p.
        let mut k_ciphertext = zero(&ctx);
        add_scaled(&ctx, &mut k_ciphertext, &tray.views[0].ciphertext, 2);
        add_scaled(&ctx, &mut k_ciphertext, &tray.views[1].ciphertext, -2);
        let k_bound = tray.views[0].bound.add(tray.views[1].bound).mul_u128(2);
        runtime
            .noise
            .admit(k_bound, "paired-chart K-Elimination")
            .unwrap();

        let selected_k = CARRIES[selected_index];
        let chart_residual = 99 * Z99_VALUES[selected_index] - M * selected_k;
        let actual_k = decode_at(&ctx, &k_ciphertext, &keys.secret_key, k_bound, 0..ctx.n);
        assert_eq!(actual_k[0] as i128, selected_k.rem_euclid(ctx.t as i128));
        assert!(actual_k[1..].iter().all(|&value| value == 0));

        // The adjacent M+1 view is another dependent tray on this same root.
        // Its source-correlated quotient is exactly K, and 2*(M+1)=p+1.
        let adjacent = root.attach(&[ADJACENT as u64, ctx.t]).unwrap();
        root.validate(&adjacent).unwrap();
        let mut adjacent_k = zero(&ctx);
        add_scaled(&ctx, &mut adjacent_k, &adjacent.views[1].ciphertext, 2);
        add_scaled(&ctx, &mut adjacent_k, &adjacent.views[0].ciphertext, -2);
        let adjacent_k_bound = adjacent.views[0]
            .bound
            .add(adjacent.views[1].bound)
            .mul_u128(2);
        runtime
            .noise
            .admit(adjacent_k_bound, "adjacent-tray K-Elimination")
            .unwrap();
        let adjacent_k_value = decode_at(
            &ctx,
            &adjacent_k,
            &keys.secret_key,
            adjacent_k_bound,
            0..ctx.n,
        );
        assert_eq!(
            adjacent_k_value[0] as i128,
            selected_k.rem_euclid(ctx.t as i128)
        );
        assert!(adjacent_k_value[1..].iter().all(|&value| value == 0));

        let mut adjacent_residual = zero(&ctx);
        add_scaled(
            &ctx,
            &mut adjacent_residual,
            &adjacent.views[0].ciphertext,
            1,
        );
        add_scaled(&ctx, &mut adjacent_residual, &adjacent_k, 1);
        let half_modulus = public_constant(&ctx, (M / 2) as i64);
        add_scaled(&ctx, &mut adjacent_residual, &half_modulus, -1);
        let adjacent_residual_bound = adjacent.views[0].bound.add(adjacent_k_bound);
        runtime
            .noise
            .admit(
                adjacent_residual_bound,
                "adjacent-tray centered chart residual",
            )
            .unwrap();
        let adjacent_residual_value = decode_at(
            &ctx,
            &adjacent_residual,
            &keys.secret_key,
            adjacent_residual_bound,
            0..ctx.n,
        );
        assert_eq!(
            adjacent_residual_value[0] as i128,
            chart_residual.rem_euclid(ctx.t as i128)
        );
        assert!(adjacent_residual_value[1..].iter().all(|&value| value == 0));

        // Once K is available, the centered chart residual is linear and
        // independent of the integer sheet: e99=99*Z99-M*K=r-M/2.
        let z99_view = runtime.project(&state, |row| {
            ((row.remainder - M / 2).div_euclid(99)) as i64
        });
        let mut residual = zero(&ctx);
        add_scaled(&ctx, &mut residual, &z99_view.ciphertext, 99);
        add_scaled(&ctx, &mut residual, &k_ciphertext, -(M as i64));
        let residual_bound = z99_view.bound.mul_u128(99).add(k_bound.mul_u128(M as u128));
        runtime
            .noise
            .admit(residual_bound, "paired-chart centered residual")
            .unwrap();
        let expected_residual = 99 * Z99_VALUES[selected_index] - M * selected_k;
        let actual_residual =
            decode_at(&ctx, &residual, &keys.secret_key, residual_bound, 0..ctx.n);
        assert_eq!(
            actual_residual[0] as i128,
            expected_residual.rem_euclid(ctx.t as i128)
        );
        assert!(actual_residual[1..].iter().all(|&value| value == 0));

        // Composite-98 candidate: Y=198*Z99=2*X-M=p*K+(2*e99-K).
        // Both residues below come from the same root-bound selector state.
        // The common-p ciphertext retains the small linear representative
        // 47*(Y_98-w_98), which is congruent to K modulo 98.
        let y_mod_98 = runtime.project(&state, |row| (2 * row.remainder - M).rem_euclid(98) as i64);
        let centered_y_mod_p_mod_98 = runtime.project(&state, |row| {
            let y = 2 * row.remainder - M;
            let residue = y.rem_euclid(ctx.t as i128);
            let centered = if residue > ctx.t as i128 / 2 {
                residue - ctx.t as i128
            } else {
                residue
            };
            centered.rem_euclid(98) as i64
        });
        let mut k_mod_98 = zero(&ctx);
        add_scaled(&ctx, &mut k_mod_98, &y_mod_98.ciphertext, 47);
        add_scaled(
            &ctx,
            &mut k_mod_98,
            &centered_y_mod_p_mod_98.ciphertext,
            -47,
        );
        let k_mod_98_bound = y_mod_98
            .bound
            .add(centered_y_mod_p_mod_98.bound)
            .mul_u128(47);
        runtime
            .noise
            .admit(k_mod_98_bound, "composite-98 K-Elimination")
            .unwrap();
        let decoded_k_mod_98 =
            decode_at(&ctx, &k_mod_98, &keys.secret_key, k_mod_98_bound, 0..ctx.n);
        let signed_residue = if decoded_k_mod_98[0] as i128 > ctx.t as i128 / 2 {
            decoded_k_mod_98[0] as i128 - ctx.t as i128
        } else {
            decoded_k_mod_98[0] as i128
        };
        let centered_k = signed_residue.rem_euclid(98);
        let centered_k = if centered_k >= 49 {
            centered_k - 98
        } else {
            centered_k
        };
        assert_eq!(centered_k, selected_k);
        assert!(decoded_k_mod_98[1..].iter().all(|&value| value == 0));

        // Follow the recovered carry through its first dependent product
        // whenever the public ledger admits it; otherwise require typed
        // refusal before ciphertext multiplication.
        match runtime.noise.multiply(k_bound, k_bound) {
            Ok(square_bound) => {
                let square = runtime
                    .exact
                    .try_mul_exact(&k_ciphertext, &k_ciphertext, &relin)
                    .unwrap();
                let decoded = decode_at(&ctx, &square, &keys.secret_key, square_bound, 0..ctx.n);
                assert_eq!(
                    decoded[0] as i128,
                    (selected_k * selected_k).rem_euclid(ctx.t as i128)
                );
                assert!(decoded[1..].iter().all(|&value| value == 0));
            }
            Err(Refusal::Noise { .. }) => {}
            Err(other) => panic!("unexpected follow-up refusal: {other:?}"),
        }
        eprintln!(
            "paired chart K-Elimination: selected K={selected_k}, e99={expected_residual}, one root, 2^15/98/32769/65537 trays in common plaintext; composite-98 residue checked; dense chart producer remains separate"
        );
    }
}

#[test]
fn symbolic_scale_jacobian_residual_lifts_through_one_root_into_common_p() {
    const P: u64 = 65_537;
    const STEP: i128 = 19_965; // 3 * 5 * 11^3; odd composite lift period.
    const ODD_TRAY: u64 = STEP as u64;
    const RESIDUAL_BOUND: u64 = 408;
    const CASES: [(i128, i128); 5] = [(-48, -408), (-1, -1), (0, 0), (1, 1), (48, 408)];

    let ctx = RNSFHEContext::try_new(&config_with(6)).unwrap();
    assert_eq!(ctx.t, P);
    let mut rng = ShadowHarvester::with_seed(0x4a41_434f_4249_414e);
    let keys = ctx.generate_keys_dual(&mut rng);
    let runtime = CarryRuntime::new(&ctx, STEP, [211, 2], 27);
    let one_message = {
        let mut message = vec![0i8; ctx.n];
        message[0] = 1;
        message
    };
    let selected_one = precharge(&ctx, &keys, &one_message, &mut rng);
    let selected_zero = precharge(&ctx, &keys, &vec![0i8; ctx.n], &mut rng);
    let relin = relin_key(&runtime, &keys, &mut rng);
    let family = runtime.family;
    let mut rows: Vec<_> = CASES
        .iter()
        .map(|&(k, e)| Row {
            remainder: e,
            winding: k as i64,
            selector: None,
            bound: runtime.noise.projected,
        })
        .collect();

    for selected in 0..CASES.len() {
        for (index, row) in rows.iter_mut().enumerate() {
            row.selector = Some(if index == selected {
                selected_one.clone()
            } else {
                selected_zero.clone()
            });
        }
        let state = State {
            rows: rows.clone(),
            family,
            source_q: STEP,
            coefficients: vec![0],
        };
        let root = Root211::new(&runtime, &state).unwrap();
        let tray = root.attach(&[ODD_TRAY, P]).unwrap();
        root.validate(&tray).unwrap();
        let e_common = root
            .project_bounded_remainder(&tray, ODD_TRAY, RESIDUAL_BOUND, P)
            .unwrap();

        let k_expected = CASES[selected].0.rem_euclid(P as i128) as u64;
        let e_expected = CASES[selected].1.rem_euclid(P as i128) as u64;
        let delta_expected =
            (STEP * CASES[selected].0 + CASES[selected].1).rem_euclid(P as i128) as u64;
        let odd_expected = CASES[selected].1.rem_euclid(ODD_TRAY as i128) as u64;
        let decoded_odd = decode_at(
            &ctx,
            &tray.views[0].ciphertext,
            &keys.secret_key,
            tray.views[0].bound,
            0..ctx.n,
        );
        assert_eq!(decoded_odd[0], odd_expected);
        assert!(decoded_odd[1..].iter().all(|&value| value == 0));
        let decoded_e = decode_at(
            &ctx,
            &e_common.ciphertext,
            &keys.secret_key,
            e_common.bound,
            0..ctx.n,
        );
        assert_eq!(decoded_e[0], e_expected);
        assert!(decoded_e[1..].iter().all(|&value| value == 0));

        // Δ_p=L*K+e and e_p share the exact same root/history. K-Elimination
        // now needs only a public modular inverse and no oracle residual.
        let inverse_step = inverse(STEP.rem_euclid(P as i128) as u64, P) as i64;
        let mut carry = zero(&ctx);
        add_scaled(&ctx, &mut carry, &tray.views[1].ciphertext, inverse_step);
        add_scaled(&ctx, &mut carry, &e_common.ciphertext, -inverse_step);
        let carry_bound = tray.views[1]
            .bound
            .add(e_common.bound)
            .mul_u128(inverse_step.unsigned_abs() as u128);
        runtime
            .noise
            .admit(carry_bound, "scale-Jacobian K-Elimination")
            .unwrap();
        let decoded_carry = decode_at(&ctx, &carry, &keys.secret_key, carry_bound, 0..ctx.n);
        assert_eq!(decoded_carry[0], k_expected);
        assert!(decoded_carry[1..].iter().all(|&value| value == 0));

        let delta = &tray.views[1];
        let decoded_delta = decode_at(
            &ctx,
            &delta.ciphertext,
            &keys.secret_key,
            delta.bound,
            0..ctx.n,
        );
        assert_eq!(decoded_delta[0], delta_expected);
        assert!(decoded_delta[1..].iter().all(|&value| value == 0));

        // Root rebinding and a period too small to sign-lift are both refused
        // before another projection is emitted.
        if selected == 0 {
            let other_state = runtime.initial(0).unwrap();
            let other_root = Root211::new(&runtime, &other_state).unwrap();
            assert!(matches!(
                other_root.project_bounded_remainder(&tray, ODD_TRAY, RESIDUAL_BOUND, P),
                Err(TrayRefusal::ForeignRoot)
            ));
            assert!(matches!(
                root.project_bounded_remainder(&tray, ODD_TRAY, ODD_TRAY / 2 + 1, P),
                Err(TrayRefusal::InvalidLiftBound)
            ));
        }

        // A dependent square follows the recovered carry at every boundary.
        let square_bound = runtime.noise.multiply(carry_bound, carry_bound).unwrap();
        let square = runtime.exact.try_mul_exact(&carry, &carry, &relin).unwrap();
        let decoded_square = decode_at(&ctx, &square, &keys.secret_key, square_bound, 0..ctx.n);
        assert_eq!(
            decoded_square[0],
            (k_expected as u128 * k_expected as u128 % P as u128) as u64
        );
        assert!(decoded_square[1..].iter().all(|&value| value == 0));
    }
}

#[test]
fn one_root_projects_bounded_offset_into_composite_pj_tray() {
    const P: u64 = 65_537;
    const TRAY_FACTOR: u64 = 16_390; // 2 * 5 * 11 * 149
    const M1: u64 = P + 1;
    const OFFSET_BOUND: u64 = 129;
    const OFFSET_MAX: u64 = 2 * OFFSET_BOUND;
    const P_J_TRAY: u64 = TRAY_FACTOR * M1;

    let mut config = config_with(6);
    config.n = 32;
    config.t = P_J_TRAY;
    let ctx = RNSFHEContext::try_new(&config).unwrap();
    assert!(TRAY_FACTOR > 2 * OFFSET_MAX);
    let mut rng = ShadowHarvester::with_seed(0x504a_5452_4159_3236);
    let keys = ctx.generate_keys_dual(&mut rng);
    let mut one_message = vec![0i8; ctx.n];
    one_message[0] = 1;
    let selected_one = precharge(&ctx, &keys, &one_message, &mut rng);
    let selected_zero = precharge(&ctx, &keys, &vec![0i8; ctx.n], &mut rng);
    let runtime = CarryRuntime::new_composite_sister_target(&ctx, P as i128, [TRAY_FACTOR, 2], 8);
    let values = [0i128, OFFSET_BOUND as i128, OFFSET_MAX as i128];
    let mut rows: Vec<_> = values
        .iter()
        .map(|&remainder| Row {
            remainder,
            winding: 0,
            selector: None,
            bound: runtime.noise.projected,
        })
        .collect();

    for selected in 0..values.len() {
        for (index, row) in rows.iter_mut().enumerate() {
            row.selector = Some(if index == selected {
                selected_one.clone()
            } else {
                selected_zero.clone()
            });
        }
        let state = State {
            rows: rows.clone(),
            family: runtime.family,
            source_q: P as i128,
            coefficients: vec![0],
        };
        let root = Root211::new(&runtime, &state).unwrap();
        let tray = root.attach(&[TRAY_FACTOR, M1, P_J_TRAY]).unwrap();
        let bounded_offset = root
            .project_bounded_remainder(&tray, TRAY_FACTOR, OFFSET_MAX, P_J_TRAY)
            .unwrap();
        let decoded = decode_at(
            &ctx,
            &bounded_offset.ciphertext,
            &keys.secret_key,
            bounded_offset.bound,
            0..ctx.n,
        );
        assert_eq!(decoded[0], values[selected] as u64);
        assert!(decoded[1..].iter().all(|&value| value == 0));
    }
}

#[test]
fn symbolic_selectors_project_bounded_k_elimination_carry_into_high_mpj_correction() {
    const P: u64 = 65_537;
    const FACTOR: u64 = 16_390;
    const M_PJ: u64 = FACTOR * (P + 1);
    const HIGH_T: u64 = P * P * M_PJ;
    const CARRY_BOUND: u64 = 8_193;
    const CARRIES: [i128; 5] = [-8_193, -23, 0, 23, 8_193];

    let mut config = SecureConfig::secure_128().into_config();
    config.n = 4;
    config.primes = vec![
        9_223_372_036_853_661_697,
        9_223_372_036_853_235_713,
        9_223_372_036_852_744_193,
    ];
    config.q = config.primes[0];
    config.security_bits = 0;
    config.t = HIGH_T;
    let ctx = RNSFHEContext::try_new(&config).unwrap();
    assert!(P > 2 * CARRY_BOUND);
    assert!(HIGH_T > 2 * M_PJ * CARRY_BOUND);

    let mut rng = ShadowHarvester::with_seed(0x4b45_4c49_4654_4332);
    let keys = ctx.generate_keys_dual(&mut rng);
    let mut one_message = vec![0i8; ctx.n];
    one_message[0] = 1;
    let selected_one = precharge(&ctx, &keys, &one_message, &mut rng);
    let selected_zero = precharge(&ctx, &keys, &vec![0i8; ctx.n], &mut rng);
    let q = U512::product_u64s(&config.primes);

    for (selected, &carry) in CARRIES.iter().enumerate() {
        let mut correction = zero(&ctx);
        let mut error_bound = U512::zero();
        for (index, &support_carry) in CARRIES.iter().enumerate() {
            let selector = if index == selected {
                selected_one.clone()
            } else {
                selected_zero.clone()
            };
            let coefficient = (M_PJ as i128 * support_carry) as i64;
            add_scaled(&ctx, &mut correction, &selector, coefficient);
            error_bound = error_bound.add(U512::from_u128(
                (config.eta as u128) * coefficient.unsigned_abs() as u128,
            ));
        }
        assert!(words(error_bound.mul_u128(HIGH_T as u128 * 2)) < words(q));
        let decoded = decode_at(&ctx, &correction, &keys.secret_key, error_bound, 0..ctx.n);
        assert_eq!(
            decoded[0],
            (M_PJ as i128 * carry).rem_euclid(HIGH_T as i128) as u64,
            "the root must emit the bounded M_pJ*K correction in T"
        );
        assert!(decoded[1..].iter().all(|&value| value == 0));
    }
}

#[test]
fn full_bound_sister_runtime_initializes_at_native_degree() {
    const HIGH_T: u64 = 4_613_656_451_714_285_580;
    const PRIMES: [u64; 3] = [
        9_223_372_036_853_661_697,
        9_223_372_036_853_235_713,
        9_223_372_036_852_744_193,
    ];

    let mut config = SecureConfig::secure_128().into_config();
    config.n = 16_384;
    config.primes = PRIMES.to_vec();
    config.q = PRIMES[0];
    config.security_bits = 0;
    config.t = HIGH_T;
    let ctx = RNSFHEContext::try_new(&config).unwrap();
    let runtime = CarryRuntime::new_composite_sister_target(&ctx, 5_000_003, [211, 3], 27);
    let state = runtime.initial(0).unwrap();
    let root = Root211::new(&runtime, &state).unwrap();

    assert_eq!(root.evaluated_views.get(), 9);
    assert!(runtime.exact.plan().certificate().shift_multiplier > u64::MAX as u128);
    assert!(
        runtime.exact.plan().certificate().aux_bits
            > runtime.exact.plan().certificate().required_bits
    );
}

#[test]
fn full_bound_root_unscales_encrypted_selector_mod_quotient_period() {
    const P: u64 = 65_537;
    const FACTOR: u64 = 16_390;
    const M_PJ: u64 = FACTOR * (P + 1);
    const HIGH_T: u64 = P * P * M_PJ;
    const PRIMES: [u64; 3] = [
        9_223_372_036_853_661_697,
        9_223_372_036_853_235_713,
        9_223_372_036_852_744_193,
    ];

    let mut config = SecureConfig::secure_128().into_config();
    config.n = 4;
    config.primes = PRIMES.to_vec();
    config.q = PRIMES[0];
    config.security_bits = 0;
    config.t = HIGH_T;
    let ctx = RNSFHEContext::try_new(&config).unwrap();
    let runtime = CarryRuntime::new_composite_sister_target(&ctx, 5_000_003, [211, 3], 27);
    let mut rng = ShadowHarvester::with_seed(0x4b45_4c49_4654_4c56);
    let keys = ctx.generate_keys_dual(&mut rng);
    let native_secret = RNSSecretKey {
        s: RNSPolynomial {
            n: ctx.n,
            limbs: ctx
                .rns
                .mont_contexts
                .iter()
                .zip(&keys.secret_key.s.main)
                .map(|(mont, lane)| {
                    lane.iter()
                        .map(|&value| mont.to_montgomery(value))
                        .collect()
                })
                .collect(),
        },
    };

    let galois = RNSGaloisEvaluator::new(&ctx).unwrap();
    let mut trace = Vec::new();
    let mut stride = ctx.n;
    while stride > 1 {
        trace.push(
            galois
                .generate_key_with_rng(&native_secret, stride as u64 + 1, &mut rng)
                .unwrap(),
        );
        stride /= 2;
    }
    let relin = relin_key(&runtime, &keys, &mut rng);

    // One encrypted ternary key coefficient is projected into three encrypted
    // one-hot selectors. No selector outcome is supplied to the evaluator.
    let mut source = vec![0i8; ctx.n];
    source[0] = 1;
    source[1] = -1;
    let packed = core::array::from_fn(|label| {
        let values: Vec<i8> = source
            .iter()
            .map(|&value| if value == label as i8 - 1 { -8 } else { 0 })
            .collect();
        precharge(&ctx, &keys, &values, &mut rng)
    });
    let trit = project_trit(
        &ctx,
        &packed,
        &trace,
        0,
        runtime.family,
        runtime.noise.projected,
    );
    let state = runtime
        .advance(&runtime.initial(0).unwrap(), 1, &trit, &relin)
        .unwrap();
    let root = Root211::new(&runtime, &state).unwrap();
    let tray = root.attach(&[2, 11, 22]).unwrap();
    let raw_correction = root
        .project_bounded_scaled_remainder(&tray, 22, 1, M_PJ as i64, HIGH_T)
        .unwrap();
    let raw_decoded = decode_at(
        &ctx,
        &raw_correction.ciphertext,
        &keys.secret_key,
        raw_correction.bound,
        0..ctx.n,
    );
    assert_eq!(raw_decoded[0], (HIGH_T as u128 - 32 * M_PJ as u128) as u64);
    assert!(raw_decoded[1..].iter().all(|&value| value == 0));

    // `project_trit`'s trace leaves each selected branch scaled by -8*N=-32.
    // Since T=p^2*M_pJ, correct that known factor modulo the quotient period
    // p^2; it is invertible there even though it is not invertible modulo T.
    // Multiplying the full-T ciphertext by this public scalar emits M_pJ*K.
    let quotient_period = P * P;
    let correction_scale = -(inverse(32, quotient_period) as i64);
    let mut corrected = zero(&ctx);
    add_scaled(
        &ctx,
        &mut corrected,
        &raw_correction.ciphertext,
        correction_scale,
    );
    let corrected_bound = raw_correction
        .bound
        .mul_u128(correction_scale.unsigned_abs() as u128);
    let q = U512::product_u64s(&config.primes);
    assert!(words(corrected_bound.mul_u128(2)) < words(q));
    let decoded = decode_at(
        &ctx,
        &corrected,
        &keys.secret_key,
        corrected_bound,
        0..ctx.n,
    );
    assert_eq!(decoded[0], M_PJ);
    assert!(decoded[1..].iter().all(|&value| value == 0));
    eprintln!(
        "encrypted selector scale-lock: N={}, raw selector scale=-32, correction inverse modulo p^2, output error bound={} bits; hidden source trit +1 maps to M_pJ in T",
        ctx.n,
        bits(corrected_bound),
    );
}

fn run_second_k_elimination_quotient_winding(degree: usize) {
    const P: u64 = 65_537;
    const P2: u64 = P * P;
    const FACTOR: u64 = 16_390;
    const M_PJ: u64 = FACTOR * (P + 1);
    const FULL_T: u64 = M_PJ * P2;
    const PRIMES: [u64; 3] = [
        9_223_372_036_853_661_697,
        9_223_372_036_853_235_713,
        9_223_372_036_852_744_193,
    ];

    let mut config = SecureConfig::secure_128().into_config();
    config.n = degree;
    config.primes = PRIMES.to_vec();
    config.q = PRIMES[0];
    config.security_bits = 0;
    config.t = P2;
    let p2_ctx = RNSFHEContext::try_new(&config).unwrap();
    config.t = P;
    let p_ctx = RNSFHEContext::try_new(&config).unwrap();
    config.t = FULL_T;
    let full_ctx = RNSFHEContext::try_new(&config).unwrap();

    let runtime = CarryRuntime::new_composite_sister_target(&p2_ctx, P as i128, [211, 3], 10_000);
    let mut rng = ShadowHarvester::with_seed(0x4b45_4c49_4654_4a51);
    let keys = p2_ctx.generate_keys_dual(&mut rng);
    let mut input = vec![0i8; degree];
    input[0] = 23;
    input[1] = -17;
    let secret =
        super::super::safe_basis_precharge_tests::signed_secret(&keys.secret_key, PRIMES[0]);
    // Apply the same exact componentwise K-Elimination quotient used by the
    // pJ tray: dividing an Enc_p ciphertext by p changes its BFV scale to
    // Enc_(p^2), while exposing a second hidden p-multiple winding.
    let projector = MainOnlyBaseExt::new(&PRIMES, &[P]).unwrap();
    let component_remainders = |poly: &RNSPolynomial| {
        let ordinary: Vec<Vec<u64>> = poly
            .limbs
            .iter()
            .zip(&p_ctx.rns.mont_contexts)
            .map(|(lane, mont)| {
                lane.iter()
                    .map(|&value| mont.from_montgomery(value))
                    .collect()
            })
            .collect();
        (0..p2_ctx.n)
            .map(|coefficient| {
                let residues: Vec<_> = ordinary.iter().map(|lane| lane[coefficient]).collect();
                let mut remainder = [0];
                projector
                    .project_centered(&residues, &mut remainder)
                    .unwrap();
                if remainder[0] > P / 2 {
                    remainder[0] as i64 - P as i64
                } else {
                    remainder[0] as i64
                }
            })
            .collect::<Vec<_>>()
    };
    let (encrypted_k_p, r0, r1, expected_from_remainders) = (0..128)
        .find_map(|trial| {
            let mut trial_rng = ShadowHarvester::with_seed(0x4b45_4c49_0000_0000 + trial);
            let ciphertext = precharge(&p_ctx, &keys, &input, &mut trial_rng);
            let r0 = component_remainders(&ciphertext.c0);
            let r1 = component_remainders(&ciphertext.c1);
            let mut phase_remainder = r0[0] as i128;
            for key_coefficient in 0..p2_ctx.n {
                let index = (p2_ctx.n - key_coefficient) % p2_ctx.n;
                let term = if key_coefficient == 0 {
                    r1[index]
                } else {
                    -r1[index]
                };
                phase_remainder += term as i128 * secret[key_coefficient] as i128;
            }
            let winding = (phase_remainder + P as i128 / 2).div_euclid(P as i128);
            (winding != 0).then_some((ciphertext, r0, r1, winding))
        })
        .expect("deterministic search should produce a nonzero quotient carry");
    let divide_component = |poly: &RNSPolynomial| {
        let ordinary: Vec<Vec<u64>> = poly
            .limbs
            .iter()
            .zip(&p_ctx.rns.mont_contexts)
            .map(|(lane, mont)| {
                lane.iter()
                    .map(|&value| mont.from_montgomery(value))
                    .collect()
            })
            .collect();
        let inverses: Vec<_> = PRIMES.iter().map(|&q| inverse(P % q, q)).collect();
        let mut divided = vec![vec![0; p2_ctx.n]; PRIMES.len()];
        for coefficient in 0..p2_ctx.n {
            let residues: Vec<_> = ordinary.iter().map(|lane| lane[coefficient]).collect();
            let mut remainder = [0];
            projector
                .project_centered(&residues, &mut remainder)
                .unwrap();
            let centered = if remainder[0] > P / 2 {
                remainder[0] as i128 - P as i128
            } else {
                remainder[0] as i128
            };
            for lane in 0..PRIMES.len() {
                let numerator =
                    (residues[lane] as i128 - centered).rem_euclid(PRIMES[lane] as i128) as u128;
                divided[lane][coefficient] =
                    (numerator * inverses[lane] as u128 % PRIMES[lane] as u128) as u64;
            }
        }
        RNSPolynomial {
            n: p2_ctx.n,
            limbs: divided
                .iter()
                .zip(&p2_ctx.rns.mont_contexts)
                .map(|(lane, mont)| {
                    lane.iter()
                        .map(|&value| mont.to_montgomery(value))
                        .collect()
                })
                .collect(),
        }
    };
    let lifted_k = RNSCiphertext {
        c0: divide_component(&encrypted_k_p.c0),
        c1: divide_component(&encrypted_k_p.c1),
        num_primes: PRIMES.len(),
    };
    let lifted_plain = decode_at(
        &p2_ctx,
        &lifted_k,
        &keys.secret_key,
        U512::from_u64(1_000_000),
        0..p2_ctx.n,
    );
    let residue_k0 = (input[0] as i128).rem_euclid(P2 as i128) as u64;
    let delta = (lifted_plain[0] as i128 - residue_k0 as i128).rem_euclid(P2 as i128);
    let centered_delta = if delta > P2 as i128 / 2 {
        delta - P2 as i128
    } else {
        delta
    };
    assert_eq!(centered_delta % P as i128, 0);
    let expected_quotient_winding = centered_delta / P as i128;
    assert_eq!(expected_quotient_winding, expected_from_remainders);
    assert_ne!(expected_quotient_winding, 0);

    let native_secret = RNSSecretKey {
        s: RNSPolynomial {
            n: p2_ctx.n,
            limbs: p2_ctx
                .rns
                .mont_contexts
                .iter()
                .zip(&keys.secret_key.s.main)
                .map(|(mont, lane)| {
                    lane.iter()
                        .map(|&value| mont.to_montgomery(value))
                        .collect()
                })
                .collect(),
        },
    };
    let galois = RNSGaloisEvaluator::new(&p2_ctx).unwrap();
    let mut trace = Vec::new();
    let mut stride = p2_ctx.n;
    while stride > 1 {
        trace.push(
            galois
                .generate_key_with_rng(&native_secret, stride as u64 + 1, &mut rng)
                .unwrap(),
        );
        stride /= 2;
    }
    let relin = relin_key(&runtime, &keys, &mut rng);
    let inverse_trace_size = inverse(p2_ctx.n as u64, P2);
    let trace_unit = if inverse_trace_size > P2 / 2 {
        inverse_trace_size as i64 - P2 as i64
    } else {
        inverse_trace_size as i64
    };
    // Precharge the nine possible two-trit words for each pair. The two
    // words are selected by separate coefficient traces from the same nine
    // ciphertexts, so the encrypted carry tree starts at pair granularity.
    let packed_pairs: [RNSCiphertext; 9] = core::array::from_fn(|label| {
        let first = (label / 3) as i8 - 1;
        let second = (label % 3) as i8 - 1;
        let mut indicators = vec![0i64; p2_ctx.n];
        for start in (0..p2_ctx.n).step_by(2) {
            if secret[start] == first && secret[start + 1] == second {
                indicators[start] = trace_unit;
            }
        }
        crate::ops::rns_fhe::cram_precharge::precharge_centered_polynomial_with_rng(
            &p2_ctx,
            &indicators,
            &native_secret,
            &mut rng,
        )
        .unwrap()
    });

    let project_pair_selector = |label: usize, coefficient: usize| {
        let mut output = zero(&p2_ctx);
        let mut selected = shift(
            &p2_ctx,
            &packed_pairs[label],
            if coefficient == 0 {
                0
            } else {
                2 * p2_ctx.n - coefficient
            },
        );
        for key in &trace {
            selected = p2_ctx.add(&selected, &galois.apply(&selected, key).unwrap());
        }
        add_scaled(&p2_ctx, &mut output, &selected, 1);
        output
    };
    let pair_state = |start: usize, terms: [i64; 2]| {
        let mut destinations = BTreeMap::new();
        let mut rows: Vec<Row> = Vec::new();
        for left_label in -1i64..=1 {
            for right_label in -1i64..=1 {
                let total =
                    terms[0] as i128 * left_label as i128 + terms[1] as i128 * right_label as i128;
                let winding = (total + P as i128 / 2).div_euclid(P as i128);
                let destination = (total - P as i128 * winding, winding as i64);
                let label = ((left_label + 1) * 3 + right_label + 1) as usize;
                let selector = project_pair_selector(label, start);
                runtime
                    .noise
                    .admit(runtime.noise.projected, "pair selector")
                    .unwrap();
                let index = if let Some(&index) = destinations.get(&destination) {
                    index
                } else {
                    let index = rows.len();
                    destinations.insert(destination, index);
                    rows.push(Row {
                        remainder: destination.0,
                        winding: destination.1,
                        selector: None,
                        bound: U512::zero(),
                    });
                    index
                };
                rows[index].bound = rows[index].bound.add(runtime.noise.projected);
                runtime
                    .noise
                    .admit(rows[index].bound, "merged pair selector")
                    .unwrap();
                rows[index].selector = Some(match rows[index].selector.take() {
                    None => selector,
                    Some(previous) => p2_ctx.add(&previous, &selector),
                });
            }
        }
        State {
            rows,
            family: runtime.family,
            source_q: P as i128,
            coefficients: vec![start, start + 1],
        }
    };
    let mut pair_states: Vec<_> = (0..p2_ctx.n)
        .step_by(2)
        .map(|start| {
            let terms = if start == 0 {
                [r1[0], -r1[p2_ctx.n - 1]]
            } else {
                [-r1[p2_ctx.n - start], -r1[p2_ctx.n - start - 1]]
            };
            pair_state(start, terms)
        })
        .collect();
    while pair_states.len() > 1 {
        let mut next_level = Vec::with_capacity(pair_states.len().div_ceil(2));
        for pair in pair_states.chunks(2) {
            next_level.push(if pair.len() == 2 {
                runtime.compose(&pair[0], &pair[1], &relin).unwrap()
            } else {
                pair[0].clone()
            });
        }
        pair_states = next_level;
    }
    let paired_sum = pair_states.pop().unwrap();
    let initial = runtime.initial(r0[0] as i128).unwrap();
    let state = runtime.compose(&initial, &paired_sum, &relin).unwrap();
    eprintln!(
        "quotient-carry tree cost: N={}, states={}, exact selector products={}",
        p2_ctx.n,
        state.rows.len(),
        runtime.multiplications.get(),
    );
    let root = Root211::new(&runtime, &state).unwrap();
    let winding = runtime.project(root.state, |row| row.winding);
    // Precharge each pair indicator by N^-1 mod p^2. Multiplication by
    // X^(2N-k) moves coefficient k to the constant term without a sign,
    // because X^(2N)=1. The native Galois trace emits a unit selector.
    assert_eq!(
        (p2_ctx.n as u128 * trace_unit.rem_euclid(P2 as i64) as u128) % P2 as u128,
        1
    );
    let winding_plaintext = winding.ciphertext;
    let winding_bound = winding.bound;
    let (projected_winding, measured_winding_bound) =
        decode_at_with_error(&p2_ctx, &winding_plaintext, &keys.secret_key, [0]);
    eprintln!(
        "one-root quotient winding: modeled bound={} bits, measured error={} bits, p^2 decoding radius={} bits",
        bits(winding_bound),
        bits(measured_winding_bound),
        bits(runtime.noise.half()),
    );
    assert!(words(winding_bound) >= words(measured_winding_bound));
    decode_at(
        &p2_ctx,
        &winding_plaintext,
        &keys.secret_key,
        winding_bound,
        [0],
    );
    assert_eq!(
        projected_winding[0],
        expected_quotient_winding.rem_euclid(P2 as i128) as u64,
        "the one-root selector must recover the component quotient winding"
    );

    let mut corrected_k = lifted_k.clone();
    add_scaled(&p2_ctx, &mut corrected_k, &winding_plaintext, -(P as i64));
    let q = U512::product_u64s(&PRIMES);
    let scaled_correction_bound = winding_bound.mul_u128(P as u128);
    let correction_admitted = words(scaled_correction_bound.mul_u128(2 * P2 as u128)) < words(q);
    let corrected_k_plain = decode_at(
        &p2_ctx,
        &corrected_k,
        &keys.secret_key,
        scaled_correction_bound.add(U512::from_u64(1_000_000)),
        [0],
    );
    let corrected_matches = corrected_k_plain[0] == residue_k0;
    eprintln!(
        "second quotient carry: Enc_p(K)->Enc_(p^2)(K+p*J_q), J_q={} recovered by the live unit-scale one-root trit path; multiply-by-p correction bound={} bits, admitted={}, corrected coefficient exact={}",
        expected_quotient_winding.unsigned_abs(),
        bits(scaled_correction_bound),
        correction_admitted,
        corrected_matches,
    );
    if correction_admitted {
        assert!(
            corrected_matches,
            "admitted quotient correction must decode exactly"
        );
        // An Enc_(p^2)(K) ciphertext is the same RNS object as
        // Enc_T(M_pJ*K), because T=M_pJ*p^2.
        let expected_high_correction =
            (M_PJ as i128 * input[0] as i128).rem_euclid(FULL_T as i128) as u64;
        let high_scale_bound = scaled_correction_bound.mul_u128(M_PJ as u128);
        let high_admitted = words(high_scale_bound.mul_u128(2 * FULL_T as u128)) < words(q);
        let (high_plain, measured_high_bound) =
            decode_at_with_error(&full_ctx, &corrected_k, &keys.secret_key, [0]);
        let high_exact = high_plain[0] == expected_high_correction;
        let high_t_radius = Noise::new_for_composite_sister_target(&full_ctx.config).half();
        eprintln!(
            "p^2-to-full-T scale: modeled error={} bits, measured error={} bits, high-T radius={} bits; admitted={}, exact high correction={}",
            bits(high_scale_bound),
            bits(measured_high_bound),
            bits(high_t_radius),
            high_admitted,
            high_exact,
        );
        if high_admitted {
            assert!(
                high_exact,
                "an admitted high correction must decode exactly"
            );
        }
    }
}

#[test]
fn safe_basis_root_projects_second_k_elimination_quotient_winding() {
    run_second_k_elimination_quotient_winding(4);
}

#[test]
fn safe_basis_root_projects_second_k_elimination_quotient_winding_at_degree_eight() {
    run_second_k_elimination_quotient_winding(8);
}

#[test]
fn one_root_projects_pj_from_even_p_plus_one_winding_tray_into_high_t() {
    const P: u64 = 65_537;
    const WINDING_PERIOD: u64 = P + 1;
    const WINDING_BOUND: u64 = 16_386;
    const HIGH_T: u64 = 145_531_445_121_188_874;
    const WINDINGS: [i128; 5] = [
        -(WINDING_BOUND as i128),
        -147,
        0,
        147,
        WINDING_BOUND as i128,
    ];

    let mut config = SecureConfig::secure_128().into_config();
    config.n = 32;
    config.primes = vec![288_230_376_152_137_729, 288_230_376_152_727_553];
    config.q = config.primes[0];
    config.security_bits = 0;
    config.t = HIGH_T;
    let ctx = RNSFHEContext::try_new(&config).unwrap();
    assert!(WINDING_PERIOD > 2 * WINDING_BOUND);
    let mut rng = ShadowHarvester::with_seed(0x504a_4556_454e_3131);
    let keys = ctx.generate_keys_dual(&mut rng);
    let mut one_message = vec![0i8; ctx.n];
    one_message[0] = 1;
    let selected_one = precharge(&ctx, &keys, &one_message, &mut rng);
    let selected_zero = precharge(&ctx, &keys, &vec![0i8; ctx.n], &mut rng);
    let runtime = CarryRuntime::new_composite_sister_target(&ctx, P as i128, [517, 2], 8);
    let selector_error = U512::from_u64(config.eta as u64);
    let mut rows: Vec<_> = WINDINGS
        .iter()
        .map(|&winding| Row {
            remainder: winding,
            winding: 0,
            selector: None,
            // Each row is a direct key-holder precharge. No composition or
            // projection has yet expanded its exact eta phase error.
            bound: selector_error,
        })
        .collect();

    for (selected, &winding) in WINDINGS.iter().enumerate() {
        for (index, row) in rows.iter_mut().enumerate() {
            row.selector = Some(if index == selected {
                selected_one.clone()
            } else {
                selected_zero.clone()
            });
        }
        let state = State {
            rows: rows.clone(),
            family: runtime.family,
            source_q: P as i128,
            coefficients: vec![0],
        };
        let root = Root211::new(&runtime, &state).unwrap();
        let tray = root.attach(&[WINDING_PERIOD]).unwrap();
        let p_winding = root
            .project_bounded_scaled_remainder(
                &tray,
                WINDING_PERIOD,
                WINDING_BOUND,
                P as i64,
                HIGH_T,
            )
            .unwrap();
        let decoded = decode_at(
            &ctx,
            &p_winding.ciphertext,
            &keys.secret_key,
            p_winding.bound,
            0..ctx.n,
        );
        assert_eq!(
            decoded[0],
            (P as i128 * winding).rem_euclid(HIGH_T as i128) as u64,
            "the root must emit signed pJ directly in the high encoding"
        );
        assert!(decoded[1..].iter().all(|&value| value == 0));
    }
}

#[test]
fn one_root_emits_adjacent_residual_at_common_composite_t_and_k_eliminates() {
    const P: u64 = 65_537;
    const M: u64 = P + 1;
    const SCALE_FACTOR: u64 = 16_390 * M;
    const HIGH_T: u64 = 17_601_581_752_325;
    const K_BOUND: i128 = 8_193;
    const J_BOUND: i128 = 8_193;
    const RESIDUAL_BOUND: u64 = 16_386;
    const CASES: [(i128, i128); 5] = [
        (-K_BOUND, -J_BOUND),
        (-K_BOUND, J_BOUND),
        (0, 0),
        (K_BOUND, -J_BOUND),
        (K_BOUND, J_BOUND),
    ];

    let mut config = SecureConfig::secure_128().into_config();
    config.n = 32;
    config.primes = vec![
        9_223_372_036_853_661_697,
        9_223_372_036_853_235_713,
        9_223_372_036_852_744_193,
    ];
    config.q = config.primes[0];
    config.security_bits = 0;
    config.t = HIGH_T;
    let ctx = RNSFHEContext::try_new(&config).unwrap();
    assert_eq!(M * ((HIGH_T + 1) / M), HIGH_T + 1);
    assert_eq!(HIGH_T % M, M - 1);
    assert!(2 * SCALE_FACTOR as u128 * (K_BOUND as u128) < HIGH_T as u128);
    assert!(M > 2 * RESIDUAL_BOUND);

    let mut rng = ShadowHarvester::with_seed(0x494e_5652_4553_5441);
    let keys = ctx.generate_keys_dual(&mut rng);
    let mut one_message = vec![0i8; ctx.n];
    one_message[0] = 1;
    let selected_one = precharge(&ctx, &keys, &one_message, &mut rng);
    let selected_zero = precharge(&ctx, &keys, &vec![0i8; ctx.n], &mut rng);
    let runtime = CarryRuntime::new_composite_sister_target(&ctx, P as i128, [16_390, 2], 8);
    let selector_error = U512::from_u64(config.eta as u64);
    let mut rows: Vec<_> = CASES
        .iter()
        .map(|&(k, j)| Row {
            remainder: k,
            winding: j as i64,
            selector: None,
            // These are direct key-holder precharges, so use their exact eta
            // phase-error contract rather than the post-transform envelope.
            bound: selector_error,
        })
        .collect();
    let mut max_residual_bits = 0;
    let mut max_j_bits = 0;
    let mut max_k_bits = 0;
    let mut max_scaled_k_bits = 0;

    for (selected, &(k, j)) in CASES.iter().enumerate() {
        for (index, row) in rows.iter_mut().enumerate() {
            row.selector = Some(if index == selected {
                selected_one.clone()
            } else {
                selected_zero.clone()
            });
        }
        let state = State {
            rows: rows.clone(),
            family: runtime.family,
            source_q: P as i128,
            coefficients: vec![0],
        };
        let root = Root211::new(&runtime, &state).unwrap();
        let tray = root.attach(&[P, M, HIGH_T]).unwrap();
        root.validate(&tray).unwrap();
        if selected == 0 {
            let foreign_state = runtime.initial(0).unwrap();
            let foreign_root = Root211::new(&runtime, &foreign_state).unwrap();
            assert!(matches!(
                foreign_root.project_bounded_affine_sheet(&tray, M, RESIDUAL_BOUND, 1, -1, HIGH_T,),
                Err(TrayRefusal::ForeignRoot)
            ));
            assert!(matches!(
                root.project_bounded_affine_sheet(&tray, M, RESIDUAL_BOUND - 1, 1, -1, HIGH_T,),
                Err(TrayRefusal::InvalidLiftBound)
            ));
        }

        // The attached M view and the bounded affine sheet view are derived
        // from this same root/history. The latter is already Enc_T(K-J),
        // rather than an Enc_M residue relabelled after projection.
        let residual = root
            .project_bounded_affine_sheet(&tray, M, RESIDUAL_BOUND, 1, -1, HIGH_T)
            .unwrap();
        let c_bound = tray.views[2].bound;
        let mut c_minus_r = zero(&ctx);
        add_scaled(&ctx, &mut c_minus_r, &tray.views[2].ciphertext, 1);
        add_scaled(&ctx, &mut c_minus_r, &residual.ciphertext, -1);
        let inverse_m = (HIGH_T + 1) / M;
        let j_view_bound = c_bound.add(residual.bound).mul_u128(inverse_m as u128);
        runtime
            .noise
            .admit(j_view_bound, "inverse-residual J")
            .unwrap();
        let mut j_view = zero(&ctx);
        add_scaled(&ctx, &mut j_view, &c_minus_r, inverse_m as i64);

        let mut corrected = zero(&ctx);
        add_scaled(&ctx, &mut corrected, &tray.views[2].ciphertext, 1);
        add_scaled(&ctx, &mut corrected, &j_view, -(P as i64));
        let corrected_bound = c_bound.add(j_view_bound.mul_u128(P as u128));
        runtime
            .noise
            .admit(corrected_bound, "inverse-residual K correction")
            .unwrap();

        let mut sum_form = zero(&ctx);
        add_scaled(&ctx, &mut sum_form, &residual.ciphertext, 1);
        add_scaled(&ctx, &mut sum_form, &j_view, 1);
        let sum_bound = residual.bound.add(j_view_bound);
        runtime.noise.admit(sum_bound, "r+J K correction").unwrap();

        let scaled_bound = corrected_bound.mul_u128(SCALE_FACTOR as u128);
        runtime
            .noise
            .admit(scaled_bound, "full M_pJ K scale")
            .unwrap();
        max_residual_bits = max_residual_bits.max(bits(residual.bound));
        max_j_bits = max_j_bits.max(bits(j_view_bound));
        max_k_bits = max_k_bits.max(bits(corrected_bound));
        max_scaled_k_bits = max_scaled_k_bits.max(bits(scaled_bound));
        let mut scaled = zero(&ctx);
        add_scaled(&ctx, &mut scaled, &corrected, SCALE_FACTOR as i64);

        let decoded_c = decode_at(
            &ctx,
            &tray.views[2].ciphertext,
            &keys.secret_key,
            c_bound,
            0..ctx.n,
        );
        let decoded_m = decode_at(
            &ctx,
            &tray.views[1].ciphertext,
            &keys.secret_key,
            tray.views[1].bound,
            0..ctx.n,
        );
        let decoded_r = decode_at(
            &ctx,
            &residual.ciphertext,
            &keys.secret_key,
            residual.bound,
            0..ctx.n,
        );
        let decoded_j = decode_at(&ctx, &j_view, &keys.secret_key, j_view_bound, 0..ctx.n);
        let decoded_k = decode_at(
            &ctx,
            &corrected,
            &keys.secret_key,
            corrected_bound,
            0..ctx.n,
        );
        let decoded_sum = decode_at(&ctx, &sum_form, &keys.secret_key, sum_bound, 0..ctx.n);
        let decoded_scaled = decode_at(&ctx, &scaled, &keys.secret_key, scaled_bound, 0..ctx.n);

        let expected_c = k + P as i128 * j;
        let expected_r = k - j;
        let expected_scaled_k = SCALE_FACTOR as i128 * k;
        assert_eq!(decoded_c[0], expected_c.rem_euclid(HIGH_T as i128) as u64);
        assert_eq!(decoded_m[0] % M, expected_r.rem_euclid(M as i128) as u64);
        assert_eq!(decoded_r[0], expected_r.rem_euclid(HIGH_T as i128) as u64);
        assert_eq!(decoded_j[0], j.rem_euclid(HIGH_T as i128) as u64);
        assert_eq!(decoded_k[0], k.rem_euclid(HIGH_T as i128) as u64);
        assert_eq!(decoded_sum[0], k.rem_euclid(HIGH_T as i128) as u64);
        assert_eq!(
            decoded_scaled[0],
            expected_scaled_k.rem_euclid(HIGH_T as i128) as u64
        );
        for decoded in [
            decoded_c,
            decoded_m,
            decoded_r,
            decoded_j,
            decoded_k,
            decoded_sum,
            decoded_scaled,
        ] {
            assert!(decoded[1..].iter().all(|&value| value == 0));
        }
    }
    eprintln!(
        "same-root common-T residual: cases={}, certified error bits r/J/K/full-scale={}/{}/{}/{}, half-Delta={} bits; wrong-root and insufficient-bound refusals checked",
        CASES.len(),
        max_residual_bits,
        max_j_bits,
        max_k_bits,
        max_scaled_k_bits,
        bits(runtime.noise.half()),
    );
}

fn relin_key(
    runtime: &CarryRuntime<'_>,
    keys: &DualRNSKeySet,
    rng: &mut ShadowHarvester,
) -> RNSHybridGadgetKey {
    let native = RNSSecretKey {
        s: RNSPolynomial {
            n: runtime.ctx.n,
            limbs: runtime
                .ctx
                .rns
                .mont_contexts
                .iter()
                .zip(&keys.secret_key.s.main)
                .map(|(mont, lane)| {
                    lane.iter()
                        .map(|&value| mont.to_montgomery(value))
                        .collect()
                })
                .collect(),
        },
    };
    runtime
        .exact
        .generate_hybrid_gadget_key_with_rng(&native, rng)
}

// Called inside the existing opt-in native composition probe, reusing its
// actual packed extraction and encrypted states instead of duplicating keys.
fn wide_layouts() -> Vec<Vec<u64>> {
    vec![
        vec![
            chimera_by_name("shadow_bridge").unwrap().product,
            chimera_by_name("boundary_saturation").unwrap().product,
        ],
        vec![1, 6, 10, 8, 27, 121, 385, 4199, 6, 65537],
    ]
}

pub(super) fn check_native_trays(
    runtime: &CarryRuntime<'_>,
    state: &State,
    secret: &DualRNSSecretKey,
    expected_sum: i128,
) {
    assert_eq!(
        check_native_views(runtime, state, secret, expected_sum, &wide_layouts()),
        21 * runtime.ctx.n
    );
}

fn check_native_views(
    runtime: &CarryRuntime<'_>,
    state: &State,
    secret: &DualRNSSecretKey,
    expected_sum: i128,
    layouts: &[Vec<u64>],
) -> usize {
    let before = runtime.multiplications.get();
    let root = Root211::new(runtime, state).unwrap();
    let trays: Vec<_> = layouts.iter().map(|m| root.attach(m).unwrap()).collect();
    for tray in &trays {
        root.validate(tray).unwrap();
        assert!(std::ptr::eq(&root, tray.root));
    }
    let mut checked = 0;
    for (modulus, view) in ROOT.iter().copied().zip(&root.lanes).chain(
        trays
            .iter()
            .flat_map(|t| t.moduli.iter().copied().zip(&t.views)),
    ) {
        let decoded = decode_at(
            runtime.ctx,
            &view.ciphertext,
            secret,
            view.bound,
            0..runtime.ctx.n,
        );
        assert_eq!(decoded[0] as i128, expected_sum.rem_euclid(modulus as i128));
        assert!(decoded[1..].iter().all(|&x| x == 0));
        checked += decoded.len();
    }
    let decoded = decode_at(
        runtime.ctx,
        &root.shadow_index.ciphertext,
        secret,
        root.shadow_index.bound,
        0..runtime.ctx.n,
    );
    assert_eq!(
        decoded[0] as i128,
        expected_sum.div_euclid(2).rem_euclid(11)
    );
    assert!(decoded[1..].iter().all(|&x| x == 0));
    checked += decoded.len();
    assert_eq!(
        checked,
        (9 + layouts.iter().map(Vec::len).sum::<usize>()) * runtime.ctx.n
    );
    assert_eq!(runtime.multiplications.get(), before);
    eprintln!("sister tray: {checked} encrypted coefficient/error checks; one S8 root, two borrowed trays; live 2/11 index; arbitrary/shared/repeated targets; no extra ciphertext multiplication");
    checked
}

#[test]
fn sister_tray_update_plan_is_bound_to_its_parent_and_refuses_before_execution() {
    let ctx = RNSFHEContext::try_new(&config_with(5)).unwrap();
    let runtime = CarryRuntime::new(&ctx, 101, [211, 2], 27);
    let state = runtime.initial(1).unwrap();
    let other_state = runtime.initial(23).unwrap();
    let root = Root211::new(&runtime, &state).unwrap();
    let other = Root211::new(&runtime, &other_state).unwrap();
    // Public valid one-hot u=0 fixture, not an encryption/randomness claim.
    let mut encrypted = core::array::from_fn(|_| zero(&ctx));
    for lane in 0..ctx.config.primes.len() {
        encrypted[1].c0.limbs[lane][0] =
            ctx.rns.mont_contexts[lane].to_montgomery(ctx.delta_rns[lane]);
    }
    let trit = Trit {
        encrypted,
        bound: runtime.noise.projected,
        family: runtime.family,
        coefficient: 0,
    };
    let before = root.evaluated_views.get();
    let prepared = root.prepare_advance(50, &trit, &wide_layouts()).unwrap();
    prepared.validate_parent(&root).unwrap();
    assert_eq!(
        prepared.validate_parent(&other),
        Err(TrayRefusal::ForeignRoot)
    );
    assert_eq!(prepared.advance.composition.result.coefficients, vec![0]);
    assert_eq!(prepared.advance.composition.result.rows.len(), 3);
    drop(prepared); // A cancelled plan cannot change its source or emit views.
    let mut corrupted = root.prepare_advance(50, &trit, &wide_layouts()).unwrap();
    let destination = corrupted.advance.composition.edges[0].2;
    corrupted.advance.composition.result.rows[destination].remainder += 1;
    assert_eq!(
        verify_phase_edges(&runtime, &corrupted.advance),
        Err(TrayRefusal::PhaseTransition)
    );
    drop(corrupted); // Deliberately malformed test plan is never executed.
    assert!(matches!(
        root.prepare_advance(50, &trit, &[vec![6], vec![0]]),
        Err(TrayRefusal::InvalidModulus)
    ));
    assert!(matches!(
        root.prepare_advance(50, &trit, &[vec![6], vec![ctx.t + 1]]),
        Err(TrayRefusal::EncodingCapacity)
    ));
    assert!(matches!(
        root.prepare_advance(51, &trit, &wide_layouts()),
        Err(TrayRefusal::Transition(Refusal::NonCentered))
    ));
    let mut foreign = trit.clone();
    foreign.family[1] += 1;
    assert!(matches!(
        root.prepare_advance(50, &foreign, &wide_layouts()),
        Err(TrayRefusal::Transition(Refusal::Regime))
    ));
    assert!(matches!(
        root.prepare_composite_advance(
            50,
            &trit,
            &wide_layouts(),
            CompositeBudget {
                min_modulus: 4,
                max_modulus: 12,
                max_view_error: U512::zero(),
            }
        ),
        Err(TrayRefusal::NoCompositeFits)
    ));
    let (cancelled, choice) = root
        .prepare_composite_advance(
            50,
            &trit,
            &[vec![6, 10]],
            CompositeBudget {
                min_modulus: 35,
                max_modulus: ctx.t,
                max_view_error: runtime.noise.half().div_u64(4),
            },
        )
        .unwrap();
    cancelled.validate_parent(&root).unwrap();
    assert_eq!(
        cancelled.validate_parent(&other),
        Err(TrayRefusal::ForeignRoot)
    );
    assert_eq!(cancelled.layouts, vec![vec![6, 10], vec![choice.modulus]]);
    assert_eq!(choice.distinct_support, 3);
    drop(cancelled);
    assert_eq!(root.evaluated_views.get(), before);
    assert_eq!(runtime.multiplications.get(), 0);
    assert!(state.coefficients.is_empty());
    assert_eq!(state.rows[0].remainder, 1);
}

pub(super) fn advance_native_with_trays(
    runtime: &CarryRuntime<'_>,
    state: &State,
    term: i128,
    trit: &Trit,
    relin: &RNSHybridGadgetKey,
    secret: &DualRNSSecretKey,
    expected_sum: i128,
    step: usize,
) -> State {
    let root = Root211::new(runtime, state).unwrap();
    let old_tray = root.attach(&[2, 11]).unwrap();
    let before = runtime.multiplications.get();
    let views_before = root.evaluated_views.get();
    let wide = wide_layouts();
    let prepared = if step < 2 {
        root.prepare_advance(term, trit, &wide).unwrap()
    } else {
        // Carry/root updates fit, but keeping the larger sister targets does
        // not. Reject the WHOLE proposal before multiplication, then retry
        // with smaller target views. No error bound is reset by this choice.
        let refused = root.prepare_advance(term, trit, &wide).err().unwrap();
        assert!(matches!(refused, TrayRefusal::Noise(_)));
        assert_eq!(runtime.multiplications.get(), before);
        assert_eq!(root.evaluated_views.get(), views_before);
        eprintln!("sister transition: wide third-step proposal refused before multiplication: {refused:?}");
        let retained = vec![vec![6, 10, 15, 21], vec![1, 8, 9, 11, 22, 6]];
        let budget = CompositeBudget {
            min_modulus: 35,
            max_modulus: runtime.ctx.t,
            max_view_error: runtime.noise.half().div_u64(4),
        };
        let (prepared, choice) = root
            .prepare_composite_advance(term, trit, &retained, budget)
            .unwrap();
        let proposed = &prepared.advance.composition.result;
        // Independently reproduced by the arbitrary-precision Python probe.
        let expected = if term < 0 {
            [315, 194, 158, 78, 45]
        } else {
            [300, 206, 123, 93, 65]
        };
        for (divisor, expected_modulus) in [2, 3, 4, 5, 8].into_iter().zip(expected) {
            let alternative = choose_composite(
                runtime,
                proposed,
                CompositeBudget {
                    max_view_error: runtime.noise.half().div_u64(divisor),
                    ..budget
                },
            )
            .unwrap();
            assert_eq!(alternative.modulus, expected_modulus);
            assert_eq!(alternative.distinct_support, 7);
            let b = alternative.error_bound;
            eprintln!("composite tray: sign={}, cap=half/{divisor}, modulus={}, error_bits={}, distinct_support={}, bound_hex={:032x}{:032x}{:032x}{:032x}", term.signum(), alternative.modulus, bits(b), alternative.distinct_support, b.d3, b.d2, b.d1, b.d0);
        }
        assert_eq!(choice.modulus, if term < 0 { 158 } else { 123 });
        let fixed = CompositeBudget {
            min_modulus: choice.modulus,
            max_modulus: choice.modulus,
            max_view_error: choice.error_bound,
        };
        assert_eq!(choose_composite(runtime, proposed, fixed).unwrap(), choice);
        assert_eq!(
            choose_composite(
                runtime,
                proposed,
                CompositeBudget {
                    max_view_error: choice.error_bound.sub(U512::from_u64(1)),
                    ..fixed
                }
            ),
            Err(TrayRefusal::NoCompositeFits)
        );
        assert_eq!(
            choose_composite(
                runtime,
                proposed,
                CompositeBudget {
                    max_view_error: runtime.noise.half().div_u64(16),
                    ..budget
                }
            ),
            Err(TrayRefusal::NoCompositeFits)
        );
        assert_eq!(runtime.multiplications.get(), before);
        assert_eq!(root.evaluated_views.get(), views_before);
        prepared
    };
    let layouts = prepared.layouts.clone();
    prepared.validate_parent(&root).unwrap();
    let planned_bounds: Vec<_> = prepared
        .advance
        .composition
        .result
        .rows
        .iter()
        .map(|r| r.bound)
        .collect();
    let (next_state, committed_layouts) = prepared.commit(relin);
    assert_eq!(committed_layouts, layouts);
    assert_eq!(
        next_state.rows.iter().map(|r| r.bound).collect::<Vec<_>>(),
        planned_bounds
    );
    let next_root = Root211::new(runtime, &next_state).unwrap();
    assert_eq!(next_root.validate(&old_tray), Err(TrayRefusal::ForeignRoot));
    root.validate(&old_tray).unwrap(); // old immutable snapshot remains valid only for its source.
    if step < 2 {
        check_native_trays(runtime, &next_state, secret, expected_sum);
    } else {
        assert_eq!(
            check_native_views(runtime, &next_state, secret, expected_sum, &layouts),
            20 * runtime.ctx.n
        );
    }
    eprintln!("sister transition: committed step={}, source coefficients={:?}, executed selector products={}", step + 1, next_state.coefficients, runtime.multiplications.get() - before);
    next_state
}

pub(super) fn check_native_noise_refusal(runtime: &CarryRuntime<'_>, state: &State) {
    let root = Root211::new(runtime, state).unwrap();
    let before = root.evaluated_views.get();
    assert!(matches!(
        root.attach(&[6, 4199]),
        Err(TrayRefusal::Noise(_))
    ));
    assert_eq!(
        root.evaluated_views.get(),
        before,
        "preflight the whole tray before producing even its first view"
    );
}
