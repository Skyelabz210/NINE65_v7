//! One S8 root, dependent arbitrary-modulus trays, and a bounded 2/11 phase
//! relation. Private research capability; not a production phase authenticator.

use super::*;
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
    assert_eq!(first.period, 30);
    assert_eq!(second.period, 605);
    assert_eq!(root.lanes.len(), 8);
    assert!(std::ptr::eq(first.root, second.root));
    root.validate(&first).unwrap();
    root.validate(&second).unwrap();
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
