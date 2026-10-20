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

impl<'a> Root211<'a> {
    fn new(runtime: &'a CarryRuntime<'a>, state: &'a State) -> Result<Self, TrayRefusal> {
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

    fn attach<'b>(&'b self, moduli: &[u64]) -> Result<SisterTray<'a, 'b>, TrayRefusal> {
        // Arbitrary positive target moduli, NOT another coprime source basis.
        // Shared factors, repeats, prime powers, and modulus 1 are valid.
        for &m in moduli {
            if m == 0 {
                return Err(TrayRefusal::InvalidModulus);
            }
            if m > self.runtime.ctx.t {
                return Err(TrayRefusal::EncodingCapacity);
            }
            self.runtime
                .noise
                .admit(
                    self.runtime
                        .projection_bound(self.state, |r| self.runtime.root_value(r, m)),
                    "dependent sister view",
                )
                .map_err(TrayRefusal::Noise)?;
        }
        let period = period(moduli)?;
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
pub(super) fn check_native_trays(
    runtime: &CarryRuntime<'_>,
    state: &State,
    secret: &DualRNSSecretKey,
    expected_sum: i128,
) {
    let before = runtime.multiplications.get();
    let root = Root211::new(runtime, state).unwrap();
    let bridge = chimera_by_name("shadow_bridge").unwrap();
    let boundary = chimera_by_name("boundary_saturation").unwrap();
    let first = root.attach(&[bridge.product, boundary.product]).unwrap();
    let second = root
        .attach(&[1, 6, 10, 8, 27, 121, 385, 4199, 6, 65537])
        .unwrap();
    root.validate(&first).unwrap();
    root.validate(&second).unwrap();
    assert!(std::ptr::eq(first.root, second.root));
    let mut checked = 0;
    for (modulus, view) in ROOT
        .iter()
        .copied()
        .zip(&root.lanes)
        .chain(first.moduli.iter().copied().zip(&first.views))
        .chain(second.moduli.iter().copied().zip(&second.views))
    {
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
    assert_eq!(checked, 21 * runtime.ctx.n);
    assert_eq!(runtime.multiplications.get(), before);
    eprintln!("sister tray: {checked} encrypted coefficient/error checks; one S8 root, two borrowed trays; live 2/11 index; arbitrary/shared/repeated targets; no extra ciphertext multiplication");
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
