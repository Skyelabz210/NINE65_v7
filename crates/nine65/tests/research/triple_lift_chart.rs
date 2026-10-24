//! Public shared-precharge chart producer. The native third composite is
//! 143=13*11, under a Q_source/64 phase envelope. No nonlinear gate/admission.

use super::*;

#[path = "frobenius_chart_section.rs"]
mod frobenius_chart_section;

#[derive(Clone)]
struct ChartSpec {
    coordinates: Vec<usize>,
    matrix: Vec<Vec<i64>>,
    inverse: Vec<Vec<i64>>,
}

impl ChartSpec {
    fn native() -> Self {
        Self {
            coordinates: vec![99, 121, 143],
            matrix: vec![vec![-1, -3, 5], vec![9, -11, 0], vec![0, 11, -13]],
            inverse: vec![vec![143, 16, 55], vec![117, 13, 45], vec![99, 11, 38]],
        }
    }
    fn toy() -> Self {
        Self {
            coordinates: vec![3, 5, 7],
            matrix: vec![vec![-1, 1, 1], vec![3, -5, 0], vec![0, 5, -7]],
            inverse: vec![vec![35, 12, 5], vec![21, 7, 3], vec![15, 5, 2]],
        }
    }
    fn validate(&self) -> Result<(), &'static str> {
        let size = self.coordinates.len();
        if size < 2
            || size > 3
            || self.matrix.len() != size
            || self.inverse.len() != size
            || self
                .matrix
                .iter()
                .chain(&self.inverse)
                .any(|row| row.len() != size)
            || self
                .matrix
                .iter()
                .chain(&self.inverse)
                .flatten()
                .any(|v| v.unsigned_abs() > 65536)
            || self.coordinates.iter().any(|m| *m < 3 || m % 2 == 0)
        {
            return Err("invalid chart dimensions or public coefficient range");
        }
        for i in 0..size {
            for j in 0..size {
                let value: i128 = (0..size)
                    .map(|k| self.matrix[i][k] as i128 * self.inverse[k][j] as i128)
                    .sum();
                if value != i128::from(i == j) {
                    return Err("chart must have an integer inverse");
                }
            }
        }
        Ok(())
    }
    fn windows(
        &self,
        n: usize,
        outer_n: usize,
        h: usize,
        cap: u128,
        q: u128,
    ) -> Result<Vec<u128>, &'static str> {
        self.validate()?;
        if outer_n != 2 * n || h > n || cap >= q / 2 {
            return Err("invalid public source envelope");
        }
        let windows: Vec<_> = self
            .coordinates
            .iter()
            .map(|&m| phase_window2_for_q(outer_n, h, m, cap, q))
            .collect();
        if windows.iter().any(|&w| w >= outer_n as u128) {
            return Err("a sister view exceeds its clock window");
        }
        Ok(windows)
    }
}

struct ChartRow {
    ciphertext: RNSCiphertext,
    bound: u128,
    integer_limit: u128,
    weight_l1: u128,
}
struct PublicChart<'a> {
    source: &'a RNSFHEContext,
    outer: &'a RNSFHEContext,
    precharge: &'a RNSCiphertext,
    precharge_v: u128,
    source_norm: usize,
    phase_cap: u128,
    spec: ChartSpec,
}

impl<'a> PublicChart<'a> {
    fn from_phase(phase: &'a BatchedPhase<'_>, spec: ChartSpec) -> Self {
        spec.validate().unwrap();
        Self {
            source: phase.source,
            outer: phase.outer,
            precharge: &phase.encrypted_source,
            precharge_v: phase.precharge_v,
            source_norm: phase.source_norm,
            phase_cap: phase.phase_cap,
            spec,
        }
    }
    // Public evaluator boundary. No client keys, source support, measured
    // errors, native sheets or clear (U,D,E) values are accepted.
    fn apply(&self, input: &RNSCiphertext, input_v: u128) -> Vec<ChartRow> {
        assert_eq!(self.source.t, self.outer.t);
        assert_eq!(input.num_primes, self.source.config.primes.len());
        assert_eq!(self.precharge.num_primes, self.outer.config.primes.len());
        let q: u128 = self
            .source
            .config
            .primes
            .iter()
            .map(|&q| q as u128)
            .product();
        self.spec
            .windows(
                self.source.n,
                self.outer.n,
                self.source_norm,
                self.phase_cap,
                q,
            )
            .unwrap();
        assert!(input_v <= self.phase_cap);
        let public0: Vec<_> = self
            .spec
            .coordinates
            .iter()
            .map(|&m| preprocess_for_clock(self.source, &input.c0, m, self.outer.n))
            .collect();
        let public1: Vec<_> = self
            .spec
            .coordinates
            .iter()
            .map(|&m| preprocess_for_clock(self.source, &input.c1, m, self.outer.n))
            .collect();
        let remainder = U512::product_u64s(&self.outer.config.primes).mod_u64(self.outer.t) as u128;
        self.spec
            .matrix
            .iter()
            .map(|row| {
                let mut w0 = vec![0; self.outer.n];
                let mut w1 = w0.clone();
                for j in 0..self.source.n {
                    w0[2 * j] = row
                        .iter()
                        .enumerate()
                        .map(|(i, &a)| a * public0[i].clock[j])
                        .sum();
                    w1[2 * j] = row
                        .iter()
                        .enumerate()
                        .map(|(i, &a)| a * public1[i].clock[j])
                        .sum();
                }
                let coefficient_max = w0
                    .iter()
                    .chain(&w1)
                    .map(|v| v.unsigned_abs() as u128)
                    .max()
                    .unwrap();
                let integer_limit = (self.source_norm as u128 + 1)
                    .checked_mul(coefficient_max)
                    .unwrap();
                assert!(
                    integer_limit.checked_mul(2).unwrap() < self.outer.t as u128,
                    "chart coordinate aliases in the plaintext"
                );
                let weight_l1 = w1.iter().map(|v| v.unsigned_abs() as u128).sum::<u128>();
                let constant_max = w0.iter().map(|v| v.unsigned_abs() as u128).max().unwrap();
                let bound = self
                    .precharge_v
                    .checked_mul(weight_l1)
                    .unwrap()
                    .checked_add(remainder.checked_mul(constant_max).unwrap())
                    .unwrap();
                assert!(
                    words(U512::from_u128(bound).mul_u128(2))
                        < words(U512::product_u64s(&self.outer.config.primes))
                );
                let ciphertext = add(
                    self.outer,
                    &multiply_signed_plain(self.outer, self.precharge, &w1),
                    &public_plain(self.outer, &w0),
                );
                ChartRow {
                    ciphertext,
                    bound,
                    integer_limit,
                    weight_l1,
                }
            })
            .collect()
    }
}

fn check_chart(n: usize, h: usize, denominator: u128, spec: ChartSpec) {
    use std::time::Instant;
    let mut config = SecureConfig::secure_128().into_config();
    config.n = n;
    config.security_bits = 0;
    config.name = "UNADMITTED native triple chart; nonlinear lift OPEN";
    let mut source_config = config.clone();
    source_config.primes.truncate(2);
    let source = RNSFHEContext::try_new(&source_config).unwrap();
    let mut outer_config = config;
    outer_config.n = 2 * n;
    outer_config.primes.extend(EXTRA);
    let outer = RNSFHEContext::try_new(&outer_config).unwrap();
    let q: u128 = source.config.primes.iter().map(|&q| q as u128).product();
    let mut rng = ShadowHarvester::with_seed(0x5452_4950_4c45_4348 + n as u64);
    let trits = balanced_source(n, h, &mut rng);
    let source_keys = sparse_keys(&source, &trits, &mut rng);
    let outer_keys = outer.generate_keys(&mut rng);
    let message: Vec<_> = (0..n)
        .map(|j| if j % 2 == 0 { 1 } else { source.t - 1 })
        .collect();
    let mut input = encrypt_polynomial(&source, &source_keys, &message, &mut rng);
    let load = q / ((denominator + 4) * source.t as u128);
    input.c0 = input.c0.add(
        &montgomery(
            &source,
            source
                .config
                .primes
                .iter()
                .map(|&prime| {
                    (0..n)
                        .map(|j| {
                            let value = (load % prime as u128) as u64;
                            if j % 2 == 0 || value == 0 {
                                value
                            } else {
                                prime - value
                            }
                        })
                        .collect()
                })
                .collect(),
        ),
        &source.rns,
    );
    let input_v = source.t as u128 * (2 * n + 1) as u128 * source.config.eta as u128
        + (q % source.t as u128) * (source.t - 1) as u128
        + load * source.t as u128;
    assert!(
        observe_polynomial(&source, &input, &source_keys, &message) <= input_v
            && input_v <= q / denominator
    );
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
    let mut phase = BatchedPhase {
        source: &source,
        outer: &outer,
        clock_n: outer.n,
        encrypted_source,
        precharge_v,
        source_norm: h,
        coordinate: spec.coordinates[0],
        phase_cap: q / denominator,
    };
    let evaluator = PublicChart::from_phase(&phase, spec.clone());
    let start = Instant::now();
    let chart = evaluator.apply(&input, input_v);
    let elapsed = start.elapsed().as_secs_f64();
    let windows = spec.windows(n, outer.n, h, q / denominator, q).unwrap();
    // Independent CLIENT observations below. The public producer above
    // has already returned all ciphertexts and public error certificates.
    let mut references = Vec::new();
    let mut clear_views = Vec::new();
    let mut sheets = BTreeSet::new();
    for &coordinate in &spec.coordinates {
        phase.coordinate = coordinate;
        let reference = phase.apply(&input, input_v);
        let c0 = preprocess_for_clock(&source, &input.c0, coordinate, outer.n);
        let c1 = preprocess_for_clock(&source, &input.c1, coordinate, outer.n);
        let mut values = vec![0; outer.n];
        for j in 0..n {
            let mut z = c0.clock[j] as i128;
            let mut affine = c0.a[j] as i128;
            for (i, &s) in trits.iter().enumerate().filter(|(_, s)| **s != 0) {
                let k = (j + n - i) % n;
                let sign = s as i128 * if i > j { -1 } else { 1 };
                z += sign * c1.clock[k] as i128;
                affine += sign * c1.a[k] as i128;
            }
            let residue = (message[j] as i128 - affine).rem_euclid(source.t as i128);
            let lift = if residue > source.t as i128 / 2 {
                residue - source.t as i128
            } else {
                residue
            };
            assert_eq!(
                (coordinate as i128 * z + outer.n as i128).div_euclid((2 * outer.n) as i128),
                lift
            );
            sheets.insert(lift);
            values[2 * j] = z.rem_euclid(outer.t as i128) as u64;
        }
        assert!(
            observe_polynomial(&outer, &reference.ciphertext, &outer_keys, &values)
                <= reference.bound
        );
        references.push(reference);
        clear_views.push(values);
    }
    let mut observed_bits = Vec::new();
    let mut bound_bits = Vec::new();
    let mut magnitudes = Vec::new();
    let mut limits = Vec::new();
    let mut weights = Vec::new();
    for (row_index, row) in chart.iter().enumerate() {
        let coefficients = &spec.matrix[row_index];
        let mut combined = zero(&outer);
        let mut triangle = 0;
        for (i, &coefficient) in coefficients.iter().enumerate() {
            combined = add(
                &outer,
                &combined,
                &signed_scale(&outer, &references[i].ciphertext, coefficient),
            );
            triangle += coefficient.unsigned_abs() as u128 * references[i].bound;
        }
        assert_eq!(combined.c0.limbs, row.ciphertext.c0.limbs);
        assert_eq!(combined.c1.limbs, row.ciphertext.c1.limbs);
        assert!(row.bound < triangle);
        let expected: Vec<_> = (0..outer.n)
            .map(|j| {
                coefficients
                    .iter()
                    .enumerate()
                    .map(|(i, &a)| a as i128 * clear_views[i][j] as i128)
                    .sum::<i128>()
                    .rem_euclid(outer.t as i128) as u64
            })
            .collect();
        let magnitude = expected
            .iter()
            .map(|&v| v.min(outer.t - v) as u128)
            .max()
            .unwrap();
        assert!(magnitude <= row.integer_limit);
        let observed = observe_polynomial(&outer, &row.ciphertext, &outer_keys, &expected);
        assert!(observed <= row.bound);
        magnitudes.push(magnitude);
        limits.push(row.integer_limit);
        weights.push(row.weight_l1);
        observed_bits.push(bits(observed));
        bound_bits.push(bits(row.bound));
    }
    for (i, inverse) in spec.inverse.iter().enumerate() {
        let mut recovered = zero(&outer);
        for (j, &a) in inverse.iter().enumerate() {
            recovered = add(
                &outer,
                &recovered,
                &signed_scale(&outer, &chart[j].ciphertext, a),
            );
        }
        assert_eq!(recovered.c0.limbs, references[i].ciphertext.c0.limbs);
        assert_eq!(recovered.c1.limbs, references[i].ciphertext.c1.limbs);
    }
    eprintln!("public triple lift chart: sourceN{n}/outerN{}, H{h}, cap Q/{denominator}, coordinates={:?}, windows={windows:?}; three public signed polynomial products, ALL{n} coefficients and odd zeros correct, integer matrix/inverse determinant1, original three ciphertexts recovered BIT-IDENTICALLY; magnitudes={magnitudes:?}, public bounds={limits:?}, weight l1={weights:?}, V observed bits={observed_bits:?}, producer bound bits={bound_bits:?}, full public evaluator time={elapsed:.6}s, sheets={sheets:?}; native encrypted initializer only, nonlinear chart map/refresh admission OPEN",outer.n,spec.coordinates);
}

#[test]
fn triple_chart_public_preflight_refuses_wide_phase_and_nonunit_coordinate_map() {
    let q = 998244353u128 * 985661441;
    let mut spec = ChartSpec::native();
    assert!(spec.windows(8192, 16384, 96, q / 16, q).is_err());
    assert_eq!(
        spec.windows(8192, 16384, 96, q / 64, q).unwrap(),
        vec![10627, 12761, 14895]
    );
    spec.matrix[0][0] *= 2;
    assert!(spec.validate().is_err());
}

#[test]
fn triple_chart_public_producer_matches_original_views_and_inverse() {
    check_chart(16, 2, 256, ChartSpec::toy());
}

#[test]
#[ignore = "opt-in native encrypted 99/121/143 chart with public producer and complete inverse checks"]
fn triple_chart_native_public_producer_initializes_11_locked_three_view_state() {
    check_chart(8192, 96, 64, ChartSpec::native());
}
