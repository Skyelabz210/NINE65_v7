use super::*;
use crate::entropy::ShadowHarvester;
use crate::ops::public_refresh_circuit::PublicRefreshCircuitPlan;
use crate::ops::public_refresh_source::{PublicRefreshSourceClient, PublicRefreshSourcePlan};
use crate::params::FHEConfig;

const P: u64 = 65_537;
const WORK: [u64; 4] = [998244353, 985661441, 754974721, 469762049];
const BOOT: [u64; 13] = [
    998244353,
    985661441,
    754974721,
    469762049,
    576460752301785089,
    576460752301391873,
    576460752300015617,
    576460752298835969,
    576460752298180609,
    576460752293134337,
    576460752291954689,
    576460752290775041,
    575870995836829697,
];

fn config(n: usize, primes: &[u64], t: u64) -> FHEConfig {
    FHEConfig {
        n,
        primes: primes.to_vec(),
        q: primes[0],
        t,
        eta: 3,
        security_bits: 0,
        name: "INSECURE public scheduler test fixture",
    }
}

fn setup(
    seed: u64,
    budget: u64,
) -> (
    PublicRefreshSourceClient,
    PublicResearchRefreshScheduler,
    ShadowHarvester,
) {
    let mut rng = ShadowHarvester::with_seed(seed);
    let source = PublicRefreshSourcePlan::new(&config(8, &WORK, P), 8, 2, 4, 3).unwrap();
    let plan =
        PublicRefreshCircuitPlan::new(source, config(32, &BOOT, P * P), 4, 3, 16 << 20).unwrap();
    let (client, circuit) = plan.generate_with_rng(&mut rng).unwrap();
    (
        client,
        PublicResearchRefreshScheduler::new(circuit, budget),
        rng,
    )
}

// Independent plaintext schoolbook oracle; no evaluator or noise model calls.
fn product(a: &[u64], b: &[u64]) -> Vec<u64> {
    let mut result = vec![0i128; a.len()];
    for (i, &x) in a.iter().enumerate() {
        for (j, &y) in b.iter().enumerate() {
            let value = x as i128 * y as i128;
            if i + j < a.len() {
                result[i + j] += value;
            } else {
                result[i + j - a.len()] -= value;
            }
        }
    }
    result
        .into_iter()
        .map(|v| v.rem_euclid(P as i128) as u64)
        .collect()
}

fn boundary(
    scheduler: &mut PublicResearchRefreshScheduler,
    mut value: SourceWorkCiphertext,
) -> SourceWorkCiphertext {
    for _ in 0..16 {
        let forecast = scheduler.forecast_square(&value).unwrap();
        if forecast.refresh_operands != RefreshOperands::Neither {
            return value;
        }
        value = scheduler.square(&value).unwrap();
    }
    panic!("fixture did not reach its prospective refresh boundary");
}

#[test]
fn scheduler_forecasts_match_real_arithmetic_and_bind_histories() {
    let (client, mut scheduler, mut rng) = setup(0x5343_4845_4401, 8);
    let left = scheduler.encrypt_with_rng(&[7; 8], &mut rng).unwrap();
    let right = scheduler.encrypt_with_rng(&[11; 8], &mut rng).unwrap();
    let forecast = scheduler.forecast_add(&left, &right).unwrap();
    assert_eq!(forecast.refresh_operands, RefreshOperands::Neither);
    assert_eq!(forecast.input_lineages, [*left.lineage(), *right.lineage()]);
    assert_eq!(forecast.family_id, *client.family_id());
    assert_eq!(scheduler.real_refreshes(), 0);
    let sum = scheduler.add(&left, &right).unwrap();
    assert_eq!(sum.scaled_error_bound(), forecast.output_scaled_error_bound);
    assert_eq!(client.decrypt_work(&sum).unwrap(), vec![18; 8]);
    let next = scheduler.forecast_multiply(&sum, &right).unwrap();
    assert_ne!(next.input_lineages, forecast.input_lineages);
    let output = scheduler.multiply(&sum, &right).unwrap();
    assert_eq!(output.scaled_error_bound(), next.output_scaled_error_bound);
    assert_eq!(
        client.decrypt_work(&output).unwrap(),
        product(&[18; 8], &[11; 8])
    );
    assert_eq!(scheduler.refresh_attempts(), 0);
    assert_eq!(client.decrypt_work(&left).unwrap(), vec![7; 8]);
}

#[test]
fn scheduler_repeated_encrypted_squares_use_real_refresh_once_per_input() {
    for seed in [0x5343_4845_4402, 0x5343_4845_4403] {
        let (client, mut scheduler, mut rng) = setup(seed, 32);
        let mut expected = vec![0, 1, P - 1, P / 2, 7, 0, 31, 17];
        let original = scheduler.encrypt_with_rng(&expected, &mut rng).unwrap();
        let original_lineage = *original.lineage();
        let mut current = original.clone();
        let mut planned_refreshes = 0;
        for _ in 0..12 {
            let forecast = scheduler.forecast_square(&current).unwrap();
            assert!(forecast.output_source_radius <= scheduler.certificate().carry_radius as u64);
            assert!(forecast.refresh_operands.count() <= 1);
            planned_refreshes += forecast.refresh_operands.count();
            expected = product(&expected, &expected);
            let next = scheduler.square(&current).unwrap();
            assert_eq!(
                next.scaled_error_bound(),
                forecast.output_scaled_error_bound
            );
            assert_eq!(client.decrypt_work(&next).unwrap(), expected);
            assert_ne!(next.lineage(), current.lineage());
            assert_ne!(next.root().identity(), current.root().identity());
            current = next;
        }
        assert!(
            planned_refreshes >= 2,
            "test must execute repeated encrypted refresh"
        );
        assert_eq!(scheduler.real_refreshes(), planned_refreshes);
        assert_eq!(scheduler.refresh_attempts(), planned_refreshes);
        assert_eq!(original.lineage(), &original_lineage);
        assert_eq!(
            client.decrypt_work(&original).unwrap(),
            vec![0, 1, P - 1, P / 2, 7, 0, 31, 17]
        );
        eprintln!("scheduler seed {seed}: 12 encrypted squares, {planned_refreshes} real refreshes, 96 coefficient comparisons");
    }
}

#[test]
fn scheduler_binary_refresh_forecast_counts_actual_work() {
    let (client, mut scheduler, mut rng) = setup(0x5343_4845_4404, 8);
    let fresh = scheduler.encrypt_with_rng(&[3; 8], &mut rng).unwrap();
    let input = boundary(&mut scheduler, fresh);
    let expected = client.decrypt_work(&input).unwrap();
    let forecast = scheduler.forecast_multiply(&input, &input).unwrap();
    assert_ne!(forecast.refresh_operands, RefreshOperands::Neither);
    let before = scheduler.real_refreshes();
    let output = scheduler.multiply(&input, &input).unwrap();
    assert_eq!(
        scheduler.real_refreshes() - before,
        forecast.refresh_operands.count()
    );
    assert_eq!(
        client.decrypt_work(&output).unwrap(),
        product(&expected, &expected)
    );
    assert_eq!(client.decrypt_work(&input).unwrap(), expected);
}

#[test]
fn scheduler_rejects_foreign_family_before_any_refresh() {
    let (_, mut scheduler, mut rng) = setup(0x5343_4845_4405, 8);
    let source = PublicRefreshSourcePlan::new(&config(8, &WORK, P), 8, 2, 4, 3).unwrap();
    let (_, other) = source.generate_with_rng(&mut rng, 16 << 20).unwrap();
    let own = scheduler.encrypt_with_rng(&[7; 8], &mut rng).unwrap();
    let foreign = other.encrypt_with_rng(&[7; 8], &mut rng).unwrap();
    assert!(matches!(
        scheduler.forecast_add(&own, &foreign),
        Err(SchedulerError::Source(SourceError::DomainMismatch))
    ));
    assert!(matches!(
        scheduler.multiply(&foreign, &own),
        Err(SchedulerError::Source(SourceError::DomainMismatch))
    ));
    assert!(matches!(
        scheduler.square(&foreign),
        Err(SchedulerError::Source(SourceError::DomainMismatch))
    ));
    assert_eq!(scheduler.refresh_attempts(), 0);
    assert_eq!(scheduler.real_refreshes(), 0);
}

#[test]
fn scheduler_budget_refuses_before_work_and_rechecks_stale_forecasts() {
    let (client, mut scheduler, mut rng) = setup(0x5343_4845_4406, 1);
    let fresh = scheduler.encrypt_with_rng(&[2; 8], &mut rng).unwrap();
    let input = boundary(&mut scheduler, fresh);
    let expected = client.decrypt_work(&input).unwrap();
    let snapshot = scheduler.forecast_square(&input).unwrap();
    assert_eq!(snapshot.refresh_operands.count(), 1);
    scheduler.square(&input).unwrap();
    assert_eq!(scheduler.remaining_refresh_attempts(), 0);
    // The old snapshot cannot authorize execution against the spent budget.
    assert!(matches!(
        scheduler.square(&input),
        Err(SchedulerError::RefreshBudgetExceeded {
            required: 1,
            remaining: 0
        })
    ));
    assert_eq!(scheduler.refresh_attempts(), 1);
    assert_eq!(scheduler.real_refreshes(), 1);
    assert_eq!(client.decrypt_work(&input).unwrap(), expected);
}

#[test]
fn scheduler_backend_failure_is_typed_and_never_falls_back() {
    let (client, mut scheduler, mut rng) = setup(0x5343_4845_4407, 2);
    let fresh = scheduler.encrypt_with_rng(&[5; 8], &mut rng).unwrap();
    let input = boundary(&mut scheduler, fresh);
    let expected = client.decrypt_work(&input).unwrap();
    // Fault injection available only in this private unit-test module: leave
    // the forecast certificate intact but force the backend's radius refusal.
    scheduler.circuit.plan.radius = 0;
    assert!(matches!(
        scheduler.square(&input),
        Err(SchedulerError::RefreshFailed {
            operand: RefreshOperands::Left,
            ..
        })
    ));
    assert_eq!(scheduler.refresh_attempts(), 1);
    assert_eq!(scheduler.real_refreshes(), 0);
    assert_eq!(client.decrypt_work(&input).unwrap(), expected);
}

#[test]
fn scheduler_cannot_recover_a_history_already_outside_source_support() {
    let (client, mut scheduler, mut rng) = setup(0x5343_4845_4408, 8);
    let mut input = scheduler.encrypt_with_rng(&[0; 8], &mut rng).unwrap();
    // Bypass scheduling with raw public arithmetic, which admits decode but
    // need not preserve this particular refresh circuit's bounded support.
    while let Ok(next) = scheduler.circuit.source.add(&input, &input) {
        input = next;
    }
    assert_eq!(client.decrypt_work(&input).unwrap(), vec![0; 8]);
    assert!(matches!(
        scheduler.square(&input),
        Err(SchedulerError::OperationUnfunded {
            operation: ScheduledOperation::Square
        })
    ));
    assert_eq!(scheduler.refresh_attempts(), 0);
    assert_eq!(scheduler.real_refreshes(), 0);
}

#[test]
fn numeric_forecasts_reject_wide_unadmitted_bounds() {
    let source = PublicRefreshSourcePlan::new(&config(8, &WORK, P), 8, 2, 4, 3).unwrap();
    let huge = U512 {
        d0: u128::MAX,
        d1: u128::MAX,
        d2: u128::MAX,
        d3: u128::MAX,
    };
    assert!(matches!(
        source.forecast_multiply_bounds(huge, huge),
        Err(SourceError::NoiseExhausted)
    ));
    assert!(matches!(
        source.forecast_add_bounds(huge, huge),
        Err(SourceError::NoiseExhausted)
    ));
    assert!(matches!(
        source.forecast_source_radius(huge),
        Err(SourceError::NoiseExhausted)
    ));
}

#[test]
fn scheduler_addition_refreshes_before_losing_source_support() {
    let (client, mut scheduler, mut rng) = setup(0x5343_4845_4409, 2);
    let mut expected = vec![1, P - 1, 0, 7, 11, 31, P / 2, 2];
    let mut input = scheduler.encrypt_with_rng(&expected, &mut rng).unwrap();
    for _ in 0..128 {
        let forecast = scheduler.forecast_add(&input, &input).unwrap();
        expected
            .iter_mut()
            .for_each(|value| *value = 2 * *value % P);
        let output = scheduler.add(&input, &input).unwrap();
        assert_eq!(client.decrypt_work(&output).unwrap(), expected);
        assert_eq!(
            output.scaled_error_bound(),
            forecast.output_scaled_error_bound
        );
        if forecast.refresh_operands != RefreshOperands::Neither {
            assert_eq!(
                scheduler.real_refreshes(),
                forecast.refresh_operands.count()
            );
            assert!(scheduler.forecast_square(&output).is_ok());
            return;
        }
        input = output;
    }
    panic!("addition fixture must execute a real public refresh");
}

#[test]
fn scheduler_two_refresh_schedule_reserves_the_whole_budget() {
    let (client, mut scheduler, mut rng) = setup(0x5343_4845_4410, 1);
    let fresh = scheduler.encrypt_with_rng(&[3; 8], &mut rng).unwrap();
    let input = boundary(&mut scheduler, fresh);
    let expected = client.decrypt_work(&input).unwrap();
    assert!(matches!(
        scheduler.multiply(&input, &input),
        Err(SchedulerError::RefreshBudgetExceeded {
            required: 2,
            remaining: 1
        })
    ));
    assert_eq!(scheduler.refresh_attempts(), 0);
    assert_eq!(scheduler.real_refreshes(), 0);
    assert_eq!(client.decrypt_work(&input).unwrap(), expected);
}

#[test]
fn scheduler_second_refresh_failure_keeps_partial_work_accounted() {
    let (client, mut scheduler, mut rng) = setup(0x5343_4845_4411, 2);
    let fresh = scheduler.encrypt_with_rng(&[3; 8], &mut rng).unwrap();
    let input = boundary(&mut scheduler, fresh);
    let expected = client.decrypt_work(&input).unwrap();
    assert_eq!(
        scheduler
            .forecast_multiply(&input, &input)
            .unwrap()
            .refresh_operands,
        RefreshOperands::Both
    );
    // Private fault injection: the first real refresh completes; the second
    // reaches the backend's checked counter overflow and returns failure.
    scheduler.circuit.refreshes = u64::MAX - 1;
    assert!(matches!(
        scheduler.multiply(&input, &input),
        Err(SchedulerError::RefreshFailed {
            operand: RefreshOperands::Right,
            ..
        })
    ));
    assert_eq!(scheduler.real_refreshes(), u64::MAX);
    assert_eq!(scheduler.refresh_attempts(), 2);
    assert_eq!(scheduler.remaining_refresh_attempts(), 0);
    assert_eq!(client.decrypt_work(&input).unwrap(), expected);
}
