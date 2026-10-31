//! Complete encrypted research circuit. Tests keep the original client key
//! outside every evaluator stage and compare every returned coefficient.

use super::public_refresh_source::PublicRefreshSourcePlan;
use crate::entropy::ShadowHarvester;
use crate::params::FHEConfig;
use std::time::Instant;

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
        name: "encrypted public refresh research circuit",
    }
}

// Independent schoolbook negacyclic arithmetic, with no evaluator NTT.
fn square(values: &[u64], p: u64) -> Vec<u64> {
    let n = values.len();
    let mut sums = vec![0i128; n];
    for (i, &a) in values.iter().enumerate() {
        for (j, &b) in values.iter().enumerate() {
            let product = a as i128 * b as i128;
            if i + j < n {
                sums[i + j] += product;
            } else {
                sums[i + j - n] -= product;
            }
        }
    }
    sums.into_iter()
        .map(|v| v.rem_euclid(p as i128) as u64)
        .collect()
}

fn run_public_api(work_n: usize, weight: usize, baby: usize, radius: usize, cycles: usize) {
    use super::public_refresh_circuit::PublicRefreshCircuitPlan;
    let start = Instant::now();
    let work = config(work_n, &WORK, 65537);
    let source = PublicRefreshSourcePlan::new(&work, work_n, 2, weight, 3).unwrap();
    let plan = PublicRefreshCircuitPlan::new(
        source,
        config(4 * work_n, &BOOT, 65537 * 65537),
        baby,
        radius,
        4usize << 30,
    )
    .unwrap();
    eprintln!(
        "public-refresh N={work_n} certificate={:?}",
        plan.certificate()
    );
    let mut rng = ShadowHarvester::with_seed(0x4352_414d_0000 + work_n as u64);
    eprintln!("public-refresh N={work_n} key generation started");
    let (client, mut evaluator) = plan.generate_with_rng(&mut rng).unwrap();
    eprintln!(
        "public-refresh N={work_n} key generation complete elapsed={:?}",
        start.elapsed()
    );
    let mut expected: Vec<_> = (0..work_n)
        .map(|i| match i % 7 {
            0 => 0,
            1 => 1,
            2 => 65536,
            3 => 32768,
            _ => (i as u64 * 7927 + 17) % 65537,
        })
        .collect();
    let mut input = evaluator.encrypt_with_rng(&expected, &mut rng).unwrap();
    input = evaluator.multiply(&input, &input).unwrap();
    expected = square(&expected, 65537);
    for cycle in 0..cycles {
        let value_identity = *input.root().identity();
        let representation_lineage = *input.lineage();
        input = evaluator.refresh_with_progress(&input, &mut |stage, done, total| {
            if done == total || done % 8 == 0 {
                eprintln!("public-refresh N={work_n} cycle={cycle} {stage} {done}/{total} elapsed={:?}", start.elapsed());
            }
        }).unwrap();
        assert_eq!(
            client.decrypt_work(&input).unwrap(),
            expected,
            "refresh cycle {cycle}"
        );
        assert_eq!(input.root().identity(), &value_identity);
        assert_ne!(input.lineage(), &representation_lineage);
        assert_eq!(input.root().logical_moduli(), &[2, 3, 5, 7, 11, 13, 17, 19]);
        assert_eq!(input.root().coefficient_upper_bound(), 65536);
        assert_eq!(
            input.scaled_error_bound(),
            evaluator.certificate().returned_scaled_error_bound
        );
        assert_eq!(evaluator.real_refreshes(), cycle as u64 + 1);
        input = evaluator.multiply(&input, &input).unwrap();
        assert_ne!(input.root().identity(), &value_identity);
        expected = square(&expected, 65537);
        assert_eq!(
            client.decrypt_work(&input).unwrap(),
            expected,
            "post-refresh square {cycle}"
        );
        eprintln!("public-refresh N={work_n} cycle={cycle} all coefficients and dependent square passed elapsed={:?}", start.elapsed());
    }
}

#[test]
fn complete_public_refresh_returns_original_key_for_three_cycles() {
    run_public_api(8, 4, 4, 3, 3);
}

#[test]
#[ignore = "native encrypted refresh, explicit resource and duration evidence run"]
fn native_public_refresh_returns_all_8192_coefficients_for_three_cycles() {
    run_public_api(8192, 96, 128, 49, 3);
}

#[test]
#[ignore = "native encrypted refresh, explicit resource and duration evidence run"]
fn native_public_refresh_returns_all_8192_coefficients_for_five_cycles() {
    run_public_api(8192, 96, 128, 49, 5);
}
