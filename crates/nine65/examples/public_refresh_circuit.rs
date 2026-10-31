//! Run with `cargo run --release -p nine65 --features allow_insecure
//! --example public_refresh_circuit`. This native research run needs several
//! GiB of memory and performs expensive encrypted arithmetic. Pass `--describe`
//! to print the key-free plan and publication inventory without generating keys.

#[cfg(feature = "allow_insecure")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use nine65::ops::public_refresh_circuit::PublicRefreshCircuitPlan;
    let arguments: Vec<_> = std::env::args().skip(1).collect();
    let describe_only = match arguments.as_slice() {
        [] => false,
        [option] if option == "--describe" => true,
        _ => return Err("usage: public_refresh_circuit [--describe]".into()),
    };
    let plan = PublicRefreshCircuitPlan::native_research(4usize << 30)?;
    println!("Research backend; production security admission remains closed.");
    println!("Preflight: {:?}", plan.certificate());
    let graph = &plan.certificate().key_graph;
    let fingerprint: String = graph
        .fingerprint()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    println!("Key-publication fingerprint: {fingerprint}");
    println!("Key domains: {:?}", graph.domains());
    println!(
        "Requires circular/joint-key security review: {}",
        graph.requires_circular_security()
    );
    println!(
        "Return effective secret degree: {}",
        graph.return_effective_secret_degree()
    );
    if describe_only {
        use nine65::ops::public_refresh_circuit::key_graph::SecretDomain;
        use nine65::params::security_estimator::{LatticeSecurityEstimator, SecretDistribution};
        for domain in graph.domains() {
            if domain.domain == SecretDomain::Source {
                println!("Source security: external sparse-secret assessment required; dense screen inapplicable.");
                continue;
            }
            let factors: Vec<_> = domain.primes.iter().map(|&q| (q, 1)).collect();
            let screen = LatticeSecurityEstimator::default().dual_estimate_with_factorization(
                domain.ring_degree,
                &factors,
                SecretDistribution::Ternary,
                128,
            );
            println!(
                "{:?} deterministic engineering screen (not joint-key proof): {:?}",
                domain.domain, screen
            );
        }
        return Ok(());
    }
    let (client, mut evaluator) = plan.generate()?;
    let mut expected = vec![0u64; evaluator.certificate().work_degree];
    expected[0] = 7;
    let mut ciphertext = evaluator.encrypt(&expected)?;
    for cycle in 0..5 {
        ciphertext = evaluator.refresh_with_progress(&ciphertext, &mut |stage, done, total| {
            if done == total || done % 8 == 0 {
                println!("cycle {cycle}: {stage} {done}/{total}");
            }
        })?;
        assert_eq!(client.decrypt_work(&ciphertext)?, expected);
        ciphertext = evaluator.multiply(&ciphertext, &ciphertext)?;
        expected[0] = expected[0] * expected[0] % 65537;
        assert_eq!(client.decrypt_work(&ciphertext)?, expected);
    }
    println!(
        "real_refreshes={} and all coefficients verified after each dependent square",
        evaluator.real_refreshes()
    );
    Ok(())
}

#[cfg(not(feature = "allow_insecure"))]
fn main() {
    eprintln!("This research example requires --features allow_insecure.");
}
