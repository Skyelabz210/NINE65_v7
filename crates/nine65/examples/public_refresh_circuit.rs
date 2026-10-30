//! Run with `cargo run --release -p nine65 --features allow_insecure
//! --example public_refresh_circuit`. This native research run needs several
//! GiB of memory and performs expensive encrypted arithmetic.

#[cfg(feature = "allow_insecure")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use nine65::ops::public_refresh_circuit::PublicRefreshCircuitPlan;
    let plan = PublicRefreshCircuitPlan::native_research(4usize << 30)?;
    println!("Research backend; production security admission remains closed.");
    println!("Preflight: {:?}", plan.certificate());
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
