//! Public-metadata probe for the canonical-lift feasibility oracle.
//!
//! Run with `cargo run -p nine65 --features serde --example canonical_lift_feasibility`.
//! No randomness, keys, ciphertexts, or secret-dependent auxiliary lanes are created.

use nine65::arithmetic::rns::U512;
use nine65::keys::bootstrap::{screen_bootstrap_security, BOOTSTRAP_PRIMES, BUILD_COMMIT_SHA};
use nine65::ops::expanded_bootstrap::ExpandedPhaseEvaluator;
use nine65::ops::prime_power_phase::{CanonicalLowDigitLiftEvaluator, PrimePowerPhaseEvaluator};
use nine65::ops::rns_fhe::exact_mul::ExactMulPlan;
use nine65::ops::rns_fhe::RNSFHEContext;
use nine65::params::{FHEConfig, SecureConfig};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

fn hex(value: U512) -> String {
    format!(
        "{:032x}{:032x}{:032x}{:032x}",
        value.d3, value.d2, value.d1, value.d0
    )
}

fn inspect(label: &str, work: &FHEConfig) -> Value {
    let expanded = work
        .t
        .checked_mul(work.t)
        .expect("probe plaintext fits u64");
    let mut record = json!({
        "name": label,
        "n": work.n,
        "base": work.t,
        "eta": work.eta,
        "claimed_security": work.security_bits.max(128),
        "primes": work.primes,
    });
    record["security_screen"] =
        match screen_bootstrap_security(&work.primes, work.n, work.security_bits.max(128) as u32) {
            Ok(screen) => json!({
                "q_bits": screen.log_q_boot,
                "core_svp_bits": screen.core_svp_bits,
                "matzov_bits": screen.matzov_bits,
                "binding_bits": screen.binding_bits,
                "meets_claim_under_both": screen.meets_claim_under_both,
            }),
            Err(error) => json!({"refusal": format!("{error:?}")}),
        };
    record["exact_multiply"] = match ExactMulPlan::new(&work.primes, work.n, expanded) {
        Ok(plan) => {
            let cert = plan.certificate();
            json!({
                "q_bits": cert.q_bits,
                "base_bits": cert.base_bits,
                "digits_per_lane": cert.digits_per_lane,
                "aux_lanes": cert.aux_lanes,
                "aux_bits": cert.aux_bits,
                "required_aux_bits": cert.required_bits,
            })
        }
        Err(error) => json!({"refusal": format!("{error:?}")}),
    };
    let mut high_config = work.clone();
    high_config.t = expanded;
    record["production_lift"] = match RNSFHEContext::try_new(&high_config) {
        Err(error) => json!({"stage": "context", "refusal": format!("{error:?}")}),
        Ok(context) => match ExpandedPhaseEvaluator::new(&context, work.t, 2) {
            Err(error) => json!({"stage": "expanded_phase", "refusal": format!("{error:?}")}),
            Ok(high) => {
                record["phase_error_bound_hex"] = json!(hex(high.certificate().phase_error_bound));
                record["half_delta_hex"] = json!(hex(high.certificate().half_delta));
                match PrimePowerPhaseEvaluator::new(&high, work) {
                    Err(error) => json!({"stage": "paired_phase", "refusal": format!("{error:?}")}),
                    Ok(paired) => match CanonicalLowDigitLiftEvaluator::new(&paired) {
                        Err(error) => {
                            json!({"stage": "canonical_lift", "refusal": format!("{error:?}")})
                        }
                        Ok(lift) => json!({
                            "stage": "canonical_lift",
                            "admitted": true,
                            "lifted_error_bound_hex": hex(lift.certificate().lifted_error_bound),
                        }),
                    },
                }
            }
        },
    };
    record
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut records = Vec::new();
    for config in [
        SecureConfig::secure_128(),
        SecureConfig::secure_128_deep(),
        SecureConfig::secure_192(),
        SecureConfig::secure_256(),
    ] {
        let work = config.into_config();
        records.push(inspect(work.name, &work));
    }
    for n in [8192, 16384] {
        for lanes in 4..=BOOTSTRAP_PRIMES.len() {
            let mut work = SecureConfig::secure_128().into_config();
            work.n = n;
            work.primes = BOOTSTRAP_PRIMES[..lanes].to_vec();
            records.push(inspect(&format!("candidate_n{n}_lanes{lanes}"), &work));
        }
    }
    // Hash the actual source bytes, including this uncommitted probe. The
    // base commit alone does not identify a working-tree experiment.
    let sources = [
        (
            "Cargo.lock",
            include_bytes!("../../../Cargo.lock").as_slice(),
        ),
        (
            "crates/nine65/Cargo.toml",
            include_bytes!("../Cargo.toml").as_slice(),
        ),
        (
            "crates/nine65/src/ops/prime_power_digit_lift.rs",
            include_bytes!("../src/ops/prime_power_digit_lift.rs").as_slice(),
        ),
        (
            "crates/nine65/src/ops/expanded_bootstrap.rs",
            include_bytes!("../src/ops/expanded_bootstrap.rs").as_slice(),
        ),
        (
            "crates/nine65/src/ops/prime_power_phase.rs",
            include_bytes!("../src/ops/prime_power_phase.rs").as_slice(),
        ),
        (
            "crates/nine65/src/ops/exact_mul.rs",
            include_bytes!("../src/ops/exact_mul.rs").as_slice(),
        ),
        (
            "crates/nine65/src/keys/bootstrap.rs",
            include_bytes!("../src/keys/bootstrap.rs").as_slice(),
        ),
        (
            "crates/nine65/src/params/secure_configs.rs",
            include_bytes!("../src/params/secure_configs.rs").as_slice(),
        ),
        (
            "crates/nine65/examples/canonical_lift_feasibility.rs",
            include_bytes!("canonical_lift_feasibility.rs").as_slice(),
        ),
    ];
    let hashes: serde_json::Map<String, Value> = sources
        .into_iter()
        .map(|(path, bytes)| {
            (
                path.to_string(),
                json!(format!("{:x}", Sha256::digest(bytes))),
            )
        })
        .collect();
    let report = json!({
        "schema": "nine65-canonical-lift-probe-v1",
        "base_commit": BUILD_COMMIT_SHA,
        "source_sha256": hashes,
        "scope": "Public parameter metadata and production constructor refusals; no key generation or refresh admission.",
        "records": records,
    });
    serde_json::to_writer_pretty(std::io::stdout(), &report)?;
    println!();
    Ok(())
}
