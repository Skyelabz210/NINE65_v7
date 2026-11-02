//! Key-free exact inputs for independent review; never an attestation.
use nine65::ops::public_refresh_circuit::PublicRefreshCircuitPlan;
use nine65::params::SecureConfig;
use serde_json::json;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let plan = PublicRefreshCircuitPlan::native_research(4usize << 30)?;
    let graph = &plan.certificate().key_graph;
    let domains: Vec<_> = graph
        .domains()
        .iter()
        .map(|d| {
            json!({
                "domain":format!("{:?}",d.domain), "n":d.ring_degree,
                "ordered_primes_decimal":d.primes.iter().map(u64::to_string).collect::<Vec<_>>(),
        "plaintext_moduli_decimal":d.plaintext_moduli.iter().map(u64::to_string).collect::<Vec<_>>(),
                "cbd_eta":d.cbd_eta,"secret_sampler":d.secret_distribution,
                "source_weight":d.source_weight,
            })
        })
        .collect();
    let relations: Vec<_> = graph
        .relations()
        .iter()
        .map(|r| {
            json!({
                "purpose":r.purpose,"message_secret":r.message_secret.map(|s|format!("{s:?}")),
                "encryption_secret":format!("{:?}",r.encryption_secret),
                "published_ciphertexts":r.ciphertexts,
            })
        })
        .collect();
    let named: Vec<_> = [
        SecureConfig::secure_128(),
        SecureConfig::secure_128_deep(),
        SecureConfig::secure_192(),
        SecureConfig::secure_256(),
    ]
    .into_iter()
    .map(|p| {
        let c = p.into_config();
        json!({"name":c.name,"n":c.n,"ordered_primes_decimal":c.primes.iter().map(u64::to_string).collect::<Vec<_>>(),
               "t":c.t,"eta":c.eta,"nominal_security_bits":c.security_bits})
    })
    .collect();
    let fingerprint: String = graph
        .fingerprint()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "schema":"nine65-independent-review-inputs-v1",
            "status":"unsigned_review_inputs_not_attestation",
            "production_admitted":false,
            "key_publication_fingerprint":fingerprint,
            "native_domains":domains,"native_relations":relations,"named_profiles":named,
            "requires_joint_key_review":graph.requires_circular_security(),
            "return_effective_secret_degree":graph.return_effective_secret_degree(),
            "review_requirements":["exact factorized ring tuples and secret/error distributions",
                "full classical and quantum attack-model coverage",
                "joint and key-dependent setup confidentiality",
                "sampler bias and correctness of modeling assumptions",
                "independent reviewer identity, pinned tools, raw outputs and signed conclusion"],
            "excluded_claims":["joint confidentiality established","external attestation obtained",
                "probabilistic failure bound derived","constant-time established"]
        }))?
    );
    Ok(())
}
