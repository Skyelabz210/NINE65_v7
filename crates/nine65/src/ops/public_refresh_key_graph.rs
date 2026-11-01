//! Exact publication inventory, not a security reduction or admission grant.

use super::*;
use sha2::{Digest, Sha256};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SecretDomain {
    Work,
    Source,
    Outer,
}

#[derive(Clone, Debug)]
pub struct KeyDomainParameters {
    pub domain: SecretDomain,
    pub ring_degree: usize,
    pub primes: Vec<u64>,
    pub plaintext_moduli: Vec<u64>,
    pub cbd_eta: usize,
    pub secret_distribution: &'static str,
    pub source_weight: Option<usize>,
}

/// Dependency points from the secret in the message to the encryption key.
/// The return key uses an embedded Work secret; its security dimension is
/// Work's degree, even though its ciphertexts inhabit the outer ring.
#[derive(Clone, Debug)]
pub struct KeyRelation {
    pub purpose: &'static str,
    pub message_secret: Option<SecretDomain>,
    pub encryption_secret: SecretDomain,
    pub ciphertexts: usize,
}

#[derive(Clone, Debug)]
pub struct KeyGraphCertificate {
    fingerprint: [u8; 32],
    relations: Vec<KeyRelation>,
    work_degree: usize,
    domains: Vec<KeyDomainParameters>,
}

impl KeyGraphCertificate {
    pub fn fingerprint(&self) -> &[u8; 32] {
        &self.fingerprint
    }
    pub fn relations(&self) -> &[KeyRelation] {
        &self.relations
    }
    pub fn domains(&self) -> &[KeyDomainParameters] {
        &self.domains
    }
    pub fn return_effective_secret_degree(&self) -> usize {
        self.work_degree
    }
    pub fn requires_circular_security(&self) -> bool {
        let mut reach = [[false; 3]; 3];
        for relation in &self.relations {
            if let Some(source) = relation.message_secret {
                reach[source as usize][relation.encryption_secret as usize] = true;
            }
        }
        for k in 0..3 {
            for i in 0..3 {
                for j in 0..3 {
                    reach[i][j] |= reach[i][k] && reach[k][j];
                }
            }
        }
        (0..3).any(|i| reach[i][i])
    }

    pub(super) fn new(source: &PublicRefreshSourcePlan, high: &FHEConfig, baby: usize) -> Self {
        use SecretDomain::*;
        let digits = |primes: &[u64], base: u32| -> usize {
            primes
                .iter()
                .map(|q| (64 - q.leading_zeros()).div_ceil(base) as usize)
                .sum()
        };
        let work = source.work_config();
        let sparse = source.source_config();
        let outer_digits = digits(&high.primes, 10);
        let counts = [
            1,
            digits(&work.primes, 10),
            digits(&sparse.primes, source.gadget_base_bits()),
            2 * baby,
            outer_digits,
            outer_digits * (3 + usize::from(baby < sparse.n)),
            digits(&work.primes, 3),
        ];
        let specifications = [
            ("work public key: zero", None, Work),
            ("work relinearization: gadget*W^2", Some(Work), Work),
            ("source switch: gadget*embedded W", Some(Work), Source),
            (
                "phase bank: shifted S, independent p^2/p encodings",
                Some(Source),
                Outer,
            ),
            ("outer relinearization: gadget*B^2", Some(Outer), Outer),
            (
                "phase/inverse automorphisms: gadget*sigma(B)",
                Some(Outer),
                Outer,
            ),
            ("return: gadget*B under embedded W", Some(Outer), Work),
        ];
        let relations: Vec<_> = specifications
            .into_iter()
            .zip(counts)
            .map(
                |((purpose, message_secret, encryption_secret), ciphertexts)| KeyRelation {
                    purpose,
                    message_secret,
                    encryption_secret,
                    ciphertexts,
                },
            )
            .collect();
        let mut hash = Sha256::new();
        hash.update(b"NINE65-public-refresh-key-graph-v1");
        for config in [work, sparse, high] {
            for value in [
                config.n as u64,
                config.t,
                config.eta as u64,
                config.primes.len() as u64,
            ] {
                hash.update(value.to_le_bytes());
            }
            for &prime in &config.primes {
                hash.update(prime.to_le_bytes());
            }
        }
        for value in [
            source.source_weight() as u64,
            source.gadget_base_bits() as u64,
            baby as u64,
        ] {
            hash.update(value.to_le_bytes());
        }
        for relation in &relations {
            hash.update((relation.purpose.len() as u64).to_le_bytes());
            hash.update(relation.purpose.as_bytes());
            hash.update((relation.ciphertexts as u64).to_le_bytes());
        }
        // Bind generator semantics as well as numeric parameters. A changed
        // sampler or key relation requires new evidence even at the same Q.
        for bytes in [
            include_bytes!("public_refresh_circuit.rs").as_slice(),
            include_bytes!("public_refresh_source.rs").as_slice(),
            include_bytes!("public_refresh_source_kernels.rs").as_slice(),
            include_bytes!("direct_slot_phase.rs").as_slice(),
            include_bytes!("public_refresh_slots.rs").as_slice(),
            include_bytes!("public_refresh_return.rs").as_slice(),
            include_bytes!("rns_fhe.rs").as_slice(),
            include_bytes!("exact_mul.rs").as_slice(),
            include_bytes!("rns_galois.rs").as_slice(),
            include_bytes!("../entropy/rng_trait.rs").as_slice(),
            include_bytes!("../entropy/secure.rs").as_slice(),
            include_bytes!("public_refresh_key_graph.rs").as_slice(),
        ] {
            hash.update(Sha256::digest(bytes));
        }
        Self {
            fingerprint: hash.finalize().into(),
            relations,
            work_degree: work.n,
            domains: [
                (
                    Work,
                    work,
                    vec![work.t],
                    "dense ternary via next_u64()%3",
                    None,
                ),
                (
                    Source,
                    sparse,
                    vec![sparse.t],
                    "balanced sparse ternary; hidden support",
                    Some(source.source_weight()),
                ),
                (
                    Outer,
                    high,
                    vec![sparse.t, high.t],
                    "dense ternary via FheRng::ternary_vector",
                    None,
                ),
            ]
            .into_iter()
            .map(
                |(domain, config, plaintext_moduli, secret_distribution, source_weight)| {
                    KeyDomainParameters {
                        domain,
                        ring_degree: config.n,
                        primes: config.primes.clone(),
                        plaintext_moduli,
                        cbd_eta: config.eta,
                        secret_distribution,
                        source_weight,
                    }
                },
            )
            .collect(),
        }
    }

    pub(super) fn verify_generated_counts(&self, counts: [usize; 7]) -> Nine65Result<()> {
        if self.relations.iter().map(|r| r.ciphertexts).ne(counts) {
            return Err(refused(
                "generated evaluation keys differ from the planned publication inventory",
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_inventory_is_exact_and_requires_joint_key_review() {
        let plan = PublicRefreshCircuitPlan::native_research(4 << 30).unwrap();
        let graph = &plan.certificate().key_graph;
        graph
            .verify_generated_counts([1, 12, 20, 256, 66, 264, 40])
            .unwrap();
        assert_eq!(
            graph
                .relations()
                .iter()
                .map(|r| r.ciphertexts)
                .sum::<usize>(),
            659
        );
        assert_eq!(graph.return_effective_secret_degree(), 8192);
        assert!(graph.requires_circular_security());
        assert!(graph
            .verify_generated_counts([1, 12, 20, 256, 66, 264, 39])
            .is_err());
        assert!(graph
            .verify_generated_counts([1, 12, 20, 256, 66, 198, 40])
            .is_err());
    }

    #[test]
    fn publication_fingerprint_binds_order_and_key_schedule() {
        let plan = PublicRefreshCircuitPlan::native_research(4 << 30).unwrap();
        let original = plan.certificate().key_graph.fingerprint();
        let same = KeyGraphCertificate::new(&plan.source, &plan.high, plan.baby);
        assert_eq!(original, same.fingerprint());
        let mut reordered = plan.high.clone();
        reordered.primes.swap(0, 1); // Identical Q, different ordered tuple.
        assert_ne!(
            original,
            KeyGraphCertificate::new(&plan.source, &reordered, plan.baby).fingerprint()
        );
        assert_ne!(
            original,
            KeyGraphCertificate::new(&plan.source, &plan.high, plan.baby * 2).fingerprint()
        );
    }

    #[test]
    fn breaking_return_cycle_still_leaves_self_key_dependencies() {
        let plan = PublicRefreshCircuitPlan::native_research(4 << 30).unwrap();
        let mut graph = plan.certificate().key_graph.clone();
        graph
            .relations
            .retain(|r| !r.purpose.starts_with("return:"));
        assert!(graph.requires_circular_security());
        graph
            .relations
            .retain(|r| r.message_secret != Some(r.encryption_secret));
        assert!(!graph.requires_circular_security());

        let mut graph = plan.certificate().key_graph.clone();
        graph
            .relations
            .retain(|r| r.message_secret != Some(r.encryption_secret));
        assert!(graph.requires_circular_security()); // W -> S -> B -> W.
    }
}
