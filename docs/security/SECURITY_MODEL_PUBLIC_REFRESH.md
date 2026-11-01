# Security model for PublicRefreshCircuit

Current routing: [public refresh status](../PUBLIC_REFRESH_STATUS.md).

This model states what an adversary is allowed to see, how the three secrets are related, and what the model does not cover. It adopts the conditional public-evaluation lemma in [PUBLIC_REFRESH_SECURITY_REDUCTION.md](../execution/2026-10-31/PUBLIC_REFRESH_SECURITY_REDUCTION.md). It does not prove the joint-setup premise that lemma needs.

PublicRefreshCircuit is executable under allow_insecure. Correctness was observed on an identified older arithmetic snapshot: five refresh cycles and five following squares, 81,920 coefficient comparisons, not a latest-head rerun. A deterministic noise certificate is published (documented 562-bit return bound against a 633-bit threshold); a probabilistic decryption-failure bound is not derived. Confidentiality of the related-key setup is not established. External parameter attestation is not obtained. Constant-time posture is not established. The circuit is not admitted for production use. Legacy Clockwork bootstrap remains disabled (issues #95 and #117).

## Adversary view

The experiment is one key-holder setup, then public evaluation.

The adversary receives:

* the work public key;
* the published evaluation material enumerated by `KeyGraphCertificate` (659 RLWE samples on the native plan);
* public producer metadata: family id, lineage tags, and producer-issued error bounds;
* refresh and arithmetic transcripts for any finite history of permitted public operations the adversary requests;
* progress callbacks, which the implementation limits to stage names and operation counts.

The adversary does not receive the work secret, the sparse source secret, the outer secret, or the client decoder. A test harness that decrypts is not part of this view.

Multiple refresh outputs are inside the public-evaluation lemma: if the joint-setup IND-CPA premise holds, extra public refreshes do not increase distinguishing advantage. The premise is not established, so this sentence is not a confidentiality theorem.

## Key relations

`KeyGraphCertificate` records three secret domains. On the native research plan (`PublicRefreshCircuitPlan::native_research`):

| Domain | Ring | Secret label recorded by the certificate | Plaintext |
| --- | --- | --- | --- |
| Work `W` | N = 8192, four 30-bit primes, `security_bits = 0` | `dense ternary via next_u64()%3` | t = 65537 |
| Source `S` | N = 8192, first two work primes, weight 96, gadget base 3 | `balanced sparse ternary; hidden support` | t = 65537 |
| Outer `B` | N = 32768, thirteen primes, `security_bits = 0` | `dense ternary via FheRng::ternary_vector` | t and t² |

Those distribution strings are inventory labels. This document does not audit the sampler. The certificate fingerprint hashes the generator sources, including `entropy/secure.rs` and `entropy/rng_trait.rs`. A reduction has to start from those functions, not from the label.

Published relations, native counts:

| Role | Message secret → encryption secret | Samples |
| --- | --- | ---: |
| Work public key | zero → W | 1 |
| Work relinearization | W² → W | 12 |
| Source switch | embedded W → S | 20 |
| Phase bank, independent p² and p encodings of shifted S | S → B | 256 |
| Outer relinearization | B² → B | 66 |
| Phase and inverse automorphisms | sigma(B) → B | 264 |
| Return to the embedded work key | B → W | 40 |

`requires_circular_security()` is true. Removing the return edge leaves the self-key edges. Removing the self-key edges leaves the cycle W → S → B → W. The return key's effective secret degree is 8192, not 32768: its samples live in the outer ring but the receiver is the embedded work secret.

The outer secret is a fresh `ternary_vector` draw. Freshness does not erase the published functions of S under B, of B under W, or of each secret under itself.

## Source decomposition

Legacy `K_0` and native `K_native` are not the same producer.

* Legacy `K_0` / `K_j` is the displaced correction lost when Clockwork rounds ciphertext components independently. Issues #95 and #117 diagnose that path. `supports_public_refresh` staying false does not mean the research circuit is absent. It means the legacy Clockwork entry points stay refused.
* Native phase: `x = d0 + d1·s = rho + p·K_native`, with the certified support `|rho| ≤ 49` and `|K_native| ≤ 48` for source weight 96 and p = 65537. `rho` is the residual. It is not the quotient.
* `Y = K_native + 48` lies in `[0, 96]`. The fused restoration consumes the already-derived encrypted `K_native`. It does not emit independent encrypted remainders.

Using `K_0` and `K_native` as interchangeable names is a claim error.

## What is not covered

* A malicious evaluator, or ciphertexts that were not produced by the checked public API.
* Chosen-ciphertext refresh. There is no decryption oracle in the experiment.
* Multi-client aggregation and key sharing across clients.
* Adaptive key queries. Setup runs once.
* Physical side channels and remote-execution authentication.
* Joint/KDM confidentiality. See the related-key analysis. It is not established.
* External parameter attestation, including any reading of `secure_256`'s 240-bit in-tree MATZOV screen as a certificate. That screen is 16 bits short of the name 256 and is not an attestation.
* A probabilistic decryption-failure bound.
* Constant-time behavior of this circuit.
* Independent encrypted remainder outputs, and a latest-head repeat of the five-cycle native run.
