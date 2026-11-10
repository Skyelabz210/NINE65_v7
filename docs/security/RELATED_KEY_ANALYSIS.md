# Related-key analysis for PublicRefreshCircuit

Current routing: [public refresh status](../PUBLIC_REFRESH_STATUS.md).

The question is whether confidentiality of the published key graph follows from standard RLWE. It does not, on present evidence. The honest endpoint is Route D.

## Route A — reduction to standard RLWE

Not completed.

[PUBLIC_REFRESH_SECURITY_REDUCTION.md](../execution/2026-10-31/PUBLIC_REFRESH_SECURITY_REDUCTION.md) proves a simulation lemma only: public refresh does not increase distinguishing advantage beyond the joint-setup IND-CPA experiment defined there. That experiment gives the adversary the real correlated setup. The lemma does not reduce the experiment to independent RLWE samples. No such reduction is claimed.

## Route B — the relation is benign because randomness is independent

Route B is not a confidentiality argument.

The outer secret is sampled with a fresh `FheRng::ternary_vector`, and the source secret is a separate sparse secret. That is a fact about key generation. It does not make the published relation benign. The native graph still contains:

* W² encrypted under W, and B² encrypted under B;
* sigma(B) encrypted under B;
* a function of S encrypted under B (the phase bank, in two plaintext trays);
* a function of B encrypted under the embedded work secret (the return key).

`requires_circular_security()` stays true if the return edge is deleted, and stays true if only the three-domain cycle remains. Independent sampling of B is bookkeeping. It is not a proof.

## Route C — estimator on the joint distribution

Not done.

What exists are separate screens: the in-tree factorization-aware screen on the dense work and outer domains, sparse-source attack estimates, and the pinned Hou–Jiang authors' implementation in [HOU_JIANG_ASSESSMENT.md](../execution/2026-10-31/HOU_JIANG_ASSESSMENT.md). The evidence summary's lowest reported modeled cost on that implementation is 161.33894 bits, and the outer in-tree screen binds at 129 bits. Those figures are not a joint-distribution estimate, not a lattice-estimator certificate, and not additive. The key-graph document already excludes the sparse source from the dense-secret screen.

The [November 10 external marginal outputs](../execution/2026-11-10/EXTERNAL_ESTIMATOR_EVIDENCE.md) add selected uSVP/dual cost models for exact scalar product-Q tuples. The [current graph audit](../execution/2026-11-10/PUBLIC_KEY_GRAPH_EVIDENCE.md) also makes the four return channels per ciphertext and their shared N8192 Work secret explicit. Neither models or proves confidentiality of the complete correlated setup; Route C remains not done.

## Route D — selected

Confidentiality of the related-key setup is not established.

The conditional lemma may be cited only with its premise attached: refresh preserves confidentiality if the joint setup is secure. The premise is an assumption, not a theorem and not an accepted production hypothesis. Route D is the endpoint until a cryptographer reduces the joint experiment or the construction drops the cyclic relations. It must not be described as a proof that is merely waiting on paperwork.
