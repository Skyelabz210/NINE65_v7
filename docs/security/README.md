# PublicRefreshCircuit security pack

Current routing: [public refresh status](../PUBLIC_REFRESH_STATUS.md).

This directory is the claim surface for `PublicRefreshCircuit` on the research backend. It records the security model, the related-key route that actually applies, the noise certificate's scope, and the items that are explicitly not established. It does not contain a confidentiality proof, an external parameter attestation, a probabilistic decryption-failure bound, or a constant-time measurement.

PublicRefreshCircuit is executable under allow_insecure. Correctness was observed on an identified older arithmetic snapshot: five refresh cycles and five following squares, 81,920 coefficient comparisons, not a latest-head rerun. A deterministic noise certificate is published (documented 562-bit return bound against a 633-bit threshold); a probabilistic decryption-failure bound is not derived. Confidentiality of the related-key setup is not established. External parameter attestation is not obtained. Constant-time posture is not established. The circuit is not admitted for production use. Legacy Clockwork bootstrap remains disabled (issues #95 and #117).

| Artifact | What it is allowed to say |
| --- | --- |
| [Security model](SECURITY_MODEL_PUBLIC_REFRESH.md) | Adversary view, key relations, native-versus-legacy K, exclusions |
| [Related-key analysis](RELATED_KEY_ANALYSIS.md) | Route D. Routes A–C are not completed |
| [Noise bound](NOISE_BOUND_PUBLIC_REFRESH.md) | Deterministic certificate only |
| [External attestation](EXTERNAL_PARAMETER_ATTESTATION.md) | Not obtained |
| [Constant time](CT_PUBLIC_REFRESH.md) | Not established |
| [Correctness evidence](CORRECTNESS_EVIDENCE_PUBLIC_REFRESH.md) | Observed snapshot versus bounded certificate versus security |
| [Machine-readable status](../status/CURRENT.json) | Same statuses, checked by CI |

The conditional public-evaluation lemma remains [where it was written](../execution/2026-10-31/PUBLIC_REFRESH_SECURITY_REDUCTION.md). This pack does not strengthen it.
