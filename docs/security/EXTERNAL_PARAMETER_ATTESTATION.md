# External parameter attestation for PublicRefreshCircuit

Current routing: [public refresh status](../PUBLIC_REFRESH_STATUS.md).

External parameter attestation is not obtained.

An unsigned, key-free [exact-input packet and review request](../execution/2026-11-01/INDEPENDENT_REVIEW_REQUEST.md)
is now reproducible from the native planner and named profile constructors.
It prepares independent review; it is not an attestation or acceptance of the
joint-key confidentiality premise.

## What would count

An attestation for this circuit would name an external lattice estimator and its version, the exact dual-RNS inputs including the joint key distribution (not only the work-key margins), the raw output, and the identity of a reviewer who did not produce the implementation. That complete attestation is absent. Local execution of an external estimator does not supply the independent reviewer or establish the joint-key premise.

## What exists instead

* The native research tuple sets `security_bits` to 0. That field is not a screen result.
* In-tree factorization-aware screens on the dense domains, and the sparse-source estimates, are engineering screens of separate distributions. [PUBLIC_REFRESH_KEY_GRAPH.md](../execution/2026-10-31/PUBLIC_REFRESH_KEY_GRAPH.md) says they are not joint-key proofs.
* [HOU_JIANG_ASSESSMENT.md](../execution/2026-10-31/HOU_JIANG_ASSESSMENT.md) runs a pinned authors' implementation. Modeled costs are not certificates. Corrected-theorem conformity and complete quantum-hybrid coverage remain unestablished.
* The [November 10 marginal estimator packet](../execution/2026-11-10/EXTERNAL_ESTIMATOR_EVIDENCE.md) archives 32 selected external uSVP/dual attack-model outputs for eight distinct named work, legacy bootstrap and native-domain tuples at source `7ada6503634a824e80bc4bcfd6231ad0178d7ed3`. It pins Sage and upstream source, exact inputs and implemented-distribution approximations. The models use scalar product-Q and idealized standalone LWE distributions; they do not assess factorized-ring structure, embedded return material or the joint publication graph. No independent reviewer or signed conclusion is supplied.
* Shipped named profiles are a different surface. README records `secure_256` at a 240-bit in-tree MATZOV screen against the name 256, which is 16 bits short, and states that no external lattice-estimator attestation exists for the shipped N = 8192 / 16384 tuples. Issue #75 tracks that gap. This note does not close it and does not reclassify `secure_256`.

Until an attestation of the kind above exists, the permitted phrase is "external parameter attestation is not obtained." Naming this circuit, or its joint key graph, as a 128-, 192-, or 256-bit profile is not permitted. "Screened" is not a permitted description of the joint setup.
