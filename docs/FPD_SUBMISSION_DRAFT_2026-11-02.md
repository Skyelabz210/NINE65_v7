# External submission drafts — not submitted

The technical content is ready for review in
[the scoped implementation note](FPD_DIVISION_SCOPE_2026-11-02.md).
Author/speaker names, affiliations, public contact email and the ePrint
license have not been supplied for this submission. Do not infer coauthors
or author consent from repository commit identities.

## ePrint metadata draft

**Title:** Prepared-Key FPD in NINE65: BFV Rescaling, Shared-Factor Vectors,
and Benchmarks

**Keywords:** fully homomorphic encryption, BFV, residue arithmetic,
relinearization, reproducible benchmarks

**Abstract:** We document the implementation boundary and performance of
remainder-adjusted fused piggyback division (FPD) in NINE65's main-Q BFV
evaluator. Coherent auxiliary residues permit exact computation of the
declared BFV scale-and-round result despite the rescaling divisor sharing
factors with the main residue lanes. Reusing prepared hybrid
relinearization keys yields 2.10–2.53 times faster multiplication than the
raw-key route in two local release runs across three parameter profiles.
The archive includes source revisions, parameter tuples, integer timing
samples, setup costs and ciphertext-equality checks. We provide explicit
signed coefficient vectors for the BFV scaler and a separate bounded S8
exact-division witness kernel, and distinguish both from general encrypted
division. The public encrypted division API still rejects nonunit divisors.
We make no claim of a newly enabled general encrypted division adapter,
constant-time execution, independent validation or production security of
the related-key refresh setup.

**Manuscript content:** the linked implementation note, with an author/contact
block added before PDF export. The measured source is
`dde5ea20ecff8198d0eb3353ec038243b42b188f`; coefficient showcase execution is
`7cf18cd1cfb21073da4a0f7a4171892a698d97ee`.

The [ePrint submission form](https://eprint.iacr.org/submit) requires a PDF,
author information and a license selection. Its
[publication conditions](https://eprint.iacr.org/operations.html) require
author agreement and grant continuing distribution rights; acceptance does
not attest to the claims. This draft does not assert compliance on behalf of
unidentified authors.

## FHE.org demo proposal draft

**To:** contact@fhe.org

**Subject:** Demo proposal: reproducible BFV FPD rescaling and shared-factor
division boundaries in NINE65

Hello FHE.org organizers,

We would like to propose an implementation demo of NINE65's BFV rescaling
path, with reproducible benchmarks and an explicit account of its division
limits.

The demo would cover the main-Q evaluator's remainder-adjusted FPD kernel,
prepared-key relinearization, and two local release measurements showing a
2.10–2.53× multiplication speedup over raw keys. It would run signed
coefficient vectors through the shared-factor BFV scaler and a separate
bounded S8 witness divider, then show the public encrypted API refusing a
nonunit divisor. The distinction is deliberate: general encrypted
shared-factor division is not implemented by this branch.

Source, raw timing samples, parameters, host/build provenance and correctness
checks are public:

- https://github.com/Skyelabz210/NINE65_v7/tree/feat/enable-fpd-stack
- https://github.com/Skyelabz210/NINE65_v7/blob/feat/enable-fpd-stack/docs/FPD_DIVISION_SCOPE_2026-11-02.md

We would welcome independent scrutiny of auxiliary-residue coherence,
quotient bounds, supported divisor domains and the gap between the witness
kernel and a verified encrypted adapter. We do not claim external
attestation, a constant-time implementation, or that these results establish
refresh security.

Please let us know whether this would fit an implementation-focused online
meetup and what scheduling information you need.

The [FHE.org presentations page](https://fhe.org/submit) directs proposals
through the community or to this email address. Speaker identity and sender
details remain to be supplied before sending.
