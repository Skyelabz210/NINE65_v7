# Written proof coverage and review

Reviewed against source `a7f8531` on 2026-11-04. These notes supply explicit
pen-and-paper arguments before further Lean development. They do not silently
upgrade a Rust implementation, a model assumption or a security premise to a
machine-checked theorem.

## Read in this order

1. [Arithmetic and encoding](REFRESH_ARITHMETIC.md): construction of the G/H
   certificates, coefficient divisibility, source carry and fused restoration.
2. [Pipeline composition](REFRESH_PIPELINE.md): slot return, ring projection,
   noise accounting, finite-width bounds, root authority and exact closure scope.
3. [Existing formal proof record](../execution/2026-11-01/PUBLIC_REFRESH_PROOFS.md):
   the five library modules already covering Taylor/digit identities, native
   lifts, the separate phase-clock return/budget model and its geometry.
4. [Security pack](../security/README.md): confidentiality, attestation and
   physical side-channel obligations that arithmetic does not prove.

## Coverage and remaining obligations

The [2026-11-12 CRAM path repair](../execution/2026-11-12/CRAM_PATH_REPAIR.md)
adds executed boundary-projection and lane-identity regressions. Its direct-CRT
identity and bounds are written there as an implementation review argument,
not a new Lean theorem. It does not discharge stored-K migration, phase-source
authenticity, encrypted integration or whole-program security obligations.

| Obligation | Existing coverage | Written supplement / limitation |
| --- | --- | --- |
| Signed Taylor and G/H quotient identity | `PublicRefreshDigit.lean` | A1 proves the finite certificates can be constructed and why H is even |
| Plaintext slot CRT and division by p | Runtime transforms and regression tests | A2 proves the ring-wide divisibility and exact change of encoding scale |
| Native source norm / quotient lift / adjacent query | `PublicRefreshNativeLift.lean` | A3 derives rho from the source scaled error; A4 explains the restoration composition |
| Slot-to-coefficient transform | `public_refresh_slots.rs`, small-ring regressions | P1 proves the intended linear map and a conservative error bound; correctness of every optimized index is still an implementation obligation |
| Dense-key return | Native runtime and tests; separate phase-clock algebra in `PublicRefreshReturn.lean` | P2 proves the native embedding/projection identity; P3 derives drop/switch bounds |
| Native error-budget composition | Executable certificate, identified native execution | P0 and P3–P4 derive the tensor/drop/switch envelopes and composition; low-level Rust correspondence remains scoped |
| Fixed-width arithmetic | Checked wide arithmetic and plan restrictions | P5 proves selected source-plan U512 intermediates fit; no blanket proof of every Rust operation |
| Root/history acceptance | Sealed types and regression tests | P6 gives the safe-API induction and its crate-trust assumption |
| Repeated refresh/square admission | Native next-radius certificate; separate phase-clock cycle theorem | P4 states the exact inductive premise and tested-versus-general distinction |
| Related-key confidentiality | Conditional public-evaluation simulation argument only | Still OPEN; arithmetic supplies no reduction from this joint setup to ordinary RLWE |
| Probabilistic decryption failure | Deterministic envelopes only | Still OPEN; a probability requires a specified experiment and justified sampler/kernel envelope assumptions |
| Constant-time posture | Source checks, scoped timing evidence | Still OPEN; an algebraic proof cannot establish compiler/cache/timing behavior |
| Whole-program Rust refinement | Tests plus source review | Still OPEN; the notes identify the correspondence obligations rather than assume they have been formally discharged |

A complete argument must expose its premises. These notes close specific
mathematical gaps, not the open cryptographic or whole-program obligations in
the table. Existing library results are reused instead of written again as new
achievements. General encrypted shared-factor division, independent protected
S8 remainder emission and the legacy Clockwork correction are not implemented
by these arguments.

## Double-check method

The first pass derives each result from its definitions. The second pass checks
signs, units, odd-modulus endpoints, negative lifts, every coefficient rather
than one slot, source-versus-boot secret norms, and counterexamples when a
premise is removed. Each note records these checks and exact source locations.
This is two passes by the same reviewer, not independent external review.

`python3 scripts/check_refresh_prose_witnesses.py` checks small exhaustive
instances and negative controls using integer/Fraction arithmetic, independently
of the Rust evaluator. `python3 -m unittest discover -s scripts -p
'test_public_refresh_lift_refinement.py' -v` also checks the native 9,603
quotient/residual combinations. Finite witnesses supplement the arguments;
they do not prove their universal quantifiers or execute encrypted refresh.
