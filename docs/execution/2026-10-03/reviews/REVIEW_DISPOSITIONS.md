# Coordinator review of Aider, Gemini and Mistral findings

These assistants received bounded source excerpts and returned read-only
reviews. The coordinator checked the recommendations against additional
source. Their raw recommendations are **not task instructions**. Follow
[the accepted planning contracts](../tasks.json), whose implementation still
requires the recorded acceptance evidence.

Only final answers are retained here. No provider reasoning trace, credentials
or unrelated chat history is part of this package. Source revisions and hashes
are recorded in [evidence.json](../evidence.json). This is source-level review,
not a new Rust, historical Lean or physical-security certification.

## Aider: evidence producers and tracked ciphertext state

| Finding / proposal | Disposition and source check | Task |
|---|---|---|
| Historical WR-1 oracle uses the one-product N/4 bound and omits summed d1 | Confirmed coverage gap: `scripts/verify_wr1_transient_exact.py:180` uses `ring_n // 4`; production `exact_mul.rs` documents the N/2 requirement for d1. Preserve valid single-product tests and add the two-product case. This is not evidence that current production still uses N/4. | F01, C06 |
| Depth matrix labels nonzero depth/no collapses as correctness | Confirmed at `scripts/generate_depth_correctness_matrix.py:99`. Require actual client-side oracle comparisons tied to the run and all coefficients. | F01, V04 |
| Tuple names and benchmark configuration are not bound to runtime parameters | Confirmed: the Python oracle calls MAIN_3 `secure_128`, while the current runtime alias uses four primes; the matrix parser does not validate its `config` argument against measured output. | F01 |
| Public `TrackedCiphertext.ct` can drift from its private ledger | Confirmed at `auto_bootstrap.rs:67`. Encapsulation and atomic operation transitions are required on the new certified route. | C02, B08 |
| `fresh(ct, config)` creates fresh-looking state without proving freshness | Confirmed. **Strengthen** the proposed fix: shape/context validation alone cannot establish actual input noise or key provenance. Constructors must correspond to a sound admitted operation or an explicitly trusted input policy. | C01, C02, C03 |
| AUX capacity evidence is not tied to the runtime | Accept as a provenance/testing obligation, not a demonstrated production capacity defect. Test each exact tuple and both sides of its capacity boundary. | F01, C06, B01 |

The Aider review's statement that omitted lines prevent confirmation is resolved
by the source checks above. Its suggested negative tests are retained where they
exercise real behavior rather than a naming convention.

## Gemini: actual Shadow-source claims and proof statements

| Finding / proposal | Disposition and source check | Task |
|---|---|---|
| Quotient in Python vs remainder in `shadow_uniform_distribution` | Confirmed statement mismatch in external `nist/shadow_nist_tests.py:72` and `ShadowUniform.lean:99`. **Do not replace a valid remainder theorem merely to match its title.** Preserve it, identify any existing quotient theorem, and prove the exact missing correspondence and input distribution. | F03, H01 |
| `nist_compliance` and shadow independence include `True` conclusions | Confirmed in `ShadowNISTCompliance.lean:138` and `ShadowSecurityTheorems.lean:134`. These statements cannot establish the advertised statistical/independence claims. Inventory actual types and axioms before reuse. | F03, H01, V02 |
| `func_of_indep_is_indep` is axiomatized | Confirmed at `ShadowSecurityTheorems.lean:97`. A finite-distribution proof can discharge this particular mathematical fact. It would still assume independent inputs; it cannot establish independence of the live NTT source. | H01, V02 |
| Python input simulation differs from actual multiplication | Confirmed: `secrets.randbelow(m*(m+1))` samples uniform V rather than an NTT trace or `a*b`. Characterize the actual source conditioned on what the attacker knows. | H00, H01 |
| Require NIST failure when quotient is replaced by remainder | **Reject this acceptance test.** Both sequences may pass statistical tests. Use an exact transform/correspondence oracle with distinguishing input vectors instead. | H00, H01 |
| A Rust doc-test naming a Lean theorem proves linkage | **Insufficient.** A symbol reference does not prove equal semantics, distributions or attacker views. Require explicit assumptions and a checked correspondence. | H01, V02 |
| Sharing a seed necessarily makes two variables dependent | **Reject as a general rule.** Shared-source functions can be independent under a specified distribution. Use explicit correlated distributions, repeated identical nonconstant outputs and public-input fixtures; compute their joint law. | H01 |
| A uniform k-bit slicing lemma resolves this generator's entropy | **Insufficient.** The generator's quotient has m+1 possible values, not generally a power-of-two range. Derive the actual bit-output distribution and conditioning loss. Statistical tests need not detect every bias in a finite sample. | H01 |
| Prove all p-values >0.01 implies NIST compliance/security | **Reject this substitute for a source/security claim.** Correctly random finite samples can fail tests, and passing selected thresholds cannot certify unpredictability or all requirements of a test suite. | F03, H01 |

The source findings justify a bridge from the historical experiments to the
actual off-path Shadow computation. They do not justify discarding the owner's
architecture or asserting that useful hidden-source uncertainty is impossible.

## Mistral at maximum configured reasoning: prime-power contraction

The task-local `mistral-medium-3.5` configuration used `thinking = "max"`.
The installed Vibe backend maps this setting to provider `reasoning_effort =
"high"`, its highest exposed level. The completed invocation disabled tools,
limited turns/tokens and set a price cap. Earlier sandbox attempts produced no
review and were stopped/timed out; the completed retry supplied the answer.

| Finding / proposal | Disposition and source check | Task |
|---|---|---|
| Private `CanonicalLowDigitLift` has no producer; make its constructor public | **Reject.** `prime_power_digit_lift.rs:376` provides `CanonicalLowDigitLiftEvaluator::evaluate`, returning the private evidence type at line 424. Its admission deliberately refuses the present native tuple. An unrestricted constructor would bypass the proof obligation. | Preserve producer restriction; B05 adds the admitted bounded producer |
| Every existing lift must contain a rho-radius certificate | **Narrow the scope.** The existing producer evaluates a full-domain canonical polynomial and does not require a bounded-support hypothesis. The proposed cheaper bounded producer does require reviewed radius and history evidence. | R01, R02, B05 |
| `words()` is missing/undocumented magnitude arithmetic | Definition is at `prime_power_phase.rs:31`: `(v.d3, v.d2, v.d1, v.d0)`. Rust tuple ordering compares the most significant limb first. The review packet omitted this definition. | No defect established |
| Reject `words(x) >= 512` | **Reject.** `words(x)` is a four-limb tuple, not a bit count; this proposed test is ill-typed and would not express capacity. Wider arithmetic must use explicit range/capacity checks. | B00 |
| Input contraction certificate's `half_delta` is not checked | **Reject as a finding on this function.** `PrimePowerContractionCertificate` is an output, constructed after validation from the context-derived `half_delta`; it is not a caller-supplied input to `contract`. | No defect established |
| Sum tuple-valued `words()` before checking the addition | **Reject the proposed fix.** The function first checks each nonnegative bound against `half_delta` and then checks their sum. For the admitted context, `2*half_delta <= Q/base`, within the represented Q capacity. Preserve that argument and test its boundaries when extending widths. | C06, B00, B06 |
| Output certificate has no grid identifier | The wrapper has private fields and is returned by the context-bound producer after lineage/family/basis/base checks. Lack of a public field alone does not establish a bypass. Serialized/new certified APIs still need explicit domain binding and validated provenance. | C02, C03, B06 |
| Exact rho/history bridge remains unknown | Confirmed research obligation for the new bounded construction. It was already a hard prerequisite, not permission to infer B from a successful sample. | C01, C02, R01 |
| First multiplication and complete-lift certificates cite different limits | They bound different stages of the same baseline. Report both with their tuple/circuit; neither proves all possible bootstrap constructions impossible. | R00, R03 |

The main lesson for subsequent workers is operational: retrieve an omitted
definition before proposing a change, preserve restricted evidence producers,
and separate a new construction's obligations from an existing full-domain
kernel. More reasoning effort does not remove the need for source validation.
