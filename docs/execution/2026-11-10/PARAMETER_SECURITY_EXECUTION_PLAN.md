# Parameter and security-evidence execution plan

Prepared 2026-11-10 for source `7ada6503634a824e80bc4bcfd6231ad0178d7ed3`.
Current routing: [public-refresh status](../../PUBLIC_REFRESH_STATUS.md).

This track exports and checks exact public parameters, actual sampling laws,
the evaluation-key publication graph, and scoped external attack estimates.
It does not establish confidentiality of the related-key setup. External
parameter attestation is not obtained. Production admission stays closed.

## Source and scope reconciliation

The live remote `main` matched the checkout at the source SHA above. The saved
`origin/main` was stale at `bbfa754` and was refreshed before branch comparison.
The F01 parameter-evidence, R03 bootstrap-admission, and November 1 proof
branches are ancestors of the inspected source. Reuse their integrated work;
do not cherry-pick them again. The research-gates branch has one additional
commit, `71fdbaf`, affecting timing verification and its workflow/evidence.
That separate follow-up is outside this track and was not merged.

The authorized GitHub connector returned no open PRs at capture. PRs #201 and
#204 are merged. Issue #75 is open; #76 is closed with the typed admission
distinction already documented in source. A closed issue does not turn the
`secure_256` API label into independently attested security. Exact remote SHAs,
ancestry, PR metadata, issue state, and capture times are archived in
[`parameter-security-orchestration`](../../../artifacts/execution/2026-11-10/parameter-security-orchestration/).

At the final ref check, concurrent integration had advanced `main` to
`676c4ec68ec497ff5ef2bbc4697393ec9090a7bc`, adding the separate scheduler,
entropy-boundary and Lean repairs. Four bound files changed:
`entropy/rng_trait.rs`, `ops/public_refresh_circuit.rs`,
`ops/public_refresh_source.rs`, and `ops/public_refresh_source_plan.rs`.
The inspected diff adds guard/refusal handling, the scheduler module and
forecast helpers; it does not change the sampled coefficient formulas or
the parameter tuples. Fresh key-free parameter and graph exports were then
executed at `676c4ec`: their tuples, laws and seven publication relations
match the frozen packet exactly. The recomputed graph fingerprint is
`7b23a4c8f6fc168393e199a8e88232fafdc6049111a28a69ad8a7329389ee2c4`.
Commands, outputs, comparison and hashes are archived as `main676-*` in the
orchestration directory. Rust test execution and the external-cost packet
remain explicitly pinned to `7ada650`; the supplement is key-free. The
final-main comparison and initial failed freshness assertion are preserved.

The separate refresh scheduler, optimization integration, entropy guard repair,
and Lean trust-boundary repair retain their existing owners. No work package
below edits those implementations, enables legacy refresh, changes account
settings, merges to `main`, purchases resources, or sends review requests.

## Decomposed work packages

| ID | Owner / dispatch | Dependencies | Concrete output and acceptance | State |
| --- | --- | --- | --- | --- |
| P00 | Orchestrator, dispatched | None | Freeze source SHA; inspect live refs and relevant PRs; classify already integrated work versus unmerged work | Complete |
| P10 | Parameter/distribution agent, dispatched | P00 | Export the four named RNS work tuples with ordered primes, exact product, N, t, eta, aliases, and source hashes; compare with the existing source-derived registry | Complete; fresh Rust registry byte-identical |
| P11 | Parameter/distribution agent, dispatched | P10 | State exact dense `%3`, rejection ternary, balanced sparse, CBD and uniform-mask laws; distinguish idealized models; reject relevant source/packet drift | Complete; ten new controls and two existing Rust sampler tests pass |
| P12 | Parameter/distribution agent, dispatched | P10 | Inventory the distinct legacy Clockwork bootstrap tuple derived for each named profile, or report exact unexecuted scope; keep it separate from native Outer | Complete; Q widths 146/146/177/206 |
| P20 | Public-key-graph agent, dispatched | P00 | Run the current key-free exporter; validate seven publication relations, 659 polynomial samples, graph fingerprint and effective return dimension | Complete; source-bound audit and six exact Rust tests pass |
| P21 | Public-key-graph agent, dispatched | P20 | Compare inventory against actual generators; enumerate self-key and W→S→B→W cycle obligations; preserve Route D | Complete inventory; confidentiality obligation stays open |
| P30 | External-estimator agent, dispatched | P10, P11, P20 | Obtain pinned Sage/upstream estimator from official sources using free local resources; archive versions, source hashes and actual setup output | Complete; Sage 10.6, upstream f31b86fe |
| P31 | External-estimator agent, dispatched | P30 | Execute bounded independent tasks for exact named work and other explicitly selected marginal tuples; retain raw output, sample model, attack/cost model, approximations and timeout/failure state | Complete focused pass; 32/32 finite, no errors/timeouts |
| P32 | External-estimator agent, dispatched | P12, P30 | Classify legacy boot and embedded return scopes independently; do not substitute native Outer or ambient N for them | Complete classification; legacy tuples modeled, embedded return excluded from iid-key estimates |
| P33 | Attack-model agent, ready | P31 and reviewed model choices | Extend dense classical/quantum coverage to supported hybrid/dual-hybrid/BKW algorithms with explicit cost/shape/sample assumptions and incremental deadline-limited outputs; preserve baseline results | Open coverage task |
| P34 | Sparse-attack specialist, ready | P11, existing pinned Hou–Jiang packet | Validate corrected-theorem correspondence and quantum-hybrid completeness against the actual balanced 48/48 source; reuse the existing authors' run and lock | Open model-validation task |
| P35 | Ring/embedded-secret specialist, ready | P20, P21 | Supply reviewed transformations for factorized negacyclic rings and the 160 embedded-return channels under shared Work; identify which generic-LWE tools can represent them | Open modeling obligation |
| P40 | Orchestrator, dispatched | P10–P32 | Review new artifacts against actual commands and old evidence; run focused claim/status/parameter controls; produce integrity manifest and concrete handoff | Complete; focused controls and artifact/source consistency pass |
| P41 | Parameter/graph agents, redispatched after ref advance | P40 and integrated source 676c4ec | Generate fresh source-bound packets in a separate directory; recheck tuple/law equality, graph fingerprint and key-free controls; preserve frozen original packets | Complete at 676c4ec; all semantic inputs and relations unchanged |
| P42 | Integration owner, ready | Applied evidence patch and chosen integration commit | Rerun exact setup tests on the final integrated commit if new source-specific Rust execution is required; retain the source of existing tests and marginal outputs explicitly | Not claimed by the key-free freshness supplement |
| P50 | Cryptographic reviewer, ready after packet completion | P11, P21, P31–P35 | Assess the complete joint-setup experiment, structured/factorized rings, sample laws, sparse and embedded-secret attacks; supply an explicit reduction or reviewed assumption with exclusions | Open confidentiality obligation |
| P51 | Independent reviewer, ready after model review | P50 | Identity, pinned source/tools, exact inputs/raw outputs, signed scoped conclusion; distinguish ordinary marginal estimates from complete-setup acceptance | External attestation not obtained |
| P60 | Admission/API owner, ready after review | P50, P51 and independent correctness/CT/failure gates | Evaluate claim/admission changes only against evidence for the exact construction; no automatic promotion from model costs | Blocked on substantive evidence |

The specialized agents use `gpt-6.1-sol` with ultra reasoning as requested.
Each owns separate files and artifacts. The orchestrator owns branch audit,
cross-track review, this plan, and the final integrity/handoff packet.

The external pass covers eight distinct idealized generic-LWE instances and
eleven retained aliases, with two attacks (uSVP and plain dual) under MATZOV
classical and ADPS16 quantum-lattice reduction costs. It ran in 117.82 seconds
including the successful container creation. The native Outer selected
minima are 174.6898218 and 130.645 bits respectively; the legacy bootstrap
`secure_256` selected quantum-lattice minimum is 242.21 bits, below its nominal
label. These are modeled attack costs within the stated approximations, not
security lower bounds or complete attack coverage. They do not replace the
earlier, lower Hou–Jiang sparse-source cost or the distinct in-tree MATZOV 240
Work screen. See the [external report](EXTERNAL_ESTIMATOR_EVIDENCE.md) for
the full table and raw-output binding. The legacy refresh route stays disabled.

## Bounded execution and intervention points

1. Reuse the pinned Rust 1.89.0 installation under `/workspace/.tooling` and
   isolated Cargo targets. Run key-free planner/exporter checks before any
   key generation. No expensive native encrypted cycle is needed to establish
   this packet's parameter/graph facts.
2. Bootstrap Sage with an existing pinned official image where possible.
   A failed install must preserve its actual output and try the supported
   official route. Do not invent results or mark skipped tasks successful.
3. Launch estimator tasks with explicit deadlines and process isolation.
   Archive results as each task completes. A timeout is an unresolved model
   task; it does not block tuple export, graph review or independent work.
4. Estimator inputs must specify exact `q`, N, implemented secret/error laws,
   finite or unlimited sample policy, algorithm and reduction cost model.
   Keep per-prime and full-product cases identifiable. An ideal ternary model
   requires an explicit approximation for the `%3` sampler.
5. The return key needs an explicit effective-N/channel model. The ambient
   N32768 ring cannot justify assigning its embedded N8192 receiver that
   larger secret dimension. Its KDM relation remains in P50.
6. Stop only the dependent action if a model cannot represent a distribution,
   a required runtime fails, an operation is denied, or a confidentiality
   premise remains unsupported. Record exact target, failure/denial output,
   completed independent work, and the intervention needed. A deadline is
   neither user approval nor security evidence.
7. A reviewer identity and signed conclusion require an actual independent
   reviewer. This execution prepares the packet; it does not send it to
   anyone or invent reviewer agreement. Account/security changes, paid
   services or external communications require separate authorization.

## Focused verification

The existing controls have already run successfully on the inspected source:

```sh
bash scripts/check_claim_registry.sh
python3 scripts/check_public_refresh_status.py --self-test
python3 scripts/check_public_refresh_security_claims.py --self-test
python3 scripts/test_parameter_evidence.py
```

The last command executes 10 controls, including tuple/alias/product checks
and historical-parameter rejection. These are evidence-contract checks, not
encrypted refresh execution. Actual output, exit status and duration are in
`parameter-security-orchestration/focused-checks.json` and its adjacent logs.
The final agent reports and manifest will record new focused commands and
their actual completion separately.

## Practical handoff

Use the exact-distribution packet for model selection, the current key-free
graph packet for published relations, and external raw results only within
their stated models. Preserve the historical native five-cycle measurements,
Hou–Jiang source lock and existing noise bounds unchanged. No latest-head
encrypted rerun, probabilistic decryption-failure bound, constant-time
guarantee, ordinary-RLWE reduction of the joint graph, or independent
attestation follows from this track.
