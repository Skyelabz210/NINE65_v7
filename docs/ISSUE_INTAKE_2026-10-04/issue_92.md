# Issue #92: [META] NINE65 v7 completion-to-100% tracker: correctness, security, CI, performance, claims

- state: open
- labels: (none)
- created: 2026-08-31T07:13:56Z  updated: 2026-09-23T16:28:41Z
- url: https://github.com/Skyelabz210/NINE65_v7/issues/92

---

## Purpose

This is the authoritative completion gate for the current NINE65 v7 tree audited on 2026-08-31. “100%” here means **no known wrong-output path, no unverified production security claim, active mechanical CI, exact integer-only owned code, reproducible before/after performance evidence, and explicit disposition of every remaining open audit item**.

Do not close this issue because a headline test count is green. Close it only when every phase below is satisfied with artifacts tied to exact commit + tuple fingerprints.

---

## Phase 0 — restore trustworthy evidence infrastructure

- [ ] #79 Restore active GitHub Actions execution and required release checks
- [ ] #80 Remove bot-author bypass from mechanical CI gates
- [ ] #19 Build real automated performance regression testing
- [ ] #77 Archive raw benchmark artifacts per run
- [ ] #78 Categorize tests for tiered CI without hiding release gates
- [ ] #64 Make the full suite reproducible in constrained environments

**Gate:** current `main` HEAD has executed required checks; BASE/HEAD benchmark artifacts can be reproduced on a controlled runner.

---

## Phase 1 — zero known arithmetic/ciphertext correctness failures

- [ ] #81 Fix fixed-basis depth-2 ct×ct correctness (symmetric + public)
- [ ] #16 Bootstrap/auto-refresh stress and boundary isolation
- [ ] #29 Restore recumbent bootstrap and exact RNS metadata
- [ ] #32 Replace reconstruction in production K-Elimination rescale
- [ ] #65 Complete CRAM M2b/M3 EliminationFirst multiplication route
- [ ] #73 Increase public-mode depth only after current depth is exact
- [ ] #27 Fail closed on large products / invalid custom moduli

**Gate:** no accepted production test produces a wrong plaintext; original failing assertions are repaired rather than weakened; all range/capacity failures are typed; fixed-basis main/anchor identity holds through every operation.

---

## Phase 2 — bootstrap/key-material correctness and security

- [ ] #82 Full-Q_boot uniform RLWE mask sampling for circular bootstrap PK
- [ ] #83 Exact, non-tautological bootstrap security validation
- [ ] #29 addendum: exact floored Delta in BSK anchors; no zero-anchor/reconstruct-later refresh path; KSK dual-track identity
- [ ] #16 all circular/KSK/auto-refresh stress gates

**Gate:** circular, KSK-separated and auto-refresh paths preserve exact plaintext + DualRNS identity across all named configurations and deterministic seed matrices. No security-sensitive mask is sampled from narrow joint support.

---

## Phase 3 — parameter/security claim discipline

- [ ] #87 Adopt factorization-aware screening in production constructors
- [ ] #88 Remove unchecked security labeling from raw custom/depth configs
- [ ] #75 External lattice-estimator attestation for work **and bootstrap** tuples
- [ ] #76 Resolve `secure_256` name vs MATZOV binding result
- [ ] #71 External security audit
- [ ] #18 Complete internal constant-time/security audit work
- [ ] #72 Close constant-time findings F-2 / F-3

**Gate:** every production-facing security number is traceable to an exact tuple and explicit model/artifact; an unscreenable tuple is reported/refused rather than assigned a number; external estimator artifacts exist for every named work/bootstrap tuple.

---

## Phase 4 — diagnostics, failure semantics, input hardening

- [ ] #84 Fix negative-branch DualRNS noise-margin calculation
- [ ] #85 Make fallible constructors return typed errors rather than production panics
- [ ] #86 Context-complete validated deserialization
- [ ] #89 Enforce/ratchet production panic/unwrap/expect gate
- [ ] #69 Clear compiler warnings/dead code inventory

**Gate:** caller-controlled malformed input cannot terminate the release process; diagnostics agree with independent integer oracles; no known warning/panic backlog is silently advisory.

---

## Phase 5 — exact-integer and architecture conformance

- [ ] #90 Zero floating-point arithmetic across all owned Rust source, including benches/tests
- [ ] #68 Finish SBNI/Wassan retirement/dead dependency cleanup
- [ ] #70 Consolidate duplicate K-Elimination implementations or prove why both remain
- [ ] #74 Restore/clarify `allow_insecure` gating without breaking testability
- [ ] #67 Dispose of deprecated Coq proofs as historical (and resolve overlap with #20)
- [ ] #20 close/merge/supersede legacy Coq expansion task explicitly

**Gate:** source-level architecture scanners cover all production arithmetic modules and all owned Rust source obeys the integer-only contract.

---

## Phase 6 — API, bindings, docs, and claim correspondence

- [ ] #91 Sync README/claim registry/performance baselines to current four-prime `secure_128`
- [ ] #62 Sync stale library docs/parameter examples
- [ ] #66 Rewrite architecture documentation to the current tree
- [ ] #63 Stabilize one published binding
- [ ] #17 Python bindings work/disposition

**Gate:** current-facing documentation, bindings, examples and performance tables are generated/verified against exact current tuple fingerprints and contain no retired capability as current fact.

---

## Mandatory benchmark protocol for EVERY code-changing child issue

#19 owns the shared implementation. Each child issue must attach:

### BEFORE
1. BASE_SHA and exact tuple fingerprint(s).
2. Rust toolchain, target CPU/OS, feature set, acceleration state.
3. Correctness result for the affected operation/circuit.
4. Focused benchmark for the changed primitive.
5. Canonical operation matrix where relevant: encrypt/add/public-mul/symmetric-mul/decrypt/bootstrap.
6. Raw integer timing samples/artifacts.

### AFTER
Repeat **the identical commands on the same environment** and publish:
- exact correctness equality/oracle results,
- integer ns/us medians and dispersion,
- integer-scaled ratios (permille/basis-points/rational),
- allocation/memory deltas when relevant,
- explanation of every reproducible regression.

A faster wrong result is a failed build. A correct slowdown remains open until understood or explicitly accepted.

---

## Independent oracle requirements

For arithmetic fixes where a separate implementation is possible, use a Python arbitrary-precision **integer-only** oracle on reduced public vectors. It must not share the Rust implementation's helper functions or algorithmic state. Pin boundary vectors around:
- limb carries,
- exact powers of two,
- `floor(Q/t)`,
- quotient/winding limits,
- anchor uniqueness bounds,
- signed/centered boundaries,
- u128/U256 crossover points.

---

## Final release gate

This meta issue can close only when:

- [ ] all P0/P1 child issues above are closed with evidence;
- [ ] all remaining open legacy issues have a recorded disposition (completed, merged into another issue, superseded, or intentionally retained with rationale);
- [ ] current `main` CI executes and passes required checks;
- [ ] full workspace compiles under release/default and required feature matrices;
- [ ] no known accepted correctness test is ignored merely because it fails;
- [ ] ignored/slow/vestigial tests have an explicit inventory and reason;
- [ ] zero-float owned-source gate passes;
- [ ] production panic ratchet/hard gate passes;
- [ ] exact tuple security artifacts are archived;
- [ ] before/after performance artifacts exist for every arithmetic/security remediation;
- [ ] README/claim registry is synchronized to the same final SHA;
- [ ] final benchmark suite establishes the new speed baseline only after all correctness/security gates are green.

This tracker is the place to record the final SHA and evidence bundle when those conditions are met.