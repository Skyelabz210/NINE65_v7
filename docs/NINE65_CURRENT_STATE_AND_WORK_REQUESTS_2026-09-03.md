# NINE65 v7 — Current State, Direction, and Next-Wave Work Requests

**Snapshot date:** 2026-09-03  
**Canonical source snapshot:** `main@2547cf0d8c3d618c0c3fe39bf122c902c763e8ff`  
**Purpose:** execution control plane for the next completion wave. This document is a work request, not a capability claim.

---

## 1. Executive state

The repository has changed materially since the July CRAM remediation. The current production direction is no longer “publish a persistent DualRNS main+coprime-anchor ciphertext and make every operation recumbent in that enlarged wire state.” The current security architecture is the **WIRE-Q** partition established by the CRAM × RLWE coexistence work:

- published secret-dependent objects carry only residues modulo divisors of the RLWE security modulus `Q`;
- CRAM exactness is fully admissible in plaintext space (D1), inside the secret-holder boundary (D2), and in evaluator-local **derived/transient** state (D3);
- no anchor, shadow-11 lane, syndrome, StarLift anchor, redundant lane, or other modulus coprime to `Q` may survive into a published secret-dependent object (D4).

That architectural correction changes how old issues #29 and #32 should be interpreted. Their exactness, checked-capacity, no-Garner/MRC, and no-reconstruction requirements remain valuable, but any language requiring a persistent coprime anchor on ciphertext/key wire objects is superseded by WIRE-Q.

### 1.1 What is now landed on `main`

1. **Track 1 T1.1 — failure lock and target semantics**
   - the old limb-local rescale failure is pinned;
   - the wrong direct-multiply regime is demonstrated;
   - WIRE-Q failure of serialized dual ciphertexts is pinned;
   - an exact BFV oracle target is defined.

2. **Track 1 T1.2 — `MainOnlyBaseExt`**
   - auxiliary residues are derived from main mod-Q residues only;
   - no redundant input residue is required;
   - the canonical-rank correction is exact;
   - production-prefix oracle tests exist.

3. **Track 1 T1.3 — `ExactScaleRound`**
   - an exact coefficient-level BFV scale-and-round kernel exists;
   - it uses derived transient auxiliary bases;
   - it refuses insufficient auxiliary capacity;
   - it is not yet wired into the evaluator.

4. **WIRE-Q fail-closed safety patch (PR #107)**
   - dual-RNS service import/export is refused;
   - the known uncertified direct single-RNS multiply route fails closed where the selected route requires K-Elimination/derived-transient handling.

5. **Safe-Basis lifted transduction work (PR #99)**
   - exact theorem/regression coverage for S6/S8 product-space and lifted transduction is landed;
   - `lifted_transduction.rs` remains staged behind the integration-test shim and is not yet exported as a production crate API;
   - the first-wrap rule `X = g + K M_A` is encoded without requiring a scalar carried `K`.

6. **Public bootstrap fail-closed guard**
   - `ClockworkBootstrap::bootstrap` and `bootstrap_with_ksk` still call `public_phase1_soundness_gate()`;
   - public BFV refresh therefore returns a typed `BootstrapFailed` instead of emitting a wrong-but-plausible ciphertext;
   - issue #95 was reopened on 2026-09-03 because its actual replacement acceptance criteria are not met.

7. **Track 2 CompareBit work remains open in PR #104**
   - source-level fixed-work D2 centering is implemented;
   - exact Python/Rust-oracle evidence was recorded;
   - the branch is stale against current `main` and currently non-mergeable;
   - current-facing constant-time claims must remain scoped until Rust gates and hardware evidence are resolved.

8. **Repository-wide rustfmt baseline is now clean**
   - PR #106 landed the mechanical `cargo fmt --all` baseline;
   - future feature work must not reintroduce repository-wide formatting drift.

### 1.2 What is *not* complete

The following remain open and load-bearing:

- Track 1 **T1.4 evaluator integration**;
- Track 1 **T1.5 full differential/wire/call-graph validation**;
- public bootstrap replacement for #95;
- full-Q bootstrap RLWE mask sampling (#82);
- non-tautological bootstrap security validation (#83);
- per-ciphertext auto-refresh/noise state (#93);
- current-main hosted CI execution and required branch/ruleset checks (#79);
- external lattice-estimator attestation (#75);
- security-name correction / `secure_256` disposition (#76);
- factorization-aware production admission (#87/#88);
- remaining service/input/diagnostic hardening and claim synchronization.

The exact multiply kernel is therefore **mathematically staged but not a production evaluator route**, and public bootstrap is **safely unavailable**, not complete.

---

## 2. Canonical direction

The next wave shall follow these invariants.

### D0 — WIRE-Q is the production security boundary

Every published secret-dependent object must be mod-Q-only. Coprime auxiliary residues may exist only as deterministic, operation-local D3 state and must be destroyed/dropped before return.

### D1 — exact integer/residue arithmetic remains mandatory

No load-bearing `f32`/`f64`, no approximate correctness oracle, no floating-point capacity/security/routing decision.

### D2 — no Garner or mixed-radix hot path

No Garner cascade, mixed-radix conversion, or sequential reconstruction walk may enter production evaluator arithmetic. Test-only arbitrary-precision or reconstruction oracles are permitted when clearly isolated.

### D3 — do not materialize canonical `X` in production evaluator kernels

The production multiply/rescale path should derive the information it needs from residues and certified quotient/rank/lift state. Number-line reconstruction remains an explicit boundary/oracle operation, not an implementation shortcut.

### D4 — K-Elimination is a bounded quotient/carry projection, not a wire format

Use K-Elimination, canonical-rank extraction, lifted transduction, or equivalent exact quotient machinery only with explicit range/capacity certificates. Preserve the Safe-Basis ontology:

- field/NTT lanes that require field arithmetic are prime and distinct;
- composite carriers/anchors are allowed only where their coprimality/range contract is the actual requirement;
- no fake primality requirement is imposed on a composite-class carrier merely to simplify code;
- no saturated or sentinel product is accepted as an exact capacity witness.

### D5 — complexity claims must distinguish work from parallel depth

For an unbounded number of lanes, sequential software work is at least proportional to the lanes touched. O(1) is acceptable only for fixed-width hardware or a fixed instantiated basis; O(log lanes) may be claimed for a balanced parallel reduction/transduction tree when proved. Do not describe unbounded scalar work as O(1).

### D6 — fail closed before optimizing

A typed unsupported/capacity/security error is correct behavior. Wrong plaintext, silent wrap, route fallback through an uncertified algorithm, or a misleading security label is not.

---

# 3. Priority and dependency graph

```text
WR-0  CI/evidence + issue-tracker truth  ───────────────────────────────┐
                                                                      │
WR-1  Track 1 T1.4 exact evaluator integration                       │
  │                                                                   │
  └──> WR-2 Track 1 T1.5 differential + WIRE-Q completion             │
          │                                                           │
          ├──> closes/supersedes production parts of #32/#65/#81      │
          │                                                           │
          └───────────────┐                                           │
                          │                                           │
WR-4  Lift-aware transduction API/provider ───────┐                   │
                                                  │                   │
WR-5A Bootstrap sampler #82 ───────────────┐      │                   │
WR-5B Bootstrap security screen #83 ───────┼──> WR-5C #95 replacement│
WR-5D bootstrap exact-metadata cleanup ─────┘      │                   │
                                                  │                   │
                                                  └──> WR-6 #93 DAG/noise state
                                                           │
                                                           └──> #16 stress
                                                                  │
                                                                  └──> #73 depth

WR-3  PR #104 D2 fixed-work completion      (parallel root)
WR-7  parameter/security admission          (parallel until tuple freeze)
WR-8  service/API/input hardening           (parallel root)
WR-9  benchmark/claim/docs discipline       (infra in parallel; final claims after correctness)
```

**Critical arithmetic path:** `WR-1 -> WR-2 -> WR-5C -> WR-6 -> #16 -> #73`.

Do not move #73 depth upward by threshold tuning before the preceding correctness chain is green.

---

# 4. Work requests

## WR-0 — Restore executable evidence and reconcile the issue ledger

**Priority:** P0 infrastructure  
**Can run in parallel:** yes, immediately  
**Primary issues:** #79, #80, #92, #19, #77, #78, #64

### Objective

Make current `main` mechanically testable and make the issue tracker describe the current tree rather than historical states.

### Required actions

1. Restore GitHub Actions execution for the current `main` SHA.
2. Add/enable branch protection or a ruleset requiring deterministic mechanical gates.
3. Prove required jobs execute for human and bot-authored branches; no actor bypass.
4. Record run IDs/artifacts against an exact SHA.
5. Pin a Rust toolchain (`rust-toolchain.toml`) or otherwise make the rustfmt/compiler baseline deterministic; do this in its own maintenance change.
6. Audit open issues against current source and recent merges.
7. Do **not** close an issue merely because part of its remediation landed.

### Required issue-disposition review

- **#95:** keep open. Public refresh is still fail-closed; the replacement algorithm is absent.
- **#27:** source now contains `try_rns_product`, exact limb/bit-length APIs, and `t < q_i` assertions. Treat as a **verification-to-close candidate**, not an implementation ticket. Close only after its full boundary tests and caller audit are demonstrated on current `main`.
- **#80:** actor-bypass source remediation appears landed, but completion still depends on executed equivalent job matrices. Keep open until CI actually runs.
- **#32:** rewrite/supersede any requirement that implies persistent coprime anchor state on the wire. Its production-rescale objective now converges on WR-1/WR-2.
- **#65/#81:** keep open until the integrated exact multiply route makes the original failing assertions green without changing their expected plaintext.
- **#29:** split current value from obsolete topology assumptions. Keep exact metadata, no-sentinel, range/capacity, and bootstrap recumbency requirements; remove any requirement that conflicts with WIRE-Q.
- **#92:** update phase checkboxes only from attached current-SHA evidence.

### Gates

```text
cargo fmt --all -- --check
cargo check --workspace --all-targets --features allow_insecure
cargo test -p nine65 --lib --release --features allow_insecure
python/shell exactness, WIRE-Q, no-float, residue-native, CT/NTT gates
```

No issue may be marked “CI green” when the commit has no executed checks.

---

## WR-1 — Track 1 T1.4: integrate the derived-transient exact multiply

**Priority:** P0 arithmetic  
**Can run in parallel:** yes, but only one agent owns the evaluator integration branch  
**Depends on:** T1.1/T1.2/T1.3 already landed  
**Primary issues:** #32, #65, #81, #27

### Objective

Turn `MainOnlyBaseExt + ExactScaleRound` from isolated verified kernels into the real evaluator multiply/rescale route while preserving a mod-Q-only wire object.

### Required implementation

1. Add an explicit experimental/certified route type. Do not silently switch every legacy route on the first commit.
2. Tensor the incoming mod-Q ciphertexts.
3. Derive all auxiliary residues from the main mod-Q residues using `MainOnlyBaseExt` or an equivalent main-only certified rank projection.
4. Choose transient auxiliary moduli from public parameters only.
5. Prove at construction that the auxiliary basis is:
   - pairwise coprime;
   - cross-coprime to the main basis;
   - large enough for the `ExactScaleRound` bound;
   - NTT-compatible where the implementation actually performs NTT arithmetic in that auxiliary lane.
6. Compute exact BFV rounded scale-and-round using `ExactScaleRound`; truncation is forbidden.
7. Carry relinearization through the exact route without introducing a serialized auxiliary/redundant/anchor lane.
8. Emit a normal mod-Q ciphertext only.
9. Explicitly zeroize or drop transient scratch state before return.
10. Make every failed capacity/basis/route proof a typed error.
11. Remove production dependence on the old wrong limb-local rescale for configurations routed here.

### CRAM requirements

- The Safe Basis remains a factor/identity substrate and theorem source; it is **not** permission to publish extra coprime RLWE lanes.
- Use K-Elimination/canonical-rank/lift logic as bounded residue projections with explicit range witnesses.
- No `RNSContext::to_int`, `extract_k_rns*`, `crt_reconstruct*`, Garner, or MRC in the production call graph of the new route.
- Test-only exact bigint/reconstruction oracles remain allowed.

### Required tests

1. Keep the T1.1 failing-old-route test, but add a replacement assertion showing the new route equals the exact oracle on the same vectors.
2. Exact `mul_no_relin` tensor differential.
3. Exact `mul` differential including relinearization.
4. Boundary cases:
   - zero/one;
   - `t/2` neighbors;
   - negative-centered representatives;
   - rounding ties;
   - maximum certified tensor magnitude;
   - exact capacity boundary ±1;
   - u128/U256 crossover products.
5. Main-lane permutation invariance where the algorithm is mathematically permutation-invariant.
6. Auxiliary-basis ordering invariance where applicable.
7. A source/call-graph gate proving the route contains no forbidden reconstruction or Garner/MRC symbol.
8. WIRE-Q assertion on output.

### Completion gate

The route is not complete until the original depth-2 wrong-plaintext tests from #81 pass unchanged through the new implementation.

### Performance gate

Archive BASE/HEAD integer timings for:

- tensor product;
- base extension;
- exact scale-and-round;
- relinearization;
- full ct×ct multiply;
- allocations/scratch bytes if available.

Correctness is the first gate. A faster wrong output is a failure.

---

## WR-2 — Track 1 T1.5: differential, serialization, and long-chain closure

**Priority:** P0 validation  
**Depends on:** WR-1  
**Primary issues:** #32, #65, #81, #73, #91

### Objective

Prove the integrated exact multiply is the production-safe mod-Q route before any depth/performance claim is raised.

### Required matrix

For `secure_128`, `secure_128_deep`/alias status, `secure_192`, and `secure_256`:

1. deterministic seed matrix;
2. random and adversarial plaintext pairs;
3. squaring and mixed operands;
4. `mul_no_relin` oracle equality;
5. `mul` + relinearization oracle equality;
6. repeated multiplication until the actual noise limit;
7. exact decrypt equality at every node;
8. no lane-count mutation unless the API explicitly requests a level change;
9. serialized output contains only divisors of Q;
10. keys/ciphertexts/rlk/Galois/bootstrap artifacts remain WIRE-Q compliant.

### Required call-graph gate

Production path must reject:

- Garner;
- mixed-radix conversion;
- canonical coefficient reconstruction;
- persistent redundant/anchor input;
- saturated capacity or overflow sentinels used as exact metadata.

### Documentation correction

`TRACK1_D3_EXACT_MULTIPLY_IMPLEMENTATION.md` still carries a stale prerequisite saying public/evaluation-key sampling draws one `u64` and reduces it into every lane. Current source has exact full-width rejection sampling for the main dual key paths. Update the doc only after re-verifying every relevant sampler; do not repeat stale prose as an active defect.

### Issue disposition after green gates

- close or rewrite #32 around the actual derived-transient route;
- close #65 only when the emission/call graph is genuinely elimination/derived-transient and no materialization remains in the new hot path;
- close #81 only when its original assertions pass unchanged across the required seed/config matrix;
- only then begin #73 depth expansion.

---

## WR-3 — Finish Track 2 PR #104 without overclaiming constant time

**Priority:** P1 security/D2  
**Can run in parallel:** yes  
**Current PR:** #104

### Objective

Land the fixed-work D2 centering improvement on top of current `main` while preserving the WIRE-Q domain boundary and making the claim surface exact.

### Required actions

1. Rebase/update PR #104 onto current `main` after the repository-wide rustfmt pass and recent Track 1/WIRE-Q merges.
2. Resolve conflicts without copying stale pre-WIRE-Q assumptions back into the tree.
3. Run:

```text
cargo fmt --all -- --check
cargo test -p nine65 --lib arithmetic::compare_bit --release --features allow_insecure -- --nocapture
cargo test -p nine65 --lib --release --features allow_insecure
python3 scripts/verify_compare_bit_ct.py
```

4. Preserve the D2-only boundary. `CompareBit::decide_ct` is not a license to reconstruct evaluator D3 values.
5. If hardware evidence is unavailable, merge only with the claim scoped to **fixed source-level work / exactness**. Do not describe the implementation as hardware constant-time.
6. For a hardware constant-time claim, collect disassembly plus two-class timing/address-trace evidence on x86-64 and ARM.

### Merge gate

No new failure relative to current `main`; no reintroduction of repository-wide formatting drift; no WIRE-Q regression.

---

## WR-4 — Promote lift-aware transduction into a typed, testable provider

**Priority:** P1 CRAM substrate  
**Can run in parallel:** yes  
**Source:** PR #99 / `lifted_transduction.rs`

### Objective

Convert the staged theorem implementation into a typed provider usable by later CRAM operations, especially public-bootstrap research, without creating a scalar winding state or violating WIRE-Q.

### Required actions

1. Re-run the exact transduction theorem battery on current `main`.
2. Export `lifted_transduction` from `exact_transcendentals` only after those tests pass.
3. Introduce a typed phase-lock/lift provider that supplies `K mod b_j` on demand.
4. Do not carry/store a general scalar `K` merely for convenience.
5. Keep the identity explicit:

```text
X = g + K*M_A
X mod b_j = g mod b_j + (K mod b_j)*(M_A mod b_j) mod b_j
```

6. Preserve exact distinctions between:
   - integer-named state;
   - reversible heterogeneous product/topology state;
   - disjoint repacking with full-product identity;
   - overlapping composite views whose information capacity is LCM, not raw product.
7. Keep Shadow-11 as integrity/disambiguation where appropriate; do not treat a non-coprime shadow lane as an independent K-Elimination anchor when the required inverse does not exist.
8. Add typed failure when lift evidence is absent or the target-lane basis/range contract is not satisfied.

### Security boundary

This provider may be used in D1/D2/D3. It may not cause a coprime lift/anchor residue to become part of a published secret-dependent D4 object.

---

## WR-5 — Rebuild public bootstrap around a valid encrypted correction

**Priority:** P0 once WR-1/WR-2 are stable  
**Primary issues:** #95, #82, #83, #29  
**Related:** #16, #93

Public bootstrap remains fail-closed until this packet is complete.

### WR-5A — Full-Q_boot uniform sampling (#82)

Can run now in parallel.

1. Reuse/extract a canonical exact full-width rejection sampler.
2. Sample uniformly over `[0, Q_boot)`; no narrow `u64 % min_prime` joint support.
3. Reduce the accepted value into boot main lanes only as required by the wire representation.
4. If auxiliary D3 lanes are needed later, derive them from the public mod-Q/boot-Q value; never publish them.
5. Add deterministic support/identity tests and keygen/roundtrip tests.

### WR-5B — Exact bootstrap security validation (#83)

Can run now in parallel.

1. Separate structural modulus validation from security screening.
2. Use exact product bit length, not summed lane widths.
3. Take the security target from the declared work/config contract, never from `Q_boot` itself.
4. Run both in-tree models and factorization-aware screening; structural refusal fails closed.
5. Archive exact boot tuple for external estimator work (#75).

### WR-5C — #95 encrypted Phase-1 correction / encoding architecture

This is the actual public-bootstrap replacement.

#### CRAM-aligned route

Prefer an encrypted Safe-Root/Lift/carry transduction if it can satisfy WIRE-Q:

1. keep all published BSK/KSK/ciphertext material modulo divisors of the security modulus;
2. represent the displaced secret-dependent correction under encryption;
3. evaluate the missing quotient/carry `K` or an algebraically equivalent correction circuit homomorphically;
4. use D3 derived-transient residues only when they are deterministic functions of already-public encrypted state and are discarded before return;
5. use WR-4 lift-state machinery for exact residue/carry organization, not to expose the secret-linear integer;
6. do not publish a non-wrapped coprime anchor of `a*s+e`.

If that route cannot satisfy the proof obligations, the alternative is an explicitly typed encoding migration (for example the documented BGV/low-bits direction). Do **not** silently reinterpret BFV `Delta*m` ciphertexts as a different encoding regime.

#### Required acceptance ladder

```text
A  Enc(9) -> refresh -> 9
B  square(Enc(3)) -> refresh -> 9
C  Enc(3)+Enc(6) -> refresh -> 9
D  Enc(3)*Enc(3) -> refresh -> 9
E  B -> refresh -> square -> 81
```

Run circular and KSK-separated modes, every named configuration, deterministic seed matrix, fresh/add/mul/relinearized/boundary-noise inputs, and u128/U256 crossover cases.

The legacy component-wise `modswitch_to_t` remains diagnostic/test-only until this matrix is green.

### WR-5D — Exact bootstrap/context metadata

Carry forward the still-valid parts of #29:

- exact product limbs and exact product bit length;
- `Option<u128>`/checked scalar projections, never zero sentinels;
- exact floored Delta representation;
- no saturation in capacity/routing/security decisions;
- no Garner/MRC or production canonical reconstruction;
- explicit prime/coprime/range validation.

Rewrite any old persistent-DualRNS-on-wire requirement to WIRE-Q-compatible D3 transient state.

---

## WR-6 — Per-ciphertext auto-refresh state (#93)

**Priority:** P0 after a correct public refresh primitive exists; wrapper/type design may begin earlier  
**Depends on:** WR-5C for end-to-end activation

### Objective

Make refresh decisions a property of the actual operand history, not one mutable evaluator-session ledger.

### Preferred design

Create a tracked ciphertext wrapper containing the mod-Q ciphertext plus its exact refresh/noise-cycle metadata.

Requirements:

- encryption initializes independent state;
- cloning copies state exactly;
- binary operations inspect both operands;
- refreshing one branch does not reset another;
- squaring a single object refreshes at most the required operand state once;
- output state is derived from the actual operation bound;
- no unrelated ciphertext can consume another ciphertext’s budget.

### Required DAG tests

- two independent branches of unequal depth;
- refresh on one branch, then reuse the other;
- clone/evolve/recombine;
- add-heavy and mul-heavy DAGs;
- exact plaintext oracle at every node;
- exact record of which operand refreshed.

Only after this state model is correct may auto-refresh thresholds/reserves be tuned.

---

## WR-7 — Parameter/security admission and external attestation

**Priority:** P1 blocking any final security claim  
**Can run partly in parallel:** yes  
**Issues:** #87, #88, #75, #76, #71, #18, #72

### Required order

1. Integrate factorization-aware screening into production admission (#87).
2. Separate claimed/screened/unverified states in raw constructors (#88).
3. Resolve `secure_256` naming against the weakest accepted model (#76).
4. Freeze exact work and bootstrap tuples.
5. Run external lattice-estimator artifacts for those exact tuples (#75).
6. Only then synchronize public claims and seek external audit (#71).

### Non-negotiable

- an internal heuristic is not an external security attestation;
- an unscreenable tuple is refused or labeled unverified, not assigned a security number;
- exact tuple fingerprints must include ordered primes, N, t, eta, feature set, and commit SHA;
- no old benchmark/security artifact may be relabeled as evidence for a newer tuple.

---

## WR-8 — Service/API/input and diagnostic hardening

**Priority:** P1/P2 parallel work  
**Issues:** #94, #85, #86, #84, #89, #74

Parallel subtracks are allowed because these should not alter the arithmetic architecture.

1. HTTP framing fail-closed work (#94).
2. Convert caller-controlled panic-through-`Result` constructors to typed errors (#85).
3. Context-complete validated decode and trailing-byte rejection (#86).
4. Fix negative-branch diagnostic ideal-point calculation (#84).
5. Enforce panic/unwrap/expect ratchet (#89).
6. Restore `allow_insecure` production gating without destroying testability (#74).

Every code-changing subtrack must run the canonical FHE correctness baseline before/after and prove no route/features changed accidentally.

---

## WR-9 — Performance evidence, zero-float reporting, and claims/docs

**Priority:** infrastructure may run now; final numbers only after P0 correctness  
**Issues:** #19, #77, #78, #64, #90, #91, #62, #66, #69, #68, #70, #67

### Immediate work

- benchmark artifact plumbing and exact SHA/tuple metadata;
- tiered test categorization without hiding the full release suite;
- constrained-runner reproducibility;
- repository-wide owned-source zero-float gate including tests/benches;
- warning/dead-code inventory;
- K-Elimination implementation/discoverability cleanup where it does not rewrite active arithmetic.

### Deferred until architecture freezes

- final README performance tables;
- final depth/capability claims;
- final architecture narrative;
- new formal proof expansion.

The documentation may describe the current fail-closed boundaries immediately, but it must not pre-announce unmerged capability.

---

# 5. Parallel agent allocation

The following decomposition minimizes overlap.

| Agent lane | Work request | Main write surface | Can start now? |
|---|---|---|---|
| A | WR-1 exact multiply integration | `arithmetic/*`, `ops/rns_fhe.rs` / new exact evaluator module | **Yes** |
| B | WR-3 PR #104 completion | `compare_bit.rs`, D2 decrypt integration, CT evidence | **Yes** |
| C | WR-4 lift provider | `exact_transcendentals/*` | **Yes** |
| D | WR-0 CI/evidence/issue truth | `.github/*`, scripts, tracker/docs | **Yes** |
| E | WR-5A sampler | bootstrap key sampling only | **Yes** |
| F | WR-5B security validator | bootstrap config/security validation | **Yes** |
| G | WR-7 production security admission | parameter/security modules | **Yes, avoid tuple edits until coordinated** |
| H | WR-8 service/input hardening | `fhe-service`, decode/constructor boundaries | **Yes** |
| I | WR-2 integration validation | tests/source gates | **After WR-1 API stabilizes** |
| J | WR-5C bootstrap correction | bootstrap architecture | **After WR-1/WR-4 interfaces stabilize; research can start now** |
| K | WR-6 per-ciphertext noise state | auto-bootstrap state model | **Type design now; activation after WR-5C** |

One agent owns each production file at a time. Merge small prerequisite branches before downstream agents rebase; do not maintain long-lived divergent copies of `rns_fhe.rs` or `bootstrap.rs`.

---

# 6. Required quality gate for every arithmetic work PR

Every arithmetic/security PR must include the following evidence in its PR body or an attached artifact.

## Before

- BASE_SHA;
- exact tuple fingerprint(s);
- Rust/cargo/rustfmt version;
- CPU/OS/feature set;
- original failing/passing correctness matrix;
- integer-only benchmark samples for the affected primitive;
- source-gate output.

## After

- HEAD_SHA;
- identical test/benchmark commands;
- exact oracle equality;
- changed bootstrap/operation counts if applicable;
- integer ns/us medians and integer-scaled ratios;
- allocation/scratch delta where relevant;
- explanation of every changed failure or performance regression.

## Hard source prohibitions

Production evaluator/bootstrap arithmetic must not newly contain:

- `f32` / `f64` correctness arithmetic;
- Garner;
- mixed-radix conversion;
- canonical coefficient reconstruction used as an evaluator shortcut;
- serialized coprime-to-Q secret-dependent lanes;
- saturation or sentinel values used as exact capacity/security/routing state;
- weakened/deleted failing correctness assertions;
- an automatic level drop added solely to hide a fixed-basis arithmetic error.

---

# 7. Immediate execution order

1. **Start WR-0, WR-1, WR-3, WR-4, WR-5A, WR-5B, WR-7 and WR-8 in parallel.**
2. **WR-1 is the highest-priority arithmetic branch.** It completes the exact evaluator kernel already staged in main.
3. Once WR-1 stabilizes, run WR-2 immediately and use it to dispose of #32/#65/#81 truthfully.
4. Use WR-4 + WR-5A + WR-5B as prerequisites for the public-bootstrap redesign; do not reactivate public refresh before WR-5C passes its exact ladder.
5. Integrate WR-6 only after bootstrap has a correct operation to schedule.
6. Run #16 stress only after the bootstrap and per-ciphertext state models are correct.
7. Increase depth (#73) only after all earlier correctness gates are green.
8. Freeze named security and performance claims only after tuple/correctness stability, then complete WR-7/WR-9 external evidence and documentation.

---

# 8. Completion definition for this next wave

This work-request PR itself is complete when every workstream is either:

- merged with the stated gates and linked evidence;
- explicitly superseded by a stronger implementation with the same acceptance criteria; or
- split into a named follow-up issue/PR with a recorded blocking reason.

The next architectural milestone is reached when:

1. public ct×ct multiply uses the exact derived-transient mod-Q route and matches an independent oracle;
2. WIRE-Q is mechanically enforced for every published object;
3. public bootstrap has a mathematically valid encrypted correction/encoding route and is no longer fail-closed;
4. auto-refresh tracks state per ciphertext/DAG branch;
5. current `main` has executed required CI with branch/ruleset enforcement;
6. no named security claim exceeds the weakest accepted model and exact external artifacts exist;
7. performance/depth claims are regenerated from the final exact tuple and code SHA.

Until then, the safe product stance is:

> **Exact mod-Q arithmetic kernels are advancing; WIRE-Q is enforced; unsafe public multiply/refresh routes fail closed; public bootstrap and general auto-refresh remain incomplete.**
