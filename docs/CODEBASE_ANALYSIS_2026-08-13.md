# Codebase Analysis — 2026-08-13

**Scope:** everything the concurrent security re-audit (docs/SECURITY_REAUDIT_2026-08-13.md,
in progress) does *not* cover — the service/API surface, the accelerator stack, the ops
surface beyond multiplication, keys/entropy/noise, and the CRAM engine. Five read-only
analysts, every claim verified by call-site census (workspace-wide grep), LOC counts, and
git history — not impressions. A sixth analyst (K-Elimination consolidation prep) was lost
to a session limit and its territory remains open; see "Not covered" at the end.

**Companion documents:** docs/EXECUTION_PLAN_2026-08-12.md (the phase plan this feeds),
docs/DEPTH1_ROOT_CAUSE_2026-08-12.md, CRAM_OPPORTUNITY_REPORT.md (ledger).

---

## 1. Health map

| Subsystem | Health | One-line verdict |
|---|---|---|
| fhe-service + SDK/FFI perimeter | **sound-with-debt** | The HTTP core is well-built and routes 100% to the fixed dual-RNS path; the perimeter (auth wiring, shipped binary, Dockerfile, SDKs, FFI) is decayed or dead. |
| Accelerator stack (mana/unhal/accelerated.rs) | **dead** | Aspirational scaffolding, not a working accelerator: zero production call sites, a u128 spine that cannot represent any production track, no polynomial multiply, and a confirmed semantic bug in dead bridge code. |
| Ops surface beyond mul | **sound-with-debt** | A thin live core (gso_fhe partially) surrounded by a large, mostly well-labeled museum: legacy single-modulus stack, 5,854 LOC of quarantined bootstrap, and several fully dead modules. |
| Keys / entropy / noise | **sound-with-debt** | Production keygen is sound (OS CSPRNG, ternary secret, zeroized session keys); the debt is dead enforcement (require_secure_rng: 0 call sites), dead noise modelling (~1,400 LOC), and sampling hygiene. |
| CRAM engine (exact_transcendentals, clockwork-core, cram-core) | **sound-with-debt** | Disciplined, fully-tested research stack (518/518 tests live) that is production-orphaned by design; the FPD/D3 rescale the bootstrap bet depends on stops one seam short of the dual-RNS path and is capacity-limited (~2^58 vs ~2^89 needed). |

---

## 2. Service and API surface

**The strength first:** all 8 FHE operations in `fhe-service` route through the fixed
dual-RNS path — `encrypt_dual_secure`, `decrypt_dual`, `add_dual`, `sub_dual`,
`negate_dual`, `add_plain_dual`, `mul_plain_dual`, and `mul_dual_public` with the session
eval key (`handlers.rs:442-623`). Zero legacy single-modulus calls anywhere in the crate.
The service **fully inherits the depth-1→256 fix** with no routing work. Sessions are
RAM-only with CSPRNG 128-bit IDs, TTL reaping, and `ZeroizeOnDrop` keys; untrusted
deserialization is layered, bounded, and fuzz-covered; error responses are uniformly
generic with tests asserting non-leakage.

**The defects:**

1. **`auth.rs` is dead code** (`fhe-service/src/main.rs:11-14` vs `auth.rs:59`). Commit
   `da9b2ef` ("security(service): add tenant-bound ingress authentication") added only the
   file — no `mod auth;` was ever declared, so it is not compiled and its 2 tests never
   run. Live auth is one shared `FHE_API_TOKEN` plus a **self-declared**
   `x-fhe-tenant-id` header: any token holder can claim any tenant. The per-tenant
   credential binding the crate is credited with does not exist at runtime.
2. **`panic = "abort"` (workspace `Cargo.toml:35`) nullifies the service's
   `catch_unwind`** (`main.rs:147-153`). Any panic in the FHE core — including the new
   capacity asserts on the depth-fix surface — kills the whole process and every tenant's
   in-RAM keys. One request that reaches an assert = full-service crash DoS. (The panic
   *messages* do not leak to callers; stderr only.)
3. **Every distributed artifact is stale.** The checked-in 634KB binary
   (`apps/fhe-service/`, committed 2026-02-23) predates both the auth layer (+141 days)
   and the depth fix (+172 days) — it serves an unauthenticated, depth-1-broken API. The
   Python SDK sends **no auth headers** (`sdks/python/nine65_sdk/client.py:30-37`) and
   cannot talk to any current build; all 18 of its tests are live-integration with zero
   mocks, so the drift is invisible to CI. The Dockerfile builds and runs
   `nine65_v7_demo --help` — **not fhe-service** — so the documented Cloud Run deployment
   cannot serve port 8080 at all.
4. **nine65-ffi** is workspace-excluded, has 0 tests, aborts the process on modulus 0 and
   hangs forever on modulus 1 (`lib.rs:59-63`), and `nine65_receipt_verify` can never
   verify a genuine receipt (`lib.rs:292-302` vs `kiosk/receipt.rs:78-87`).
5. Cross-tenant DoS via the **global** 64-session cap (no per-tenant quota,
   `session.rs:166-174`) and an unbounded rate-limit map (`handlers.rs:63-77`).

---

## 3. Accelerator stack — verdict: aspirational scaffolding

3,397 LOC (mana 2,194 + unhal 899 + accelerated.rs 304), 42 tests, and **zero production
call sites**. The only consumer of mana/unhal is `accelerated.rs`, whose types are called
by nothing (feature-on/off timing measured identical in commit `d6f6e82`). Four
independent structural blockers make "wire it in" a rebuild, not an integration:

1. **u128 product spine cannot represent any production track** (`mana/src/stream.rs:36`):
   the anchor product alone is ~158 bits at n=8192 and ~318 bits at n=16384, so
   `product_cache` hits the overflow sentinel and `reconstruct_at` divides by zero.
2. **No polynomial multiplication** — the production hot loop is per-limb negacyclic NTT
   convolution (11 sequential per-limb NTT loops enumerated, e.g. `rns_fhe.rs:2435`,
   `:4458-4475`, `:1623-1631`); mana offers only Hadamard products.
3. **The bridge targets the wrong types**, and `AcceleratedRNS::add/mul` are semantically
   wrong for len ≥ 4 (`accelerated.rs:222`) — computing the residue vector of `a[0]+b[0]`
   and discarding the rest. Proof nobody has ever run it.
4. Even opted-in, **unhal's `parallel_threshold=256` is compared against lane count**
   (8-16 in production), so the parallel path can never engage
   (`unhal/src/accelerator.rs:142`).

Genuine positives: feature/dependency hygiene is well-executed, and lane-parallel
execution is output-deterministic by construction — the bit-identical A/B requirement is
achievable *if* a deterministic lane executor is built (ledger [31]). The Phase 4 brief:
do not route through ManaStream; build the deterministic executor against the real dual-RNS
layout, and delete `PersistentLane`/Montgomery machinery (~430 lines, zero dependents —
ledger [39]/[41] already concluded Shoup constants win at 1.66 c/op vs 3.92).

---

## 4. Ops surface beyond multiplication

Definitive census of 13,882 LOC (`ops/mod.rs` as ground truth):

- **Live on the dual-RNS path:** effectively nothing outside `rns_fhe.rs`. `GSOFHEContext`
  is a benchmark shell — its "basin collapse" bookkeeping never modifies a ciphertext, and
  fhe-service bypasses it entirely (`session.rs:39` holds `RNSFHEContext` directly).
- **Legacy single-modulus stack** (encrypt, homomorphic, galois, batch, parallel,
  rns_mul): a parallel BFV universe the dual-RNS path imports nothing from. `encrypt.rs`
  itself is well-built and worth keeping as the legacy reference.
- **Quarantined:** 5,854 LOC of bootstrap across four modules, 76 ignored tests, zero
  production callers. Quarantine discipline is exemplary — every `#[ignore]` carries a
  tailored reason.
- **Dead (zero external callers, workspace-wide):** `compiler.rs` (its f64 noise model
  leaks into no runtime decision — nothing calls it at all), `neural.rs` (**contains no
  FHE: not one ciphertext type in 498 lines**), `sbni.rs` (off-tree), the entire
  `src/bootstrap/` subtree (name-collides with `ops::bootstrap::ClockworkBootstrap`),
  `rns_mul.rs` (a dead *duplicate* of the production DualRNS type family —
  `DualRNSPoly`/`DualRNSCiphertext`/`DualRNSSecretKey` defined twice).

**The rotation gap is two gaps** (`galois.rs:492`): no dual-RNS Galois machinery AND no
slot encoding on *any* path (`batch.rs` says "planned for v0.3"). Good news: parameters
are already slot-compatible (t=65537 ≡ 1 mod 2N for every secure config), and the
noise-critical key-switch machinery rotation needs is exactly the `extract_digit_dual`
path PR #44 just fixed. Realistic scope ~800-1,100 LOC.

**SDK routing bug:** both the Python and WASM bindings call the *deprecated legacy*
`BFVEvaluator::mul` (`nine65-wasm/src/lib.rs:297`, `nine65-python/src/lib.rs:544`) — the
depth-256 fix is **unreachable from every published binding**.

**Q17 note:** the recorded auto-bootstrap defect (wrong plaintexts after ~10 muls) should
be re-diagnosed post-depth-fix — its failure signature matches the unsigned-k bug just
fixed, so it may already be resolved.

---

## 5. Keys, entropy, noise

**Sound core:** the deployed path (`fhe-service/session.rs:65` →
`generate_keys_dual_full_secure` → `SecureRng`) uses OS `getrandom`, always compiled,
correctly independent of the optional shadow-entropy feature; ternary secret sampled
consistently across main and anchor limbs; `params/` security floors fail closed
(n≥8192 for 128-bit claims).

**Debt, concentrated in three rings:**

1. **Dead enforcement:** `require_secure_rng` has **zero call sites** — nothing blocks a
   deterministic-RNG keygen in production; 16 bins use the deterministic
   `generate_keys_dual_full()`, 0 use `_secure`. The `secret_data.rs` CT type family has
   0% production integration. `NTTEngine::multiply_ct` is a bare alias of `multiply`
   (`ntt_fft.rs:303-305`) — the name overpromises.
2. **Dead noise modelling:** `NoiseBudgetTracker`, P²/EMA/multi-window detectors,
   `ExactNoiseTracker` (~1,400 LOC) — zero external callers. Only `budget.rs` is live,
   wired into fhe-service as a flat-cost predictive *rejection gate* that will now diverge
   from reality (public depth 256 vs its hardcoded costs). **Recommendation:** migrate
   accounting to the measured-margin authority (`decrypt_dual_with_diagnostics`); real LWE
   error still grows, so accounting is warranted — just not this model.
3. **Sampling hygiene:** dual ternary sampler uses biased `next_u64() % 3` while unbiased
   rejection samplers sit unused beside it (`rns_fhe.rs:1694-1703`); the public/eval-key
   `a` polynomial samples from `[0, min_prime)` (~30 bits) rather than uniform over the
   full modulus (`rns_fhe.rs:1746-1755`) — flagged for the security re-audit's follow-up;
   production `DualRNSEvalKey` (carries s²) has no Zeroize while its legacy twin does
   (`rns_fhe.rs:309-321` vs `keys/mod.rs:396-403`).

---

## 6. CRAM engine

**Strengths are real:** all 518 exact_transcendentals tests live (zero ignored);
`cram_ct.rs` (3,439 lines: ~2,151 production + 93 in-file tests) has every section covered;
fail-closed posture is systematic; ledger [42]/[43] resolutions verified genuine in code
and tests; `transduction.rs` post-[42] confirmed lanewise-Garner-free.

**The load-bearing share is small:** under default features, nine65 consumes ~1,300 LOC
directly (cordic → transcendental_backend → neural evaluator) out of 20,404 — ~6%. The
rest is research plus test oracles.

**The finding that matters for the bootstrap bet (Phase 7):** the FPD/D3 rescale exists,
is tested (`cram_ct.rs:1454/1461`), and nine65 even has the full ingestion seam built
(`cram_ct_wrap.rs`, 423 lines, 9 tests) — **and nothing calls it**. Even if wired: the
shipped 7-prime aux pool caps certifiable quotients at ~2^58 against secure_128's ~2^89
coefficients (a ~31-bit ceiling gap), the i128 witness API structurally excludes
secure_192/256 (refused, not truncated — correct posture, but a hard wall), and **every
homomorphic op except FPD itself drops `c0_aux`** (`cram_ct.rs:963`), so the division lane
is unreachable after any add/mul. The bet's wiring gap is real but the capacity gap is the
deeper obstacle.

**Ledger work orders, sized:**
- **[7]** `composite_division.rs` (491 LOC): 100% dead outside its own tests; its division
  algorithm cannot be de-Garnered — retire or quarantine, don't refactor.
- **[8]** `cram_pde.rs ExactState::to_u128`: adjacent-anchor recipe applies cleanly,
  ~150-250 in-crate LOC, exhaustive corridor test already waiting.
- **[9]** `k_elim::garner_reconstruct`: exactly 4 non-test call sites; one 5-line lanewise
  fix in `k_elim_divide_named`, one intentional counted exit to document.
- Also found: the p2 no-Garner gate is a source-string check that `lift_state` silently
  bypasses (`cram_anchor.rs:434`) — a gate bug, not an arithmetic bug.

**clockwork-core:** CI-maintained (46 tests), but wraps only the legacy path behind the
non-default `clockwork` feature — a security sidecar in a parallel universe.
**cram-core:** zero dependents in any workspace Cargo.toml; its `ArchitectureCounters`
([14]) has a concrete wiring plan but currently measures nothing.

---

## 7. Feed-through to the execution plan

**Immediate security wiring (before/with the next release, outside phase order):**
- Wire `mod auth;` into fhe-service (or delete auth.rs and document shared-token-only).
- Decide `panic=abort` vs `catch_unwind` for the service binary.
- Delete the stale `apps/fhe-service` binary; fix the Dockerfile to actually build
  fhe-service; add auth headers to the Python SDK.
- Route Python/WASM SDKs to the dual-RNS mul (they currently ship the deprecated legacy
  multiply, making the depth fix unreachable from bindings).

**Phase 4 (ledger/consolidation):** the [7]/[8]/[9] work orders above; retire
`PersistentLane`/Montgomery (~430 LOC, zero dependents); do NOT wire `exact_divide_stream`
([33] confirmed: reconstruction in K-Elim clothing); delete or quarantine `rns_mul.rs`
(dead duplicate type family); `compiler.rs` deletion candidate; cram-core wiring decision;
the deterministic lane executor is the only honest accelerator path.

**Phase 7 (bootstrap/capability decisions):** the FPD capacity ceiling (~2^58 vs ~2^89)
and the dropped-`c0_aux` design are the two facts the bootstrap-bet decision must weigh;
rotation = Galois + slot-encoding double gap, ~800-1,100 LOC, unlocked by the PR #44 fix;
`src/bootstrap/` subtree quantified as a deletion candidate; re-diagnose Q17 post-fix;
`neural.rs` contains no FHE and needs an honest rename or removal.

**Phase 8 (test/bench hygiene):** mana + exact_transcendentals benches never execute
(undeclared harness); SDK tests are all live-integration with zero mocks (drift invisible);
`test_depth_50_bootstrap_free` asserts a heuristic against itself; gso depth benchmarks
never decrypt (already known, now quantified); 7 tracked `.pyc` files.

---

## 8. Not covered here

- The **security re-audit territory** (the depth-fix surface: `rns_fhe.rs` internals,
  `rns.rs`, RLWE posture, CT analysis of the new signed-k branches) — companion doc, in
  progress.
- The **K-Elimination five-implementation consolidation matrix** — its analyst was lost to
  a session limit; territory remains open for Phase 4. Known inputs: the five
  implementations list, mana::KAnchor's hardcoded constants matching
  nine65::KElimConfig::Standard (unverified numerically), and the orphaned
  `BoundedResidueDivider` implementation still awaiting landing.

---

## 9. Top actions by value/effort

1. **Wire `mod auth;`** (one line + tests) — converts a committed security fix from dead
   code to live enforcement. First step: add the module declaration, run the 2 dormant
   tests.
2. **Fix SDK multiply routing** (Python + WASM → dual-RNS path) — makes the depth fix
   reachable by users. First step: swap `BFVEvaluator::mul` for the dual context calls.
3. **Delete the stale service binary + fix Dockerfile target** — stops shipping an
   unauthenticated depth-1 API. First step: `git rm apps/fhe-service/fhe-service`,
   point Dockerfile at `-p fhe-service`.
4. **Decide the service panic posture** — abort-kills-all-keys vs unwind-per-connection.
5. **Land ledger [8]+[9]** (~200 LOC total, recipes verified) — two of three Garner sites
   closed cleanly.
6. **Migrate noise accounting to measured-margin** — retire the flat-cost gate before it
   mis-rejects valid depth-256 workloads.
7. **Fix ternary-sampler bias + eval-key `a` sampling range** — small diffs, real
   distribution hygiene (coordinate with the security re-audit's findings).
8. **Add Zeroize to `DualRNSEvalKey`** — parity with the legacy key it replaced.
9. **Delete dead mass** (`rns_mul.rs`, `src/bootstrap/` subtree, `compiler.rs`,
   `PersistentLane`) — ~5,000 LOC of confusion risk, all zero-caller-verified; needs the
   owner's sign-off per plan Phase 5/7 conventions.
10. **Declare the benches** (`[[bench]] harness = false` for mana +
    exact_transcendentals) — makes `cargo bench` mean something.
