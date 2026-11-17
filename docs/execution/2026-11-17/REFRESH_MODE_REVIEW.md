# Refresh report review and operational mode boundaries

Reviewed 2026-11-17 against the report's exact source commit
`88a7bdadbf0e1f8fbfdb2b37e9843101b8db3484` in NINE65_v7. The report is
“Symmetric-mode bootstrap: findings and better refresh designs”, dated
2026-11-16. This document records a source/history investigation and a bounded
implementation plan. It does not implement a new refresh protocol or change
any arithmetic, entropy enforcement, public scheduler, or admission gate.

Read [current public-refresh status](../../PUBLIC_REFRESH_STATUS.md) for the
separate native execution, security and provenance claims.

## Findings

The report's scalar trusted-key refresh observations are substantially useful.
Its principal weakness is incomplete reconciliation with existing history,
followed by conclusions that exceed the demonstrated mode or security model.
The existing public research implementation does not automatically modernize
the separate symmetric wrapper.

| Finding | Repository evidence | Disposition |
| --- | --- | --- |
| Finite symmetric depth was already known | `54cce6921a74e1dfa8f354b6395ee976d406d275` (Nov 2), `time_crystal_verification::symmetric_depth_is_finite_and_noise_limited` | The fixed-seed mul-by-Enc(1) test documents correct depth 3 and failure at 4; it asserts a floor of 3 and failure before a cap of 16. A measured chain is not a universal scheduling guarantee for other keys, operands or squaring workloads. |
| The missing carry is not confined to a one-unit error | `dc5989d046997c0c71c03c885510ed17b3bf7a28` (Oct 25), `bootstrap::tests::diag_refresh_error_is_exactly_the_displaced_phase1_carry` | The legacy identity is `decrypt(refresh(ct))[0] = (m - K_0) mod t`; archived native examples have `K_0 = -18, -18, 12`. A single 0-to-65536 failure cannot establish an off-by-one classification. The phase-1-only map is incorrect without its correction. |
| A working, separate public research solution already existed | PR #201 merge `77e68882c8e78fcd337da1912f0a01d2e271909e` (Nov 1); current status document | Encrypted carry extraction, restoration and original-key return have archived native execution. Legacy Clockwork remains disabled. These are different APIs and trust boundaries; public research costs are not the report's 10 ms trusted-key cost. |
| Explicit public refresh scheduling already existed | `8f0d6bc5551354c9314122330f32b6ca3026e3e4`, [scheduler record](../2026-11-10/PUBLIC_RESEARCH_SCHEDULER.md) | It forecasts source-conversion and work bounds, preserves the next refresh opportunity, limits attempts, and never falls back to a secret-key refresh. It is not a symmetric scheduler. |
| This diagnosis confusion was previously investigated | `dde9762`, [November 1 correction record](../../maintenance/PUBLIC_REFRESH_STALE_DIAGNOSES_2026-11-01.md), issue #200 | The earlier audit separated branch visibility, stale documentation, legacy refusal, native arithmetic and open security obligations. The report's commit already contains those corrections. |
| Scalar shape and RNG limitations remain in the symmetric wrapper | `ops/symmetric_bootstrap.rs`, `bootstrap`, `bootstrap_timed`, `reencrypt_symmetric` | These call scalar `decrypt_dual` and take `ShadowHarvester`. A secure encryption API exists elsewhere, but this wrapper has not acquired that path. `post_noise_mb` is a model value. The hard-coded “200+” output remains stale. |
| Full-modulus symmetric mask sampling was already repaired | `c53bc772b92e050defca1194c4bc894dcaa069ec` (Sep 8), merged in PR #142 | Reuse `sample_uniform_dual_poly` and its active mask tests. The ignored historical bootstrap tests do not mean that all tests in this module are ignored. |

The scalar inner-product idea is a reasonable optimization candidate, but the
report explicitly did not compare its decoded output to the actual decryptor.
Its lane-only timing is not an end-to-end replacement measurement. No earlier
implementation of the three exact proposed variants was established by this
investigation; the old public solution is not evidence that those variants
were already implemented.

The report's security suggestions require separate review:

* Blind refresh: uniformity of the decoded masked message proves only that
  projection of the key-holder view. The service also receives a ciphertext;
  its full view, chosen-ciphertext admission, permitted operations, replay and
  key-dependent-message behavior need a protocol argument. The report itself
  identifies a crafted-ciphertext leak. Existing root/value provenance is a
  local typed capability, explicitly **not remote execution attestation**; it
  cannot be assumed to authenticate arbitrary remote inputs. See the
  [canonical-root contract](../2026-10-31/CANONICAL_PLAINTEXT_ROOT.md).
* In-place snap: correctness under a toy phase equation does not establish
  confidentiality of keeping the old `c1`. Deleting a local old copy does not
  remove copies already observed by another party or prove the resulting
  ciphertext distribution safe. This review does not claim a demonstrated
  key-recovery attack on that proposal; it rejects the unsupported assurance
  that deletion alone is a sufficient safety rule.
* The factorization criterion quoted from CRAM-Proofs is not an executable
  producer of a secret-dependent correction. Applying it requires identifying
  the actual source, observation map, target map and admissible domain. Legacy
  `K_0` and native `K_native` must retain their distinct defining equations.

## Operational mode contracts

These are implementation boundaries to preserve or make explicit, not claims
that every planned API separation is already implemented.

| Mode | Authority and data | Refresh contract | Required isolation |
| --- | --- | --- | --- |
| Trusted-key symmetric | Explicit secret-key holder; current wrapper reads scalar coefficient 0 | Decrypt correctly while recoverable, then encrypt with fresh secure randomness | Separate scalar API; explicit polynomial API if added. No silent use as a public evaluator fallback. |
| Public leveled evaluation | Public/evaluation keys; admitted bounded operations | Stop or return a typed capacity error unless an explicit research scheduler was selected | No hidden secret-key requirement, model-noise reset or automatic change of security mode. |
| Public research refresh | `PublicRefreshCircuit` and sealed `SourceWorkCiphertext`; `allow_insecure` | Encrypted correction, canonical-root preservation, advancing lineage and bounded return | Retain scheduler attempt accounting, family checks, source headroom and open related-key confidentiality status. |
| Legacy Clockwork | Historical component-rounding construction | Typed refusal at the unsound phase-1 gate | Keep failure diagnostics and tests; do not enable this gate because another mode passes. |
| Exact residue/CRAM substrate | Its own admitted integer/residue representation and lift evidence | Exact arithmetic according to its representation contract | Basis preservation does not establish unbounded RLWE plaintext correctness or confidentiality. |
| Proposed interactive blind/snap experiments | Explicit service/adversary model still required | Toy correctness only at present | Independent experimental API, tests and security review before connection to any established evaluator. |

Share arithmetic primitives only where their preconditions match. Mode
selection must not silently grant secret-key access, relax input admission,
change scalar data into a polynomial claim, or promote research security.

## Decomposed implementation and regression plan

1. **Freeze contracts before changing code.** Record selected mode, exact
   parameter tuple, key family, plaintext shape and expected failure behavior.
   Preserve the existing public scheduler and legacy refusal tests as baseline.
2. **Modernize only the trusted-key symmetric wrapper.** Reuse the repository's
   secure RNG abstraction and full-Q sampler. Make scalar-only behavior explicit.
   Replace stale depth/noise prose with actual scoped assertions. Test successful
   refresh, fresh randomness, unsupported input rejection and scalar boundaries.
   Do not infer recoverability from a decode remainder alone: an exhausted
   ciphertext can decode to an incorrect message with an apparently plausible
   local remainder.
3. **Validate the scalar optimization before replacing a primitive.** Compare
   coefficient-0 inner products and final decode against the existing NTT path
   across admitted levels, small and U256 modulus paths, signed negacyclic wrap,
   rounding boundaries and multiple keys/messages. Keep polynomial decoding and
   public source conversion unchanged. Benchmark the checked end-to-end output.
4. **Run cross-mode compatibility checks on shared changes.** Keep the public
   scheduler's full-polynomial/root/history/family tests, both production
   phase-1 refusal regressions and symmetric full-Q sampler tests. A symmetric
   success must coexist with a legacy refusal; no mode may pass by resetting
   metadata or switching to another backend. Existing reduced public encrypted
   tests are the bounded default; native multi-cycle work is a separately scoped
   resource decision.
5. **Review experimental protocols independently.** Specify complete adversary
   view and remote admission before implementing blind-service exposure. Require
   a ciphertext-distribution argument for snap. Reuse the toy only as arithmetic
   evidence, not as security or production-integration evidence.
6. **Integrate serially with scoped evidence.** Each patch reports source commit,
   executed tests, mode and parameters. Measure multiply-by-fresh and squaring
   separately; preserve historical logs. Integrate checked non-main branches
   through the designated owner; do not repair one mode by loosening another.

## Investigation and validation record

Repository searches used `git log --all` (message and pickaxe searches),
`git show`, `git blame`, ancestor checks and source inspection in a detached
worktree at the report SHA, followed by a dedicated documentation branch.
The initial clone fetched only main. `git ls-remote --heads origin` found 56
branches; `git fetch --no-tags origin '+refs/heads/*:refs/remotes/origin/*'`
then fetched all branch refs, and the history searches were repeated.
Sources include the
actual `symmetric_bootstrap`, `bootstrap`, `rns_fhe`, `public_refresh_circuit`
and scheduler implementations, current status and the dated records above.

Relevant branch tips checked on 2026-11-17:

| Remote branch | Exact tip | Relationship to report snapshot |
| --- | --- | --- |
| `research/encrypted-k0-dense-source` | `0986fca6183d9e537e955c2285ba59f66f9003d1` | Ancestor |
| `feat/public-research-refresh-scheduler` | `8f0d6bc5551354c9314122330f32b6ca3026e3e4` | Ancestor |
| `refresh-error-localization-99b21` | `dc5989d046997c0c71c03c885510ed17b3bf7a28` | Ancestor |
| `research/phase1-carry-transducer` | `93d62573a78cfdcc9e97c4be23cd9f10e310850c` | One unmerged candidate commit: integer/oracle model, explicitly not an encrypted producer or public admission |
| `public-refresh-localization-2026-10-24` | `5bd657bb6aec50f8b411ec9534735deaa6dd4b7e` | Separate localization/accounting commits; integrated `dc5989d` supplies the cited native carry identity |
| `fix/public-refresh-research-gates` | `71fdbaf6ebb6df0e65070a0c347373b6f422b7f8` | Tip has a separate timing-test follow-up; the PR #201 research merge is already an ancestor |

The depth, carry, PR #201 merge, scheduler, stale-diagnosis and mask-fix
commits cited in the findings table were all checked as ancestors of `88a7bda`.

Passed on the reviewed snapshot:

```text
python3 scripts/check_public_refresh_status.py --self-test
Refresh status routing and historical evidence checks passed.
```

Focused Rust execution used pinned Rust 1.89.0, the existing local dependency
cache, default features plus `allow_insecure`, and optimized test code with
debug assertions. The command was bounded by `timeout 180`; it completed in
94 seconds of compilation plus 0.67 seconds of test execution:

```bash
env PATH=/workspace/.tooling/rustup/toolchains/1.89.0-x86_64-unknown-linux-gnu/bin:/usr/local/bin:/usr/bin:/bin \
  CARGO_HOME=/workspace/.tooling/cargo RUSTUP_HOME=/workspace/.tooling/rustup \
  CARGO_TARGET_DIR=/tmp/nine65-refresh-review-target CARGO_PROFILE_TEST_OPT_LEVEL=2 \
  cargo test --offline --locked -p nine65 --features allow_insecure \
  --test time_crystal_verification symmetric_depth_is_finite_and_noise_limited \
  -- --exact --nocapture
```

```text
SECURE_128 symmetric mul-by-1: EXACT to depth 3 (floor 3, cap 16, no bootstrap); first wrong decryption at depth 4
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 6 filtered out
```

Availability of the pinned compiler in this workspace does not establish that
it was available in the report author's different environment. This test
reproduces a correctness result, not the report's release timing measurements.

Four existing unit regressions also passed, each with exactly one test
executed and zero ignored. They used the same environment and Cargo options,
replacing the integration-test arguments with `--lib TEST_NAME -- --exact
--nocapture`:

* `ops::bootstrap::tests::zero_noise_phase1_carry_witness_secure128`:
  proves failure of component rounding even for the manufactured zero-noise
  phase at the shipped modulus. Compilation took 133 seconds under a
  180-second cap; execution took 0.33 seconds.
* `ops::bootstrap::tests::public_phase1_is_typed_fail_closed`.
* `params::secure_configs::tests::public_refresh_support_requires_sound_phase1`.
* `ops::symmetric_bootstrap::tests::symmetric_encrypt_mask_is_uniform_over_full_q`.

The last three commands each had a 30-second timeout. The documentation status
checker, local Markdown link targets and `git diff --check` passed. This is
five focused Rust regressions, not a workspace sweep or scheduler rerun.

The original benchmark harness/raw outputs and `sym_refresh_lab.py` were not
present in this checkout. The report's timings, 300-case toy result and
3,349,152-case count were not independently reproduced. The named CRAM-Proofs
package was not located in the local checkout or repository-name search;
its omitted files and complete theorem application remain unverified here.
No new native full encrypted refresh, security proof or external attestation
is claimed.
