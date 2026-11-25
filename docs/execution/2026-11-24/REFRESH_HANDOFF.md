# NINE65 refresh implementation handoff

**24 November 2026 · America/Chicago**

The trusted-key scalar refresh is implemented, tested and available in draft PR #207. The full hosted workspace test job passed. Two workflows failed on checks that also fail on the PR’s base. The timing collector has a verified repair on a separate branch. The production panic-pattern check remains above budget. The next integration decision belongs to the maintainer serializing changes to `main`. [PR #207](https://github.com/Skyelabz210/NINE65_v7/pull/207) · [Hosted full test job](https://github.com/Skyelabz210/NINE65_v7/actions/runs/45531662329/job/138928487093)

## Where to resume

| Item | Revision or location | State at handoff |
| --- | --- | --- |
| Integration base | `64c1c89b191093dc12cf81b87da5fb1a02c46dc1` | Verified remote `main` and PR base |
| Trusted-key implementation | `102601ba720f9f39c70ecb06c4a99de5d3252418` | Scalar decode, two secure refresh APIs and cross-basis encoding repair |
| Tested PR head | `48f5012480f53005aa288bdb9ede1fa944cba904` on `codex/trusted-scalar-refresh-2026-11-24` | Open draft, two commits, eight files, no submitted GitHub reviews or review threads at inspection |
| Historical investigation | `f867ad421ede5665070ce91f2a19ae96e593825d` on `codex/refresh-mode-review-2026-11-17` | Separate documentation branch |
| Timing-collector repair | `e8cb667f759381dff2997b90d259c6a174a4bc9a` on `codex/ct-evidence-inventory-2026-11-24` | Based on `main`, checked locally and fetched back from origin. Ready for serialized integration |
| This report and paper | `codex/refresh-handoff-2026-11-24`, based on the tested PR head | The handoff commit contains the report, paper, editable paper package and timing replay inputs |

The [implementation paper](../../../artifacts/execution/2026-11-24/trusted-scalar-refresh/paper/NINE65_Checked_Scalar_Refresh.pdf) derives the scalar decoder and the conditions for preserving a message. The [editable package](../../../artifacts/execution/2026-11-24/trusted-scalar-refresh/paper/NINE65_Checked_Scalar_Refresh_Source.zip) includes the LaTeX, figures, source manifest and raw benchmark data. The repository also carries a [short execution record](TRUSTED_SCALAR_REFRESH.md).

## Which operation a caller is selecting

| Mode | Contract and evidence |
| --- | --- |
| Trusted-key scalar | A caller with the matching secret key decodes coefficient zero and re-encrypts it on the full working basis. The other plaintext coefficients are discarded. The caller establishes scalar encoding, key provenance and sufficient remaining decode capacity. |
| Public leveled evaluation | Its public-key operations retain bounded arithmetic and explicit refusal. Public-only roundtrips and exact division with typed refusal were exercised during implementation. |
| Explicit public research refresh | `PublicRefreshCircuit` and its scheduler handle sealed polynomial ciphertexts under `allow_insecure`. Encrypted carry extraction, restoration and original-key return already have archived native evidence. The handoff reran reduced-ring scheduler tests. |
| Legacy Clockwork | Its default Phase-1 route lacks the required carry correction. Both production-boundary refusal regressions passed again at the PR head. |
| Interactive blind refresh, in-place snapping and a packed trusted-key API | Separate proposals. Blind refresh would need a protocol covering the whole service view and remote input authorization. Snapping would need a confidentiality argument for observers of both versions. A packed API would need coefficient-wise preservation and its own tests. |

Service and client modes retain their declared key holders and entry points. The distinction matters when reading a benchmark or deciding which API a service may call. [Mode matrix](../../SECURITY_MODE_MATRIX.md) · [Public refresh status](../../PUBLIC_REFRESH_STATUS.md)

## What changed, and what was already known

The checked decoder computes the constant term of the negacyclic product directly in each active main lane, then reuses the centered scalar decoder. It validates shape, residues and supported arithmetic width. A negative diagnostic margin triggers refusal. A positive margin can occur in the wrong decoding cell after excessive noise, so recoverability remains a caller precondition. [Decoder and differential tests](../../../crates/nine65/src/ops/scalar_decrypt_tests.rs)

`SymmetricBootstrap::bootstrap_secure` re-encrypts with a public key. `reencrypt_symmetric_secure` re-encrypts with the secret key. Both use OS randomness. Secret-key re-encryption now embeds the message with the same scale, `floor(Q_main/t)`, reduced into every main and anchor lane. An all-coefficient phase test checks the encoding and a subsequent multiplication. The former deterministic entry points still refuse use in release builds. [Implementation](../../../crates/nine65/src/ops/symmetric_bootstrap.rs) · [Release entropy tests](../../../crates/nine65/tests/native_key_entropy.rs)

The November 16 report correctly identified the scalar-wrapper and RNG gaps. Its depth-three result was already covered by a fixed-seed regression. Its one-unit explanation of the legacy failure missed measured carries of −18, −18 and +12. A working public research correction and a bounded scheduler both predated its snapshot. The original toy and raw benchmark harness were unavailable to the investigation. The subsequent CRAM collection made it possible to run the quotient verifier, which checked 1,183,744 congruences and 217,748 bounded recoveries. [History review against the report’s exact commit](https://github.com/Skyelabz210/NINE65_v7/blob/f867ad421ede5665070ce91f2a19ae96e593825d/docs/execution/2026-11-17/REFRESH_MODE_REVIEW.md) · [CRAM and implementation evidence](TRUSTED_SCALAR_REFRESH.md)

## Verification and performance

| Evidence | Result | Scope |
| --- | --- | --- |
| Scalar test filter, rerun at PR head | 29 passed, one historical ignore | Includes all 12 new decode and refresh regressions. Coverage includes reduced levels, all 697 phases of a small modulus, rejection paths, both OS-random routes and subsequent multiplication. |
| Release entropy, rerun at PR head | Eight passed | Includes refusal before sampling or counting on all three deterministic refresh wrappers. |
| Public and legacy boundaries, rerun at PR head | 11 scheduler regressions and two legacy refusals passed | Two reduced-ring seeds delivered 24 encrypted squares, six refreshes and 192 coefficient comparisons. The refresh-status self-test also passed. |
| Hosted PR job | Full test job passed, including the MEDIUM workspace tier, error variants, prepared-key sequential execution and Clockwork feature tests | Seven of nine PR-triggered workflows reported success. CI and Constant-Time Verification were red. |
| Paper and measurements | Verified the standalone PDF against the copy in the ZIP, its seven repository source hashes, the 21 raw pairs, all four medians and the 16 paired end-to-end wins | The paper contains nine pages. The paper and editable ZIP pass their integrity checks. |

In the matched release run on Rust 1.89.0 at `secure_128` (N = 8192), median coefficient-zero decode went from **2.062 ms to 0.199 ms**. Median decode plus public-key re-encryption went from **31.506 ms to 29.917 ms**, a **5.04%** reduction. One process and one key supplied 21 fresh matched inputs. Secret-key re-encryption has correctness coverage and awaits its own end-to-end timing. The earlier 10 ms figure used a different setup. [Raw CSV](../../../artifacts/execution/2026-11-24/trusted-scalar-refresh/secure_128.csv) · [Benchmark source](../../../crates/nine65/examples/trusted_scalar_refresh_timings.rs)

## Disposition of the two red workflows

**CI, production panic-pattern check.** The ratchet found 79 production `.expect` calls in `crates/nine65/src` against the committed allowance of 77. The scan returned the same result on clean checkouts of the base and PR head. The earlier optimization integration recorded three new U256 refusal sites and the removal of one existing call. A repair must preserve explicit refusal of unsupported conversions and the behavior of existing callers. [Hosted failure](https://github.com/Skyelabz210/NINE65_v7/actions/runs/45531662329/job/138928203087) · [Original integration record](../2026-11-10/FINAL_INTEGRATION.md)

**Constant-Time Verification, evidence collection.** The workflow executed 11 exact tests. Its collector expected 10 and missed the two observations from cached extraction at `secure_128` and `secure_192`. The old collector failed two of 16 controls on both base and head and classified the hosted archive as invalid. The isolated repair brings all 16 controls to passing. Replaying the original bytes produced **13 observations, 12 below threshold and one inconclusive**. The inconclusive result was the `secure_192` same-class control with t = 5.3392. The existing threshold is 5. The local replay supplies no new timing measurement or constant-time certification. The original hosted workflow remains red pending integration and a fresh run. [Collector repair](https://github.com/Skyelabz210/NINE65_v7/commit/e8cb667f759381dff2997b90d259c6a174a4bc9a) · [Hosted timing job](https://github.com/Skyelabz210/NINE65_v7/actions/runs/45531662018/job/138928202813) · [Hosted collector controls](https://github.com/Skyelabz210/NINE65_v7/actions/runs/45531662018/job/138928203040)

## Remaining work and acceptance criteria

| Order | Suggested owner | Deliverable and completion evidence |
| --- | --- | --- |
| 1a | CI maintainer | Integrate the isolated collector repair. A hosted run must enumerate 11 tests and 13 observations and preserve the harness verdict for each. |
| 1b | Arithmetic maintainer | Resolve the inherited U256 panic ratchet. Exercise empty and oversized bases and existing callers. Record the resulting ratchet count and reviewed compatibility decision. This can proceed alongside 1a. |
| 2 | Serialized integrator | Review PR #207 against the intended base, resolve the two workflow statuses, rerun the scalar, entropy, public and legacy checks, and record the integrated SHA. Carry the paper and handoff via the handoff-only commit once the implementation is in place. |
| 3 | Benchmark owner | Run matched native timings for both re-encryption routes on fresh and still-recoverable multiplied scalar inputs across independent keys. Check outputs outside the timed interval and retain raw pairs and variability. |
| Separate public research | Cryptography reviewer | Review the full joint publication graph, including self-key and return relations. Bind a conclusion or explicit remaining premise to the exact graph. |
| Separate public research | Parameter-review owner | Prepare an independent assessment of the exact distributions, moduli and cost models. Obtain owner authorization before any external contact and retain reviewer attribution and scope. |

The parameter evidence is already integrated into `main` through `a6780e9`. It includes 32 completed estimator jobs over eight distinct tuples. The integrated key-graph audit records 659 ciphertexts, 160 return channels and 5,184 finite channel equalities. The full correlated setup still lacks an established confidentiality argument and independent parameter attestation. Those two research tasks are independent of the trusted-key PR. The archived five-cycle native public run belongs to its recorded historical revision. A new native public run, packed refresh, blind service and snap implementation would each be separate work. [Estimator evidence](../2026-11-10/EXTERNAL_ESTIMATOR_EVIDENCE.md) · [Key-graph obligations](../2026-11-10/PUBLIC_KEY_GRAPH_EVIDENCE.md) · [Integration evidence](../2026-11-10/FINAL_INTEGRATION.md)

## Reproduction and artifact integrity

With pinned Rust 1.89.0, run the following at PR head `48f5012`. The [execution record](TRUSTED_SCALAR_REFRESH.md) includes the remaining named tests and the benchmark command.

```sh
cargo test --locked --config profile.test.package.nine65.opt-level=2 \
  -p nine65 --features allow_insecure --lib scalar_ -- --test-threads=1
cargo test --locked --release -p nine65 --test native_key_entropy
python3 scripts/run_public_refresh_research_gates.py --suite scheduler
python3 scripts/run_public_refresh_research_gates.py --suite production-boundary
bash scripts/check_no_panics.sh ratchet
```

For an offline timing replay, use the handoff checkout with the collector commit available locally. The [replay ZIP](../../../artifacts/execution/2026-11-24/trusted-scalar-refresh/ct-dudect-45531662018.zip) contains the status ledger and 11 test logs copied byte-for-byte from GitHub artifact `14984359254`. The hosted tests ran against merge checkout `cc3d0ece76b0c844f6fba6858b66e23767b3471b`.

```sh
replay_dir=$(mktemp -d)
unzip -q artifacts/execution/2026-11-24/trusted-scalar-refresh/ct-dudect-45531662018.zip -d "$replay_dir"
git show e8cb667f759381dff2997b90d259c6a174a4bc9a:scripts/summarize_ct_verdicts.py > "$replay_dir/collector.py"
python3 "$replay_dir/collector.py" --input-dir "$replay_dir/ct_dudect_tests" \
  --output "$replay_dir/summary.json" --markdown "$replay_dir/summary.md" \
  --source-sha 48f5012480f53005aa288bdb9ede1fa944cba904 \
  --checkout-sha cc3d0ece76b0c844f6fba6858b66e23767b3471b
```

| Artifact | SHA-256 |
| --- | --- |
| Paper PDF | `dcdb3c239d69624c13fbd51d818b3001d5655aa1d8781c00f54e7876930aa02c` |
| Editable paper ZIP | `14e14393d00245a06621440bccf70453cc48633f8846b9d2396f7d280ae089c4` |
| Matched-input CSV | `6327497ec5c8329d941628a0688018ee5149868c19b96ba6bb2b3680fd87f418` |
| Handoff timing replay ZIP | `d89d98faa662de7435d58ab8ef24a7fff5ca017820ace30e2b688f15f5d29b16` |
| Original GitHub timing ZIP | `b6ef4f1ac3d5eba7c2d4ef965055adfbdff869dba5f27da27648257ccf4413e2` |
