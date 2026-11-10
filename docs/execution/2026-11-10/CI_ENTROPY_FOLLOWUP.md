# CI follow-up after native entropy integration

Source diagnosis: main `676c4ec68ec497ff5ef2bbc4697393ec9090a7bc`.
This follow-up changes harness/evidence configuration, not library arithmetic,
RNG policy, native refresh, or security admission.

## Current failures and scoped repairs

- [Static analysis](https://github.com/Skyelabz210/NINE65_v7/actions/runs/42756770063/job/129632952757)
  counts 35 panic sites against a baseline of 33. The two additions are the
  existing infallible `BFVEncryptor::encrypt_poly` and
  `BFVEncryptor::encrypt_poly_with_rng` APIs, now wrapping their typed `try_*`
  counterparts. They fail closed on forbidden release entropy. Removing those
  refusals would regress the boundary. The reviewed budget becomes 35; unwrap
  and expect budgets are unchanged. This is an explicit backlog admission,
  not removal of the panic sites or a claim of panic-free APIs. Callers that
  require returned errors must use the new fallible APIs.
- [Fuzz Smoke](https://github.com/Skyelabz210/NINE65_v7/actions/runs/42756769959)
  invoked seeded arithmetic targets with `--release`, disabling debug assertions.
  Both failed at `KeySet::generate`'s correct rejection of `ShadowHarvester`,
  before encryption/decryption arithmetic. Run them in an optimized development
  profile, preserving seeded reproduction, overflow checks, sanitizers and
  release entropy refusal. The excluded fuzz package's lockfile is synchronized
  with the current path dependencies (clockwork-core, crc32fast and
  nexgen_rational replace the obsolete blake3 dependency graph).
  Compile-time guards catch accidental release-profile
  misuse. No `allow_insecure` release bypass is added.
- [Audit Remediation](https://github.com/Skyelabz210/NINE65_v7/actions/runs/42756770041)
  and [CRAM Recumbency](https://github.com/Skyelabz210/NINE65_v7/actions/runs/42756769914)
  both compute `PASS` and then fail the current-ledger diff. Only `rns.rs`'s
  source hash and the derived evidence hash differ. Regenerate the explicitly
  mutable `modulus_class_audit_current.json` with the actual Rust catalogue
  cross-check. Historical artifacts remain unchanged.
- [Strict comparative scale](https://github.com/Skyelabz210/NINE65_v7/actions/runs/42756769997)
  reports two completed depth chains, two unsupported cases, zero wrong
  plaintexts and zero supported-operation correctness failures. The classifier
  preserves the retired legacy multiplication refusal (`refused-#135`) as
  unsupported, not PASS. This is incomplete capability coverage, not evidence
  that the newly integrated entropy guard broke arithmetic. The user explicitly
  asked that diagnostics not stall active development. This known-incomplete
  sweep is now manual-only via `workflow_dispatch`; the strict runner,
  unsupported classification, artifact capture and failing exit are unchanged.
  Its quick and configured scale jobs remain runnable. Passing automated gates
  do not establish full comparison coverage or resolve issue #135.

The exact-source CI Fast Gate and MEDIUM full workspace suite passed. Optional
skipped jobs and the failed workflows are not included in that claim.

## Validation

On the source base above plus this harness/configuration patch:

- `python3 scripts/test_audit_modulus_classes.py`: 8 controls passed. The audit
  was regenerated twice with Rust 1.89.0 and produced identical output. Only
  `source_sha256.rns.rs` and `evidence_sha256` changed; all audited facts are
  identical to the prior ledger and status remains `PASS`.
- `bash scripts/check_no_panics.sh ratchet`: passes with the reviewed 35-site
  budget. An isolated synthetic source containing 36 panic sites still fails.
- `python3 scripts/test_benchmark_contract.py`: 21 controls passed, including
  unsupported, wrong-plaintext and missing-result distinctions. The comparative
  workflow parses as dispatch-only and both strict post-artifact exits remain.
- `cargo +nightly-2025-08-04 fuzz build fuzz_encrypt_decrypt --release`
  fails at the new explicit compile-time research-profile guard, as intended.
- `cargo +1.89.0 test --locked --release -p nine65 --test native_key_entropy`:
  7 passed. Both newly reviewed infallible wrappers reject deterministic release
  entropy, their fallible counterparts return typed errors, and secure
  constructors/encryption roundtrips remain available.
- Five actor-bypass controls, actor-independent-job source check, claim registry,
  stale-claim/security-claim gates, workspace formatting, changed-target Rust
  formatting, fuzz locked metadata, workflow parsing and `git diff --check`
  passed.
- All five actual libFuzzer targets pass 20-second bounded runs (21 seconds
  observed each), with seed 42, nightly-2025-08-04, cargo-fuzz 0.13.2, `--dev`
  and AddressSanitizer: encrypt/decrypt 756 inputs, homomorphic 3,516,
  deserialize 1,105,908, K-Elimination 1,059,334, NTT 2,304. These counts include
  inputs that the harness rejects as too short, not that many encryptions.
  The encrypt/decrypt run reused the corpus generated during the initial run.

Local sanitizer limitation: the first encrypt/decrypt invocation completed
2,160 inputs without an arithmetic failure, then LeakSanitizer failed at
shutdown because this container uses ptrace. Successful local reruns set
`ASAN_OPTIONS=detect_leaks=0`; address checking remained enabled. The workflow
has no such override and retains its normal hosted sanitizer configuration.
Local smoke success is not a hosted result or a leak-free guarantee.

The full workspace suite, full audit/recumbency workflows and strict scale
matrix were not rerun locally for this configuration-only follow-up. Their
previous exact-source results and limitations are stated above; no refreshed
native-execution or production-security claim is made.
