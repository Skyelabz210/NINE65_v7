# T6 — CI Quality Gates (v7 + cram-substrate)

**Tier: HANDOFF-SAFE.** Mechanical workflow-file authoring, modeled directly
on an existing house pattern. No evaluator logic changes.

**Status: LANDED (2026-08-26).**
`NINE65_v7/.github/workflows/cram_public_gates.yml` (correctness job:
build + cram_public_mode + m2b_manufactured_rescale + cram_public_guardrails
+ in-module guardrails + M3 tests + arrow-harness witnesses +
unified_rescale module tests, all blocking; timings job: informational,
`continue-on-error: true`) and `cram-substrate/.github/workflows/audit.yml`
(audit.py 8/8 + pytest, no extra deps beyond pytest — the package and
audit script use only the standard library). Every command in both
workflows was run locally before being committed to the workflow file, per
this card's verification requirement.

## Goal

Two new CI workflows:

1. NINE65_v7: `.github/workflows/cram_public_gates.yml` — builds and runs
   the full CRAM-public + guardrail test surface on every push/PR touching
   it.
2. cram-substrate: `.github/workflows/audit.yml` — runs the Python
   arrow-harness audit (`python3 -m cram_fhe.audit`, must stay 8/8) and the
   pytest suite on every push. **This repo currently has no
   `.github/workflows/` directory at all** — verify with `ls
   .github/workflows/` before assuming one exists to extend.

## Files (read these first)

- `.github/workflows/cram_residue_native_gates.yml` (NINE65_v7) — the house
  pattern for a cram-family gate workflow: `pull_request` with `paths:`
  filters, `push: branches: [main]`, a `concurrency:` group with
  `cancel-in-progress`, `permissions: contents: read`, and jobs built from
  `actions/checkout@v4` + `dtolnay/rust-toolchain@stable`. Copy this
  structure; do not invent a different shape.
- `.github/workflows/` (NINE65_v7, list the directory) — other `cram_*.yml`
  workflows for additional idiom reference (matrix profiles, artifact
  upload) if useful, but `cram_residue_native_gates.yml` alone is enough to
  copy from.
- `crates/nine65/Cargo.toml` — the `[[test]]` blocks with `required-features
  = ["allow_insecure"]` for every CRAM-public test target
  (`cram_public_mode`, `m2b_manufactured_rescale`, `cram_public_guardrails`,
  and whatever T5 added as `cram_public_timings`) — the workflow's test
  invocations must pass `--features allow_insecure` or they will fail to
  even compile (this is not a workflow bug, it's how these targets are
  gated; do not try to work around it, just pass the feature flag).
- cram-substrate `cram_fhe/audit.py` — run via `python3 -m cram_fhe.audit`;
  read its `if __name__ == "__main__"` exit-code behavior (must exit
  nonzero on any of the 8 sections failing, or CI will report green on a
  failing audit — verify this before wiring it into CI, don't assume).
- cram-substrate `tests/test_cram_fhe.py` — the pytest suite; check for a
  `requirements.txt` / `pyproject.toml` to know what to `pip install` in
  CI (there was none found as of this card being written — verify again,
  it may have been added since).

## DO NOT

- **Gates never soften to warnings.** A red gate is work to be done, not
  noise to be silenced — do not add `continue-on-error: true` or move a
  failing check to a non-blocking job "to unblock the PR." This repo's
  own babysit/steward posture (see the top-level session instructions on
  driving a PR to green) treats a red CI check as something to fix, not
  route around.
- **Do not invent a different workflow shape** than
  `cram_residue_native_gates.yml`'s. Consistency with the existing
  `cram_*.yml` family matters more than any individual preference here.
- **Do not skip `--features allow_insecure`** on any CRAM-public test
  invocation — every relevant `[[test]]` target in `Cargo.toml` requires it
  (see Files above); omitting it produces a confusing "no test target"
  failure, not a clean skip.
- **Do not assume cram-substrate has a `.github/workflows/` directory** —
  verify with `ls` first; if it doesn't exist, `mkdir -p .github/workflows`
  is a normal, safe, additive action (not a destructive one), but don't
  skip the check.

## Steps (NINE65_v7)

1. `ls .github/workflows/` and read `cram_residue_native_gates.yml` in full.
2. Create `.github/workflows/cram_public_gates.yml`:
   - `on: pull_request: paths:` — `crates/nine65/src/ops/cram_public.rs`,
     `crates/nine65/src/ops/rns_fhe.rs`, `crates/nine65/src/arithmetic/unified_rescale.rs`,
     `crates/nine65/src/params/manufactured.rs`, `crates/nine65/tests/cram_public_*.rs`,
     `crates/nine65/tests/m2b_manufactured_rescale.rs`,
     `crates/nine65/tests/residue_space_ciphertext.rs`, this workflow file itself.
   - `on: push: branches: [main]`.
   - `concurrency:` group keyed on `cram-public-${{ github.ref }}`, `cancel-in-progress: true`.
   - `permissions: contents: read`.
   - One job: checkout, install stable Rust toolchain, then run in sequence
     (or as separate steps — your call, but all must run):
     ```
     cargo build -p nine65 --release --features allow_insecure
     cargo test -p nine65 --test cram_public_mode --release --features allow_insecure
     cargo test -p nine65 --test m2b_manufactured_rescale --release --features allow_insecure
     cargo test -p nine65 --test cram_public_guardrails --release --features allow_insecure
     cargo test -p nine65 --lib --release cram_public_guardrail
     cargo test -p nine65 --test residue_space_ciphertext --release --features allow_insecure -- ct_multiply
     cargo test -p nine65 --lib --release arithmetic::unified_rescale
     ```
     (the last two are the "harness witnesses" and "unified_rescale module
     tests" the plan named — adjust the exact filter strings if the test
     names have moved by the time this runs; verify each command locally
     before committing the workflow).
   - If T5 has landed, add a non-blocking (`continue-on-error: true` is
     the ONE place this is acceptable — a slow perf number should not gate
     merges, only correctness should) step running the `--ignored` timing
     suite for visibility.

## Steps (cram-substrate)

1. `ls .github/workflows/` — confirm empty/missing.
2. Create `.github/workflows/audit.yml`:
   - `on: push`, `on: pull_request` (no path filters needed for a small
     repo — verify repo size/CI budget before adding narrow filters; if in
     doubt, run on every push).
   - Job: checkout, set up Python (`actions/setup-python@v5`, pin a
     version matching what's used locally — check for a `.python-version`
     file or ask if none found), `pip install` whatever `test_cram_fhe.py`
     and `cram_fhe/audit.py` need (check their imports; if there's no
     manifest, list what actually gets imported), then:
     ```
     python3 -m cram_fhe.audit
     pytest tests/ -q
     ```
   - The audit step MUST fail the job if any of the 8 sections fail —
     verify `audit.py`'s exit code behavior (see Files above) before
     trusting this.

## Commands (local verification before pushing either workflow)

```
# NINE65_v7
cargo build -p nine65 --release --features allow_insecure
cargo test -p nine65 --test cram_public_mode --test m2b_manufactured_rescale --test cram_public_guardrails --release --features allow_insecure

# cram-substrate
python3 -m cram_fhe.audit
pytest tests/ -q
```

## Acceptance criteria

- Both workflows run green on their respective PR branches
  (`claude/cram-fhe-reversible-residue-1mts3a`).
- NINE65_v7 workflow fails (red) if any CRAM-public test target fails —
  verify by temporarily breaking a test locally and confirming the exact
  same command fails, before trusting the CI config (do not push a
  deliberately-broken commit to verify this in CI itself).
- cram-substrate workflow fails (red) if any of the 8 audit sections fail
  or any pytest test fails.

## Escalate-if

- The cram-substrate repo turns out to need a dependency-pinning file that
  doesn't exist yet (`requirements.txt`/`pyproject.toml`) and it's unclear
  what versions are safe to pin — this is a small decision but touches
  reproducibility; a quick note to the owner beats guessing.
