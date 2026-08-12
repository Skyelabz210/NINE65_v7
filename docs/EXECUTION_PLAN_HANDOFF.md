# Execution Plan — Boilerplate & Medium-Hard Follow-ups

**Audience:** an autonomous coding model picking up after the audit-verification
pass on branch `claude/tool-installation-sth96a` (PR #39).
**Prerequisite reading:** `docs/AUDIT_VERIFICATION_2026-08-12.md` (what changed
and why), `CLAUDE.md` (project rules).

## Context

The heavy lifting is done on PR #39: the anchor basis is now dimension-keyed
(5 primes for n ≤ 8192 — byte-identical to before; 10 primes for n = 16384),
`extract_k_rns_level` caps U256 Garner reconstruction at 8 anchors and
verifies the remaining lanes as integrity witnesses, and secure_256/secure_192
ct×ct multiplication passes the strict public-mode gates with exact
decryption. Three layers of pre-existing test-build rot were also cleared
(`noise_profile`, `fhe-service` test helpers, and two unimplemented metadata
contracts pinned by `rns_context_metadata_regression.rs` /
`dual_rns_context_metadata_regression.rs`).

What remains is cleanup, calibration, and hardening — none of it blocks the
PR, all of it is well-scoped below.

## Non-negotiable rules (from CLAUDE.md, enforced by tests/gates)

- ZERO floats anywhere in the workspace. Integer-only arithmetic.
- Constant-time ops for security-sensitive paths; `allow_insecure` configs are
  blocked in release.
- Deterministic, bit-identical results across platforms.
- n ≤ 8192 anchor behavior must stay **byte-identical** (5 primes; no witness
  path). Do not change gate thresholds in `noise/boundary.rs` (80%/90%).
- Build: `cargo build --release --workspace --exclude nine65-python --exclude nine65-wasm`
- Full suite: same command with `test`. It must end fully green — a compile
  failure in ANY test target masks later targets, so re-run until you see
  actual `test result:` lines for every crate.

---

## Tier 1 — Boilerplate (mechanical, low risk)

### B1. Warning sweep
`cargo test --release --workspace ...` currently emits ~13 warnings in nine65
plus 6 in fhe-service. Fix, don't suppress (except where noted):
- `crates/nine65/src/ops/auto_bootstrap.rs:8` — unused `Nine65Error` import.
- `crates/nine65/src/arithmetic/rns.rs:91` area — `let mut limbs` doesn't need `mut`.
- `crates/nine65/src/arithmetic/k_elimination.rs:580/606/632` —
  `validate_alpha_family` / `validate_beta_family` / `validate_cross_family`
  are dead. Check git history first: if they were meant to be wired into
  `KElimination::for_fhe` validation, wire them; otherwise delete.
- `crates/nine65/src/ops/bootstrap.rs:752` — deprecated `ke.capacity()`;
  replace with `try_capacity()` / `capacity_bit_length()` per the deprecation note.
- fhe-service unused-import warnings.

### B2. Documentation truth pass
- `CLAUDE.md`: performance baselines for secure_192/secure_256 are stale — the
  n = 16384 tiers now carry 10 anchor lanes instead of 5 (mul/encrypt slower,
  and secure_256 mul *works* now, which the old table can't show). Re-measure
  (see M2) then update. The secure_128 n was already corrected to 8192.
- `crates/nine65/src/ops/rns_fhe.rs` lines ~2745/2862/2956: assertion messages
  still say canonical_anchor_primes_for_n "provides 5 anchors" — update to
  reflect the dimension-keyed 5/10 split.
- `crates/nine65/src/arithmetic/rns.rs`: the big comment block above
  `extract_k_rns_level` (~line 1330) still narrates the old "always
  reconstruct from the FULL canonical anchor set" fix. It's now capped +
  witness-verified; rewrite the block to match the code.

### B3. Test symmetry
- `crates/nine65/tests/anchor_drift_diagnostics.rs`: add a secure_192
  public-mode mul roundtrip mirroring
  `test_secure_256_mul_succeeds_with_10_anchor_basis` (secure_192 was at 100%
  utilization before this PR; pin that it now works and stays < 80%).

---

## Tier 2 — Medium

### M1. Scalar-aware `mul_plain_cost` (deferred tarball idea)
`crates/nine65/src/noise/budget.rs:224` — current cost model ignores scalar
magnitude: `mul_plain_cost(config) = scalar_bit_length(config.t) * 1000`.
Change to `mul_plain_cost(scalar: u64, config) = (scalar_bits + t_bits) * 1000`
(see the tarball variant quoted in the audit report §3). Call sites:
`crates/nine65/src/ops/homomorphic.rs:352` (pre-flight — use a conservative
representative scalar) and `:412` (actual scalar `m`).
**Required companion work:** a calibration test that multiplies by small vs
large scalars and asserts measured noise growth (via
`decrypt_dual_with_diagnostics` margins, see `tests/noise_profile.rs` for the
measurement pattern) brackets the predicted cost. Check
`ops/auto_bootstrap.rs` threshold tests still pass — the cost model feeds
auto-bootstrap triggering.

### M2. Re-benchmark n = 16384 tiers
Run `cargo test -p nine65 --lib --release ops::gso_fhe::depth_benchmarks::... -- --nocapture`
and the `nine65_bench` bin for secure_192/secure_256. Record encrypt/add/mul/
decrypt times with the 10-anchor basis, update `CLAUDE.md` and any
`docs/` baseline files. Note in the results that secure_128 numbers are
unchanged by construction.

### M3. Latent hazard: sentinel-product inverses in `DualRNSContext::new`
`crates/nine65/src/arithmetic/rns.rs` (~line 985): `main_inv_anchor_rns` is
computed as `mod_inverse(main_product % pi, pi)` — but `main_product` is the
**0-sentinel** u128 when M overflows (true for secure_192/256!). The values
are garbage on those configs; they're only *currently* harmless because the
U256 path (`extract_k_rns_level`) recomputes inverses from `m_level`. Fix
properly: compute `M mod pi` from `main_product_limbs` (new exact field, see
`product_limbs_u64`) so the precomputed inverses are correct for any M, and
add a regression test asserting `main_inv_anchor_rns[i]` equals the inverse
derived from the limb product for secure_256. Audit the u128 legacy path
`extract_k_rns` (rns.rs:~1290) for the same hazard and add a loud guard if it
is ever called with sentinel products.

### M4. Cap remaining full-anchor U256 reconstructions
`crates/nine65/src/ops/rns_fhe.rs:6237 / 7005 / 7104` (test-cfg diagnostics)
call `to_u256_level(&…, ctx.dual_rns.anchor.primes.len())`. With a 10-anchor
context that Garner product is ~315 bits and `U256::mul_u64` will
assert-overflow. They only run with small insecure configs today. Make them
robust: reconstruct over `ctx.dual_rns.k_reconstruction_anchor_count()`
anchors instead of the full set (same capping rule as production). Same
review for `crates/nine65/src/ops/rns_fhe.rs:10901`-area diagnostics.

### M5. fhe-service secure_256 end-to-end test
`crates/fhe-service` now sits on a working secure_256 tier. Add a service
test: create session at secure_256, encrypt two values, multiply
(public mode), decrypt, assert product and noise-budget bookkeeping. Follow
existing test patterns in `crates/fhe-service/src/` `#[cfg(test)]` modules.

---

## Tier 3 — Medium-hard

### H1. Witness dissent as typed error, not panic
`extract_k_rns_level` (rns.rs, witness block added in this PR) panics on
witness disagreement. Production-grade behavior: propagate
`Nine65Error::IntegrityFailure` (new variant) through `k_elim_rescale_dual`
→ `mul_dual_*` so `mul_dual_public` returns `Err` instead of aborting the
process. Constraint: `mul_dual_symmetric` returns a bare ciphertext (no
Result) — decide between (a) making the internal rescale fallible and
panicking only at the symmetric boundary, or (b) a deprecation-path signature
change. Keep the loud-failure guarantee either way; a silent fallback is not
acceptable (see AUDIT_VERIFICATION §2.2 for why).

### H2. Deep-circuit chain test at secure_256
Add an integration test chaining 3–5 public-mode multiplications at
secure_256 (with relinearization), asserting exact decryption at each depth
and that the witness lanes stay consistent. This exercises k growth toward
the A_recon ceiling. If depth-3+ trips the 80% gate, that is the *gate
working* — pin the exact depth where it fires as a regression contract, and
document the depth budget in CLAUDE.md.

### H3. Constant-time policy for the witness path
The witness check computes `magnitude.mod_u64(a_w)` (variable-time) on
k-derived data, matching the existing variable-time Garner in
`crt_reconstruct_u256`. `U256::mod_u64_ct` exists (rns.rs:~164) but is
bit-by-bit/slow. Decide and document a policy: either (a) k-residue
reconstruction is declared non-secret-dependent (write the argument down in
`docs/`, citing where k derives from), or (b) switch the witness + Garner
mods to a CT limb-based reduction (implement a faster `mod_u64_ct` via
Horner over limbs with CT select, ~8 mulmods instead of 256 iterations).
Do not silently mix the two postures.

### H4. Bootstrap paths at secure_256
`bootstrap()` / `bootstrap_with_ksk()` / `AutoBootstrapEvaluator::mul_auto`
have never run on a working secure_256 tier. Run
`cargo test -p nine65 --lib --release -- bootstrap` plus the
`bootstrap_integration` target, then add one secure_256 auto-bootstrap chain
test (mul_auto until a bootstrap triggers, assert exact recovery). Expect
slow tests — gate behind `--ignored` if wall-clock is prohibitive, but they
must exist and pass on demand.

---

## Verification checklist (run after every tier)

```
cargo build --release --workspace --exclude nine65-python --exclude nine65-wasm
cargo test  --release --workspace --exclude nine65-python --exclude nine65-wasm
cargo test -p nine65 --test anchor_drift_diagnostics --release
cargo test -p nine65 --test rns_context_metadata_regression --release
cargo test -p nine65 --test dual_rns_context_metadata_regression --release
cargo test -p nine65 --test noise_profile --release
cargo test -p fhe-service --release
```

All must be green with zero compile errors in every test target. Commit per
tier with descriptive messages; push to the working branch and let PR CI run.
