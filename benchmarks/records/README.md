# NINE65 `fhe-comparison-record-v1` records — secure_128, N=8192, scalar-mod-t

This directory is additive only. Nothing under `crates/` was deleted, rewritten,
or "optimized" to produce these records. The only executable added was
`crates/nine65/examples/comparison_record_probe.rs`, which calls the existing
public API (`RNSFHEContext::{generate_keys_dual, encrypt_dual, decrypt_dual,
add_dual, mul_dual_symmetric}`) in a tight timed loop and prints integer
nanoseconds. It does not touch the constant-time arithmetic layer, does not
change any parameter set, and is picked up by cargo's example autodiscovery,
so `crates/nine65/Cargo.toml` was not edited to register it.

## Files

| File | Contents |
|---|---|
| `hardware.json` | The hardware document (CPU, RAM, OS, kernel, toolchain, build profile, runtime pinning). Its canonical-JSON sha256 is the `hardware_fingerprint` quoted in every record below. |
| `hardware.sha256.txt` | Both sha256 values for `hardware.json` (canonical-JSON hash used as the fingerprint, and a plain file-bytes hash for reference), with exact reproduction commands. |
| `nine65_keygen_secure128.json` | `fhe-comparison-record-v1` for `RNSFHEContext::generate_keys_dual` |
| `nine65_encrypt_secure128.json` | same, for `encrypt_dual` |
| `nine65_decrypt_secure128.json` | same, for `decrypt_dual` |
| `nine65_add_ct_secure128.json` | same, for `add_dual` |
| `nine65_mul_ct_secure128.json` | same, for `mul_dual_symmetric` |
| `raw/comparison_record_probe_run{1,2,3}.json` | Full raw probe output for three independent runs, kept for cross-validation. `run2` is the source of the five records above. |
| `build_records.py` | The exact, auditable script that turned `raw/comparison_record_probe_run2.json` into the five records (median reduced to lowest-terms numerator/denominator, no numbers invented). |

No packed/SIMD-slot record is present. Slot batching is permitted by the
parameters (`t=65537 ≡ 1 mod 2N` for `N=8192`) but is **unimplemented** —
there is no plaintext-side NTT over `t`, no vector encrypt/decrypt entry
point, and no encoder anywhere in the workspace (verified by grep against
`encrypt_dual_vec` / `slot_encode` / `pack_slots` — zero hits). Per the
"additive only, do not build a replacement" rule, no encoder was built, so
no packed multiply could be timed. `raw/comparison_record_probe_run2.json`
records `"packed": {"permitted_by_parameters": true, "measured": false, ...}`
honestly instead of a fabricated number.

## How these were measured

```
cargo build --release -p nine65 --example comparison_record_probe
RAYON_NUM_THREADS=1 taskset -c 0 ./target/release/examples/comparison_record_probe
```

Single thread, pinned to core 0. `/proc/loadavg` was checked immediately
before each of the three runs (0.55, 0.42, 0.64 — all quiet, no other
CPU-bound process on the host per `ps aux --sort=-%cpu`). The three runs
agree with each other to within ~1-2% on every operation (see
`raw/comparison_record_probe_run{1,3}.json`), so `run2` is not a fluke of a
particularly quiet or particularly loaded window — it sits in the middle of
the three.

**These absolute numbers are noticeably slower than the "MEASURED BASELINE"
figures quoted in the task brief** (e.g. `mul_ct` ≈ 215 ms here vs. ≈ 105 ms
in the brief; `encrypt`/`decrypt`/`keygen` roughly 2x the brief's figures;
`add_ct` is close, within ~6%). `add_ct` being the outlier that agrees closely
while the others don't is itself informative: it is the only one of the five
whose cost is dominated by RNS-lane addition rather than by an NTT-heavy
inner loop, so this pattern is consistent with a difference in per-cycle NTT
throughput between the two machines, not a code change. This container's CPU
is `Intel(R) Xeon(R) Processor @ 2.80GHz` under KVM with **no boost clock
exposed to the guest** (see `hardware.json`) — a different, and evidently
slower for this workload, virtual machine than whatever produced the brief's
baseline. The brief's own baseline numbers are not reproduced or asserted
here; only what this run actually measured, on the hardware this run actually
measured it on, is recorded. That is the entire point of shipping
`hardware.json` and its fingerprint alongside every record.

## What "comparable" means — quoted from `benchmarks/comparative/README.md`

> Two records are ranked only when every field in `compatibility` and the
> `operation` field are identical. A mismatch produces an `INCOMPARABLE`
> result with the differing fields listed.
>
> This deliberately blocks misleading comparisons such as:
> - BFV ciphertext multiplication versus TFHE programmable bootstrapping;
> - scalar messages versus packed SIMD throughput;
> - 98-bit estimates versus 128-bit estimates;
> - different CPUs or thread counts;
> - simulated refresh versus real bootstrap;
> - N=1024 testing parameters versus N=4096 production parameters;
> - cold key generation versus warm key retrieval;
> - published figures from another machine versus local measurements.

Applying that rule to what exists today:

### (a) INCOMPARABLE to TFHE programmable bootstrapping (any library)

Differing fields: `operation` (`mul_ct`/`encrypt`/`decrypt`/`add_ct`/`keygen`
vs. `bootstrap`/`pbs`), `compatibility.scheme` (`BFV-DualRNS` vs. TFHE/GSW),
`compatibility.refresh_kind` (`none` here — no bootstrap ever runs in these
five records — vs. a real PBS elsewhere). The contract names this exact
comparison as one it exists to block.

### (b) INCOMPARABLE to the Feb 2026 report and the harness README example (n=4096)

Both cited different parameters:

| Field | These records | Feb 2026 report (`n=4096, q=998244353`) | harness README example (`n=4096, log_q=90`) |
|---|---|---|---|
| `compatibility.n` | 8192 | 4096 | 4096 |
| `compatibility.log_q_bits` | 90 | not restated as a full RNS product here | 90 (matches by coincidence at n=4096, not the same ring) |
| `compatibility.hardware_fingerprint` | `09fd291610c1ec6ef6d42ba79896772de5fa10e1a4f933384417676527ba3f2d` | absent / different machine | absent / different machine |
| `provenance.commit` | `28e7ce2fb5ccf7c8823170603821e08bd8093cce` | different session, no commit recorded | example record in the README, not a real run |

`n` alone already produces `INCOMPARABLE` under the contract's own listed
example ("N=1024 testing parameters versus N=4096 production parameters" —
the same principle applies to 4096 vs. 8192). Do not rank NINE65's own
historical n=4096 numbers against these n=8192 numbers.

### (c) INCOMPARABLE to any packed/SIMD throughput number from another library

Every record in this directory carries `compatibility.slots: 1` and
`compatibility.plaintext_semantics: "scalar-mod-t"`. A competitor's packed
BFV/CKKS throughput number (amortized cost per slot across thousands of
slots) differs in both `slots` and, typically, `plaintext_semantics`
("packed"/"simd" rather than "scalar-mod-t"). Per the contract: "scalar
messages versus packed SIMD throughput" is explicitly listed as a blocked
comparison. NINE65 itself cannot yet produce the other side of that
comparison either — see "No packed/SIMD-slot record" above — so there is
currently no NINE65 record, packed or otherwise, that may be placed next to
a packed competitor number.

### What these five records ARE comparable to

Another `fhe-comparison-record-v1` record — from NINE65 or any other adapter
— that matches every one of: `scheme=BFV-DualRNS`,
`plaintext_semantics=scalar-mod-t`, `target_security_bits=128`, `n=8192`,
`log_q_bits=90`, `plaintext_modulus=65537`, `slots=1`, `refresh_kind=none`,
`hardware_fingerprint` equal to this machine's (i.e. actually run on this
same host, or a host with a bit-identical `hardware.json`), `threads=1`,
`build_profile=release-fat-lto-cgu1`, and the same `operation`. In practice
that means: rerunning this exact probe on this exact container is the only
thing today's records can be safely compared against; even a rerun on a
*different* container needs its own `hardware.json` and will differ in
`hardware_fingerprint`, which is disclosed rather than hidden.

## Honesty notes on individual fields

- **`log_q_bits`**: computed, not guessed. `998244353 * 985661441 * 754974721
  = 742843007632383847780319233`, whose bit length is 90
  (`128 - leading_zeros() = 90`), matching `secure_128`'s documented "~90
  bits" in `crates/nine65/src/params/secure_configs.rs`.
- **`security_estimator`**: named as exactly what it is — the repository's
  own in-tree `LatticeSecurityEstimator` (CoreSVP + MATZOV cost models,
  integer-millibits arithmetic), which is a deterministic screening gate
  built into this codebase, **not** an independent third-party lattice
  security certificate (e.g. not a run of the external Sage/Python
  `lattice-estimator`). The gate's own output for this configuration is
  recorded in the field verbatim: `core_svp_effective_bits=259,
  matzov_effective_bits=233, binding_bits=233, meets_both=true`.
- **`build_profile`**: `"release-fat-lto-cgu1"` is read from the workspace
  root `Cargo.toml`'s `[profile.release]` (`opt-level=3, lto="fat",
  codegen-units=1, panic="abort"`) — the profile cargo actually applies.
  `crates/nine65/Cargo.toml` declares its own `[profile.release]`/`[profile.bench]`
  too, but cargo prints `warning: profiles for the non root package will be
  ignored, specify profiles at the workspace root` for those, confirmed at
  build time in this session, so the workspace-root profile is the one that
  governs these binaries.
- **`threads`**: 1, genuinely — `RAYON_NUM_THREADS=1` and `taskset -c 0`.
- **`refresh_kind`**: `"none"` — no bootstrap call appears anywhere in the
  probe; only keygen/encrypt/decrypt/add/mul are exercised.
- **`provenance.commit`**: the literal output of `git rev-parse HEAD`
  (`28e7ce2fb5ccf7c8823170603821e08bd8093cce`) as instructed. **Caveat**:
  the working tree was not clean at measurement time — other concurrent
  workflows had uncommitted edits in flight, including to
  `crates/nine65/src/ops/rns_fhe.rs` and
  `crates/nine65/src/params/secure_configs.rs` (files this task was told not
  to touch, and did not touch). `git stash create` (non-destructive: it
  builds a commit object without altering the working tree or index) was
  used to snapshot exactly what was on disk into commit
  `227bd869b53fccd5da8a915627ae41407dd07d81`, recorded in each record's
  `integrity_notes` block, so the exact measured source is resolvable via
  `git show 227bd869b53fccd5da8a915627ae41407dd07d81` for as long as that
  dangling object survives garbage collection. Before trusting these numbers
  as representative of `secure_128`, the actual `secure_128()` function body
  was diffed against HEAD and confirmed byte-identical in its parameters
  (`n=8192`, primes `[998244353, 985661441, 754974721]`, `t=65537`,
  `128`-bit target); the concurrent edits touching that file were confined to
  test code.
- **`hardware_fingerprint`**: sha256 of the canonical-JSON encoding of
  `hardware.json` (`json.dumps(obj, sort_keys=True,
  separators=(",", ":"))`, matching the convention already used by
  `scripts/normalize_nine65_bench.py:canonical_hash`), computed and verified
  in this session:
  `09fd291610c1ec6ef6d42ba79896772de5fa10e1a4f933384417676527ba3f2d`. A plain
  `sha256sum` of the raw file bytes is also recorded, in `hardware.sha256.txt`,
  for cross-reference, but is **not** the value used in the records (it is a
  different, non-canonical hash and would not match if `hardware.json` were
  re-serialized with different whitespace). Both values, and the exact
  commands to reproduce each, are in `hardware.sha256.txt`.
- **`samples_ns`**: raw integer nanoseconds exactly as printed by the probe,
  sorted ascending, nothing dropped, nothing smoothed.
- **Median**: reported as an exact reduced numerator/denominator pair inside
  `derived_statistics_not_part_of_contract_gate` (e.g. `mul_ct`:
  `214853118/1`; `keygen`: `18715545/2`), computed by taking the
  average-of-middle-two-samples fraction the probe already emits and
  reducing it with Python's `fractions.Fraction`. This block is explicitly
  labeled as *not* part of the contract's comparison gate — the contract's
  own analyzer recomputes statistics straight from `samples_ns` — so it
  cannot silently disagree with a re-derivation.
- **`p95_ns_nearest_rank`**: nearest-rank p95 (`rank = ceil(95*n/100)`),
  integer, as computed by the probe.

## Numbers, for reference (all five, run2, n=8192, secure_128)

| Operation | n | min ns | median (exact) | p95 (nearest-rank) | max ns | correctness |
|---|---:|---:|---:|---:|---:|---|
| `keygen` | 40 | 9,275,136 | 18,715,545/2 (9,357,772.5) | 9,752,376 | 10,492,441 | 5/5 |
| `encrypt` | 40 | 18,999,921 | 19,357,998/1 | 20,397,690 | 22,390,196 | 9/9 |
| `decrypt` | 40 | 8,360,386 | 17,015,479/2 (8,507,739.5) | 9,336,475 | 10,619,836 | 9/9 |
| `add_ct` | 100 | 759,830 | 1,613,259/2 (806,629.5) | 870,003 | 1,017,256 | 6/6 |
| `mul_ct` | 20 | 212,028,726 | 214,853,118/1 | 219,752,516 | 221,174,315 | 7/7 |

"correctness" is `trials`/`total`, 0 failures in every case (round-trip or
add/mul-then-decrypt checks against a plaintext tracked in the clear; see
`crates/nine65/examples/comparison_record_probe.rs` for the exact operand
lists).
