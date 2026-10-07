# PR #169 evidence — `c1a502c`

**Code SHA:** `c1a502cafaa90aeeb53b90e9df2c18097c42dab7`
**PR:** [#169](https://github.com/Skyelabz210/NINE65_v7/pull/169)
**Checkpoint date:** 2026-10-07

## Completed on this SHA

| Gate | Result | Run |
|---|---|---|
| T1 static analysis, no-float scoped scans, proofs | Pass | [37680342663](https://github.com/Skyelabz210/NINE65_v7/actions/runs/37680342663) |
| T1 fmt, Clippy, deny | Pass | [37680342663](https://github.com/Skyelabz210/NINE65_v7/actions/runs/37680342663) |
| CT source/functional checks | Pass | [37680342677](https://github.com/Skyelabz210/NINE65_v7/actions/runs/37680342677) |
| Blocking Dudect | Pass; details below | [37680342677](https://github.com/Skyelabz210/NINE65_v7/actions/runs/37680342677) |
| Application Platform | Pass | [37680342729](https://github.com/Skyelabz210/NINE65_v7/actions/runs/37680342729) |
| CRAM-public correctness and timings | Pass; 48 correctness tests and 2 timing tests | [37680342717](https://github.com/Skyelabz210/NINE65_v7/actions/runs/37680342717) |
| Quick scale sweep | Pass, both jobs/configurations; required depth 2/2 | [37680831309](https://github.com/Skyelabz210/NINE65_v7/actions/runs/37680831309) |
| Comparative v7 smoke | Pass, required depth 2/2; v6 comparison skipped (missing `NINE65_CROSS_REPO_TOKEN`) | [37680837528](https://github.com/Skyelabz210/NINE65_v7/actions/runs/37680837528) |

Dudect contrasts:

- `U512::mod_u256`: control `0.0954`, signal `1.7807`.
- Full `mod_switch_down_dual`, zero vs uniform: control `0.9485`, signal `0.0290`; medians `239,281,405 ns` and `239,271,675 ns`.
- Magnitude-matched sign: control `0.5590`, signal `0.1890`.
- Adjacency K-Elimination magnitude is **inconclusive** on this run: control `34.2862`, signal `13.2414`. Keep that independent finding open. Repeat CT measurements before accepting the remediation.

The CT decimals are statistical outputs (`f64` Welch t-scores); timing samples are integer nanoseconds. The CT verifier uses floating point for means, variances, and square-root standard error. The compiler noise estimator and benchmark reporters also use floating point. CI's no-float scans are scoped and explicitly exclude the CT harness; their green status is not a repository-wide zero-float result. Issue #90 is closed, while #92 Phase 5 still has its all-owned-source checkbox open; reconcile that scope before closing the parent gate.

## Failed gates/findings

- Fuzz Smoke [37680342693](https://github.com/Skyelabz210/NINE65_v7/actions/runs/37680342693): deserialize OOM on six-byte input `/P/+//7/`; encrypt/decrypt `16712` vs `16713`; homomorphic `65312` vs `65315`. K-Elimination and NTT pass.
- Real Refresh [37680342700](https://github.com/Skyelabz210/NINE65_v7/actions/runs/37680342700): release benchmark reaches the secure RNG guard because it supplies the test Shadow RNG; refresh was not exercised.
- Audit Remediation [37680342703](https://github.com/Skyelabz210/NINE65_v7/actions/runs/37680342703): expected exact delta-bit-length accounting is absent.
- CRAM Recumbency [37680342650](https://github.com/Skyelabz210/NINE65_v7/actions/runs/37680342650): existing CRT reconstruction, zero overflow sentinels, capacity fallback/saturation, bounded-k reconstruction, and missing checked inverse metadata.
- Residue-native architecture [37680342747](https://github.com/Skyelabz210/NINE65_v7/actions/runs/37680342747): 21 prohibited constructs in 11 files.

## Still running at this checkpoint

- CI T2 full suite: [37680342663](https://github.com/Skyelabz210/NINE65_v7/actions/runs/37680342663).
- Previous-head T2 on `84ce6da`: [37678425778](https://github.com/Skyelabz210/NINE65_v7/actions/runs/37678425778); this cannot validate c1a's fixed-work changes.
- The separate local serial 27-target `allow_insecure` matrix is still active in `/home/acid/Projects/NINE65_v7`; do not start another local Cargo build until it exits.

Fuzz artifacts are under `fuzz/`; the full failure logs are in `logs/`. The CT timing report is under `ct/`; quick scale and comparative artifacts are under `scale/` and `comparative/`.

Key SHA-256 hashes:

- Dudect report: `303ec2b59e8ec2c54f6a1cbab05d90b6031793da40a6174d146bcb8af0760e6d`
- Fuzz failed log: `236f90ccada0edc3e0c0e25fe2cf15a596412fa794cc4f393a5ac6c2e6442bb9`
- Refresh failed log: `19afc2606d8f9f69bacb81df780aacdd635bbf8fad195fbbcacffdd780d5abc8`
- CRAM-public complete log: `3221f5fa542c4e0f17e1f0a013b19aadb196e5d8bd0a490eaf425e6e787fd593`
- Deserialize reproducer: `0ef615a22002e3ef6cc0fe7ca726457e8ffe22a89a2c33f378b5be4a10861551`
- Encrypt/decrypt reproducer: `d22d60ad00595db36bad37c45fa4df80f4084ab0efc4927b96fefaf40fc937ef`
- Homomorphic reproducer: `dc717cd66fe3f5b3d3071f607c500208af1208dc42e6717bab79d7c82d1dae60`
