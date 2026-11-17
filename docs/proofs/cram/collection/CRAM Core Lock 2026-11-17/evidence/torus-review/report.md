# Torus package audit: CRAM proof evidence and remaining obligations

Review date: 2026-11-17. Scope: the new Torus-Fiber Markdown reports, both standalone Rust uploads, and three reproduction ZIP variants. This is a source audit and finite reproduction; it does not certify a deployed CRAM engine or NINE65. `certified_lift-2.tar.gz` and `PROOFS.pdf` are handled by the separate proof audit.

## Result

The latest bundle is useful evidence for exact CRT rank recovery over **pairwise-coprime composite moduli**, with real improvements in overflow handling and benchmark correctness gates. Its broad composite probe and default Rust runs reproduce successfully. This is more than a prime-only demonstration. It does not remove the stated coprimality assumptions from this particular Garner/CRT constructor, establish an independent source of canonical redundant observations, or demonstrate constant total cost for an arbitrary number of lanes.

Two additional caller-input defects were reproduced in the latest Rust harness: an undersized readout modulus is admitted even though the full reconstruction path needs an exact rank, and the maximal-rank test assumes a value that is false for legitimate small bases. Both are safe preflight failures: the harness refuses to emit a timing row. Neither invalidates the passed default large-modulus experiment or the underlying CRT identity.

## Provenance and variant reconciliation

All embedded checksum manifests validate: ZIP4 has 27 checked entries, ZIP10 has 27, and ZIP9 has 38. Hashes provide integrity against the supplied manifest, not independent authenticity.

| Uploaded archive | SHA-256 | Relationship |
|---|---|---|
| `4-Torus_Fiber_Checks_Reproduction_2026-11-17-2.zip` | `798184126dc9e94f1905201d5ef650bdf5001ed3a2ac9fb5a27b746b11ec64a8` | Earlier report, 28 members |
| `10-Torus_Fiber_Checks_Reproduction_2026-11-17.zip` | `7df56010e286baf8f7c18bc856e54f62bcc60f34fa404bd1f15edcd415d9aedf` | Same code/logs as ZIP4; adds detailed source-change explanation to report, 28 members |
| `9-Torus_Fiber_Checks_Reproduction_2026-11-17-3.zip` | `cd178f865faedf545eec035c5b194a0d696b4663261b4427679db61675ff6dcd` | Richest bundle: 11 additional v2 arbitrary-composite artifacts, 39 members |

ZIP9 was path-checked and extracted locally. Its report matches standalone upload1 exactly (SHA-256 `c601980470ec6f8a429fa3110952c3f9de7ac0be68863247a1ee6797de13fda8`). Standalone report3 instead matches ZIP10 (`08c6d2d045351cb3cdde8229aad9146d1df0d086c8fb88ca2dedd7445a6673d2`). Standalone Rust uploads2 and8 match the corresponding latest-bundle sources, hashes respectively `3bdc6d868c2381aec951931d21938d5fb49bd792822e79f579d4ddc16ef1654d` and `95f04e33c1b4656db7565003accdf244795f6ac6bc1ce843e53e220388aee5d1`.

The original nested input archive is retained with SHA-256 `125112c0de435fa729d65df27cce5f10476b1f6194030020fca434bd37e9fea0`. No supplied source was edited. `source_inventory.json`, `all_zip_checksum_validation.json`, and `older_report_diff.patch` record these distinctions.

## Exact mathematical contract

Let pairwise-coprime lane moduli satisfy `m_i > 1`, let `M = product(m_i)`, and let `x` be the canonical representative in `[0,M)`. Define

```
M_i = M/m_i
xi_i = ((x mod m_i) * inverse(M_i,m_i)) mod m_i
S = sum(xi_i * M_i)
alpha = floor(S/M)
S = x + alpha*M,                 0 <= alpha < k.
```

For a modulus `q` coprime to `M`, and the **canonical** observation `x_q = x mod q`,

```
((S mod q - x_q) * inverse(M,q)) mod q = alpha mod q.
```

If `q >= k`, this residue identifies the integer alpha throughout the conservative range `[0,k)`. A tighter base-dependent upper bound is

```
alpha_max = floor(sum_i ((m_i - 1)/m_i)).
```

All ranks `0..alpha_max` are attainable: start with every xi zero and increment one xi at a time; the sum increases by less than one at each step until its maximum. Thus `q > alpha_max` is the exact threshold for unique recovery from this one rank residue over all inputs in a fixed base. The simpler `q >= k` remains a sufficient portable contract.

**Rank alpha is not winding K.** If the supplied extra reading is instead `X mod q` for `X = x + K*M`, the same expression returns `alpha - K mod q`. With the opposite signed defect,

```
c = ((X mod A - S mod A) * inverse(M,A)) mod A,
K = alpha + c mod A.
```

This separates the raw CRT-sum correction from the lifted source coordinate. To obtain the integer K, the anchor result additionally needs an admitted representative interval; a congruence class alone is insufficient.

The uploaded report correctly identifies the canonical-versus-shifted distinction. The unresolved engineering obligation is to supply the canonical extra observation on the actual residue-only path without assuming the reconstruction that the optimized path is intended to avoid. This can be an explicit observation or maintenance contract; it cannot be silently inferred from the base residues at zero cost.

## Reproduced findings and counterexamples

**1. Missing exact-rank bound for the actual readout modulus.** `validate_for_k` checks `q2 >= k` but omits this check for `mr`. The rank consumed by `S - alpha*M` is computed using `mr`. The secondary `q2` gate validates it but does not repair it.

Fixture: `9 25 49 121 2 169`. At k=4, all lane pairwise gcds and both required lane/check gcds are one, and q2=169 exceeds k. For residues `(5,14,19,107)`:

```
M=1334025, S=5096264, x=1094189, alpha=3.
rank mod mr=2: 1
rank mod q2=169: 3
```

The untouched harness exits101 at its preflight assertion for k=4. Correct the full-reconstruction input contract by requiring `mr >= k`, or the tighter `mr > alpha_max`, unless a separate exact-rank resolution step is actually implemented. A modular-rank API may legitimately accept small mr but must not return it as an exact integer rank.

**2. The maximal-rank test incorrectly assumes alpha=k−1.** It sets `xi_i=m_i−1`, which achieves the raw sum maximum, but that rank is `floor(k−sum_i 1/m_i)`. For fixture `2 3 5 7 11 13`, k=4 has lanes `[2,3,5,7]`, mr=11 and q2=13. The induced residues `(1,2,3,5)` give

```
M=210, S=593, x=173, alpha=2, not k−1=3.
```

This valid configuration also exits101 at preflight. The rank formula and full reconstruction are correct; the test oracle is wrong. Replace the hardcoded expected rank with the exact bound above, or retain the maximizing vector without asserting the unsupported k−1 label. This matters directly for small safe bases: for `[2,3,5,7,11,13]`, alpha_max=4, not5.

These regressions are independent of composite-vs-prime status: the second uses prime lanes. They should be retained as named regression tests in the CRAM evidence package.

## What was executed in this audit

Host: Linux x86_64, Rust1.89.0; source compiled unchanged with `rustc -O`.

| Check | Fresh result |
|---|---|
| Latest Rust default composite corpus, k=2,4,8,16,32,64,128 | All PASS; 24 preflight vectors per k |
| Supplied fixture `9 25 49 121 8 4` | PASS at k=2 and4; shared anchor/witness factors permitted |
| Small readout fixture above | Expected preflight failure, exit101 |
| Valid small-base fixture above | Exposes incorrect boundary oracle, exit101 |
| Supplied `arbitrary_composite_probe.py` | PASS: 1,801,800 canonical cases; 217,800 exhaustive square-anchor pairs; 516 q2-boundary vectors, plus shifted inputs, >2^63 checks, k=1 and3 rejected non-unit inverses |
| Independent `audit_probes.py` | PASS: 57 small bases, 10,687 canonical states, 39,486 rank readouts, 118,458 shifted readouts |
| Independent tropical piecewise/value probe | 48,040 cases PASS |
| Supplied lunation script | PASS; its integer arithmetic/output reproduced |
| Supplied integer AST audit of the three original Python scripts | Zero findings |

The fresh broad probe also internally checks five winding samples per canonical input in its first block. Its own printed count is the canonical-input count; these should not be confused with independent observations or proof declarations.

The original 28,488,600-pair older composite sweep, full `exact_checks.py` including partition/curvature experiments, and full `carry_questions.py` were **not rerun** here. Their records remain archived evidence. We inspected their source; the tropical correction was independently checked at the original 48,040-point grid. These are finite executable tests, not general formal proofs.

The corrected tropical result is: for `z=g+QK`, `0<=g<Q`, `Q>0`, the minimizer of `Q*n*n + 2*n*z` is `-K` when `2g<Q`, `-K−1` when `2g>Q`, and both at equality. Its value is `-Q*K*K - 2*K*g + b*(Q−2*g)`, with `b=[2*g>=Q]`. This supplies a precise arithmetic obligation for a future tropical extension; it does not itself establish a continuum reconstruction or physical synchronization.

## Cost and implementation boundaries

The latest source improves on the earlier semiprime-only performance family: squareful/cubic/multifactor composites, an even modulus and values above2^63 are included; EEA replaces Fermat inversion; `u128` products and branch-based normalized modular add/sub avoid the earlier u64 expressions' overflow; failures terminate before timing; full-output sinks consume all limbs.

The primitive counts are `k(k−1)/2` modular multiplications for Garner digit conversion versus `2k+1` for the rank readout. These are different outputs: all mixed-radix digits versus one rank. They support a useful query-specific algorithmic comparison, conditional on the extra observation, not general O(1) reconstruction from k lanes. The final subtraction/multiplication is constant in arithmetic-operation count **after** its inputs have been formed. The residue accumulation itself is O(k); word widths and any parallel execution model must be stated separately.

Setup is excluded: inverse tables, coefficient products, wide M/M_i construction, and the redundant input observations. In particular, each canonical `x_r` and `x_q` is generated from a **Garner-produced full canonical limb result** before timing and cached. Reducing that result by a separate routine is an independent reduction check, not an independently sourced canonical observation. Production provenance remains an obligation.

The full optimized output path explicitly forms wide `S - alpha*M`; it is a reconstruction path. It can be an explicit CRAM boundary operation if desired. It cannot be counted as proof that the strict computation core never materializes a positional integer.

The fresh single default run gives k=128 values of92,666ns versus2,058ns for the primitives and90,403ns versus20,474ns for full outputs. These are logs of a correctness smoke run in a shared environment, not a controlled performance replication; do not promote their ratios as guaranteed gains. The uploaded ARM three-run medians50.69x and6.32x remain attributed to that earlier measurement. Neither source demonstrates an end-to-end NINE65 gain.

The q2 cross-check verifies bounded arithmetic consistency when its observations are correct. It does not authenticate the observations or detect all jointly consistent corruption. Authentication/integrity provenance belongs in a separate contract if required.

## CRAM proof obligations contributed by this packet

1. Prove the normalized CRT coefficient sum identity and exact rank bound for pairwise-coprime `m_i>1`; no primality/squarefreeness assumptions.
2. Type and prove canonical-rank recovery separately from winding recovery; test shifted observations explicitly.
3. State the exact-rank capacity contract for **each modulus actually used to produce an exact result**, including mr as well as q2.
4. Certify source coherence of base, canonical redundant, and lifted observations; exhibit the actual producer/update path and charge its cost.
5. Prove machine-width refinements for modular helpers, limb accumulation, borrow/carry behavior and normalized inputs, then link those routines to the abstract theorem.
6. Keep modular rank, exact rank, winding residue and exact winding as separate return contracts; integer outputs require their admissible-domain certificates.
7. Preserve the two newly found failing fixtures and original negative controls in regression tests. A reported FAIL must continue to prevent timing output.
8. Put full limb assembly in the declared reconstruction boundary; prove the residue core independently of that optional emitter.
9. State work, depth, setup/amortization and input-production costs separately. Benchmark equivalent outputs and additional inputs when judging integration speed.
10. If tropical machinery is included, prove the half-boundary/tie cases and corrected value formula before promoting any broader lift claim.

These obligations strengthen the core with a precise composite CRT rank/query module and an auditable performance experiment. General non-coprime observation resolution, universal transport and other CRAM mechanisms should retain their own proved contracts rather than borrowing a capability this specific benchmark does not implement.
