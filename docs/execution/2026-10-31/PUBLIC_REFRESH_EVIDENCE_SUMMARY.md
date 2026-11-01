# What the public-refresh evidence establishes

**A complete public refresh works in the implemented research backend, with
substantial bounded-parameter correctness evidence. Production-security
justification for the exact complete key setup is unfinished.** These are
different claims; an unfinished security argument is not a demonstrated
failure to preserve plaintext.

## Supporting evidence

| Claim | Evidence | Scope |
| --- | --- | --- |
| Evaluation is public | Evaluator contains public evaluation/switch keys; the client owns the work secret and performs test decryption | Key-holder setup uses secrets; refresh evaluation does not |
| Native refresh preserves plaintext and permits continued computation | Five native refreshes and five following full-polynomial squares; all 8,192 coefficients checked after every operation: 81,920 comparisons | Actual archived execution, with seeded research randomness |
| Correctness has an algebraic basis | Certified source support and G/H identity recover encrypted K; affine+K restores m | Applies to the stated source/support and checked error bounds |
| Full return fits the native budget | 562-bit error bound after slot return against a 633-bit threshold; next square/source radius 48 within support 49 | Current exact-integer parameter certificate; not a measured-error reset |
| Canonical root survives refresh | Same sealed plaintext-root capability retained through source/return; wrong-root return rejected; arithmetic issues new roots | Current local typed API; independent encrypted S8 lane emission remains separate |
| Parameter-level security evidence is encouraging | 24 previous source estimates plus four new authors' implementation runs; lowest reported modeled cost remains 161.33894 bits. The outer in-tree classical/hybrid screen binds at 129 bits | Models and heuristics, not a whole-system confidentiality proof or a 128-bit quantum claim |

The native five-cycle run took 3393.19 seconds including setup and peaked at
about 8.70 GiB resident memory. It demonstrates functionality, not low latency.
Its source/binary snapshot predates recent root/inventory additions. Current
regressions and preflight checks cover those additions; the expensive full
native execution has not been repeated at the latest commit.

The native log and result hashes were rechecked against the evidence manifest,
including explicit completion of cycles 0 through 4. The new estimator report's
hash and all four finite results were also rechecked against its provenance.

## What remains unresolved

The exact published material contains related-key dependencies W→S→B→W and
self-key functions such as W²→W and B²→B. Individual domain attack estimates
do not establish confidentiality of that correlated setup. The conditional
public-evaluation lemma shows that refresh preserves confidentiality **if the
joint setup is secure**. The premise still needs a defensible argument under
explicit assumptions or a construction that avoids the unsupported relations.
This is not a request for assumption-free cryptographic security.

The pinned authors' attack code also predates the paper's corrected theorem.
Its execution is now assessed, but correspondence to that revision and full
quantum-hybrid coverage are not established. These are evidence/review limits,
not observed refresh arithmetic failures or demonstrated key-recovery attacks.

The supported claim is therefore a working, repeatedly tested research public
refresh. The stronger claim of production-admitted security remains open. The
working backend is explicitly selected with `allow_insecure`; the legacy
default production gate remains closed.

## Primary implementation evidence

* [Native five-cycle transcript](../../../artifacts/execution/2026-10-28/public-refresh-circuit/native/five-cycle-run.log)
  and [hashed evidence manifest](../../../artifacts/execution/2026-10-28/public-refresh-circuit/manifest.json).
* [Lift and return proof](PUBLIC_REFRESH_LIFT_REFINEMENT.md) and
  [canonical plaintext-root binding](CANONICAL_PLAINTEXT_ROOT.md).
* [Completed attack assessment](HOU_JIANG_ASSESSMENT.md),
  [exact published-key inventory](PUBLIC_REFRESH_KEY_GRAPH.md), and
  [conditional confidentiality reduction](PUBLIC_REFRESH_SECURITY_REDUCTION.md).
