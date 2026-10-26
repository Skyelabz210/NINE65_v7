# Correction program execution — 2026-10-26

The attached plan is **not executable to release as written**. This execution
preserves its evidence, completes independent capacity/governance corrections,
and records the prerequisites that block the FHE port. Public refresh remains
disabled. No depth, security, constant-time or performance capability is added.

## Source and evidence

The clean workspace checkout matched remote main
`bbfa754f9db2e9a7b69fca6c468e0f601a2cf123`. Implementation branches from that
commit so subsequent repairs are preserved. The packet's audited commit
`4bc1f0f42ea7127f67f6fe1f921c7c9db1d50a06` exists in Git; the three requested
source files were independently SHA-256 hashed at both revisions. See
[evidence/baseline.json](evidence/baseline.json) and the byte-for-byte
[packet](evidence/technical-packet.txt). No expected audit hashes were supplied,
so “matches the audit report” cannot be asserted. Git objects and the manifest
preserve provenance; this repository is not a write-once storage service.

All five named witness/blueprint/patch artifacts and `crates/ns_v5/recumbent.rs`
are absent at both revisions and at the tips of all 37 remote branches
([search record](evidence/remote-source-search.json)). The available `exact_transcendentals::Recumbent`
is a different type, with scalar reconstruction in subtraction and other paths;
it is not evidence for the specified FHE port. `ops/rns_mul.rs` has already been
removed. Its active replacement is in `ops/rns_fhe.rs`.

Related depth-four evidence does exist under
`artifacts/execution/2026-10-04-depth-gate` and in
`docs/DEPTH_CORRECTNESS_MATRIX.md`. It records exact rescale agreement for the
selected lift and unresolved phase/fold provenance. Those artifacts are useful
context; they are not silently substituted for the packet's differently named
centered-lift experiment or 100-step-chain report.

## Construction blockers

1. **Signed lift uniqueness.** The prescribed `|K| < A` does not certify signed
   recovery from `K mod A`. With `M=17,A=19,r=3`, `K=-1` and `K=18` give
   `X=-14` and `X=309`; both main and anchor residues coincide. A specified
   interval of width at most A is needed; for `|K| <= B`, require `2B < A`.
   Range metadata must come from an analytic operation bound or authenticated
   epoch history, not from checking the aliased residues themselves.
2. **Safe Basis coprimality.** For odd prime p, `gcd(p-1,p+1)=2`. Multiple
   positive adjacency anchors also share at least 2. For p=2 the shadow modulus
   is 1. Thus the literal pair construction cannot satisfy the existing divider's
   pairwise-coprime anchor law. A generalized CRT design would use lcm capacity,
   compatibility checks, and new proofs. The existing NTT contexts additionally
   require prime, NTT-compatible moduli, so composite pairs are not drop-in lanes.
3. **Missing divider algorithm.** `residue_division.rs` already defines the trait;
   `kelim_residue_divider.rs` implements it by reconstructing X. That module
   explicitly documents the contract violation and prohibits wiring it into live
   division. The packet lists “four-step K-Elimination” without those steps or a
   proof for rounded division with authentic quotient anchors. Modular inverse
   multiplication alone does not implement integer quotient rounding.
4. **Secret-dependent carry.** A scalar residue divider does not supply the
   encrypted carry and key-domain return required by public refresh (#95).
   The packet itself lists these as open O1/O2/O4. Passing a scalar oracle would
   not authorize the public refresh gate.
5. **Parity statement.** The stated gcd implication is true but with coprime
   moduli concludes only `1 | X-Y`. An independently maintained witness can help
   detect corruption, but that implication does not prove the claimed syndrome
   coverage or authenticated provenance.

[Exact counterexamples](evidence/packet-counterexamples.json) record concrete
small integers. These blockers do not justify blanket centering, relaxing
coprimality checks, or declaring disabled refresh profiles admitted.

## Task disposition

| Packet tasks | Status and evidence |
| --- | --- |
| T0.1 | Audited/current hashes recorded. Expected audit report hashes unavailable. |
| T0.2 | Supplied packet preserved. Five named artifacts missing; immutable external storage not supplied. |
| T0.3 | README introduction corrected; registry links this report; retired claims retained. |
| T0.4 | Release baseline and target inventory recorded in validation artifacts. The packet's 24 ignored failures have no supplied name manifest and cannot be equated to today's ignored set. |
| T1.1 | Blocked port source and signed-lift invariant. No speculative carrier is presented as a port. |
| T1.2 | Existing divider inventoried; residue-native replacement blocked by missing algorithm/certificate. |
| T1.3 | New source gate implemented and injection-tested. Existing production reconstruction remains; hiding live symbols with cfg(test) would break production. Gate remains red. |
| T1.4 | Depends on signed representative/epoch contract. Reconstructing only the main residue would wrongly reject authentic noncanonical quotient anchors. |
| T2.1–T2.2 | Blocked by T1 and encrypted carry; current fail-closed refresh gate preserved. |
| T2.3 | Existing checked u128 and arbitrary-limb APIs retained; additive exact U256 view implemented. No new panicking capacity call. |
| T2.4 | Reparameterizing to 128_deep/192 cannot make public refresh admitted: all profiles are disabled. Existing oracle/diagnostic tests are retained until their individual contracts are reconciled. |
| T2.5 | Baseline tests are evidence only; no claim that boundary plaintext soundness is repaired. |
| T3.1–T3.4 | Blocked by incompatible adjacency construction and T2. |
| T4.1 | Existing custom-t validation and exact limb APIs retained; checked U256 product view added. |
| T4.2 | Production source gate for rns_product() passes. |
| T4.3 | DualRNSContext.anchor_product becomes Option<U256>; narrow helpers use checked u128 metadata. CRAM wrapper now reads checked Q capacity. |
| T5.1–T5.3 | Optional, not applicable before T2/T3 pass. “Collapse from 2NQ to 4NQ” is not a tightening as written. |
| T6.1–T6.2 | Full rescale/bootstrap proof and stress acceptance blocked on construction. Lean is the repository's proof record; no new Coq certification is asserted. |
| T6.3 | External estimator/SEAL artifacts unavailable. The current 240-bit heuristic screen is disclosed; the packet's 227-bit number refers to a superseded tuple per CLAUDE.md. |

## Implemented capacity changes and compatibility

`U256::checked_product_u64s` returns `None` above the fixed width. It uses only
exact public-modulus multiplication. `FHEConfig::try_rns_product_u256` and
`KElimination::try_capacity_u256` are additive; existing checked u128 APIs and
arbitrarily wide limb vectors retain their signatures and semantics.

**Source compatibility change:** `DualRNSContext::anchor_product` changes from
`u128` with a zero overflow sentinel to `Option<U256>`. Consumers requiring
u128 should use `anchor_product_checked`; consumers requiring all widths should
use `anchor_product_limbs`. Both existing fields are retained. In-tree test
fingerprints now serialize exact limbs. Legacy narrow reconstruction helpers
still have their documented u128 preconditions; this change does not certify
or rewrite their arithmetic.

CRAM witness admission now uses `q_product_checked`, refuses absent/zero values,
and preserves its existing strict `< 2^127` corridor. A missing checked value
cannot be admitted by a stale scalar field.

## Verification and release decision

The unmodified release baseline completed with **1,986 passed, 31 failed and
223 ignored** in 62 executed targets. Four failures are in nine65's library
(three symmetric-depth controls and the triple-precharge preflight test); 27
are in `coefficient_slot_gate`, including research parameter-admission failures
and assertion failures. Individual names, counts and ignore reasons are in
[baseline-results.json](evidence/baseline-results.json); the complete log is
[archived compressed](evidence/baseline-tests.log.gz). These are baseline
failures, not successes or ignored-failure classifications.

Cargo discovery lists 12 crates, 99 targets and 46 integration targets; **18 of
the 46 integration targets ran** in this baseline. Default
release execution skips targets requiring `allow_insecure`; explicitly combining
that feature with a release integration test hits the intended compile-time
security guard. The two modified test-fingerprint targets are checked in debug
mode instead. The stale guidance in `CLAUDE.md` is corrected; no build guard is
weakened to make a test run.


See [validation.json](evidence/validation.json) for exact commands/results and
[the source-gate report](evidence/recumbency-gate.txt) for the reconstruction debt.
The lexical source gate is an engineering check, not a proof against aliases,
macros, or hidden reconstruction. Its product-only mode is a separate gate and
must never be cited as a pass for zero reconstruction.

**Release blocked.** No last-green Phase-2/3 commit has been established, so there
is no basis to claim the packet's release or rollback criteria have been met.
To resume the critical path, supply the named source/evidence and a corrected
signed-lift, general-division, and compatible anchor contract; then implement
and prove the encrypted public carry before enabling refresh.
