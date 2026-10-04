# Safe Basis is a required CRAM substrate

This revision incorporates the owner's clarification after the initial plan.
The earlier plan underweighted the intact priming layer and treated too much
of CRAM as the existing main-Q arithmetic backend. A working backend alone
does not finish the intended configurable residue machine.

## Architecture to preserve

The priming root has at least the eight role lanes in the existing S8 profile:
`{2,3,5,7,11,13,17,19}`. The owner named the first six and specified at least
eight; the repository supplies the last two. S6 experiments remain historical
or explicitly restricted profiles, not replacements for this root.

Sister trays attach to the root through specified phase relationships, notably
the 2/11 roles. A sister tray may contain composite, shared-factor or repeated
moduli and heterogeneous operators. Adding, removing or replacing a sister
lane must preserve the live root and its identity/range obligations. This is
different from changing the modulus of an RLWE ciphertext or its encoding.

The source's CRT identity machinery and the target's view moduli have different
requirements. With a resolved state `X = g + K*M`, projection is

```text
X mod b = (g mod b + (K mod b)*(M mod b)) mod b,  b > 0.
```

There is no inverse modulo b in this expression. Target b need not be prime
or coprime to another target or to M. The existing production projection
primitive supports this distinction. It must derive `K mod b` from authentic
live state on demand; a scalar winding cache is not the required design.

The small S8 product is the range of one coordinate system, not the proposed
total workspace or an RLWE security parameter. Higher-power lanes or additional
independent coordinates can expand the represented range under a proved bound.
Duplicated views alone cannot expand the distinguishable state space.

## Exact conditions that workers must encode

| Operation | Required condition |
|---|---|
| Source CRT idempotents | Valid independent source factors and checked arithmetic capacity |
| Project to a sister lane | Positive target modulus and enough authenticated-by-construction state/lineage and range evidence to identify the represented lift |
| Count shared-factor view capacity | Use LCM and the actual constrained image, not the raw product of overlapping moduli |
| Modular inverse of an operand | The operand is a unit for that modulus; source coprimality does not make every target operand invertible |
| Shared-factor exact division | A separate exact-divisibility and disambiguation construction; never silently substitute an unavailable inverse |
| Remove a sister lane | Preserve the root and all information still needed by later admitted operations, or refuse/restrict the resulting domain |
| Apply heterogeneous operators | Declare whether the result names one integer or a topology product state; validate compatibility before treating it as a shared integer again |
| Change BFV Q, t or key domain | Separate encoding, error, sampler, transform and security checks for that specific transition |

For example, views modulo6 and10 have a joint period30, not60. A modulus1
view is the constant0 and contributes no distinguishing information. Neither
fact prevents these views from being useful when the intact root remains live.

The usual K-elimination equation `K=(r_A-r_M)*M^-1 mod A` requires the inverse
for that particular source/anchor split. If M is the whole S8 product, A=11
does not satisfy it because 11 divides M. A local source excluding11, a suitable
higher-power construction with its own derivation, or an independent anchor
is a different case. Do not reject the whole architecture because one split
is invalid, and do not apply the inverse formula to an invalid split.

The existing adjacent construction uses A=M+1, whose inverse of M is -1,
and identifies K within `[0,M*(M+1))`. The owner's authoritative 2/11/higher-power
construction is still to be pinned in S00; this plan does not silently replace
it with adjacency. The subsequent monograph places Shadow-11 outside the
primary payload range, distinguishing that M from the whole priming product.
The owner then marked its MRS reconstruction description as stale. See
[the monograph reconciliation](OWNER_MODEL_RECONCILIATION.md).

These elementary CRT/unit distinctions agree with the
[Handbook of Applied Cryptography, chapter2](https://cacr.uwaterloo.ca/hac/about/chap2.pdf).
The useful asymmetric source/target projection above is also already explicit
in [the repository's lifted-transduction packet](../../CRAM_SAFE_BASIS_LIFTED_TRANSDUCTION_EXECUTION.md).

## Source findings and concrete work

| Source | What exists | What remains |
|---|---|---|
| `transduction.rs:56,307` | S6/S8 constants; canonical source-to-target projection with rank correction | Preserve its bounded domain and propagate typed capacity errors |
| `lifted_transduction.rs:339` | Per-target lift provider and arbitrary positive target projection | Bind provider to source identity, epoch, range and semantic domain |
| `cram_anchor.rs:177` | Adjacent winding provider derives from residue coordinates on demand | Connect the selected, reviewed phase mechanism to live operations |
| `cram_ct.rs:342,544` | Named 2→11 Shadow edge; current evidence snapshots a lane | Define the complete sister-tray coherence relation; snapshot equality alone is insufficient |
| `chimera_page.rs:74` | Custom page sizes, including fewer than8 | Admit production priming roots only when all required roles remain present |
| `cram_machine.rs:69` | Operator/discriminating basis excludes2 for its degree gate | Keep operator subtrays distinct from the intact root |
| `cram_ops.rs:165,185,215` | Composite schema admission but prime-only Fermat inversion | Fix composite unit inversion and composite validity counts; keep nonunit refusal |
| `k_elim.rs:394` | DIV3 modular product through reciprocals/division on units | Classify domain, nonunit routing and any encrypted realization separately |
| `cram_ct_wrap.rs:1` | S8 fingerprint of a public ciphertext component, regenerated after operations | An actual preserved substrate with production dataflow and transitions |
| `cram_pde.rs:112`, `dyn_crt.rs:100` | Other carriers retain scalar winding/digits | Do not present these as the completed on-demand carrier |
| `cram_ops.rs:255` | Independent lane operations executed in a loop | Measure actual lane/tray scheduling and remaining dependency stages |

The current schema inverse defect is directly reproducible: `Inv(2) mod15`
returns2; the inverse is8. This is a concrete implementation mismatch with
composite sister trays, not a reason to forbid them. The separate `mul_via_div`
primitive uses an appropriate inverse and succeeds on its composite unit domain.

## DIV3, operator counts and noise

`mul_via_div` implements `1 / ((1/a)/b)` exactly where every required operand
is a unit. The inversions themselves do not create exact-arithmetic rounding
error. A prime lane still contains zero, which is not invertible; prime labels
alone do not prove the operator's domain condition. Nonunits need a separately
valid route with explicit output semantics.

No production public BFV `mul_via_div` call was found in this source review.
The audit binary's printed zero-noise claim uses clear residue vectors.
For phases `Delta*m1+e1` and `Delta*m2+e2`, an algebraically identical product
still contains `Delta*(m1*e2+m2*e1)+e1*e2` before subsequent BFV processing.
This does not rule out a different construction with improved bounds; it makes
the encrypted operator and its error invariant an explicit obligation in S04.
See the scheme definitions in the
[Homomorphic Encryption guidelines](https://homomorphicencryption.org/wp-content/uploads/2024/08/Homomorphic-Encryption-Standard-v1.1.pdf).

The corpus references a 14M catalog and separately counts `8^8=16,777,216`
operator assignments. Preserve the catalog/provenance search. Count raw
assignments, admissible schemas and semantically distinct operators separately;
no novelty or security conclusion follows from the assignment count alone.

Lane-independent operations can run across lanes/trays concurrently. DIV3's
three dependent stages and any inter-tray dependency remain part of the
scheduler's work/depth model. Measure scaling rather than interpreting a
sequential Rust loop or an algebraic identity as an instantaneous computation.

## Revision to the execution order

Six explicit packets supplement the original 37:

1. S00 freezes the priming-root and phase-mechanism contract.
2. S01 binds on-demand lift providers to live state and ranges.
3. S02 fixes composite operator arithmetic and domain handling.
4. S03 implements root-preserving sister-view layouts and transitions.
5. S04 supplies operator/DIV3 domain, catalog and error evidence.
6. S05 connects the preserved substrate to the public CRAM evaluator.

C00 now reads S00 before choosing its wrapper. C03/service integration waits
for S05. R00's tight-bound study includes S04's actual operator semantics.
Source-to-target view conversion remains distinct from BFV modulus switching.
The main-Q wire policy controls externally emitted ciphertext information; it
must not be interpreted as permission to remove the internal Safe Basis.

## Reproducible review probe

From the repository root:

```sh
rustc --edition=2021 --cfg 'feature="std"' --cap-lints allow docs/execution/2026-10-03/probes/safe_basis_probe.rs -o /tmp/nine65-safe-basis-probe
/tmp/nine65-safe-basis-probe
cargo test --locked --offline -p exact_transcendentals --test safe_basis_lifted_transduction --test lifted_transduction_module -j1
```

The source-including probe deliberately records the current inverse defect;
a successful run means the finding was reproduced, not that the defect was
fixed. It also exercises the actual lift-aware entry point on S8 boundary
states and arbitrary target views. Test inputs/clear state are oracle-only;
this is not public encrypted refresh or an EMP test. Results are recorded in
`safe_basis_review.json`; the original baseline evidence is retained.
