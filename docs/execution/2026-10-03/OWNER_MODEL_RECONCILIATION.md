# Owner monograph and subsequent reconstruction correction

Source: Anthony Diaz's CRAM monograph supplied in this conversation, followed
by his correction that its reconstruction discussion is stale. This is a
planning interpretation, not a replacement monograph or a proof certification.

## Requirements promoted into the execution contracts

* Preserve exact residue arithmetic, configurable capacity and the intact
  S8 priming root. Attach operator/sister trays without removing root roles.
* Maintain residue coordinates and derive winding on demand. A running scalar
  K or accumulated mixed-radix winding tower is not the requested live design.
* Name M and A separately for every K-elimination invocation. The monograph
  places Shadow-11 outside the **primary payload product** when used as its
  anchor; its membership in the S8 priming root is a different relationship.
* With `gcd(M,A)=1`, the given formula determines K modulo A. Record the range
  that makes that residue the unique requested winding. Record separate
  derivations for higher-power or shared-factor constructions.
* Separate frame-to-frame transduction from explicit observation/emission.
  The owner has withdrawn the monograph's MRS pipeline as a description of
  current reconstruction. Do not implement a new MRS/Garner emission pipeline
  because that older paragraph mentions one.

## What the current subtraction path returns

`cram_anchor.rs:152` implements `Anchor::winding` as `(r-a_res) mod A` for
A=M+1. Its `Anchor::lift` at line171 then returns `r+M*K`. For the existing
coordinate convention `r=X mod M`, `a_res=X mod(M+1)`, the subtraction returns
the winding K, not generally X. Example: M=36, X=100 gives r=28, a_res=26,
K=2 and X=28+36*2.

If another admitted representation makes the desired output itself that
winding, subtraction may directly return the requested value. S00/S01 must
name the encoded quantity and prove that relation rather than infer it from
the name of an API. This preserves the subtraction shortcut without assigning
the wrong semantic type to its result. The current adjacent provider does
not require an MRS reconstruction to answer each target-lane query.

The monograph gives general and adjacent formulas, but does not specify all
live 2/11/higher-power sister-tray transition rules. S00 records that remaining
interface rather than picking a historical implementation silently.

## Claims to make precise for workers

| Wording | Required engineering meaning/evidence |
|---|---|
| O(1) K recovery | Fixed modular-operation count for a fixed representation; separately account for operand width, lane count and obtaining the source coordinates |
| Zero memory overhead | No persistent scalar-K accumulator; measure actual root/anchor, scratch and certificate storage |
| Total lane independence | Dependency graph of independent lane work and required snapshot/phase/operation barriers |
| Unique phase transfer | Defined state, range, exact projection and recovery conditions; enough retained information for claimed reversibility |
| Sign, comparison, zero detection | Signed interval and sufficient phase information; exhaustive ties, zero aliases and wrap boundaries |
| General division | Explicit exact quotient, quotient/remainder, modular quotient or rational state; defined zero/nonunit handling |
| Every operation reversible | Inverse or retained-information rule for each operator/domain; zero multiplication and squaring need restrictions or extra information |
| Noise-free DIV3 | Zero arithmetic approximation on its unit domain, plus a separate invariant for an encrypted realization |
| Whole instruction set verified in Coq | Each instruction maps to built theorems, hypotheses, axioms and Rust correspondence |
| Single-cycle mana | Named hardware/RTL and measurements; existing Rust execution does not establish a gate-level timing claim |
| Negligible observation cost | Timed workload lengths, emit costs and baseline, rather than a universal ratio |

`lean4/KElimination/coq/K_Elimination.v` contains K-elimination lemmas with
positivity/range hypotheses. It was inspected, not rebuilt during this revision;
its presence alone does not certify the full instruction set.

The code expands MANA as Modular Anchored Number Arithmetic and UNHAL as
Universal Neuromorphic Hardware Abstraction Layer, unlike the monograph.
Preserve existing interfaces while reconciling terminology. Current
`unhal/src/lib.rs` documents production deterministic scoped-thread dispatch
through `mana::executor`; older mana README claims of complete disconnection
or rayon-only execution are stale. Verify the new sister-frame path's own
connection to the executor.

The non-Archimedean and thermodynamic interpretation does not replace the
algebraic admission conditions. Exact arithmetic alone does not make every
operation reversible or establish a heat claim. Physics and hardware claims
retain their own model/evidence requirements.

These requirements feed S00–S05, C01, R00, V02 and V04.
