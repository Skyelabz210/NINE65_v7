# CRAM integration assessment, 2026-10-28

The new expanded carry circuit is a real reusable encrypted kernel, but there
is no sound cast from its current output to the repository's `Root211`
capability. This is a missing producer and semantic contract, not a missing
hash or an API visibility change. No production admission was changed here.

## Preserved contract

`docs/execution/2026-10-21/PUBLIC_REFRESH_ARCHITECTURE.md:480` sketches a
bounded expanded-plaintext DAG as part of a possible complete pipeline.
Thus this arithmetic is not categorically prohibited as an internal kernel.
The same document at line 497 requires the Safe Basis root and derived views
to participate in actual native transitions, and at line 535 requires
integration into `CramMainEvaluator`. The standalone research API does not
yet satisfy either boundary.

`docs/execution/2026-10-03/PRIMING_ROOT_CONTRACT.md`, section 7, and
`artifacts/execution/priming_root_profiles.json` still mark
`OWNER-LIVE2-11` unresolved and S00 unaccepted. The contract explicitly says
not to silently select a reference profile as its replacement. The missing
owner-level definitions are the quantity named by the root; payload and
anchor roles/powers; exact 2/11 coordinate meanings and relation; uniqueness
interval and extension rule; transition equations; signed/division semantics;
and public versus protected observation classification. Selecting those
semantics would be a concrete architecture decision, not ordinary adapter code.

## What the existing capability actually proves

`safe_basis_composition_tests.rs:170` stores public support rows `(g,K)` and
an encrypted one-hot selector for each row. `State` also binds family,
source modulus and consumed coefficient identities. `root_value` at line 267
names **S = g + q*K**, not K alone. A projection is an encrypted weighted sum
of the actual row selectors (`project`, line 438), with a propagated bound.

`safe_basis_sister_tray_tests.rs:109` borrows that exact immutable State.
`Root211::new`, line 163, actually evaluates all eight root residues and the
joint phase index. `PreparedStep` owns the proposed right input, support,
transition edges and bounds. `verify_phase_edges`, line 143, proves the
binary crossing and 11-coordinate carry relation before commit. Pointer
identity is a local capability check on this real encrypted state, not a
portable authenticated root certificate. The file explicitly labels this
private research capability as not a production phase authenticator.

The new packed phase/carry pipeline does not contain these encrypted row
selectors or an equivalent native root provider. Promoting the existing test
types would reintroduce their explicit support enumeration and does not make
the native producer appear.

## A concrete reason K cannot be retagged as that root

At the Q60 source, let p=65537, c0=0 and c1=1. For a source coefficient
s_j in {-1,0,1}, the centered residual sum is S_j=p*s_j, its native carry is
K_j=0, and round(p*S_j/q)=0 because p^2<q/2. These ciphertexts decode to zero
with very small certified error. Taking c1=0 instead also gives K_j=0.
Nevertheless S_j mod each root prime generally differs (e.g. root2 differs
when s_j=1). The root defined by the existing code therefore is not a function
of the extracted carry alone. A family or lineage hash cannot supply the lost
protected coordinate information.

The retained original source and key-holder precharges can in principle
produce additional encrypted linear residues of S in separate plaintext
trays. That does not itself produce the canonical shared 2/11 phase index,
prove an intended common signed lift across those trays, or provide the
consuming native transition. Those need their own encrypted construction,
noise budget and protected conversion proof. This note does not prove that
such a construction is impossible.

## Minimal legitimate interfaces after the missing producer is resolved

1. A private `RootSourceId` binds the exact work/source/outer key domains,
   ciphertext lineage, level, epoch and the declared protected integer.
2. A producer-issued `RootState` contains either the genuine encrypted
   `(g,K)` support representation or a proved equivalent compact native
   representation. It owns the intact logical S8 roles, actual phase data,
   uniqueness interval and coefficient error bounds. No raw-ciphertext plus
   caller-bound constructor is exposed.
3. `RootState::attach(moduli)` emits dependent views of that same source and
   epoch; it accepts composite/overlapping moduli and records the LCM rather
   than inventing independent capacity from a product.
4. `prepare_transition` proves all required phase/carry equations, target
   bounds, encoding/key conversions and operation identity before executing
   dependent work. `commit` consumes that prepared capability and atomically
   issues updated root, views, ciphertext and history. A topology/operator
   frame must not be relabeled as an integer-named root without its lift rule.
5. The packed digit result becomes one private input to this real transition;
   it is not itself root authority. The output root must be consumed by the
   subsequent declared operation. Merely computing unused root residues is
   not sufficient.
6. Key-holder setup must provision refresh material for an existing
   `CramMainClient` key. `PublicRefreshSourcePlan::generate_with_rng` currently
   makes a fresh independent work key (`public_refresh_source.rs:199`), so
   its ciphertext family cannot be attached to an existing CramMain family.
   The scalar main wrapper's bound cannot be treated as a generic polynomial
   bound; keep a proven scalar witness or introduce the full-polynomial
   certificate type and its real producers.
7. Only after these contracts and the separate security admission are met
   should `CramMainEvaluator::refresh` issue a new main-Q ciphertext bound and
   history under the same validated family. The invalid legacy Phase 1 gate
   remains closed.

## Implemented prerequisite in this task

`ops/cram_precharge.rs` had a stale 256-bit guard dating from the old
full-integer mask sampler. The current main sampler uses exact independent
CRT residues, and the context, Delta and centering setup now admit Q650.
The guard was removed while preserving message shape/range, ternary-secret
validation and signed eta capacity. A temporary source-trit plaintext vector
is now zeroized. New reduced-ring Q650 tests independently check every
coefficient in all 13 lanes, at p and p^2, using Python-integer Delta constants
and signed schoolbook phase arithmetic; malformed shape/secret/message
refusals remain covered. These tests were queued with the coordinated build,
not represented as already passed when this note was written.

This shared primitive is useful for future real root/tray producers. It does
not establish a Root211 producer or authorize CRAM production admission.
