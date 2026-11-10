# Lean trust boundary correction

Date: 2026-11-10. Base: `7ada650`. This is an isolated local repair, not a
production-security grant or evidence of a new encrypted refresh run.

## Historical AHOP claim is inconsistent, not merely unproved

The former global axiom `KElimination.AHOP.Hardness.ahop_hardness` quantified
over every positive modulus and every function from instances to optional
words. At `q = 1`, `ZMod 1` is a singleton. Every instance's starting and target
states are equal. The function that always returns the empty word therefore
solves every instance, and its word length is zero, not greater than `q*q = 1`.
The axiom consequently implied `False`.

The repair removes that axiom from the elaborated environment. Its exact body
is retained as the *unasserted* proposition `LegacyHardnessClaim`, accompanied
by `legacyHardnessClaim_one_false`. Repository source search found no theorem
consuming the old axiom. This is an intentional removal of an unsafe assertion,
not a change to the claims of the separate arithmetic proofs.

Restricting the modulus to primes or adding `q > 2` would remove this particular
counterexample but would not supply a cryptographic hardness model. The old
statement has no computational resource bound, security-parameter family,
instance distribution, success probability, or reduction. A replacement
security definition and any supporting assumption require their own review.
This finding is not a demonstrated key-recovery attack on an implementation.

## Global decoding tag is impossible; restricted results are separate

The premise `forall s i, tag (reflect i s) = i` in `injective_all_lengths` and
`orbit_exponential_from_tag` is false for every positive modulus. All four
reflections fix the zero state, whose one tag would then have to equal both
0 and 1. `no_global_decoding_tag` records this direct contradiction.

In addition, repeating an involutive reflection is the identity. Thus the
unrestricted length-two words `[0,0]` and `[1,1]` have the same action on every
starting state when the existing involution lemma applies.
`not_injective_length_two` records the collision explicitly. No long-word
counting or finite-size asymptotic argument is needed.

The two historical conditional lemmas are retained, with explicit vacuity
warnings, to avoid erasing valid logic or breaking consumers needlessly. Their
conclusions must not be cited as realizable all-length orbit-growth evidence.
`orbit_exponential_lower_bound` still has an explicit injectivity premise for
the selected length. Length-one separation results, algebraic invariants and
bounds on the explicitly restricted `ZeroTaggedWord` subtype are separate
conditional statements. This repair neither manufactures instances satisfying
those premises nor invalidates them wholesale.

## Parameter sanity is not security

The historical `params_128bit_secure` name states only dimension, primality,
and positive rational-noise components. The functions `orbitLowerBound` and
`quantumLowerBound` are numerical definitions `q*q` and `q`, not proved bounds
on orbit cardinality or adversarial work. Their comments now state that scope.

The previous `native_decide` uses also depended on `Lean.ofReduceBool`, which
adds compiler/runtime trust beyond kernel checking. The repair uses
Mathlib's `lucas_primality` with explicit factorizations and modular-power
certificates for the fixed prime, and ordinary `norm_num` proofs for the
remaining inequalities. No custom axiom is added or whitelisted. The small
certificate chain proves primality only, not cryptographic strength.

## Audit boundary

`scripts/axiom_audit.sh` still imports every project proof module and the root.
It now checks every declaration owned by a `KElimination` source module,
regardless of declaration namespace, and follows transitive axiom dependencies
in types and values. Only `propext`, `Quot.sound` and `Classical.choice` are
allowed. Direct custom axioms, imported custom dependencies, `sorryAx`, and
`Lean.ofReduceBool` are rejected. Definitions and opaque declarations are
checked even if no theorem uses them. Temporary audit files are unique and
removed on exit.

This is an axiom-dependency audit, not a proof of the semantic adequacy of a
theorem's statement or its premises. An unused axiom in an unrelated imported
module is not a dependency of the project theorem. A fresh `lake build` is
required before auditing; the script does not claim stale object files are
freshly compiled source. CI runs the build first, then the audit and controls.

`scripts/test_lean_axiom_audit.py` builds fresh standard-library-only fixtures
to exercise clean declarations, direct and namespace-escaped axioms,
macro-generated axioms, imported multi-hop axioms, definition and type-only
dependencies, theorem/opaque `sorry`, native computation trust, and an unused
foreign axiom. It intentionally permits fixture `sorry` build warnings so
the transitive audit itself must catch them.

## Public-refresh slice and verification

The five independent standard-library-only public-refresh proof modules and
their separate transitive audit are unchanged. Their actual run on this local
repair reports **142 theorems, no custom axioms or sorryAx**, with pinned Lean
`4.27.0-rc1` (commit `2fcce7258eeb6e324366bc25f9058293b04b7547`). All ten
public-refresh negative/positive gate controls pass. These proofs concern the
stated arithmetic/models, not Rust refinement, confidentiality of the joint
key setup, or production admission. Legacy/default bootstrap remains gated.

The focused AHOP build passes (`lake build KElimination.AHOP.Hardness
KElimination.AHOP.Parameters`, including Algebra; 1,586 jobs). Running the
same transitive audit body over those three modules passes for **196 project
declarations**, including the counterexamples and fixed-prime certificates.
All **11** whole-library gate-control fixtures pass.

The full-library build/audit was **not completed**. Installing the official
pinned Lean succeeded. The initial whole-Mathlib cache download hit HTTP 429
rate limits; a targeted, throttled fetch succeeded and enabled the AHOP checks.
The throttled full-cache continuation also failed, leaving 746 downloads
unavailable. This is a dependency-fetch limitation, not a passing full-library
check. Do not interpret either focused slice as a full-library pass.

Local commands actually run:

```bash
# Repository root, with pinned Lean/lake on PATH:
python3 scripts/check_public_refresh_proofs.py --output work/lean-trust/public-refresh-proofs.json
python3 scripts/test_public_refresh_proofs.py
python3 scripts/test_lean_axiom_audit.py
bash -n lean4/KElimination/scripts/axiom_audit.sh
python3 -m py_compile scripts/test_lean_axiom_audit.py
git diff --check

# lean4/KElimination:
lake build KElimination.AHOP.Hardness KElimination.AHOP.Parameters
```

The focused AHOP audit imported Algebra, Hardness and Parameters and used the
exact `run_cmd` body of the strengthened audit script. Its result is distinct
from running `bash scripts/axiom_audit.sh` after a full build. The full-library
build/audit must pass before promoting this local repair to a full verification
claim.
