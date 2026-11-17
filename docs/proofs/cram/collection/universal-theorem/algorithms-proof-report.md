# Executable residue-space division and Euclidean GCD

`ResidueAlgorithms.lean` contains six compiled theorem declarations under
Lean4.27.0-rc1, using `Std`. The [build log](algorithms-build.log) lists their
transitive axioms: only `propext` and `Quot.sound`. There are no admitted proofs,
custom axioms, or assumed division/GCD correctness conclusions.

## Runtime representation and proof contract

The runtime `Ops S` interface contains a public capacity, an encoded zero,
increment, nonnegative subtraction, comparison and a zero test. It contains
**no source integer, encoding function, scalar reconstruction or stored K**.
The loops receive only these operations, represented operands, and public fuel.

`Correct ops encode` is a separate proposition used by the proofs. It specifies
that each primitive agrees with its natural-number meaning on the admitted
interval `[0,capacity)`. This generic theorem needs a concrete instance of that
contract. [ResiduePrimitives.lean](ResiduePrimitives.lean) supplies it using the
actual paired modular readings, on-demand K comparison, modular subtraction
and modular increment. No division or GCD result is a primitive hypothesis.

`encode_injective_on` proves that the exact-comparison contract itself forces
the encoding to be injective on the admitted domain. Encoded output equality
therefore identifies a unique natural value there; faithfulness is not merely
an unstated interpretation of a possibly constant encoding.

## Division

`divLoop` repeatedly tests whether the represented remainder is less than the
represented divisor. If so, it returns the represented quotient and remainder.
Otherwise it increments the quotient in the representation and subtracts the
divisor in the representation. Its scalar `fuel` is a public resource bound.
At fuel zero it still performs the terminal comparison, returning `none` only
if another subtraction would be required.

The induction proves the invariant

\[
q+r<\mathrm{capacity},\qquad 0<d<\mathrm{capacity},\qquad r\le\mathrm{fuel}
\]

and the exact result

\[
\operatorname{divLoop}(\mathrm{fuel},E(q),E(r),E(d))
 =\operatorname{some}\bigl(E(q+\lfloor r/d\rfloor),E(r\bmod d)\bigr).
\]

Here q,r,d are specification variables. The executable function receives their
representations, not these variables. If a subtraction is needed, d≥1 and r≥d,
so q+1 remains below capacity, the remainder decreases, and
`(q+1)+(r-d) ≤ q+r`. Both the capacity and fuel invariants are maintained.

`divmod` checks for a represented zero divisor, initializes the quotient with
the supplied encoded zero, and calls `divLoop` with public fuel `capacity`.
For every admitted n and positive admitted d it returns exactly

\[
\operatorname{some}(E(n/d),E(n\bmod d)).
\]

No invertibility or coprimality assumption on the **divisor d** occurs. The
algorithm supports inexact integer division and divisors sharing factors with
the representation moduli. The representation frame has its own independently
proved observation/inverse contract. A zero divisor produces `none`; the
`divmod_zero_refused` theorem covers any dividend state once capacity is positive.

## Euclidean GCD

`gcdLoop` tests the represented second operand for zero. A zero returns the
first represented operand. Otherwise it calls the proved `divmod`, takes the
represented remainder, and repeats on `(b,remainder)`. At zero fuel it still
accepts a zero second operand.

The outer induction uses `b ≤ fuel`, together with both operands below capacity.
For b>0, the new remainder `a%b` is less than b. Thus the same original capacity
is sufficient throughout the complete computation, and the public fuel cannot
expire on valid inputs. The library Euclidean identity

\[
\gcd(a,b)=\gcd(b,a\bmod b)
\]

closes the step. The resulting theorem is

\[
\operatorname{gcd}(E(a),E(b))=\operatorname{some}(E(\gcd(a,b)))
\]

for all a,b below capacity, including `(0,0)`. The division quotient state is
ordinary temporary algorithm output in the same representation; it is not a
persistent winding register.

## Scope and cost

These are proofs of actual recursive program definitions, not just finite-step
composition promises. Malformed or out-of-domain states can return `none` or
an unspecified represented result; correctness is stated on the proved domain.
All functions terminate structurally on public fuel.

Repeated subtraction is a simple constructive witness. Its iteration count
depends on the operands and can be large in their bit width. This module does
not claim that complete division or GCD takes the two operations of the K
readout, or that these clear branches constitute an encrypted evaluator.
Integrating an efficient NINE65 division kernel requires its own refinement
to the same primitive/result specification.

The checker should build `ResidueAlgorithms` before `ResiduePrimitives`; the
latter discharges every generic primitive hypothesis and states the concrete
paired-residue division and GCD corollaries.
