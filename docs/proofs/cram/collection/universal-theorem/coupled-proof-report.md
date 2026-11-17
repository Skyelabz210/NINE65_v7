# Coupled-anchor resolution: checked integer specialization

`CoupledAnchors.lean` contains **19 compiled theorem declarations**, using the pinned Lean4.27.0-rc1 standard library only. Every theorem has an axiom query. The final [build log](coupled-build.log) and [manifest](coupled-result.json) record the source hash and transitive dependencies; there are no admitted proofs or custom axioms.

## Exact law

Let M be the nonnegative main modulus and A₁,…,Aₙ positive anchor moduli. Practical residue frames take M>0. Define the actual computed natural numbers

\[
L=\operatorname{lcm}(A_1,\ldots,A_n),\qquad
R=L/\gcd(M,L).
\]

The empty list has L=1. The main result proves, for every signed integer coordinate change δ,

\[
(\forall i,\ A_i\mid M\delta)\quad\Longleftrightarrow\quad R\mid\delta.
\]

No pairwise coprimality assumption appears. Shared, repeated and composite anchors are handled by the LCM. This is an exact description of the kernel, not an upper estimate for the number of ambiguous candidates.

The package additionally proves the coupled resolution identity

\[
\boxed{\frac{\operatorname{lcm}_i A_i}{\gcd(M,\operatorname{lcm}_i A_i)}
=\operatorname{lcm}_i\left(\frac{A_i}{\gcd(M,A_i)}\right).}
\]

The proof reduces divisibility using the GCD laws, combines it through LCM divisibility, and establishes equality by mutual divisibility. It uses the standard library's actual `Nat.gcd` and `Nat.lcm`, rather than assuming a purported resolution law as a certificate.

`resolution_minimal` proves that R is an invisible coordinate change and that every positive invisible change is at least R. `resolution_pos` proves R>0 from positive anchors.

## Source observations, windows and targets

For a fixed reference r and coordinates k,j,

\[
\left(\forall i,\ (r+Mk)\bmod A_i=(r+Mj)\bmod A_i\right)
\quad\Longleftrightarrow\quad R\mid(k-j).
\]

If k,j lie in the same half-open signed interval [ℓ,ℓ+R), they are equal. This is the checked uniqueness condition; no stored quotient register is introduced.

The total source ambiguity period is

\[
\boxed{MR=\operatorname{lcm}(M,A_1,\ldots,A_n).}
\]

`main_and_anchor_readings_iff` proves the corresponding observational statement, beyond the numerical equality: the main and all anchor residue readings of X and Y agree exactly when MR divides X−Y.

For a fixed reference and every integer coordinate, the desired residue modulo b is determined by the anchor observations exactly when

\[
\boxed{b\mid MR.}
\]

`combined_target_iff` proves both directions. Sufficiency transports the invisible coordinate multiples into multiples of b; necessity compares coordinates R and zero. Thus the target criterion previously derived on paper is now checked as an integer specialization. A bounded exact-coordinate window can enable other targets; the theorem here concerns unrestricted coordinates and a fixed reference.

`dependent_anchor_resolution` proves that adding a modulus already dividing the existing LCM leaves R unchanged. This makes the capacity consequence of dependent observations explicit.

## Scope and integration

These are kernel, capacity, uniqueness and exact-target theorems. They do not implement a multi-anchor fusion decoder, create authentic new readings, or prove constant-time GCD/LCM computation. The existing `IntegerSpecialization.lean` supplies the separate certified reduced-congruence readout. Together these modules establish the correct resolution available to such a solver and the exact conditions on its consumer.

The source's main modulus and anchor moduli are naturals; coordinate/source values are signed integers. Positivity is explicit where a positive finite resolution is needed. Some purely algebraic lemmas also cover zero moduli through Lean's totalized remainder convention; that does not make modulus zero a physical RNS lane.

The build uses only foundational `propext`, `Quot.sound`, and, in four algebraic rewriting proofs, `Classical.choice`. No theorem depends on `sorryAx` or a project axiom. This phase adds formal verification and does not claim new empirical benchmarks or a production NINE65 change.

Reproduce from this directory using the pinned toolchain:

```sh
lean +leanprover/lean4:v4.27.0-rc1 -o CoupledAnchors.olean CoupledAnchors.lean
```
