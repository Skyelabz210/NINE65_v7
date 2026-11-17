# Concrete residue primitives and bounded divmod/GCD

`ResiduePrimitives.lean` supplies the concrete implementation needed to discharge
`ResidueAlgorithms.Correct`. Fourteen theorem declarations compile with pinned
Lean 4.27.0-rc1 and bundled Std. [primitives-build.log](primitives-build.log)
contains the compiler/axiom output; [primitives-axiom-audit.json](primitives-axiom-audit.json)
records the source hash and each theorem's dependencies. There are no admitted
proofs or project axioms; dependencies are standard `propext`, `Classical.choice`,
and `Quot.sound` only.

## Exact representation and computational interface

A public `Frame` contains positive natural moduli M,A, an integer inverse u, and
the certificate u*M ≡ 1 (mod A). Its capacity is M*A. The complete runtime
`State` contains only two fields:

```text
main   : Int
anchor : Int
```

On the admitted natural domain 0 ≤ n < M*A, their semantic meaning is
`main=n%M`, `anchor=n%A`. `Frame.encode` is the specification/declared ingress
map; none of the arithmetic runtime definitions call it.

The actual primitive operations are:

- `kQuery`: the existing modular subtraction/multiplication query, derived on
  demand from the two observations. No K or scalar n is a state field.
- `less`: lexicographic comparison of transient `(kQuery, main)` coordinates.
- `increment`: add one and reduce independently in each lane.
- `subtract`: subtract and reduce independently in each lane, with the
  nonnegative-semantic-difference precondition proved by the calling loop.
- `isZero`: test whether both stored residue fields equal the zero state.

`kQuery_exact` derives the actual quotient n/M on the admitted window from the
proved integer query. `euclidean_lex_order` proves the ordinary signed integer
order equivalence for quotient/remainder coordinates under positive M;
`less_encode` then proves the concrete comparator. Lane-wise increment and
nonnegative subtraction preserve their encoded semantics. Encoding is injective
on the admitted window; this proves zero-test correctness there.

`Frame.adjacent M` constructs the public inverse -1 for A=M+1 directly from the
proved star-anchor formula. `adjacent_query` proves the resulting query is one
modular subtraction. The main result is more general: it applies to any positive
M,A equipped with the inverse certificate, not only adjacent frames.

## Closed concrete algorithm proofs

`Frame.ops` supplies only the executable operations and public capacity to the
generic algorithm. The theorem `ops_correct` proves every field of its primitive
contract from these concrete definitions. No correct comparator, division
result, GCD result, or semantic decoder is assumed.

`Frame.divmod` calls the actual generic repeated-subtraction loop. For all
natural n,d with n,d<M*A and d>0, the compiled theorem proves

```text
Frame.divmod (encode n) (encode d)
  = some (encode (n/d), encode (n%d)).
```

There is no assumption that d is coprime to either M or A, and no assumption
that d divides n. Thus arbitrary positive admitted divisors, shared factors,
and inexact divisions are covered. Division by an encoded zero is proved to
return `none`, for any supplied dividend state.

`Frame.gcd` calls the actual Euclidean loop over that division program. For
all natural a,b<M*A, including zeros, its compiled correctness theorem is

```text
Frame.gcd (encode a) (encode b) = some (encode (Nat.gcd a b)).
```

The quotient accumulator and each remainder are residue states. The algorithms
receive public frame capacity as fuel; neither fuel nor any loop operation is
computed from a scalar source oracle. Semantic integers in the correctness
statements are proof variables. The loop's mathematical quotient accumulator
is represented by two residues; it is distinct from a forbidden persistent
scalar K associated with the representation frame.

## Scope and integration

These are proofs of a concrete bounded clear arithmetic model, connected to
the universal theorem through the already checked integer readout. Repeated
subtraction is deliberately simple and data dependent. The result proves
existence, closure and actual executable correctness without scalar
reconstruction; it does not establish an efficient division implementation,
a constant-time program, an encrypted circuit or Rust/NINE65 refinement.

Runtime observations must be authentic encodings in the admitted window.
The proof does not validate arbitrary malformed states or detect all values
that were encoded after exceeding capacity. No full scalar reconstruction,
Garner/MRC, persistent scalar magnitude or persistent scalar K is introduced.

Run from this directory after its imports have been compiled:

```sh
ELAN_HOME=/workspace/k-elimination-audit/proof-check/elan LEAN_PATH=. \
  /workspace/k-elimination-audit/proof-check/elan/bin/lean \
  -o ResiduePrimitives.olean ResiduePrimitives.lean
```

The integrated clean-build checker maintained by the parent is the preferred
reproduction route once this module is included in its dependency list.
