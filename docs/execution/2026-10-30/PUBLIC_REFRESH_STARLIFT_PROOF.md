# Public refresh: digit extraction and StarLift capacity proof

This proof concerns the digit primitive's plaintext arithmetic and the
capacity of proposed StarLift coordinates. It does not certify a protected
coordinate producer, CRAM root binding, or production security. The circuit
uses the plaintext rings `Z/p²Z` and `F_p` with `p = 65537`; its certified
residual support is `-49 <= r <= 49`. Write a slot as

```text
x = r + p K    (mod p²).
```

Here `K` is an integer lift used in the proof. The primitive recovers
`k = K mod p`, canonically represented by `0 <= k <= 65536`. The radius 49
applies to `r`. **Correction, 2026-10-31:** the native producer also supplies
the independent source-norm bound `|K| <= 48`, proved and wired in the
[lift refinement](../2026-10-31/PUBLIC_REFRESH_LIFT_REFINEMENT.md). Thus the
unrestricted primitive's 65,537-state capacity requirement does not apply to
the native producer's 97-state signed support. The earlier inference that
36/37 was insufficient for this producer was too broad.

## 1. The circuit's extracted quantity

Let `B = 49` and `G(X) = product_{j=-B}^B (X-j)`. The 99 support elements are
distinct in `F_p` because `2B = 98 < p`. Thus every `G'(r)` is nonzero modulo
`p`, and interpolation gives a polynomial `H` over `F_p` with
`H(r) = G'(r)^(-1)` at each supported `r`.

**Theorem 1.** For every integer `K` and supported `r`, `G(x)` is divisible by
`p`, and the circuit's pointwise digit expression is `K mod p`:

```text
(G(r+pK) / p) H(r) = K    (mod p).
```

**Proof.** Expand `G` at `r` over the integers. Since `G(r)=0`, all terms of
degree at least two in `pK` are multiples of `p²`. Therefore
`G(r+pK) = pK G'(r) (mod p²)`. Its residue modulo `p²` is divisible by `p`,
and division by `p` gives `K G'(r) (mod p)`. Multiplication by `H(r)` cancels
the nonzero derivative. Replacing `r+pK` by any congruent representative
modulo `p²` leaves that quotient residue unchanged. QED.

The native slot circuit implements this identity under encryption. Applying
the identity to every ciphertext slot additionally requires the circuit's
coherent slot views, source relation, residual bound, and noise certificate;
the polynomial identity alone does not establish those conditions.

**Information limit.** `r+p(K+p t) = r+pK (mod p²)` for every integer `t`.
For example, `(r,K)=(0,0)` and `(0,65537)` produce the same plaintext ring
element. No deterministic operation on this `p²` plaintext can derive the
unbounded integer `K` or an epoch counting these lost multiples of `p`.
This is independent of which StarLift moduli are later chosen. It does not
prevent recovery of the canonical `k = K mod p`. Indeed, `K=0` and `K=p`
would demand different direct StarLift residues for the integer `K`:
`p mod (36,37,73) = (17,10,56)`, versus `(0,0,0)` for zero. StarLift must
specify its representative and interval: canonical k for the unrestricted
primitive, or the separately certified signed K for the native producer.

## 2. Exact capacity of 36/37 and 36/37/73

For positive moduli `m_i`, let `V(k) = (k mod m_i)_i` and
`L = lcm(m_i)`. Two integers have the same `V` exactly when their difference
is divisible by `L`. Consequently `V` is injective on the whole canonical
interval `0 <= k < p` **if and only if** `L >= p`: if `L < p`, `0` and `L`
collide; if `L >= p`, two distinct integers in the interval differ by less
than `p` and cannot differ by a nonzero multiple of `L`.

For the shell 36 and first star anchor 37, `L = 36*37 = 1332 < 65537`.
The explicit collision is `V(0)=V(1332)=(0,0)`. Thus this pair cannot be a
complete coordinate system for an arbitrary canonical field value `k`.
If instead the pair encodes `r+49` in `[0,98]`, it identifies that residual,
but every value of `K` with the same `r` still has that same residual view.

Adding star anchor 73 gives pairwise-coprime moduli `36,37,73` and
`L = 36*37*73 = 97236 > 65536`. The resulting three-residue map is
injective on `0 <= k <= 65536`. This is a **capacity theorem**: if authentic
protected views of the same canonical `k` in all three moduli are produced,
their values uniquely identify `k` within that public interval. The theorem
does not produce or authenticate those views.

## 3. K-elimination interpretation, derived on demand

For a canonical `k`, put `g = k mod 36` and `q = floor(k/36)`. Then
`k = g + 36q` and `0 <= q <= floor(65536/36) = 1820`. If `a_37` and `a_73`
are authentic same-value views of `k`, reduction of this identity gives

```text
q mod 37 = (g - a_37) mod 37,       since 36^(-1) = -1 (mod 37),
q mod 73 = 2(g - a_73) mod 73,     since 36^(-1) = -2 (mod 73).
```

These are on-demand winding queries; they do not require a persistent `q`
coordinate. The two anchor residues determine `q mod (37*73)`, and
`37*73 = 2701 > 1820`, so they determine the bounded `q` uniquely. This
proves the same capacity result as Section 2 through K-elimination. It is a
mathematical uniqueness argument, not a request to add Garner or scalar
reconstruction to the runtime graph.

For the 36/37 pair alone, only `q mod 37` is available. Both `k=0` and
`k=1332` have `g=0` and `q mod 37=0`, while their exact `q` values are
`0` and `37`. This example concerns arbitrary `k`. For the newly certified
native support, use `Y=K+48` in `[0,96]`; then `floor(Y/36) <= 2 < 37`.

## 4. Consequence for wiring

The existing circuit obtains and consumes encrypted `k` without maintaining
a StarLift coordinate. Its newly certified signed support makes 36/37
arithmetically sufficient for `Y=K+48`. A protected producer for both views
of that same shifted quantity, with a source binding and an encrypted
consumer, is still necessary. The capacity theorem does not supply it.
Canonical remainder maps are generally nonlinear: `65536+1=0` in `F_p`,
while `(65536 mod 36)+1=17` modulo 36. The bounded-domain projection cost
is evaluated separately in the refinement.

The native producer bound also excludes the `K` versus `K+p` ambiguity in
Section 1 for its per-refresh correction. It does not encode an unbounded
historical winding or make a phase-defect congruence an authentication proof.
Source lineage remains distinct from an arithmetic winding ledger.

Run `python3 scripts/verify_public_refresh_starlift_proof.py` for an
independent exact-integer check of the polynomial identity at all 99 support
points and boundary quotient lifts, plus exhaustive capacity and on-demand
K-elimination checks over all 65,537 canonical `k` values. The algebraic
proof above covers every integer `K`; the script is a regression oracle,
not a formal Lean proof or a cryptographic admission certificate.
