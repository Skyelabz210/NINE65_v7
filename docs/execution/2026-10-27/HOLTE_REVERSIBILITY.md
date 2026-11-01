# Holte carry reversibility: exact statement, proof, and regressions

For independent uniform driving digits in integer base `M >= 2`, the Holte
carry chain on `n >= 1` summands is reversible exactly when `n <= 3`. For every
`n >= 4`, the single stationary corner flux from state 0 to state 1 already
witnesses failure of detailed balance. This document gives an ordinary
mathematical proof for all arities and bases. The accompanying Python script
checks finite instances with exact integers and rationals; neither artifact
claims a Lean, Coq, or other proof-assistant certification.

## Model and the meaning of iid

Let `D[t,r]`, for time `t >= 0` and summand `1 <= r <= n`, be independent and
identically distributed uniforms on `{0,...,M-1}`. With `C[t]` the incoming
carry, define

```text
C[t+1] = floor((C[t] + sum_r D[t,r]) / M).
T[i,j] = #{digit tuples d : floor((i + sum_r d[r])/M) = j}.
P[i,j] = T[i,j] / M^n,              0 <= i,j <= n-1.
```

The iid hypothesis applies to the driving digits. The carry process can be
correlated across time. For example, at `n=2, M=36`, the stationary law is
`(1/2,1/2)` but `P[0,0]=37/72`, so consecutive carries are dependent. This
does not violate the driving-digit hypothesis. A test of joint independence
of all output coordinates is a diagnostic for that separate property; its
failure does not reject the Holte model or, by itself, an operation policy.

Write `A(n,j)` for the Eulerian number counting permutations of `n` elements
with `j` descents. The stationary distribution is

```text
pi[j] = A(n,j)/n!,       A(n,0)=1,       A(n,1)=2^n-n-1.
```

For the model, transition formula, and Eulerian stationary law, see
Diaconis and Fulman, [*Carries, Shuffling, and Symmetric Functions*,
arXiv:0902.0179](https://arxiv.org/abs/0902.0179), Section 1.1 and Theorem 2.5.
The proofs below derive the corner sign and coefficient claims explicitly.

## Exact corner counts by inclusion and exclusion

For the sum `Z=sum_r d[r]` of `n` digits, let `F(s)=#{d: Z<=s}`. Stars and bars
with inclusion and exclusion gives

```text
F(s) = sum_(ell=0)^n (-1)^ell * binom(n,ell)
                         * binom(s-ell*M+n,n),
```

where the last binomial is zero when its upper argument is less than `n`.
For `n >= 2`, the corner events are

```text
T[0,1] = F(2M-1)-F(M-1)
       = binom(2M+n-1,n) - (n+1)*binom(M+n-1,n),
T[1,0] = F(M-2)
       = binom(M+n-2,n).
```

The first formula counts the entire interval `M <= Z <= 2M-1`; it is not
merely a CDF at its upper endpoint. In `F(2M-1)`, only terms `ell=0,1` survive.
In the other two CDFs only `ell=0` survives.

Define the signed integer count gap

```text
Delta[n,M] = T[0,1] - (2^n-n-1)*T[1,0].
```

Then the signed stationary corner flux is exactly

```text
pi[0]*P[0,1] - pi[1]*P[1,0] = Delta[n,M] / (n! * M^n).
```

A nonzero corner gap therefore proves nonreversibility. Its absolute flux
is a lower bound on the maximum detailed-balance defect. The corner need
not attain that maximum at every arity and base.

## All-arity sign proof

Fix `M >= 2` and put

```text
t   = M-1 > 0,
B_n = binom(M+n-2,n) > 0,
R_n = binom(2M+n-1,n) / B_n,
H_n = 2^n + n*(n+1)/t.
```

The ratio `binom(M+n-1,n)/B_n=(M+n-1)/(M-1)` shows directly that

```text
Delta[n,M]/B_n = R_n-H_n.
```

At `n=3`, direct cancellation gives `R_3=H_3=8+12/t`. The binomial ratios
also give

```text
R_(n+1) = R_n*f_n,
f_n     = (2t+n+2)/(t+n) = 2-(n-2)/(t+n) > 0.
```

The exact slack of the proposed upper bound is

```text
H_(n+1)-H_n*f_n = (n-2)*(2^n-n-1)/(t+n) > 0     for n >= 3.
```

Thus `R_4 < H_4`. Multiplying `R_n < H_n` by the positive factor `f_n` and
adding the strictly positive slack proves `R_(n+1) < H_(n+1)`. Induction
establishes

```text
Delta[n,M] < 0       for every integer n >= 4 and M >= 2.
```

This is an all-arity proof, independent of the size of a checked table.

## Positive Newton coefficients at arbitrary arity

The coefficient claim also has a general proof. Set `G_n(M)=-Delta[n,M]`.
Multiplying the ratio recurrence by `B_(n+1)=B_n*(M+n-1)/(n+1)` gives

```text
G_(n+1)(M) = ((2M+n)*G_n(M)
              + (n-2)*(2^n-n-1)*binom(M+n-2,n)) / (n+1).
```

Here `G_3=0` and `G_4=binom(M+1,3)`. Put `u=M-2`. The new multiplier is
`2u+n+4`, while

```text
binom(M+n-2,n) = product_(r=1)^n (u+r) / n!.
```

Every coefficient of that polynomial is strictly positive. Starting from
`G_4=(u+1)(u+2)(u+3)/6`, the recurrence proves that `G_n(u+2)` has strictly
positive ordinary coefficients in every degree `0,...,n-1`, for every
`n >= 4`. Its degree is exactly `n-1`.

To convert to the Newton basis, use the identity

```text
u^r = sum_(j=0)^r j! * Stirling2(r,j) * binom(u,j).
```

The Stirling numbers are nonnegative, and the contribution of the positive
ordinary coefficient of `u^j` is itself positive. Consequently

```text
G_n(M) = sum_(j=0)^(n-1) a[n,j]*binom(M-2,j),
a[n,j] = (forward_difference^j G_n)(2) > 0.
```

These Newton coefficients are integers because they are finite differences
of integer values. The first rows are

```text
n=4: [1, 3, 3, 1]
n=5: [6, 24, 36, 24, 6]
n=6: [22, 111, 224, 226, 114, 23]
n=7: [64, 392, 1000, 1360, 1040, 424, 72]
n=8: [163, 1178, 3646, 6265, 6455, 3988, 1368, 201]
```

## Low arities and exact examples

At `n=1`, the one-state matrix is `[1]`. There is no state 1 and hence no
`0 -> 1` corner. For `n=2`,

```text
P = 1/(2M) * [[M+1, M-1], [M-1, M+1]],     pi=(1,1)/2.
```

For `n=3`, writing `b=M`,

```text
P = 1/(6b^2) * [[b^2+3b+2, 4b^2-4, b^2-3b+2],
                 [b^2-1,   4b^2+2, b^2-1],
                 [b^2-3b+2, 4b^2-4, b^2+3b+2]],
pi=(1,4,1)/6.
```

The weighted matrices `diag(pi)*P` are symmetric, proving detailed balance
for every base at these low arities. Direct evaluation gives `Delta=0` at
`n=2,3`; zero for only one corner would not by itself prove reversibility.

The supplied factorizations are exact. With `F=M*(M-1)*(M+1)`, they are

| n | Delta[n,M] |
|---|---|
| 4 | `-F/6` |
| 5 | `-F*(M+2)/4` |
| 6 | `-F*(M+2)*(23M+64)/120` |
| 7 | `-F*(M+2)*(M+3)*(3M+10)/30` |
| 8 | `-F*(M+2)*(M+3)*(67M^2+512M+990)/1680` |

The resulting exact corner table is:

| n | M=2 | M=3 | M=4 | M=5 | M=10 | M=36 |
|---|---:|---:|---:|---:|---:|---:|
| 4 | -1 | -4 | -10 | -20 | -165 | -7770 |
| 5 | -6 | -30 | -90 | -210 | -2970 | -442890 |
| 6 | -22 | -133 | -468 | -1253 | -29106 | -13168596 |
| 7 | -64 | -456 | -1848 | -5600 | -205920 | -271757304 |
| 8 | -163 | -1341 | -6165 | -20900 | -1177605 | -4369748877 |

Two compact regressions are `Delta[4,M]=-binom(M+1,3)` and
`Delta[5,M]=-6*binom(M+2,4)`. The corner fluxes at `(4,2)` and `(5,10)` are
respectively `-1/384` and `-99/400000`. The existing maximum-defect tests
check the corresponding positive absolute values, which coincide with the
corner magnitudes at those two particular inputs.

## Order in a centered chart

Separately from the stochastic chain, let `Q` be a positive integer and choose one common chart
of exactly `Q` consecutive integers, `a <= g <= a+Q-1`. For the exact identity
`S=g+KQ`, numerical order of `S` equals lexicographic order of `(K,g)`. If
`K'>K`, then

```text
S'-S = (K'-K)*Q+(g'-g) >= Q-(Q-1) = 1.
```

When `K'=K`, the sign is the sign of `g'-g`. A centered convention is
`a=-floor(Q/2)`, including the even-Q boundary convention
`-Q/2 <= g <= Q/2-1`. Then `K=floor((S-a)/Q)` and `g=S-KQ` as an ordinary
integer identity. The common contiguous chart matters: at `Q=10`, pairs
`(K,g)=(0,20)` and `(1,0)` have opposite numerical and lexicographic orders.

This order identity does not supply an encrypted algorithm for obtaining,
authenticating, or comparing `K`, nor does it define a new native divider.
Those operations require their own permitted implementation and provenance.

## Reversibility is not operation inversion

Detailed balance is the stationary equality
`pi[i]*P[i,j]=pi[j]*P[j,i]`; it says a stationary stochastic trajectory has
the same law under time reversal. An algebraic inverse instead recovers an
individual input from a particular output with all necessary state retained.
Neither property implies the other. In particular, a reversible carry chain
does not make a lossy quotient operation invertible, and a stored quotient
and remainder do not force the resulting carry chain to be reversible.

## Executable coverage and limits

Run `python3 scripts/check_holte_reversibility.py` from the repository root.
The script uses only the standard library and retains its checks under `-O`.
It independently obtains transition counts by digit-sum DP, then checks:

- All row masses, Eulerian stationarity, explicit low-arity matrices,
  corner identities, and the reversibility dichotomy at 144 cases:
  `1 <= n <= 12`, `M in {2,...,12,36}`.
- Corner signs, closed forms, ratio slack, and polynomial recurrence at
  1,914 big-integer cases: `2 <= n <= 30`,
  `M in {2,...,64,127,256,65536}`. Recurrence checks also evaluate `n+1`.
- Exact Newton coefficients at `4 <= n <= 30`, with independent evaluation
  of their Newton expansions at additional bases.
- The displayed table, both existing defect constants, and 539 centered
  chart states with positive and negative windings.

The source implementation in
[`cram_carry.rs`](../../../../crates/exact_transcendentals/src/cram_carry.rs)
already counts digit sums and computes Eulerian stationarity and maximum
detailed-balance defect with `i128` rational arithmetic. Its unit tests and
[`cram_gates.rs`](../../../../crates/exact_transcendentals/tests/cram_gates.rs)
check stationarity for `2 <= n <= 5`, bases `{2,10,36}`, reversibility for
`n=2,3`, nonreversibility for `n=4,5` at those bases, and the two defect
constants. Those finite tests alone do not prove the general dichotomy.
The new Python grid uses arbitrary precision; it does not establish that
the Rust `i128` implementation supports the Python grid's entire domain.

The new integration target
[`holte_reversibility.rs`](../../../../crates/exact_transcendentals/tests/holte_reversibility.rs)
adds independent inclusion-and-exclusion counts, tiny exhaustive digit words,
Eulerian checks, and the factored/Newton tables on finite grids through
`n=8`, `M=64`. It also pins a dependent but reversible carry example.
Those regressions exercise the production carry implementation; the
all-arity claim follows from the induction above.
