# The Nine-Plus Acts of K-Elimination

Every act below deploys the same standing number `k = (s − r)·M⁻¹ mod A = ⌊X/M⌋`.
What differs is the utility extracted. This is the discriminator for act selection:
match the user's need to the **Utility** field, not the mechanism.

Table of contents:
1. Exact in-residue division
2. Magnitude accounting
3. Sign detection
4. Magnitude comparison
5. Overflow / winding tracking
6. Scaling / division-by-constant
7. Lossless transfer (dual codex)
8. Non-coprime division (Fused Piggyback Division, FPD)
9. Magnitude lifting (κ-ladder / anchor tower)
+. Transduction (the fifth operator)
+. Four-Division Chimera (certified dispatch)
+. Operational completeness (the meta-purpose)

---

## Act 1 — Exact in-residue division

**Utility.** Compute `⌊X/m⌋` exactly without leaving residue space and without
multi-precision integer division. Closes the 60-year RNS division obstacle.

**Mechanism.** To divide by a basis lane `m`, consume lane `m`: read `k` against
each surviving lane. The quotient is then already addressed on the remaining lanes;
the remainder is `r = X mod m`, held in the consumed lane.

**Worked instance** (basis {7, 11, 13}, X = 500, divide by 7; residues (3,5,6)):
- K-Elim(7,11): k = (5−3)·7⁻¹ mod 11 = 8
- K-Elim(7,13): k = (6−3)·7⁻¹ mod 13 = 6
- Quotient ⌊500/7⌋ = 71 is now addressed as (8 mod 11, 6 mod 13); check 71 mod 11 = 8,
  71 mod 13 = 6. Remainder r = 3 = 500 mod 7 in the consumed lane. The integer 500 was
  never assembled.

**Cost.** One modular subtraction + one modular multiply per surviving lane;
lane-parallel, O(log n). **Precondition.** Divisor is a basis lane (for a general
coprime divisor use scaling/Act 6; for a shared-factor divisor use FPD/Act 8).
Validated exact past 4.9M instances.

---

## Act 2 — Magnitude accounting

**Utility.** Recover the integer magnitude of a residue-encoded value on demand —
the bridge between residue space (where exact arithmetic lives) and integer space
(where magnitude lives). Magnitude is *recovered*, never approximated.

**Mechanism.** The winding `w` of a value is exactly the K-Elimination quotient read
against an anchor. A value accumulated with its winding tracked carries its own
magnitude; a value *without* tracked winding still yields magnitude on demand,
because divisor and value together determine the quotient's winding.

**Cost.** 1 modular subtraction + 1 modular multiply per lane. **Precondition.** An
anchor coprime to the shell (adjacent anchor → subtraction only).

---

## Act 3 — Sign detection

**Utility.** Determine whether X is positive or negative in a signed residue range,
without reconstruction. Historically an O(k²) CRT operation; here near-constant-time.

**Mechanism.** In a signed layout over `[0, M)` with sign split at `M/2`, the winding
`k` against the anchor places X relative to the corridor. If `k < A/2` (equivalently
the recovered magnitude < M/2) the value is on the positive sheet, else negative.
Corridor-bounded: valid over the signed range up to `M/2`.

**Cost.** O(1) once k is in hand. **Precondition.** Corridor ≤ M/2; use the largest
odd basis prime as the sign-proxy lane (smallest prime m=2 gives a degenerate
zero-width corridor — a known failure mode, designate a larger lane).

---

## Act 4 — Magnitude comparison

**Utility.** Decide `X > Y` for two residue-encoded values without reconstructing
either. The classical RNS "magnitude problem."

**Mechanism.** Recover the winding/magnitude of each via K-Elim against a shared
anchor, then compare as tuples: compare windings `K_X` vs `K_Y` first; on a tie,
compare the in-window residues. `(K, r)` ordering is the integer ordering.

**Cost.** Two K-Elim reads + a lexicographic compare. **Precondition.** Shared anchor;
both values in the supported window (else lift, Act 9). Validated 1.4M comparison ops
at 100%.

---

## Act 5 — Overflow / winding tracking

**Utility.** Track how many times an accumulation has wrapped the shell — a running
ledger of magnitude across a long chain of additions/multiplications, so the lifted
integer `X = residues + K·M` is always available exactly.

**Mechanism.** Carry a winding ledger `K ∈ ℤ` alongside the residue tuple. On each
operation that crosses a shell boundary, increment/adjust K (linear propagation for
add/scale; for nonlinear steps, evaluate on the lifted value). This is K-Elimination
used *continuously* rather than on-demand — the standing-object deployment.

**Cost.** O(1) ledger update per operation. **Precondition.** Ledger carried from
encode time. Verified for linear (heat/Poisson) and nonlinear (Burgers) propagation,
including mixed and negative windings, 30-step deep chains.

---

## Act 6 — Scaling / division-by-constant

**Utility.** Multiply or divide a residue value by a constant `c` exactly, residue-
native (e.g. learning-rate steps, batch-size division, rational operations).

**Mechanism.** For `c` coprime to a lane prime `p`: result lane = `r · c⁻¹ mod p`
(division) or `r · c mod p` (scaling) — one modular op per lane, O(1) per lane. This
is the CRAM DIV lane: the inline per-cell workhorse. When `gcd(c, basis) > 1`, this
lane fails and you route to FPD (Act 8).

**Cost.** One modular multiply per lane. **Precondition.** `gcd(c, p) = 1` on the
lanes used; otherwise Act 8.

---

## Act 7 — Lossless transfer (dual codex)

**Utility.** Move a computation between two codices (or bases) — e.g. between security
domains, or a primary and reference manifold — with O(k) overhead and **zero CRT
communication**, no full decrypt/re-encrypt, with fault tolerance via disagreement
detection between the two codices.

**Mechanism.** Represent X in two coprime codices `(C_P, C_R)`. The phase differential
`k = (r_R − r_P)·C_P⁻¹ mod C_R` connects them; the value transfers by re-addressing
through k rather than reconstructing. "k was never lost — it is encoded in the phase
differential between manifolds." Transfer is O(k), not O(k²).

**Cost.** O(k) transfer. **Precondition.** Two coprime codices. Validated: dual-codex
transfer and roundtrip at 0 errors.

---

## Act 8 — Non-coprime division (Fused Piggyback Division, FPD)

**Utility.** Compute `X/b` even when `gcd(b, basis) > 1` — the case where the direct
lane inverse (Act 6) does not exist. Removes the coprimality requirement on the divisor.

**Mechanism.** Piggyback onto auxiliary coprime anchors: solve `X/b` exactly in each
of several anchors coprime to `b`, then fuse. Emit an error certificate `error_bound =
gcd(P, M)` (P = anchor product) — a mathematical guarantee, or the coupled-anchor
resolution law (see `coupled-anchor.md`) which removes the precondition entirely.

**Cost.** k anchor solves + fuse, + certificate. **Precondition.** Auxiliary anchors
coprime to b available (catalog: 23,29,31,37,41,43,47…). FPD alone ~99.9998%; the
coupled-anchor generalization is exact.

---

## Act 9 — Magnitude lifting (κ-ladder / anchor tower)

**Utility.** Recover magnitude for values far exceeding a single shell window —
unbounded magnitude at **linear** cost in the number of anchors.

**Mechanism.** Hold a separator lane open (e.g. shadow prime 11), define magnitude
`K₁₁ = ⌊N/11⌋`, then lift `K₁₁` against successive star anchors and put the readings
against each other: double lift {37,73} exact to 11·37·73 = 29,711; triple lift
{37,73,181} exact to 5,377,691. Each added coprime anchor multiplies the window at
one pairwise combine — linear cost, exact at every size.

**Cost.** One pairwise combine per added anchor (linear). **Precondition.** Anchor
tower of pairwise-coprime anchors. See `coupled-anchor.md` for the resolution law
`R = lcm(anchors)/gcd(M, lcm)` and the fixed-anchor-set unbounded form.

---

## + Transduction (the fifth operator, 𝒳_{A→B})

**Utility.** Move a value between bases while carrying **value + winding + operator
schema**, staying in residue space — the operation that makes heterogeneous CRAM lanes
composable and enables in-space basis GROWTH for arbitrary precision. No RNS analog
(RNS base-extension is value-only, window-0, homogeneous, and drops winding).

**Mechanism.** Package `(Φ, Θ, Π, Ω)` = value map, signature transport, topology
transport, winding policy. Carries winding so over-window values survive the change;
reversible (A→B→A identity); transports the per-lane operator schema. Act 6's lanewise
coprime division is its in-frame degenerate instance (Φ = ·d⁻¹, identity transport,
winding preserved). Machine-checked composition with the tower: see `proofs.md`.

---

## + Four-Division Chimera (certified single-cycle dispatch)

**Utility.** One certified branch over the four disjoint single-shot integer-quotient
kernels, so a divide "just works" regardless of the divisor's relationship to the basis.

**Mechanism.** Parallel-evaluate {INV (direct modular/lanewise inverse), K-Elim,
DivExact (FPD factor-split specialization), FPD multi-anchor} and emit a
`ChimeraResolverCertificate` naming the taken path. The four kernels are genuinely
disjoint (INV and DivExact are distinct: direct modular inverse vs FPD factor-split),
exhaustive over the single-shot quotient kernel space. Parallel eval removes branch-
prediction penalty. (Historical note: some early docs say "Five-Division Chimera";
**four** is canonical for the Chimera; the ordinal "fifth operator" is reserved for
Transduction / lineage extraction, a naming collision resolved in the corpus.)

**Finite-Inv Principle.** The validity product `V = ∏_{i: rootᵢ=÷} (pᵢ−1)/pᵢ → 0`
as more division-assigned primes enter (same statement as the divergence of Σ1/p).
Valid division has finite support — a design constraint on how many lanes carry ÷.

---

## + Operational completeness (the meta-purpose)

**Utility.** This is the purpose that contains the others: by supplying exact division
and magnitude in-residue, K-Elimination makes residue space a **complete computational
substrate** rather than an add/subtract/multiply-only island. Comparison, sign, scaling,
transfer, and division — every operation RNS classically had to leave residue space
for — become native. That closure is the reason the whole CRAM stack (exact PDE solvers,
residue-space learning, arbitrary-precision integer work) is possible at all.

**Under A2 (2026-07-22):** the operation formerly called "reconstruction" is obsolete —
magnitude and number-line/adelic representation are derived through K-Elimination and a
simple modular subtraction, never a mixed-radix assembly in residue space. The line
between the integer on the number line and the residues in CRAM space is obliterated:
algorithms use residue operations in the same breath as integer operations.

**Saturation Principle (2026-07-22):** primality is not a prerequisite of residue-space
utility under CRAM, and coprimality also loses its required nature — through product-space
saturation via the Safe Basis remaining intact and the work on the identity of a number,
the system shares its satisfaction of primality/coprimality, enabling arbitrary composite
utility. (Coupled-anchor recovery, `coupled-anchor.md`, is the concrete mechanism behind
the coprimality half of this.)
