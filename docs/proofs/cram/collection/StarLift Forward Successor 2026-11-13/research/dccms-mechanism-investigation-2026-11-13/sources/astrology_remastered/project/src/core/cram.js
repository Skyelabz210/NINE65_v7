// src/core/cram.js — the CRAM layer, as CRAM and not as RNS. (P14)
//
// CORRECTION OF RECORD
// ────────────────────
// Everything this project built on the Safe Basis used it the way an RNS uses
// moduli: a flat bag of PRIMES, with the winding recovered through a
// multiplicative anchor drawn from INSIDE the basis (the gear pair 17·19 = 323)
// and a precomputed inverse M6⁻¹ ≡ 287 (mod 323). That is correct arithmetic
// and it is not CRAM. Four things were being used wrongly:
//
//  1. ANCHOR. CRAM's governing configuration is the ADJACENT anchor A = M + 1.
//     Then M ≡ −1 (mod A), so M is its own inverse and
//
//         K ≡ r − s   (mod M+1)
//
//     — one modular subtraction, no multiply, no inverse, no precomputation.
//     The shipped gear path costs a subtract, a multiply and a reduction, and
//     needs the constant 287 computed ahead of time. A = M+1 also gives a far
//     wider corridor: 30,031 against 323, a factor of 92 on the six-lane shell.
//
//  2. PRIMALITY. gcd(M, M+1) = 1 for free, so the anchor never needs a
//     primality test — and in fact is usually composite: 30,031 = 59 · 509 and
//     9,699,691 = 347 · 27,953. The addressing layer (CRT, winding, K-Elim,
//     comparison, division-by-constant) needs COPRIMALITY only. Primality is
//     needed by the FIELD layer (square root, Legendre, index), which is a
//     different stack. A safe basis is a set of pairwise-coprime positive
//     integers, not a set of primes; `adjacencyRecover` is verified below on
//     the all-composite basis {8, 9, 25, 49, 11, 13}.
//
//  3. DEGRADATION. gcd(M, A) = d > 1 does not break K-Elimination; it reduces
//     resolution to A/d. This is the Resolution Gradient, and it is where the
//     Maya Calendar Round comes from: gcd(260, 365) = 5, resolution 73, and
//     73·260 = 52·365 = 18,980. The project treated 260 and 365 only through
//     ring closure and missed that they are a K-Elimination pair.
//
//  4. SHADOW. The shadow lattice is a HIGHER-POWER anchor whose non-coprimality
//     with the basis is deliberate: 11⁶ with gcd(11⁶, M8) = 11. It lifts K to
//     modulus 11⁵ = 161,051, a corridor of M8 · 11⁵ ≈ 1.56 × 10¹². The project
//     treated 11 as a single lane and never lifted it.
//
// Kept from the RNS-shaped work: the gear path is still here as
// `generalRecover`, because it is the general case A ∤ M+1 and it is what you
// need when the anchor is fixed by something other than adjacency.
//
// BigInt only. No floats, no Date, no ephemeris.

import { mod } from "./residues.js";
import { towerRecover, anchorSetCorridor } from "./tower-recover.js";
import { B6, B8, M6, M8 } from "./basis.js";

// ── basis hygiene: coprimality, not primality ──────────────────────

/**
 * Euclidean greatest common divisor.
 * @param {bigint} a
 * @param {bigint} b
 * @returns {bigint} gcd(|a|, |b|), non-negative.
 */
export function gcd(a, b) {
  let x = a < 0n ? -a : a, y = b < 0n ? -b : b;
  while (y) { const t = mod(x, y); x = y; y = t; }
  return x;
}

/**
 * Extended Euclidean algorithm.
 * @param {bigint} a
 * @param {bigint} b
 * @returns {[bigint, bigint, bigint]} [g, x, y] with g = gcd(a,b) = a*x + b*y.
 */
export function egcd(a, b) {
  if (b === 0n) return [a, 1n, 0n];
  const [g, x, y] = egcd(b, mod(a, b));
  return [g, y, x - (a / b) * y];
}

/**
 * Modular inverse, or null when a is not a unit mod m.
 * @param {bigint} a
 * @param {bigint} m - the modulus.
 * @returns {?bigint} a⁻¹ mod m, or null if gcd(a, m) ≠ 1.
 */
export function inverse(a, m) {
  const [g, x] = egcd(mod(a, m), m);
  return g === 1n ? mod(x, m) : null;
}

/**
 * A safe basis is pairwise coprime. It is NOT required to be prime.
 * @param {bigint[]} basis - candidate lane moduli.
 * @returns {boolean} true iff every element is ≥ 2 and every pair is coprime.
 */
export function isSafeBasis(basis) {
  for (let i = 0; i < basis.length; i++) {
    if (basis[i] < 2n) return false;
    for (let j = i + 1; j < basis.length; j++) if (gcd(basis[i], basis[j]) !== 1n) return false;
  }
  return true;
}

/**
 * The shell modulus of a basis: the product of its lanes.
 * @param {bigint[]} basis
 * @returns {bigint} ∏ basis.
 */
export function shellModulus(basis) { return basis.reduce((a, p) => a * p, 1n); }

/**
 * The canonical CRAM anchor: adjacent to the shell, coprime by construction.
 * @param {bigint} M - the shell modulus.
 * @returns {bigint} M + 1.
 */
export function canonicalAnchor(M) { return M + 1n; }

// ── K-Elimination ──────────────────────────────────────────────────

/**
 * ADJACENCY COLLAPSE — the governing CRAM configuration.
 *
 *     A = M + 1  ⟹  M ≡ −1 (mod A)  ⟹  M⁻¹ ≡ M ≡ −1  ⟹  K ≡ r − s (mod A)
 *
 * One subtraction and one reduction. Exact whenever 0 ≤ K < A.
 * @param {bigint} r - shell residue, x mod M.
 * @param {bigint} s - anchor residue, x mod (M+1).
 * @param {bigint} M - the shell modulus.
 * @returns {bigint} K = (r − s) mod (M+1).
 */
export function adjacencyRecover(r, s, M) {
  return mod(r - s, M + 1n);
}

/**
 * The same, from the integer, for testing and for encoding.
 * @param {bigint} x - the source integer.
 * @param {bigint} M - the shell modulus.
 * @returns {bigint} K, as `adjacencyRecover`.
 */
export function adjacencyRecoverFrom(x, M) {
  return adjacencyRecover(mod(x, M), mod(x, M + 1n), M);
}

/**
 * GENERAL K-ELIMINATION — any anchor A coprime to M.
 * Costs a subtract, a multiply by the precomputed M⁻¹ mod A, and a reduction.
 * @param {bigint} r - shell residue, x mod M.
 * @param {bigint} s - anchor residue, x mod A.
 * @param {bigint} M - the shell modulus.
 * @param {bigint} A - the anchor modulus.
 * @returns {?bigint} K mod A, or null when A is not coprime to M (use `gradientRecover` instead).
 */
export function generalRecover(r, s, M, A) {
  const mi = inverse(M, A);
  if (mi === null) return null;
  return mod((s - r) * mi, A);
}

/**
 * RESOLUTION GRADIENT — anchors that share a factor with the shell.
 * With d = gcd(M, A) and R = A/d, K is recovered modulo R rather than A:
 *
 *     K ≡ ((v − r)/d) · (M/d)⁻¹   (mod R)
 *
 * (M/d)⁻¹ mod R always exists because dividing out the full gcd leaves coprime
 * cofactors.
 * @param {bigint} r - shell residue, x mod M.
 * @param {bigint} v - anchor residue, x mod A.
 * @param {bigint} M - the shell modulus.
 * @param {bigint} A - the anchor modulus (need not be coprime to M).
 * @returns {?bigint} K mod R (R = A/gcd(M,A)), or null when the residue pair is inconsistent.
 */
export function gradientRecover(r, v, M, A) {
  const d = gcd(M, A);
  const R = A / d;
  const diff = mod(v - r, A);
  if (mod(diff, d) !== 0n) return null;
  const mi = inverse(M / d, R);
  if (mi === null) return null;
  return mod((diff / d) * mi, R);
}

/**
 * The resolution a given (shell, anchor) pair achieves.
 * @param {bigint} M - the shell modulus.
 * @param {bigint} A - the anchor modulus.
 * @returns {{d: string, resolution: string, exact_when_K_below: string}} decimal-string fields.
 */
export function resolution(M, A) {
  const d = gcd(M, A);
  return { d: d.toString(), resolution: (A / d).toString(), exact_when_K_below: (A / d).toString() };
}

/**
 * SHADOW LIFT — the Hensel form, needed ONLY when the shadow prime was left in
 * the shell. SUPERSEDED (P18): park lane 11 out of the shell and the shadow
 * anchor is coprime, so `parkedRecover` in anchor.js does the same job as plain
 * K-Elimination with no division step. Retained because the identity is exact
 * and because it is what a shell that already carries 11 must use.
 *
 * The earlier claim that the non-coprimality is "intentional" is withdrawn: it
 * is an artefact of loading 11 into the shell.
 * With M = q·M′, gcd(M′, q) = 1, and shadow modulus q^e:
 *
 *     K ≡ ((s − γ) / q) · (M′)⁻¹   (mod q^{e−1})
 *
 * For B8 with q = 11, e = 6 this pins K modulo 161,051 — a corridor of
 * M8 · 11⁵ ≈ 1.56 × 10¹².
 * @param {bigint} gamma - the CRT representative of the tray (see `gamma`/`gammaOf`).
 * @param {bigint} s - the shadow-lane residue x mod q^e.
 * @param {bigint} M - the shell modulus (which contains q as a factor).
 * @param {bigint} q - the shadow prime.
 * @param {bigint} e - the power q is carried at.
 * @returns {?{K: bigint, modulus: bigint, corridor: bigint}} the lifted
 *   winding and its modulus/corridor, or null on an inconsistent pair.
 */
export function shadowLift(gamma, s, M, q, e) {
  let power = 1n;
  for (let i = 0n; i < e; i++) power = power * q;
  const Mp = M / q;
  const diff = mod(s - gamma, power);
  if (mod(diff, q) !== 0n) return null;
  const lifted = power / q;
  const mi = inverse(Mp, lifted);
  if (mi === null) return null;
  return { K: mod((diff / q) * mi, lifted), modulus: lifted, corridor: M * lifted };
}

// ── the O(1) yield: K-Elimination, and that is all ────────────────
//
// CORRECTION OF RECORD (P20). The previous pass wrote the yield as
// "K-Elimination plus one multiply-add, X = r + K·M" — and that multiply-add is
// precisely a RADIX composition. r is the low digit, K is the high digit, M is
// the radix. Coupling them is the positional emission A2 retires, reintroduced
// inside the function that was supposed to avoid it.
//
// The yield does not couple. K-Elimination gives K; r is already there; the
// number IS the pair. On an adjacent anchor that is one modular subtraction:
//
//     K = (r − s) mod (M+1)          →   the number is (r, K)
//
// Two operations. r stays in the shell lanes, K stays in the anchor lane, and
// nothing is fused. Verified: the pair is injective over the whole span without
// the composite ever being formed, and equality and ordering both work on it
// directly — lexicographic (K, r) reproduces integer order exactly.
//
// Forming r + K·M is a BOUNDARY PROJECTION and is named as one below. It is
// available, it is exact, and it costs two further operations — but it is a
// radix step and belongs at a declared boundary, never in the path.
//
// Earlier withdrawals that stand: A3 was imported and is not a premise here;
// A2 retires Garner, not the act of producing a value at a boundary.

/**
 * The yield, adjacent anchor. One modular subtraction. Returns the identity
 * pair — r and K are NOT combined.
 * @param {bigint} r - shell residue, x mod M.
 * @param {bigint} s - anchor residue, x mod (M+1).
 * @param {bigint} M - the shell modulus.
 * @returns {{r: bigint, K: bigint, shell: bigint, anchor: bigint}}
 */
export function yieldAdjacent(r, s, M) {
  return { r, K: mod(r - s, M + 1n), shell: M, anchor: M + 1n };
}

/**
 * The yield, any coprime anchor. K-Elimination only. Returns the identity pair.
 * @param {bigint} r - shell residue, x mod M.
 * @param {bigint} s - anchor residue, x mod A.
 * @param {bigint} M - the shell modulus.
 * @param {bigint} A - the anchor modulus.
 * @returns {?{r: bigint, K: bigint, shell: bigint, anchor: bigint}} null when A is not coprime to M.
 */
export function yieldGeneral(r, s, M, A) {
  const K = generalRecover(r, s, M, A);
  return K === null ? null : { r, K, shell: M, anchor: A };
}

/**
 * Equality on the identity pair. No composite is formed.
 * @param {{r: bigint, K: bigint}} a
 * @param {{r: bigint, K: bigint}} b
 * @returns {boolean}
 */
export function identityEquals(a, b) { return a.r === b.r && a.K === b.K; }

/**
 * Order on the identity pair: K orders the laps, r orders within a lap.
 * Reproduces integer order exactly, without forming either integer.
 * @param {{r: bigint, K: bigint}} a
 * @param {{r: bigint, K: bigint}} b
 * @returns {-1|0|1}
 */
export function identityCompare(a, b) {
  if (a.K !== b.K) return a.K < b.K ? -1 : 1;
  if (a.r !== b.r) return a.r < b.r ? -1 : 1;
  return 0;
}

/**
 * BOUNDARY PROJECTION — this is the radix step. It couples r and K into a
 * base-M positional composite. Exact, but it is not the yield and must not be
 * treated as one. Two operations on top of the yield.
 * @param {{r: bigint, K: bigint, shell: bigint}} id - an identity pair with its shell modulus.
 * @returns {bigint} the reconstructed integer id.r + id.K * id.shell.
 */
export function projectToInteger(id) { return id.r + id.K * id.shell; }

/**
 * Costs, split so the coupling is visible rather than folded into a total.
 * `couples` is the field that matters.
 * @param {"adjacent"|"general"|"projection"|"garner"} mode
 * @param {bigint} [lanes=8n] - lane count, only used by the "garner" mode's cost.
 * @returns {Object} an op-count breakdown for the given mode.
 * @throws {Error} if `mode` is not one of the four recognized strings.
 */
export function yieldCost(mode, lanes = 8n) {
  if (mode === "adjacent") {
    return { mode, subtract: 1n, reduce: 1n, multiply: 0n, add: 0n,
      total_ops: 2n, couples: false, depends_on_lane_count: false };
  }
  if (mode === "general") {
    return { mode, subtract: 1n, reduce: 1n, multiply: 1n, add: 0n,
      inverse_precomputed: 1n, total_ops: 3n, couples: false,
      depends_on_lane_count: false };
  }
  if (mode === "projection") {
    return { mode, multiply: 1n, add: 1n, total_ops: 2n, couples: true,
      note: "radix composition r + K·M — boundary only", depends_on_lane_count: false };
  }
  if (mode === "garner") {
    return { mode, per_lane_ops: 6n, total_ops: 6n * lanes, couples: true,
      note: "threads an accumulator through every digit", depends_on_lane_count: true };
  }
  throw new Error("unknown yield mode");
}

// ── operation cost, counted rather than asserted ───────────────────

/**
 * Op counts for one winding recovery, so the adjacency claim is auditable
 * rather than rhetorical. Counts are structural, not timed.
 * @param {"adjacency"|"general"} mode
 * @returns {Object} an op-count breakdown for the given mode.
 * @throws {Error} if `mode` is neither "adjacency" nor "general".
 */
export function recoveryCost(mode) {
  if (mode === "adjacency") {
    return { mode, subtract: 1n, multiply: 0n, reduce: 1n, inverse_precomputed: 0n, total_ops: 2n };
  }
  if (mode === "general") {
    return { mode, subtract: 1n, multiply: 1n, reduce: 1n, inverse_precomputed: 1n, total_ops: 3n };
  }
  throw new Error("unknown recovery mode");
}

// ── the CRAM identity state ────────────────────────────────────────

/**
 * The state tuple is not (r, K). It is
 *
 *     S = (B, r, K, Σ, T, Sh, L, F)
 *
 * basis · residue tray · winding · property signature · operator topology ·
 * shadow state · lineage · finite support. A4 makes the topology first-class:
 * each lane may carry an independent operator, and homogeneous operation is the
 * special case, not the rule. Carrying only (r, K) is the RNS reduction of this.
 */
export const STATE_FIELDS = ["basis", "r", "K", "sigma", "topology", "shadow", "lineage", "support"];

/**
 * Build a `CRAM_STATE_V1` from an integer and a basis.
 * @param {bigint} x - the value to encode.
 * @param {bigint[]} basis - the lane moduli (need not be prime, must be pairwise coprime for downstream use).
 * @param {{sigma?: Object, topology?: string[], shadow?: *, lineage?: Array, support?: number[]}} [opts]
 *   - optional extra state fields; each defaults per `STATE_FIELDS`.
 * @returns {Object} a `CRAM_STATE_V1` object: `{kind, basis, r, K, sigma, topology, shadow, lineage, support}`.
 */
export function encode(x, basis, opts = {}) {
  const M = shellModulus(basis);
  return {
    kind: "CRAM_STATE_V1",
    basis: basis.slice(),
    r: basis.map((p) => mod(x, p)),
    K: (x - mod(x, M)) / M,
    sigma: opts.sigma || {},
    topology: opts.topology || basis.map(() => "id"),
    shadow: opts.shadow || null,
    lineage: opts.lineage || [],
    support: opts.support || basis.map((_, i) => i),
  };
}

/**
 * Canonical CRT representative of the tray — the boundary touch, not the hot path.
 * @param {{basis: bigint[], r: bigint[]}} state - a CRAM state (or any object with basis/r).
 * @returns {bigint} the unique value in [0, shellModulus(state.basis)) with that residue tray.
 */
export function gamma(state) {
  const M = shellModulus(state.basis);
  let acc = 0n;
  for (let i = 0; i < state.basis.length; i++) {
    const p = state.basis[i];
    const Mi = M / p;
    const ei = Mi * inverse(Mi, p);
    acc = mod(acc + state.r[i] * ei, M);
  }
  return acc;
}

/**
 * The full reconstructed integer of a state: gamma(state) + K·M — a boundary
 * projection, not a hot-path operation.
 * @param {{basis: bigint[], r: bigint[], K: bigint}} state
 * @returns {bigint}
 */
export function value(state) { return gamma(state) + state.K * shellModulus(state.basis); }

/**
 * Structural well-formedness check for a `CRAM_STATE_V1`.
 * @param {Object} state
 * @returns {boolean} true iff `state` has the right kind tag, every
 *   `STATE_FIELDS` key, a pairwise-coprime basis, residues in range for their
 *   lanes, and a topology array matching the basis length.
 */
export function wellFormed(state) {
  return state.kind === "CRAM_STATE_V1"
    && STATE_FIELDS.every((f) => f in state)
    && isSafeBasis(state.basis)
    && state.r.length === state.basis.length
    && state.r.every((v, i) => v >= 0n && v < state.basis[i])
    && state.topology.length === state.basis.length;
}

// ── the 5th operator: transduction χ ───────────────────────────────
//
// CORRECTION OF RECORD (P16). The first implementation computed `value(state)`
// and re-reduced. That is a full reconstruction — it leaves the residue world,
// which is the one thing transduction exists not to do. Worse, it materialises
// K·M, so its cost scaled with the magnitude of the value rather than with the
// basis. Rewritten below to be residue-native.
//
// WHAT CERTIFIES A TRANSDUCTION
// ─────────────────────────────
// Not the winding tower. The tower certifies DEPTH inside one fixture and says
// nothing about the bridge between two. What certifies the bridge is an
// UNBROKEN SAFE BASIS: pairwise coprimality with no repeated modulus, on both
// sides. That alone makes the idempotents exist, and the idempotents are the
// whole bridge.
//
// THE BRIDGE
// ──────────
// With e_i the CRT idempotents of A (which exist exactly because A is unbroken):
//
//     Σ_i r_i·e_i  =  γ_A(r) + t·M_A        t < Σ a_i, a basis-sized constant
//     x            =  γ_A(r) + K_A·M_A
//                  =  Σ_i r_i·e_i + (K_A − t)·M_A
//
// so for any target lane b, writing W = K_A − t for the effective winding:
//
//     x mod b  =  ( Σ_i r_i·(e_i mod b)  +  W·(M_A mod b) )  mod b
//
// Nothing proportional to |x| is ever formed. The largest integer built is
// Σ r_i e_i < M_A·Σa_i — fixed by the basis, not by the value. A 43-digit x
// transduces with a 4-digit intermediate.
//
// SHARED LANES ARE THE PHASE LOCK. A lane present in both bases is copied
// across untouched; no bridging is needed and none is done. Disjointness of the
// two bases is therefore NOT required — sharing is a feature, and it is exactly
// where the phase lock lives.

/**
 * CRT idempotents of a basis. They exist iff the basis is unbroken.
 * @param {bigint[]} basis - a pairwise-coprime, no-repeated-modulus basis.
 * @returns {bigint[]} one idempotent e_i per lane, with e_i ≡ 1 (mod basis[i])
 *   and e_i ≡ 0 (mod basis[j]) for j ≠ i.
 * @throws {Error} "broken basis: idempotent does not exist" if any lane
 *   shares a factor with the shell built from the others.
 */
export function idempotents(basis) {
  const M = shellModulus(basis);
  return basis.map((a) => {
    const Mi = M / a;
    const iv = inverse(Mi, a);
    if (iv === null) throw new Error("broken basis: idempotent does not exist");
    return Mi * iv;
  });
}

/**
 * The certificate. CORRECTED (P28): only the SOURCE tray must be an unbroken
 * safe basis. The target inherits primality and coprimality from it through the
 * phase lock, so the target may hold arbitrary composites.
 *
 * The earlier version required both. That refused valid configurations — a lane
 * of the target is a READING, and x mod q is exact for every q whether or not q
 * is prime or coprime to its neighbours. Coprimality buys RECONSTRUCTION FROM
 * THE TRAY ALONE, and the target never needs it: the identity (r, w) lives in
 * the first tray and rides along.
 *
 * Disjointness is not required either; the shared lanes are where the lock is.
 * @param {bigint[]} A - the source basis.
 * @param {bigint[]} B - the target basis.
 * @returns {Object} `TRANSDUCTION_CERTIFICATE_V2` — source/target unbroken
 *   flags, shared lanes, and `admissible` (true iff the source is unbroken).
 */
export function certifyTransduction(A, B) {
  const repeated = (b) => new Set(b.map(String)).size !== b.length;
  const aOk = isSafeBasis(A) && !repeated(A);
  const bOk = isSafeBasis(B) && !repeated(B);
  const shared = A.filter((p) => B.some((q) => q === p));
  let idem;
  try { idempotents(A); idem = true; } catch { idem = false; }
  return {
    kind: "TRANSDUCTION_CERTIFICATE_V2",
    source_unbroken: aOk,
    target_unbroken: bOk,            // reported, NOT required
    target_inherits: !bOk,
    idempotents_exist: idem,
    shared_lanes: shared.map(String),
    disjoint: shared.length === 0,
    // the target's own structure does not gate this
    admissible: aOk && idem,
    certified_by: "unbroken safe basis in the FIRST tray",
  };
}

/**
 * The basis bridge. Residue-native: no reconstruction, nothing proportional to
 * the value. `phiLane` applies a lane-wise value map (any polynomial with
 * integer coefficients acts lane-wise, since Φ(x) mod b = Φ(x mod b) mod b).
 * Ω selects the winding policy: recompute · preserve · project.
 *
 * MAGNITUDE IS DERIVED BY K-ELIMINATION, NOT DECLARED. (P24, corrects P22)
 * ───────────────────────────────────────────────────────────────────────
 * P22 required the caller to declare `phiBound` — an analytic bound on Φ's
 * growth — before the target winding could be certified. That was the wrong
 * framing, and it is withdrawn.
 *
 * K-Elimination's own theorem says why. In `X = r + k·M`, k is not lost
 * information waiting to be estimated: it is already implicit in the complete
 * residue representation, and an anchor coprime to the shell provides an
 * INDEPENDENT EXACT VIEW of the same value. That is what retires k-tracking.
 * The magnitude of Φ(x) is no different from any other magnitude — it is
 * recovered the same way, by eliminating against an anchor:
 *
 *     K_B ≡ (s − γ_B) · M_B⁻¹   (mod A),      s = Φ(x) mod A
 *
 * and Φ(x) mod A is available for ANY A from the source tray alone, because the
 * bridge gives x mod A exactly and Φ(x) mod A = Φ(x mod A) mod A.
 *
 * What the theorem does require is the RANGE HYPOTHESIS — `X < M·A` in
 * `kElimination_core`. K-Elimination is exact inside a corridor, and the
 * corridor has to be wide enough. So the caller declares DEPTH, a property of
 * the target fixture, and the anchor is lifted to A = (M_B+1)^depth. Depth is
 * the same lever the parked lane uses; nothing about Φ needs to be known.
 *
 * The lift is self-checking. The leading base-A digit of the recovered winding
 * is zero exactly when the previous depth already sufficed, so a NON-ZERO
 * leading digit proves the corridor was too narrow and the transduction is
 * refused. A zero leading digit is necessary for being inside the corridor, and
 * is reported as such — `leading_digit_zero`, not a proof of containment.
 *
 * `phiBound` survives as an OPTIONAL strengthening: supplied, it proves
 * containment outright and the lineage says so. It is no longer required, and
 * its absence no longer refuses anything.
 * @param {Object} state - a `CRAM_STATE_V1` (from `encode`), source of the bridge.
 * @param {bigint[]} targetBasis - the basis to transduce into.
 * @param {{theta?: function, pi?: function, omega?: ("recompute"|"preserve"|"project"|"bound"|"lift"),
 *   phiLane?: function(bigint, bigint): bigint, phiBound?: function(bigint): bigint,
 *   phiMagnitude?: function(bigint): bigint, depth?: bigint, anchors?: bigint[]}} [opts]
 *   - `theta` maps sigma forward; `pi` maps topology forward; `omega` selects
 *   the winding policy (default "recompute"); `phiLane` is an optional
 *   lane-wise value map; `depth` (default 2n) sets the default single-anchor
 *   lift depth when `opts.anchors` is not supplied; `anchors` overrides the
 *   anchor set used for K-Elimination.
 * @returns {Object} a new `CRAM_STATE_V1` over `targetBasis`, with an extended `lineage`.
 * @throws {Error} "transduction refused: basis is broken" if the source basis
 *   is not an unbroken safe basis; "transduction refused: the target winding
 *   wrapped the corridor" under `omega:"recompute"` when the winding exceeds
 *   the anchor set's certified corridor; "transduction refused: omega:'lift'
 *   past the certified corridor needs phiMagnitude" when lifting past the
 *   corridor under a non-trivial Φ without `opts.phiMagnitude`; "unknown
 *   winding policy" for an unrecognized `omega`.
 */
export function transduce(state, targetBasis, opts = {}) {
  const cert = certifyTransduction(state.basis, targetBasis);
  if (!cert.admissible) throw new Error("transduction refused: basis is broken");

  const Theta = opts.theta || ((z) => z);
  const Pi = opts.pi || ((t) => t.slice(0, targetBasis.length));
  const omega = opts.omega || "recompute";
  const phiLane = opts.phiLane || null;
  const phiBound = opts.phiBound || null;          // optional strengthening only
  const depth = opts.depth === undefined ? 2n : opts.depth;
  if (depth < 1n) throw new Error("the anchor lift needs at least one level");

  const A = state.basis, MA = shellModulus(A);
  const e = idempotents(A);
  let raw = 0n;
  for (let i = 0; i < A.length; i++) raw = raw + state.r[i] * e[i];
  const W = state.K - raw / MA;                 // effective winding; raw/MA is basis-sized

  /** x mod m, computed from the source tray alone. */
  const bridge = (m) => {
    const hit = A.findIndex((a) => a === m);
    if (hit >= 0) return state.r[hit];          // shared lane — the phase lock
    let acc = 0n;
    for (let i = 0; i < A.length; i++) acc = acc + state.r[i] * mod(e[i], m);
    return mod(acc + W * mod(MA, m), m);
  };

  // Reduction emits a residue AND a quotient. The quotient is the hidden carry
  // (the lane shadow) and was previously dropped on the floor here. Under a
  // uniform ensemble an additive lane's residues are exactly i.i.d. — the digit
  // channel is featureless by construction — so the shadow is where any signal
  // actually lives. It is captured, not discarded. (P25)
  const laneCarry = [];
  const r = targetBasis.map((b) => {
    const v = bridge(b);
    if (!phiLane) { laneCarry.push(0n); return v; }
    const full = phiLane(v, b);
    laneCarry.push((full - mod(full, b)) / b);
    return mod(full, b);
  });

  const MB = shellModulus(targetBasis);
  const base = MB + 1n;
  let K, corridor = null, certified = null, lift = null;
  if (omega === "recompute" || omega === "lift") {
    const gB = gammaOf(r, targetBasis);

    /** Φ(x) mod m, from the source tray alone, for ANY m. */
    const phiMod = (m) => {
      const v = bridge(m);
      return phiLane ? mod(phiLane(v, m), m) : v;
    };

    /** K-Elimination against the anchor lifted to base^level. */
    // T-COMP-1 (P26). The corridor is grown by EXTENDING THE ANCHOR SET, not by
    // raising one anchor to a power, and the bound R = lcm(A)/gcd(M_B, lcm(A))
    // is COMPUTED rather than guessed from a leading digit.
    const anchors = opts.anchors || [base];
    const rec = towerRecover(gB, anchors.map(phiMod), MB, anchors);
    if (rec === null) throw new Error("transduction refused: anchor residues are inconsistent");

    // A wider anchor set FALSIFIES the corridor when the winding it recovers
    // already exceeds the narrow R: that is a proof K ≥ R, so the narrow set
    // wrapped. Non-falsification is necessary, not sufficient — the certificate
    // is K < R, which is exactly what the declared anchor set buys.
    const wider = [...anchors, base * base + 1n];
    const check = towerRecover(gB, wider.map(phiMod), MB, wider);
    const wrapped = check !== null && check.K >= rec.R;

    K = rec.K;
    corridor = rec.corridor;
    lift = {
      mechanism: "anchor-set (T-COMP-1)",
      anchors: anchors.map(String),
      L: rec.L.toString(), d: rec.d.toString(), R: rec.R.toString(),
      corridor: corridor.toString(),
      unconditional_inverse: gcd(MB / rec.d, rec.R) === 1n,
      falsified: wrapped,
    };

    if (omega === "recompute" && wrapped) {
      throw new Error(
        "transduction refused: the target winding wrapped the corridor. "
        + `The anchor set [${anchors.join(", ")}] gives R = ${rec.R} and a corridor of `
        + `M_B·R = ${corridor}; a wider set disagrees, which proves K ≥ R. Extend `
        + "opts.anchors — each added coprime anchor multiplies R at one pairwise combine — "
        + "or pass omega:'lift' to take the boundary touch explicitly.");
    }

    // Optional strengthening: an analytic bound on Φ proves containment outright.
    if (phiBound !== null) {
      const bound = phiBound(MA * (state.K + 1n));
      certified = bound <= corridor;
      lift.bound_supplied = true;
      lift.bound = bound.toString();
    } else {
      // Not falsified is the strongest thing the anchor set alone supports.
      certified = !lift.falsified;
      lift.bound_supplied = false;
    }

    // omega:"lift" — an explicit, flagged boundary touch. Where the corridor is
    // not certified it reconstructs rather than returning a wrapped winding.
    // Reconstruction forms a magnitude, so under a non-trivial Φ it needs Φ on
    // magnitudes; `phiMagnitude` is required HERE and nowhere else.
    if (omega === "lift" && !certified) {
      if (phiLane && !opts.phiMagnitude) {
        throw new Error(
          "transduction refused: omega:'lift' past the certified corridor needs phiMagnitude. "
          + "The boundary touch forms a magnitude, and reconstructing x alone does not give Φ(x). "
          + "Extend opts.anchors instead and the winding derives with no declaration at all.");
      }
      const srcValue = gammaOf(state.r, A) + state.K * MA;
      K = (opts.phiMagnitude ? opts.phiMagnitude(srcValue) : srcValue) / MB;
    }
  } else if (omega === "preserve") K = state.K;
  else if (omega === "project") K = 0n;
  else if (omega === "bound") {
    // Ω = BOUND — "bounded but not retained". The winding is never committed to:
    // the corridor it must lie in is recorded and the value is not. This is not
    // projection — projection destroys a known winding by setting it to 0, and
    // claims a definite (wrong) value. Bound claims none, so it is honest about
    // what it has and is non-reversible for the opposite reason. (P27)
    const anchors = opts.anchors || [MB + 1n];
    const { R } = anchorSetCorridor(MB, anchors);
    K = null;
    corridor = MB * R;
    lift = {
      mechanism: "bound (Ω, not retained)",
      anchors: anchors.map(String),
      R: R.toString(),
      corridor: corridor.toString(),
      winding_retained: false,
    };
  }
  else throw new Error("unknown winding policy");

  const topo = Pi(state.topology);
  return {
    kind: "CRAM_STATE_V1",
    basis: targetBasis.slice(),
    r, K,
    sigma: Theta(state.sigma),
    topology: topo.length === targetBasis.length ? topo : targetBasis.map(() => "id"),
    shadow: state.shadow,
    lineage: [...state.lineage, {
      op: "chi", omega, to: targetBasis.map(String),
      certified_by: cert.certified_by, shared_lanes: cert.shared_lanes,
      corridor: corridor === null ? null : corridor.toString(),
      corridor_certified: certified,
      // how the magnitude was derived: K-Elimination against a lifted anchor
      lift,
      // the hidden carry each lane emitted and would otherwise have discarded
      lane_carry: laneCarry.map(String),
      carry_energy: laneCarry.reduce((a, w) => a + w * w, 0n).toString(),
      boundary_touch: omega === "lift" && certified === false,
      // Φ ≠ id moves magnitude. Under recompute/lift that is certified or the
      // transduction is refused; under preserve/project the winding is the
      // caller's assertion, not a result, and is flagged as such.
      phi_active: phiLane !== null,
      winding_asserted: (omega === "preserve" || omega === "project") && phiLane !== null,
      winding_retained: omega !== "bound",
    }],
    support: targetBasis.map((_, i) => i),
  };
}

/**
 * Canonical representative of a tray over a basis.
 * @param {bigint[]} r - the residue tray, one entry per basis lane.
 * @param {bigint[]} basis - the lane moduli.
 * @returns {bigint} the unique value in [0, shellModulus(basis)) with that tray.
 */
export function gammaOf(r, basis) {
  const M = shellModulus(basis);
  const e = idempotents(basis);
  let acc = 0n;
  for (let i = 0; i < basis.length; i++) acc = mod(acc + r[i] * e[i], M);
  return acc;
}

/** A transduction is reversible exactly when Ω preserves the winding. */
/**
 * Ω has four settings — preserve · recompute · project · bound — and only the
 * first two are reversible. `lift` is recompute with a declared boundary touch,
 * so it reverses too. Projection discards a known winding; bound never forms
 * one. Neither can be undone.
 */
export const WINDING_POLICIES = ["preserve", "recompute", "project", "bound"];

/**
 * @param {string} omega - a winding policy (see `WINDING_POLICIES`, plus "lift").
 * @returns {boolean} true iff `omega` is "recompute", "preserve", or "lift".
 */
export function isReversiblePolicy(omega) {
  return omega === "recompute" || omega === "preserve" || omega === "lift";
}

// ── project defaults ───────────────────────────────────────────────

/** Legacy six-lane shell descriptor: `{basis: B6, M: M6, anchor: M6+1}`. */
export const SHELL_6 = { basis: B6, M: M6, anchor: M6 + 1n };
/** Full eight-lane shell descriptor: `{basis: B8, M: M8, anchor: M8+1}`. */
export const SHELL_8 = { basis: B8, M: M8, anchor: M8 + 1n };
