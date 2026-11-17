// src/core/carry.js — the hidden carry. (P25)
//
// Every reduction emits TWO things: a residue and a quotient. The residue is
// kept, the quotient is thrown away, and the quotient is the carry. This module
// stops throwing it away.
//
// THE CARRY IS SIGNED.
// ───────────────────
// With least-nonnegative residues (r ∈ [0,p)) the winding is always ≥ 0 and the
// sign information is lost. The centred residue r ∈ (−p/2, p/2] keeps it:
//
//     x = r + p·w,     r centred,     w = (x − r)/p
//
// w is the K-Elimination winding, NOT the p-adic valuation. Under the centred
// convention w counts to the NEAREST shell rather than the one below, so it goes
// negative on the lower half of every shell — which is exactly the information
// the [0,p) convention discards.
//
// THE ANCHOR READS THE CARRY WITH A SIGN.
// ──────────────────────────────────────
// Lemma 1 (signed carry). For any anchor A with M ≡ −1 (mod A):
//
//     v_A = N mod A = (r − K) mod A
//
// so K enters the anchor NEGATED. On a closed shell (r = 0) this reads
// v_A = (−K) mod A: the anchor counts DOWN as the hidden carry counts UP. In the
// residue lane alone the closed shells 0, M, 2M, … are indistinguishable — each
// reads r = 0 — and the descending anchor is the direct readout that separates
// them. That descent is the signature; the bare residue is not.
//
// THE SHADOW IS THE READABLE CHANNEL.
// ──────────────────────────────────
// Under a uniform ensemble an additive lane's emissions are exactly i.i.d.
// uniform (Lemma 3′), so the digit channel is featureless BY CONSTRUCTION —
// absence of structure there proves nothing. Squaring is not an additive shift,
// so Lemma 3 does not apply: r ↦ r² mod p is 2-to-1 on nonzero residues, its
// image covers only (p+1)/2 of p values, and the discarded quotient ⌊r²/p⌋
// inherits that structure. The shadow is the one channel that carries signal.
//
// BigInt only.

import { mod } from "./residues.js";

// ── centred residue and signed winding ─────────────────────────────

/**
 * Centred residue: the representative of x mod p in (−p/2, p/2].
 * @param {bigint} x
 * @param {bigint} p - the lane modulus.
 * @returns {bigint} the centred residue.
 */
export function centeredResidue(x, p) {
  const r = mod(x, p);
  return 2n * r <= p ? r : r - p;
}

/**
 * The K-Elimination winding under the centred convention: w = (x − r)/p.
 * @param {bigint} x
 * @param {bigint} p - the lane modulus.
 * @returns {bigint} the signed winding (may be negative).
 */
export function signedWinding(x, p) {
  return (x - centeredResidue(x, p)) / p;
}

/**
 * x = r + p·w, exactly, for every x — the identity the pair must satisfy.
 * @param {bigint} x
 * @param {bigint} p - the lane modulus.
 * @returns {{r: bigint, w: bigint, p: bigint, exact: boolean}} the centred
 *   residue, the signed winding, the modulus, and a self-check flag.
 */
export function carrySplit(x, p) {
  const r = centeredResidue(x, p);
  const w = (x - r) / p;
  return { r, w, p, exact: x === r + p * w };
}

/**
 * The unsigned winding, for contrast: ⌊x/M⌋ with r ∈ [0,M).
 * @param {bigint} x
 * @param {bigint} p - the lane modulus.
 * @returns {bigint} the non-negative winding.
 */
export function unsignedWinding(x, p) { return (x - mod(x, p)) / p; }

// ── Lemma 1: the anchor reads the carry negated ────────────────────

/**
 * v_A = (r − K) mod A, for any anchor A with M ≡ −1 (mod A).
 * K enters with a sign; this is what makes the anchor a carry readout and not
 * merely another residue.
 * @param {bigint} r - the phase.
 * @param {bigint} K - the winding.
 * @param {bigint} A - the anchor modulus.
 * @returns {bigint} the anchor readout.
 */
export function signedAnchorResidue(r, K, A) { return mod(r - K, A); }

/**
 * Whether an anchor is in the signed regime: M ≡ −1 (mod A).
 * @param {bigint} M - the shell modulus.
 * @param {bigint} A - the anchor modulus.
 * @returns {boolean}
 */
export function isSignedAnchor(M, A) { return mod(M, A) === mod(-1n, A); }

/**
 * The closed-shell descent. At r = 0 the anchor reads (−K) mod A, so successive
 * closed shells walk the anchor DOWNWARD one step at a time. Returns the readout
 * for the first `count` closed shells.
 * @param {bigint} M - the shell modulus.
 * @param {bigint} A - the anchor modulus (typically M+1).
 * @param {bigint} count - how many closed shells (K = 0..count-1) to report.
 * @returns {{N: bigint, K: bigint, r: bigint, v: bigint, predicted: bigint}[]}
 */
export function closedShellDescent(M, A, count) {
  const out = [];
  for (let K = 0n; K < count; K++) {
    const N = M * K;
    out.push({
      N, K,
      r: mod(N, M),                       // 0 for every one of them
      v: mod(N, A),                       // the anchor: the only thing that moves
      predicted: signedAnchorResidue(0n, K, A),
    });
  }
  return out;
}

// ── the emitted carry: what reduction throws away ──────────────────

/**
 * Reduce a lane value and keep BOTH halves. The residue is what a lane
 * normally reports; `carry` is the quotient it normally discards.
 * @param {bigint} value
 * @param {bigint} p - the lane modulus.
 * @returns {{residue: bigint, carry: bigint, lane: bigint}}
 */
export function emitWithCarry(value, p) {
  return { residue: mod(value, p), carry: (value - mod(value, p)) / p, lane: p };
}

/**
 * The shadow of a lane operation: the discarded quotient alone.
 * @param {bigint} value
 * @param {bigint} p - the lane modulus.
 * @returns {bigint} ⌊value/p⌋ computed via the unsigned residue.
 */
export function laneShadow(value, p) { return (value - mod(value, p)) / p; }

// ── the carry functional: winding energy ───────────────────────────

/**
 * C(field, p) = Σ w_p(x)² over the field — the total winding energy.
 * Non-negative and integer-valued, and zero exactly when every value is a pure
 * centred residue (no value has wound past its shell).
 * @param {Iterable<bigint>} field - the values to sum over.
 * @param {bigint} p - the lane modulus.
 * @returns {bigint} the total winding energy, ≥ 0.
 */
export function carryFunctional(field, p) {
  let acc = 0n;
  for (const x of field) { const w = signedWinding(x, p); acc += w * w; }
  return acc;
}

/**
 * C is zero iff nothing wound — the certificate that a field is residue-pure.
 * @param {Iterable<bigint>} field
 * @param {bigint} p - the lane modulus.
 * @returns {boolean}
 */
export function isResiduePure(field, p) { return carryFunctional(field, p) === 0n; }

// ── the Sqr exception: the channel that is not blind ───────────────

/**
 * The image of r ↦ r² mod p. Squaring is 2-to-1 on nonzero residues, so the
 * image covers (p+1)/2 of p values — non-uniform even for uniform r.
 * @param {bigint} p - the lane modulus.
 * @returns {{p: bigint, distinct: bigint, of: bigint, expected: bigint}}
 */
export function squareImage(p) {
  const seen = new Set();
  for (let r = 0n; r < p; r++) seen.add(mod(r * r, p).toString());
  return { p, distinct: BigInt(seen.size), of: p, expected: (p + 1n) / 2n };
}

/**
 * The shadow law of squaring: how often each discarded quotient ⌊r²/p⌋ occurs.
 * @param {bigint} p - the lane modulus.
 * @returns {Map<bigint, bigint>} quotient → occurrence count.
 */
export function squareShadowLaw(p) {
  const counts = new Map();
  for (let r = 0n; r < p; r++) {
    const s = (r * r - mod(r * r, p)) / p;
    counts.set(s, (counts.get(s) || 0n) + 1n);
  }
  return counts;
}

/**
 * An additive shift absorbs into uniformity (Lemma 3) and its emission is flat;
 * squaring does not. Returns whether each lane's emission law is uniform.
 * @param {bigint} p - the lane modulus.
 * @param {function(bigint): bigint} op - the lane operation to test, e.g. `(r) => r + 1n`.
 * @returns {{uniform: boolean, distinct: bigint}}
 */
export function emissionIsUniform(p, op) {
  const counts = new Map();
  for (let r = 0n; r < p; r++) {
    const v = mod(op(r), p);
    counts.set(v, (counts.get(v) || 0n) + 1n);
  }
  const vals = [...counts.values()];
  const distinct = BigInt(counts.size);
  return { uniform: distinct === p && vals.every((c) => c === vals[0]), distinct };
}
