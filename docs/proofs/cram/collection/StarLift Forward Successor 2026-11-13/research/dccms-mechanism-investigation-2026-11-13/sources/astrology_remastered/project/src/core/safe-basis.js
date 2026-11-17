// src/core/safe-basis.js — the Safe Basis as an architecture, not a list. (P12)
//
// CORRECTION OF RECORD
// ────────────────────
// An earlier pass in this project treated the Safe Basis as eight
// interchangeable primes and derived a "spine" from the single question
// "does p divide the ecliptic ring?". That is a real property, but it is the
// CLOSURE axis, not the shadow axis, and it is not what the basis is.
//
// The Safe Basis S = {2,3,5,7,11,13,17,19} carries a fixed role taxonomy, and
// each prime additionally carries family attributes that are not optional:
// its class in Z[i] (mod 4), its twin/cousin/sexy/Sophie-Germain memberships,
// its Ramanujan status, and its gap to its neighbours. SHADOW is the mod-4
// attribute: a shadow prime is one that is INERT in the Gaussian integers,
// i.e. p ≡ 3 (mod 4), the primes Fermat's two-square theorem excludes.
//
//   shadow primes in S : {3, 7, 11, 19}      — 11 is the Shadow Anchor
//   split  primes in S : {5, 13, 17}         — p = a² + b²
//   ramified           : {2}                 — 2 = −i(1+i)²
//
// Note that this is NOT the off-ring set {7,11,13,17,19}. The two axes cross,
// and keeping them apart is the whole point (see shadow-spine.js).
//
// SATURATION
// ──────────
// M6 = 30,030 is the priming-saturated shell: within one lap the residue tuple
// over B6 is a bijection. But M6 < 1,296,000, so the six-prime basis
// UNDER-SATURATES the ecliptic ring — a ring position needs ⌊x/M6⌋ ∈ [0,43] as
// well as its phase. The twin pair 17·19 = 323 > 43 restores unique
// representation. That is precisely what "saturation extender" means here, and
// it is the same fact the K-Elimination certificate rests on.
//
// BigInt only. No floats, no Date, no ephemeris.

import { mod } from "./residues.js";
import { B6, B8, GEAR, M6, M8, ARCSEC_CIRCLE } from "./basis.js";

/** The Colony: the product of the full Safe Basis. */
export const COLONY = M8;          // 9,699,690
/** The shell: the product of the classical six. */
export const SHELL = M6;           // 30,030

// ── small exact integer helpers ────────────────────────────────────

/**
 * Exact integer square root by binary search.
 * @param {bigint} n - a non-negative integer.
 * @returns {bigint} ⌊√n⌋.
 * @throws {Error} "isqrt of a negative integer" if n < 0.
 */
export function isqrt(n) {
  if (n < 0n) throw new Error("isqrt of a negative integer");
  if (n < 2n) return n;
  let lo = 1n, hi = n;
  while (lo < hi) {
    const mid = (lo + hi + 1n) / 2n;
    if (mid * mid <= n) lo = mid; else hi = mid - 1n;
  }
  return lo;
}

/**
 * Trial-division primality test.
 * @param {bigint} n
 * @returns {boolean}
 */
export function isPrime(n) {
  if (n < 2n) return false;
  for (let p = 2n; p * p <= n; p++) if (mod(n, p) === 0n) return false;
  return true;
}

// ── Gaussian / mod-4 class — this is what "shadow" means ───────────

/**
 * "ramified" (p=2) · "split" (p≡1 mod 4) · "inert" (p≡3 mod 4).
 * @param {bigint} p - a prime.
 * @returns {"ramified"|"split"|"inert"} its class in Z[i].
 */
export function gaussianClass(p) {
  if (p === 2n) return "ramified";
  return mod(p, 4n) === 1n ? "split" : "inert";
}

/**
 * A shadow prime is inert in Z[i]: p ≡ 3 (mod 4). Fermat excludes exactly these.
 * @param {bigint} p - a prime.
 * @returns {boolean}
 */
export function isShadowPrime(p) {
  return p > 2n && mod(p, 4n) === 3n;
}

/**
 * The witness that a split prime is a sum of two squares, e.g. 13 = 2² + 3².
 * Returns null for inert primes — that absence IS the shadow.
 * @param {bigint} p - a prime.
 * @returns {?[bigint, bigint]} [a, b] with p = a² + b², or null if p is inert (or 2 gives [1,1]).
 */
export function sumOfTwoSquares(p) {
  if (p === 2n) return [1n, 1n];
  if (mod(p, 4n) !== 1n) return null;
  for (let a = 1n; a * a * 2n <= p; a++) {
    const rest = p - a * a;
    const b = isqrt(rest);
    if (b * b === rest) return [a, b];
  }
  return null;
}

// ── prime families — required attributes, not decoration ───────────

export const FAMILY_GAPS = [
  { id: "twin", gap: 2n }, { id: "cousin", gap: 4n }, { id: "sexy", gap: 6n },
];

/**
 * Family partners of p inside a given prime set (both directions).
 * @param {bigint} p - the prime to find partners for.
 * @param {bigint[]} set - the candidate partner pool.
 * @returns {{family: string, partner: string}[]} twin/cousin/sexy partners of p found in `set`.
 */
export function familyPartners(p, set) {
  const out = [];
  for (const f of FAMILY_GAPS) {
    for (const q of [p - f.gap, p + f.gap]) {
      if (q > 1n && set.some((z) => z === q)) out.push({ family: f.id, partner: q.toString() });
    }
  }
  return out;
}

/**
 * Sophie Germain: p is SG when 2p+1 is prime.
 * @param {bigint} p
 * @returns {boolean}
 */
export function isSophieGermain(p) { return isPrime(2n * p + 1n); }

/**
 * Safe prime: p = 2q+1 with q prime. (The other half of the SG pair.)
 * @param {bigint} p
 * @returns {boolean}
 */
export function isSafePrime(p) {
  if (mod(p - 1n, 2n) !== 0n) return false;
  const q = (p - 1n) / 2n;
  return q > 1n && isPrime(q);
}

/**
 * CORRECTION OF RECORD (P16). An earlier pass read "Ramanujan prime" as OEIS
 * A104272 — the counting-function primes {2, 11, 17, 29, …}. That is the wrong
 * notion for this architecture. S_R here means the RAMANUJAN PARTITION
 * CONGRUENCE primes: the p for which the partition function satisfies an exact
 * congruence on an arithmetic progression,
 *
 *     p(5n+4) ≡ 0 (mod 5)    p(7n+5) ≡ 0 (mod 7)    p(11n+6) ≡ 0 (mod 11)
 *
 * so S_R = {5, 7, 11}. There is no such congruence for 13 at any offset —
 * verified exhaustively over every residue class in test/safe-basis.test.js —
 * which is exactly why 13 is capacity and not structure.
 */
export const RAMANUJAN_CONGRUENCE = [
  { prime: 5n, offset: 4n }, { prime: 7n, offset: 5n }, { prime: 11n, offset: 6n },
];
export const S_R = [5n, 7n, 11n];
/**
 * @param {bigint} p - a prime.
 * @returns {boolean} true iff p ∈ S_R = {5, 7, 11}.
 */
export function hasRamanujanCongruence(p) { return S_R.some((r) => r === p); }

/**
 * Exact partition numbers via the pentagonal number theorem. Integers only.
 * @param {bigint} N - compute p(0)..p(N).
 * @returns {Map<bigint, bigint>} n → p(n), keyed by BigInt.
 */
export function partitionNumbers(N) {
  const p = new Map([[0n, 1n]]);
  const order = [0n];
  for (let n = 1n; n <= N; n++) {
    let s = 0n;
    for (let k = 1n; ; k++) {
      const g1 = k * (3n * k - 1n) / 2n, g2 = k * (3n * k + 1n) / 2n;
      if (g1 > n && g2 > n) break;
      const sign = mod(k, 2n) === 1n ? 1n : -1n;
      if (g1 <= n) s = s + sign * p.get(n - g1);
      if (g2 <= n) s = s + sign * p.get(n - g2);
    }
    p.set(n, s);
    order.push(n);
  }
  return p;   // Map keyed by BigInt — no Number() coercion anywhere
}

// ── the three-tier structure ───────────────────────────────────────
//
// The Safe Basis is not a flat set. Fibonacci entry and the partition
// congruences split S6 into three disjoint tiers, and the tiers are NOT
// interchangeable.
//
//   T_fabric      {2, 3}      structural integrity — the fabric does not tear
//   T_measurement {5, 7, 11}  = S_R, exact partition congruences, analyzability
//   T_boundary    {13}        CAPACITY ONLY. Fails every Ramanujan congruence.
//
// Rule: 13 provides capacity, not structure. It must never be treated as
// equivalent to {5, 7, 11} in a structural argument.

export const T_FABRIC = [2n, 3n];
export const T_MEASUREMENT = [5n, 7n, 11n];
export const T_BOUNDARY = [13n];

/**
 * @param {bigint} p - a Safe Basis prime.
 * @returns {"fabric"|"measurement"|"boundary"|"extender"} its structural tier.
 */
export function tierOf(p) {
  if (T_FABRIC.some((z) => z === p)) return "fabric";
  if (T_MEASUREMENT.some((z) => z === p)) return "measurement";
  if (T_BOUNDARY.some((z) => z === p)) return "boundary";
  return "extender";
}

/**
 * @param {bigint} p
 * @returns {boolean} true iff p's tier is "fabric" or "measurement" (not boundary/extender).
 */
export function providesStructure(p) { return tierOf(p) !== "boundary" && tierOf(p) !== "extender"; }

/**
 * Fibonacci entry path. 7 and 11 enter only through COMPOSITE Fibonacci values.
 * @param {bigint} upTo - compute F(0)..F(upTo).
 * @returns {Map<bigint, bigint>} index → Fibonacci value, keyed by BigInt.
 */
export function fibonacci(upTo) {
  const F = new Map([[0n, 0n], [1n, 1n]]);
  for (let i = 2n; i <= upTo; i++) F.set(i, F.get(i - 1n) + F.get(i - 2n));
  return F;   // Map keyed by BigInt
}

export const FIBONACCI_ENTRY = [
  { prime: 2n, index: 3n, value: 2n, direct: true },
  { prime: 3n, index: 4n, value: 3n, direct: true },
  { prime: 5n, index: 5n, value: 5n, direct: true },
  { prime: 13n, index: 7n, value: 13n, direct: true },
  { prime: 7n, index: 8n, value: 21n, direct: false },    // 21 = 3 · 7
  { prime: 11n, index: 10n, value: 55n, direct: false },  // 55 = 5 · 11
];

// ── boot gates B001–B004 ───────────────────────────────────────────
//
// These are the "unbroken safe basis" check. They are what certifies the
// fixture — and, per P16, what certifies a transduction. The winding tower
// certifies depth inside one fixture and has nothing to say about the bridge.

export const SD11_ANCHOR = 11n ** 6n * 13n * 17n * 19n;   // 7,438,784,639
export const SD11_REJECT = 7437683639n;                   // known transcription error

/**
 * B001–B004: the "unbroken safe basis" boot-gate check.
 * @param {bigint[]} [basis=B8] - the basis to certify.
 * @param {bigint[]} [auxiliary=[]] - extra values (e.g. shadow-lattice moduli) to check coprime to the basis.
 * @returns {Object} `SAFE_BASIS_BOOT_GATES_V1` — B001_colony/B002_sd11_anchor/
 *   B003_no_repeat/B004_aux_coprime pass/fail detail, plus overall `unbroken`.
 */
export function bootGates(basis = B8, auxiliary = []) {
  const repeated = new Set(basis.map(String)).size !== basis.length;
  const g = (a, b) => { let x = a, y = b; while (y) { const t = mod(x, y); x = y; y = t; } return x; };
  return {
    kind: "SAFE_BASIS_BOOT_GATES_V1",
    B001_colony: { expected: "9699690", actual: basis.reduce((a, p) => a * p, 1n).toString(),
      pass: basis.reduce((a, p) => a * p, 1n) === 9699690n },
    B002_sd11_anchor: { expected: SD11_ANCHOR.toString(), reject: SD11_REJECT.toString(),
      pass: SD11_ANCHOR === 7438784639n && SD11_ANCHOR !== SD11_REJECT },
    B003_no_repeat: { pass: !repeated },
    B004_aux_coprime: { checked: auxiliary.map(String),
      pass: auxiliary.every((x) => basis.every((p) => g(x, p) === 1n)) },
    unbroken: !repeated
      && basis.reduce((a, p) => a * p, 1n) === 9699690n
      && auxiliary.every((x) => basis.every((p) => g(x, p) === 1n)),
  };
}

// ── the role taxonomy — architectural, not negotiable ──────────────

export const ROLES = [
  { prime: 2n, role: "parity witness", tier: "classical-six",
    note: "even/odd, binary carry chains, characteristic-2 operations; the minimal tick" },
  { prime: 3n, role: "triadic witness", tier: "classical-six",
    note: "three-fold symmetry and ternary parity; carries the trine" },
  { prime: 5n, role: "surface witness", tier: "classical-six",
    note: "dense residue coverage at small range; quadratic reciprocity; outer envelope" },
  { prime: 7n, role: "bridge witness", tier: "classical-six",
    note: "links the lower primes to the higher; transition prime" },
  { prime: 11n, role: "shadow anchor", tier: "classical-six",
    note: "the δ = 1 threshold; disambiguates isomorphic configurations" },
  { prime: 13n, role: "boundary witness", tier: "classical-six",
    note: "upper edge of the classical six; interacts with modular-form structure" },
  { prime: 17n, role: "saturation extender", tier: "extender",
    note: "with 19 lifts the shell to full object saturation; gear anchor (low)" },
  { prime: 19n, role: "saturation extender", tier: "extender",
    note: "with 17 lifts the shell to full object saturation; gear anchor (high); δ = 2 threshold" },
];

/**
 * @param {bigint} p - a Safe Basis prime.
 * @returns {Object} the matching `ROLES` entry: `{prime, role, tier, note}`.
 * @throws {Error} `"${p} is not in the Safe Basis"` if p is not one of the 8 basis primes.
 */
export function role(p) {
  const r = ROLES.find((z) => z.prime === p);
  if (!r) throw new Error(`${p} is not in the Safe Basis`);
  return r;
}

/** The shadow spine of the Safe Basis: its inert primes, in order. */
export const SHADOW_SPINE = B8.filter(isShadowPrime);      // 3, 7, 11, 19
/** The split primes of the Safe Basis. */
export const SPLIT_PRIMES = B8.filter((p) => gaussianClass(p) === "split");  // 5, 13, 17
/** The shadow anchor — the δ = 1 threshold and the disambiguating lane. */
export const SHADOW_ANCHOR = 11n;
/** The δ = 2 threshold — the first shadow prime above the anchor. */
export const SHADOW_ESCALATION = 19n;

/**
 * Consecutive gaps across the basis: 1, 2, 2, 4, 2, 4, 2.
 * @returns {bigint[]} B8[i] − B8[i-1] for i = 1..7.
 */
export function basisGaps() {
  const g = [];
  for (let i = 1; i < B8.length; i++) g.push(B8[i] - B8[i - 1]);
  return g;
}

/**
 * The full attribute record for one basis prime. All strings — JSON-safe.
 * @param {bigint} p - a Safe Basis prime.
 * @returns {Object} role, Gaussian class, shadow/family/Sophie-Germain/safe-prime/
 *   Ramanujan flags, tier, and ring-divisibility, all as decimal strings where numeric.
 * @throws {Error} propagated from `role(p)` if p is not a basis prime.
 */
export function primeProfile(p) {
  const r = role(p);
  const sq = sumOfTwoSquares(p);
  return {
    prime: p.toString(),
    role: r.role,
    note: r.note,
    gaussian_class: gaussianClass(p),
    mod_4: mod(p, 4n).toString(),
    is_shadow: isShadowPrime(p),
    two_squares: sq === null ? null : `${sq[0].toString()}² + ${sq[1].toString()}²`,
    families: familyPartners(p, B8),
    sophie_germain: isSophieGermain(p),
    safe_prime: isSafePrime(p),
    ramanujan_congruence: hasRamanujanCongruence(p),
    tier: tierOf(p),
    divides_ring: mod(ARCSEC_CIRCLE, p) === 0n,
    ring_defect: mod(ARCSEC_CIRCLE, p).toString(),
  };
}

/**
 * @returns {Object} `SAFE_BASIS_PROFILE_V1` — the whole basis, its tiers,
 *   shadow/split subsets, gaps, and per-prime `primeProfile` records.
 */
export function basisProfile() {
  return {
    kind: "SAFE_BASIS_PROFILE_V1",
    basis: B8.map(String),
    classical_six: B6.map(String),
    extenders: GEAR.map(String),
    shell: SHELL.toString(),
    colony: COLONY.toString(),
    shadow_spine: SHADOW_SPINE.map(String),
    shadow_anchor: SHADOW_ANCHOR.toString(),
    split_primes: SPLIT_PRIMES.map(String),
    tier_fabric: T_FABRIC.map(String),
    tier_measurement: T_MEASUREMENT.map(String),
    tier_boundary: T_BOUNDARY.map(String),
    gaps: basisGaps().map(String),
    primes: B8.map(primeProfile),
  };
}

// ── saturation: why the extenders exist ────────────────────────────

/**
 * Saturation report against a target range (default: the ecliptic ring).
 *
 *   shell_saturates : does M6 alone give unique representation over the range?
 *   colony_saturates: does M8?
 *   winding_bound   : K_max = ⌊(range−1)/M6⌋, the lift the shell cannot carry
 *   anchor_suffices : gear product 323 > K_max, so K mod 323 determines K
 *
 * For the ecliptic ring this reads: the classical six under-saturate by a
 * factor of 44 laps; the twin extenders carry exactly that deficit.
 * @param {bigint} [range=ARCSEC_CIRCLE] - the target range (default the ecliptic ring).
 * @returns {Object} `SAFE_BASIS_SATURATION_V1` — saturation flags and the
 *   winding bound the shell alone cannot carry, plus whether the extenders suffice.
 */
export function saturationReport(range = ARCSEC_CIRCLE) {
  const kMax = (range - 1n) / SHELL;
  const gearProduct = GEAR.reduce((a, p) => a * p, 1n);
  return {
    kind: "SAFE_BASIS_SATURATION_V1",
    range: range.toString(),
    shell: SHELL.toString(),
    colony: COLONY.toString(),
    shell_saturates: SHELL >= range,
    colony_saturates: COLONY >= range,
    winding_bound: kMax.toString(),
    laps_required: (kMax + 1n).toString(),
    gear_product: gearProduct.toString(),
    anchor_suffices: gearProduct > kMax,
    extenders: GEAR.map(String),
  };
}
