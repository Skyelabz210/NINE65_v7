// src/core/basis.js — exact HCRM basis constants. BigInt only.
// No floats, no Date, no synthetic periods. (P3, re-based P21)
//
// THE BASIS IS UNCHANGED. THE SPLIT IS WHAT MOVED.
// ───────────────────────────────────────────────
// SafeS8 = {2,3,5,7,11,13,17,19} is still the basis. What changed in P21 is
// which lanes carry value and which lane anchors:
//
//   CANONICAL (parked)   shell {2,3,5,7,13,17,19} = 881,790   anchor lane 11
//   LEGACY   (gear)      shell {2,3,5,7,11,13}    =  30,030   anchor 17·19 = 323
//
// Lane 11 is PARKED: in the basis, so the tray reaches it and the anchor stays
// internal, but out of the shell product so it can carry the winding. A lane
// cannot be both. The consequences, all verified:
//
//   · over the ecliptic ring the parked shell needs only K ≤ 1, so the bare
//     lane-11 anchor covers it outright. The legacy K ≤ 43 and the gear pair
//     were artefacts of loading 11 into the shell;
//   · gcd(11⁶, 881,790) = 1, so the shadow lift is plain coprime K-Elimination
//     with no divide-by-11 Hensel step.
//
// The legacy constants stay exported and stay PROVEN — the gear split is exact
// arithmetic and remains a valid configuration. It is simply no longer the one
// the register is built on.

/** The classical six-lane Safe Basis (legacy shell lanes). BigInt primes. */
export const B6 = [2n, 3n, 5n, 7n, 11n, 13n];
/** The legacy gear-pair extender lanes, used as the legacy external anchor. */
export const GEAR = [17n, 19n];
/** The full eight-lane Safe Basis ("the Colony"): B6 ∪ GEAR. BigInt primes. */
export const B8 = [2n, 3n, 5n, 7n, 11n, 13n, 17n, 19n];

/** ∏ B6 = 30,030 — legacy shell modulus. */
export const M6 = 30030n;            // ∏ B6        — legacy shell
/** 17 · 19 = 323 — legacy external anchor modulus. */
export const GEAR_PRODUCT = 323n;    // 17 · 19     — legacy anchor
/** ∏ B8 = 9,699,690 — the Colony (full-basis modulus). */
export const M8 = 9699690n;          // ∏ B8        — the Colony
/** The ecliptic arcsecond ring: 1,296,000 arcsec = 360°. Every core longitude lives in [0, ARCSEC_CIRCLE). */
export const ARCSEC_CIRCLE = 1296000n;

/** M6 mod GEAR_PRODUCT = 314 — precomputed for the legacy K-Elimination recovery. */
export const M6_MOD_GEAR = M6 % GEAR_PRODUCT;   // 314
/** Modular inverse of M6_MOD_GEAR mod GEAR_PRODUCT: 314⁻¹ ≡ 287 (mod 323). */
export const M6_INV_MOD_GEAR = 287n;            // 314⁻¹ mod 323

// ── canonical parked split ─────────────────────────────────────────

/** The parked lane: in the basis, out of the shell, carrying the winding. */
export const PARK = 11n;

/** Shell lanes once lane 11 is parked. */
export const SHELL_LANES = [2n, 3n, 5n, 7n, 13n, 17n, 19n];

/** ∏ SHELL_LANES = M8 / 11. */
export const M_SHELL = 881790n;

/** M_SHELL mod 11 = 8, and 8 · 7 ≡ 1 (mod 11). */
export const M_SHELL_MOD_PARK = M_SHELL % PARK;   // 8
export const M_SHELL_INV_MOD_PARK = 7n;           // 8⁻¹ mod 11

/** Winding bound over the ecliptic ring with the parked shell: ⌊(ARC−1)/M_SHELL⌋. */
export const K_MAX_PARKED = (ARCSEC_CIRCLE - 1n) / M_SHELL;   // 1
/** Winding bound with the legacy gear shell. */
export const K_MAX_LEGACY = (ARCSEC_CIRCLE - 1n) / M6;        // 43
