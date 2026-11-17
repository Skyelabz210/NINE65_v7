// src/core/variants.js — the astrological variant registry, stated exactly. (P11)
//
// Every major tradition that divides the zodiac is entered here as integer
// arithmetic on the arcsecond ring: a frame offset (ayanamsa or node
// reference) plus the set of divisions it cuts. Nothing here interprets;
// everything here is checkable.
//
// Status vocabulary follows CLAIM_BOUNDARY.md:
//   CLASSICAL  — the tradition's own established structure
//   DEFINED    — a constant or convention adopted here, not derived here
//   PROVEN     — certified by exhaustive exact test in test/
//   OPEN       — requires a certified ledger this core will not synthesise
//   LEDGER     — fulfilled via the ledger admission path (not a core float
//                implementation): a float solver lives in
//                project/tools/ephemeris/houses.js (outside src/core/, so
//                Mandate A1 does not apply to it), and its output enters
//                this core only as a schema-conformant, admitForCore()-
//                checked ledger entry — see project/src/ledger/
//                import-ledger.js and project/src/ledger/
//                ephemeris-ledger-schema.json. This core still never
//                computes house-circle trigonometry itself; LEDGER records
//                that the number now has a real, checkable provenance
//                chain instead of the bare "requires a ledger" placeholder
//                that OPEN was still communicating. (WP-12)
//
// BigInt only. No floats, no Date, no ephemeris.

import { mod } from "./residues.js";
import { RING, closes, stepArcsec, defect, offRingPrimes, divisionReport } from "./ring.js";

export const ARCSEC_PER_DEGREE = 3600n;
export const ARCSEC_PER_SIGN = 108000n;   // RING / 12

// ───────────────────────────────────────────────────────────────────
// Frames — a frame is a rotation of the ring. Ayanamsa values are exact
// integer arcseconds at epoch J2000.0 and are DEFINED inputs, not derived.
// The certification below is universal in the offset ω, so ayanamsa accuracy
// is orthogonal to it (see test/shadow-spine.test.js, rotation invariance).
// ───────────────────────────────────────────────────────────────────

export const FRAMES = [
  { id: "tropical", label: "Tropical (vernal point)", offset_arcsec: 0n, status: "CLASSICAL" },
  { id: "lahiri", label: "Sidereal · Lahiri / Chitrapaksha", offset_arcsec: 85871n, status: "DEFINED" },
  { id: "fagan_bradley", label: "Sidereal · Fagan–Bradley", offset_arcsec: 86741n, status: "DEFINED" },
  { id: "raman", label: "Sidereal · B. V. Raman", offset_arcsec: 80568n, status: "DEFINED" },
  { id: "krishnamurti", label: "Sidereal · Krishnamurti (KP)", offset_arcsec: 85691n, status: "DEFINED" },
  { id: "draconic", label: "Draconic (North Node origin)", offset_arcsec: null, status: "DEFINED" },
  { id: "heliocentric", label: "Heliocentric projection", offset_arcsec: null, status: "LEDGER" },
];

/**
 * @param {string} id - a frame id (see `FRAMES`).
 * @returns {Object} the matching `FRAMES` entry.
 * @throws {Error} `"unknown frame: ${id}"` if not found.
 */
export function frame(id) {
  const f = FRAMES.find((v) => v.id === id);
  if (!f) throw new Error(`unknown frame: ${id}`);
  return f;
}

/**
 * Rotate a ring position into a frame. A frame change subtracts the offset
 * modulo the ring — a bijection that preserves every difference, hence every
 * aspect. Only attribution (which sign, which nakshatra, which house) moves.
 * BigInt arcsecond regime: x and offset are integer arcseconds in [0, RING).
 * @param {bigint} x - a tropical ring position, in arcseconds.
 * @param {bigint} offset - the frame's offset, in arcseconds.
 * @returns {bigint} x rotated into the frame, in [0, RING).
 */
export function toFrame(x, offset) {
  return mod(x - offset, RING);
}

/**
 * Rotation is invertible on the ring; this is its exact inverse.
 * @param {bigint} x - a frame-relative ring position, in arcseconds.
 * @param {bigint} offset - the frame's offset, in arcseconds.
 * @returns {bigint} x rotated back to tropical, in [0, RING).
 */
export function fromFrame(x, offset) {
  return mod(x + offset, RING);
}

/**
 * Separation between two ring positions, as the shorter arc in [0, RING/2].
 * Frame-independent by construction.
 * @param {bigint} a - a ring position, in arcseconds.
 * @param {bigint} b - a ring position, in arcseconds.
 * @returns {bigint} the angular separation, in arcseconds, in [0, RING/2].
 */
export function separation(a, b) {
  const d = mod(a - b, RING);
  return d > RING / 2n ? RING - d : d;
}

// ───────────────────────────────────────────────────────────────────
// Divisions — every named cut of the zodiac, by its divisor n.
// ───────────────────────────────────────────────────────────────────

export const DIVISIONS = [
  // Western / Hellenistic
  { id: "sign", n: 12n, label: "Signs (rāśi / zōidion)", traditions: ["western", "hellenistic", "vedic", "medieval"] },
  { id: "decan", n: 36n, label: "Decans (Egyptian) ≡ drekkāṇa D-3", traditions: ["egyptian", "hellenistic", "vedic"] },
  { id: "dwad", n: 144n, label: "Dodecatemoria ≡ dvādaśāṁśa D-12", traditions: ["hellenistic", "vedic"] },
  { id: "degree", n: 360n, label: "Degrees", traditions: ["all"] },
  { id: "minute", n: 21600n, label: "Arcminutes", traditions: ["all"] },
  { id: "arcsec", n: RING, label: "Arcseconds (register unit)", traditions: ["all"] },
  // Preserve the legacy divisor API; this proxy is not the traditional
  // single-degree ruler assignment called monomoiria.
  { id: "monomoiria", n: 4320n, label: "Legacy equal 12-per-degree proxy", traditions: ["hellenistic"],
    convention: "Uniform proxy only; traditional monomoiria assign rulers to single degrees and are not implemented" },

  // Vedic / Jyotiṣa — the ṣoḍaśavarga
  { id: "hora", n: 24n, label: "Horā D-2", traditions: ["vedic"] },
  { id: "chaturthamsa", n: 48n, label: "Chaturthāṁśa D-4", traditions: ["vedic"] },
  { id: "saptamsa", n: 84n, label: "Saptāṁśa D-7", traditions: ["vedic"] },
  { id: "navamsa", n: 108n, label: "Navāṁśa D-9 ≡ nakṣatra pada", traditions: ["vedic"] },
  { id: "dasamsa", n: 120n, label: "Daśāṁśa D-10", traditions: ["vedic"] },
  { id: "rudramsa", n: 132n, label: "Rudrāṁśa D-11", traditions: ["vedic"] },
  { id: "shodasamsa", n: 192n, label: "Ṣoḍaśāṁśa D-16", traditions: ["vedic"] },
  { id: "vimsamsa", n: 240n, label: "Viṁśāṁśa D-20", traditions: ["vedic"] },
  { id: "siddhamsa", n: 288n, label: "Siddhāṁśa D-24", traditions: ["vedic"] },
  { id: "bhamsa", n: 324n, label: "Bhāṁśa D-27", traditions: ["vedic"] },
  { id: "trimsamsa", n: 360n, label: "Triṁśāṁśa D-30", traditions: ["vedic"] },
  { id: "khavedamsa", n: 480n, label: "Khavedāṁśa D-40", traditions: ["vedic"] },
  { id: "akshavedamsa", n: 540n, label: "Akṣavedāṁśa D-45", traditions: ["vedic"] },
  { id: "shashtiamsa", n: 720n, label: "Ṣaṣṭyāṁśa D-60", traditions: ["vedic"] },
  { id: "nakshatra", n: 27n, label: "Nakṣatras", traditions: ["vedic"] },

  // Krishnamurti Paddhati
  // Actual sublord widths are unequal: nakshatra arc times period/120.
  // Non-closure of this legacy uniform proxy says nothing about those widths.
  { id: "kp_sub", n: 249n, label: "Legacy uniform 249-cut KP proxy", traditions: ["kp"],
    convention: "Uniform proxy only; actual unequal Vimshottari-proportioned sublord boundaries are not implemented" },

  // Mesoamerican
  { id: "tzolkin", n: 260n, label: "Tzolk'in sacred round (13 × 20)", traditions: ["maya"] },
  { id: "haab", n: 365n, label: "Haab vague year", traditions: ["maya"] },
  { id: "trecena", n: 13n, label: "Trecena tone cycle", traditions: ["maya"] },
  { id: "veintena", n: 20n, label: "Veintena day-sign cycle", traditions: ["maya"] },

  // Sinitic
  { id: "branch", n: 12n, label: "Earthly branches", traditions: ["chinese"] },
  { id: "stem", n: 10n, label: "Heavenly stems", traditions: ["chinese"] },
  { id: "sexagenary", n: 60n, label: "Sexagenary cycle (jiǎzǐ)", traditions: ["chinese"] },
  { id: "xiu", n: 28n, label: "Twenty-eight lunar mansions (xiù)", traditions: ["chinese", "vedic"] },

  // Uranian / Hamburg
  { id: "dial_90", n: 4n, label: "90° dial", traditions: ["uranian"] },
  { id: "dial_45", n: 8n, label: "45° dial", traditions: ["uranian"] },
  { id: "dial_22_5", n: 16n, label: "22°30′ dial", traditions: ["uranian"] },

  // Speculative / modern
  { id: "ophiuchus", n: 13n, label: "Thirteen-sign zodiac", traditions: ["modern"] },
  { id: "mansion_arabic", n: 28n, label: "Arabic lunar mansions (manāzil)", traditions: ["medieval"] },
];

/**
 * @param {string} id - a division id (see `DIVISIONS`).
 * @returns {Object} the matching `DIVISIONS` entry.
 * @throws {Error} `"unknown division: ${id}"` if not found.
 */
export function division(id) {
  const d = DIVISIONS.find((v) => v.id === id);
  if (!d) throw new Error(`unknown division: ${id}`);
  return d;
}

/**
 * Which cut of a division does x fall in? Exact; null when the cut does not close.
 * @param {bigint} x - a ring position, in arcseconds.
 * @param {bigint} n - the division divisor.
 * @returns {?bigint} the 0-indexed cut number, or null if n does not divide RING.
 */
export function divisionIndex(x, n) {
  const step = stepArcsec(n);
  if (step === null) return null;
  return mod(x, RING) / step;
}

/**
 * Sign index 0–11 in a given frame.
 * @param {bigint} x - a tropical ring position, in arcseconds.
 * @param {bigint} offset - the frame's offset, in arcseconds.
 * @returns {bigint} the 0-indexed sign (0 = Aries in the tropical frame).
 */
export function signIndex(x, offset) {
  return toFrame(x, offset) / ARCSEC_PER_SIGN;
}

// ───────────────────────────────────────────────────────────────────
// Aspect families — an aspect set is a set of harmonic divisors.
// ───────────────────────────────────────────────────────────────────

export const ASPECT_FAMILIES = [
  { id: "ptolemaic", short: "Ptolemaic", label: "Ptolemaic (conj · sextile · square · trine · opp)", divisors: [1n, 2n, 3n, 4n, 6n], status: "CLASSICAL" },
  { id: "kepler_minor", short: "Minor", label: "Minor — semisextile · semisquare · sesquiquadrate · quincunx", divisors: [8n, 12n], status: "CLASSICAL" },
  { id: "quintile", short: "Quintile", label: "Quintile family (72° · 144°; classical tredecile 108°)", divisors: [5n, 10n], status: "CLASSICAL" },
  { id: "novile", short: "Novile", label: "Novile family (40° · 80° · 160°)", divisors: [9n, 18n], status: "CLASSICAL" },
  { id: "septile", short: "Septile", label: "Septile family (360/7)", divisors: [7n, 14n], status: "CLASSICAL" },
  { id: "undecile", short: "Undecile", label: "Undecile family (360/11)", divisors: [11n], status: "CLASSICAL" },
  { id: "harmonic_13", short: "13th harmonic", label: "Thirteenth-harmonic family (360/13)", divisors: [13n], status: "CLASSICAL" },
];

/**
 * Exact aspect angles for a family, in arcseconds; non-closing divisors yield null.
 * @param {Object} fam - an `ASPECT_FAMILIES` entry.
 * @returns {Object[]} one `{divisor, angle_arcsec, closes, defect_arcsec, off_ring_primes}` per divisor.
 */
export function familyAngles(fam) {
  return fam.divisors.map((n) => ({
    divisor: n.toString(),
    angle_arcsec: closes(n) ? (RING / n).toString() : null,
    closes: closes(n),
    defect_arcsec: defect(n).toString(),
    off_ring_primes: offRingPrimes(n).map(String),
  }));
}

// ───────────────────────────────────────────────────────────────────
// House systems — split by whether they are integer-exact on the ring or
// require oblique ascension (trigonometry), which this core will not admit.
// ───────────────────────────────────────────────────────────────────

export const HOUSE_SYSTEMS = [
  { id: "whole_sign", label: "Whole sign (Hellenistic · Jyotiṣa bhāva)", exact: true, status: "PROVEN" },
  { id: "equal_asc", label: "Equal from Ascendant", exact: true, status: "PROVEN" },
  { id: "equal_mc", label: "Equal from Midheaven", exact: true, status: "PROVEN" },
  { id: "vehlow", label: "Vehlow equal (ASC at cusp mid-point)", exact: true, status: "PROVEN" },
  { id: "porphyry", label: "Porphyry (quadrant trisection)", exact: true, status: "PROVEN" },
  // The eight quadrant systems below are all status: "LEDGER" (WP-12,
  // superseding the earlier "OPEN" placeholder — see the status-vocabulary
  // comment above). Each has a real float solver in
  // project/tools/ephemeris/houses.js (Koch/Regiomontanus/Campanus/
  // Alcabitius/Topocentric/Morinus/Meridian added there in WP-12; Placidus
  // in WP-11), verified there against genuine Swiss Ephemeris reference
  // output. This registry still refuses to compute any of them directly —
  // "exact: false" stays accurate, and the only way a value for one of
  // these systems reaches this core is by round-tripping through the
  // ledger contract (see project/src/ledger/import-ledger.js's
  // admitForCore(), which rejects anything not schema-conformant).
  { id: "placidus", label: "Placidus", exact: false, status: "LEDGER" },
  { id: "koch", label: "Koch (birthplace)", exact: false, status: "LEDGER" },
  { id: "regiomontanus", label: "Regiomontanus", exact: false, status: "LEDGER" },
  { id: "campanus", label: "Campanus", exact: false, status: "LEDGER" },
  { id: "alcabitius", label: "Alcabitius", exact: false, status: "LEDGER" },
  { id: "topocentric", label: "Topocentric (Polich–Page)", exact: false, status: "LEDGER" },
  { id: "morinus", label: "Morinus", exact: false, status: "LEDGER" },
  { id: "meridian", label: "Meridian / axial rotation", exact: false, status: "LEDGER" },
];

/**
 * Whole-sign house 1–12 of x given the ascendant, in a frame. Exact.
 * @param {bigint} x - a tropical ring position, in arcseconds.
 * @param {bigint} asc - the ascendant, in tropical arcseconds.
 * @param {bigint} offset - the frame's offset, in arcseconds.
 * @returns {bigint} the house number, 1–12.
 */
export function wholeSignHouse(x, asc, offset) {
  const s = signIndex(x, offset);
  const a = signIndex(asc, offset);
  return mod(s - a, 12n) + 1n;
}

/**
 * Equal house 1–12 measured from a cusp origin. Exact.
 * @param {bigint} x - a ring position, in arcseconds.
 * @param {bigint} origin - the house-1 cusp origin, in arcseconds.
 * @returns {bigint} the house number, 1–12.
 */
export function equalHouse(x, origin) {
  return mod(x - origin, RING) / ARCSEC_PER_SIGN + 1n;
}

/**
 * Vehlow: equal houses with the ascendant at the mid-point of house 1.
 * @param {bigint} x - a ring position, in arcseconds.
 * @param {bigint} asc - the ascendant, in arcseconds.
 * @returns {bigint} the house number, 1–12.
 */
export function vehlowHouse(x, asc) {
  return equalHouse(x, mod(asc - ARCSEC_PER_SIGN / 2n, RING));
}

/**
 * Thrown by porphyryCusps() when (asc, mc) do not stand in the cyclic
 * relationship quadrant-trisection houses require — see that function's
 * comment.
 */
export class DegenerateAnglesError extends Error {
  constructor(asc, mc) {
    super(
      `DegenerateAnglesError: porphyryCusps(asc=${asc}, mc=${mc}) — MC does not lead ASC by more ` +
        `than half the ring, so the fixed house-1..4..7..10 = ASC/IC/DSC/MC labeling cannot be ` +
        `trisected without a quadrant "arc" wrapping most of the way around the ring. This is not ` +
        `a rounding edge case: it means asc/mc do not come from an ordinary (non-polar) chart.`
    );
    this.name = "DegenerateAnglesError";
    this.asc = asc;
    this.mc = mc;
  }
}

/**
 * Porphyry: trisect each ecliptic quadrant. Houses run in increasing
 * longitude ASC(1) → IC(4) → DSC(7) → MC(10) — a FIXED labeling, not a
 * choice — so the twelve arcs sum to exactly one ring only when IC and MC
 * are actually encountered in that order walking forward from ASC.
 *
 * ASC/DSC and MC/IC are each an antipodal pair, so going around the ring
 * from ASC they interleave in exactly one of two ways: IC before MC (the
 * ordinary case for every non-polar chart — MC leads ASC by more than half
 * the ring) or MC before IC (MC leads by less than half). An earlier
 * version of this function assumed the first case unconditionally; when fed
 * an (asc, mc) pair from the second case (reachable at extreme/polar
 * latitudes, where the semi-arc geometry ASC/MC derive from becomes
 * asymmetric enough to invert this), the four arcs computed under the FIXED
 * asc→ic→dsc→mc labeling stop being the genuine local quadrants — one or
 * more balloons to cover most of the ring — and silently sum to a multiple
 * of the ring (verified: 3x) instead of exactly one ring, corrupting every
 * cusp. Rather than silently emit that corrupted output, this function now
 * validates the precondition and throws — the same "refuse rather than be
 * silently wrong" choice this codebase already makes for the float quadrant
 * systems beyond the polar circle (see project/tools/ephemeris/houses.js's
 * PolarLatitudeError). In the normal producer pipeline this is unreachable
 * in practice: ascMc() itself now throws before producing an asc/mc pair
 * that could violate this precondition (see houses.js) — this check exists
 * because porphyryCusps() is a general pure function callable with any
 * (asc, mc), not only ones that came from ascMc().
 *
 * Exact integer arithmetic — each quadrant arc is divided by 3 and the
 * remainder (0, 1, or 2 arcseconds) is distributed to the earliest houses of
 * that quadrant, so every cusp stays on the arcsecond lattice and the twelve
 * houses partition the ring with no gap and no overlap.
 * @param {bigint} asc - the ascendant, in arcseconds.
 * @param {bigint} mc - the midheaven, in arcseconds.
 * @returns {bigint[]} the twelve house cusps, in arcseconds, house 1 first.
 * @throws {DegenerateAnglesError} if MC does not lead ASC by more than half the ring.
 */
export function porphyryCusps(asc, mc) {
  if (mod(mc - asc, RING) <= RING / 2n) {
    throw new DegenerateAnglesError(asc, mc);
  }
  const ic = mod(mc + RING / 2n, RING);
  const dsc = mod(asc + RING / 2n, RING);
  const order = [asc, ic, dsc, mc];
  const cusps = [];
  for (let q = 0; q < 4; q++) {
    const start = order[q];
    const arc = mod(order[(q + 1) % 4] - start, RING);
    const base = arc / 3n;
    const rem = mod(arc, 3n);
    let cur = start;
    for (let i = 0n; i < 3n; i++) {
      cusps.push(cur);
      cur = mod(cur + base + (i < rem ? 1n : 0n), RING);
    }
  }
  return cusps;
}

// ───────────────────────────────────────────────────────────────────
// Medieval / Perso-Arabic time-lord periods. Integer years — and the
// Firdaria table is itself built from the spine primes 7, 11, 13.
// ───────────────────────────────────────────────────────────────────

export const FIRDARIA_YEARS = [
  { lord: "Sun", years: 10n }, { lord: "Venus", years: 8n }, { lord: "Mercury", years: 13n },
  { lord: "Moon", years: 9n }, { lord: "Saturn", years: 11n }, { lord: "Jupiter", years: 12n },
  { lord: "Mars", years: 7n }, { lord: "NorthNode", years: 3n }, { lord: "SouthNode", years: 2n },
];

export const VIMSHOTTARI_YEARS = [
  { lord: "Ketu", years: 7n }, { lord: "Venus", years: 20n }, { lord: "Sun", years: 6n },
  { lord: "Moon", years: 10n }, { lord: "Mars", years: 7n }, { lord: "Rahu", years: 18n },
  { lord: "Jupiter", years: 16n }, { lord: "Saturn", years: 19n }, { lord: "Mercury", years: 17n },
];

/**
 * @param {{lord: string, years: bigint}[]} table - a time-lord table (`FIRDARIA_YEARS` or `VIMSHOTTARI_YEARS`).
 * @returns {bigint} the sum of every lord's years.
 */
export function totalYears(table) {
  return table.reduce((a, r) => a + r.years, 0n);
}

// ───────────────────────────────────────────────────────────────────
// The variant registry — one entry per major tradition.
// ───────────────────────────────────────────────────────────────────

export const VARIANTS = [
  {
    id: "western_tropical", name: "Western Tropical", tradition: "western",
    frame: "tropical", houses: ["whole_sign", "equal_asc", "placidus", "koch"],
    aspects: ["ptolemaic", "kepler_minor"],
    divisions: ["sign", "decan", "degree"],
    note: "Modern tropical practice: 12 signs, quadrant houses, Ptolemaic plus minor aspects.",
  },
  {
    id: "hellenistic", name: "Hellenistic", tradition: "hellenistic",
    frame: "tropical", houses: ["whole_sign", "porphyry"],
    aspects: ["ptolemaic"],
    divisions: ["sign", "decan", "dwad", "monomoiria"],
    note: "Whole-sign houses, sect, bounds/terms, faces, lots. Aspects strictly Ptolemaic.",
  },
  {
    id: "medieval", name: "Medieval / Perso-Arabic", tradition: "medieval",
    frame: "tropical", houses: ["whole_sign", "alcabitius", "regiomontanus"],
    aspects: ["ptolemaic"],
    divisions: ["sign", "decan", "mansion_arabic"],
    timeLords: "firdaria",
    note: "Almuten, temperament, Firdāria time-lords, Arabic parts, 28 manāzil.",
  },
  {
    id: "vedic", name: "Vedic / Jyotiṣa (sidereal)", tradition: "vedic",
    frame: "lahiri", houses: ["whole_sign"],
    aspects: ["ptolemaic"],
    divisions: [
      "sign", "nakshatra", "navamsa", "hora", "decan", "chaturthamsa", "saptamsa",
      "dasamsa", "rudramsa", "dwad", "shodasamsa", "vimsamsa", "siddhamsa",
      "bhamsa", "trimsamsa", "khavedamsa", "akshavedamsa", "shashtiamsa",
    ],
    timeLords: "vimshottari",
    note: "Sidereal frame, 27 nakṣatras, the ṣoḍaśavarga divisional charts, Viṁśottarī daśā.",
  },
  {
    id: "kp", name: "Krishnamurti Paddhati", tradition: "kp",
    frame: "krishnamurti", houses: ["placidus"],
    aspects: ["ptolemaic"],
    divisions: ["sign", "nakshatra", "navamsa", "kp_sub"],
    note: "Registry only: J2000 KP frame and a legacy uniform 249-cut proxy; actual unequal Vimshottari sublord assignments and date-dependent ayanamsa are not implemented.",
  },
  {
    id: "maya", name: "Maya / Mesoamerican", tradition: "maya",
    frame: "tropical", houses: [],
    aspects: [],
    divisions: ["trecena", "veintena", "tzolkin", "haab"],
    note: "Tzolk'in 13 × 20, Haab 365, Calendar Round. The cylindrical-time layer.",
  },
  {
    id: "chinese", name: "Chinese Four Pillars", tradition: "chinese",
    frame: "tropical", houses: [],
    aspects: [],
    divisions: ["stem", "branch", "sexagenary", "xiu"],
    note: "Ten stems × twelve branches → sexagenary cycle; 28 xiù lunar mansions.",
  },
  {
    id: "uranian", name: "Uranian / Hamburg School", tradition: "uranian",
    frame: "tropical", houses: ["meridian"],
    aspects: ["ptolemaic", "kepler_minor"],
    divisions: ["dial_90", "dial_45", "dial_22_5"],
    note: "Midpoint trees on the 90°/45°/22°30′ dials; hypothetical bodies require a ledger.",
  },
  {
    id: "draconic", name: "Draconic", tradition: "modern",
    frame: "draconic", houses: ["whole_sign", "equal_asc"],
    aspects: ["ptolemaic"],
    divisions: ["sign", "decan"],
    note: "Zodiac re-originated at the North Node — a pure ring rotation.",
  },
  {
    id: "harmonic", name: "Harmonic (Addey)", tradition: "modern",
    frame: "tropical", houses: [],
    aspects: ["ptolemaic", "kepler_minor", "quintile", "novile", "septile", "undecile", "harmonic_13"],
    divisions: [],
    note: "Every nth-harmonic division treated as a first-class aspect family.",
  },
  {
    id: "heliocentric", name: "Heliocentric", tradition: "modern",
    frame: "heliocentric", houses: [],
    aspects: ["ptolemaic"],
    divisions: ["sign", "degree"],
    note: "A change of origin, not a ring rotation — admissible only from a certified ledger.",
  },
  {
    id: "sidereal_western", name: "Western Sidereal (Fagan–Bradley)", tradition: "western",
    frame: "fagan_bradley", houses: ["campanus", "whole_sign"],
    aspects: ["ptolemaic", "kepler_minor"],
    divisions: ["sign", "decan"],
    note: "Fagan–Bradley synetic vernal point; otherwise the Western apparatus unchanged.",
  },
  {
    id: "ophiuchus", name: "Thirteen-sign (constellational)", tradition: "modern",
    frame: "tropical", houses: [],
    aspects: [],
    divisions: ["ophiuchus"],
    note: "Popular thirteen-fold division. Included because its arithmetic is instructive.",
  },
];

/**
 * @param {string} id - a variant id (see `VARIANTS`).
 * @returns {Object} the matching `VARIANTS` entry.
 * @throws {Error} `"unknown variant: ${id}"` if not found.
 */
export function variant(id) {
  const v = VARIANTS.find((z) => z.id === id);
  if (!v) throw new Error(`unknown variant: ${id}`);
  return v;
}

/**
 * Exact coverage report for one variant: its frame, every division it cuts with
 * closure verdict and defect, its house systems split exact/ledger-gated, and
 * its aspect families with per-divisor closure.
 * @param {string} id - a variant id.
 * @returns {Object} `HCRM_VARIANT_REPORT_V1` — frame, divisions (each with a
 *   `divisionReport`), houses (split exact vs ledger-gated), and aspects
 *   (each with `familyAngles`).
 * @throws {Error} propagated from `variant(id)` if id is unknown.
 */
export function variantReport(id) {
  const v = variant(id);
  const f = frame(v.frame);
  const divisions = v.divisions.map((d) => {
    const dv = division(d);
    return { id: dv.id, label: dv.label, ...(dv.convention ? { convention: dv.convention } : {}), ...divisionReport(dv.n) };
  });
  const houses = v.houses.map((h) => HOUSE_SYSTEMS.find((s) => s.id === h)).filter(Boolean);
  const aspects = v.aspects.map((a) => {
    const fam = ASPECT_FAMILIES.find((z) => z.id === a);
    return { id: fam.id, short: fam.short, label: fam.label, angles: familyAngles(fam) };
  });
  const nonClosing = divisions.filter((d) => !d.closes);
  return {
    kind: "HCRM_VARIANT_REPORT_V1",
    id: v.id, name: v.name, tradition: v.tradition, note: v.note,
    frame: {
      id: f.id, label: f.label, status: f.status,
      offset_arcsec: f.offset_arcsec === null ? null : f.offset_arcsec.toString(),
      is_ring_rotation: f.offset_arcsec !== null,
    },
    divisions,
    non_closing_divisions: nonClosing.map((d) => d.id),
    houses: houses.map((h) => ({ id: h.id, label: h.label, exact: h.exact, status: h.status })),
    houses_exact: houses.filter((h) => h.exact).length,
    houses_ledger_gated: houses.filter((h) => !h.exact).length,
    aspects,
    time_lords: v.timeLords || null,
  };
}

/** @returns {Object[]} `variantReport(id)` for every entry in `VARIANTS`. */
export function allVariantReports() {
  return VARIANTS.map((v) => variantReport(v.id));
}
