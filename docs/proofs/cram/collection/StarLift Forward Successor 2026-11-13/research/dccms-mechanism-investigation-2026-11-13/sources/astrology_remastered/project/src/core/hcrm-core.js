// src/core/hcrm-core.js — exact HCRM register computation. (P3, re-based P21)
// Deterministic, BigInt-only, all outputs as strings. Imports no UI, no demo,
// no astrology prose. Input is a ledger entry with integer-string arcseconds.
//
// The register is now built on the PARKED split: shell {2,3,5,7,13,17,19} =
// 881,790 with the internal anchor on the parked lane 11. The winding is
// reported as the identity PAIR (r, K) — the two are never fused here. The
// legacy gear split is still computed alongside and still certified, so the
// re-base loses nothing.

import {
  B6, B8, GEAR, M6, M8, GEAR_PRODUCT, ARCSEC_CIRCLE,
  PARK, SHELL_LANES, M_SHELL, M_SHELL_INV_MOD_PARK, K_MAX_PARKED,
} from "./basis.js";
import { residueObject } from "./residues.js";
import { parseArcsecString } from "./validators.js";
import {
  parkedShellResidue, parkResidue, recoverShellWindingFrom, verifyShellWinding,
  shellResidue, recoverShellWindingFromGear, verifyLegacyShellWinding,
  windingFromTray,
} from "./shell-kelim.js";
import { gearClass } from "./gear-class.js";

/**
 * Build the full HCRM register for one ledger entry — every residue lane,
 * both the canonical (parked) and legacy (gear) shell splits, and their
 * K-Elimination winding certificates. Pure BigInt arithmetic throughout;
 * `entry.longitude_arcsec` is the sole numeric input and is expected as a
 * decimal-integer string or BigInt (see `parseArcsecString` in validators.js)
 * — an integer arcsecond in [0, 1296000), never a float degree.
 * @param {{longitude_arcsec: (string|bigint), body?: string, source?: *, certificate?: *}} entry
 *   - a schema-conformant ledger entry (see project/src/ledger/ephemeris-ledger-schema.json).
 *   `body` and `source`/`certificate` are passed through verbatim into the result.
 * @returns {Object} `HCRM_REGISTER_V2` — basis constants, residue trays
 *   (B8/shell/B6/gear), the canonical parked-shell identity pair (r, K) with
 *   its double K-Elimination lift, the legacy gear-shell identity pair, the
 *   gear class of the value, and the passed-through source/certificate.
 * @throws {Error} if `entry.longitude_arcsec` is not a valid integer-string in
 *   range (via `parseArcsecString`), or if the internal winding-recovery
 *   self-checks (parked-shell / legacy-shell / tray-lift) disagree with the
 *   directly computed windings — an implementation-fault signal, not a normal
 *   domain error.
 */
export function computeHcrmRegister(entry) {
  const x = parseArcsecString(entry.longitude_arcsec);

  const shellCheck = verifyShellWinding(x);
  if (!shellCheck.ok) throw new Error("HCRM shell winding recovery failed");

  const legacyCheck = verifyLegacyShellWinding(x);
  if (!legacyCheck.ok) throw new Error("HCRM legacy winding recovery failed");

  // The winding is derived, not stored: a double K-Elimination lift on the
  // phase-locked parked lane. Level 1 already covers the ring; the second level
  // is carried so the register shows how depth is obtained rather than asserted.
  const lift = windingFromTray(x, 2n);
  if (lift.K !== x / M_SHELL) throw new Error("HCRM winding lift failed");

  return {
    kind: "HCRM_REGISTER_V2",
    body: entry.body,
    longitude_arcsec: x.toString(),
    basis: {
      B8: B8.map(String), B6: B6.map(String), gear: GEAR.map(String),
      shell_lanes: SHELL_LANES.map(String), parked_lane: PARK.toString(),
      M_shell: M_SHELL.toString(), M6: M6.toString(), M8: M8.toString(),
      gear_product: GEAR_PRODUCT.toString(), arcsec_circle: ARCSEC_CIRCLE.toString(),
      k_max_over_ring: K_MAX_PARKED.toString(),
    },
    residues_B8: residueObject(x, B8),
    residues_shell: residueObject(x, SHELL_LANES),
    residues_B6: residueObject(x, B6),
    residues_gear: residueObject(x, GEAR),
    // canonical: the identity pair, uncoupled. r in the shell lanes, K on the
    // parked lane. Fusing them is a boundary projection and is not done here.
    shell: {
      split: "parked",
      r: parkedShellResidue(x).toString(),
      s: parkResidue(x).toString(),
      // K is DERIVED, never carried — a K-Elimination lift on the parked lane.
      // The ring needs only level 1 (K ≤ 1); the double lift is reported
      // alongside to show the mechanism that supplies depth beyond it.
      K: recoverShellWindingFrom(x).toString(),
      winding_derived: true,
      winding_carried: false,
      lift: {
        levels: lift.levels.toString(),
        depth: lift.depth.toString(),
        digits: lift.digits.map(String),
        corridor: lift.corridor.toString(),
        phase: lift.phases[0].toString(),
        phase_locked: lift.phases.every((p) => p % PARK === lift.phases[0]),
      },
      anchor: PARK.toString(),
      anchor_internal: true,
      inverse: M_SHELL_INV_MOD_PARK.toString(),
      K_certificate: shellCheck,
    },
    // retained, still certified — exact under the gear split
    legacy_shell: {
      split: "gear",
      r_M6: shellResidue(x).toString(),
      K: recoverShellWindingFromGear(x).toString(),
      K_certificate: legacyCheck,
    },
    gear_class: gearClass(x),
    source: entry.source,
    certificate: entry.certificate,
  };
}
