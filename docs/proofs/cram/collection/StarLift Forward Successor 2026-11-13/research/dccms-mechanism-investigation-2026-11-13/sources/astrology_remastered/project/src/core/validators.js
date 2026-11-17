// src/core/validators.js — admit only exact integer arcseconds. (P2)
// No Number, no Math.round, no parseFloat.

/** The ecliptic ring: 1,296,000 arcseconds = 360°. All core longitudes are BigInt residues in [0, ARCSEC_CIRCLE). */
export const ARCSEC_CIRCLE = 1296000n;

/**
 * Validate and parse a ledger longitude field. This is the sole entry point
 * by which an ecliptic-longitude value crosses from string/BigInt input into
 * the BigInt-arcsecond regime the rest of `src/core/` assumes.
 * @param {string|bigint} value - a decimal-integer string (digits only, no
 *   sign, no leading zero unless the value is "0") or a BigInt already in range.
 * @returns {bigint} the value as a BigInt in [0, ARCSEC_CIRCLE).
 * @throws {Error} if `value` is neither a bigint nor a string; if a string
 *   value contains anything but decimal digits; or if the numeric value is
 *   negative or ≥ ARCSEC_CIRCLE.
 */
export function parseArcsecString(value) {
  if (typeof value === "bigint") {
    if (value < 0n || value >= ARCSEC_CIRCLE)
      throw new Error("longitude_arcsec outside ecliptic arcsecond ring");
    return value;
  }
  if (typeof value !== "string")
    throw new Error("longitude_arcsec must be a decimal integer string");
  if (!/^(0|[1-9][0-9]*)$/.test(value))
    throw new Error("longitude_arcsec must contain only decimal digits");
  const x = BigInt(value);
  if (x < 0n || x >= ARCSEC_CIRCLE)
    throw new Error("longitude_arcsec outside ecliptic arcsecond ring");
  return x;
}

/**
 * Validate and parse a generic (non-longitude) ledger integer field — signed,
 * unbounded, decimal only. Unlike `parseArcsecString` this allows negative
 * values and does not range-check against the ring.
 * @param {string|bigint} value - a decimal integer string (optional leading
 *   "-", digits only, no leading zero unless the value is "0"/"-0"-shaped) or
 *   a BigInt.
 * @param {string} fieldName - used only to compose the thrown error message.
 * @returns {bigint} the value as a BigInt.
 * @throws {Error} if `value` is neither a bigint nor a valid decimal integer string.
 */
export function assertIntegerString(value, fieldName) {
  if (typeof value === "bigint") return value;
  if (typeof value !== "string")
    throw new Error(`${fieldName} must be a decimal integer string`);
  if (!/^-?(0|[1-9][0-9]*)$/.test(value))
    throw new Error(`${fieldName} must contain only decimal integer digits`);
  return BigInt(value);
}
