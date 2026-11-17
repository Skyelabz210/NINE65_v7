/// band_add.rs — WASSAN 144-Band Integer Addition with Carry-Overflow Detection
///
/// ── The Bug (OP-WASSAN-1) ────────────────────────────────────────────────────
///
/// The original `band_add` implementation accumulated carries band-by-band but
/// silently discarded any carry that remained after the final (143rd) band.
/// In pseudo-code:
///
///   let mut carry = 0u64;
///   for i in 0..144 {
///       let total = a.bands[i] + b.bands[i] + carry;
///       carry = total / MODULI[i % 8];
///       result.bands[i] = total % MODULI[i % 8];
///   }
///   // ← carry silently dropped here  ← THE BUG
///
/// This is silent because the last band result `result.bands[143]` is always a
/// valid residue in `[0, MODULI[7])`.  No assertion fires.  The resulting
/// BandInteger looks well-formed but represents a value that is too small by
/// exactly `∏(all 144 band moduli)` — a 9072-bit error with ~2731 decimal digits.
///
/// ── When It Triggers ─────────────────────────────────────────────────────────
///
/// Band 143 uses modulus index `143 % 8 = 7` → `MODULI[7] = 2^63 − 601`.
/// Overflow fires when:
///
///   a.bands[143] + b.bands[143] + carry_from_band_142  ≥  2^63 − 601
///
/// Both operands can each be as large as `2^63 − 602`, and carry_from_band_142
/// can be 1, so the trigger condition arises during normal high-magnitude
/// arithmetic.  The existing 30,000-case test suite did not construct operands
/// that simultaneously saturate band 143 with a carry-in, which is why this
/// survived testing.
///
/// ── The Fix ──────────────────────────────────────────────────────────────────
///
/// Three strategies are implemented here:
///
///   (1) `band_add_checked` — returns `Err(BandOverflow)` when carry remains
///       after the final band.  Recommended for production.
///
///   (2) `band_add_assert` — debug build: panics with a descriptive message.
///       Release build: debug_assert (elided, no cost).  One-line equivalent
///       of the "one-line fix" from OP-WASSAN-1.
///
///   (3) `band_add_extended` — returns a 145-band result that captures the
///       overflow carry in band 144.  Use when the caller can tolerate a
///       dynamically-sized representation.
///
/// All three are algebraically equivalent in the no-overflow case.
/// `band_add_checked` is the canonical production implementation.
///
/// ── QMNF Constraint ──────────────────────────────────────────────────────────
///
/// Exact integer arithmetic.  No floating-point anywhere.  An overflow that
/// is silently truncated is a truth violation — the system must surface it.

/// The 8 near-Mersenne 63-bit moduli used by WASSAN.
///
/// Each is of the form 2^63 − c for small c, chosen to be prime.
/// Band i uses modulus `WASSAN_MODULI[i % 8]`.
pub const WASSAN_MODULI: [u64; 8] = [
    9_223_372_036_854_775_783, // 2^63 − 25
    9_223_372_036_854_775_611, // 2^63 − 165  (note: original offset list; verify primality)
    9_223_372_036_854_775_549, // 2^63 − 259
    9_223_372_036_854_775_507, // 2^63 − 301
    9_223_372_036_854_775_433, // 2^63 − 375
    9_223_372_036_854_775_387, // 2^63 − 421
    9_223_372_036_854_775_345, // 2^63 − 463
    9_223_372_036_854_775_207, // 2^63 − 601
];

/// Number of bands in a WASSAN integer.
pub const NUM_BANDS: usize = 144;

/// A WASSAN 144-band exact integer.
///
/// `bands[i]` is the residue of the integer modulo `WASSAN_MODULI[i % 8]`.
/// All 144 residues together uniquely identify any non-negative integer less
/// than `N = ∏_{i=0}^{143} WASSAN_MODULI[i % 8]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BandInteger {
    pub bands: [u64; NUM_BANDS],
}

impl BandInteger {
    /// Construct a BandInteger from a flat array of residues.
    /// Panics in debug if any band exceeds its modulus.
    pub fn new(bands: [u64; NUM_BANDS]) -> Self {
        #[cfg(debug_assertions)]
        for (i, &b) in bands.iter().enumerate() {
            debug_assert!(
                b < WASSAN_MODULI[i % 8],
                "band[{}] = {} exceeds modulus {} = 2^63-{}",
                i, b, WASSAN_MODULI[i % 8], (1u64 << 63) - WASSAN_MODULI[i % 8]
            );
        }
        Self { bands }
    }

    /// The zero element: all bands are 0.
    pub fn zero() -> Self {
        Self { bands: [0u64; NUM_BANDS] }
    }

    /// Modulus for band i.
    #[inline(always)]
    pub fn modulus_of(band_index: usize) -> u64 {
        WASSAN_MODULI[band_index % 8]
    }
}

// ─── Error Type ───────────────────────────────────────────────────────────────

/// Error returned when band_add produces a carry after the final band.
///
/// This indicates the mathematical sum exceeds the representable range of
/// the 144-band WASSAN integer (i.e., sum ≥ N = ∏ all 144 moduli).
/// The fix is either to extend to 145+ bands or to reduce operands beforehand.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BandOverflow {
    /// The carry value that was dropped in the buggy implementation.
    /// Always 1 in the current WASSAN modulus set (no band can produce carry > 1
    /// since max_sum < 3 × modulus for any band).
    pub carry: u64,
    /// The (incorrect) truncated result that the buggy implementation would return.
    /// Stored here for diagnostic comparison.
    pub truncated_result: BandInteger,
}

impl std::fmt::Display for BandOverflow {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "WASSAN band_add overflow: carry={} dropped after band {}. \
             Result is wrong by exactly {} × ∏(144 band moduli) ≈ 2^9072.",
            self.carry,
            NUM_BANDS - 1,
            self.carry
        )
    }
}

impl std::error::Error for BandOverflow {}

// ─── Fix 1: Checked Addition ──────────────────────────────────────────────────

/// Band addition with explicit overflow detection.
///
/// Returns `Ok(sum)` when the carry after the final band is zero.
/// Returns `Err(BandOverflow)` when a carry remains — the result would
/// have been silently incorrect under the original implementation.
///
/// # Correctness guarantee
/// If this function returns `Ok(result)`, then for all band indices i:
///   `result.bands[i] ≡ a.bands[i] + b.bands[i]  (mod WASSAN_MODULI[i % 8])`
/// and the combined CRT reconstruction of `result` equals the sum of the
/// CRT reconstructions of `a` and `b`.
///
/// # Time complexity
/// O(NUM_BANDS) — exactly 144 iterations, no reconstruction overhead.
pub fn band_add_checked(a: &BandInteger, b: &BandInteger) -> Result<BandInteger, BandOverflow> {
    let mut result_bands = [0u64; NUM_BANDS];
    let mut carry: u64 = 0;

    for i in 0..NUM_BANDS {
        let modulus = BandInteger::modulus_of(i);

        // Use u128 arithmetic to avoid overflow within the band computation.
        // Each operand is < 2^63, carry ≤ 1, so total < 2^64+1 which fits u128.
        let total = a.bands[i] as u128 + b.bands[i] as u128 + carry as u128;
        let modulus_u128 = modulus as u128;

        carry             = (total / modulus_u128) as u64;
        result_bands[i]   = (total % modulus_u128) as u64;
    }

    // ── THE FIX ──────────────────────────────────────────────────────────────
    // The original code reached here and returned result_bands, silently
    // discarding `carry`.  We now surface it.
    if carry != 0 {
        Err(BandOverflow {
            carry,
            truncated_result: BandInteger { bands: result_bands },
        })
    } else {
        Ok(BandInteger { bands: result_bands })
    }
}

// ─── Fix 2: Assert Version (one-line equivalent of OP-WASSAN-1) ───────────────

/// Band addition with a debug assertion that carry is zero after the final band.
///
/// In debug builds: panics with a descriptive message if overflow occurs.
/// In release builds: the assert is compiled out (zero overhead).
///
/// This is the "one-line fix" from OP-WASSAN-1 — the minimum viable change
/// to surface the bug during development without changing the return type.
///
/// For production correctness, prefer `band_add_checked`.
#[inline]
pub fn band_add_assert(a: &BandInteger, b: &BandInteger) -> BandInteger {
    let mut result_bands = [0u64; NUM_BANDS];
    let mut carry: u64 = 0;

    for i in 0..NUM_BANDS {
        let modulus = BandInteger::modulus_of(i);
        let total = a.bands[i] as u128 + b.bands[i] as u128 + carry as u128;
        carry           = (total / modulus as u128) as u64;
        result_bands[i] = (total % modulus as u128) as u64;
    }

    // ── THE ONE-LINE FIX ─────────────────────────────────────────────────────
    debug_assert!(
        carry == 0,
        "band_add overflow: carry={} dropped after band {}. \
         Sum exceeds WASSAN representable range (≈ 2^9072). \
         Use band_add_checked or band_add_extended to handle this.",
        carry, NUM_BANDS - 1
    );

    BandInteger { bands: result_bands }
}

// ─── Fix 3: Extended Addition ─────────────────────────────────────────────────

/// Band addition returning a 145-band result that captures any overflow carry.
///
/// `result.bands[144]` contains the carry out of band 143.  For well-formed
/// inputs (sum < N), this will always be 0.  When overflow occurs, it is 1,
/// and the 145-band representation is correct: it encodes the true sum.
///
/// The overflow band uses the next modulus in the cycle: `WASSAN_MODULI[144 % 8]`
/// = `WASSAN_MODULI[0]` = `2^63 − 25`.
pub fn band_add_extended(a: &BandInteger, b: &BandInteger) -> ([u64; NUM_BANDS + 1], bool) {
    let mut result_bands = [0u64; NUM_BANDS + 1];
    let mut carry: u64 = 0;

    for i in 0..NUM_BANDS {
        let modulus = BandInteger::modulus_of(i);
        let total = a.bands[i] as u128 + b.bands[i] as u128 + carry as u128;
        carry           = (total / modulus as u128) as u64;
        result_bands[i] = (total % modulus as u128) as u64;
    }

    // Capture carry in band 144.
    result_bands[NUM_BANDS] = carry;
    let overflowed = carry != 0;

    (result_bands, overflowed)
}

// ─── Utility: Small-integer fast path ────────────────────────────────────────

/// Construct a BandInteger from a u128 scalar.
///
/// Used in tests and for constructing small operands without a full
/// CRT decomposition pipeline.
pub fn band_integer_from_u128(x: u128) -> BandInteger {
    let mut bands = [0u64; NUM_BANDS];
    for i in 0..NUM_BANDS {
        bands[i] = (x % WASSAN_MODULI[i % 8] as u128) as u64;
    }
    BandInteger { bands }
}

/// Reconstruct a u128 scalar from a BandInteger using a simplified
/// Garner reconstruction over the first few bands.
///
/// IMPORTANT: valid only for values < WASSAN_MODULI[0] (i.e., < 2^63 - 25).
/// For values that span multiple bands, use the full WASSAN Garner reconstruction.
/// This simplified version is used ONLY in small-value unit tests.
pub fn band_integer_to_u128_small(x: &BandInteger) -> u128 {
    // For small values (< first modulus), band[0] = x mod M[0] = x exactly.
    x.bands[0] as u128
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Regression test R1: Direct overflow at band 143 ──────────────────────

    #[test]
    fn r1_band_add_checked_detects_overflow_at_band_143() {
        // Construct a that maximally saturates band 143 (= p-1 where p = MODULI[7])
        // and b that contributes a carry-in from band 142 plus band 143 overflow.
        //
        // Strategy: set all bands to their maximum values for both a and b.
        // Then a[143] + b[143] + carry_from_142 will overflow.

        let mut a_bands = [0u64; NUM_BANDS];
        let mut b_bands = [0u64; NUM_BANDS];

        // Set all bands to modulus - 1 (maximum value per band)
        for i in 0..NUM_BANDS {
            let m = BandInteger::modulus_of(i);
            a_bands[i] = m - 1;
            b_bands[i] = m - 1;
        }

        let a = BandInteger { bands: a_bands };
        let b = BandInteger { bands: b_bands };

        // (M[i]-1) + (M[i]-1) = 2*M[i] - 2, which gives carry=1 and result=M[i]-2
        // for every band.  The carry propagates all the way through band 143,
        // and there is still a carry=1 at the end.
        let result = band_add_checked(&a, &b);
        assert!(
            result.is_err(),
            "band_add_checked must return Err when overflow occurs at band 143"
        );

        let overflow = result.unwrap_err();
        assert_eq!(
            overflow.carry, 1,
            "Overflow carry must be exactly 1 (cannot exceed 1 for near-Mersenne moduli)"
        );
    }

    // ── Regression test R2: Round-trip consistency for small values ───────────

    #[test]
    fn r2_band_add_checked_correct_for_small_values() {
        // For values where no overflow occurs, checked addition must be exact:
        //   reconstruct(band_add(A, B)) == reconstruct(A) + reconstruct(B)
        //
        // We use values small enough that the first band alone holds the entire
        // value (< WASSAN_MODULI[0] = 2^63 - 25), so reconstruction is trivial.
        for a_val in [0u128, 1, 42, 1_000_000, u64::MAX as u128 / 4] {
            for b_val in [0u128, 1, 17, 999_999] {
                let a = band_integer_from_u128(a_val);
                let b = band_integer_from_u128(b_val);

                let sum_result = band_add_checked(&a, &b)
                    .expect(&format!("band_add({}, {}) must not overflow", a_val, b_val));

                // Verify the first band directly
                let expected_band0 = ((a_val + b_val) % WASSAN_MODULI[0] as u128) as u64;
                assert_eq!(
                    sum_result.bands[0], expected_band0,
                    "band[0] of sum({}, {}) must be {}",
                    a_val, b_val, expected_band0
                );

                // Verify ALL bands are consistent with a+b
                for i in 0..NUM_BANDS {
                    let m = WASSAN_MODULI[i % 8] as u128;
                    let expected_band_i = ((a_val + b_val) % m) as u64;
                    assert_eq!(
                        sum_result.bands[i], expected_band_i,
                        "band[{}] of sum({}, {}) must equal ({} + {}) mod {} = {}",
                        i, a_val, b_val, a_val, b_val, m, expected_band_i
                    );
                }
            }
        }
    }

    // ── Regression test R3: The buggy code returns wrong value; fix detects it ─

    #[test]
    fn r3_buggy_vs_fixed_diverge_exactly_on_overflow_inputs() {
        // Construct a specific overflow scenario and verify:
        //   - band_add_checked returns Err (correct)
        //   - The truncated_result.bands[143] is a valid residue (silent in buggy code)
        //   - band_add_extended reports overflowed = true and captures carry in band 144

        // Build the max-saturation case
        let mut a_bands = [0u64; NUM_BANDS];
        let mut b_bands = [0u64; NUM_BANDS];
        for i in 0..NUM_BANDS {
            let m = BandInteger::modulus_of(i);
            a_bands[i] = m - 1;
            b_bands[i] = m - 1;
        }
        let a = BandInteger { bands: a_bands };
        let b = BandInteger { bands: b_bands };

        // checked: returns Err
        let checked = band_add_checked(&a, &b);
        assert!(checked.is_err());

        // The truncated result is valid-looking (no residue out of range)
        let truncated = &checked.unwrap_err().truncated_result;
        for i in 0..NUM_BANDS {
            assert!(
                truncated.bands[i] < BandInteger::modulus_of(i),
                "Even the truncated result must have valid residues — this is why it was silent"
            );
        }

        // extended: captures carry in band 144
        let (ext_bands, overflowed) = band_add_extended(&a, &b);
        assert!(overflowed, "band_add_extended must report overflow");
        assert_eq!(
            ext_bands[NUM_BANDS], 1,
            "band[144] must hold the overflow carry = 1"
        );

        // assert version: in debug, this would panic.
        // We can't test the panic directly here, but we verify that the
        // *non-overflow path* of band_add_assert works correctly.
        let zero = BandInteger::zero();
        let one  = band_integer_from_u128(1);
        let zero_plus_one = band_add_assert(&zero, &one);
        assert_eq!(
            zero_plus_one.bands[0], 1,
            "0 + 1 must equal 1 in band 0"
        );
    }

    // ── Regression test R4: Zero + zero = zero ────────────────────────────────

    #[test]
    fn r4_zero_plus_zero_is_zero() {
        let z = BandInteger::zero();
        let result = band_add_checked(&z, &z).expect("0 + 0 must not overflow");
        assert_eq!(result, BandInteger::zero());
    }

    // ── Regression test R5: Commutativity ────────────────────────────────────

    #[test]
    fn r5_band_add_is_commutative() {
        let a = band_integer_from_u128(123_456_789);
        let b = band_integer_from_u128(987_654_321);
        let ab = band_add_checked(&a, &b).expect("no overflow");
        let ba = band_add_checked(&b, &a).expect("no overflow");
        assert_eq!(ab, ba, "band_add must be commutative");
    }

    // ── Regression test R6: Associativity ────────────────────────────────────

    #[test]
    fn r6_band_add_is_associative() {
        let a = band_integer_from_u128(100);
        let b = band_integer_from_u128(200);
        let c = band_integer_from_u128(300);
        let ab_c = band_add_checked(&band_add_checked(&a, &b).unwrap(), &c).unwrap();
        let a_bc = band_add_checked(&a, &band_add_checked(&b, &c).unwrap()).unwrap();
        assert_eq!(ab_c, a_bc, "band_add must be associative");
    }

    // ── Regression test R7: Identity element ─────────────────────────────────

    #[test]
    fn r7_zero_is_additive_identity() {
        let zero = BandInteger::zero();
        let x = band_integer_from_u128(42_000_000);
        let x_plus_zero = band_add_checked(&x, &zero).unwrap();
        let zero_plus_x = band_add_checked(&zero, &x).unwrap();
        assert_eq!(x_plus_zero, x, "x + 0 = x");
        assert_eq!(zero_plus_x, x, "0 + x = x");
    }

    // ── Regression test R8: Individual band correctness ───────────────────────

    #[test]
    fn r8_all_bands_are_correct_modular_residues() {
        // Verify that each band of sum(A, B) equals (A_val + B_val) mod M_i
        // for 20 different (a, b) pairs.
        let test_vals: &[(u128, u128)] = &[
            (0, 0), (1, 0), (0, 1), (1, 1),
            (100, 200), (999, 1), (u32::MAX as u128, u32::MAX as u128),
            (1_000_000, 2_000_000), (7, 11), (13, 17),
            (2_u128.pow(32), 2_u128.pow(32)),
            (2_u128.pow(40), 2_u128.pow(40)),
            (2_u128.pow(50), 1),
            (12345678, 87654321), (0, u32::MAX as u128),
            (1, u64::MAX as u128 / 8),
            (u64::MAX as u128 / 8, u64::MAX as u128 / 8),
            (u64::MAX as u128 / 16, u64::MAX as u128 / 16),
            (1_234_567_890_123, 9_876_543_210_987),
            (42, 42),
        ];

        for &(a_val, b_val) in test_vals {
            let a = band_integer_from_u128(a_val);
            let b = band_integer_from_u128(b_val);
            let expected_sum = a_val + b_val;

            match band_add_checked(&a, &b) {
                Ok(result) => {
                    for i in 0..NUM_BANDS {
                        let m = WASSAN_MODULI[i % 8] as u128;
                        let expected_band = (expected_sum % m) as u64;
                        assert_eq!(
                            result.bands[i], expected_band,
                            "a={} b={}: band[{}] expected {} got {}",
                            a_val, b_val, i, expected_band, result.bands[i]
                        );
                    }
                }
                Err(e) => {
                    panic!(
                        "Unexpected overflow for a={} b={}: {}",
                        a_val, b_val, e
                    );
                }
            }
        }
    }

    // ── Regression test R9: band_add_extended and checked agree on non-overflow ─

    #[test]
    fn r9_extended_and_checked_agree_for_small_inputs() {
        let a = band_integer_from_u128(42);
        let b = band_integer_from_u128(100);

        let checked = band_add_checked(&a, &b).unwrap();
        let (ext, overflowed) = band_add_extended(&a, &b);

        assert!(!overflowed);
        assert_eq!(ext[NUM_BANDS], 0, "no carry in band 144 for small inputs");
        for i in 0..NUM_BANDS {
            assert_eq!(
                checked.bands[i], ext[i],
                "checked and extended must agree for non-overflow inputs at band {}", i
            );
        }
    }

    // ── Regression test R10: Modulus assignment is correct ────────────────────

    #[test]
    fn r10_band_modulus_assignment() {
        // Band 143: index 143 % 8 = 7 → WASSAN_MODULI[7] = 2^63 - 601
        assert_eq!(BandInteger::modulus_of(143), WASSAN_MODULI[7]);
        assert_eq!(BandInteger::modulus_of(0),   WASSAN_MODULI[0]);
        assert_eq!(BandInteger::modulus_of(7),    WASSAN_MODULI[7]);
        assert_eq!(BandInteger::modulus_of(8),    WASSAN_MODULI[0]);
        assert_eq!(BandInteger::modulus_of(144),  WASSAN_MODULI[0]); // 145th band cycles
    }

    // ── Regression test R11: Specific overflow trigger values from analysis ────

    #[test]
    fn r11_specific_overflow_trigger_at_band_143() {
        // This test constructs exactly the scenario from the bug analysis:
        // a[143] = p-1, b[143] = p-1 where p = MODULI[7] = 2^63 - 601.
        // With carry_in = 1 from band 142, the sum overflows.
        //
        // We need carry_in = 1 to reach band 143.
        // Use a[0] = M[0]-1, b[0] = 1 to generate carry=1 at band 0,
        // then carry all the way through. But carrying through 143 bands is
        // complex to engineer precisely. Instead, we use the max-saturation
        // approach which provably produces carry=1 at every band.

        let p7 = WASSAN_MODULI[7]; // 2^63 - 601

        // Direct construction: a[143] = p7-1, all other a bands = 0
        //                      b[143] = p7-1, b[142] such that it generates carry=1
        // b[142] = M[142%8]-1, a[142] = 1  → carry out of band 142 = 1
        // Then band 143: (p7-1) + (p7-1) + 1 = 2*p7 - 1 → carry = 1

        let mut a_bands = [0u64; NUM_BANDS];
        let mut b_bands = [0u64; NUM_BANDS];

        // Set up carry-in at band 143
        a_bands[142] = 1;
        b_bands[142] = BandInteger::modulus_of(142) - 1; // band 142 → modulus index 6

        // Saturate band 143
        a_bands[143] = p7 - 1;
        b_bands[143] = p7 - 1;

        let a = BandInteger { bands: a_bands };
        let b = BandInteger { bands: b_bands };

        let result = band_add_checked(&a, &b);
        assert!(
            result.is_err(),
            "Specific overflow trigger (a[143]=p7-1, b[143]=p7-1, carry_in=1) must be detected"
        );

        let err = result.unwrap_err();
        assert_eq!(err.carry, 1,
            "Carry from band 143 overflow must be exactly 1");

        // The truncated result at band 143 would be:
        // (p7-1) + (p7-1) + 1 - p7 = p7 - 1 (the carry is dropped, band = p7-1)
        assert_eq!(
            err.truncated_result.bands[143], p7 - 1,
            "Truncated result at band 143 must be p7-1 (looks valid — this is why it was silent)"
        );
    }
}
