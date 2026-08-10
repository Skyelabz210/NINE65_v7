//! Safe-basis entry layer: feed text and arithmetic straight in, read the
//! actual magnitude back out.
//!
//! This is the residue-native front door. Values enter as Safe Basis residues
//! plus an exact winding count and never leave that form until an explicit
//! read-out. It is deliberately NOT an adapter over `DualRNSCiphertext` — the
//! safe basis is the foundation, not a witness bolted onto something else.
//!
//! # Why the winding is the point
//!
//! [`ExactState`] carries `lanes` (X mod each of {2,3,5,7,11,13}) *and*
//! `winding` (how many times X has wound past M = 30,030):
//!
//! ```text
//! X = garner(lanes) + winding * M_SAFE
//! ```
//!
//! An S8-style signature carries only the first term. That is why a signature
//! cannot see magnitude growth: growth lives entirely in the second. Every
//! operation here propagates the winding exactly, so
//! [`magnitude_bits`] reports the true size of the value at any point —
//! no estimate, no proxy, no counter maintained alongside the data.
//!
//! # Failure posture
//!
//! Winding is `i128`. A product of two large-winding states can exceed that.
//! Every operation is checked and returns `None` on overflow rather than
//! wrapping — an operation that cannot be represented exactly is refused, not
//! approximated.

use crate::cram_pde::{ExactState, M_SAFE, SAFE_BASIS};

// ─── Arithmetic ───────────────────────────────────────────────────────────

/// Canonical representative in `[0, M_SAFE)` — the first term of the
/// winding decomposition.
fn canonical(s: &ExactState) -> i128 {
    s.to_u128() as i128
}

/// Exact lane-wise addition with winding propagation.
///
/// Lanes add independently (no carry between lanes — that is the point of a
/// residue system). The winding absorbs the single carry that occurs when the
/// canonical parts sum past `M_SAFE`.
///
/// Returns `None` if the resulting winding does not fit `i128`.
pub fn add(a: &ExactState, b: &ExactState) -> Option<ExactState> {
    let mut lanes = [0u64; 6];
    for (i, &p) in SAFE_BASIS.iter().enumerate() {
        lanes[i] = (a.lanes[i] + b.lanes[i]) % p;
    }
    let (ga, gb) = (canonical(a), canonical(b));
    let carry = if ga + gb >= M_SAFE { 1i128 } else { 0 };
    let winding = a.winding.checked_add(b.winding)?.checked_add(carry)?;
    Some(ExactState { lanes, winding })
}

/// Exact lane-wise multiplication with winding propagation.
///
/// Every Safe Basis prime divides `M_SAFE`, so the cross terms in
/// `(g_a + K_a·M)(g_b + K_b·M)` vanish modulo each lane and the lanes are a
/// plain modular product. The winding carries everything else:
///
/// ```text
/// K_out = floor(g_a·g_b / M) + g_a·K_b + g_b·K_a + K_a·K_b·M
/// ```
///
/// Returns `None` on `i128` overflow in any term.
pub fn mul(a: &ExactState, b: &ExactState) -> Option<ExactState> {
    let mut lanes = [0u64; 6];
    for (i, &p) in SAFE_BASIS.iter().enumerate() {
        lanes[i] = (a.lanes[i] * b.lanes[i]) % p;
    }
    let (ga, gb) = (canonical(a), canonical(b));
    let prod = ga.checked_mul(gb)?;
    let winding = (prod / M_SAFE)
        .checked_add(ga.checked_mul(b.winding)?)?
        .checked_add(gb.checked_mul(a.winding)?)?
        .checked_add(a.winding.checked_mul(b.winding)?.checked_mul(M_SAFE)?)?;
    Some(ExactState { lanes, winding })
}

// ─── Reading the actual magnitude ─────────────────────────────────────────

/// Bit length of the true integer this state encodes.
///
/// This is a *measurement*, not an estimate: it is derived from the value
/// itself via the exact winding, not from an operation counter or a noise
/// model maintained beside the data.
pub fn magnitude_bits(s: &ExactState) -> u32 {
    let v = s.to_i128_exact();
    128 - v.unsigned_abs().leading_zeros()
}

/// How far past the corridor `[0, M_SAFE)` the value has travelled.
/// Zero means the value still fits one sheet of the CRT torus.
pub fn winding_bits(s: &ExactState) -> u32 {
    if s.winding == 0 {
        0
    } else {
        128 - s.winding.unsigned_abs().leading_zeros()
    }
}

// ─── Text ─────────────────────────────────────────────────────────────────

/// Bytes per chunk. `M_SAFE = 30,030` is the corridor, so a chunk that fits
/// one sheet must stay under it; 1 byte per lane-set keeps every chunk inside
/// the corridor with the winding free to carry arithmetic growth instead of
/// encoding artefacts.
const BYTES_PER_CHUNK: usize = 1;

/// Feed text straight in. Each byte becomes one [`ExactState`] inside the
/// corridor, so any winding observed later is arithmetic, not encoding.
pub fn encode_text(s: &str) -> Vec<ExactState> {
    s.as_bytes()
        .iter()
        .map(|&b| ExactState::from_i128(b as i128))
        .collect()
}

/// Read text back out. Returns `None` if any state is outside byte range —
/// which is the signal that arithmetic has moved it off the character it
/// started as.
pub fn decode_text(states: &[ExactState]) -> Option<String> {
    let bytes: Option<Vec<u8>> = states
        .iter()
        .map(|s| {
            let v = s.to_i128_exact();
            if (0..=255).contains(&v) {
                Some(v as u8)
            } else {
                None
            }
        })
        .collect();
    String::from_utf8(bytes?).ok()
}

const _: () = assert!(BYTES_PER_CHUNK == 1);

#[cfg(test)]
mod tests {
    use super::*;

    /// Exhaustive: every value in the corridor round-trips exactly.
    #[test]
    fn corridor_round_trips_exactly_for_every_value() {
        let mut checked = 0i128;
        for x in 0..M_SAFE {
            assert_eq!(ExactState::from_i128(x).to_i128_exact(), x, "x={x}");
            checked += 1;
        }
        assert_eq!(checked, M_SAFE, "must sweep the whole corridor, not a sample");
    }

    /// Addition must agree with i128 ground truth, including across the
    /// corridor boundary where the winding carry fires.
    #[test]
    fn add_agrees_with_ground_truth_across_the_corridor_boundary() {
        let cases = [
            (0i128, 0i128),
            (1, 1),
            (M_SAFE - 1, 1),          // exactly onto the boundary
            (M_SAFE - 1, M_SAFE - 1), // carry
            (M_SAFE, M_SAFE),
            (123_456_789, 987_654_321),
            (-5, 12),
            (-M_SAFE, -M_SAFE),
        ];
        let mut carried = 0;
        for (x, y) in cases {
            let got = add(&ExactState::from_i128(x), &ExactState::from_i128(y))
                .expect("no overflow expected")
                .to_i128_exact();
            assert_eq!(got, x + y, "add({x}, {y})");
            if ExactState::from_i128(x).to_u128() as i128
                + ExactState::from_i128(y).to_u128() as i128
                >= M_SAFE
            {
                carried += 1;
            }
        }
        assert!(carried > 0, "cases must actually exercise the winding carry");
    }

    /// Multiplication must agree with i128 ground truth, including cases where
    /// both operands already carry winding.
    #[test]
    fn mul_agrees_with_ground_truth_including_wound_operands() {
        let cases = [
            (0i128, 5i128),
            (1, 1),
            (7, 11),
            (M_SAFE - 1, 2),
            (M_SAFE + 3, M_SAFE + 5), // both wound
            (100_003, 99_991),
            (-7, 13),
            (-M_SAFE, 3),
        ];
        let mut wound = 0;
        for (x, y) in cases {
            let a = ExactState::from_i128(x);
            let b = ExactState::from_i128(y);
            let got = mul(&a, &b).expect("no overflow expected").to_i128_exact();
            assert_eq!(got, x * y, "mul({x}, {y})");
            if a.winding != 0 && b.winding != 0 {
                wound += 1;
            }
        }
        assert!(wound > 0, "cases must include operands that already carry winding");
    }

    /// The magnitude reader must track the real value, and a chain of squarings
    /// must show growth in the winding — this is the property an S8 signature
    /// cannot report.
    #[test]
    fn magnitude_is_read_from_the_value_not_from_a_counter() {
        let mut s = ExactState::from_i128(3);
        assert_eq!(winding_bits(&s), 0, "3 sits inside the corridor");

        let mut seen = Vec::new();
        for _ in 0..5 {
            s = mul(&s, &s).expect("no overflow in five squarings of 3");
            seen.push((s.to_i128_exact(), magnitude_bits(&s), winding_bits(&s)));
        }

        // 3^2, 3^4, 3^8, 3^16, 3^32 — checked against ground truth.
        let expect = [9i128, 81, 6561, 43_046_721, 1_853_020_188_851_841];
        for (i, &(v, _, _)) in seen.iter().enumerate() {
            assert_eq!(v, expect[i], "squaring step {i}");
        }

        let mags: Vec<u32> = seen.iter().map(|&(_, m, _)| m).collect();
        assert!(
            mags.windows(2).all(|w| w[1] > w[0]),
            "magnitude must strictly grow across squarings, got {mags:?}"
        );
        let last_winding = seen.last().unwrap().2;
        assert!(
            last_winding > 0,
            "3^32 far exceeds the corridor; winding must be nonzero, got {last_winding}"
        );
    }

    /// Overflow is refused, not wrapped.
    #[test]
    fn overflow_is_refused_rather_than_wrapped() {
        let huge = ExactState::from_i128(i128::MAX / 2);
        assert!(
            mul(&huge, &huge).is_none(),
            "a product that cannot be represented exactly must be refused"
        );
    }

    #[test]
    fn text_round_trips_and_arithmetic_moves_it_off_the_character() {
        let msg = "CRAM";
        let enc = encode_text(msg);
        assert_eq!(enc.len(), 4);
        assert_eq!(decode_text(&enc).as_deref(), Some(msg));

        for st in &enc {
            assert_eq!(winding_bits(st), 0, "a fresh character must sit in the corridor");
        }

        // Push one character out of byte range; decode must report the loss
        // rather than silently truncating.
        let mut moved = enc.clone();
        moved[0] = mul(&moved[0], &ExactState::from_i128(1000)).unwrap();
        assert!(
            decode_text(&moved).is_none(),
            "decode must refuse a value arithmetic has moved out of byte range"
        );
    }
}
