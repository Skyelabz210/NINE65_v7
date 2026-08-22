//! Public forwarding layer for the exact align-and-drop primitive.
//!
//! # Why this module exists
//!
//! [`crate::ops::rns_fhe`]'s `exact_modulus_switch_drop_poly` /
//! `exact_modulus_switch_drop_ct` are `pub(crate)`: they are verified
//! standalone primitives with no production caller yet by design (the
//! BGV/Clockwork migration that would call them is separate work — see
//! `docs/MODULUS_SWITCHING.md`), so nothing outside the crate had needed
//! them.
//!
//! The arrow-emission gate matrix
//! (`crates/nine65/tests/arrow_emission_fhe_gate_matrix.rs`) is an
//! *integration* test target: it links this crate from the outside. Two of
//! its gates are defined on exactly this primitive —
//!
//! * **G5, lift preserved across frame changes**: the represented value must
//!   survive a basis transition, i.e. the dropped-frame state must represent
//!   `floor(X / q_k)` EXACTLY on every surviving lane, and the winding must
//!   be carried across unchanged.
//! * **G6, refuse-not-project**: a drop that cannot be performed exactly
//!   (non-coprime lane, shape/index violation) must return a typed `Err`,
//!   never a silently wrong value.
//!
//! # What this module is NOT
//!
//! It performs no arithmetic of its own, adds no new contract, and changes
//! nothing about the primitives' behaviour or their `pub(crate)` visibility
//! inside the crate — the wrappers below are pure forwarding. It
//! deliberately exposes nothing secret-bearing: both entry points take and
//! return residue containers that the caller already holds.
//!
//! Re-read the caveat on the underlying function before using it for
//! anything other than a gate: this is a modulus switch by an RNS prime
//! `q_k`, **not** the BFV message rescale by `Δ = floor(Q/t)`. Substituting
//! one for the other mis-scales the message and breaks decryption.

use crate::errors::Nine65Result;
use crate::ops::rns_fhe::{DualRNSCiphertext, DualRNSPoly};

/// Exact modulus-switch by dropping one main-basis prime, applied to a single
/// polynomial. Forwards to `rns_fhe::exact_modulus_switch_drop_poly`; see
/// that function for the full exactness contract and error taxonomy.
pub fn exact_drop_poly(
    poly: &DualRNSPoly,
    main_primes: &[u64],
    anchor_primes: &[u64],
    drop_idx: usize,
) -> Nine65Result<DualRNSPoly> {
    crate::ops::rns_fhe::exact_modulus_switch_drop_poly(poly, main_primes, anchor_primes, drop_idx)
}

/// Exact modulus-switch by dropping one main-basis prime, applied to both
/// ciphertext components (and decrementing the level). Forwards to
/// `rns_fhe::exact_modulus_switch_drop_ct`.
pub fn exact_drop_ct(
    ct: &DualRNSCiphertext,
    main_primes: &[u64],
    anchor_primes: &[u64],
    drop_idx: usize,
) -> Nine65Result<DualRNSCiphertext> {
    crate::ops::rns_fhe::exact_modulus_switch_drop_ct(ct, main_primes, anchor_primes, drop_idx)
}
