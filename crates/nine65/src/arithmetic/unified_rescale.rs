//! Exact-Δ unified rescale — one residue-native primitive, two exits.
//!
//! # What rounds in BFV, and why
//!
//! Textbook BFV encodes a message as `Δ·m` with `Δ = ⌊Q/t⌋`, and the rescale
//! after a tensor product computes `round(X·t/Q)`. The floor in `Δ = ⌊Q/t⌋` is
//! not an implementation choice — it is forced, because the modulus chain was
//! **hunted**: each `q_i` was searched for until it was simultaneously prime,
//! NTT-friendly (`q_i ≡ 1 mod 2N`), pairwise coprime, and coprime to `t`. A
//! chain built that way has `t ∤ Q` essentially always, so `Q/t` is not an
//! integer and `Δ` is a truncation of it. The shipped implementation in
//! `ops/rns_fhe.rs::exact_rescale` therefore rounds twice over: once in the
//! definition of the divisor, and again per lane in the Bajard-style quotient
//! (`+ q_i/2`). Its own doc comment says so.
//!
//! This module removes the premise instead of working around it. If the chain
//! is **manufactured** so that `Q = t · D`, then
//!
//! ```text
//!     Δ = Q/t = D    exactly — no floor, no residual, no rounding term
//! ```
//!
//! and, more importantly, `Δ` is a *product of lanes*. Dividing by a lane is
//! the align-and-drop phase differential that this repository already proves
//! exact in `ops/rns_fhe.rs::exact_modulus_switch_drop_poly`:
//!
//! ```text
//!     x_i' = (x_i − r_k) · q_k⁻¹   (mod q_i)      = ⌊X/q_k⌋ mod q_i
//! ```
//!
//! exact, no rounding term, never leaving residue space. Dividing by `Δ` is
//! then just that drop repeated once per Δ-lane, and `⌊⌊X/d₀⌋/d₁⌋ = ⌊X/(d₀d₁)⌋`
//! for positive integers, so the composition stays exact.
//!
//! ## Exactly which step would round under a hunted chain
//!
//! **The Δ-division, and only it.** Under a hunted `Q`, `Δ = ⌊Q/t⌋` is not a
//! divisor of `Q` and hence not a product of lanes, so align-and-drop is not
//! merely inaccurate — it is *inapplicable*, and the implementation is pushed
//! onto an approximate per-lane quotient. Under a manufactured `Q = t·D` that
//! same step becomes `|Δ-lanes|` exact integer divisions. The only rounding
//! left in this module is the one the caller *asks for*: round-to-nearest of
//! `X/Δ`, applied once, up front, as an exact integer offset `⌊Δ/2⌋`
//! ([`DeltaRounding::NearestHalfUp`]), after which every remaining step is
//! exact. [`DeltaRounding::Floor`] removes even that.
//!
//! Consequently this kernel computes `round(X·t/Q)` — the true BFV rescale
//! target — with **zero** implementation error. `tests::exhaustive_*` verify
//! that against directly computed integer ground truth over a complete range.
//!
//! # The pipeline
//!
//! ```text
//!   input residues (main lanes ‖ anchor lanes)
//!     → optional rounding offset ⌊Δ/2⌋            (BFV semantics)
//!     → align-and-drop every Δ-lane in turn       (each drop exact)
//!     → K-Elimination winding read: X = γ + K·M   (γ = X mod M, K = ⌊X/M⌋)
//!     → Universal Projection onto the target lanes
//! ```
//!
//! ## Two exits from one primitive
//!
//! [`RescaleExit`] is the whole difference between the two operations:
//!
//! | Exit | Result | Classical name |
//! |---|---|---|
//! | [`RescaleExit::ModulusReduced`] | value divided by `Δ`, held on the surviving lanes (modulus `Q/Δ = t`) | BGV-style modulus switch |
//! | [`RescaleExit::Reraise`] | the same value, projected back onto arbitrary target lanes | BFV-style rescale |
//!
//! They coincide *because* of the manufacturing: `Δ = Q/t` is simultaneously
//! the BFV message-scale divisor and a factor of the modulus, so "divide by the
//! scale" and "switch the modulus down" are literally the same division. Under
//! a hunted chain they cannot coincide, since `Δ ∤ Q` — which is precisely why
//! `ops/rns_fhe.rs` documents the two as distinct operations. See
//! `tests::two_exits_are_one_primitive`.
//!
//! # Nothing is reconstructed
//!
//! `Q` and `Δ` are never materialised as integers anywhere in this module —
//! not even to compute the rounding offset, which is obtained per-lane from
//! `Δ mod 2q` ([`RescaleChain::delta_half_mod`]). The only integers formed
//! are `γ < t` and the winding number `K < A`. `U256` is therefore not needed
//! and is not used; chains far wider than 128 bits are handled.
//!
//! # Preconditions, stated honestly
//!
//! Universal Projection needs no coprimality and no primality — that part of
//! the architecture holds unconditionally, and `tests::universal_projection_*`
//! exercises even, composite, repeated and chain-sharing target moduli. The
//! *drop* is a different matter: `(x_i − r_k)·q_k⁻¹ mod q_i` requires `q_k` to
//! be invertible mod every retained lane. So arbitrary moduli are free at the
//! **projection** boundary but not at the **division** boundary, and
//! [`RescaleChain::new`] refuses a chain that violates it with a typed
//! [`Nine65Error::NotCoprime`] rather than returning a wrong value.
//!
//! ## The one condition this module cannot check for you
//!
//! Every *shape* violation is refused with a typed error, but the **capacity**
//! condition is not detectable from residues and so is not enforced:
//!
//! ```text
//!     X + ⌊Δ/2⌋  <  Q · A        (A = anchor product; ⌊X/Q⌋ < A)
//! ```
//!
//! Exceed it and the winding number `K` wraps, and
//! [`exact_delta_rescale`] returns `Ok(_)` holding a **wrong value** — no
//! error, no flag. This is the ordinary RNS capacity condition rather than a
//! defect in the kernel, and it is measurable: on the `t = 6, Q = 546, A = 55`
//! test chain the first out-of-range input reconstructs to `0` where the true
//! rescale is `330`. It is the module's only silent-wrong-answer path, so an
//! integrator wiring this into `ops/` **must** establish the bound upstream
//! from the noise budget; the kernel cannot do it from what it is given.
//!
//! # Corrected identities
//!
//! The source white paper "Arbitrary Moduli in RNS-FHE" publishes the adjacency
//! read as `X mod A = (γ + K) mod A`. That is false: `A = P + 1` gives
//! `P ≡ −1 (mod A)`, so `K·P ≡ −K` and the read is `(γ − K) mod A`.
//! [`adjacency_project`] implements the corrected form and
//! `tests::adjacency_read_is_minus_not_plus` is a standing regression guard
//! that measures the published form failing.
//!
//! # Status
//!
//! Standalone, tested kernel. It is deliberately **not** wired into the
//! production multiply — that is a scheme-parameter decision, not a code
//! change, because it requires shipping a manufactured chain. Nothing under
//! `ops/` is touched.

use crate::arithmetic::rns::U256;
use crate::errors::{Nine65Error, Nine65Result};

/// Largest lane modulus this kernel accepts, exclusive.
///
/// Lanes are held below `2^63` so that `2·q` still fits in `u64` and every
/// intermediate product fits in `u128`. Every modulus used anywhere in this
/// workspace is far below this bound.
pub const MAX_LANE: u64 = 1u64 << 63;

// ═══════════════════════════════════════════════════════════════════
// Small integer helpers — integer-only, no floats, no reconstruction
// ═══════════════════════════════════════════════════════════════════

/// Greatest common divisor (binary-free Euclid, integer-only).
#[inline]
fn gcd(mut a: u64, mut b: u64) -> u64 {
    while b != 0 {
        let t = b;
        b = a % b;
        a = t;
    }
    a
}

#[cfg(test)]
pub(crate) mod mod_inverse_calls {
    use std::cell::Cell;
    thread_local! {
        static COUNT: Cell<usize> = const { Cell::new(0) };
    }
    pub(crate) fn increment() {
        COUNT.with(|c| c.set(c.get() + 1));
    }
    pub(crate) fn get() -> usize {
        COUNT.with(|c| c.get())
    }
    pub(crate) fn reset() {
        COUNT.with(|c| c.set(0));
    }
}

/// Modular inverse via the extended Euclidean algorithm.
///
/// Returns `None` when `gcd(a, m) ≠ 1` — the caller turns that into a typed
/// error rather than a wrong value.
#[inline]
fn mod_inverse_checked(a: u64, m: u64) -> Option<u64> {
    #[cfg(test)]
    mod_inverse_calls::increment();
    if m == 0 {
        return None;
    }
    if m == 1 {
        return Some(0);
    }
    let a = a % m;
    if a == 0 {
        return None;
    }
    // Extended Euclid over i128 so the Bézout coefficients cannot overflow.
    let (mut old_r, mut r) = (a as i128, m as i128);
    let (mut old_s, mut s) = (1i128, 0i128);
    while r != 0 {
        let q = old_r / r;
        let nr = old_r - q * r;
        old_r = r;
        r = nr;
        let ns = old_s - q * s;
        old_s = s;
        s = ns;
    }
    if old_r != 1 {
        return None;
    }
    let m_i = m as i128;
    Some((((old_s % m_i) + m_i) % m_i) as u64)
}

/// `(a · b) mod m` for `m < 2^63`.
#[inline]
fn mul_mod(a: u64, b: u64, m: u64) -> u64 {
    ((a as u128 * b as u128) % m as u128) as u64
}

/// Incremental Garner reconstruction.
///
/// Returns `(x, M)` with `x ≡ residues[i] (mod mods[i])` for all `i`,
/// `0 ≤ x < M`, and `M = ∏ mods`. Fails with [`Nine65Error::NotCoprime`] if the
/// moduli are not pairwise coprime and [`Nine65Error::Overflow`] if `M` exceeds
/// `u128`.
/// Parallel-summation CRT (R8, direct sum): every term is computed
/// independently — `term_i = M_i · ((r_i · (M_i⁻¹ mod m_i)) mod m_i)` — and
/// the terms are summed and reduced mod `M = ∏ m_i`. No digit reads any
/// other digit; no running value threads the lanes. This is the
/// materialization the lift inventory licenses (R8) where the sequential
/// Garner/MRC cascade (R9) is retired from runtime paths. Result-identical
/// to `garner` (the `#[cfg(test)]` oracle below cross-checks them).
fn parallel_summation_crt(
    residues: &[u64],
    mods: &[u64],
    precomputed_inv: Option<&[u64]>,
) -> Nine65Result<(u128, u128)> {
    #[cfg(test)]
    call_counters::PSUM_CALLS.with(|c| c.set(c.get() + 1));
    let mut m_prod: u128 = 1;
    for &m in mods {
        if m < 2 {
            return Err(Nine65Error::InvalidParameter {
                message: format!("unified_rescale: CRT modulus {m} < 2"),
            });
        }
        m_prod = m_prod
            .checked_mul(m as u128)
            .ok_or(Nine65Error::Overflow { operation: "unified_rescale::psum modulus" })?;
    }
    let mut x: u128 = 0;
    for (idx, (&r, &m)) in residues.iter().zip(mods.iter()).enumerate() {
        let mi = m_prod / m as u128;
        // `(M_i)^-1 mod m_i` depends only on `mods` (never on `residues`), so
        // a caller iterating this basis across many coefficients can compute
        // it once and pass it here instead of re-deriving it by extended
        // Euclid on every call -- see `RescaleChain`'s `gamma_merge_inv` /
        // `winding_merge_inv`, which is exactly this table precomputed once
        // per manufactured rescale instead of once per coefficient (measured
        // regression otherwise: this was the second instance of the same
        // per-coefficient-recompute bug the `drop_*_inv` tables fixed).
        let inv = if let Some(table) = precomputed_inv {
            table[idx]
        } else {
            let mi_mod = (mi % m as u128) as u64;
            mod_inverse_checked(mi_mod, m).ok_or(Nine65Error::NotCoprime {
                m: mi_mod,
                a: m,
                gcd: gcd(mi_mod, m),
            })?
        };
        // r·M_i·inv ≡ M_i·((r·inv) mod m_i) (mod M); the reduced form keeps
        // every term below M, so the running sum stays below k·M.
        let s = ((r % m) as u128 * inv as u128 % m as u128) as u64;
        let term = mi
            .checked_mul(s as u128)
            .ok_or(Nine65Error::Overflow { operation: "unified_rescale::psum term" })?;
        x = x
            .checked_add(term)
            .ok_or(Nine65Error::Overflow { operation: "unified_rescale::psum sum" })?;
        x %= m_prod;
    }
    Ok((x, m_prod))
}

/// [`parallel_summation_crt`] over a basis whose product exceeds `u128`.
///
/// Same R8 parallel summation — NOT a Garner cascade — carried in `U256` so
/// the anchor basis that certifies a manufactured rescale's winding is not
/// silently truncated to the first 128 bits' worth of anchors. Every term is
/// reduced modulo its own lane before the wide multiply, so the running sum
/// stays below `k·M` and `U256` is never overrun for the bases this kernel
/// accepts (`M < 2^192` covers every canonical anchor set).
fn parallel_summation_crt_u256(
    residues: &[u64],
    mods: &[u64],
    precomputed_inv: Option<&[u64]>,
) -> Nine65Result<(U256, U256)> {
    #[cfg(test)]
    call_counters::PSUM_CALLS.with(|c| c.set(c.get() + 1));
    for &m in mods {
        if m < 2 {
            return Err(Nine65Error::InvalidParameter {
                message: format!("unified_rescale: CRT modulus {m} < 2"),
            });
        }
    }
    let m_prod = U256::product_u64s(mods);
    let mut x = U256::zero();
    for (idx, (&r, &m)) in residues.iter().zip(mods.iter()).enumerate() {
        // M_i = ∏_{j≠i} m_j, formed by product rather than division so no
        // wide division is needed on the hot path.
        let mut mi = U256::from_u64(1);
        for (j, &mj) in mods.iter().enumerate() {
            if j != idx {
                mi = mi.mul_u64(mj);
            }
        }
        // Same precomputable quantity as `parallel_summation_crt` above,
        // widened to U256's `mi`: depends only on `mods`, not `residues`.
        let inv = if let Some(table) = precomputed_inv {
            table[idx]
        } else {
            let mi_mod = mi.mod_u64(m);
            mod_inverse_checked(mi_mod, m).ok_or(Nine65Error::NotCoprime {
                m: mi_mod,
                a: m,
                gcd: gcd(mi_mod, m),
            })?
        };
        let s = mul_mod(r % m, inv, m);
        x = x.add(mi.mul_u64(s)).rem_u256(m_prod);
    }
    Ok((x, m_prod))
}

/// Sequential Garner/MRC reconstruction. R9 in the lift-inventory taxonomy:
/// retired from runtime paths, retained here strictly as the independent
/// TEST ORACLE the corpus licenses it to be. Runtime code must call
/// `parallel_summation_crt` instead.
/// T2 tripwire-3 call counters, THREAD-LOCAL rather than process-global:
/// `cargo test` runs each test function on its own thread by default, and a
/// global counter would be incremented by whatever OTHER tests happen to
/// call `garner`/`parallel_summation_crt` concurrently, making a
/// before/after delta check flaky (the same bug measured and fixed for
/// `arithmetic::rns::to_u256_level_calls` — see its doc comment). A
/// thread-local counter only sees calls made by the thread running the
/// guardrail test itself.
#[cfg(test)]
mod call_counters {
    use core::cell::Cell;
    thread_local! {
        pub(super) static PSUM_CALLS: Cell<usize> = const { Cell::new(0) };
        pub(super) static GARNER_CALLS: Cell<usize> = const { Cell::new(0) };
    }
}

#[cfg(test)]
fn garner(residues: &[u64], mods: &[u64]) -> Nine65Result<(u128, u128)> {
    call_counters::GARNER_CALLS.with(|c| c.set(c.get() + 1));
    let mut x: u128 = 0;
    let mut m_acc: u128 = 1;
    for (&r, &m) in residues.iter().zip(mods.iter()) {
        if m < 2 {
            return Err(Nine65Error::InvalidParameter {
                message: format!("unified_rescale: garner modulus {m} < 2"),
            });
        }
        let m128 = m as u128;
        let x_mod = (x % m128) as u64;
        let r = r % m;
        let diff = (r + m - x_mod) % m;
        let acc_mod = (m_acc % m128) as u64;
        let inv = mod_inverse_checked(acc_mod, m).ok_or(Nine65Error::NotCoprime {
            m: acc_mod,
            a: m,
            gcd: gcd(acc_mod, m),
        })?;
        let k = mul_mod(diff, inv, m);
        let term = m_acc
            .checked_mul(k as u128)
            .ok_or(Nine65Error::Overflow { operation: "unified_rescale::garner term" })?;
        x = x
            .checked_add(term)
            .ok_or(Nine65Error::Overflow { operation: "unified_rescale::garner sum" })?;
        m_acc = m_acc
            .checked_mul(m128)
            .ok_or(Nine65Error::Overflow { operation: "unified_rescale::garner modulus" })?;
    }
    Ok((x, m_acc))
}

// ═══════════════════════════════════════════════════════════════════
// Universal Projection (A3) and its adjacency specialisation (U3)
// ═══════════════════════════════════════════════════════════════════

/// Universal Projection: read `X = γ + K·M` on **any** modulus `A ≥ 2`.
///
/// ```text
///     X mod A = (γ mod A + (K mod A)·(M mod A)) mod A
/// ```
///
/// This identity carries **no coprimality and no primality precondition** on
/// `A`: `A` may be even, composite, a power of two, equal to a chain lane, or
/// share arbitrary factors with `M`. It is the step that makes the re-raise
/// work over arbitrary target moduli, where a classical CRT basis extension
/// would demand a coprime target basis.
///
/// `X` itself is never formed, so this stays correct for `X` far beyond `u128`.
pub fn universal_project(gamma: u128, winding_k: u128, main_modulus: u128, target: u64) -> Nine65Result<u64> {
    if target < 2 {
        return Err(Nine65Error::InvalidParameter {
            message: format!("unified_rescale: projection target {target} < 2"),
        });
    }
    let a = target as u128;
    let g = gamma % a;
    let k = winding_k % a;
    let m = main_modulus % a;
    // k, m < 2^64 each, so the product cannot overflow u128.
    Ok(((g + (k * m) % a) % a) as u64)
}

/// Adjacency read (corrected U3): project onto the adjacent anchor `A = M + 1`.
///
/// Because `A = M + 1` we have `M ≡ −1 (mod A)`, so `K·M ≡ −K` and
///
/// ```text
///     X mod A = (γ − K) mod A          NOT (γ + K) mod A
/// ```
///
/// The published form `(γ + K) mod A` is wrong; the witness script measures it
/// holding for only 24 of 100 random cases, and
/// `tests::adjacency_read_is_minus_not_plus` keeps that measurement standing.
/// This also yields `M⁻¹ mod A = M` with no extended-gcd call, since
/// `M·M ≡ (−1)(−1) ≡ 1 (mod A)`.
pub fn adjacency_project(gamma: u128, winding_k: u128, main_modulus: u128) -> Nine65Result<u64> {
    if main_modulus >= u128::from(u64::MAX) {
        return Err(Nine65Error::Overflow {
            operation: "unified_rescale::adjacency_project anchor exceeds u64",
        });
    }
    // The anchor is A = M + 1, so the usable floor is A >= 2, i.e. M >= 1.
    // M = 1 is therefore accepted, not rejected: it gives A = 2, where
    // (γ − K) mod 2 == (γ + K) mod 2 and the read is still correct. Only
    // M = 0 is degenerate. The message names the condition actually tested.
    if main_modulus < 1 {
        return Err(Nine65Error::InvalidParameter {
            message: "unified_rescale: main modulus M must be at least 1 so that the \
                      adjacency anchor A = M + 1 is at least 2"
                .to_string(),
        });
    }
    let a = main_modulus + 1;
    let g = gamma % a;
    let k = winding_k % a;
    Ok(((g + a - k) % a) as u64)
}

// ═══════════════════════════════════════════════════════════════════
// Configuration
// ═══════════════════════════════════════════════════════════════════

/// Rounding convention applied *before* the exact division by `Δ`.
///
/// The offset is added once, as an exact integer, in residue form. Everything
/// downstream is exact regardless of the choice.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeltaRounding {
    /// `⌊X/Δ⌋` — no offset. Pure exact integer division.
    Floor,
    /// `round(X/Δ)` with ties up — offset `⌊Δ/2⌋`. This is BFV rescale
    /// semantics, and equals `round(X·t/Q)` exactly when `Q = t·Δ`.
    NearestHalfUp,
}

/// Which exit the unified primitive takes after the `Δ`-division.
///
/// This enum *is* the difference between a BGV-style modulus switch and a
/// BFV-style rescale; every step before it is shared.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RescaleExit<'a> {
    /// Stop after the drops: the value divided by `Δ`, held on the surviving
    /// lanes. The modulus has been reduced from `Q` to `Q/Δ = t`.
    ModulusReduced,
    /// Continue through the winding read into Universal Projection: the same
    /// value re-raised onto `target_lanes`, which may be the original chain
    /// (scale restored, modulus unchanged) or anything else.
    ///
    /// `target_lanes` carry **no** coprimality or primality precondition.
    Reraise {
        /// Arbitrary moduli, each `≥ 2`. Duplicates permitted.
        target_lanes: &'a [u64],
    },
}

// ═══════════════════════════════════════════════════════════════════
// The manufactured chain
// ═══════════════════════════════════════════════════════════════════

/// A modulus chain manufactured so that `Q = t · Δ` holds by construction,
/// with `Δ` a product of designated lanes.
///
/// Construction validates every precondition of the pipeline and refuses,
/// with a typed error, anything it cannot execute exactly. In particular a
/// chain with `t ∤ Q` — i.e. an ordinary hunted chain — is rejected outright
/// rather than silently rounded. That refusal is the safety property.
///
/// # Relationship to [`crate::params::manufactured::ManufacturedChain`]
///
/// The two types are adjacent layers, not duplicates, and were named apart to
/// keep them that way:
///
/// | | `params::manufactured::ManufacturedChain` | `RescaleChain` (here) |
/// |---|---|---|
/// | Role | **manufactures** the parameters | **executes** the rescale on them |
/// | Builds | `Q = t·∏Dᵢ` from star lanes `D = c·t + 1` | nothing; takes a basis as given |
/// | Width | unbounded (`ExactMagnitude` limbs) | `u64` lanes, `u128` intermediates |
/// | Answers | how wide is `Q`, is `Δ` exact, is any lane weak | what is `round(X·t/Q)` |
///
/// A deployment picks a chain with the `params` type and then executes on it
/// with this one. This type deliberately does not re-derive `Q`: it never
/// materialises it at all (see the module docs), which is why it needs no
/// unbounded-width arithmetic even for chains far past 128 bits.
#[derive(Clone, Debug)]
pub struct RescaleChain {
    lanes: Vec<u64>,
    delta_lanes: Vec<usize>,
    surviving_idx: Vec<usize>,
    surviving_lanes: Vec<u64>,
    anchors: Vec<u64>,
    anchor_product: U256,
    t: u64,
    // Precomputed inverses for the per-coefficient hot path. Every value
    // `mod_inverse_checked` used to compute inside `exact_delta_rescale` /
    // `rescale_drop_only` depends only on this chain's fixed lane and anchor
    // structure -- never on the coefficient's residues -- so recomputing it
    // once per coefficient (measured: 32 extended-Euclid calls/coefficient,
    // 16,384 for one 512-coefficient rescale) redid identical work up to N
    // times. Same disease `precompute_m_level_inverses` (arithmetic/rns.rs)
    // already exists to cure for `extract_k_rns_level`; this applies the
    // same fix here. `drop_main_inv[step][i] = Some(inv)` when main lane `i`
    // is still alive (not yet dropped, not the lane being dropped) at drop
    // step `step`, mirroring the align-and-drop loop's own `alive[]`
    // bookkeeping exactly so the set of populated entries matches what the
    // original loop would have computed, one-for-one.
    drop_main_inv: Vec<Vec<Option<u64>>>,
    drop_anchor_inv: Vec<Vec<u64>>,
    winding_anchor_inv: Vec<u64>,
    // The second instance of the same disease, in the CRT-basis merge
    // (`parallel_summation_crt`/`_u256`) both hot-path calls run into once
    // per coefficient: `(M_i)^-1 mod m_i` depends only on the merge basis
    // (`surviving_lanes` / `anchors`), never on the coefficient's residues.
    gamma_merge_inv: Vec<u64>,
    winding_merge_inv: Vec<u64>,
}

impl RescaleChain {
    /// Build and validate a manufactured chain.
    ///
    /// * `lanes` — the main RNS basis; `Q = ∏ lanes`. Lanes may be composite.
    /// * `delta_lanes` — indices whose product is `Δ`. The remaining lanes must
    ///   multiply to exactly `t`, which is what makes `Δ = Q/t` exact.
    /// * `t` — the plaintext modulus. May be composite.
    /// * `anchors` — the K-Elimination anchor basis used for the winding read.
    ///   May be empty; see [`Self::anchors`].
    ///
    /// # Errors
    ///
    /// * [`Nine65Error::InexactDivision`] — `t ∤ Q`. This is the hunted-chain
    ///   refusal: the kernel will not round on your behalf.
    /// * [`Nine65Error::InvalidParameter`] — shape violations, or `t | Q` but
    ///   `Δ` is not the product of the nominated lanes (align-and-drop needs
    ///   `Δ` factored over the basis, not merely dividing `Q`).
    /// * [`Nine65Error::NotCoprime`] — a Δ-lane is not invertible modulo some
    ///   retained lane or anchor, or the surviving/anchor bases are not
    ///   pairwise coprime.
    /// * [`Nine65Error::Overflow`] — the anchor product exceeds `u128`.
    pub fn new(
        lanes: &[u64],
        delta_lanes: &[usize],
        t: u64,
        anchors: &[u64],
    ) -> Nine65Result<Self> {
        // ── shape ────────────────────────────────────────────────────
        if lanes.is_empty() {
            return Err(Nine65Error::InvalidParameter {
                message: "unified_rescale: empty lane chain".to_string(),
            });
        }
        if t < 2 {
            return Err(Nine65Error::InvalidParameter {
                message: format!("unified_rescale: plaintext modulus t={t} < 2"),
            });
        }
        for &q in lanes.iter().chain(anchors.iter()) {
            if q < 2 {
                return Err(Nine65Error::InvalidParameter {
                    message: format!("unified_rescale: modulus {q} < 2"),
                });
            }
            if q >= MAX_LANE {
                return Err(Nine65Error::InvalidParameter {
                    message: format!("unified_rescale: modulus {q} >= 2^63 (MAX_LANE)"),
                });
            }
        }

        // ── the manufacturing guard: does t divide Q? ────────────────
        //
        // Q mod t is computed from the lane residues, so no big integer is
        // ever formed and chains far wider than u128 are handled.
        let mut q_mod_t: u128 = 1 % t as u128;
        for &q in lanes {
            q_mod_t = (q_mod_t * (q % t) as u128) % t as u128;
        }
        if q_mod_t != 0 {
            // Report Q itself when it is representable; a hunted chain wide
            // enough to overflow u128 still gets a typed refusal.
            let mut q_full: Option<u128> = Some(1);
            for &q in lanes {
                q_full = q_full.and_then(|v| v.checked_mul(q as u128));
            }
            return match q_full {
                Some(q) => Err(Nine65Error::InexactDivision { value: q, divisor: t }),
                None => Err(Nine65Error::InvalidParameter {
                    message: format!(
                        "unified_rescale: t={t} does not divide Q (Q mod t = {q_mod_t}); \
                         Q exceeds u128 so it cannot be reported inline. \
                         This chain is hunted, not manufactured — rescaling it would round."
                    ),
                }),
            };
        }

        // ── Δ must be factored over the basis, not merely divide Q ───
        let mut seen = vec![false; lanes.len()];
        for &i in delta_lanes {
            if i >= lanes.len() {
                return Err(Nine65Error::InvalidParameter {
                    message: format!(
                        "unified_rescale: delta lane index {i} >= chain length {}",
                        lanes.len()
                    ),
                });
            }
            if seen[i] {
                return Err(Nine65Error::InvalidParameter {
                    message: format!("unified_rescale: delta lane index {i} repeated"),
                });
            }
            seen[i] = true;
        }
        let surviving_idx: Vec<usize> = (0..lanes.len()).filter(|i| !seen[*i]).collect();
        let surviving_lanes: Vec<u64> = surviving_idx.iter().map(|&i| lanes[i]).collect();

        let mut surviving_product: u128 = 1;
        for &q in &surviving_lanes {
            surviving_product = surviving_product.checked_mul(q as u128).ok_or(
                Nine65Error::Overflow { operation: "unified_rescale: surviving product" },
            )?;
        }
        if surviving_product != t as u128 {
            return Err(Nine65Error::InvalidParameter {
                message: format!(
                    "unified_rescale: Δ is not the product of the nominated lanes — \
                     the retained lanes multiply to {surviving_product}, not t={t}. \
                     Align-and-drop divides by lanes, so Δ = Q/t must be factored over \
                     the basis, not merely divide Q."
                ),
            });
        }

        // ── coprimality the *division* needs (projection needs none) ──
        for &i in delta_lanes {
            let d = lanes[i];
            for (j, &q) in lanes.iter().enumerate() {
                if j == i {
                    continue;
                }
                let g = gcd(d, q);
                if g != 1 {
                    return Err(Nine65Error::NotCoprime { m: d, a: q, gcd: g });
                }
            }
            for &a in anchors {
                let g = gcd(d, a);
                if g != 1 {
                    return Err(Nine65Error::NotCoprime { m: d, a, gcd: g });
                }
            }
        }
        // Surviving lanes pairwise coprime (Garner on γ).
        for x in 0..surviving_lanes.len() {
            for y in (x + 1)..surviving_lanes.len() {
                let g = gcd(surviving_lanes[x], surviving_lanes[y]);
                if g != 1 {
                    return Err(Nine65Error::NotCoprime {
                        m: surviving_lanes[x],
                        a: surviving_lanes[y],
                        gcd: g,
                    });
                }
            }
        }
        // Anchors pairwise coprime (Garner on K) and coprime to M (winding read).
        for x in 0..anchors.len() {
            for y in (x + 1)..anchors.len() {
                let g = gcd(anchors[x], anchors[y]);
                if g != 1 {
                    return Err(Nine65Error::NotCoprime { m: anchors[x], a: anchors[y], gcd: g });
                }
            }
            let g = gcd((surviving_product % anchors[x] as u128) as u64, anchors[x]);
            if g != 1 {
                return Err(Nine65Error::NotCoprime { m: t, a: anchors[x], gcd: g });
            }
        }
        // U256, not u128: the manufactured rescale's winding bound scales with
        // the OPERAND magnitude, and dual-RNS ciphertext coefficients are not
        // canonical in [0,Q) (measured: |V| up to 2·N·Q). The anchor product
        // that certifies that winding therefore has to be allowed past 128
        // bits — capping it here was what forced the shipped path onto a
        // 4-anchor, 125-bit subset that silently aliased.
        let anchor_product = U256::product_u64s(anchors);

        // Precompute the hot-path inverses. Every coprimality check this
        // needs already ran above (the "coprimality the division needs" and
        // "surviving/anchors pairwise coprime" blocks), so every
        // `mod_inverse_checked` call here is guaranteed `Some` -- a `None`
        // here would mean this function should already have returned
        // `NotCoprime` earlier, which is a bug in THIS function, not a
        // reachable runtime state.
        let mut alive: Vec<bool> = vec![true; lanes.len()];
        let mut drop_main_inv: Vec<Vec<Option<u64>>> = Vec::with_capacity(delta_lanes.len());
        let mut drop_anchor_inv: Vec<Vec<u64>> = Vec::with_capacity(delta_lanes.len());
        for &k in delta_lanes {
            let d = lanes[k];
            let mut main_row: Vec<Option<u64>> = vec![None; lanes.len()];
            for i in 0..lanes.len() {
                if i == k || !alive[i] {
                    continue;
                }
                let q = lanes[i];
                main_row[i] = Some(
                    mod_inverse_checked(d % q, q)
                        .expect("RescaleChain::new: coprimality already verified above"),
                );
            }
            drop_main_inv.push(main_row);
            let anchor_row: Vec<u64> = anchors
                .iter()
                .map(|&a| {
                    mod_inverse_checked(d % a, a)
                        .expect("RescaleChain::new: coprimality already verified above")
                })
                .collect();
            drop_anchor_inv.push(anchor_row);
            alive[k] = false;
        }
        // Winding-read inverses: `m_mod_a = surviving_product() mod a = t mod a`,
        // fixed for the whole chain (surviving_product() == t always).
        let winding_anchor_inv: Vec<u64> = anchors
            .iter()
            .map(|&a| {
                let m_mod_a = t % a;
                mod_inverse_checked(m_mod_a, a)
                    .expect("RescaleChain::new: coprimality already verified above")
            })
            .collect();

        // gamma_merge_inv: (M_i)^-1 mod m_i for the surviving-lane CRT merge
        // `parallel_summation_crt` runs in step 3. M_i = surviving_product / m_i;
        // both are chain-fixed, so this is computable here once instead of
        // once per coefficient in the merge itself.
        let surviving_product_u128: u128 = surviving_lanes.iter().map(|&m| m as u128).product();
        let gamma_merge_inv: Vec<u64> = surviving_lanes
            .iter()
            .map(|&m| {
                let mi = surviving_product_u128 / m as u128;
                let mi_mod = (mi % m as u128) as u64;
                mod_inverse_checked(mi_mod, m)
                    .expect("RescaleChain::new: coprimality already verified above")
            })
            .collect();

        // winding_merge_inv: the same quantity for the anchor-basis CRT merge
        // `parallel_summation_crt_u256` runs to combine the winding K.
        let winding_merge_inv: Vec<u64> = anchors
            .iter()
            .enumerate()
            .map(|(idx, &m)| {
                let mut mi = U256::from_u64(1);
                for (j, &mj) in anchors.iter().enumerate() {
                    if j != idx {
                        mi = mi.mul_u64(mj);
                    }
                }
                let mi_mod = mi.mod_u64(m);
                mod_inverse_checked(mi_mod, m)
                    .expect("RescaleChain::new: coprimality already verified above")
            })
            .collect();

        Ok(Self {
            lanes: lanes.to_vec(),
            delta_lanes: delta_lanes.to_vec(),
            surviving_idx,
            surviving_lanes,
            anchors: anchors.to_vec(),
            anchor_product,
            t,
            drop_main_inv,
            drop_anchor_inv,
            winding_anchor_inv,
            gamma_merge_inv,
            winding_merge_inv,
        })
    }

    /// The full main basis. `Q = ∏ lanes`.
    pub fn lanes(&self) -> &[u64] {
        &self.lanes
    }

    /// Indices of the lanes whose product is `Δ`.
    pub fn delta_lane_indices(&self) -> &[usize] {
        &self.delta_lanes
    }

    /// The lanes that survive the `Δ`-division. Their product is exactly `t`.
    pub fn surviving_lanes(&self) -> &[u64] {
        &self.surviving_lanes
    }

    /// The anchor basis used for the K-Elimination winding read.
    ///
    /// May be empty, in which case the winding number is taken to be `0` and
    /// the caller asserts that the post-division value is below `t`.
    pub fn anchors(&self) -> &[u64] {
        &self.anchors
    }

    /// The plaintext modulus `t`. Equals `∏ surviving_lanes` by construction.
    pub fn t(&self) -> u64 {
        self.t
    }

    /// Product of the surviving lanes as an integer — equal to `t`.
    pub fn surviving_product(&self) -> u128 {
        self.t as u128
    }

    /// Product of the anchor lanes; `1` when there are no anchors.
    ///
    /// `U256` because the winding capacity a manufactured rescale needs can
    /// exceed 128 bits — see [`Self::anchor_product_u128`] for the narrow
    /// read used by callers whose bases are small by construction.
    pub fn anchor_product(&self) -> U256 {
        self.anchor_product
    }

    /// The anchor product as a `u128`, or `None` when it does not fit.
    pub fn anchor_product_u128(&self) -> Option<u128> {
        if self.anchor_product.hi == 0 {
            Some(self.anchor_product.lo)
        } else {
            None
        }
    }

    /// `Q mod t`. Always `0` for a constructed chain — that is the invariant.
    ///
    /// Exposed so a caller can display the residual next to a hunted chain's,
    /// which is nonzero. It is computed from lane residues; `Q` is not formed.
    pub fn residual_q_mod_t(&self) -> u64 {
        let mut r: u128 = 1 % self.t as u128;
        for &q in &self.lanes {
            r = (r * (q % self.t) as u128) % self.t as u128;
        }
        r as u64
    }

    /// `Δ mod m`, computed from lane residues without forming `Δ`.
    pub fn delta_mod(&self, m: u64) -> u64 {
        let mut r: u128 = 1 % m as u128;
        for &i in &self.delta_lanes {
            r = (r * (self.lanes[i] % m) as u128) % m as u128;
        }
        r as u64
    }

    /// `⌊Δ/2⌋ mod m`, computed without forming `Δ`.
    ///
    /// Write `Δ = 2m·s + u` with `u = Δ mod 2m`. Then `⌊Δ/2⌋ = m·s + ⌊u/2⌋`,
    /// so `⌊Δ/2⌋ mod m = ⌊u/2⌋ mod m`. Exact for even `m` as well, where
    /// halving cannot be done by multiplying by `2⁻¹`. Requires `m < 2^63`,
    /// which [`MAX_LANE`] enforces.
    pub fn delta_half_mod(&self, m: u64) -> u64 {
        let m2 = (m as u128) * 2;
        let mut u: u128 = 1 % m2;
        for &i in &self.delta_lanes {
            u = (u * (self.lanes[i] as u128 % m2)) % m2;
        }
        ((u / 2) % m as u128) as u64
    }

    /// `Δ` as an integer, when it fits in `u128`. Diagnostics only — the
    /// pipeline never calls this.
    pub fn try_delta_u128(&self) -> Option<u128> {
        let mut d: u128 = 1;
        for &i in &self.delta_lanes {
            d = d.checked_mul(self.lanes[i] as u128)?;
        }
        Some(d)
    }

    /// `Q` as an integer, when it fits in `u128`. Diagnostics only.
    pub fn try_q_u128(&self) -> Option<u128> {
        let mut q: u128 = 1;
        for &l in &self.lanes {
            q = q.checked_mul(l as u128)?;
        }
        Some(q)
    }
}

// ═══════════════════════════════════════════════════════════════════
// Output
// ═══════════════════════════════════════════════════════════════════

/// Result of [`exact_delta_rescale`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RescaleOutput {
    /// Residues of `Y = X/Δ` on the surviving lanes (modulus `t`).
    ///
    /// This is the BGV-style modulus-switched ciphertext value, and it is
    /// produced identically on both exits.
    pub surviving_residues: Vec<u64>,
    /// Residues of `Y` on the anchor lanes, carried through the drops.
    pub anchor_residues: Vec<u64>,
    /// `γ = Y mod t` from the K-Elimination winding read.
    pub gamma: u128,
    /// `K = ⌊Y/t⌋`, the winding number, from the anchors. `0` when the chain
    /// has no anchors.
    ///
    /// `U256`: the winding a manufactured rescale carries can exceed `u128`,
    /// where a narrow read wrapped silently.
    ///
    /// This is the LEAST NON-NEGATIVE representative, `K mod C`. When `X` is
    /// negative — which it routinely is, the negacyclic convolution subtracts
    /// — the true winding is negative and this field holds `C − |K|`. Read
    /// [`Self::winding_signed`] instead unless you specifically want the
    /// unsigned residue.
    pub winding_k: U256,
    /// Sign of the winding under the BALANCED lift about `C/2`.
    ///
    /// The balanced lift is what lets the rescale carry a signed `X` with no
    /// positive shift at all — the same convention `SignedK256::from_unsigned`
    /// applies on the materializing path, which never needed a shift.
    pub winding_k_neg: bool,
    /// `|K|` under the balanced lift. `winding_k` when non-negative,
    /// `C − winding_k` when negative.
    pub winding_k_mag: U256,
    /// Residues of `Y` on the target lanes. Empty on
    /// [`RescaleExit::ModulusReduced`].
    pub target_residues: Vec<u64>,
}

impl RescaleOutput {
    /// `Y = γ + K·t` as an integer, when it fits in `u128`.
    ///
    /// The pipeline does not need this; it is here so tests and callers can
    /// compare against directly computed ground truth.
    pub fn reconstruct(&self, chain: &RescaleChain) -> Nine65Result<u128> {
        let y = self
            .winding_k
            .mul_u64(chain.t())
            .add(U256::from_u128(self.gamma));
        if y.hi != 0 {
            return Err(Nine65Error::Overflow {
                operation: "unified_rescale: reconstruct γ+K·M exceeds u128",
            });
        }
        Ok(y.lo)
    }

    /// The winding as a `u128`, or `None` when it does not fit.
    ///
    /// Callers whose anchor basis is narrow by construction can use this;
    /// the manufactured rescale cannot, which is why the field is `U256`.
    pub fn winding_k_u128(&self) -> Option<u128> {
        if self.winding_k.hi == 0 {
            Some(self.winding_k.lo)
        } else {
            None
        }
    }

    /// The winding under the balanced lift: `(is_negative, |K|)`.
    ///
    /// Prefer this to [`Self::winding_k`] anywhere `X` may be negative.
    pub fn winding_signed(&self) -> (bool, U256) {
        (self.winding_k_neg, self.winding_k_mag)
    }

    /// `Y = γ + K·t` as a `U256` — always exact for the chains this kernel
    /// accepts, and the form the manufactured rescale actually consumes.
    pub fn reconstruct_wide(&self, chain: &RescaleChain) -> U256 {
        self.winding_k
            .mul_u64(chain.t())
            .add(U256::from_u128(self.gamma))
    }
}

// ═══════════════════════════════════════════════════════════════════
// The primitive
// ═══════════════════════════════════════════════════════════════════

/// Divide a residue-borne value by `Δ = Q/t` exactly, then take one of two
/// exits.
///
/// `main_residues[i] = X mod lanes[i]` and `anchor_residues[j] = X mod
/// anchors[j]`, where `X` is the value being rescaled. `X` is never
/// reconstructed.
///
/// # Range precondition
///
/// `X` may be SIGNED. The align-and-drop is exact over all of ℤ — `r_d` is the
/// least non-negative residue, so `X − r_d = d·⌊X/d⌋` holds for negative `X`
/// too, and the drops compose. What the representation bounds is the
/// magnitude: under the balanced lift the condition is
/// `|X + ⌊Δ/2⌋| < Q·A/2`, equivalently `|K| < C/2`. This is the ordinary
/// BALANCED RNS capacity condition and cannot be detected from residues
/// alone; violating it wraps the winding number.
///
/// A caller that keeps `X ≥ 0` may use the full range `X + ⌊Δ/2⌋ < Q·A` and
/// read [`RescaleOutput::winding_k`] directly; one that carries a signed `X`
/// reads [`RescaleOutput::winding_signed`] and gets half the range. The
/// manufactured rescale does the latter, which is why it needs no shift.
/// With no anchors, the condition is `X/Δ < t`.
///
/// # Errors
///
/// Shape mismatches, non-invertible drop lanes, and target moduli below `2`
/// all return typed errors. No path returns an approximate value.
/// Steps 1–2 only: the rounding offset and the align-and-drop, with **no
/// winding read and no materialization of any kind** — every operation is a
/// per-lane update using a cross-lane *read* of the dropped lane's residue
/// (never a running value). This is the fully lane-local
/// `RescaleExit::ModulusReduced` path, exposed for the ct-path hot loop
/// (charter milestone M2b): the output IS the carried state — residues of
/// `Y = ⌊(X+offset)/Δ⌋` on the surviving and anchor lanes.
pub fn rescale_drop_only(
    chain: &RescaleChain,
    main_residues: &[u64],
    anchor_residues: &[u64],
    rounding: DeltaRounding,
) -> Nine65Result<(Vec<u64>, Vec<u64>)> {
    if main_residues.len() != chain.lanes.len() || anchor_residues.len() != chain.anchors.len() {
        return Err(Nine65Error::InvalidParameter {
            message: "unified_rescale: residue count does not match chain shape".into(),
        });
    }
    let mut main: Vec<u64> = Vec::with_capacity(chain.lanes.len());
    for (i, &q) in chain.lanes.iter().enumerate() {
        let mut x = main_residues[i] % q;
        if rounding == DeltaRounding::NearestHalfUp {
            x = (x + chain.delta_half_mod(q)) % q;
        }
        main.push(x);
    }
    let mut anchor: Vec<u64> = Vec::with_capacity(chain.anchors.len());
    for (j, &a) in chain.anchors.iter().enumerate() {
        let mut x = anchor_residues[j] % a;
        if rounding == DeltaRounding::NearestHalfUp {
            x = (x + chain.delta_half_mod(a)) % a;
        }
        anchor.push(x);
    }
    // Inverses read from `chain.drop_main_inv`/`drop_anchor_inv` -- precomputed
    // once in `RescaleChain::new`, since they depend only on the chain's
    // fixed lane structure, never on these residues. See that struct's docs.
    for (step, &k) in chain.delta_lanes.iter().enumerate() {
        let d = chain.lanes[k];
        let r_d = main[k] % d;
        for i in 0..chain.lanes.len() {
            let Some(inv) = chain.drop_main_inv[step][i] else {
                continue;
            };
            let q = chain.lanes[i];
            let diff = (main[i] + q - r_d % q) % q;
            main[i] = mul_mod(diff, inv, q);
        }
        for (j, &a) in chain.anchors.iter().enumerate() {
            let inv = chain.drop_anchor_inv[step][j];
            let diff = (anchor[j] + a - r_d % a) % a;
            anchor[j] = mul_mod(diff, inv, a);
        }
    }
    let surviving: Vec<u64> = chain.surviving_idx.iter().map(|&i| main[i]).collect();
    Ok((surviving, anchor))
}

pub fn exact_delta_rescale(
    chain: &RescaleChain,
    main_residues: &[u64],
    anchor_residues: &[u64],
    rounding: DeltaRounding,
    exit: RescaleExit<'_>,
) -> Nine65Result<RescaleOutput> {
    if main_residues.len() != chain.lanes.len() {
        return Err(Nine65Error::InvalidParameter {
            message: format!(
                "unified_rescale: {} main residues for {} lanes",
                main_residues.len(),
                chain.lanes.len()
            ),
        });
    }
    if anchor_residues.len() != chain.anchors.len() {
        return Err(Nine65Error::InvalidParameter {
            message: format!(
                "unified_rescale: {} anchor residues for {} anchors",
                anchor_residues.len(),
                chain.anchors.len()
            ),
        });
    }

    // ── step 1: the rounding offset, in residue form ─────────────────
    //
    // The one and only rounding in the whole pipeline, and it is the caller's
    // explicit choice. ⌊Δ/2⌋ is obtained per lane without forming Δ.
    let mut main: Vec<u64> = Vec::with_capacity(chain.lanes.len());
    for (i, &q) in chain.lanes.iter().enumerate() {
        let mut x = main_residues[i] % q;
        if rounding == DeltaRounding::NearestHalfUp {
            x = (x + chain.delta_half_mod(q)) % q;
        }
        main.push(x);
    }
    let mut anchor: Vec<u64> = Vec::with_capacity(chain.anchors.len());
    for (j, &a) in chain.anchors.iter().enumerate() {
        let mut x = anchor_residues[j] % a;
        if rounding == DeltaRounding::NearestHalfUp {
            x = (x + chain.delta_half_mod(a)) % a;
        }
        anchor.push(x);
    }

    // ── step 2: align-and-drop every Δ-lane in turn ──────────────────
    //
    // Each drop computes ⌊V/d⌋ exactly:  v_i' = (v_i − r_d)·d⁻¹ (mod q_i).
    // ⌊⌊V/d₀⌋/d₁⌋ = ⌊V/(d₀d₁)⌋, so the composition divides by Δ exactly.
    // This is the step that would round under a hunted chain, where Δ is not
    // a product of lanes at all.
    // Inverses read from `chain.drop_main_inv`/`drop_anchor_inv` -- precomputed
    // once in `RescaleChain::new`, since they depend only on the chain's
    // fixed lane structure, never on these residues. See that struct's docs.
    for (step, &k) in chain.delta_lanes.iter().enumerate() {
        let d = chain.lanes[k];
        let r_d = main[k] % d;
        for i in 0..chain.lanes.len() {
            let Some(inv) = chain.drop_main_inv[step][i] else {
                continue;
            };
            let q = chain.lanes[i];
            let diff = (main[i] + q - r_d % q) % q;
            main[i] = mul_mod(diff, inv, q);
        }
        for (j, &a) in chain.anchors.iter().enumerate() {
            let inv = chain.drop_anchor_inv[step][j];
            let diff = (anchor[j] + a - r_d % a) % a;
            anchor[j] = mul_mod(diff, inv, a);
        }
    }
    let surviving_residues: Vec<u64> = chain.surviving_idx.iter().map(|&i| main[i]).collect();

    // ── step 3: K-Elimination winding read ──────────────────────────
    //
    // γ = Y mod t from the surviving lanes; K = ⌊Y/t⌋ from the anchors via
    // K ≡ (Y − γ)·t⁻¹ (mod a_j). Together they give Y = γ + K·t exactly,
    // without ever forming Y in the residue domain.
    // R8 parallel summation, not a Garner cascade: the winding read is a
    // boundary materialization and must not smuggle R9 into the runtime.
    let (gamma, m_prod) = parallel_summation_crt(
        &surviving_residues,
        &chain.surviving_lanes,
        Some(&chain.gamma_merge_inv),
    )?;
    debug_assert_eq!(m_prod, chain.surviving_product());
    let winding_k = if chain.anchors.is_empty() {
        U256::zero()
    } else {
        // `chain.winding_anchor_inv[j]` is the precomputed inverse of
        // `t mod a` -- `m_prod` is always `chain.surviving_product() == t`
        // (the debug_assert above), so this is the same value the original
        // per-coefficient `mod_inverse_checked(m_mod_a, a)` computed, read
        // instead of recomputed.
        let mut k_res: Vec<u64> = Vec::with_capacity(chain.anchors.len());
        for (j, &a) in chain.anchors.iter().enumerate() {
            let inv = chain.winding_anchor_inv[j];
            let g_mod_a = (gamma % a as u128) as u64;
            let diff = (anchor[j] + a - g_mod_a) % a;
            k_res.push(mul_mod(diff, inv, a));
        }
        // The ladder merge, likewise R8 — "must not be silently substituted
        // with a runtime Garner cascade" (lift inventory, ladder policy).
        parallel_summation_crt_u256(&k_res, &chain.anchors, Some(&chain.winding_merge_inv))?.0
    };

    // ── step 4: the exit ────────────────────────────────────────────
    let target_residues = match exit {
        RescaleExit::ModulusReduced => Vec::new(),
        RescaleExit::Reraise { target_lanes } => {
            let mut out = Vec::with_capacity(target_lanes.len());
            for &a in target_lanes {
                // K is reduced modulo the target first; universal projection
                // only ever uses `K mod A`, so this is the identical value
                // with no u128 truncation.
                out.push(universal_project(gamma, winding_k.mod_u64(a) as u128, m_prod, a)?);
            }
            out
        }
    };

    // ── the balanced lift ───────────────────────────────────────────
    //
    // `parallel_summation_crt_u256` reduces into `[0, C)`, which erases the
    // sign of a negative winding. Recover it about `C/2` — the identical
    // convention `SignedK256::from_unsigned` uses on the materializing path.
    // This is a read of a value that function already returned, not a second
    // reconstruction: no CRT, no Garner, three U256 ops.
    let (winding_k_neg, winding_k_mag) = if chain.anchors.is_empty() {
        (false, U256::zero())
    } else {
        let half = chain.anchor_product.shr1();
        if winding_k.gt(half) {
            (true, chain.anchor_product.sub(winding_k))
        } else {
            (false, winding_k)
        }
    };

    Ok(RescaleOutput {
        surviving_residues,
        anchor_residues: anchor,
        gamma,
        winding_k,
        winding_k_neg,
        winding_k_mag,
        target_residues,
    })
}

// ═══════════════════════════════════════════════════════════════════
#[cfg(test)]
mod tests {
    use super::*;

    /// Pins `RescaleChain::new`'s precomputed inverse tables against fresh
    /// `mod_inverse_checked` calls computed independently here, on the real
    /// manufactured chain. Regression guard for the 2026-08-30 fix: these
    /// tables replaced 16,384 redundant extended-Euclid calls per rescale
    /// (32/coefficient, all chain-derived, none coefficient-derived) with 32
    /// computed once — if a future edit desyncs the tables from what the
    /// hot-path loops actually need, this catches it as a wrong VALUE, not
    /// just a slow one.
    #[test]
    fn precomputed_inverses_match_fresh_computation_on_the_real_chain() {
        let lanes = [65_537u64, 738_208_769, 1_409_307_649, 2_617_285_633];
        let delta_idx = [1usize, 2, 3];
        let anchors = [
            2_013_265_921u64,
            2_281_701_377,
            2_483_027_969,
            2_885_681_153,
            3_221_225_473,
        ];
        let chain = RescaleChain::new(&lanes, &delta_idx, 65_537, &anchors).unwrap();

        let mut alive = vec![true; lanes.len()];
        for (step, &k) in chain.delta_lanes.iter().enumerate() {
            let d = lanes[k];
            for i in 0..lanes.len() {
                let expected = if i == k || !alive[i] {
                    None
                } else {
                    Some(mod_inverse_checked(d % lanes[i], lanes[i]).unwrap())
                };
                assert_eq!(
                    chain.drop_main_inv[step][i], expected,
                    "drop_main_inv mismatch at step {step}, lane {i}"
                );
            }
            for (j, &a) in anchors.iter().enumerate() {
                let expected = mod_inverse_checked(d % a, a).unwrap();
                assert_eq!(
                    chain.drop_anchor_inv[step][j], expected,
                    "drop_anchor_inv mismatch at step {step}, anchor {j}"
                );
            }
            alive[k] = false;
        }
        for (j, &a) in anchors.iter().enumerate() {
            let expected = mod_inverse_checked(65_537u64 % a, a).unwrap();
            assert_eq!(
                chain.winding_anchor_inv[j], expected,
                "winding_anchor_inv mismatch at anchor {j}"
            );
        }
    }

    /// Same regression class, for the SECOND instance of the bug: the
    /// `(M_i)^-1 mod m_i` cofactor inverses `parallel_summation_crt` /
    /// `parallel_summation_crt_u256` need for their basis merge, which are
    /// likewise chain-fixed (depend on `surviving_lanes`/`anchors` alone).
    /// Pins `gamma_merge_inv` and `winding_merge_inv` against inverses
    /// computed independently here, over both the real manufactured chain
    /// (single surviving lane, exercising the trivial-cofactor case since
    /// `M_i = M_prod` when there is only one lane) and a multi-lane
    /// synthetic basis (`small_chain`, three anchors — no chain in this
    /// module's own fixtures has more than one surviving lane, so a
    /// standalone multi-element merge is checked directly below instead of
    /// only through the single-lane chains).
    #[test]
    fn merge_inverses_match_fresh_computation() {
        let lanes = [65_537u64, 738_208_769, 1_409_307_649, 2_617_285_633];
        let delta_idx = [1usize, 2, 3];
        let anchors = [
            2_013_265_921u64,
            2_281_701_377,
            2_483_027_969,
            2_885_681_153,
            3_221_225_473,
        ];
        let chain = RescaleChain::new(&lanes, &delta_idx, 65_537, &anchors).unwrap();

        // Single surviving lane (t = 65537 itself): M_i = M_prod / t = 1,
        // so the cofactor inverse is trivially 1 -- still computed via the
        // real path here, not asserted from the mathematical shortcut.
        assert_eq!(chain.surviving_lanes.len(), 1);
        let m_prod: u128 = chain.surviving_lanes[0] as u128;
        for (idx, &m) in chain.surviving_lanes.iter().enumerate() {
            let mi = m_prod / m as u128;
            let expected = mod_inverse_checked((mi % m as u128) as u64, m).unwrap();
            assert_eq!(chain.gamma_merge_inv[idx], expected, "gamma_merge_inv[{idx}]");
        }
        for (idx, &a) in anchors.iter().enumerate() {
            let mut mi = U256::from_u64(1);
            for (j, &aj) in anchors.iter().enumerate() {
                if j != idx {
                    mi = mi.mul_u64(aj);
                }
            }
            let expected = mod_inverse_checked(mi.mod_u64(a), a).unwrap();
            assert_eq!(chain.winding_merge_inv[idx], expected, "winding_merge_inv[{idx}]");
        }

        // The multi-lane case, standalone: `parallel_summation_crt` and its
        // U256 sibling agree with `None` (fresh) vs an explicitly supplied
        // table over a basis with more than one modulus, so the trivial
        // single-lane case above isn't the only shape exercised.
        let mods = [7u64, 11, 13, 17];
        let residues = [3u64, 5, 9, 2];
        let m_prod_multi: u128 = mods.iter().map(|&m| m as u128).product();
        let table: Vec<u64> = mods
            .iter()
            .map(|&m| {
                let mi = m_prod_multi / m as u128;
                mod_inverse_checked((mi % m as u128) as u64, m).unwrap()
            })
            .collect();
        let fresh = parallel_summation_crt(&residues, &mods, None).unwrap();
        let cached = parallel_summation_crt(&residues, &mods, Some(&table)).unwrap();
        assert_eq!(fresh, cached, "parallel_summation_crt: fresh vs precomputed must agree");

        let fresh_u256 = parallel_summation_crt_u256(&residues, &mods, None).unwrap();
        let cached_u256 = parallel_summation_crt_u256(&residues, &mods, Some(&table)).unwrap();
        assert_eq!(
            fresh_u256, cached_u256,
            "parallel_summation_crt_u256: fresh vs precomputed must agree"
        );
    }

    /// `round(a/b)` with ties up, integer-only. Ground-truth helper.
    fn round_half_up(a: u128, b: u128) -> u128 {
        (2 * a + b) / (2 * b)
    }

    /// A star-family manufactured chain: `t = 6`, lanes `6 · 7 · 13`.
    /// `7 = 1·6 + 1` and `13 = 2·6 + 1` are star lanes (`q = c·t + 1`).
    /// `Q = 546`, `Δ = 91`, anchors `5 · 11 = 55`.
    fn small_chain() -> RescaleChain {
        RescaleChain::new(&[6, 7, 13], &[1, 2], 6, &[5, 11]).unwrap()
    }

    /// Composite everywhere: `t = 12` (composite), lanes `12 · 61 · 85`,
    /// where `61 = 5·12 + 1` and `85 = 7·12 + 1 = 5·17` is a **composite**
    /// star lane. `Q = 62220`, `Δ = 5185`, anchors `7 · 11 = 77`.
    fn composite_chain() -> RescaleChain {
        RescaleChain::new(&[12, 61, 85], &[1, 2], 12, &[7, 11]).unwrap()
    }

    // ── construction invariants ──────────────────────────────────────

    #[test]
    fn manufactured_chain_has_exact_delta_and_zero_residual() {
        for c in [small_chain(), composite_chain()] {
            let q = c.try_q_u128().unwrap();
            let d = c.try_delta_u128().unwrap();
            // Δ = Q/t EXACTLY: no floor, no residual.
            assert_eq!(q % c.t() as u128, 0, "t must divide Q");
            assert_eq!(q / c.t() as u128, d, "Δ must equal Q/t exactly");
            assert_eq!(c.residual_q_mod_t(), 0, "residual must be zero");
            assert_eq!(c.surviving_product(), c.t() as u128);
        }
    }

    #[test]
    fn delta_half_mod_matches_direct_halving() {
        // The residue-only offset must agree with ⌊Δ/2⌋ mod m computed the
        // obvious way — including for even m, where 2 is not invertible.
        for c in [small_chain(), composite_chain()] {
            let d = c.try_delta_u128().unwrap();
            let half = d / 2;
            for m in 2u64..400 {
                assert_eq!(
                    c.delta_half_mod(m) as u128,
                    half % m as u128,
                    "⌊Δ/2⌋ mod {m} mismatch (Δ={d})"
                );
                assert_eq!(c.delta_mod(m) as u128, d % m as u128, "Δ mod {m} mismatch");
            }
        }
    }

    // ── the refusals (item 4: the safety property) ────────────────────

    #[test]
    fn refuses_hunted_chain_where_t_does_not_divide_q() {
        // A genuinely hunted chain: 769 = 3·256+1 and 3329 = 13·256+1 are both
        // prime and NTT-friendly for N=128; t = 257 is prime and coprime to
        // both. Q = 2_560_001, and 2_560_001 mod 257 = 24 ≠ 0.
        let err = RescaleChain::new(&[769, 3329], &[0], 257, &[5, 11]).unwrap_err();
        match err {
            Nine65Error::InexactDivision { value, divisor } => {
                assert_eq!(value, 769u128 * 3329);
                assert_eq!(divisor, 257);
                assert_ne!(value % divisor as u128, 0);
            }
            other => panic!("expected InexactDivision, got {other:?}"),
        }
    }

    #[test]
    fn refuses_when_delta_is_not_a_product_of_lanes() {
        // t | Q here (Q = 546, t = 6), but the caller nominates only lane 1,
        // so the retained lanes multiply to 78, not 6. Align-and-drop divides
        // by lanes, so this cannot be executed exactly and is refused.
        let err = RescaleChain::new(&[6, 7, 13], &[1], 6, &[5, 11]).unwrap_err();
        assert!(
            matches!(err, Nine65Error::InvalidParameter { .. }),
            "expected InvalidParameter, got {err:?}"
        );
        let msg = format!("{err}");
        assert!(msg.contains("78"), "message should name the actual product: {msg}");
    }

    #[test]
    fn refuses_non_invertible_drop_lane() {
        // Δ-lane 14 shares the factor 7 with lane 7, so (x − r)·14⁻¹ mod 7 does
        // not exist. The division boundary genuinely needs coprimality even
        // though the projection boundary does not.
        let err = RescaleChain::new(&[6, 14, 7], &[1, 2], 6, &[5, 11]).unwrap_err();
        assert!(
            matches!(err, Nine65Error::NotCoprime { .. }),
            "expected NotCoprime, got {err:?}"
        );
    }

    #[test]
    fn refuses_target_lane_below_two() {
        let c = small_chain();
        let x = 1234u128;
        let main: Vec<u64> = c.lanes().iter().map(|&q| (x % q as u128) as u64).collect();
        let anc: Vec<u64> = c.anchors().iter().map(|&a| (x % a as u128) as u64).collect();
        let err = exact_delta_rescale(
            &c,
            &main,
            &anc,
            DeltaRounding::NearestHalfUp,
            RescaleExit::Reraise { target_lanes: &[1] },
        )
        .unwrap_err();
        assert!(matches!(err, Nine65Error::InvalidParameter { .. }), "{err:?}");
    }

    #[test]
    fn refuses_residue_shape_mismatch() {
        let c = small_chain();
        let err = exact_delta_rescale(
            &c,
            &[0, 0],
            &[0, 0],
            DeltaRounding::Floor,
            RescaleExit::ModulusReduced,
        )
        .unwrap_err();
        assert!(matches!(err, Nine65Error::InvalidParameter { .. }), "{err:?}");
    }

    // ── item 3: THE DECISIVE TEST ────────────────────────────────────

    /// Exhaustive differential against exact integer arithmetic over the
    /// **entire** representable range of the manufactured chain.
    ///
    /// Ground truth is computed directly in `u128`, two independent ways:
    /// `⌊(X + ⌊Δ/2⌋)/Δ⌋` and `round(X·t/Q)`. They must agree with each other
    /// (that is the exact-Δ identity `Q = t·Δ` in action) and with the kernel,
    /// on every single value. Exact equality, not "within 1".
    #[test]
    fn decisive_exhaustive_exact_over_full_range_small() {
        let c = small_chain();
        let q = c.try_q_u128().unwrap(); // 546
        let d = c.try_delta_u128().unwrap(); // 91
        let a = c.anchor_product_u128().unwrap(); // 55
        let t = c.t() as u128; // 6
        let off = d / 2;
        let limit = q * a - off; // full dual range minus offset headroom
        let targets: Vec<u64> = vec![6, 7, 13, 5, 11, 546, 64, 100, 3, 2];

        let mut checked = 0u64;
        let mut max_k = 0u128;
        for x in 0..limit {
            let main: Vec<u64> = c.lanes().iter().map(|&m| (x % m as u128) as u64).collect();
            let anc: Vec<u64> = c.anchors().iter().map(|&m| (x % m as u128) as u64).collect();
            let out = exact_delta_rescale(
                &c,
                &main,
                &anc,
                DeltaRounding::NearestHalfUp,
                RescaleExit::Reraise { target_lanes: &targets },
            )
            .unwrap();

            let truth_floor_offset = (x + off) / d;
            let truth_bfv = round_half_up(x * t, q);
            assert_eq!(
                truth_floor_offset, truth_bfv,
                "exact-Δ identity broken at x={x}: ⌊(X+⌊Δ/2⌋)/Δ⌋ != round(X·t/Q)"
            );

            let y = out.reconstruct(&c).unwrap();
            assert_eq!(y, truth_bfv, "kernel != round(X·t/Q) at x={x}");
            assert_eq!(out.gamma, y % t, "γ wrong at x={x}");
            assert_eq!(out.winding_k_u128().unwrap(), y / t, "winding K wrong at x={x}");
            for (i, &tg) in targets.iter().enumerate() {
                assert_eq!(
                    out.target_residues[i] as u128,
                    y % tg as u128,
                    "projection onto {tg} wrong at x={x}"
                );
            }
            max_k = max_k.max(out.winding_k_u128().unwrap());
            checked += 1;
        }
        assert_eq!(checked, limit as u64);
        assert_eq!(checked, 29_985, "expected the full dual range");
        assert_eq!(max_k, a - 1, "winding read must exercise the full anchor range");
        println!(
            "EXACT-Δ small chain (t=6, Q=546, Δ=91, A=55): {checked} values, \
             0 rounding error, max winding K = {max_k}"
        );
    }

    /// Same differential on a chain that is composite in every position:
    /// composite `t`, a composite star lane, and a composite `Δ`.
    #[test]
    fn decisive_exhaustive_exact_over_full_range_composite() {
        let c = composite_chain();
        let q = c.try_q_u128().unwrap(); // 62220
        let d = c.try_delta_u128().unwrap(); // 5185
        let a = c.anchor_product_u128().unwrap(); // 77
        let t = c.t() as u128; // 12
        let off = d / 2;
        let limit = q * a - off;
        let targets: Vec<u64> = vec![12, 61, 85, 62220, 2, 1024, 255, 77];

        let mut checked = 0u64;
        for x in 0..limit {
            let main: Vec<u64> = c.lanes().iter().map(|&m| (x % m as u128) as u64).collect();
            let anc: Vec<u64> = c.anchors().iter().map(|&m| (x % m as u128) as u64).collect();
            let out = exact_delta_rescale(
                &c,
                &main,
                &anc,
                DeltaRounding::NearestHalfUp,
                RescaleExit::Reraise { target_lanes: &targets },
            )
            .unwrap();
            let truth = round_half_up(x * t, q);
            assert_eq!((x + off) / d, truth, "exact-Δ identity broken at x={x}");
            assert_eq!(out.reconstruct(&c).unwrap(), truth, "kernel != truth at x={x}");
            for (i, &tg) in targets.iter().enumerate() {
                assert_eq!(out.target_residues[i] as u128, truth % tg as u128, "x={x} tgt={tg}");
            }
            checked += 1;
        }
        assert_eq!(checked, 4_790_940 - (5185 / 2) as u64);
        println!(
            "EXACT-Δ composite chain (t=12, Q=62220, Δ=5185, A=77): {checked} values, \
             0 rounding error"
        );
    }

    /// The contrast. A hunted chain has `t ∤ Q`, so `Δ = ⌊Q/t⌋` carries a
    /// nonzero residual, and dividing by it is **not** the same map as
    /// `round(X·t/Q)`. Measured exhaustively over the full range of the hunted
    /// modulus. This is the evidence that manufacturing — not the code — is
    /// what buys exactness.
    ///
    /// Scope note: this measures only the *definitional* `⌊Q/t⌋` term. The
    /// shipped `ops/rns_fhe.rs::exact_rescale` adds a further per-lane
    /// Bajard-style `+ q_i/2` rounding on top of it, which is not modelled here.
    #[test]
    fn hunted_chain_classical_divisor_carries_a_nonzero_rounding_term() {
        let t: u128 = 257;
        let q: u128 = 769 * 3329; // 2_560_001, both lanes prime and ≡1 mod 256
        let residual = q % t;
        assert_ne!(residual, 0, "hunted chain must not divide");
        assert_eq!(residual, 24);
        let delta_hunted = q / t; // ⌊Q/t⌋ — the classical BFV divisor
        assert_ne!(delta_hunted * t, q, "⌊Q/t⌋·t != Q — that gap is the rounding term");

        let mut mismatches: u64 = 0;
        let mut max_dev: u128 = 0;
        for x in 0..q {
            let classical = round_half_up(x, delta_hunted); // round(X/⌊Q/t⌋)
            let truth = round_half_up(x * t, q); // round(X·t/Q)
            let dev = classical.abs_diff(truth);
            if dev != 0 {
                mismatches += 1;
            }
            max_dev = max_dev.max(dev);
        }

        // Manufactured chains: exhaustively zero (the two tests above).
        // Hunted chain: nonzero, measured here.
        assert!(mismatches > 0, "the classical divisor must deviate somewhere");
        assert_eq!(max_dev, 1);
        assert_eq!(mismatches, 3_084, "measured constant; exhaustive and deterministic");
        println!(
            "CONTRAST hunted (t=257, Q=769·3329=2560001): Q mod t = {residual} (nonzero), \
             round(X/⌊Q/t⌋) != round(X·t/Q) on {mismatches}/{q} values \
             ({} per 100000), max deviation {max_dev}.  \
             Manufactured chains above: 0/29985 and 0/4788348, max deviation 0.",
            mismatches as u128 * 100_000 / q
        );

        // And the kernel refuses this chain outright rather than rounding.
        assert!(matches!(
            RescaleChain::new(&[769, 3329], &[0], 257, &[5, 11]).unwrap_err(),
            Nine65Error::InexactDivision { .. }
        ));
    }

    // ── item 2: two exits, one primitive ─────────────────────────────

    #[test]
    fn two_exits_are_one_primitive() {
        let c = small_chain();
        let q = c.try_q_u128().unwrap();
        let a = c.anchor_product_u128().unwrap();
        let d = c.try_delta_u128().unwrap();
        let targets: Vec<u64> = vec![6, 7, 13, 546, 40];
        let mut n = 0u64;
        for x in (0..(q * a - d / 2)).step_by(7) {
            let main: Vec<u64> = c.lanes().iter().map(|&m| (x % m as u128) as u64).collect();
            let anc: Vec<u64> = c.anchors().iter().map(|&m| (x % m as u128) as u64).collect();
            let bgv = exact_delta_rescale(
                &c,
                &main,
                &anc,
                DeltaRounding::NearestHalfUp,
                RescaleExit::ModulusReduced,
            )
            .unwrap();
            let bfv = exact_delta_rescale(
                &c,
                &main,
                &anc,
                DeltaRounding::NearestHalfUp,
                RescaleExit::Reraise { target_lanes: &targets },
            )
            .unwrap();

            // Everything up to the exit is bit-identical.
            assert_eq!(bgv.surviving_residues, bfv.surviving_residues);
            assert_eq!(bgv.anchor_residues, bfv.anchor_residues);
            assert_eq!(bgv.gamma, bfv.gamma);
            assert_eq!(bgv.winding_k, bfv.winding_k);
            assert!(bgv.target_residues.is_empty());

            // The reduced-modulus exit holds Y mod t; the re-raised exit holds
            // the same Y on arbitrary lanes. One value, two representations.
            let y = bfv.reconstruct(&c).unwrap();
            let (g, m) = garner(&bgv.surviving_residues, c.surviving_lanes()).unwrap();
            assert_eq!(m, c.t() as u128, "reduced modulus is Q/Δ = t");
            assert_eq!(g, y % c.t() as u128);
            for (i, &tg) in targets.iter().enumerate() {
                assert_eq!(bfv.target_residues[i] as u128, y % tg as u128);
            }
            n += 1;
        }
        println!("TWO EXITS agree on {n} values; they differ only in the re-raise step");
    }

    // ── item 1 detail: floor mode ────────────────────────────────────

    #[test]
    fn floor_mode_is_exact_floor_division() {
        let c = composite_chain();
        let q = c.try_q_u128().unwrap();
        let a = c.anchor_product_u128().unwrap();
        let d = c.try_delta_u128().unwrap();
        let mut n = 0u64;
        for x in (0..(q * a)).step_by(13) {
            let main: Vec<u64> = c.lanes().iter().map(|&m| (x % m as u128) as u64).collect();
            let anc: Vec<u64> = c.anchors().iter().map(|&m| (x % m as u128) as u64).collect();
            let out = exact_delta_rescale(
                &c,
                &main,
                &anc,
                DeltaRounding::Floor,
                RescaleExit::Reraise { target_lanes: &[61] },
            )
            .unwrap();
            assert_eq!(out.reconstruct(&c).unwrap(), x / d, "⌊X/Δ⌋ wrong at x={x}");
            assert_eq!(out.target_residues[0] as u128, (x / d) % 61);
            n += 1;
        }
        println!("FLOOR mode exact on {n} values");
    }

    // ── universal projection: no preconditions ───────────────────────

    #[test]
    fn universal_projection_needs_no_coprimality_or_primality() {
        // Targets deliberately hostile: even, powers of two, composite,
        // repeated, equal to chain lanes, sharing factors with M.
        let c = composite_chain(); // t = 12, so M = 12 shares 2 and 3 freely
        let targets: Vec<u64> = vec![2, 3, 4, 6, 8, 12, 12, 16, 1024, 85, 61, 62220, 9, 15, 100];
        let q = c.try_q_u128().unwrap();
        let a = c.anchor_product_u128().unwrap();
        let d = c.try_delta_u128().unwrap();
        let mut n = 0u64;
        for x in (0..(q * a - d / 2)).step_by(11) {
            let main: Vec<u64> = c.lanes().iter().map(|&m| (x % m as u128) as u64).collect();
            let anc: Vec<u64> = c.anchors().iter().map(|&m| (x % m as u128) as u64).collect();
            let out = exact_delta_rescale(
                &c,
                &main,
                &anc,
                DeltaRounding::NearestHalfUp,
                RescaleExit::Reraise { target_lanes: &targets },
            )
            .unwrap();
            let y = out.reconstruct(&c).unwrap();
            for (i, &tg) in targets.iter().enumerate() {
                assert_eq!(
                    out.target_residues[i] as u128,
                    y % tg as u128,
                    "projection onto hostile target {tg} failed at x={x}"
                );
            }
            n += 1;
        }
        println!("UNIVERSAL PROJECTION exact on {n} values × {} hostile targets", targets.len());
    }

    #[test]
    fn universal_project_matches_direct_reduction_standalone() {
        // A3 in isolation, on unfiltered moduli.
        let mut bad = 0;
        let mut total = 0u64;
        for m in 2u128..60 {
            for k in 0u128..40 {
                for g in 0..m {
                    let x = g + k * m;
                    for a in 2u64..70 {
                        total += 1;
                        if universal_project(g, k, m, a).unwrap() as u128 != x % a as u128 {
                            bad += 1;
                        }
                    }
                }
            }
        }
        assert_eq!(bad, 0, "universal projection failed on {bad}/{total}");
        println!("A3 universal projection: {total}/{total} hold on unfiltered moduli");
    }

    // ── corrected U3 ─────────────────────────────────────────────────

    #[test]
    fn adjacency_read_is_minus_not_plus() {
        // A = P + 1 ⇒ P ≡ −1 (mod A) ⇒ X = γ + K·P ≡ γ − K (mod A).
        let mut published_holds = 0u32;
        let mut corrected_holds = 0u32;
        let mut total = 0u32;
        for p in 2u128..50 {
            let a = p + 1;
            for k in 0u128..30 {
                for g in 0..p {
                    let x = g + k * p;
                    total += 1;
                    if (g + k) % a == x % a {
                        published_holds += 1;
                    }
                    if adjacency_project(g, k, p).unwrap() as u128 == x % a {
                        corrected_holds += 1;
                    }
                }
            }
        }
        assert_eq!(corrected_holds, total, "corrected (γ − K) must always hold");
        assert!(
            published_holds < total,
            "the published (γ + K) form must be observed failing"
        );
        println!(
            "U3 adjacency: published (γ+K) holds {published_holds}/{total}; \
             corrected (γ−K) holds {corrected_holds}/{total}"
        );
        // P⁻¹ mod A = P, self-inverse, no egcd (corrected U6).
        for p in 2u64..500 {
            let a = p + 1;
            assert_eq!(mul_mod(p, p, a), 1 % a, "P·P ≢ 1 mod A for P={p}");
        }
    }

    #[test]
    fn adjacency_agrees_with_universal_projection_on_the_chain() {
        let c = small_chain();
        let q = c.try_q_u128().unwrap();
        let a = c.anchor_product_u128().unwrap();
        let d = c.try_delta_u128().unwrap();
        let anchor_mod = c.surviving_product() as u64 + 1; // A = t + 1 = 7
        let mut n = 0u64;
        for x in (0..(q * a - d / 2)).step_by(3) {
            let main: Vec<u64> = c.lanes().iter().map(|&m| (x % m as u128) as u64).collect();
            let anc: Vec<u64> = c.anchors().iter().map(|&m| (x % m as u128) as u64).collect();
            let out = exact_delta_rescale(
                &c,
                &main,
                &anc,
                DeltaRounding::NearestHalfUp,
                RescaleExit::Reraise { target_lanes: &[anchor_mod] },
            )
            .unwrap();
            let fast =
                adjacency_project(out.gamma, out.winding_k_u128().unwrap(), c.surviving_product())
                    .unwrap();
            assert_eq!(fast, out.target_residues[0], "adjacency fast path disagrees at x={x}");
            n += 1;
        }
        println!("ADJACENCY fast path agrees with A3 on {n} values");
    }

    // ── degenerate: no anchors ───────────────────────────────────────

    #[test]
    fn no_anchor_chain_has_zero_winding() {
        let c = RescaleChain::new(&[6, 7, 13], &[1, 2], 6, &[]).unwrap();
        let q = c.try_q_u128().unwrap();
        let d = c.try_delta_u128().unwrap();
        for x in 0..(q - d / 2) {
            let main: Vec<u64> = c.lanes().iter().map(|&m| (x % m as u128) as u64).collect();
            let out = exact_delta_rescale(
                &c,
                &main,
                &[],
                DeltaRounding::NearestHalfUp,
                RescaleExit::Reraise { target_lanes: &[6, 7] },
            )
            .unwrap();
            let truth = (x + d / 2) / d;
            assert!(truth < c.t() as u128, "range precondition");
            assert_eq!(out.winding_k_u128().unwrap(), 0);
            assert_eq!(out.reconstruct(&c).unwrap(), truth, "x={x}");
        }
    }

    // ── star family, used as construction rather than search ─────────

    #[test]
    fn star_lanes_give_message_transparency_and_the_inverse_by_construction() {
        // q = c·t + 1 ⇒ q ≡ 1 (mod t) and t⁻¹ mod q = q − c, for composite
        // c and composite t alike.
        for t in 2u64..40 {
            for cc in 1u64..40 {
                let q = cc * t + 1;
                assert_eq!(q % t, 1 % t, "star lane not ≡1 mod t");
                assert_eq!(mul_mod(t % q, q - cc, q), 1 % q, "t⁻¹ != q − c");
            }
        }
        // And the chains above are built from star lanes.
        let c = composite_chain();
        for &i in c.delta_lane_indices() {
            assert_eq!(c.lanes()[i] % c.t(), 1, "Δ-lane must be a star lane");
        }
    }
    // ═══════════════════════════════════════════════════════════════
    // THE HEADLINE MEASUREMENT
    // ═══════════════════════════════════════════════════════════════

    /// End-to-end: manufactured `Q = t·Δ` rescales with **zero** error, while
    /// the classical `⌊Q/t⌋` divisor on a hunted chain carries a **nonzero**
    /// rounding term. Both sides measured exhaustively against integer ground
    /// truth computed directly in `u128` from the raw input.
    ///
    /// This is the single claim the manufactured-moduli build exists to make,
    /// so it is measured rather than asserted, and it prints its own numbers.
    ///
    /// Scope note, stated so the number is not over-read: the hunted side
    /// measures the *definitional* `⌊Q/t⌋` term only. The shipped
    /// `ops/rns_fhe.rs::exact_rescale` layers a further per-lane Bajard-style
    /// `+ q_i/2` rounding on top of it, which is not modelled here — so the
    /// hunted error measured below is a **lower bound** on the classical
    /// route's total rounding, not the whole of it.
    #[test]
    fn headline_manufactured_is_exact_and_hunted_is_not() {
        println!("\n╔══════════════════════════════════════════════════════════════════╗");
        println!("║  HEADLINE: exact-Δ rescale vs classical ⌊Q/t⌋ rescale             ║");
        println!("╚══════════════════════════════════════════════════════════════════╝");

        // ── MANUFACTURED SIDE ────────────────────────────────────────
        // Ground truth: round(X·t/Q), computed directly in u128 from X.
        // Error is counted, never asserted away.
        let mut manufactured_rows: Vec<(String, u64, u64, u128)> = Vec::new();

        for (label, c) in [
            ("t=6  (prime lanes)   Q=546   Δ=91  ", small_chain()),
            ("t=12 (composite all) Q=62220 Δ=5185", composite_chain()),
        ] {
            let q = c.try_q_u128().unwrap();
            let d = c.try_delta_u128().unwrap();
            let a = c.anchor_product_u128().unwrap();
            let t = c.t() as u128;

            // Δ = Q/t EXACTLY. This is the premise the whole result rests on.
            assert_eq!(q % t, 0, "manufactured chain must have t | Q");
            assert_eq!(d, q / t, "Δ must equal Q/t with no floor");
            assert_eq!(c.residual_q_mod_t(), 0, "residual must be exactly zero");

            let off = d / 2;
            let limit = q * a - off;
            let mut errors: u64 = 0;
            let mut max_dev: u128 = 0;
            let mut checked: u64 = 0;

            for x in 0..limit {
                let main: Vec<u64> =
                    c.lanes().iter().map(|&m| (x % m as u128) as u64).collect();
                let anc: Vec<u64> =
                    c.anchors().iter().map(|&m| (x % m as u128) as u64).collect();
                let out = exact_delta_rescale(
                    &c,
                    &main,
                    &anc,
                    DeltaRounding::NearestHalfUp,
                    RescaleExit::ModulusReduced,
                )
                .expect("manufactured chain must rescale");

                let y = out.reconstruct(&c).unwrap();
                let truth = round_half_up(x * t, q); // round(X·t/Q), from raw X
                let dev = y.abs_diff(truth);
                if dev != 0 {
                    errors += 1;
                }
                max_dev = max_dev.max(dev);
                checked += 1;
            }

            println!(
                "  MANUFACTURED  {label}  Q mod t = {:>2}  |  {checked:>9} values exhaustive  \
                 →  rounding errors = {errors},  max deviation = {max_dev}",
                c.residual_q_mod_t()
            );
            manufactured_rows.push((label.to_string(), checked, errors, max_dev));
        }

        // ── HUNTED SIDE ──────────────────────────────────────────────
        // A genuinely hunted chain: 769 and 3329 are both prime and ≡ 1 mod 256.
        let t: u128 = 257;
        let q: u128 = 769 * 3329; // 2_560_001
        let residual = q % t; // nonzero — this is the whole difference
        let delta_hunted = q / t; // ⌊Q/t⌋ — the classical BFV divisor

        let mut hunted_errors: u64 = 0;
        let mut hunted_max_dev: u128 = 0;
        for x in 0..q {
            let classical = round_half_up(x, delta_hunted); // round(X/⌊Q/t⌋)
            let truth = round_half_up(x * t, q); // round(X·t/Q)
            let dev = classical.abs_diff(truth);
            if dev != 0 {
                hunted_errors += 1;
            }
            hunted_max_dev = hunted_max_dev.max(dev);
        }

        println!(
            "  HUNTED        t=257 (prime lanes)   Q=769·3329=2560001  Q mod t = {residual}  |  \
             {q:>9} values exhaustive  →  rounding errors = {hunted_errors}, \
             max deviation = {hunted_max_dev}"
        );
        println!(
            "                ⌊Q/t⌋ = {delta_hunted}, and ⌊Q/t⌋·t = {} ≠ Q = {q}  \
             (gap of {residual} — the rounding term)",
            delta_hunted * t
        );
        println!(
            "                error rate = {} per 100000 values",
            hunted_errors as u128 * 100_000 / q
        );

        // And the kernel does not quietly round this chain: it refuses it.
        let refusal = RescaleChain::new(&[769, 3329], &[0], 257, &[5, 11]).unwrap_err();
        println!("  REFUSAL       kernel on the hunted chain → {refusal:?}");
        println!("╚══════════════════════════════════════════════════════════════════╝\n");

        // ── THE CLAIM, ASSERTED ──────────────────────────────────────
        for (label, checked, errors, max_dev) in &manufactured_rows {
            assert_eq!(
                *errors, 0,
                "MANUFACTURED chain {label} must rescale with ZERO error, got {errors} \
                 over {checked} values"
            );
            assert_eq!(*max_dev, 0, "MANUFACTURED chain {label} max deviation must be 0");
        }
        assert_ne!(residual, 0, "the hunted chain must not divide — that is what makes it hunted");
        assert!(
            hunted_errors > 0,
            "the classical ⌊Q/t⌋ divisor must deviate from round(X·t/Q) somewhere"
        );

        // Pinned measured constants: exhaustive and deterministic, so any drift
        // is a real change rather than noise.
        assert_eq!(manufactured_rows[0].1, 29_985);
        assert_eq!(manufactured_rows[1].1, 4_788_348);
        assert_eq!(residual, 24);
        assert_eq!(hunted_errors, 3_084);
        assert_eq!(hunted_max_dev, 1);
    }

    /// The R8 parallel summation must agree with the R9 Garner ORACLE on
    /// every input — result-identical reconstruction, cascade-free
    /// implementation. Garner's licensed role is exactly this: independent
    /// test oracle, never the runtime path.
    #[test]
    fn parallel_summation_matches_garner_oracle() {
        let cases: &[&[u64]] = &[
            &[7, 11, 13],
            &[36, 37],
            &[97, 101, 103, 107],
            &[3, 5, 7, 11, 13, 17, 19],
        ];
        let mut checked = 0usize;
        for mods in cases {
            let m: u128 = mods.iter().map(|&x| x as u128).product();
            let step = (m / 257).max(1);
            let mut x: u128 = 0;
            while x < m {
                let res: Vec<u64> = mods.iter().map(|&q| (x % q as u128) as u64).collect();
                let (a, ma) = parallel_summation_crt(&res, mods, None).expect("psum");
                let (b, mb) = garner(&res, mods).expect("garner oracle");
                assert_eq!((a, ma), (b, mb), "psum vs garner at x={x} mods={mods:?}");
                assert_eq!(a, x, "reconstruction must equal ground truth");
                checked += 1;
                x += step;
            }
        }
        assert!(checked > 1000, "oracle cross-check must not go vacuous");
    }

    /// The drop-only primitive (steps 1-2, no winding read, no
    /// materialization of any kind) must agree with the full pipeline's
    /// surviving and anchor residues at every point of the exhaustive range.
    #[test]
    fn drop_only_agrees_with_full_pipeline_exhaustively() {
        // Same manufactured shape the exhaustive tests use: t=30, delta lanes
        // {7, 11, 13} -> Q = 30 * 1001, one anchor.
        let chain = RescaleChain::new(&[2, 3, 5, 7, 11, 13], &[3, 4, 5], 30, &[30031])
            .expect("manufactured chain");
        let q: u128 = chain.lanes().iter().map(|&x| x as u128).product();
        let a_prod: u128 = 30031;
        let step = 977u128; // prime stride over the full dual range
        let mut x: u128 = 0;
        let mut checked = 0usize;
        while x < q * a_prod {
            let main: Vec<u64> = chain.lanes().iter().map(|&m| (x % m as u128) as u64).collect();
            let anch: Vec<u64> = chain.anchors().iter().map(|&m| (x % m as u128) as u64).collect();
            for rounding in [DeltaRounding::Floor, DeltaRounding::NearestHalfUp] {
                let (surv, anchor_out) =
                    rescale_drop_only(&chain, &main, &anch, rounding).expect("drop only");
                let full = exact_delta_rescale(
                    &chain, &main, &anch, rounding, RescaleExit::ModulusReduced,
                )
                .expect("full pipeline");
                assert_eq!(surv, full.surviving_residues, "surviving residues at x={x}");
                assert_eq!(anchor_out, full.anchor_residues, "anchor residues at x={x}");
            }
            checked += 1;
            x += step;
        }
        assert!(checked > 10_000, "sweep must not go vacuous");
    }

    /// T2 tripwire 3 (no-Garner): the manufactured CRAM-public hot path must
    /// use `parallel_summation_crt` (R8, order-invariant, no cascade) and
    /// never `garner` (R9, sequential MRC cascade — retired from runtime,
    /// kept only as the `#[cfg(test)]` oracle above). This is enforced at
    /// COMPILE TIME already (`garner` does not exist in a release build:
    /// non-test code cannot even name it), so this test adds the runtime
    /// half — a call counter — to catch a regression that reintroduces a
    /// sequential-cascade equivalent under a different name while still
    /// calling through `garner` itself (e.g. a debug cross-check left
    /// enabled, or `garner` promoted out of `#[cfg(test)]`).
    ///
    /// Never-vacuous both directions: runs one full manufactured public
    /// multiply (tensor → 3x rescale → relinearize → fold → canonicalize)
    /// through [`crate::ops::cram_public::CramPublicEvaluator::mul_manufactured`]
    /// and asserts `garner` was called exactly 0 times, while
    /// `parallel_summation_crt` was called MORE than 0 times — so a change
    /// that stops calling `parallel_summation_crt` at all (e.g. the rescale
    /// silently short-circuiting) also fails this guardrail, not just a
    /// change that reintroduces `garner`.
    #[test]
    fn cram_public_guardrail_manufactured_multiply_never_calls_garner() {
        use crate::entropy::ShadowHarvester;
        use crate::ops::cram_public::CramPublicEvaluator;
        use crate::params::FHEConfig;

        let garner_before = call_counters::GARNER_CALLS.with(|c| c.get());
        let psum_before = call_counters::PSUM_CALLS.with(|c| c.get());

        let eval = CramPublicEvaluator::new(&FHEConfig::manufactured_m2b_insecure());
        let mut rng = ShadowHarvester::with_seed(77001);
        let (pk, client) = eval.keygen_with_rng(&mut rng);
        let mut eval = eval;
        let mut r1 = ShadowHarvester::with_seed(77002);
        let mut r2 = ShadowHarvester::with_seed(77003);
        let a = eval.encrypt_with_rng(123, &client.public_key, &mut r1);
        let b = eval.encrypt_with_rng(456, &client.public_key, &mut r2);
        let ab = eval.mul_manufactured(&a, &b, &pk).expect("manufactured multiply");
        assert_eq!(
            eval.decrypt(&ab, &client),
            123 * 456,
            "guardrail setup: the multiply itself must be correct, or this test \
             proves nothing about which reconstruction path ran"
        );

        let garner_after = call_counters::GARNER_CALLS.with(|c| c.get());
        let psum_after = call_counters::PSUM_CALLS.with(|c| c.get());

        assert_eq!(
            garner_after, garner_before,
            "REGRESSION: a manufactured public multiply called the retired \
             sequential Garner/MRC cascade (R9) — the CRAM-public hot path must \
             use parallel_summation_crt (R8) exclusively. Do not 'fix' this by \
             promoting garner out of #[cfg(test)]; investigate the call site."
        );
        assert!(
            psum_after > psum_before,
            "REGRESSION-SHAPE FAILURE: a manufactured public multiply performed \
             zero parallel_summation_crt calls — the rescale did not run the \
             reconstruction it was supposed to, so the garner_after==garner_before \
             assertion above proves nothing. Investigate why the winding read \
             stopped calling parallel_summation_crt."
        );
    }
}
