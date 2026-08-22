//! Arrow emission — the no-leak gate matrix over the REAL FHE surface.
//!
//! # Where this comes from
//!
//! `crates/exact_transcendentals/tests/arrow_emission_reversibility.rs` (and
//! its companion `arrow_emission_joint_property.rs`) establish the arrow
//! emission contract on the folded heat-stencil operator. That contract is
//! stated in terms of a small linear operator over a Safe Basis, and it is
//! four tests wide. It says three things that are NOT specific to a stencil:
//!
//! 1. A structural property is a property of the (operator, frame, lane)
//!    triple JOINTLY. It must be MEASURED and PINNED, never inferred from
//!    basis membership.
//! 2. Every lane is independent. No cascade, no cross-lane carry, exact
//!    integer arithmetic only.
//! 3. **An operation that cannot be performed exactly must REFUSE, loudly.**
//!    Reversing the lanes you can and leaving the rest desynchronised is
//!    projection, not reversal (T-X-PROJ). A silent partial answer IS the
//!    leak.
//!
//! This file carries that vocabulary onto the surface that actually handles
//! secrets: `RNSFHEContext`'s dual-RNS BFV pipeline. The matrix is
//! CONFIGS x MODES x GATES.
//!
//! ## CONFIGS (all four production tiers, 128 through 256)
//!
//! | config | N | main lanes | anchor lanes |
//! |---|---|---|---|
//! | `secure_128`      | 8192  | 3 | 5  |
//! | `secure_128_deep` | 8192  | 4 | 5  |
//! | `secure_192`      | 16384 | 5 | 10 |
//! | `secure_256`      | 16384 | 6 | 10 |
//!
//! ## MODES (both)
//!
//! * **PUBLIC** — `encrypt_dual` + `mul_dual_public` with the evaluation
//!   key. The untrusted-caller-facing mode: the evaluator never holds the
//!   secret key.
//! * **SYMMETRIC** — `mul_dual_symmetric` with the secret key. Single-party.
//!
//! ## GATES
//!
//! * **G1 WINDING DERIVABLE, NOT CARRIED** — the winding number `k` is
//!   recomputed from the residue pair `(v_main, v_anchor)` and must agree
//!   with the library's own `extract_k_rns`; and a ciphertext rebuilt from
//!   nothing but its residues must still decrypt.
//! * **G2 TRANSITION DEFECT ZERO** — `encrypt -> op -> decrypt` is exact for
//!   add and for depth-1 multiply, including the plaintext-space edges
//!   `0`, `1`, `t-1` and the `(t-1)^2` case.
//! * **G3 NO STATE COLLISIONS** — distinct plaintexts give distinct residue
//!   states; identical plaintexts under different randomness also give
//!   distinct residue states.
//! * **G4 SHARED-FACTOR CONSISTENCY (phase lock)** — the redundant anchor
//!   lanes, the ones NOT used to reconstruct `k`, must agree with the
//!   integer the main frame implies; and every residue emitted by every
//!   operation must be canonical for its lane.
//! * **G5 LIFT PRESERVED ACROSS FRAME CHANGES** — the exact align-and-drop
//!   primitive must land on `floor(X / q_k)` EXACTLY on every surviving
//!   lane, and must carry the winding across the frame change unchanged.
//! * **G6 REFUSE-NOT-PROJECT** — the direct FHE analogue of
//!   `unfold_refuses_partial_reversal_loudly`.
//! * **G7 NO SECRET LEAK IN EMISSIONS** — structural only; see that
//!   section's own caveat, which is deliberately blunt about what a
//!   structural check can and cannot establish.
//!
//! # Discipline
//!
//! Exact integer arithmetic throughout — the reference reconstruction below
//! is a little-endian `u64`-limb bignum with Garner CRT, so nothing here
//! depends on `q_product` fitting in `u128` (it does not for `secure_192`
//! at 147 bits or `secure_256` at 177 bits). No floats anywhere. Every
//! per-lane check is independent of every other lane.

use std::collections::HashSet;
use std::sync::OnceLock;

use nine65::arithmetic::DualRNSContext;
use nine65::entropy::ShadowHarvester;
use nine65::errors::Nine65Error;
use nine65::ops::arrow_emission_gate::{exact_drop_ct, exact_drop_poly};
use nine65::ops::rns_fhe::{DualRNSCiphertext, DualRNSFullKeySet, DualRNSPoly, RNSFHEContext};
use nine65::params::secure_configs::SecureConfig;
use zeroize::{Zeroize, ZeroizeOnDrop};

// ===========================================================================
// EXACT INTEGER REFERENCE ARITHMETIC
//
// A minimal little-endian u64-limb unsigned bignum. It exists because the
// gate must reconstruct the integer a residue tuple represents at EVERY
// config, and M does not fit in u128 for secure_192 (147 bits) or
// secure_256 (177 bits) -- `RNSContext::try_to_int_level` correctly returns
// `None` there. Everything below is add / multiply-by-small /
// divide-by-small / mod-small: integer only, no cascade beyond the Garner
// accumulator it is built for, deterministic.
// ===========================================================================

#[derive(Clone, Debug, PartialEq, Eq)]
struct Big(Vec<u64>);

impl Big {
    fn zero() -> Self {
        Big(Vec::new())
    }

    fn from_u64(x: u64) -> Self {
        if x == 0 {
            Big::zero()
        } else {
            Big(vec![x])
        }
    }

    fn norm(mut v: Vec<u64>) -> Self {
        while v.last() == Some(&0) {
            v.pop();
        }
        Big(v)
    }

    fn is_zero(&self) -> bool {
        self.0.is_empty()
    }

    fn add(&self, other: &Big) -> Big {
        let n = self.0.len().max(other.0.len());
        let mut out = Vec::with_capacity(n + 1);
        let mut carry: u128 = 0;
        for i in 0..n {
            let a = *self.0.get(i).unwrap_or(&0) as u128;
            let b = *other.0.get(i).unwrap_or(&0) as u128;
            let s = a + b + carry;
            out.push(s as u64);
            carry = s >> 64;
        }
        if carry != 0 {
            out.push(carry as u64);
        }
        Big::norm(out)
    }

    fn mul_small(&self, m: u64) -> Big {
        if m == 0 || self.is_zero() {
            return Big::zero();
        }
        let mut out = Vec::with_capacity(self.0.len() + 1);
        let mut carry: u128 = 0;
        for &limb in &self.0 {
            let p = limb as u128 * m as u128 + carry;
            out.push(p as u64);
            carry = p >> 64;
        }
        while carry != 0 {
            out.push(carry as u64);
            carry >>= 64;
        }
        Big::norm(out)
    }

    /// `self mod p`. Requires `p < 2^32` (every NINE65 lane prime is ~28-32
    /// bits) so that `rem << 64` stays inside `u128`.
    fn mod_u64(&self, p: u64) -> u64 {
        debug_assert!(p > 0 && p < (1u64 << 32));
        let mut rem: u128 = 0;
        for &limb in self.0.iter().rev() {
            rem = ((rem << 64) | limb as u128) % p as u128;
        }
        rem as u64
    }

    /// Exact `floor(self / d)`. Requires `d < 2^32`, same reason as above.
    fn div_small(&self, d: u64) -> Big {
        debug_assert!(d > 0 && d < (1u64 << 32));
        let mut out = vec![0u64; self.0.len()];
        let mut rem: u128 = 0;
        for i in (0..self.0.len()).rev() {
            let cur = (rem << 64) | self.0[i] as u128;
            out[i] = (cur / d as u128) as u64;
            rem = cur % d as u128;
        }
        Big::norm(out)
    }

    fn to_u128(&self) -> Option<u128> {
        match self.0.len() {
            0 => Some(0),
            1 => Some(self.0[0] as u128),
            2 => Some(self.0[0] as u128 | ((self.0[1] as u128) << 64)),
            _ => None,
        }
    }
}

fn mulmod(a: u64, b: u64, p: u64) -> u64 {
    ((a as u128 * b as u128) % p as u128) as u64
}

/// Extended Euclid. Panics if `a` is not invertible mod `p` -- every call
/// site here is a lane prime, so a panic means the basis itself is broken.
fn inv_mod(a: u64, p: u64) -> u64 {
    let (mut t, mut newt) = (0i128, 1i128);
    let (mut r, mut newr) = (p as i128, (a % p) as i128);
    while newr != 0 {
        let q = r / newr;
        let tmp = t - q * newt;
        t = newt;
        newt = tmp;
        let tmp = r - q * newr;
        r = newr;
        newr = tmp;
    }
    assert_eq!(r, 1, "inv_mod: {a} is not invertible mod {p}");
    (((t % p as i128) + p as i128) % p as i128) as u64
}

/// Garner CRT reconstruction of the unique `x` in `[0, prod(primes))` with
/// `x = residues[i] (mod primes[i])`. Exact, arbitrary width.
fn crt_garner(residues: &[u64], primes: &[u64]) -> Big {
    assert_eq!(residues.len(), primes.len());
    assert!(!primes.is_empty());
    let mut acc = Big::from_u64(residues[0] % primes[0]);
    let mut m = Big::from_u64(primes[0]);
    for i in 1..primes.len() {
        let p = primes[i];
        let acc_p = acc.mod_u64(p);
        let diff = (residues[i] % p + p - acc_p) % p;
        let d = mulmod(diff, inv_mod(m.mod_u64(p), p), p);
        acc = acc.add(&m.mul_small(d));
        m = m.mul_small(p);
    }
    acc
}

/// `prod(primes) mod a`, without materialising the product.
fn product_mod(primes: &[u64], a: u64) -> u64 {
    primes.iter().fold(1u64 % a, |acc, &p| mulmod(acc, p % a, a))
}

// ===========================================================================
// THE WINDING NUMBER, DERIVED
// ===========================================================================

/// The winding (`k`) of a dual-RNS coefficient, recomputed here from
/// scratch. `k` is the CRAM/K-Elimination phase differential: the residue
/// pair determines a unique integer `X = v_main + k*M`, and `k` is the part
/// of that integer the main frame alone cannot see.
///
/// `k` is reconstructed from the first three anchor lanes (product ~94 bits,
/// which is what `DualRNSContext::extract_k_rns` also uses) and interpreted
/// signed around the half-range, so a coefficient whose true integer is
/// negative yields a small negative `k` rather than a ~157-bit positive one.
struct Winding {
    /// Signed winding number.
    k: i128,
    /// Unsigned winding as reconstructed mod `a0*a1*a2`, for comparison
    /// against the library's `extract_k_rns`, which returns that form.
    k_unsigned: u128,
    /// The canonical main-frame value in `[0, M_level)`.
    v_main: Big,
}

fn derive_winding(
    main_res: &[u64],
    main_primes: &[u64],
    anchor_res: &[u64],
    anchor_primes: &[u64],
) -> Winding {
    assert!(
        anchor_primes.len() >= 3,
        "k reconstruction needs at least 3 anchor lanes"
    );
    let v_main = crt_garner(main_res, main_primes);

    // Per-lane winding residues on the reconstruction lanes:
    //   k_j = (v_anchor_j - v_main) * M^-1   (mod a_j)
    let recon = &anchor_primes[..3];
    let mut k_res = Vec::with_capacity(3);
    for (j, &a) in recon.iter().enumerate() {
        let m_mod_a = product_mod(main_primes, a);
        let diff = (anchor_res[j] % a + a - v_main.mod_u64(a)) % a;
        k_res.push(mulmod(diff, inv_mod(m_mod_a, a), a));
    }

    let k_big = crt_garner(&k_res, recon);
    let k_unsigned = k_big.to_u128().expect("3 anchor lanes fit in u128");
    let p3 = recon.iter().fold(1u128, |acc, &p| acc * p as u128);
    let k = if k_unsigned > p3 / 2 {
        k_unsigned as i128 - p3 as i128
    } else {
        k_unsigned as i128
    };

    Winding {
        k,
        k_unsigned,
        v_main,
    }
}

/// Does anchor lane `a` agree with the integer `v_main + k*M` implied by the
/// main frame plus the derived winding? For the three reconstruction lanes
/// this is true by construction; for the REDUNDANT lanes it is a real,
/// falsifiable claim -- those lanes were never consulted when `k` was
/// derived. That is the phase lock.
fn anchor_lane_agrees(w: &Winding, main_primes: &[u64], a: u64, y: u64) -> bool {
    let m_mod_a = product_mod(main_primes, a);
    let k_mod = w.k.rem_euclid(a as i128) as u64;
    let lhs =
        ((w.v_main.mod_u64(a) as u128 + k_mod as u128 * m_mod_a as u128) % a as u128) as u64;
    lhs == y % a
}

// ===========================================================================
// HARNESS: CONFIGS x MODES
// ===========================================================================

struct Harness {
    name: &'static str,
    ctx: RNSFHEContext,
    keys: DualRNSFullKeySet,
}

impl Harness {
    /// Main primes active at a full-level ciphertext.
    fn main_primes(&self) -> &[u64] {
        &self.ctx.config.primes
    }
    fn anchor_primes(&self) -> &[u64] {
        &self.ctx.dual_rns.anchor.primes
    }
    fn t(&self) -> u64 {
        self.ctx.t
    }
    fn n(&self) -> usize {
        self.ctx.n
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Mode {
    Public,
    Symmetric,
}

impl Mode {
    fn label(self) -> &'static str {
        match self {
            Mode::Public => "PUBLIC",
            Mode::Symmetric => "SYMMETRIC",
        }
    }
}

const MODES: [Mode; 2] = [Mode::Public, Mode::Symmetric];

fn secure_configs() -> Vec<(&'static str, SecureConfig)> {
    vec![
        ("secure_128", SecureConfig::secure_128()),
        ("secure_128_deep", SecureConfig::secure_128_deep()),
        ("secure_192", SecureConfig::secure_192()),
        ("secure_256", SecureConfig::secure_256()),
    ]
}

/// Built once per test binary. Key generation at n=16384 with a gadget
/// evaluation key is the dominant cost in this file, so the four harnesses
/// are shared across every gate rather than rebuilt per test. One full key
/// set serves both modes: PUBLIC uses `eval_key`, SYMMETRIC uses
/// `secret_key`, and both decrypt with the same `secret_key`, which is also
/// what makes the two modes directly comparable.
static HARNESSES: OnceLock<Vec<Harness>> = OnceLock::new();

fn harnesses() -> &'static [Harness] {
    HARNESSES.get_or_init(|| {
        secure_configs()
            .into_iter()
            .map(|(name, sc)| {
                let ctx = RNSFHEContext::try_new(&sc.into_config())
                    .unwrap_or_else(|e| panic!("{name}: context construction failed: {e}"));
                let mut rng = ShadowHarvester::with_seed(0xA770_0001);
                let keys = ctx.generate_keys_dual_full(&mut rng);
                Harness { name, ctx, keys }
            })
            .collect()
    })
}

fn encrypt_seeded(h: &Harness, m: u64, seed: u64) -> DualRNSCiphertext {
    let mut rng = ShadowHarvester::with_seed(seed);
    h.ctx.encrypt_dual(m, &h.keys.public_key, &mut rng)
}

/// Depth-1 multiply in the requested mode. PUBLIC returns a `Result`;
/// a failure here is unwrapped loudly with the config and mode named,
/// because a mode that cannot multiply at all is a matrix cell that must be
/// reported, not skipped.
fn mul_in_mode(
    h: &Harness,
    mode: Mode,
    a: &DualRNSCiphertext,
    b: &DualRNSCiphertext,
) -> DualRNSCiphertext {
    match mode {
        Mode::Public => h
            .ctx
            .mul_dual_public(a, b, &h.keys.eval_key)
            .unwrap_or_else(|e| panic!("{} {}: mul_dual_public failed: {e}", h.name, mode.label())),
        Mode::Symmetric => h.ctx.mul_dual_symmetric(a, b, &h.keys.secret_key),
    }
}

fn coeff_main(poly: &DualRNSPoly, c: usize) -> Vec<u64> {
    poly.main.iter().map(|limb| limb[c]).collect()
}

fn coeff_anchor(poly: &DualRNSPoly, c: usize) -> Vec<u64> {
    poly.anchor.iter().map(|limb| limb[c]).collect()
}

/// Coefficient indices probed by the per-coefficient gates. A handful, not a
/// sweep: n is 8192 or 16384 and the reference reconstruction is exact
/// bignum Garner. Index 0 is the message-bearing constant term; the rest
/// exercise positions the negacyclic wrap treats differently.
fn probe_coeffs(n: usize) -> Vec<usize> {
    vec![0, 1, n / 2, n - 1]
}

/// FNV-1a over every residue in a polynomial, used to compare residue states.
///
/// HONEST SCOPE: the DISTINCTNESS claims in G3 are digest-based. A 64-bit FNV
/// collision between two states that genuinely differ is possible in
/// principle and would show up as a false failure, not a false pass -- the
/// gate can only be fooled into reporting a collision that is not there, and
/// never into missing one that is. The EQUALITY claim (c1 unchanged under a
/// varying message) is not left to the digest: it is asserted directly on the
/// residue vectors as well.
fn fingerprint(poly: &DualRNSPoly) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    let mut eat = |x: u64| {
        for b in x.to_le_bytes() {
            h ^= b as u64;
            h = h.wrapping_mul(0x0000_0100_0000_01b3);
        }
    };
    eat(poly.n as u64);
    eat(poly.main.len() as u64);
    eat(poly.anchor.len() as u64);
    for limb in poly.main.iter().chain(poly.anchor.iter()) {
        for &v in limb {
            eat(v);
        }
    }
    h
}

fn fingerprint_ct(ct: &DualRNSCiphertext) -> u64 {
    fingerprint(&ct.c0)
        .wrapping_mul(0x9e37_79b9_7f4a_7c15)
        .wrapping_add(fingerprint(&ct.c1))
        .wrapping_add(ct.level as u64)
}

// ===========================================================================
// G1 -- WINDING DERIVABLE, NOT CARRIED
//
// The central CRAM invariant. `k` is not state the pipeline hands forward;
// it is a function of the residue pair, recomputable at any point from the
// ciphertext alone. Two independent halves:
//
//   (a) STRUCTURAL, checked by the compiler. The rebuild below uses
//       EXHAUSTIVE struct literals for both `DualRNSPoly` and
//       `DualRNSCiphertext`. If either type ever grew a carried-winding
//       field, this file would stop compiling -- which is the strongest
//       available statement that the winding is not carried. The rebuilt
//       ciphertext, holding nothing but residues, must still decrypt.
//
//   (b) NUMERIC. `k` recomputed here from `(v_main, v_anchor)` by an
//       independent Garner implementation must equal what the library's own
//       `extract_k_rns` derives from the same live state.
// ===========================================================================

#[test]
fn g1_winding_is_derivable_from_residues_and_is_never_carried_as_state() {
    for h in harnesses() {
        for mode in MODES {
            let a = encrypt_seeded(h, 5, 0x6100_0001);
            let b = encrypt_seeded(h, 7, 0x6100_0002);
            let product = mul_in_mode(h, mode, &a, &b);

            for (label, ct) in [("fresh", &a), ("product", &product)] {
                // (a) Rebuild from residues alone. EXHAUSTIVE struct
                // literals -- a new field on either type breaks this build.
                let rebuilt = DualRNSCiphertext {
                    c0: DualRNSPoly {
                        main: ct.c0.main.clone(),
                        anchor: ct.c0.anchor.clone(),
                        n: ct.c0.n,
                    },
                    c1: DualRNSPoly {
                        main: ct.c1.main.clone(),
                        anchor: ct.c1.anchor.clone(),
                        n: ct.c1.n,
                    },
                    level: ct.level,
                };
                assert_eq!(
                    h.ctx.decrypt_dual(&rebuilt, &h.keys.secret_key),
                    h.ctx.decrypt_dual(ct, &h.keys.secret_key),
                    "{} {} [{label}]: a ciphertext rebuilt from nothing but its \
                     residue tuple must decrypt identically -- if it does not, \
                     some state outside the residues is load-bearing",
                    h.name,
                    mode.label()
                );
            }

            // (b) Independent derivation vs the library's own.
            let level = product.level;
            let main_primes = &h.main_primes()[..level];
            let anchor_primes = h.anchor_primes();

            for c in probe_coeffs(h.n()) {
                for (label, poly) in [("c0", &product.c0), ("c1", &product.c1)] {
                    let m_res = coeff_main(poly, c);
                    let a_res = coeff_anchor(poly, c);
                    let w = derive_winding(&m_res, main_primes, &a_res, anchor_primes);

                    // Cross-check against the library. `extract_k_rns` takes
                    // `v_main` as a u128, so it is only callable where M
                    // fits in 128 bits: secure_128 (90) and
                    // secure_128_deep (119) yes, secure_192 (147) and
                    // secure_256 (177) no. Where it is callable, the two
                    // derivations must agree exactly; where it is not, the
                    // independent derivation still runs and G4's phase lock
                    // is what falsifies it.
                    if let Some(v_main_u128) = h.ctx.rns.try_to_int_level(&m_res, level) {
                        assert_eq!(
                            Some(v_main_u128),
                            w.v_main.to_u128(),
                            "{} {} [{label} coeff {c}]: independent Garner \
                             reconstruction disagrees with RNSContext",
                            h.name,
                            mode.label()
                        );
                        let k_lib = h.ctx.dual_rns.extract_k_rns(v_main_u128, &a_res);
                        assert_eq!(
                            k_lib, w.k_unsigned,
                            "{} {} [{label} coeff {c}]: the winding the library \
                             derives ({k_lib}) differs from the winding derived \
                             independently from the same residue pair ({}) -- k \
                             is not a pure function of the state",
                            h.name,
                            mode.label(),
                            w.k_unsigned
                        );
                    }
                }
            }
        }
    }
}

/// The multiply path ends in `canonicalize_dual_anchor`, which rewrites the
/// anchor frame to the residues of the main-frame value. A product
/// ciphertext is therefore expected to have winding EXACTLY zero on every
/// probed coefficient of both components -- it is canonical, ready to be
/// squared again without the anchor capacity absorbing a stale surplus.
///
/// This is pinned as a measured fact, in the same spirit as the singular-set
/// pin in the transcendentals suite: if canonicalisation ever stops running
/// (or starts running on only one component), the winding stops being zero
/// and this fails loudly instead of showing up later as a capacity overflow.
#[test]
fn g1_product_ciphertexts_carry_zero_winding_in_both_modes() {
    for h in harnesses() {
        for mode in MODES {
            let a = encrypt_seeded(h, 11, 0x6100_0011);
            let b = encrypt_seeded(h, 13, 0x6100_0012);
            let product = mul_in_mode(h, mode, &a, &b);
            let level = product.level;
            let main_primes = &h.main_primes()[..level];
            let anchor_primes = h.anchor_primes();

            for c in probe_coeffs(h.n()) {
                for (label, poly) in [("c0", &product.c0), ("c1", &product.c1)] {
                    let w = derive_winding(
                        &coeff_main(poly, c),
                        main_primes,
                        &coeff_anchor(poly, c),
                        anchor_primes,
                    );
                    assert_eq!(
                        w.k, 0,
                        "{} {} [{label} coeff {c}]: product ciphertext must be \
                         canonical (winding 0), got k={}",
                        h.name,
                        mode.label(),
                        w.k
                    );
                }
            }
        }
    }
}

// ===========================================================================
// G2 -- TRANSITION DEFECT ZERO
//
// encrypt -> operation -> decrypt must be EXACT, for every (config, mode),
// at the edges of the plaintext space as well as in its interior. t = 65537
// for all four tiers, so the edge cases are 0, 1, t-1, and the product
// (t-1)^2 = 1 (mod t), which is the largest-magnitude plaintext multiply the
// space admits.
// ===========================================================================

/// Plaintext pairs. `(t-1, t-1)` is the (t-1)^2 case; `(t-1, 1)` isolates a
/// single maximal operand; `(0, 0)` and `(1, 1)` pin the absorbing and
/// identity elements, which are exactly the values a broken encoding is
/// most likely to get accidentally right.
fn edge_pairs(t: u64) -> Vec<(u64, u64)> {
    vec![(0, 0), (0, 1), (1, 1), (2, 3), (t - 1, 1), (t - 1, t - 1)]
}

#[test]
fn g2_add_transition_defect_is_zero_for_every_config_and_mode() {
    for h in harnesses() {
        let t = h.t();
        for (i, (x, y)) in edge_pairs(t).into_iter().enumerate() {
            let cx = encrypt_seeded(h, x, 0x6200_0000 + i as u64 * 2);
            let cy = encrypt_seeded(h, y, 0x6200_0001 + i as u64 * 2);
            let sum = h.ctx.add_dual(&cx, &cy);
            let got = h.ctx.decrypt_dual(&sum, &h.keys.secret_key);
            // `add_dual` takes no key and has no mode-dependent branch, so
            // the PUBLIC and SYMMETRIC cells of this row are the SAME code
            // path over the same state. The addition is therefore performed
            // once and the result asserted under both labels, rather than
            // recomputed -- the matrix cell is covered, and the redundant
            // half of the work is not paid for at n=16384.
            for mode in MODES {
                assert_eq!(
                    got,
                    (x + y) % t,
                    "{} {}: add({x}, {y}) decrypted to {got}, expected {}",
                    h.name,
                    mode.label(),
                    (x + y) % t
                );
            }
        }
    }
}

#[test]
fn g2_depth1_mul_transition_defect_is_zero_for_every_config_and_mode() {
    for h in harnesses() {
        let t = h.t();
        for mode in MODES {
            for (i, (x, y)) in edge_pairs(t).into_iter().enumerate() {
                let cx = encrypt_seeded(h, x, 0x6210_0000 + i as u64 * 2);
                let cy = encrypt_seeded(h, y, 0x6210_0001 + i as u64 * 2);
                let prod = mul_in_mode(h, mode, &cx, &cy);
                let expected = ((x as u128 * y as u128) % t as u128) as u64;
                let got = h.ctx.decrypt_dual(&prod, &h.keys.secret_key);
                assert_eq!(
                    got,
                    expected,
                    "{} {}: mul({x}, {y}) decrypted to {got}, expected {expected}",
                    h.name,
                    mode.label()
                );
            }
        }
    }
}

/// Decryption must not merely land on the right value -- it must land on it
/// with margin. `try_decrypt_dual` returns `Err` when the rounding margin
/// has gone negative, i.e. when the answer happens to be right but the
/// budget says it should not be trusted. A cell that passes the value check
/// while failing this one is a latent leak, not a pass.
#[test]
fn g2_depth1_results_decrypt_with_positive_noise_margin() {
    for h in harnesses() {
        let t = h.t();
        for mode in MODES {
            // Only the hardest case: (t-1)^2 is the largest-magnitude
            // plaintext multiply the space admits, so it is the one whose
            // margin is tightest. The interior cases are already covered for
            // VALUE by the test above; re-multiplying them here would double
            // the multiply count of this file for no extra discrimination.
            for (x, y) in [(t - 1, t - 1)] {
                let cx = encrypt_seeded(h, x, 0x6220_0001);
                let cy = encrypt_seeded(h, y, 0x6220_0002);
                let prod = mul_in_mode(h, mode, &cx, &cy);
                let checked = h.ctx.try_decrypt_dual(&prod, &h.keys.secret_key);
                assert!(
                    checked.is_ok(),
                    "{} {}: mul({x}, {y}) exhausted the noise margin: {:?}",
                    h.name,
                    mode.label(),
                    checked.err()
                );
                assert_eq!(
                    checked.unwrap(),
                    ((x as u128 * y as u128) % t as u128) as u64,
                    "{} {}: checked decryption disagrees with the plain one",
                    h.name,
                    mode.label()
                );
            }
        }
    }
}

// ===========================================================================
// G3 -- NO STATE COLLISIONS
//
// Injectivity of the encoding, separated from the randomisation that hides
// it. Encryption is randomised, so "distinct plaintexts give distinct
// ciphertexts" is nearly vacuous when the randomness also differs. The sharp
// form holds the randomness FIXED: then the only thing that varies is the
// message, and the two claims below are the interesting ones --
//
//   * c0 must differ for every distinct message (the message rides there);
//   * c1 must be IDENTICAL for every message (it must carry no message
//     state at all -- a c1 that moved with m would be a plaintext channel
//     outside the masked component).
//
// The randomised direction is then checked separately: the same message
// under different randomness must NOT produce the same state, which is the
// necessary structural condition for semantic security.
// ===========================================================================

#[test]
fn g3_fixed_randomness_makes_c0_injective_in_the_message_and_c1_independent_of_it() {
    for h in harnesses() {
        let t = h.t();
        let messages = [0u64, 1, 2, 3, 4097, t - 1];
        const FIXED_SEED: u64 = 0x6300_0BAD;

        let mut c0_prints = Vec::new();
        let mut c1_prints = HashSet::new();
        let mut c1_reference: Option<DualRNSPoly> = None;

        for &m in &messages {
            let ct = encrypt_seeded(h, m, FIXED_SEED);
            c0_prints.push((m, fingerprint(&ct.c0)));
            c1_prints.insert(fingerprint(&ct.c1));

            // Direct, non-digest form of the c1 claim.
            match &c1_reference {
                None => c1_reference = Some(ct.c1.clone()),
                Some(reference) => {
                    assert_eq!(
                        (&ct.c1.main, &ct.c1.anchor),
                        (&reference.main, &reference.anchor),
                        "{}: c1 residues changed when only the message changed \
                         (m={m}) -- compared limb by limb, not by digest",
                        h.name
                    );
                }
            }
        }

        let unique: HashSet<u64> = c0_prints.iter().map(|&(_, f)| f).collect();
        assert_eq!(
            unique.len(),
            messages.len(),
            "{}: c0 residue states collided across distinct plaintexts {:?} \
             under fixed randomness -- the encoding is not injective",
            h.name,
            messages
        );

        assert_eq!(
            c1_prints.len(),
            1,
            "{}: c1 moved with the message under fixed randomness. c1 must be \
             a function of (public key, randomness) only; if it tracks m it is \
             a plaintext side channel",
            h.name
        );
    }
}

#[test]
fn g3_same_message_under_different_randomness_never_repeats_a_residue_state() {
    for h in harnesses() {
        let m = 4242u64;
        let mut seen = HashSet::new();
        for s in 0..6u64 {
            let ct = encrypt_seeded(h, m, 0x6310_0000 + s);
            assert!(
                seen.insert(fingerprint_ct(&ct)),
                "{}: two encryptions of the same message under different \
                 randomness produced the SAME residue state",
                h.name
            );
        }
    }
}

#[test]
fn g3_distinct_plaintexts_stay_distinct_through_a_multiply_in_both_modes() {
    for h in harnesses() {
        for mode in MODES {
            let mut seen = HashSet::new();
            // Distinct products, so distinct result states are required
            // rather than merely likely.
            for (i, (x, y)) in [(2u64, 3u64), (5, 7), (11, 13)].into_iter().enumerate()
            {
                let cx = encrypt_seeded(h, x, 0x6320_0000 + i as u64 * 2);
                let cy = encrypt_seeded(h, y, 0x6320_0001 + i as u64 * 2);
                let prod = mul_in_mode(h, mode, &cx, &cy);
                assert!(
                    seen.insert(fingerprint_ct(&prod)),
                    "{} {}: products of distinct plaintext pairs collided in \
                     residue space",
                    h.name,
                    mode.label()
                );
            }
        }
    }
}

// ===========================================================================
// G4 -- SHARED-FACTOR CONSISTENCY (THE PHASE LOCK)
//
// Two separate claims.
//
//   (a) THE REDUNDANT ANCHOR LANES AGREE. `k` is reconstructed from the
//       first three anchor lanes. Every remaining anchor lane -- two more at
//       n=8192, seven more at n=16384 -- was never consulted, so its
//       agreement with the integer `v_main + k*M` is a real, falsifiable
//       claim about the frames being locked to ONE value. This is the direct
//       analogue of the transcendentals gate's per-lane independence: each
//       lane is checked on its own, no cascade.
//
//   (b) EVERY EMITTED RESIDUE IS CANONICAL. `validate_dual_ciphertext` is
//       the config-aware check (`limb < prime` on every lane); it runs on
//       the output of every operation in the matrix, not just on fresh
//       ciphertexts.
// ===========================================================================

#[test]
fn g4_redundant_anchor_lanes_agree_with_the_main_frame_in_both_modes() {
    for h in harnesses() {
        for mode in MODES {
            let a = encrypt_seeded(h, 23, 0x6400_0001);
            let b = encrypt_seeded(h, 29, 0x6400_0002);
            let product = mul_in_mode(h, mode, &a, &b);
            let sum = h.ctx.add_dual(&a, &b);

            for (state, ct) in [("fresh", &a), ("sum", &sum), ("product", &product)] {
                let level = ct.level;
                let main_primes = &h.main_primes()[..level];
                let anchor_primes = h.anchor_primes();
                assert!(
                    anchor_primes.len() > 3,
                    "{}: the phase lock needs at least one redundant anchor \
                     lane beyond the three used for reconstruction",
                    h.name
                );

                for c in probe_coeffs(h.n()) {
                    for (label, poly) in [("c0", &ct.c0), ("c1", &ct.c1)] {
                        let m_res = coeff_main(poly, c);
                        let a_res = coeff_anchor(poly, c);
                        let w = derive_winding(&m_res, main_primes, &a_res, anchor_primes);

                        for (j, &a_j) in anchor_primes.iter().enumerate() {
                            let redundant = j >= 3;
                            assert!(
                                anchor_lane_agrees(&w, main_primes, a_j, a_res[j]),
                                "{} {} [{state} {label} coeff {c}]: anchor lane \
                                 {j} (prime {a_j}, redundant={redundant}) carries \
                                 {} but the main frame plus winding k={} implies a \
                                 different residue -- the frames are not locked to \
                                 one value",
                                h.name,
                                mode.label(),
                                a_res[j],
                                w.k
                            );
                        }
                    }
                }
            }
        }
    }
}

#[test]
fn g4_every_operation_emits_only_canonical_residues_in_both_modes() {
    for h in harnesses() {
        for mode in MODES {
            let a = encrypt_seeded(h, 31, 0x6410_0001);
            let b = encrypt_seeded(h, 37, 0x6410_0002);

            let mut states: Vec<(&str, DualRNSCiphertext)> = vec![
                ("fresh_a", a.clone()),
                ("fresh_b", b.clone()),
                ("add", h.ctx.add_dual(&a, &b)),
                ("sub", h.ctx.sub_dual(&a, &b)),
                ("negate", h.ctx.negate_dual(&a)),
                ("add_plain", h.ctx.add_plain_dual(&a, 9)),
                ("mul_plain", h.ctx.mul_plain_dual(&a, 9)),
                ("mul", mul_in_mode(h, mode, &a, &b)),
            ];

            // The exact align-and-drop output is an emitted state too, and
            // it lands in a SHORTER main frame -- validate it against the
            // surviving prime list.
            let drop_idx = a.level - 1;
            let dropped = exact_drop_ct(
                &a,
                &h.main_primes()[..a.level],
                h.anchor_primes(),
                drop_idx,
            )
            .expect("exact drop of the top main lane must succeed on a prime basis");
            states.push(("exact_drop", dropped));

            for (label, ct) in &states {
                let level = ct.c0.main.len();
                assert!(
                    ct.validate().is_ok(),
                    "{} {} [{label}]: shape validation failed",
                    h.name,
                    mode.label()
                );
                let res = ct.validate_residues(&h.main_primes()[..level], h.anchor_primes());
                assert!(
                    res.is_ok(),
                    "{} {} [{label}]: emitted a non-canonical residue: {:?}",
                    h.name,
                    mode.label(),
                    res.err()
                );
            }
        }
    }
}

// ===========================================================================
// G5 -- LIFT PRESERVED ACROSS FRAME CHANGES
//
// `exact_modulus_switch_drop_*` moves the state from the frame
// {q_0..q_{L-1}} into the frame with q_k removed. It is an EXACT integer
// division by q_k -- no rounding term, never leaving residue space -- and it
// is NOT the BFV message rescale by Delta (see docs/MODULUS_SWITCHING.md;
// conflating the two mis-scales the message).
//
// Two things must survive the frame change:
//
//   (a) THE VALUE. Every surviving main lane must carry
//       floor(v_main / q_k) mod q_i EXACTLY, checked against an independent
//       bignum floor division of the Garner-reconstructed value.
//
//   (b) THE LIFT. The winding derived in the OLD frame and the winding
//       derived in the NEW frame must be the same number. The winding is the
//       part of the represented integer the main frame cannot see; if a
//       frame change could alter it, the frame would be carrying information
//       the residues do not determine.
// ===========================================================================

#[test]
fn g5_exact_drop_lands_on_floor_division_exactly_on_every_surviving_lane() {
    for h in harnesses() {
        for mode in MODES {
            let a = encrypt_seeded(h, 41, 0x6500_0001);
            let b = encrypt_seeded(h, 43, 0x6500_0002);
            let product = mul_in_mode(h, mode, &a, &b);

            for (state, ct) in [("fresh", &a), ("product", &product)] {
                let level = ct.level;
                let main_primes = &h.main_primes()[..level];
                let anchor_primes = h.anchor_primes();
                let drop_idx = level - 1;
                let q_k = main_primes[drop_idx];
                let surviving: Vec<u64> = main_primes
                    .iter()
                    .copied()
                    .enumerate()
                    .filter(|&(i, _)| i != drop_idx)
                    .map(|(_, p)| p)
                    .collect();

                let out = exact_drop_ct(ct, main_primes, anchor_primes, drop_idx)
                    .expect("exact drop must succeed on a disjoint prime basis");

                // Shape: exactly one main lane gone, every anchor lane kept,
                // degree untouched, level decremented. A frame change, not a
                // reshaping.
                assert_eq!(out.level, level - 1, "{}: level must decrement by 1", h.name);
                assert_eq!(out.c0.main.len(), level - 1);
                assert_eq!(out.c0.anchor.len(), anchor_primes.len());
                assert_eq!(out.c0.n, ct.c0.n);
                assert_eq!(out.c1.main.len(), level - 1);

                for c in probe_coeffs(h.n()) {
                    for (label, (pre, post)) in
                        [("c0", (&ct.c0, &out.c0)), ("c1", (&ct.c1, &out.c1))]
                    {
                        // (a) the value
                        let v_main = crt_garner(&coeff_main(pre, c), main_primes);
                        let expected = v_main.div_small(q_k);
                        for (lane, &q_i) in surviving.iter().enumerate() {
                            assert_eq!(
                                post.main[lane][c],
                                expected.mod_u64(q_i),
                                "{} {} [{state} {label} coeff {c}]: surviving main \
                                 lane {q_i} does not carry floor(X / {q_k}) after \
                                 the frame change",
                                h.name,
                                mode.label()
                            );
                        }

                        // (b) the lift
                        let w_pre = derive_winding(
                            &coeff_main(pre, c),
                            main_primes,
                            &coeff_anchor(pre, c),
                            anchor_primes,
                        );
                        let w_post = derive_winding(
                            &coeff_main(post, c),
                            &surviving,
                            &coeff_anchor(post, c),
                            anchor_primes,
                        );
                        assert_eq!(
                            w_pre.k, w_post.k,
                            "{} {} [{state} {label} coeff {c}]: the winding changed \
                             across the frame transition ({} -> {}) -- the lift is \
                             not preserved",
                            h.name,
                            mode.label(),
                            w_pre.k,
                            w_post.k
                        );
                    }
                }
            }
        }
    }
}

/// The drop is not privileged to the top of the chain. Every main lane is
/// droppable, and the exactness and lift-preservation claims must hold for
/// EVERY choice of `drop_idx`, not only the last one -- a primitive that is
/// exact only at the end of the chain would be an ordering artefact, and the
/// whole point of an align-and-drop is that it is a frame change, indifferent
/// to which lane leaves.
///
/// Run on fresh ciphertexts (no multiply), so this sweep costs no additional
/// ct x ct work at n=16384: it is 3, 4, 5 and 6 drops respectively, each one
/// a linear pass over the residues.
#[test]
fn g5_every_droppable_lane_preserves_value_and_lift() {
    for h in harnesses() {
        let ct = encrypt_seeded(h, 67, 0x6520_0001);
        let level = ct.level;
        let main_primes = &h.main_primes()[..level];
        let anchor_primes = h.anchor_primes();

        for drop_idx in 0..level {
            let q_k = main_primes[drop_idx];
            let surviving: Vec<u64> = main_primes
                .iter()
                .copied()
                .enumerate()
                .filter(|&(i, _)| i != drop_idx)
                .map(|(_, p)| p)
                .collect();

            let out = exact_drop_ct(&ct, main_primes, anchor_primes, drop_idx)
                .unwrap_or_else(|e| panic!("{}: drop of lane {drop_idx} refused: {e}", h.name));
            assert_eq!(out.c0.main.len(), level - 1);
            assert_eq!(out.c0.anchor.len(), anchor_primes.len());

            for c in probe_coeffs(h.n()) {
                for (label, (pre, post)) in
                    [("c0", (&ct.c0, &out.c0)), ("c1", (&ct.c1, &out.c1))]
                {
                    let v_main = crt_garner(&coeff_main(pre, c), main_primes);
                    let expected = v_main.div_small(q_k);
                    for (lane, &q_i) in surviving.iter().enumerate() {
                        assert_eq!(
                            post.main[lane][c],
                            expected.mod_u64(q_i),
                            "{} [{label} coeff {c}]: dropping lane {drop_idx} \
                             (prime {q_k}) did not land on floor(X/{q_k}) on \
                             surviving lane {q_i}",
                            h.name
                        );
                    }

                    let w_pre = derive_winding(
                        &coeff_main(pre, c),
                        main_primes,
                        &coeff_anchor(pre, c),
                        anchor_primes,
                    );
                    let w_post = derive_winding(
                        &coeff_main(post, c),
                        &surviving,
                        &coeff_anchor(post, c),
                        anchor_primes,
                    );
                    assert_eq!(
                        w_pre.k, w_post.k,
                        "{} [{label} coeff {c}]: dropping lane {drop_idx} changed \
                         the winding ({} -> {})",
                        h.name, w_pre.k, w_post.k
                    );
                }
            }
        }
    }
}

/// Dropping a lane must move the value, not merely relabel it: applying the
/// drop must produce a DIFFERENT residue state from the input on the
/// surviving lanes (otherwise "exact division by q_k" would be a no-op that
/// happens to typecheck), and applying it twice must equal one division by
/// the product of the two dropped primes.
#[test]
fn g5_two_successive_drops_compose_into_one_division_by_the_product() {
    for h in harnesses() {
        let ct = encrypt_seeded(h, 47, 0x6510_0001);
        let level = ct.level;
        assert!(level >= 3, "{}: need at least 3 main lanes", h.name);
        let main_primes = &h.main_primes()[..level];
        let anchor_primes = h.anchor_primes();

        let q_last = main_primes[level - 1];
        let q_prev = main_primes[level - 2];

        let once = exact_drop_ct(&ct, main_primes, anchor_primes, level - 1)
            .expect("first drop must succeed");
        let after_one: Vec<u64> = main_primes[..level - 1].to_vec();
        let twice = exact_drop_ct(&once, &after_one, anchor_primes, level - 2)
            .expect("second drop must succeed");

        let surviving: Vec<u64> = main_primes[..level - 2].to_vec();

        for c in probe_coeffs(h.n()) {
            let v_main = crt_garner(&coeff_main(&ct.c0, c), main_primes);
            let expected = v_main.div_small(q_last).div_small(q_prev);
            for (lane, &q_i) in surviving.iter().enumerate() {
                assert_eq!(
                    twice.c0.main[lane][c],
                    expected.mod_u64(q_i),
                    "{}: two successive exact drops must compose into \
                     floor(floor(X/{q_last})/{q_prev}) on lane {q_i}",
                    h.name
                );
            }
            // Non-triviality: the single drop already moved the value.
            let after_one_val = v_main.div_small(q_last);
            assert_ne!(
                after_one_val, v_main,
                "{}: an exact drop that leaves the value unchanged is not a \
                 frame change at all (coeff {c})",
                h.name
            );
        }
    }
}

// ===========================================================================
// G6 -- REFUSE, DO NOT PROJECT
//
// The FHE analogue of `unfold_refuses_partial_reversal_loudly`. Every
// operation that CANNOT be performed exactly must return a typed error, and
// the RIGHT typed error, rather than a plausible-looking wrong value. The
// failure modes are driven deliberately, not waited for.
// ===========================================================================

fn expect_invalid_parameter<T>(res: Result<T, Nine65Error>, needle: &str, what: &str) {
    match res {
        Ok(_) => panic!("{what}: expected a refusal, got a value"),
        Err(e) => {
            assert!(
                matches!(e, Nine65Error::InvalidParameter { .. }),
                "{what}: expected Nine65Error::InvalidParameter, got {e:?}"
            );
            let msg = e.to_string();
            assert!(
                msg.contains(needle),
                "{what}: refusal message {msg:?} does not name the cause {needle:?}"
            );
        }
    }
}

#[test]
fn g6_exact_drop_refuses_a_non_coprime_lane_rather_than_projecting() {
    for h in harnesses() {
        let ct = encrypt_seeded(h, 53, 0x6600_0001);
        let level = ct.level;
        let main_primes = &h.main_primes()[..level];
        let drop_idx = level - 1;
        let q_k = main_primes[drop_idx];

        // Doctor the anchor list so one anchor lane collides with the
        // dropped prime: gcd != 1, the align-and-drop inverse does not
        // exist, and the only correct answer is a refusal.
        let mut bad_anchor = h.anchor_primes().to_vec();
        bad_anchor[0] = q_k;
        expect_invalid_parameter(
            exact_drop_poly(&ct.c0, main_primes, &bad_anchor, drop_idx),
            "not coprime",
            &format!("{}: non-coprime anchor lane", h.name),
        );

        // Same collision on the main side.
        let mut bad_main = main_primes.to_vec();
        bad_main[0] = q_k;
        expect_invalid_parameter(
            exact_drop_poly(&ct.c0, &bad_main, h.anchor_primes(), drop_idx),
            "not coprime",
            &format!("{}: non-coprime main lane", h.name),
        );
    }
}

#[test]
fn g6_exact_drop_refuses_shape_and_index_violations_rather_than_projecting() {
    for h in harnesses() {
        let ct = encrypt_seeded(h, 59, 0x6610_0001);
        let level = ct.level;
        let main_primes = &h.main_primes()[..level];
        let anchor_primes = h.anchor_primes();

        expect_invalid_parameter(
            exact_drop_poly(&ct.c0, main_primes, anchor_primes, level),
            "drop_idx",
            &format!("{}: drop index out of range", h.name),
        );
        expect_invalid_parameter(
            exact_drop_poly(&ct.c0, &main_primes[..level - 1], anchor_primes, 0),
            "main_primes",
            &format!("{}: main prime count mismatch", h.name),
        );
        expect_invalid_parameter(
            exact_drop_poly(
                &ct.c0,
                main_primes,
                &anchor_primes[..anchor_primes.len() - 1],
                0,
            ),
            "anchor_primes",
            &format!("{}: anchor prime count mismatch", h.name),
        );
        expect_invalid_parameter(
            exact_drop_ct(&ct, main_primes, anchor_primes, level + 3),
            "drop_idx",
            &format!("{}: ciphertext-level drop index out of range", h.name),
        );
    }
}

/// Anchor capacity is what makes K-Elimination exact. If the anchor system
/// cannot represent the full `N * Q^2` tensor product, the rescale WRAPS --
/// producing a wrong-but-plausible ciphertext rather than an error. That is
/// precisely the silent partial answer the arrow-emission contract forbids,
/// so the capacity audit must refuse first.
///
/// Driven deliberately: `secure_256` is rebuilt on a truncated 5-lane anchor
/// basis (A ~157 bits instead of ~315), which is the configuration that used
/// to fail outright, and the multiply must return `Err` before touching a
/// single residue. The ciphertexts and keys come from the intact harness --
/// only the anchor frame is starved.
#[test]
fn g6_public_multiply_refuses_when_anchor_capacity_cannot_hold_the_tensor_product() {
    let h = harnesses()
        .iter()
        .find(|h| h.name == "secure_256")
        .expect("secure_256 harness");

    let a = encrypt_seeded(h, 3, 0x6620_0001);
    let b = encrypt_seeded(h, 5, 0x6620_0002);

    // Sanity: the intact frame multiplies fine, so a refusal below is
    // attributable to the starved anchor and to nothing else.
    assert!(
        h.ctx.mul_dual_public(&a, &b, &h.keys.eval_key).is_ok(),
        "secure_256 must multiply on the intact 10-lane anchor basis"
    );

    let config = SecureConfig::secure_256().into_config();
    let mut starved = RNSFHEContext::try_new(&config).expect("context");
    starved.dual_rns = DualRNSContext::new(
        config.primes.clone(),
        h.anchor_primes()[..5].to_vec(),
        config.n,
    );

    expect_invalid_parameter(
        starved.mul_dual_public(&a, &b, &h.keys.eval_key),
        "Capacity overflow",
        "secure_256 on a starved 5-lane anchor basis",
    );
}

/// Non-canonical residues at the deserialization boundary.
///
/// HONEST SCOPE, and this is a finding in its own right: the serde entry
/// points `DualRNSCiphertext::from_json_validated` /
/// `from_bytes_validated` call `validate()` only. `validate()` checks SHAPE
/// -- degree, limb counts, limb lengths, level bounds -- and has no prime
/// list, so it cannot and does not reject a limb that is >= its lane's
/// prime. A `u64::MAX` sitting in a ~30-bit lane therefore survives
/// deserialization. The config-aware `RNSFHEContext::validate_dual_ciphertext`
/// is the gate that catches it, and an untrusted-input boundary MUST call
/// that one; the validated constructors alone are not sufficient.
///
/// Both halves are asserted below so the gap cannot close silently in either
/// direction.
#[test]
fn g6_non_canonical_residues_are_refused_by_the_config_aware_validator() {
    for h in harnesses() {
        let ct = encrypt_seeded(h, 61, 0x6630_0001);
        let level = ct.level;

        // Intact ciphertext passes both checks.
        assert!(ct.validate().is_ok(), "{}: intact shape must validate", h.name);
        assert!(
            h.ctx.validate_dual_ciphertext(&ct).is_ok(),
            "{}: intact residues must validate",
            h.name
        );

        // Poison one main limb with a value far above its lane prime.
        let mut poisoned = ct.clone();
        poisoned.c0.main[0][0] = u64::MAX;
        assert!(
            poisoned.validate().is_ok(),
            "{}: shape-only validation is documented NOT to catch a \
             non-canonical residue; if it now does, this test's premise (and \
             the serde boundary note above it) needs updating",
            h.name
        );
        expect_invalid_parameter(
            h.ctx.validate_dual_ciphertext(&poisoned),
            "non-canonical residue",
            &format!("{}: poisoned main limb", h.name),
        );

        // ...and one anchor limb, at the last lane, which is a redundant
        // witness lane rather than one of the three reconstruction lanes.
        let mut poisoned_anchor = ct.clone();
        let last = poisoned_anchor.c1.anchor.len() - 1;
        poisoned_anchor.c1.anchor[last][0] = u64::MAX;
        expect_invalid_parameter(
            h.ctx.validate_dual_ciphertext(&poisoned_anchor),
            "non-canonical residue",
            &format!("{}: poisoned anchor witness limb", h.name),
        );

        // Shape violations are refused by the shape validator itself.
        let mut ragged = ct.clone();
        ragged.c0.main.truncate(1);
        assert!(
            ragged.validate().is_err(),
            "{}: mismatched c0/c1 main lane counts must be refused",
            h.name
        );
        let mut short_limb = ct.clone();
        short_limb.c0.main[0].truncate(level);
        assert!(
            short_limb.validate().is_err(),
            "{}: a limb shorter than n must be refused",
            h.name
        );
    }
}

/// Out-of-space plaintexts.
///
/// HONEST SCOPE: `encrypt_dual` refuses `m >= t` with a debug/release
/// `assert!`, i.e. a PANIC, not a typed `Err`. It is a loud refusal -- it
/// cannot return a wrong ciphertext -- but it is outside the
/// `Nine65Error` taxonomy that the rest of this gate asserts on, so it
/// cannot be handled by a caller and it is not catchable at an API
/// boundary without `catch_unwind`. That is recorded here rather than
/// papered over.
#[test]
fn g6_encrypting_outside_the_plaintext_space_refuses_loudly() {
    // NOTE ON OUTPUT: this test deliberately triggers four panics (one per
    // config) and catches them. The default panic hook prints each to stderr,
    // so a passing run of this file shows four "Plaintext must be < t"
    // backtraces. That is the refusal being observed, not a failure. The hook
    // is left in place on purpose: replacing it is process-global and would
    // suppress a genuine panic message from any test running concurrently.
    for h in harnesses() {
        let t = h.t();
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut rng = ShadowHarvester::with_seed(0x6640_0001);
            h.ctx.encrypt_dual(t, &h.keys.public_key, &mut rng)
        }));
        assert!(
            outcome.is_err(),
            "{}: encrypt_dual({t}) with t={t} must refuse, not silently wrap \
             the message into the plaintext space",
            h.name
        );
    }
}

// ===========================================================================
// G7 -- NO SECRET LEAK IN EMISSIONS
//
// WHAT THIS GATE IS. A STRUCTURAL check, from the public API only. It
// establishes that (i) the secret-bearing types are wired for zeroization,
// (ii) the redacted `Debug` really is redacted, (iii) no public artifact --
// public key, evaluation key, ciphertext -- reproduces a secret-key lane,
// and (iv) a ciphertext does not decrypt under the wrong secret key.
//
// WHAT THIS GATE IS NOT. It is NOT a cryptographic proof and must never be
// cited as one. It cannot show that the eval key is computationally hiding,
// it cannot rule out a statistical correlation between public artifacts and
// the secret, and it cannot speak to side channels. Those are the province
// of the security estimator, the constant-time work, and a lattice
// assumption -- not of an integration test. What it CAN do is catch the
// blunt failures: a secret copied verbatim into an emitted artifact, a
// Debug impl that prints residues, a type that stopped zeroizing.
// ===========================================================================

fn assert_zeroize<T: Zeroize>() {}
fn assert_zeroize_on_drop<T: ZeroizeOnDrop>() {}

#[test]
fn g7_secret_bearing_types_are_wired_for_zeroization() {
    // A compile-time obligation: if `DualRNSSecretKey` ever stops deriving
    // `ZeroizeOnDrop`, or `DualRNSPoly` stops deriving `Zeroize`, this file
    // fails to build.
    assert_zeroize_on_drop::<nine65::ops::rns_fhe::DualRNSSecretKey>();
    assert_zeroize::<nine65::ops::rns_fhe::DualRNSSecretKey>();
    assert_zeroize::<DualRNSPoly>();

    // Note also what is absent by construction: `DualRNSSecretKey` derives
    // no `Debug` at all, so there is no formatting path that could print it.
    // That cannot be asserted positively in Rust, but any attempt to add
    // `format!("{:?}", secret_key)` here would fail to compile, which is the
    // enforcement.
}

#[test]
fn g7_redacted_debug_does_not_print_residues() {
    for h in harnesses() {
        let poly = &h.keys.secret_key.s;
        let rendered = format!("{poly:?}");

        assert!(
            rendered.contains("DualRNSPoly"),
            "{}: Debug should still identify the type",
            h.name
        );

        // Pick a residue large enough that a coincidental substring match
        // against the shape numbers Debug does print (n, lane counts) is not
        // possible.
        let distinctive = poly
            .main
            .iter()
            .flat_map(|limb| limb.iter().copied())
            .find(|&v| v > 1_000_000);
        if let Some(v) = distinctive {
            assert!(
                !rendered.contains(&v.to_string()),
                "{}: the redacted Debug leaked a secret-key residue ({v})",
                h.name
            );
        }

        // The ciphertext Debug embeds the polynomial Debug, so it inherits
        // the redaction; check that too, since ciphertexts are the thing
        // most likely to end up in a log line.
        let ct = encrypt_seeded(h, 7, 0x6700_0001);
        let ct_rendered = format!("{ct:?}");
        if let Some(v) = ct.c0.main[0].iter().copied().find(|&v| v > 1_000_000) {
            assert!(
                !ct_rendered.contains(&v.to_string()),
                "{}: ciphertext Debug leaked a residue ({v})",
                h.name
            );
        }
    }
}

#[test]
fn g7_public_artifacts_never_reproduce_a_secret_key_lane() {
    for h in harnesses() {
        let sk = &h.keys.secret_key.s;
        let ct = encrypt_seeded(h, 71, 0x6710_0001);

        // Collect every polynomial a public-mode participant can hold.
        let mut public_polys: Vec<(String, &DualRNSPoly)> = vec![
            ("pk0".to_string(), &h.keys.public_key.pk0),
            ("pk1".to_string(), &h.keys.public_key.pk1),
            ("ct.c0".to_string(), &ct.c0),
            ("ct.c1".to_string(), &ct.c1),
        ];
        for (i, (r0, r1)) in h.keys.eval_key.rlk.iter().enumerate() {
            // Indexed so a failure names the gadget digit.
            public_polys.push((format!("rlk{i}.0"), r0));
            public_polys.push((format!("rlk{i}.1"), r1));
        }

        for (label, poly) in public_polys {
            for (lane, limb) in poly.main.iter().enumerate() {
                if lane >= sk.main.len() {
                    continue;
                }
                assert_ne!(
                    limb, &sk.main[lane],
                    "{}: public artifact {label} main lane {lane} is BIT-IDENTICAL \
                     to the secret key lane",
                    h.name
                );
                // Positional coincidences should be at the level of chance
                // (the secret is ternary, the artifacts are ~uniform mod p),
                // so anything above 1% of the ring is a structural signal.
                let matches = limb
                    .iter()
                    .zip(sk.main[lane].iter())
                    .filter(|(a, b)| a == b)
                    .count();
                assert!(
                    matches * 100 < h.n(),
                    "{}: public artifact {label} main lane {lane} agrees with the \
                     secret key at {matches}/{} coefficient positions -- far above \
                     chance",
                    h.name,
                    h.n()
                );
            }
            for (lane, limb) in poly.anchor.iter().enumerate() {
                if lane >= sk.anchor.len() {
                    continue;
                }
                assert_ne!(
                    limb, &sk.anchor[lane],
                    "{}: public artifact {label} anchor lane {lane} is \
                     BIT-IDENTICAL to the secret key lane",
                    h.name
                );
            }
        }
    }
}

/// A ciphertext must not decrypt under a secret key it was not made for.
/// This is a behavioural check, not a proof: it establishes that the
/// plaintext is not recoverable from the ciphertext by an unrelated key,
/// which is the crude failure mode (a decryption that ignores the key, or a
/// message riding in the clear).
///
/// Run on `secure_128` only: it needs a SECOND full key generation, and the
/// property under test has no config dependence -- the same code path
/// decrypts at every tier.
#[test]
fn g7_ciphertexts_do_not_decrypt_under_an_unrelated_secret_key() {
    let h = harnesses()
        .iter()
        .find(|h| h.name == "secure_128")
        .expect("secure_128 harness");

    let mut rng = ShadowHarvester::with_seed(0xDEAD_BEEF);
    let other = h.ctx.generate_keys_dual_full(&mut rng);

    for m in [1u64, 12345, 65536] {
        let ct = encrypt_seeded(h, m, 0x6720_0000 + m);
        assert_eq!(
            h.ctx.decrypt_dual(&ct, &h.keys.secret_key),
            m,
            "sanity: the right key must recover the message"
        );
        let wrong = h.ctx.decrypt_dual(&ct, &other.secret_key);
        assert_ne!(
            wrong, m,
            "secure_128: a ciphertext decrypted to its plaintext under an \
             UNRELATED secret key -- the ciphertext is not key-bound"
        );
    }
}

// ===========================================================================
// MATRIX COMPLETENESS
//
// A gate matrix whose config list silently shrank would keep passing. This
// pins the shape of the matrix itself.
// ===========================================================================

#[test]
fn matrix_covers_all_four_production_tiers_and_both_modes() {
    let hs = harnesses();
    let names: Vec<&str> = hs.iter().map(|h| h.name).collect();
    assert_eq!(
        names,
        vec![
            "secure_128",
            "secure_128_deep",
            "secure_192",
            "secure_256"
        ],
        "the gate matrix must span every production tier from 128 through 256"
    );
    assert_eq!(MODES.len(), 2, "both FHE modes must be in the matrix");

    // Pin the frame shapes the gates above reason about, so a config change
    // that alters lane counts cannot quietly invalidate the reasoning.
    let expected: [(usize, usize, usize); 4] = [
        // (n, main lanes, anchor lanes)
        (8192, 3, 5),
        (8192, 4, 5),
        (16384, 5, 10),
        (16384, 6, 10),
    ];
    for (h, (n, main, anchor)) in hs.iter().zip(expected) {
        assert_eq!(h.n(), n, "{}: N", h.name);
        assert_eq!(h.main_primes().len(), main, "{}: main lanes", h.name);
        assert_eq!(h.anchor_primes().len(), anchor, "{}: anchor lanes", h.name);
        assert_eq!(h.t(), 65537, "{}: plaintext modulus", h.name);
    }
}
