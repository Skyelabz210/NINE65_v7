//! CRAM-CT wrapper around `DualRNSCiphertext`.
//!
//! Wires the `exact_transcendentals::cram_ct::CramCiphertext<C>` shell
//! against NINE65's `DualRNSCiphertext`. The witness signature extracts
//! the first RNS lane's coefficients (`c0.main[0]`) as a per-coefficient
//! S8 fingerprint — small (each entry is a residue mod the first lane
//! prime, typically a 30-bit value), invariant under decrypt, and
//! consistent under homomorphic operations. The witness is a *fingerprint*,
//! not a replacement for the security-bearing RNS layer.
//!
//! Each homomorphic op runs the underlying NINE65 routine first
//! (`add_dual`, `mul_dual_public`, ...), then re-extracts the signature
//! from the new ciphertext rather than evolving it locally. This keeps
//! the witness tightly synchronised with the actual ciphertext, which
//! matters because BFV operations may produce intermediate quantities
//! that wrap the lane-0 modulus — the local-evolution path used in the
//! generic `cram_add` would diverge.

#![cfg(feature = "exact_transcendentals_backend")]

use exact_transcendentals::cram_ct::{
    default_phase_locks, CramCiphertext, CramOpError, CramWitnessState, S8_CHIMERA_V1,
};
use exact_transcendentals::lane_projector::PolynomialS8Signature;

use crate::ops::rns_fhe::{DualRNSCiphertext, DualRNSEvalKey, RNSFHEContext};

/// Wrap a `DualRNSCiphertext` with the canonical `S8_CHIMERA_V1` topology
/// and default phase-lock graph. Witness signature = `c0.main[0]` projected
/// onto S8.
pub fn wrap_dual_rns(ct: DualRNSCiphertext) -> CramCiphertext<DualRNSCiphertext> {
    let coeffs = lane0_as_i128(&ct);
    CramCiphertext::wrap_default(ct, &coeffs, None)
}

/// Wrap two ciphertexts and run a `cram_add` whose underlying base op is
/// `RNSFHEContext::add_dual`. Re-extracts the signature from the result
/// rather than evolving it — keeps the witness in lock-step with the
/// post-op ciphertext.
pub fn cram_add_dual(
    ctx: &RNSFHEContext,
    a: CramCiphertext<DualRNSCiphertext>,
    b: CramCiphertext<DualRNSCiphertext>,
) -> Result<CramCiphertext<DualRNSCiphertext>, CramOpError> {
    a.verify().map_err(CramOpError::InputVerifyFailed)?;
    b.verify().map_err(CramOpError::InputVerifyFailed)?;
    let new_base = ctx.add_dual(&a.base, &b.base);
    rewrap_after_op(new_base, a.witness.op_counter.max(b.witness.op_counter) + 1)
}

/// Wrap two ciphertexts and run a `cram_mul` whose underlying base op is
/// `RNSFHEContext::mul_dual_public`. Eval key required.
pub fn cram_mul_dual(
    ctx: &RNSFHEContext,
    a: CramCiphertext<DualRNSCiphertext>,
    b: CramCiphertext<DualRNSCiphertext>,
    eval_key: &DualRNSEvalKey,
) -> Result<CramCiphertext<DualRNSCiphertext>, CramOpError> {
    a.verify().map_err(CramOpError::InputVerifyFailed)?;
    b.verify().map_err(CramOpError::InputVerifyFailed)?;
    let new_base = ctx
        .mul_dual_public(&a.base, &b.base, eval_key)
        .map_err(|_| CramOpError::OutputVerifyFailed(
            exact_transcendentals::cram_ct::LockFailure::TopologyIllFormed,
        ))?;
    rewrap_after_op(new_base, a.witness.op_counter.max(b.witness.op_counter) + 1)
}

// ─── Helpers ──────────────────────────────────────────────────────────────

fn lane0_as_i128(ct: &DualRNSCiphertext) -> Vec<i128> {
    ct.c0.main[0].iter().map(|&x| x as i128).collect()
}

// ─── Division seam (FPD) ──────────────────────────────────────────────────
//
// The add/mul path above fingerprints lane 0, which is cheap and needs no
// reconstruction. That is NOT sufficient for division: Fused Piggyback
// Division recovers the winding through an auxiliary lane coprime to the
// divisor, and it needs `x mod p_aux` for the TRUE coefficient x. Lane-0
// residues cannot supply it — `(x mod p0) mod 23 != x mod 23` in general.
//
// So the division seam projects the real centered coefficient. That is a
// deliberate boundary crossing, confined to the ingestion point of a
// division, and it is bounded: `AuxResidueSet::from_coeffs` takes `i128`,
// so a config whose centered range exceeds i128 CANNOT be lifted. We refuse
// rather than truncate — same fail-closed posture as FPD's own
// `BoundInsufficient`.

/// Auxiliary primes for FPD, coprime to the S8 safe basis
/// {2,3,5,7,11,13,17,19} by construction.
pub const FPD_AUX_PRIMES: &[u32] = &[23, 29, 31, 37, 41, 43, 47];

/// Why a ciphertext could not be lifted into the CRAM division lane.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CramLiftError {
    /// The context's coefficient modulus is too wide for the `i128` witness
    /// API. `secure_192` (Q=146 bits) and `secure_256` (Q=175 bits) hit this;
    /// `secure_128` (90), `secure_128_deep` (119) and `hardware_opt` (90)
    /// do not.
    ModulusTooWideForWitness { q_bits: u32 },
    /// An aux prime shares a factor with the divisor, so it cannot carry the
    /// piggyback lane for this division.
    AuxSharesFactorWithDivisor { aux: u32, divisor: i128 },
}

/// True iff centered coefficients for this context fit the `i128` witness API.
///
/// `q_product == 0` is this codebase's sentinel for "Q did not fit u128"
/// (see `RNSFHEContext::try_new`), so it is disqualifying on its own.
pub fn cram_witness_capacity_ok(ctx: &RNSFHEContext) -> bool {
    ctx.q_product != 0 && ctx.q_product < (1u128 << 127)
}

/// Project `c0` to centered integer coefficients in `[-Q/2, Q/2)`.
///
/// This reconstructs against the main basis — the same operation
/// `canonicalize_dual_anchor` already performs in the multiply path — and is
/// the reason this function is confined to the division boundary.
fn c0_centered_i128(
    ctx: &RNSFHEContext,
    ct: &DualRNSCiphertext,
) -> Result<Vec<i128>, CramLiftError> {
    if !cram_witness_capacity_ok(ctx) {
        return Err(CramLiftError::ModulusTooWideForWitness {
            q_bits: if ctx.q_product == 0 {
                128
            } else {
                128 - ctx.q_product.leading_zeros()
            },
        });
    }
    let level = ct.c0.main.len();
    let q = ctx.q_product;
    let half = q >> 1;
    let mut residues = vec![0u64; level];
    let mut out = Vec::with_capacity(ct.c0.n);
    for i in 0..ct.c0.n {
        for (j, limb) in ct.c0.main.iter().enumerate() {
            residues[j] = limb[i];
        }
        // Q < 2^127 was checked above, so the reconstruction fits the low
        // 128 bits and the centered value fits i128.
        let v = ctx.rns.to_u256_level(&residues, level).lo;
        out.push(if v > half {
            (v as i128) - (q as i128)
        } else {
            v as i128
        });
    }
    Ok(out)
}

/// Lift a `DualRNSCiphertext` into CRAM residue space **with the FPD
/// auxiliary lane populated**, so the division path is reachable.
///
/// Unlike [`wrap_dual_rns`], this carries `c0_aux`, which
/// `CramCiphertext::cram_rescale_by_scalar_fpd` requires; without it that
/// call returns `DivisionLaneNotImplemented` regardless of the divisor.
pub fn wrap_dual_rns_fpd(
    ctx: &RNSFHEContext,
    ct: DualRNSCiphertext,
    aux_primes: &[u32],
) -> Result<CramCiphertext<DualRNSCiphertext>, CramLiftError> {
    let coeffs = c0_centered_i128(ctx, &ct)?;
    Ok(CramCiphertext::wrap_with_fpd_aux(
        ct, &coeffs, None, aux_primes,
    ))
}

/// Select aux primes from [`FPD_AUX_PRIMES`] that are coprime to `divisor`.
pub fn aux_primes_for(divisor: i128) -> Result<Vec<u32>, CramLiftError> {
    let d = divisor.unsigned_abs();
    let picked: Vec<u32> = FPD_AUX_PRIMES
        .iter()
        .copied()
        .filter(|&p| d % (p as u128) != 0)
        .collect();
    if picked.is_empty() {
        return Err(CramLiftError::AuxSharesFactorWithDivisor {
            aux: FPD_AUX_PRIMES[0],
            divisor,
        });
    }
    Ok(picked)
}

fn rewrap_after_op(
    new_base: DualRNSCiphertext,
    op_counter: i128,
) -> Result<CramCiphertext<DualRNSCiphertext>, CramOpError> {
    let coeffs = lane0_as_i128(&new_base);
    let topology = S8_CHIMERA_V1.clone();
    let locks = default_phase_locks();
    let mut witness = CramWitnessState::from_coeffs(&coeffs, None, &locks);
    witness.op_counter = op_counter;
    // Rebuild lock evidence at the post-op counter so the boundary
    // corridor reflects accumulated work.
    witness.lock_witness = exact_transcendentals::cram_ct::LockWitnessSet::compute(
        &locks,
        &PolynomialS8Signature::from_coeffs(&coeffs),
        op_counter,
    );
    let out = CramCiphertext {
        base: new_base,
        topology,
        locks,
        witness,
    };
    out.verify().map_err(CramOpError::OutputVerifyFailed)?;
    Ok(out)
}

// ─── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entropy::ShadowHarvester;
    use crate::ops::rns_fhe::DualRNSFullKeySet;
    use crate::params::secure_configs::SecureConfig;

    fn fresh_ctx_and_full_keys() -> (RNSFHEContext, DualRNSFullKeySet) {
        let cfg = SecureConfig::secure_128();
        let ctx = RNSFHEContext::new(&cfg.config);
        let mut rng = ShadowHarvester::with_seed(42);
        let keys = ctx.generate_keys_dual_full(&mut rng);
        (ctx, keys)
    }

    #[test]
    fn wrap_dual_rns_after_encrypt_passes_metadata_check() {
        let (ctx, keys) = fresh_ctx_and_full_keys();
        let mut rng = ShadowHarvester::with_seed(7);
        let ct = ctx.encrypt_dual(42, &keys.public_key, &mut rng);
        let wrapped = wrap_dual_rns(ct);
        assert!(wrapped.verify_metadata(), "metadata must verify");
        assert!(wrapped.verify().is_ok(), "full verify must pass");
        assert_eq!(wrapped.witness.op_counter, 0);
    }

    #[test]
    fn cram_add_dual_round_trip_decrypts_to_sum() {
        let (ctx, keys) = fresh_ctx_and_full_keys();
        let mut rng = ShadowHarvester::with_seed(13);
        let a = ctx.encrypt_dual(7, &keys.public_key, &mut rng);
        let b = ctx.encrypt_dual(11, &keys.public_key, &mut rng);

        let wa = wrap_dual_rns(a);
        let wb = wrap_dual_rns(b);
        let sum = cram_add_dual(&ctx, wa, wb).unwrap();
        assert_eq!(sum.witness.op_counter, 1);
        assert!(sum.verify().is_ok());

        let recovered = ctx.decrypt_dual(&sum.base, &keys.secret_key);
        let expected = (7u64 + 11) % ctx.t;
        assert_eq!(recovered, expected, "BFV add must still decrypt to a + b");
    }

    #[test]
    fn cram_add_dual_chain_keeps_op_counter_in_sync() {
        let (ctx, keys) = fresh_ctx_and_full_keys();
        let mut rng = ShadowHarvester::with_seed(2);
        let mut acc = wrap_dual_rns(ctx.encrypt_dual(0, &keys.public_key, &mut rng));
        for k in 1..=5u64 {
            let b = wrap_dual_rns(ctx.encrypt_dual(k, &keys.public_key, &mut rng));
            acc = cram_add_dual(&ctx, acc, b).unwrap();
        }
        assert_eq!(acc.witness.op_counter, 5);
        let recovered = ctx.decrypt_dual(&acc.base, &keys.secret_key);
        // 0+1+2+3+4+5 = 15.
        assert_eq!(recovered, 15 % ctx.t);
    }

    #[test]
    fn cram_mul_dual_round_trip_decrypts_to_product() {
        let (ctx, keys) = fresh_ctx_and_full_keys();
        let mut rng = ShadowHarvester::with_seed(99);
        let a = ctx.encrypt_dual(3, &keys.public_key, &mut rng);
        let b = ctx.encrypt_dual(5, &keys.public_key, &mut rng);

        let wa = wrap_dual_rns(a);
        let wb = wrap_dual_rns(b);
        let prod = cram_mul_dual(&ctx, wa, wb, &keys.eval_key).unwrap();
        assert!(prod.verify().is_ok());
        assert_eq!(prod.witness.op_counter, 1);

        let recovered = ctx.decrypt_dual(&prod.base, &keys.secret_key);
        let expected = (3u64 * 5) % ctx.t;
        assert_eq!(recovered, expected, "BFV mul must still decrypt to a * b");
    }

    #[test]
    fn cram_add_dual_signature_changes_after_op() {
        let (ctx, keys) = fresh_ctx_and_full_keys();
        let mut rng = ShadowHarvester::with_seed(1);
        let a1 = wrap_dual_rns(ctx.encrypt_dual(1, &keys.public_key, &mut rng));
        let b1 = wrap_dual_rns(ctx.encrypt_dual(2, &keys.public_key, &mut rng));
        let pre_sig = a1.witness.c0_signature.signatures.clone();
        let sum = cram_add_dual(&ctx, a1, b1).unwrap();
        let post_sig = sum.witness.c0_signature.signatures;
        assert_ne!(pre_sig, post_sig, "signature must change after add");
    }

    // ─── Division seam ────────────────────────────────────────────────────

    /// The centered projection must be EXACT, not approximate: reducing each
    /// centered coefficient back against every main prime must reproduce the
    /// original lane residue, for every coefficient. Full sweep, no sampling.
    #[test]
    fn centered_projection_round_trips_exactly_on_every_coefficient() {
        let (ctx, keys) = fresh_ctx_and_full_keys();
        let mut rng = ShadowHarvester::with_seed(7);
        let ct = ctx.encrypt_dual(12345, &keys.public_key, &mut rng);

        let centered = c0_centered_i128(&ctx, &ct).expect("secure_128 must lift");
        assert_eq!(
            centered.len(),
            ct.c0.n,
            "projection must cover every coefficient, not a prefix"
        );

        let q = ctx.q_product as i128;
        let mut checked = 0usize;
        for (i, &c) in centered.iter().enumerate() {
            assert!(
                c >= -(q / 2) - 1 && c < q,
                "coefficient {i} = {c} outside the centered range"
            );
            for (j, &p) in ctx.config.primes[..ct.c0.main.len()].iter().enumerate() {
                let back = c.rem_euclid(p as i128) as u64;
                assert_eq!(
                    back, ct.c0.main[j][i],
                    "lane {j} coeff {i}: centered value does not reduce back to the \
                     original residue — the projection is lossy"
                );
            }
            checked += 1;
        }
        assert_eq!(
            checked, ct.c0.n,
            "must sweep every coefficient, not a sample"
        );
    }

    /// The seam that matters: `wrap_dual_rns_fpd` populates `c0_aux`, and
    /// `wrap_dual_rns` does not. Without `c0_aux` the FPD division lane is
    /// unreachable by construction, so this is the difference between the
    /// division path existing and not existing.
    #[test]
    fn fpd_wrap_populates_the_division_lane_and_default_wrap_does_not() {
        let (ctx, keys) = fresh_ctx_and_full_keys();
        let mut rng = ShadowHarvester::with_seed(9);
        let ct = ctx.encrypt_dual(42, &keys.public_key, &mut rng);

        let plain = wrap_dual_rns(ct.clone());
        assert!(
            plain.witness.c0_aux.is_none(),
            "control: the default wrap must NOT carry an aux lane — if this \
             ever becomes Some, this test no longer distinguishes the two paths"
        );

        let aux = aux_primes_for(4).expect("4 is coprime to the aux catalogue");
        let lifted = wrap_dual_rns_fpd(&ctx, ct, &aux).expect("secure_128 must lift");
        let set = lifted
            .witness
            .c0_aux
            .as_ref()
            .expect("FPD wrap must carry the aux lane");
        assert_eq!(
            set.residues.len(),
            lifted.witness.poly_len(),
            "one aux residue vector per tracked coefficient"
        );
        assert!(lifted.verify().is_ok(), "lifted ciphertext must verify");
    }

    /// Negative control: a config whose centered range exceeds `i128` must be
    /// REFUSED, not silently truncated. `secure_192` has Q = 146 bits.
    #[test]
    fn wide_config_is_refused_rather_than_truncated() {
        let cfg = SecureConfig::secure_192();
        let ctx = RNSFHEContext::new(&cfg.config);
        assert!(
            !cram_witness_capacity_ok(&ctx),
            "secure_192 (Q=146 bits) must not be reported as witness-capable"
        );

        let mut rng = ShadowHarvester::with_seed(3);
        let keys = ctx.generate_keys_dual_full(&mut rng);
        let ct = ctx.encrypt_dual(5, &keys.public_key, &mut rng);

        match wrap_dual_rns_fpd(&ctx, ct, FPD_AUX_PRIMES) {
            Err(CramLiftError::ModulusTooWideForWitness { q_bits }) => {
                assert!(
                    q_bits > 127,
                    "refusal must report a genuinely over-wide modulus, got {q_bits} bits"
                );
            }
            other => panic!("secure_192 must be refused, got {other:?}"),
        }
    }

    /// Aux selection must drop any prime sharing a factor with the divisor —
    /// that is the precondition FPD relies on.
    #[test]
    fn aux_selection_excludes_primes_sharing_a_factor_with_the_divisor() {
        let picked = aux_primes_for(23 * 29).unwrap();
        assert!(
            !picked.contains(&23) && !picked.contains(&29),
            "23 and 29 divide the divisor and must be excluded, got {picked:?}"
        );
        assert!(!picked.is_empty(), "remaining catalogue must still be usable");
        for p in &picked {
            assert_ne!(
                (23i128 * 29) % (*p as i128),
                0,
                "every retained aux prime must be coprime to the divisor"
            );
        }
    }
}
