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
}
