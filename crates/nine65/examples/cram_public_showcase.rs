//! A runnable, correctness-checked tour of the public CRAM evaluator.
//!
//! Run from the repository root:
//! cargo run --offline -p nine65 --example cram_public_showcase

use nine65::entropy::SecureRng;
use nine65::ops::cram_public::CramPublicEvaluator;
use nine65::params::secure_configs::SecureConfig;

// Public coefficient vectors: these are arithmetic-kernel checks, separate
// from the encrypted operations below. They do not implement plaintext divide.
fn check_shared_factor_bfv_rescale() {
    use nine65::arithmetic::exact_scale_round::ExactScaleRound;

    let main = [17, 97];
    let aux = [193, 257];
    let q = 17 * 97i128;
    let scaler = ExactScaleRound::new(&main, &aux, 3, 1).unwrap();
    let inputs = [-1649i128, -1100, -550, -275, 0, 275, 550, 1100, 1649];
    let expected = [-3i128, -2, -1, -1, 0, 1, 1, 2, 3];
    for (x, quotient) in inputs.into_iter().zip(expected) {
        let z = 3 * x + q / 2;
        let remainder = z.rem_euclid(q);
        assert_eq!(z - remainder, q * quotient);
        let residues = |basis: &[u64]| {
            basis
                .iter()
                .map(|&m| x.rem_euclid(m as i128) as u64)
                .collect::<Vec<_>>()
        };
        let mut got = [0; 2];
        scaler
            .scale_round(&residues(&main), &residues(&aux), &mut got)
            .unwrap();
        for (lane, &modulus) in main.iter().enumerate() {
            assert_eq!(q % modulus as i128, 0); // Q is a nonunit on both lanes.
            assert_eq!(got[lane], quotient.rem_euclid(modulus as i128) as u64);
        }
    }
    println!("BFV coefficient kernel: floor((3*X+824)/1649) = {expected:?} [all main residues verified; Q shares both lane factors]");
}

#[cfg(feature = "exact_transcendentals_backend")]
fn check_shared_factor_s8_witness() {
    use exact_transcendentals::chimera_division::ChimeraLane;
    use exact_transcendentals::cram_ct::{AuxResidueSet, CramCiphertext};

    let inputs = [612i128, -3006, 4200, 0, 66, -12, 6];
    let expected = [102i128, -501, 700, 0, 11, -2, 1];
    let aux = AuxResidueSet::select_for_divisor(6, 1000).unwrap();
    // Unit payload: deliberately no encrypted BFV ciphertext or rescale adapter.
    let witness = CramCiphertext::wrap_with_fpd_aux((), &inputs, None, &aux);
    let basis = witness.topology.basis;
    let (out, plan) = witness
        .cram_rescale_by_scalar_fpd(6, 1000, |(), _| ())
        .unwrap();
    assert_eq!(plan.primary, ChimeraLane::FusedPiggyback);
    assert_eq!(plan.gcd_with_basis, 6);
    assert_eq!(out.topology.basis, basis);
    assert_eq!(out.witness.c0_signature.signatures.len(), expected.len());
    for ((signature, quotient), numerator) in out
        .witness
        .c0_signature
        .signatures
        .iter()
        .zip(expected)
        .zip(inputs)
    {
        assert_eq!(numerator, 6 * quotient);
        for (&residue, &modulus) in signature.residues.iter().zip(basis.moduli()) {
            assert_eq!(residue, quotient.rem_euclid(modulus as i128) as u32);
        }
    }
    println!("S8 witness kernel: {inputs:?} / 6 = {expected:?} [all eight lane residues verified; gcd(6, S8 product)=6; no encrypted payload]");
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    check_shared_factor_bfv_rescale();
    #[cfg(feature = "exact_transcendentals_backend")]
    check_shared_factor_s8_witness();

    let config = SecureConfig::secure_128_deep();
    let mut evaluator = CramPublicEvaluator::new(&config.config);
    let mut rng = SecureRng::new();
    let (public_keys, client_keys) = evaluator.keygen_with_rng(&mut rng);

    let a = evaluator.encrypt_with_rng(6, &client_keys.public_key, &mut rng);
    let b = evaluator.encrypt_with_rng(7, &client_keys.public_key, &mut rng);

    println!("NINE65 CRAM public evaluator");
    println!(
        "Config: secure_128_deep, N={}",
        evaluator.context().config.n
    );

    let sum = evaluator.add(&a, &b);
    let product = evaluator.mul(&a, &b, &public_keys)?;
    let scaled = evaluator.mul_plain(&a, 97);
    let restored = evaluator.exact_divide(&scaled, 97)?;

    for (label, ciphertext, expected) in [
        ("encrypted 6 + 7", &sum, 13),
        ("encrypted 6 × 7", &product, 42),
        ("encrypted (6 × 97) ÷ 97", &restored, 6),
    ] {
        let actual = evaluator.decrypt(ciphertext, &client_keys);
        if actual != expected {
            return Err(format!("{label}: expected {expected}, got {actual}").into());
        }
        println!("{label} = {actual} [verified by client decryption]");
    }

    let non_unit = evaluator.context().config.primes[0];
    if evaluator.exact_divide(&a, non_unit).is_ok() {
        return Err("non-unit divisor was accepted".into());
    }
    println!("CramPublicEvaluator::exact_divide by non-unit {non_unit} was refused [verified; the general encrypted division adapter is not enabled]");
    println!("{}", evaluator.ledger().report());
    println!("Refresh was not exercised here. PublicRefreshCircuit is a separate research opt-in; legacy Clockwork bootstrap remains disabled.");

    Ok(())
}
