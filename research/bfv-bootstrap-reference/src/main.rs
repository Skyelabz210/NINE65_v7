//! Independent implementation reference, outside NINE65's production runtime.
//! Evaluator calls receive public evaluation keys and never a debug secret.

use feanor_math::homomorphism::Homomorphism;
use feanor_math::integer::{BigIntRing, int_cast};
use feanor_math::primitive_int::StaticRing;
use feanor_math::ring::*;
use feanor_math::rings::extension::FreeAlgebraStore;
use feanor_math::rings::zn::ZnRingStore;
use feanor_math::seq::*;
use fheanor::bfv::bootstrap::{SparseKeyEncapsulationKey, ThinBootstrapper};
use fheanor::bfv::{
    BFVInstantiation, Ciphertext, CiphertextRing, KeySwitchKey, Pow2BFV, RelinKey,
    SecretKeyDistribution,
};
use fheanor::gadget_product::digits::RNSGadgetVectorDigitIndices;
use fheanor::number_ring::galois::GaloisGroupEl;
use serde_json::json;
use std::time::Instant;

const P: u64 = 65537;

fn power(mut a: u64, mut e: u64) -> u64 {
    let mut out = 1;
    while e != 0 {
        if e & 1 != 0 {
            out = out * a % P;
        }
        a = a * a % P;
        e >>= 1;
    }
    out
}

// Independent integer-only negacyclic multiplication oracle. The reference
// library is not used to calculate the expected plaintext products.
fn transform(a: &mut [u64], root: u64) {
    let n = a.len();
    let mut j = 0;
    for i in 1..n {
        let mut bit = n / 2;
        while j & bit != 0 {
            j ^= bit;
            bit >>= 1;
        }
        j ^= bit;
        if i < j {
            a.swap(i, j);
        }
    }
    let mut width = 2;
    while width <= n {
        let step = power(root, (n / width) as u64);
        for chunk in a.chunks_exact_mut(width) {
            let mut w = 1;
            for k in 0..width / 2 {
                let left = chunk[k];
                let right = chunk[k + width / 2] * w % P;
                chunk[k] = (left + right) % P;
                chunk[k + width / 2] = (left + P - right) % P;
                w = w * step % P;
            }
        }
        width *= 2;
    }
}

fn square_plain(a: &[u64]) -> Vec<u64> {
    let n = a.len();
    let psi = power(3, (P - 1) / (2 * n as u64));
    assert_eq!(power(psi, n as u64), P - 1);
    let mut twist = 1;
    let mut out: Vec<u64> = a
        .iter()
        .map(|&v| {
            let result = v * twist % P;
            twist = twist * psi % P;
            result
        })
        .collect();
    let root = psi * psi % P;
    transform(&mut out, root);
    out.iter_mut().for_each(|v| *v = *v * *v % P);
    transform(&mut out, power(root, P - 2));
    let inverse_psi = power(psi, P - 2);
    let mut scale = power(n as u64, P - 2);
    for value in &mut out {
        *value = *value * scale % P;
        scale = scale * inverse_psi % P;
    }
    out
}

fn option(args: &[String], name: &str, default: usize) -> Result<usize, String> {
    match args.iter().position(|arg| arg == name) {
        Some(index) => args
            .get(index + 1)
            .ok_or_else(|| format!("missing {name}"))?
            .parse()
            .map_err(|_| format!("invalid {name}")),
        None => Ok(default),
    }
}

// This boundary receives no secret key or plaintext. The client-side checks in
// main cannot participate in the evaluator's refresh computation.
fn public_refresh(
    bootstrapper: &ThinBootstrapper<Pow2BFV>,
    ciphertext: &CiphertextRing<Pow2BFV>,
    multiply_ring: &CiphertextRing<Pow2BFV>,
    encrypted: Ciphertext<Pow2BFV>,
    relin: &RelinKey<Pow2BFV>,
    galois: &[(GaloisGroupEl, KeySwitchKey<Pow2BFV>)],
    encapsulation: &SparseKeyEncapsulationKey<Pow2BFV>,
) -> Ciphertext<Pow2BFV> {
    bootstrapper.bootstrap_thin(
        ciphertext,
        multiply_ring,
        encrypted,
        relin,
        galois,
        Some(encapsulation),
        None,
    )
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let valid = [
        "--log-n",
        "--rounds",
        "--q-bits",
        "--digit-bound",
        "--transform-levels",
        "--gadget-digits",
        "--pre-squares",
    ];
    if args.len() % 2 != 0
        || args
            .chunks_exact(2)
            .any(|pair| !valid.contains(&pair[0].as_str()))
        || valid
            .iter()
            .any(|flag| args.iter().filter(|arg| arg.as_str() == *flag).count() > 1)
    {
        return Err(format!("expected unique flag/value pairs: {}", valid.join(", ")).into());
    }
    let log_n = option(&args, "--log-n", 10)?;
    let rounds = option(&args, "--rounds", 2)?;
    let q_bits = option(&args, "--q-bits", 820)?;
    let bound = option(&args, "--digit-bound", 32)?;
    let levels = option(&args, "--transform-levels", 4)?;
    let digits_count = option(&args, "--gadget-digits", 5)?;
    let pre_squares = option(&args, "--pre-squares", 2)?;
    if !(6..=15).contains(&log_n)
        || !(1..=100).contains(&rounds)
        || !(17..=128).contains(&bound)
        || !(400..=1200).contains(&q_bits)
        || !(1..=8).contains(&levels)
        || !(1..=16).contains(&digits_count)
        || pre_squares > 16
    {
        return Err("unsupported reference parameters".into());
    }
    let n = 1usize << log_n;
    let started = Instant::now();
    let params = Pow2BFV::new(2 * n);
    let plaintext = params.create_plaintext_ring(int_cast(
        P as i64,
        BigIntRing::RING,
        StaticRing::<i64>::RING,
    ));
    let (ciphertext, multiply_ring) = params.create_ciphertext_rings(q_bits - 15..q_bits);
    let primes: Vec<i64> = ciphertext
        .base_ring()
        .as_iter()
        .map(|ring| *ring.modulus())
        .collect();
    if digits_count > primes.len() {
        return Err("gadget digit count exceeds available RNS factors".into());
    }
    let digits =
        RNSGadgetVectorDigitIndices::select_digits(digits_count, ciphertext.base_ring().len());
    eprintln!(
        "building bootstrap circuit: N={n}, t={P}, Q near {q_bits} bits, error radius={bound}"
    );
    let bootstrapper = ThinBootstrapper::build_pow2(
        &params,
        &plaintext,
        &ciphertext,
        1,
        Some(bound as i64),
        levels,
        &digits,
        None,
    );
    let required = bootstrapper.required_galois_keys(&plaintext);
    eprintln!(
        "circuit built in {} ms; generating {} Galois keys",
        started.elapsed().as_millis(),
        required.len()
    );
    let mut rng = rand::rng();
    let secret = Pow2BFV::gen_sk(&ciphertext, &mut rng, SecretKeyDistribution::UniformTernary);
    let galois = Pow2BFV::gen_gks(&ciphertext, &mut rng, &secret, required, &digits, 3.2);
    let relin = Pow2BFV::gen_rk(&ciphertext, &mut rng, &secret, &digits, 3.2);
    let encapsulation = SparseKeyEncapsulationKey::new(
        bootstrapper.intermediate_plaintext_ring(),
        &ciphertext,
        &secret,
        2,
        32,
        &mut rng,
        3.2,
    );
    let boundary = [0, 1, P - 1, 2, P / 2, P / 2 + 1, 7, P - 2];
    let mut expected: Vec<u64> = (0..n)
        .map(|j| {
            if j < boundary.len() {
                boundary[j]
            } else {
                (113 * j as u64 + 19) % P
            }
        })
        .collect();
    let encode = |values: &[u64]| {
        plaintext.from_canonical_basis(
            values
                .iter()
                .map(|&v| plaintext.base_ring().int_hom().map(v as i32)),
        )
    };
    let mut encrypted = Pow2BFV::enc_sym(
        &plaintext,
        &ciphertext,
        &mut rng,
        &encode(&expected),
        &secret,
        3.2,
    );
    let decoded = Pow2BFV::dec(
        &plaintext,
        &ciphertext,
        Pow2BFV::clone_ct(&ciphertext, &encrypted),
        &secret,
    );
    if !plaintext.eq_el(&decoded, &encode(&expected)) {
        return Err("fresh encryption mismatch".into());
    }
    let initial_budget = Pow2BFV::noise_budget(&plaintext, &ciphertext, &encrypted, &secret);
    // Exercise ciphertext addition and relinearized multiplication before the
    // first refresh; the input is already an evaluated ciphertext.
    let increment = vec![1; n];
    let addend = Pow2BFV::enc_sym(
        &plaintext,
        &ciphertext,
        &mut rng,
        &encode(&increment),
        &secret,
        3.2,
    );
    encrypted = Pow2BFV::hom_add(&ciphertext, encrypted, &addend);
    expected.iter_mut().for_each(|v| *v = (*v + 1) % P);
    for _ in 0..pre_squares {
        encrypted = Pow2BFV::hom_mul(
            &plaintext,
            &ciphertext,
            &multiply_ring,
            Pow2BFV::clone_ct(&ciphertext, &encrypted),
            encrypted,
            &relin,
        );
        expected = square_plain(&expected);
    }
    let decoded = Pow2BFV::dec(
        &plaintext,
        &ciphertext,
        Pow2BFV::clone_ct(&ciphertext, &encrypted),
        &secret,
    );
    if !plaintext.eq_el(&decoded, &encode(&expected)) {
        return Err("pre-refresh evaluated input mismatch".into());
    }
    let mut records = Vec::new();
    for round in 0..rounds {
        let input_budget = Pow2BFV::noise_budget(&plaintext, &ciphertext, &encrypted, &secret);
        let before = Instant::now();
        encrypted = public_refresh(
            &bootstrapper,
            &ciphertext,
            &multiply_ring,
            encrypted,
            &relin,
            &galois,
            &encapsulation,
        );
        let elapsed = before.elapsed().as_millis();
        let decoded = Pow2BFV::dec(
            &plaintext,
            &ciphertext,
            Pow2BFV::clone_ct(&ciphertext, &encrypted),
            &secret,
        );
        if !plaintext.eq_el(&decoded, &encode(&expected)) {
            return Err(format!("refresh plaintext mismatch in round {round}").into());
        }
        let output_budget = Pow2BFV::noise_budget(&plaintext, &ciphertext, &encrypted, &secret);
        encrypted = Pow2BFV::hom_mul(
            &plaintext,
            &ciphertext,
            &multiply_ring,
            Pow2BFV::clone_ct(&ciphertext, &encrypted),
            encrypted,
            &relin,
        );
        expected = square_plain(&expected);
        let decoded = Pow2BFV::dec(
            &plaintext,
            &ciphertext,
            Pow2BFV::clone_ct(&ciphertext, &encrypted),
            &secret,
        );
        if !plaintext.eq_el(&decoded, &encode(&expected)) {
            return Err(format!("post-refresh multiplication mismatch in round {round}").into());
        }
        let after_multiply_budget =
            Pow2BFV::noise_budget(&plaintext, &ciphertext, &encrypted, &secret);
        eprintln!(
            "round {round}: refresh and multiplication exact for all {n} coefficients; refresh {elapsed} ms; budgets {input_budget} -> {output_budget} -> {after_multiply_budget}"
        );
        records.push(
            json!({"round": round, "checked_coefficients": n, "refresh_ms": elapsed,
            "input_budget_bits": input_budget, "output_budget_bits": output_budget,
            "after_multiply_budget_bits": after_multiply_budget}),
        );
    }
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "schema": "nine65-bfv-bootstrap-reference-v1", "reference_version": "fheanor 0.11.9",
            "n": n, "plaintext_modulus": P, "requested_q_bits": q_bits,
            "ciphertext_primes": primes,
            "transform_levels": levels, "gadget_digits": digits_count, "pre_squares": pre_squares,
            "initial_budget_bits": initial_budget, "pre_refresh_additions": 1,
            "digit_bound": bound, "sparse_encapsulation_weight": 32, "secret_distribution": "uniform_ternary",
            "galois_keys": galois.len(), "evaluator_debug_secret": false,
            "security_attestation": null, "native_nine65_refresh_enabled": false,
            "total_ms": started.elapsed().as_millis(), "rounds": records,
        }))?
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn plaintext_oracle_matches_schoolbook() {
        for n in [8, 16, 32, 64] {
            let input: Vec<u64> = (0..n).map(|j| (1237 * j as u64 + 65530) % P).collect();
            let mut expected = vec![0; n];
            for i in 0..n {
                for j in 0..n {
                    let product = input[i] * input[j] % P;
                    let term = if i + j >= n {
                        (P - product) % P
                    } else {
                        product
                    };
                    expected[(i + j) % n] = (expected[(i + j) % n] + term) % P;
                }
            }
            assert_eq!(square_plain(&input), expected);
        }
    }
}
