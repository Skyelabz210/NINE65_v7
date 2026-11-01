use super::*;
use crate::arithmetic::rns::mod_inverse;
use zeroize::Zeroizing;

pub(crate) fn ordinary(ctx: &RNSFHEContext, p: &RNSPolynomial) -> RNSPolynomial {
    RNSPolynomial {
        n: p.n,
        limbs: p
            .limbs
            .iter()
            .zip(&ctx.rns.mont_contexts)
            .map(|(lane, mont)| lane.iter().map(|&v| mont.from_montgomery(v)).collect())
            .collect(),
    }
}

fn montgomery(ctx: &RNSFHEContext, mut limbs: Vec<Vec<u64>>) -> RNSPolynomial {
    for (lane, mont) in limbs.iter_mut().zip(&ctx.rns.mont_contexts) {
        for value in lane {
            *value = mont.to_montgomery(*value);
        }
    }
    RNSPolynomial { n: ctx.n, limbs }
}

pub(super) fn encode(ctx: &RNSFHEContext, values: &[u64]) -> RNSPolynomial {
    montgomery(
        ctx,
        ctx.config
            .primes
            .iter()
            .zip(&ctx.delta_rns)
            .map(|(&q, &delta)| {
                values
                    .iter()
                    .map(|&m| (m as u128 * delta as u128 % q as u128) as u64)
                    .collect()
            })
            .collect(),
    )
}

pub(super) fn balanced_secret<R: FheRng>(
    ctx: &RNSFHEContext,
    weight: usize,
    rng: &mut R,
) -> RNSSecretKey {
    let mut trits = Zeroizing::new(vec![0i8; ctx.n]);
    let mut count = 0;
    while count < weight {
        // N is a power of two, so masking a full uniform word is unbiased.
        let index = rng.next_u64() as usize & (ctx.n - 1);
        if trits[index] == 0 {
            trits[index] = if count < weight / 2 { 1 } else { -1 };
            count += 1;
        }
    }
    RNSSecretKey {
        s: montgomery(
            ctx,
            ctx.config
                .primes
                .iter()
                .map(|&q| {
                    trits
                        .iter()
                        .map(|&s| (s as i128).rem_euclid(q as i128) as u64)
                        .collect()
                })
                .collect(),
        ),
    }
}

pub(crate) fn embed(poly: &RNSPolynomial, n: usize, lanes: usize) -> RNSPolynomial {
    let stride = n / poly.n;
    RNSPolynomial {
        n,
        limbs: poly.limbs[..lanes]
            .iter()
            .map(|lane| {
                let mut output = vec![0; n];
                for (j, &value) in lane.iter().enumerate() {
                    output[j * stride] = value;
                }
                output
            })
            .collect(),
    }
}

// Residue-only nearest division by the last public prime. The secret remains
// the original dense work secret throughout this operation, before embedding.
pub(crate) fn drop_last(
    work: &RNSFHEContext,
    input: &RNSCiphertext,
    active: usize,
) -> RNSCiphertext {
    let special = work.config.primes[active - 1];
    let apply = |poly: &RNSPolynomial| {
        let last_mont = &work.rns.mont_contexts[active - 1];
        let last: Vec<_> = poly.limbs[active - 1]
            .iter()
            .map(|&value| {
                let r = last_mont.from_montgomery(value);
                if r > special / 2 {
                    r as i128 - special as i128
                } else {
                    r as i128
                }
            })
            .collect();
        RNSPolynomial {
            n: work.n,
            limbs: (0..active - 1)
                .map(|lane| {
                    let q = work.config.primes[lane];
                    let mont = &work.rns.mont_contexts[lane];
                    let inverse = mod_inverse(special % q, q);
                    poly.limbs[lane]
                        .iter()
                        .zip(&last)
                        .map(|(&value, &r)| {
                            let x = mont.from_montgomery(value) as i128;
                            mont.to_montgomery(
                                ((x - r).rem_euclid(q as i128) as u128 * inverse as u128
                                    % q as u128) as u64,
                            )
                        })
                        .collect()
                })
                .collect(),
        }
    };
    RNSCiphertext {
        c0: apply(&input.c0),
        c1: apply(&input.c1),
        num_primes: active - 1,
    }
}

pub(super) fn decode(
    ctx: &RNSFHEContext,
    input: &RNSCiphertext,
    key: &RNSSecretKey,
) -> Result<Vec<u64>, SourceError> {
    let c0 = ordinary(ctx, &input.c0);
    let c1 = ordinary(ctx, &input.c1);
    let secret = Zeroizing::new(ordinary(ctx, &key.s));
    let phase = Zeroizing::new(
        ctx.config
            .primes
            .iter()
            .enumerate()
            .map(|(lane, &q)| {
                ctx.ntt_engines[lane]
                    .multiply(&c1.limbs[lane], &secret.limbs[lane])
                    .iter()
                    .zip(&c0.limbs[lane])
                    .map(|(&a, &b)| ((a as u128 + b as u128) % q as u128) as u64)
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>(),
    );
    let scaler =
        CanonicalScaleRound::new(&ctx.config.primes, ctx.t).map_err(|_| SourceError::Decode)?;
    (0..ctx.n)
        .map(|j| {
            scaler
                .scale_round(&phase.iter().map(|lane| lane[j]).collect::<Vec<_>>())
                .map_err(|_| SourceError::Decode)
        })
        .collect()
}

pub(super) fn digest(
    family: &[u8; 32],
    operation: &[u8],
    parents: &[[u8; 32]],
    raw: &RNSCiphertext,
    bound: U512,
) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"NINE65-public-refresh-source-v1");
    hash.update(family);
    hash.update((operation.len() as u64).to_le_bytes());
    hash.update(operation);
    hash.update((parents.len() as u64).to_le_bytes());
    for parent in parents {
        hash.update(parent);
    }
    hash.update((raw.num_primes as u64).to_le_bytes());
    hash.update((raw.c0.n as u64).to_le_bytes());
    for poly in [&raw.c0, &raw.c1] {
        for lane in &poly.limbs {
            for value in lane {
                hash.update(value.to_le_bytes());
            }
        }
    }
    for value in [bound.d0, bound.d1, bound.d2, bound.d3] {
        hash.update(value.to_le_bytes());
    }
    hash.finalize().into()
}

// Bind the actual public keys and exact plan, as well as a fresh nonce. This
// remains a domain fingerprint if a research RNG accidentally repeats a nonce.
pub(super) fn derive_family_id(
    plan: &PublicRefreshSourcePlan,
    public_key: &RNSPublicKey,
    switch: &RNSHybridGadgetKey,
    nonce: [u8; 32],
) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"NINE65-public-refresh-key-family-v1");
    hash.update(nonce);
    for config in [&plan.work, &plan.source] {
        for value in [
            config.n as u64,
            config.t,
            config.eta as u64,
            config.primes.len() as u64,
        ] {
            hash.update(value.to_le_bytes());
        }
        for value in &config.primes {
            hash.update(value.to_le_bytes());
        }
    }
    hash.update((plan.source_weight as u64).to_le_bytes());
    hash.update(plan.base_bits.to_le_bytes());
    let polys = [&public_key.pk0, &public_key.pk1]
        .into_iter()
        .chain(switch.rlk.iter().flatten().flat_map(|(a, b)| [a, b]));
    for poly in polys {
        for lane in &poly.limbs {
            for value in lane {
                hash.update(value.to_le_bytes());
            }
        }
    }
    hash.finalize().into()
}
