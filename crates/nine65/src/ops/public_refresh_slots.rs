//! Research-only public return from source-coefficient slots to a work-ring
//! polynomial embedded in a larger ring. No refresh admission is issued.
//!
//! Slot order is +5^i followed by -5^i modulo 2N. The first `source_n`
//! positive-row slots become coefficients at multiples of `N/source_n`.
//! Other input slots are deliberately ignored. Diagonals are generated from
//! that explicit matrix; an N-by-N matrix is never allocated.

use super::direct_slot_phase::SlotEncoding;
use super::rns_fhe::{RNSCiphertext, RNSFHEContext, RNSSecretKey};
use super::rns_galois::{validate_main, PreparedRNSGaloisKey, RNSGaloisEvaluator};
use crate::arithmetic::RNSPolynomial;
use crate::entropy::FheRng;
use crate::errors::{Nine65Error, Nine65Result};

#[path = "public_refresh_slots_aux.rs"]
mod auxiliary;

fn failure(reason: impl Into<String>) -> Nine65Error {
    Nine65Error::BootstrapFailed {
        reason: reason.into(),
    }
}

fn power(mut a: u64, mut e: usize, q: u64) -> u64 {
    let mut y = 1;
    while e != 0 {
        if e & 1 != 0 {
            y = (y as u128 * a as u128 % q as u128) as u64;
        }
        a = (a as u128 * a as u128 % q as u128) as u64;
        e >>= 1;
    }
    y
}

// Minimize 2*B+G for B*G=cyclic. When the two power-of-two
// choices tie, keep the smaller B to halve the cached baby payload.
fn inverse_baby_count(cyclic: usize) -> usize {
    1usize << ((cyclic.ilog2() - 1) / 2)
}

/// Deterministic ideal-grid phase-error bound Eout <= factor*Ein + added.
/// The caller must apply its wide-integer decoding and return certificates.
#[derive(Clone, Debug)]
pub(crate) struct SlotReturnCertificate {
    pub input_error_factor: u128,
    pub added_error: u128,
    pub ciphertext_babies: usize,
    pub plaintext_diagonals: usize,
    pub galois_calls: usize,
}

pub(crate) struct SlotReturnKeys {
    baby_step: PreparedRNSGaloisKey,
    giant_step: PreparedRNSGaloisKey,
    conjugate: PreparedRNSGaloisKey,
}

impl SlotReturnKeys {
    pub(crate) fn published_ciphertexts(&self) -> usize {
        self.baby_step.published_ciphertexts()
            + self.giant_step.published_ciphertexts()
            + self.conjugate.published_ciphertexts()
    }
}

// Values are cyclic-NTT transformed, psi-twisted, MONTGOMERY residues.
// Plaintext NTT diagonals are standard; their Montgomery product is standard.
struct CachedBaby {
    components: [Vec<Vec<u64>>; 2],
}

pub(crate) struct PublicSlotReturn<'a> {
    ctx: &'a RNSFHEContext,
    source_n: usize,
    encoding: SlotEncoding,
    baby_count: usize,
    giant_count: usize,
    galois: RNSGaloisEvaluator<'a>,
    powers: Vec<u64>,
    certificate: SlotReturnCertificate,
}

impl<'a> PublicSlotReturn<'a> {
    pub(crate) fn new(ctx: &'a RNSFHEContext, source_n: usize) -> Nine65Result<Self> {
        if ctx.t != 65_537
            || source_n < 2
            || !source_n.is_power_of_two()
            || ctx.n != 4 * source_n
            || ctx.n > 32_768
        {
            return Err(failure(
                "slot return requires p=65537 and outer N=4*source N<=32768",
            ));
        }
        let encoding = SlotEncoding::new(ctx.n, ctx.t)?;
        let cyclic = ctx.n / 2;
        let baby_count = inverse_baby_count(cyclic);
        let giant_count = cyclic / baby_count;
        let exact = ctx
            .try_exact_evaluator()
            .map_err(|e| failure(format!("slot return exact capacity: {e:?}")))?;
        let gadget = exact.plan().certificate();
        let switch_error = ctx.n as u128
            * ctx.config.eta as u128
            * ((1u128 << gadget.base_bits) - 1)
            * gadget.digits_per_lane.iter().sum::<usize>() as u128;
        // N diagonals, each with N centered coefficients of magnitude <=p/2.
        let factor = ctx.n as u128 * ctx.n as u128 * (ctx.t / 2) as u128;
        // Baby chains have at most B-1 rotations, plus one conjugation.
        // Horner accumulation adds G-1 switches AFTER plaintext multiplication.
        let added_error = switch_error * (factor * baby_count as u128 + (giant_count - 1) as u128);
        let mut powers = vec![1; 2 * ctx.n];
        for i in 1..powers.len() {
            powers[i] =
                (powers[i - 1] as u128 * encoding.primitive_root() as u128 % ctx.t as u128) as u64;
        }
        Ok(Self {
            ctx,
            source_n,
            encoding,
            baby_count,
            giant_count,
            galois: RNSGaloisEvaluator::new(ctx)?,
            powers,
            certificate: SlotReturnCertificate {
                input_error_factor: factor,
                added_error,
                ciphertext_babies: 2 * baby_count,
                plaintext_diagonals: ctx.n,
                galois_calls: 2 * baby_count + giant_count - 2,
            },
        })
    }

    pub(crate) fn certificate(&self) -> &SlotReturnCertificate {
        &self.certificate
    }

    pub(crate) fn generate_keys<R: FheRng>(
        &self,
        sk: &RNSSecretKey,
        rng: &mut R,
    ) -> Nine65Result<SlotReturnKeys> {
        let modulus = 2 * self.ctx.n as u64;
        let mut prepared = |exponent| {
            let raw = self.galois.generate_key_with_rng(sk, exponent, rng)?;
            self.galois.prepare_key(&raw)
        };
        Ok(SlotReturnKeys {
            baby_step: prepared(power(5, self.giant_count, modulus))?,
            giant_step: prepared(5)?,
            conjugate: prepared(modulus - 1)?,
        })
    }

    fn cache(&self, input: &RNSCiphertext) -> CachedBaby {
        let transform = |poly: &RNSPolynomial| {
            poly.limbs
                .iter()
                .enumerate()
                .map(|(lane, values)| {
                    let mont = &self.ctx.rns.mont_contexts[lane];
                    let engine = &self.ctx.ntt_engines[lane];
                    let twisted: Vec<_> = values
                        .iter()
                        .zip(&engine.psi_powers)
                        .map(|(&v, &psi)| mont.montgomery_mul(v, mont.to_montgomery(psi)))
                        .collect();
                    engine.ntt(&twisted)
                })
                .collect()
        };
        CachedBaby {
            components: [transform(&input.c0), transform(&input.c1)],
        }
    }

    // Reindexed D_(baby*giant): sigma_g(D' * sigma_b(input)). The selected
    // source slot at the reindexed coordinate is sigma_b(slot), while the
    // desired output root is shifted back by sigma_g^-1.
    fn diagonal(&self, giant: usize, sign: usize, baby: usize) -> Nine65Result<Vec<u64>> {
        let n = self.ctx.n;
        let cyclic = n / 2;
        let inverse_giant = power(5, (cyclic - giant) % cyclic, (2 * n) as u64);
        let stride = n / self.source_n;
        let values: Vec<_> = self
            .encoding
            .exponents()
            .iter()
            .enumerate()
            .map(|(slot, &exponent)| {
                let half = slot / cyclic;
                let index = (slot % cyclic + baby * self.giant_count) % cyclic;
                if half ^ sign != 0 || index >= self.source_n {
                    return 0;
                }
                let original_root = exponent * inverse_giant % (2 * n) as u64;
                self.powers
                    [(stride as u64 * original_root * index as u64 % (2 * n) as u64) as usize]
            })
            .collect();
        self.encoding.encode_slots(&values)
    }

    fn add_diagonal(
        &self,
        accumulators: &mut [Vec<Vec<u64>>; 2],
        baby: &CachedBaby,
        polynomial: &[u64],
    ) {
        for (lane, &q) in self.ctx.config.primes.iter().enumerate() {
            let mont = &self.ctx.rns.mont_contexts[lane];
            let engine = &self.ctx.ntt_engines[lane];
            let twisted: Vec<_> = polynomial
                .iter()
                .zip(&engine.psi_powers)
                .map(|(&v, &psi)| {
                    let centered = if v <= self.ctx.t / 2 {
                        v as i128
                    } else {
                        v as i128 - self.ctx.t as i128
                    };
                    let centered = centered.rem_euclid(q as i128) as u64;
                    mont.montgomery_mul(centered, mont.to_montgomery(psi))
                })
                .collect();
            let diagonal = engine.ntt(&twisted);
            for component in 0..2 {
                for ((sum, &a), &b) in accumulators[component][lane]
                    .iter_mut()
                    .zip(&baby.components[component][lane])
                    .zip(&diagonal)
                {
                    let product = mont.montgomery_mul(a, b);
                    let combined = *sum as u128 + product as u128;
                    *sum = if combined >= q as u128 {
                        (combined - q as u128) as u64
                    } else {
                        combined as u64
                    };
                }
            }
        }
    }

    fn finish_sum(&self, components: &[Vec<Vec<u64>>; 2]) -> RNSCiphertext {
        let finish = |lanes: &Vec<Vec<u64>>| RNSPolynomial {
            n: self.ctx.n,
            limbs: lanes
                .iter()
                .enumerate()
                .map(|(lane, values)| {
                    let engine = &self.ctx.ntt_engines[lane];
                    let mont = &self.ctx.rns.mont_contexts[lane];
                    engine
                        .intt(values)
                        .iter()
                        .zip(&engine.psi_inv_powers)
                        .map(|(&v, &psi)| {
                            mont.to_montgomery(mont.montgomery_mul(v, mont.to_montgomery(psi)))
                        })
                        .collect()
                })
                .collect(),
        };
        RNSCiphertext {
            c0: finish(&components[0]),
            c1: finish(&components[1]),
            num_primes: self.ctx.config.primes.len(),
        }
    }

    #[cfg(test)]
    pub(crate) fn apply(
        &self,
        input: &RNSCiphertext,
        keys: &SlotReturnKeys,
    ) -> Nine65Result<RNSCiphertext> {
        self.apply_with_progress(input, keys, &mut |_, _, _| {})
    }

    pub(crate) fn apply_with_progress(
        &self,
        input: &RNSCiphertext,
        keys: &SlotReturnKeys,
        progress: &mut dyn FnMut(&str, usize, usize),
    ) -> Nine65Result<RNSCiphertext> {
        if self.ctx.n <= 64 {
            self.apply_main(input, keys, progress)
        } else {
            self.apply_auxiliary(input, keys, progress)
        }
    }

    fn apply_main(
        &self,
        input: &RNSCiphertext,
        keys: &SlotReturnKeys,
        progress: &mut dyn FnMut(&str, usize, usize),
    ) -> Nine65Result<RNSCiphertext> {
        validate_main(self.ctx, input)?;
        let mut babies = Vec::with_capacity(2 * self.baby_count);
        for sign in 0..2 {
            let mut current = if sign == 0 {
                input.clone()
            } else {
                self.galois.apply_prepared(input, &keys.conjugate)?
            };
            for baby in 0..self.baby_count {
                if baby != 0 {
                    current = self.galois.apply_prepared(&current, &keys.baby_step)?;
                }
                babies.push(self.cache(&current));
                progress("inverse babies", babies.len(), 2 * self.baby_count);
            }
        }
        let mut output = None;
        let mut observed_plain_l1 = 0u128;
        for giant in (0..self.giant_count).rev() {
            let zero = || vec![vec![0; self.ctx.n]; self.ctx.config.primes.len()];
            let mut accumulators = [zero(), zero()];
            for sign in 0..2 {
                for baby in 0..self.baby_count {
                    let diagonal = self.diagonal(giant, sign, baby)?;
                    observed_plain_l1 += diagonal
                        .iter()
                        .map(|&v| v.min(self.ctx.t - v) as u128)
                        .sum::<u128>();
                    self.add_diagonal(
                        &mut accumulators,
                        &babies[sign * self.baby_count + baby],
                        &diagonal,
                    );
                }
            }
            let sum = self.finish_sum(&accumulators);
            output = Some(match output {
                None => sum,
                Some(previous) => self.ctx.add(
                    &self.galois.apply_prepared(&previous, &keys.giant_step)?,
                    &sum,
                ),
            });
            progress("inverse giants", self.giant_count - giant, self.giant_count);
        }
        if observed_plain_l1 > self.certificate.input_error_factor {
            return Err(failure(
                "slot return plaintext norm exceeded its preflight certificate",
            ));
        }
        output.ok_or_else(|| failure("empty slot return schedule"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arithmetic::canonical_scale_round::CanonicalScaleRound;
    use crate::entropy::ShadowHarvester;
    use crate::ops::rns_fhe::RNSKeySet;
    use crate::params::SecureConfig;

    fn decrypt(ctx: &RNSFHEContext, input: &RNSCiphertext, keys: &RNSKeySet) -> Vec<u64> {
        let phases: Vec<Vec<u64>> = ctx
            .config
            .primes
            .iter()
            .enumerate()
            .map(|(lane, &q)| {
                let mont = &ctx.rns.mont_contexts[lane];
                let standard = |values: &[u64]| {
                    values
                        .iter()
                        .map(|&v| mont.from_montgomery(v))
                        .collect::<Vec<_>>()
                };
                let product = ctx.ntt_engines[lane].multiply(
                    &standard(&input.c1.limbs[lane]),
                    &standard(&keys.secret_key.s.limbs[lane]),
                );
                standard(&input.c0.limbs[lane])
                    .iter()
                    .zip(product)
                    .map(|(&a, b)| ((a as u128 + b as u128) % q as u128) as u64)
                    .collect()
            })
            .collect();
        let decoder = CanonicalScaleRound::new(&ctx.config.primes, ctx.t).unwrap();
        (0..ctx.n)
            .map(|j| {
                decoder
                    .scale_round(&phases.iter().map(|lane| lane[j]).collect::<Vec<_>>())
                    .unwrap()
            })
            .collect()
    }

    #[test]
    fn centered_diagonal_reduces_into_main_primes_smaller_than_plaintext() {
        let mut config = SecureConfig::secure_128().into_config();
        config.n = 32;
        config.primes = vec![193, 257, 449];
        config.q = config.primes[0];
        config.security_bits = 0;
        config.name = "INSECURE small-main-prime slot-return arithmetic test";
        let ctx = RNSFHEContext::try_new(&config).unwrap();
        let plan = PublicSlotReturn::new(&ctx, 8).unwrap();
        let component = |offset: usize| RNSPolynomial {
            n: ctx.n,
            limbs: ctx
                .config
                .primes
                .iter()
                .enumerate()
                .map(|(lane, &q)| {
                    (0..ctx.n)
                        .map(|j| {
                            ctx.rns.mont_contexts[lane]
                                .to_montgomery(((j * 91 + offset) as u64) % q)
                        })
                        .collect()
                })
                .collect(),
        };
        let input = RNSCiphertext {
            c0: component(17),
            c1: component(43),
            num_primes: 3,
        };
        let plain: Vec<_> = (0..ctx.n)
            .map(|j| [0, 1, 32_768, 32_769, 65_536][j % 5])
            .collect();
        let zero = || vec![vec![0; ctx.n]; ctx.config.primes.len()];
        let mut sums = [zero(), zero()];
        plan.add_diagonal(&mut sums, &plan.cache(&input), &plain);
        let output = plan.finish_sum(&sums);
        for (input, output) in [(&input.c0, &output.c0), (&input.c1, &output.c1)] {
            for (lane, &q) in ctx.config.primes.iter().enumerate() {
                let mont = &ctx.rns.mont_contexts[lane];
                let mut expected = vec![0i128; ctx.n];
                for i in 0..ctx.n {
                    for (j, &value) in plain.iter().enumerate() {
                        let centered = if value <= ctx.t / 2 {
                            value as i128
                        } else {
                            value as i128 - ctx.t as i128
                        };
                        let product = mont.from_montgomery(input.limbs[lane][i]) as i128 * centered;
                        expected[(i + j) % ctx.n] += if i + j < ctx.n { product } else { -product };
                    }
                }
                let expected: Vec<_> = expected
                    .into_iter()
                    .map(|v| v.rem_euclid(q as i128) as u64)
                    .collect();
                let actual: Vec<_> = output.limbs[lane]
                    .iter()
                    .map(|&v| mont.from_montgomery(v))
                    .collect();
                assert_eq!(actual, expected);
            }
        }
    }

    #[test]
    fn balanced_inverse_partition_halves_cache_without_more_switches() {
        let n = 32768usize;
        let cyclic = n / 2;
        let baby = inverse_baby_count(cyclic);
        assert_eq!(baby, 64);
        assert_eq!(2 * baby + cyclic / baby - 2, 382);
        // Native Q650: four 30-bit and nine 59-bit primes, two components.
        let chunks = 2 * (4 * 2 + 9 * 3);
        assert_eq!(2 * baby * chunks * n * 8, 2_348_810_240);
    }

    #[test]
    fn streamed_slot_return_recovers_embedded_coefficients_with_three_keys() {
        verify_streamed_return(64);
    }

    #[test]
    fn reduced_cache_partition_preserves_every_coefficient() {
        verify_streamed_return(128);
    }

    fn verify_streamed_return(outer_n: usize) {
        let mut config = SecureConfig::secure_128().into_config();
        config.n = outer_n;
        config.security_bits = 0;
        config.name = "INSECURE streamed slot-return test";
        // Exercise the auxiliary backend's third 24-bit word as well as
        // ordinary 31-bit lanes in the same exact ciphertext comparison.
        config.primes.push(576_460_752_301_785_089);
        let ctx = RNSFHEContext::try_new(&config).unwrap();
        let plan = PublicSlotReturn::new(&ctx, outer_n / 4).unwrap();
        let mut rng = ShadowHarvester::with_seed(0x5354_4f43_5245_5455);
        let keys = ctx.generate_keys(&mut rng);
        let return_keys = plan.generate_keys(&keys.secret_key, &mut rng).unwrap();
        // Populate every slot, including the unused three quarters. The
        // independently specified output must depend only on the source coefficient slots.
        let values: Vec<u64> = (0..ctx.n)
            .map(|j| ((j * j * 7 + 13 * j + 3) % ctx.t as usize) as u64)
            .collect();
        let polynomial = plan.encoding.encode_slots(&values).unwrap();
        let mut input = ctx.encrypt(0, &keys.public_key, &mut rng);
        for (lane, &q) in ctx.config.primes.iter().enumerate() {
            let mont = &ctx.rns.mont_contexts[lane];
            for (j, &value) in polynomial.iter().enumerate() {
                let encoded = mont.to_montgomery(
                    (ctx.delta_rns[lane] as u128 * value as u128 % q as u128) as u64,
                );
                input.c0.limbs[lane][j] =
                    ((input.c0.limbs[lane][j] as u128 + encoded as u128) % q as u128) as u64;
            }
        }
        assert_eq!(
            plan.encoding
                .decode_slots(&decrypt(&ctx, &input, &keys))
                .unwrap(),
            values
        );
        let output = plan.apply(&input, &return_keys).unwrap();
        let mut stages = Vec::new();
        let auxiliary = plan
            .apply_auxiliary(&input, &return_keys, &mut |stage, done, total| {
                stages.push((stage.to_owned(), done, total));
            })
            .unwrap();
        assert_eq!(auxiliary.c0.limbs, output.c0.limbs);
        assert_eq!(auxiliary.c1.limbs, output.c1.limbs);
        assert_eq!(
            stages.last().unwrap(),
            &("inverse giants".into(), plan.giant_count, plan.giant_count)
        );
        let mut expected = vec![0; ctx.n];
        for j in 0..outer_n / 4 {
            expected[4 * j] = values[j];
        }
        assert_eq!(decrypt(&ctx, &output, &keys), expected);
        assert_eq!(plan.certificate().plaintext_diagonals, ctx.n);
        assert_eq!(plan.certificate().ciphertext_babies, 8);
        assert_eq!(
            plan.certificate().galois_calls,
            if outer_n == 64 { 14 } else { 22 }
        );
        assert_eq!(
            plan.certificate().input_error_factor,
            outer_n as u128 * outer_n as u128 * 32768
        );
    }
}
