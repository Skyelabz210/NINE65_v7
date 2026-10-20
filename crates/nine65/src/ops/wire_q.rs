//! Main-Q wire v1 with session-local, producer-backed certificate provenance.
//! Only exact bytes emitted from a certified value in this key domain can be
//! imported. Wire parsing alone never establishes a noise bound.

use super::{CramMainCiphertext, CramMainEvaluator, PublicState};
use crate::arithmetic::RNSPolynomial;
use crate::noise::certified::CertifiedNoiseBound;
use crate::ops::RNSCiphertext;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Arc;

const MAGIC: &[u8; 8] = b"N65Qv001";
const HEADER_BYTES: usize = 84;
// Low byte = Montgomery coefficient representation, next byte = scalar mod t.
const DOMAIN_FLAGS: u32 = 0x101;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum WireQError {
    #[error("invalid main-Q wire shape or context")]
    InvalidEncoding,
    #[error("ciphertext was not issued in this session/key domain")]
    Uncertified,
    #[error("session ciphertext issuance limit reached")]
    Capacity,
}

/// Bounded provenance registry. It retains hashes and bounds, not ciphertexts
/// or plaintexts. Replay copies the original bound; it cannot reset history.
pub struct MainQTransport {
    state: Arc<PublicState>,
    issued: HashMap<[u8; 32], CertifiedNoiseBound>,
    max_entries: usize,
}

impl CramMainEvaluator {
    pub fn transport(&self, max_entries: usize) -> MainQTransport {
        MainQTransport {
            state: self.state.clone(),
            issued: HashMap::new(),
            max_entries,
        }
    }
}

impl MainQTransport {
    pub fn encoded_len(&self) -> usize {
        HEADER_BYTES + 2 * self.state.ctx.n * self.state.ctx.config.primes.len() * 8
    }

    pub fn remaining_capacity(&self) -> usize {
        self.max_entries.saturating_sub(self.issued.len())
    }

    fn header(&self) -> [u8; HEADER_BYTES] {
        let mut header = [0; HEADER_BYTES];
        header[..8].copy_from_slice(MAGIC);
        header[8..40].copy_from_slice(&self.state.context_id);
        header[40..72].copy_from_slice(&self.state.key_id);
        header[72..76].copy_from_slice(&(self.state.ctx.n as u32).to_le_bytes());
        header[76..80].copy_from_slice(&(self.state.ctx.config.primes.len() as u32).to_le_bytes());
        header[80..84].copy_from_slice(&DOMAIN_FLAGS.to_le_bytes());
        header
    }

    pub fn export(&mut self, ct: &CramMainCiphertext) -> Result<Vec<u8>, WireQError> {
        if !Arc::ptr_eq(&self.state, &ct.state) {
            return Err(WireQError::Uncertified);
        }
        let mut bytes = Vec::with_capacity(self.encoded_len());
        bytes.extend_from_slice(&self.header());
        for poly in [&ct.raw.c0, &ct.raw.c1] {
            for lane in &poly.limbs {
                for value in lane {
                    bytes.extend_from_slice(&value.to_le_bytes());
                }
            }
        }
        let digest: [u8; 32] = Sha256::digest(&bytes).into();
        if let Some(bound) = self.issued.get_mut(&digest) {
            // Identical bytes can be produced by different valid histories
            // (notably multiplication by zero). Never upgrade an existing
            // record to a smaller bound on re-export.
            let old = bound.scaled_error_words();
            let new = ct.bound.scaled_error_words();
            if new.iter().rev().cmp(old.iter().rev()).is_gt() {
                *bound = ct.bound.clone();
            }
        } else {
            if self.issued.len() >= self.max_entries {
                return Err(WireQError::Capacity);
            }
            self.issued.insert(digest, ct.bound.clone());
        }
        Ok(bytes)
    }

    pub fn import(&self, bytes: &[u8]) -> Result<CramMainCiphertext, WireQError> {
        // Exact size and all context/shape/domain fields are checked before
        // allocation. No input length or bound is ever trusted.
        if bytes.len() != self.encoded_len() || bytes[..HEADER_BYTES] != self.header() {
            return Err(WireQError::InvalidEncoding);
        }
        let digest: [u8; 32] = Sha256::digest(bytes).into();
        let bound = self
            .issued
            .get(&digest)
            .ok_or(WireQError::Uncertified)?
            .clone();
        let ctx = &self.state.ctx;
        let mut chunks = bytes[HEADER_BYTES..].chunks_exact(8);
        let mut read_poly = || -> Result<RNSPolynomial, WireQError> {
            let mut limbs = Vec::with_capacity(ctx.config.primes.len());
            for &q in &ctx.config.primes {
                let mut coefficients = Vec::with_capacity(ctx.n);
                for _ in 0..ctx.n {
                    let word = chunks.next().ok_or(WireQError::InvalidEncoding)?;
                    let value = u64::from_le_bytes(
                        word.try_into().map_err(|_| WireQError::InvalidEncoding)?,
                    );
                    if value >= q {
                        return Err(WireQError::InvalidEncoding);
                    }
                    coefficients.push(value);
                }
                limbs.push(coefficients);
            }
            Ok(RNSPolynomial { limbs, n: ctx.n })
        };
        let raw = RNSCiphertext {
            c0: read_poly()?,
            c1: read_poly()?,
            num_primes: ctx.config.primes.len(),
        };
        Ok(CramMainCiphertext {
            raw,
            bound,
            state: self.state.clone(),
        })
    }
}
