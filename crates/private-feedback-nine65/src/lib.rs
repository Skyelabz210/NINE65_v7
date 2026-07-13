#![forbid(unsafe_code)]
#![deny(clippy::float_arithmetic)]

use nine65::ops::rns_fhe::{DualRNSCiphertext, DualRNSPublicKey, RNSFHEContext};
use private_feedback_core::{FeedbackSignal, SLOT_COUNT};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AdapterError {
    PlaintextModulusTooSmall,
    InvalidCiphertextCount,
}

/// Public-evaluator application object.
///
/// It exposes ciphertexts for remote evaluation and intentionally provides no
/// decryption method or secret-key field.
#[derive(Clone, Debug)]
pub struct EncryptedFeedback {
    ciphertexts: Vec<DualRNSCiphertext>,
}

impl EncryptedFeedback {
    pub fn encrypt(
        context: &RNSFHEContext,
        public_key: &DualRNSPublicKey,
        signal: FeedbackSignal,
    ) -> Result<Self, AdapterError> {
        let slots = signal.slots();
        let mut ciphertexts = Vec::with_capacity(SLOT_COUNT);

        for value in slots {
            if value >= context.t {
                return Err(AdapterError::PlaintextModulusTooSmall);
            }
            ciphertexts.push(context.encrypt_dual_secure(value, public_key));
        }

        Ok(Self { ciphertexts })
    }

    pub fn ciphertexts(&self) -> &[DualRNSCiphertext] {
        &self.ciphertexts
    }

    pub fn validate_shape(&self) -> bool {
        self.ciphertexts.len() == SLOT_COUNT
            && self
                .ciphertexts
                .iter()
                .all(|ciphertext| ciphertext.validate().is_ok())
    }

    /// Homomorphically aggregate two structured feedback objects slot-by-slot.
    /// Values remain ciphertexts in DualRNS form.
    pub fn add_assign(
        &mut self,
        context: &RNSFHEContext,
        rhs: &Self,
    ) -> Result<(), AdapterError> {
        if self.ciphertexts.len() != SLOT_COUNT || rhs.ciphertexts.len() != SLOT_COUNT {
            return Err(AdapterError::InvalidCiphertextCount);
        }

        for index in 0..SLOT_COUNT {
            self.ciphertexts[index] =
                context.add_dual(&self.ciphertexts[index], &rhs.ciphertexts[index]);
        }

        Ok(())
    }
}
