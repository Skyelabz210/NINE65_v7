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
    pub fn add_assign(&mut self, context: &RNSFHEContext, rhs: &Self) -> Result<(), AdapterError> {
        if self.ciphertexts.len() != SLOT_COUNT || rhs.ciphertexts.len() != SLOT_COUNT {
            return Err(AdapterError::InvalidCiphertextCount);
        }

        for (left, right) in self.ciphertexts.iter_mut().zip(&rhs.ciphertexts) {
            let sum = context.add_dual(left, right);
            *left = sum;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nine65::entropy::ShadowHarvester;
    use nine65::params::secure_configs::SecureConfig;
    use private_feedback_core::{FrictionClass, QuestionClass, SentimentClass};

    fn signal(topic: u16, severity: u8, confidence_permille: u16) -> FeedbackSignal {
        FeedbackSignal::try_new(
            topic,
            FrictionClass::Confusing,
            severity,
            SentimentClass::Frustrated,
            17,
            QuestionClass::DistinguishLocationFromComprehension,
            false,
            confidence_permille,
        )
        .expect("valid structured signal")
    }

    #[test]
    fn public_adapter_encrypts_and_aggregates_live_dual_rns_slots() {
        let config = SecureConfig::test_medium_insecure().into_config();
        let context = RNSFHEContext::try_new(&config).expect("test context");
        let mut rng = ShadowHarvester::with_seed(0x4e49_4e45_3635);
        let keys = context.generate_keys_dual_full(&mut rng);

        let left_signal = signal(42, 5, 700);
        let right_signal = signal(99, 2, 250);
        let left_slots = left_signal.slots();
        let right_slots = right_signal.slots();

        let mut encrypted_left =
            EncryptedFeedback::encrypt(&context, &keys.public_key, left_signal)
                .expect("encrypt left");
        let encrypted_right = EncryptedFeedback::encrypt(&context, &keys.public_key, right_signal)
            .expect("encrypt right");

        assert!(encrypted_left.validate_shape());
        assert!(encrypted_right.validate_shape());

        encrypted_left
            .add_assign(&context, &encrypted_right)
            .expect("homomorphic slot aggregation");

        for (index, ((left, right), ciphertext)) in left_slots
            .iter()
            .zip(&right_slots)
            .zip(encrypted_left.ciphertexts())
            .enumerate()
        {
            let actual = context.decrypt_dual(ciphertext, &keys.secret_key);
            let expected = (left + right) % context.t;
            assert_eq!(actual, expected, "slot {index}");
        }
    }
}
