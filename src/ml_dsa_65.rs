use crate::{
    error::{Error, Result},
    types::{Signature, SigningKey, VerifyingKey},
    MlDsa, MlDsaParams,
};

/// ML-DSA-65 parameter set
#[derive(Debug, Clone, Copy)]
pub struct MlDsa65;

impl MlDsaParams for MlDsa65 {
    const VERIFICATION_KEY_SIZE: usize = 1952;
    const SIGNING_KEY_SIZE: usize = 4032;
    const SIGNATURE_SIZE: usize = 3309;
    const PARAMETER_SET: &'static str = "ML-DSA-65";
}

impl MlDsa for MlDsa65 {
    fn generate_keypair_with_seed(
        seed: &[u8; 32]
    ) -> Result<(SigningKey<Self>, VerifyingKey<Self>)> {
        let mut verification_key = [0u8; Self::VERIFICATION_KEY_SIZE];
        let mut signing_key = [0u8; Self::SIGNING_KEY_SIZE];

        unsafe {
            ml_dsa_65_keygen(
                verification_key.as_mut_ptr(),
                signing_key.as_mut_ptr(),
                seed.as_ptr(),
            );
        }

        Ok((
            SigningKey::from_array_unchecked(&signing_key),
            VerifyingKey::from_array_unchecked(&verification_key),
        ))
    }

    fn sign_with_seed(
        signing_key: &SigningKey<Self>,
        message: &[u8],
        context: &[u8],
        randomness: &[u8; 32],
    ) -> Result<Signature<Self>> {
        if context.len() > 255 {
            return Err(Error::InvalidContextLength);
        }

        let mut signature = [0u8; Self::SIGNATURE_SIZE];

        // Prepare context_message_randomness array for C function
        let context_ptr = context.as_ptr();
        let message_ptr = message.as_ptr();
        let randomness_ptr = randomness.as_ptr();

        let context_message_randomness = [context_ptr, message_ptr, randomness_ptr];
        let contextlen_messagelen = [context.len(), message.len()];

        let result = unsafe {
            ml_dsa_65_sign(
                signature.as_mut_ptr(),
                context_message_randomness.as_ptr(),
                contextlen_messagelen.as_ptr(),
                signing_key.as_slice().as_ptr(),
            )
        };

        if result == 0 {
            Ok(Signature::from_array_unchecked(&signature))
        } else {
            Err(Error::CryptoError)
        }
    }

    fn verify(
        verifying_key: &VerifyingKey<Self>,
        signature: &Signature<Self>,
        message: &[u8],
        context: &[u8],
    ) -> Result<()> {
        if context.len() > 255 {
            return Err(Error::InvalidContextLength);
        }

        // Prepare context_message array for C function
        let context_ptr = context.as_ptr();
        let message_ptr = message.as_ptr();

        let context_message = [context_ptr, message_ptr];
        let contextlen_messagelen = [context.len(), message.len()];

        let result = unsafe {
            ml_dsa_65_verify(
                signature.as_slice().as_ptr(),
                context_message.as_ptr(),
                contextlen_messagelen.as_ptr(),
                verifying_key.as_slice().as_ptr(),
            )
        };

        if result == 0 {
            Ok(())
        } else {
            Err(Error::InvalidSignature)
        }
    }
}

impl SigningKey<MlDsa65> {
    /// Sign a message with this signing key using provided randomness
    pub fn sign_with_seed(
        &self,
        message: &[u8],
        context: &[u8],
        randomness: &[u8; 32],
    ) -> Result<Signature<MlDsa65>> {
        MlDsa65::sign_with_seed(self, message, context, randomness)
    }

    #[cfg(feature = "rand")]
    /// Sign a message with this signing key using a random number generator
    pub fn sign<R: rand_core::RngCore + rand_core::CryptoRng>(
        &self,
        message: &[u8],
        context: &[u8],
        rng: &mut R,
    ) -> Result<Signature<MlDsa65>> {
        MlDsa65::sign(self, message, context, rng)
    }

    /// Sign a message with empty context using provided randomness
    pub fn sign_message_with_seed(
        &self,
        message: &[u8],
        randomness: &[u8; 32],
    ) -> Result<Signature<MlDsa65>> {
        self.sign_with_seed(message, &[], randomness)
    }

    #[cfg(feature = "rand")]
    /// Sign a message with empty context using a random number generator
    pub fn sign_message<R: rand_core::RngCore + rand_core::CryptoRng>(
        &self,
        message: &[u8],
        rng: &mut R,
    ) -> Result<Signature<MlDsa65>> {
        self.sign(message, &[], rng)
    }
}

impl VerifyingKey<MlDsa65> {
    /// Verify a signature with this verifying key
    pub fn verify(
        &self,
        signature: &Signature<MlDsa65>,
        message: &[u8],
        context: &[u8],
    ) -> Result<()> {
        MlDsa65::verify(self, signature, message, context)
    }

    /// Verify a signature with empty context
    pub fn verify_message(
        &self,
        signature: &Signature<MlDsa65>,
        message: &[u8],
    ) -> Result<()> {
        self.verify(signature, message, &[])
    }
}

// External C functions from the generated assembly
extern "C" {
    fn ml_dsa_65_keygen(
        verification_key: *mut u8,
        signing_key: *mut u8,
        randomness: *const u8,
    );

    fn ml_dsa_65_sign(
        signature: *mut u8,
        context_message_randomness: *const *const u8,
        contextlen_messagelen: *const usize,
        signing_key: *const u8,
    ) -> i32;

    fn ml_dsa_65_verify(
        signature: *const u8,
        context_message: *const *const u8,
        contextlen_messagelen: *const usize,
        verification_key: *const u8,
    ) -> i32;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keypair_generation() {
        let seed = [0u8; 32];
        let (signing_key, verifying_key) = MlDsa65::generate_keypair_with_seed(&seed).unwrap();
        
        assert_eq!(signing_key.as_slice().len(), MlDsa65::SIGNING_KEY_SIZE);
        assert_eq!(verifying_key.as_slice().len(), MlDsa65::VERIFICATION_KEY_SIZE);
    }

    #[test]
    fn test_sign_and_verify() {
        let seed = [1u8; 32];
        let (signing_key, verifying_key) = MlDsa65::generate_keypair_with_seed(&seed).unwrap();
        
        let message = b"Hello, ML-DSA!";
        let context = b"test";
        let randomness = [2u8; 32];
        
        let signature = signing_key.sign_with_seed(message, context, &randomness).unwrap();
        assert_eq!(signature.as_slice().len(), MlDsa65::SIGNATURE_SIZE);
        
        verifying_key.verify(&signature, message, context).unwrap();
    }

    #[test]
    fn test_verify_invalid_signature_fails() {
        let seed = [1u8; 32];
        let (signing_key, verifying_key) = MlDsa65::generate_keypair_with_seed(&seed).unwrap();
        
        let message = b"Hello, ML-DSA!";
        let wrong_message = b"Wrong message!";
        let randomness = [2u8; 32];
        
        let signature = signing_key.sign_message_with_seed(message, &randomness).unwrap();
        
        // This should fail
        assert!(verifying_key.verify_message(&signature, wrong_message).is_err());
    }
}