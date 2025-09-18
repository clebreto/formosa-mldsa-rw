use crate::{
    error::{Error, Result},
    types::{Signature, SigningKey, VerifyingKey},
    MlDsa, MlDsaParams,
};

/// ML-DSA-87 parameter set (largest, highest security)
#[derive(Debug, Clone, Copy)]
pub struct MlDsa87;

impl MlDsaParams for MlDsa87 {
    const VERIFICATION_KEY_SIZE: usize = 2592;
    const SIGNING_KEY_SIZE: usize = 4896;
    const SIGNATURE_SIZE: usize = 4627;
    const PARAMETER_SET: &'static str = "ML-DSA-87";
}

impl MlDsa for MlDsa87 {
    fn generate_keypair_with_seed(
        seed: &[u8; 32]
    ) -> Result<(SigningKey<Self>, VerifyingKey<Self>)> {
        let mut verification_key = [0u8; Self::VERIFICATION_KEY_SIZE];
        let mut signing_key = [0u8; Self::SIGNING_KEY_SIZE];

        unsafe {
            ml_dsa_87_keygen(
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

        let context_ptr = context.as_ptr();
        let message_ptr = message.as_ptr();
        let randomness_ptr = randomness.as_ptr();

        let context_message_randomness = [context_ptr, message_ptr, randomness_ptr];
        let contextlen_messagelen = [context.len(), message.len()];

        let result = unsafe {
            ml_dsa_87_sign(
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

        let context_ptr = context.as_ptr();
        let message_ptr = message.as_ptr();

        let context_message = [context_ptr, message_ptr];
        let contextlen_messagelen = [context.len(), message.len()];

        let result = unsafe {
            ml_dsa_87_verify(
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

// Implementation of convenience methods for SigningKey and VerifyingKey
impl SigningKey<MlDsa87> {
    /// Sign a message with this signing key using provided randomness
    pub fn sign_with_seed(
        &self,
        message: &[u8],
        context: &[u8],
        randomness: &[u8; 32],
    ) -> Result<Signature<MlDsa87>> {
        MlDsa87::sign_with_seed(self, message, context, randomness)
    }

    #[cfg(feature = "rand")]
    /// Sign a message with this signing key using a random number generator
    pub fn sign<R: rand_core::RngCore + rand_core::CryptoRng>(
        &self,
        message: &[u8],
        context: &[u8],
        rng: &mut R,
    ) -> Result<Signature<MlDsa87>> {
        MlDsa87::sign(self, message, context, rng)
    }

    /// Sign a message with empty context using provided randomness
    pub fn sign_message_with_seed(
        &self,
        message: &[u8],
        randomness: &[u8; 32],
    ) -> Result<Signature<MlDsa87>> {
        self.sign_with_seed(message, &[], randomness)
    }

    #[cfg(feature = "rand")]
    /// Sign a message with empty context using a random number generator
    pub fn sign_message<R: rand_core::RngCore + rand_core::CryptoRng>(
        &self,
        message: &[u8],
        rng: &mut R,
    ) -> Result<Signature<MlDsa87>> {
        self.sign(message, &[], rng)
    }
}

impl VerifyingKey<MlDsa87> {
    /// Verify a signature with this verifying key
    pub fn verify(
        &self,
        signature: &Signature<MlDsa87>,
        message: &[u8],
        context: &[u8],
    ) -> Result<()> {
        MlDsa87::verify(self, signature, message, context)
    }

    /// Verify a signature with empty context
    pub fn verify_message(
        &self,
        signature: &Signature<MlDsa87>,
        message: &[u8],
    ) -> Result<()> {
        self.verify(signature, message, &[])
    }
}

// External C functions from the generated assembly
extern "C" {
    fn ml_dsa_87_keygen(
        verification_key: *mut u8,
        signing_key: *mut u8,
        randomness: *const u8,
    );

    fn ml_dsa_87_sign(
        signature: *mut u8,
        context_message_randomness: *const *const u8,
        contextlen_messagelen: *const usize,
        signing_key: *const u8,
    ) -> i32;

    fn ml_dsa_87_verify(
        signature: *const u8,
        context_message: *const *const u8,
        contextlen_messagelen: *const usize,
        verification_key: *const u8,
    ) -> i32;
}