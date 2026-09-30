use crate::{
    error::{Error, Result},
    types::{Signature, SigningKey, VerifyingKey},
    MlDsa, MlDsaParams,
};

/// ML-DSA-44 parameter set (smallest, fastest)
#[derive(Debug, Clone, Copy)]
pub struct MlDsa44;

impl MlDsaParams for MlDsa44 {
    const VERIFICATION_KEY_SIZE: usize = 1312;
    const SIGNING_KEY_SIZE: usize = 2560;
    const SIGNATURE_SIZE: usize = 2420;
    const PARAMETER_SET: &'static str = "ML-DSA-44";
}

impl MlDsa for MlDsa44 {
    fn keygen_into(
        seed: &[u8; 32],
        verification_key: &mut [u8],
        signing_key: &mut [u8],
    ) -> Result<()> {
        if verification_key.len() != Self::VERIFICATION_KEY_SIZE
            || signing_key.len() != Self::SIGNING_KEY_SIZE
        {
            return Err(Error::InvalidLength);
        }
        unsafe {
            ml_dsa_44_keygen(verification_key.as_mut_ptr(), signing_key.as_mut_ptr(), seed.as_ptr());
        }
        Ok(())
    }

    fn sign_into(
        signing_key: &[u8],
        message: &[u8],
        context: &[u8],
        randomness: &[u8; 32],
        signature: &mut [u8],
    ) -> Result<()> {
        if context.len() > 255 {
            return Err(Error::InvalidContextLength);
        }
        if signing_key.len() != Self::SIGNING_KEY_SIZE || signature.len() != Self::SIGNATURE_SIZE {
            return Err(Error::InvalidLength);
        }

        let context_message_randomness = [context.as_ptr(), message.as_ptr(), randomness.as_ptr()];
        let contextlen_messagelen = [context.len(), message.len()];

        let result = unsafe {
            ml_dsa_44_sign(
                signature.as_mut_ptr(),
                context_message_randomness.as_ptr(),
                contextlen_messagelen.as_ptr(),
                signing_key.as_ptr(),
            )
        };

        if result == 0 {
            Ok(())
        } else {
            Err(Error::CryptoError)
        }
    }

    fn verify_bytes(
        verification_key: &[u8],
        signature: &[u8],
        message: &[u8],
        context: &[u8],
    ) -> Result<()> {
        if context.len() > 255 {
            return Err(Error::InvalidContextLength);
        }
        if verification_key.len() != Self::VERIFICATION_KEY_SIZE
            || signature.len() != Self::SIGNATURE_SIZE
        {
            return Err(Error::InvalidLength);
        }

        let context_message = [context.as_ptr(), message.as_ptr()];
        let contextlen_messagelen = [context.len(), message.len()];

        let result = unsafe {
            ml_dsa_44_verify(
                signature.as_ptr(),
                context_message.as_ptr(),
                contextlen_messagelen.as_ptr(),
                verification_key.as_ptr(),
            )
        };

        if result == 0 {
            Ok(())
        } else {
            Err(Error::InvalidSignature)
        }
    }

    fn generate_keypair_with_seed(
        seed: &[u8; 32]
    ) -> Result<(SigningKey<Self>, VerifyingKey<Self>)> {
        let mut verification_key = [0u8; Self::VERIFICATION_KEY_SIZE];
        let mut signing_key = [0u8; Self::SIGNING_KEY_SIZE];
        Self::keygen_into(seed, &mut verification_key, &mut signing_key)?;

        let keys = (
            SigningKey::from_array_unchecked(&signing_key),
            VerifyingKey::from_array_unchecked(&verification_key),
        );
        #[cfg(feature = "zeroize")]
        zeroize::Zeroize::zeroize(&mut signing_key);
        Ok(keys)
    }

    fn sign_with_seed(
        signing_key: &SigningKey<Self>,
        message: &[u8],
        context: &[u8],
        randomness: &[u8; 32],
    ) -> Result<Signature<Self>> {
        let mut signature = [0u8; Self::SIGNATURE_SIZE];
        Self::sign_into(signing_key.as_slice(), message, context, randomness, &mut signature)?;
        Ok(Signature::from_array_unchecked(&signature))
    }

    fn verify(
        verifying_key: &VerifyingKey<Self>,
        signature: &Signature<Self>,
        message: &[u8],
        context: &[u8],
    ) -> Result<()> {
        Self::verify_bytes(verifying_key.as_slice(), signature.as_slice(), message, context)
    }
}

// Implementation of convenience methods for SigningKey and VerifyingKey
impl SigningKey<MlDsa44> {
    /// Sign a message with this signing key using provided randomness
    pub fn sign_with_seed(
        &self,
        message: &[u8],
        context: &[u8],
        randomness: &[u8; 32],
    ) -> Result<Signature<MlDsa44>> {
        MlDsa44::sign_with_seed(self, message, context, randomness)
    }

    #[cfg(feature = "rand")]
    /// Sign a message with this signing key using a random number generator
    pub fn sign<R: rand_core::RngCore + rand_core::CryptoRng>(
        &self,
        message: &[u8],
        context: &[u8],
        rng: &mut R,
    ) -> Result<Signature<MlDsa44>> {
        MlDsa44::sign(self, message, context, rng)
    }

    /// Sign a message with empty context using provided randomness
    pub fn sign_message_with_seed(
        &self,
        message: &[u8],
        randomness: &[u8; 32],
    ) -> Result<Signature<MlDsa44>> {
        self.sign_with_seed(message, &[], randomness)
    }

    #[cfg(feature = "rand")]
    /// Sign a message with empty context using a random number generator
    pub fn sign_message<R: rand_core::RngCore + rand_core::CryptoRng>(
        &self,
        message: &[u8],
        rng: &mut R,
    ) -> Result<Signature<MlDsa44>> {
        self.sign(message, &[], rng)
    }
}

impl VerifyingKey<MlDsa44> {
    /// Verify a signature with this verifying key
    pub fn verify(
        &self,
        signature: &Signature<MlDsa44>,
        message: &[u8],
        context: &[u8],
    ) -> Result<()> {
        MlDsa44::verify(self, signature, message, context)
    }

    /// Verify a signature with empty context
    pub fn verify_message(
        &self,
        signature: &Signature<MlDsa44>,
        message: &[u8],
    ) -> Result<()> {
        self.verify(signature, message, &[])
    }
}

// External C functions from the generated assembly
extern "C" {
    fn ml_dsa_44_keygen(
        verification_key: *mut u8,
        signing_key: *mut u8,
        randomness: *const u8,
    );

    fn ml_dsa_44_sign(
        signature: *mut u8,
        context_message_randomness: *const *const u8,
        contextlen_messagelen: *const usize,
        signing_key: *const u8,
    ) -> i32;

    fn ml_dsa_44_verify(
        signature: *const u8,
        context_message: *const *const u8,
        contextlen_messagelen: *const usize,
        verification_key: *const u8,
    ) -> i32;
}