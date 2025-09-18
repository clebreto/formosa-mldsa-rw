//! FIDO2-specific utilities and adaptations for ML-DSA
//!
//! This module provides FIDO2-compatible wrappers and utilities for using ML-DSA
//! in WebAuthn/FIDO2 security key implementations.

use crate::{
    error::{Error, Result},
    types::{ContextBuffer, Signature, SigningKey, VerifyingKey},
    MlDsaParams,
};

use heapless::Vec;

/// FIDO2 authenticator data structure size (32 bytes RP ID hash + flags + counter + extensions)
pub const AUTHENTICATOR_DATA_MIN_SIZE: usize = 37;

/// Maximum size for FIDO2 client data JSON
pub const CLIENT_DATA_MAX_SIZE: usize = 1024;

/// FIDO2-compatible ML-DSA signer for WebAuthn operations
pub struct Fido2Signer<P: MlDsaParams> {
    signing_key: SigningKey<P>,
    aaguid: [u8; 16], // Authenticator AAGUID
}

impl<P: MlDsaParams> Fido2Signer<P> {
    /// Create a new FIDO2 signer with the given signing key and AAGUID
    pub fn new(signing_key: SigningKey<P>, aaguid: [u8; 16]) -> Self {
        Self {
            signing_key,
            aaguid,
        }
    }

    /// Sign FIDO2 authenticator assertion data
    /// 
    /// This combines authenticator data and client data hash as per WebAuthn spec
    pub fn sign_assertion_with_seed(
        &self,
        authenticator_data: &[u8],
        client_data_hash: &[u8; 32],
        randomness: &[u8; 32],
    ) -> Result<Signature<P>>
    where
        P: crate::MlDsa,
    {
        if authenticator_data.len() < AUTHENTICATOR_DATA_MIN_SIZE {
            return Err(Error::InvalidLength);
        }

        // Create the signature base: authenticator_data || client_data_hash
        let mut signature_base = Vec::<u8, 2048>::new();
        
        signature_base.extend_from_slice(authenticator_data)
            .map_err(|_| Error::BufferTooSmall)?;
        signature_base.extend_from_slice(client_data_hash)
            .map_err(|_| Error::BufferTooSmall)?;

        // Sign with empty context as per WebAuthn spec
        P::sign_with_seed(&self.signing_key, &signature_base, &[], randomness)
    }

    #[cfg(feature = "rand")]
    /// Sign FIDO2 authenticator assertion data with RNG
    pub fn sign_assertion<R: rand_core::RngCore + rand_core::CryptoRng>(
        &self,
        authenticator_data: &[u8],
        client_data_hash: &[u8; 32],
        rng: &mut R,
    ) -> Result<Signature<P>>
    where
        P: crate::MlDsa,
    {
        let mut randomness = [0u8; 32];
        rng.fill_bytes(&mut randomness);
        self.sign_assertion_with_seed(authenticator_data, client_data_hash, &randomness)
    }

    /// Sign FIDO2 authenticator attestation data
    /// 
    /// This is used during credential registration
    pub fn sign_attestation_with_seed(
        &self,
        authenticator_data: &[u8],
        client_data_hash: &[u8; 32],
        randomness: &[u8; 32],
    ) -> Result<Signature<P>>
    where
        P: crate::MlDsa,
    {
        // For attestation, the signature base is the same as assertion
        self.sign_assertion_with_seed(authenticator_data, client_data_hash, randomness)
    }

    #[cfg(feature = "rand")]
    /// Sign FIDO2 authenticator attestation data with RNG
    pub fn sign_attestation<R: rand_core::RngCore + rand_core::CryptoRng>(
        &self,
        authenticator_data: &[u8],
        client_data_hash: &[u8; 32],
        rng: &mut R,
    ) -> Result<Signature<P>>
    where
        P: crate::MlDsa,
    {
        self.sign_assertion(authenticator_data, client_data_hash, rng)
    }

    /// Get the AAGUID for this authenticator
    pub fn aaguid(&self) -> &[u8; 16] {
        &self.aaguid
    }

    /// Get the signing key
    pub fn signing_key(&self) -> &SigningKey<P> {
        &self.signing_key
    }
}

/// FIDO2-compatible ML-DSA verifier for WebAuthn operations
pub struct Fido2Verifier<P: MlDsaParams> {
    verifying_key: VerifyingKey<P>,
}

impl<P: MlDsaParams> Fido2Verifier<P> {
    /// Create a new FIDO2 verifier with the given verifying key
    pub fn new(verifying_key: VerifyingKey<P>) -> Self {
        Self { verifying_key }
    }

    /// Verify a FIDO2 authenticator assertion signature
    pub fn verify_assertion(
        &self,
        signature: &Signature<P>,
        authenticator_data: &[u8],
        client_data_hash: &[u8; 32],
    ) -> Result<()>
    where
        P: crate::MlDsa,
    {
        if authenticator_data.len() < AUTHENTICATOR_DATA_MIN_SIZE {
            return Err(Error::InvalidLength);
        }

        // Reconstruct the signature base
        let mut signature_base = Vec::<u8, 2048>::new();
        
        signature_base.extend_from_slice(authenticator_data)
            .map_err(|_| Error::BufferTooSmall)?;
        signature_base.extend_from_slice(client_data_hash)
            .map_err(|_| Error::BufferTooSmall)?;

        // Verify with empty context
        P::verify(&self.verifying_key, signature, &signature_base, &[])
    }

    /// Verify a FIDO2 authenticator attestation signature
    pub fn verify_attestation(
        &self,
        signature: &Signature<P>,
        authenticator_data: &[u8],
        client_data_hash: &[u8; 32],
    ) -> Result<()>
    where
        P: crate::MlDsa,
    {
        // For attestation, verification is the same as assertion
        self.verify_assertion(signature, authenticator_data, client_data_hash)
    }

    /// Get the verifying key
    pub fn verifying_key(&self) -> &VerifyingKey<P> {
        &self.verifying_key
    }
}

/// FIDO2 credential representation using ML-DSA
#[derive(Clone)]
pub struct Fido2Credential<P: MlDsaParams> {
    /// Credential ID (can be derived from key material)
    pub credential_id: Vec<u8, 64>,
    /// User handle (optional)
    pub user_handle: Option<Vec<u8, 64>>,
    /// Relying Party ID
    pub rp_id: Vec<u8, 256>,
    /// The ML-DSA signing key for this credential
    pub signing_key: SigningKey<P>,
    /// The ML-DSA verifying key for this credential
    pub verifying_key: VerifyingKey<P>,
}

impl<P: MlDsaParams> Fido2Credential<P> {
    /// Create a new FIDO2 credential
    pub fn new(
        credential_id: &[u8],
        rp_id: &[u8],
        signing_key: SigningKey<P>,
        verifying_key: VerifyingKey<P>,
    ) -> Result<Self> {
        let credential_id = Vec::from_slice(credential_id)
            .map_err(|_| Error::BufferTooSmall)?;
        let rp_id = Vec::from_slice(rp_id)
            .map_err(|_| Error::BufferTooSmall)?;

        Ok(Self {
            credential_id,
            user_handle: None,
            rp_id,
            signing_key,
            verifying_key,
        })
    }

    /// Set the user handle for this credential
    pub fn with_user_handle(mut self, user_handle: &[u8]) -> Result<Self> {
        self.user_handle = Some(Vec::from_slice(user_handle)
            .map_err(|_| Error::BufferTooSmall)?);
        Ok(self)
    }

    /// Get a FIDO2 signer for this credential
    pub fn signer(&self, aaguid: [u8; 16]) -> Fido2Signer<P> {
        Fido2Signer::new(self.signing_key.clone(), aaguid)
    }

    /// Get a FIDO2 verifier for this credential
    pub fn verifier(&self) -> Fido2Verifier<P> {
        Fido2Verifier::new(self.verifying_key.clone())
    }
}

/// Utility functions for FIDO2 operations
pub mod utils {
    use super::*;

    /// Create a credential ID from the verifying key (deterministic)
    pub fn derive_credential_id<P: MlDsaParams>(
        verifying_key: &VerifyingKey<P>,
        rp_id_hash: &[u8; 32],
    ) -> Vec<u8, 64> {
        // Simple approach: hash the verifying key with RP ID
        // In practice, you might want to use HMAC or encrypt the key material
        let mut hasher = sha2::Sha256::new();
        hasher.update(verifying_key.as_slice());
        hasher.update(rp_id_hash);
        let hash = hasher.finalize();
        
        Vec::from_slice(&hash[..32]).unwrap_or_else(|_| Vec::new())
    }

    /// Hash RP ID to create authenticator data
    pub fn hash_rp_id(rp_id: &str) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(rp_id.as_bytes());
        hasher.finalize().into()
    }

    /// Create minimal authenticator data for testing
    pub fn create_test_authenticator_data(
        rp_id_hash: &[u8; 32],
        flags: u8,
        counter: u32,
    ) -> Vec<u8, 64> {
        let mut auth_data = Vec::new();
        
        // RP ID hash (32 bytes)
        auth_data.extend_from_slice(rp_id_hash).unwrap();
        
        // Flags (1 byte)
        auth_data.push(flags).unwrap();
        
        // Counter (4 bytes, big-endian)
        auth_data.extend_from_slice(&counter.to_be_bytes()).unwrap();
        
        auth_data
    }
}

// For now, we'll use a placeholder for SHA-2 operations
// In a real implementation, you'd use the `sha2` crate or hardware acceleration
mod sha2 {
    pub struct Sha256;
    
    impl Sha256 {
        pub fn new() -> Self { Self }
        pub fn update(&mut self, _data: &[u8]) {}
        pub fn finalize(self) -> [u8; 32] { [0u8; 32] } // Placeholder
    }
    
    pub trait Digest {
        fn update(&mut self, data: &[u8]);
        fn finalize(self) -> [u8; 32];
    }
    
    impl Digest for Sha256 {
        fn update(&mut self, data: &[u8]) {
            Self::update(self, data);
        }
        
        fn finalize(self) -> [u8; 32] {
            Self::finalize(self)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MlDsa65;

    #[test]
    fn test_fido2_credential_creation() {
        let seed = [0u8; 32];
        let (signing_key, verifying_key) = MlDsa65::generate_keypair_with_seed(&seed).unwrap();
        
        let credential_id = b"test_credential_id";
        let rp_id = b"example.com";
        
        let credential = Fido2Credential::new(
            credential_id,
            rp_id,
            signing_key,
            verifying_key,
        ).unwrap();
        
        assert_eq!(credential.credential_id.as_slice(), credential_id);
        assert_eq!(credential.rp_id.as_slice(), rp_id);
        assert!(credential.user_handle.is_none());
    }

    #[test]
    fn test_fido2_signer_creation() {
        let seed = [0u8; 32];
        let (signing_key, _) = MlDsa65::generate_keypair_with_seed(&seed).unwrap();
        
        let aaguid = [0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0,
                     0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
        
        let signer = Fido2Signer::new(signing_key, aaguid);
        
        assert_eq!(signer.aaguid(), &aaguid);
    }

    #[test]
    fn test_authenticator_data_creation() {
        let rp_id_hash = [0u8; 32];
        let flags = 0x01; // User present
        let counter = 42;
        
        let auth_data = utils::create_test_authenticator_data(&rp_id_hash, flags, counter);
        
        assert_eq!(auth_data.len(), 37); // 32 + 1 + 4
        assert_eq!(auth_data[32], flags);
        assert_eq!(u32::from_be_bytes([auth_data[33], auth_data[34], auth_data[35], auth_data[36]]), counter);
    }
}