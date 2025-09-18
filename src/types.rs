use core::marker::PhantomData;
use heapless::Vec;

use crate::{error::Result, MlDsaParams};

#[cfg(feature = "zeroize")]
use zeroize::{Zeroize, ZeroizeOnDrop};

/// A signing key for ML-DSA
#[derive(Clone)]
pub struct SigningKey<P: MlDsaParams> {
    pub(crate) bytes: Vec<u8, 8192>, // Max size to accommodate all parameter sets
    pub(crate) _params: PhantomData<P>,
}

impl<P: MlDsaParams> SigningKey<P> {
    /// Create a signing key from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != P::SIGNING_KEY_SIZE {
            return Err(crate::Error::InvalidLength);
        }
        
        let mut key_bytes = Vec::new();
        key_bytes.extend_from_slice(bytes)
            .map_err(|_| crate::Error::BufferTooSmall)?;
            
        Ok(Self {
            bytes: key_bytes,
            _params: PhantomData,
        })
    }

    /// Create a signing key from a fixed-size array (internal use)
    pub(crate) fn from_array_unchecked(bytes: &[u8]) -> Self {
        let mut key_bytes = Vec::new();
        key_bytes.extend_from_slice(bytes).unwrap(); // Safe - we control the input
        
        Self {
            bytes: key_bytes,
            _params: PhantomData,
        }
    }

    /// Get the signing key as a byte slice
    pub fn as_slice(&self) -> &[u8] {
        &self.bytes
    }

    /// Get the expected size for this parameter set
    pub fn size() -> usize {
        P::SIGNING_KEY_SIZE
    }
}

impl<P: MlDsaParams> AsRef<[u8]> for SigningKey<P> {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

#[cfg(feature = "zeroize")]
impl<P: MlDsaParams> Drop for SigningKey<P> {
    fn drop(&mut self) {
        self.bytes.as_mut_slice().zeroize();
    }
}

#[cfg(feature = "zeroize")]
impl<P: MlDsaParams> ZeroizeOnDrop for SigningKey<P> {}

/// A verification key for ML-DSA
#[derive(Clone)]
pub struct VerifyingKey<P: MlDsaParams> {
    pub(crate) bytes: Vec<u8, 4096>, // Max size to accommodate all parameter sets
    pub(crate) _params: PhantomData<P>,
}

impl<P: MlDsaParams> VerifyingKey<P> {
    /// Create a verifying key from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != P::VERIFICATION_KEY_SIZE {
            return Err(crate::Error::InvalidLength);
        }
        
        let mut key_bytes = Vec::new();
        key_bytes.extend_from_slice(bytes)
            .map_err(|_| crate::Error::BufferTooSmall)?;
            
        Ok(Self {
            bytes: key_bytes,
            _params: PhantomData,
        })
    }

    /// Create a verifying key from a fixed-size array (internal use)
    pub(crate) fn from_array_unchecked(bytes: &[u8]) -> Self {
        let mut key_bytes = Vec::new();
        key_bytes.extend_from_slice(bytes).unwrap(); // Safe - we control the input
        
        Self {
            bytes: key_bytes,
            _params: PhantomData,
        }
    }

    /// Get the verifying key as a byte slice
    pub fn as_slice(&self) -> &[u8] {
        &self.bytes
    }

    /// Get the expected size for this parameter set
    pub fn size() -> usize {
        P::VERIFICATION_KEY_SIZE
    }
}

impl<P: MlDsaParams> AsRef<[u8]> for VerifyingKey<P> {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

/// A signature for ML-DSA
#[derive(Clone)]
pub struct Signature<P: MlDsaParams> {
    pub(crate) bytes: Vec<u8, 8192>, // Max size to accommodate all parameter sets
    pub(crate) _params: PhantomData<P>,
}

impl<P: MlDsaParams> Signature<P> {
    /// Create a signature from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != P::SIGNATURE_SIZE {
            return Err(crate::Error::InvalidLength);
        }
        
        let mut sig_bytes = Vec::new();
        sig_bytes.extend_from_slice(bytes)
            .map_err(|_| crate::Error::BufferTooSmall)?;
            
        Ok(Self {
            bytes: sig_bytes,
            _params: PhantomData,
        })
    }

    /// Create a signature from a fixed-size array (internal use)
    pub(crate) fn from_array_unchecked(bytes: &[u8]) -> Self {
        let mut sig_bytes = Vec::new();
        sig_bytes.extend_from_slice(bytes).unwrap(); // Safe - we control the input
        
        Self {
            bytes: sig_bytes,
            _params: PhantomData,
        }
    }

    /// Get the signature as a byte slice
    pub fn as_slice(&self) -> &[u8] {
        &self.bytes
    }

    /// Get the expected size for this parameter set
    pub fn size() -> usize {
        P::SIGNATURE_SIZE
    }
}

impl<P: MlDsaParams> AsRef<[u8]> for Signature<P> {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

/// Randomness for deterministic operations (32 bytes)
pub type Randomness = [u8; 32];

/// Context data for ML-DSA signatures (max 255 bytes)
pub type Context<'a> = &'a [u8];

/// Message data for signing/verification
pub type Message<'a> = &'a [u8];

/// A heapless buffer for embedded contexts (max 255 bytes as per ML-DSA spec)
#[derive(Clone, Debug)]
pub struct ContextBuffer(Vec<u8, 255>);

impl ContextBuffer {
    /// Create a context buffer from a slice
    pub fn from_context(context: Context<'_>) -> Result<Self> {
        if context.len() > 255 {
            return Err(crate::Error::InvalidContextLength);
        }
        
        Vec::from_slice(context)
            .map(Self)
            .map_err(|_| crate::Error::BufferTooSmall)
    }

    /// Get the inner buffer as a slice
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    /// Get the length of the context
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Check if the context is empty
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl AsRef<[u8]> for ContextBuffer {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// A heapless buffer for messages in constrained environments
#[derive(Clone, Debug)]
pub struct MessageBuffer<const N: usize>(Vec<u8, N>);

impl<const N: usize> MessageBuffer<N> {
    /// Create a message buffer from a slice
    pub fn from_message(message: Message<'_>) -> Result<Self> {
        Vec::from_slice(message)
            .map(Self)
            .map_err(|_| crate::Error::BufferTooSmall)
    }

    /// Get the inner buffer as a slice
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    /// Get the length of the message
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Check if the message is empty
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl<const N: usize> AsRef<[u8]> for MessageBuffer<N> {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}