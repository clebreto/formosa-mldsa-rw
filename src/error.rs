/// ML-DSA error types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// Invalid signature - verification failed
    InvalidSignature,
    /// Invalid input length
    InvalidLength,
    /// Invalid context length (must be ≤ 255 bytes)
    InvalidContextLength,
    /// Internal cryptographic error
    CryptoError,
    /// Buffer too small for the operation
    BufferTooSmall,
    /// Feature not available in this configuration
    FeatureNotAvailable,
}

impl Error {
    /// Get a human-readable description of the error
    pub fn as_str(&self) -> &'static str {
        match self {
            Error::InvalidSignature => "signature verification failed",
            Error::InvalidLength => "invalid input length",
            Error::InvalidContextLength => "context length must be ≤ 255 bytes",
            Error::CryptoError => "internal cryptographic error",
            Error::BufferTooSmall => "buffer too small for operation",
            Error::FeatureNotAvailable => "feature not available in this configuration",
        }
    }
}

#[cfg(feature = "std")]
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}

/// Result type for ML-DSA operations
pub type Result<T> = core::result::Result<T, Error>;