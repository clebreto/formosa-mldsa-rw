//! # Formosa ML-DSA
//!
//! Rust wrapper for the Formosa ML-DSA (Module-Lattice-Based Digital Signature Algorithm) 
//! implementation with embedded and no_std support.
//!
//! This crate provides safe Rust bindings to high-performance Jasmin-generated assembly 
//! implementations of ML-DSA for ARM Cortex-M4 and x86-64 platforms.
//!
//! ## Features
//!
//! - **Post-quantum secure**: ML-DSA is standardized by NIST as part of the post-quantum cryptography standard
//! - **High performance**: Uses Jasmin-generated assembly for optimal performance
//! - **Embedded friendly**: `no_std` support with heapless collections for RTIC applications
//! - **Multiple parameter sets**: ML-DSA-44, ML-DSA-65, and ML-DSA-87
//! - **Memory efficient**: Low-RAM implementations available for resource-constrained devices
//! - **FIDO2 ready**: Suitable for security key implementations
//!
//! ## Usage
//!
//! ```rust,no_run
//! use formosa_ml_dsa::{MlDsa65, Signature, SigningKey, VerifyingKey};
//!
//! // Generate a keypair
//! let mut rng = /* your RNG */;
//! let (signing_key, verifying_key) = MlDsa65::generate_keypair(&mut rng)?;
//!
//! // Sign a message
//! let message = b"Hello, post-quantum world!";
//! let signature = signing_key.sign(message, &[], &mut rng)?;
//!
//! // Verify the signature
//! verifying_key.verify(&signature, message, &[])?;
//! ```

#![no_std]
#![deny(unsafe_op_in_unsafe_fn)]
#![warn(missing_docs, rust_2018_idioms)]

#[cfg(feature = "std")]
extern crate std;

/// Error types and result handling for ML-DSA operations.
///
/// This module provides comprehensive error handling for all ML-DSA operations,
/// including validation errors, cryptographic failures, and platform-specific issues.
pub mod error;

/// Core types for ML-DSA keys and signatures.
///
/// This module defines the fundamental data structures used throughout the library,
/// including signing keys, verifying keys, and signatures for all ML-DSA parameter sets.
pub mod types;

/// ML-DSA-44 parameter set implementation.
///
/// Provides ML-DSA with security category 2, offering 128-bit security level.
/// This is the smallest parameter set with the fastest operations and smallest key/signature sizes.
#[cfg(feature = "ml-dsa-44")]
pub mod ml_dsa_44;

/// ML-DSA-65 parameter set implementation.
///
/// Provides ML-DSA with security category 3, offering 192-bit security level.
/// This is the recommended parameter set balancing security and performance.
#[cfg(feature = "ml-dsa-65")]
pub mod ml_dsa_65;

/// ML-DSA-87 parameter set implementation.
///
/// Provides ML-DSA with security category 5, offering 256-bit security level.
/// This is the highest security parameter set with larger keys and signatures.
#[cfg(feature = "ml-dsa-87")]
pub mod ml_dsa_87;

/// RTIC (Real-Time Interrupt-driven Concurrency) integration utilities.
///
/// This module provides specialized types and utilities for using ML-DSA in
/// RTIC-based embedded applications, including interrupt-safe operations and
/// task scheduling integration.
#[cfg(feature = "rtic")]
pub mod rtic;

/// FIDO2/WebAuthn security key implementation utilities.
///
/// This module provides specialized types and utilities for implementing
/// FIDO2 authenticators and WebAuthn security keys using ML-DSA signatures.
#[cfg(feature = "fido2")]
pub mod fido2;

// Re-export commonly used types
pub use error::{Error, Result};
pub use types::{Context, Message, Randomness, Signature, SigningKey, VerifyingKey};

#[cfg(feature = "ml-dsa-44")]
pub use ml_dsa_44::MlDsa44;

#[cfg(feature = "ml-dsa-65")]
pub use ml_dsa_65::MlDsa65;

#[cfg(feature = "ml-dsa-87")]
pub use ml_dsa_87::MlDsa87;

/// ML-DSA parameter trait for generic programming over different parameter sets.
pub trait MlDsaParams {
    /// Size of the verification key in bytes
    const VERIFICATION_KEY_SIZE: usize;
    /// Size of the signing key in bytes  
    const SIGNING_KEY_SIZE: usize;
    /// Size of the signature in bytes
    const SIGNATURE_SIZE: usize;
    /// Parameter set name
    const PARAMETER_SET: &'static str;
}

/// Common ML-DSA operations trait
pub trait MlDsa: MlDsaParams {
    /// Generate a new keypair using the provided randomness
    fn generate_keypair_with_seed(
        seed: &[u8; 32]
    ) -> Result<(SigningKey<Self>, VerifyingKey<Self>)>
    where
        Self: Sized;

    #[cfg(feature = "rand")]
    /// Generate a new keypair using a random number generator
    fn generate_keypair<R: rand_core::RngCore + rand_core::CryptoRng>(
        rng: &mut R
    ) -> Result<(SigningKey<Self>, VerifyingKey<Self>)>
    where
        Self: Sized,
    {
        let mut seed = [0u8; 32];
        rng.fill_bytes(&mut seed);
        Self::generate_keypair_with_seed(&seed)
    }

    /// Sign a message with optional context
    fn sign_with_seed(
        signing_key: &SigningKey<Self>,
        message: &[u8],
        context: &[u8],
        randomness: &[u8; 32],
    ) -> Result<Signature<Self>>
    where
        Self: Sized;

    #[cfg(feature = "rand")]
    /// Sign a message with optional context using a random number generator
    fn sign<R: rand_core::RngCore + rand_core::CryptoRng>(
        signing_key: &SigningKey<Self>,
        message: &[u8],
        context: &[u8],
        rng: &mut R,
    ) -> Result<Signature<Self>>
    where
        Self: Sized,
    {
        let mut randomness = [0u8; 32];
        rng.fill_bytes(&mut randomness);
        Self::sign_with_seed(signing_key, message, context, &randomness)
    }

    /// Verify a signature
    fn verify(
        verifying_key: &VerifyingKey<Self>,
        signature: &Signature<Self>,
        message: &[u8],
        context: &[u8],
    ) -> Result<()>
    where
        Self: Sized;
}