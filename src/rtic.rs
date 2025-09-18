//! RTIC-specific utilities and adaptations for ML-DSA
//!
//! This module provides RTIC-friendly wrappers and utilities for using ML-DSA
//! in real-time systems with shared resources and interrupt-driven architectures.

use crate::{
    error::{Error, Result},
    types::{ContextBuffer, MessageBuffer, Signature, SigningKey, VerifyingKey},
    MlDsaParams,
};

use heapless::{pool::Pool, Deque};

/// RTIC-compatible ML-DSA signer that can be shared across tasks
pub struct RticSigner<P: MlDsaParams, const BUFFER_SIZE: usize = 1024> {
    signing_key: SigningKey<P>,
    message_pool: Pool<[u8; BUFFER_SIZE]>,
}

impl<P: MlDsaParams, const BUFFER_SIZE: usize> RticSigner<P, BUFFER_SIZE> {
    /// Create a new RTIC signer with the given signing key
    pub fn new(signing_key: SigningKey<P>) -> Self {
        Self {
            signing_key,
            message_pool: Pool::new(),
        }
    }

    /// Sign a message using a buffer from the pool (interrupt-safe)
    pub fn try_sign_message_with_seed(
        &mut self,
        message: &[u8],
        context: &ContextBuffer,
        randomness: &[u8; 32],
    ) -> Result<Signature<P>>
    where
        P: crate::MlDsa,
    {
        if message.len() > BUFFER_SIZE {
            return Err(Error::BufferTooSmall);
        }

        // This is safe to use in interrupt context if properly protected by RTIC
        P::sign_with_seed(&self.signing_key, message, context.as_ref(), randomness)
    }

    #[cfg(feature = "rand")]
    /// Sign a message using a buffer from the pool with RNG (interrupt-safe)
    pub fn try_sign_message<R: rand_core::RngCore + rand_core::CryptoRng>(
        &mut self,
        message: &[u8],
        context: &ContextBuffer,
        rng: &mut R,
    ) -> Result<Signature<P>>
    where
        P: crate::MlDsa,
    {
        if message.len() > BUFFER_SIZE {
            return Err(Error::BufferTooSmall);
        }

        P::sign(&self.signing_key, message, context.as_ref(), rng)
    }

    /// Get a reference to the signing key
    pub fn signing_key(&self) -> &SigningKey<P> {
        &self.signing_key
    }
}

/// RTIC-compatible ML-DSA verifier that can be shared across tasks
pub struct RticVerifier<P: MlDsaParams, const BUFFER_SIZE: usize = 1024> {
    verifying_key: VerifyingKey<P>,
}

impl<P: MlDsaParams, const BUFFER_SIZE: usize> RticVerifier<P, BUFFER_SIZE> {
    /// Create a new RTIC verifier with the given verifying key
    pub fn new(verifying_key: VerifyingKey<P>) -> Self {
        Self { verifying_key }
    }

    /// Verify a signature (interrupt-safe)
    pub fn try_verify_message(
        &self,
        signature: &Signature<P>,
        message: &[u8],
        context: &ContextBuffer,
    ) -> Result<()>
    where
        P: crate::MlDsa,
    {
        if message.len() > BUFFER_SIZE {
            return Err(Error::BufferTooSmall);
        }

        P::verify(&self.verifying_key, signature, message, context.as_ref())
    }

    /// Get a reference to the verifying key
    pub fn verifying_key(&self) -> &VerifyingKey<P> {
        &self.verifying_key
    }
}

/// A bounded queue for storing signing/verification tasks in RTIC systems
#[derive(Debug)]
pub struct CryptoTaskQueue<T, const N: usize> {
    queue: Deque<T, N>,
}

impl<T, const N: usize> CryptoTaskQueue<T, N> {
    /// Create a new crypto task queue
    pub fn new() -> Self {
        Self {
            queue: Deque::new(),
        }
    }

    /// Try to enqueue a task (returns false if queue is full)
    pub fn try_enqueue(&mut self, task: T) -> bool {
        self.queue.push_back(task).is_ok()
    }

    /// Try to dequeue a task (returns None if queue is empty)
    pub fn try_dequeue(&mut self) -> Option<T> {
        self.queue.pop_front()
    }

    /// Check if the queue is empty
    pub fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }

    /// Check if the queue is full
    pub fn is_full(&self) -> bool {
        self.queue.is_full()
    }

    /// Get the current length of the queue
    pub fn len(&self) -> usize {
        self.queue.len()
    }

    /// Get the maximum capacity of the queue
    pub const fn capacity(&self) -> usize {
        N
    }
}

impl<T, const N: usize> Default for CryptoTaskQueue<T, N> {
    fn default() -> Self {
        Self::new()
    }
}

/// A signing task for async processing in RTIC systems
#[derive(Debug)]
pub struct SigningTask<const MSG_SIZE: usize = 1024> {
    pub message: MessageBuffer<MSG_SIZE>,
    pub context: ContextBuffer,
    pub randomness: [u8; 32],
    pub task_id: u32,
}

impl<const MSG_SIZE: usize> SigningTask<MSG_SIZE> {
    /// Create a new signing task
    pub fn new(
        message: &[u8],
        context: &[u8],
        randomness: [u8; 32],
        task_id: u32,
    ) -> Result<Self> {
        Ok(Self {
            message: MessageBuffer::from_message(message)?,
            context: ContextBuffer::from_context(context)?,
            randomness,
            task_id,
        })
    }
}

/// A verification task for async processing in RTIC systems
#[derive(Debug)]
pub struct VerificationTask<P: MlDsaParams, const MSG_SIZE: usize = 1024> {
    pub signature: Signature<P>,
    pub message: MessageBuffer<MSG_SIZE>,
    pub context: ContextBuffer,
    pub task_id: u32,
}

impl<P: MlDsaParams, const MSG_SIZE: usize> VerificationTask<P, MSG_SIZE> {
    /// Create a new verification task
    pub fn new(
        signature: Signature<P>,
        message: &[u8],
        context: &[u8],
        task_id: u32,
    ) -> Result<Self> {
        Ok(Self {
            signature,
            message: MessageBuffer::from_message(message)?,
            context: ContextBuffer::from_context(context)?,
            task_id,
        })
    }
}

/// Result of a completed crypto operation
#[derive(Debug)]
pub struct CryptoResult<P: MlDsaParams> {
    pub task_id: u32,
    pub result: Result<Option<Signature<P>>>,
}

impl<P: MlDsaParams> CryptoResult<P> {
    /// Create a new signing result
    pub fn signing_success(task_id: u32, signature: Signature<P>) -> Self {
        Self {
            task_id,
            result: Ok(Some(signature)),
        }
    }

    /// Create a new verification result
    pub fn verification_success(task_id: u32) -> Self {
        Self {
            task_id,
            result: Ok(None),
        }
    }

    /// Create a new error result
    pub fn error(task_id: u32, error: Error) -> Self {
        Self {
            task_id,
            result: Err(error),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MlDsa65;

    #[test]
    fn test_crypto_task_queue() {
        let mut queue: CryptoTaskQueue<u32, 8> = CryptoTaskQueue::new();
        
        assert!(queue.is_empty());
        assert_eq!(queue.len(), 0);
        
        // Fill the queue
        for i in 0..8 {
            assert!(queue.try_enqueue(i));
        }
        
        assert!(queue.is_full());
        assert_eq!(queue.len(), 8);
        
        // Try to add one more (should fail)
        assert!(!queue.try_enqueue(8));
        
        // Dequeue all items
        for i in 0..8 {
            assert_eq!(queue.try_dequeue(), Some(i));
        }
        
        assert!(queue.is_empty());
        assert_eq!(queue.try_dequeue(), None);
    }

    #[test]
    fn test_signing_task_creation() {
        let message = b"Hello RTIC!";
        let context = b"test";
        let randomness = [1u8; 32];
        
        let task = SigningTask::new(message, context, randomness, 42).unwrap();
        
        assert_eq!(task.message.as_slice(), message);
        assert_eq!(task.context.as_slice(), context);
        assert_eq!(task.randomness, randomness);
        assert_eq!(task.task_id, 42);
    }

    #[test]
    fn test_verification_task_creation() {
        let seed = [0u8; 32];
        let (signing_key, _) = MlDsa65::generate_keypair_with_seed(&seed).unwrap();
        
        let message = b"Hello RTIC!";
        let context = b"";
        let randomness = [1u8; 32];
        
        let signature = signing_key.sign_with_seed(message, context, &randomness).unwrap();
        
        let task = VerificationTask::<MlDsa65>::new(signature, message, context, 42).unwrap();
        
        assert_eq!(task.message.as_slice(), message);
        assert_eq!(task.context.as_slice(), context);
        assert_eq!(task.task_id, 42);
    }
}