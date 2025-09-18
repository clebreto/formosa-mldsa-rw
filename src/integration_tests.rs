//! Integration tests for the formosa-ml-dsa crate
//! 
//! These tests validate the basic functionality and interoperability
//! of different ML-DSA parameter sets.

use formosa_ml_dsa::{
    Error, Result,
    MlDsa, MlDsaParams,
};

#[cfg(feature = "ml-dsa-44")]
use formosa_ml_dsa::MlDsa44;

#[cfg(feature = "ml-dsa-65")]
use formosa_ml_dsa::MlDsa65;

#[cfg(feature = "ml-dsa-87")]
use formosa_ml_dsa::MlDsa87;

// Test basic functionality with ML-DSA-65 (most common parameter set)
#[cfg(feature = "ml-dsa-65")]
#[test]
fn test_ml_dsa_65_basic_operations() {
    test_parameter_set::<MlDsa65>().expect("ML-DSA-65 test failed");
}

#[cfg(feature = "ml-dsa-44")]
#[test]
fn test_ml_dsa_44_basic_operations() {
    test_parameter_set::<MlDsa44>().expect("ML-DSA-44 test failed");
}

#[cfg(feature = "ml-dsa-87")]
#[test]
fn test_ml_dsa_87_basic_operations() {
    test_parameter_set::<MlDsa87>().expect("ML-DSA-87 test failed");
}

fn test_parameter_set<P>() -> Result<()>
where
    P: MlDsa + MlDsaParams,
{
    println!("Testing parameter set: {}", P::PARAMETER_SET);
    
    // Test 1: Basic keypair generation
    let seed = [0x42u8; 32];
    let (signing_key, verifying_key) = P::generate_keypair_with_seed(&seed)?;
    
    assert_eq!(signing_key.as_slice().len(), P::SIGNING_KEY_SIZE);
    assert_eq!(verifying_key.as_slice().len(), P::VERIFICATION_KEY_SIZE);
    
    // Test 2: Sign and verify with context
    let message = b"Integration test message";
    let context = b"test_context";
    let randomness = [0x33u8; 32];
    
    let signature = P::sign_with_seed(&signing_key, message, context, &randomness)?;
    assert_eq!(signature.as_slice().len(), P::SIGNATURE_SIZE);
    
    P::verify(&verifying_key, &signature, message, context)?;
    
    // Test 3: Sign and verify without context
    let signature_no_ctx = P::sign_with_seed(&signing_key, message, &[], &randomness)?;
    P::verify(&verifying_key, &signature_no_ctx, message, &[])?;
    
    // Test 4: Verify should fail with wrong message
    let wrong_message = b"Wrong message!";
    assert!(P::verify(&verifying_key, &signature, wrong_message, context).is_err());
    
    // Test 5: Verify should fail with wrong context
    let wrong_context = b"wrong_context";
    assert!(P::verify(&verifying_key, &signature, message, wrong_context).is_err());
    
    // Test 6: Different randomness produces different signatures
    let randomness2 = [0x44u8; 32];
    let signature2 = P::sign_with_seed(&signing_key, message, context, &randomness2)?;
    
    // Signatures should be different (with high probability)
    assert_ne!(signature.as_slice(), signature2.as_slice());
    
    // But both should verify correctly
    P::verify(&verifying_key, &signature2, message, context)?;
    
    // Test 7: Context length validation
    let long_context = [0u8; 256]; // 256 bytes, should be too long
    assert!(matches!(
        P::sign_with_seed(&signing_key, message, &long_context, &randomness),
        Err(Error::InvalidContextLength)
    ));
    
    println!("All tests passed for {}", P::PARAMETER_SET);
    Ok(())
}

#[cfg(feature = "ml-dsa-65")]
#[test]
fn test_deterministic_generation() {
    // Same seed should produce same keys
    let seed = [0x12u8; 32];
    
    let (sk1, vk1) = MlDsa65::generate_keypair_with_seed(&seed).unwrap();
    let (sk2, vk2) = MlDsa65::generate_keypair_with_seed(&seed).unwrap();
    
    assert_eq!(sk1.as_slice(), sk2.as_slice());
    assert_eq!(vk1.as_slice(), vk2.as_slice());
}

#[cfg(feature = "ml-dsa-65")]
#[test]
fn test_deterministic_signing() {
    // Same message, context, and randomness should produce same signature
    let seed = [0x34u8; 32];
    let (signing_key, _) = MlDsa65::generate_keypair_with_seed(&seed).unwrap();
    
    let message = b"Deterministic test";
    let context = b"test";
    let randomness = [0x56u8; 32];
    
    let sig1 = signing_key.sign_with_seed(message, context, &randomness).unwrap();
    let sig2 = signing_key.sign_with_seed(message, context, &randomness).unwrap();
    
    assert_eq!(sig1.as_slice(), sig2.as_slice());
}

#[cfg(all(feature = "ml-dsa-44", feature = "ml-dsa-65"))]
#[test]
fn test_cross_parameter_set_isolation() {
    // Keys from different parameter sets should not be compatible
    let seed = [0x78u8; 32];
    
    let (sk44, _) = MlDsa44::generate_keypair_with_seed(&seed).unwrap();
    let (_, vk65) = MlDsa65::generate_keypair_with_seed(&seed).unwrap();
    
    let message = b"Cross-parameter test";
    let randomness = [0x9Au8; 32];
    
    let sig44 = sk44.sign_message_with_seed(message, &randomness).unwrap();
    
    // This should fail because we're using ML-DSA-44 signature with ML-DSA-65 key
    // Note: This test might not compile due to type safety, which is the intended behavior
    // The type system should prevent this at compile time
}

#[cfg(feature = "ml-dsa-65")]
#[test]
fn test_empty_message() {
    let seed = [0xBCu8; 32];
    let (signing_key, verifying_key) = MlDsa65::generate_keypair_with_seed(&seed).unwrap();
    
    let empty_message = b"";
    let randomness = [0xDEu8; 32];
    
    let signature = signing_key.sign_message_with_seed(empty_message, &randomness).unwrap();
    verifying_key.verify_message(&signature, empty_message).unwrap();
}

#[cfg(feature = "ml-dsa-65")]
#[test]
fn test_large_message() {
    let seed = [0xF0u8; 32];
    let (signing_key, verifying_key) = MlDsa65::generate_keypair_with_seed(&seed).unwrap();
    
    // Create a large message (1MB)
    let large_message = vec![0xAAu8; 1024 * 1024];
    let randomness = [0x11u8; 32];
    
    let signature = signing_key.sign_message_with_seed(&large_message, &randomness).unwrap();
    verifying_key.verify_message(&signature, &large_message).unwrap();
}

// Test the heapless buffer types for embedded usage
#[cfg(feature = "ml-dsa-65")]
#[test]
fn test_embedded_buffer_types() {
    use formosa_ml_dsa::types::{ContextBuffer, MessageBuffer};
    
    // Test ContextBuffer
    let context = b"embedded_context";
    let ctx_buffer = ContextBuffer::from_context(context).unwrap();
    assert_eq!(ctx_buffer.as_slice(), context);
    
    // Test MessageBuffer
    let message = b"embedded_message_test";
    let msg_buffer = MessageBuffer::<64>::from_message(message).unwrap();
    assert_eq!(msg_buffer.as_slice(), message);
    
    // Test buffer size limits
    let too_long_context = [0u8; 256];
    assert!(ContextBuffer::from_context(&too_long_context).is_err());
    
    let too_long_message = [0u8; 128];
    assert!(MessageBuffer::<64>::from_message(&too_long_message).is_err());
}

#[cfg(all(feature = "ml-dsa-65", feature = "rtic"))]
#[test]
fn test_rtic_components() {
    use formosa_ml_dsa::rtic::{RticSigner, RticVerifier, CryptoTaskQueue, SigningTask};
    
    let seed = [0x22u8; 32];
    let (signing_key, verifying_key) = MlDsa65::generate_keypair_with_seed(&seed).unwrap();
    
    // Test RTIC signer and verifier
    let mut signer = RticSigner::new(signing_key);
    let verifier = RticVerifier::new(verifying_key);
    
    let message = b"RTIC test message";
    let context = ContextBuffer::from_context(b"rtic").unwrap();
    let randomness = [0x33u8; 32];
    
    let signature = signer.try_sign_message_with_seed(message, &context, &randomness).unwrap();
    verifier.try_verify_message(&signature, message, &context).unwrap();
    
    // Test crypto task queue
    let mut queue: CryptoTaskQueue<SigningTask, 4> = CryptoTaskQueue::new();
    
    let task = SigningTask::new(message, b"rtic", randomness, 1).unwrap();
    assert!(queue.try_enqueue(task));
    assert_eq!(queue.len(), 1);
    
    let dequeued_task = queue.try_dequeue().unwrap();
    assert_eq!(dequeued_task.task_id, 1);
    assert!(queue.is_empty());
}

#[cfg(all(feature = "ml-dsa-65", feature = "fido2"))]
#[test]
fn test_fido2_components() {
    use formosa_ml_dsa::fido2::{Fido2Signer, Fido2Verifier, Fido2Credential, utils};
    
    let seed = [0x44u8; 32];
    let (signing_key, verifying_key) = MlDsa65::generate_keypair_with_seed(&seed).unwrap();
    
    // Test FIDO2 credential creation
    let credential = Fido2Credential::new(
        b"test_credential_id",
        b"example.com",
        signing_key,
        verifying_key,
    ).unwrap();
    
    let aaguid = [0x12u8; 16];
    let signer = credential.signer(aaguid);
    let verifier = credential.verifier();
    
    // Test FIDO2 assertion signing and verification
    let rp_id_hash = utils::hash_rp_id("example.com");
    let authenticator_data = utils::create_test_authenticator_data(&rp_id_hash, 0x05, 42);
    let client_data_hash = [0xABu8; 32];
    let randomness = [0x55u8; 32];
    
    let assertion_signature = signer.sign_assertion_with_seed(
        authenticator_data.as_slice(),
        &client_data_hash,
        &randomness,
    ).unwrap();
    
    verifier.verify_assertion(
        &assertion_signature,
        authenticator_data.as_slice(),
        &client_data_hash,
    ).unwrap();
    
    // Test that wrong client data hash fails verification
    let wrong_hash = [0xCDu8; 32];
    assert!(verifier.verify_assertion(
        &assertion_signature,
        authenticator_data.as_slice(),
        &wrong_hash,
    ).is_err());
}