//! FIDO2 security key example using ML-DSA
//! 
//! This example demonstrates how to use ML-DSA in a FIDO2/WebAuthn security key
//! implementation for post-quantum authentication.

#![no_std]
#![no_main]

use panic_halt as _;
use cortex_m_rt::entry;
use cortex_m_semihosting::{debug, hprintln};

use formosa_ml_dsa::{
    MlDsa65,
    fido2::{Fido2Signer, Fido2Verifier, Fido2Credential, utils},
    Result,
};

use heapless::Vec;

#[entry]
fn main() -> ! {
    hprintln!("Formosa ML-DSA FIDO2 Example");
    
    if let Err(e) = run_fido2_example() {
        hprintln!("Error: {:?}", e);
        debug::exit(debug::EXIT_FAILURE);
    } else {
        hprintln!("FIDO2 example completed successfully!");
        debug::exit(debug::EXIT_SUCCESS);
    }
}

fn run_fido2_example() -> Result<()> {
    // Simulated FIDO2 registration flow
    hprintln!("=== FIDO2 Registration Flow ===");
    
    // 1. Generate keypair for new credential
    let seed = [0x00u8; 32]; // In practice, use secure randomness
    let (signing_key, verifying_key) = MlDsa65::generate_keypair_with_seed(&seed)?;
    
    hprintln!("Generated ML-DSA-65 keypair for new credential");
    
    // 2. Create FIDO2 credential
    let rp_id = "example.com";
    let rp_id_hash = utils::hash_rp_id(rp_id);
    let credential_id = utils::derive_credential_id(&verifying_key, &rp_id_hash);
    
    let credential = Fido2Credential::new(
        credential_id.as_slice(),
        rp_id.as_bytes(),
        signing_key,
        verifying_key,
    )?;
    
    hprintln!("Created FIDO2 credential for RP: {}", rp_id);
    hprintln!("Credential ID: {} bytes", credential.credential_id.len());
    
    // 3. Simulate authenticator attestation during registration
    let aaguid = [0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0,
                  0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
    
    let signer = credential.signer(aaguid);
    
    // Create authenticator data for attestation
    let flags = 0x41; // User present + Attested credential data included
    let counter = 1;
    let authenticator_data = utils::create_test_authenticator_data(&rp_id_hash, flags, counter);
    
    // Simulate client data hash (would come from browser in real scenario)
    let client_data_hash = [0xABu8; 32];
    let attestation_randomness = [0x01u8; 32];
    
    hprintln!("Creating attestation signature...");
    let attestation_signature = signer.sign_attestation_with_seed(
        authenticator_data.as_slice(),
        &client_data_hash,
        &attestation_randomness,
    )?;
    
    hprintln!("Attestation signature created: {} bytes", attestation_signature.size());
    
    // Verify the attestation (simulating relying party verification)
    let verifier = credential.verifier();
    verifier.verify_attestation(
        &attestation_signature,
        authenticator_data.as_slice(),
        &client_data_hash,
    )?;
    
    hprintln!("Attestation signature verified successfully!");
    
    // 4. Simulate FIDO2 authentication flow
    hprintln!("\n=== FIDO2 Authentication Flow ===");
    
    // Create authenticator data for assertion
    let auth_flags = 0x05; // User present + User verified  
    let auth_counter = 2; // Counter should increment
    let auth_data = utils::create_test_authenticator_data(&rp_id_hash, auth_flags, auth_counter);
    
    // New client data hash for this authentication
    let auth_client_data_hash = [0xCDu8; 32];
    let assertion_randomness = [0x02u8; 32];
    
    hprintln!("Creating assertion signature...");
    let assertion_signature = signer.sign_assertion_with_seed(
        auth_data.as_slice(),
        &auth_client_data_hash,
        &assertion_randomness,
    )?;
    
    hprintln!("Assertion signature created: {} bytes", assertion_signature.size());
    
    // Verify the assertion
    verifier.verify_assertion(
        &assertion_signature,
        auth_data.as_slice(),
        &auth_client_data_hash,
    )?;
    
    hprintln!("Assertion signature verified successfully!");
    
    // 5. Test invalid signature detection
    hprintln!("\n=== Testing Invalid Signature Detection ===");
    
    let wrong_client_data_hash = [0xEFu8; 32];
    match verifier.verify_assertion(
        &assertion_signature,
        auth_data.as_slice(),
        &wrong_client_data_hash,
    ) {
        Ok(_) => {
            hprintln!("ERROR: Should have failed with wrong client data hash");
            return Err(formosa_ml_dsa::Error::CryptoError);
        }
        Err(_) => {
            hprintln!("Correctly rejected invalid signature");
        }
    }
    
    // 6. Demonstrate multiple credential support
    hprintln!("\n=== Multiple Credentials ===");
    
    // Create second credential for different RP
    let rp2_id = "another-site.com";
    let rp2_seed = [0xFFu8; 32];
    let (sk2, vk2) = MlDsa65::generate_keypair_with_seed(&rp2_seed)?;
    
    let rp2_hash = utils::hash_rp_id(rp2_id);
    let cred2_id = utils::derive_credential_id(&vk2, &rp2_hash);
    
    let credential2 = Fido2Credential::new(
        cred2_id.as_slice(),
        rp2_id.as_bytes(),
        sk2,
        vk2,
    )?;
    
    hprintln!("Created second credential for RP: {}", rp2_id);
    
    // Test that credentials are independent
    let signer2 = credential2.signer(aaguid);
    let rp2_auth_data = utils::create_test_authenticator_data(&rp2_hash, auth_flags, 1);
    
    let sig2 = signer2.sign_assertion_with_seed(
        rp2_auth_data.as_slice(),
        &auth_client_data_hash,
        &assertion_randomness,
    )?;
    
    // Verify with correct credential
    let verifier2 = credential2.verifier();
    verifier2.verify_assertion(&sig2, rp2_auth_data.as_slice(), &auth_client_data_hash)?;
    hprintln!("Second credential works correctly");
    
    // Test that first credential cannot verify second credential's signature
    match verifier.verify_assertion(&sig2, rp2_auth_data.as_slice(), &auth_client_data_hash) {
        Ok(_) => {
            hprintln!("ERROR: Cross-credential verification should fail");
            return Err(formosa_ml_dsa::Error::CryptoError);
        }
        Err(_) => {
            hprintln!("Cross-credential verification correctly failed");
        }
    }
    
    hprintln!("\nAll FIDO2 tests passed!");
    Ok(())
}