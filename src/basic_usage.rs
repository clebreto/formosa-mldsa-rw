//! Basic ML-DSA usage example
//! 
//! This example demonstrates basic keypair generation, signing, and verification
//! using the formosa-ml-dsa crate.

#![no_std]
#![no_main]

use panic_halt as _;
use cortex_m_rt::entry;
use cortex_m_semihosting::{debug, hprintln};

use formosa_ml_dsa::{MlDsa65, Result};

#[entry]
fn main() -> ! {
    hprintln!("Formosa ML-DSA Example - Basic Usage");
    
    if let Err(e) = run_example() {
        hprintln!("Error: {:?}", e);
        debug::exit(debug::EXIT_FAILURE);
    } else {
        hprintln!("Example completed successfully!");
        debug::exit(debug::EXIT_SUCCESS);
    }
}

fn run_example() -> Result<()> {
    // Generate a keypair using a fixed seed (for deterministic output)
    let seed = [0x42u8; 32];
    hprintln!("Generating ML-DSA-65 keypair...");
    
    let (signing_key, verifying_key) = MlDsa65::generate_keypair_with_seed(&seed)?;
    
    hprintln!("Keypair generated successfully!");
    hprintln!("Signing key size: {} bytes", signing_key.size());
    hprintln!("Verifying key size: {} bytes", verifying_key.size());
    
    // Sign a message
    let message = b"Hello from ML-DSA on ARM Cortex-M4!";
    let context = b"example";
    let signing_randomness = [0x33u8; 32];
    
    hprintln!("Signing message: {:?}", core::str::from_utf8(message).unwrap_or("invalid utf8"));
    
    let signature = signing_key.sign_with_seed(message, context, &signing_randomness)?;
    
    hprintln!("Message signed successfully!");
    hprintln!("Signature size: {} bytes", signature.size());
    
    // Verify the signature
    hprintln!("Verifying signature...");
    
    verifying_key.verify(&signature, message, context)?;
    
    hprintln!("Signature verified successfully!");
    
    // Test that verification fails with wrong message
    let wrong_message = b"Wrong message!";
    match verifying_key.verify(&signature, wrong_message, context) {
        Ok(_) => {
            hprintln!("ERROR: Verification should have failed!");
            return Err(formosa_ml_dsa::Error::CryptoError);
        }
        Err(_) => {
            hprintln!("Verification correctly failed for wrong message");
        }
    }
    
    hprintln!("All tests passed!");
    Ok(())
}