# Formosa ML-DSA Rust Wrapper

A Rust wrapper for the [Formosa ML-DSA](https://github.com/formosa-crypto/formosa-mldsa) post-quantum digital signature algorithm implementation. This crate provides safe, `no_std`-compatible Rust bindings to high-performance Jasmin-generated assembly implementations of ML-DSA for ARM Cortex-M4 and x86-64 platforms.

## About the Original Implementation

This project wraps the Jasmin implementations of all 3 parameter-sets of the pure, hedged version of ML-DSA, from which one can obtain ML-DSA assembly implementations for use on the x86-64 and ARMv7M platforms.

## Features

- **Post-quantum secure**: ML-DSA is standardized by NIST as part of the post-quantum cryptography standard (FIPS 204)
- **High performance**: Uses Jasmin-generated assembly for optimal performance
- **Embedded friendly**: `no_std` support with heapless collections for resource-constrained devices
- **Multiple parameter sets**: ML-DSA-44, ML-DSA-65, and ML-DSA-87 support
- **Memory efficient**: Low-RAM implementations available for Cortex-M4
- **RTIC compatible**: Built-in support for Real-Time Interrupt-driven Concurrency
- **FIDO2 ready**: Specialized utilities for WebAuthn/FIDO2 security key implementations
- **Safe API**: Memory-safe Rust wrappers around the assembly implementations

## Rust Quick Start

```rust
use formosa_ml_dsa::{MlDsa65, Result};

fn main() -> Result<()> {
    // Generate a keypair
    let seed = [0u8; 32]; // Use secure randomness in production
    let (signing_key, verifying_key) = MlDsa65::generate_keypair_with_seed(&seed)?;
    
    // Sign a message
    let message = b"Hello, post-quantum world!";
    let context = b"example_context";
    let randomness = [1u8; 32]; // Use secure randomness in production
    
    let signature = signing_key.sign_with_seed(message, context, &randomness)?;
    
    // Verify the signature
    verifying_key.verify(&signature, message, context)?;
    
    println!("Signature verified successfully!");
    Ok(())
}
```

See the full [Rust API documentation](#rust-api) below for more details.

## Original Jasmin Quickstart

0. Ensure you have the [Jasmin](https://github.com/jasmin-lang/jasmin) compiler installed,
using the latest commit on the `main` branch of the project. Also ensure that `jasminc` is in the PATH, since this is what the Makefile invokes.

1. To generate assembly code for, say, the AVX2 implementation of ML-DSA-65 on the x86-64 platform, simply run `env ARCHITECTURE=x86-64 PARAMETER_SET=65 IMPLEMENTATION_TYPE=avx2 make`. The resulting assembly implementation will be found in `ml_dsa_65_avx2_x86-64.s`.

## Rust API

### Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
formosa-ml-dsa = { version = "0.1", features = ["ml-dsa-65"] }
```

For embedded targets:

```toml
[dependencies]
formosa-ml-dsa = { 
    version = "0.1", 
    features = ["ml-dsa-65", "lowram", "rtic", "fido2"],
    default-features = false 
}
```

### Prerequisites

**For development/testing on macOS/Linux:**
- The crate compiles with stub implementations for testing and development
- No additional dependencies required for development builds

**For cross-compilation to embedded targets:**

1. **Jasmin Compiler**: Install from [jasmin-lang/jasmin](https://github.com/jasmin-lang/jasmin)
2. **For ARM Cortex-M4**: ARM GCC toolchain (`arm-none-eabi-gcc`, `arm-none-eabi-as`, `arm-none-eabi-ar`)
3. **Rust targets**: 
   ```bash
   rustup target add thumbv7em-none-eabihf  # ARM Cortex-M4
   rustup target add x86_64-unknown-linux-gnu  # x86-64 Linux
   ```

**Note**: This crate uses the Formosa ML-DSA implementation as a git submodule. The submodule contains the Jasmin source code and build system required for generating optimized assembly implementations.

### Parameter Sets

| Parameter Set | Security Level | Public Key | Private Key | Signature |
|---------------|----------------|------------|-------------|-----------|
| ML-DSA-44     | Category 2     | 1312 bytes | 2560 bytes  | 2420 bytes |
| ML-DSA-65     | Category 3     | 1952 bytes | 4032 bytes  | 3309 bytes |
| ML-DSA-87     | Category 5     | 2592 bytes | 4896 bytes  | 4627 bytes |

### Embedded Usage

```rust
#![no_std]
#![no_main]

use panic_halt as _;
use cortex_m_rt::entry;
use formosa_ml_dsa::{MlDsa65, Result};

#[entry]
fn main() -> ! {
    let seed = [0x42u8; 32];
    let (signing_key, verifying_key) = MlDsa65::generate_keypair_with_seed(&seed).unwrap();
    
    let message = b"Embedded ML-DSA!";
    let randomness = [0x33u8; 32];
    
    let signature = signing_key.sign_message_with_seed(message, &randomness).unwrap();
    verifying_key.verify_message(&signature, message).unwrap();
    
    // Success - signal via LED, etc.
    loop {}
}
```

### RTIC Integration

```rust
use rtic::app;
use formosa_ml_dsa::{MlDsa65, rtic::{RticSigner, CryptoTaskQueue}};

#[app(device = stm32f4xx_hal::pac)]
mod app {
    #[shared]
    struct Shared {
        signer: RticSigner<MlDsa65>,
        task_queue: CryptoTaskQueue<SigningTask, 16>,
    }

    #[init]
    fn init(ctx: init::Context) -> (Shared, Local, init::Monotonics) {
        let seed = [0x12u8; 32];
        let (signing_key, _) = MlDsa65::generate_keypair_with_seed(&seed).unwrap();

        (Shared {
            signer: RticSigner::new(signing_key),
            task_queue: CryptoTaskQueue::new(),
        }, Local {}, init::Monotonics())
    }

    #[task(shared = [signer])]
    fn crypto_task(mut ctx: crypto_task::Context) {
        // Process signing operations in interrupt context
    }
}
```

### FIDO2 Security Key

```rust
use formosa_ml_dsa::{MlDsa65, fido2::{Fido2Signer, Fido2Credential}};

fn handle_webauthn_assertion() -> Result<()> {
    let seed = [0u8; 32];
    let (signing_key, verifying_key) = MlDsa65::generate_keypair_with_seed(&seed)?;
    
    let credential = Fido2Credential::new(
        b"credential_id",
        b"example.com",
        signing_key,
        verifying_key,
    )?;
    
    let signer = credential.signer([0x12u8; 16]); // AAGUID
    
    // Sign WebAuthn assertion
    let signature = signer.sign_assertion_with_seed(
        &authenticator_data,
        &client_data_hash,
        &randomness,
    )?;
    
    Ok(())
}
```

### Feature Flags

- **Parameter sets**: `ml-dsa-44`, `ml-dsa-65`, `ml-dsa-87`
- **Implementation types**: `lowram` (ARM Cortex-M4), `avx2` (x86-64)
- **Embedded features**: `rtic`, `fido2`
- **Additional**: `rand`, `zeroize`, `std`

### Building for Different Targets

**Development build (with stub implementations):**
```bash
# Works on any platform (macOS, Linux, etc.) for testing and development
cargo build
cargo test  # Note: tests will panic if they try to call ML-DSA functions
```

**Cross-compilation (requires Jasmin and target toolchains):**
```bash
# ARM Cortex-M4 (requires Jasmin compiler and arm-none-eabi-* toolchain)
cargo build --target thumbv7em-none-eabihf --features "ml-dsa-65,lowram,arm-m4" --no-default-features

# x86-64 Linux (requires Jasmin compiler)
cargo build --target x86_64-unknown-linux-gnu --features "ml-dsa-65,avx2,x86-64"
```

**Submodule Setup:**
```bash
# When cloning this repository:
git clone --recursive <repository-url>

# Or after cloning:
git submodule update --init --recursive
```

### Examples

See `examples/` directory:
- `basic_usage.rs`: Basic signing and verification
- `rtic_usage.rs`: RTIC framework integration
- `fido2_security_key.rs`: FIDO2/WebAuthn implementation
