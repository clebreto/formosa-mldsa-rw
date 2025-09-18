use std::env;
use std::path::{Path, PathBuf};
use std::process::Command;

fn main() {
    let out_dir = env::var("OUT_DIR").unwrap();
    let out_path = Path::new(&out_dir);
    
    // Determine target architecture
    let target = env::var("TARGET").unwrap();
    let host = env::var("HOST").unwrap();
    
    let (architecture, is_cross_compile) = if target.starts_with("thumbv") || target.contains("arm-none-") {
        ("arm-m4", true)
    } else if target.starts_with("x86_64") && !target.contains("apple") {
        ("x86-64", target != host)
    } else {
        // For development builds on unsupported host platforms (like macOS)
        if env::var("TARGET").unwrap_or_default() == "aarch64-apple-darwin" {
            let target = env::var("TARGET").unwrap_or_default();
            println!("cargo:info=Creating stub implementation for development target: {}", target);
            println!("cargo:info=This crate is designed for cross-compilation to ARM-M4 and x86-64 targets");
            println!("cargo:info=Use --target thumbv7em-none-eabihf or --target x86_64-unknown-linux-gnu for full functionality");
        }
        
        // Create stub implementations for development builds
        create_development_stubs(&out_path);
        return;
    };

    // Only proceed with assembly generation for supported cross-compilation targets
    if !is_cross_compile {
        println!("cargo:warning=Native compilation detected. Use cross-compilation for full functionality.");
        return;
    }

    // Determine implementation type based on features and availability
    let implementation_type = if cfg!(feature = "avx2") && architecture == "x86-64" {
        "avx2"
    } else if cfg!(feature = "lowram") && architecture == "arm-m4" {
        "lowram"
    } else if architecture == "arm-m4" {
        // For ARM-M4, check if lowram is available for the parameter sets, otherwise use ref
        let parameter_sets = get_enabled_parameter_sets();
        let use_lowram = parameter_sets.iter().all(|param_set| {
            // ML-DSA-65 has lowram implementation, others may not
            *param_set == "65"
        });
        if use_lowram {
            "lowram"
        } else {
            "ref"
        }
    } else {
        "ref" // Default to reference implementation
    };

    println!("cargo:rerun-if-changed=formosa-mldsa/Makefile");
    println!("cargo:rerun-if-changed=formosa-mldsa/arm-m4/");
    println!("cargo:rerun-if-changed=formosa-mldsa/x86-64/");

    // Check if Jasmin compiler is available
    let jasminc_path = find_jasmin_compiler();
    if jasminc_path.is_none() {
        print_build_requirements();
        panic!("Jasmin compiler (jasminc) not found. See build requirements above.");
    }
    let jasminc_path = jasminc_path.unwrap();

    // Generate assembly files for enabled parameter sets
    let parameter_sets = get_enabled_parameter_sets();
    
    for param_set in parameter_sets {
        generate_assembly(&param_set, architecture, implementation_type, &out_path, &jasminc_path);
        
        // For ARM targets, we also need to compile the generated assembly
        if architecture == "arm-m4" {
            compile_assembly(&param_set, architecture, implementation_type, &out_path);
        }
    }

    // Link the generated objects
    link_libraries(architecture, &out_path);
}

fn get_enabled_parameter_sets() -> Vec<&'static str> {
    let mut sets = Vec::new();
    
    if cfg!(feature = "ml-dsa-44") {
        sets.push("44");
    }
    if cfg!(feature = "ml-dsa-65") {
        sets.push("65");
    }
    if cfg!(feature = "ml-dsa-87") {
        sets.push("87");
    }
    
    // Default to ML-DSA-65 if none specified
    if sets.is_empty() {
        sets.push("65");
    }
    
    sets
}

fn generate_assembly(param_set: &str, architecture: &str, implementation_type: &str, out_dir: &Path, jasminc_path: &Path) {
    println!("Generating assembly for ML-DSA-{} on {} with {} implementation", 
             param_set, architecture, implementation_type);

    let output_name = format!("ml_dsa_{}_{}_{}",
                              param_set, implementation_type, architecture);
    
    let submodule_dir = "formosa-mldsa";
    
    let make_output = Command::new("make")
        .current_dir(submodule_dir)
        .arg(format!("{}.s", output_name))
        .env("ARCHITECTURE", architecture)
        .env("PARAMETER_SET", param_set)
        .env("IMPLEMENTATION_TYPE", implementation_type)
        .env("JASMINC", jasminc_path.to_str().unwrap())
        .output()
        .expect("Failed to execute make command");

    if !make_output.status.success() {
        println!("cargo:warning=Make stdout: {}", String::from_utf8_lossy(&make_output.stdout));
        println!("cargo:warning=Make stderr: {}", String::from_utf8_lossy(&make_output.stderr));
        panic!("Failed to generate assembly for ML-DSA-{}", param_set);
    } else {
        println!("cargo:info=Successfully generated assembly for ML-DSA-{}", param_set);
    }

    // Move generated assembly to out directory
    let source = PathBuf::from(submodule_dir).join(format!("{}.s", output_name));
    let dest = out_dir.join(format!("{}.s", output_name));
    
    std::fs::copy(&source, &dest)
        .unwrap_or_else(|e| panic!("Failed to copy {} to out dir: {}", source.display(), e));
        
    println!("cargo:rerun-if-changed={}", source.display());
}

fn compile_assembly(param_set: &str, architecture: &str, implementation_type: &str, out_dir: &Path) {
    let output_name = format!("ml_dsa_{}_{}_{}",
                              param_set, implementation_type, architecture);
    
    let asm_file = out_dir.join(format!("{}.s", output_name));
    let obj_file = out_dir.join(format!("{}.o", output_name));
    


    // Check if assembly file exists
    if !asm_file.exists() {
        panic!("Assembly file not found: {}", asm_file.display());
    }

    // Use the appropriate assembler for ARM
    let mut cmd = Command::new("arm-none-eabi-as");
    cmd.arg("-march=armv7-m")
       .arg("-mthumb")
       .arg("-o").arg(&obj_file)
       .arg(&asm_file);

    let output = cmd.output()
        .expect("Failed to execute ARM assembler - ensure arm-none-eabi-as is installed");

    if !output.status.success() {
        println!("cargo:warning=Assembler stdout: {}", String::from_utf8_lossy(&output.stdout));
        println!("cargo:warning=Assembler stderr: {}", String::from_utf8_lossy(&output.stderr));
        panic!("Failed to assemble {}", asm_file.display());
    }


    
    // Check if object file was created
    if !obj_file.exists() {
        panic!("Object file not created: {}", obj_file.display());
    }
}

fn link_libraries(architecture: &str, out_dir: &Path) {
    // Create a static library containing all the generated objects
    if architecture == "arm-m4" {
        // Find all generated object files
        let obj_files: Vec<PathBuf> = std::fs::read_dir(out_dir)
            .unwrap()
            .filter_map(|entry| {
                let entry = entry.ok()?;
                let path = entry.path();
                if path.extension()? == "o" && 
                   path.file_name()?.to_str()?.contains("ml_dsa_") {
                    Some(path)
                } else {
                    None
                }
            })
            .collect();

        println!("cargo:info=Found {} object files for ARM linking", obj_files.len());

        if !obj_files.is_empty() {
            // Create a static library for each object file instead of combining them
            for obj_file in obj_files {
                let obj_filename = obj_file.file_stem().unwrap().to_str().unwrap();
                let lib_name = format!("lib{}.a", obj_filename);
                let lib_path = out_dir.join(&lib_name);
                
                let ar_output = Command::new("arm-none-eabi-ar")
                    .arg("rcs")
                    .arg(&lib_path)
                    .arg(&obj_file)
                    .output()
                    .expect("Failed to execute ARM archiver - ensure arm-none-eabi-ar is installed");

                if !ar_output.status.success() {
                    println!("cargo:warning=Archiver stdout: {}", String::from_utf8_lossy(&ar_output.stdout));
                    println!("cargo:warning=Archiver stderr: {}", String::from_utf8_lossy(&ar_output.stderr));
                    panic!("Failed to create static library for {}", obj_file.display());
                }
                println!("cargo:rustc-link-search=native={}", out_dir.display());
                println!("cargo:rustc-link-lib=static={}", obj_filename);
            }
        } else {
            println!("cargo:warning=No object files found for ARM linking");
        }
    } else {
        // For x86-64, we can directly use the assembly files
        println!("cargo:rustc-link-search=native={}", out_dir.display());
    }
}

/// Helper function to find Jasmin compiler
fn find_jasmin_compiler() -> Option<PathBuf> {
    // Try PATH
    if Command::new("jasminc").arg("--version").output().is_ok() {
        println!("cargo:info=Found Jasmin compiler in PATH");
        return Some(PathBuf::from("jasminc"));
    }
    
    None
}



/// Helper function to provide build instructions if dependencies are missing
fn print_build_requirements() {
    println!("cargo:warning=Building formosa-ml-dsa requires:");
    println!("cargo:warning=1. Jasmin compiler (jasminc) in PATH");
    println!("cargo:warning=   Install from: https://github.com/jasmin-lang/jasmin");
    
    let target = env::var("TARGET").unwrap_or_default();
    if target.starts_with("thumbv") || target.contains("arm-none-") {
        println!("cargo:warning=2. ARM cross-compilation toolchain (arm-none-eabi-*)");
        println!("cargo:warning=   Install arm-none-eabi-gcc, arm-none-eabi-as, arm-none-eabi-ar");
    }
    
    println!("cargo:warning=See README.md for detailed installation instructions");
}

/// Create stub implementations for development builds on unsupported platforms
fn create_development_stubs(out_dir: &Path) {
    let stub_c = r#"
// Development stubs for formosa-ml-dsa
// These functions will panic if called - use proper cross-compilation for real functionality

#include <stdlib.h>
#include <stdio.h>

void panic_stub(const char* function_name) {
    fprintf(stderr, "ERROR: %s called in development build. Use cross-compilation for functionality.\n", function_name);
    abort();
}

void ml_dsa_44_keygen(unsigned char *verification_key, unsigned char *signing_key, const unsigned char *seed) {
    panic_stub("ml_dsa_44_keygen");
}

void ml_dsa_44_sign(unsigned char *signature, unsigned long long *sig_len, const unsigned char *message, unsigned long long msg_len, const unsigned char *context, unsigned char context_len, const unsigned char *signing_key, const unsigned char *randomness) {
    panic_stub("ml_dsa_44_sign");
}

int ml_dsa_44_verify(const unsigned char *signature, unsigned long long sig_len, const unsigned char *message, unsigned long long msg_len, const unsigned char *context, unsigned char context_len, const unsigned char *verification_key) {
    panic_stub("ml_dsa_44_verify");
    return -1;
}

void ml_dsa_65_keygen(unsigned char *verification_key, unsigned char *signing_key, const unsigned char *seed) {
    panic_stub("ml_dsa_65_keygen");
}

void ml_dsa_65_sign(unsigned char *signature, unsigned long long *sig_len, const unsigned char *message, unsigned long long msg_len, const unsigned char *context, unsigned char context_len, const unsigned char *signing_key, const unsigned char *randomness) {
    panic_stub("ml_dsa_65_sign");
}

int ml_dsa_65_verify(const unsigned char *signature, unsigned long long sig_len, const unsigned char *message, unsigned long long msg_len, const unsigned char *context, unsigned char context_len, const unsigned char *verification_key) {
    panic_stub("ml_dsa_65_verify");
    return -1;
}

void ml_dsa_87_keygen(unsigned char *verification_key, unsigned char *signing_key, const unsigned char *seed) {
    panic_stub("ml_dsa_87_keygen");
}

void ml_dsa_87_sign(unsigned char *signature, unsigned long long *sig_len, const unsigned char *message, unsigned long long msg_len, const unsigned char *context, unsigned char context_len, const unsigned char *signing_key, const unsigned char *randomness) {
    panic_stub("ml_dsa_87_sign");
}

int ml_dsa_87_verify(const unsigned char *signature, unsigned long long sig_len, const unsigned char *message, unsigned long long msg_len, const unsigned char *context, unsigned char context_len, const unsigned char *verification_key) {
    panic_stub("ml_dsa_87_verify");
    return -1;
}
"#;

    let stub_file = out_dir.join("ml_dsa_stubs.c");
    std::fs::write(&stub_file, stub_c).expect("Failed to write stub file");
    
    // Compile the stub file
    cc::Build::new()
        .file(&stub_file)
        .compile("ml_dsa_stubs");
        
    println!("cargo:info=Using development stubs - functions will panic if called");
}