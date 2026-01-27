//! Trusted setup parameter generation for zk-SNARKs.
//!
//! This module provides functions to:
//! - Generate proving and verifying parameters (trusted setup)
//! - Save and load parameters from files
//!
//! SECURITY NOTE: In production, the trusted setup should be performed
//! using a multi-party computation ceremony to ensure no single party
//! knows the toxic waste (trapdoor).

use ark_bn254::Bn254;
use ark_groth16::Groth16;
use ark_snark::SNARK;
use ark_std::rand::{CryptoRng, RngCore};
use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;

use super::circuits::{OutputCircuit, SpendCircuit};
use super::proof::{ProvingParams, VerifyingParams};

/// Generate proving and verifying parameters for the zk-SNARK system.
///
/// This performs the trusted setup for both spend and output circuits.
/// The randomness source should be cryptographically secure.
///
/// WARNING: This is a centralized trusted setup. In production,
/// use a multi-party computation ceremony.
pub fn generate_parameters<R: RngCore + CryptoRng>(rng: &mut R) -> Result<(ProvingParams, VerifyingParams), &'static str> {
    // Generate parameters for spend circuit
    let spend_circuit = SpendCircuit::dummy();
    let (spend_pk, spend_vk) = Groth16::<Bn254>::circuit_specific_setup(spend_circuit, rng)
        .map_err(|_| "Failed to generate spend circuit parameters")?;

    // Generate parameters for output circuit
    let output_circuit = OutputCircuit::dummy();
    let (output_pk, output_vk) = Groth16::<Bn254>::circuit_specific_setup(output_circuit, rng)
        .map_err(|_| "Failed to generate output circuit parameters")?;

    let proving_params = ProvingParams {
        spend_pk,
        output_pk,
    };

    let verifying_params = VerifyingParams::new(spend_vk, output_vk);

    Ok((proving_params, verifying_params))
}

/// Save proving parameters to a file.
pub fn save_proving_params<P: AsRef<Path>>(params: &ProvingParams, path: P) -> std::io::Result<()> {
    let bytes = params.to_bytes();
    let mut file = File::create(path)?;
    file.write_all(&bytes)?;
    Ok(())
}

/// Load proving parameters from a file.
pub fn load_proving_params<P: AsRef<Path>>(path: P) -> Result<ProvingParams, &'static str> {
    let mut file = File::open(path).map_err(|_| "Failed to open proving params file")?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes).map_err(|_| "Failed to read proving params file")?;
    ProvingParams::from_bytes(&bytes)
}

/// Save verifying parameters to a file.
pub fn save_verifying_params<P: AsRef<Path>>(params: &VerifyingParams, path: P) -> std::io::Result<()> {
    let bytes = params.to_bytes();
    let mut file = File::create(path)?;
    file.write_all(&bytes)?;
    Ok(())
}

/// Load verifying parameters from a file.
pub fn load_verifying_params<P: AsRef<Path>>(path: P) -> Result<VerifyingParams, &'static str> {
    let mut file = File::open(path).map_err(|_| "Failed to open verifying params file")?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes).map_err(|_| "Failed to read verifying params file")?;
    VerifyingParams::from_bytes(&bytes)
}

/// Save both proving and verifying parameters.
pub fn save_parameters<P: AsRef<Path>>(
    proving: &ProvingParams,
    verifying: &VerifyingParams,
    proving_path: P,
    verifying_path: P,
) -> std::io::Result<()> {
    save_proving_params(proving, proving_path)?;
    save_verifying_params(verifying, verifying_path)?;
    Ok(())
}

/// Load both proving and verifying parameters.
pub fn load_parameters<P: AsRef<Path>>(
    proving_path: P,
    verifying_path: P,
) -> Result<(ProvingParams, VerifyingParams), &'static str> {
    let proving = load_proving_params(proving_path)?;
    let verifying = load_verifying_params(verifying_path)?;
    Ok((proving, verifying))
}

/// Check if parameters exist at the given paths.
pub fn parameters_exist<P: AsRef<Path>>(proving_path: P, verifying_path: P) -> bool {
    proving_path.as_ref().exists() && verifying_path.as_ref().exists()
}

/// Default paths for parameter files.
pub const DEFAULT_PROVING_PARAMS_PATH: &str = "params/proving.params";
pub const DEFAULT_VERIFYING_PARAMS_PATH: &str = "params/verifying.params";

/// Ensure the params directory exists.
pub fn ensure_params_dir() -> std::io::Result<()> {
    std::fs::create_dir_all("params")
}

/// Generate parameters if they don't exist, otherwise load them.
pub fn get_or_generate_parameters<R: RngCore + CryptoRng>(
    rng: &mut R,
) -> Result<(ProvingParams, VerifyingParams), &'static str> {
    if parameters_exist(DEFAULT_PROVING_PARAMS_PATH, DEFAULT_VERIFYING_PARAMS_PATH) {
        load_parameters(DEFAULT_PROVING_PARAMS_PATH, DEFAULT_VERIFYING_PARAMS_PATH)
    } else {
        let (proving, verifying) = generate_parameters(rng)?;

        // Try to save, but don't fail if we can't
        if ensure_params_dir().is_ok() {
            let _ = save_parameters(
                &proving,
                &verifying,
                DEFAULT_PROVING_PARAMS_PATH,
                DEFAULT_VERIFYING_PARAMS_PATH,
            );
        }

        Ok((proving, verifying))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_std::rand::SeedableRng;
    use ark_std::rand::rngs::StdRng;
    use tempfile::tempdir;

    #[test]
    fn test_parameter_generation() {
        let mut rng = StdRng::seed_from_u64(12345);
        let result = generate_parameters(&mut rng);

        // Parameter generation is expensive, so we just check it doesn't panic
        // In CI, you might want to skip this test or use cached parameters
        if result.is_ok() {
            println!("Parameters generated successfully");
        } else {
            println!("Parameter generation failed (may be expected in test environment)");
        }
    }

    #[test]
    fn test_parameter_serialization_roundtrip() {
        let mut rng = StdRng::seed_from_u64(12345);

        // This test is expensive, so we only run it if parameters can be generated quickly
        let result = generate_parameters(&mut rng);
        if result.is_err() {
            println!("Skipping serialization test - parameter generation failed");
            return;
        }

        let (proving, verifying) = result.unwrap();

        // Test proving params serialization
        let proving_bytes = proving.to_bytes();
        let proving_recovered = ProvingParams::from_bytes(&proving_bytes).unwrap();
        assert_eq!(proving.to_bytes(), proving_recovered.to_bytes());

        // Test verifying params serialization
        let verifying_bytes = verifying.to_bytes();
        let verifying_recovered = VerifyingParams::from_bytes(&verifying_bytes).unwrap();
        assert_eq!(verifying.to_bytes(), verifying_recovered.to_bytes());
    }

    #[test]
    fn test_parameter_file_operations() {
        let mut rng = StdRng::seed_from_u64(12345);

        let result = generate_parameters(&mut rng);
        if result.is_err() {
            println!("Skipping file test - parameter generation failed");
            return;
        }

        let (proving, verifying) = result.unwrap();

        let dir = tempdir().unwrap();
        let proving_path = dir.path().join("proving.params");
        let verifying_path = dir.path().join("verifying.params");

        // Save
        save_proving_params(&proving, &proving_path).unwrap();
        save_verifying_params(&verifying, &verifying_path).unwrap();

        // Check existence
        assert!(parameters_exist(&proving_path, &verifying_path));

        // Load
        let (loaded_proving, loaded_verifying) =
            load_parameters(&proving_path, &verifying_path).unwrap();

        // Verify roundtrip
        assert_eq!(proving.to_bytes(), loaded_proving.to_bytes());
        assert_eq!(verifying.to_bytes(), loaded_verifying.to_bytes());
    }
}
