//! A crate for generating Solidity verifier contracts for BN254 Groth16 proofs.
//! This crate uses the `askama` templating engine to render Solidity code based on
//! the provided verifying key and configuration options.
//!
//! The solidity contract is based on the [Groth16 verifier implementation from
//! gnark](https://github.com/Consensys/gnark/blob/9c9cf0deb462ea302af36872669457c36da0f160/backend/groth16/bn254/solidity.go),
//! with minor modifications to be compatible with the [askama] crate.
//!
//! # Example usage
//! ```rust,no_run
//! # fn load_verification_key() -> ark_groth16::VerifyingKey<ark_bn254::Bn254> { todo!() }
//! use taceo_groth16_sol::{SolidityVerifierConfig, SolidityVerifierContext};
//! use askama::Template;
//!
//! let config = SolidityVerifierConfig::default();
//! let vk : ark_groth16::VerifyingKey<ark_bn254::Bn254> = load_verification_key();
//! let contract = SolidityVerifierContext {
//!     vk,
//!     config,
//! };
//! let rendered = contract.render().unwrap();
//! println!("{}", rendered);
//! // You can also write the rendered contract to a file, see askama documentation for details
//! let mut file = std::fs::File::create("Verifier.sol").unwrap();
//! contract.write_into(&mut file).unwrap();
//! ```
//!
//! # Preparing proofs
//! The crate also provides utility functions to prepare Groth16 proofs for verification in the generated contract.
//! The proofs can be prepared in either compressed or uncompressed format, depending on the specific deployment of the verifier contract.
//! See <https://2π.com/23/bn254-compression> for explanation of the point compression scheme used and explanation of the gas tradeoffs.
//!
//! ```rust,no_run
//! # fn load_proof() -> ark_groth16::Proof<ark_bn254::Bn254> { todo!() }
//! let proof: ark_groth16::Proof<ark_bn254::Bn254> = load_proof();
//! let compressed_proof = taceo_groth16_sol::prepare_compressed_proof(&proof);
//! let uncompressed_proof = taceo_groth16_sol::prepare_uncompressed_proof(&proof);
//! ```
#![deny(missing_docs)]

use alloy_primitives::U256;
use ark_bn254::{Fq, G1Affine, G2Affine};
use ark_ec::AffineRepr;
use ark_ff::Field;
use ark_groth16::{Proof, VerifyingKey};
use askama::Template;

/// Re-export askama for users of this crate
pub use askama;

/// Context for generating a Solidity verifier contract for BN254 Groth16 proofs.
/// The context is passed to `askama` for template rendering.
/// Parameters:
/// - `vk`: The [verifying key](ark_groth16::VerifyingKey) for the BN254 curve.
/// - `config`: Configuration options for the Solidity verifier contract generation.
#[derive(Debug, Clone, Template)]
#[template(path = "../templates/bn254_verifier.sol", escape = "none")]
pub struct SolidityVerifierContext {
    /// The Groth16 verifying key
    pub vk: VerifyingKey<ark_bn254::Bn254>,
    /// Configuration options for the Solidity verifier contract generation
    pub config: SolidityVerifierConfig,
}

/// Configuration for the Solidity verifier contract generation.
///
/// Parameters:
/// - `pragma_version`: The Solidity pragma version to use in the generated contract. Default is "^0.8.0".
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SolidityVerifierConfig {
    /// The Solidity pragma version to use in the generated contract. Default is "^0.8.0".
    pub pragma_version: String,
}

impl Default for SolidityVerifierConfig {
    fn default() -> Self {
        Self {
            pragma_version: "^0.8.0".to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use askama::Template;
    use taceo_circom_types::groth16::VerificationKey;

    const TEST_VK_BN254: &str = include_str!("../data/test_verification_key.json");
    const TEST_GNARK_OUTPUT: &str = include_str!("../data/gnark_output.txt");

    #[test]
    fn test() {
        let config = super::SolidityVerifierConfig::default();
        let vk = serde_json::from_str::<VerificationKey<ark_bn254::Bn254>>(TEST_VK_BN254).unwrap();
        let contract = super::SolidityVerifierContext {
            vk: vk.into(),
            config,
        };

        let rendered = contract.render().unwrap();
        // Askama supresses trailing newlines, so we add one for comparison
        let rendered = format!("{}\n", rendered);
        assert_eq!(rendered, TEST_GNARK_OUTPUT);
    }
}
