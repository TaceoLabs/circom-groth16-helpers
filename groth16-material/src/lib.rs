#[cfg(feature = "circom")]
pub mod circom;

/// Errors that can occur during Groth16 proof generation and verification.
#[derive(Debug, thiserror::Error)]
pub enum Groth16Error {
    /// Failed to generate a witness for the circuit.
    #[error("failed to generate witness")]
    WitnessGeneration,
    /// Failed to generate a Groth16 proof.
    #[error("failed to generate proof")]
    ProofGeneration,
    /// Generated proof could not be verified against the verification key.
    #[error("proof could not be verified")]
    InvalidProof,
}
