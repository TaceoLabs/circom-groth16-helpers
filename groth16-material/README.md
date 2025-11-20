# Groth16 Witness and Proof Material helpers

Types and utilities for producing Groth16 proofs.

Currently we support witness generation using [`circom-witness-rs`](https://docs.rs/circom-witness-rs) and proof generation using `ark-groth16`. A wrapper struct holding all the necessary material is provided, along with helper functions to generate the witness and proof.

In the future, support for producing Groth16 proofs from Noir circuits will be added.
