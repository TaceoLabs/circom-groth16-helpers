use ark_bn254::Bn254;
use circom_types::groth16::VerificationKey;
use clap::Parser;
use eyre::Context;
use std::{fs::File, path::PathBuf, process::ExitCode};
use taceo_groth16_sol::askama::Template;
use taceo_groth16_sol::{SolidityVerifierConfig, SolidityVerifierContext};

/// A tool that takes a Circom verification key and generates a Solidity verifier contract for BN254 Groth16 proofs. The solidity contract is based on gnark's Groth16 verifier.
#[derive(Debug, Parser)]
#[command(version, about, long_about = None)]
struct Config {
    /// Path to Circom verification key.
    #[clap(short, long)]
    pub input: PathBuf,

    /// Output of the Solidity file. Write to stdout if omitted.
    #[clap(short, long)]
    pub output: Option<PathBuf>,

    /// The pragma version of the Solidity contract.
    #[clap(long, default_value = "^0.8.0")]
    pub pragma_version: String,
}

fn main() -> eyre::Result<ExitCode> {
    let config = Config::parse();
    let vk = VerificationKey::<Bn254>::from_reader(
        File::open(config.input).context("while opening input file")?,
    )
    .context("while parsing verification-key")?;

    let contract = SolidityVerifierContext {
        vk: vk.into(),
        config: SolidityVerifierConfig {
            pragma_version: config.pragma_version.clone(),
        },
    };
    let rendered = contract.render().unwrap();
    if let Some(output) = config.output {
        std::fs::write(output, rendered).context("while writing output")?;
    } else {
        println!("{rendered}")
    }
    Ok(ExitCode::SUCCESS)
}
