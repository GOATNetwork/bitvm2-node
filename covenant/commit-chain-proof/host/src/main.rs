//! Generate commit chain proof
//! Example:
//!     Genesis:       RUST_LOG=debug cargo run -r
//!     Regular proof: RUST_LOG=debug cargo run -r -- --input-proof "compressed.bin"
use bitcoin_light_client::*;
use zkm_sdk::{
    include_elf, HashableKey, ProverClient, ZKMProof, ZKMProofWithPublicValues, ZKMStdin,
};

/// A program that aggregates the proofs of the simple program.
const COMMIT_CHAIN: &[u8] = include_elf!("guest");

use clap::Parser;
use std::fs;
pub const COMMITS: &[u8] = include_bytes!("../../../../node/tests_data/commits.bin");

/// The arguments for the cli.
#[derive(Debug, Clone, Parser)]
pub struct Args {
    #[clap(long, env, default_value = "none")]
    input_proof: String,

    #[clap(long, env, default_value = "compressed.bin")]
    output: String,
}

fn main() {
    let args = Args::parse();
    // Setup the logger.
    zkm_sdk::utils::setup_logger();

    // Initialize the proving client.
    let client = ProverClient::new();

    // Setup the proving and verifying keys.
    let (commit_chain_proof_pk, commit_chain_proof_vk) = client.setup(COMMIT_CHAIN);

    let vk_hash = commit_chain_proof_vk.hash_u32();

    let commits: Vec<CircuitCommit> = serde_json::from_slice(COMMITS).unwrap();

    // Set the previous proof type based on input_proof argument
    let prev_receipt = if args.input_proof.to_lowercase() == "none" {
        None
    } else {
        let proof_bytes = fs::read(args.input_proof).expect("Failed to read input proof file");
        let proof: ZKMProofWithPublicValues =
            bincode::deserialize(&proof_bytes).expect("failed to deserialize the proof");
        Some(proof)
    };
    let prev_proof = match prev_receipt.clone() {
        Some(mut receipt) => {
            let prev_output: CommitChainCircuitOutput = receipt.public_values.read();
            CommitChainPrevProofType::PrevProof(prev_output)
        }
        None => CommitChainPrevProofType::GenesisBlock,
    };

    let input: CommitChainCircuitInput = CommitChainCircuitInput { vk_hash, prev_proof, commits };

    // Generate the proofs.
    let proof = tracing::info_span!("generate proof").in_scope(|| {
        let mut stdin = ZKMStdin::new();
        stdin.write(&input);
        if let Some(proof) = prev_receipt {
            let ZKMProof::Compressed(compressed_proof) = proof.proof else { todo!() };
            stdin.write_proof(*compressed_proof, commit_chain_proof_vk.vk);
        } else {
            println!("Skip writing proof for genesis commit");
        }
        client.prove(&commit_chain_proof_pk, stdin).compressed().run().expect("proving failed")
    });

    fs::write(&args.output, bincode::serialize(&proof).unwrap()).unwrap();
    println!("Generate proof successfully, proof: {:?}", proof);
}
