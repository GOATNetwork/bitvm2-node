//! Generate header chain proof
//! Example:
//!     Genesis:       RUST_LOG=debug cargo run -r
//!     Regular proof: RUST_LOG=debug cargo run -r -- --input-proof "compressed.bin"
use borsh::BorshDeserialize;
use header_chain::{
    BlockHeaderCircuitOutput, CircuitBlockHeader, HeaderChainCircuitInput, HeaderChainPrevProofType,
};
use zkm_sdk::{
    include_elf, HashableKey, ProverClient, ZKMProof, ZKMProofWithPublicValues, ZKMStdin,
};

/// A program that aggregates the proofs of the simple program.
const HEADER_CHAIN: &[u8] = include_elf!("guest");
pub const HEADERS: &[u8] = include_bytes!("../../../node/tests_data/first_100_blocks.bin");

use clap::Parser;
use std::fs;

/// The arguments for the cli.
#[derive(Debug, Clone, Parser)]
pub struct Args {
    #[clap(long, env, default_value_t = 4)]
    batch_size: usize,

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
    let (header_chain_proof_pk, header_chain_proof_vk) = client.setup(HEADER_CHAIN);

    let vk_hash = header_chain_proof_vk.hash_u32();
    let block_headers = HEADERS
        .chunks(80)
        .map(|header| CircuitBlockHeader::try_from_slice(header).unwrap())
        .collect::<Vec<CircuitBlockHeader>>();
    let mut start = 0;
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
            let prev_output: BlockHeaderCircuitOutput = receipt.public_values.read();
            start = prev_output.chain_state.block_height as usize + 1;
            HeaderChainPrevProofType::PrevProof(prev_output)
        }
        None => HeaderChainPrevProofType::GenesisBlock,
    };
    println!(
        "header-chain length: {}, start: {}, batch_size: {}",
        block_headers.len(),
        start,
        args.batch_size
    );
    let input: HeaderChainCircuitInput = HeaderChainCircuitInput {
        vk_hash,
        prev_proof,
        block_headers: block_headers[start..start + args.batch_size].to_vec(),
    };

    // Generate the proofs.
    let proof = tracing::info_span!("generate proof").in_scope(|| {
        let mut stdin = ZKMStdin::new();
        stdin.write(&input);
        if let Some(proof) = prev_receipt {
            println!("Write proof for regular header chain");
            let ZKMProof::Compressed(compressed_proof) = proof.proof else { todo!() };
            stdin.write_proof(*compressed_proof, header_chain_proof_vk.vk);
        } else {
            println!("Skip writing proof for genesis block");
        }
        client.prove(&header_chain_proof_pk, stdin).compressed().run().expect("proving failed")
    });

    fs::write(&args.output, bincode::serialize(&proof).unwrap()).unwrap();
    println!("Generate proof successfully, proof: {:?}", proof);
}
