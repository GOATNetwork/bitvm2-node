//! Generate header chain proof
//! Example:
//! ```
//! RUST_LOG=debug cargo run -r -- --latest-sequencer-commit-txid a202e9c6cfd2274c56c35fea3d950fdbba84946d7c29fd809d6d0d6e456cd8e7 --header-chain-input-proof ../../header-chain-proof/host/0-10.bin --commit-chain-input-proof ../../commit-chain-proof/host/compressed.bin --output "output.bin"
//! ```
use header_chain::{
    BlockHeaderCircuitOutput, HeaderChainCircuitInput, HeaderChainPrevProofType,
    verify_merkle_proof, BlockInclusionProof, BitcoinMerkleTree,
};
use zkm_sdk::{
    include_elf, HashableKey, ProverClient, ZKMProof, ZKMProofWithPublicValues, ZKMStdin,
};
use bitcoin_light_client::{CommitChainCircuitInput, CommitChainCircuitOutput, CommitChainPrevProofType};

/// A program that aggregates the proofs of the simple program.
const WTACHTOWER: &[u8] = include_elf!("guest");

use clap::Parser;
use std::fs;

fn parse_hex_32(s: &str) -> Result<[u8; 32], String> {
    let mut reversed: [u8; 32] = hex::decode(s).map_err(|e| e.to_string())?.try_into().map_err(|_| "invalid length".to_string())?;
    reversed.reverse();
    Ok(reversed)
}

/// The arguments for the cli.
#[derive(Debug, Clone, Parser)]
pub struct Args {
    #[clap(long, env, value_parser = parse_hex_32)]
    latest_sequencer_commit_txid: [u8; 32],

    #[clap(long, env, short)]
    header_chain_input_proof: String,

    #[clap(long, env, short)]
    commit_chain_input_proof: String,

    #[clap(long, env, default_value = "compressed.bin")]
    output: String,
}

// Build the block inclusion proof of args.latest_sequencer_commit_txid
fn build_block_inclusion_proof(args: &Args) -> BlockInclusionProof {
    let txid = args.latest_sequencer_commit_txid; 
    let bitcoin_merkle_tree = BitcoinMerkleTree::new(vec![txid]);
    let bitcoin_merkle_proof = bitcoin_merkle_tree.generate_proof(0);
    assert!(verify_merkle_proof(
        txid,
        &bitcoin_merkle_proof,
        bitcoin_merkle_tree.root()
    ));
    bitcoin_merkle_proof
}

#[tokio::main]
async fn main() {
    let args = Args::parse();
    // fetch_header_chain(&args).await;
    // fetch_commit_chain(&args).await;
    // Setup the logger.
    zkm_sdk::utils::setup_logger();

    // Initialize the proving client.
    let client = ProverClient::new();

    // Setup the proving and verifying keys.
    let (watchtower_proof_pk, watchtower_proof_vk) = client.setup(WTACHTOWER);

    // --- header chain --- //
    let proof_bytes = fs::read(&args.header_chain_input_proof).expect("Failed to read input proof file");
    let mut proof: ZKMProofWithPublicValues =
        bincode::deserialize(&proof_bytes).expect("failed to deserialize the proof");
    let prev_output: BlockHeaderCircuitOutput = proof.public_values.read();
    let ZKMProof::Compressed(header_compressed_proof) = proof.proof else { todo!() };
    let header_chain_prev_proof = HeaderChainPrevProofType::PrevProof(prev_output.clone());

    let bytes = std::fs::read(&format!("{}.vk", args.header_chain_input_proof)).unwrap();
    let header_chain_vk: zkm_sdk::ZKMVerifyingKey = bincode::deserialize(&bytes).unwrap(); 
    assert_eq!(prev_output.vk_hash, header_chain_vk.hash_u32());

    let bytes = std::fs::read(&format!("{}.in", args.header_chain_input_proof)).unwrap();
    let header_chain_input: HeaderChainCircuitInput = bincode::deserialize(&bytes).unwrap();

    //let header_chain_input: HeaderChainCircuitInput = HeaderChainCircuitInput {
    //    vk_hash: header_chain_vk.hash_u32(),
    //    prev_proof: header_chain_prev_proof,
    //    block_headers,
    //};

    // --- commit chain --- //
    // Set the previous proof type based on input_proof argument
    let proof_bytes = fs::read(&args.commit_chain_input_proof).expect("Failed to read input proof file");
    let mut proof: ZKMProofWithPublicValues =
        bincode::deserialize(&proof_bytes).expect("failed to deserialize the proof");
    let prev_output: CommitChainCircuitOutput = proof.public_values.read();
    let ZKMProof::Compressed(commit_compressed_proof) = proof.proof else { todo!() };
    let commit_chain_prev_proof = CommitChainPrevProofType::PrevProof(prev_output.clone());

    let bytes = std::fs::read(&format!("{}.vk", args.commit_chain_input_proof)).unwrap();
    let commit_chain_vk: zkm_sdk::ZKMVerifyingKey = bincode::deserialize(&bytes).unwrap(); 
    assert_eq!(prev_output.vk_hash, commit_chain_vk.hash_u32());
    //let commit_chain_input: CommitChainCircuitInput = CommitChainCircuitInput {
    //    vk_hash: commit_chain_vk.hash_u32(),
    //    prev_proof: commit_chain_prev_proof,
    //    commits: vec![],
    //};
    let bytes = std::fs::read(&format!("{}.in", args.commit_chain_input_proof)).unwrap();
    let commit_chain_input: CommitChainCircuitInput = bincode::deserialize(&bytes).unwrap();

    let latest_sequencer_commit_txid_inclusion_proof: BlockInclusionProof = build_block_inclusion_proof(&args); 

    assert!(verify_merkle_proof(
        args.latest_sequencer_commit_txid.clone(),
        &latest_sequencer_commit_txid_inclusion_proof,
        header_chain_input.block_headers[header_chain_input.block_headers.len() - 1].merkle_root.clone(),
    ));

    // Generate the proofs.
    let proof = tracing::info_span!("generate proof").in_scope(|| {
        let mut stdin = ZKMStdin::new();
        stdin.write(&args.latest_sequencer_commit_txid);
        stdin.write(&header_chain_input);
        stdin.write(&commit_chain_input);
        stdin.write(&latest_sequencer_commit_txid_inclusion_proof);

        stdin.write_proof(*header_compressed_proof, header_chain_vk.vk);
        stdin.write_proof(*commit_compressed_proof, commit_chain_vk.vk);
        client.prove(&watchtower_proof_pk, stdin).groth16().run().expect("proving failed")
    });

    fs::write(&args.output, bincode::serialize(&proof).unwrap()).unwrap();
    fs::write(&format!("{}.vk", args.output), bincode::serialize(&watchtower_proof_vk).unwrap()).unwrap();
    println!("Generate proof successfully, proof: {:?}", proof);
}
