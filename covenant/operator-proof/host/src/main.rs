//! Generate header chain proof
//! Example:
//! ```
//! RUST_LOG=debug cargo run -r -- --latest-sequencer-commit-txid a202e9c6cfd2274c56c35fea3d950fdbba84946d7c29fd809d6d0d6e456cd8e7 --header-chain-input-proof ../../header-chain-proof/host/0-10.bin --commit-chain-input-proof ../../commit-chain-proof/host/compressed.bin --output "output.bin" --block-hashes ../../header-chain-proof/host/block_hashes.bin
//! ```
use client::btc_chain::BTCClient;
use header_chain::{
    BitcoinMerkleTree, BlockHeaderCircuitOutput, CircuitBlockHeader, CircuitTransaction,
    HeaderChainCircuitInput, HeaderChainPrevProofType, MMRHost, SPV,
};
use zkm_sdk::{
    include_elf, HashableKey, ProverClient, ZKMProof, ZKMProofWithPublicValues, ZKMStdin,
};

use alloy_primitives::U256;
use bitcoin::{Network, Txid};
use bitcoin_light_client::{
    CommitChainCircuitInput, CommitChainCircuitOutput, CommitChainPrevProofType,
};
use std::str::FromStr;

/// A program that aggregates the proofs of the simple program.
const WTACHTOWER: &[u8] = include_elf!("guest");

use clap::Parser;
use std::fs;

fn str_to_16_bytes_exact(s: &str) -> Result<[u8; 16], String> {
    let bytes = s.as_bytes();
    assert_eq!(bytes.len(), 16, "string must be exactly 16 bytes");
    let mut arr = [0u8; 16];
    arr.copy_from_slice(bytes);
    Ok(arr)
}

/// The arguments for the cli.
#[derive(Debug, Clone, Parser)]
pub struct Args {
    #[arg(long, default_value = "http://127.0.0.1:3002")]
    esplora_url: String,

    #[clap(long, env)]
    included_watchertowers: String,

    #[clap(long, env, value_parser = str_to_16_bytes_exact)]
    graph_id: [u8; 16],

    #[clap(long, env)]
    latest_sequencer_commit_txid: String,

    #[clap(long, env, short)]
    header_chain_input_proof: String,

    #[clap(long, env, short)]
    commit_chain_input_proof: String,

    #[clap(long, env, short)]
    block_hashes: String,

    #[clap(long, env, default_value = "compressed.bin")]
    output: String,
}

#[tokio::main]
async fn main() {
    let args = Args::parse();
    // Setup the logger.
    zkm_sdk::utils::setup_logger();

    // Initialize the proving client.
    let client = ProverClient::new();

    // Setup the proving and verifying keys.
    let (proof_pk, proof_vk) = client.setup(WTACHTOWER);

    // --- header chain --- //
    let proof_bytes =
        fs::read(&args.header_chain_input_proof).expect("Failed to read input proof file");
    let mut proof: ZKMProofWithPublicValues =
        bincode::deserialize(&proof_bytes).expect("failed to deserialize the proof");
    let prev_output: BlockHeaderCircuitOutput = proof.public_values.read();
    let ZKMProof::Compressed(header_compressed_proof) = proof.proof else { panic!() };
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
    let proof_bytes =
        fs::read(&args.commit_chain_input_proof).expect("Failed to read input proof file");
    let mut proof: ZKMProofWithPublicValues =
        bincode::deserialize(&proof_bytes).expect("failed to deserialize the proof");
    let prev_output: CommitChainCircuitOutput = proof.public_values.read();
    let ZKMProof::Compressed(commit_compressed_proof) = proof.proof else { panic!() };
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

    // --- spv --- //
    let network = Network::Regtest;
    let btc_client = BTCClient::new(network.into(), Some(&args.esplora_url));
    let tx = btc_client
        .fetch_btc_tx(&Txid::from_str(&args.latest_sequencer_commit_txid).unwrap())
        .await
        .unwrap();
    let tx: CircuitTransaction = CircuitTransaction(tx);
    let block_header: CircuitBlockHeader =
        header_chain_input.block_headers[header_chain_input.block_headers.len() - 1].clone();
    let bitcoin_merkle_tree: BitcoinMerkleTree = BitcoinMerkleTree::new(vec![tx.txid()]);
    let bitcoin_inclusion_proof = bitcoin_merkle_tree.generate_proof(0);

    let mut mmr_native = MMRHost::new();
    let block_hashes_bytes = std::fs::read(&args.block_hashes).unwrap();
    let block_hashes: Vec<[u8; 32]> = bincode::deserialize(&block_hashes_bytes).unwrap();

    for block_hash in block_hashes.iter() {
        mmr_native.append(*block_hash);
    }

    let (_, mmr_inclusion_proof) = mmr_native.generate_proof(0);
    let spv: SPV = SPV::new(tx, bitcoin_inclusion_proof, block_header, mmr_inclusion_proof);

    let output = bitcoin_light_client::header_chain_circuit(header_chain_input.clone());
    assert!(spv.verify(&output.chain_state.block_hashes_mmr));

    // Generate the proofs.
    let proof = tracing::info_span!("generate proof").in_scope(|| {
        let mut stdin = ZKMStdin::new();

        let included_watchertowers: U256 = U256::from_str(&args.included_watchertowers).unwrap();
        stdin.write(&included_watchertowers);

        stdin.write(&args.graph_id);

        // let operator_latest_sequencer_commit_txn: CircuitTransaction = zkm_zkvm::io::read(); // private inputs
        // let consensus_blocks: [LightBlock; 2] = zkm_zkvm::io::read(); // commit the sequencer set
        // let eth_client_execution_input: EthClientExecutorInput = zkm_zkvm::io::read();

        // let watchtower_challenge_txns: Vec<CircuitTransaction> = zkm_zkvm::io::read();
        // let watchtower_challenge_txn_script: Vec<ScriptBuf> = zkm_zkvm::io::read();
        // let watchtower_challenge_txn_prev_out: Vec<TxOut> = zkm_zkvm::io::read();
        // let watchtower_challenge_txn_pubkey: Vec<bitcoin::secp256k1::PublicKey> = zkm_zkvm::io::read();
        // let watchtower_challenge_txn_sig: Vec<bitcoin::taproot::Signature> = zkm_zkvm::io::read();

        stdin.write(&header_chain_input);
        stdin.write(&commit_chain_input);
        stdin.write(&spv);

        stdin.write_proof(*header_compressed_proof, header_chain_vk.vk);
        stdin.write_proof(*commit_compressed_proof, commit_chain_vk.vk);
        client.prove(&proof_pk, stdin).groth16().run().expect("proving failed")
    });

    fs::write(&args.output, bincode::serialize(&proof).unwrap()).unwrap();
    fs::write(&format!("{}.vk", args.output), bincode::serialize(&proof_vk).unwrap()).unwrap();
    println!("Generate proof successfully, proof: {:?}", proof);
}
