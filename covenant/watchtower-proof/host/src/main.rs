//! Generate header chain proof
//! Example:
//! ```
//! export BITCOIN_NETWORK=regtest
//! RUST_LOG=debug cargo run -r -- --latest-sequencer-commit-txid 7b5fde8cc49a0afe1bfd6534d63d3549d4b03394dab978642db866b74f6fa62c --header-chain-input-proof ../../header-chain-proof/host/0-10.bin --commit-chain-input-proof ../../commit-chain-proof/host/compressed.bin --output "output.bin"
//! ```
use client::btc_chain::BTCClient;
use header_chain::{
    BitcoinMerkleTree, BlockHeaderCircuitOutput, CircuitBlockHeader, CircuitTransaction,
    HeaderChainCircuitInput, MMRHost, SPV, verify_merkle_proof
};
use zkm_sdk::{
    include_elf, HashableKey, ProverClient, ZKMProof, ZKMProofWithPublicValues, ZKMStdin,
};

use bitcoin::{Network, Txid, hashes::Hash};
use bitcoin_light_client::{
    CommitChainCircuitInput, CommitChainCircuitOutput,
};
use std::str::FromStr;

/// A program that aggregates the proofs of the simple program.
const WTACHTOWER: &[u8] = include_elf!("guest");

use clap::Parser;
use std::fs;

/// The arguments for the cli.
#[derive(Debug, Clone, Parser)]
pub struct Args {
    #[arg(long, default_value = "http://127.0.0.1:3002")]
    esplora_url: String,

    #[clap(long, env)]
    latest_sequencer_commit_txid: String,

    #[clap(long, env, short)]
    header_chain_input_proof: String,

    #[clap(long, env, short)]
    commit_chain_input_proof: String,

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
    let (watchtower_proof_pk, watchtower_proof_vk) = client.setup(WTACHTOWER);

    // --- header chain --- //
    let proof_bytes =
        fs::read(&args.header_chain_input_proof).expect("Failed to read input proof file");
    let mut proof: ZKMProofWithPublicValues =
        bincode::deserialize(&proof_bytes).expect("failed to deserialize the proof");
    let header_chain_prev_output: BlockHeaderCircuitOutput = proof.public_values.read();
    let ZKMProof::Compressed(header_compressed_proof) = proof.proof else { panic!() };
    //let header_chain_prev_proof = HeaderChainPrevProofType::PrevProof(header_chain_prev_output.clone());

    let bytes = std::fs::read(&format!("{}.vk", args.header_chain_input_proof)).unwrap();
    let header_chain_vk: zkm_sdk::ZKMVerifyingKey = bincode::deserialize(&bytes).unwrap();
    assert_eq!(header_chain_prev_output.vk_hash, header_chain_vk.hash_u32());

    let bytes = std::fs::read(&format!("{}.in", args.header_chain_input_proof)).unwrap();
    let header_chain_input: HeaderChainCircuitInput = bincode::deserialize(&bytes).unwrap();

    // --- commit chain --- //
    // Set the previous proof type based on input_proof argument
    let proof_bytes =
        fs::read(&args.commit_chain_input_proof).expect("Failed to read input proof file");
    let mut proof: ZKMProofWithPublicValues =
        bincode::deserialize(&proof_bytes).expect("failed to deserialize the proof");
    let prev_output: CommitChainCircuitOutput = proof.public_values.read();
    let ZKMProof::Compressed(commit_compressed_proof) = proof.proof else { panic!() };

    let bytes = std::fs::read(&format!("{}.vk", args.commit_chain_input_proof)).unwrap();
    let commit_chain_vk: zkm_sdk::ZKMVerifyingKey = bincode::deserialize(&bytes).unwrap();
    assert_eq!(prev_output.vk_hash, commit_chain_vk.hash_u32());

    let bytes = std::fs::read(&format!("{}.in", args.commit_chain_input_proof)).unwrap();
    let commit_chain_input: CommitChainCircuitInput = bincode::deserialize(&bytes).unwrap();

    // --- spv --- //
    let network = Network::Regtest;
    let btc_client = BTCClient::new(network.into(), Some(&args.esplora_url));
    let latest_sequencer_commit_txid = Txid::from_str(&args.latest_sequencer_commit_txid).unwrap();
    let tx = btc_client
        .fetch_btc_tx(&latest_sequencer_commit_txid)
        .await
        .unwrap();
    let tx: CircuitTransaction = CircuitTransaction(tx);
    assert_eq!(latest_sequencer_commit_txid, tx.0.compute_txid());

    println!("add mmr");
    let mut mmr_native = MMRHost::new();
    for j in 0..header_chain_input.block_headers.len() {
        mmr_native.append(header_chain_input.block_headers[j].compute_block_hash());
    }

    let tx_merkle_proof  = btc_client
        .get_btc_merkle_proof(&latest_sequencer_commit_txid)
        .await
        .unwrap();
    let block_pos = tx_merkle_proof.1.block_height;

    let target_block_header: CircuitBlockHeader =
        header_chain_input.block_headers[block_pos as usize].clone();
    
    // find the target block
    let target_block  = btc_client.fetch_btc_block(block_pos).await.unwrap();
    let tx_pos = target_block.txdata.iter().position(|x| x.compute_txid() == latest_sequencer_commit_txid);
    let txid_list =
        target_block.txdata.iter().map(|x| x.compute_txid().to_byte_array()).collect();

    let bitcoin_merkle_tree: BitcoinMerkleTree = BitcoinMerkleTree::new(txid_list);
    let bitcoin_inclusion_proof = bitcoin_merkle_tree.generate_proof(tx_pos.unwrap() as u32);

    println!("verify merkle proof");
    if !(verify_merkle_proof(
            latest_sequencer_commit_txid.to_byte_array(),
            &bitcoin_inclusion_proof,
            bitcoin_merkle_tree.root(),
    )) {
        panic!("Can not verify merkle proof")
    }

    println!("generate proof from mmr native");

    let (_, mmr_inclusion_proof) = mmr_native.generate_proof(block_pos as u32);

    println!("constuct spv");
    let spv: SPV = SPV::new(tx, bitcoin_inclusion_proof, target_block_header, mmr_inclusion_proof);
    assert!(spv.verify(&header_chain_prev_output.chain_state.block_hashes_mmr));
    let btc_header_chain_output = bitcoin_light_client::header_chain_circuit(header_chain_input.clone());
    assert!(spv.verify(&btc_header_chain_output.chain_state.block_hashes_mmr));

    // Generate the proofs.
    let proof = tracing::info_span!("generate proof").in_scope(|| {
        let mut stdin = ZKMStdin::new();
        stdin.write(&latest_sequencer_commit_txid.to_byte_array());
        stdin.write(&header_chain_input);
        stdin.write(&commit_chain_input);
        stdin.write(&spv);

        stdin.write_proof(*header_compressed_proof, header_chain_vk.vk);
        stdin.write_proof(*commit_compressed_proof, commit_chain_vk.vk);
        client.prove(&watchtower_proof_pk, stdin).groth16().run().expect("proving failed")
    });

    fs::write(&args.output, bincode::serialize(&proof).unwrap()).unwrap();
    fs::write(&format!("{}.vk", args.output), bincode::serialize(&watchtower_proof_vk).unwrap())
        .unwrap();
    println!("Generate proof successfully, proof: {:?}", proof);
}
