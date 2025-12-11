#![feature(trim_prefix_suffix)]
//! Generate watchtower proof
//!
use borsh::BorshDeserialize;
use client::btc_chain::BTCClient;
use header_chain::{CircuitBlockHeader, HeaderChainCircuitInput, HeaderChainPrevProofType};
use zkm_sdk::{
    HashableKey, Prover, ProverClient, ZKMProof, ZKMProofKind, ZKMProofWithPublicValues, ZKMStdin,
    include_elf,
};

use bitcoin::{Network, Txid, hashes::Hash};
use bitcoin_light_client_circuit::build_spv;
use commit_chain::{CommitChainCircuitInput, CommitChainPrevProofType};
use sha2::{Digest, Sha256};
use state_chain::{StateChainCircuitInput, StateChainPrevProofType};
use std::str::FromStr;
use std::sync::OnceLock;
static ELF_ID: OnceLock<String> = OnceLock::new();

/// A program that aggregates the proofs of the simple program.
const WTACHTOWER: &[u8] = include_elf!("guest");

use clap::Parser;
use std::fs;

// The arguments for the cli.
#[derive(Debug, Clone, Parser)]
pub struct Args {
    #[arg(long, default_value = "http://127.0.0.1:3002")]
    esplora_url: String,

    #[clap(long, env)]
    genesis_sequencer_commit_txid: String,

    #[clap(long, env)]
    latest_sequencer_commit_txid: String,

    #[clap(long, env, short)]
    header_chain_input_proof: String,

    #[clap(long, env, short)]
    commit_chain_input_proof: String,

    #[clap(long, env, short)]
    state_chain_input_proof: String,

    #[clap(long, env)]
    output: String,

    #[clap(long, env, default_value = "data/header-chain/block_headers.bin")]
    block_headers: String,
}

#[tokio::main]
async fn main() {
    dotenv::dotenv().ok();
    let args = Args::parse();
    // Setup the logger.
    zkm_sdk::utils::setup_logger();

    // Initialize the proving client.
    let client = ProverClient::new();

    // Setup the proving and verifying keys.
    let (watchtower_proof_pk, watchtower_proof_vk) = client.setup(WTACHTOWER);

    // --- header chain --- //
    let bytes = std::fs::read(&format!("{}.in", args.header_chain_input_proof)).unwrap();
    let mut header_chain_input: HeaderChainCircuitInput = bincode::deserialize(&bytes).unwrap();

    let proof_bytes =
        fs::read(&args.header_chain_input_proof).expect("Failed to read input proof file");
    let proof: ZKMProofWithPublicValues =
        bincode::deserialize(&proof_bytes).expect("failed to deserialize the proof");
    header_chain_input.pv_hash = proof.public_values.hash().try_into().unwrap();

    let ZKMProof::Compressed(header_compressed_proof) = proof.proof else { panic!() };
    let bytes = std::fs::read(&format!("{}.vk", args.header_chain_input_proof)).unwrap();
    let header_chain_vk: zkm_sdk::ZKMVerifyingKey = bincode::deserialize(&bytes).unwrap();
    //assert_eq!(header_chain_output.vk_hash, header_chain_vk.hash_u32());

    // --- commit chain --- //
    let bytes = std::fs::read(&format!("{}.in", args.commit_chain_input_proof)).unwrap();
    let mut commit_chain_input: CommitChainCircuitInput = bincode::deserialize(&bytes).unwrap();

    // Set the previous proof type based on input_proof argument
    let proof_bytes =
        fs::read(&args.commit_chain_input_proof).expect("Failed to read input proof file");
    let proof: ZKMProofWithPublicValues =
        bincode::deserialize(&proof_bytes).expect("failed to deserialize the proof");

    //let commit_chain_output: CommitChainCircuitOutput = proof.public_values.read();
    commit_chain_input.pv_hash = proof.public_values.hash().try_into().unwrap();

    let ZKMProof::Compressed(commit_compressed_proof) = proof.proof else { panic!() };

    let bytes = std::fs::read(&format!("{}.vk", args.commit_chain_input_proof)).unwrap();
    let commit_chain_vk: zkm_sdk::ZKMVerifyingKey = bincode::deserialize(&bytes).unwrap();
    //assert_eq!(commit_chain_output.vk_hash, commit_chain_vk.hash_u32());

    // --- state chain --- //
    let bytes = std::fs::read(&format!("{}.in", args.state_chain_input_proof)).unwrap();
    let mut state_chain_input: StateChainCircuitInput = bincode::deserialize(&bytes).unwrap();

    // Set the previous proof type based on input_proof argument
    let proof_bytes =
        fs::read(&args.state_chain_input_proof).expect("Failed to read input proof file");
    let proof: ZKMProofWithPublicValues =
        bincode::deserialize(&proof_bytes).expect("failed to deserialize the proof");

    state_chain_input.pv_hash = proof.public_values.hash().try_into().unwrap();
    let ZKMProof::Compressed(state_compressed_proof) = proof.proof else { panic!() };
    let bytes = std::fs::read(&format!("{}.vk", args.state_chain_input_proof)).unwrap();
    let state_chain_vk: zkm_sdk::ZKMVerifyingKey = bincode::deserialize(&bytes).unwrap();
    // --- spv --- //
    let network = Network::Regtest;
    let btc_client = BTCClient::new(network, Some(&args.esplora_url));
    let genesis_sequencer_commit_txid =
        Txid::from_str(&args.genesis_sequencer_commit_txid).unwrap();
    let latest_sequencer_commit_txid = Txid::from_str(&args.latest_sequencer_commit_txid).unwrap();

    let tx = btc_client.get_tx(&latest_sequencer_commit_txid).await.unwrap().unwrap();
    // TODO: replace it by `get_raw_transaction_info`
    let tx_merkle_proof =
        btc_client.get_merkle_proof(&latest_sequencer_commit_txid).await.unwrap().unwrap();
    let block_pos = tx_merkle_proof.block_height;
    tracing::info!("block height: {block_pos}");
    let target_block = btc_client.get_block_by_height(block_pos).await.unwrap();

    let bitcoin_block_headers = {
        let headers: Vec<u8> = std::fs::read(&args.block_headers).unwrap();
        headers
            .chunks(80)
            .map(|header| CircuitBlockHeader::try_from_slice(header).unwrap())
            .collect::<Vec<CircuitBlockHeader>>()
    };
    tracing::info!("block headers: {:?}", bitcoin_block_headers.len());
    let found = bitcoin_block_headers
        .iter()
        .position(|h| h.compute_block_hash() == *target_block.block_hash().as_byte_array());
    tracing::info!("block found: {:?}", found);

    tracing::info!("construct spv");
    let spv = build_spv(&tx, block_pos, target_block, &bitcoin_block_headers);

    // Generate the proofs.
    let (proof, cycles) = tracing::info_span!("generate proof").in_scope(|| {
        let mut stdin = ZKMStdin::new();
        stdin.write(&genesis_sequencer_commit_txid.to_byte_array());
        stdin.write(&latest_sequencer_commit_txid.to_byte_array());
        stdin.write(&header_chain_input);
        stdin.write(&commit_chain_input);
        stdin.write(&state_chain_input);
        stdin.write(&spv);

        if commit_chain_input.prev_proof != CommitChainPrevProofType::GenesisBlock {
            stdin.write_proof(*commit_compressed_proof, commit_chain_vk.vk);
        } else {
            tracing::info!("skip writing commit chain proof");
        }

        if header_chain_input.prev_proof != HeaderChainPrevProofType::GenesisBlock {
            stdin.write_proof(*header_compressed_proof, header_chain_vk.vk);
        } else {
            tracing::info!("skip writing header chain proof");
        }

        if state_chain_input.prev_proof != StateChainPrevProofType::GenesisBlock {
            stdin.write_proof(*state_compressed_proof, state_chain_vk.vk);
        } else {
            tracing::info!("skip writing consensus chain proof");
        }

        let elf_id = if ELF_ID.get().is_none() {
            ELF_ID.set(hex::encode(Sha256::digest(&watchtower_proof_pk.elf))).unwrap();
            None
        } else {
            Some(ELF_ID.get().unwrap().clone())
        };
        tracing::info!("elf id: {:?}", elf_id);

        client
            .prove_with_cycles(&watchtower_proof_pk, &stdin, ZKMProofKind::Groth16, elf_id)
            .expect("proving failed")
    });

    tracing::info!("Watchtower proof cycles: {}", cycles);

    std::fs::write(&format!("{}.proof.bin", args.output), proof.bytes()).unwrap();
    std::fs::write(&format!("{}.public_inputs.bin", args.output), proof.public_values.to_vec())
        .unwrap();
    std::fs::write(&format!("{}.vk_hash.bin", args.output), watchtower_proof_vk.bytes32()).unwrap();
}
