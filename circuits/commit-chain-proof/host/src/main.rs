//! Generate commit chain proof
//! Example:
//!     Genesis:       RUST_LOG=debug cargo run -r -- --init-input --output-proof "commit-proof.bin"
//!     Regular proof: RUST_LOG=debug cargo run -r -- --input-proof "commit-proof.bin" --output-proof "commit-proof2.bin" --commit-info ../../../node/tests_data/commit_info2.json
use bitcoin::{Network, Txid, hashes::Hash, secp256k1::PublicKey};
use client::btc_chain::BTCClient;
use commit_chain::*;
use std::str::FromStr;
use zkm_sdk::{
    HashableKey, Prover, ProverClient, ZKMProof, ZKMProofKind, ZKMProofWithPublicValues, ZKMStdin,
    include_elf,
};

use sha2::{Digest, Sha256};
use std::sync::OnceLock;
static ELF_ID: OnceLock<String> = OnceLock::new();

/// A program that aggregates the proofs of the simple program.
const COMMIT_CHAIN: &[u8] = include_elf!("guest");

use clap::Parser;
use std::fs;

/// The arguments for the cli.
#[derive(Debug, Clone, Parser)]
pub struct Args {
    #[arg(long, default_value = "http://127.0.0.1:3002")]
    esplora_url: String,

    #[arg(long, env)]
    commit_info: String,

    #[arg(long, default_value = "commits.bin")]
    commits: String,

    #[clap(long, env, default_value_t = false)]
    init_input: bool,

    #[clap(long, env, default_value = "input.bin")]
    input_proof: String,

    #[clap(long, env, default_value = "output.bin")]
    output_proof: String,
}

async fn fetch_commit_chain(args: &Args) {
    let network = Network::Regtest;
    let btc_client = BTCClient::new(network, Some(&args.esplora_url));

    let mut commits: Vec<CircuitCommit> = vec![];

    let rdr = std::fs::File::open(&args.commit_info).unwrap();
    let commit_info: CommitInfo = serde_json::from_reader(rdr).unwrap();
    for ci in &[commit_info] {
        let txid = Txid::from_str(&ci.txid).unwrap();
        let commit_txn = btc_client.get_tx(&txid).await.unwrap().unwrap();
        let proof = btc_client.get_merkle_proof_extend(&txid).await.unwrap();
        let block_height = proof.height as u32;

        let op_return_data = extract_op_return_data(&commit_txn.output);
        let mut sequencer_set_hash: [u8; 32] = [0u8; 32];
        sequencer_set_hash.copy_from_slice(&op_return_data);

        if let tendermint::Hash::Sha256(expected_hash) = sequencer_hash(&ci.sequencers) {
            assert_eq!(expected_hash, sequencer_set_hash);
        } else {
            panic!("Invalid sequencer set hash");
        }

        let publisher_public_keys = ci
            .publisher_public_keys
            .iter()
            .map(|compressed_pk| PublicKey::from_str(compressed_pk).unwrap())
            .collect();
        tracing::info!("sequencer_hash: {:?}", sequencer_hash(&ci.sequencers));
        let commit = CircuitCommit {
            commit_txn,
            sequencers: ci.sequencers.clone(),
            publisher_public_keys,
            threshold: ci.threshold,
            genesis_txid: Txid::from_str(&ci.genesis_txid).unwrap().as_raw_hash().to_byte_array(),
            block_height,
        };
        commits.push(commit);
    }
    std::fs::write(&args.commits, serde_json::to_vec(&commits).unwrap()).unwrap();
}

#[tokio::main]
async fn main() {
    dotenv::dotenv().ok();
    let args = Args::parse();
    tracing::info!("args: {:?}", args);
    fetch_commit_chain(&args).await;
    // Setup the logger.
    zkm_sdk::utils::setup_logger();

    // Initialize the proving client.
    let client = ProverClient::new();

    // Setup the proving and verifying keys.
    let (commit_chain_proof_pk, commit_chain_proof_vk) = client.setup(COMMIT_CHAIN);

    let vk_hash = commit_chain_proof_vk.hash_u32();

    let cb = std::fs::read(&args.commits).unwrap();
    let commits: Vec<CircuitCommit> = serde_json::from_slice(&cb).unwrap();
    // Set the previous proof type based on input_proof argument
    let prev_receipt = if args.init_input {
        None
    } else {
        let proof_bytes = fs::read(args.input_proof).expect("Failed to read input proof file");
        let proof: ZKMProofWithPublicValues =
            bincode::deserialize(&proof_bytes).expect("failed to deserialize the proof");
        Some(proof)
    };
    let (prev_proof, pv_hash) = match prev_receipt.clone() {
        Some(mut receipt) => {
            let prev_output = receipt.public_values.read();
            let pv_hash: [u8; 32] = receipt.public_values.hash().try_into().unwrap();
            (CommitChainPrevProofType::PrevProof(prev_output), pv_hash)
        }
        None => (CommitChainPrevProofType::GenesisBlock, [0u8; 32]),
    };

    let input: CommitChainCircuitInput =
        CommitChainCircuitInput { vk_hash, pv_hash, prev_proof, commits };

    //let output = commit_chain_circuit(input.clone());
    //tracing::info!("Commit chain circuit output: {:?}", output);
    // Generate the proofs.
    let (proof, cycles) = tracing::info_span!("generate proof").in_scope(|| {
        let mut stdin = ZKMStdin::new();
        stdin.write(&input);

        if let Some(proof) = prev_receipt {
            let ZKMProof::Compressed(compressed_proof) = proof.proof else { panic!() };
            stdin.write_proof(*compressed_proof, commit_chain_proof_vk.vk.clone());
            tracing::info!("Write prev proof into stdin");
        } else {
            tracing::info!("Skip writing proof for genesis commit");
        }

        let elf_id = if ELF_ID.get().is_none() {
            ELF_ID.set(hex::encode(Sha256::digest(&commit_chain_proof_pk.elf))).unwrap();
            None
        } else {
            Some(ELF_ID.get().unwrap().clone())
        };
        tracing::info!("elf id: {:?}", elf_id);
        client
            .prove_with_cycles(&commit_chain_proof_pk, &stdin, ZKMProofKind::Compressed, elf_id)
            .expect("proving failed")
    });

    tracing::info!("Commit chain proof cycles: {}", cycles);

    if let Err(e) = client.verify(&proof, &commit_chain_proof_vk) {
        panic!("{}", e);
    }

    fs::write(&args.output_proof, bincode::serialize(&proof).unwrap()).unwrap();
    fs::write(
        &format!("{}.vk", args.output_proof),
        bincode::serialize(&commit_chain_proof_vk).unwrap(),
    )
    .unwrap();
    fs::write(&format!("{}.in", args.output_proof), bincode::serialize(&input).unwrap()).unwrap();
    tracing::info!("Generate proof successfully, proof: {:?}", proof);
}
