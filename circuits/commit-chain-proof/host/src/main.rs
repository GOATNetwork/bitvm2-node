//! Generate commit chain proof
//! Example:
//!     Genesis:       RUST_LOG=debug cargo run -r -- --init-input --output-proof "commit-proof.bin"
//!     Regular proof: RUST_LOG=debug cargo run -r -- --input-proof "commit-proof.bin" --output-proof "commit-proof2.bin" --commit-info ../../../node/tests_data/commit_info2.json
use bitcoin::{Network, Txid, secp256k1::PublicKey};
use bitcoin_light_client::*;
use client::btc_chain::BTCClient;
use std::str::FromStr;
use zkm_sdk::{
    HashableKey, ProverClient, ZKMProof, ZKMProofWithPublicValues, ZKMStdin, include_elf,
};

/// A program that aggregates the proofs of the simple program.
const COMMIT_CHAIN: &[u8] = include_elf!("guest");

use clap::Parser;
use std::fs;

/// The arguments for the cli.
#[derive(Debug, Clone, Parser)]
pub struct Args {
    #[arg(long, default_value = "http://127.0.0.1:3002")]
    esplora_url: String,

    #[arg(long, default_value = "../../../node/tests_data/commit_info.json")]
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
    let btc_client = BTCClient::new(network.into(), Some(&args.esplora_url));

    let mut commits: Vec<CircuitCommit> = vec![];

    let rdr = std::fs::File::open(&args.commit_info).unwrap();
    let commit_info: Vec<CommitInfo> = serde_json::from_reader(rdr).unwrap();
    for ci in &commit_info {
        let tx = btc_client.get_tx(&Txid::from_str(&ci.txid).unwrap()).await.unwrap().unwrap();

        let op_return_data = bitcoin_light_client::extract_op_return_data(&tx);
        let mut sequencer_set_hash: [u8; 32] = [0u8; 32];
        sequencer_set_hash.copy_from_slice(&op_return_data);

        let publisher_public_keys = ci
            .publisher_public_keys
            .iter()
            .map(|compressed_pk| PublicKey::from_str(compressed_pk).unwrap())
            .collect();
        let commit = CircuitCommit {
            commit_txn: tx,
            sequencer_set_hash,
            publisher_public_keys,
            threshold: ci.threshold,
        };
        commits.push(commit.clone());
    }
    std::fs::write(&args.commits, serde_json::to_vec(&commits).unwrap()).unwrap();
}

#[tokio::main]
async fn main() {
    let args = Args::parse();
    println!("args: {:?}", args);
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
    // Generate the proofs.
    let proof = tracing::info_span!("generate proof").in_scope(|| {
        let mut stdin = ZKMStdin::new();
        stdin.write(&input);
        if let Some(proof) = prev_receipt {
            let ZKMProof::Compressed(compressed_proof) = proof.proof else { panic!() };
            stdin.write_proof(*compressed_proof, commit_chain_proof_vk.vk.clone());
        } else {
            println!("Skip writing proof for genesis commit");
        }
        client.prove(&commit_chain_proof_pk, stdin).compressed().run().expect("proving failed")
    });

    fs::write(&args.output_proof, bincode::serialize(&proof).unwrap()).unwrap();
    fs::write(
        &format!("{}.vk", args.output_proof),
        bincode::serialize(&commit_chain_proof_vk).unwrap(),
    )
    .unwrap();
    fs::write(&format!("{}.in", args.output_proof), bincode::serialize(&input).unwrap()).unwrap();
    println!("Generate proof successfully, proof: {:?}", proof);
}
