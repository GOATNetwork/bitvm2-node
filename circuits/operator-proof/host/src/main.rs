//! Generate header chain proof
//! Example:
//! ```
//! RUST_LOG=debug cargo run -r -- --latest-sequencer-commit-txid 7b5fde8cc49a0afe1bfd6534d63d3549d4b03394dab978642db866b74f6fa62c --header-chain-input-proof ../../header-chain-proof/host/0-10.bin --commit-chain-input-proof ../../commit-chain-proof/host/compressed.bin --output "output.bin"
//! ```
use client::btc_chain::BTCClient;
use header_chain::{
    BitcoinMerkleTree, BlockHeaderCircuitOutput, CircuitBlockHeader, CircuitTransaction,
    HeaderChainCircuitInput, HeaderChainPrevProofType, MMRHost, SPV,
};
use zkm_sdk::{
    HashableKey, ProverClient, ZKMProof, ZKMProofWithPublicValues, ZKMStdin, include_elf,
};

use alloy_primitives::U256;
use bitcoin::{Network, Txid};
use bitcoin_light_client::{
    build_spv, CommitChainCircuitInput, CommitChainCircuitOutput, CommitChainPrevProofType, LightBlock
};
use std::str::FromStr;

/// A program that aggregates the proofs of the simple program.
const OPERATOR: &[u8] = include_elf!("guest");

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

    #[clap(long, env, short, default_value = "../../../crates/bitcoin-light-client/samples/light_block_5756785.json")]
    consensus_block: String,

    #[clap(long, env, short)]
    watchtower_txids: Vec<String>,

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
    let (proof_pk, proof_vk) = client.setup(OPERATOR);

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

    // --- spv --- //
    let network = Network::Regtest;
    let btc_client = BTCClient::new(network.into(), Some(&args.esplora_url));
    let latest_sequencer_commit_txid = Txid::from_str(&args.latest_sequencer_commit_txid).unwrap();

    let tx = btc_client.fetch_btc_tx(&latest_sequencer_commit_txid).await.unwrap();
    // TODO: replace it by `get_raw_transaction_info`
    let tx_merkle_proof =
        btc_client.get_btc_merkle_proof(&latest_sequencer_commit_txid).await.unwrap();
    let block_pos = tx_merkle_proof.1.block_height;
    println!("block height: {block_pos}");
    let target_block = btc_client.fetch_btc_block(block_pos).await.unwrap();

    println!("construct spv");
    let spv = build_spv(&tx, block_pos, target_block, &header_chain_input);

    // Generate the proofs.
    let proof = tracing::info_span!("generate proof").in_scope(|| {
        let mut stdin = ZKMStdin::new();

        let included_watchertowers: U256 = U256::from_str(&args.included_watchertowers).unwrap();
        stdin.write(&included_watchertowers);

        stdin.write(&args.graph_id);

        // let operator_latest_sequencer_commit_txn: CircuitTransaction = zkm_zkvm::io::read(); // private inputs

        // let consensus_blocks: LightBlock = zkm_zkvm::io::read(); // commit the sequencer set
        let bytes = std::fs::read(&args.consensus_block).unwrap();
        let consensus_block: LightBlock = bincode::deserialize(&bytes).unwrap();
        stdin.write(&consensus_block);

        // let eth_client_execution_input: EthClientExecutorInput = zkm_zkvm::io::read();

        // let watchtower_challenge_txns: Vec<CircuitTransaction> = zkm_zkvm::io::read();
        // let watchtower_challenge_txn_script: Vec<ScriptBuf> = zkm_zkvm::io::read();
        // let watchtower_challenge_txn_prev_out: Vec<TxOut> = zkm_zkvm::io::read();
        // let watchtower_challenge_txn_pubkey: Vec<bitcoin::secp256k1::PublicKey> = zkm_zkvm::io::read();
        // let watchtower_challenge_txn_sig: Vec<bitcoin::taproot::Signature> = zkm_zkvm::io::read();

        stdin.write(&header_chain_input);
        stdin.write(&commit_chain_input);
        stdin.write(&spv);

        if header_chain_input.prev_proof != HeaderChainPrevProofType::GenesisBlock {
            stdin.write_proof(*header_compressed_proof, header_chain_vk.vk);
        } else {
            println!("Skip writing header chain proof");
        }

        if commit_chain_input.prev_proof != CommitChainPrevProofType::GenesisBlock {
            stdin.write_proof(*commit_compressed_proof, commit_chain_vk.vk);
        } else {
            println!("Skip writing commit chain proof");
        }

        client.prove(&proof_pk, stdin).groth16().run().expect("proving failed")
    });

    fs::write(&args.output, bincode::serialize(&proof).unwrap()).unwrap();
    fs::write(&format!("{}.vk", args.output), bincode::serialize(&proof_vk).unwrap()).unwrap();
    println!("Generate proof successfully, proof: {:?}", proof);
}
