//! Generate header chain proof
//! Example:
//! ```
//! RUST_LOG=debug cargo run -r -- --latest-sequencer-commit-txid 7b5fde8cc49a0afe1bfd6534d63d3549d4b03394dab978642db866b74f6fa62c --header-chain-input-proof ../../header-chain-proof/host/0-10.bin --commit-chain-input-proof ../../commit-chain-proof/host/compressed.bin --output "output.bin"
//! ```
use client::btc_chain::BTCClient;
use header_chain::{CircuitTransaction, HeaderChainCircuitInput, HeaderChainPrevProofType};
use std::sync::Arc;
use zkm_sdk::{ProverClient, ZKMProof, ZKMProofWithPublicValues, ZKMStdin, include_elf};

use alloy_primitives::U256;
use bitcoin::{Network, ScriptBuf, TxOut, Txid, secp256k1::PublicKey};
use bitcoin_light_client::{
    CommitChainCircuitInput, CommitChainPrevProofType, EthClientExecutorInput, LightBlock,
    build_spv,
};
use std::str::FromStr;

//use alloy_provider::{RootProvider, network::Ethereum};

use host_executor::EthHostExecutor;
use primitives::genesis::Genesis;
use reth_chainspec::ChainSpec;
use url::Url;

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

// https://github.com/ProjectZKM/reth-processor/blob/stateless/crates/executor/host/tests/integration.rs#L69
async fn fetch_exection_layer_block(args: &Args) -> EthClientExecutorInput {
    // Setup the provider.
    let rpc_url = Url::parse(&args.execution_layer_rpc).expect("invalid rpc url");
    let provider = ::provider::create_provider(rpc_url);

    let genesis = &Genesis::GOAT;
    let chain_spec: Arc<ChainSpec> = Arc::new(genesis.try_into().unwrap());
    let custom_beneficiary = None;

    let host_executor = EthHostExecutor::eth(chain_spec.clone(), custom_beneficiary);
    // Execute the host.
    let client_input = host_executor
        .execute(
            args.execution_layer_block_number,
            &provider,
            &provider,
            genesis.clone(),
            custom_beneficiary,
            false,
        )
        .await
        .expect("failed to execute host");
    client_input
}

/// The arguments for the cli.
#[derive(Debug, Clone, Parser)]
pub struct Args {
    #[arg(long, default_value = "http://127.0.0.1:3002")]
    esplora_url: String,

    #[clap(long, env)]
    included_watchtowers: String,

    #[clap(long, env, value_parser = str_to_16_bytes_exact, default_value = "123456789ABCDEAA")]
    graph_id: [u8; 16],

    #[clap(long, env)]
    latest_sequencer_commit_txid: String,

    #[clap(long, env, short)]
    header_chain_input_proof: String,

    #[clap(long, env, short)]
    commit_chain_input_proof: String,

    #[clap(
        long,
        env,
        short,
        default_value = "../../../crates/bitcoin-light-client/samples/light_block_5756785.json"
    )]
    consensus_layer_block: String,

    #[clap(long, env, short, default_value = "https://rpc.testnet3.goat.network")]
    execution_layer_rpc: String,

    #[clap(long, env, short)]
    execution_layer_block_number: u64,

    /// All the watchtower challenges txids
    #[clap(long, env, short)]
    watchtower_challenge_info: String,

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

    let operator_latest_sequencer_commit_txn =
        btc_client.get_tx(&latest_sequencer_commit_txid).await.unwrap().unwrap();
    println!("operator_latest_seqeuncer_commit_txn: {:?}", operator_latest_sequencer_commit_txn);

    // TODO: replace it by `get_raw_transaction_info`
    let tx_merkle_proof =
        btc_client.get_btc_merkle_proof(&latest_sequencer_commit_txid).await.unwrap();
    let block_pos = tx_merkle_proof.2.block_height;
    println!("block height: {block_pos}");
    let target_block = btc_client.get_btc_block(block_pos).await.unwrap();

    println!("construct spv");
    let spv = build_spv(
        &operator_latest_sequencer_commit_txn,
        block_pos,
        target_block,
        &header_chain_input,
    );

    let eth_client_execution_input: EthClientExecutorInput =
        fetch_exection_layer_block(&args).await;
    println!("Block: {:?}", eth_client_execution_input);

    // --- watchtower_challenge_txns --- //
    let bytes = std::fs::read(&args.watchtower_challenge_info).unwrap();
    // watchtower challenge's (txid, public key)
    let watchtower_challenge_txids: Vec<(String, String)> = serde_json::from_slice(&bytes).unwrap();
    let mut watchtower_challenge_txns = Vec::new();
    let mut watchtower_challenge_txn_prev_outs: Vec<TxOut> = Vec::new();
    let mut watchtower_challenge_txn_pubkey = Vec::new();
    for (id, pk) in &watchtower_challenge_txids {
        let txid = id.parse().unwrap();
        let txn = btc_client.get_tx(&txid).await.unwrap().unwrap();
        // get prev outs
        // FIXME: update the index
        let prev_txn =
            btc_client.get_tx(&txn.input[0].previous_output.txid).await.unwrap().unwrap();
        watchtower_challenge_txn_prev_outs
            .push(prev_txn.output[txn.input[0].previous_output.vout as usize].clone());
        watchtower_challenge_txn_pubkey.push(PublicKey::from_str(pk).unwrap());
        watchtower_challenge_txns.push(CircuitTransaction(txn));
    }

    // https://github.com/GOATNetwork/BitVM/blob/GA/goat/src/transactions/watchtower_challenge.rs#L45
    // generate_pay_to_pubkey_taproot_script
    let watchtower_challenge_txn_script: ScriptBuf = ScriptBuf::new();

    // Generate the proofs.
    let proof = tracing::info_span!("generate proof").in_scope(|| {
        let mut stdin = ZKMStdin::new();

        let included_watchtowers: U256 = U256::from_str(&args.included_watchtowers).unwrap();
        stdin.write(&included_watchtowers);

        stdin.write(&args.graph_id);

        // let operator_latest_sequencer_commit_txn: CircuitTransaction = zkm_zkvm::io::read(); // private inputs
        stdin.write(&operator_latest_sequencer_commit_txn);

        // let consensus_blocks: LightBlock = zkm_zkvm::io::read(); // commit the sequencer set
        let bytes = std::fs::read(&args.consensus_layer_block).unwrap();
        let consensus_layer_block: LightBlock = bincode::deserialize(&bytes).unwrap();
        stdin.write(&consensus_layer_block);

        stdin.write(&eth_client_execution_input);

        // let watchtower_challenge_txns: Vec<CircuitTransaction> = zkm_zkvm::io::read();
        stdin.write(&watchtower_challenge_txns);
        // let watchtower_challenge_txn_pubkey: Vec<bitcoin::secp256k1::PublicKey> = zkm_zkvm::io::read();
        stdin.write(&watchtower_challenge_txn_pubkey);
        // let watchtower_challenge_txn_script: ScriptBuf = zkm_zkvm::io::read();
        stdin.write(&watchtower_challenge_txn_script);
        stdin.write(&watchtower_challenge_txn_prev_outs);

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
