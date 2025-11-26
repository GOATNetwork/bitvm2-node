use cbft_rpc::{fetch_cosmos_tx_data, fetch_cosmos_validator_info};
use consensus_chain::*;
use zkm_sdk::{
    HashableKey, ProverClient, ZKMProof, ZKMProofWithPublicValues, ZKMStdin, include_elf,
};
use alloy_provider::{RootProvider, network::Ethereum};
use primitives::genesis::Genesis;
use reth_chainspec::ChainSpec;
use rpc_db::RpcDb;
use std::sync::Arc;
use url::Url;
use bitcoin_light_client_circuit::EthClientExecutorInput;
use host_executor::EthHostExecutor;

/// A program that aggregates the proofs of the simple program.
const CONSENSUS_CHAIN: &[u8] = include_elf!("guest");

use clap::Parser;
use std::fs;

/// The arguments for the cli.
#[derive(Debug, Clone, Parser)]
pub struct Args {
    #[clap(long, env, short, default_value = "https://rpc.testnet3.goat.network")]
    execution_layer_rpc: String,

    #[arg(long, default_value = "blocks.bin")]
    blocks: String,

    #[clap(long, env, default_value_t = false)]
    init_input: bool,

    #[clap(long, env, default_value = "input.bin")]
    input_proof: String,

    #[clap(long, env, default_value = "output.bin")]
    output_proof: String,

    #[clap(long, env, default_value_t = 4)]
    batch_size: u64,

    #[clap(long, env, default_value_t = 0)]
    start: u64,

    #[clap(long, default_value_t = false)]
    force_fetch: bool,
}

// https://github.com/ProjectZKM/reth-processor/blob/stateless/crates/executor/host/tests/integration.rs#L69
async fn fetch_exection_layer_block(execution_layer_rpc: &str, execution_layer_block_number: u64) -> EthClientExecutorInput {
    // Setup the provider.
    let rpc_url = Url::parse(&execution_layer_rpc).expect("invalid rpc url");

    let provider = RootProvider::<Ethereum>::new_http(rpc_url);

    let rpc_db =
        RpcDb::new(provider.clone(), provider.clone(), execution_layer_block_number - 1);

    let genesis = &Genesis::GoatTestnet;
    let chain_spec: Arc<ChainSpec> = Arc::new(genesis.try_into().unwrap());
    let custom_beneficiary = None;

    let host_executor = EthHostExecutor::eth(chain_spec.clone(), custom_beneficiary);
    // Execute the host.
    let client_input = host_executor
        .execute(
            execution_layer_block_number,
            &rpc_db,
            &provider,
            genesis.clone(),
            custom_beneficiary,
            false,
        )
        .await
        .expect("failed to execute host");
    client_input
}

async fn fetch_consensus_chain(args: &Args) -> Vec<CiruitConsensusBlock> {
   use std::io::Read;
   let mut reader = std::fs::OpenOptions::new()
       .read(true)
       .write(true)
       .create(true)
       .open(&args.blocks)
       .unwrap();

   let mut blocks: Vec<u8> = Vec::new();
   reader.read_to_end(&mut blocks).unwrap();
   let mut blocks: Vec<CiruitConsensusBlock> = if blocks.is_empty() { Vec::new()} else { serde_json::from_slice(&blocks).unwrap() }; 

    if args.force_fetch {
        blocks.truncate(args.start as usize - 1);
    }
    assert!(blocks.len() as u64 + 1 == args.start, "Invalid starting block number");

    for i in args.start..(args.start + args.batch_size) {
        let (_, _, cl_block_number) = fetch_cosmos_validator_info(i).await.unwrap();
        let (_, consensus_data_hash, consensus_txns) = fetch_cosmos_tx_data(cl_block_number).await.unwrap(); 
        let evm_input = fetch_exection_layer_block(&args.execution_layer_rpc, i).await; 
        blocks.push(CiruitConsensusBlock {
            consensus_txns,
            consensus_data_hash,
            evm_input,
        });
    }
    let block_bytes= serde_json::to_vec(&blocks).unwrap();
    std::fs::write(&args.blocks, block_bytes).unwrap();
    blocks.split_off(args.start as usize - 1)
}

#[tokio::main]
async fn main() {
    //dotenv::dotenv().ok();
    let args = Args::parse();
    println!("args: {:?}", args);
    // Setup the logger.
    zkm_sdk::utils::setup_logger();
    let blocks = fetch_consensus_chain(&args).await;

    // Initialize the proving client.
    let client = ProverClient::new();

    // Setup the proving and verifying keys.
    let (consensus_chain_proof_pk, consensus_chain_proof_vk) = client.setup(CONSENSUS_CHAIN);

    let vk_hash = consensus_chain_proof_vk.hash_u32();

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
            (ConsensusChainPrevProofType::PrevProof(prev_output), pv_hash)
        }
        None => (ConsensusChainPrevProofType::GenesisBlock, [0u8; 32]),
    };

    let input: ConsensusChainCircuitInput =
        ConsensusChainCircuitInput { vk_hash, pv_hash, prev_proof, blocks };
    // Generate the proofs.
    let proof = tracing::info_span!("generate proof").in_scope(|| {
        let mut stdin = ZKMStdin::new();
        stdin.write(&input);
        if let Some(proof) = prev_receipt {
            let ZKMProof::Compressed(compressed_proof) = proof.proof else { panic!() };
            stdin.write_proof(*compressed_proof, consensus_chain_proof_vk.vk.clone());
        } else {
            println!("Skip writing proof for genesis evm block");
        }
        client.prove(&consensus_chain_proof_pk, stdin).compressed().run().expect("proving failed")
    });

    fs::write(&args.output_proof, bincode::serialize(&proof).unwrap()).unwrap();
    fs::write(
        &format!("{}.vk", args.output_proof),
        bincode::serialize(&consensus_chain_proof_vk).unwrap(),
    )
    .unwrap();
    fs::write(&format!("{}.in", args.output_proof), bincode::serialize(&input).unwrap()).unwrap();
    println!("Generate proof successfully, proof: {:?}", proof);
}
