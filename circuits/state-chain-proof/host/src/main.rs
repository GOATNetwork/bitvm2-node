#![feature(trim_prefix_suffix)]
use alloy_primitives::{Address, U256};
use alloy_provider::{RootProvider, network::Ethereum};
use bitcoin_light_client_circuit::EthClientExecutorInput;
use cbft_rpc::{fetch_cbft_tx_data, fetch_cbft_validator_info, fetch_cosmos_block};
use hex::FromHex;
use host_executor::EthHostExecutor;
use primitives::genesis::Genesis;
use reth_chainspec::ChainSpec;
use rpc_db::RpcDb;
use state_chain::*;
use std::sync::Arc;
use url::Url;
use zkm_sdk::{
    HashableKey, ProverClient, ZKMProof, ZKMProofWithPublicValues, ZKMStdin, include_elf,
};

/// A program that aggregates the proofs of the simple program.
const STATE_CHAIN: &[u8] = include_elf!("guest");

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

    #[clap(long, env, default_value = "99f6Dc59fB6B5b13578BeBb223e373Cb817Ac8f6")]
    l2_contract_address: String,

    #[clap(long, env, value_parser=hex_parse)]
    graph_ids: Vec<[u8; 16]>,
    #[clap(long, env)]
    graph_block_numbers: Vec<u64>,
}

pub fn hex_parse(s: &str) -> Result<[u8; 16], String> {
    let mut s = s;
    if s.starts_with("0x") {
        s = &s[2..];
    }
    let b = Vec::from_hex(s).map_err(|e| e.to_string())?;
    b.try_into().map_err(|_| "len must be 16".to_string())
}

// https://github.com/ProjectZKM/reth-processor/blob/stateless/crates/executor/host/tests/integration.rs#L69
async fn fetch_exection_layer_block(
    execution_layer_rpc: &str,
    execution_layer_block_number: u64,
    genesis: &Genesis,
) -> EthClientExecutorInput {
    // Setup the provider.
    let rpc_url = Url::parse(&execution_layer_rpc).expect("invalid rpc url");

    let provider = RootProvider::<Ethereum>::new_http(rpc_url);

    let rpc_db = RpcDb::new(provider.clone(), provider.clone(), execution_layer_block_number - 1);

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

async fn fetch_state_chain(args: &Args) -> Vec<CircuitStateBlock> {
    assert!(args.start > 0, "Don't get genesis block from the consensus layer.");
    let mut blocks: Vec<_> = Vec::new();
    let addr = args.l2_contract_address.trim_prefix("0x");
    let bytes: [u8; 20] = hex::decode(addr).unwrap().try_into().unwrap();
    let l2_contract_address = Address::from(bytes);
    let base_slot: [u8; 32] = U256::from(12).to_be_bytes().try_into().unwrap();
    let genesis = &Genesis::GoatTestnet;

    for i in args.start..(args.start + args.batch_size) {
        let (_, cl_block_number) = fetch_cbft_validator_info(i).await.unwrap();
        let cosmos_txns = fetch_cbft_tx_data(cl_block_number).await.unwrap();
        let cosmos_block = fetch_cosmos_block(cl_block_number).await.unwrap();
        let evm_block = fetch_exection_layer_block(&args.execution_layer_rpc, i, genesis).await;

        let withdrawals = if !args.graph_block_numbers.is_empty() {
            let indices: Vec<usize> = args
                .graph_block_numbers
                .iter()
                .enumerate()
                .filter(|&(_, &val)| val == i)
                .map(|(i, _)| i)
                .collect();
            let graph_ids: Vec<_> = indices.iter().map(|&x| args.graph_ids[x].clone()).collect();
            if graph_ids.len() > 0 {
                println!("block_id: {i}, check graph_ids: {:?}", graph_ids);
                Some((l2_contract_address, base_slot, graph_ids))
            } else {
                None
            }
        } else {
            None
        };

        let cosmos_block = serde_json::to_vec(&cosmos_block).unwrap();
        println!("[push] block: {}, withdrawals: {:?}", i, withdrawals);
        blocks.push(CircuitStateBlock { cosmos_txns, cosmos_block, evm_block, withdrawals });
    }
    let block_bytes = serde_json::to_vec(&blocks).unwrap();
    std::fs::write(&args.blocks, block_bytes).unwrap();
    blocks
}

#[tokio::main]
async fn main() {
    dotenv::dotenv().ok();
    let args = Args::parse();
    println!("args: {:?}", args);
    // Setup the logger.
    zkm_sdk::utils::setup_logger();
    let blocks = fetch_state_chain(&args).await;

    // Initialize the proving client.
    let client = ProverClient::new();

    // Setup the proving and verifying keys.
    let (state_chain_proof_pk, state_chain_proof_vk) = client.setup(STATE_CHAIN);

    let vk_hash = state_chain_proof_vk.hash_u32();

    // Set the previous proof type based on input_proof argument
    println!("init input: {}", args.init_input);
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
            (StateChainPrevProofType::PrevProof(prev_output), pv_hash)
        }
        None => (StateChainPrevProofType::GenesisBlock, [0u8; 32]),
    };

    let input: StateChainCircuitInput =
        StateChainCircuitInput { vk_hash, pv_hash, prev_proof, blocks };
    // Generate the proofs.
    let proof = tracing::info_span!("generate proof").in_scope(|| {
        let mut stdin = ZKMStdin::new();
        stdin.write(&input);
        if let Some(proof) = prev_receipt {
            let ZKMProof::Compressed(compressed_proof) = proof.proof else { panic!() };
            stdin.write_proof(*compressed_proof, state_chain_proof_vk.vk.clone());
        } else {
            println!("Skip writing proof for genesis evm block");
        }
        client.prove(&state_chain_proof_pk, stdin).compressed().run().expect("proving failed")
    });
    if let Err(e) = client.verify(&proof, &state_chain_proof_vk) {
        panic!("{}", e);
    }

    fs::write(&args.output_proof, bincode::serialize(&proof).unwrap()).unwrap();
    fs::write(
        &format!("{}.vk", args.output_proof),
        bincode::serialize(&state_chain_proof_vk).unwrap(),
    )
    .unwrap();
    fs::write(&format!("{}.in", args.output_proof), bincode::serialize(&input).unwrap()).unwrap();
    println!("Generate proof successfully, proof: {:?}", proof);
}
