#![feature(trim_prefix_suffix)]
use alloy_consensus::transaction::Transaction;
use alloy_primitives::{Address, U256};
use alloy_provider::Provider;
use alloy_provider::{RootProvider, network::Ethereum};
use anyhow::Context;
use bitcoin_light_client_circuit::EthClientExecutorInput;
use cbft_rpc::{fetch_cbft_tx_data, fetch_cbft_validator_info, fetch_cosmos_block};
use host_executor::EthHostExecutor;
use primitives::genesis::Genesis;
use proof_builder::ProofRequest;
use proof_builder::{LongRunning, ProofBuilder};
use reth_chainspec::ChainSpec;
use state_chain::*;
use std::sync::Arc;
use url::Url;
use zkm_sdk::{
    HashableKey, Prover, ProverClient, ZKMProof, ZKMProofKind, ZKMProofWithPublicValues, ZKMStdin,
    include_elf,
};

use sha2::{Digest, Sha256};
use std::sync::OnceLock;
use util::hex_parse;
static ELF_ID: OnceLock<String> = OnceLock::new();

/// A program that aggregates the proofs of the simple program.
const STATE_CHAIN: &[u8] = include_elf!("guest");

use std::fs;

use clap::Parser;
/// The arguments for the cli.
#[derive(Debug, Clone, Parser, serde::Deserialize, serde::Serialize)]
pub struct Args {
    #[arg(long, default_value_t = true)]
    pub enable: bool,

    #[clap(long, env, short, default_value = "https://rpc.testnet3.goat.network")]
    pub execution_layer_rpc: String,

    #[clap(long, env, default_value = "goattest")]
    pub goat_network: String,

    #[clap(long, env, default_value = "https://cosmos.testnet3.goat.network/")]
    pub cosmos_rpc_url: String,

    #[arg(long, default_value = "blocks.bin")]
    pub blocks: String,

    #[clap(long, env, default_value_t = false)]
    pub init_input: bool,

    #[clap(long, env, default_value = "input.bin")]
    pub input_proof: String,

    #[clap(long, env, default_value = "output.bin")]
    pub output_proof: String,

    #[clap(long, env, default_value_t = 10)]
    pub batch_size: u64,

    #[clap(long, env, default_value_t = 0)]
    pub start: u64,

    #[clap(long, env, default_value = "99f6Dc59fB6B5b13578BeBb223e373Cb817Ac8f6")]
    pub l2_contract_address: String,

    // https://explorer.testnet3.goat.network/address/0x9F0A61ce47678F43A326dB9F8964C56a924cd3D0?tab=read_write_contract
    #[clap(long, env, default_value = "0xc3342df3")]
    pub proceed_withdraw_method_id: String,
}

impl LongRunning for Args {
    fn rotate(&self) -> Self {
        let mut next_args = self.clone();
        next_args.input_proof = self.output_proof.clone();
        next_args.init_input = false;
        next_args.start = self.start + self.batch_size;
        next_args.output_proof = format!(
            "{}/{}-{}.bin",
            std::path::Path::new(&self.output_proof).parent().unwrap().to_str().unwrap(),
            next_args.start,
            self.batch_size
        );
        next_args
    }
}

async fn fetch_withdrawal(
    execution_layer_rpc: &str,
    l2_contract_address: &Address,
    proceed_withdraw_method_id: &[u8; 4],
    start: u64,
    batch_size: u64,
) -> anyhow::Result<(Vec<u64>, Vec<[u8; 16]>)> {
    let rpc_url = Url::parse(&execution_layer_rpc)?;
    let provider = RootProvider::<Ethereum>::new_http(rpc_url);
    let mut block_numbers = vec![];
    let mut graph_ids: Vec<[u8; 16]> = vec![];
    for i in start..start + batch_size {
        let block = provider.get_block(i.into()).await.unwrap().unwrap();
        for txid in block.transactions.hashes() {
            let txn = provider.get_transaction_by_hash(txid).await.unwrap().unwrap();
            let to = txn.to();
            let input = txn.input();
            if to == Some(*l2_contract_address) && &input[0..4] == proceed_withdraw_method_id {
                let graph_id: [u8; 16] = input[4..16 + 4].try_into().unwrap();
                block_numbers.push(i);
                graph_ids.push(graph_id);
                println!("block: {i}, graph_id: {:?}", hex::encode(graph_id));
            }
        }
    }
    Ok((block_numbers, graph_ids))
}

// https://github.com/ProjectZKM/reth-processor/blob/stateless/crates/executor/host/tests/integration.rs#L69
async fn fetch_exection_layer_block(
    execution_layer_rpc: &str,
    execution_layer_block_number: u64,
    genesis: &Genesis,
) -> anyhow::Result<EthClientExecutorInput> {
    // Setup the provider.
    let rpc_url = Url::parse(&execution_layer_rpc)?;
    let provider = RootProvider::<Ethereum>::new_http(rpc_url);
    //let rpc_db = RpcDb::new(provider.clone(), provider.clone(), execution_layer_block_number - 1);
    let chain_spec: Arc<ChainSpec> = Arc::new(genesis.try_into().unwrap());
    let custom_beneficiary = None;
    let host_executor = EthHostExecutor::eth(chain_spec, custom_beneficiary);
    // Execute the host.
    let client_input = host_executor
        .execute(
            execution_layer_block_number,
            &provider,
            &provider,
            genesis.clone(),
            custom_beneficiary,
            false,
        )
        .await?;
    Ok(client_input)
}

pub async fn fetch_state_chain(
    l2_contract_address: &str,
    proceed_withdraw_method_id: &str,
    start: u64,
    batch_size: u64,
    execution_layer_rpc: &str,
    blocks_file: &str,
    genesis: &str,
    cosmos_rpc_url: &str,
) -> anyhow::Result<Vec<CircuitStateBlock>> {
    let genesis = if genesis == "goattest" { Genesis::GoatTestnet } else { Genesis::GOAT };
    assert!(start > 0, "Don't get genesis block from the consensus layer.");
    let mut blocks: Vec<_> = Vec::new();
    let addr = l2_contract_address.trim_prefix("0x");
    let bytes: [u8; 20] = hex::decode(addr).unwrap().try_into().unwrap();
    let l2_contract_address = Address::from(bytes);
    let base_slot: [u8; 32] = U256::from(16).to_be_bytes().try_into()?;

    let proceed_withdraw_method_id =
        hex_parse::<4>(proceed_withdraw_method_id).map_err(|e| anyhow::anyhow!(e))?;
    // fetch graph_block_numbers and graph_ids between in goat block(start, start + batch_size)
    let (graph_block_numbers, graph_ids) = fetch_withdrawal(
        execution_layer_rpc,
        &l2_contract_address,
        &proceed_withdraw_method_id,
        start,
        batch_size,
    )
    .await?;

    for i in start..(start + batch_size) {
        let (_, cl_block_number) = fetch_cbft_validator_info(cosmos_rpc_url, i).await?;
        let cosmos_txns = fetch_cbft_tx_data(cosmos_rpc_url, cl_block_number).await?;
        let cosmos_block = fetch_cosmos_block(cosmos_rpc_url, cl_block_number).await?;
        let evm_block = fetch_exection_layer_block(&execution_layer_rpc, i, &genesis).await?;

        let withdrawals = if !graph_block_numbers.is_empty() {
            let indices: Vec<usize> = graph_block_numbers
                .iter()
                .enumerate()
                .filter(|&(_, &val)| val == i)
                .map(|(i, _)| i)
                .collect();
            let _graph_ids: Vec<_> = indices.iter().map(|&x| graph_ids[x].clone()).collect();
            if _graph_ids.len() > 0 {
                tracing::info!("block_id: {i}, check graph_ids: {:?}", _graph_ids);
                Some((l2_contract_address, base_slot, _graph_ids))
            } else {
                None
            }
        } else {
            None
        };

        let cosmos_block = serde_json::to_vec(&cosmos_block)?;
        tracing::info!("[push] block: {}, withdrawals: {:?}", i, withdrawals);
        blocks.push(CircuitStateBlock { cosmos_txns, cosmos_block, evm_block, withdrawals });
    }
    let block_bytes = serde_json::to_vec(&blocks)?;
    std::fs::write(&blocks_file, block_bytes)?;
    Ok(blocks)
}

pub struct StateChainProofBuilder {
    client: ProverClient,
    proving_key: zkm_sdk::ZKMProvingKey,
    verifying_key: zkm_sdk::ZKMVerifyingKey,
}

impl StateChainProofBuilder {
    pub fn new() -> Self {
        let client = ProverClient::new();
        let (proving_key, verifying_key) = client.setup(STATE_CHAIN);
        Self { client, proving_key, verifying_key }
    }
}

impl ProofBuilder for StateChainProofBuilder {
    fn client(&self) -> &zkm_sdk::ProverClient {
        &self.client
    }

    fn pk(&self) -> &zkm_sdk::ZKMProvingKey {
        &self.proving_key
    }

    fn vk(&self) -> &zkm_sdk::ZKMVerifyingKey {
        &self.verifying_key
    }

    fn name() -> String {
        "state-chain".to_string()
    }

    fn build_proof(
        &self,
        ctx: &ProofRequest,
    ) -> anyhow::Result<(Vec<u8>, ZKMProofWithPublicValues, u64, f32)> {
        let ProofRequest::StateChainProofRequest { init_input, input_proof, blocks, .. } = ctx
        else {
            anyhow::bail!("Invalid state chain inputs");
        };

        let vk_hash = self.verifying_key.hash_u32();
        // Set the previous proof type based on input_proof argument
        let prev_receipt = if *init_input {
            None
        } else {
            let proof_bytes = fs::read(input_proof).context("Failed to read input proof file")?;
            let proof: ZKMProofWithPublicValues = bincode::deserialize(&proof_bytes)?;
            Some(proof)
        };
        let (prev_proof, pv_hash) = match prev_receipt.clone() {
            Some(mut receipt) => {
                let request = receipt.public_values.read();
                let pv_hash: [u8; 32] = receipt.public_values.hash().try_into().unwrap();
                (StateChainPrevProofType::PrevProof(request), pv_hash)
            }
            None => (StateChainPrevProofType::GenesisBlock, [0u8; 32]),
        };

        let input: StateChainCircuitInput =
            StateChainCircuitInput { vk_hash, pv_hash, prev_proof, blocks: blocks.clone() };
        // Generate the proofs.
        let (proof, cycles, proving_time) = tracing::info_span!("generate proof").in_scope(
            || -> anyhow::Result<(ZKMProofWithPublicValues, u64, f32)> {
                let mut stdin = ZKMStdin::new();
                stdin.write(&input);
                if let Some(proof) = prev_receipt {
                    let ZKMProof::Compressed(compressed_proof) = proof.proof else { panic!() };
                    stdin.write_proof(*compressed_proof, self.verifying_key.vk.clone());
                } else {
                    tracing::info!("Skip writing proof for genesis evm block");
                }
                let elf_id = if ELF_ID.get().is_none() {
                    ELF_ID
                        .set(hex::encode(Sha256::digest(&self.proving_key.elf)))
                        .map_err(anyhow::Error::msg)?;
                    None
                } else {
                    Some(ELF_ID.get().unwrap().clone())
                };
                tracing::info!("elf id: {:?}", elf_id);

                let proving_start = tokio::time::Instant::now();
                let (proof, cycles) = self.client.prove_with_cycles(
                    &self.proving_key,
                    &stdin,
                    ZKMProofKind::Compressed,
                    elf_id,
                )?;
                let proving_duration = proving_start.elapsed().as_secs_f32() * 1000.0;
                Ok((proof, cycles, proving_duration))
            },
        )?;
        tracing::info!("State chain proof cycles: {}", cycles);
        if let Err(e) = self.client.verify(&proof, &self.verifying_key) {
            panic!("{}", e);
        }

        let input = bincode::serialize(&input)?;
        Ok((input, proof, cycles, proving_time))
    }

    fn save_proof(
        &self,
        ctx: &ProofRequest,
        input: &[u8],
        _cycles: u64,
        proof: ZKMProofWithPublicValues,
    ) -> anyhow::Result<(String, usize)> {
        let ProofRequest::StateChainProofRequest { output_proof, .. } = ctx else {
            anyhow::bail!("Invalid state chain inputs");
        };
        fs::write(output_proof, bincode::serialize(&proof)?)?;
        let public_value_hex = hex::encode(proof.public_values.as_slice());
        let proof_size = proof.bytes().len();
        fs::write(&format!("{}.vk", output_proof), bincode::serialize(&self.verifying_key)?)?;
        fs::write(&format!("{}.in", output_proof), input)?;
        tracing::info!("Generate proof successfully, proof: {:?}", proof);
        Ok((public_value_hex, proof_size))
    }
}
