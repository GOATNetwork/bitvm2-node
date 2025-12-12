#![feature(trim_prefix_suffix)]
use alloy_primitives::{Address, U256};
use alloy_provider::{RootProvider, network::Ethereum};
use bitcoin_light_client_circuit::EthClientExecutorInput;
use cbft_rpc::{fetch_cbft_tx_data, fetch_cbft_validator_info, fetch_cosmos_block};
use host_executor::EthHostExecutor;
use primitives::genesis::Genesis;
use proof_builder::ProofBuilder;
use proof_builder::{Context, ProofRequest};
use reth_chainspec::ChainSpec;
use rpc_db::RpcDb;
use state_chain::*;
use std::sync::Arc;
use url::Url;
use zkm_sdk::{
    HashableKey, Prover, ProverClient, ZKMProof, ZKMProofKind, ZKMProofWithPublicValues, ZKMStdin,
    include_elf,
};

use sha2::{Digest, Sha256};
use std::sync::OnceLock;
static ELF_ID: OnceLock<String> = OnceLock::new();

/// A program that aggregates the proofs of the simple program.
const STATE_CHAIN: &[u8] = include_elf!("guest");

use std::fs;

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

pub async fn fetch_state_chain(
    l2_contract_address: String,
    start: u64,
    batch_size: u64,
    execution_layer_rpc: String,
    graph_block_numbers: Vec<u64>,
    graph_ids: Vec<[u8; 16]>,
    blocks_file: String,
) -> Vec<CircuitStateBlock> {
    assert!(start > 0, "Don't get genesis block from the consensus layer.");
    let mut blocks: Vec<_> = Vec::new();
    let addr = l2_contract_address.trim_prefix("0x");
    let bytes: [u8; 20] = hex::decode(addr).unwrap().try_into().unwrap();
    let l2_contract_address = Address::from(bytes);
    let base_slot: [u8; 32] = U256::from(12).to_be_bytes().try_into().unwrap();
    let genesis = &Genesis::GoatTestnet;

    for i in start..(start + batch_size) {
        let (_, cl_block_number) = fetch_cbft_validator_info(i).await.unwrap();
        let cosmos_txns = fetch_cbft_tx_data(cl_block_number).await.unwrap();
        let cosmos_block = fetch_cosmos_block(cl_block_number).await.unwrap();
        let evm_block = fetch_exection_layer_block(&execution_layer_rpc, i, genesis).await;

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

        let cosmos_block = serde_json::to_vec(&cosmos_block).unwrap();
        tracing::info!("[push] block: {}, withdrawals: {:?}", i, withdrawals);
        blocks.push(CircuitStateBlock { cosmos_txns, cosmos_block, evm_block, withdrawals });
    }
    let block_bytes = serde_json::to_vec(&blocks).unwrap();
    std::fs::write(&blocks_file, block_bytes).unwrap();
    blocks
}

pub struct StateChainProofBuilder {
    client: ProverClient,
    proving_key: zkm_sdk::ZKMProvingKey,
    verifying_key: zkm_sdk::ZKMVerifyingKey,
    // database handle
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

    fn build_proof(
        &self,
        ctx: &Context,
    ) -> anyhow::Result<(Vec<u8>, ZKMProofWithPublicValues, u64)> {
        let ProofRequest::StateChainProofRequest {
            ref init_input,
            ref input_proof,
            ref blocks,
            ..
        } = ctx.request
        else {
            return Err(anyhow::anyhow!("Invalid state chain inputs"));
        };

        let vk_hash = self.verifying_key.hash_u32();
        // Set the previous proof type based on input_proof argument
        let prev_receipt = if *init_input {
            None
        } else {
            let proof_bytes = fs::read(input_proof).expect("Failed to read input proof file");
            let proof: ZKMProofWithPublicValues =
                bincode::deserialize(&proof_bytes).expect("failed to deserialize the proof");
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
        let (proof, cycles) = tracing::info_span!("generate proof").in_scope(|| {
            let mut stdin = ZKMStdin::new();
            stdin.write(&input);
            if let Some(proof) = prev_receipt {
                let ZKMProof::Compressed(compressed_proof) = proof.proof else { panic!() };
                stdin.write_proof(*compressed_proof, self.verifying_key.vk.clone());
            } else {
                tracing::info!("Skip writing proof for genesis evm block");
            }
            let elf_id = if ELF_ID.get().is_none() {
                ELF_ID.set(hex::encode(Sha256::digest(&self.proving_key.elf))).unwrap();
                None
            } else {
                Some(ELF_ID.get().unwrap().clone())
            };
            tracing::info!("elf id: {:?}", elf_id);

            self.client
                .prove_with_cycles(&self.proving_key, &stdin, ZKMProofKind::Compressed, elf_id)
                .expect("proving failed")
        });
        tracing::info!("State chain proof cycles: {}", cycles);
        if let Err(e) = self.client.verify(&proof, &self.verifying_key) {
            panic!("{}", e);
        }

        let input = bincode::serialize(&input)?;
        Ok((input, proof, cycles))
    }

    fn save_proof(
        &self,
        ctx: &Context,
        input: &[u8],
        proof: ZKMProofWithPublicValues,
    ) -> anyhow::Result<()> {
        let ProofRequest::StateChainProofRequest { ref output_proof, .. } = ctx.request else {
            return Err(anyhow::anyhow!("Invalid state chain inputs"));
        };
        fs::write(output_proof, bincode::serialize(&proof)?)?;
        fs::write(&format!("{}.vk", output_proof), bincode::serialize(&self.verifying_key)?)?;
        fs::write(&format!("{}.in", output_proof), input)?;
        tracing::info!("Generate proof successfully, proof: {:?}", proof);
        Ok(())
    }

    fn is_long_running(&self) -> bool {
        true
    }
}
