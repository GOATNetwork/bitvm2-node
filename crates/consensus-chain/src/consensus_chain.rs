use guest_executor::io::EthClientExecutorInput;
use crate::cbft::check_el_block_from_payload;
use serde::{Deserialize, Serialize};
use alloy_consensus::Header;
pub use tendermint_light_client_verifier::{
    ProdVerifier, Verdict, Verifier,
    options::Options,
    types::{LightBlock, ValidatorSet},
};
use alloy_primitives::{Address, U256, B256};
use guest_executor::executor::EthClientExecutor;
use std::sync::Arc; 
use alloy_primitives::utils::keccak256;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as b64;

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct ConsensusInfo {
    pub threshold: u16,
    pub publisher_public_keys: Vec<String>,
    pub txid: String,
    pub genesis_txid: String,
}

/// The input proof of the commit chain circuit.
/// The proof can be either None (implying the beginning) or a Succinct proof.
#[derive(Serialize, Deserialize, PartialEq, Clone, Debug)]
pub enum ConsensusChainPrevProofType {
    GenesisBlock,
    PrevProof(ConsensusChainCircuitOutput),
}

#[derive(Serialize, Deserialize, PartialEq, Clone, Debug)]
pub struct CiruitConsensusBlock {
    pub consensus_txns: Vec<String>,
    pub consessus_data_hash: [u8; 32],
    pub evm_input: EthClientExecutorInput,
}

/// The latest seqeuncer set
#[derive(Serialize, Deserialize, PartialEq, Clone, Debug)]
pub struct ConsensusChainState {
    pub block_height: u64,
    pub genesis_block_hash: [u8; 32],
    pub latest_block_hash: [u8; 32],
}

#[derive(Serialize, Deserialize, PartialEq, Clone, Debug)]
pub struct ConsensusChainCircuitOutput {
    pub vk_hash: [u32; 8],
    pub chain_state: ConsensusChainState,
}

#[derive(Serialize, Deserialize, PartialEq, Clone, Debug)]
pub struct ConsensusChainCircuitInput {
    pub vk_hash: [u32; 8],
    pub pv_hash: [u8; 32],
    pub prev_proof: ConsensusChainPrevProofType,
    pub blocks: Vec<CiruitConsensusBlock>,
}

impl Default for ConsensusChainState {
    fn default() -> Self {
        Self::new()
    }
}

impl ConsensusChainState {
    pub fn new() -> Self {
        ConsensusChainState {
            block_height: u64::MAX,
            genesis_block_hash: hex::decode("30f474514d6cd219f459b2d481b2d4376a6637e881b982ffa8d63610932b33f6").unwrap().try_into().unwrap(),
            latest_block_hash: hex::decode("30f474514d6cd219f459b2d481b2d4376a6637e881b982ffa8d63610932b33f6").unwrap().try_into().unwrap(),
        }
    }

    pub fn apply_block(&mut self, blocks: Vec<CiruitConsensusBlock>) {
        let sz = (1..blocks.len());
        for i in sz.into_iter() {
            let prev_block = &blocks[i - 1];
            let block = &blocks[i];
            // check evm state transition 
            let evm_header = execute_el_block_and_check_withdraw_tx(None, None, None, prev_block.evm_input.clone());
            assert_eq!(evm_header.number, prev_block.evm_input.current_block.number);

            let block_hash = evm_header.hash_slow();
            let current_block_hash: [u8; 32] = block_hash.try_into().unwrap();
            // check the evm block is committed in the consensus txns
            let parent_block_hash = self.latest_block_hash; 
            check_el_block_from_payload(
                prev_block.evm_input.current_block.number,
                &current_block_hash,
                &parent_block_hash,
                &prev_block.consensus_txns,
                prev_block.consessus_data_hash.clone(),
                //light_block_2.signed_header.header.data_hash.unwrap().as_bytes().try_into().unwrap(),
            );

            self.block_height = block.evm_input.current_block.number;
            self.latest_block_hash = current_block_hash; 
        }
    }
}


// https://github.com/GOATNetwork/bitvm2-L2-contracts/blob/main/src/Gateway.sol#L192
// Get base slot:  forge inspect src/GatewayDebug.sol:GatewayDebug storage-layout
pub fn execute_el_block_and_check_withdraw_tx(
    l2_contract_address: Option<Address>,
    withdraw_data_map_slot: Option<[u8; 32]>,
    graph_id: Option<[u8; 16]>,
    input: EthClientExecutorInput,
) -> Header {
    // verify the state transition and withdraw status
    let executor = EthClientExecutor::eth(
        Arc::new((&input.genesis).try_into().unwrap()),
        input.custom_beneficiary,
    );

    let mut storage_info = None;

    if l2_contract_address.is_some() {
        let mut data = [0u8; 32 * 2];
        data[0..16].copy_from_slice(graph_id.as_ref().unwrap());
        data[32..].copy_from_slice(withdraw_data_map_slot.as_ref().unwrap());
        let slot_id = B256::from(keccak256(data));
        storage_info = Some(vec![(l2_contract_address.unwrap(), slot_id.into(), U256::from(1))]);
    }

    let (header, _) = executor
        .execute(input, storage_info)
        .expect("failed to execute client");
    let block_hash = header.hash_slow();
    println!("block_hash: {block_hash:?}");
    header
    // assert_eq!(block_hash, next_block_hash);
}