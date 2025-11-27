use crate::cbft::check_el_block_from_payload;
use alloy_consensus::Header;
use alloy_primitives::utils::keccak256;
use alloy_primitives::{Address, B256, U256};
use guest_executor::executor::EthClientExecutor;
use guest_executor::io::EthClientExecutorInput;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// The input proof of the commit chain circuit.
/// The proof can be either None (implying the beginning) or a Succinct proof.
#[derive(Serialize, Deserialize, PartialEq, Clone, Debug)]
pub enum StateChainPrevProofType {
    GenesisBlock,
    PrevProof(StateChainCircuitOutput),
}

#[derive(Serialize, Deserialize, PartialEq, Clone, Debug)]
pub struct CircuitStateBlock {
    pub state_txns: Vec<String>,
    pub state_data_hash: [u8; 32],
    pub evm_input: EthClientExecutorInput,
    // (gateway contracts, withdraw_data_base_slot, [graph_ids])
    pub withdrawals: Option<(Address, [u8; 32], Vec<[u8; 16]>)>,
}

/// The latest seqeuncer set
#[derive(Serialize, Deserialize, PartialEq, Clone, Debug)]
pub struct StateChainState {
    pub block_height: u64,
    pub genesis_block_hash: [u8; 32],
    pub latest_block_hash: [u8; 32],
}

#[derive(Serialize, Deserialize, PartialEq, Clone, Debug)]
pub struct StateChainCircuitOutput {
    pub vk_hash: [u32; 8],
    pub chain_state: StateChainState,
}

#[derive(Serialize, Deserialize, PartialEq, Clone, Debug)]
pub struct StateChainCircuitInput {
    pub vk_hash: [u32; 8],
    pub pv_hash: [u8; 32],
    pub prev_proof: StateChainPrevProofType,
    pub blocks: Vec<CircuitStateBlock>,
}

impl Default for StateChainState {
    fn default() -> Self {
        Self::new()
    }
}

impl StateChainState {
    pub fn new() -> Self {
        // FIXME: don't hardcode
        StateChainState {
            block_height: 1,
            genesis_block_hash: hex::decode(
                "30f474514d6cd219f459b2d481b2d4376a6637e881b982ffa8d63610932b33f6",
            )
            .unwrap()
            .try_into()
            .unwrap(),
            latest_block_hash: hex::decode(
                "30f474514d6cd219f459b2d481b2d4376a6637e881b982ffa8d63610932b33f6",
            )
            .unwrap()
            .try_into()
            .unwrap(),
        }
    }

    pub fn apply_block(&mut self, blocks: Vec<CircuitStateBlock>) {
        for block in blocks {
            // check evm state transition
            let evm_header =
                execute_el_block_and_check_withdraw_tx(&block.withdrawals, block.evm_input.clone());
            assert_eq!(evm_header.number, block.evm_input.current_block.number);
            assert_eq!(evm_header.number, self.block_height);

            let block_hash = evm_header.hash_slow();
            let current_block_hash: [u8; 32] = block_hash.try_into().unwrap();
            // check the evm block is committed in the consensus txns
            let parent_block_hash = self.latest_block_hash;
            assert_eq!(self.latest_block_hash, parent_block_hash);
            check_el_block_from_payload(
                block.evm_input.current_block.number,
                &current_block_hash,
                &parent_block_hash,
                &block.state_txns,
                block.state_data_hash.clone(),
            );

            self.block_height += 1;
            self.latest_block_hash = current_block_hash;
        }
    }
}

// https://github.com/GOATNetwork/bitvm2-L2-contracts/blob/main/src/Gateway.sol#L192
// Get base slot:  forge inspect src/GatewayDebug.sol:GatewayDebug storage-layout
pub fn execute_el_block_and_check_withdraw_tx(
    withdrawals: &Option<(Address, [u8; 32], Vec<[u8; 16]>)>,
    //l2_contract_address: &Option<Address>,
    //withdraw_data_map_slot: &Option<[u8; 32]>,
    //graph_id: &Option<[u8; 16]>,
    input: EthClientExecutorInput,
) -> Header {
    // verify the state transition and withdraw status
    let executor = EthClientExecutor::eth(
        Arc::new((&input.genesis).try_into().unwrap()),
        input.custom_beneficiary,
    );

    let mut storage_info = None;

    if withdrawals.is_some() {
        let mut tuple = vec![];
        for graph_id in &withdrawals.as_ref().unwrap().2 {
            let mut data = [0u8; 32 * 2];
            data[0..16].copy_from_slice(graph_id);
            data[32..].copy_from_slice(&withdrawals.as_ref().unwrap().1);
            let slot_id = B256::from(keccak256(data));
            tuple.push((withdrawals.as_ref().unwrap().0.clone(), slot_id.into(), U256::ONE));
        }

        //storage_info = Some(vec![(l2_contract_address.unwrap(), slot_id.into(), U256::from(1))]);
        storage_info = Some(tuple);
    }

    let (header, _) = executor.execute(input, storage_info).expect("failed to execute client");
    let block_hash = header.hash_slow();
    println!("block_hash: {block_hash:?}");
    header
    // assert_eq!(block_hash, next_block_hash);
}
