use crate::cbft::check_el_block_from_payload;
use alloy_consensus::Header;
use alloy_primitives::utils::keccak256;
use alloy_primitives::{Address, B256, U256};
use guest_executor::executor::EthClientExecutor;
use guest_executor::io::EthClientExecutorInput;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tendermint_light_client_verifier::types::LightBlock;

// Contract address, base slot and key, the expected value of the slot is hardcoded to 1.
type WithdrawalSlot = (Address, [u8; 32], Vec<[u8; 16]>);

/// The input proof of the commit chain circuit.
/// The proof can be either None (implying the beginning) or a Succinct proof.
#[derive(Serialize, Deserialize, PartialEq, Clone, Debug)]
pub enum StateChainPrevProofType {
    GenesisBlock,
    PrevProof(StateChainCircuitOutput),
}

#[derive(Serialize, Deserialize, PartialEq, Clone, Debug)]
pub struct CircuitStateBlock {
    pub cosmos_txns: Vec<Vec<u8>>,
    // Cosmos light block
    pub cosmos_block: Vec<u8>,
    pub evm_block: EthClientExecutorInput,
    // (gateway contracts, withdraw_data_base_slot, [graph_ids])
    pub withdrawals: Option<(Address, [u8; 32], Vec<[u8; 16]>)>,
}

/// The latest seqeuncer set
#[derive(Serialize, Deserialize, PartialEq, Clone, Debug)]
pub struct StateChainState {
    pub evm_block_height: u64,
    pub genesis_evm_block_hash: [u8; 32],
    pub latest_evm_block_hash: [u8; 32],
    pub latest_cosmos_block: Vec<u8>,
    pub withdrawals: Vec<(Address, [u8; 32], Vec<[u8; 16]>)>,
}

#[derive(Serialize, Deserialize, PartialEq, Clone, Debug)]
pub struct StateChainCircuitOutput {
    pub chain_state: StateChainState,
}

#[derive(Serialize, Deserialize, PartialEq, Clone, Debug)]
pub struct StateChainCircuitInput {
    pub zkm_proof: Vec<u8>,
    pub zkm_public_values: Vec<u8>,
    pub zkm_vk_hash: Vec<u8>,
    pub prev_proof: StateChainPrevProofType,
    pub blocks: Vec<CircuitStateBlock>,
}

impl StateChainState {
    pub fn new(
        evm_block_height: u64,
        genesis_evm_block_hash: [u8; 32],
        latest_cosmos_block: Vec<u8>,
    ) -> Self {
        StateChainState {
            evm_block_height,
            latest_evm_block_hash: genesis_evm_block_hash,
            genesis_evm_block_hash,
            latest_cosmos_block,
            withdrawals: vec![],
        }
    }

    pub fn apply_block(&mut self, blocks: Vec<CircuitStateBlock>) {
        for block in blocks {
            // check evm state transition
            let evm_header =
                execute_el_block_and_check_withdraw_tx(&block.withdrawals, block.evm_block.clone());
            assert_eq!(evm_header.number, block.evm_block.current_block.number);
            println!("[apply_block] block_height: {}", self.evm_block_height);
            assert_eq!(evm_header.number, self.evm_block_height);
            let current_block_hash: [u8; 32] = evm_header.hash_slow().into();
            // check the evm block is committed in the consensus txns
            // TODO: we carry the data hash in the state chain block for optimization
            let cosmos_block: LightBlock = serde_json::from_slice(&block.cosmos_block)
                .expect("failed to deserialize cosmos block");
            if current_block_hash != self.genesis_evm_block_hash {
                let data_hash: [u8; 32] = cosmos_block
                    .signed_header
                    .header
                    .data_hash
                    .unwrap()
                    .as_bytes()
                    .try_into()
                    .unwrap();
                check_el_block_from_payload(
                    block.evm_block.current_block.number,
                    &current_block_hash,
                    &self.latest_evm_block_hash,
                    &block.cosmos_txns,
                    &data_hash,
                );
                if let Some(w) = block.withdrawals {
                    self.withdrawals.push(w);
                }
            }
            self.evm_block_height += 1;
            self.latest_evm_block_hash = current_block_hash;
            self.latest_cosmos_block = block.cosmos_block.clone();
        }
    }
}

// https://github.com/GOATNetwork/bitvm2-L2-contracts/blob/main/src/Gateway.sol#L192
// Get base slot:  forge inspect src/GatewayDebug.sol:GatewayDebug storage-layout
pub fn execute_el_block_and_check_withdraw_tx(
    withdrawals: &Option<WithdrawalSlot>,
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
            // FIXME: hardcode the value to 1 for now
            tuple.push((withdrawals.as_ref().unwrap().0, slot_id.into(), U256::ONE));
        }
        storage_info = Some(tuple);
    }

    let (header, _) = executor.execute(input, storage_info).expect("failed to execute client");
    //let block_hash = header.hash_slow();
    //println!("block_hash: {block_hash:?}");
    header
    // assert_eq!(block_hash, next_block_hash);
}
