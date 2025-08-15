#![no_main]
zkm_zkvm::entrypoint!(main);

//use guest_executor::verify_block;
/// Client program input data types.
use alloy_primitives::utils::keccak256;
use alloy_primitives::{B256, U256};
use guest_executor::executor::{EthClientExecutor, DESERIALZE_INPUTS};
use guest_executor::io::EthClientExecutorInput;
use std::sync::Arc;
use alloy_primitives::{Address, address};
use revm::DatabaseRef;

use consensus_light_client::verify_validator_set_hash;

//use bitcoin::Address as addddddd;
//use header_chain::{HeaderChainCircuitInput, BlockHeaderCircuitOutput, ChainState, HeaderChainPrevProofType};

pub fn verify_block(input: EthClientExecutorInput) -> (B256, B256, B256) {
    // Execute the block.
    let executor = EthClientExecutor::eth(
        Arc::new((&input.genesis).try_into().unwrap()),
        input.custom_beneficiary,
    );
    let (header, prev_state_root) = executor.execute(input).expect("failed to execute client");
    let block_hash = header.hash_slow();
    (block_hash, header.state_root, prev_state_root)
}

// pub fn verify_sequencer_sig(public_keys: Vec<>, )

pub fn verify_withdraw_tx(l2_contract_address: Address, base_slot: U256, key: U256, input: &EthClientExecutorInput) -> U256 {
    let mut data = [0u8; 64];
    let mut base = base_slot.to_be_bytes::<32>();
    data[0..32].copy_from_slice(&mut base);
    let mut k = key.to_be_bytes::<32>();
    data[32..].copy_from_slice(&mut k);
    let slot_id = B256::from(keccak256(data));

    let wtns_db = input.witness_db().unwrap();
    wtns_db.storage_ref(l2_contract_address, slot_id.into()).unwrap()
}

// /// The main entry point of the header chain circuit.
// pub fn header_chain_circuit(input: HeaderChainCircuitInput) -> BlockHeaderCircuitOutput {
//     // println!("Detected network: {:?}", NETWORK_TYPE);
//     // println!("NETWORK_CONSTANTS: {:?}", NETWORK_CONSTANTS);
//     let mut chain_state = match input.prev_proof {
//         HeaderChainPrevProofType::GenesisBlock => ChainState::new(),
//         HeaderChainPrevProofType::PrevProof(prev_proof) => {
//             assert_eq!(prev_proof.method_id, input.method_id);
//             // FIXME
//             // guest.verify(input.method_id, &prev_proof);
//             prev_proof.chain_state
//         }
//     };
// 
//     chain_state.apply_blocks(input.block_headers);
// 
//     BlockHeaderCircuitOutput {
//         method_id: input.method_id,
//         chain_state,
//     }
// }

pub fn main() {
    // let btc_header_chain_input = zkm_zkvm::io::read_vec();
    // let btc_header_chain_input: HeaderChainCircuitInput = bincode::deserialize::<HeaderChainCircuitInput>(&btc_header_chain_input).unwrap();
    // let _btc_header_chain_output = header_chain_circuit(btc_header_chain_input);
    // TODO

    // Read the input.
    let goat_block_input = zkm_zkvm::io::read_vec();

    println!("cycle-tracker-report-start: {}", DESERIALZE_INPUTS);
    let goat_block_input: EthClientExecutorInput = bincode::deserialize::<EthClientExecutorInput>(&goat_block_input).unwrap();
    println!("cycle-tracker-report-end: {}", DESERIALZE_INPUTS);

    // hardcode 
    let l2_contract_address = address!("0x377B8c3d7Dc2466D329C71B936a8D528cbF59C2e");

    // Can graph_id be hardcoded?
    let slot_base = U256::from(1u32);
    let graph_id = U256::from(122u32);

    let withdraw_data_base = verify_withdraw_tx(l2_contract_address, slot_base, graph_id, &goat_block_input);
    assert_ne!(withdraw_data_base, U256::from(0u32));

    let (_, cur_state_root, prev_state_root) = verify_block(goat_block_input);

    zkm_zkvm::io::commit(&prev_state_root);
    zkm_zkvm::io::commit(&cur_state_root);
}
