#![no_main]
zkm_zkvm::entrypoint!(main);

use header_chain::{
    verify_merkle_proof, BlockHeaderCircuitOutput, BlockInclusionProof, ChainState,
    CircuitTransaction, HeaderChainCircuitInput, HeaderChainPrevProofType,
};
use alloy_primitives::hex;
use alloy_primitives::utils::keccak256;
use alloy_primitives::Address;
use alloy_primitives::{B256, U128, U256};
use bitcoin::{
    TxOut, ScriptBuf
};
use guest_executor::executor::EthClientExecutor;
use guest_executor::io::EthClientExecutorInput;
use revm::DatabaseRef;
use sha2::Digest;
use std::sync::Arc;
use zkm_verifier::Groth16Verifier;

use consensus_light_client::LightBlock;


//pub fn main() {
//    let total_work: [u8; 32] = zkm_zkvm::io::read::<[u8; 32]>();
//    let latest_sequencer_commit_txid = zkm_zkvm::io::read::<[u8; 32]>();
//    let genesis_sequencer_commit_txid = zkm_zkvm::io::read::<[u8; 32]>(); // hardcode
//    let header_chain: HeaderChainCircuitInput = zkm_zkvm::io::read::<HeaderChainCircuitInput>(); // private inputs
//    let latest_sequencer_commit_txid_inclusion_proof: BlockInclusionProof =
//        zkm_zkvm::io::read::<BlockInclusionProof>();
//    let sequencer_set_commit_vk: [u32; 8] = zkm_zkvm::io::read::<[u32; 8]>();
//
//    bitcoin_light_client::generate_watchtower_proof();
//}


pub fn main() {
     // calculate operator public input:  https://github.com/ProjectZKM/Ziren/blob/main/crates/sdk/src/utils.rs#L42
    let included_watchertowers: U256 = zkm_zkvm::io::read::<U256>();
    let graph_id: [u8; 16] = zkm_zkvm::io::read::<[u8; 16]>();

    // hardcode
    let genesis_sequencer_commit_txid: [u8; 32] = zkm_zkvm::io::read();

    //latest_sequencer_commit_tx: &CircuitTransaction,
    let operator_latest_sequencer_commit_txn: CircuitTransaction = zkm_zkvm::io::read(); // private inputs
    // extract consensus block height

    let consensus_blocks: [LightBlock; 2] = zkm_zkvm::io::read(); // commit the sequencer set
    let eth_client_execution_input: EthClientExecutorInput = zkm_zkvm::io::read();

    // https://github.com/KSlashh/BitVM/blob/v2/goat/src/transactions/watchtower_challenge.rs#L128
    let watchtower_challenge_txns: Vec<CircuitTransaction> = zkm_zkvm::io::read();

    let watchtower_challenge_txn_script: Vec<ScriptBuf> = zkm_zkvm::io::read();
    let watchtower_challenge_txn_prev_out: Vec<TxOut> = zkm_zkvm::io::read();
    let watchtower_challenge_txn_pubkey: Vec<bitcoin::secp256k1::PublicKey> = zkm_zkvm::io::read();
    let watchtower_challenge_txn_sig: Vec<bitcoin::taproot::Signature> = zkm_zkvm::io::read();

    let operator_header_chain: HeaderChainCircuitInput = zkm_zkvm::io::read();

    // hardcode
    let l2_contract_address: Address = zkm_zkvm::io::read();
    // hardcode
    let base_slot: U256 = zkm_zkvm::io::read();

    let latest_sequencer_commit_txid_inclusion_proof: BlockInclusionProof = zkm_zkvm::io::read();
    let sequencer_set_commit_vk: [u32; 8] = zkm_zkvm::io::read();

    bitcoin_light_client::generate_operator_proof(
        included_watchertowers,
        graph_id,
        genesis_sequencer_commit_txid,
        operator_latest_sequencer_commit_txn,
        consensus_blocks,
        eth_client_execution_input,
        watchtower_challenge_txns,
        watchtower_challenge_txn_script,
        watchtower_challenge_txn_prev_out,
        watchtower_challenge_txn_pubkey,
        watchtower_challenge_txn_sig,
        operator_header_chain,
        l2_contract_address,
        base_slot,
        latest_sequencer_commit_txid_inclusion_proof,
        sequencer_set_commit_vk,
    );
}
