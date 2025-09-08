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


pub fn main() {
    let total_work: [u8; 32] = zkm_zkvm::io::read::<[u8; 32]>();
    let latest_sequencer_commit_txid = zkm_zkvm::io::read::<[u8; 32]>();
    let genesis_sequencer_commit_txid = zkm_zkvm::io::read::<[u8; 32]>(); // hardcode
    let header_chain: HeaderChainCircuitInput = zkm_zkvm::io::read::<HeaderChainCircuitInput>(); // private inputs
    let latest_sequencer_commit_txid_inclusion_proof: BlockInclusionProof =
        zkm_zkvm::io::read::<BlockInclusionProof>();
    let sequencer_set_commit_vk: [u32; 8] = zkm_zkvm::io::read::<[u32; 8]>();

    bitcoin_light_client::generate_watchtower_proof(
        total_work, 
        latest_sequencer_commit_txid,
        genesis_sequencer_commit_txid,
        header_chain,
        latest_sequencer_commit_txid_inclusion_proof,
        sequencer_set_commit_vk,
    );
}
