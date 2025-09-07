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

use header_chain::{HeaderChainCircuitInput, HeaderChainPrevProofType, BlockHeaderCircuitOutput};
use bitcoin_light_client::header_chain_circuit;

pub fn main() {
    let input: HeaderChainCircuitInput = zkm_zkvm::io::read();
    let output = header_chain_circuit(input);
    zkm_zkvm::io::commit(output);
}
