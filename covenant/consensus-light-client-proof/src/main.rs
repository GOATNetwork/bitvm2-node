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

    let prev_commit_txn: CircuitTransaction = zkm_zkvm::io::read();
    let prev_sequencer_set: consensus_light_client::ValidatorSet = zkm_zkvm::io::read(); 

    let latest_commit_txn_with_wtns: CircuitTransaction = zkm_zkvm::io::read();
    let latest_sequencer_set: consensus_light_client::ValidatorSet = zkm_zkvm::io::read(); 

    let publisher_public_keys: Vec<PublicKey> = zkm_zkvm::io::read();
    let threshold: usize = zkm_zkvm::io::read();

    bitcoin_light_client::prove_publisher_commitment_continuality(
        prev_commit_txn,
        prev_sequencer_set, 
        latest_commit_txn_with_wtns,
        latest_sequencer_set, 
        publisher_public_keys,
        threshold,
    );

    zkm_zkvm::io::commit(prev_commit_txn.0.compute_txid());
    zkm_zkvm::io::commit(latest_commit_txn.0.compute_txid());
}
