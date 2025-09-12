#![no_main]
zkm_zkvm::entrypoint!(main);

use header_chain::{
    HeaderChainCircuitInput, SPV, CircuitTransaction, 
};
use alloy_primitives::{U256, Address};
use bitcoin_light_client::{LightBlock, CommitChainCircuitInput, EthClientExecutorInput};
use bitcoin::{ScriptBuf, TxOut};

pub fn main() {
    // calculate operator public input:  https://github.com/ProjectZKM/Ziren/blob/main/crates/sdk/src/utils.rs#L42
    let included_watchertowers: U256 = zkm_zkvm::io::read::<U256>();
    let graph_id: [u8; 16] = zkm_zkvm::io::read::<[u8; 16]>();
    //latest_sequencer_commit_tx: &CircuitTransaction,
    let operator_latest_sequencer_commit_txn: CircuitTransaction = zkm_zkvm::io::read(); // private inputs
    let latest_sequencer_commit_txid = operator_latest_sequencer_commit_txn.0.compute_txid(); // public input
    // extract consensus block height
    let consensus_blocks: LightBlock = zkm_zkvm::io::read(); // commit the sequencer set
    let eth_client_execution_input: EthClientExecutorInput = zkm_zkvm::io::read();
    // https://github.com/KSlashh/BitVM/blob/v2/goat/src/transactions/watchtower_challenge.rs#L128
    let watchtower_challenge_txns: Vec<CircuitTransaction> = zkm_zkvm::io::read();

    let watchtower_challenge_txn_script: Vec<ScriptBuf> = zkm_zkvm::io::read();
    let watchtower_challenge_txn_prev_out: Vec<TxOut> = zkm_zkvm::io::read();
    let watchtower_challenge_txn_pubkey: Vec<bitcoin::secp256k1::PublicKey> = zkm_zkvm::io::read();
    let watchtower_challenge_txn_sig: Vec<bitcoin::taproot::Signature> = zkm_zkvm::io::read();

    let operator_header_chain: HeaderChainCircuitInput = zkm_zkvm::io::read();
    let operator_commit_chain: CommitChainCircuitInput = zkm_zkvm::io::read();
    let spv: SPV = zkm_zkvm::io::read();

    // hardcode
    let l2_contract_address: Address = zkm_zkvm::io::read();
    // hardcode
    let base_slot: U256 = zkm_zkvm::io::read();

    let operator_total_work = bitcoin_light_client::generate_operator_proof(
        included_watchertowers,
        graph_id,
        operator_latest_sequencer_commit_txn,
        consensus_blocks,
        eth_client_execution_input,
        watchtower_challenge_txns,
        watchtower_challenge_txn_script,
        watchtower_challenge_txn_prev_out,
        watchtower_challenge_txn_pubkey,
        watchtower_challenge_txn_sig,
        operator_header_chain,
        operator_commit_chain,
        spv,
        l2_contract_address,
        base_slot,
    );

    zkm_zkvm::io::commit(&operator_total_work);
    zkm_zkvm::io::commit(&latest_sequencer_commit_txid);
}

