#![no_main]
zkm_zkvm::entrypoint!(main);
use std::str::FromStr;
use header_chain::{
    HeaderChainCircuitInput, SPV, CircuitTransaction, 
};
use alloy_primitives::{U256, Address};
use bitcoin_light_client::{LightBlock, EthClientExecutorInput};
use commit_chain::CommitChainCircuitInput;
use bitcoin::{ScriptBuf, TxOut};

pub fn main() {
    // calculate operator public input:  https://github.com/ProjectZKM/Ziren/blob/main/crates/sdk/src/utils.rs#L42
    let included_watchertowers: U256 = zkm_zkvm::io::read::<U256>();
    let graph_id: [u8; 16] = zkm_zkvm::io::read::<[u8; 16]>();
    //latest_sequencer_commit_tx: &CircuitTransaction,
    println!("read operator commit txn");
    let operator_latest_sequencer_commit_txn: CircuitTransaction = zkm_zkvm::io::read(); // private inputs
    let latest_sequencer_commit_txid = operator_latest_sequencer_commit_txn.0.compute_txid(); // public input
    // extract consensus block height
    println!("read cosmos block");
    let consensus_block_bytes: Vec<u8> = zkm_zkvm::io::read_vec(); // commit the sequencer set
    let consensus_block: LightBlock = serde_cbor::from_slice(&consensus_block_bytes).unwrap();
    let consensus_txns: Vec<String> = zkm_zkvm::io::read(); 
    println!("read geth block");
    let eth_client_execution_input: EthClientExecutorInput = zkm_zkvm::io::read();
    // https://github.com/KSlashh/BitVM/blob/v2/goat/src/transactions/watchtower_challenge.rs#L128
    let watchtower_challenge_txns: Vec<CircuitTransaction> = zkm_zkvm::io::read();
    let watchtower_challenge_txn_pubkey: Vec<bitcoin::secp256k1::PublicKey> = zkm_zkvm::io::read();
    let watchtower_challenge_txn_scripts: Vec<ScriptBuf> = zkm_zkvm::io::read();
    let watchtower_challenge_txn_prev_outs: Vec<TxOut> = zkm_zkvm::io::read();
    let watchtower_challenge_txn_prev_indices: Vec<usize> = zkm_zkvm::io::read();

    let operator_header_chain: HeaderChainCircuitInput = zkm_zkvm::io::read();
    let operator_commit_chain: CommitChainCircuitInput = zkm_zkvm::io::read();
    let spv: SPV = zkm_zkvm::io::read();

    // hardcode
    let l2_contract_address: Address = Address::from_str("0x99f6Dc59fB6B5b13578BeBb223e373Cb817Ac8f6").unwrap();
    let base_slot: U256 = U256::from(11);

    let operator_total_work = bitcoin_light_client::generate_operator_proof(
        included_watchertowers,
        graph_id,
        operator_latest_sequencer_commit_txn,
        consensus_block,
        consensus_txns,
        eth_client_execution_input,
        watchtower_challenge_txns,
        watchtower_challenge_txn_pubkey,
        watchtower_challenge_txn_scripts,
        watchtower_challenge_txn_prev_outs,
        watchtower_challenge_txn_prev_indices,
        operator_header_chain,
        operator_commit_chain,
        spv,
        l2_contract_address,
        base_slot,
    );

    zkm_zkvm::io::commit(&operator_total_work);
    zkm_zkvm::io::commit(&latest_sequencer_commit_txid);
}

