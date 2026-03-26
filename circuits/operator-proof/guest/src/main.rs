#![no_main]
zkm_zkvm::entrypoint!(main);
use std::str::FromStr;
use header_chain::{
    HeaderChainCircuitInput, SPV, 
};
use alloy_primitives::{U256, Address};
use bitcoin_light_client_circuit::{EthClientExecutorInput, OperatorAttestationInputs};
use commit_chain::CommitChainCircuitInput;
use state_chain::StateChainCircuitInput;
use bitcoin::{ScriptBuf, TxOut, Transaction};

pub fn main() {
    // calculate operator public input:  https://github.com/ProjectZKM/Ziren/blob/main/crates/sdk/src/utils.rs#L42
    let included_watchertowers: U256 = zkm_zkvm::io::read::<U256>();
    let graph_id: [u8; 16] = zkm_zkvm::io::read::<[u8; 16]>();
    let operator_genesis_sequencer_commit_txid: [u8; 32] = zkm_zkvm::io::read(); 
    println!("read operator commit txn");
    let operator_latest_sequencer_commit_txn: Transaction = zkm_zkvm::io::read(); // private inputs
    let latest_sequencer_commit_txid = operator_latest_sequencer_commit_txn.compute_txid(); // public input
    // https://github.com/KSlashh/BitVM/blob/v2/goat/src/transactions/watchtower_challenge.rs#L128
    let watchtower_challenge_txns: Vec<Transaction> = zkm_zkvm::io::read();
    let watchtower_challenge_txn_pubkey: Vec<bitcoin::secp256k1::PublicKey> = zkm_zkvm::io::read();
    let watchtower_challenge_txn_scripts: Vec<ScriptBuf> = zkm_zkvm::io::read();
    let watchtower_challenge_txn_prev_outs: Vec<TxOut> = zkm_zkvm::io::read();

    let operator_header_chain: HeaderChainCircuitInput = zkm_zkvm::io::read();
    let operator_commit_chain: CommitChainCircuitInput = zkm_zkvm::io::read();
    let operator_state_chain: StateChainCircuitInput = zkm_zkvm::io::read();
    let attestation: OperatorAttestationInputs = zkm_zkvm::io::read();
    let spv_ss_commit: SPV = zkm_zkvm::io::read();
    let operator_committed_blockhash: [u8; 32] = zkm_zkvm::io::read();

    let output = bitcoin_light_client_circuit::propose_longest_chain(
        included_watchertowers,
        graph_id,
        operator_genesis_sequencer_commit_txid,
        watchtower_challenge_txns,
        watchtower_challenge_txn_pubkey,
        watchtower_challenge_txn_scripts,
        watchtower_challenge_txn_prev_outs,
        operator_header_chain,
        operator_commit_chain,
        operator_state_chain,
        attestation,
        spv_ss_commit,
        operator_committed_blockhash,
    );

    zkm_zkvm::io::commit(&output);
}
