#![no_std]
#![no_main]
zkm_zkvm::entrypoint!(main);

use header_chain::{
    HeaderChainCircuitInput, 
    SPV,
};
use commit_chain::CommitChainCircuitInput;

pub fn main() {
    let genesis_sequencer_commit_txid = zkm_zkvm::io::read::<[u8; 32]>();
    let latest_sequencer_commit_txid = zkm_zkvm::io::read::<[u8; 32]>();
    let header_chain: HeaderChainCircuitInput = zkm_zkvm::io::read(); // private inputs
    let commit_chain: CommitChainCircuitInput = zkm_zkvm::io::read();
    let spv: SPV = zkm_zkvm::io::read();

    let (total_work, latest_sequencer_commit_txid) = bitcoin_light_client_circuit::generate_watchtower_proof(
        genesis_sequencer_commit_txid,
        latest_sequencer_commit_txid,
        header_chain,
        commit_chain,
        spv
    );
    zkm_zkvm::io::commit(&total_work);
    zkm_zkvm::io::commit(&latest_sequencer_commit_txid);
}
