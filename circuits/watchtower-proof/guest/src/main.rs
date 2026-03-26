#![no_std]
#![no_main]
zkm_zkvm::entrypoint!(main);

use header_chain::{
    HeaderChainCircuitInput, 
    SPV,
};
use bitcoin_light_client_circuit::WatchtowerAttestationInputs;
use commit_chain::CommitChainCircuitInput;
use state_chain::StateChainCircuitInput;

pub fn main() {
    let genesis_sequencer_commit_txid = zkm_zkvm::io::read::<[u8; 32]>();
    let latest_sequencer_commit_txid = zkm_zkvm::io::read::<[u8; 32]>();
    let header_chain: HeaderChainCircuitInput = zkm_zkvm::io::read(); // private inputs
    let commit_chain: CommitChainCircuitInput = zkm_zkvm::io::read();
    let state_chain: StateChainCircuitInput = zkm_zkvm::io::read();
    let attestation: WatchtowerAttestationInputs = zkm_zkvm::io::read();
    let spv: SPV = zkm_zkvm::io::read();

    let output = bitcoin_light_client_circuit::watch_longest_chain(
        genesis_sequencer_commit_txid,
        latest_sequencer_commit_txid,
        header_chain,
        commit_chain,
        state_chain,
        attestation,
        spv
    );
    zkm_zkvm::io::commit(&output);
}
