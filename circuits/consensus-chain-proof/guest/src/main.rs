#![no_std]
#![no_main]
zkm_zkvm::entrypoint!(main);
use consensus_chain::{ConsensusChainCircuitInput, consensus_chain_circuit};

pub fn main() {
    let input: ConsensusChainCircuitInput = zkm_zkvm::io::read();
    let output = consensus_chain_circuit(input);
    zkm_zkvm::io::commit(&output);
}
