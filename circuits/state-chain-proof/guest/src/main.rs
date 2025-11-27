#![no_std]
#![no_main]
zkm_zkvm::entrypoint!(main);
use state_chain::{StateChainCircuitInput, state_chain_circuit};

pub fn main() {
    let input: StateChainCircuitInput = zkm_zkvm::io::read();
    let output = state_chain_circuit(input);
    zkm_zkvm::io::commit(&output);
}
