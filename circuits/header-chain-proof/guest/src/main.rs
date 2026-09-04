#![no_main]
zkm_zkvm::entrypoint!(main);

use header_chain::{header_chain_circuit, HeaderChainCircuitInput};

use borsh::{BorshDeserialize, BorshSerialize};

pub fn main() {
    let input: HeaderChainCircuitInput = zkm_zkvm::io::read();
    let output = header_chain_circuit(input);
    zkm_zkvm::io::commit(&output);
}
