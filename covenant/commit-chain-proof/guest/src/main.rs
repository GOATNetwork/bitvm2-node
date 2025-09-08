#![no_std]
#![no_main]
zkm_zkvm::entrypoint!(main);
use bitcoin_light_client::*;

pub fn main() {
    let input: CommitChainCircuitInput = zkm_zkvm::io::read();
    let output = commit_chain_circuit(input);
    zkm_zkvm::io::commit(&output);
}
