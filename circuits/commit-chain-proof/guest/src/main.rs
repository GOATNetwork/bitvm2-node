#![no_main]
zkm_zkvm::entrypoint!(main);
use commit_chain::commit_chain_circuit;

pub fn main() {
    let input = zkm_zkvm::io::read();
    let output = commit_chain_circuit(input);
    zkm_zkvm::io::commit(&output);
}
