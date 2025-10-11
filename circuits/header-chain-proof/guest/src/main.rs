#![no_main]
zkm_zkvm::entrypoint!(main);

use header_chain::{
    verify_merkle_proof, BlockHeaderCircuitOutput, BlockInclusionProof, ChainState,
    CircuitTransaction, HeaderChainCircuitInput, HeaderChainPrevProofType,
    header_chain_circuit,
};

use borsh::{BorshDeserialize, BorshSerialize};


pub fn main() {
    let input: HeaderChainCircuitInput = zkm_zkvm::io::read();
    let output = header_chain_circuit(input);
    zkm_zkvm::io::commit(&output);
}
