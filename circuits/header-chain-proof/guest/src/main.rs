#![no_main]
zkm_zkvm::entrypoint!(main);

use header_chain::{
    verify_merkle_proof, BlockHeaderCircuitOutput, BlockInclusionProof, ChainState,
    CircuitTransaction, HeaderChainCircuitInput, HeaderChainPrevProofType,
};

use borsh::{BorshDeserialize, BorshSerialize};

use bitcoin_light_client::header_chain_circuit;

pub fn main() {
    let input: HeaderChainCircuitInput = zkm_zkvm::io::read();
    let output = header_chain_circuit(input);
    zkm_zkvm::io::commit(&output);
}
