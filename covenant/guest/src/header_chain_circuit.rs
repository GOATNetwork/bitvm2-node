use header_chain::{
    BlockHeaderCircuitOutput, ChainState, HeaderChainCircuitInput, HeaderChainPrevProofType,
};

/// Watchtower Proof: the main entry point of the header chain circuit.
pub fn header_chain_circuit(input: HeaderChainCircuitInput) -> BlockHeaderCircuitOutput {
    // println!("Detected network: {:?}", NETWORK_TYPE);
    // println!("NETWORK_CONSTANTS: {:?}", NETWORK_CONSTANTS);
    let mut chain_state = match input.prev_proof {
        HeaderChainPrevProofType::GenesisBlock => ChainState::new(),
        HeaderChainPrevProofType::PrevProof(prev_proof) => {
            assert_eq!(prev_proof.method_id, input.method_id);
            // TODO:
            // guest.verify(input.method_id, &prev_proof);
            prev_proof.chain_state
        }
    };

    chain_state.apply_blocks(input.block_headers);

    BlockHeaderCircuitOutput {
        method_id: input.method_id,
        chain_state,
    }
}