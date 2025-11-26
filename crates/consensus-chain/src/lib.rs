mod consensus_chain;
mod cbft;

pub use consensus_chain::*;
pub use cbft::*;

pub fn consensus_chain_circuit(input: ConsensusChainCircuitInput) -> ConsensusChainCircuitOutput {
    let mut chain_state = match input.prev_proof {
        ConsensusChainPrevProofType::GenesisBlock => ConsensusChainState::new(),
        ConsensusChainPrevProofType::PrevProof(prev_proof) => {
            println!("verify commit chain of prev proof");
            assert_eq!(prev_proof.vk_hash, input.vk_hash);
            zkm_zkvm::lib::verify::verify_zkm_proof(&input.vk_hash, &input.pv_hash);
            prev_proof.chain_state
        }
    };

    chain_state.apply_block(input.blocks);
    ConsensusChainCircuitOutput { vk_hash: input.vk_hash, chain_state }
}
