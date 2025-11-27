mod cbft;
mod state_chain;

pub use cbft::*;
pub use state_chain::*;

pub fn state_chain_circuit(input: StateChainCircuitInput) -> StateChainCircuitOutput {
    let mut chain_state = match input.prev_proof {
        StateChainPrevProofType::GenesisBlock => StateChainState::new(),
        StateChainPrevProofType::PrevProof(prev_proof) => {
            println!("verify consensus chain of prev proof");
            assert_eq!(prev_proof.vk_hash, input.vk_hash);
            zkm_zkvm::lib::verify::verify_zkm_proof(&input.vk_hash, &input.pv_hash);
            prev_proof.chain_state
        }
    };

    chain_state.apply_block(input.blocks);
    StateChainCircuitOutput { vk_hash: input.vk_hash, chain_state }
}
