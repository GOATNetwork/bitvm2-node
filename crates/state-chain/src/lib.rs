mod cbft;
mod state_chain;

pub use cbft::*;
pub use state_chain::*;

pub fn state_chain_circuit(input: StateChainCircuitInput) -> StateChainCircuitOutput {
    let mut chain_state = match input.prev_proof {
        StateChainPrevProofType::GenesisBlock => {
            let block_hash: [u8; 32] =
                input.blocks[0].evm_input.current_block.parent_hash.try_into().unwrap();
            println!("state chain genesis: {}", hex::encode(block_hash));
            StateChainState::new(block_hash)
        }
        StateChainPrevProofType::PrevProof(prev_proof) => {
            println!("verify state chain of prev proof");
            assert_eq!(prev_proof.vk_hash, input.vk_hash);
            zkm_zkvm::lib::verify::verify_zkm_proof(&input.vk_hash, &input.pv_hash);
            prev_proof.chain_state
        }
    };

    chain_state.apply_block(input.blocks);
    StateChainCircuitOutput { vk_hash: input.vk_hash, chain_state }
}
