mod cbft;
mod state_chain;

pub use cbft::*;
pub use state_chain::*;

pub fn state_chain_circuit(input: StateChainCircuitInput) -> StateChainCircuitOutput {
    let mut chain_state = match input.prev_proof {
        StateChainPrevProofType::GenesisBlock => {
            let block_hash: [u8; 32] = input.blocks[0].evm_block.current_block.hash_slow().into();
            let block_height = input.blocks[0].evm_block.current_block.header.number;
            println!("state chain genesis: {}, number: {}", hex::encode(block_hash), block_height);
            let cosmos_block = input.blocks[0].cosmos_block.clone();
            StateChainState::new(block_height, block_hash, cosmos_block)
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
