mod cbft;
mod state_chain;

pub use cbft::*;
pub use state_chain::*;

use zkm_primitives::io::ZKMPublicValues;

pub fn state_chain_circuit(input: StateChainCircuitInput) -> StateChainCircuitOutput {
    let mut chain_state = match input.prev_proof {
        StateChainPrevProofType::GenesisBlock => {
            let block_hash: [u8; 32] = input.blocks[0].evm_block.current_block.hash_slow().into();
            let block_height = input.blocks[0].evm_block.current_block.header.number;
            let cosmos_block = input.blocks[0].cosmos_block.clone();
            StateChainState::new(block_height, block_hash, cosmos_block)
        }
        StateChainPrevProofType::PrevProof => {
            println!("verify state chain of prev proof");
            verifier::verify_groth16_proof(
                &input.zkm_proof,
                &input.zkm_public_values,
                &input.zkm_vk_hash,
                &input.zkm_version,
            )
            .unwrap();

            let state_chain_output: StateChainCircuitOutput =
                ZKMPublicValues::from(&input.zkm_public_values).read();
            state_chain_output.chain_state
        }
    };

    chain_state.apply_blocks(input.blocks);
    StateChainCircuitOutput { chain_state }
}
