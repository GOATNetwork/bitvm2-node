mod cbft;
mod state_chain;

pub use cbft::*;
pub use state_chain::*;
use zkm_verifier::Groth16Verifier;

pub fn state_chain_circuit(input: StateChainCircuitInput) -> StateChainCircuitOutput {
    let mut chain_state = match input.prev_proof {
        StateChainPrevProofType::GenesisBlock => {
            let block_hash: [u8; 32] = input.blocks[0].evm_block.current_block.hash_slow().into();
            let block_height = input.blocks[0].evm_block.current_block.header.number;
            let cosmos_block = input.blocks[0].cosmos_block.clone();
            StateChainState::new(block_height, block_hash, cosmos_block)
        }
        StateChainPrevProofType::PrevProof(prev_proof) => {
            println!("verify state chain of prev proof");
            let groth16_vk = *zkm_verifier::GROTH16_VK_BYTES;
            let zkm_vk_hash = String::from_utf8(input.zkm_vk_hash.to_vec()).unwrap();
            Groth16Verifier::verify(
                &input.zkm_proof,
                &input.zkm_public_values,
                &zkm_vk_hash,
                groth16_vk,
            )
            .unwrap();
            prev_proof.chain_state
        }
    };

    chain_state.apply_blocks(input.blocks);
    StateChainCircuitOutput { chain_state }
}
