//! Modified from https://github.com/BitVM/BitVM/tree/main/header-chain
mod header_chain;
pub use header_chain::*;
pub mod merkle_tree;
pub mod mmr;
pub mod transaction;
pub mod utils;

pub use merkle_tree::*;
pub use mmr::*;
pub use transaction::*;

pub mod spv;
pub use spv::SPV;
use zkm_verifier::{Groth16Verifier, IMM_GROTH16_VK_BYTES};

/// The main entry point of the header chain circuit.
pub fn header_chain_circuit(input: HeaderChainCircuitInput) -> BlockHeaderCircuitOutput {
    let current_part_stark_vk = Groth16Verifier::get_part_stark_vk(&input.zkm_version).to_vec();
    // println!("Detected network: {:?}", NETWORK_TYPE);
    // println!("NETWORK_CONSTANTS: {:?}", NETWORK_CONSTANTS);
    let mut chain_state = match input.prev_proof {
        HeaderChainPrevProofType::GenesisBlock => ChainState::new(),
        HeaderChainPrevProofType::PrevProof(prev_proof) => {
            println!("verify header chain of prev proof");
            let groth16_vk = *IMM_GROTH16_VK_BYTES;
            let zkm_vk_hash = String::from_utf8(input.zkm_vk_hash.to_vec()).unwrap();
            Groth16Verifier::verify_by_imm_groth16_vk(
                &input.zkm_proof,
                &input.zkm_public_values,
                &zkm_vk_hash,
                groth16_vk,
                &current_part_stark_vk,
            )
            .unwrap();

            prev_proof.chain_state
        }
    };

    chain_state.apply_blocks(input.block_headers);
    BlockHeaderCircuitOutput { chain_state, part_stark_vk: current_part_stark_vk }
}
