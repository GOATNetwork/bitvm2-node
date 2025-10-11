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

/// The main entry point of the header chain circuit.
pub fn header_chain_circuit(input: HeaderChainCircuitInput) -> BlockHeaderCircuitOutput {
    // println!("Detected network: {:?}", NETWORK_TYPE);
    // println!("NETWORK_CONSTANTS: {:?}", NETWORK_CONSTANTS);
    let mut chain_state = match input.prev_proof {
        HeaderChainPrevProofType::GenesisBlock => ChainState::new(),
        HeaderChainPrevProofType::PrevProof(prev_proof) => {
            println!("verify header chain of prev proof");
            assert_eq!(prev_proof.vk_hash, input.vk_hash);
            zkm_zkvm::lib::verify::verify_zkm_proof(&input.vk_hash, &input.pv_hash);
            prev_proof.chain_state
        }
    };

    chain_state.apply_blocks(input.block_headers);
    BlockHeaderCircuitOutput { vk_hash: input.vk_hash, chain_state }
}
