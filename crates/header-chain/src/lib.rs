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

use zkm_primitives::io::ZKMPublicValues;

pub mod spv;
pub use spv::SPV;

/// The main entry point of the header chain circuit.
pub fn header_chain_circuit(input: HeaderChainCircuitInput) -> BlockHeaderCircuitOutput {
    // println!("Detected network: {:?}", NETWORK_TYPE);
    // println!("NETWORK_CONSTANTS: {:?}", NETWORK_CONSTANTS);
    let mut chain_state = match input.prev_proof {
        HeaderChainPrevProofType::GenesisBlock => ChainState::new(),
        HeaderChainPrevProofType::PrevProof => {
            println!("verify header chain of prev proof");
            verifier::verify_groth16_proof(
                &input.zkm_proof,
                &input.zkm_public_values,
                &input.zkm_vk_hash,
                &input.zkm_version,
            )
            .unwrap();

            let btc_header_chain_output: BlockHeaderCircuitOutput =
                ZKMPublicValues::from(&input.zkm_public_values).read();
            btc_header_chain_output.chain_state
        }
    };

    chain_state.apply_blocks(input.block_headers);
    BlockHeaderCircuitOutput { chain_state }
}
