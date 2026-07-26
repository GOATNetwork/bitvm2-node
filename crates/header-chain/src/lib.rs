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
    let self_program_id = input.self_program_id;
    let (mut chain_state, program_history_hash) = match input.prev_proof {
        HeaderChainPrevProofType::GenesisBlock => {
            (ChainState::new(), verifier::initial_history(verifier::ProgramType::Header))
        }
        HeaderChainPrevProofType::PrevProof => {
            println!("verify header chain of prev proof");
            let previous_program_id = verifier::verify_groth16_proof(
                &input.zkm_proof,
                &input.zkm_public_values,
                &input.zkm_vk_hash,
                &input.zkm_version,
            )
            .unwrap();

            let output = decode_header_chain_circuit_output(&input.zkm_public_values);
            assert_eq!(output.self_program_id, previous_program_id);
            let history = verifier::next_history(
                verifier::ProgramType::Header,
                output.program_history_hash,
                previous_program_id,
                self_program_id,
            );
            (output.chain_state, history)
        }
    };

    chain_state.apply_blocks(input.block_headers);
    BlockHeaderCircuitOutput { chain_state, self_program_id, program_history_hash }
}

#[cfg(test)]
mod circuit_output_tests {
    use super::*;
    use serde::Serialize;

    #[derive(Serialize)]
    struct LegacyOutput {
        chain_state: ChainState,
    }

    #[test]
    fn classifies_only_strict_current_outputs() {
        let legacy = bincode::serialize(&LegacyOutput { chain_state: ChainState::new() }).unwrap();
        assert!(classify_header_chain_output(&legacy).is_err());

        let mut current = bincode::serialize(&BlockHeaderCircuitOutput {
            chain_state: ChainState::new(),
            self_program_id: [1u8; 32],
            program_history_hash: [2u8; 32],
        })
        .unwrap();
        assert_eq!(
            classify_header_chain_output(&current).unwrap(),
            HeaderChainPrevProofType::PrevProof
        );
        current.push(0);
        assert!(classify_header_chain_output(&current).is_err());
        assert!(classify_header_chain_output(b"unknown").is_err());
    }
}
