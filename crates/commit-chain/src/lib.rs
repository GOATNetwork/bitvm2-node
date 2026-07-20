mod publisher;
pub use publisher::*;
mod commit_chain;
pub use commit_chain::*;

pub fn commit_chain_circuit(input: CommitChainCircuitInput) -> CommitChainCircuitOutput {
    let self_program_id = input.self_program_id;
    let (mut chain_state, program_history_hash) = match input.prev_proof {
        CommitChainPrevProofType::GenesisBlock => (
            CommitChainState::new(input.commits[0].genesis_txid),
            verifier::initial_history(verifier::ProgramType::Commit),
        ),
        CommitChainPrevProofType::PrevProof => {
            println!("verify commit chain of prev proof");
            let previous_program_id = verifier::verify_groth16_proof(
                &input.zkm_proof,
                &input.zkm_public_values,
                &input.zkm_vk_hash,
                &input.zkm_version,
            )
            .unwrap();

            let output: CommitChainCircuitOutput =
                bincode::deserialize(&input.zkm_public_values).unwrap();
            assert_eq!(output.self_program_id, previous_program_id);
            let history = verifier::next_history(
                verifier::ProgramType::Commit,
                output.program_history_hash,
                previous_program_id,
                self_program_id,
            );
            (output.chain_state, history)
        }
        CommitChainPrevProofType::LegacyPrevProof => {
            let previous_program_id = verifier::verify_groth16_proof(
                &input.zkm_proof,
                &input.zkm_public_values,
                &input.zkm_vk_hash,
                &input.zkm_version,
            )
            .unwrap();
            let chain_state =
                decode_pre_identity_commit_chain_output(&input.zkm_public_values).unwrap();
            let history = verifier::legacy_history(
                verifier::ProgramType::Commit,
                previous_program_id,
                &input.zkm_public_values,
            );
            (chain_state, history)
        }
    };

    chain_state.apply_commit(input.commits);
    CommitChainCircuitOutput { chain_state, self_program_id, program_history_hash }
}

#[cfg(test)]
mod circuit_output_tests {
    use super::*;
    use serde::Serialize;

    #[derive(Serialize)]
    struct LegacyOutput {
        chain_state: CommitChainState,
    }

    fn chain_state() -> CommitChainState {
        CommitChainState::new([1u8; 32])
    }

    #[test]
    fn classifies_only_current_and_immediate_legacy_outputs() {
        let legacy = bincode::serialize(&LegacyOutput { chain_state: chain_state() }).unwrap();
        assert_eq!(
            classify_commit_chain_output(&legacy).unwrap(),
            CommitChainPrevProofType::LegacyPrevProof
        );

        let current = bincode::serialize(&CommitChainCircuitOutput {
            chain_state: chain_state(),
            self_program_id: [1u8; 32],
            program_history_hash: [2u8; 32],
        })
        .unwrap();
        assert_eq!(
            classify_commit_chain_output(&current).unwrap(),
            CommitChainPrevProofType::PrevProof
        );
        assert!(classify_commit_chain_output(b"unknown").is_err());
    }
}
