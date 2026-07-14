mod publisher;
pub use publisher::*;
mod commit_chain;
pub use commit_chain::*;

pub fn commit_chain_circuit(input: CommitChainCircuitInput) -> CommitChainCircuitOutput {
    let mut chain_state = match input.prev_proof {
        CommitChainPrevProofType::GenesisBlock => {
            CommitChainState::new(input.commits[0].genesis_txid)
        }
        CommitChainPrevProofType::PrevProof => {
            println!("verify commit chain of prev proof");
            verifier::verify_groth16_proof(
                &input.zkm_proof,
                &input.zkm_public_values,
                &input.zkm_vk_hash,
                &input.zkm_version,
            )
            .unwrap();

            decode_commit_chain_circuit_output(&input.zkm_public_values).chain_state
        }
    };

    chain_state.apply_commit(input.commits);
    CommitChainCircuitOutput { chain_state }
}
