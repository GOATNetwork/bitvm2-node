mod publisher;
pub use publisher::*;
mod commit_chain;
pub use commit_chain::*;
use zkm_verifier::{Groth16Verifier, IMM_GROTH16_VK_BYTES};

pub const TRUSTED_COMMIT_CHAIN_ZKM_VERSION: &str = "v1.2.5";

/// Return the fixed `part_stark_vk` used by commit-chain's internal recursive verifier.
pub fn trusted_commit_chain_part_stark_vk() -> Vec<u8> {
    Groth16Verifier::get_part_stark_vk(TRUSTED_COMMIT_CHAIN_ZKM_VERSION).to_vec()
}

pub fn commit_chain_circuit(input: CommitChainCircuitInput) -> CommitChainCircuitOutput {
    let current_part_stark_vk = trusted_commit_chain_part_stark_vk();
    let mut chain_state = match input.prev_proof {
        CommitChainPrevProofType::GenesisBlock => {
            CommitChainState::new(input.commits[0].genesis_txid)
        }
        CommitChainPrevProofType::PrevProof(prev_proof) => {
            println!("verify commit chain of prev proof");
            let groth16_vk = *IMM_GROTH16_VK_BYTES;
            let zkm_vk_hash = String::from_utf8(input.zkm_vk_hash.to_vec()).unwrap();
            assert_eq!(input.zkm_version, TRUSTED_COMMIT_CHAIN_ZKM_VERSION);
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

    chain_state.apply_commit(input.commits);
    CommitChainCircuitOutput { chain_state }
}
