mod publisher;
pub use publisher::*;
mod commit_chain;
pub use commit_chain::*;
use zkm_verifier::{Groth16Verifier, get_snark_vk_meta};

pub fn commit_chain_circuit(input: CommitChainCircuitInput) -> CommitChainCircuitOutput {
    let mut chain_state = match input.prev_proof {
        CommitChainPrevProofType::GenesisBlock => {
            CommitChainState::new(input.commits[0].genesis_txid)
        }
        CommitChainPrevProofType::PrevProof(prev_proof) => {
            println!("verify commit chain of prev proof");
            let groth16_vk = *zkm_verifier::GROTH16_VK_BYTES;
            let zkm_vk_hash = String::from_utf8(input.zkm_vk_hash.to_vec()).unwrap();
            let snark_vk_meta = get_snark_vk_meta(&input.zkm_version).unwrap();
            Groth16Verifier::verify(
                &input.zkm_proof,
                &input.zkm_public_values,
                &zkm_vk_hash,
                &snark_vk_meta,
                groth16_vk,
            )
            .unwrap();
            prev_proof.chain_state
        }
    };

    chain_state.apply_commit(input.commits);
    CommitChainCircuitOutput { chain_state }
}
