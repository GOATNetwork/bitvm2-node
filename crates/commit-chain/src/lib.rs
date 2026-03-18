mod publisher;
pub use publisher::*;
mod commit_chain;
pub use commit_chain::*;
use zkm_verifier::{Groth16Verifier, get_snark_vk_meta};

fn decode_zkm_version(version: &[u8; ZKM_VERSION_SIZE]) -> Result<String, String> {
    let end = version.iter().position(|b| *b == 0).unwrap_or(version.len());
    if end == 0 {
        return Err("zkm_version is empty".to_string());
    }
    String::from_utf8(version[..end].to_vec()).map_err(|e| format!("invalid zkm_version: {e}"))
}

pub fn commit_chain_circuit(input: CommitChainCircuitInput) -> CommitChainCircuitOutput {
    let mut chain_state = match input.prev_proof {
        CommitChainPrevProofType::GenesisBlock => {
            CommitChainState::new(input.commits[0].genesis_txid)
        }
        CommitChainPrevProofType::PrevProof(prev_proof) => {
            println!("verify commit chain of prev proof");
            let groth16_vk = *zkm_verifier::GROTH16_VK_BYTES;
            let zkm_vk_hash = String::from_utf8(input.zkm_vk_hash.to_vec()).unwrap();
            let zkm_version = decode_zkm_version(&input.zkm_version).unwrap();
            let snark_vk_meta = get_snark_vk_meta(&zkm_version).unwrap();
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
