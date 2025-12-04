mod publisher;
pub use publisher::*;
mod commit_chain;
pub use commit_chain::*;

pub fn commit_chain_circuit(input: CommitChainCircuitInput) -> CommitChainCircuitOutput {
    let mut chain_state = match input.prev_proof {
        CommitChainPrevProofType::GenesisBlock => {
            CommitChainState::new(input.commits[0].genesis_txid, build_dummy_tx())
        }
        CommitChainPrevProofType::PrevProof(prev_proof) => {
            println!("verify commit chain of prev proof");
            assert_eq!(prev_proof.vk_hash, input.vk_hash);
            zkm_zkvm::lib::verify::verify_zkm_proof(&input.vk_hash, &input.pv_hash);
            prev_proof.chain_state
        }
    };

    chain_state.apply_commit(input.commits);
    CommitChainCircuitOutput { vk_hash: input.vk_hash, chain_state }
}
