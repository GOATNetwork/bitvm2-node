#![no_std]
#![no_main]
zkm_zkvm::entrypoint!(main);

use header_chain::{
    BlockInclusionProof,
    HeaderChainCircuitInput, 
};
use bitcoin_light_client::CommitChainCircuitInput;

pub fn main() {
    let latest_sequencer_commit_txid = zkm_zkvm::io::read::<[u8; 32]>();
    let header_chain: HeaderChainCircuitInput = zkm_zkvm::io::read(); // private inputs
    let commit_chain: CommitChainCircuitInput = zkm_zkvm::io::read();
    let latest_sequencer_commit_txid_inclusion_proof: BlockInclusionProof =
        zkm_zkvm::io::read::<BlockInclusionProof>();

    let (total_work, latest_sequencer_commit_txid) = bitcoin_light_client::generate_watchtower_proof(
        latest_sequencer_commit_txid,
        header_chain,
        commit_chain,
        latest_sequencer_commit_txid_inclusion_proof,
    );
    zkm_zkvm::io::commit(&total_work);
    zkm_zkvm::io::commit(&latest_sequencer_commit_txid);
}
