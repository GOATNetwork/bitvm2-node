use borsh::{BorshDeserialize, BorshSerialize};

mod header_chain;
pub use header_chain::*;
mod fetcher;
mod merkle_tree;
mod transaction;
mod utils;

pub use merkle_tree::*;
pub use transaction::*;

#[derive(Eq, PartialEq, Clone, Debug, BorshDeserialize, BorshSerialize)]
pub struct SPV {
    pub transaction: CircuitTransaction,
    pub block_inclusion_proof: BlockInclusionProof,
    pub block_header: CircuitBlockHeader,
}

impl SPV {
    pub fn new(
        transaction: CircuitTransaction,
        block_inclusion_proof: BlockInclusionProof,
        block_header: CircuitBlockHeader,
    ) -> Self {
        SPV { transaction, block_inclusion_proof, block_header }
    }

    pub fn verify(&self) -> bool {
        let txid: [u8; 32] = self.transaction.txid();
        println!("txid: {:?}", txid);
        let block_merkle_root = self.block_inclusion_proof.get_root(txid);
        println!("block_merkle_root: {:?}", block_merkle_root);
        assert_eq!(block_merkle_root, self.block_header.merkle_root);
        let block_hash = self.block_header.compute_block_hash();
        println!("block_hash: {:?}", hex::encode(block_hash));
        //mmr_guest.verify_proof(block_hash, &self.mmr_inclusion_proof)
        true
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_spv() {}
}
