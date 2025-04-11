use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

mod header_chain;
pub use header_chain::*;
mod merkle_tree;
mod transaction;
mod utils;
mod fetcher;

use crate::utils::hash_pair;
pub use merkle_tree::*;
pub use transaction::*;

#[derive(Serialize, Deserialize, Eq, PartialEq, Clone, Debug, BorshDeserialize, BorshSerialize)]
pub struct MMRInclusionProof {
    pub subroot_idx: usize,
    pub internal_idx: u32,
    pub inclusion_proof: Vec<[u8; 32]>,
}

impl MMRInclusionProof {
    pub fn new(subroot_idx: usize, internal_idx: u32, inclusion_proof: Vec<[u8; 32]>) -> Self {
        MMRInclusionProof { subroot_idx, internal_idx, inclusion_proof }
    }

    pub fn get_subroot(&self, leaf: [u8; 32]) -> [u8; 32] {
        let mut current_hash = leaf;
        for i in 0..self.inclusion_proof.len() {
            let sibling = self.inclusion_proof[i];
            if self.internal_idx & (1 << i) == 0 {
                current_hash = hash_pair(current_hash, sibling);
            } else {
                current_hash = hash_pair(sibling, current_hash);
            }
        }
        current_hash
    }
}

/// Represents the MMR for inside zkVM (guest)
#[derive(Serialize, Deserialize, Eq, PartialEq, Clone, Debug, BorshDeserialize, BorshSerialize)]

pub struct MMRGuest {
    pub subroots: Vec<[u8; 32]>,
    pub size: u32,
}

impl MMRGuest {
    /// Creates a new MMR for inside zkVM
    pub fn new() -> Self {
        MMRGuest { subroots: vec![], size: 0 }
    }

    pub fn append(&mut self, leaf: [u8; 32]) {
        let mut current = leaf;
        let mut size = self.size;
        while size % 2 == 1 {
            let sibling = self.subroots.pop().unwrap();
            current = hash_pair(sibling, current);
            size /= 2
        }
        self.subroots.push(current);
        self.size += 1;
    }

    /// Verifies an inclusion proof against the current MMR root
    pub fn verify_proof(&self, leaf: [u8; 32], mmr_proof: &MMRInclusionProof) -> bool {
        println!("GUEST: mmr_proof: {:?}", mmr_proof);
        println!("GUEST: leaf: {:?}", leaf);
        let mut current_hash = leaf;
        for i in 0..mmr_proof.inclusion_proof.len() {
            let sibling = mmr_proof.inclusion_proof[i];
            if mmr_proof.internal_idx & (1 << i) == 0 {
                current_hash = hash_pair(current_hash, sibling);
            } else {
                current_hash = hash_pair(sibling, current_hash);
            }
        }
        println!("GUEST: calculated subroot: {:?}", current_hash);
        println!("GUEST: subroots: {:?}", self.subroots);
        self.subroots[mmr_proof.subroot_idx] == current_hash
    }
}

#[derive(Eq, PartialEq, Clone, Debug, BorshDeserialize, BorshSerialize)]
pub struct SPV {
    pub transaction: CircuitTransaction,
    pub block_inclusion_proof: BlockInclusionProof,
    pub block_header: CircuitBlockHeader,
    pub mmr_inclusion_proof: MMRInclusionProof,
}

impl SPV {
    pub fn new(
        transaction: CircuitTransaction,
        block_inclusion_proof: BlockInclusionProof,
        block_header: CircuitBlockHeader,
        mmr_inclusion_proof: MMRInclusionProof,
    ) -> Self {
        SPV { transaction, block_inclusion_proof, block_header, mmr_inclusion_proof }
    }

    pub fn verify(&self, mmr_guest: MMRGuest) -> bool {
        let txid: [u8; 32] = self.transaction.txid();
        println!("txid: {:?}", txid);
        let block_merkle_root = self.block_inclusion_proof.get_root(txid);
        println!("block_merkle_root: {:?}", block_merkle_root);
        assert_eq!(block_merkle_root, self.block_header.merkle_root);
        let block_hash = self.block_header.compute_block_hash();
        mmr_guest.verify_proof(block_hash, &self.mmr_inclusion_proof)
    }
}

#[cfg(test)]
mod tests {
    use borsh::BorshDeserialize;
    use hex_literal::hex;

    #[test]
    fn test_spv() {}
}
