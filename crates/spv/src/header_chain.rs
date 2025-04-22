use bitcoin::{
    block::{Header, Version},
    hashes::Hash,
    BlockHash, CompactTarget, TxMerkleNode,
};
use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
/// Bitcoin block header.
#[derive(Serialize, Deserialize, Eq, PartialEq, Clone, Debug, BorshDeserialize, BorshSerialize)]
pub struct CircuitBlockHeader {
    pub version: i32,
    pub prev_block_hash: [u8; 32],
    pub merkle_root: [u8; 32],
    pub time: u32,
    pub bits: u32,
    pub nonce: u32,
}

impl CircuitBlockHeader {
    pub fn compute_block_hash(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(&self.version.to_le_bytes());
        hasher.update(&self.prev_block_hash);
        hasher.update(&self.merkle_root);
        hasher.update(&self.time.to_le_bytes());
        hasher.update(&self.bits.to_le_bytes());
        hasher.update(&self.nonce.to_le_bytes());
        let first_hash_result = hasher.finalize_reset();

        hasher.update(first_hash_result);
        let result: [u8; 32] =
            hasher.finalize().try_into().expect("SHA256 should produce a 32-byte output");
        result
    }
}

impl From<Header> for CircuitBlockHeader {
    fn from(header: Header) -> Self {
        CircuitBlockHeader {
            version: header.version.to_consensus(),
            prev_block_hash: header.prev_blockhash.to_byte_array(),
            merkle_root: header.merkle_root.as_raw_hash().to_byte_array(),
            time: header.time,
            bits: header.bits.to_consensus(),
            nonce: header.nonce,
        }
    }
}

impl Into<Header> for CircuitBlockHeader {
    fn into(self) -> Header {
        Header {
            version: Version::from_consensus(self.version),
            prev_blockhash: BlockHash::from_slice(&self.prev_block_hash)
                .expect("Previous block hash is 32 bytes"),
            merkle_root: TxMerkleNode::from_slice(&self.merkle_root)
                .expect("Merkle root is 32 bytes"),
            time: self.time,
            bits: CompactTarget::from_consensus(self.bits),
            nonce: self.nonce,
        }
    }
}
