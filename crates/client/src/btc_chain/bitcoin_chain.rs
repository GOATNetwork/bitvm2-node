use crate::btc_chain::BtcTxProofData;
use crate::btc_chain::bitcoin_adaptor::BitcoinAdaptor;
use anyhow::bail;
use bitcoin::consensus::serialize;
use bitcoin::hashes::Hash;
use bitcoin::{Address as BtcAddress, Block, BlockHash, Network, Transaction, TxMerkleNode, Txid};
use esplora_client::{MerkleProof, Tx, Utxo};

pub struct BitcoinChain {
    adaptor: Box<dyn BitcoinAdaptor + Send + Sync>,
}

impl std::fmt::Debug for BitcoinChain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BitcoinChain").finish()
    }
}

impl BitcoinChain {
    pub fn new(adaptor: Box<dyn BitcoinAdaptor + Send + Sync>) -> Self {
        Self { adaptor }
    }

    pub fn network(&self) -> Network {
        self.adaptor.network()
    }

    /// Get transaction status
    pub async fn get_tx_status(&self, txid: &Txid) -> anyhow::Result<esplora_client::TxStatus> {
        self.adaptor.get_tx_status(txid).await
    }

    /// Get transaction
    pub async fn get_tx(&self, txid: &Txid) -> anyhow::Result<Option<Transaction>> {
        self.adaptor.get_tx(txid).await
    }

    pub async fn get_tx_info(&self, tx_id: &Txid) -> anyhow::Result<Option<Tx>> {
        self.adaptor.get_tx_info(tx_id).await
    }

    /// Get address UTXOs
    pub async fn get_address_utxo(&self, address: BtcAddress) -> anyhow::Result<Vec<Utxo>> {
        self.adaptor.get_address_utxo(address).await
    }

    /// Get block height
    pub async fn get_height(&self) -> anyhow::Result<u32> {
        self.adaptor.get_height().await
    }

    /// Get fee estimates
    pub async fn get_fee_estimates(&self) -> anyhow::Result<std::collections::HashMap<u16, f64>> {
        self.adaptor.get_fee_estimates().await
    }

    /// Broadcast transaction
    pub async fn broadcast(&self, tx: &Transaction) -> anyhow::Result<()> {
        self.adaptor.broadcast(tx).await
    }

    /// Get output status
    pub async fn get_output_status(
        &self,
        txid: &Txid,
        vout: u64,
    ) -> anyhow::Result<Option<esplora_client::OutputStatus>> {
        self.adaptor.get_output_status(txid, vout).await
    }

    /// Get transaction hex string by serialize txid
    pub async fn get_tx_hex_by_tx_id(&self, tx_id: &Txid) -> anyhow::Result<String> {
        if let Some(tx) = self.adaptor.get_tx(&tx_id).await? {
            return Ok(bitcoin::consensus::encode::serialize_hex(&tx));
        }
        bail!("not found tx:{} on chain", tx_id.to_string());
    }

    pub async fn get_btc_block(&self, block_height: u32) -> anyhow::Result<Block> {
        let block_hash = self.adaptor.get_block_hash(block_height).await?;
        self.adaptor.get_block_by_hash(&block_hash).await?.ok_or(anyhow::format_err!(
            "failed to fetch block at :{} hash:{}",
            block_height,
            block_hash.to_string()
        ))
    }

    pub async fn get_btc_address_utxos(&self, address: BtcAddress) -> anyhow::Result<Vec<Utxo>> {
        self.adaptor.get_address_utxo(address).await
    }

    pub async fn get_btc_merkle_proof(
        &self,
        tx_id: &Txid,
    ) -> anyhow::Result<(BlockHash, TxMerkleNode, MerkleProof, Vec<u8>)> {
        let proof = self.adaptor.get_merkle_proof(tx_id).await?;
        if let Some(proof) = proof {
            let block_hash = self.adaptor.get_block_hash(proof.block_height).await?;
            let header = self.adaptor.get_header_by_hash(&block_hash).await?;
            let raw_header = serialize(&header);
            return Ok((block_hash, header.merkle_root, proof, raw_header));
        }
        bail!("get {} merkle proof is none", tx_id)
    }

    pub async fn get_btc_tx_proof_info(&self, tx_id: &Txid) -> anyhow::Result<BtcTxProofData> {
        let (block_hash, root, proof_info, raw_header) = self.get_btc_merkle_proof(tx_id).await?;
        let proof: Vec<[u8; 32]> = proof_info.merkle.iter().map(|v| v.to_byte_array()).collect();
        Ok(BtcTxProofData {
            txid: tx_id.to_byte_array(),
            height: proof_info.block_height as u64,
            block_hash: block_hash.to_byte_array(),
            raw_header,
            root: root.to_byte_array(),
            index: proof_info.pos as u64,
            proof,
        })
    }
}
