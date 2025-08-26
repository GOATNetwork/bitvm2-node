use crate::client::btc_chain::esplora::get_esplora_url;
use anyhow::bail;
use bitcoin::consensus::serialize;
use bitcoin::hashes::Hash;
use bitcoin::{Address as BtcAddress, Block, Network, Transaction, TxMerkleNode, Txid};
use esplora_client::{AsyncClient, Builder, MerkleProof, Utxo};

pub mod esplora;

#[derive(Debug, Clone)]
pub struct BTCClient {
    esplora: AsyncClient,
    network: Network,
}

impl BTCClient {
    pub fn new(esplora_url: Option<&str>, network: Network) -> Self {
        BTCClient {
            esplora: Builder::new(esplora_url.unwrap_or(get_esplora_url(network)))
                .build_async()
                .expect("Could not build esplora client"),
            network,
        }
    }

    pub fn network(&self) -> Network {
        self.network
    }

    /// Get transaction status
    pub async fn get_tx_status(&self, txid: &Txid) -> anyhow::Result<esplora_client::TxStatus> {
        Ok(self.esplora.get_tx_status(txid).await?)
    }

    /// Get transaction
    pub async fn get_tx(&self, txid: &Txid) -> anyhow::Result<Option<Transaction>> {
        Ok(self.esplora.get_tx(txid).await?)
    }

    /// Get address UTXOs
    pub async fn get_address_utxo(&self, address: BtcAddress) -> anyhow::Result<Vec<Utxo>> {
        Ok(self.esplora.get_address_utxo(address).await?)
    }

    /// Get block height
    pub async fn get_height(&self) -> anyhow::Result<u32> {
        Ok(self.esplora.get_height().await?)
    }

    /// Get fee estimates
    pub async fn get_fee_estimates(&self) -> anyhow::Result<std::collections::HashMap<u16, f64>> {
        Ok(self.esplora.get_fee_estimates().await?)
    }

    /// Broadcast transaction
    pub async fn broadcast(&self, tx: &Transaction) -> anyhow::Result<()> {
        Ok(self.esplora.broadcast(tx).await?)
    }

    /// Get output status
    pub async fn get_output_status(
        &self,
        txid: &Txid,
        vout: u64,
    ) -> anyhow::Result<Option<esplora_client::OutputStatus>> {
        Ok(self.esplora.get_output_status(txid, vout).await?)
    }

    /// Get transaction hex string by serialize txid
    pub async fn get_tx_hex_by_serialize_tx_id(&self, tx_id_hex: &str) -> anyhow::Result<String> {
        let tx_id: Txid = bitcoin::consensus::encode::deserialize_hex(tx_id_hex)?;
        if let Some(tx) = self.esplora.get_tx(&tx_id).await? {
            return Ok(bitcoin::consensus::encode::serialize_hex(&tx));
        }
        bail!("not found tx:{} on chain", tx_id.to_string());
    }

    pub async fn fetch_btc_block(&self, block_height: u32) -> anyhow::Result<Block> {
        let block_hash = self.esplora.get_block_hash(block_height).await?;
        self.esplora.get_block_by_hash(&block_hash).await?.ok_or(anyhow::format_err!(
            "failed to fetch block at :{} hash:{}",
            block_height,
            block_hash.to_string()
        ))
    }

    pub async fn fetch_btc_address_utxos(&self, address: BtcAddress) -> anyhow::Result<Vec<Utxo>> {
        Ok(self.esplora.get_address_utxo(address).await?)
    }

    pub async fn get_bitc_merkle_proof(
        &self,
        tx_id: &Txid,
    ) -> anyhow::Result<(TxMerkleNode, MerkleProof, Vec<u8>)> {
        let proof = self.esplora.get_merkle_proof(tx_id).await?;
        if let Some(proof) = proof {
            let block_hash = self.esplora.get_block_hash(proof.block_height).await?;
            let header = self.esplora.get_header_by_hash(&block_hash).await?;
            let raw_header = serialize(&header);
            return Ok((header.merkle_root, proof, raw_header));
        }
        bail!("get {} merkle proof is none", tx_id)
    }

    pub async fn fetch_btc_tx(
        &self,
        tx_id: &Txid,
    ) -> Result<Transaction, Box<dyn std::error::Error>> {
        self.esplora.get_tx(tx_id).await?.ok_or(format!("{tx_id} is not on chain").into())
    }

    pub async fn get_btc_tx_proof_info(
        &self,
        tx_id: &Txid,
    ) -> anyhow::Result<([u8; 32], Vec<[u8; 32]>, [u8; 32], u64, u64, Vec<u8>)> {
        let (root, proof_info, raw_header) = self.get_bitc_merkle_proof(tx_id).await?;
        let proof: Vec<[u8; 32]> = proof_info.merkle.iter().map(|v| v.to_byte_array()).collect();
        let leaf = tx_id.to_byte_array();
        Ok((
            root.to_byte_array(),
            proof,
            leaf,
            proof_info.block_height as u64,
            proof_info.pos as u64,
            raw_header,
        ))
    }
}
