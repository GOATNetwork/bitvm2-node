use crate::btc_chain::bitcoin_adaptor::{BitcoinNetwork, get_btc_chain_adapter};
use crate::btc_chain::bitcoin_chain::BitcoinChain;
use bitcoin::{Address as BtcAddress, Block, Network, Transaction, TxMerkleNode, Txid};
use esplora_client::{MerkleProof, Utxo};
use std::str::FromStr;

pub mod bitcoin_adaptor;
pub mod bitcoin_chain;
mod esplora_bitcoin_adaptor;
mod mock_bitcoin_adaptor;

#[derive(Debug)]
pub struct BTCClient {
    chain_service: BitcoinChain,
}

impl BTCClient {
    pub fn new(network: BitcoinNetwork, esplora_url: Option<&str>) -> Self {
        BTCClient { chain_service: BitcoinChain::new(get_btc_chain_adapter(network, esplora_url)) }
    }

    pub fn from_str(network: &str, esplora_url: Option<&str>) -> Self {
        BTCClient {
            chain_service: BitcoinChain::new(get_btc_chain_adapter(
                BitcoinNetwork::from_str(network).unwrap_or_default(),
                esplora_url,
            )),
        }
    }

    pub fn network(&self) -> Network {
        self.chain_service.network()
    }

    /// Get transaction status
    pub async fn get_tx_status(&self, txid: &Txid) -> anyhow::Result<esplora_client::TxStatus> {
        self.chain_service.get_tx_status(txid).await
    }

    /// Get transaction
    pub async fn get_tx(&self, txid: &Txid) -> anyhow::Result<Option<Transaction>> {
        self.chain_service.get_tx(txid).await
    }

    /// Get address UTXOs
    pub async fn get_address_utxo(&self, address: BtcAddress) -> anyhow::Result<Vec<Utxo>> {
        self.chain_service.get_address_utxo(address).await
    }

    /// Get block height
    pub async fn get_height(&self) -> anyhow::Result<u32> {
        self.chain_service.get_height().await
    }

    /// Get fee estimates
    pub async fn get_fee_estimates(&self) -> anyhow::Result<std::collections::HashMap<u16, f64>> {
        self.chain_service.get_fee_estimates().await
    }

    /// Broadcast transaction
    pub async fn broadcast(&self, tx: &Transaction) -> anyhow::Result<()> {
        self.chain_service.broadcast(tx).await
    }

    /// Get output status
    pub async fn get_output_status(
        &self,
        txid: &Txid,
        vout: u64,
    ) -> anyhow::Result<Option<esplora_client::OutputStatus>> {
        self.chain_service.get_output_status(txid, vout).await
    }

    /// Get transaction hex string by serialize txid
    pub async fn get_tx_hex_by_tx_id(&self, tx_id: &Txid) -> anyhow::Result<String> {
        self.chain_service.get_tx_hex_by_tx_id(tx_id).await
    }

    pub async fn fetch_btc_block(&self, block_height: u32) -> anyhow::Result<Block> {
        self.chain_service.fetch_btc_block(block_height).await
    }

    pub async fn fetch_btc_address_utxos(&self, address: BtcAddress) -> anyhow::Result<Vec<Utxo>> {
        self.chain_service.fetch_btc_address_utxos(address).await
    }

    pub async fn get_btc_merkle_proof(
        &self,
        tx_id: &Txid,
    ) -> anyhow::Result<(TxMerkleNode, MerkleProof, Vec<u8>)> {
        self.chain_service.get_btc_merkle_proof(tx_id).await
    }

    pub async fn fetch_btc_tx(
        &self,
        tx_id: &Txid,
    ) -> Result<Transaction, Box<dyn std::error::Error>> {
        self.chain_service.fetch_btc_tx(tx_id).await
    }

    pub async fn get_btc_tx_proof_info(
        &self,
        tx_id: &Txid,
    ) -> anyhow::Result<([u8; 32], Vec<[u8; 32]>, [u8; 32], u64, u64, Vec<u8>)> {
        self.chain_service.get_btc_tx_proof_info(tx_id).await
    }
}
