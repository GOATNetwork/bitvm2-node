use crate::btc_chain::esplora_bitcoin_adaptor::EsploraBitcoinAdaptor;
use bitcoin::{Address as BtcAddress, Block, Network, Transaction, Txid, block::Header};
use esplora_client::{MerkleProof, Tx, Utxo};

#[async_trait::async_trait]
pub trait BitcoinAdaptor: Send + Sync {
    fn network(&self) -> Network;
    async fn get_tx_status(&self, txid: &Txid) -> anyhow::Result<esplora_client::TxStatus>;
    async fn get_tx(&self, txid: &Txid) -> anyhow::Result<Option<Transaction>>;
    async fn get_tx_info(&self, txid: &Txid) -> anyhow::Result<Option<Tx>>;
    async fn get_address_utxo(&self, address: BtcAddress) -> anyhow::Result<Vec<Utxo>>;
    async fn get_height(&self) -> anyhow::Result<u32>;
    async fn get_fee_estimates(&self) -> anyhow::Result<std::collections::HashMap<u16, f64>>;
    async fn broadcast(&self, tx: &Transaction) -> anyhow::Result<()>;
    async fn broadcast_package(&self, txns: &[Transaction]) -> anyhow::Result<()>;
    async fn get_output_status(
        &self,
        txid: &Txid,
        vout: u64,
    ) -> anyhow::Result<Option<esplora_client::OutputStatus>>;
    async fn get_block_hash(&self, block_height: u32) -> anyhow::Result<bitcoin::BlockHash>;
    async fn get_block_by_hash(
        &self,
        block_hash: &bitcoin::BlockHash,
    ) -> anyhow::Result<Option<Block>>;
    async fn get_merkle_proof(&self, tx_id: &Txid) -> anyhow::Result<Option<MerkleProof>>;
    async fn get_header_by_hash(&self, block_hash: &bitcoin::BlockHash) -> anyhow::Result<Header>;
}

pub fn get_btc_chain_adapter(
    network: Network,
    esplora_url: Option<&str>,
) -> Box<dyn BitcoinAdaptor> {
    Box::new(EsploraBitcoinAdaptor::new(network, esplora_url))
}
