use crate::client::btc_chain::bitcoin_adaptor::BitcoinAdaptor;
use bitcoin::block::Header;
use bitcoin::{Address as BtcAddress, Block, Network, Transaction, Txid};
use esplora_client::{AsyncClient, Builder, MerkleProof, Utxo};

const TEST_URL: &str = "https://mempool.space/testnet/api";
const MAIN_URL: &str = "https://mempool.space/api";

pub fn get_esplora_url(network: Network) -> &'static str {
    match network {
        Network::Bitcoin => MAIN_URL,
        _ => TEST_URL,
    }
}

pub struct EsploraBitcoinAdaptor {
    esplora: AsyncClient,
    network: Network,
}

impl EsploraBitcoinAdaptor {
    pub fn new(network: Network, esplora_url: Option<&str>) -> Self {
        EsploraBitcoinAdaptor {
            esplora: Builder::new(esplora_url.unwrap_or(get_esplora_url(network)))
                .build_async()
                .expect("Could not build esplora client"),
            network,
        }
    }
}

#[async_trait::async_trait]
impl BitcoinAdaptor for EsploraBitcoinAdaptor {
    fn network(&self) -> Network {
        self.network
    }

    async fn get_tx_status(&self, txid: &Txid) -> anyhow::Result<esplora_client::TxStatus> {
        Ok(self.esplora.get_tx_status(txid).await?)
    }

    async fn get_tx(&self, txid: &Txid) -> anyhow::Result<Option<Transaction>> {
        Ok(self.esplora.get_tx(txid).await?)
    }

    async fn get_address_utxo(&self, address: BtcAddress) -> anyhow::Result<Vec<Utxo>> {
        Ok(self.esplora.get_address_utxo(address).await?)
    }

    async fn get_height(&self) -> anyhow::Result<u32> {
        Ok(self.esplora.get_height().await?)
    }

    async fn get_fee_estimates(&self) -> anyhow::Result<std::collections::HashMap<u16, f64>> {
        Ok(self.esplora.get_fee_estimates().await?)
    }

    async fn broadcast(&self, tx: &Transaction) -> anyhow::Result<()> {
        Ok(self.esplora.broadcast(tx).await?)
    }

    async fn get_output_status(
        &self,
        txid: &Txid,
        vout: u64,
    ) -> anyhow::Result<Option<esplora_client::OutputStatus>> {
        Ok(self.esplora.get_output_status(txid, vout).await?)
    }

    async fn get_block_hash(&self, block_height: u32) -> anyhow::Result<bitcoin::BlockHash> {
        Ok(self.esplora.get_block_hash(block_height).await?)
    }

    async fn get_block_by_hash(
        &self,
        block_hash: &bitcoin::BlockHash,
    ) -> anyhow::Result<Option<Block>> {
        Ok(self.esplora.get_block_by_hash(block_hash).await?)
    }

    async fn get_merkle_proof(&self, tx_id: &Txid) -> anyhow::Result<Option<MerkleProof>> {
        Ok(self.esplora.get_merkle_proof(tx_id).await?)
    }

    async fn get_header_by_hash(&self, block_hash: &bitcoin::BlockHash) -> anyhow::Result<Header> {
        Ok(self.esplora.get_header_by_hash(block_hash).await?)
    }
}
