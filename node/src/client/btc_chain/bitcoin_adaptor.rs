use crate::client::btc_chain::esplora_bitcoin_adaptor::EsploraBitcoinAdaptor;
use crate::client::btc_chain::mock_bitcoin_adaptor::MockBitcoinAdaptor;
use bitcoin::{Address as BtcAddress, Block, Network, Transaction, Txid, block::Header};
use esplora_client::{MerkleProof, Utxo};

#[derive(Eq, PartialEq, Clone, Copy)]
pub enum BitcoinNetwork {
    Bitcoin,
    Testnet,
    Testnet4,
    Signet,
    Regtest,
    Local,
}

impl BitcoinNetwork {
    pub fn to_network(&self) -> Network {
        match self {
            BitcoinNetwork::Bitcoin => Network::Bitcoin,
            BitcoinNetwork::Testnet => Network::Testnet,
            BitcoinNetwork::Testnet4 => Network::Testnet4,
            BitcoinNetwork::Signet => Network::Signet,
            BitcoinNetwork::Regtest => Network::Regtest,
            BitcoinNetwork::Local => Network::Testnet, // Local map to Testnet
        }
    }
}

impl From<Network> for BitcoinNetwork {
    fn from(network: Network) -> Self {
        match network {
            Network::Bitcoin => BitcoinNetwork::Bitcoin,
            Network::Testnet => BitcoinNetwork::Testnet,
            Network::Testnet4 => BitcoinNetwork::Testnet4,
            Network::Signet => BitcoinNetwork::Signet,
            Network::Regtest => BitcoinNetwork::Regtest,
        }
    }
}

#[async_trait::async_trait]
pub trait BitcoinAdaptor: Send + Sync {
    fn network(&self) -> Network;
    async fn get_tx_status(&self, txid: &Txid) -> anyhow::Result<esplora_client::TxStatus>;
    async fn get_tx(&self, txid: &Txid) -> anyhow::Result<Option<Transaction>>;
    async fn get_address_utxo(&self, address: BtcAddress) -> anyhow::Result<Vec<Utxo>>;
    async fn get_height(&self) -> anyhow::Result<u32>;
    async fn get_fee_estimates(&self) -> anyhow::Result<std::collections::HashMap<u16, f64>>;
    async fn broadcast(&self, tx: &Transaction) -> anyhow::Result<()>;
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
    network: BitcoinNetwork,
    esplora_url: Option<&str>,
) -> Box<dyn BitcoinAdaptor> {
    match network {
        BitcoinNetwork::Local => Box::new(MockBitcoinAdaptor::new(network.to_network())),
        _ => Box::new(EsploraBitcoinAdaptor::new(network.to_network(), esplora_url)),
    }
}
