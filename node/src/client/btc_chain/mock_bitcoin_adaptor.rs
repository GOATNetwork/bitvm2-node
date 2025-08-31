use crate::client::btc_chain::bitcoin_adaptor::BitcoinAdaptor;
use bitcoin::block::Header;
use bitcoin::{Address as BtcAddress, Block, BlockHash, Network, Transaction, Txid};
use esplora_client::{MerkleProof, OutputStatus, TxStatus, Utxo};
use std::collections::HashMap;

pub struct MockBitcoinAdaptor {
    network: Network,
}
impl MockBitcoinAdaptor {
    pub fn new(network: Network) -> Self {
        Self { network }
    }
}

#[async_trait::async_trait]
impl BitcoinAdaptor for MockBitcoinAdaptor {
    fn network(&self) -> Network {
        self.network
    }

    async fn get_tx_status(&self, _txid: &Txid) -> anyhow::Result<TxStatus> {
        anyhow::bail!("get_tx_status() not implemented for mock_bitcoin_adaptor")
    }

    async fn get_tx(&self, _txid: &Txid) -> anyhow::Result<Option<Transaction>> {
        anyhow::bail!("get_tx() not implemented for mock_bitcoin_adaptor")
    }

    async fn get_address_utxo(&self, _address: BtcAddress) -> anyhow::Result<Vec<Utxo>> {
        anyhow::bail!("get_address_utxo() not implemented for mock_bitcoin_adaptor")
    }

    async fn get_height(&self) -> anyhow::Result<u32> {
        Ok(0)
    }

    async fn get_fee_estimates(&self) -> anyhow::Result<HashMap<u16, f64>> {
        Ok(HashMap::new())
    }

    async fn broadcast(&self, _tx: &Transaction) -> anyhow::Result<()> {
        Ok(())
    }

    async fn get_output_status(
        &self,
        _txid: &Txid,
        _vout: u64,
    ) -> anyhow::Result<Option<OutputStatus>> {
        anyhow::bail!("get_output_status() not implemented for mock_bitcoin_adaptor")
    }

    async fn get_block_hash(&self, _block_height: u32) -> anyhow::Result<BlockHash> {
        anyhow::bail!("get_block_hash() not implemented for mock_bitcoin_adaptor")
    }

    async fn get_block_by_hash(&self, _block_hash: &BlockHash) -> anyhow::Result<Option<Block>> {
        anyhow::bail!("get_block_hash() not implemented for mock_bitcoin_adaptor")
    }

    async fn get_merkle_proof(&self, _tx_id: &Txid) -> anyhow::Result<Option<MerkleProof>> {
        anyhow::bail!("get_merkle_proof() not implemented for mock_bitcoin_adaptor")
    }

    async fn get_header_by_hash(&self, _block_hash: &BlockHash) -> anyhow::Result<Header> {
        anyhow::bail!("get_header_by_hash() not implemented mock_bitcoin_adaptor")
    }
}
