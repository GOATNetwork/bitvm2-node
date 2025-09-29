use crate::btc_chain::bitcoin_adaptor::{BitcoinNetwork, get_btc_chain_adapter};
use crate::btc_chain::bitcoin_chain::BitcoinChain;
use crate::btc_chain::mock_bitcoin_adaptor::MockBitcoinAdaptor;
use bitcoin::{Address as BtcAddress, Block, BlockHash, Network, Transaction, Txid};
use esplora_client::{MerkleProof, OutputStatus, Tx, TxStatus, Utxo};
use std::collections::HashMap;
use std::str::FromStr;

#[async_trait::async_trait]
pub trait BTCClientTrait: Send + Sync {
    fn network(&self) -> Network;
    async fn get_tx_status(&self, txid: &Txid) -> anyhow::Result<TxStatus>;
    async fn get_tx(&self, txid: &Txid) -> anyhow::Result<Option<Transaction>>;
    async fn get_tx_info(&self, tx_id: &Txid) -> anyhow::Result<Option<Tx>>;
    async fn get_address_utxo(&self, address: BtcAddress) -> anyhow::Result<Vec<Utxo>>;
    async fn get_height(&self) -> anyhow::Result<u32>;
    async fn get_fee_estimates(&self) -> anyhow::Result<HashMap<u16, f64>>;
    async fn get_output_status(
        &self,
        txid: &Txid,
        vout: u64,
    ) -> anyhow::Result<Option<OutputStatus>>;
    async fn get_block_hash(&self, block_height: u32) -> anyhow::Result<BlockHash>;
    async fn get_block_by_hash(&self, block_hash: &BlockHash) -> anyhow::Result<Option<Block>>;
    async fn get_block_by_height(&self, block_height: u32) -> anyhow::Result<Block>;
    async fn get_merkle_proof(&self, tx_id: &Txid) -> anyhow::Result<Option<MerkleProof>>;
    async fn get_merkle_proof_extend(&self, tx_id: &Txid) -> anyhow::Result<MerkleProofExtend>;
    async fn broadcast(&self, tx: &Transaction) -> anyhow::Result<()>;
}

pub mod bitcoin_adaptor;
pub mod bitcoin_chain;
mod esplora_bitcoin_adaptor;
mod mock_bitcoin_adaptor;

#[derive(Debug)]
pub struct BTCClient {
    chain_service: BitcoinChain,
}

pub struct MockBTCClient {
    mock_adaptor: MockBitcoinAdaptor,
    chain_service: BitcoinChain,
}

pub struct MerkleProofExtend {
    pub txid: [u8; 32],
    pub height: u64,
    pub block_hash: [u8; 32],
    pub raw_header: Vec<u8>,
    pub root: [u8; 32],
    pub index: u64,
    pub merkle: Vec<[u8; 32]>,
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
}

#[async_trait::async_trait]
impl BTCClientTrait for BTCClient {
    fn network(&self) -> Network {
        self.chain_service.network()
    }

    async fn get_tx_status(&self, txid: &Txid) -> anyhow::Result<TxStatus> {
        self.chain_service.get_tx_status(txid).await
    }

    async fn get_tx(&self, txid: &Txid) -> anyhow::Result<Option<Transaction>> {
        self.chain_service.get_tx(txid).await
    }

    async fn get_tx_info(&self, tx_id: &Txid) -> anyhow::Result<Option<Tx>> {
        self.chain_service.get_tx_info(tx_id).await
    }

    async fn get_address_utxo(&self, address: BtcAddress) -> anyhow::Result<Vec<Utxo>> {
        self.chain_service.get_address_utxo(address).await
    }

    async fn get_height(&self) -> anyhow::Result<u32> {
        self.chain_service.get_height().await
    }

    async fn get_fee_estimates(&self) -> anyhow::Result<HashMap<u16, f64>> {
        self.chain_service.get_fee_estimates().await
    }

    async fn get_output_status(
        &self,
        txid: &Txid,
        vout: u64,
    ) -> anyhow::Result<Option<OutputStatus>> {
        self.chain_service.get_output_status(txid, vout).await
    }

    async fn get_block_hash(&self, block_height: u32) -> anyhow::Result<BlockHash> {
        self.chain_service.get_block_hash(block_height).await
    }

    async fn get_block_by_hash(&self, block_hash: &BlockHash) -> anyhow::Result<Option<Block>> {
        self.chain_service.get_block_by_hash(block_hash).await
    }

    async fn get_block_by_height(&self, block_height: u32) -> anyhow::Result<Block> {
        self.chain_service.get_block_by_height(block_height).await
    }

    async fn get_merkle_proof(&self, tx_id: &Txid) -> anyhow::Result<Option<MerkleProof>> {
        self.chain_service.get_merkle_proof(tx_id).await
    }

    async fn get_merkle_proof_extend(&self, tx_id: &Txid) -> anyhow::Result<MerkleProofExtend> {
        self.chain_service.get_merkle_proof_extend(tx_id).await
    }

    async fn broadcast(&self, tx: &Transaction) -> anyhow::Result<()> {
        self.chain_service.broadcast(tx).await
    }
}

impl MockBTCClient {
    pub fn new() -> Self {
        let mock_adaptor = MockBitcoinAdaptor::new(Network::Testnet);
        let chain_service = BitcoinChain::new(Box::new(mock_adaptor.clone()));
        Self { mock_adaptor, chain_service }
    }

    pub fn network(&self) -> Network {
        self.chain_service.network()
    }

    pub fn set_height(&self, height: u32) {
        self.mock_adaptor.set_height(height);
    }

    pub fn set_block_hash(&self, height: u32, block_hash: BlockHash) {
        self.mock_adaptor.set_block_hash(height, block_hash);
    }

    pub fn set_tx(&self, txid: Txid, tx: Tx) {
        self.mock_adaptor.set_tx(txid, tx);
    }

    pub fn set_block(&self, block_hash: BlockHash, block: Block) {
        self.mock_adaptor.set_block(block_hash, block);
    }

    pub fn set_fee_estimates(&self, estimates: HashMap<u16, f64>) {
        self.mock_adaptor.set_fee_estimates(estimates);
    }

    pub fn set_fee_estimate(&self, target: u16, fee_rate: f64) {
        self.mock_adaptor.set_fee_estimate(target, fee_rate);
    }

    pub fn set_address_utxos(&self, address: BtcAddress, utxos: Vec<Utxo>) {
        self.mock_adaptor.set_address_utxos(address, utxos);
    }

    pub fn add_address_utxo(&self, address: BtcAddress, utxo: Utxo) {
        self.mock_adaptor.add_address_utxo(address, utxo);
    }

    pub fn set_output_status(&self, txid: Txid, vout: u64, status: OutputStatus) {
        self.mock_adaptor.set_output_status(txid, vout, status);
    }

    pub fn set_merkle_proof(&self, txid: Txid, proof: MerkleProof) {
        self.mock_adaptor.set_merkle_proof(txid, proof);
    }

    pub fn as_btc_client(&self) -> &dyn BTCClientTrait {
        self
    }
}

#[async_trait::async_trait]
impl BTCClientTrait for MockBTCClient {
    fn network(&self) -> Network {
        self.chain_service.network()
    }

    async fn get_tx_status(&self, txid: &Txid) -> anyhow::Result<TxStatus> {
        self.chain_service.get_tx_status(txid).await
    }

    async fn get_tx(&self, txid: &Txid) -> anyhow::Result<Option<Transaction>> {
        self.chain_service.get_tx(txid).await
    }

    async fn get_tx_info(&self, tx_id: &Txid) -> anyhow::Result<Option<Tx>> {
        self.chain_service.get_tx_info(tx_id).await
    }

    async fn get_address_utxo(&self, address: BtcAddress) -> anyhow::Result<Vec<Utxo>> {
        self.chain_service.get_address_utxo(address).await
    }

    async fn get_height(&self) -> anyhow::Result<u32> {
        self.chain_service.get_height().await
    }

    async fn get_fee_estimates(&self) -> anyhow::Result<HashMap<u16, f64>> {
        self.chain_service.get_fee_estimates().await
    }

    async fn get_output_status(
        &self,
        txid: &Txid,
        vout: u64,
    ) -> anyhow::Result<Option<OutputStatus>> {
        self.chain_service.get_output_status(txid, vout).await
    }

    async fn get_block_hash(&self, block_height: u32) -> anyhow::Result<BlockHash> {
        self.chain_service.get_block_hash(block_height).await
    }

    async fn get_block_by_hash(&self, block_hash: &BlockHash) -> anyhow::Result<Option<Block>> {
        self.chain_service.get_block_by_hash(block_hash).await
    }

    async fn get_block_by_height(&self, block_height: u32) -> anyhow::Result<Block> {
        self.chain_service.get_block_by_height(block_height).await
    }

    async fn get_merkle_proof(&self, tx_id: &Txid) -> anyhow::Result<Option<MerkleProof>> {
        self.chain_service.get_merkle_proof(tx_id).await
    }

    async fn get_merkle_proof_extend(&self, tx_id: &Txid) -> anyhow::Result<MerkleProofExtend> {
        self.chain_service.get_merkle_proof_extend(tx_id).await
    }

    async fn broadcast(&self, tx: &Transaction) -> anyhow::Result<()> {
        self.chain_service.broadcast(tx).await
    }
}

#[cfg(test)]
mod tests {
    use crate::btc_chain::{BTCClientTrait, MockBTCClient};

    #[tokio::test(flavor = "multi_thread")]
    async fn test_mack_btc_client() -> anyhow::Result<()> {
        let mock_client = MockBTCClient::new();
        let height_in = 1234_u32;
        mock_client.set_height(height_in);
        let height_out = mock_client.get_height().await?;
        assert_eq!(height_out, height_in);

        Ok(())
    }
}
