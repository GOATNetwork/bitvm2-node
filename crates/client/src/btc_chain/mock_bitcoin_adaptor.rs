use crate::btc_chain::bitcoin_adaptor::BitcoinAdaptor;
use bitcoin::block::Header;
use bitcoin::{Address as BtcAddress, Block, BlockHash, Network, Transaction, Txid};
use esplora_client::{MerkleProof, OutputStatus, Tx, TxStatus, Utxo};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

#[derive(Clone)]

pub struct MockBitcoinAdaptor {
    network: Network,
    height: Arc<Mutex<u32>>,
    block_hashes: Arc<Mutex<HashMap<u32, BlockHash>>>,
    tx_map: Arc<Mutex<HashMap<Txid, Tx>>>,
    blocks: Arc<Mutex<HashMap<BlockHash, Block>>>,
    fee_estimates: Arc<Mutex<HashMap<u16, f64>>>,
    address_utxos: Arc<Mutex<HashMap<BtcAddress, Vec<Utxo>>>>,
    output_statuses: Arc<Mutex<HashMap<(Txid, u64), OutputStatus>>>,
    merkle_proofs: Arc<Mutex<HashMap<Txid, MerkleProof>>>,
}
impl MockBitcoinAdaptor {
    pub fn new(network: Network) -> Self {
        Self {
            network,
            height: Arc::new(Mutex::new(0)),
            block_hashes: Arc::new(Mutex::new(HashMap::new())),
            tx_map: Arc::new(Mutex::new(HashMap::new())),
            blocks: Arc::new(Mutex::new(HashMap::new())),
            fee_estimates: Arc::new(Mutex::new(HashMap::new())),
            address_utxos: Arc::new(Mutex::new(HashMap::new())),
            output_statuses: Arc::new(Mutex::new(HashMap::new())),
            merkle_proofs: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn set_height(&self, height: u32) {
        if let Ok(mut h) = self.height.lock() {
            *h = height;
        }
    }

    pub fn set_block_hash(&self, height: u32, block_hash: BlockHash) {
        if let Ok(mut hashes) = self.block_hashes.lock() {
            hashes.insert(height, block_hash);
        }
    }

    pub fn get_block_hash_for_height(&self, height: u32) -> Option<BlockHash> {
        if let Ok(hashes) = self.block_hashes.lock() { hashes.get(&height).copied() } else { None }
    }

    pub fn set_tx(&self, txid: Txid, tx: Tx) {
        if let Ok(mut statuses) = self.tx_map.lock() {
            statuses.insert(txid, tx.clone());
        }
        if tx.status.confirmed
            && let Ok(mut status_map) = self.output_statuses.lock()
        {
            for (index, vin) in tx.vin.into_iter().enumerate() {
                status_map.insert(
                    (vin.txid, vin.vout as u64),
                    OutputStatus {
                        spent: true,
                        txid: Some(txid.clone()),
                        vin: Some(index as u64),
                        status: Some(tx.status.clone()),
                    },
                );
            }
        }
    }

    pub fn set_block(&self, block_hash: BlockHash, block: Block) {
        if let Ok(mut blocks) = self.blocks.lock() {
            blocks.insert(block_hash, block);
        }
    }

    pub fn set_fee_estimates(&self, estimates: HashMap<u16, f64>) {
        if let Ok(mut fees) = self.fee_estimates.lock() {
            *fees = estimates;
        }
    }

    pub fn set_fee_estimate(&self, target: u16, fee_rate: f64) {
        if let Ok(mut fees) = self.fee_estimates.lock() {
            fees.insert(target, fee_rate);
        }
    }

    pub fn set_address_utxos(&self, address: BtcAddress, utxos: Vec<Utxo>) {
        if let Ok(mut utxo_map) = self.address_utxos.lock() {
            utxo_map.insert(address, utxos);
        }
    }

    pub fn add_address_utxo(&self, address: BtcAddress, utxo: Utxo) {
        if let Ok(mut utxo_map) = self.address_utxos.lock() {
            utxo_map.entry(address).or_insert_with(Vec::new).push(utxo);
        }
    }

    pub fn set_output_status(&self, txid: Txid, vout: u64, status: OutputStatus) {
        if let Ok(mut status_map) = self.output_statuses.lock() {
            status_map.insert((txid, vout), status);
        }
    }

    pub fn set_merkle_proof(&self, txid: Txid, proof: MerkleProof) {
        if let Ok(mut proof_map) = self.merkle_proofs.lock() {
            proof_map.insert(txid, proof);
        }
    }
}

#[async_trait::async_trait]
impl BitcoinAdaptor for MockBitcoinAdaptor {
    fn network(&self) -> Network {
        self.network
    }

    async fn get_tx_status(&self, txid: &Txid) -> anyhow::Result<TxStatus> {
        match self.get_tx_info(txid).await? {
            Some(tx) => Ok(tx.status),
            None => anyhow::bail!("Transaction status not found for txid {}", txid),
        }
    }

    async fn get_tx(&self, txid: &Txid) -> anyhow::Result<Option<Transaction>> {
        Ok(self.get_tx_info(txid).await?.map(|v| v.to_tx()))
    }

    async fn get_tx_info(&self, txid: &Txid) -> anyhow::Result<Option<Tx>> {
        Ok(if let Ok(statuses) = self.tx_map.lock() { statuses.get(txid).cloned() } else { None })
    }

    async fn get_address_utxo(&self, address: BtcAddress) -> anyhow::Result<Vec<Utxo>> {
        Ok(if let Ok(utxo_map) = self.address_utxos.lock() {
            utxo_map.get(&address).cloned().unwrap_or_default()
        } else {
            Vec::new()
        })
    }

    async fn get_height(&self) -> anyhow::Result<u32> {
        match self.height.lock() {
            Ok(guard) => Ok(*guard),
            Err(_) => Ok(0),
        }
    }

    async fn get_fee_estimates(&self) -> anyhow::Result<HashMap<u16, f64>> {
        Ok(if let Ok(fees) = self.fee_estimates.lock() { fees.clone() } else { HashMap::new() })
    }

    async fn broadcast(&self, _tx: &Transaction) -> anyhow::Result<()> {
        Ok(())
    }

    async fn broadcast_package(&self, _txns: &[Transaction]) -> anyhow::Result<()> {
        Ok(())
    }

    async fn get_output_status(
        &self,
        txid: &Txid,
        vout: u64,
    ) -> anyhow::Result<Option<OutputStatus>> {
        Ok(if let Ok(status_map) = self.output_statuses.lock() {
            status_map.get(&(*txid, vout)).cloned()
        } else {
            None
        })
    }

    async fn get_block_hash(&self, block_height: u32) -> anyhow::Result<BlockHash> {
        match self.get_block_hash_for_height(block_height) {
            Some(hash) => Ok(hash),
            None => anyhow::bail!("Block hash not found for height {}", block_height),
        }
    }

    async fn get_block_by_hash(&self, block_hash: &BlockHash) -> anyhow::Result<Option<Block>> {
        Ok(if let Ok(blocks) = self.blocks.lock() { blocks.get(block_hash).cloned() } else { None })
    }

    async fn get_merkle_proof(&self, tx_id: &Txid) -> anyhow::Result<Option<MerkleProof>> {
        Ok(if let Ok(proof_map) = self.merkle_proofs.lock() {
            proof_map.get(tx_id).cloned()
        } else {
            None
        })
    }

    async fn get_header_by_hash(&self, block_hash: &BlockHash) -> anyhow::Result<Header> {
        match self.get_block_by_hash(block_hash).await? {
            Some(b) => Ok(b.header),
            None => anyhow::bail!("Block hash not found for height {}", block_hash),
        }
    }
}
