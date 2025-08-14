use crate::client::goat_chain::chain_adaptor::*;
use crate::utils::generate_random_bytes;
use alloy::primitives::TxHash;
use alloy::rpc::types::TransactionReceipt;
use anyhow::bail;
use async_trait::async_trait;
use bitcoin::Transaction;
use bitcoin::absolute::LockTime;
use bitcoin::hashes::Hash;
use bitcoin::transaction::Version;
use serde::Serialize;
use serde::de::DeserializeOwned;
use std::collections::HashMap;
use tracing::info;
use uuid::Uuid;

const PEGIN_DATA_MAP: &str = "pegin_data_map";
const OPERATOR_DATA_MAP: &str = "operator_data_map";
const WITHDRAW_DATA_MAP: &str = "withdraw_data_map";

pub struct MockAdaptorConfig {
    pub base_path: std::path::PathBuf,
}

pub struct MockAdaptor {
    config: MockAdaptorConfig,
}

impl MockAdaptor {
    fn load_object(&self, file_name: &str, file_path: Option<&str>) -> std::io::Result<Vec<u8>> {
        let path = match file_path {
            Some(file_path) => self.config.base_path.join(file_path).join(file_name),
            None => self.config.base_path.join(file_name),
        };
        if !path.exists() {
            return Ok(vec![]);
        }
        std::fs::read(path)
    }

    fn save_object(
        &self,
        file_name: &str,
        data: Vec<u8>,
        file_path: Option<&str>,
    ) -> std::io::Result<()> {
        let path = match file_path {
            Some(file_path) => self.config.base_path.join(file_path).join(file_name),
            None => self.config.base_path.join(file_name),
        };
        if let Some(parent) = path.parent()
            && !parent.exists()
        {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(path, data)
    }

    fn save_hash_map<T: Serialize>(
        &self,
        file_name: &str,
        data: T,
        file_path: Option<&str>,
    ) -> anyhow::Result<()> {
        let content = serde_json::to_vec(&data)?;
        self.save_object(file_name, content, file_path)?;
        Ok(())
    }

    fn load_hash_map<T: DeserializeOwned>(
        &self,
        file_name: &str,
        file_path: Option<&str>,
    ) -> anyhow::Result<HashMap<String, T>> {
        let contents = self.load_object(file_name, file_path)?;
        if contents.is_empty() {
            return Ok(HashMap::default());
        }
        Ok(serde_json::from_slice(&contents)?)
    }
}

#[async_trait]
impl ChainAdaptor for MockAdaptor {
    async fn get_finalized_block_number(&self) -> anyhow::Result<i64> {
        Ok(1)
    }
    async fn get_latest_block_number(&self) -> anyhow::Result<i64> {
        Ok(1)
    }

    async fn get_tx_receipt(&self, _tx_hash: &str) -> anyhow::Result<Option<TransactionReceipt>> {
        info!("call is_tx_execute_success");
        Ok(None)
    }

    async fn pegin_tx_used(&self, _tx_id: &[u8; 32]) -> anyhow::Result<bool> {
        Ok(true)
    }

    async fn get_pegin_data(&self, instance_id: &[u8; 16]) -> anyhow::Result<PeginData> {
        info!("call get_pegin_data");
        let pegin_data_map = self.load_hash_map::<PeginData>(PEGIN_DATA_MAP, None)?;
        if let Some(pegin_data) = pegin_data_map.get(&hex::encode(instance_id)) {
            Ok(pegin_data.clone())
        } else {
            bail!("not find pegin data")
        }
    }

    async fn is_operator_withdraw(&self, graph_id: &[u8; 16]) -> anyhow::Result<bool> {
        info!("call get_withdraw_data");
        let withdraw_data_map = self.load_hash_map::<WithdrawData>(WITHDRAW_DATA_MAP, None)?;
        if let Some(withdraw_data) = withdraw_data_map.get(&hex::encode(graph_id)) {
            Ok(withdraw_data.status == WithdrawStatus::Processing)
        } else {
            bail!("not find withdraw data")
        }
    }

    async fn get_withdraw_data(&self, graph_id: &[u8; 16]) -> anyhow::Result<WithdrawData> {
        info!("call get_withdraw_data");
        let withdraw_data_map = self.load_hash_map::<WithdrawData>(WITHDRAW_DATA_MAP, None)?;
        if let Some(withdraw_data) = withdraw_data_map.get(&hex::encode(graph_id)) {
            Ok(withdraw_data.clone())
        } else {
            bail!("not find withdraw data")
        }
    }

    async fn get_graph_data(&self, graph_id: &[u8; 16]) -> anyhow::Result<GraphData> {
        info!("call get_operator_data");
        let operator_data_map = self.load_hash_map::<GraphData>(OPERATOR_DATA_MAP, None)?;
        if let Some(operator_data) = operator_data_map.get(&hex::encode(graph_id)) {
            Ok(operator_data.clone())
        } else {
            bail!("not find operator data")
        }
    }

    async fn get_response_window_blocks(&self) -> anyhow::Result<u64> {
        Ok(0)
    }

    async fn answer_pegin_request(
        &self,
        _instance_id: &[u8; 16],
        _pub_key: &[u8; 32],
    ) -> anyhow::Result<String> {
        Ok(TxHash::default().to_string())
    }

    async fn post_pegin_data(
        &self,
        instance_id: &[u8; 16],
        raw_pgin_tx: &BitcoinTx,
        _pegin_proof: &BitcoinTxProof,
    ) -> anyhow::Result<String> {
        info!("call post_pegin_data");
        let tx = Transaction {
            version: Version::non_standard(raw_pgin_tx.version as i32),
            lock_time: LockTime::from_consensus(raw_pgin_tx.lock_time),
            input: bitcoin::consensus::deserialize(raw_pgin_tx.input_vector.as_slice())?,
            output: bitcoin::consensus::deserialize(raw_pgin_tx.output_vector.as_slice())?,
        };
        let mut pegin_data_map = self.load_hash_map::<PeginData>(PEGIN_DATA_MAP, None)?;
        pegin_data_map.insert(
            hex::encode(instance_id),
            PeginData {
                status: PeginStatus::None,
                pegin_amount_sats: 0,
                fee_rate: 0,
                user_inputs: vec![],
                pegin_txid: tx.compute_txid().to_byte_array(),
                created_at: 0,
                committee_addresses: vec![],
                committee_pubkeys: vec![],
            },
        );

        self.save_hash_map(PEGIN_DATA_MAP, pegin_data_map, None)?;
        Ok(hex::encode(generate_random_bytes(32)))
    }

    async fn post_graph_data(
        &self,
        _instance_id: &[u8; 16],
        graph_id: &[u8; 16],
        operator_data: &GraphData,
        _committee_signs: &[u8],
    ) -> anyhow::Result<String> {
        info!("call post_operator_data");
        let mut operator_data_map = self.load_hash_map::<GraphData>(OPERATOR_DATA_MAP, None)?;
        operator_data_map.insert(hex::encode(graph_id), operator_data.clone());
        self.save_hash_map(OPERATOR_DATA_MAP, operator_data_map, None)?;
        Ok(hex::encode(generate_random_bytes(32)))
    }

    async fn get_btc_block_hash(&self, _height: u64) -> anyhow::Result<[u8; 32]> {
        info!("call get_btc_block_hash");
        Ok([0; 32])
    }

    async fn parse_btc_block_header(
        &self,
        _raw_header: &[u8],
    ) -> anyhow::Result<([u8; 32], [u8; 32])> {
        info!("call parse_btc_block_header");
        Ok(([0; 32], [0; 32]))
    }

    async fn get_initialized_ids(&self) -> anyhow::Result<Vec<(Uuid, Uuid)>> {
        info!("call get_initialized_ids");
        Ok(vec![])
    }

    async fn get_instanceids_by_pubkey(
        &self,
        _operator_pubkey: &[u8; 32],
    ) -> anyhow::Result<Vec<(Uuid, Uuid)>> {
        info!("call get_instanceids_by_pubkey");
        Ok(vec![])
    }

    async fn init_withdraw(
        &self,
        instance_id: &[u8; 16],
        graph_id: &[u8; 16],
    ) -> anyhow::Result<String> {
        info!("call init_withdraw");
        let mut withdraw_data_map = self.load_hash_map::<WithdrawData>(WITHDRAW_DATA_MAP, None)?;
        let mut withdraw_data = withdraw_data_map
            .get(&hex::encode(graph_id))
            .unwrap_or(&WithdrawData {
                pegin_txid: generate_random_bytes(32).try_into().expect("fail to cast"),
                operator_address: generate_random_bytes(20).try_into().expect("fail to cast"),
                status: WithdrawStatus::Initialized,
                instance_id: *instance_id,
                lock_amount: Default::default(),
                btc_block_height_withdraw: Default::default(),
            })
            .clone();
        withdraw_data.status = WithdrawStatus::Initialized;
        withdraw_data_map.insert(hex::encode(graph_id), withdraw_data);
        self.save_hash_map(WITHDRAW_DATA_MAP, withdraw_data_map, None)?;
        Ok(hex::encode(generate_random_bytes(32)))
    }

    async fn cancel_withdraw(&self, graph_id: &[u8; 16]) -> anyhow::Result<String> {
        let mut withdraw_data_map = self.load_hash_map::<WithdrawData>(WITHDRAW_DATA_MAP, None)?;
        if let Some(withdraw_data) = withdraw_data_map.get(&hex::encode(graph_id)) {
            info!("call cancel_withdraw");
            let mut withdraw_data = withdraw_data.clone();
            withdraw_data.status = WithdrawStatus::Canceled;
            withdraw_data_map.insert(hex::encode(graph_id), withdraw_data);
            self.save_hash_map(WITHDRAW_DATA_MAP, withdraw_data_map, None)?;
            Ok(hex::encode(generate_random_bytes(32)))
        } else {
            bail!("fail to get withdraw data");
        }
    }

    async fn process_withdraw(
        &self,
        graph_id: &[u8; 16],
        _raw_kickoff_tx: &BitcoinTx,
        _kickoff_proof: &BitcoinTxProof,
    ) -> anyhow::Result<String> {
        let mut withdraw_data_map = self.load_hash_map::<WithdrawData>(WITHDRAW_DATA_MAP, None)?;
        if let Some(withdraw_data) = withdraw_data_map.get(&hex::encode(graph_id)) {
            info!("call process_withdraw");
            let mut withdraw_data = withdraw_data.clone();
            withdraw_data.status = WithdrawStatus::Processing;
            withdraw_data_map.insert(hex::encode(graph_id), withdraw_data);
            self.save_hash_map(WITHDRAW_DATA_MAP, withdraw_data_map, None)?;
            Ok(hex::encode(generate_random_bytes(32)))
        } else {
            bail!("fail to get withdraw data");
        }
    }

    async fn finish_withdraw_happy_path(
        &self,
        graph_id: &[u8; 16],
        _raw_take1_tx: &BitcoinTx,
        _take1_proof: &BitcoinTxProof,
    ) -> anyhow::Result<String> {
        let mut withdraw_data_map = self.load_hash_map::<WithdrawData>(WITHDRAW_DATA_MAP, None)?;
        if let Some(withdraw_data) = withdraw_data_map.get(&hex::encode(graph_id)) {
            info!("call finish_withdraw_happy_path");
            let mut withdraw_data = withdraw_data.clone();
            withdraw_data.status = WithdrawStatus::Complete;
            withdraw_data_map.insert(hex::encode(graph_id), withdraw_data);
            self.save_hash_map(WITHDRAW_DATA_MAP, withdraw_data_map, None)?;
            Ok(hex::encode(generate_random_bytes(32)))
        } else {
            bail!("fail to get withdraw data");
        }
    }

    async fn finish_withdraw_unhappy_path(
        &self,
        graph_id: &[u8; 16],
        _raw_take2_tx: &BitcoinTx,
        _take2_proof: &BitcoinTxProof,
    ) -> anyhow::Result<String> {
        let mut withdraw_data_map = self.load_hash_map::<WithdrawData>(WITHDRAW_DATA_MAP, None)?;
        if let Some(withdraw_data) = withdraw_data_map.get(&hex::encode(graph_id)) {
            info!("call finish_withdraw_unhappy_path");
            let mut withdraw_data = withdraw_data.clone();
            withdraw_data.status = WithdrawStatus::Complete;
            withdraw_data_map.insert(hex::encode(graph_id), withdraw_data);
            self.save_hash_map(WITHDRAW_DATA_MAP, withdraw_data_map, None)?;
            Ok(hex::encode(generate_random_bytes(32)))
        } else {
            bail!("fail to get withdraw data");
        }
    }

    async fn finish_withdraw_disproved(
        &self,
        graph_id: &[u8; 16],
        _raw_disproved_tx: &BitcoinTx,
        _disproved_proof: &BitcoinTxProof,
        _raw_challenge_tx: &BitcoinTx,
        _challenge_proof: &BitcoinTxProof,
    ) -> anyhow::Result<String> {
        let mut withdraw_data_map = self.load_hash_map::<WithdrawData>(WITHDRAW_DATA_MAP, None)?;
        if let Some(withdraw_data) = withdraw_data_map.get(&hex::encode(graph_id)) {
            info!("call finish_withdraw_disproved");
            let mut withdraw_data = withdraw_data.clone();
            withdraw_data.status = WithdrawStatus::Complete;
            withdraw_data_map.insert(hex::encode(graph_id), withdraw_data);
            self.save_hash_map(WITHDRAW_DATA_MAP, withdraw_data_map, None)?;
            Ok(hex::encode(generate_random_bytes(32)))
        } else {
            bail!("fail to get withdraw data");
        }
    }

    async fn verify_merkle_proof(
        &self,
        _root: &[u8; 32],
        _proof: &[[u8; 32]],
        _pleaf: &[u8; 32],
        _pindex: u64,
    ) -> anyhow::Result<bool> {
        info!("call verify_merkle_proof");
        Ok(true)
    }

    async fn get_stake_amount_check_info(&self) -> anyhow::Result<(u64, u64)> {
        Ok((0, 0))
    }

    async fn get_pegin_fee_check_info(&self) -> anyhow::Result<(u64, u64)> {
        Ok((0, 0))
    }
}

impl MockAdaptor {
    pub fn new(config: Option<MockAdaptorConfig>) -> Self {
        let config = if let Some(config) = config {
            config
        } else {
            let tmp_file = tempfile::NamedTempFile::new().unwrap();
            MockAdaptorConfig { base_path: tmp_file.path().to_path_buf() }
        };
        Self { config }
    }
}
