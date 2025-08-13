use crate::client::chain::goat_adaptor::{GoatAdaptor, GoatInitConfig};
use crate::client::chain::mock_adaptor::{MockAdaptor, MockAdaptorConfig};
use alloy::primitives::{Address, U256};
use alloy::rpc::types::TransactionReceipt;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use strum::Display;
use uuid::Uuid;

#[async_trait]
pub trait ChainAdaptor: Send + Sync {
    async fn get_finalized_block_number(&self) -> anyhow::Result<i64>;
    async fn pegin_tx_used(&self, tx_id: &[u8; 32]) -> anyhow::Result<bool>;
    async fn get_pegin_data(&self, instance_id: &Uuid) -> anyhow::Result<PeginData>;
    async fn is_operator_withdraw(&self, graph_id: &Uuid) -> anyhow::Result<bool>;
    async fn get_withdraw_data(&self, graph_id: &Uuid) -> anyhow::Result<WithdrawData>;
    async fn get_graph_data(&self, graph_id: &Uuid) -> anyhow::Result<GraphData>;

    async fn answer_pegin_request(
        &self,
        instance_id: &Uuid,
        pub_key: &[u8; 32],
    ) -> anyhow::Result<String>;
    async fn post_pegin_data(
        &self,
        instance_id: &Uuid,
        raw_pgin_tx: &BitcoinTx,
        pegin_proof: &BitcoinTxProof,
    ) -> anyhow::Result<String>;

    async fn post_graph_data(
        &self,
        instance_id: &Uuid,
        graph_id: &Uuid,
        operator_data: &GraphData,
        committee_signs: &[u8],
    ) -> anyhow::Result<String>;

    async fn get_btc_block_hash(&self, height: u64) -> anyhow::Result<[u8; 32]>;

    async fn parse_btc_block_header(
        &self,
        raw_header: &[u8],
    ) -> anyhow::Result<([u8; 32], [u8; 32])>;

    async fn get_initialized_ids(&self) -> anyhow::Result<Vec<(Uuid, Uuid)>>;
    async fn get_instanceids_by_pubkey(
        &self,
        operator_pubkey: &[u8; 32],
    ) -> anyhow::Result<Vec<(Uuid, Uuid)>>;
    async fn init_withdraw(&self, instance_id: &Uuid, graph_id: &Uuid) -> anyhow::Result<String>;
    async fn cancel_withdraw(&self, graph_id: &Uuid) -> anyhow::Result<String>;
    async fn process_withdraw(
        &self,
        graph_id: &Uuid,
        raw_kickoff_tx: &BitcoinTx,
        kickoff_proof: &BitcoinTxProof,
    ) -> anyhow::Result<String>;
    async fn finish_withdraw_happy_path(
        &self,
        graph_id: &Uuid,
        raw_take1_tx: &BitcoinTx,
        take1_proof: &BitcoinTxProof,
    ) -> anyhow::Result<String>;
    async fn finish_withdraw_unhappy_path(
        &self,
        graph_id: &Uuid,
        raw_take2_tx: &BitcoinTx,
        take2_proof: &BitcoinTxProof,
    ) -> anyhow::Result<String>;

    async fn finish_withdraw_disproved(
        &self,
        graph_id: &Uuid,
        raw_disproved_tx: &BitcoinTx,
        disproved_proof: &BitcoinTxProof,
        raw_challenge_tx: &BitcoinTx,
        challenge_proof: &BitcoinTxProof,
    ) -> anyhow::Result<String>;

    async fn verify_merkle_proof(
        &self,
        root: &[u8; 32],
        proof: &[[u8; 32]],
        leaf: &[u8; 32],
        index: u64,
    ) -> anyhow::Result<bool>;

    async fn get_tx_receipt(&self, tx_hash: &str) -> anyhow::Result<Option<TransactionReceipt>>;

    async fn get_stake_amount_check_info(&self) -> anyhow::Result<(u64, u64)>;
    async fn get_pegin_fee_check_info(&self) -> anyhow::Result<(u64, u64)>;
}
#[derive(Eq, PartialEq, Clone, Copy)]
pub enum GoatNetwork {
    Main,
    Test,
    /// Locally hosted network.
    Local,
}

#[derive(Eq, PartialEq, Clone, Debug, Serialize, Deserialize)]
pub enum PeginStatus {
    None,
    Pending,
    Withdrawbale,
    Processing,
    Locked,
    Claimed,
    Discarded,
}

impl From<u8> for PeginStatus {
    fn from(value: u8) -> Self {
        match value {
            0 => PeginStatus::None,
            1 => PeginStatus::Processing,
            2 => PeginStatus::Withdrawbale,
            3 => PeginStatus::Locked,
            4 => PeginStatus::Claimed,
            _ => PeginStatus::None,
        }
    }
}

#[derive(Eq, PartialEq, Clone, Debug, Serialize, Deserialize, Display)]
pub enum WithdrawStatus {
    None,
    Processing,
    Initialized,
    Canceled,
    Complete,
    Disproved,
}
impl From<u8> for WithdrawStatus {
    fn from(value: u8) -> Self {
        match value {
            0 => WithdrawStatus::None,
            1 => WithdrawStatus::Processing,
            2 => WithdrawStatus::Initialized,
            3 => WithdrawStatus::Canceled,
            4 => WithdrawStatus::Complete,
            5 => WithdrawStatus::Disproved,
            _ => WithdrawStatus::None,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PeginData {
    pub status: PeginStatus,
    pub pegin_amount_sats: u64,
    pub fee_rate: u64,
    pub user_inputs: Vec<u8>,
    pub pegin_txid: [u8; 32],
    pub created_at: u64,
    pub committee_addresses: Vec<Address>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WithdrawData {
    pub pegin_txid: [u8; 32],
    pub operator_address: [u8; 20],
    pub status: WithdrawStatus,
    pub instance_id: Uuid,
    pub lock_amount: U256,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GraphData {
    pub stake_amount_sats: u64,
    pub operator_pubkey_prefix: u8,
    pub operator_pubkey: [u8; 32],
    pub pegin_txid: [u8; 32],
    pub kickoff_txid: [u8; 32],
    pub take1_txid: [u8; 32],
    pub take2_txid: [u8; 32],
    pub assert_timeout_txid: [u8; 32],
    pub commit_timout_txid: [u8; 32],
    pub nack_txids: Vec<[u8; 32]>,
}

#[derive(Clone, Debug)]
pub struct BitcoinTx {
    pub version: u32,
    pub input_vector: Vec<u8>,
    pub output_vector: Vec<u8>,
    pub lock_time: u32,
}

#[derive(Clone, Debug)]
pub struct BitcoinTxProof {
    pub raw_header: Vec<u8>,
    pub height: u64,
    pub proof: Vec<[u8; 32]>,
    pub index: u64,
}

pub fn get_chain_adaptor(
    network: GoatNetwork,
    goat_config: GoatInitConfig,
    mock_adaptor_config: Option<MockAdaptorConfig>,
) -> Box<dyn ChainAdaptor> {
    match network {
        //GoatAdaptor
        GoatNetwork::Main => Box::new(GoatAdaptor::new(goat_config)),
        GoatNetwork::Test => Box::new(GoatAdaptor::new(goat_config)),
        GoatNetwork::Local => Box::new(MockAdaptor::new(mock_adaptor_config)),
    }
}
