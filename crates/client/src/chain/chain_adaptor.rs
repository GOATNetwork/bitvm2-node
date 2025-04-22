use crate::chain::goat_adaptor::{GoatAdaptor, GoatInitConfig};
use crate::chain::mock_addaptor::{MockAdaptor, MockAdaptorConfig};
use alloy::primitives::U256;
use async_trait::async_trait;
use uuid::Uuid;

#[async_trait]
pub trait ChainAdaptor: Send + Sync {
    async fn pegin_tx_used(&self, tx_id: &[u8; 32]) -> anyhow::Result<bool>;
    async fn get_pegin_data(&self, instance_id: Uuid) -> anyhow::Result<PeginData>;
    async fn is_operator_withdraw(&self, graph_id: Uuid) -> anyhow::Result<bool>;
    async fn get_withdraw_data(&self, graph_id: Uuid) -> anyhow::Result<WithdrawData>;
    async fn get_operator_data(&self, graph_id: Uuid) -> anyhow::Result<OperatorData>;
    async fn post_pegin_data(
        &self,
        instance_id: &Uuid,
        raw_pgin_tx: &BitcoinTx,
        height: u64,
        proof: &[[u8; 32]],
        index: u64,
    ) -> anyhow::Result<()>;

    async fn post_operator_data(
        &self,
        instance_id: &Uuid,
        graph_id: &Uuid,
        operator_data: &OperatorData,
    ) -> anyhow::Result<()>;

    async fn post_operator_data_batch(
        &self,
        instance_id: &Uuid,
        graph_ids: &[Uuid],
        operator_datas: &[OperatorData],
    ) -> anyhow::Result<()>;

    async fn init_withdraw(&self, instance_id: &Uuid, graph_id: &Uuid) -> anyhow::Result<()>;
    async fn cancel_withdraw(&self, graph_id: &Uuid) -> anyhow::Result<()>;
    async fn process_withdraw(
        &self,
        graph_id: &Uuid,
        raw_kickoff_tx: &BitcoinTx,
        height: u64,
        proof: &[[u8; 32]],
        index: u64,
    ) -> anyhow::Result<()>;
    async fn finish_withdraw_happy_path(
        &self,
        graph_id: &Uuid,
        raw_take1_tx: &BitcoinTx,
        height: u64,
        proof: &[[u8; 32]],
        index: u64,
    ) -> anyhow::Result<()>;
    async fn finish_withdraw_unhappy_path(
        &self,
        graph_id: &Uuid,
        raw_take2_tx: &BitcoinTx,
        height: u64,
        proof: &[[u8; 32]],
        index: u64,
    ) -> anyhow::Result<()>;

    async fn finish_withdraw_disproved(
        &self,
        graph_id: &Uuid,
        raw_disproved_tx: &BitcoinTx,
        height: u64,
        proof: &[[u8; 32]],
        index: u64,
    ) -> anyhow::Result<()>;

    async fn verify_merkle_proof(
        &self,
        root: &[u8; 32],
        proof: &[[u8; 32]],
        leaf: &[u8; 32],
        index: u64,
    ) -> anyhow::Result<bool>;
}
#[derive(Eq, PartialEq, Clone, Copy)]
pub enum GoatNetwork {
    Main,
    Test,
    /// Locally hosted network.
    Local,
}

#[derive(Eq, PartialEq, Clone, Debug)]
pub enum PeginStatus {
    None,
    Processing,
    Withdrawbale,
    Locked,
    Claimed,
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

#[derive(Eq, PartialEq, Clone, Debug)]
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

#[derive(Clone, Debug)]
pub struct PeginData {
    pub pegin_txid: [u8; 32],
    pub pegin_status: PeginStatus,
    pub pegin_amount: u64,
}

#[derive(Clone, Debug)]
pub struct WithdrawData {
    pub pegin_txid: [u8; 32],
    pub operator_address: [u8; 20],
    pub status: WithdrawStatus,
    pub instance_id: Uuid,
    pub lock_amount: U256,
}

#[derive(Clone, Debug)]
pub struct OperatorData {
    pub stake_amount: u64,
    pub operator_pubkey_prefix: u8,
    pub operator_pubkey: [u8; 32],
    pub pegin_txid: [u8; 32],
    pub pre_kickoff_txid: [u8; 32],
    pub kickoff_txid: [u8; 32],
    pub take1_txid: [u8; 32],
    pub assert_init_txid: [u8; 32],
    pub assert_commit_txids: [[u8; 32]; 4],
    pub assert_final_txid: [u8; 32],
    pub take2_txid: [u8; 32],
}

#[derive(Clone, Debug)]
pub struct BitcoinTx {
    pub version: u32,
    pub input_vector: Vec<u8>,
    pub output_vector: Vec<u8>,
    pub lock_time: u32,
}

pub fn get_chain_adaptor(
    network: GoatNetwork,
    goat_config: Option<GoatInitConfig>,
    mock_adaptor_config: Option<MockAdaptorConfig>,
) -> Box<dyn ChainAdaptor> {
    match network {
        //GoatAdaptor
        GoatNetwork::Main => Box::new(GoatAdaptor::new(goat_config)),
        GoatNetwork::Test => Box::new(GoatAdaptor::new(goat_config)),
        GoatNetwork::Local => Box::new(MockAdaptor::new(mock_adaptor_config)),
    }
}
