use crate::client::goat_chain::chain_adaptor::{
    BitcoinTx, BitcoinTxProof, ChainAdaptor, GraphData, PeginData, WithdrawData,
};
use crate::client::goat_chain::mock_goat_adaptor::MockAdaptor;
use alloy::rpc::types::TransactionReceipt;
use uuid::Uuid;

pub struct EvmChain {
    adaptor: Box<dyn ChainAdaptor + Send + Sync>,
}

impl Default for EvmChain {
    fn default() -> Self {
        Self::new(Box::new(MockAdaptor::new(None)))
    }
}

impl EvmChain {
    pub fn new(adaptor: Box<dyn ChainAdaptor>) -> Self {
        Self { adaptor }
    }

    // Proxy all ChainAdaptor methods
    pub async fn get_finalized_block_number(&self) -> anyhow::Result<i64> {
        self.adaptor.get_finalized_block_number().await
    }
    pub async fn get_latest_block_number(&self) -> anyhow::Result<i64> {
        self.adaptor.get_latest_block_number().await
    }

    pub async fn pegin_tx_used(&self, tx_id: &[u8; 32]) -> anyhow::Result<bool> {
        self.adaptor.pegin_tx_used(tx_id).await
    }

    pub async fn get_response_window_blocks(&self) -> anyhow::Result<u64> {
        self.adaptor.get_response_window_blocks().await
    }

    pub async fn get_pegin_data(&self, instance_id: &Uuid) -> anyhow::Result<PeginData> {
        self.adaptor.get_pegin_data(instance_id.as_bytes()).await
    }

    pub async fn is_operator_withdraw(&self, graph_id: &Uuid) -> anyhow::Result<bool> {
        self.adaptor.is_operator_withdraw(graph_id.as_bytes()).await
    }

    pub async fn get_withdraw_data(&self, graph_id: &Uuid) -> anyhow::Result<WithdrawData> {
        self.adaptor.get_withdraw_data(graph_id.as_bytes()).await
    }

    pub async fn get_graph_data(&self, graph_id: &Uuid) -> anyhow::Result<GraphData> {
        self.adaptor.get_graph_data(graph_id.as_bytes()).await
    }

    pub async fn answer_pegin_request(
        &self,
        instance_id: &Uuid,
        pub_key: &[u8; 32],
    ) -> anyhow::Result<String> {
        self.adaptor.answer_pegin_request(instance_id.as_bytes(), pub_key).await
    }

    pub async fn post_pegin_data(
        &self,
        instance_id: &Uuid,
        raw_pgin_tx: &BitcoinTx,
        pegin_proof: &BitcoinTxProof,
    ) -> anyhow::Result<String> {
        self.adaptor.post_pegin_data(instance_id.as_bytes(), raw_pgin_tx, pegin_proof).await
    }

    pub async fn post_graph_data(
        &self,
        instance_id: &Uuid,
        graph_id: &Uuid,
        operator_data: &GraphData,
        committee_signs: &[u8],
    ) -> anyhow::Result<String> {
        self.adaptor
            .post_graph_data(
                instance_id.as_bytes(),
                graph_id.as_bytes(),
                operator_data,
                committee_signs,
            )
            .await
    }

    pub async fn get_btc_block_hash(&self, height: u64) -> anyhow::Result<[u8; 32]> {
        self.adaptor.get_btc_block_hash(height).await
    }

    pub async fn parse_btc_block_header(
        &self,
        raw_header: &[u8],
    ) -> anyhow::Result<([u8; 32], [u8; 32])> {
        self.adaptor.parse_btc_block_header(raw_header).await
    }

    pub async fn get_initialized_ids(&self) -> anyhow::Result<Vec<(Uuid, Uuid)>> {
        self.adaptor.get_initialized_ids().await
    }

    pub async fn get_instanceids_by_pubkey(
        &self,
        operator_pubkey: &[u8; 32],
    ) -> anyhow::Result<Vec<(Uuid, Uuid)>> {
        self.adaptor.get_instanceids_by_pubkey(operator_pubkey).await
    }

    pub async fn init_withdraw(
        &self,
        instance_id: &Uuid,
        graph_id: &Uuid,
    ) -> anyhow::Result<String> {
        self.adaptor.init_withdraw(instance_id.as_bytes(), graph_id.as_bytes()).await
    }

    pub async fn cancel_withdraw(&self, graph_id: &Uuid) -> anyhow::Result<String> {
        self.adaptor.cancel_withdraw(graph_id.as_bytes()).await
    }

    pub async fn process_withdraw(
        &self,
        graph_id: &Uuid,
        raw_kickoff_tx: &BitcoinTx,
        kickoff_proof: &BitcoinTxProof,
    ) -> anyhow::Result<String> {
        self.adaptor.process_withdraw(graph_id.as_bytes(), raw_kickoff_tx, kickoff_proof).await
    }

    pub async fn finish_withdraw_happy_path(
        &self,
        graph_id: &Uuid,
        raw_take1_tx: &BitcoinTx,
        take1_proof: &BitcoinTxProof,
    ) -> anyhow::Result<String> {
        self.adaptor
            .finish_withdraw_happy_path(graph_id.as_bytes(), raw_take1_tx, take1_proof)
            .await
    }

    pub async fn finish_withdraw_unhappy_path(
        &self,
        graph_id: &Uuid,
        raw_take2_tx: &BitcoinTx,
        take2_proof: &BitcoinTxProof,
    ) -> anyhow::Result<String> {
        self.adaptor
            .finish_withdraw_unhappy_path(graph_id.as_bytes(), raw_take2_tx, take2_proof)
            .await
    }

    pub async fn finish_withdraw_disproved(
        &self,
        graph_id: &Uuid,
        raw_disproved_tx: &BitcoinTx,
        disproved_proof: &BitcoinTxProof,
        raw_challenge_tx: &BitcoinTx,
        challenge_proof: &BitcoinTxProof,
    ) -> anyhow::Result<String> {
        self.adaptor
            .finish_withdraw_disproved(
                graph_id.as_bytes(),
                raw_disproved_tx,
                disproved_proof,
                raw_challenge_tx,
                challenge_proof,
            )
            .await
    }

    pub async fn verify_merkle_proof(
        &self,
        root: &[u8; 32],
        proof: &[[u8; 32]],
        leaf: &[u8; 32],
        index: u64,
    ) -> anyhow::Result<bool> {
        self.adaptor.verify_merkle_proof(root, proof, leaf, index).await
    }

    pub async fn get_tx_receipt(
        &self,
        tx_hash: &str,
    ) -> anyhow::Result<Option<TransactionReceipt>> {
        self.adaptor.get_tx_receipt(tx_hash).await
    }

    pub async fn get_stake_amount_check_info(&self) -> anyhow::Result<(u64, u64)> {
        self.adaptor.get_stake_amount_check_info().await
    }

    pub async fn get_pegin_fee_check_info(&self) -> anyhow::Result<(u64, u64)> {
        self.adaptor.get_pegin_fee_check_info().await
    }
}
