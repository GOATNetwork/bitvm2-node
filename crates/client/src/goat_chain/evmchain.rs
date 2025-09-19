use crate::Utxo;
use crate::goat_chain::DisproveTxType;
use crate::goat_chain::chain_adaptor::{
    BitcoinTx, BitcoinTxProof, ChainAdaptor, GraphData, PeginData, SequencerSet, WithdrawData,
};
use crate::goat_chain::mock_goat_adaptor::MockAdaptor;
use alloy::primitives::{Address, Bytes, FixedBytes, U256};
use alloy::rpc::types::TransactionReceipt;
use alloy::signers::Signature;
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
    pub fn get_default_signer_address(&self) -> Address {
        self.adaptor.get_default_signer_address()
    }
    pub async fn get_finalized_block_number(&self) -> anyhow::Result<i64> {
        self.adaptor.get_finalized_block_number().await
    }
    pub async fn get_latest_block_number(&self) -> anyhow::Result<i64> {
        self.adaptor.get_latest_block_number().await
    }

    pub async fn gateway_get_response_window_blocks(&self) -> anyhow::Result<u64> {
        self.adaptor.gateway_get_response_window_blocks().await
    }

    pub async fn gateway_get_min_challenge_amount_sats(&self) -> anyhow::Result<u64> {
        self.adaptor.gateway_get_min_challenge_amount_sats().await
    }

    pub async fn gateway_get_min_pegin_fee_sats(&self) -> anyhow::Result<u64> {
        self.adaptor.gateway_get_min_pegin_fee_sats().await
    }

    pub async fn gateway_get_pegin_fee_rate(&self) -> anyhow::Result<u64> {
        self.adaptor.gateway_get_pegin_fee_rate().await
    }

    pub async fn gateway_get_min_operator_reward_sats(&self) -> anyhow::Result<u64> {
        self.adaptor.gateway_get_min_operator_reward_sats().await
    }

    pub async fn gateway_get_operator_reward_rate(&self) -> anyhow::Result<u64> {
        self.adaptor.gateway_get_operator_reward_rate().await
    }

    pub async fn gateway_get_min_stake_amount(&self) -> anyhow::Result<u64> {
        self.adaptor.gateway_get_min_stake_amount().await
    }

    pub async fn gateway_get_min_challenger_reward(&self) -> anyhow::Result<u64> {
        self.adaptor.gateway_get_min_challenger_reward().await
    }

    pub async fn gateway_get_min_disprover_reward(&self) -> anyhow::Result<u64> {
        self.adaptor.gateway_get_min_disprover_reward().await
    }

    pub async fn gateway_get_min_slash_amount(&self) -> anyhow::Result<u64> {
        self.adaptor.gateway_get_min_slash_amount().await
    }

    pub async fn gateway_get_committee_management(&self) -> anyhow::Result<[u8; 20]> {
        self.adaptor.gateway_get_committee_management().await
    }

    pub async fn gateway_get_stake_management(&self) -> anyhow::Result<[u8; 20]> {
        self.adaptor.gateway_get_stake_management().await
    }
    pub async fn gateway_get_pegin_data(&self, instance_id: &Uuid) -> anyhow::Result<PeginData> {
        self.adaptor.gateway_get_pegin_data(instance_id.as_bytes()).await
    }

    pub async fn gateway_get_withdraw_data(&self, graph_id: &Uuid) -> anyhow::Result<WithdrawData> {
        self.adaptor.gateway_get_withdraw_data(graph_id.as_bytes()).await
    }

    pub async fn gateway_get_graph_data(&self, graph_id: &Uuid) -> anyhow::Result<GraphData> {
        self.adaptor.gateway_get_graph_data(graph_id.as_bytes()).await
    }

    pub async fn gateway_post_pegin_request(
        &self,
        instance_id: &Uuid,
        pegin_amount_sats: u64,
        tx_fees: &[u64; 3],
        receiver_addr: &[u8; 20],
        user_inputs: &[Utxo],
        user_xonly_pubkey: &[u8; 32],
        user_change_addr: &str,
        user_refund_addr: &str,
    ) -> anyhow::Result<String> {
        self.adaptor
            .gateway_post_pegin_request(
                instance_id.as_bytes(),
                pegin_amount_sats,
                tx_fees,
                receiver_addr,
                user_inputs,
                user_xonly_pubkey,
                user_change_addr,
                user_refund_addr,
            )
            .await
    }

    pub async fn gateway_answer_pegin_request(
        &self,
        instance_id: &Uuid,
        committee_xonly_pubkey: &[u8; 33],
    ) -> anyhow::Result<String> {
        self.adaptor
            .gateway_answer_pegin_request(instance_id.as_bytes(), committee_xonly_pubkey)
            .await
    }

    pub async fn gateway_post_pegin_data(
        &self,
        instance_id: &Uuid,
        raw_pgin_tx: &BitcoinTx,
        pegin_proof: &BitcoinTxProof,
        committee_signs: &[Vec<u8>],
    ) -> anyhow::Result<String> {
        self.adaptor
            .gateway_post_pegin_data(
                instance_id.as_bytes(),
                raw_pgin_tx,
                pegin_proof,
                committee_signs,
            )
            .await
    }

    pub async fn gateway_post_graph_data(
        &self,
        instance_id: &Uuid,
        graph_id: &Uuid,
        graph_data: &GraphData,
        committee_signs: &[Vec<u8>],
    ) -> anyhow::Result<String> {
        self.adaptor
            .gateway_post_graph_data(
                instance_id.as_bytes(),
                graph_id.as_bytes(),
                graph_data,
                committee_signs,
            )
            .await
    }

    pub async fn gateway_get_btc_block_hash(&self, height: u64) -> anyhow::Result<[u8; 32]> {
        self.adaptor.btc_spv_blockhash(height).await
    }

    pub async fn gateway_get_initialized_ids(&self) -> anyhow::Result<Vec<(Uuid, Uuid)>> {
        self.adaptor.gateway_get_initialized_ids().await
    }

    pub async fn gateway_get_instanceids_by_pubkey(
        &self,
        operator_pubkey: &[u8; 32],
    ) -> anyhow::Result<Vec<(Uuid, Uuid)>> {
        self.adaptor.gateway_get_instanceids_by_pubkey(operator_pubkey).await
    }

    pub async fn gateway_init_withdraw(
        &self,
        instance_id: &Uuid,
        graph_id: &Uuid,
    ) -> anyhow::Result<String> {
        self.adaptor.gateway_init_withdraw(instance_id.as_bytes(), graph_id.as_bytes()).await
    }

    pub async fn gateway_cancel_withdraw(&self, graph_id: &Uuid) -> anyhow::Result<String> {
        self.adaptor.gateway_cancel_withdraw(graph_id.as_bytes()).await
    }

    pub async fn gateway_process_withdraw(
        &self,
        graph_id: &Uuid,
        raw_kickoff_tx: &BitcoinTx,
        kickoff_proof: &BitcoinTxProof,
    ) -> anyhow::Result<String> {
        self.adaptor
            .gateway_process_withdraw(graph_id.as_bytes(), raw_kickoff_tx, kickoff_proof)
            .await
    }

    pub async fn gateway_finish_withdraw_happy_path(
        &self,
        graph_id: &Uuid,
        raw_take1_tx: &BitcoinTx,
        take1_proof: &BitcoinTxProof,
    ) -> anyhow::Result<String> {
        self.adaptor
            .gateway_finish_withdraw_happy_path(graph_id.as_bytes(), raw_take1_tx, take1_proof)
            .await
    }

    pub async fn gateway_finish_withdraw_unhappy_path(
        &self,
        graph_id: &Uuid,
        raw_take2_tx: &BitcoinTx,
        take2_proof: &BitcoinTxProof,
    ) -> anyhow::Result<String> {
        self.adaptor
            .gateway_finish_withdraw_unhappy_path(graph_id.as_bytes(), raw_take2_tx, take2_proof)
            .await
    }

    pub async fn gateway_finish_withdraw_disproved(
        &self,
        graph_id: &Uuid,
        disprove_type: DisproveTxType,
        tx_index: u64,
        raw_challenge_start_tx: &BitcoinTx,
        challenge_start_proof: &BitcoinTxProof,
        raw_challenge_finshish_tx: &BitcoinTx,
        challenge_finish_proof: &BitcoinTxProof,
    ) -> anyhow::Result<String> {
        self.adaptor
            .gateway_finish_withdraw_disproved(
                graph_id.as_bytes(),
                disprove_type,
                tx_index,
                raw_challenge_start_tx,
                challenge_start_proof,
                raw_challenge_finshish_tx,
                challenge_finish_proof,
            )
            .await
    }

    pub async fn get_tx_receipt(
        &self,
        tx_hash: &str,
    ) -> anyhow::Result<Option<TransactionReceipt>> {
        self.adaptor.get_tx_receipt(tx_hash).await
    }

    pub async fn seq_set_pub_get_last_block_height(&self) -> anyhow::Result<u64> {
        self.adaptor.seq_set_pub_get_last_block_height().await
    }

    pub async fn seq_set_pub_calc_commitment(&self, height: U256) -> anyhow::Result<FixedBytes<32>> {
        self.adaptor.seq_set_pub_calc_commitment(height).await
    }

    pub async fn seq_set_pub_multi_sig_verifier_get_owners(&self) -> anyhow::Result<Vec<Address>> {
        self.adaptor.seq_set_pub_multi_sig_verifier_get_owners().await
    }

    pub async fn seq_set_pub_multi_sig_verifier_get_nonce(&self) -> anyhow::Result<U256> {
        self.adaptor.seq_set_pub_multi_sig_verifier_get_nonce().await
    }

    pub async fn seq_set_pub_get_publisher_public_keys(
        &self,
        publisher: Address,
    ) -> anyhow::Result<Bytes> {
        self.adaptor.seq_set_pub_get_publisher_public_keys(publisher).await
    }

    pub async fn seq_set_pub_update_sequencer_set(
        &self,
        sequencer_set: &SequencerSet,
        signature: &Signature,
    ) -> anyhow::Result<String> {
        self.adaptor.seq_set_pub_update_sequencer_set(sequencer_set, signature).await
    }

    pub async fn seq_set_pub_update_publisher_set(
        &self,
        new_publishers: Vec<Address>,
        new_publisher_btc_pubkeys: &[Vec<u8>],
        signatures: &[Vec<u8>],
        height: U256,
    ) -> anyhow::Result<String> {
        self.adaptor
            .seq_set_pub_update_publisher_set(
                new_publishers,
                new_publisher_btc_pubkeys,
                signatures,
                height,
            )
            .await
    }
    pub async fn stake_mana_stake_token_address(&self) -> anyhow::Result<[u8; 20]> {
        self.adaptor.stake_mana_stake_token_address().await
    }
    pub async fn stake_mana_pubkey_to_address(
        &self,
        pubkey: &[u8; 32],
    ) -> anyhow::Result<[u8; 20]> {
        self.adaptor.stake_mana_pubkey_to_address(pubkey).await
    }
    pub async fn stake_mana_stake_of(&self, operator: &[u8; 20]) -> anyhow::Result<u64> {
        self.adaptor.stake_mana_stake_of(operator).await
    }
    pub async fn stake_mana_lock_stake_of(&self, operator: &[u8; 20]) -> anyhow::Result<u64> {
        self.adaptor.stake_mana_lock_stake_of(operator).await
    }
    pub async fn stake_mana_slash_stake(
        &self,
        operator: &[u8; 20],
        amount: u64,
    ) -> anyhow::Result<String> {
        self.adaptor.stake_mana_slash_stake(operator, amount).await
    }

    pub async fn stake_mana_lock_stake(
        &self,
        operator: &[u8; 20],
        amount: u64,
    ) -> anyhow::Result<String> {
        self.adaptor.stake_mana_lock_stake(operator, amount).await
    }

    pub async fn stake_mana_unlock_stake(
        &self,
        operator: &[u8; 20],
        amount: u64,
    ) -> anyhow::Result<String> {
        self.adaptor.stake_mana_unlock_stake(operator, amount).await
    }
    pub async fn committee_mana_is_committee_member(
        &self,
        member: &[u8; 20],
    ) -> anyhow::Result<bool> {
        self.adaptor.committee_mana_is_committee_member(member).await
    }

    pub async fn committee_mana_committee_size(&self) -> anyhow::Result<u64> {
        self.adaptor.committee_mana_committee_size().await
    }
    pub async fn committee_mana_quorum_size(&self) -> anyhow::Result<u64> {
        self.adaptor.committee_mana_quorum_size().await
    }
    pub async fn committee_mana_verify_signatures(
        &self,
        msg_hash: &[u8; 32],
        signs: &[Vec<u8>],
    ) -> anyhow::Result<bool> {
        self.adaptor.committee_mana_verify_signatures(msg_hash, signs).await
    }
}
