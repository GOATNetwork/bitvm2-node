use crate::client::goat_chain::chain_adaptor::{
    BitcoinTx, BitcoinTxProof, ChainAdaptor, GraphData, PeginData, PeginStatus, WithdrawData,
    WithdrawStatus,
};
use crate::client::goat_chain::goat_adaptor::IGateway::IGatewayInstance;
use alloy::eips::BlockNumberOrTag;
use alloy::primitives::TxHash;
use alloy::providers::Identity;
use alloy::providers::fillers::{FillProvider, JoinFill, RecommendedFillers};
use alloy::rpc::types::TransactionReceipt;
use alloy::{
    network::{Ethereum, EthereumWallet, NetworkWallet, eip2718::Encodable2718},
    primitives::{Address as EvmAddress, Bytes, ChainId, FixedBytes, U256},
    providers::{Provider, ProviderBuilder, RootProvider},
    rpc::types::TransactionRequest,
    signers::{Signer, local::PrivateKeySigner},
    sol,
    transports::http::reqwest::Url,
};
use anyhow::{bail, format_err};
use async_trait::async_trait;
use std::str::FromStr;
use std::time::Duration;
use tokio::time;
sol!(
    #[derive(Debug)]
    #[allow(missing_docs)]
    #[sol(rpc)]
    interface IGateway {
        enum DisproveTxType {
             AssertTimeout,
             OperatorCommitTimeout,
             OperatorNack,
             Disprove
        }
        enum PeginStatus {
            None,
            Pending,
            Withdrawbale,
            Processing,
            Locked,
            Claimed,
            Discarded,
        }
        enum WithdrawStatus {
            None,
            Processing,
            Initialized,
            Canceled,
            Complete,
            Disproved
        }
        struct PeginData {
            PeginStatus status;
            uint64 peginAmountSats;
            uint64 feeRate;
            bytes userInputs;
            bytes32 peginTxid;
            uint256 createdAt;
            address[] committeeAddresses;
        }
        struct WithdrawData {
            bytes32 peginTxid;
            address operatorAddress;
            WithdrawStatus status;
            bytes16 instanceId;
            uint256 lockAmount;
            uint256 btcBlockHeightAtWithdraw;
        }

        struct GraphData {
            uint64 stakeAmountSats;
            bytes1 operatorPubkeyPrefix;
            bytes32 operatorPubkey;
            bytes32 peginTxid;
            bytes32 kickoffTxid;
            bytes32 take1Txid;
            bytes32 take2Txid;
            bytes32 assertTimoutTxid;
            bytes32 commitTimoutTxid;
            bytes32[] NackTxids;
        }

        struct BitcoinTx {
            bytes4 version;
            bytes inputVector;
            bytes outputVector;
            bytes4 locktime;
        }

        struct BitcoinTxProof {
            bytes rawHeader;
            uint256 height;
            bytes32[] proof;
            uint256 index;
        }

        uint64 public minPeginFeeSats;
        uint64 public peginFeeRate;
        uint64 public minStakeAmountSats;
        uint64 public stakeRate;
        address public  pegBTC;
        address public  bitcoinSPV;
        address public  relayer;
        mapping(bytes32 => bool) public peginTxUsed;
        mapping(bytes16 instanceId => PeginData) public peginDataMap;
        mapping(bytes16 graphId => bool) public operatorWithdrawn;
        mapping(bytes16 graphId => GraphData) public graphDataMap;
        mapping(bytes16 graphId => WithdrawData) public withdrawDataMap;
        bytes16[] public instanceIds;
        mapping(bytes16 instanceId => bytes16[] graphIds)
        public instanceIdToGraphIds;

        function getBlockHash(uint256 height) external view returns (bytes32);
        function parseBtcBlockHeader(bytes calldata rawHeader) public pure returns (bytes32 blockHash, bytes32 merkleRoot);
        function getInitializedInstanceIds() external view returns (bytes16[] memory retInstanceIds, bytes16[] memory retGraphIds);
        function getInstanceIdsByPubKey(bytes32 operatorPubkey) external view returns (bytes16[] memory retInstanceIds, bytes16[] memory retGraphIds);
        function getWithdrawableInstances(bytes32 operatorPubkey) external view returns ( bytes16[] memory retInstanceIds, bytes16[] memory retGraphIds, uint64[] memory retPeginAmounts);

        function postPeginData(bytes16 instanceId, BitcoinTx calldata rawPeginTx, BitcoinTxProof calldata peginProof) external ;
        function postGraphData(bytes16 instanceId, bytes16 graphId, GraphData calldata graphData, bytes calldata committeeSigs) public;
        function initWithdraw(bytes16 instanceId, bytes16 graphId) external;
        function cancelWithdraw(bytes16 graphId) external;
        function proceedWithdraw(bytes16 graphId, BitcoinTx calldata rawKickoffTx, BitcoinTxProof calldata kickoffProof) external;
        function finishWithdrawHappyPath(bytes16 graphId, BitcoinTx calldata rawTake1Tx, BitcoinTxProof calldata take1Proof) external;
        function finishWithdrawUnhappyPath(bytes16 graphId, BitcoinTx calldata rawTake2Tx, BitcoinTxProof calldata take2Proof) external;
        function finishWithdrawDisproved(bytes16 graphId, BitcoinTx calldata rawDisproveTx, BitcoinTxProof calldata disproveProof, BitcoinTx calldata rawChallengeTx, BitcoinTxProof calldata ngeCProof) external;
        function verifyMerkleProof(bytes32 root,bytes32[] memory proof, bytes32 leaf,uint256 index) public pure returns (bool);
        function answerPeginRequest(bytes16 instanceId, bytes32 pubkey) onlyCommittee() external;

        // TODO
        // function getCommitteeAddresses(bytes16 instanceId) external view returns (address[] memory);

    }
);

use uuid::Uuid;

pub struct GoatInitConfig {
    pub rpc_url: Url,
    pub gateway_address: EvmAddress,
    pub private_key: Option<String>,
    pub chain_id: u32,
}

impl GoatInitConfig {
    pub fn from_env_for_test() -> Self {
        GoatInitConfig {
            rpc_url: "https://rpc.testnet3.goat.network".parse::<Url>().expect("decode url"),
            gateway_address: "0xeD8AeeD334fA446FA03Aa00B28aFf02FA8aC02df"
                .parse()
                .expect("parse contract address"),
            private_key: None,
            chain_id: 48816_u32,
        }
    }
}

pub struct GoatAdaptor {
    chain_id: ChainId,
    _gateway_address: EvmAddress,
    // provider: FillProvider<JoinFill<Identity, <Ethereum as RecommendedFillers>::RecommendedFillers>, RootProvider>,
    provider: FillProvider<
        JoinFill<Identity, <Ethereum as RecommendedFillers>::RecommendedFillers>,
        RootProvider,
    >,
    gate_way: IGatewayInstance<
        FillProvider<
            JoinFill<Identity, <Ethereum as RecommendedFillers>::RecommendedFillers>,
            RootProvider,
        >,
    >,
    signer: EthereumWallet,
}

impl GoatAdaptor {
    #[allow(unused)]
    fn get_price_amend(&self, price: u128) -> u128 {
        price
    }

    fn get_default_signer_address(&self) -> EvmAddress {
        <EthereumWallet as NetworkWallet<Ethereum>>::default_signer_address(&self.signer)
    }

    async fn handle_transaction_request(
        &self,
        mut tx_request: TransactionRequest,
    ) -> anyhow::Result<TxHash> {
        // update  gas price nonce gas_limit
        tx_request.gas_price = Some(self.provider.clone().get_gas_price().await?);
        tx_request.nonce =
            Some(self.provider.clone().get_transaction_count(tx_request.from.unwrap()).await?);
        tx_request.gas = Some(self.provider.clone().estimate_gas(tx_request.clone()).await?);

        // change into unsigned tx
        let unsigned_tx = tx_request
            .build_typed_tx()
            .map_err(|v| format_err!("{:?} fail to build typed tx", v))?;
        // signed tx
        let signed_tx = <EthereumWallet as NetworkWallet<Ethereum>>::sign_transaction(
            &self.signer,
            unsigned_tx,
        )
        .await?;
        // send tx
        let pending_tx =
            self.provider.send_raw_transaction(signed_tx.encoded_2718().as_slice()).await?;
        let tx_hash = pending_tx.tx_hash();
        tracing::info!("finish send tx_hash: {}", tx_hash.to_string());

        // TODO update latter
        let mut is_success = false;
        for i in 0..5 {
            time::sleep(Duration::from_millis(2000)).await;
            match self.provider.get_transaction_receipt(*tx_hash).await {
                Err(_) => {
                    tracing::info!(
                        "Get transaction:{} receipt failed at {} times, will try later",
                        tx_hash.to_string(),
                        i
                    );
                    continue;
                }
                Ok(receipt) => {
                    if receipt.is_none() {
                        tracing::info!(
                            "Get transaction:{} receipt is none at {} times, will try later",
                            tx_hash.to_string(),
                            i
                        );
                        continue;
                    }
                    if receipt.unwrap().status() {
                        is_success = true;
                        break;
                    }
                }
            };
        }
        if !is_success {
            bail!("tx_hash:{} execute failed on chain", tx_hash.to_string());
        }
        Ok(*tx_hash)
    }
}

impl From<&BitcoinTx> for IGateway::BitcoinTx {
    fn from(value: &BitcoinTx) -> Self {
        Self {
            version: FixedBytes::<4>::from_slice(&value.version.to_le_bytes()),
            inputVector: Bytes::copy_from_slice(&value.input_vector),
            outputVector: Bytes::copy_from_slice(&value.output_vector),
            locktime: FixedBytes::<4>::from(value.lock_time),
        }
    }
}

impl From<&BitcoinTxProof> for IGateway::BitcoinTxProof {
    fn from(value: &BitcoinTxProof) -> Self {
        let proof: Vec<FixedBytes<32>> =
            value.proof.iter().map(|v| FixedBytes::<32>::from_slice(v)).collect();
        Self {
            rawHeader: Bytes::copy_from_slice(&value.raw_header),
            height: U256::from(value.height),
            proof,
            index: U256::from(value.index),
        }
    }
}

impl From<GraphData> for IGateway::GraphData {
    fn from(value: GraphData) -> Self {
        Self {
            stakeAmountSats: value.stake_amount_sats,
            operatorPubkeyPrefix: FixedBytes::from(value.operator_pubkey_prefix),
            operatorPubkey: FixedBytes::from_slice(&value.operator_pubkey),
            peginTxid: FixedBytes::from_slice(&value.pegin_txid),
            kickoffTxid: FixedBytes::from_slice(&value.kickoff_txid),
            take1Txid: FixedBytes::from_slice(&value.take1_txid),
            take2Txid: FixedBytes::from_slice(&value.take2_txid),
            assertTimoutTxid: FixedBytes::from_slice(&value.assert_timeout_txid),
            commitTimoutTxid: FixedBytes::from_slice(&value.commit_timout_txid),
            NackTxids: value
                .nack_txids
                .into_iter()
                .map(|txid| FixedBytes::from_slice(&txid))
                .collect::<Vec<_>>(),
        }
    }
}
impl From<IGateway::GraphData> for GraphData {
    fn from(value: IGateway::GraphData) -> Self {
        GraphData {
            stake_amount_sats: value.stakeAmountSats,
            operator_pubkey_prefix: value.operatorPubkeyPrefix.0[0],
            operator_pubkey: value.operatorPubkey.0,
            pegin_txid: value.peginTxid.0,
            kickoff_txid: value.kickoffTxid.0,
            take1_txid: value.take1Txid.0,
            take2_txid: value.take2Txid.0,
            assert_timeout_txid: value.assertTimoutTxid.0,
            commit_timout_txid: value.commitTimoutTxid.0,
            nack_txids: value.NackTxids.into_iter().map(|txid| txid.into()).collect(),
        }
    }
}

impl From<IGateway::PeginStatus> for PeginStatus {
    fn from(value: IGateway::PeginStatus) -> Self {
        match value {
            IGateway::PeginStatus::None => PeginStatus::None,
            IGateway::PeginStatus::Pending => PeginStatus::Pending,
            IGateway::PeginStatus::Withdrawbale => PeginStatus::Withdrawbale,
            IGateway::PeginStatus::Processing => PeginStatus::Processing,
            IGateway::PeginStatus::Locked => PeginStatus::Locked,
            IGateway::PeginStatus::Claimed => PeginStatus::Claimed,
            IGateway::PeginStatus::Discarded => PeginStatus::Discarded,
            _ => PeginStatus::None,
        }
    }
}

impl From<IGateway::WithdrawStatus> for WithdrawStatus {
    fn from(value: IGateway::WithdrawStatus) -> Self {
        match value {
            IGateway::WithdrawStatus::None => WithdrawStatus::None,
            IGateway::WithdrawStatus::Processing => WithdrawStatus::Processing,
            IGateway::WithdrawStatus::Initialized => WithdrawStatus::Initialized,
            IGateway::WithdrawStatus::Canceled => WithdrawStatus::Canceled,
            IGateway::WithdrawStatus::Complete => WithdrawStatus::Complete,
            IGateway::WithdrawStatus::Disproved => WithdrawStatus::Disproved,
            _ => WithdrawStatus::None,
        }
    }
}

impl From<IGateway::WithdrawData> for WithdrawData {
    fn from(value: IGateway::WithdrawData) -> Self {
        Self {
            pegin_txid: value.peginTxid.0,
            operator_address: value.operatorAddress.0.map(|v| v),
            status: value.status.into(),
            instance_id: value.instanceId.0,
            lock_amount: value.lockAmount,
            btc_block_height_withdraw: value.btcBlockHeightAtWithdraw,
        }
    }
}

#[async_trait]
impl ChainAdaptor for GoatAdaptor {
    async fn pegin_tx_used(&self, tx_id: &[u8; 32]) -> anyhow::Result<bool> {
        Ok(self.gate_way.peginTxUsed(FixedBytes::<32>::from_slice(tx_id)).call().await?)
    }

    async fn get_pegin_data(&self, instance_id: &[u8; 16]) -> anyhow::Result<PeginData> {
        let res =
            self.gate_way.peginDataMap(FixedBytes::<16>::from_slice(instance_id)).call().await?;

        // let committee_addresses = self
        //     .gate_way
        //     .getCommitteeAddresses(FixedBytes::<16>::from_slice(instance_id.as_bytes()))
        //     .call()
        //     .await?;

        Ok(PeginData {
            status: res._0.into(),
            pegin_amount_sats: res._1,
            fee_rate: res._2,
            user_inputs: res._3.to_vec(),
            pegin_txid: res._4.0,
            created_at: res._5.try_into().expect("fail to decoded"),
            committee_addresses: vec![],
        })
    }

    async fn is_operator_withdraw(&self, graph_id: &[u8; 16]) -> anyhow::Result<bool> {
        Ok(self.gate_way.operatorWithdrawn(FixedBytes::<16>::from_slice(graph_id)).call().await?)
    }

    async fn get_withdraw_data(&self, graph_id: &[u8; 16]) -> anyhow::Result<WithdrawData> {
        let res =
            self.gate_way.withdrawDataMap(FixedBytes::<16>::from_slice(graph_id)).call().await?;
        Ok(WithdrawData {
            pegin_txid: res._0.0,
            operator_address: res._1.0.0,
            status: res._2.into(),
            instance_id: res._3.0,
            lock_amount: res._4,
            btc_block_height_withdraw: res._5,
        })
    }

    async fn get_graph_data(&self, graph_id: &[u8; 16]) -> anyhow::Result<GraphData> {
        let res = self.gate_way.graphDataMap(FixedBytes::<16>::from_slice(graph_id)).call().await?;

        // TODO
        Ok(GraphData {
            stake_amount_sats: res._0,
            operator_pubkey_prefix: res._1.0[0],
            operator_pubkey: res._2.0,
            pegin_txid: res._3.0,
            kickoff_txid: res._4.0,
            take1_txid: res._5.0,
            take2_txid: res._6.0,
            assert_timeout_txid: res._7.0,
            commit_timout_txid: res._8.0,
            nack_txids: vec![],
        })
    }

    async fn post_pegin_data(
        &self,
        instance_id: &[u8; 16],
        raw_pgin_tx: &BitcoinTx,
        pegin_proof: &BitcoinTxProof,
    ) -> anyhow::Result<String> {
        let tx_request: TransactionRequest = self
            .gate_way
            .postPeginData(
                FixedBytes::<16>::from_slice(instance_id),
                raw_pgin_tx.into(),
                pegin_proof.into(),
            )
            .from(self.get_default_signer_address())
            .chain_id(self.chain_id)
            .into_transaction_request();
        let res = self.handle_transaction_request(tx_request).await?;
        Ok(res.to_string())
    }

    async fn get_btc_block_hash(&self, height: u64) -> anyhow::Result<[u8; 32]> {
        Ok(self.gate_way.getBlockHash(U256::from(height)).call().await?.0)
    }

    async fn get_initialized_ids(&self) -> anyhow::Result<Vec<(Uuid, Uuid)>> {
        let ids = self.gate_way.getInitializedInstanceIds().call().await?;
        let instance_ids: Vec<Uuid> =
            ids.retInstanceIds.iter().map(|v| Uuid::from_bytes(v.0)).collect();
        let graph_ids: Vec<Uuid> =
            ids.retGraphIds.into_iter().map(|v| Uuid::from_bytes(v.0)).collect();
        Ok(instance_ids.into_iter().zip(graph_ids.into_iter()).collect())
    }

    async fn get_instanceids_by_pubkey(
        &self,
        operator_pubkey: &[u8; 32],
    ) -> anyhow::Result<Vec<(Uuid, Uuid)>> {
        let ids = self
            .gate_way
            .getInstanceIdsByPubKey(FixedBytes::<32>::from_slice(operator_pubkey))
            .call()
            .await?;
        let instance_ids: Vec<Uuid> =
            ids.retInstanceIds.iter().map(|v| Uuid::from_bytes(v.0)).collect();
        let graph_ids: Vec<Uuid> =
            ids.retGraphIds.into_iter().map(|v| Uuid::from_bytes(v.0)).collect();
        Ok(instance_ids.into_iter().zip(graph_ids.into_iter()).collect())
    }

    async fn post_graph_data(
        &self,
        instance_id: &[u8; 16],
        graph_id: &[u8; 16],
        operator_data: &GraphData,
        committee_signs: &[u8],
    ) -> anyhow::Result<String> {
        let tx_request = self
            .gate_way
            .postGraphData(
                FixedBytes::from_slice(instance_id),
                FixedBytes::from_slice(graph_id),
                (*operator_data).clone().into(),
                Bytes::copy_from_slice(committee_signs),
            )
            .from(self.get_default_signer_address())
            .chain_id(self.chain_id)
            .into_transaction_request();

        let res = self.handle_transaction_request(tx_request).await?;
        Ok(res.to_string())
    }

    async fn init_withdraw(
        &self,
        instance_id: &[u8; 16],
        graph_id: &[u8; 16],
    ) -> anyhow::Result<String> {
        let tx_request = self
            .gate_way
            .initWithdraw(FixedBytes::from_slice(instance_id), FixedBytes::from_slice(graph_id))
            .from(self.get_default_signer_address())
            .chain_id(self.chain_id)
            .into_transaction_request();
        let tx_hash = self.handle_transaction_request(tx_request).await?;
        Ok(tx_hash.to_string())
    }

    async fn cancel_withdraw(&self, graph_id: &[u8; 16]) -> anyhow::Result<String> {
        let tx_request = self
            .gate_way
            .cancelWithdraw(FixedBytes::from_slice(graph_id))
            .from(self.get_default_signer_address())
            .chain_id(self.chain_id)
            .into_transaction_request();
        let tx_hash = self.handle_transaction_request(tx_request).await?;
        Ok(tx_hash.to_string())
    }

    async fn process_withdraw(
        &self,
        graph_id: &[u8; 16],
        raw_kickoff_tx: &BitcoinTx,
        kickoff_proof: &BitcoinTxProof,
    ) -> anyhow::Result<String> {
        let tx_request = self
            .gate_way
            .proceedWithdraw(
                FixedBytes::from_slice(graph_id),
                raw_kickoff_tx.into(),
                kickoff_proof.into(),
            )
            .from(self.get_default_signer_address())
            .chain_id(self.chain_id)
            .into_transaction_request();
        let tx_hash = self.handle_transaction_request(tx_request).await?;
        Ok(tx_hash.to_string())
    }

    async fn finish_withdraw_happy_path(
        &self,
        graph_id: &[u8; 16],
        raw_take1_tx: &BitcoinTx,
        take1_proof: &BitcoinTxProof,
    ) -> anyhow::Result<String> {
        let tx_request = self
            .gate_way
            .finishWithdrawHappyPath(
                FixedBytes::from_slice(graph_id),
                raw_take1_tx.into(),
                take1_proof.into(),
            )
            .from(self.get_default_signer_address())
            .chain_id(self.chain_id)
            .into_transaction_request();
        let tx_hash = self.handle_transaction_request(tx_request).await?;
        Ok(tx_hash.to_string())
    }

    async fn finish_withdraw_unhappy_path(
        &self,
        graph_id: &[u8; 16],
        raw_take2_tx: &BitcoinTx,
        take2_proof: &BitcoinTxProof,
    ) -> anyhow::Result<String> {
        let tx_request = self
            .gate_way
            .finishWithdrawUnhappyPath(
                FixedBytes::from_slice(graph_id),
                raw_take2_tx.into(),
                take2_proof.into(),
            )
            .from(self.get_default_signer_address())
            .chain_id(self.chain_id)
            .into_transaction_request();
        let tx_hash = self.handle_transaction_request(tx_request).await?;
        Ok(tx_hash.to_string())
    }

    async fn finish_withdraw_disproved(
        &self,
        graph_id: &[u8; 16],
        raw_disproved_tx: &BitcoinTx,
        disproved_proof: &BitcoinTxProof,
        raw_challenge_tx: &BitcoinTx,
        challenge_proof: &BitcoinTxProof,
    ) -> anyhow::Result<String> {
        let tx_request = self
            .gate_way
            .finishWithdrawDisproved(
                FixedBytes::from_slice(graph_id),
                raw_disproved_tx.into(),
                disproved_proof.into(),
                raw_challenge_tx.into(),
                challenge_proof.into(),
            )
            .from(self.get_default_signer_address())
            .chain_id(self.chain_id)
            .into_transaction_request();
        let tx_hash = self.handle_transaction_request(tx_request).await?;
        Ok(tx_hash.to_string())
    }

    async fn verify_merkle_proof(
        &self,
        root: &[u8; 32],
        proof: &[[u8; 32]],
        leaf: &[u8; 32],
        index: u64,
    ) -> anyhow::Result<bool> {
        let proof: Vec<FixedBytes<32>> =
            proof.iter().map(|v| FixedBytes::<32>::from_slice(v)).collect();
        Ok(self
            .gate_way
            .verifyMerkleProof(
                FixedBytes::from_slice(root),
                proof,
                FixedBytes::from_slice(leaf),
                U256::from(index),
            )
            .call()
            .await?)
    }

    async fn parse_btc_block_header(
        &self,
        raw_header: &[u8],
    ) -> anyhow::Result<([u8; 32], [u8; 32])> {
        let res =
            self.gate_way.parseBtcBlockHeader(Bytes::copy_from_slice(raw_header)).call().await?;
        Ok((res.blockHash.0, res.merkleRoot.0))
    }

    async fn get_tx_receipt(&self, tx_hash: &str) -> anyhow::Result<Option<TransactionReceipt>> {
        Ok(self.provider.get_transaction_receipt(TxHash::from_str(tx_hash)?).await?)
    }

    async fn get_finalized_block_number(&self) -> anyhow::Result<i64> {
        if let Some(block) = self.provider.get_block_by_number(BlockNumberOrTag::Finalized).await? {
            Ok(block.header.number as i64)
        } else {
            bail!("fail to get finalize block");
        }
    }

    async fn get_stake_amount_check_info(&self) -> anyhow::Result<(u64, u64)> {
        Ok((
            self.gate_way.minStakeAmountSats().call().await?,
            self.gate_way.stakeRate().call().await?,
        ))
    }

    async fn get_pegin_fee_check_info(&self) -> anyhow::Result<(u64, u64)> {
        Ok((
            self.gate_way.minPeginFeeSats().call().await?,
            self.gate_way.peginFeeRate().call().await?,
        ))
    }

    async fn answer_pegin_request(
        &self,
        instance_id: &[u8; 16],
        pub_key: &[u8; 32],
    ) -> anyhow::Result<String> {
        let tx_request = self
            .gate_way
            .answerPeginRequest(
                FixedBytes::from_slice(instance_id),
                FixedBytes::from_slice(pub_key),
            )
            .from(self.get_default_signer_address())
            .chain_id(self.chain_id)
            .into_transaction_request();

        let res = self.handle_transaction_request(tx_request).await?;
        Ok(res.to_string())
    }
}
impl GoatAdaptor {
    pub fn new(config: GoatInitConfig) -> Self {
        Self::from_config(config)
    }

    fn from_config(config: GoatInitConfig) -> Self {
        let chain_id = ChainId::from(config.chain_id);
        let signer = if let Some(private_key) = config.private_key {
            PrivateKeySigner::from_str(private_key.as_str())
                .expect("create signer")
                .with_chain_id(Some(chain_id))
        } else {
            PrivateKeySigner::random()
        };
        let provider = ProviderBuilder::new().connect_http(config.rpc_url);
        Self {
            _gateway_address: config.gateway_address,
            provider: provider.clone(),
            gate_way: IGateway::new(config.gateway_address, provider),
            signer: EthereumWallet::new(signer),
            chain_id,
        }
    }
}
