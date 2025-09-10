use crate::goat_chain::chain_adaptor::{
    BitcoinTx, BitcoinTxProof, ChainAdaptor, GraphData, PeginData, PeginStatus, SequencerSet, Utxo,
    WithdrawData, WithdrawStatus,
};
use crate::goat_chain::goat_adaptor::ICommitteeManagement::ICommitteeManagementInstance;
use crate::goat_chain::goat_adaptor::IGateway::IGatewayInstance;
use crate::goat_chain::goat_adaptor::ISequencerSetPublisher::ISequencerSetPublisherInstance;
use crate::goat_chain::goat_adaptor::IStakeManagement::IStakeManagementInstance;
use alloy::eips::BlockNumberOrTag;
use alloy::primitives::{Address, TxHash};
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
use uuid::Uuid;

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

        struct Utxo {
             bytes32 txid;
             uint32 vout;
             uint64 amountSats;
        }

        struct PeginData {
             PeginStatus status;
             bytes16 instanceId;
             address depositorAddress;
             uint64 peginAmountSats;
             uint64[3] txnFees;
             Utxo[] userInputs;
             bytes32 userXonlyPubkey;
             string userChangeAddress;
             string userRefundAddress;
             bytes32 peginTxid;
             uint256 createdAt;
             address[] committeeAddresses;
             bytes32[] committeeXonlyPubkeys;
        }
        struct WithdrawData {
            WithdrawStatus status;
            bytes32 peginTxid;
            address operatorAddress;
            bytes16 instanceId;
            uint256 lockAmount;
            uint256 btcBlockHeightAtWithdraw;
        }

        struct GraphData {
            bytes1 operatorPubkeyPrefix;
            bytes32 operatorPubkey;
            bytes32 peginTxid;
            bytes32 kickoffTxid;
            bytes32 take1Txid;
            bytes32 take2Txid;
            bytes32 commitTimoutTxid;
            bytes32[] assertTimoutTxids;
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

        // uint64 constant rateMultiplier = 10000;

        uint64 public minChallengeAmountSats;
        uint64 public minPeginFeeSats;
        uint64 public peginFeeRate;
        uint64 public minOperatorRewardSats;
        uint64 public operatorRewardRate;
        uint64 public minStakeAmount;
        uint64 public minChallengerReward;
        uint64 public minDisproverReward;
        uint64 public minSlashAmount;

        address public  pegBTC;
        address public  bitcoinSPV;
        address public  committeeManagement;
        address public  stakeManagement;

        uint256 public responseWindowBlocks;
        bytes16[] public instanceIds;
        mapping(bytes16 graphId => GraphData) public graphDataMap;
        mapping(bytes16 graphId => WithdrawData) public withdrawDataMap;
        mapping(bytes16 instanceId => bytes16[] graphIds)
        public instanceIdToGraphIds;

        function getBlockHash(uint256 height) external view returns (bytes32);
        function parseBtcBlockHeader(bytes calldata rawHeader) public pure returns (bytes32 blockHash, bytes32 merkleRoot);

        function postPeginRequest(bytes16 instanceId, uint64 peginAmountSats, uint64[3] calldata txnFees, address receiverAddress, Utxo[] calldata userInputs, bytes32 userXonlyPubkey, string calldata userChangeAddress, string calldata userRefundAddress) external payable;
        function answerPeginRequest(bytes16 instanceId, bytes32 committeeXonlyPubkey) onlyCommittee() external;
        function postPeginData(bytes16 instanceId, BitcoinTx calldata rawPeginTx, BitcoinTxProof calldata peginProof, bytes[] calldata committeeSigs) external;
        function getPeginData(bytes16 instanceId) external view returns (PeginData memory);
        function postGraphData(bytes16 instanceId, bytes16 graphId, GraphData calldata graphData, bytes[] calldata committeeSigs) public;
        function getGraphData(bytes16 graphId) external view returns (GraphData memory);
        function initWithdraw(bytes16 instanceId, bytes16 graphId) external;
        function cancelWithdraw(bytes16 graphId) external;
        function proceedWithdraw(bytes16 graphId, BitcoinTx calldata rawKickoffTx, BitcoinTxProof calldata kickoffProof) external;
        function finishWithdrawHappyPath(bytes16 graphId, BitcoinTx calldata rawTake1Tx, BitcoinTxProof calldata take1Proof) external;
        function finishWithdrawUnhappyPath(bytes16 graphId, BitcoinTx calldata rawTake2Tx, BitcoinTxProof calldata take2Proof) external;
        function finishWithdrawDisproved(bytes16 graphId, BitcoinTx calldata rawDisproveTx, BitcoinTxProof calldata disproveProof, BitcoinTx calldata rawChallengeTx, BitcoinTxProof calldata ngeCProof) external;
        function verifyMerkleProof(bytes32 root,bytes32[] memory proof, bytes32 leaf,uint256 index) public pure returns (bool);

        // Contract is not implements this functions, do something later
        function getInitializedInstanceIds() external view returns (bytes16[] memory retInstanceIds, bytes16[] memory retGraphIds);
        function getInstanceIdsByPubKey(bytes32 operatorPubkey) external view returns (bytes16[] memory retInstanceIds, bytes16[] memory retGraphIds);
    }
);

sol!(
    #[derive(Debug)]
    #[allow(missing_docs)]
    #[sol(rpc)]
    interface ISequencerSetPublisher {
        struct SequencerSet {
            bytes32 sequencer_set_hash; // validator_hash
            bytes32 publishers_hash;
            bytes32 p2wsh_sig_hash;
            bytes32 next_sequencer_set_hash; // next_validator_hash
            uint256 goat_block_number;
        }
        uint256 public latest_height;
        function updateSequencerSet(SequencerSet calldata ss,  bytes calldata signature) external;
        function updatePublisherSet(address[] calldata newOwners, bytes[] calldata changeOwnerSigs, SequencerSet calldata ss, bytes calldata sequencerSetCmtSigs) external;
    }
);

sol!(
    #[derive(Debug)]
    #[allow(missing_docs)]
    #[sol(rpc)]
    interface IStakeManagement {
        function stakeTokenAddress() external view returns (address);
        function pubkeyToAddress(bytes32 pubkey) external view returns (address); // XOnlyPubkey
        function stakeOf(address operator) external view returns (uint256);
        function lockedStakeOf(address operator) external view returns (uint256);
        function slashStake(address operator, uint256 amount) external;
        function lockStake(address operator, uint256 amount) external;
        function unlockStake(address operator, uint256 amount) external;
    }
);

sol!(
    #[derive(Debug)]
    #[allow(missing_docs)]
    #[sol(rpc)]
    interface ICommitteeManagement {
        function isCommitteeMember(address member) external view returns (bool);
        function committeeSize() external view returns (uint256);
        function quorumSize() external view returns (uint256);
        function verifySignatures(bytes32 msgHash, bytes[] memory signatures) external view returns (bool);
    }
);

pub struct GoatInitConfig {
    pub rpc_url: Url,
    pub private_key: Option<String>,
    pub chain_id: u32,
    pub gateway_address: Option<EvmAddress>,
    pub sequencer_set_publisher_address: Option<EvmAddress>,
    pub committee_management_address: Option<EvmAddress>,
    pub stake_management_address: Option<EvmAddress>,
}

impl GoatInitConfig {
    pub fn from_env_for_test() -> Self {
        GoatInitConfig {
            rpc_url: "https://rpc.testnet3.goat.network".parse::<Url>().expect("decode url"),
            chain_id: 48816_u32,
            private_key: None,
            gateway_address: Some(
                "0xeD8AeeD334fA446FA03Aa00B28aFf02FA8aC02df"
                    .parse()
                    .expect("parse contract address"),
            ),
            sequencer_set_publisher_address: None,
            committee_management_address: None,
            stake_management_address: None,
        }
    }
}

pub struct GoatAdaptor {
    chain_id: ChainId,
    signer: EthereumWallet,
    provider: FillProvider<
        JoinFill<Identity, <Ethereum as RecommendedFillers>::RecommendedFillers>,
        RootProvider,
    >,
    gateway: Option<
        IGatewayInstance<
            FillProvider<
                JoinFill<Identity, <Ethereum as RecommendedFillers>::RecommendedFillers>,
                RootProvider,
            >,
        >,
    >,
    sequencer_set_publisher: Option<
        ISequencerSetPublisherInstance<
            FillProvider<
                JoinFill<Identity, <Ethereum as RecommendedFillers>::RecommendedFillers>,
                RootProvider,
            >,
        >,
    >,
    committee_management: Option<
        ICommitteeManagementInstance<
            FillProvider<
                JoinFill<Identity, <Ethereum as RecommendedFillers>::RecommendedFillers>,
                RootProvider,
            >,
        >,
    >,
    stake_management: Option<
        IStakeManagementInstance<
            FillProvider<
                JoinFill<Identity, <Ethereum as RecommendedFillers>::RecommendedFillers>,
                RootProvider,
            >,
        >,
    >,
}

impl GoatAdaptor {
    #[allow(unused)]
    fn get_price_amend(&self, price: u128) -> u128 {
        price
    }

    fn get_gateway(
        &self,
    ) -> anyhow::Result<
        &IGatewayInstance<
            FillProvider<
                JoinFill<Identity, <Ethereum as RecommendedFillers>::RecommendedFillers>,
                RootProvider,
            >,
        >,
    > {
        self.gateway.as_ref().ok_or_else(|| anyhow::anyhow!("Gateway not initialized"))
    }

    fn get_sequencer_set_publisher(
        &self,
    ) -> anyhow::Result<
        &ISequencerSetPublisherInstance<
            FillProvider<
                JoinFill<Identity, <Ethereum as RecommendedFillers>::RecommendedFillers>,
                RootProvider,
            >,
        >,
    > {
        self.sequencer_set_publisher
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("SequencerSetPublisher not initialized"))
    }

    fn get_committee_management(
        &self,
    ) -> anyhow::Result<
        &ICommitteeManagementInstance<
            FillProvider<
                JoinFill<Identity, <Ethereum as RecommendedFillers>::RecommendedFillers>,
                RootProvider,
            >,
        >,
    > {
        self.committee_management
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("CommitteeMnagement not initialized"))
    }

    fn get_stake_management(
        &self,
    ) -> anyhow::Result<
        &IStakeManagementInstance<
            FillProvider<
                JoinFill<Identity, <Ethereum as RecommendedFillers>::RecommendedFillers>,
                RootProvider,
            >,
        >,
    > {
        self.stake_management
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("StakeManagement not initialized"))
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

impl From<&IGateway::Utxo> for Utxo {
    fn from(value: &IGateway::Utxo) -> Self {
        Self { txid: value.txid.0, vout: value.vout, amount_stats: value.amountSats }
    }
}

impl From<&Utxo> for IGateway::Utxo {
    fn from(value: &Utxo) -> Self {
        Self {
            txid: FixedBytes::from_slice(&value.txid),
            vout: value.vout,
            amountSats: value.amount_stats,
        }
    }
}

impl From<IGateway::PeginData> for PeginData {
    fn from(value: IGateway::PeginData) -> Self {
        Self {
            status: value.status.into(),
            instance_id: value.instanceId.0,
            depositor_address: value.depositorAddress.into_array(),
            pegin_amount_sats: value.peginAmountSats,

            txn_fees: value.txnFees,
            user_inputs: value.userInputs.iter().map(|v| v.into()).collect(),
            user_xonly_pubkey: value.userXonlyPubkey.0,
            user_change_addr: value.userChangeAddress,
            user_refund_addr: value.userRefundAddress,
            pegin_txid: value.peginTxid.0,
            created_at: value.createdAt.try_into().expect("failed to convert created"),
            committee_addresses: value.committeeAddresses.to_vec(),
            committee_xonly_pubkeys: value
                .committeeXonlyPubkeys
                .into_iter()
                .map(|pubkey| pubkey.0)
                .collect(),
        }
    }
}
impl From<GraphData> for IGateway::GraphData {
    fn from(value: GraphData) -> Self {
        Self {
            operatorPubkeyPrefix: FixedBytes::from(value.operator_pubkey_prefix),
            operatorPubkey: FixedBytes::from_slice(&value.operator_pubkey),
            peginTxid: FixedBytes::from_slice(&value.pegin_txid),
            kickoffTxid: FixedBytes::from_slice(&value.kickoff_txid),
            take1Txid: FixedBytes::from_slice(&value.take1_txid),
            take2Txid: FixedBytes::from_slice(&value.take2_txid),
            commitTimoutTxid: FixedBytes::from_slice(&value.commit_timout_txid),
            assertTimoutTxids: value
                .assert_timeout_txids
                .into_iter()
                .map(|txid| FixedBytes::from_slice(&txid))
                .collect::<Vec<_>>(),
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
            // stake_amount_sats: value.stakeAmountSats,
            operator_pubkey_prefix: value.operatorPubkeyPrefix.0[0],
            operator_pubkey: value.operatorPubkey.0,
            pegin_txid: value.peginTxid.0,
            kickoff_txid: value.kickoffTxid.0,
            take1_txid: value.take1Txid.0,
            take2_txid: value.take2Txid.0,
            commit_timout_txid: value.commitTimoutTxid.0,
            assert_timeout_txids: value
                .assertTimoutTxids
                .into_iter()
                .map(|txid| txid.into())
                .collect(),
            nack_txids: value.NackTxids.into_iter().map(|txid| txid.into()).collect(),
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

impl From<&SequencerSet> for ISequencerSetPublisher::SequencerSet {
    fn from(value: &SequencerSet) -> Self {
        Self {
            sequencer_set_hash: FixedBytes::from_slice(&value.sequencer_set_hash),
            publishers_hash: FixedBytes::from_slice(&value.publishers_hash),
            p2wsh_sig_hash: FixedBytes::from_slice(&value.p2wsh_sig_hash),
            next_sequencer_set_hash: FixedBytes::from_slice(&value.next_sequencer_set_hash),
            goat_block_number: U256::from(value.goat_block_number),
        }
    }
}

#[async_trait]
impl ChainAdaptor for GoatAdaptor {
    fn get_default_signer_address(&self) -> EvmAddress {
        <EthereumWallet as NetworkWallet<Ethereum>>::default_signer_address(&self.signer)
    }

    async fn get_finalized_block_number(&self) -> anyhow::Result<i64> {
        if let Some(block) = self.provider.get_block_by_number(BlockNumberOrTag::Finalized).await? {
            Ok(block.header.number as i64)
        } else {
            bail!("fail to get finalize block");
        }
    }

    async fn get_latest_block_number(&self) -> anyhow::Result<i64> {
        if let Some(block) = self.provider.get_block_by_number(BlockNumberOrTag::Latest).await? {
            Ok(block.header.number as i64)
        } else {
            bail!("fail to get latest block");
        }
    }

    async fn get_tx_receipt(&self, tx_hash: &str) -> anyhow::Result<Option<TransactionReceipt>> {
        Ok(self.provider.get_transaction_receipt(TxHash::from_str(tx_hash)?).await?)
    }

    async fn gateway_get_min_challenge_amount_sats(&self) -> anyhow::Result<u64> {
        let gateway = self.get_gateway()?;
        Ok(gateway.minChallengeAmountSats().call().await?)
    }

    async fn gateway_get_min_pegin_fee_sats(&self) -> anyhow::Result<u64> {
        let gateway = self.get_gateway()?;
        Ok(gateway.minPeginFeeSats().call().await?)
    }

    async fn gateway_get_pegin_fee_rate(&self) -> anyhow::Result<u64> {
        let gateway = self.get_gateway()?;
        Ok(gateway.peginFeeRate().call().await?)
    }

    async fn gateway_get_min_operator_reward_sats(&self) -> anyhow::Result<u64> {
        let gateway = self.get_gateway()?;
        Ok(gateway.minOperatorRewardSats().call().await?)
    }

    async fn gateway_get_operator_reward_rate(&self) -> anyhow::Result<u64> {
        let gateway = self.get_gateway()?;
        Ok(gateway.operatorRewardRate().call().await?)
    }

    async fn gateway_get_min_stake_amount(&self) -> anyhow::Result<u64> {
        let gateway = self.get_gateway()?;
        Ok(gateway.minStakeAmount().call().await?)
    }

    async fn gateway_get_min_challenger_reward(&self) -> anyhow::Result<u64> {
        let gateway = self.get_gateway()?;
        Ok(gateway.minChallengerReward().call().await?)
    }

    async fn gateway_get_min_disprover_reward(&self) -> anyhow::Result<u64> {
        let gateway = self.get_gateway()?;
        Ok(gateway.minDisproverReward().call().await?)
    }

    async fn gateway_get_min_slash_amount(&self) -> anyhow::Result<u64> {
        let gateway = self.get_gateway()?;
        Ok(gateway.minSlashAmount().call().await?)
    }

    async fn gateway_get_committee_management(&self) -> anyhow::Result<[u8; 20]> {
        let gateway = self.get_gateway()?;
        Ok(gateway.committeeManagement().call().await?.into_array())
    }

    async fn gateway_get_stake_management(&self) -> anyhow::Result<[u8; 20]> {
        let gateway = self.get_gateway()?;
        Ok(gateway.stakeManagement().call().await?.into_array())
    }

    async fn gateway_get_pegin_data(&self, instance_id: &[u8; 16]) -> anyhow::Result<PeginData> {
        let gateway = self.get_gateway()?;
        Ok(gateway.getPeginData(FixedBytes::<16>::from_slice(instance_id)).call().await?.into())
    }

    async fn gateway_get_withdraw_data(&self, graph_id: &[u8; 16]) -> anyhow::Result<WithdrawData> {
        let gateway = self.get_gateway()?;
        let res = gateway.withdrawDataMap(FixedBytes::<16>::from_slice(graph_id)).call().await?;
        Ok(WithdrawData {
            status: res._0.into(),
            pegin_txid: res._1.0,
            operator_address: res._2.0.0,
            instance_id: res._3.0,
            lock_amount: res._4,
            btc_block_height_withdraw: res._5,
        })
    }

    async fn gateway_get_graph_data(&self, graph_id: &[u8; 16]) -> anyhow::Result<GraphData> {
        let gateway = self.get_gateway()?;
        Ok(gateway.getGraphData(FixedBytes::<16>::from_slice(graph_id)).call().await?.into())
    }

    async fn gateway_get_response_window_blocks(&self) -> anyhow::Result<u64> {
        let gateway = self.get_gateway()?;
        Ok(gateway.responseWindowBlocks().call().await?.try_into()?)
    }

    async fn gateway_post_pegin_request(
        &self,
        instance_id: &[u8; 16],
        pegin_amount_sats: u64,
        tx_fees: &[u64; 3],
        receiver_addr: &[u8; 20],
        user_inputs: &[Utxo],
        user_xonly_pubkey: &[u8; 32],
        user_change_addr: &str,
        user_refund_addr: &str,
    ) -> anyhow::Result<String> {
        let gateway = self.get_gateway()?;
        let user_inputs: Vec<IGateway::Utxo> = user_inputs.iter().map(|u| u.into()).collect();
        let tx_request = gateway
            .postPeginRequest(
                FixedBytes::from_slice(instance_id),
                pegin_amount_sats,
                tx_fees.clone(),
                Address::from_slice(receiver_addr),
                user_inputs,
                FixedBytes::from_slice(user_xonly_pubkey),
                user_change_addr.to_string(),
                user_refund_addr.to_string(),
            )
            .from(self.get_default_signer_address())
            .chain_id(self.chain_id)
            .into_transaction_request();
        let res = self.handle_transaction_request(tx_request).await?;
        Ok(res.to_string())
    }

    async fn gateway_answer_pegin_request(
        &self,
        instance_id: &[u8; 16],
        committee_xonly_pubkey: &[u8; 32],
    ) -> anyhow::Result<String> {
        let gateway = self.get_gateway()?;
        let tx_request = gateway
            .answerPeginRequest(
                FixedBytes::from_slice(instance_id),
                FixedBytes::from_slice(committee_xonly_pubkey),
            )
            .from(self.get_default_signer_address())
            .chain_id(self.chain_id)
            .into_transaction_request();

        let res = self.handle_transaction_request(tx_request).await?;
        Ok(res.to_string())
    }

    async fn gateway_post_pegin_data(
        &self,
        instance_id: &[u8; 16],
        raw_pgin_tx: &BitcoinTx,
        pegin_proof: &BitcoinTxProof,
        committee_signs: &[Vec<u8>],
    ) -> anyhow::Result<String> {
        let gateway = self.get_gateway()?;
        let signs: Vec<Bytes> = committee_signs.iter().map(|v| Bytes::copy_from_slice(v)).collect();
        let tx_request: TransactionRequest = gateway
            .postPeginData(
                FixedBytes::<16>::from_slice(instance_id),
                raw_pgin_tx.into(),
                pegin_proof.into(),
                signs,
            )
            .from(self.get_default_signer_address())
            .chain_id(self.chain_id)
            .into_transaction_request();
        let res = self.handle_transaction_request(tx_request).await?;
        Ok(res.to_string())
    }

    async fn gateway_post_graph_data(
        &self,
        instance_id: &[u8; 16],
        graph_id: &[u8; 16],
        operator_data: &GraphData,
        committee_signs: &[Vec<u8>],
    ) -> anyhow::Result<String> {
        let gateway = self.get_gateway()?;
        let signs: Vec<Bytes> = committee_signs.iter().map(|v| Bytes::copy_from_slice(v)).collect();
        let tx_request = gateway
            .postGraphData(
                FixedBytes::from_slice(instance_id),
                FixedBytes::from_slice(graph_id),
                (*operator_data).clone().into(),
                signs,
            )
            .from(self.get_default_signer_address())
            .chain_id(self.chain_id)
            .into_transaction_request();

        let res = self.handle_transaction_request(tx_request).await?;
        Ok(res.to_string())
    }

    async fn gateway_get_btc_block_hash(&self, height: u64) -> anyhow::Result<[u8; 32]> {
        let gateway = self.get_gateway()?;
        Ok(gateway.getBlockHash(U256::from(height)).call().await?.0)
    }

    async fn gateway_parse_btc_block_header(
        &self,
        raw_header: &[u8],
    ) -> anyhow::Result<([u8; 32], [u8; 32])> {
        let gateway = self.get_gateway()?;
        let res = gateway.parseBtcBlockHeader(Bytes::copy_from_slice(raw_header)).call().await?;
        Ok((res.blockHash.0, res.merkleRoot.0))
    }

    async fn gateway_get_initialized_ids(&self) -> anyhow::Result<Vec<(Uuid, Uuid)>> {
        let gateway = self.get_gateway()?;
        let ids = gateway.getInitializedInstanceIds().call().await?;
        let instance_ids: Vec<Uuid> =
            ids.retInstanceIds.iter().map(|v| Uuid::from_bytes(v.0)).collect();
        let graph_ids: Vec<Uuid> =
            ids.retGraphIds.into_iter().map(|v| Uuid::from_bytes(v.0)).collect();
        Ok(instance_ids.into_iter().zip(graph_ids).collect())
    }

    async fn gateway_get_instanceids_by_pubkey(
        &self,
        operator_pubkey: &[u8; 32],
    ) -> anyhow::Result<Vec<(Uuid, Uuid)>> {
        let gateway = self.get_gateway()?;
        let ids = gateway
            .getInstanceIdsByPubKey(FixedBytes::<32>::from_slice(operator_pubkey))
            .call()
            .await?;
        let instance_ids: Vec<Uuid> =
            ids.retInstanceIds.iter().map(|v| Uuid::from_bytes(v.0)).collect();
        let graph_ids: Vec<Uuid> =
            ids.retGraphIds.into_iter().map(|v| Uuid::from_bytes(v.0)).collect();
        Ok(instance_ids.into_iter().zip(graph_ids).collect())
    }

    async fn gateway_init_withdraw(
        &self,
        instance_id: &[u8; 16],
        graph_id: &[u8; 16],
    ) -> anyhow::Result<String> {
        let gateway = self.get_gateway()?;
        let tx_request = gateway
            .initWithdraw(FixedBytes::from_slice(instance_id), FixedBytes::from_slice(graph_id))
            .from(self.get_default_signer_address())
            .chain_id(self.chain_id)
            .into_transaction_request();
        let tx_hash = self.handle_transaction_request(tx_request).await?;
        Ok(tx_hash.to_string())
    }

    async fn gateway_cancel_withdraw(&self, graph_id: &[u8; 16]) -> anyhow::Result<String> {
        let gateway = self.get_gateway()?;
        let tx_request = gateway
            .cancelWithdraw(FixedBytes::from_slice(graph_id))
            .from(self.get_default_signer_address())
            .chain_id(self.chain_id)
            .into_transaction_request();
        let tx_hash = self.handle_transaction_request(tx_request).await?;
        Ok(tx_hash.to_string())
    }

    async fn gateway_process_withdraw(
        &self,
        graph_id: &[u8; 16],
        raw_kickoff_tx: &BitcoinTx,
        kickoff_proof: &BitcoinTxProof,
    ) -> anyhow::Result<String> {
        let gateway = self.get_gateway()?;
        let tx_request = gateway
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

    async fn gateway_finish_withdraw_happy_path(
        &self,
        graph_id: &[u8; 16],
        raw_take1_tx: &BitcoinTx,
        take1_proof: &BitcoinTxProof,
    ) -> anyhow::Result<String> {
        let gateway = self.get_gateway()?;
        let tx_request = gateway
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

    async fn gateway_finish_withdraw_unhappy_path(
        &self,
        graph_id: &[u8; 16],
        raw_take2_tx: &BitcoinTx,
        take2_proof: &BitcoinTxProof,
    ) -> anyhow::Result<String> {
        let gateway = self.get_gateway()?;
        let tx_request = gateway
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

    async fn gateway_finish_withdraw_disproved(
        &self,
        graph_id: &[u8; 16],
        raw_disproved_tx: &BitcoinTx,
        disproved_proof: &BitcoinTxProof,
        raw_challenge_tx: &BitcoinTx,
        challenge_proof: &BitcoinTxProof,
    ) -> anyhow::Result<String> {
        let gateway = self.get_gateway()?;
        let tx_request = gateway
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

    async fn gateway_verify_merkle_proof(
        &self,
        root: &[u8; 32],
        proof: &[[u8; 32]],
        leaf: &[u8; 32],
        index: u64,
    ) -> anyhow::Result<bool> {
        let gateway = self.get_gateway()?;
        let proof: Vec<FixedBytes<32>> =
            proof.iter().map(|v| FixedBytes::<32>::from_slice(v)).collect();
        Ok(gateway
            .verifyMerkleProof(
                FixedBytes::from_slice(root),
                proof,
                FixedBytes::from_slice(leaf),
                U256::from(index),
            )
            .call()
            .await?)
    }

    async fn seq_set_pub_get_last_block_height(&self) -> anyhow::Result<u64> {
        let sequencer_set_publisher = self.get_sequencer_set_publisher()?;
        Ok(sequencer_set_publisher.latest_height().call().await?.try_into()?)
    }

    async fn seq_set_pub_update_sequencer_set(
        &self,
        sequencer_set: &SequencerSet,
        signature: &[u8],
    ) -> anyhow::Result<String> {
        let sequencer_set_publisher = self.get_sequencer_set_publisher()?;
        let tx_request = sequencer_set_publisher
            .updateSequencerSet(sequencer_set.into(), Bytes::copy_from_slice(signature))
            .from(self.get_default_signer_address())
            .chain_id(self.chain_id)
            .into_transaction_request();
        let tx_hash = self.handle_transaction_request(tx_request).await?;
        Ok(tx_hash.to_string())
    }

    async fn seq_set_pub_update_publisher_set(
        &self,
        new_owners: &[[u8; 20]],
        signatures: &[Vec<u8>],
        sequencer_set: &SequencerSet,
        sequencer_set_cmt_sigs: &[u8],
    ) -> anyhow::Result<String> {
        let sequencer_set_publisher = self.get_sequencer_set_publisher()?;
        let new_owners: Vec<EvmAddress> =
            new_owners.iter().map(|v| EvmAddress::from_slice(v)).collect();
        let signatures: Vec<Bytes> = signatures.iter().map(|v| Bytes::copy_from_slice(v)).collect();

        let tx_request = sequencer_set_publisher
            .updatePublisherSet(
                new_owners,
                signatures,
                sequencer_set.into(),
                Bytes::copy_from_slice(sequencer_set_cmt_sigs),
            )
            .from(self.get_default_signer_address())
            .chain_id(self.chain_id)
            .into_transaction_request();
        let tx_hash = self.handle_transaction_request(tx_request).await?;
        Ok(tx_hash.to_string())
    }

    async fn stake_mana_stake_token_address(&self) -> anyhow::Result<[u8; 20]> {
        let stake_management = self.get_stake_management()?;
        Ok(stake_management.stakeTokenAddress().call().await?.into_array())
    }

    async fn stake_mana_pubkey_to_address(&self, pubkey: &[u8; 32]) -> anyhow::Result<[u8; 20]> {
        let stake_management = self.get_stake_management()?;
        Ok(stake_management
            .pubkeyToAddress(FixedBytes::from_slice(pubkey))
            .call()
            .await?
            .into_array())
    }

    async fn stake_mana_stake_of(&self, operator: &[u8; 20]) -> anyhow::Result<u64> {
        let stake_management = self.get_stake_management()?;
        Ok(stake_management
            .stakeOf(Address::from_slice(operator))
            .call()
            .await?
            .try_into()
            .map_err(|e| anyhow::anyhow!("StakeOf error :{e:?}"))?)
    }

    async fn stake_mana_lock_stake_of(&self, operator: &[u8; 20]) -> anyhow::Result<u64> {
        let stake_management = self.get_stake_management()?;
        Ok(stake_management
            .lockedStakeOf(Address::from_slice(operator))
            .call()
            .await?
            .try_into()
            .map_err(|e| anyhow::anyhow!("StakeOf error :{e:?}"))?)
    }

    async fn stake_mana_slash_stake(
        &self,
        operator: &[u8; 20],
        amount: u64,
    ) -> anyhow::Result<String> {
        let stake_management = self.get_stake_management()?;
        let tx_request = stake_management
            .slashStake(Address::from_slice(operator), U256::from(amount))
            .from(self.get_default_signer_address())
            .chain_id(self.chain_id)
            .into_transaction_request();
        let tx_hash = self.handle_transaction_request(tx_request).await?;
        Ok(tx_hash.to_string())
    }

    async fn stake_mana_lock_stake(
        &self,
        operator: &[u8; 20],
        amount: u64,
    ) -> anyhow::Result<String> {
        let stake_management = self.get_stake_management()?;
        let tx_request = stake_management
            .lockStake(Address::from_slice(operator), U256::from(amount))
            .from(self.get_default_signer_address())
            .chain_id(self.chain_id)
            .into_transaction_request();
        let tx_hash = self.handle_transaction_request(tx_request).await?;
        Ok(tx_hash.to_string())
    }

    async fn stake_mana_unlock_stake(
        &self,
        operator: &[u8; 20],
        amount: u64,
    ) -> anyhow::Result<String> {
        let stake_management = self.get_stake_management()?;
        let tx_request = stake_management
            .unlockStake(Address::from_slice(operator), U256::from(amount))
            .from(self.get_default_signer_address())
            .chain_id(self.chain_id)
            .into_transaction_request();
        let tx_hash = self.handle_transaction_request(tx_request).await?;
        Ok(tx_hash.to_string())
    }

    async fn committee_mana_is_committee_member(&self, member: &[u8; 20]) -> anyhow::Result<bool> {
        let committee_management = self.get_committee_management()?;
        Ok(committee_management.isCommitteeMember(Address::from_slice(member)).call().await?)
    }

    async fn committee_mana_committee_size(&self) -> anyhow::Result<u64> {
        let committee_management = self.get_committee_management()?;
        Ok(committee_management
            .committeeSize()
            .call()
            .await?
            .try_into()
            .map_err(|e| anyhow::anyhow!("StakeOf error :{e:?}"))?)
    }

    async fn committee_mana_quorum_size(&self) -> anyhow::Result<u64> {
        let committee_management = self.get_committee_management()?;
        Ok(committee_management
            .quorumSize()
            .call()
            .await?
            .try_into()
            .map_err(|e| anyhow::anyhow!("StakeOf error :{e:?}"))?)
    }

    async fn committee_mana_verify_signatures(
        &self,
        msg_hash: &[u8; 32],
        signs: &[Vec<u8>],
    ) -> anyhow::Result<bool> {
        let committee_management = self.get_committee_management()?;
        let signatures: Vec<Bytes> = signs.iter().map(|v| Bytes::copy_from_slice(v)).collect();
        Ok(committee_management
            .verifySignatures(FixedBytes::from_slice(msg_hash), signatures)
            .call()
            .await?
            .try_into()
            .map_err(|e| anyhow::anyhow!("StakeOf error :{e:?}"))?)
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
            chain_id,
            signer: EthereumWallet::new(signer),
            provider: provider.clone(),
            gateway: config.gateway_address.map(|addr| IGateway::new(addr, provider.clone())),
            sequencer_set_publisher: config
                .sequencer_set_publisher_address
                .map(|addr| ISequencerSetPublisher::new(addr, provider.clone())),
            committee_management: config
                .committee_management_address
                .map(|addr| ICommitteeManagement::new(addr, provider.clone())),
            stake_management: config
                .stake_management_address
                .map(|addr| IStakeManagement::new(addr, provider.clone())),
        }
    }
}
