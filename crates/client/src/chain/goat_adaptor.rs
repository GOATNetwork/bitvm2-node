use crate::chain::chain_adaptor::{
    BitcoinTx, ChainAdaptor, OperatorData, PeginData, PeginStatus, WithdrawData, WithdrawStatus,
};
use crate::chain::goat_adaptor::IGateway::IGatewayInstance;
use alloy::primitives::TxHash;
use alloy::{
    eips::BlockNumberOrTag,
    network::{Ethereum, EthereumWallet, NetworkWallet, eip2718::Encodable2718},
    primitives::{Address as EvmAddress, Bytes, ChainId, FixedBytes, U256},
    providers::{Provider, ProviderBuilder, RootProvider},
    rpc::types::TransactionRequest,
    signers::{Signer, local::PrivateKeySigner},
    sol,
    transports::http::{Client, Http, reqwest::Url},
};
use anyhow::format_err;
use async_trait::async_trait;
use std::str::FromStr;
use uuid::Uuid;

sol!(
    #[derive(Debug)]
    #[allow(missing_docs)]
    #[sol(rpc)]
    interface IGateway {
        enum PeginStatus {
            None,
            Processing,
            Withdrawbale,
            Locked,
            Claimed
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
            bytes32 peginTxid;
            PeginStatus status;
            uint64 peginAmount;
        }
        struct WithdrawData {
            bytes32 peginTxid;
            address operatorAddress;
            WithdrawStatus status;
            bytes16 instanceId;
            uint256 lockAmount;
        }
        struct OperatorData {
            uint64 stakeAmount;
            bytes1 operatorPubkeyPrefix;
            bytes32 operatorPubkey;
            bytes32 peginTxid;
            bytes32 preKickoffTxid;
            bytes32 kickoffTxid;
            bytes32 take1Txid;
            bytes32 assertInitTxid;
            bytes32[4] assertCommitTxids;
            bytes32 assertFinalTxid;
            bytes32 take2Txid;
        }
        struct BitcoinTx {
            bytes4 version;
            bytes inputVector;
            bytes outputVector;
            bytes4 locktime;
        }

        address public  pegBTC;
        address public  bitcoinSPV;
        address public  relayer;
        mapping(bytes32 => bool) public peginTxUsed;
        mapping(bytes16 instanceId => PeginData) public peginDataMap;
        mapping(bytes16 graphId => bool) public operatorWithdrawn;
        mapping(bytes16 graphId => OperatorData) public operatorDataMap;
        mapping(bytes16 graphId => WithdrawData) public withdrawDataMap;
        bytes16[] public instanceIds;
        mapping(bytes16 instanceId => bytes16[] graphIds)
        public instanceIdToGraphIds;

        function getBlockHash(uint256 height) external view returns (bytes32);
        function parseBtcBlockHeader(bytes calldata rawHeader) public pure returns (bytes32 blockHash, bytes32 merkleRoot);
        function getInitializedInstanceIds() external view returns (bytes16[] memory retInstanceIds, bytes16[] memory retGraphIds);
        function getInstanceIdsByPubKey(bytes32 operatorPubkey) external view returns (bytes16[] memory retInstanceIds, bytes16[] memory retGraphIds);
        function getWithdrawableInstances() external view returns ( bytes16[] memory retInstanceIds, bytes16[] memory retGraphIds, uint64[] memory retPeginAmounts);
        function postPeginData(bytes16 instanceId,BitcoinTx calldata rawPeginTx, bytes calldata rawHeader, uint256 height,bytes32[] calldata proof,uint256 index) external ;
        function postOperatorData(bytes16 instanceId,bytes16 graphId,OperatorData calldata operatorData) public;
        function postOperatorDataBatch(bytes16 instanceId,bytes16[] calldata graphIds,OperatorData[] calldata operatorData) external;
        function initWithdraw(bytes16 instanceId, bytes16 graphId) external;
        function cancelWithdraw(bytes16 graphId) external;
        function proceedWithdraw(bytes16 graphId,BitcoinTx calldata rawKickoffTx, bytes calldata rawHeader, uint256 height,bytes32[] calldata proof,uint256 index) external;
        function finishWithdrawHappyPath(bytes16 graphId,BitcoinTx calldata rawTake1Tx,bytes calldata rawHeader, uint256 height,bytes32[] calldata proof,uint256 index) external;
        function finishWithdrawUnhappyPath(bytes16 graphId,BitcoinTx calldata rawTake2Tx, bytes calldata rawHeader,uint256 height,bytes32[] calldata proof,uint256 index) external;
        function finishWithdrawDisproved(bytes16 graphId,BitcoinTx calldata rawDisproveTx, bytes calldata rawHeader,uint256 height,bytes32[] calldata proof,uint256 index) external;
        function verifyMerkleProof(bytes32 root,bytes32[] memory proof,bytes32 leaf,uint256 index) public pure returns (bool);

    }
);

pub struct GoatInitConfig {
    pub rpc_url: Url,
    pub gateway_address: EvmAddress,
    pub gateway_creation_block: u64,
    pub to_block: Option<BlockNumberOrTag>,
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
            gateway_creation_block: 0,
            to_block: None,
            private_key: None,
            chain_id: 48816_u32,
        }
    }
}

pub struct GoatAdaptor {
    chain_id: ChainId,
    _gateway_address: EvmAddress,
    _gateway_creation_block: u64,
    provider: RootProvider<Http<Client>>,
    _to_block: Option<BlockNumberOrTag>,
    gate_way: IGatewayInstance<Http<Client>, RootProvider<Http<Client>>>,
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
        tx_request.gas = Some(self.provider.clone().estimate_gas(&tx_request).await?);

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
        Ok(*tx_hash)
    }
}

impl From<BitcoinTx> for IGateway::BitcoinTx {
    fn from(value: BitcoinTx) -> Self {
        Self {
            version: FixedBytes::<4>::from_slice(&value.version.to_le_bytes()),
            inputVector: Bytes::copy_from_slice(&value.input_vector),
            outputVector: Bytes::copy_from_slice(&value.output_vector),
            locktime: FixedBytes::<4>::from(value.lock_time),
        }
    }
}

impl From<OperatorData> for IGateway::OperatorData {
    fn from(value: OperatorData) -> Self {
        let mut commit_ids_arr = [FixedBytes::<32>::ZERO; 4];
        for (i, v) in (0..value.assert_commit_txids.len()).zip(value.assert_commit_txids) {
            commit_ids_arr[i] = FixedBytes::from_slice(&v);
        }
        Self {
            stakeAmount: value.stake_amount,
            operatorPubkeyPrefix: FixedBytes::from(value.operator_pubkey_prefix),
            operatorPubkey: FixedBytes::from_slice(&value.operator_pubkey),
            peginTxid: FixedBytes::from_slice(&value.pegin_txid),
            preKickoffTxid: FixedBytes::from_slice(&value.pre_kickoff_txid),
            kickoffTxid: FixedBytes::from_slice(&value.kickoff_txid),
            take1Txid: FixedBytes::from_slice(&value.take1_txid),
            assertInitTxid: FixedBytes::from_slice(&value.assert_init_txid),
            assertCommitTxids: commit_ids_arr,
            assertFinalTxid: FixedBytes::from_slice(&value.assert_final_txid),
            take2Txid: FixedBytes::from_slice(&value.take2_txid),
        }
    }
}
impl From<IGateway::OperatorData> for OperatorData {
    fn from(value: IGateway::OperatorData) -> Self {
        OperatorData {
            stake_amount: value.stakeAmount,
            operator_pubkey_prefix: value.operatorPubkeyPrefix.0[0],
            operator_pubkey: value.operatorPubkey.0,
            pegin_txid: value.peginTxid.0,
            pre_kickoff_txid: value.kickoffTxid.0,
            kickoff_txid: value.kickoffTxid.0,
            take1_txid: value.take1Txid.0,
            assert_init_txid: value.take1Txid.0,
            assert_commit_txids: value.assertCommitTxids.map(|v| v.0),
            assert_final_txid: value.assertFinalTxid.0,
            take2_txid: value.take2Txid.0,
        }
    }
}

impl From<IGateway::PeginStatus> for PeginStatus {
    fn from(value: IGateway::PeginStatus) -> Self {
        match value {
            IGateway::PeginStatus::None => PeginStatus::None,
            IGateway::PeginStatus::Processing => PeginStatus::Processing,
            IGateway::PeginStatus::Withdrawbale => PeginStatus::Withdrawbale,
            IGateway::PeginStatus::Locked => PeginStatus::Locked,
            IGateway::PeginStatus::Claimed => PeginStatus::Claimed,
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
impl From<IGateway::PeginData> for PeginData {
    fn from(value: IGateway::PeginData) -> Self {
        Self {
            pegin_txid: value.peginTxid.0,
            pegin_status: value.status.into(),
            pegin_amount: value.peginAmount,
        }
    }
}

impl From<IGateway::WithdrawData> for WithdrawData {
    fn from(value: IGateway::WithdrawData) -> Self {
        Self {
            pegin_txid: value.peginTxid.0,
            operator_address: value.operatorAddress.0.map(|v| v),
            status: value.status.into(),
            instance_id: Uuid::from_slice(value.instanceId.as_slice()).expect("decode uuid"),
            lock_amount: value.lockAmount,
        }
    }
}

#[async_trait]
impl ChainAdaptor for GoatAdaptor {
    async fn pegin_tx_used(&self, tx_id: &[u8; 32]) -> anyhow::Result<bool> {
        Ok(self.gate_way.peginTxUsed(FixedBytes::<32>::from_slice(tx_id)).call().await?._0)
    }

    async fn get_pegin_data(&self, instance_id: &Uuid) -> anyhow::Result<PeginData> {
        let res = self
            .gate_way
            .peginDataMap(FixedBytes::<16>::from_slice(instance_id.as_bytes()))
            .call()
            .await?;
        Ok(PeginData { pegin_txid: res._0.0, pegin_status: res._1.into(), pegin_amount: res._2 })
    }

    async fn is_operator_withdraw(&self, graph_id: &Uuid) -> anyhow::Result<bool> {
        Ok(self
            .gate_way
            .operatorWithdrawn(FixedBytes::<16>::from_slice(graph_id.as_bytes()))
            .call()
            .await?
            ._0)
    }

    async fn get_withdraw_data(&self, graph_id: &Uuid) -> anyhow::Result<WithdrawData> {
        let res = self
            .gate_way
            .withdrawDataMap(FixedBytes::<16>::from_slice(graph_id.as_bytes()))
            .call()
            .await?;
        Ok(WithdrawData {
            pegin_txid: res._0.0,
            operator_address: res._1.0.0,
            status: res._2.into(),
            instance_id: Uuid::from_slice(res._3.as_slice())?,
            lock_amount: res._4,
        })
    }

    async fn get_operator_data(&self, graph_id: &Uuid) -> anyhow::Result<OperatorData> {
        let res = self
            .gate_way
            .operatorDataMap(FixedBytes::<16>::from_slice(graph_id.as_bytes()))
            .call()
            .await?;

        Ok(OperatorData {
            stake_amount: res._0,
            operator_pubkey_prefix: res._1.0[0],
            operator_pubkey: res._2.0,
            pegin_txid: res._3.0,
            pre_kickoff_txid: res._4.0,
            kickoff_txid: res._5.0,
            take1_txid: res._6.0,
            assert_init_txid: res._7.0,
            assert_commit_txids: [[0; 32]; 4], // fixed later
            assert_final_txid: res._8.0,
            take2_txid: res._9.0,
        })
    }

    async fn post_pegin_data(
        &self,
        instance_id: &Uuid,
        raw_pgin_tx: &BitcoinTx,
        raw_header: &[u8],
        height: u64,
        proof: &[[u8; 32]],
        index: u64,
    ) -> anyhow::Result<()> {
        let proof: Vec<FixedBytes<32>> =
            proof.iter().map(|v| FixedBytes::<32>::from_slice(v)).collect();
        let tx_request: TransactionRequest = self
            .gate_way
            .postPeginData(
                FixedBytes::<16>::from_slice(instance_id.as_bytes()),
                (*raw_pgin_tx).clone().into(),
                Bytes::copy_from_slice(raw_header),
                U256::try_from(height)?,
                proof,
                U256::try_from(index)?,
            )
            .from(self.get_default_signer_address())
            .chain_id(self.chain_id)
            .into_transaction_request();
        let _ = self.handle_transaction_request(tx_request).await?;
        Ok(())
    }

    async fn get_btc_block_hash(&self, height: u64) -> anyhow::Result<[u8; 32]> {
        Ok(self.gate_way.getBlockHash(U256::from(height)).call().await?._0.0)
    }

    async fn get_initialized_ids(&self) -> anyhow::Result<Vec<(Uuid, Uuid)>> {
        let ids = self.gate_way.getInitializedInstanceIds().call().await?;
        let instance_ids: Vec<Uuid> =
            ids.retInstanceIds.iter().map(|v| Uuid::from_bytes(v.0)).collect();
        let graph_ids: Vec<Uuid> =
            ids.retGraphIds.into_iter().map(|v| Uuid::from_bytes(v.0)).collect();
        Ok(instance_ids.into_iter().zip(graph_ids.into_iter()).collect())
    }

    async fn post_operator_data(
        &self,
        instance_id: &Uuid,
        graph_id: &Uuid,
        operator_data: &OperatorData,
    ) -> anyhow::Result<()> {
        let tx_request = self
            .gate_way
            .postOperatorData(
                FixedBytes::from_slice(instance_id.as_bytes()),
                FixedBytes::from_slice(graph_id.as_bytes()),
                (*operator_data).clone().into(),
            )
            .from(self.get_default_signer_address())
            .chain_id(self.chain_id)
            .into_transaction_request();

        let _ = self.handle_transaction_request(tx_request).await?;
        Ok(())
    }

    async fn post_operator_data_batch(
        &self,
        instance_id: &Uuid,
        graph_ids: &[Uuid],
        operator_datas: &[OperatorData],
    ) -> anyhow::Result<()> {
        let graph_ids =
            graph_ids.iter().map(|v| FixedBytes::<16>::from_slice(&v.into_bytes())).collect();
        let operator_datas: Vec<IGateway::OperatorData> =
            operator_datas.iter().map(|v| (*v).clone().into()).collect();
        let tx_request = self
            .gate_way
            .postOperatorDataBatch(
                FixedBytes::from_slice(instance_id.as_bytes()),
                graph_ids,
                operator_datas,
            )
            .from(self.get_default_signer_address())
            .chain_id(self.chain_id)
            .into_transaction_request();
        let _ = self.handle_transaction_request(tx_request).await?;

        Ok(())
    }

    async fn init_withdraw(&self, instance_id: &Uuid, graph_id: &Uuid) -> anyhow::Result<()> {
        let tx_request = self
            .gate_way
            .initWithdraw(
                FixedBytes::from_slice(instance_id.as_bytes()),
                FixedBytes::from_slice(graph_id.as_bytes()),
            )
            .from(self.get_default_signer_address())
            .chain_id(self.chain_id)
            .into_transaction_request();
        let _ = self.handle_transaction_request(tx_request).await?;
        Ok(())
    }

    async fn cancel_withdraw(&self, graph_id: &Uuid) -> anyhow::Result<()> {
        let tx_request = self
            .gate_way
            .cancelWithdraw(FixedBytes::from_slice(graph_id.as_bytes()))
            .from(self.get_default_signer_address())
            .chain_id(self.chain_id)
            .into_transaction_request();
        let _ = self.handle_transaction_request(tx_request).await?;
        Ok(())
    }

    async fn process_withdraw(
        &self,
        graph_id: &Uuid,
        raw_kickoff_tx: &BitcoinTx,
        raw_header: &[u8],
        height: u64,
        proof: &[[u8; 32]],
        index: u64,
    ) -> anyhow::Result<()> {
        let proof: Vec<FixedBytes<32>> =
            proof.iter().map(|v| FixedBytes::<32>::from_slice(v)).collect();
        let tx_request = self
            .gate_way
            .proceedWithdraw(
                FixedBytes::from_slice(graph_id.as_bytes()),
                (*raw_kickoff_tx).clone().into(),
                Bytes::copy_from_slice(raw_header),
                U256::from(height),
                proof,
                U256::from(index),
            )
            .from(self.get_default_signer_address())
            .chain_id(self.chain_id)
            .into_transaction_request();
        let _ = self.handle_transaction_request(tx_request).await?;
        Ok(())
    }

    async fn finish_withdraw_happy_path(
        &self,
        graph_id: &Uuid,
        raw_take1_tx: &BitcoinTx,
        raw_header: &[u8],
        height: u64,
        proof: &[[u8; 32]],
        index: u64,
    ) -> anyhow::Result<()> {
        let proof: Vec<FixedBytes<32>> =
            proof.iter().map(|v| FixedBytes::<32>::from_slice(v)).collect();
        let tx_request = self
            .gate_way
            .finishWithdrawHappyPath(
                FixedBytes::from_slice(graph_id.as_bytes()),
                (*raw_take1_tx).clone().into(),
                Bytes::copy_from_slice(raw_header),
                U256::from(height),
                proof,
                U256::from(index),
            )
            .from(self.get_default_signer_address())
            .chain_id(self.chain_id)
            .into_transaction_request();
        let _ = self.handle_transaction_request(tx_request).await?;
        Ok(())
    }

    async fn finish_withdraw_unhappy_path(
        &self,
        graph_id: &Uuid,
        raw_take2_tx: &BitcoinTx,
        raw_header: &[u8],
        height: u64,
        proof: &[[u8; 32]],
        index: u64,
    ) -> anyhow::Result<()> {
        let proof: Vec<FixedBytes<32>> =
            proof.iter().map(|v| FixedBytes::<32>::from_slice(v)).collect();
        let tx_request = self
            .gate_way
            .finishWithdrawUnhappyPath(
                FixedBytes::from_slice(graph_id.as_bytes()),
                (*raw_take2_tx).clone().into(),
                Bytes::copy_from_slice(raw_header),
                U256::from(height),
                proof,
                U256::from(index),
            )
            .from(self.get_default_signer_address())
            .chain_id(self.chain_id)
            .into_transaction_request();
        let _ = self.handle_transaction_request(tx_request).await?;
        Ok(())
    }

    async fn finish_withdraw_disproved(
        &self,
        graph_id: &Uuid,
        raw_disproved_tx: &BitcoinTx,
        raw_header: &[u8],
        height: u64,
        proof: &[[u8; 32]],
        index: u64,
    ) -> anyhow::Result<()> {
        let proof: Vec<FixedBytes<32>> =
            proof.iter().map(|v| FixedBytes::<32>::from_slice(v)).collect();
        let tx_request = self
            .gate_way
            .finishWithdrawDisproved(
                FixedBytes::from_slice(graph_id.as_bytes()),
                (*raw_disproved_tx).clone().into(),
                Bytes::copy_from_slice(raw_header),
                U256::from(height),
                proof,
                U256::from(index),
            )
            .from(self.get_default_signer_address())
            .chain_id(self.chain_id)
            .into_transaction_request();
        let _ = self.handle_transaction_request(tx_request).await?;
        Ok(())
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
            .await?
            ._0)
    }

    async fn parse_btc_block_header(
        &self,
        raw_header: &[u8],
    ) -> anyhow::Result<([u8; 32], [u8; 32])> {
        let res =
            self.gate_way.parseBtcBlockHeader(Bytes::copy_from_slice(raw_header)).call().await?;
        Ok((res.blockHash.0, res.merkleRoot.0))
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
        let provider = ProviderBuilder::new().on_http(config.rpc_url);
        Self {
            _gateway_address: config.gateway_address,
            _gateway_creation_block: config.gateway_creation_block,
            provider: provider.clone(),
            _to_block: config.to_block,
            gate_way: IGateway::new(config.gateway_address, provider),
            signer: EthereumWallet::new(signer),
            chain_id,
        }
    }
}
