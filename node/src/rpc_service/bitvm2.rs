use super::utils::{deserialize_u256, serialize_u256};
use crate::rpc_service::current_time_secs;
use crate::scheduled_tasks::graph_maintenance_tasks::{
    AssertCommitStatus, ChallengeSubStatus, WatchtowerChallengeStatus,
};
use crate::utils::{check_bridge_in_uxto_available_or_self_spent, reflect_goat_address};
use alloy::hex::ToHexExt;
use alloy::primitives::U256;
use bitcoin::Txid;
use client::Utxo;
use client::btc_chain::BTCClient;
use indexmap::IndexMap;
use serde::{Deserialize, Serialize};
use std::default::Default;
use std::str::FromStr;
use store::localdb::GraphQuery;
use store::{
    ByteArray32, Graph, GraphStatus, Instance, InstanceBridgeInStatus, InstanceBridgeOutStatus,
    ProofState, SerializableTxid, UInt64Array3,
};
use strum::{Display, EnumString};
use tracing::warn;
use uuid::Uuid;

pub const WATCHTOWER_CHALLENGE_STEP_INIT: &str = "Watchtower Challenge init";
pub const WATCHTOWER_CHALLENGE_STEP_CHALLENGE: &str = "Watchtower Challenge";
pub const WATCHTOWER_CHALLENGE_STEP_CHALLENGE_TIMEOUT: &str = "Watchtower Challenge Timeout";
pub const WATCHTOWER_CHALLENGE_STEP_ACK: &str = "Operator Challenge ACK";
pub const WATCHTOWER_CHALLENGE_STEP_COMMIT_BLOCKHASH: &str = "Operator Commit BlockHash";
pub const WATCHTOWER_CHALLENGE_STEP_COMMIT_BLOCKHASH_TIMEOUT: &str =
    "Operator Commit BlockHash Timeout";
pub const ASSERT_STEP_INIT: &str = "Assert init";
pub const ASSERT_STEP_COMMIT: &str = "Assert Commit";

const BRIDGE_IN_FAIL_AS_UTXO_BEEN_SPENT: &str = "Your UTXO has already been spent.";
// const BRIDGE_IN_FAIL_AS_NO_ENOUGH_COMMITTEES: &str = "Unfortunately, no enough committee answered.";
const BRIDGE_IN_FAIL_AS_PRESIGNED_FAILED: &str = "Unfortunately, the presigned failed.";
const BRIDGE_IN_FAIL_AS_VERIFICATION_FAILED: &str = "Unfortunately, the verification failed.";

const BRIDGE_IN_FAIL_AS_L2_MINTED_FAILED: &str = "Unfortunately, PegBTC minted failed.";

const BRIDGE_IN_FAIL_AS_TIMEOUT: &str = "The operation timed out. Please try again.";
const _BRIDGE_OUT_FAIL_AS_CLAIM_TIMEOUT: &str =
    "Claim timed out. Please initiate a new transaction.";
const _BRIDGE_IN_FAIL_AS_L1_LOCK_TIMEOUT: &str =
    "The operator timed out and failed to lock BTC. Please cancel the transaction.";
pub const BRIDGE_IN_AMOUNTS: [f32; 2] = [0.1, 0.01];

const GOAT_BLOCK_INTERVAL_SECS: i64 = 3;
const INSTANCE_BRIDGE_OUT_INIT_STATUS_DURATION_SECS: i64 = 3600; // todo update
const INSTANCE_USER_BROADCAST_PREPARE_STATUS_DURATION_SECS: i64 = 3600 * 3;
const INSTANCE_RELAYER_L1_BROADCAST_STATUS_DURATION_SECS: i64 = 3600 * 3;
const GRAPH_OPERATOR_KICKOFFING_STATUS_DURATION_SECS: i64 = 1800;
const GRAPH_OPERATOR_KICKOFF_STATUS_DURATION_SECS: i64 = 3600 * 3;
const GRAPH_OPERATOR_CHALLENGE_STATUS_DURATION_SECS: i64 = 3600 * 9;

#[derive(Debug, Deserialize, Serialize)]
pub struct BridgeInPrepareRequest {
    pub instance_id: String,            // UUID
    pub contract_address: String,       // gateway address
    pub from_addr: String,              // BTC /charge
    pub to_addr: String,                // BTC /charge
    pub bridge_request_tx_hash: String, // goat tx hash
}
#[derive(Debug, Deserialize, Serialize)]
pub struct BridgeInPrepareResponse {}

#[derive(Debug, Deserialize, Serialize)]
pub struct BridgeOutInitTagRequest {
    pub contract_address: String, // gateway address
    pub from_addr: String,        // goat addr
    pub to_addr: String,          // btc addr
    pub escrow_hash: String,      // goat tx hash
}
#[derive(Debug, Deserialize, Serialize)]
pub struct BridgeOutInitTagResponse {}

#[derive(Debug, Deserialize, Serialize)]
pub struct EscrowDataResponse {
    pub instance_id: String,
    pub escrow: Option<String>,
    pub error: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct InstanceSettingResponse {
    pub bridge_in_amount: Vec<f32>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct SendChallengeResponse {
    pub challenge_txid: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct PegoutRequest {
    pub graph_id: Option<String>,
    #[serde(default)]
    pub dry_run: bool,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct PegoutResponse {
    pub graph_id: String,
    pub instance_id: String,
    pub kickoff_index: i64,
    pub amount: i64,
    pub tx_hash: Option<String>,
    pub dry_run: bool,
}

#[derive(Debug, Deserialize)]
pub struct GraphTxGetParams {
    pub tx_name: String,
}

#[derive(Debug, Deserialize)]
pub struct GraphTxnGetParams {
    pub cursor: i32, //  -1 pre graph tx : 0: current graph tx; 1 next graph tx
}
/// get tx detail
#[derive(Debug, Deserialize)]
pub struct InstanceListRequest {
    pub is_bridge_in: bool,
    pub from_addr: Option<String>,
    pub offset: Option<u32>,
    pub limit: Option<u32>,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default, PartialEq, Display, EnumString)]
pub enum StatusUserAction {
    #[default]
    None,
    Cancel,
    BroadcastPreparePegin,
    BroadcastCancelPegin,
    Refund,
}
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct StatusExtra {
    pub user_action: StatusUserAction,
    pub is_failed: bool,
    pub error: Option<String>,
}
#[derive(Deserialize, Serialize, Default)]
pub struct InstanceDisplay {
    pub instance_id: Uuid,
    pub is_bridge_in: bool,
    pub network: String,
    pub from_addr: String,
    pub to_addr: String, // goat deposit addr
    #[serde(serialize_with = "serialize_u256", deserialize_with = "deserialize_u256")]
    pub amount: U256,
    pub fees: UInt64Array3,
    pub input_utxos: String,  // init should been []
    pub status: String,       // InstanceBridgeInStatus | InstanceBridgeOutStatus
    pub goat_tx_hash: String, // bridgeIn:pegin Request tx || bridgeOut goat tx
    pub goat_tx_height: i64,
    pub user_xonly_pubkey: ByteArray32,
    pub user_change_addr: String,
    pub user_refund_addr: String,
    pub btc_txid: Option<SerializableTxid>, // bridgeIn: Pegin Prepare Request tx || bridgeOut Btc tx
    pub btc_height: i64,
    pub pegin_confirm_txid: Option<SerializableTxid>, // btc txid
    pub pegin_cancel_txid: Option<SerializableTxid>,  // btc txid
    pub committees_answers: IndexMap<String, Vec<u8>>,
    pub pegin_data_tx_hash: String,
    pub parameters: Option<String>,
    pub escrow_hash: Option<String>,
    pub bridge_out_lock_time: i64,
    pub post_pegin_txhash: Option<String>,
    pub status_updated_at: i64,
    pub created_at: i64,
    pub updated_at: i64,
}
impl From<Instance> for InstanceDisplay {
    fn from(instance: Instance) -> Self {
        let amount = if instance.is_bridge_in {
            U256::from(instance.amount)
        } else {
            U256::from_str(&instance.bridge_out_amount).unwrap_or_default()
        };
        Self {
            instance_id: instance.instance_id,
            is_bridge_in: instance.is_bridge_in,
            network: instance.network,
            from_addr: instance.from_addr,
            to_addr: instance.to_addr,
            amount,
            fees: instance.fees,
            input_utxos: instance.input_utxos,
            status: instance.status,
            goat_tx_hash: instance.goat_tx_hash,
            goat_tx_height: instance.goat_tx_height,
            user_xonly_pubkey: instance.user_xonly_pubkey,
            user_change_addr: instance.user_change_addr,
            user_refund_addr: instance.user_refund_addr,
            btc_txid: instance.btc_txid,
            btc_height: instance.btc_height,
            pegin_confirm_txid: instance.pegin_confirm_txid,
            pegin_cancel_txid: instance.pegin_cancel_txid,
            committees_answers: instance.committees_answers,
            pegin_data_tx_hash: instance.pegin_data_tx_hash,
            parameters: instance.parameters,
            escrow_hash: instance.escrow_hash,
            bridge_out_lock_time: instance.bridge_out_lock_time,
            post_pegin_txhash: instance.post_pegin_txhash,
            status_updated_at: instance.status_updated_at,
            created_at: instance.created_at,
            updated_at: instance.updated_at,
        }
    }
}

#[derive(Deserialize, Serialize, Default)]
pub struct InstanceExtended {
    pub instance: InstanceDisplay,
    pub utxo: Vec<Utxo>,
    pub waiting_time_in_secs: i64,
    pub current_status_waiting_time_in_secs: i64,
    pub confirmations: u32,
    pub target_confirmations: u32,
    pub status_extra: StatusExtra,
}

impl InstanceExtended {
    pub async fn convert_from_instance(
        btc_client: &BTCClient,
        btc_current_height: u32,
        response_window_blocks: i64,
        instance: Instance,
    ) -> anyhow::Result<Self> {
        let utxos: Vec<Utxo> = serde_json::from_str(&instance.input_utxos).map_err(|e| {
            anyhow::Error::msg(format!(
                "convert input utxos:{} failed, error:{}",
                instance.input_utxos, e
            ))
        })?;
        let (confirmations, target_confirmations) = get_instance_block_confirm_progress(
            btc_client,
            btc_current_height,
            instance.is_bridge_in,
            instance.btc_txid.clone(),
        )
        .await?;
        let status_extra = get_instance_status_extra(
            btc_client,
            instance.instance_id,
            instance.is_bridge_in,
            instance.status.clone(),
            instance.btc_txid.clone().map(|v| v.0.to_string()),
            &utxos,
            instance.pegin_cancel_txid.clone().map(|v| v.0),
        )
        .await?;
        let (current_status_waiting_time_in_secs, waiting_time_in_secs) =
            get_instance_waiting_times(
                instance.is_bridge_in,
                &instance.status,
                instance.created_at,
                instance.status_updated_at,
                response_window_blocks,
                instance.bridge_out_lock_time,
            );

        // instance.status = instance.convert_to_display_status();
        Ok(Self {
            waiting_time_in_secs,
            current_status_waiting_time_in_secs,
            confirmations,
            target_confirmations,
            status_extra,
            utxo: utxos,
            instance: instance.into(),
        })
    }
}

async fn get_instance_status_extra(
    btc_client: &BTCClient,
    instance_id: Uuid,
    is_bridge_in: bool,
    status: String,
    target_txid: Option<String>,
    utxos: &[Utxo],
    pegin_cancel_txid: Option<Txid>,
) -> anyhow::Result<StatusExtra> {
    let mut status_extra = StatusExtra::default();
    if is_bridge_in && let Ok(bridge_in_status) = InstanceBridgeInStatus::from_str(&status) {
        match bridge_in_status {
            InstanceBridgeInStatus::UserInited => {
                if !check_bridge_in_uxto_available_or_self_spent(btc_client, target_txid, utxos)
                    .await?
                {
                    status_extra.is_failed = true;
                    status_extra.error = Some(BRIDGE_IN_FAIL_AS_UTXO_BEEN_SPENT.to_string());
                    status_extra.user_action = StatusUserAction::Cancel;
                }
            }
            InstanceBridgeInStatus::UserDiscarded => {
                status_extra.is_failed = true;
                status_extra.error = Some(BRIDGE_IN_FAIL_AS_UTXO_BEEN_SPENT.to_string());
                status_extra.user_action = StatusUserAction::Cancel;
            }
            InstanceBridgeInStatus::CommitteesAnswered => {
                if !check_bridge_in_uxto_available_or_self_spent(btc_client, target_txid, utxos)
                    .await?
                {
                    status_extra.is_failed = true;
                    status_extra.error = Some(BRIDGE_IN_FAIL_AS_UTXO_BEEN_SPENT.to_string());
                    status_extra.user_action = StatusUserAction::Cancel;
                } else {
                    status_extra.is_failed = false;
                    status_extra.error = None;
                    status_extra.user_action = StatusUserAction::BroadcastPreparePegin;
                }
            }
            InstanceBridgeInStatus::NoEnoughCommitteesAnswered => {
                status_extra.is_failed = true;
                status_extra.error = Some(BRIDGE_IN_FAIL_AS_VERIFICATION_FAILED.to_string());
                status_extra.user_action = StatusUserAction::Cancel;
            }
            InstanceBridgeInStatus::PresignedFailed => {
                status_extra.is_failed = true;
                status_extra.error = Some(BRIDGE_IN_FAIL_AS_PRESIGNED_FAILED.to_string());
                status_extra.user_action = StatusUserAction::None;
            }
            InstanceBridgeInStatus::RelayerL2MintedFailed => {
                status_extra.is_failed = true;
                status_extra.error = Some(BRIDGE_IN_FAIL_AS_L2_MINTED_FAILED.to_string());
                status_extra.user_action = StatusUserAction::None;
            }
            InstanceBridgeInStatus::Timeout => {
                status_extra.is_failed = true;
                status_extra.error = Some(BRIDGE_IN_FAIL_AS_TIMEOUT.to_string());
                status_extra.user_action = StatusUserAction::BroadcastCancelPegin;
                if let Some(ref txid) = pegin_cancel_txid {
                    match btc_client.get_tx(txid).await {
                        Ok(Some(_)) => {
                            status_extra.user_action = StatusUserAction::None;
                        }
                        Err(err) => {
                            warn!(
                                "instance:{instance_id} failed to query pegin_cancel_txid {txid}: {err}"
                            );
                        }
                        _ => {} // tx not found on chain, keep BroadcastCancelPegin
                    }
                }
            }
            _ => {}
        }
    } else if !is_bridge_in
        && let Ok(bridge_out_status) = InstanceBridgeOutStatus::from_str(&status)
    {
        if bridge_out_status == InstanceBridgeOutStatus::Timeout {
            status_extra.is_failed = true;
            status_extra.error = Some(BRIDGE_IN_FAIL_AS_TIMEOUT.to_string());
            status_extra.user_action = StatusUserAction::Refund;
        }
    } else {
        warn!("instance:with {instance_id}, is_bridge_in:{is_bridge_in} has wrong status:{status}");
    }
    Ok(status_extra)
}

async fn get_instance_block_confirm_progress(
    btc_client: &BTCClient,
    current_height: u32,
    is_bridge_in: bool,
    txid: Option<SerializableTxid>,
) -> anyhow::Result<(u32, u32)> {
    if !is_bridge_in {
        if let Some(txid) = txid
            && let Ok(tx_status) = btc_client.get_tx_status(&txid.into()).await
            && let Some(height) = tx_status.block_height
        {
            Ok((current_height + 1_u32 - height, 6_u32))
        } else {
            Ok((0, 6))
        }
    } else {
        Ok((0, 0))
    }
}

fn get_bridge_in_status_time_window_secs(status: &str, response_window_blocks: i64) -> (i64, i64) {
    let response_window_blocks_with_margin = response_window_blocks * 105 / 100;
    let total_time = response_window_blocks_with_margin * GOAT_BLOCK_INTERVAL_SECS
        + INSTANCE_USER_BROADCAST_PREPARE_STATUS_DURATION_SECS
        + INSTANCE_RELAYER_L1_BROADCAST_STATUS_DURATION_SECS;

    match InstanceBridgeInStatus::from_str(status) {
        Ok(InstanceBridgeInStatus::UserIniting)
        | Ok(InstanceBridgeInStatus::Initiated)
        | Ok(InstanceBridgeInStatus::UserInited) => {
            (response_window_blocks_with_margin * GOAT_BLOCK_INTERVAL_SECS, total_time)
        }
        Ok(InstanceBridgeInStatus::CommitteesAnswered) | Ok(InstanceBridgeInStatus::Verified) => {
            (0, total_time - response_window_blocks_with_margin * GOAT_BLOCK_INTERVAL_SECS)
        }
        Ok(InstanceBridgeInStatus::Submitted)
        | Ok(InstanceBridgeInStatus::UserBroadcastPeginPrepare) => (
            INSTANCE_USER_BROADCAST_PREPARE_STATUS_DURATION_SECS,
            total_time - response_window_blocks_with_margin * GOAT_BLOCK_INTERVAL_SECS,
        ),
        Ok(InstanceBridgeInStatus::Processing)
        | Ok(InstanceBridgeInStatus::Presigned)
        | Ok(InstanceBridgeInStatus::RelayerL1Broadcasted) => (
            INSTANCE_RELAYER_L1_BROADCAST_STATUS_DURATION_SECS,
            total_time
                - response_window_blocks_with_margin * GOAT_BLOCK_INTERVAL_SECS
                - INSTANCE_USER_BROADCAST_PREPARE_STATUS_DURATION_SECS,
        ),
        Ok(_) | Err(_) => (0, 0),
    }
}

// dead time
fn get_bridge_out_status_time_window_secs(status: &str, bridge_out_lock_time: i64) -> (i64, i64) {
    let deadline_time = if bridge_out_lock_time > 0 {
        bridge_out_lock_time
    } else {
        // for history data not set bridge_out_lock_time
        INSTANCE_BRIDGE_OUT_INIT_STATUS_DURATION_SECS
    };

    match InstanceBridgeOutStatus::from_str(status) {
        Ok(InstanceBridgeOutStatus::Initialize) => (deadline_time, deadline_time),
        Ok(_) | Err(_) => (0, 0),
    }
}

fn get_instance_waiting_times(
    is_bridge_in: bool,
    status: &str,
    created_at: i64,
    last_updated: i64,
    response_window_blocks: i64,
    bridge_out_lock_time: i64,
) -> (i64, i64) {
    let current_time = current_time_secs();
    let current_state_past = current_time - last_updated;
    let total_past = current_time - created_at;
    if is_bridge_in {
        let (current_status_window, total_window) =
            get_bridge_in_status_time_window_secs(status, response_window_blocks);
        ((current_status_window - current_state_past).max(0), (total_window - total_past).max(0))
    } else {
        let (current_status_deadline, status_deadline) =
            get_bridge_out_status_time_window_secs(status, bridge_out_lock_time);
        ((current_status_deadline - current_time).max(0), (status_deadline - current_time).max(0))
    }
}

#[derive(Deserialize, Serialize, Default)]
pub struct InstanceListResponse {
    pub instance_wraps: Vec<InstanceExtended>,
    pub total: i64,
}

#[derive(Deserialize, Serialize)]
pub struct InstanceGetResponse {
    pub instance_wrap: Option<InstanceExtended>,
}

#[derive(Deserialize, Serialize, Default)]
pub struct InstanceOverviewResponse {
    pub instances_overview: InstanceOverview,
}

#[derive(Deserialize, Serialize, Default)]
pub struct InstanceOverview {
    pub total_bridge_in_amount: i64,
    pub total_bridge_in_txn: i64,
    #[serde(serialize_with = "serialize_u256", deserialize_with = "deserialize_u256")]
    pub total_bridge_out_amount: U256,
    pub total_bridge_out_txn: i64,
    pub total_peg_out_amount: i64,
    pub total_peg_out_txn: i64,
    pub online_nodes: i64,
    pub total_nodes: i64,
}

pub type GraphGetResponse = GraphExtended;

#[derive(Deserialize, Serialize, Default)]
pub struct GraphTxnGetResponse {
    pub assert_init: BtcTxData,
    pub watchtower_challenge_init: BtcTxData,
    pub pre_kickoff: BtcTxData,
    pub challenge: BtcTxData,
    pub disprove: BtcTxData,
    pub kickoff: BtcTxData,
    pub pegin: BtcTxData,
    pub take1: BtcTxData,
    pub take2: BtcTxData,
}
#[derive(Deserialize, Serialize, Default)]
pub struct GraphTxGetResponse {
    pub btc_tx_data: BtcTxData,
}

#[derive(Deserialize, Serialize, Default)]
pub struct GraphNeighborIdsResponse {
    pub current_id: Uuid,
    pub previous_id: Option<Uuid>,
    pub next_id: Option<Uuid>,
}

#[derive(Deserialize, Serialize, Default)]
pub struct ProgressData {
    pub name: String,
    pub current: usize,
    pub total: usize,
}
#[derive(Deserialize, Serialize, Default)]
pub struct BtcTxData {
    pub raw_data: String,
    pub progresses: Vec<ProgressData>,
    pub fail_reason: Option<String>,
}

impl BtcTxData {
    pub fn new(raw_data: String) -> Self {
        Self { raw_data, progresses: vec![], fail_reason: None }
    }
    pub fn with_progresses(mut self, progresses: Vec<ProgressData>) -> Self {
        self.progresses = progresses;
        self
    }
    pub fn with_fail_reason(mut self, fail_reason: Option<String>) -> Self {
        self.fail_reason = fail_reason;
        self
    }
}

#[derive(Debug, Deserialize)]
pub struct GraphQueryParams {
    pub status: Option<String>,
    pub operator: Option<String>,
    pub from_addr: Option<String>,
    #[serde(default = "default_is_peg_out")]
    pub is_pegout_started: bool,
    pub graph_field: Option<String>,
    pub offset: Option<u32>,
    pub limit: Option<u32>,
}
fn default_is_peg_out() -> bool {
    false
}

impl From<GraphQueryParams> for GraphQuery {
    fn from(value: GraphQueryParams) -> Self {
        let mut pegin_txid_op: Option<SerializableTxid> = None;
        let mut graph_id_op: Option<String> = None;
        if let Some(filed) = value.graph_field {
            if let Ok(pegin_txid) = Txid::from_str(&filed) {
                pegin_txid_op = Some(pegin_txid.into());
            }
            if let Ok(uuid) = Uuid::from_str(&filed) {
                graph_id_op = Some(uuid.encode_hex());
            }
        }
        let (_, from_addr) = reflect_goat_address(value.from_addr.clone());

        let mut is_init_withdraw_not_null = value
            .status
            .as_ref()
            .map(|status| status == &GraphStatus::OperatorKickOffing.to_string())
            .unwrap_or(false);
        is_init_withdraw_not_null = is_init_withdraw_not_null || value.is_pegout_started;
        let mut statuses = vec![];
        if let Some(status) = value.status {
            statuses = Graph::parse_display_status(&status)
        }

        let mut raw_conditions = vec![];
        if is_init_withdraw_not_null && statuses.is_empty() {
            raw_conditions.push(
                "( status NOT IN ('OperatorPresigned','CommitteePresigned', 'OperatorDataPushed') OR \
                 (status = 'OperatorDataPushed'  AND init_withdraw_tx_hash IS NOT NULL ) )".to_string()
            );
        }
        if is_init_withdraw_not_null {
            raw_conditions.push("init_withdraw_tx_hash IS NOT NULL".to_string());
        }
        GraphQuery {
            statuses,
            operator_pubkey: value.operator,
            kickoff_index: None,
            from_addr,
            graph_id: graph_id_op,
            pegin_txid: pegin_txid_op,
            raw_conditions,
            order: Some(
                "CASE
                     WHEN bridge_out_start_at > 0
                     THEN bridge_out_start_at
                    ELSE created_at
                END DESC"
                    .to_string(),
            ),
            offset: value.offset,
            limit: value.limit,
        }
    }
}

/// graph_overview
// All fields can be optional
// if all are none, we fetch all the graph list order by timestamp desc.

#[derive(Clone, Default, Deserialize, Serialize)]
pub struct GraphListResponse {
    pub graphs: Vec<GraphExtended>,
    pub total: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Display, EnumString, Default)]
pub enum SimpleChallengeSubStatus {
    #[default]
    None,
    WatchtowerChallenge,
    Assert,
}

#[derive(Clone, Default, Deserialize, Serialize)]
pub struct GraphExtended {
    pub graph: Option<Graph>,
    pub challenge_sub_status: SimpleChallengeSubStatus,
    pub waiting_time_in_secs: i64,
    pub current_status_waiting_time_in_secs: i64,
    pub proof_status: ProofState,
}

impl GraphExtended {
    pub async fn convert_from_graph(
        _btc_client: &BTCClient,
        mut graph: Graph,
    ) -> anyhow::Result<Self> {
        let (current_status_waiting_time_in_secs, waiting_time_in_secs) = get_graph_waiting_times(
            graph.created_at,
            graph.status_updated_at,
            &graph.status,
            graph.init_withdraw_tx_hash.is_some(),
        );
        if ![
            GraphStatus::Disprove.to_string(),
            GraphStatus::Challenge.to_string(),
            GraphStatus::OperatorTake2.to_string(),
        ]
        .contains(&graph.status)
        {
            graph.proceed_withdraw_height = 0;
        }
        graph.status = graph.convert_to_display_status();
        let challenge_sub_status =
            match serde_json::from_str::<ChallengeSubStatus>(&graph.sub_status) {
                Ok(v) => {
                    if v.assert_commit_status != AssertCommitStatus::None {
                        SimpleChallengeSubStatus::Assert
                    } else if v.watchtower_challenge_status != WatchtowerChallengeStatus::None {
                        SimpleChallengeSubStatus::WatchtowerChallenge
                    } else {
                        SimpleChallengeSubStatus::None
                    }
                }
                Err(e) => {
                    warn!(
                        "fail to covert graph {} sub_status:{}, error:{e}",
                        graph.graph_id, graph.sub_status
                    );
                    SimpleChallengeSubStatus::None
                }
            };
        // todo update proof status
        Ok(GraphExtended {
            current_status_waiting_time_in_secs,
            challenge_sub_status,
            waiting_time_in_secs,
            proof_status: ProofState::New,
            graph: Some(graph),
        })
    }
}

fn get_graph_waiting_times(
    created_at: i64,
    last_updated: i64,
    status: &str,
    is_start_kickoff: bool,
) -> (i64, i64) {
    let total_time = GRAPH_OPERATOR_KICKOFFING_STATUS_DURATION_SECS
        + GRAPH_OPERATOR_KICKOFF_STATUS_DURATION_SECS
        + GRAPH_OPERATOR_CHALLENGE_STATUS_DURATION_SECS;
    let (current_status_window, total_window) = match GraphStatus::from_str(status) {
        Ok(GraphStatus::OperatorDataPushed) if is_start_kickoff => {
            (GRAPH_OPERATOR_KICKOFFING_STATUS_DURATION_SECS, total_time)
        }
        Ok(GraphStatus::OperatorKickOff) => (
            GRAPH_OPERATOR_KICKOFF_STATUS_DURATION_SECS,
            total_time - GRAPH_OPERATOR_KICKOFFING_STATUS_DURATION_SECS,
        ),
        Ok(GraphStatus::Challenge) => (
            GRAPH_OPERATOR_CHALLENGE_STATUS_DURATION_SECS,
            total_time
                - GRAPH_OPERATOR_KICKOFFING_STATUS_DURATION_SECS
                - GRAPH_OPERATOR_KICKOFF_STATUS_DURATION_SECS,
        ),

        _ => (0, 0),
    };
    let current_state_past = current_time_secs() - last_updated;
    let total_past = current_time_secs() - created_at;
    ((current_status_window - current_state_past).max(0), (total_window - total_past).max(0))
}

#[derive(Debug, Deserialize)]
pub struct GraphReadyToKickoffRequest {
    pub goat_addr: Option<String>,
    pub btc_pub_key: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct GraphReadyToKickoffResponse {
    pub graph: Option<Graph>,
    pub no_ready_reason: Option<String>,
}

#[derive(Deserialize, Serialize, Default)]
pub struct UnsignPeginTxnResponse {
    pub pegin_prepare: Option<String>,
    pub pegin_cancel_psbt: Option<String>,
}
trait DisplayStatusConvert {
    fn convert_to_display_status(&self) -> String;

    fn parse_display_status(ori_status: &str) -> Vec<String>;
}

impl DisplayStatusConvert for Graph {
    fn convert_to_display_status(&self) -> String {
        match GraphStatus::from_str(&self.status) {
            Ok(GraphStatus::OperatorPresigned) => GraphStatus::Created.to_string(),
            Ok(GraphStatus::CommitteePresigned) => GraphStatus::Presigned.to_string(),
            Ok(GraphStatus::OperatorDataPushed) => {
                if self.init_withdraw_tx_hash.is_some() {
                    GraphStatus::OperatorKickOffing.to_string()
                } else {
                    GraphStatus::L2Recorded.to_string()
                }
            }
            Ok(_) | Err(_) => self.status.clone(),
        }
    }
    fn parse_display_status(ori_status: &str) -> Vec<String> {
        match GraphStatus::from_str(ori_status) {
            Ok(GraphStatus::Created) => vec![GraphStatus::OperatorPresigned.to_string()],
            Ok(GraphStatus::Presigned) => vec![GraphStatus::CommitteePresigned.to_string()],
            Ok(GraphStatus::L2Recorded) => vec![GraphStatus::OperatorDataPushed.to_string()],
            Ok(GraphStatus::OperatorKickOffing) => {
                vec![GraphStatus::OperatorDataPushed.to_string()]
            }
            Ok(v) => vec![v.to_string()],
            Err(_) => vec![],
        }
    }
}

impl DisplayStatusConvert for Instance {
    fn convert_to_display_status(&self) -> String {
        if !self.is_bridge_in {
            return self.status.clone();
        }
        match InstanceBridgeInStatus::from_str(&self.status) {
            Ok(InstanceBridgeInStatus::UserInited) => InstanceBridgeInStatus::Initiated.to_string(),
            Ok(InstanceBridgeInStatus::CommitteesAnswered) => {
                InstanceBridgeInStatus::Verified.to_string()
            }
            Ok(InstanceBridgeInStatus::UserBroadcastPeginPrepare) => {
                InstanceBridgeInStatus::Submitted.to_string()
            }
            Ok(InstanceBridgeInStatus::Presigned) => InstanceBridgeInStatus::Processing.to_string(),
            Ok(InstanceBridgeInStatus::RelayerL1Broadcasted) => {
                InstanceBridgeInStatus::Processing.to_string()
            }
            Ok(InstanceBridgeInStatus::RelayerL2Minted) => {
                InstanceBridgeInStatus::Success.to_string()
            }
            Ok(InstanceBridgeInStatus::PresignedFailed)
            | Ok(InstanceBridgeInStatus::RelayerL2MintedFailed)
            | Ok(InstanceBridgeInStatus::NoEnoughCommitteesAnswered) => {
                InstanceBridgeInStatus::Failed.to_string()
            }
            Ok(InstanceBridgeInStatus::UserCanceled) => {
                InstanceBridgeInStatus::Canceled.to_string()
            }
            Ok(_) | Err(_) => self.status.clone(),
        }
    }

    fn parse_display_status(ori_status: &str) -> Vec<String> {
        match InstanceBridgeInStatus::from_str(ori_status) {
            Ok(InstanceBridgeInStatus::Initiated) => {
                vec![InstanceBridgeInStatus::UserInited.to_string()]
            }
            Ok(InstanceBridgeInStatus::Verified) => {
                vec![InstanceBridgeInStatus::CommitteesAnswered.to_string()]
            }
            Ok(InstanceBridgeInStatus::Submitted) => {
                vec![InstanceBridgeInStatus::UserBroadcastPeginPrepare.to_string()]
            }
            Ok(InstanceBridgeInStatus::Processing) => {
                vec![
                    InstanceBridgeInStatus::RelayerL1Broadcasted.to_string(),
                    InstanceBridgeInStatus::Presigned.to_string(),
                ]
            }
            Ok(InstanceBridgeInStatus::Success) => {
                vec![InstanceBridgeInStatus::RelayerL2Minted.to_string()]
            }
            Ok(InstanceBridgeInStatus::Canceled) => {
                vec![InstanceBridgeInStatus::UserCanceled.to_string()]
            }
            Ok(InstanceBridgeInStatus::Failed) => vec![
                InstanceBridgeInStatus::PresignedFailed.to_string(),
                InstanceBridgeInStatus::RelayerL2MintedFailed.to_string(),
                InstanceBridgeInStatus::NoEnoughCommitteesAnswered.to_string(),
            ],
            Ok(v) => vec![v.to_string()],
            Err(_) => vec![],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use esplora_client::{Tx, TxStatus};

    fn build_mock_tx(txid: Txid, confirmed: bool) -> Tx {
        Tx {
            txid,
            version: 2,
            locktime: 0,
            vin: vec![],
            vout: vec![],
            size: 10,
            weight: 40,
            status: TxStatus {
                confirmed,
                block_height: if confirmed { Some(1) } else { None },
                block_hash: None,
                block_time: if confirmed { Some(1) } else { None },
            },
            fee: 0,
        }
    }

    async fn timeout_status_extra(
        btc_client: &BTCClient,
        cancel_txid: Option<Txid>,
    ) -> StatusExtra {
        get_instance_status_extra(
            btc_client,
            Uuid::new_v4(),
            true,
            InstanceBridgeInStatus::Timeout.to_string(),
            None,
            &[],
            cancel_txid,
        )
        .await
        .unwrap()
    }

    #[tokio::test]
    async fn timeout_without_cancel_txid_should_broadcast_cancel_pegin() {
        let (btc_client, _) = BTCClient::new_mock_client();
        let extra = timeout_status_extra(&btc_client, None).await;
        assert_eq!(extra.user_action, StatusUserAction::BroadcastCancelPegin);
    }

    #[tokio::test]
    async fn timeout_with_cancel_txid_in_mempool_should_have_no_action() {
        let (btc_client, mock_adaptor) = BTCClient::new_mock_client();
        let txid =
            Txid::from_str("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
                .unwrap();
        mock_adaptor.set_tx(txid, build_mock_tx(txid, false));

        let extra = timeout_status_extra(&btc_client, Some(txid)).await;
        assert_eq!(extra.user_action, StatusUserAction::None);
    }

    #[tokio::test]
    async fn timeout_with_confirmed_cancel_txid_should_have_no_action() {
        let (btc_client, mock_adaptor) = BTCClient::new_mock_client();
        let txid =
            Txid::from_str("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
                .unwrap();
        mock_adaptor.set_tx(txid, build_mock_tx(txid, true));

        let extra = timeout_status_extra(&btc_client, Some(txid)).await;
        assert_eq!(extra.user_action, StatusUserAction::None);
    }

    #[tokio::test]
    async fn timeout_with_non_existing_cancel_txid_should_broadcast_cancel_pegin() {
        let (btc_client, _) = BTCClient::new_mock_client();
        let txid =
            Txid::from_str("cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc")
                .unwrap();

        let extra = timeout_status_extra(&btc_client, Some(txid)).await;
        assert_eq!(extra.user_action, StatusUserAction::BroadcastCancelPegin);
    }
}
