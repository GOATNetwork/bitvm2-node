use crate::utils::reflect_goat_address;
use alloy::hex::ToHexExt;
use bitcoin::Txid;
use client::Utxo;
use serde::{Deserialize, Serialize};
use std::default::Default;
use std::str::FromStr;
use store::localdb::GraphQuery;
use store::{Graph, GraphStatus, Instance, SerializableTxid, convert_to_step_state};
use strum::{Display, EnumString};
use uuid::Uuid;

#[derive(Debug, Deserialize, Serialize)]
pub struct InstanceSettingResponse {
    pub bridge_in_amount: Vec<f32>,
}

#[derive(Debug, Deserialize)]
pub struct GraphTxGetParams {
    pub tx_name: String,
}

#[derive(Debug, Deserialize)]
pub struct GraphTxnGetParams {
    pub _cursor: i32, //  -1 pre graph tx : 0: current graph tx; 1 next graph tx
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
    Submit,
    Cancel,
}
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct StatusExtra {
    pub user_action: StatusUserAction,
    pub is_failed: bool,
    pub error: Option<String>,
}
#[derive(Deserialize, Serialize, Default)]
pub struct InstanceExtended {
    pub instance: Instance,
    pub utxo: Vec<Utxo>,
    pub waiting_time_in_mins: i64,
    // pub confirmations: u32,
    // pub target_confirmations: u32,
    pub status_extra: StatusExtra,
}

#[derive(Deserialize, Serialize, Default)]
pub struct InstanceListResponse {
    pub instance_wraps: Vec<InstanceExtended>,
    pub total: i64,
}

#[derive(Deserialize, Serialize)]
pub struct InstanceGetResponse {
    pub instance_wrap: InstanceExtended,
}

#[derive(Deserialize, Serialize, Default)]
pub struct InstanceOverviewResponse {
    pub instances_overview: InstanceOverview,
}

#[derive(Deserialize, Serialize, Default)]
pub struct InstanceOverview {
    pub total_bridge_in_amount: i64,
    pub total_bridge_in_txn: i64,
    pub total_bridge_out_amount: i64,
    pub total_bridge_out_txn: i64,
    pub total_peg_out_amount: i64,
    pub total_peg_out_txn: i64,
    pub online_nodes: i64,
    pub total_nodes: i64,
}

#[derive(Deserialize, Serialize)]
pub struct GraphGetResponse {
    pub graph: Option<GraphExtended>,
}
#[derive(Deserialize, Serialize, Default)]
pub struct GraphTxnGetResponse {
    #[serde(rename = "assert-init")]
    pub assert_init: BtcTxData,
    #[serde(rename = "watchtower-challenge-init")]
    pub watchtower_challenge_init: BtcTxData,
    #[serde(rename = "pre-kickoff")]
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
    pub graph_field: Option<String>,
    pub offset: Option<u32>,
    pub limit: Option<u32>,
}

impl From<GraphQueryParams> for GraphQuery {
    fn from(value: GraphQueryParams) -> Self {
        let mut pegin_txid_op: Option<SerializableTxid> = None;
        let mut graph_ip_op: Option<String> = None;
        if let Some(filed) = value.graph_field {
            if let Ok(pegin_txid) = Txid::from_str(&filed) {
                pegin_txid_op = Some(pegin_txid.into());
            }
            if let Ok(uuid) = Uuid::from_str(&filed) {
                graph_ip_op = Some(uuid.encode_hex());
            }
        }
        let (is_bridge_out, from_addr) = reflect_goat_address(value.from_addr.clone());
        let is_init_withdraw_not_null = if let Some(status) = value.status.clone()
            && status == GraphStatus::KickOffing.to_string()
        {
            true
        } else {
            false
        };

        let statuses = match value.status.map(|status| convert_to_step_state(&status)) {
            Some(v) => vec![v],
            None => vec![],
        };
        let mut raw_conditions = vec![];
        if is_bridge_out && statuses.is_empty() {
            raw_conditions.push(
                "( status NOT IN ('OperatorPresigned','CommitteePresigned', 'OperatorDataPushed') OR \
                 (status = 'OperatorDataPushed'  AND init_withdraw_txid IS NOT NULL ) )".to_string()
            );
        }
        if is_init_withdraw_not_null {
            raw_conditions.push("init_withdraw_txid IS NOT NULL".to_string());
        }

        GraphQuery {
            statuses,
            operator_pubkey: value.operator,
            kickoff_index: None,
            from_addr,
            graph_id: graph_ip_op,
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

#[derive(Clone, Default, Deserialize, Serialize)]
pub struct GraphExtended {
    pub graph: Graph,
    pub waiting_time_in_mins: i64,
    // pub proof_height: Option<i64>,
    // pub proof_query_url: Option<String>,
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
