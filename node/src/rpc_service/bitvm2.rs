use crate::utils::reflect_goat_address;
use alloy::hex::ToHexExt;
use bitcoin::Txid;
use client::Utxo;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::default::Default;
use std::str::FromStr;
use store::localdb::GraphQuery;
use store::{Graph, GraphStatus, Instance, SerializableTxid, convert_to_step_state};
use uuid::Uuid;

#[derive(Debug, Deserialize, Serialize)]
pub struct InstanceSettingResponse {
    pub bridge_in_amount: Vec<f32>,
}

#[derive(Deserialize, Serialize)]
#[allow(dead_code)]
pub struct BridgeInTransactionPrepareResponse {}

#[derive(Debug, Deserialize)]
pub struct GraphPresignCheckParams {
    pub instance_id: String,
}

#[derive(Debug, Deserialize)]
pub struct GraphTxGetParams {
    pub tx_name: String,
}

#[derive(Clone, Deserialize, Serialize)]
pub struct GraphPresignCheckResponse {
    pub instance_id: String,
    pub instance_status: String,
    pub graph_status: HashMap<String, String>,
    pub tx: Option<Instance>,
}

/// get tx detail
#[derive(Debug, Deserialize)]
pub struct InstanceListRequest {
    pub from_addr: Option<String>,
    pub offset: Option<u32>,
    pub limit: Option<u32>,
}

#[derive(Deserialize, Serialize, Default)]
pub struct InstanceExtended {
    pub instance: Option<Instance>,
    pub utxo: Option<Vec<Utxo>>,
    pub confirmations: u32,
    pub target_confirmations: u32,
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

#[derive(Deserialize)]
pub struct InstanceUpdateRequest {
    pub instance: Instance,
}

#[derive(Deserialize, Serialize)]
pub struct InstanceUpdateResponse {}

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
}

impl BtcTxData {
    pub fn new(raw_data: String) -> Self {
        Self { raw_data, progresses: vec![] }
    }
    pub fn with_progresses(mut self, progresses: Vec<ProgressData>) -> Self {
        self.progresses = progresses;
        self
    }
}

#[derive(Deserialize)]
pub struct GraphUpdateRequest {
    pub graph: Graph,
}

#[derive(Deserialize, Serialize)]
pub struct GraphUpdateResponse {}

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

        let status = value.status.map(|status| convert_to_step_state(&status));
        GraphQuery {
            status,
            is_bridge_out,
            operator: value.operator,
            from_addr,
            graph_id: graph_ip_op,
            pegin_txid: pegin_txid_op,
            offset: value.offset,
            limit: value.limit,
            is_init_withdraw_not_null,
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
    pub confirmations: u32,
    pub target_confirmations: u32,
    pub proof_height: Option<i64>,
    pub proof_query_url: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::{generate_random_bytes, get_rand_goat_address};
    use store::localdb::GraphQuery;
    use uuid::Uuid;

    #[test]
    fn test_from_graph_query_params_basic() {
        let params = GraphQueryParams {
            status: Some("pending".to_string()),
            operator: Some("op1".to_string()),
            from_addr: Some(get_rand_goat_address()),
            graph_field: None,
            offset: Some(10),
            limit: Some(20),
        };
        let filter: GraphQuery = params.into();
        assert!(filter.status.is_some());
        assert_eq!(filter.operator, Some("op1".to_string()));
        assert_eq!(filter.offset, Some(10));
        assert_eq!(filter.limit, Some(20));
        assert!(filter.is_bridge_out);
    }

    #[test]
    fn test_from_graph_query_params_with_graph_field_txid() {
        let params = GraphQueryParams {
            status: None,
            operator: None,
            from_addr: None,
            graph_field: Some(hex::encode(generate_random_bytes(32))),
            offset: None,
            limit: None,
        };
        let filter: GraphQuery = params.into();
        assert!(filter.pegin_txid.is_some() || filter.graph_id.is_some());
    }

    #[test]
    fn test_from_graph_query_params_with_graph_field_uuid() {
        let params = GraphQueryParams {
            status: None,
            operator: None,
            from_addr: None,
            graph_field: Some(Uuid::new_v4().to_string()),
            offset: None,
            limit: None,
        };
        let filter: GraphQuery = params.into();
        assert!(filter.graph_id.is_some() || filter.pegin_txid.is_some());
    }

    #[test]
    fn test_filter_graph_params_builder_pattern() {
        let params = GraphQuery::default()
            .with_status("pending".to_string())
            .with_operator("op1".to_string())
            .with_from_addr("0x1234567890abcdef".to_string())
            .with_pagination(10, 20)
            .with_bridge_out(true);

        assert_eq!(params.status, Some("pending".to_string()));
        assert_eq!(params.operator, Some("op1".to_string()));
        assert_eq!(params.from_addr, Some("0x1234567890abcdef".to_string()));
        assert_eq!(params.offset, Some(10));
        assert_eq!(params.limit, Some(20));
        assert!(params.is_bridge_out);
    }
}
