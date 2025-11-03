use serde::{Deserialize, Serialize};
use store::NodesOverview;

pub const ALIVE_TIME_JUDGE_THRESHOLD: i64 = 4 * 3600;

/// node_overview
#[derive(Serialize, Deserialize)]
#[allow(dead_code)]
pub struct NodeListRequest {
    pub actor: String,
    pub offset: u32,
    pub limit: u32,
}

#[derive(Debug, Deserialize)]
pub struct NodeQueryParams {
    pub actor: Option<String>,
    pub status: Option<String>,
    pub goat_addr: Option<String>,
    pub offset: Option<u32>,
    pub limit: Option<u32>,
}

#[derive(Serialize, Deserialize)]
pub struct NodeListResponse {
    pub nodes: Vec<NodeDesc>,
    pub total: i64,
}

#[derive(Serialize, Deserialize, Default)]
pub struct NodeOverViewResponse {
    pub nodes_overview: NodesOverview,
}

#[derive(Clone, Serialize, Deserialize, Default)]
pub struct NodeDesc {
    pub peer_id: String,
    pub actor: String,
    pub name: String,
    pub service_fee_rate: f64,
    pub available_peg_btc: i64,
    pub goat_addr: String,
    pub btc_pub_key: String,
    pub socket_addr: String,
    pub reward: i64,
    pub updated_at: i64,
    pub status: String, //dynamic status: online/offline
}
