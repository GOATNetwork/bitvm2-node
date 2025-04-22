use bitvm2_lib::actors::Actor;
use serde::{Deserialize, Serialize};
use store::NodesOverview;

pub const ALIVE_TIME_JUDGE_THRESHOLD: i64 = 4 * 3600;
// the input to our `create_user` handler
#[derive(Deserialize)]
pub struct UpdateOrInsertNodeRequest {
    pub peer_id: String,
    pub actor: Actor,
    pub goat_addr: String,
    pub btc_pub_key: String,
}

/// node_overview
#[derive(Serialize, Deserialize)]
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

#[derive(Clone, Serialize, Deserialize)]
pub struct NodeDesc {
    pub peer_id: String,
    pub actor: String,
    pub goat_addr: String,
    pub btc_pub_key: String,
    pub updated_at: i64,
    pub status: String, //dynamic status: online/offline
}
