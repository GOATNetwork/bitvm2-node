use crate::rpc_service::current_time_secs;
use bitvm2_lib::actors::Actor;
use serde::{Deserialize, Serialize};
use store::Node;

pub const ALIVE_TIME_JUDGE_THRESHOLD: i64 = 4 * 3600;
// the input to our `create_user` handler
#[derive(Deserialize)]
pub struct UpdateOrInsertNodeRequest {
    pub peer_id: String,
    pub actor: Actor,
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
    pub offset: u32,
    pub limit: u32,
}

#[derive(Serialize, Deserialize)]
pub struct NodeListResponse {
    pub nodes: Vec<NodeDesc>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct NodeDesc {
    pub peer_id: String,
    pub actor: String,
    pub updated_at: i64,
    pub status: String, //dynamic status: online/offline
}
impl From<Node> for NodeDesc {
    fn from(node: Node) -> Self {
        let mut status = "online".to_string();
        let current_time = current_time_secs();
        if node.updated_at + ALIVE_TIME_JUDGE_THRESHOLD < current_time {
            status = "offline".to_string()
        };
        Self { peer_id: node.peer_id, actor: node.actor, updated_at: node.updated_at, status }
    }
}
