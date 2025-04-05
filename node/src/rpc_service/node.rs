use bitvm2_lib::actors::Actor;
use serde::{Deserialize, Serialize};
use std::default::Default;

// the input to our `create_user` handler
#[derive(Deserialize)]
pub struct UpdateOrInsertNode {
    pub peer_id: String,
    pub actor: Actor,
}

/// node_overview
#[derive(Serialize, Deserialize)]
pub struct NodeListRequest {
    pub actor: String,
    // pub status: String, // online/offline
    pub offset: u32,
    pub limit: u32,
}

#[derive(Debug, Deserialize)]
pub struct NodeQueryParams {
    pub actor: Option<String>,
    pub offset: usize,
    pub limit: usize,
}

#[derive(Serialize, Deserialize)]
pub struct NodeListResponse {
    pub nodes: Vec<NodeDesc>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct NodeDesc {
    // node
    pub peer_id: String,
    pub actor: String,
    pub update_at: std::time::SystemTime,
    // dynamic status: online/offline
    pub status: String,
}
