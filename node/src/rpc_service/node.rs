use axum::extract::State;
use axum::{Json, Router, http::StatusCode};
use bitvm2_lib::actors::Actor;
use serde::{Deserialize, Serialize};
use std::default::Default;
use std::sync::Arc;
use store::Node;
use store::localdb::LocalDB;
use tracing_subscriber::fmt::time;

// the input to our `create_user` handler
#[derive(Deserialize)]
pub struct UpdateOrInsertNode {
    pub peer_id: String,
    pub role: Actor,
}

#[axum::debug_handler]
pub async fn update_node(
    State(local_db): State<Arc<LocalDB>>,
    Json(payload): Json<UpdateOrInsertNode>,
) -> (StatusCode, Json<Node>) {
    // insert your application logic here
    let node = Node {
        peer_id: payload.peer_id,
        role: payload.role.to_string(),
        update_at: std::time::SystemTime::now(),
    };
    local_db.update_node(node.clone()).await;
    (StatusCode::OK, Json(node))
}
/// node_overview
pub struct NodeListRequest {
    pub role: String,
    pub status: String, // online/offline

    pub offset: u32,
    pub limit: u32,
}

pub struct NodeListResponse {
    pub nodes: Vec<NodeDesc>,
}

pub struct NodeDesc {
    // node
    pub peer_id: String,
    pub role: String,
    pub update_at: std::time::SystemTime,

    // dynamic status: online/offline
    pub status: String,
}
