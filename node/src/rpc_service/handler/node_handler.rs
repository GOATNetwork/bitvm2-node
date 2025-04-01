use crate::rpc_service::node::{NodeDesc, NodeListRequest, NodeListResponse, UpdateOrInsertNode};
use axum::Json;
use axum::extract::State;
use http::StatusCode;
use std::sync::Arc;
use store::Node;
use store::localdb::LocalDB;

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

#[axum::debug_handler]
pub async fn node_list(
    State(local_db): State<Arc<LocalDB>>,
    Json(payload): Json<NodeListRequest>,
) -> (StatusCode, Json<NodeListResponse>) {
    let _ = local_db.node_list(&payload.role, payload.offset, payload.limit).await;
    //TODO
    let node_list = NodeListResponse {
        nodes: vec![
            NodeDesc {
                peer_id: "QmNnooDu7bfjPFoTZYxMNLWUQJyrVwtbZg5gBMjTezGAJN".to_string(),
                role: payload.role,
                update_at: std::time::SystemTime::now(),
                status: "online".to_string(),
            };
            payload.limit as usize
        ],
    };

    (StatusCode::OK, Json(node_list))
}
