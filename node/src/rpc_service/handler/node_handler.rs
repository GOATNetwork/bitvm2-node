use crate::rpc_service::node::{
    NodeDesc, NodeListRequest, NodeListResponse, NodeQueryParams, UpdateOrInsertNode,
};
use axum::Json;
use axum::extract::{Path, Query, State};
use http::StatusCode;
use serde::Deserialize;
use std::sync::Arc;
use store::Node;
use store::localdb::LocalDB;

#[axum::debug_handler]
pub async fn create_node(
    State(local_db): State<Arc<LocalDB>>,
    Json(payload): Json<UpdateOrInsertNode>,
) -> (StatusCode, Json<Node>) {
    // insert your application logic here
    let node = Node {
        peer_id: payload.peer_id,
        actor: payload.actor.to_string(),
        update_at: std::time::SystemTime::now(),
    };
    local_db.update_node(node.clone()).await;
    (StatusCode::OK, Json(node))
}

#[axum::debug_handler]
pub async fn get_nodes(
    Query(query_params): Query<NodeQueryParams>,
    State(local_db): State<Arc<LocalDB>>,
) -> (StatusCode, Json<NodeListResponse>) {
    let actor = match query_params.actor {
        Some(actor) => {
            let _ = local_db.node_list(&actor, query_params.offset, query_params.limit).await;
            actor
        }
        None => "COMMITTEE".to_string(),
    };
    //TODO
    let node_list = NodeListResponse {
        nodes: vec![
            NodeDesc {
                peer_id: "QmNnooDu7bfjPFoTZYxMNLWUQJyrVwtbZg5gBMjTezGAJN".to_string(),
                actor: actor,
                update_at: std::time::SystemTime::now(),
                status: "online".to_string(),
            };
            query_params.limit
        ],
    };

    (StatusCode::OK, Json(node_list))
}
