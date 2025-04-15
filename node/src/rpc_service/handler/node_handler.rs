use crate::rpc_service::AppState;
use crate::rpc_service::node::{
    NodeDesc, NodeListResponse, NodeQueryParams, UpdateOrInsertNodeRequest,
};
use axum::Json;
use axum::extract::{Query, State};
use http::StatusCode;
use std::sync::Arc;
use std::time::UNIX_EPOCH;
use store::Node;
use store::localdb::LocalDB;

#[axum::debug_handler]
pub async fn create_node(
    State(app_state): State<Arc<AppState>>,
    Json(payload): Json<UpdateOrInsertNodeRequest>,
) -> (StatusCode, Json<Node>) {
    let async_fn = || async move {
        let node = Node {
            peer_id: payload.peer_id.clone(),
            actor: payload.actor.to_string(),
            updated_at: std::time::SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
                as i64,
        };
        let mut storage_process = app_state.local_db.acquire().await?;
        let _ = storage_process.update_node(node.clone()).await?;
        Ok::<Node, Box<dyn std::error::Error>>(node)
    };
    match async_fn().await {
        Ok(res) => (StatusCode::OK, Json(res)),
        Err(err) => {
            tracing::warn!("create, error: {}", err);
            (StatusCode::INTERNAL_SERVER_ERROR, Json(Node::default()))
        }
    }
}

#[axum::debug_handler]
pub async fn get_nodes(
    Query(query_params): Query<NodeQueryParams>,
    State(app_state): State<Arc<AppState>>,
) -> (StatusCode, Json<NodeListResponse>) {
    let async_fn = || async move {
        let mut storage_process = app_state.local_db.acquire().await?;
        let nodes = storage_process
            .node_list(query_params.actor.clone(), query_params.offset, query_params.limit)
            .await?;
        let node_desc_list: Vec<NodeDesc> = nodes.into_iter().map(|v| v.into()).collect();
        Ok::<NodeListResponse, Box<dyn std::error::Error>>(NodeListResponse {
            nodes: node_desc_list,
        })
    };
    match async_fn().await {
        Ok(res) => (StatusCode::OK, Json(res)),
        Err(err) => {
            tracing::warn!("get_nodes failed, error:{}", err);
            (StatusCode::INTERNAL_SERVER_ERROR, Json(NodeListResponse { nodes: vec![] }))
        }
    }
}
