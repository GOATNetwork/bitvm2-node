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
    State(local_db): State<Arc<LocalDB>>,
    Json(payload): Json<UpdateOrInsertNodeRequest>,
) -> (StatusCode, Json<Node>) {
    let node = Node {
        peer_id: payload.peer_id,
        actor: payload.actor.to_string(),
        updated_at: std::time::SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
            as i64,
    };
    match local_db.update_node(node.clone()).await {
        Ok(res) => {
            tracing::info!("create node, db rows affected:{}", res);
            (StatusCode::OK, Json(node))
        }
        Err(err) => {
            tracing::warn!("create node:{:?}, error: {}", node, err);
            (StatusCode::INTERNAL_SERVER_ERROR, Json(Node::default()))
        }
    }
}

#[axum::debug_handler]
pub async fn get_nodes(
    Query(query_params): Query<NodeQueryParams>,
    State(local_db): State<Arc<LocalDB>>,
) -> (StatusCode, Json<NodeListResponse>) {
    match local_db
        .node_list(query_params.actor.clone(), query_params.offset, query_params.limit)
        .await
    {
        Ok(nodes) => {
            let node_desc_list: Vec<NodeDesc> = nodes.into_iter().map(|v| v.into()).collect();
            (StatusCode::OK, Json(NodeListResponse { nodes: node_desc_list }))
        }
        Err(err) => {
            tracing::warn!("get_nodes failed, params: {:?}, error:{}", query_params, err);
            (StatusCode::INTERNAL_SERVER_ERROR, Json(NodeListResponse { nodes: vec![] }))
        }
    }
}
