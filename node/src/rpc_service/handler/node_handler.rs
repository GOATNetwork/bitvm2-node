use crate::rpc_service::handler::bitvm2_handler::reflect_goat_address;
use crate::rpc_service::node::{
    ALIVE_TIME_JUDGE_THRESHOLD, NodeDesc, NodeListResponse, NodeOverViewResponse, NodeQueryParams,
    UpdateOrInsertNodeRequest,
};
use crate::rpc_service::{AppState, current_time_secs};
use axum::Json;
use axum::extract::{Path, Query, State};
use http::StatusCode;
use std::sync::Arc;
use std::time::UNIX_EPOCH;
use store::{NODE_STATUS_OFFLINE, NODE_STATUS_ONLINE, Node};

#[axum::debug_handler]
pub async fn create_node(
    State(app_state): State<Arc<AppState>>,
    Json(payload): Json<UpdateOrInsertNodeRequest>,
) -> (StatusCode, Json<Node>) {
    let async_fn = || async move {
        let node = Node {
            peer_id: payload.peer_id.clone(),
            actor: payload.actor.to_string(),
            goat_addr: payload.goat_addr.to_string(),
            btc_pub_key: payload.btc_pub_key.to_string(),
            updated_at: std::time::SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
                as i64,
            created_at: std::time::SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
                as i64,
        };
        let mut storage_process = app_state.bitvm2_client.local_db.acquire().await?;
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
        let mut storage_process = app_state.bitvm2_client.local_db.acquire().await?;
        let time_threshold = current_time_secs() - ALIVE_TIME_JUDGE_THRESHOLD;
        let (_, goat_addr) = reflect_goat_address(query_params.goat_addr);
        let (nodes, total) = storage_process
            .node_list(
                query_params.actor,
                goat_addr,
                query_params.offset,
                query_params.limit,
                time_threshold,
                query_params.status,
            )
            .await?;

        let node_desc_list: Vec<NodeDesc> = nodes
            .into_iter()
            .map(|v| {
                let status: String = if v.updated_at <= time_threshold {
                    NODE_STATUS_OFFLINE.to_string()
                } else {
                    NODE_STATUS_ONLINE.to_string()
                };
                NodeDesc {
                    peer_id: v.peer_id,
                    actor: v.actor,
                    updated_at: v.updated_at,
                    status,
                    goat_addr: v.goat_addr,
                    btc_pub_key: v.btc_pub_key,
                }
            })
            .collect();

        Ok::<NodeListResponse, Box<dyn std::error::Error>>(NodeListResponse {
            nodes: node_desc_list,
            total,
        })
    };
    match async_fn().await {
        Ok(res) => (StatusCode::OK, Json(res)),
        Err(err) => {
            tracing::warn!("get_nodes failed, error:{}", err);
            (StatusCode::INTERNAL_SERVER_ERROR, Json(NodeListResponse { nodes: vec![], total: 0 }))
        }
    }
}

#[axum::debug_handler]
pub async fn get_nodes_overview(
    State(app_state): State<Arc<AppState>>,
) -> (StatusCode, Json<NodeOverViewResponse>) {
    let async_fn = || async move {
        let mut storage_process = app_state.bitvm2_client.local_db.acquire().await?;
        let time_threshold = current_time_secs() - ALIVE_TIME_JUDGE_THRESHOLD;
        let nodes_overview = storage_process.node_overview(time_threshold).await?;
        Ok::<NodeOverViewResponse, Box<dyn std::error::Error>>(NodeOverViewResponse {
            nodes_overview,
        })
    };
    match async_fn().await {
        Ok(res) => (StatusCode::OK, Json(res)),
        Err(err) => {
            tracing::warn!("get_nodes failed, error:{}", err);
            (StatusCode::INTERNAL_SERVER_ERROR, Json(NodeOverViewResponse::default()))
        }
    }
}

#[axum::debug_handler]
pub async fn get_node(
    Path(peer_id): Path<String>,
    State(app_state): State<Arc<AppState>>,
) -> (StatusCode, Json<Option<Node>>) {
    let async_fn = || async move {
        let mut storage_process = app_state.bitvm2_client.local_db.acquire().await?;
        let res = storage_process.node_by_id(peer_id.as_str()).await?;
        Ok::<Option<Node>, Box<dyn std::error::Error>>(res)
    };
    match async_fn().await {
        Ok(res) => (StatusCode::OK, Json(res)),
        Err(err) => {
            tracing::warn!("get_nodes failed, error:{}", err);
            (StatusCode::INTERNAL_SERVER_ERROR, Json(None))
        }
    }
}
