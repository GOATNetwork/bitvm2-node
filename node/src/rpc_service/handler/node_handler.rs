use crate::rpc_service::node::{
    ALIVE_TIME_JUDGE_THRESHOLD, NodeDesc, NodeListResponse, NodeOverViewResponse, NodeQueryParams,
};
use crate::rpc_service::response::{ApiResult, ErrorResponse};
use crate::rpc_service::validation::InputValidator;
use crate::rpc_service::{AppState, current_time_secs};
use crate::utils::reflect_goat_address;
use axum::Json;
use axum::extract::{Path, Query, State};
use bitvm2_lib::actors::Actor;
use http::StatusCode;
use std::sync::Arc;

use store::localdb::NodeQuery;
use store::{NODE_STATUS_OFFLINE, NODE_STATUS_ONLINE, Node};

#[axum::debug_handler]
pub async fn get_nodes(
    Query(query_params): Query<NodeQueryParams>,
    State(app_state): State<Arc<AppState>>,
) -> ApiResult<NodeListResponse> {
    // todo update node filed
    // Validate pagination parameters
    let (offset, limit) =
        InputValidator::validate_pagination(query_params.offset, query_params.limit)?;

    // Validate goat_addr format (if provided)
    if let Some(ref goat_addr) = query_params.goat_addr {
        InputValidator::validata_goat_address(goat_addr, "goat_addr")?;
    }

    // Validate actor field (if provided)
    if let Some(ref actor) = query_params.actor {
        InputValidator::validate_actor(actor, "actor")?;
    }
    let async_fn = || async move {
        let mut storage_process = app_state.local_db.acquire().await?;
        storage_process.update_node_timestamp(&app_state.peer_id, current_time_secs()).await?;
        let time_threshold = current_time_secs() - ALIVE_TIME_JUDGE_THRESHOLD;
        let (_, goat_addr) = reflect_goat_address(query_params.goat_addr);
        let actor = if let Some(actor) = query_params.actor
            && actor != Actor::All.to_string()
        {
            Some(actor)
        } else {
            None
        };
        let (nodes, total) = storage_process
            .find_nodes(&NodeQuery {
                actor,
                goat_addr,
                time_threshold,
                status_expect: query_params.status,
                order: None,
                offset: Some(offset),
                limit: Some(limit),
            })
            .await?;
        let node_desc_list: Vec<NodeDesc> = nodes
            .into_iter()
            .map(|v| {
                let status: String =
                    if v.updated_at >= time_threshold || v.peer_id == app_state.peer_id {
                        NODE_STATUS_ONLINE.to_string()
                    } else {
                        NODE_STATUS_OFFLINE.to_string()
                    };
                NodeDesc {
                    peer_id: v.peer_id,
                    actor: v.actor,
                    name: "zkm".to_string(),
                    service_fee: 0,
                    available_btc: 0,
                    updated_at: v.updated_at,
                    status,
                    goat_addr: v.goat_addr,
                    btc_pub_key: v.btc_pub_key,
                    socket_addr: v.socket_addr,
                    reward: v.reward,
                    available_peg_btc: 0,
                }
            })
            .collect();

        Ok::<NodeListResponse, Box<dyn std::error::Error>>(NodeListResponse {
            nodes: node_desc_list,
            total,
        })
    };
    match async_fn().await {
        Ok(res) => Ok((StatusCode::OK, Json(res))),
        Err(err) => {
            tracing::warn!("get nodes err:{:?}", err);
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "GET_NODES_ERROR".to_string(),
                    message: err.to_string(),
                }),
            ))
        }
    }
}

#[axum::debug_handler]
pub async fn get_nodes_overview(
    State(app_state): State<Arc<AppState>>,
) -> ApiResult<NodeOverViewResponse> {
    let async_fn = || async move {
        let mut storage_process = app_state.local_db.acquire().await?;
        storage_process.update_node_timestamp(&app_state.peer_id, current_time_secs()).await?;
        let time_threshold = current_time_secs() - ALIVE_TIME_JUDGE_THRESHOLD;
        let nodes_overview = storage_process.node_overview(time_threshold).await?;
        Ok::<NodeOverViewResponse, Box<dyn std::error::Error>>(NodeOverViewResponse {
            nodes_overview,
        })
    };
    match async_fn().await {
        Ok(res) => Ok((StatusCode::OK, Json(res))),
        Err(err) => {
            tracing::warn!("nodes overview err:{:?}", err);
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "NODES_OVERVIEW_ERROR".to_string(),
                    message: err.to_string(),
                }),
            ))
        }
    }
}

/// Get detailed information for a specific node
///
/// Get detailed information for a single node based on peer_id.
///
/// # Parameters
///
/// - `peer_id`: Node's peer_id
///
/// # Returns
///
/// - `200 OK`: Successfully returns node details
/// - `500 Internal Server Error`: Server internal error
///
/// # Example
///
/// ```http
/// GET /v1/nodes/QmPeerId...
/// ```
///
/// Response example:
/// ```json
/// {
///   "peer_id": "QmPeerId...",
///   "actor": "Operator",
///   "btc_pub_key": "02...",
///   "goat_addr": "0x...",
///   "socket_addr": "127.0.0.1:8080",
///   "reward": 0,
///   "updated_at": 1640995200,
///   "created_at": 1640995200
/// }
/// ```
#[axum::debug_handler]
pub async fn get_node(
    Path(peer_id): Path<String>,
    State(app_state): State<Arc<AppState>>,
) -> ApiResult<Option<Node>> {
    // Validate peer_id format
    InputValidator::validate_peer_id(&peer_id, "peer_id")?;
    let async_fn = || async move {
        let mut storage_process = app_state.local_db.acquire().await?;
        if peer_id == app_state.peer_id {
            storage_process.update_node_timestamp(&app_state.peer_id, current_time_secs()).await?;
        }
        let res = storage_process.node_by_id(peer_id.as_str()).await?;
        Ok::<Option<Node>, Box<dyn std::error::Error>>(res)
    };
    match async_fn().await {
        Ok(res) => Ok((StatusCode::OK, Json(res))),
        Err(err) => {
            tracing::warn!("get node err:{:?}", err);
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "GET_NODE_ERROR".to_string(),
                    message: err.to_string(),
                }),
            ))
        }
    }
}
