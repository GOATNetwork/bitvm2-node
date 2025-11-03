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

/// Get node list
///
/// Returns a paginated list of BitVM2 network nodes based on query parameters. Supports filtering by
/// GOAT address, actor type, and online status. Automatically updates the current node's timestamp.
///
/// # Query Parameters
///
/// - `goat_addr`: GOAT address filter (optional) - filters nodes by their GOAT address
/// - `actor`: Actor type filter (optional) - filters by actor role (Operator, Watchtower, Verifier, All)
/// - `status`: Status filter (optional) - filters by online/offline status
/// - `offset`: Pagination offset (default: 0) - number of items to skip
/// - `limit`: Items per page (default: 10) - maximum number of items to return
///
/// # Returns
///
/// - `200 OK`: Successfully returns node list with status information
/// - `500 Internal Server Error`: Server internal error or database operation failed
/// - Response includes total count and paginated node data with online status
///
/// # Use Case
///
/// Frontend applications use this to display the list of active nodes in the BitVM2 network,
/// showing their roles, availability, and connection information.
///
/// # Example
///
/// ```http
/// GET /v1/nodes?actor=Operator&status=online&offset=0&limit=10
/// ```
///
/// Response example:
/// ```json
/// {
///   "nodes": [
///     {
///       "peer_id": "QmPeerId123abc...",
///       "actor": "Operator",
///       "name": "zkm",
///       "service_fee_rate": 0.001,
///       "updated_at": 1699123456,
///       "status": "online",
///       "goat_addr": "0x1234567890abcdef1234567890abcdef12345678",
///       "btc_pub_key": "02abc123def456...",
///       "socket_addr": "127.0.0.1:8080",
///       "reward": 1000000,
///       "available_peg_btc": 0
///     }
///   ],
///   "total": 1
/// }
/// ```
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
                    name: v.node_name,
                    service_fee_rate: v.service_fee_rate,
                    updated_at: v.updated_at,
                    status,
                    goat_addr: v.goat_addr,
                    btc_pub_key: v.btc_pub_key,
                    socket_addr: v.socket_addr,
                    reward: v.reward,
                    available_peg_btc: v.available_peg_btc,
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

/// Get nodes overview statistics
///
/// Returns statistical overview of all nodes in the BitVM2 network, including counts by actor type
/// and online/offline status. Automatically updates the current node's timestamp.
///
/// # Returns
///
/// - `200 OK`: Successfully returns nodes overview statistics
/// - `500 Internal Server Error`: Server internal error or database operation failed
/// - Response includes aggregated statistics for all node types and their status
///
/// # Use Case
///
/// Frontend applications use this to display dashboard statistics showing network health,
/// including total node counts by role and availability status.
///
/// # Example
///
/// ```http
/// GET /v1/nodes/overview
/// ```
///
/// Response example:
/// ```json
/// {
///   "nodes_overview": {
///     "total_operators": 10,
///     "online_operators": 8,
///     "total_watchtowers": 5,
///     "online_watchtowers": 4,
///     "total_verifiers": 3,
///     "online_verifiers": 2,
///     "total_nodes": 18,
///     "online_nodes": 14
///   }
/// }
/// ```
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

/// Get node by peer ID
///
/// Returns detailed information for a specific node based on its peer_id. If the requested
/// node is the current node, automatically updates its timestamp.
///
/// # Path Parameters
///
/// - `peer_id`: The unique peer identifier of the node (IPFS-style peer ID)
///
/// # Returns
///
/// - `200 OK`: Successfully returns node details (or None if not found)
/// - `500 Internal Server Error`: Server internal error or database operation failed
/// - Returns complete node information including actor type, addresses, and reward data
///
/// # Use Case
///
/// Applications use this to retrieve detailed information about a specific node in the network,
/// including its configuration, role, reward balance, and last active timestamp.
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
///   "btc_pub_key": "02abc...",
///   "goat_addr": "0x123...",
///   "socket_addr": "127.0.0.1:8080",
///   "reward": 1000000,
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
