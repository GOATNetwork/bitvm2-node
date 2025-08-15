use crate::rpc_service::node::{
    ALIVE_TIME_JUDGE_THRESHOLD, NodeDesc, NodeListResponse, NodeOverViewResponse, NodeQueryParams,
    UpdateOrInsertNodeRequest,
};
use crate::rpc_service::{AppState, current_time_secs};
use crate::utils::reflect_goat_address;
use axum::Json;
use axum::extract::{Path, Query, State};
use bitvm2_lib::actors::Actor;
use http::StatusCode;
use std::sync::Arc;
use std::time::UNIX_EPOCH;
use store::{NODE_STATUS_OFFLINE, NODE_STATUS_ONLINE, Node};

/// Create or update node information
///
/// Create a new node record or update existing node information. Node information includes peer_id, role, addresses, etc.
/// The function uses INSERT OR REPLACE, so it can also update existing nodes.
///
/// # Request Body
///
/// Contains complete node information including peer_id, role, addresses, etc.
///
/// # Returns
///
/// - `200 OK`: Successfully created or updated node
/// - `500 Internal Server Error`: Server internal error
///
/// # Example
///
/// ```http
/// POST /v1/nodes
/// Content-Type: application/json
///
/// {
///   "peer_id": "QmPeerId...",
///   "actor": "Operator",
///   "btc_pub_key": "02...",
///   "goat_addr": "0x...",
///   "socket_addr": "127.0.0.1:8080",
///   "reward": 0
/// }
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
pub async fn create_node(
    State(app_state): State<Arc<AppState>>,
    Json(payload): Json<UpdateOrInsertNodeRequest>,
) -> (StatusCode, Json<Node>) {
    let async_fn = || async move {
        let node = Node {
            peer_id: payload.peer_id.clone(),
            actor: payload.actor.to_string(),
            goat_addr: payload.goat_addr.clone(),
            btc_pub_key: payload.btc_pub_key.clone(),
            socket_addr: payload.socket_addr.clone(),
            reward: 0,
            updated_at: std::time::SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
                as i64,
            created_at: std::time::SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
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

/// Get node list
///
/// Get node list based on query parameters, supports filtering by role, address, status and pagination.
///
/// # Query Parameters
///
/// - `actor`: Node role filter (optional, supports: Operator, Challenger, Relayer, All)
/// - `goat_addr`: GOAT address filter (optional)
/// - `status`: Node status filter (optional, supports: Online, Offline)
/// - `offset`: Pagination offset (default: 0)
/// - `limit`: Items per page (default: 10)
///
/// # Returns
///
/// - `200 OK`: Successfully returns node list
/// - `500 Internal Server Error`: Server internal error
///
/// # Example
///
/// ```http
/// GET /v1/nodes?actor=Operator&status=Online&offset=0&limit=10
/// ```
///
/// Response example:
/// ```json
/// {
///   "nodes": [
///     {
///       "peer_id": "QmPeerId...",
///       "actor": "Operator",
///       "status": "Online",
///       "goat_addr": "0x...",
///       "btc_pub_key": "02...",
///       "socket_addr": "127.0.0.1:8080",
///       "reward": 0,
///       "updated_at": 1640995200
///     }
///   ],
///   "total": 1
/// }
/// ```
#[axum::debug_handler]
pub async fn get_nodes(
    Query(query_params): Query<NodeQueryParams>,
    State(app_state): State<Arc<AppState>>,
) -> (StatusCode, Json<NodeListResponse>) {
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
            .node_list(
                actor,
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
                let status: String =
                    if v.updated_at >= time_threshold || v.peer_id == app_state.peer_id {
                        NODE_STATUS_ONLINE.to_string()
                    } else {
                        NODE_STATUS_OFFLINE.to_string()
                    };
                NodeDesc {
                    peer_id: v.peer_id,
                    actor: v.actor,
                    updated_at: v.updated_at,
                    status,
                    goat_addr: v.goat_addr,
                    btc_pub_key: v.btc_pub_key,
                    socket_addr: v.socket_addr,
                    reward: v.reward,
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

/// Get node overview statistics
///
/// Returns overall statistics for nodes in the network, including node counts by role and online status.
///
/// # Returns
///
/// - `200 OK`: Successfully returns node overview information
/// - `500 Internal Server Error`: Server internal error
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
///     "total_nodes": 8,
///     "online_nodes": 5,
///     "operator_count": 2,
///     "challenger_count": 3,
///     "relayer_count": 3,
///     "online_operator_count": 1,
///     "online_challenger_count": 2,
///     "online_relayer_count": 2
///   }
/// }
/// ```
#[axum::debug_handler]
pub async fn get_nodes_overview(
    State(app_state): State<Arc<AppState>>,
) -> (StatusCode, Json<NodeOverViewResponse>) {
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
        Ok(res) => (StatusCode::OK, Json(res)),
        Err(err) => {
            tracing::warn!("get_nodes failed, error:{}", err);
            (StatusCode::INTERNAL_SERVER_ERROR, Json(NodeOverViewResponse::default()))
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
) -> (StatusCode, Json<Option<Node>>) {
    let async_fn = || async move {
        let mut storage_process = app_state.local_db.acquire().await?;
        if peer_id == app_state.peer_id {
            storage_process.update_node_timestamp(&app_state.peer_id, current_time_secs()).await?;
        }
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
