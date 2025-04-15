use crate::rpc_service::bitvm2::*;
use crate::rpc_service::node::ALIVE_TIME_JUDGE_THRESHOLD;
use crate::rpc_service::{AppState, current_time_secs};
use axum::Json;
use axum::extract::{Path, Query, State};
use http::StatusCode;
use serde_json::json;
use std::collections::HashMap;
use std::default::Default;
use std::sync::Arc;
use store::localdb::{ConnectionHolder, LocalDB, StorageProcessor};
use store::{
    BridgeInStatus, BridgeOutStatus, BridgePath, FilterGraphsInfo, Graph, GraphStatus, Instance,
    Message, MessageState,
};
use uuid::Uuid;

#[axum::debug_handler]
pub async fn bridge_in_tx_prepare(
    State(app_state): State<Arc<AppState>>,
    Json(payload): Json<BridgeInTransactionPreparerRequest>,
) -> (StatusCode, Json<BridgeInTransactionPrepareResponse>) {
    let async_fn = || async move {
        let instance_id = Uuid::parse_str(&payload.instance_id)?;
        let instance = Instance {
            instance_id,
            bridge_path: BridgePath::BtcToPGBtc.to_u8(),
            from_addr: payload.from.clone(),
            to_addr: payload.to.clone(),
            amount: payload.amount,
            created_at: current_time_secs(),
            updated_at: current_time_secs(),
            status: BridgeInStatus::Submitted.to_string(),
            ..Default::default()
        };

        let mut tx = app_state.local_db.start_transaction().await?;
        let _ = tx.create_instance(instance.clone()).await?;
        let content = serde_json::to_vec::<P2pUserData>(&(&payload).into())?;
        tx.create_message(Message {
            id: 0,
            actor: app_state.actor.to_string(),
            from_peer: app_state.peer_id.clone(),
            msg_type: "user_data".to_string(),
            content,
            state: MessageState::Pending.to_string(),
        })
        .await?;

        tx.commit().await?;
        Ok::<BridgeInTransactionPrepareResponse, Box<dyn std::error::Error>>(
            BridgeInTransactionPrepareResponse {},
        )
    };
    match async_fn().await {
        Ok(resp) => (StatusCode::OK, Json(resp)),
        Err(err) => {
            tracing::warn!("bridge_in_tx_prepare  err:{:?}", err);
            (StatusCode::INTERNAL_SERVER_ERROR, Json(BridgeInTransactionPrepareResponse {}))
        }
    }
}

#[axum::debug_handler]
pub async fn create_graph(
    State(app_state): State<Arc<AppState>>,
    Json(payload): Json<GraphGenerateRequest>,
) -> (StatusCode, Json<GraphGenerateResponse>) {
    let resp = GraphGenerateResponse {
        instance_id: payload.instance_id.clone(),
        graph_id: payload.graph_id.clone(),
        graph_ipfs_unsigned_txns: "".to_string(),
    };
    let mut resp_clone = resp.clone();
    let async_fn = || async move {
        // TODO create graph
        resp_clone.graph_ipfs_unsigned_txns =
            "[https://ipfs.io/ipfs/QmXxwbk8eA2bmKBy7YEjm5w1zKiG7g6ebF1JYfqWvnLnhH/pegin.hex]"
                .to_string();

        let graph = Graph {
            instance_id: Uuid::parse_str(&payload.instance_id)?,
            graph_id: Uuid::parse_str(&payload.graph_id)?,
            ..Default::default()
        };
        let mut storage_process = app_state.local_db.acquire().await?;
        storage_process.update_graph(graph).await?;
        Ok::<GraphGenerateResponse, Box<dyn std::error::Error>>(resp_clone)
    };
    match async_fn().await {
        Ok(resp) => (StatusCode::OK, Json(resp)),
        Err(err) => {
            tracing::warn!("create_graph  err:{:?}", err);
            (StatusCode::INTERNAL_SERVER_ERROR, Json(resp))
        }
    }
}

#[axum::debug_handler]
pub async fn graph_presign(
    Path(graph_id): Path<String>,
    State(app_state): State<Arc<AppState>>,
    Json(payload): Json<GraphPresignRequest>,
) -> (StatusCode, Json<GraphPresignResponse>) {
    let resp = GraphPresignResponse {
        instance_id: payload.instance_id.clone(),
        graph_id: graph_id.clone(),
        graph_ipfs_committee_txns:
            "[https://ipfs.io/ipfs/QmXxwbk8eA2bmKBy7YEjm5w1zKiG7g6ebF1JYfqWvnLnhH/pegin.hex]"
                .to_string(),
    };
    let resp_clone = resp.clone();
    let async_fn = || async move {
        //TODO update filed
        let mut tx = app_state.local_db.start_transaction().await?;
        let graph_id = Uuid::parse_str(&graph_id)?;
        let instance_id = Uuid::parse_str(&payload.instance_id)?;
        let mut instance = tx.get_instance(&instance_id).await?;
        let mut graph = tx.get_graph(&graph_id).await?;
        graph.graph_ipfs_base_url = payload.graph_ipfs_base_url;
        instance.status = BridgeInStatus::Presigned.to_string();
        let _ = tx.update_instance(instance.clone()).await?;
        let _ = tx.update_graph(graph.clone()).await?;
        let _ = tx.commit().await?;
        Ok::<GraphPresignResponse, Box<dyn std::error::Error>>(resp_clone)
    };
    match async_fn().await {
        Ok(resp) => (StatusCode::OK, Json(resp)),
        Err(err) => {
            tracing::warn!("graph_presign  err:{:?}", err);
            (StatusCode::INTERNAL_SERVER_ERROR, Json(resp))
        }
    }
}

#[axum::debug_handler]
pub async fn graph_presign_check(
    State(app_state): State<Arc<AppState>>,
    Json(payload): Json<GraphPresignCheckRequest>,
) -> (StatusCode, Json<GraphPresignCheckResponse>) {
    let resp = GraphPresignCheckResponse {
        instance_id: payload.instance_id.to_string(),
        instance_status: BridgeInStatus::Presigned,
        graph_status: HashMap::new(),
        tx: None,
    };
    let mut resp_clone = resp.clone();
    let async_fn = || async move {
        let instance_id = Uuid::parse_str(&payload.instance_id)?;
        let mut storage_process = app_state.local_db.acquire().await?;
        let instance = storage_process.get_instance(&instance_id).await?;
        resp_clone.tx = Some(instance);
        let graphs = storage_process.get_graph_by_instance_id(&payload.instance_id).await?;
        resp_clone.graph_status = graphs
            .into_iter()
            .map(|v| (v.graph_id.to_string(), GraphStatus::OperatorPresigned))
            .collect();
        Ok::<GraphPresignCheckResponse, Box<dyn std::error::Error>>(resp_clone)
    };
    match async_fn().await {
        Ok(resp) => (StatusCode::OK, Json(resp)),
        Err(err) => {
            tracing::warn!("graph_presign_check  err:{:?}", err);
            (StatusCode::INTERNAL_SERVER_ERROR, Json(resp))
        }
    }
}

#[axum::debug_handler]
pub async fn peg_btc_mint(
    Path(instance_id): Path<String>,
    State(app_state): State<Arc<AppState>>,
    Json(payload): Json<PegBTCMintRequest>,
) -> (StatusCode, Json<PegBTCMintResponse>) {
    let async_fn = || async move {
        let mut storage_process = app_state.local_db.acquire().await?;
        let _graphs: Vec<Graph> = storage_process.get_graphs(&payload.graph_ids).await?;
        let instance_id = Uuid::parse_str(&instance_id)?;
        let _instance = storage_process.get_instance(&instance_id).await?;
        /// TODO create graph_ipfs_committee_sig
        Ok::<PegBTCMintResponse, Box<dyn std::error::Error>>(PegBTCMintResponse {})
    };
    match async_fn().await {
        Ok(resp) => (StatusCode::OK, Json(resp)),
        Err(err) => {
            tracing::warn!("peg_btc_mint  err:{:?}", err);
            (StatusCode::INTERNAL_SERVER_ERROR, Json(PegBTCMintResponse {}))
        }
    }
}

#[axum::debug_handler]
pub async fn create_instance(
    State(app_state): State<Arc<AppState>>,
    Json(payload): Json<InstanceUpdateRequest>,
) -> (StatusCode, Json<InstanceUpdateResponse>) {
    let async_fn = || async move {
        let mut storage_process = app_state.local_db.acquire().await?;
        storage_process.create_instance(payload.instance).await?;
        Ok::<(), Box<dyn std::error::Error>>(())
    };
    match async_fn().await {
        Ok(_) => (StatusCode::OK, Json(InstanceUpdateResponse {})),
        Err(err) => {
            tracing::warn!("create_instance  err:{:?}", err);
            (StatusCode::INTERNAL_SERVER_ERROR, Json(InstanceUpdateResponse {}))
        }
    }
}

#[axum::debug_handler]
pub async fn update_instance(
    Path(instance_id): Path<String>,
    State(app_state): State<Arc<AppState>>,
    Json(payload): Json<InstanceUpdateRequest>,
) -> (StatusCode, Json<InstanceUpdateResponse>) {
    if instance_id != payload.instance.instance_id.to_string() {
        tracing::warn!("instance id in boy and path not match");
        return (StatusCode::BAD_REQUEST, Json(InstanceUpdateResponse {}));
    }

    let async_fn = || async move {
        let mut storage_process = app_state.local_db.acquire().await?;
        storage_process.update_instance(payload.instance).await?;
        Ok::<(), Box<dyn std::error::Error>>(())
    };
    match async_fn().await {
        Ok(_) => (StatusCode::OK, Json(InstanceUpdateResponse {})),
        Err(err) => {
            tracing::warn!("update_instance  err:{:?}", err);
            (StatusCode::INTERNAL_SERVER_ERROR, Json(InstanceUpdateResponse {}))
        }
    }
}

#[axum::debug_handler]
pub async fn get_instances_with_query_params(
    Query(params): Query<InstanceListRequest>,
    State(app_state): State<Arc<AppState>>,
) -> (StatusCode, Json<InstanceListResponse>) {
    let async_fn = || async move {
        let mut storage_process = app_state.local_db.acquire().await?;
        let instances = storage_process
            .instance_list(&params.user_address, params.offset, params.limit)
            .await?;
        Ok::<InstanceListResponse, Box<dyn std::error::Error>>(InstanceListResponse { instances })
    };
    match async_fn().await {
        Ok(res) => (StatusCode::OK, Json(res)),
        Err(err) => {
            tracing::warn!("get_instances_with_query_params err:{:?}", err);
            (StatusCode::OK, Json(InstanceListResponse { instances: vec![] }))
        }
    }
}

#[axum::debug_handler]
pub async fn get_instance(
    Path(instance_id): Path<String>,
    State(app_state): State<Arc<AppState>>,
) -> (StatusCode, Json<InstanceGetResponse>) {
    let async_fn = || async move {
        let instance_id = Uuid::parse_str(&instance_id)?;
        let mut storage_process = app_state.local_db.acquire().await?;
        let instance = storage_process.get_instance(&instance_id).await?;
        Ok::<InstanceGetResponse, Box<dyn std::error::Error>>(InstanceGetResponse { instance })
    };
    match async_fn().await {
        Ok(res) => (StatusCode::OK, Json(res)),
        Err(err) => {
            tracing::warn!("get_instances, err:{:?}", err);
            (StatusCode::OK, Json(InstanceGetResponse { instance: Instance::default() }))
        }
    }
}

#[axum::debug_handler]
pub async fn get_graph(
    Path(graph_id): Path<String>,
    State(app_state): State<Arc<AppState>>,
) -> (StatusCode, Json<GraphGetResponse>) {
    let async_fn = || async move {
        let graph_id = Uuid::parse_str(&graph_id).unwrap();
        let mut storage_process = app_state.local_db.acquire().await?;
        let graph = storage_process.get_graph(&graph_id).await?;
        Ok::<GraphGetResponse, Box<dyn std::error::Error>>(GraphGetResponse { graph })
    };
    match async_fn().await {
        Ok(res) => (StatusCode::OK, Json(res)),
        Err(err) => {
            tracing::warn!("get_graph  err:{:?}", err);
            (StatusCode::OK, Json(GraphGetResponse { graph: Graph::default() }))
        }
    }
}

#[axum::debug_handler]
pub async fn update_graph(
    Path(graph_id): Path<String>,
    State(app_state): State<Arc<AppState>>,
    Json(payload): Json<GraphUpdateRequest>,
) -> (StatusCode, Json<GraphUpdateResponse>) {
    if graph_id != payload.graph.graph_id.to_string() {
        tracing::warn!("graph id in boy and path not match");
        return (StatusCode::BAD_REQUEST, Json(GraphUpdateResponse {}));
    }

    let async_fn = || async move {
        let mut storage_process = app_state.local_db.acquire().await?;
        let _ = storage_process.update_graph(payload.graph).await?;
        Ok::<(), Box<dyn std::error::Error>>(())
    };
    match async_fn().await {
        Ok(_) => (StatusCode::OK, Json(GraphUpdateResponse {})),
        Err(err) => {
            tracing::warn!("update_graph  err:{:?}", err);
            (StatusCode::INTERNAL_SERVER_ERROR, Json(GraphUpdateResponse {}))
        }
    }
}

#[axum::debug_handler]
pub async fn graph_list(
    Query(pagination): Query<Pagination>,
    State(app_state): State<Arc<AppState>>,
    Json(payload): Json<GraphListRequest>,
) -> (StatusCode, Json<GraphListResponse>) {
    let resp = GraphListResponse::default();
    let mut resp_clone = resp.clone();
    let async_fn = || async move {
        let mut storage_process = app_state.local_db.acquire().await?;
        resp_clone.graphs = storage_process
            .filter_graphs(&FilterGraphsInfo {
                status: payload.status.to_string(),
                pegin_txid: payload.pegin_txid,
                offset: pagination.offset,
                limit: pagination.limit,
            })
            .await?;
        let (pegin_sum, pegin_count) =
            storage_process.get_sum_bridge_in_or_out(BridgePath::BtcToPGBtc.to_u8()).await?;
        let (pegout_sum, pegout_count) =
            storage_process.get_sum_bridge_in_or_out(BridgePath::PGBtcToBtc.to_u8()).await?;
        let (total, alive) = storage_process.get_nodes_info(ALIVE_TIME_JUDGE_THRESHOLD).await?;
        resp_clone.total_bridge_in_amount = pegin_sum;
        resp_clone.total_bridge_in_txn = pegin_count;
        resp_clone.total_bridge_out_amount = pegout_sum;
        resp_clone.total_bridge_out_txn = pegout_count;
        resp_clone.total_nodes = total;
        resp_clone.online_nodes = alive;
        Ok::<GraphListResponse, Box<dyn std::error::Error>>(resp_clone)
    };
    match async_fn().await {
        Ok(resp) => (StatusCode::OK, Json(resp)),
        Err(err) => {
            tracing::warn!("graph_list  err:{:?}", err);
            (StatusCode::INTERNAL_SERVER_ERROR, Json(resp))
        }
    }
}
