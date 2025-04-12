use crate::rpc_service::bitvm2::*;
use crate::rpc_service::node::ALIVE_TIME_JUDGE_THRESHOLD;
use crate::rpc_service::{AppState, current_time_secs};
use axum::Json;
use axum::extract::{Path, Query, State};
use http::StatusCode;
use std::collections::HashMap;
use std::default::Default;
use std::sync::Arc;
use store::localdb::LocalDB;
use store::{
    BridgeInStatus, BridgeOutStatus, BridgePath, FilterGraphsInfo, Graph, GraphStatus, Instance,
};

#[axum::debug_handler]
pub async fn bridge_in_tx_prepare(
    State(app_state): State<Arc<AppState>>,
    Json(payload): Json<BridgeInTransactionPreparerRequest>,
) -> (StatusCode, Json<BridgeInTransactionPrepareResponse>) {
    let instance = Instance {
        instance_id: payload.instance_id.clone(),
        bridge_path: BridgePath::BtcToPGBtc.to_u8(),
        from_addr: payload.from.clone(),
        to_addr: payload.to.clone(),
        amount: payload.amount,
        created_at: current_time_secs(),
        updated_at: current_time_secs(),
        status: BridgeInStatus::Submitted.to_string(),
        ..Default::default()
    };

    match app_state.local_db.create_instance(instance.clone()).await {
        Ok(_res) => (StatusCode::OK, Json(BridgeInTransactionPrepareResponse {})),
        Err(err) => {
            tracing::warn!("bridge_in_tx_prepare, params:{:?} err:{:?}", payload, err);
            (StatusCode::INTERNAL_SERVER_ERROR, Json(BridgeInTransactionPrepareResponse {}))
        }
    }
}

#[axum::debug_handler]
pub async fn create_graph(
    State(app_state): State<Arc<AppState>>,
    Json(payload): Json<GraphGenerateRequest>,
) -> (StatusCode, Json<GraphGenerateResponse>) {
    // TODO create graph
    let graph_ipfs_unsigned_txns =
        "[https://ipfs.io/ipfs/QmXxwbk8eA2bmKBy7YEjm5w1zKiG7g6ebF1JYfqWvnLnhH/pegin.hex]"
            .to_string();
    let graph = Graph {
        instance_id: payload.instance_id.clone(),
        graph_id: payload.graph_id.clone(),
        ..Default::default()
    };

    match app_state.local_db.update_graph(graph).await {
        Ok(_res) => {
            let resp = GraphGenerateResponse {
                instance_id: payload.instance_id,
                graph_id: payload.graph_id,
                graph_ipfs_unsigned_txns,
            };
            (StatusCode::OK, Json(resp))
        }
        Err(err) => {
            tracing::warn!("create_graph,  params:{:?} err:{:?}", payload, err);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(GraphGenerateResponse {
                    instance_id: payload.instance_id,
                    graph_id: payload.graph_id,
                    graph_ipfs_unsigned_txns: "".to_string(),
                }),
            )
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
        let graph = app_state.local_db.get_graph(&graph_id).await?;
        let instance = app_state.local_db.get_instance(&payload.instance_id).await?;
        let _ = app_state.local_db.update_instance(instance.clone()).await?;
        let _ = app_state.local_db.update_graph(graph.clone()).await?;
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
    let mut resp = GraphPresignCheckResponse {
        instance_id: payload.instance_id.to_string(),
        instance_status: BridgeInStatus::Presigned,
        graph_status: HashMap::new(),
        tx: None,
    };
    let mut resp_clone = resp.clone();
    let async_fn = || async move {
        let instance = app_state.local_db.get_instance(&payload.instance_id).await?;
        resp_clone.tx = Some(instance);
        let graphs = app_state.local_db.get_graph_by_instance_id(&payload.instance_id).await?;
        resp_clone.graph_status =
            graphs.into_iter().map(|v| (v.graph_id, GraphStatus::OperatorPresigned)).collect();
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
        let _graphs: Vec<Graph> = app_state.local_db.get_graphs(&payload.graph_ids).await?;
        let _instance = app_state.local_db.get_instance(&instance_id).await?;
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

// #[axum::debug_handler]
// pub async fn bridge_out_tx_prepare(
//    State(app_state): State<Arc<AppState>>,
//     Json(payload): Json<BridgeOutTransactionPrepareRequest>,
// ) -> (StatusCode, Json<BridgeOutTransactionPrepareResponse>) {
//     // TODO
//     let instance = Instance {
//         instance_id: payload.instance_id.clone(),
//         bridge_path: BridgePath::BtcToPGBtc.to_u8(),
//         from_addr: "e38f368dd8187af3af56d1af3ad3125152cfbcf9".to_string(),
//         to_addr: "tb1qkrhp3khxam3hj2kl9y77m2uctj2hkyh248chkp".to_string(),
//         amount: 10000,
//         created_at: current_time_secs(),
//         updated_at: current_time_secs(),
//         status: BridgeOutStatus::L2Locked.to_string(),
//         ..Default::default()
//     };
//
//     match app_state.local_db.create_instance(instance.clone()).await {
//         Ok(_res) => {
//             let resp = BridgeOutTransactionPrepareResponse {
//                 instance_id: instance.instance_id.clone(),
//             };
//             (StatusCode::OK, Json(resp))
//         }
//         Err(err) => {
//             tracing::warn!("bridge_out_tx_prepare, params:{:?} err:{:?}", payload, err);
//             (
//                 StatusCode::INTERNAL_SERVER_ERROR,
//                 Json(BridgeOutTransactionPrepareResponse::default()),
//             )
//         }
//     }
// }

#[axum::debug_handler]
pub async fn create_instance(
    State(app_state): State<Arc<AppState>>,
    Json(payload): Json<InstanceUpdateRequest>,
) -> (StatusCode, Json<InstanceUpdateResponse>) {
    match app_state.local_db.create_instance(payload.instance).await {
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
    if instance_id != payload.instance.instance_id {
        tracing::warn!("instance id in boy and path not match");
        return (StatusCode::BAD_REQUEST, Json(InstanceUpdateResponse {}));
    }
    match app_state.local_db.update_instance(payload.instance).await {
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
    match app_state.local_db.instance_list(&params.user_address, params.offset, params.limit).await
    {
        Ok(instances) => (StatusCode::OK, Json(InstanceListResponse { instances })),
        Err(err) => {
            tracing::warn!("get_instances_with_query_params,  params:{:?} err:{:?}", params, err);
            (StatusCode::OK, Json(InstanceListResponse { instances: vec![] }))
        }
    }
}

#[axum::debug_handler]
pub async fn get_instance(
    Path(instance_id): Path<String>,
    State(app_state): State<Arc<AppState>>,
) -> (StatusCode, Json<InstanceGetResponse>) {
    match app_state.local_db.get_instance(&instance_id).await {
        Ok(instance) => (StatusCode::OK, Json(InstanceGetResponse { instance })),
        Err(err) => {
            tracing::warn!("get_instances, instance_id:{:?} err:{:?}", instance_id, err);
            (StatusCode::OK, Json(InstanceGetResponse { instance: Instance::default() }))
        }
    }
}

#[axum::debug_handler]
pub async fn get_graph(
    Path(graph_id): Path<String>,
    State(app_state): State<Arc<AppState>>,
) -> (StatusCode, Json<GraphGetResponse>) {
    ///TODO
    (
        StatusCode::OK,
        Json(GraphGetResponse {
            graph: app_state.local_db.get_graph(&graph_id).await.expect("get graph"),
        }),
    )
}

#[axum::debug_handler]
pub async fn update_graph(
    Path(graph_id): Path<String>,
    State(app_state): State<Arc<AppState>>,
    Json(payload): Json<GraphUpdateRequest>,
) -> (StatusCode, Json<GraphUpdateResponse>) {
    if graph_id != payload.graph.graph_id {
        tracing::warn!("graph id in boy and path not match");
        return (StatusCode::BAD_REQUEST, Json(GraphUpdateResponse {}));
    }
    match app_state.local_db.update_graph(payload.graph).await {
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
    //TODO use operator
    let resp = GraphListResponse::default();
    let mut resp_clone = resp.clone();
    let async_fn = || async move {
        resp_clone.graphs = app_state
            .local_db
            .filter_graphs(&FilterGraphsInfo {
                status: payload.status.to_string(),
                pegin_txid: payload.pegin_txid,
                offset: pagination.offset,
                limit: pagination.limit,
            })
            .await?;
        let (pegin_sum, pegin_count) =
            app_state.local_db.get_sum_bridge_in_or_out(BridgePath::BtcToPGBtc.to_u8()).await?;
        let (pegout_sum, pegout_count) =
            app_state.local_db.get_sum_bridge_in_or_out(BridgePath::PGBtcToBtc.to_u8()).await?;
        let (total, alive) = app_state.local_db.get_nodes_info(ALIVE_TIME_JUDGE_THRESHOLD).await?;
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
