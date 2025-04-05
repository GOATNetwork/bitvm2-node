use crate::rpc_service::bitvm2::*;
use crate::rpc_service::current_time_secs;
use axum::Json;
use axum::extract::{Path, Query, State};
use http::StatusCode;
use std::collections::HashMap;
use std::default::Default;
use std::sync::Arc;
use store::localdb::LocalDB;
use store::{BridgeInStatus, BridgePath, FilterGraphsInfo, Graph, GraphStatus, Instance};

#[axum::debug_handler]
pub async fn bridge_in_tx_prepare(
    State(local_db): State<Arc<LocalDB>>,
    Json(payload): Json<BridgeInTransactionPrepare>,
) -> (StatusCode, Json<BridgeInTransactionPrepareResponse>) {
    // insert your application logic here
    let instance = Instance {
        instance_id: payload.instance_id,
        bridge_path: BridgePath::BtcToPGBtc.to_u8(),
        from: payload.from,
        to: payload.to,
        // in sat
        amount: payload.amount,
        created_at: current_time_secs(),

        // updating time
        update_at: current_time_secs(),

        // BridgeInStatus | BridgeOutStutus
        status: BridgeInStatus::Submitted.to_string(),

        ..Default::default() //pub goat_txid: String,
                             //pub btc_txid: String,
    };

    local_db.create_instance(instance.clone()).await;

    let resp = BridgeInTransactionPrepareResponse {};
    (StatusCode::OK, Json(resp))
}

#[axum::debug_handler]
pub async fn create_graph(
    State(local_db): State<Arc<LocalDB>>,
    Json(payload): Json<GraphGenerate>,
) -> (StatusCode, Json<GraphGenerateResponse>) {
    let graph = Graph {
        instance_id: payload.instance_id.clone(),
        graph_id: payload.graph_id.clone(),
        ..Default::default()
    };
    local_db.update_graph(graph).await;
    /// TODO
    let resp = GraphGenerateResponse {
        instance_id: payload.instance_id,
        graph_id: payload.graph_id,
        graph_ipfs_unsigned_txns:
            "[https://ipfs.io/ipfs/QmXxwbk8eA2bmKBy7YEjm5w1zKiG7g6ebF1JYfqWvnLnhH/pegin.hex]"
                .to_string(),
    };
    (StatusCode::OK, Json(resp))
}

#[axum::debug_handler]
pub async fn graph_presign(
    Path(graph_id): Path<String>,
    State(local_db): State<Arc<LocalDB>>,
    Json(payload): Json<GraphPresign>,
) -> (StatusCode, Json<GraphPresignResponse>) {
    let graph = local_db.get_graph(&graph_id).await.expect("get_graph");
    let instance = local_db.get_instance(&payload.instance_id).await.expect("get_graph");
    /// TODO create graph_ipfs_committee_sig
    local_db.update_instance(instance.clone()).await;
    local_db.update_graph(graph.clone()).await;
    let resp = GraphPresignResponse {
        instance_id: instance.instance_id,
        graph_id: graph.graph_id,
        graph_ipfs_committee_txns:
            "[https://ipfs.io/ipfs/QmXxwbk8eA2bmKBy7YEjm5w1zKiG7g6ebF1JYfqWvnLnhH/pegin.hex]"
                .to_string(),
    };
    (StatusCode::OK, Json(resp))
}

#[axum::debug_handler]
pub async fn graph_presign_check(
    State(local_db): State<Arc<LocalDB>>,
    Json(payload): Json<GraphPresignCheck>,
) -> (StatusCode, Json<GraphPresignCheckResponse>) {
    // TODO
    let instance = local_db.get_instance(&payload.instance_id).await.expect("get_instance");
    let graph_vec = local_db
        .get_graph_by_instance_id(&payload.instance_id)
        .await
        .expect("get_graph_by_instance_id");
    let graph_status: HashMap<String, GraphStatus> =
        graph_vec.into_iter().map(|v| (v.graph_id, GraphStatus::OperatorPresigned)).collect();

    let resp = GraphPresignCheckResponse {
        instance_id: payload.instance_id.to_string(),
        instance_status: BridgeInStatus::Presigned,
        graph_status,
        tx: Some(instance),
    };
    (StatusCode::OK, Json(resp))
}

#[axum::debug_handler]
pub async fn peg_btc_mint(
    Path(instance_id): Path<String>,
    State(local_db): State<Arc<LocalDB>>,
    Json(payload): Json<PegBTCMint>,
) -> (StatusCode, Json<PegBTCMintResponse>) {
    let graphs = local_db.get_graphs(&payload.graph_id).await.expect("get_graphs");
    let instance = local_db.get_instance(&instance_id).await.expect("get_instance");
    /// TODO create graph_ipfs_committee_sig
    local_db.update_instance(instance.clone()).await;
    // local_db.update_graph(graphs.clone()).await;
    let resp = PegBTCMintResponse {};
    (StatusCode::OK, Json(resp))
}

#[axum::debug_handler]
pub async fn bridge_out_tx_prepare(
    State(local_db): State<Arc<LocalDB>>,
    Json(payload): Json<BridgeOutTransactionPrepare>,
) -> (StatusCode, Json<BridgeOutTransactionPrepareResponse>) {

    /// TODO
    let instance = Instance {
        instance_id: payload.instance_id,
        bridge_path: BridgePath::BtcToPGBtc.to_u8(),
        from: "from_TODO".to_string(),
        to: "to_TODO".to_string(),
        // in sat
        amount: 10000,
        created_at: current_time_secs(),
        // updating time
        update_at: current_time_secs(),
        // BridgeInStatus | BridgeOutStutus
        status: BridgeInStatus::Submitted.to_string(),
        goat_txid : payload.pegout_txid.clone(),
        ..Default::default()
    };

    local_db.create_instance(instance.clone()).await;
    /// TODO create graph_ipfs_committee_sig
    local_db.update_instance(instance.clone()).await;
    let resp = BridgeOutTransactionPrepareResponse {
        instance_id: instance.instance_id.clone(),
        btc_hashed_timelock_utxo: UTXO {
            txid: "ffc54e9cf37d9f87ebaa703537e93e20caece862d9bc1c463c487583905ec49c".to_string(), // for test
            vout: 0,
            value: 100,
        },
        operator_refund_address: "tb1qkrhp3khxam3hj2kl9y77m2uctj2hkyh248chkp".to_string(), // for test
    };
    (StatusCode::OK, Json(resp))
}

#[axum::debug_handler]
pub async fn bridge_out_user_claim(
    Path(instance_id): Path<String>,
    State(local_db): State<Arc<LocalDB>>,
    Json(payload): Json<BridgeOutUserClaimRequest>,
) -> (StatusCode, Json<BridgeOutUserClaimResponse>) {
    let mut instance = local_db.get_instance(&instance_id).await.expect("get_instance");
    instance.goat_txid = payload.pegout_txid.clone();
    /// TODO create graph_ipfs_committee_sig
    local_db.update_instance(instance.clone()).await;
    let resp = BridgeOutUserClaimResponse {
        instance_id: instance_id.to_string(),
        claim_txid: "ffc54e9cf37d9f87ebaa703537e93e20caece862d9bc1c463c487583905ec49c".to_string(),
    };
    (StatusCode::OK, Json(resp))
}

#[axum::debug_handler]
pub async fn get_instances_with_query_params(
    Query(params): Query<InstanceListRequest>,
    State(local_db): State<Arc<LocalDB>>,
) -> (StatusCode, Json<InstanceListResponse>) {
    ///TODO
    let mut instances = local_db
        .get_instance_by_user(&params.user_address, params.offset, params.limit)
        .await
        .expect("get_instance_by_user");
    let resp = InstanceListResponse { instances };
    (StatusCode::OK, Json(resp))
}

#[axum::debug_handler]
pub async fn get_instance(
    Path(instance_id): Path<String>,
    State(local_db): State<Arc<LocalDB>>,
) -> (StatusCode, Json<InstanceGetResponse>) {
    ///TODO
    (
        StatusCode::OK,
        Json(InstanceGetResponse {
            instance: local_db.get_instance(&instance_id).await.expect("get instance"),
        }),
    )
}

#[axum::debug_handler]
pub async fn get_graph(
    Path(graph_id): Path<String>,
    State(local_db): State<Arc<LocalDB>>,
) -> (StatusCode, Json<GraphGetResponse>) {
    ///TODO
    (
        StatusCode::OK,
        Json(GraphGetResponse { graph: local_db.get_graph(&graph_id).await.expect("get graph") }),
    )
}
#[axum::debug_handler]
pub async fn graph_list(
    Query(pagination): Query<Pagination>,
    State(local_db): State<Arc<LocalDB>>,
    Json(payload): Json<GraphListRequest>,
) -> (StatusCode, Json<GraphListResponse>) {
    ///TODO
    let graphs = local_db
        .filter_graphs(&FilterGraphsInfo {
            status: payload.status,
            pegin_txid: payload.pegin_txid,
            offset: pagination.offset,
            limit: pagination.limit,
        })
        .await
        .expect("filter_graphs");
    let resp = GraphListResponse {
        graphs,
        total_bridge_in_amount: 100000,
        total_bridge_in_txn: 20000,
        total_bridge_out_amount: 30000,
        total_bridge_out_txn: 400000,
        online_nodes: 30,
        total_nodes: 40,
    };
    (StatusCode::OK, Json(resp))
}
