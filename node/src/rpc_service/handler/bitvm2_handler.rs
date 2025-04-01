use crate::rpc_service::bitvm2::*;
use crate::rpc_service::current_time_secs;
use axum::Json;
use axum::extract::State;
use http::StatusCode;
use std::collections::HashMap;
use std::default::Default;
use std::sync::Arc;
use store::localdb::LocalDB;
use store::{BridgeInStatus, FilterGraphsInfo, Graph, GraphStatus, Instance};

#[axum::debug_handler]
pub async fn create_instance(
    State(local_db): State<Arc<LocalDB>>,
    Json(payload): Json<BridgeInTransactionPrepare>,
) -> (StatusCode, Json<BridgeInTransactionPrepareResponse>) {
    // insert your application logic here
    let tx = Instance {
        instance_id: payload.instance_id,
        bridge_path: payload.bridge_path,
        from: payload.from,
        to: payload.to,
        // in sat
        amount: payload.amount,
        created_at: current_time_secs(),

        // updating time
        eta_at: current_time_secs(),

        // BridgeInStatus | BridgeOutStutus
        status: BridgeInStatus::Submitted.to_string(),

        ..Default::default() //pub goat_txid: String,
                             //pub btc_txid: String,
    };

    local_db.create_instance(tx.clone()).await;

    let resp = BridgeInTransactionPrepareResponse {};
    (StatusCode::OK, Json(resp))
}

#[axum::debug_handler]
pub async fn graph_generate(
    State(local_db): State<Arc<LocalDB>>,
    Json(payload): Json<GraphGenerate>,
) -> (StatusCode, Json<GraphGenerateResponse>) {
    let graph = Graph {
        instance_id: payload.instance_id.clone(),
        graph_id: payload.graph_id.clone(),
        ..Default::default()
    };
    local_db.update_graph(graph).await;
    ///unsiigned_txns, operator signature, this steps ask operator to publish unsigned txns
    /// TODO
    let resp = GraphGenerateResponse {
        instance_id: payload.instance_id,
        graph_id: payload.graph_id,
        graph_ipfs_unsigned_txns:
            "https://ipfs.io/ipfs/QmXoypizjW3WknFiJnKLwHCnL72vedxjQkDDP1mXWo6uco/unsigned_txn"
                .to_string(),
        graph_ipfs_operator_sig:
            "https://ipfs.io/ipfs/QmXoypizjW3WknFiJnKLwHCnL72vedxjQkDDP1mXWo6uco/operator_sign"
                .to_string(),
    };
    (StatusCode::OK, Json(resp))
}

#[axum::debug_handler]
pub async fn graph_presign(
    State(local_db): State<Arc<LocalDB>>,
    Json(payload): Json<GraphPresign>,
) -> (StatusCode, Json<GraphPresignResponse>) {
    let graph = local_db.get_graph(&payload.graph_id).await.expect("get_graph");
    let instance = local_db.get_instance(&payload.instance_id).await.expect("get_graph");
    /// TODO create graph_ipfs_committee_sig
    local_db.update_instance(instance.clone()).await;
    local_db.update_graph(graph.clone()).await;
    let resp = GraphPresignResponse {
        instance_id: instance.instance_id,
        graph_id: graph.graph_id,
        graph_ipfs_committee_sig:
            "https://ipfs.io/ipfs/QmXoypizjW3WknFiJnKLwHCnL72vedxjQkDDP1mXWo6uco/committe_sign"
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
        instace_status: BridgeInStatus::Presigned,
        graph_status,
        tx: Some(instance),
    };
    (StatusCode::OK, Json(resp))
}

#[axum::debug_handler]
pub async fn peg_btc_mint(
    State(local_db): State<Arc<LocalDB>>,
    Json(payload): Json<PegBTCMint>,
) -> (StatusCode, Json<PegBTCMintResponse>) {
    let graphs = local_db.get_graphs(&payload.graph_id).await.expect("get_graphs");
    let instance = local_db.get_instance(&payload.instance_id).await.expect("get_instance");
    /// TODO create graph_ipfs_committee_sig
    local_db.update_instance(instance.clone()).await;
    let resp = PegBTCMintResponse {};
    (StatusCode::OK, Json(resp))
}

#[axum::debug_handler]
pub async fn bridge_out_tx_prepare(
    State(local_db): State<Arc<LocalDB>>,
    Json(payload): Json<BridgeOutTransactionPrepare>,
) -> (StatusCode, Json<BridgeOutTransactionPrepareResponse>) {
    let mut instance = local_db.get_instance(&payload.instance_id).await.expect("get_instance");
    instance.goat_txid = payload.pegout_txid.clone();
    /// TODO create graph_ipfs_committee_sig
    local_db.update_instance(instance.clone()).await;
    let resp = BridgeOutTransactionPrepareResponse {
        instance_id: instance.instance_id.clone(),
        btc_hashed_timelock_utxo: UTXO {
            txid: "ffc54e9cf37d9f87ebaa703537e93e20caece862d9bc1c463c487583905ec49c".to_string(), // for test
            vout: 0,
        },
        operator_refund_address: "tb1qkrhp3khxam3hj2kl9y77m2uctj2hkyh248chkp".to_string(), // for test
    };
    (StatusCode::OK, Json(resp))
}

#[axum::debug_handler]
pub async fn bridge_out_user_claim(
    State(local_db): State<Arc<LocalDB>>,
    Json(payload): Json<BridgeOutUserClaimRequest>,
) -> (StatusCode, Json<BridgeOutUserClaimResponse>) {
    let mut instance = local_db.get_instance(&payload.instance_id).await.expect("get_instance");
    instance.goat_txid = payload.pegout_txid.clone();
    /// TODO create graph_ipfs_committee_sig
    local_db.update_instance(instance.clone()).await;
    let resp = BridgeOutUserClaimResponse {
        instance_id: payload.instance_id.to_string(),
        claim_txid: "ffc54e9cf37d9f87ebaa703537e93e20caece862d9bc1c463c487583905ec49c".to_string(),
    };
    (StatusCode::OK, Json(resp))
}

#[axum::debug_handler]
pub async fn user_instance_list(
    State(local_db): State<Arc<LocalDB>>,
    Json(payload): Json<InstanceListRequest>,
) -> (StatusCode, Json<InstanceListResponse>) {
    ///TODO
    let mut instances = local_db
        .get_instance_by_user(&payload.user_address, payload.offset, payload.limit)
        .await
        .expect("get_instance_by_user");
    let resp = InstanceListResponse { instances };
    (StatusCode::OK, Json(resp))
}

#[axum::debug_handler]
pub async fn get_instance(
    State(local_db): State<Arc<LocalDB>>,
    Json(payload): Json<InstanceGetRequest>,
) -> (StatusCode, Json<InstanceGetResponse>) {
    ///TODO
    let mut instance = local_db.get_instance(&payload.instance_id).await.expect("get_instance");
    let resp = InstanceGetResponse { instance };
    (StatusCode::OK, Json(resp))
}

#[axum::debug_handler]
pub async fn graph_list(
    State(local_db): State<Arc<LocalDB>>,
    Json(payload): Json<GraphListRequest>,
) -> (StatusCode, Json<GraphListResponse>) {
    ///TODO
    let graphs = local_db
        .filter_graphs(&FilterGraphsInfo {
            status: payload.status,
            pegin_txid: payload.pegin_txid,
            offset: payload.offset,
            limit: payload.limit,
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
