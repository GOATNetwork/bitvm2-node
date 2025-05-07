use crate::env::MODIFY_GRAPH_STATUS_TIME_THRESHOLD;
use crate::rpc_service::bitvm2::*;
use crate::rpc_service::node::ALIVE_TIME_JUDGE_THRESHOLD;
use crate::rpc_service::{AppState, current_time_secs};
use crate::utils::node_p2wsh_address;
use alloy::primitives::Address;
use axum::Json;
use axum::extract::{Path, Query, State};
use bitcoin::{Network, PublicKey, Txid};
use esplora_client::AsyncClient;
use http::StatusCode;
use std::collections::HashMap;
use std::default::Default;
use std::str::FromStr;
use std::sync::Arc;
use store::localdb::FilterGraphParams;
use store::{
    BridgeInStatus, BridgePath, GrapRpcQueryData, Instance, Message, MessageState, MessageType,
    modify_graph_status,
};
use uuid::Uuid;

#[axum::debug_handler]
pub async fn instance_settings(
    State(_app_state): State<Arc<AppState>>,
) -> (StatusCode, Json<InstanceSettingResponse>) {
    (StatusCode::OK, Json(InstanceSettingResponse { bridge_in_amount: vec![1.0, 0.5, 0.2, 0.1] }))
}

#[axum::debug_handler]
pub async fn bridge_in_tx_prepare(
    State(app_state): State<Arc<AppState>>,
    Json(payload): Json<BridgeInTransactionPreparerRequest>,
) -> (StatusCode, Json<BridgeInTransactionPrepareResponse>) {
    let async_fn = || async move {
        let instance_id = Uuid::parse_str(&payload.instance_id)?;
        let (is_goat_addr, to_address) = reflect_goat_address(Some(payload.to.clone()));
        if !is_goat_addr {
            return Err(format!("payload field {}   is not goat chain address", payload.to).into());
        }
        let instance = Instance {
            instance_id,
            network: payload.network.clone(),
            bridge_path: BridgePath::BTCToPgBTC.to_u8(),
            from_addr: payload.from.clone(),
            to_addr: to_address.unwrap().to_string(),
            amount: payload.amount,
            created_at: current_time_secs(),
            updated_at: current_time_secs(),
            status: BridgeInStatus::Submitted.to_string(),
            input_uxtos: serde_json::to_string(&payload.utxo)?,
            ..Default::default()
        };

        let mut tx = app_state.bitvm2_client.local_db.start_transaction().await?;
        let instance_pre_op = tx.get_instance(&instance_id).await?;
        if instance_pre_op.is_some() {
            tracing::info!("{instance_id} is used");
            return Err(format!("{instance_id} is used").into());
        }

        let _ = tx.create_instance(instance.clone()).await?;
        let p2p_user_data: P2pUserData = (&payload).into();
        if !p2p_user_data.user_inputs.validate_amount() {
            return Err("inputs_amount_sum < inputs.fee_amount + inputs.input_amount".into());
        }
        let content = serde_json::to_vec::<P2pUserData>(&p2p_user_data)?;
        tx.create_message(
            Message {
                id: 0,
                actor: app_state.actor.to_string(),
                from_peer: app_state.peer_id.clone(),
                msg_type: MessageType::BridgeInData.to_string(),
                content,
                state: MessageState::Pending.to_string(),
            },
            current_time_secs(),
        )
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
pub async fn graph_presign_check(
    Query(params): Query<GraphPresignCheckParams>,
    State(app_state): State<Arc<AppState>>,
) -> (StatusCode, Json<GraphPresignCheckResponse>) {
    let resp = GraphPresignCheckResponse {
        instance_id: params.instance_id.to_string(),
        instance_status: BridgeInStatus::Submitted.to_string(),
        graph_status: HashMap::new(),
        tx: None,
    };
    let current_time = current_time_secs();
    let mut resp_clone = resp.clone();
    let async_fn = || async move {
        let instance_id = Uuid::parse_str(&params.instance_id)?;
        let mut storage_process = app_state.bitvm2_client.local_db.acquire().await?;
        let instance_op = storage_process.get_instance(&instance_id).await?;
        if instance_op.is_none() {
            tracing::info!("instance_id {} has no record in database", instance_id);
            return Ok::<GraphPresignCheckResponse, Box<dyn std::error::Error>>(resp_clone);
        }
        let mut instance = instance_op.unwrap();
        instance.reverse_btc_txid();
        resp_clone.instance_status = instance.status.clone();
        resp_clone.tx = Some(instance);
        let graphs = storage_process.get_graph_by_instance_id(&instance_id).await?;
        resp_clone.graph_status = graphs
            .into_iter()
            .map(|v| {
                (
                    v.graph_id.to_string(),
                    modify_graph_status(
                        &v.status,
                        v.updated_at,
                        current_time,
                        MODIFY_GRAPH_STATUS_TIME_THRESHOLD,
                    ),
                )
            })
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
pub async fn create_instance(
    State(app_state): State<Arc<AppState>>,
    Json(payload): Json<InstanceUpdateRequest>,
) -> (StatusCode, Json<InstanceUpdateResponse>) {
    let async_fn = || async move {
        let mut storage_process = app_state.bitvm2_client.local_db.acquire().await?;
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
        let mut storage_process = app_state.bitvm2_client.local_db.acquire().await?;
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

pub async fn get_btc_height(btc_client: &AsyncClient) -> anyhow::Result<u32> {
    Ok(btc_client.get_height().await?)
}

pub fn get_btc_block_interval(network: &str) -> u32 {
    let mut interval = BTC_TEST_BLOCK_INTERVAL;
    if network == BTC_MAIN {
        interval = BTC_MAIN_BLOCK_INTERVAL;
    }
    interval
}

async fn get_tx_eta(
    btc_client: &AsyncClient,
    tx_id: Option<String>,
    current_height: u32,
    confirm_num: u32,
    interval: u32,
) -> anyhow::Result<String> {
    if tx_id.is_none() {
        return Ok("-".to_string());
    }
    let tx_id = tx_id.unwrap();
    let status = btc_client.get_tx_status(&Txid::from_str(&tx_id)?).await?;
    let blocks_pass = if let Some(block_height) = status.block_height {
        current_height - block_height
    } else {
        confirm_num
    };
    if blocks_pass >= confirm_num {
        Ok("Est.completed".to_string())
    } else {
        Ok(format!("Est. wait for {} mins", (confirm_num - blocks_pass) * interval))
    }
}

#[axum::debug_handler]
pub async fn get_instances(
    Query(params): Query<InstanceListRequest>,
    State(app_state): State<Arc<AppState>>,
) -> (StatusCode, Json<InstanceListResponse>) {
    let async_fn = || async move {
        let mut storage_process = app_state.bitvm2_client.local_db.acquire().await?;
        let (instances, total) = storage_process
            .instance_list(
                params.from_addr,
                params.bridge_path,
                None,
                None,
                params.offset,
                params.limit,
            )
            .await?;

        if instances.is_empty() {
            tracing::warn!("get_instances instance is empty: total {}", total);
            return Ok::<InstanceListResponse, Box<dyn std::error::Error>>(
                InstanceListResponse::default(),
            );
        }

        if instances.is_empty() {
            return Ok::<InstanceListResponse, Box<dyn std::error::Error>>(InstanceListResponse {
                instance_wraps: vec![],
                total,
            });
        }

        let current_height = get_btc_height(&app_state.bitvm2_client.esplora).await?;
        let interval = get_btc_block_interval(instances[0].network.clone().as_str());

        let mut items = vec![];
        for mut instance in instances {
            let eta = get_tx_eta(
                &app_state.bitvm2_client.esplora,
                instance.pegin_txid.clone(),
                current_height,
                6,
                interval,
            )
            .await?;
            instance.reverse_btc_txid();
            let utxo: Vec<UTXO> = serde_json::from_str(&instance.input_uxtos).unwrap();

            items.push(InstanceWrap { utxo: Some(utxo), instance: Some(instance), eta: Some(eta) })
        }

        Ok::<InstanceListResponse, Box<dyn std::error::Error>>(InstanceListResponse {
            instance_wraps: items,
            total,
        })
    };
    match async_fn().await {
        Ok(res) => (StatusCode::OK, Json(res)),
        Err(err) => {
            tracing::warn!("get_instances err:{:?}", err);
            (StatusCode::OK, Json(InstanceListResponse::default()))
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
        let mut storage_process = app_state.bitvm2_client.local_db.acquire().await?;
        let instance_op = storage_process.get_instance(&instance_id).await?;
        if instance_op.is_none() {
            tracing::info!("instance_id {} has no record in database", instance_id);
            return Ok::<InstanceGetResponse, Box<dyn std::error::Error>>(InstanceGetResponse {
                instance_wrap: InstanceWrap { utxo: None, instance: None, eta: None },
            });
        }
        let mut instance = instance_op.unwrap();
        instance.reverse_btc_txid();
        let network = instance.network.clone();
        let current_height = get_btc_height(&app_state.bitvm2_client.esplora).await?;
        let interval = get_btc_block_interval(network.as_str());
        let utxo: Vec<UTXO> = serde_json::from_str(&instance.input_uxtos).unwrap();
        let eta = get_tx_eta(
            &app_state.bitvm2_client.esplora,
            instance.pegin_txid.clone(),
            current_height,
            6,
            interval,
        )
        .await?;

        Ok::<InstanceGetResponse, Box<dyn std::error::Error>>(InstanceGetResponse {
            instance_wrap: InstanceWrap {
                utxo: Some(utxo),
                instance: Some(instance),
                eta: Some(eta),
            },
        })
    };
    match async_fn().await {
        Ok(res) => (StatusCode::OK, Json(res)),
        Err(err) => {
            tracing::warn!("get_instances, err:{:?}", err);
            (StatusCode::OK, Json(InstanceGetResponse { instance_wrap: InstanceWrap::default() }))
        }
    }
}

pub async fn get_instances_overview(
    State(app_state): State<Arc<AppState>>,
) -> (StatusCode, Json<InstanceOverviewResponse>) {
    let async_fn = || async move {
        let mut storage_process = app_state.bitvm2_client.local_db.acquire().await?;
        let (pegin_sum, pegin_count) =
            storage_process.get_sum_bridge_in_or_out(BridgePath::BTCToPgBTC.to_u8()).await?;
        let (pegout_sum, pegout_count) =
            storage_process.get_sum_bridge_in_or_out(BridgePath::PgBTCToBTC.to_u8()).await?;
        let (total, alive) = storage_process.get_nodes_info(ALIVE_TIME_JUDGE_THRESHOLD).await?;
        Ok::<InstanceOverviewResponse, Box<dyn std::error::Error>>(InstanceOverviewResponse {
            instances_overview: InstanceOverview {
                total_bridge_in_amount: pegin_sum,
                total_bridge_in_txn: pegin_count,
                total_bridge_out_amount: pegout_sum,
                total_bridge_out_txn: pegout_count,
                online_nodes: alive,
                total_nodes: total,
            },
        })
    };
    match async_fn().await {
        Ok(resp) => (StatusCode::OK, Json(resp)),
        Err(err) => {
            tracing::warn!("graph_list  err:{:?}", err);
            (StatusCode::INTERNAL_SERVER_ERROR, Json(InstanceOverviewResponse::default()))
        }
    }
}

#[axum::debug_handler]
pub async fn get_graph(
    Path(graph_id): Path<String>,
    State(app_state): State<Arc<AppState>>,
) -> (StatusCode, Json<GraphGetResponse>) {
    let async_fn = || async move {
        let current_time = current_time_secs();
        let graph_id = Uuid::parse_str(&graph_id).unwrap();
        let mut storage_process = app_state.bitvm2_client.local_db.acquire().await?;
        let graph_op = storage_process.get_graph(&graph_id).await?;
        if graph_op.is_none() {
            tracing::warn!("graph:{} is not record in db", graph_id);
            return Ok::<GraphGetResponse, Box<dyn std::error::Error>>(GraphGetResponse {
                graph: None,
            });
        };
        let mut graph = graph_op.unwrap();
        // front end unused data
        graph.raw_data = None;
        graph.status = modify_graph_status(
            &graph.status,
            graph.updated_at,
            current_time,
            MODIFY_GRAPH_STATUS_TIME_THRESHOLD,
        );
        graph.reverse_btc_txid();
        Ok::<GraphGetResponse, Box<dyn std::error::Error>>(GraphGetResponse { graph: Some(graph) })
    };
    match async_fn().await {
        Ok(res) => (StatusCode::OK, Json(res)),
        Err(err) => {
            tracing::warn!("get_graph  err:{:?}", err);
            (StatusCode::OK, Json(GraphGetResponse { graph: None }))
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
        let mut storage_process = app_state.bitvm2_client.local_db.acquire().await?;
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
pub async fn get_graphs(
    Query(params): Query<GraphQueryParams>,
    State(app_state): State<Arc<AppState>>,
) -> (StatusCode, Json<GraphListResponse>) {
    let resp = GraphListResponse::default();
    let mut resp_clone = resp.clone();
    let async_fn = || async move {
        let mut storage_process = app_state.bitvm2_client.local_db.acquire().await?;
        let mut from_addr = params.from_addr.clone();
        let (is_goat_address, goat_address) = reflect_goat_address(params.from_addr);
        if is_goat_address {
            from_addr = goat_address;
        }
        let (graphs, total) = storage_process
            .filter_graphs(FilterGraphParams {
                is_bridge_out: is_goat_address,
                status: params.status,
                operator: params.operator,
                from_addr: from_addr.clone(),
                pegin_txid: params.pegin_txid,
                offset: params.offset,
                limit: params.limit,
            })
            .await?;
        resp_clone.total = total;

        if graphs.is_empty() {
            return Ok::<GraphListResponse, Box<dyn std::error::Error>>(resp_clone);
        }
        let current_time = current_time_secs();

        let current_height = get_btc_height(&app_state.bitvm2_client.esplora).await?;
        let interval = get_btc_block_interval(graphs[0].network.clone().as_str());
        for mut graph in graphs {
            convert_addrs_for_bridge_out(&mut graph, is_goat_address, from_addr.clone())?;
            graph.status = modify_graph_status(
                &graph.status,
                graph.updated_at,
                current_time,
                MODIFY_GRAPH_STATUS_TIME_THRESHOLD,
            );
            graph.reverse_btc_txid();
            let eta = match graph.get_check_tx_param() {
                Ok((tx_id, confirm_num)) => {
                    get_tx_eta(
                        &app_state.bitvm2_client.esplora,
                        tx_id,
                        current_height,
                        confirm_num,
                        interval,
                    )
                    .await?
                }
                Err(err) => err,
            };
            resp_clone.graphs.push(GrapRpcQueryDataWrap { graph, eta });
        }
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

pub fn reflect_goat_address(addr_op: Option<String>) -> (bool, Option<String>) {
    if let Some(addr) = addr_op {
        if let Ok(addr) = Address::from_str(&addr) {
            return (true, Some(addr.to_string()));
        }
    }
    (false, None)
}

pub fn convert_addrs_for_bridge_out(
    graph: &mut GrapRpcQueryData,
    is_bridge_out: bool,
    from_addr: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    if !is_bridge_out {
        return Ok(());
    }
    graph.bridge_path = 1_u8;
    if let Some(from_addr) = from_addr {
        graph.from_addr = from_addr;
    }
    graph.to_addr = node_p2wsh_address(
        Network::from_str(&graph.network)?,
        &PublicKey::from_str(&graph.operator)?,
    )
    .to_string();
    Ok(())
}
