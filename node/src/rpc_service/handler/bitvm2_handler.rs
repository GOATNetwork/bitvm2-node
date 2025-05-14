use crate::env::{IpfsTxName, MODIFY_GRAPH_STATUS_TIME_THRESHOLD};
use crate::rpc_service::bitvm2::*;
use crate::rpc_service::node::ALIVE_TIME_JUDGE_THRESHOLD;
use crate::rpc_service::{AppState, current_time_secs};
use crate::utils::node_p2wsh_address;
use alloy::primitives::Address as EvmAddress;
use axum::Json;
use axum::extract::{Path, Query, State};
use bitcoin::address::NetworkUnchecked;
use bitcoin::consensus::encode::serialize_hex;
use bitcoin::{Address, AddressType};
use bitcoin::{Network, PublicKey, Txid};
use bitvm2_lib::types::Bitvm2Graph;
use esplora_client::AsyncClient;
use goat::transactions::pre_signed::PreSignedTransaction;
use http::StatusCode;
use std::collections::HashMap;
use std::default::Default;
use std::str::FromStr;
use std::sync::Arc;
use store::localdb::FilterGraphParams;
use store::{
    BridgeInStatus, BridgePath, GrapFullData, GraphStatus, Instance, Message, MessageState,
    MessageType, modify_graph_status,
};
use uuid::Uuid;

#[axum::debug_handler]
pub async fn instance_settings(
    State(_app_state): State<Arc<AppState>>,
) -> (StatusCode, Json<InstanceSettingResponse>) {
    (
        StatusCode::OK,
        Json(InstanceSettingResponse { bridge_in_amount: vec![0.1, 0.05, 0.02, 0.01] }),
    )
}

#[axum::debug_handler]
pub async fn bridge_in_tx_prepare(
    State(app_state): State<Arc<AppState>>,
    Json(payload): Json<BridgeInTransactionPreparerRequest>,
) -> (StatusCode, Json<BridgeInTransactionPrepareResponse>) {
    let async_fn = || async move {
        let instance_id = Uuid::parse_str(&payload.instance_id)?;
        let is_segwit_addr = is_segwit_address(&payload.from, &payload.network)?;
        if !is_segwit_addr {
            return Err(
                format!("payload from field {} is not btc segwit address", payload.from).into()
            );
        }
        let (is_goat_addr, to_address) = reflect_goat_address(Some(payload.to.clone()));
        if !is_goat_addr {
            return Err(
                format!("payload to field {}  is not goat chain address", payload.to).into()
            );
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
                        current_time - MODIFY_GRAPH_STATUS_TIME_THRESHOLD,
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
pub async fn get_graph_tx(
    Query(params): Query<GraphTxGetParams>,
    Path(graph_id): Path<String>,
    State(app_state): State<Arc<AppState>>,
) -> (StatusCode, Json<Option<GraphTxGetResponse>>) {
    let async_fn = || async move {
        let mut storage_process = app_state.bitvm2_client.local_db.acquire().await?;
        let graph_op = storage_process.get_graph(&Uuid::parse_str(&graph_id)?).await?;
        if graph_op.is_none() {
            tracing::warn!("graph:{} is not record in db", graph_id);
            return Err(format!("graph:{graph_id} is not record in db").into());
        };
        let graph = graph_op.unwrap();
        if graph.raw_data.is_none() {
            return Err(format!("grap with graph_id:{graph_id} raw data is none").into());
        }
        let bitvm2_graph: Bitvm2Graph = serde_json::from_str(graph.raw_data.unwrap().as_str())?;
        let tx_name_op = IpfsTxName::from_str(&params.tx_name);
        if tx_name_op.is_err() {
            return Err(format!(
                "grap with graph_id:{graph_id} decode tx_name:{} failed",
                params.tx_name
            )
            .into());
        }
        let tx_hex = match tx_name_op.unwrap() {
            IpfsTxName::AssertCommit0 => {
                serialize_hex(bitvm2_graph.assert_commit.commit_txns[0].tx())
            }
            IpfsTxName::AssertCommit1 => {
                serialize_hex(bitvm2_graph.assert_commit.commit_txns[1].tx())
            }
            IpfsTxName::AssertCommit2 => {
                serialize_hex(bitvm2_graph.assert_commit.commit_txns[2].tx())
            }
            IpfsTxName::AssertCommit3 => {
                serialize_hex(bitvm2_graph.assert_commit.commit_txns[3].tx())
            }
            IpfsTxName::AssertInit => serialize_hex(bitvm2_graph.assert_init.tx()),
            IpfsTxName::AssertFinal => serialize_hex(bitvm2_graph.assert_final.tx()),
            IpfsTxName::Challenge => serialize_hex(bitvm2_graph.challenge.tx()),
            IpfsTxName::Disprove => serialize_hex(bitvm2_graph.disprove.tx()),
            IpfsTxName::Kickoff => serialize_hex(bitvm2_graph.kickoff.tx()),
            IpfsTxName::Pegin => serialize_hex(bitvm2_graph.pegin.tx()),
            IpfsTxName::Take1 => serialize_hex(bitvm2_graph.take1.tx()),
            IpfsTxName::Take2 => serialize_hex(bitvm2_graph.take2.tx()),
        };
        Ok::<GraphTxGetResponse, Box<dyn std::error::Error>>(GraphTxGetResponse { tx_hex })
    };
    match async_fn().await {
        Ok(resp) => (StatusCode::OK, Json(Some(resp))),
        Err(err) => {
            tracing::warn!("get_graph_tx  err:{:?}", err);
            (StatusCode::INTERNAL_SERVER_ERROR, Json(None))
        }
    }
}

#[axum::debug_handler]
pub async fn get_graph_txn(
    Path(graph_id): Path<String>,
    State(app_state): State<Arc<AppState>>,
) -> (StatusCode, Json<Option<GraphTxnGetResponse>>) {
    let async_fn = || async move {
        let mut storage_process = app_state.bitvm2_client.local_db.acquire().await?;
        let graph_op = storage_process.get_graph(&Uuid::parse_str(&graph_id)?).await?;
        if graph_op.is_none() {
            tracing::warn!("graph:{} is not record in db", graph_id);
            return Err(format!("graph:{graph_id} is not record in db").into());
        };
        let graph = graph_op.unwrap();
        if graph.raw_data.is_none() {
            return Err(format!("grap with graph_id:{graph_id} raw data is none").into());
        }
        let bitvm2_graph: Bitvm2Graph = serde_json::from_str(graph.raw_data.unwrap().as_str())?;
        let resp = GraphTxnGetResponse {
            assert_commit0: serialize_hex(bitvm2_graph.assert_commit.commit_txns[0].tx()),
            assert_commit1: serialize_hex(bitvm2_graph.assert_commit.commit_txns[1].tx()),
            assert_commit2: serialize_hex(bitvm2_graph.assert_commit.commit_txns[2].tx()),
            assert_commit3: serialize_hex(bitvm2_graph.assert_commit.commit_txns[3].tx()),
            assert_init: serialize_hex(bitvm2_graph.assert_init.tx()),
            assert_final: serialize_hex(bitvm2_graph.assert_final.tx()),
            challenge: serialize_hex(bitvm2_graph.challenge.tx()),
            disprove: serialize_hex(bitvm2_graph.disprove.tx()),
            kickoff: serialize_hex(bitvm2_graph.kickoff.tx()),
            pegin: serialize_hex(bitvm2_graph.pegin.tx()),
            take1: serialize_hex(bitvm2_graph.take1.tx()),
            take2: serialize_hex(bitvm2_graph.take2.tx()),
        };
        Ok::<GraphTxnGetResponse, Box<dyn std::error::Error>>(resp)
    };
    match async_fn().await {
        Ok(resp) => (StatusCode::OK, Json(Some(resp))),
        Err(err) => {
            tracing::warn!("get_graph_txn  err:{:?}", err);
            (StatusCode::INTERNAL_SERVER_ERROR, Json(None))
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

async fn get_tx_confirmation_info(
    btc_client: &AsyncClient,
    btc_tx_id: Option<String>,
    current_height: u32,
    target_confirm_num: u32,
) -> anyhow::Result<(u32, u32)> {
    if btc_tx_id.is_none() {
        return Ok((0, target_confirm_num));
    }
    let tx_id = btc_tx_id.unwrap();
    let status = btc_client.get_tx_status(&Txid::from_str(&tx_id)?).await?;
    let blocks_pass = if let Some(block_height) = status.block_height {
        current_height - block_height
    } else {
        0
    };
    Ok((blocks_pass, target_confirm_num))
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

        let mut items = vec![];
        for mut instance in instances {
            let (confirmations, target_confirmations) = get_tx_confirmation_info(
                &app_state.bitvm2_client.esplora,
                instance.pegin_txid.clone(),
                current_height,
                6,
            )
            .await?;
            instance.reverse_btc_txid();
            let utxo: Vec<UTXO> = serde_json::from_str(&instance.input_uxtos).unwrap();

            items.push(InstanceWrap {
                utxo: Some(utxo),
                instance: Some(instance),
                confirmations,
                target_confirmations,
            })
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
                instance_wrap: InstanceWrap::default(),
            });
        }
        let mut instance = instance_op.unwrap();
        instance.reverse_btc_txid();
        let current_height = get_btc_height(&app_state.bitvm2_client.esplora).await?;
        let utxo: Vec<UTXO> = serde_json::from_str(&instance.input_uxtos).unwrap();
        let (confirmations, target_confirmations) = get_tx_confirmation_info(
            &app_state.bitvm2_client.esplora,
            instance.pegin_txid.clone(),
            current_height,
            6,
        )
        .await?;

        Ok::<InstanceGetResponse, Box<dyn std::error::Error>>(InstanceGetResponse {
            instance_wrap: InstanceWrap {
                utxo: Some(utxo),
                instance: Some(instance),
                confirmations,
                target_confirmations,
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
            storage_process.get_sum_bridge_in(BridgePath::BTCToPgBTC.to_u8()).await?;
        let (pegout_sum, pegout_count) = storage_process.get_sum_bridge_out().await?;
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
            current_time - MODIFY_GRAPH_STATUS_TIME_THRESHOLD,
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
        let filter_params: FilterGraphParams = params.into();
        let from_addr = filter_params.from_addr.clone();
        let update_at_threshold = filter_params.update_at_threshold;
        let (graphs, total) = storage_process.filter_graphs(filter_params).await?;
        resp_clone.total = total;
        if graphs.is_empty() {
            return Ok::<GraphListResponse, Box<dyn std::error::Error>>(resp_clone);
        }
        let current_height = get_btc_height(&app_state.bitvm2_client.esplora).await?;
        let mut graph_vec = vec![];
        let bridge_in_status = vec![
            GraphStatus::CommitteePresigned.to_string(),
            GraphStatus::OperatorDataPushed.to_string(),
            GraphStatus::OperatorPresigned.to_string(),
        ];
        for mut graph in graphs {
            graph.reverse_btc_txid();
            let (confirmations, target_confirmations) = match graph.get_check_tx_param() {
                Ok((tx_id, confirm_num)) => {
                    get_tx_confirmation_info(
                        &app_state.bitvm2_client.esplora,
                        tx_id,
                        current_height,
                        confirm_num,
                    )
                    .await?
                }
                Err(_) => (0, 0),
            };
            // TODO remove middle status
            graph.status =
                modify_graph_status(&graph.status, graph.updated_at, update_at_threshold);
            let graph = convert_to_rpc_query_data(&graph, from_addr.clone(), &bridge_in_status)?;
            graph_vec.push(GrapRpcQueryDataWrap { graph, confirmations, target_confirmations });
        }
        graph_vec.sort_by(|a, b| b.graph.created_at.cmp(&a.graph.created_at));
        resp_clone.graphs = graph_vec;
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
        if let Ok(addr) = EvmAddress::from_str(&addr) {
            return (true, Some(addr.to_string()));
        }
    }
    (false, None)
}

pub fn convert_to_rpc_query_data(
    graph: &GrapFullData,
    from_addr: Option<String>,
    bridge_in_status: &[String],
) -> Result<GrapRpcQueryData, Box<dyn std::error::Error>> {
    let mut graph_res = GrapRpcQueryData {
        graph_id: graph.graph_id,
        instance_id: graph.instance_id,
        bridge_path: graph.bridge_path,
        network: graph.network.clone(),
        from_addr: graph.from_addr.clone(),
        to_addr: graph.to_addr.clone(),
        amount: graph.amount,
        pegin_txid: graph.pegin_txid.clone(),
        status: graph.status.clone(),
        kickoff_txid: graph.kickoff_txid.clone(),
        challenge_txid: graph.challenge_txid.clone(),
        take1_txid: graph.take1_txid.clone(),
        assert_init_txid: graph.assert_init_txid.clone(),
        assert_commit_txids: graph.assert_commit_txids.clone(),
        assert_final_txid: graph.assert_final_txid.clone(),
        take2_txid: graph.take2_txid.clone(),
        disprove_txid: graph.disprove_txid.clone(),
        operator: graph.operator.clone(),
        updated_at: graph.updated_at,
        created_at: graph.created_at,
    };

    if graph.bridge_out_start_at > 0 || !bridge_in_status.contains(&graph.status) {
        if graph.bridge_out_start_at > 0 {
            graph_res.created_at = graph.bridge_out_start_at;
        }
        graph_res.bridge_path = 1_u8;
        graph_res.from_addr = "".to_string();
        if let Some(from_addr) = from_addr {
            graph_res.from_addr = from_addr;
        }

        if !graph.bridge_out_from_addr.is_empty() {
            graph_res.from_addr = graph.bridge_out_from_addr.clone();
        }
        if graph.bridge_out_to_addr.is_empty() {
            graph_res.to_addr = node_p2wsh_address(
                Network::from_str(&graph.network)?,
                &PublicKey::from_str(&graph.operator)?,
            )
            .to_string();
        } else {
            graph_res.to_addr = graph.bridge_out_to_addr.clone();
        }
    }
    Ok(graph_res)
}

fn is_segwit_address(address: &str, network: &str) -> anyhow::Result<bool> {
    let addr: Address<NetworkUnchecked> = Address::from_str(address)?;
    let addr = addr.require_network(Network::from_str(network)?)?;
    Ok(matches!(
        addr.address_type(),
        Some(AddressType::P2wpkh) | Some(AddressType::P2wsh) | Some(AddressType::P2tr)
    ))
}
