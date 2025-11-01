use crate::env::{GraphBtcTxName, get_network};
use crate::rpc_service::bitvm2::*;
use crate::rpc_service::handler::is_use_mock_data;
use crate::rpc_service::node::ALIVE_TIME_JUDGE_THRESHOLD;
use crate::rpc_service::response::{ApiResult, ErrorResponse};
use crate::rpc_service::validation::InputValidator;
use crate::rpc_service::{AppState, current_time_secs};
use crate::scheduled_tasks::graph_maintenance_tasks::{
    AssertInitTxVoutMonitorData, WTInitTxVoutMonitorData,
};
use crate::utils::{get_rand_btc_address_p2wpkh, get_rand_goat_address};
use axum::Json;
use axum::extract::{Path, Query, State};
use bitcoin::consensus::encode::serialize_hex;
use bitcoin::{Network, Txid};
use bitvm2_lib::types::Bitvm2Graph;
use client::Utxo;
use client::btc_chain::BTCClient;
use goat::transactions::pre_signed::PreSignedTransaction;
use http::StatusCode;
use std::collections::HashMap;
use std::default::Default;
use std::str::FromStr;
use std::sync::Arc;
use store::localdb::{GraphQuery, InstanceQuery, StorageProcessor};
use store::{
    GoatTxType, Graph, GraphStatus, Instance, InstanceStatus, SerializableTxid, UInt64Array3,
    modify_graph_status,
};
use uuid::Uuid;

const WATCHTOWER_CHALLENGE_STEP_INIT: &str = "Watchtower Challenge init";
const WATCHTOWER_CHALLENGE_STEP_CHALLENGE: &str = "Watchtower Challenge";
const WATCHTOWER_CHALLENGE_STEP_CHALLENGE_TIMEOUT: &str = "Watchtower Challenge Timeout";
const WATCHTOWER_CHALLENGE_STEP_ACK: &str = "Operator Challenge NACK";
const WATCHTOWER_CHALLENGE_STEP_COMMIT_BLOCKHASH: &str = "Operator Commit BlockHash";
const WATCHTOWER_CHALLENGE_STEP_COMMIT_BLOCKHASH_TIMEOUT: &str =
    "Operator Commit BlockHash Timeout";
const ASSERT_STEP_INIT: &str = "Assert init";
const ASSERT_STEP_COMMIT: &str = "Assert Commit";
/// Get instance settings
///
/// Returns bridge-in amount configuration information for frontend display of available bridge amount options.
/// This endpoint provides the list of supported bridge-in amounts that users can choose from.
///
/// # Returns
///
/// - `200 OK`: Successfully returns instance settings
/// - Response body contains available bridge-in amount list in BTC
///
/// # Use Case
///
/// Frontend applications use this to display available bridge amount options to users.
///
/// # Example
///
/// ```http
/// GET /v1/instances/settings
/// ```
///
/// Response example:
/// ```json
/// {
///   "bridge_in_amount": [0.1, 0.05, 0.02, 0.01]
/// }
/// ```
#[axum::debug_handler]
pub async fn instance_settings(
    State(_app_state): State<Arc<AppState>>,
) -> ApiResult<InstanceSettingResponse> {
    Ok((
        StatusCode::OK,
        Json(InstanceSettingResponse { bridge_in_amount: vec![0.1, 0.05, 0.02, 0.01] }),
    ))
}

#[axum::debug_handler]
pub async fn get_instances(
    Query(params): Query<InstanceListRequest>,
    State(app_state): State<Arc<AppState>>,
) -> ApiResult<InstanceListResponse> {
    // todo update statusExtra
    // Validate pagination parameters
    let (offset, limit) = InputValidator::validate_pagination(params.offset, params.limit)?;

    // Validate from_addr format (if provided)
    if let Some(ref from_addr) = params.from_addr {
        InputValidator::validate_btc_address(from_addr, "from_addr")?;
    }

    if is_use_mock_data() {
        let (from_addr, to_addr) = if params.is_bridge_in {
            (get_rand_btc_address_p2wpkh(Network::Testnet), get_rand_goat_address())
        } else {
            (get_rand_goat_address(), get_rand_btc_address_p2wpkh(Network::Testnet))
        };
        return Ok((
            StatusCode::OK,
            Json(InstanceListResponse {
                instance_wraps: vec![InstanceExtended {
                    instance: Instance {
                        instance_id: Uuid::new_v4(),
                        is_bridge_in: params.is_bridge_in,
                        network: "testnet".to_string(),
                        from_addr,
                        to_addr,
                        amount: 100000000,
                        fees: UInt64Array3([10, 20, 30]),
                        input_utxos: "".to_string(),
                        status: InstanceStatus::CommitteesAnswered.to_string(),
                        goat_tx_hash: "0xf6d6523a4344806aca5c66f23554bc574cb93634572f5e115cc630b3d8db3c6e".to_string(),
                        goat_tx_height: 8509060,
                        user_xonly_pubkey: Default::default(),
                        user_change_addr: "".to_string(),
                        user_refund_addr: "".to_string(),
                        btc_txid: Some(Txid::from_str("0xf6d6523a4344806aca5c66f23554bc574cb93634572f5e115cc630b3d8db3c6e").expect("fail to decode btc txid").into()),
                        btc_height: 0,
                        pegin_confirm_txid: None,
                        pegin_cancel_txid: None,
                        committees_answers: Default::default(),
                        pegin_data_tx_hash: "".to_string(),
                        parameters: None,
                        created_at: 0,
                        updated_at: 0,
                    },
                    utxo: vec![],
                    waiting_time_in_mins: 60,
                    confirmations: 0,
                    target_confirmations: 6,
                    status_extra: StatusExtra{
                        user_action: StatusUserAction::Submit,
                        is_failed: false,
                        error: None,
                    },
                }],
                total: 1,
            }),
        ));
    }

    let async_fn = || async move {
        let mut storage_process = app_state.local_db.acquire().await?;
        let mut query = InstanceQuery::default();
        if let Some(from_addr) = params.from_addr {
            query = query.with_from_addr(from_addr);
        }
        query = query
            .with_pagination(offset, limit)
            .with_order("created_at DESC".to_string())
            .with_is_bridge_in(params.is_bridge_in);

        let (instances, total) = storage_process.find_instances(query).await?;

        if instances.is_empty() {
            tracing::warn!("get_instances instance is empty: total {}", total);
            return Ok::<InstanceListResponse, Box<dyn std::error::Error>>(
                InstanceListResponse::default(),
            );
        }
        let current_height = app_state.btc_client.get_height().await?;
        let mut items = vec![];
        for instance in instances {
            let (confirmations, target_confirmations) = get_btc_tx_confirmation_info(
                &app_state.btc_client,
                instance.pegin_confirm_txid.clone(),
                current_height,
                6,
            )
            .await?;
            let utxo: Vec<Utxo> =
                serde_json::from_str(&instance.input_utxos).map_err(|_| "failed to parse utxos")?;
            items.push(InstanceExtended {
                utxo,
                instance,
                confirmations,
                target_confirmations,
                waiting_time_in_mins: 0,
                status_extra: Default::default(),
            })
        }

        Ok::<InstanceListResponse, Box<dyn std::error::Error>>(InstanceListResponse {
            instance_wraps: items,
            total,
        })
    };
    match async_fn().await {
        Ok(res) => Ok((StatusCode::OK, Json(res))),
        Err(err) => {
            tracing::warn!("get instances err:{:?}", err);
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "GET_INSTANCE_ERROR".to_string(),
                    message: err.to_string(),
                }),
            ))
        }
    }
}

#[axum::debug_handler]
pub async fn get_instance(
    Path(instance_id): Path<String>,
    State(app_state): State<Arc<AppState>>,
) -> ApiResult<InstanceGetResponse> {
    // todo update statusExtra
    // Validate instance_id format
    let instance_id_uuid = InputValidator::validate_uuid(&instance_id, "instance_id")?;

    if is_use_mock_data() {
        return Ok((
            StatusCode::OK,
            Json(InstanceGetResponse {
                instance_wrap: InstanceExtended {
                    instance: Instance {
                        instance_id: Uuid::new_v4(),
                        is_bridge_in: true,
                        network: "testnet".to_string(),
                        from_addr:get_rand_btc_address_p2wpkh(Network::Testnet),
                        to_addr:get_rand_goat_address(),
                        amount: 100000000,
                        fees: UInt64Array3([10, 20, 30]),
                        input_utxos: "".to_string(),
                        status: InstanceStatus::CommitteesAnswered.to_string(),
                        goat_tx_hash: "0xf6d6523a4344806aca5c66f23554bc574cb93634572f5e115cc630b3d8db3c6e".to_string(),
                        goat_tx_height: 8509060,
                        user_xonly_pubkey: Default::default(),
                        user_change_addr: "".to_string(),
                        user_refund_addr: "".to_string(),
                        btc_txid: Some(Txid::from_str("0xf6d6523a4344806aca5c66f23554bc574cb93634572f5e115cc630b3d8db3c6e").expect("fail to decode btc txid").into()),
                        btc_height: 0,
                        pegin_confirm_txid: None,
                        pegin_cancel_txid: None,
                        committees_answers: Default::default(),
                        pegin_data_tx_hash: "".to_string(),
                        parameters: None,
                        created_at: 0,
                        updated_at: 0,
                    },
                    utxo: vec![],
                    waiting_time_in_mins: 60,
                    confirmations: 0,
                    target_confirmations: 6,
                    status_extra: StatusExtra{
                        user_action: StatusUserAction::Submit,
                        is_failed: false,
                        error: None,
                    },
                }
            }),
        ));
    }

    let async_fn = || async move {
        let mut storage_process = app_state.local_db.acquire().await?;
        if let Some(instance) = storage_process.find_instance(&instance_id_uuid).await? {
            let current_height = app_state.btc_client.get_height().await?;
            let (confirmations, target_confirmations) = get_btc_tx_confirmation_info(
                &app_state.btc_client,
                instance.pegin_confirm_txid.clone(),
                current_height,
                6,
            )
            .await?;

            let utxo: Vec<Utxo> =
                serde_json::from_str(&instance.input_utxos).map_err(|_| "failed to parse utxos")?;
            Ok::<InstanceGetResponse, Box<dyn std::error::Error>>(InstanceGetResponse {
                instance_wrap: InstanceExtended {
                    utxo,
                    instance,
                    confirmations,
                    target_confirmations,
                    waiting_time_in_mins: 0,
                    status_extra: Default::default(),
                },
            })
        } else {
            tracing::info!("instance_id {} has no record in database", instance_id);
            Ok::<InstanceGetResponse, Box<dyn std::error::Error>>(InstanceGetResponse {
                instance_wrap: InstanceExtended::default(),
            })
        }
    };
    match async_fn().await {
        Ok(res) => Ok((StatusCode::OK, Json(res))),
        Err(err) => {
            tracing::warn!("get instances err:{:?}", err);
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "GET_INSTANCE_ERROR".to_string(),
                    message: err.to_string(),
                }),
            ))
        }
    }
}

#[axum::debug_handler]
pub async fn get_instances_overview(
    State(app_state): State<Arc<AppState>>,
) -> ApiResult<InstanceOverviewResponse> {
    if is_use_mock_data() {
        return Ok((
            StatusCode::OK,
            Json(InstanceOverviewResponse {
                instances_overview: InstanceOverview {
                    total_bridge_in_amount: 3000000,
                    total_bridge_in_txn: 1,
                    total_bridge_out_amount: 2000000,
                    total_bridge_out_txn: 2,
                    total_peg_out_amount: 1000000,
                    total_peg_out_txn: 1,
                    online_nodes: 3,
                    total_nodes: 4,
                },
            }),
        ));
    }
    let async_fn = || async move {
        let mut storage_process = app_state.local_db.acquire().await?;
        let (pegin_sum, pegin_count) = storage_process
            .get_sum_bridge_in(&[
                InstanceStatus::RelayerL1Broadcasted.to_string(),
                InstanceStatus::RelayerL2Minted.to_string(),
            ])
            .await?;
        let (pegout_sum, pegout_count) = storage_process
            .get_sum_bridge_out(&[
                GraphStatus::OperatorTake1.to_string(),
                GraphStatus::OperatorTake2.to_string(),
                GraphStatus::Disprove.to_string(),
            ])
            .await?;
        let (total, alive) = storage_process.get_nodes_info(ALIVE_TIME_JUDGE_THRESHOLD).await?;
        Ok::<InstanceOverviewResponse, Box<dyn std::error::Error>>(InstanceOverviewResponse {
            instances_overview: InstanceOverview {
                total_bridge_in_amount: pegin_sum,
                total_bridge_in_txn: pegin_count,
                total_bridge_out_amount: pegout_sum,
                total_bridge_out_txn: pegout_count,
                total_peg_out_amount: 0,
                total_peg_out_txn: 0,
                online_nodes: alive,
                total_nodes: total,
            },
        })
    };
    match async_fn().await {
        Ok(resp) => Ok((StatusCode::OK, Json(resp))),
        Err(err) => {
            tracing::warn!("get instances overview err:{:?}", err);
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "INSTANCE_OVERVIEW_ERROR".to_string(),
                    message: err.to_string(),
                }),
            ))
        }
    }
}

/// Get Bitcoin transaction confirmation information
///
/// Helper function to retrieve confirmation status for Bitcoin transactions.
///
/// # Parameters
///
/// - `btc_client`: Bitcoin client instance
/// - `btc_tx_id`: Optional Bitcoin transaction ID
/// - `current_height`: Current blockchain height
/// - `target_confirm_num`: Required number of confirmations
///
/// # Returns
///
/// - `Ok((blocks_passed, target_confirmations))`: Tuple of blocks passed and target confirmations
/// - `Err`: Error if transaction lookup fails
///
/// Get Bitcoin transaction confirmation information
///
/// Helper function to retrieve confirmation status for Bitcoin transactions.
/// Calculates how many blocks have passed since a transaction was included in a block.
///
/// # Parameters
///
/// - `btc_client`: Bitcoin client instance for blockchain queries
/// - `btc_tx_id`: Optional Bitcoin transaction ID (SerializableTxid format)
/// - `current_height`: Current blockchain height
/// - `target_confirm_num`: Required number of confirmations
///
/// # Returns
///
/// - `Ok((blocks_passed, target_confirmations))`: Tuple of blocks passed and target confirmations
/// - `Err`: Error if transaction lookup fails
///
/// # Note
///
/// Returns (0, target_confirmations) if no transaction ID is provided.
async fn get_btc_tx_confirmation_info(
    btc_client: &BTCClient,
    btc_tx_id: Option<SerializableTxid>,
    current_height: u32,
    target_confirm_num: u32,
) -> anyhow::Result<(u32, u32)> {
    if btc_tx_id.is_none() {
        return Ok((0, target_confirm_num));
    }
    let status = btc_client.get_tx_status(&btc_tx_id.unwrap().0).await?;
    let blocks_pass = if let Some(block_height) = status.block_height {
        current_height - block_height
    } else {
        0
    };
    Ok((blocks_pass, target_confirm_num))
}

/// Get transaction confirmation information (legacy function)
///
/// TODO: This function will be removed after graph update.
/// Helper function to retrieve confirmation status for transactions using string transaction IDs.
///
/// # Parameters
///
/// - `btc_client`: Bitcoin client instance
/// - `btc_tx_id`: Optional transaction ID as string
/// - `current_height`: Current blockchain height
/// - `target_confirm_num`: Required number of confirmations
///
/// # Returns
///
/// - `Ok((blocks_passed, target_confirmations))`: Tuple of blocks passed and target confirmations
/// - `Err`: Error if transaction lookup fails
///
/// # Note
///
/// Returns (0, target_confirmations) if no transaction ID is provided.
/// This function will be deprecated in favor of get_btc_tx_confirmation_info.
async fn get_tx_confirmation_info(
    btc_client: &BTCClient,
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
pub async fn get_graph(
    Path(graph_id): Path<String>,
    State(app_state): State<Arc<AppState>>,
) -> ApiResult<GraphGetResponse> {
    // Validate graph_id format
    let graph_id_uuid = InputValidator::validate_uuid(&graph_id, "graph_id")?;
    let async_fn = || async move {
        let mut storage_process = app_state.local_db.acquire().await?;
        if let Some(graph) = storage_process.find_graph(&graph_id_uuid).await? {
            let graphs =
                add_extend_data_to_graphs(&mut storage_process, &app_state.btc_client, vec![graph])
                    .await?;
            if graphs.is_empty() {
                tracing::warn!("graph:{} is convert failed", graph_id);
                Ok::<GraphGetResponse, Box<dyn std::error::Error>>(GraphGetResponse { graph: None })
            } else {
                Ok::<GraphGetResponse, Box<dyn std::error::Error>>(GraphGetResponse {
                    graph: Some(graphs[0].clone()),
                })
            }
        } else {
            tracing::warn!("graph:{} is not record in db", graph_id);
            Ok::<GraphGetResponse, Box<dyn std::error::Error>>(GraphGetResponse { graph: None })
        }
    };
    match async_fn().await {
        Ok(res) => Ok((StatusCode::OK, Json(res))),
        Err(err) => {
            tracing::warn!("get graph err:{:?}", err);
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "GET_GRAPH_ERROR".to_string(),
                    message: err.to_string(),
                }),
            ))
        }
    }
}

/// Get graph list
///
/// Get graph list based on query parameters, supports various filtering conditions and pagination.
/// Each graph includes confirmation status and proof information.
///
/// # Query Parameters
///
/// - `from_addr`: Source address filter (optional) - filters graphs by source address
/// - `status`: Status filter (optional) - filters graphs by current status
/// - `offset`: Pagination offset (default: 0) - number of items to skip
/// - `limit`: Items per page (default: 10) - maximum number of items to return
///
/// # Returns
///
/// - `200 OK`: Successfully returns graph list with confirmation status
/// - `500 Internal Server Error`: Server internal error or database operation failed
/// - Response includes total count and paginated graph data
///
/// # Example
///
/// ```http
/// GET /v1/graphs?status=OperatorPresigned&offset=0&limit=10
/// ```
///
/// Response example:
/// ```json
/// {
///   "graphs": [
///     {
///       "graph": {
///         "graph_id": "123e4567-e89b-12d3-a456-426614174000",
///         "status": "OperatorPresigned",
///         "amount": 1000,
///         ...
///       },
///       "confirmations": 3,
///       "target_confirmations": 6
///     }
///   ],
///   "total": 1
/// }
/// ```
#[axum::debug_handler]
pub async fn get_graphs(
    Query(params): Query<GraphQueryParams>,
    State(app_state): State<Arc<AppState>>,
) -> ApiResult<GraphListResponse> {
    let async_fn = || async move {
        let mut resp = GraphListResponse::default();
        let mut storage_process = app_state.local_db.acquire().await?;
        let filter_params: GraphQuery = params.into();
        let (graphs, total) = storage_process.find_graphs(filter_params).await?;
        resp.total = total;
        if graphs.is_empty() {
            return Ok::<GraphListResponse, Box<dyn std::error::Error>>(resp);
        }
        resp.graphs =
            add_extend_data_to_graphs(&mut storage_process, &app_state.btc_client, graphs).await?;
        Ok::<GraphListResponse, Box<dyn std::error::Error>>(resp)
    };
    match async_fn().await {
        Ok(resp) => Ok((StatusCode::OK, Json(resp))),
        Err(err) => {
            tracing::warn!("get graphs err:{:?}", err);
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "GET GRAPHS_ERROR".to_string(),
                    message: err.to_string(),
                }),
            ))
        }
    }
}

#[axum::debug_handler]
pub async fn get_ready_to_kickoff_graph(
    Query(params): Query<GraphReadyToKickoffRequest>,
    State(_app_state): State<Arc<AppState>>,
) -> ApiResult<GraphReadyToKickoffResponse> {
    if params.btc_pub_key.is_none() || params.btc_pub_key.is_none() {
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "GET READT_KICKOFF_GRAPHS_ERROR".to_string(),
                message: "Wrong input: btc_pub_key and btc_pub_key should not all been none "
                    .to_string(),
            }),
        ));
    }

    let async_fn = || async move {
        let mut graph = Graph {
            graph_id: Uuid::new_v4(),
            instance_id: Uuid::new_v4(),
            kickoff_index: 10,
            from_addr: get_rand_goat_address(),
            to_addr: get_rand_btc_address_p2wpkh(get_network()),
            graph_ipfs_base_url: "".to_string(),
            amount: 2000000,
            challenge_amount: 1000000,
            status: GraphStatus::OperatorDataPushed.to_string(),
            sub_status: "".to_string(),
            operator_pubkey: "btc_pub_key".to_string(),
            next_prekickoff: None,
            cur_prekickoff_txid: None,
            force_skip_kickoff_txid: None,
            quick_challenge_txid: None,
            challenge_incomplete_kickoff_txid: None,
            pegin_txid: None,
            kickoff_txid: None,
            take1_txid: None,
            challenge_txid: None,
            take2_txid: None,
            disprove_txid: None,
            watchtower_challenge_init_txid: None,
            watchtower_challenge_timeout_txids: vec![],
            nack_txids: vec![],
            blockhash_commit_timeout_txid: None,
            assert_init_txid: None,
            assert_commit_timeout_txids: vec![],
            init_withdraw_tx_hash: None,
            bridge_out_start_at: 0,
            zkm_version: "zkm1.0.0".to_string(),
            created_at: current_time_secs(),
            updated_at: current_time_secs(),
        };
        if let Some(goat_addr) = params.goat_addr {
            graph.from_addr = goat_addr;
        }
        if let Some(btc_pub_key) = params.btc_pub_key {
            graph.operator_pubkey = btc_pub_key;
        }

        Ok::<GraphReadyToKickoffResponse, Box<dyn std::error::Error>>(GraphReadyToKickoffResponse {
            graph: Some(graph),
            no_ready_reason: None,
        })
    };
    match async_fn().await {
        Ok(resp) => Ok((StatusCode::OK, Json(resp))),
        Err(err) => {
            tracing::warn!("get ready to kickoff graph  err:{:?}", err);
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "GET READT_KICKOFF_GRAPHS_ERROR".to_string(),
                    message: err.to_string(),
                }),
            ))
        }
    }
}

/// Add extended data to graphs
///
/// Helper function to enrich graph data with confirmation status and proof information.
/// This function processes a list of graphs and adds confirmation counts, target confirmations,
/// and proof-related metadata.
///
/// # Parameters
///
/// - `storage_processor`: Database storage processor for querying additional data
/// - `btc_client`: Bitcoin client for getting current blockchain height
/// - `graphs`: Vector of graphs to process
///
/// # Returns
///
/// - `Ok(Vec<GraphExtended>)`: Vector of graphs with extended data
/// - `Err`: Error if processing fails
///
/// # Features
///
/// - Calculates transaction confirmation status
/// - Modifies graph status based on withdrawal transaction presence
/// - Adds proof height and query URL information
///
/// Add extended data to graphs
///
/// Helper function to enrich graph data with confirmation status and proof information.
/// This function processes a list of graphs and adds confirmation counts, target confirmations,
/// and proof-related metadata.
///
/// # Parameters
///
/// - `storage_processor`: Database storage processor for querying additional data
/// - `btc_client`: Bitcoin client for getting current blockchain height
/// - `graphs`: Vector of graphs to process
///
/// # Returns
///
/// - `Ok(Vec<GraphExtended>)`: Vector of graphs with extended data
/// - `Err`: Error if processing fails
///
/// # Features
///
/// - Calculates transaction confirmation status
/// - Modifies graph status based on withdrawal transaction presence
/// - Adds proof height and query URL information
/// - Reverses Bitcoin transaction IDs for proper display
///
/// # Note
///
/// This function modifies the input graphs in-place and returns enhanced versions.
pub async fn add_extend_data_to_graphs<'a>(
    storage_processor: &mut StorageProcessor<'a>,
    btc_client: &BTCClient,
    graphs: Vec<Graph>,
) -> Result<Vec<GraphExtended>, Box<dyn std::error::Error>> {
    let current_height = btc_client.get_height().await?;
    let mut graph_vec = vec![];
    let mut graph_ids = vec![];

    for mut graph in graphs {
        graph.reverse_btc_txid();
        let (confirmations, target_confirmations) = match graph.get_check_tx_param() {
            Ok((tx_id, confirm_num)) => {
                get_tx_confirmation_info(btc_client, tx_id, current_height, confirm_num).await?
            }
            Err(_) => (0, 0),
        };
        graph.status = modify_graph_status(&graph.status, graph.init_withdraw_tx_hash.is_some());
        graph_ids.push(graph.graph_id);
        graph_vec.push(GraphExtended {
            graph,
            confirmations,
            target_confirmations,
            proof_height: None,
            proof_query_url: None,
        });
    }

    let socket_info_map: HashMap<Uuid, (String, i64)> = storage_processor
        .get_socket_addr_for_graph_query_proof(&graph_ids, &GoatTxType::ProceedWithdraw.to_string())
        .await?;
    Ok(graph_vec
        .into_iter()
        .map(|mut v| {
            if let Some((socket_addr, height)) = socket_info_map.get(&v.graph.graph_id)
                && *height > 0
            {
                v.proof_height = Some(*height);
                v.proof_query_url = Some(format!("http://{socket_addr}/v1/proofs/{}", *height));
            }
            v
        })
        .collect())
}

pub async fn get_graph_btc_tx_process_data<'a>(
    storage_processor: &mut StorageProcessor<'a>,
    btc_tx_name: GraphBtcTxName,
    graph: &Graph,
) -> anyhow::Result<(Vec<ProgressData>, Option<String>)> {
    let mut progress_datas: Vec<ProgressData> = vec![];
    // todo update fail reason
    let fail_reason: Option<String> = None;

    match btc_tx_name {
        GraphBtcTxName::WatchtowerChallengeInit => {
            if let Some(tx) = graph.watchtower_challenge_init_txid.clone()
                && let Some(vout_monitor) =
                    storage_processor.get_graph_btc_tx_vout_monitor(&graph.graph_id, &tx).await?
                && let Ok(monitor_data) =
                    serde_json::from_str::<WTInitTxVoutMonitorData>(&vout_monitor.monitor_data)
            {
                progress_datas.push(ProgressData {
                    name: WATCHTOWER_CHALLENGE_STEP_INIT.to_string(),
                    current: 1,
                    total: 1,
                });
                let (current, total) = monitor_data.get_challenge_process_desc();
                progress_datas.push(ProgressData {
                    name: WATCHTOWER_CHALLENGE_STEP_CHALLENGE.to_string(),
                    current,
                    total,
                });
                let (current, total) = monitor_data.get_challenge_timeout_process_desc();
                progress_datas.push(ProgressData {
                    name: WATCHTOWER_CHALLENGE_STEP_CHALLENGE_TIMEOUT.to_string(),
                    current,
                    total,
                });
                let (current, total) = monitor_data.get_ack_process_desc();
                progress_datas.push(ProgressData {
                    name: WATCHTOWER_CHALLENGE_STEP_ACK.to_string(),
                    current,
                    total,
                });

                let (current, total) = monitor_data.get_commit_block_hash_desc();
                progress_datas.push(ProgressData {
                    name: WATCHTOWER_CHALLENGE_STEP_COMMIT_BLOCKHASH.to_string(),
                    current,
                    total,
                });

                let (current, total) = monitor_data.get_commit_block_hash_timeout_desc();
                progress_datas.push(ProgressData {
                    name: WATCHTOWER_CHALLENGE_STEP_COMMIT_BLOCKHASH_TIMEOUT.to_string(),
                    current,
                    total,
                });
            }
        }
        GraphBtcTxName::AssertInit => {
            if let Some(tx) = graph.assert_init_txid.clone()
                && let Some(vout_monitor) =
                    storage_processor.get_graph_btc_tx_vout_monitor(&graph.graph_id, &tx).await?
                && let Ok(monitor_data) =
                    serde_json::from_str::<AssertInitTxVoutMonitorData>(&vout_monitor.monitor_data)
            {
                progress_datas.push(ProgressData {
                    name: ASSERT_STEP_INIT.to_string(),
                    current: 1,
                    total: 1,
                });
                let (current, total) = monitor_data.get_commit_process_desc();
                progress_datas.push(ProgressData {
                    name: ASSERT_STEP_COMMIT.to_string(),
                    current,
                    total,
                });
            }
        }
        _ => {}
    }
    Ok((progress_datas, fail_reason))
}

#[axum::debug_handler]
pub async fn get_graph_tx(
    Query(params): Query<GraphTxGetParams>,
    Path(graph_id): Path<String>,
    State(app_state): State<Arc<AppState>>,
) -> ApiResult<GraphTxGetResponse> {
    // Validate graph_id format
    let graph_id_uuid = InputValidator::validate_uuid(&graph_id, "graph_id")?;
    // Validate tx_name format
    let tx_name = InputValidator::validate_tx_name(&params.tx_name)?;
    let async_fn = || async move {
        let mut storage_process = app_state.local_db.acquire().await?;
        if let Some(graph_raw_data) = storage_process.get_graph_raw_data(&graph_id_uuid).await?
            && let Some(graph) = storage_process.find_graph(&graph_id_uuid).await?
        {
            let (progresses, fail_reason) =
                get_graph_btc_tx_process_data(&mut storage_process, tx_name.clone(), &graph)
                    .await?;
            let bitvm2_graph: Bitvm2Graph = serde_json::from_str(graph_raw_data.raw_data.as_str())?;
            let raw_data = match tx_name {
                GraphBtcTxName::AssertInit => serialize_hex(bitvm2_graph.assert_init.tx()),
                GraphBtcTxName::PreKickoff => serialize_hex(bitvm2_graph.cur_prekickoff.tx()),
                GraphBtcTxName::Kickoff => serialize_hex(bitvm2_graph.kickoff.tx()),
                GraphBtcTxName::Pegin => serialize_hex(bitvm2_graph.pegin.tx()),
                GraphBtcTxName::Take1 => serialize_hex(bitvm2_graph.take1.tx()),
                GraphBtcTxName::Take2 => serialize_hex(bitvm2_graph.take2.tx()),
                GraphBtcTxName::WatchtowerChallengeInit => {
                    serialize_hex(bitvm2_graph.watchtower_challenge_init.tx())
                }
                GraphBtcTxName::Challenge => {
                    if let Some(challenge_txid) = graph.challenge_txid
                        && let Ok(Some(tx)) = app_state.btc_client.get_tx(&challenge_txid.0).await
                    {
                        serialize_hex(&tx)
                    } else {
                        serialize_hex(bitvm2_graph.challenge.tx())
                    }
                }
                GraphBtcTxName::Disprove => {
                    if let Some(disprove_txid) = graph.disprove_txid
                        && let Ok(Some(tx)) = app_state.btc_client.get_tx(&disprove_txid.0).await
                    {
                        serialize_hex(&tx)
                    } else {
                        "".to_string()
                    }
                }
            };
            Ok::<GraphTxGetResponse, Box<dyn std::error::Error>>(GraphTxGetResponse {
                btc_tx_data: BtcTxData { raw_data, progresses, fail_reason },
            })
        } else {
            tracing::warn!("graph:{} is not record in db", graph_id);
            Err(format!("graph:{graph_id} is not record in db").into())
        }
    };
    match async_fn().await {
        Ok(resp) => Ok((StatusCode::OK, Json(resp))),
        Err(err) => {
            tracing::warn!("get_graph_tx err:{:?}", err);
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "GET_GRAPH_TX_ERROR".to_string(),
                    message: err.to_string(),
                }),
            ))
        }
    }
}

#[axum::debug_handler]
pub async fn get_graph_txn(
    Path(graph_id): Path<String>,
    Query(_params): Query<GraphTxnGetParams>,
    State(app_state): State<Arc<AppState>>,
) -> ApiResult<GraphTxnGetResponse> {
    // Validate graph_id format
    let graph_id_uuid = InputValidator::validate_uuid(&graph_id, "graph_id")?;

    let async_fn = || async move {
        let mut storage_process = app_state.local_db.acquire().await?;
        if let Some(graph_raw_data) = storage_process.get_graph_raw_data(&graph_id_uuid).await?
            && let Some(graph) = storage_process.find_graph(&graph_id_uuid).await?
        {
            let bitvm2_graph: Bitvm2Graph = serde_json::from_str(graph_raw_data.raw_data.as_str())?;
            let (wt_progresses, wt_fail_reason) = get_graph_btc_tx_process_data(
                &mut storage_process,
                GraphBtcTxName::WatchtowerChallengeInit,
                &graph,
            )
            .await?;
            let (assert_progresses, assert_fail_reason) = get_graph_btc_tx_process_data(
                &mut storage_process,
                GraphBtcTxName::AssertInit,
                &graph,
            )
            .await?;
            let mut resp = GraphTxnGetResponse {
                assert_init: BtcTxData::new(serialize_hex(bitvm2_graph.assert_init.tx())),
                watchtower_challenge_init: BtcTxData::new(serialize_hex(
                    bitvm2_graph.watchtower_challenge_init.tx(),
                ))
                .with_progresses(wt_progresses)
                .with_fail_reason(wt_fail_reason),
                pre_kickoff: BtcTxData::new(serialize_hex(bitvm2_graph.cur_prekickoff.tx()))
                    .with_progresses(assert_progresses)
                    .with_fail_reason(assert_fail_reason),
                challenge: BtcTxData::new(serialize_hex(bitvm2_graph.challenge.tx())),
                disprove: Default::default(),
                kickoff: BtcTxData::new(serialize_hex(bitvm2_graph.kickoff.tx())),
                pegin: BtcTxData::new(serialize_hex(bitvm2_graph.pegin.tx())),
                take1: BtcTxData::new(serialize_hex(bitvm2_graph.take1.tx())),
                take2: BtcTxData::new(serialize_hex(bitvm2_graph.take2.tx())),
            };
            if let Some(challenge_txid) = graph.challenge_txid
                && let Ok(Some(tx)) = app_state.btc_client.get_tx(&challenge_txid.0).await
            {
                resp.challenge.raw_data = serialize_hex(&tx);
            }
            if let Some(disprove_txid) = graph.disprove_txid
                && let Ok(Some(tx)) = app_state.btc_client.get_tx(&disprove_txid.0).await
            {
                resp.disprove.raw_data = serialize_hex(&tx);
            }
            Ok::<GraphTxnGetResponse, Box<dyn std::error::Error>>(resp)
        } else {
            tracing::warn!("graph:{} is not record in db", graph_id);
            Err(format!("graph:{graph_id} is not record in db").into())
        }
    };
    match async_fn().await {
        Ok(resp) => Ok((StatusCode::OK, Json(resp))),
        Err(err) => {
            tracing::warn!("get graph txn err:{:?}", err);
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "GET_GRAPH_TXN_ERROR".to_string(),
                    message: err.to_string(),
                }),
            ))
        }
    }
}

// fn is_segwit_address(address: &str, network: &str) -> anyhow::Result<bool> {
//     let addr: Address<NetworkUnchecked> = Address::from_str(address)?;
//     let addr = addr.require_network(Network::from_str(network)?)?;
//     Ok(matches!(
//         addr.address_type(),
//         Some(AddressType::P2wpkh) | Some(AddressType::P2wsh) | Some(AddressType::P2tr)
//     ))
// }
