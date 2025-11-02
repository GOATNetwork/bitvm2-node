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
use std::default::Default;
use std::str::FromStr;
use std::sync::Arc;
use store::localdb::{GraphQuery, InstanceQuery, StorageProcessor};
use store::{Graph, GraphStatus, Instance, InstanceStatus, UInt64Array3};
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

/// Get instance list
///
/// Returns a paginated list of bridge instances based on query parameters. Supports filtering by
/// source address and bridge direction (bridge-in or bridge-out).
///
/// # Query Parameters
///
/// - `from_addr`: Source address filter (optional) - filters instances by source Bitcoin address
/// - `is_bridge_in`: Bridge direction filter (required) - true for bridge-in, false for bridge-out
/// - `offset`: Pagination offset (default: 0) - number of items to skip
/// - `limit`: Items per page (default: 10) - maximum number of items to return
///
/// # Returns
///
/// - `200 OK`: Successfully returns instance list with status information
/// - `500 Internal Server Error`: Server internal error or database operation failed
/// - Response includes total count and paginated instance data with UTXO details
///
/// # Use Case
///
/// Frontend applications use this to display user's bridge transaction history and current status.
///
/// # Example
///
/// ```http
/// GET /v1/instances?is_bridge_in=true&offset=0&limit=10
/// ```
///
/// Response example:
/// ```json
/// {
///   "instance_wraps": [
///     {
///       "instance": {
///         "instance_id": "123e4567-e89b-12d3-a456-426614174000",
///         "is_bridge_in": true,
///         "network": "testnet",
///         "from_addr": "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx",
///         "to_addr": "0x1234567890abcdef1234567890abcdef12345678",
///         "amount": 100000000,
///         "fees": [10, 20, 30],
///         "input_utxos": "[{\"txid\":\"abc123...\",\"vout\":0,\"value\":100000000}]",
///         "status": "CommitteesAnswered",
///         "goat_tx_hash": "0xf6d6523a4344806aca5c66f23554bc574cb93634572f5e115cc630b3d8db3c6e",
///         "goat_tx_height": 8509060,
///         "user_xonly_pubkey": "02abc123...",
///         "user_change_addr": "tb1q...",
///         "user_refund_addr": "tb1q...",
///         "btc_txid": "f6d6523a4344806aca5c66f23554bc574cb93634572f5e115cc630b3d8db3c6e",
///         "btc_height": 2500000,
///         "pegin_confirm_txid": "a1b2c3d4...",
///         "pegin_cancel_txid": null,
///         "committees_answers": {},
///         "pegin_data_tx_hash": "0x...",
///         "parameters": null,
///         "created_at": 1699123456,
///         "updated_at": 1699123456
///       },
///       "utxo": [
///         {
///           "txid": "abc123...",
///           "vout": 0,
///           "value": 100000000,
///           "script_pubkey": "0014..."
///         }
///       ],
///       "waiting_time_in_mins": 60,
///       "status_extra": {
///         "user_action": "Submit",
///         "is_failed": false,
///         "error": null
///       }
///     }
///   ],
///   "total": 1
/// }
/// ```
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
        let mut items = vec![];
        for instance in instances {
            let utxo: Vec<Utxo> =
                serde_json::from_str(&instance.input_utxos).map_err(|_| "failed to parse utxos")?;
            items.push(InstanceExtended {
                utxo,
                instance,
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

/// Get instance by ID
///
/// Returns detailed information for a specific bridge instance including UTXO details
/// and current processing state.
///
/// # Path Parameters
///
/// - `instance_id`: UUID of the bridge instance to retrieve
///
/// # Returns
///
/// - `200 OK`: Successfully returns instance details with UTXO and status information
/// - `500 Internal Server Error`: Server internal error or database operation failed
/// - Returns empty instance wrap if instance_id not found in database
///
/// # Use Case
///
/// Frontend applications use this to display detailed information about a specific bridge transaction,
/// including its current status and associated UTXOs.
///
/// # Example
///
/// ```http
/// GET /v1/instances/123e4567-e89b-12d3-a456-426614174000
/// ```
///
/// Response example:
/// ```json
/// {
///   "instance_wrap": {
///     "instance": {
///       "instance_id": "123e4567-e89b-12d3-a456-426614174000",
///       "is_bridge_in": true,
///       "network": "testnet",
///       "from_addr": "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx",
///       "to_addr": "0x1234567890abcdef1234567890abcdef12345678",
///       "amount": 100000000,
///       "fees": [10, 20, 30],
///       "input_utxos": "[{\"txid\":\"abc123...\",\"vout\":0,\"value\":100000000}]",
///       "status": "CommitteesAnswered",
///       "goat_tx_hash": "0xf6d6523a4344806aca5c66f23554bc574cb93634572f5e115cc630b3d8db3c6e",
///       "goat_tx_height": 8509060,
///       "user_xonly_pubkey": "02abc123...",
///       "user_change_addr": "tb1q...",
///       "user_refund_addr": "tb1q...",
///       "btc_txid": "f6d6523a4344806aca5c66f23554bc574cb93634572f5e115cc630b3d8db3c6e",
///       "btc_height": 2500000,
///       "pegin_confirm_txid": "a1b2c3d4...",
///       "pegin_cancel_txid": null,
///       "committees_answers": {},
///       "pegin_data_tx_hash": "0x...",
///       "parameters": null,
///       "created_at": 1699123456,
///       "updated_at": 1699123456
///     },
///     "utxo": [
///       {
///         "txid": "abc123...",
///         "vout": 0,
///         "value": 100000000,
///         "script_pubkey": "0014..."
///       }
///     ],
///     "waiting_time_in_mins": 60,
///     "status_extra": {
///       "user_action": "Submit",
///       "is_failed": false,
///       "error": null
///     }
///   }
/// }
/// ```
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
            let utxo: Vec<Utxo> =
                serde_json::from_str(&instance.input_utxos).map_err(|_| "failed to parse utxos")?;
            Ok::<InstanceGetResponse, Box<dyn std::error::Error>>(InstanceGetResponse {
                instance_wrap: InstanceExtended {
                    utxo,
                    instance,
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

/// Get instances overview statistics
///
/// Returns statistical overview of all bridge instances including total bridge-in/bridge-out amounts,
/// transaction counts, and node status information.
///
/// # Returns
///
/// - `200 OK`: Successfully returns overview statistics
/// - `500 Internal Server Error`: Server internal error or database operation failed
/// - Response includes aggregated statistics for bridge operations and node status
///
/// # Use Case
///
/// Frontend applications use this to display dashboard statistics showing overall system activity,
/// including total bridged amounts, transaction counts, and network health.
///
/// # Example
///
/// ```http
/// GET /v1/instances/overview
/// ```
///
/// Response example:
/// ```json
/// {
///   "instances_overview": {
///     "total_bridge_in_amount": 3000000,
///     "total_bridge_in_txn": 1,
///     "total_bridge_out_amount": 2000000,
///     "total_bridge_out_txn": 2,
///     "total_peg_out_amount": 1000000,
///     "total_peg_out_txn": 1,
///     "online_nodes": 3,
///     "total_nodes": 4
///   }
/// }
/// ```
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

// async fn get_tx_confirmation_info(
//     btc_client: &BTCClient,
//     btc_tx_id: Option<String>,
//     current_height: u32,
//     target_confirm_num: u32,
// ) -> anyhow::Result<(u32, u32)> {
//     if btc_tx_id.is_none() {
//         return Ok((0, target_confirm_num));
//     }
//     let tx_id = btc_tx_id.unwrap();
//     let status = btc_client.get_tx_status(&Txid::from_str(&tx_id)?).await?;
//     let blocks_pass = if let Some(block_height) = status.block_height {
//         current_height - block_height
//     } else {
//         0
//     };
//     Ok((blocks_pass, target_confirm_num))
// }

/// Get graph by ID
///
/// Returns detailed information for a specific BitVM2 graph including transaction status
/// and waiting time information.
///
/// # Path Parameters
///
/// - `graph_id`: UUID of the BitVM2 graph to retrieve
///
/// # Returns
///
/// - `200 OK`: Successfully returns graph details with extended information
/// - `500 Internal Server Error`: Server internal error or database operation failed
/// - Returns None graph if graph_id not found in database
///
/// # Use Case
///
/// Applications use this to retrieve detailed information about a specific BitVM2 graph,
/// including its current status and estimated waiting time.
///
/// # Example
///
/// ```http
/// GET /v1/graphs/123e4567-e89b-12d3-a456-426614174000
/// ```
///
/// Response example:
/// ```json
/// {
///   "graph": {
///     "graph": {
///       "graph_id": "123e4567-e89b-12d3-a456-426614174000",
///       "instance_id": "987e6543-e89b-12d3-a456-426614174000",
///       "kickoff_index": 10,
///       "from_addr": "0x1234567890abcdef1234567890abcdef12345678",
///       "to_addr": "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx",
///       "graph_ipfs_base_url": "https://ipfs.io/ipfs/Qm...",
///       "amount": 2000000,
///       "challenge_amount": 1000000,
///       "status": "OperatorPresigned",
///       "sub_status": "",
///       "operator_pubkey": "03abc123...",
///       "next_prekickoff": null,
///       "cur_prekickoff_txid": "a1b2c3d4...",
///       "force_skip_kickoff_txid": null,
///       "quick_challenge_txid": null,
///       "challenge_incomplete_kickoff_txid": null,
///       "pegin_txid": null,
///       "kickoff_txid": null,
///       "take1_txid": null,
///       "challenge_txid": null,
///       "take2_txid": null,
///       "disprove_txid": null,
///       "watchtower_challenge_init_txid": null,
///       "watchtower_challenge_timeout_txids": [],
///       "nack_txids": [],
///       "blockhash_commit_timeout_txid": null,
///       "assert_init_txid": null,
///       "assert_commit_timeout_txids": [],
///       "init_withdraw_tx_hash": null,
///       "bridge_out_start_at": 1699123456,
///       "zkm_version": "zkm1.0.0",
///       "created_at": 1699123456,
///       "updated_at": 1699123456
///     },
///     "waiting_time_in_mins": 1000
///   }
/// }
/// ```
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
/// Each graph includes status and waiting time information.
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
/// - `200 OK`: Successfully returns graph list with status and waiting time
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
///         "instance_id": "987e6543-e89b-12d3-a456-426614174000",
///         "kickoff_index": 10,
///         "from_addr": "0x1234567890abcdef1234567890abcdef12345678",
///         "to_addr": "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx",
///         "graph_ipfs_base_url": "https://ipfs.io/ipfs/Qm...",
///         "amount": 2000000,
///         "challenge_amount": 1000000,
///         "status": "OperatorPresigned",
///         "sub_status": "",
///         "operator_pubkey": "03abc123...",
///         "next_prekickoff": null,
///         "cur_prekickoff_txid": "a1b2c3d4...",
///         "force_skip_kickoff_txid": null,
///         "quick_challenge_txid": null,
///         "challenge_incomplete_kickoff_txid": null,
///         "pegin_txid": null,
///         "kickoff_txid": null,
///         "take1_txid": null,
///         "challenge_txid": null,
///         "take2_txid": null,
///         "disprove_txid": null,
///         "watchtower_challenge_init_txid": null,
///         "watchtower_challenge_timeout_txids": [],
///         "nack_txids": [],
///         "blockhash_commit_timeout_txid": null,
///         "assert_init_txid": null,
///         "assert_commit_timeout_txids": [],
///         "init_withdraw_tx_hash": null,
///         "bridge_out_start_at": 1699123456,
///         "zkm_version": "zkm1.0.0",
///         "created_at": 1699123456,
///         "updated_at": 1699123456
///       },
///       "waiting_time_in_mins": 1000
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

/// Get ready to kickoff graph
///
/// Returns a BitVM2 graph that is ready for the operator to kickoff. This endpoint is used by
/// operators to query available graphs that need kickoff processing.
///
/// # Query Parameters
///
/// - `btc_pub_key`: Operator's Bitcoin public key (required) - identifies the operator
/// - `goat_addr`: GOAT address filter (optional) - filters by source address
///
/// # Returns
///
/// - `200 OK`: Successfully returns ready graph or reason why no graph is ready
/// - `500 Internal Server Error`: Server internal error or missing required parameters
/// - Response includes graph data if available, or reason why no graph is ready
///
/// # Use Case
///
/// Operators use this endpoint to poll for graphs that are in OperatorDataPushed status
/// and ready for kickoff processing. The operator can start the kickoff process once a
/// suitable graph is found.
///
/// # Example
///
/// ```http
/// GET /v1/graphs/ready-to-kickoff?btc_pub_key=03abc...&goat_addr=0x123...
/// ```
///
/// Response example:
/// ```json
/// {
///   "graph": {
///     "graph_id": "123e4567-e89b-12d3-a456-426614174000",
///     "instance_id": "987e6543-e89b-12d3-a456-426614174000",
///     "kickoff_index": 10,
///     "from_addr": "0x1234567890abcdef1234567890abcdef12345678",
///     "to_addr": "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx",
///     "graph_ipfs_base_url": "",
///     "amount": 2000000,
///     "challenge_amount": 1000000,
///     "status": "OperatorDataPushed",
///     "sub_status": "",
///     "operator_pubkey": "03abc...",
///     "next_prekickoff": null,
///     "cur_prekickoff_txid": null,
///     "force_skip_kickoff_txid": null,
///     "quick_challenge_txid": null,
///     "challenge_incomplete_kickoff_txid": null,
///     "pegin_txid": null,
///     "kickoff_txid": null,
///     "take1_txid": null,
///     "challenge_txid": null,
///     "take2_txid": null,
///     "disprove_txid": null,
///     "watchtower_challenge_init_txid": null,
///     "watchtower_challenge_timeout_txids": [],
///     "nack_txids": [],
///     "blockhash_commit_timeout_txid": null,
///     "assert_init_txid": null,
///     "assert_commit_timeout_txids": [],
///     "init_withdraw_tx_hash": null,
///     "bridge_out_start_at": 0,
///     "zkm_version": "zkm1.0.0",
///     "created_at": 1699123456,
///     "updated_at": 1699123456
///   },
///   "no_ready_reason": null
/// }
/// ```
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
async fn add_extend_data_to_graphs<'a>(
    _storage_processor: &mut StorageProcessor<'a>,
    _btc_client: &BTCClient,
    graphs: Vec<Graph>,
) -> Result<Vec<GraphExtended>, Box<dyn std::error::Error>> {
    // todo update waiting in time
    Ok(graphs
        .into_iter()
        .map(|graph| GraphExtended { graph, waiting_time_in_mins: 1000 })
        .collect())
}

/// Get graph Bitcoin transaction progress data
///
/// Helper function to retrieve progress tracking data for specific BitVM2 graph transactions.
/// This function monitors transaction vout status and extracts progress information for
/// watchtower challenges and assert operations.
///
/// # Parameters
///
/// - `storage_processor`: Database storage processor for querying transaction monitoring data
/// - `btc_tx_name`: The type of Bitcoin transaction to query (WatchtowerChallengeInit or AssertInit)
/// - `graph`: The graph instance containing transaction IDs
///
/// # Returns
///
/// - `Ok((progress_data_vec, fail_reason))`: Tuple of progress data steps and optional failure reason
/// - `Err`: Error if database query or JSON deserialization fails
///
/// # Features
///
/// - For WatchtowerChallengeInit: Tracks init, challenge, challenge timeout, NACK, commit blockhash, and timeout steps
/// - For AssertInit: Tracks init and commit steps
/// - Returns empty progress data for other transaction types
///
/// # Note
///
/// Progress data includes current/total counts for each step in multi-stage transaction processes.
pub(crate) async fn get_graph_btc_tx_process_data<'a>(
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

/// Get graph transaction by name
///
/// Returns raw Bitcoin transaction data and progress information for a specific transaction
/// within a BitVM2 graph. Supports querying various transaction types including kickoff,
/// challenge, and take transactions.
///
/// # Path Parameters
///
/// - `graph_id`: UUID of the BitVM2 graph
///
/// # Query Parameters
///
/// - `tx_name`: Name of the transaction to retrieve (e.g., "kickoff", "challenge", "take1", etc.)
///
/// # Returns
///
/// - `200 OK`: Successfully returns transaction raw data and progress information
/// - `500 Internal Server Error`: Server internal error or invalid parameters
/// - Returns serialized transaction hex and progress tracking data
///
/// # Use Case
///
/// Applications use this to retrieve specific transaction details from a graph, including
/// the raw transaction data for broadcasting and progress information for multi-step processes.
///
/// # Example
///
/// ```http
/// GET /v1/graphs/123e4567-e89b-12d3-a456-426614174000/tx?tx_name=watchtower-challenge-init.hex
/// ```
///
/// Response example (for WatchtowerChallengeInit transaction):
/// ```json
/// {
///   "btc_tx_data": {
///     "raw_data": "020000000001...",
///     "progresses": [
///       {
///         "name": "Watchtower Challenge init",
///         "current": 1,
///         "total": 1
///       },
///       {
///         "name": "Watchtower Challenge",
///         "current": 3,
///         "total": 5
///       },
///       {
///         "name": "Watchtower Challenge Timeout",
///         "current": 0,
///         "total": 2
///       },
///       {
///         "name": "Operator Challenge NACK",
///         "current": 2,
///         "total": 3
///       },
///       {
///         "name": "Operator Commit BlockHash",
///         "current": 1,
///         "total": 4
///       },
///       {
///         "name": "Operator Commit BlockHash Timeout",
///         "current": 0,
///         "total": 1
///       }
///     ],
///     "fail_reason": null
///   }
/// }
/// ```
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

/// Get all graph transactions
///
/// Returns raw Bitcoin transaction data and progress information for all transactions
/// in a BitVM2 graph. This includes all transaction types: assert_init, watchtower_challenge_init,
/// pre_kickoff, challenge, disprove, kickoff, pegin, take1, and take2.
///
/// # Path Parameters
///
/// - `graph_id`: UUID of the BitVM2 graph
///
/// # Query Parameters
///
/// - Currently no query parameters are required
///
/// # Returns
///
/// - `200 OK`: Successfully returns all transaction raw data with progress information
/// - `500 Internal Server Error`: Server internal error or graph not found
/// - Response includes serialized hex data for all graph transactions and their progress tracking
///
/// # Use Case
///
/// Applications use this to retrieve all transaction details from a graph in a single request,
/// which is useful for displaying the complete transaction flow and status of a BitVM2 graph.
///
/// # Example
///
/// ```http
/// GET /v1/graphs/123e4567-e89b-12d3-a456-426614174000/txn
/// ```
///
/// Response example:
/// ```json
/// {
///   "assert_init": {
///     "raw_data": "020000000001...",
///     "progresses": [],
///     "fail_reason": null
///   },
///   "watchtower_challenge_init": {
///     "raw_data": "020000000001...",
///     "progresses": [
///       {
///         "name": "Watchtower Challenge init",
///         "current": 1,
///         "total": 1
///       },
///       {
///         "name": "Watchtower Challenge",
///         "current": 3,
///         "total": 5
///       },
///       {
///         "name": "Watchtower Challenge Timeout",
///         "current": 0,
///         "total": 2
///       },
///       {
///         "name": "Operator Challenge NACK",
///         "current": 2,
///         "total": 3
///       },
///       {
///         "name": "Operator Commit BlockHash",
///         "current": 1,
///         "total": 4
///       },
///       {
///         "name": "Operator Commit BlockHash Timeout",
///         "current": 0,
///         "total": 1
///       }
///     ],
///     "fail_reason": null
///   },
///   "pre_kickoff": {
///     "raw_data": "020000000001...",
///     "progresses": [],
///     "fail_reason": null
///   },
///   "challenge": {
///     "raw_data": "020000000001...",
///     "progresses": [],
///     "fail_reason": null
///   },
///   "disprove": {
///     "raw_data": "",
///     "progresses": [],
///     "fail_reason": null
///   },
///   "kickoff": {
///     "raw_data": "020000000001...",
///     "progresses": [],
///     "fail_reason": null
///   },
///   "pegin": {
///     "raw_data": "020000000001...",
///     "progresses": [],
///     "fail_reason": null
///   },
///   "take1": {
///     "raw_data": "020000000001...",
///     "progresses": [],
///     "fail_reason": null
///   },
///   "take2": {
///     "raw_data": "020000000001...",
///     "progresses": [],
///     "fail_reason": null
///   }
/// }
/// ```
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
