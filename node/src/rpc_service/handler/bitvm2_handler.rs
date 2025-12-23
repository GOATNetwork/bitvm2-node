use crate::env::{
    ENV_GOAT_GATEWAY_CONTRACT_ADDRESS, ENV_GOAT_SWAP_CONTRACT_ADDRESS, GraphBtcTxName,
    get_goat_address_from_env, get_network,
};
use crate::rpc_service::bitvm2::*;
use crate::rpc_service::node::ALIVE_TIME_JUDGE_THRESHOLD;
use crate::rpc_service::response::{
    ApiErrorExt, ApiResult, ErrorResponse, error_response, ok_response,
};
use crate::rpc_service::validation::InputValidator;
use crate::rpc_service::{AppState, current_time_secs};
use crate::scheduled_tasks::graph_maintenance_tasks::{
    AssertInitTxVoutMonitorData, ChallengeSubStatus, WTInitTxVoutMonitorData,
};
use crate::utils::{
    find_instances_by_escrow_hash, gen_instance_parameters_local, parse_graph_raw_data,
};
use alloy::primitives::Address;
use axum::Json;
use axum::extract::{Path, Query, State};
use bitcoin::consensus::encode::serialize_hex;
use bitvm2_lib::types::{Bitvm2Graph, SimplifiedBitvm2Graph};
use client::goat_chain::DisproveTxType;
use goat::transactions::pre_signed::PreSignedTransaction;
use http::StatusCode;
use std::default::Default;
use std::sync::Arc;
use store::localdb::{GraphQuery, InstanceQuery, StorageProcessor};
use store::{
    GoatTxType, Graph, GraphStatus, Instance, InstanceBridgeInStatus, InstanceBridgeOutStatus,
};
use tracing::warn;
use uuid::Uuid;

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
    ok_response(InstanceSettingResponse { bridge_in_amount: BRIDGE_IN_AMOUNTS.to_vec() })
}

/// Prepare bridge-in request
///
/// Validates user-provided data against the allowed bridge-in options returned by
/// [`instance_settings`](routes::v1::INSTANCES_SETTINGS). Clients should first call
/// `instance_settings` to know the supported `bridge_in_amount` list and then submit a
/// bridge-in request using one of those amounts.
///
/// This function creates or updates a bridge-in instance record with status `UserIniting`.
/// The network configuration is read from the environment variable `ENV_BTC_NETWORK`, not
/// from the request body.
///
/// # Request Body
///
/// - `instance_id`: UUID of the bridge-in request (must be a valid UUID format)
/// - `contract_address`: GOAT chain contract address (gateway contract address). Must match
///   the gateway contract address configured in environment variables.
/// - `network`: Target Bitcoin network (e.g. `testnet3`, `mainnet`). Note: This field is
///   present in the request but the actual network is determined from environment configuration.
/// - `from_addr`: Funding Bitcoin address selected by the user (must be a valid BTC address)
/// - `to_addr`: Destination address on GOAT chain that receives bridged assets (must be a valid GOAT address)
/// - `bridge_request_tx_hash`: GOAT chain transaction hash referencing the bridge intent
///
/// # Validation
///
/// The function validates:
/// - `contract_address` matches the configured gateway contract address
/// - `from_addr` is a valid Bitcoin address
/// - `to_addr` is a valid GOAT chain address
/// - `instance_id` is a valid UUID format
///
/// # Returns
///
/// - `200 OK`: Request is valid and instance record created/updated successfully
/// - `500 Internal Server Error`: Validation failed, contract address mismatch, or database error
/// - Response body is an empty object `{}`
///
/// # Example
///
/// ```http
/// PUT /v1/instances/bridge-in-request-tag
/// {
///   "instance_id": "123e4567-e89b-12d3-a456-426614174000",
///   "contract_address": "0xabcdef1234567890abcdef1234567890abcdef12",
///   "from_addr": "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx",
///   "to_addr": "0x1234567890abcdef1234567890abcdef12345678",
///   "bridge_request_tx_hash": "0xf6d6523a4344806aca5c66f23554bc574cb93634572f5e115cc630b3d8db3c6e"
/// }
/// ```
///
/// Response example:
/// ```json
/// {}
/// ```
#[axum::debug_handler]
pub async fn bridge_in_request_tag(
    State(app_state): State<Arc<AppState>>,
    Json(payload): Json<BridgeInPrepareRequest>,
) -> ApiResult<BridgeInPrepareResponse> {
    InputValidator::validate_btc_address(&payload.from_addr, None, "from_addr")?;
    let to_addr = InputValidator::validate_goat_address(&payload.to_addr, "to_addr")?;
    let instance_id = InputValidator::validate_uuid(&payload.instance_id, "instance_id")?;
    let contract_address =
        InputValidator::validate_goat_address(&payload.contract_address, "contract_address")?;
    let gateway_contract: Address = get_goat_address_from_env(ENV_GOAT_GATEWAY_CONTRACT_ADDRESS)
        .ok_or(anyhow::anyhow!("need to set swap contract address"))
        .api_error("PUT_BRIDGE_IN_REQUEST_TAG_ERROR")?;
    if contract_address != gateway_contract.to_string() {
        return error_response(
            format!(
                "Invalid contract address: input: {contract_address}, expect:{gateway_contract}"
            ),
            format!(
                "Invalid contract address: input: {contract_address}, expect:{gateway_contract}"
            ),
        );
    }
    let mut storage_process =
        app_state.local_db.acquire().await.api_error("PUT_BRIDGE_IN_REQUEST_TAG_ERROR")?;
    let current_time = current_time_secs();
    storage_process
        .upsert_instance(&Instance {
            instance_id,
            is_bridge_in: true,
            network: get_network().to_string(),
            from_addr: payload.from_addr,
            to_addr,
            input_utxos: "[]".to_string(),
            status: InstanceBridgeInStatus::UserIniting.to_string(),
            status_updated_at: current_time,
            created_at: current_time,
            updated_at: current_time,
            ..Default::default()
        })
        .await
        .api_error("PUT_BRIDGE_IN_REQUEST_TAG_ERROR")?;
    ok_response(BridgeInPrepareResponse {})
}

/// Initialize bridge-out request
///
/// Validates user-provided bridge-out data and creates a bridge-out instance record. This is the first step
/// in the bridge-out workflow, used to prepare bridging assets from L2 (GOAT) to L1 (Bitcoin). Clients should
/// provide an escrow hash (`escrow_hash`) to associate with an escrow contract already created on the GOAT chain.
///
/// If an instance with the same `escrow_hash` already exists, the function updates the existing instance
/// if it is in `Initialize` status. Otherwise, a new instance is created with an auto-generated UUID.
/// The network configuration is read from the environment variable `ENV_BTC_NETWORK`.
///
/// # Request Body
///
/// - `contract_address`: GOAT chain contract address (swap contract address). Must match the swap contract
///   address configured in environment variables.
/// - `from_addr`: User's source address on the GOAT chain (must be a valid GOAT address)
/// - `to_addr`: Bitcoin destination address that receives the bridged assets (must be a valid BTC address)
/// - `escrow_hash`: Hash of the escrow contract on the GOAT chain (32-byte hex string), referencing the escrow
///   transaction for the bridge intent. Used to identify existing instances.
///
/// # Validation
///
/// The function validates:
/// - `contract_address` matches the configured swap contract address
/// - `from_addr` is a valid GOAT chain address
/// - `to_addr` is a valid Bitcoin address
/// - `escrow_hash` is a valid 32-byte hex string
///
/// # Returns
///
/// - `200 OK`: Request is valid and instance record created/updated successfully
/// - `500 Internal Server Error`: Validation failed, contract address mismatch, or database error
/// - Response body is an empty object `{}`
///
/// # Use Case
///
/// Frontend applications use this endpoint to initiate the bridge-out flow, recording the user's intent to bridge
/// from L2 to L1 into the system. The endpoint handles both new instance creation and updates to existing instances
/// based on the escrow hash.
///
/// # Example
///
/// ```http
/// PUT /v1/instances/bridge-out-init-tag
/// {
///   "contract_address": "0xabcdef1234567890abcdef1234567890abcdef12",
///   "from_addr": "0x1234567890abcdef1234567890abcdef12345678",
///   "to_addr": "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx",
///   "escrow_hash": "0xf6d6523a4344806aca5c66f23554bc574cb93634572f5e115cc630b3d8db3c6e"
/// }
/// ```
///
/// Response example:
/// ```json
/// {}
/// ```
#[axum::debug_handler]
pub async fn bridge_out_init_tag(
    State(app_state): State<Arc<AppState>>,
    Json(payload): Json<BridgeOutInitTagRequest>,
) -> ApiResult<BridgeOutInitTagResponse> {
    let instance_id = Uuid::new_v4();
    let from_addr = InputValidator::validate_goat_address(&payload.from_addr, "from_addr")?;
    InputValidator::validate_btc_address(&payload.to_addr, None, "network and to_addr")?;
    let contract_address =
        InputValidator::validate_goat_address(&payload.contract_address, "contract_address")?;
    let swap_contract: Address = get_goat_address_from_env(ENV_GOAT_SWAP_CONTRACT_ADDRESS)
        .ok_or(anyhow::anyhow!("need to set swap contract address"))
        .api_error("PUT_BRIDGE_OUT_INIT_TAG_ERROR")?;
    if contract_address != swap_contract.to_string() {
        return error_response(
            format!("Invalid contract address: input: {contract_address}, expect:{swap_contract}"),
            format!("Invalid contract address: input: {contract_address}, expect:{swap_contract}"),
        );
    }
    let escrow_hash = InputValidator::validate_hex(&payload.escrow_hash, true, 32, "escrow_hash")?;
    let mut storage_process =
        app_state.local_db.acquire().await.api_error("PUT_BRIDGE_OUT_INIT_TAG_ERROR")?;
    let current_time = current_time_secs();
    let mut instance = match find_instances_by_escrow_hash(&mut storage_process, &escrow_hash)
        .await
        .api_error("PUT_BRIDGE_OUT_INIT_TAG_ERROR")?
    {
        Some(instance) => instance,
        None => Instance {
            instance_id,
            from_addr,
            network: get_network().to_string(),
            input_utxos: "[]".to_string(),
            escrow_hash: Some(escrow_hash),
            status: InstanceBridgeOutStatus::Initialize.to_string(),
            status_updated_at: current_time,
            created_at: current_time,
            ..Default::default()
        },
    };
    if instance.status == InstanceBridgeOutStatus::Initialize.to_string() {
        instance.to_addr = payload.to_addr;
        instance.network = get_network().to_string();
        storage_process
            .upsert_instance(&instance)
            .await
            .api_error("PUT_BRIDGE_OUT_INIT_TAG_ERROR")?;
    }

    ok_response(BridgeOutInitTagResponse {})
}

/// Get instance escrow data
///
/// Returns escrow hash information for a specified bridge instance. Escrow data is used in the bridge-out workflow,
/// containing information about the escrow contract created on the GOAT chain. This endpoint allows clients to query
/// the escrow hash associated with a specific instance for verification and tracking of bridge status.
///
/// # Path Parameters
///
/// - `instance_id`: UUID of the bridge instance to query
///
/// # Returns
///
/// - `200 OK`: Successfully returns escrow data information
/// - `500 Internal Server Error`: Server internal error or database operation failed
/// - Response includes instance ID, escrow hash (if present), and optional error information
///
/// # Use Case
///
/// Frontend applications use this endpoint to query the escrow hash for a bridge-out instance, to verify escrow
/// contract status and track bridge progress.
///
/// # Example
///
/// ```http
/// GET /v1/instances/123e4567-e89b-12d3-a456-426614174000/escrow-data
/// ```
///
/// Response example:
/// ```json
/// {
///   "instance_id": "123e4567-e89b-12d3-a456-426614174000",
///   "escrow": "0xf6d6523a4344806aca5c66f23554bc574cb93634572f5e115cc630b3d8db3c6e",
///   "error": null
/// }
/// ```
#[axum::debug_handler]
pub async fn get_instance_escrow_data(
    State(app_state): State<Arc<AppState>>,
    Path(instance_id): Path<String>,
) -> ApiResult<EscrowDataResponse> {
    let instance_id = InputValidator::validate_uuid(&instance_id, "instance_id")?;
    let mut storage_process =
        app_state.local_db.acquire().await.api_error("PUT_BRIDGE_OUT_INIT_TAG_ERROR")?;
    match storage_process
        .find_graph_goat_tx_record(
            &instance_id,
            &Uuid::nil(),
            &GoatTxType::SwapInitialize.to_string(),
        )
        .await
        .api_error("PUT_BRIDGE_OUT_INIT_TAG_ERROR")?
    {
        Some(tx_record) => ok_response(EscrowDataResponse {
            instance_id: instance_id.to_string(),
            escrow: tx_record.extra,
            error: None,
        }),
        None => ok_response(EscrowDataResponse {
            instance_id: instance_id.to_string(),
            escrow: None,
            error: Some("no escrow record in db".to_string()),
        }),
    }
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
///         "user_xonly_pubkey": [2, 171, 193, 35, ...],
///         "user_change_addr": "tb1q...",
///         "user_refund_addr": "tb1q...",
///         "btc_txid": "f6d6523a4344806aca5c66f23554bc574cb93634572f5e115cc630b3d8db3c6e",
///         "btc_height": 2500000,
///         "pegin_confirm_txid": "a1b2c3d4...",
///         "pegin_cancel_txid": null,
///         "committees_answers": {},
///         "pegin_data_tx_hash": "0x...",
///         "parameters": null,
///         "escrow_hash": null,
///         "status_updated_at": 1699123456,
///         "bridge_out_lock_time": 0,
///         "created_at": 1699123456,
///         "updated_at": 1699123456
///       },
///       "utxo": [
///         {
///           "txid": [171, 193, 35, ...],
///           "vout": 0,
///           "amount_sats": 100000000
///         }
///       ],
///       "confirmations": 0,
///       "target_confirmations": 6,
///       "waiting_time_in_secs": 60,
///       "current_status_waiting_time_in_secs": 30,
///       "status_extra": {
///         "user_action": "None",
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
    // Validate pagination parameters
    let (offset, limit) = InputValidator::validate_pagination(params.offset, params.limit)?;
    // Database query
    let mut storage_process = app_state.local_db.acquire().await.api_error("GET_INSTANCE_ERROR")?;

    let mut query = InstanceQuery::default();
    if let Some(from_addr) = params.from_addr {
        // Validate from_addr format (if provided)
        let from_addr = if params.is_bridge_in {
            InputValidator::validate_btc_address(&from_addr, None, "bridge in from_addr")?;
            from_addr
        } else {
            InputValidator::validate_goat_address(&from_addr, "Bridge out from_addr")?.to_string()
        };
        query = query.with_from_addr(from_addr);
    }
    query = query
        .with_pagination(offset, limit)
        .with_order("created_at DESC".to_string())
        .with_is_bridge_in(params.is_bridge_in);

    let (instances, total) =
        storage_process.find_instances(query).await.api_error("GET_INSTANCE_ERROR")?;

    if instances.is_empty() {
        warn!("get_instances instance is empty: total {}", total);
        return ok_response(InstanceListResponse::default());
    }
    let btc_current_height =
        app_state.btc_client.get_height().await.api_error("GET_INSTANCE_ERROR")?;
    let response_window_blocks = app_state
        .goat_client
        .gateway_get_response_window_blocks()
        .await
        .api_error("GET_INSTANCE_ERROR")?;
    let mut items = vec![];
    for instance in instances {
        let item = InstanceExtended::convert_from_instance(
            &app_state.btc_client,
            btc_current_height,
            response_window_blocks as i64,
            instance,
        )
        .await
        .api_error("GET_INSTANCE_ERROR")?;
        items.push(item);
    }

    ok_response(InstanceListResponse { instance_wraps: items, total })
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
///       "user_xonly_pubkey": [2, 171, 193, 35, ...],
///       "user_change_addr": "tb1q...",
///       "user_refund_addr": "tb1q...",
///       "btc_txid": "f6d6523a4344806aca5c66f23554bc574cb93634572f5e115cc630b3d8db3c6e",
///       "btc_height": 2500000,
///       "pegin_confirm_txid": "a1b2c3d4...",
///       "pegin_cancel_txid": null,
///       "committees_answers": {},
///       "pegin_data_tx_hash": "0x...",
///       "parameters": null,
///       "escrow_hash": null,
///       "bridge_out_lock_time": 0,
///       "status_updated_at": 1699123456,
///       "created_at": 1699123456,
///       "updated_at": 1699123456
///     },
///     "utxo": [
///       {
///         "txid": [171, 193, 35, ...],
///         "vout": 0,
///         "amount_sats": 100000000
///       }
///     ],
///     "confirmations": 0,
///     "target_confirmations": 6,
///     "waiting_time_in_secs": 60,
///     "current_status_waiting_time_in_secs": 30,
///     "status_extra": {
///       "user_action": "None",
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
    // Validate instance_id format
    let instance_id_uuid = InputValidator::validate_uuid(&instance_id, "instance_id")?;

    let mut storage_process = app_state.local_db.acquire().await.api_error("GET_INSTANCE_ERROR")?;

    if let Some(instance) =
        storage_process.find_instance(&instance_id_uuid).await.api_error("GET_INSTANCE_ERROR")?
    {
        let btc_current_height =
            app_state.btc_client.get_height().await.api_error("GET_INSTANCE_ERROR")?;
        let response_window_blocks = app_state
            .goat_client
            .gateway_get_response_window_blocks()
            .await
            .api_error("GET_INSTANCE_ERROR")?;

        let instance_wrap = Some(
            InstanceExtended::convert_from_instance(
                &app_state.btc_client,
                btc_current_height,
                response_window_blocks as i64,
                instance,
            )
            .await
            .api_error("GET_INSTANCE_ERROR")?,
        );

        ok_response(InstanceGetResponse { instance_wrap })
    } else {
        tracing::info!("instance_id {} has no record in database", instance_id);
        ok_response(InstanceGetResponse { instance_wrap: None })
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
    // todo update bridge out calc
    let mut storage_process =
        app_state.local_db.acquire().await.api_error("INSTANCE_OVERVIEW_ERROR")?;

    let (bridge_in_sum, bridge_in_count) = storage_process
        .get_sum_bridge_txn(true, &[InstanceBridgeInStatus::RelayerL2Minted.to_string()])
        .await
        .api_error("INSTANCE_OVERVIEW_ERROR")?;

    let (bridge_out_sum, bridge_out_count) = storage_process
        .get_sum_bridge_txn(false, &[InstanceBridgeOutStatus::Claim.to_string()])
        .await
        .api_error("INSTANCE_OVERVIEW_ERROR")?;

    let (pegout_sum, pegout_count) = storage_process
        .get_sum_peg_out(&[
            GraphStatus::OperatorTake1.to_string(),
            GraphStatus::OperatorTake2.to_string(),
            GraphStatus::Disprove.to_string(),
        ])
        .await
        .api_error("INSTANCE_OVERVIEW_ERROR")?;

    let (total, alive) = storage_process
        .get_nodes_info(ALIVE_TIME_JUDGE_THRESHOLD)
        .await
        .api_error("INSTANCE_OVERVIEW_ERROR")?;

    ok_response(InstanceOverviewResponse {
        instances_overview: InstanceOverview {
            total_bridge_in_amount: bridge_in_sum,
            total_bridge_in_txn: bridge_in_count,
            total_bridge_out_amount: bridge_out_sum,
            total_bridge_out_txn: bridge_out_count,
            total_peg_out_amount: pegout_sum,
            total_peg_out_txn: pegout_count,
            online_nodes: alive,
            total_nodes: total,
        },
    })
}

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
///       "status_updated_at": 1699123456,
///       "created_at": 1699123456,
///       "updated_at": 1699123456
///     },
///     "challenge_sub_status": "Assert",
///     "waiting_time_in_secs": 1000,
///     "proof_status": "Pending"
/// }
/// ```
#[axum::debug_handler]
pub async fn get_graph(
    Path(graph_id): Path<String>,
    State(app_state): State<Arc<AppState>>,
) -> ApiResult<GraphGetResponse> {
    // Validate graph_id format
    let graph_id_uuid = InputValidator::validate_uuid(&graph_id, "graph_id")?;

    let mut storage_process = app_state.local_db.acquire().await.api_error("GET_GRAPH_ERROR")?;

    if let Some(graph) =
        storage_process.find_graph(&graph_id_uuid).await.api_error("GET_GRAPH_ERROR")?
    {
        let graph_extended = GraphExtended::convert_from_graph(&app_state.btc_client, graph)
            .await
            .api_error("GET_GRAPH_ERROR")?;

        ok_response(graph_extended)
    } else {
        tracing::warn!("graph:{} is not record in db", graph_id);
        ok_response(GraphExtended::default())
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
///         "status_updated_at": 1699123456,
///         "created_at": 1699123456,
///         "updated_at": 1699123456
///       },
///       "challenge_sub_status": "Assert",
///       "waiting_time_in_secs": 1000,
///       "proof_status": "Pending"
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
    let mut resp = GraphListResponse::default();
    let mut storage_process = app_state.local_db.acquire().await.api_error("GET_GRAPHS_ERROR")?;

    let filter_params: GraphQuery = params.into();
    let (graphs, total) =
        storage_process.find_graphs(filter_params).await.api_error("GET_GRAPHS_ERROR")?;

    resp.total = total;
    if graphs.is_empty() {
        return ok_response(resp);
    }

    let mut converted_graphs = Vec::new();
    for graph in graphs {
        let graph_extended = GraphExtended::convert_from_graph(&app_state.btc_client, graph)
            .await
            .api_error("GET_GRAPHS_ERROR")?;
        converted_graphs.push(graph_extended);
    }
    resp.graphs = converted_graphs;

    ok_response(resp)
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
///     "status_updated_at": 1699123456,
///     "created_at": 1699123456,
///     "updated_at": 1699123456
///   },
///   "no_ready_reason": null
/// }
/// ```
#[axum::debug_handler]
pub async fn get_ready_to_kickoff_graph(
    Query(params): Query<GraphReadyToKickoffRequest>,
    State(app_state): State<Arc<AppState>>,
) -> ApiResult<GraphReadyToKickoffResponse> {
    let mut graph_query = GraphQuery::default()
        .with_status(GraphStatus::OperatorDataPushed.to_string())
        .with_order("kickoff_index ASC".to_string())
        .with_raw_condition("init_withdraw_tx_hash IS NULL".to_string())
        .with_limit(1);
    if params.btc_pub_key.is_none() && params.goat_addr.is_none() {
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "GET READT_KICKOFF_GRAPHS_ERROR".to_string(),
                message: "Wrong input: btc_pub_key and goat_addr should not all been none "
                    .to_string(),
            }),
        ));
    } else {
        if let Some(ref goat_addr) = params.goat_addr {
            graph_query = graph_query
                .with_from_addr(InputValidator::validate_goat_address(goat_addr, "goat_addr")?);
        }
        if let Some(ref btc_pub_key) = params.btc_pub_key {
            graph_query = graph_query.with_operator_pubkey(InputValidator::validate_btc_pubkey(
                btc_pub_key,
                "btc_pub_key",
            )?);
        }
    }

    let mut storage_processor =
        app_state.local_db.acquire().await.api_error("GET_READY_KICKOFF_GRAPHS_ERROR")?;

    let graphs = storage_processor
        .get_operator_graphs(graph_query)
        .await
        .api_error("GET_READY_KICKOFF_GRAPHS_ERROR")?;

    if graphs.is_empty() {
        return ok_response(GraphReadyToKickoffResponse { graph: None, no_ready_reason: None });
    }

    let graph = graphs[0].clone();
    if graph.kickoff_index > 0 {
        let pre_graphs = storage_processor
            .get_operator_graphs(
                GraphQuery::default()
                    .with_operator_pubkey(graph.operator_pubkey.clone())
                    .with_kickoff_index(graph.kickoff_index - 1),
            )
            .await
            .api_error("GET_READY_KICKOFF_GRAPHS_ERROR")?;

        if !pre_graphs.is_empty()
            && [
                GraphStatus::OperatorDataPushed.to_string(),
                GraphStatus::OperatorKickOff.to_string(),
                GraphStatus::Challenge.to_string(),
            ]
            .contains(&pre_graphs[0].status)
        {
            return ok_response(GraphReadyToKickoffResponse {
                graph: None,
                no_ready_reason: Some(pre_graphs[0].graph_id.to_string()),
            });
        }
    }

    ok_response(GraphReadyToKickoffResponse { graph: Some(graph), no_ready_reason: None })
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
    let mut fail_reason: Option<String> = None;

    match btc_tx_name {
        GraphBtcTxName::WatchtowerChallengeInit => {
            if let Some(tx) = graph.watchtower_challenge_init_txid.clone()
                && let Some(vout_monitor) =
                    storage_processor.find_graph_btc_tx_vout_monitor(&graph.graph_id, &tx).await?
                && let Ok(monitor_data) =
                    serde_json::from_str::<WTInitTxVoutMonitorData>(&vout_monitor.monitor_data)
                && let Ok(challenge_status) =
                    serde_json::from_str::<ChallengeSubStatus>(&graph.sub_status)
            {
                progress_datas.push(ProgressData {
                    name: WATCHTOWER_CHALLENGE_STEP_INIT.to_string(),
                    current: 1,
                    total: 1,
                });
                let (challenge_current, challenge_total) =
                    monitor_data.get_challenge_process_desc();
                progress_datas.push(ProgressData {
                    name: WATCHTOWER_CHALLENGE_STEP_CHALLENGE.to_string(),
                    current: challenge_current,
                    total: challenge_total,
                });

                let (challenge_timeout_current, challenge_timeout_total) =
                    monitor_data.get_challenge_timeout_process_desc();
                progress_datas.push(ProgressData {
                    name: WATCHTOWER_CHALLENGE_STEP_CHALLENGE_TIMEOUT.to_string(),
                    current: challenge_timeout_current,
                    total: challenge_timeout_total,
                });

                let (ack_current, ack_total) = monitor_data.get_ack_process_desc();
                if ack_total > 0 {
                    progress_datas.push(ProgressData {
                        name: WATCHTOWER_CHALLENGE_STEP_ACK.to_string(),
                        current: ack_current,
                        total: ack_total,
                    });
                }

                let (block_hash_current, block_hash_total) =
                    monitor_data.get_commit_block_hash_desc();
                progress_datas.push(ProgressData {
                    name: WATCHTOWER_CHALLENGE_STEP_COMMIT_BLOCKHASH.to_string(),
                    current: block_hash_current,
                    total: block_hash_total,
                });

                let (current, total) = monitor_data.get_commit_block_hash_timeout_desc();
                progress_datas.push(ProgressData {
                    name: WATCHTOWER_CHALLENGE_STEP_COMMIT_BLOCKHASH_TIMEOUT.to_string(),
                    current,
                    total,
                });

                if let Some(disprove_type) = challenge_status.disprove_type {
                    match disprove_type {
                        DisproveTxType::OperatorCommitTimeout => {
                            fail_reason = Some("Operator commit block hash timeout".to_string());
                        }
                        DisproveTxType::OperatorNack => {
                            let (challenge_timeout_num, nack_num) = (
                                challenge_timeout_total - challenge_timeout_current,
                                ack_total - ack_current,
                            );

                            fail_reason = match (challenge_timeout_num > 0, nack_num > 0) {
                                (true, true) => Some(format!(
                                    "Operator has {challenge_timeout_num} challenge timeout txn no sent, {nack_num} ack txn no sent"
                                )),
                                (false, true) => {
                                    Some(format!("Operator has {nack_num} ack txn no sent"))
                                }
                                (true, false) => Some(format!(
                                    "Operator has {challenge_timeout_num} challenge timeout txn no sent"
                                )),
                                (false, false) => None,
                            };
                        }
                        _ => {}
                    }
                }
            } else {
                progress_datas.push(ProgressData {
                    name: WATCHTOWER_CHALLENGE_STEP_INIT.to_string(),
                    current: 0,
                    total: 1,
                });
            }
        }
        GraphBtcTxName::AssertInit => {
            if let Some(tx) = graph.assert_init_txid.clone()
                && let Some(vout_monitor) =
                    storage_processor.find_graph_btc_tx_vout_monitor(&graph.graph_id, &tx).await?
                && let Ok(monitor_data) =
                    serde_json::from_str::<AssertInitTxVoutMonitorData>(&vout_monitor.monitor_data)
                && let Ok(challenge_status) =
                    serde_json::from_str::<ChallengeSubStatus>(&graph.sub_status)
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

                if let Some(DisproveTxType::AssertTimeout) = challenge_status.disprove_type {
                    fail_reason = Some(format!("Operator has {} assert no sent", total - current));
                }
            } else {
                progress_datas.push(ProgressData {
                    name: ASSERT_STEP_INIT.to_string(),
                    current: 0,
                    total: 1,
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

    let mut storage_process = app_state.local_db.acquire().await.api_error("GET_GRAPH_TX_ERROR")?;

    let graph_raw_data = storage_process
        .find_graph_raw_data(&graph_id_uuid)
        .await
        .api_error("GET_GRAPH_TX_ERROR")?;
    let graph = storage_process.find_graph(&graph_id_uuid).await.api_error("GET_GRAPH_TX_ERROR")?;

    if let (Some(graph_raw_data), Some(graph)) = (graph_raw_data, graph) {
        let (progresses, fail_reason) =
            get_graph_btc_tx_process_data(&mut storage_process, tx_name.clone(), &graph)
                .await
                .api_error("GET_GRAPH_TX_ERROR")?;

        let simplified_bitvm2_graph: SimplifiedBitvm2Graph =
            parse_graph_raw_data(graph_raw_data.raw_data.clone(), graph_id_uuid)
                .await
                .api_error("GET_GRAPH_TXN_ERROR")?;

        let bitvm2_graph: Bitvm2Graph = Bitvm2Graph::from_simplified(&simplified_bitvm2_graph)
            .api_error("GET_GRAPH_TX_ERROR")?;

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

        ok_response(GraphTxGetResponse {
            btc_tx_data: BtcTxData { raw_data, progresses, fail_reason },
        })
    } else {
        tracing::warn!("graph:{} is not record in db", graph_id);
        Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "GET_GRAPH_TX_ERROR".to_string(),
                message: format!("graph:{graph_id} is not record in db"),
            }),
        ))
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
    Query(params): Query<GraphTxnGetParams>,
    State(app_state): State<Arc<AppState>>,
) -> ApiResult<GraphTxnGetResponse> {
    // Validate graph_id format
    let graph_id_uuid = InputValidator::validate_uuid(&graph_id, "graph_id")?;
    let mut storage_processor =
        app_state.local_db.acquire().await.api_error("GET_GRAPH_TXN_ERROR")?;
    if let Some(graph) =
        storage_processor.find_graph(&graph_id_uuid).await.api_error("GET_GRAPH_TXN_ERROR")?
    {
        let kickoff_index = graph.kickoff_index + params.cursor as i64;
        let graph = if kickoff_index != graph.kickoff_index {
            let graph_arrays = storage_processor
                .get_operator_graphs(
                    GraphQuery::default()
                        .with_operator_pubkey(graph.operator_pubkey)
                        .with_kickoff_index(kickoff_index)
                        .with_limit(1),
                )
                .await
                .api_error("GET_OPERATOR_GRAPHS")?;
            if graph_arrays.is_empty() {
                return Err((
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ErrorResponse {
                        error: "GET_GRAPH_TXN_ERROR".to_string(),
                        message: format!(
                            "graph:{graph_id} with cursor:{} is not record in db",
                            params.cursor
                        ),
                    }),
                ));
            }
            graph_arrays[0].clone()
        } else {
            graph
        };

        let graph_raw_data = storage_processor
            .find_graph_raw_data(&graph.graph_id)
            .await
            .api_error("GET_GRAPH_TXN_ERROR")?
            .ok_or_else(|| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ErrorResponse {
                        error: "GET_GRAPH_TXN_ERROR".to_string(),
                        message: format!(
                            "graph:{graph_id} with cursor:{} raw data is not record in db",
                            params.cursor
                        ),
                    }),
                )
            })?;
        let simplified_bitvm2_graph: SimplifiedBitvm2Graph =
            parse_graph_raw_data(graph_raw_data.raw_data.clone(), graph_id_uuid)
                .await
                .api_error("GET_GRAPH_TXN_ERROR")?;
        let bitvm2_graph: Bitvm2Graph = Bitvm2Graph::from_simplified(&simplified_bitvm2_graph)
            .api_error("GET_GRAPH_TXN_ERROR")?;

        let (wt_progresses, wt_fail_reason) = get_graph_btc_tx_process_data(
            &mut storage_processor,
            GraphBtcTxName::WatchtowerChallengeInit,
            &graph,
        )
        .await
        .api_error("GET_GRAPH_TXN_ERROR")?;

        let (assert_progresses, assert_fail_reason) = get_graph_btc_tx_process_data(
            &mut storage_processor,
            GraphBtcTxName::AssertInit,
            &graph,
        )
        .await
        .api_error("GET_GRAPH_TXN_ERROR")?;

        let mut resp = GraphTxnGetResponse {
            assert_init: BtcTxData::new(serialize_hex(bitvm2_graph.assert_init.tx()))
                .with_progresses(assert_progresses)
                .with_fail_reason(assert_fail_reason),
            watchtower_challenge_init: BtcTxData::new(serialize_hex(
                bitvm2_graph.watchtower_challenge_init.tx(),
            ))
            .with_progresses(wt_progresses)
            .with_fail_reason(wt_fail_reason),
            pre_kickoff: BtcTxData::new(serialize_hex(bitvm2_graph.cur_prekickoff.tx())),
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

        ok_response(resp)
    } else {
        warn!("graph:{} is not record in db", graph_id);
        Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "GET_GRAPH_TXN_ERROR".to_string(),
                message: format!(
                    "graph:{graph_id} with cursor:{} is not record in db",
                    params.cursor
                ),
            }),
        ))
    }
}

/// Get neighboring graph IDs
///
/// Returns the previous and next graphs (by kickoff index) for the same operator,
/// which allows the UI to implement previous/next navigation when browsing graph details.
///
/// # Path Parameters
///
/// - `graph_id`: UUID of the current BitVM2 graph
///
/// # Returns
///
/// - `200 OK`: Successfully returns the current graph ID plus its previous and next neighbors
/// - `500 Internal Server Error`: Parameter validation failed or database query failed
///
/// # Use Case
///
/// Frontend can call this endpoint when showing a graph detail page to quickly fetch
/// the `previous_id` and `next_id` for navigation controls.
///
/// # Example
///
/// ```http
/// GET /v1/graphs/123e4567-e89b-12d3-a456-426614174000/neighbor-ids
/// ```
///
/// Response example:
/// ```json
/// {
///   "current_id": "123e4567-e89b-12d3-a456-426614174000",
///   "previous_id": "123e4567-e89b-12d3-a456-426614173999",
///   "next_id": "123e4567-e89b-12d3-a456-426614174001"
/// }
/// ```
#[axum::debug_handler]
pub async fn get_graph_neighbor_ids(
    Path(graph_id): Path<String>,
    State(app_state): State<Arc<AppState>>,
) -> ApiResult<GraphNeighborIdsResponse> {
    let current_id = InputValidator::validate_uuid(&graph_id, "graph_id")?;
    let mut storage_processor =
        app_state.local_db.acquire().await.api_error("GET_GRAPH_NEIGHBOR_ERROR")?;
    let id_with_kickoff_indexes = storage_processor
        .find_graph_neighbor_ids(current_id, 1)
        .await
        .api_error("GET_GRAPH_NEIGHBOR_ERROR")?;
    let mut res = GraphNeighborIdsResponse { current_id, previous_id: None, next_id: None };
    for (i, (_kickoff_index, graph_id)) in id_with_kickoff_indexes.iter().enumerate() {
        if i == 0 && *graph_id != current_id {
            res.previous_id = Some(*graph_id);
        }
        if i > 0 && *graph_id != current_id {
            res.next_id = Some(*graph_id);
        }
    }
    ok_response(res)
}

/// Get unsigned pegin transactions
///
/// Returns the unsigned pegin deposit transaction (prepare) and pegin refund transaction (cancel)
/// for a given instance, which allows users to sign and broadcast these transactions for pegin operations.
///
/// # Path Parameters
///
/// - `instance_id`: UUID of the BitVM2 instance
///
/// # Returns
///
/// - `200 OK`: Successfully returns the unsigned pegin transactions (if instance exists)
/// - `500 Internal Server Error`: Parameter validation failed or database query failed
///
/// # Use Case
///
/// Frontend can call this endpoint to get the unsigned pegin transactions for an instance,
/// allowing users to sign and broadcast the `pegin_prepare` transaction to deposit funds,
/// or the `pegin_cancel` transaction to refund if needed.
///
/// # Example
///
/// ```http
/// GET /v1/instances/123e4567-e89b-12d3-a456-426614174000/unsigned-pegin-txn
/// ```
///
/// Response example:
/// ```json
/// {
///   "pegin_prepare": "0200000001...",
///   "pegin_cancel_psbt": "0200000001..."
/// }
/// ```
#[axum::debug_handler]
pub async fn get_unsigned_pegin_txn(
    Path(instance_id): Path<String>,
    State(app_state): State<Arc<AppState>>,
) -> ApiResult<UnsignPeginTxnResponse> {
    let current_id = InputValidator::validate_uuid(&instance_id, "instance_id")?;
    let mut storage_processor =
        app_state.local_db.acquire().await.api_error("GET_UNSIGNED_PEGIN_ERROR")?;
    let mut res = UnsignPeginTxnResponse::default();
    if let Some(instance) =
        storage_processor.find_instance(&current_id).await.api_error("GET_UNSIGNED_PEGIN_ERROR")?
        && [
            InstanceBridgeInStatus::CommitteesAnswered.to_string(),
            InstanceBridgeInStatus::UserBroadcastPeginPrepare.to_string(),
            InstanceBridgeInStatus::Presigned.to_string(),
            InstanceBridgeInStatus::PresignedFailed.to_string(),
            InstanceBridgeInStatus::Timeout.to_string(),
        ]
        .contains(&instance.status)
    {
        let instance_parameters =
            gen_instance_parameters_local(&instance).api_error("GET_UNSIGNED_PEGIN_ERROR")?;
        let (pegin_deposit_tx, _, _) =
            instance_parameters.build_pegin_tx().api_error("GET_UNSIGNED_PEGIN_ERROR")?;
        res.pegin_prepare = Some(serialize_hex(pegin_deposit_tx.tx()));
        res.pegin_cancel_psbt = Some(hex::encode(
            instance_parameters
                .build_pegin_cancel_psbt()
                .api_error("GET_UNSIGNED_PEGIN_ERROR")?
                .serialize(),
        ));
    } else {
        warn!(
            "instance:{instance_id} is not record in db or instance status neq CommitteesAnswered"
        );
    }
    ok_response(res)
}

// fn is_segwit_address(address: &str, network: &str) -> anyhow::Result<bool> {
//     let addr: Address<NetworkUnchecked> = Address::from_str(address)?;
//     let addr = addr.require_network(Network::from_str(network)?)?;
//     Ok(matches!(
//         addr.address_type(),
//         Some(AddressType::P2wpkh) | Some(AddressType::P2wsh) | Some(AddressType::P2tr)
//     ))
// }
