use crate::env::IpfsTxName;
use crate::rpc_service::AppState;
use crate::rpc_service::bitvm2::*;
use crate::rpc_service::node::ALIVE_TIME_JUDGE_THRESHOLD;
use axum::Json;
use axum::extract::{Path, Query, State};
use bitcoin::Txid;
use bitcoin::consensus::encode::serialize_hex;
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
    GoatTxType, Graph, GraphStatus, InstanceStatus, SerializableTxid, modify_graph_status,
};
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
) -> (StatusCode, Json<InstanceSettingResponse>) {
    (
        StatusCode::OK,
        Json(InstanceSettingResponse { bridge_in_amount: vec![0.1, 0.05, 0.02, 0.01] }),
    )
}

/// Check graph presign status
///
/// Check the presign status of graphs based on instance ID, returns instance status and all related graph status information.
/// This endpoint provides a comprehensive view of the bridge instance and its associated graphs' current states.
///
/// # Parameters
///
/// - `instance_id`: Instance ID (UUID format)
///
/// # Returns
///
/// - `200 OK`: Successfully returns presign check result
/// - `500 Internal Server Error`: Server internal error or database operation failed
///
/// # Response Includes
///
/// - Instance status and transaction details
/// - Graph status mapping for all related graphs
/// - Complete instance information
///
/// # Example
///
/// ```http
/// GET /v1/graphs/presign_check?instance_id=123e4567-e89b-12d3-a456-426614174000
/// ```
///
/// Response example:
/// ```json
/// {
///   "instance_id": "123e4567-e89b-12d3-a456-426614174000",
///   "instance_status": "Submitted",
///   "graph_status": {
///     "graph-id-1": "OperatorPresigned",
///     "graph-id-2": "Created"
///   },
///   "tx": {
///     "instance_id": "123e4567-e89b-12d3-a456-426614174000",
///     "status": "Submitted",
///     "amount": 1000,
///     ...
///   }
/// }
/// ```
#[axum::debug_handler]
pub async fn graph_presign_check(
    Query(params): Query<GraphPresignCheckParams>,
    State(app_state): State<Arc<AppState>>,
) -> (StatusCode, Json<GraphPresignCheckResponse>) {
    let resp = GraphPresignCheckResponse {
        instance_id: params.instance_id.to_string(),
        instance_status: InstanceStatus::UserInited.to_string(),
        graph_status: HashMap::new(),
        tx: None,
    };
    let mut resp_clone = resp.clone();
    let async_fn = || async move {
        let instance_id = Uuid::parse_str(&params.instance_id)?;
        let mut storage_process = app_state.local_db.acquire().await?;
        if let Some(instance) = storage_process.find_instance(&instance_id).await? {
            resp_clone.instance_status = instance.status.clone();
            resp_clone.tx = Some(instance);
            let graphs = storage_process.get_graph_by_instance_id(&instance_id).await?;
            resp_clone.graph_status = graphs
                .into_iter()
                .map(|v| {
                    (
                        v.graph_id.to_string(),
                        modify_graph_status(&v.status, v.init_withdraw_tx_hash.is_some()),
                    )
                })
                .collect();
            Ok::<GraphPresignCheckResponse, Box<dyn std::error::Error>>(resp_clone)
        } else {
            tracing::info!("instance_id {} has no record in database", instance_id);
            Ok::<GraphPresignCheckResponse, Box<dyn std::error::Error>>(resp_clone)
        }
    };
    match async_fn().await {
        Ok(resp) => (StatusCode::OK, Json(resp)),
        Err(err) => {
            tracing::warn!("graph_presign_check  err:{:?}", err);
            (StatusCode::INTERNAL_SERVER_ERROR, Json(resp))
        }
    }
}

/// Get specific transaction hex data for a graph
///
/// Get corresponding Bitcoin transaction hex data based on graph ID and transaction name.
/// This endpoint retrieves the raw transaction hex for a specific transaction type within a graph.
///
/// # Parameters
///
/// - `graph_id`: Graph ID (UUID format)
/// - `tx_name`: Transaction name, supported values include:
///   - `pegin`: Bridge-in transaction
///   - `kickoff`: Kickoff transaction
///   - `assert-commit0` to `assert-commit3`: Assert commit transactions
///   - `assert-init`: Assert init transaction
///   - `assert-final`: Assert final transaction
///   - `challenge`: Challenge transaction
///   - `take1`, `take2`: Withdrawal transactions
///   - `disprove`: Disprove transaction
///
/// # Returns
///
/// - `200 OK`: Successfully returns transaction hex data
/// - `500 Internal Server Error`: Server internal error or graph not found
///
/// # Use Case
///
/// Used by clients to broadcast transactions or verify transaction details.
///
/// # Example
///
/// ```http
/// GET /v1/graphs/123e4567-e89b-12d3-a456-426614174000/tx?tx_name=pegin
/// ```
///
/// Response example:
/// ```json
/// {
///   "tx_hex": "0200000001..."
/// }
/// ```
#[axum::debug_handler]
pub async fn get_graph_tx(
    Query(params): Query<GraphTxGetParams>,
    Path(graph_id): Path<String>,
    State(app_state): State<Arc<AppState>>,
) -> (StatusCode, Json<Option<GraphTxGetResponse>>) {
    let async_fn = || async move {
        let mut storage_process = app_state.local_db.acquire().await?;
        if let Some(graph_raw_data) =
            storage_process.get_graph_raw_data(&Uuid::parse_str(&graph_id)?).await?
            && let Some(graph) = storage_process.get_graph(&Uuid::parse_str(&graph_id)?).await?
        {
            let bitvm2_graph: Bitvm2Graph = serde_json::from_str(graph_raw_data.raw_data.as_str())?;
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
                IpfsTxName::Challenge => {
                    let mut ori_tx_hex = serialize_hex(bitvm2_graph.challenge.tx());
                    if let Some(challenge_txid) = graph.challenge_txid
                        && let Ok(tx_hex) =
                            app_state.btc_client.get_tx_hex_by_tx_id(&challenge_txid.0).await
                    {
                        ori_tx_hex = tx_hex
                    }
                    ori_tx_hex
                }
                IpfsTxName::Disprove => serialize_hex(bitvm2_graph.disprove.tx()),
                IpfsTxName::Kickoff => serialize_hex(bitvm2_graph.kickoff.tx()),
                IpfsTxName::Pegin => serialize_hex(bitvm2_graph.pegin.tx()),
                IpfsTxName::Take1 => serialize_hex(bitvm2_graph.take1.tx()),
                IpfsTxName::Take2 => serialize_hex(bitvm2_graph.take2.tx()),
            };
            Ok::<GraphTxGetResponse, Box<dyn std::error::Error>>(GraphTxGetResponse { tx_hex })
        } else {
            tracing::warn!("graph:{} is not record in db", graph_id);
            Err(format!("graph:{graph_id} is not record in db").into())
        }
    };
    match async_fn().await {
        Ok(resp) => (StatusCode::OK, Json(Some(resp))),
        Err(err) => {
            tracing::warn!("get_graph_tx  err:{:?}", err);
            (StatusCode::INTERNAL_SERVER_ERROR, Json(None))
        }
    }
}

/// Get all transaction hex data for a graph
///
/// Get hex data for all transactions in a graph based on graph ID, including all assert, challenge, withdrawal, etc. transactions.
/// This endpoint provides a complete view of all transaction types within a graph in a single request.
///
/// # Parameters
///
/// - `graph_id`: Graph ID (UUID format)
///
/// # Returns
///
/// - `200 OK`: Successfully returns all transaction data
/// - `500 Internal Server Error`: Server internal error or graph not found
///
/// # Transaction Types
///
/// Returns hex data for all supported transaction types including assert commits, init/final, challenge, withdrawal, etc.
///
/// # Use Case
///
/// Used by clients to get all transaction data at once for graph analysis or bulk operations.
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
///   "assert_commit0": "0200000001...",
///   "assert_commit1": "0200000001...",
///   "assert_commit2": "0200000001...",
///   "assert_commit3": "0200000001...",
///   "assert_init": "0200000001...",
///   "assert_final": "0200000001...",
///   "challenge": "0200000001...",
///   "disprove": "0200000001...",
///   "kickoff": "0200000001...",
///   "pegin": "0200000001...",
///   "take1": "0200000001...",
///   "take2": "0200000001..."
/// }
/// ```
#[axum::debug_handler]
pub async fn get_graph_txn(
    Path(graph_id): Path<String>,
    State(app_state): State<Arc<AppState>>,
) -> (StatusCode, Json<Option<GraphTxnGetResponse>>) {
    let async_fn = || async move {
        let mut storage_process = app_state.local_db.acquire().await?;
        if let Some(graph_raw_data) =
            storage_process.get_graph_raw_data(&Uuid::parse_str(&graph_id)?).await?
            && let Some(graph) = storage_process.get_graph(&Uuid::parse_str(&graph_id)?).await?
        {
            let bitvm2_graph: Bitvm2Graph = serde_json::from_str(graph_raw_data.raw_data.as_str())?;
            let mut resp = GraphTxnGetResponse {
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
            if let Some(challenge_txid) = graph.challenge_txid
                && let Ok(tx_hex) =
                    app_state.btc_client.get_tx_hex_by_tx_id(&challenge_txid.0).await
            {
                resp.challenge = tx_hex;
            }
            Ok::<GraphTxnGetResponse, Box<dyn std::error::Error>>(resp)
        } else {
            tracing::warn!("graph:{} is not record in db", graph_id);
            Err(format!("graph:{graph_id} is not record in db").into())
        }
    };
    match async_fn().await {
        Ok(resp) => (StatusCode::OK, Json(Some(resp))),
        Err(err) => {
            tracing::warn!("get_graph_txn  err:{:?}", err);
            (StatusCode::INTERNAL_SERVER_ERROR, Json(None))
        }
    }
}

/// Create new bridge instance
///
/// Create a new bridge instance for managing asset transfers from Bitcoin to GOAT network.
/// This endpoint initializes a new pegin (bridge-in) process.
/// The function uses INSERT OR REPLACE, so it can also update existing instances.
///
/// # Request Body
///
/// Contains complete instance information wrapped in an InstanceUpdateRequest.
/// Required fields include instance_id, network, from_addr, to_addr, amount, and status.
///
/// # Returns
///
/// - `200 OK`: Successfully created/updated instance
/// - `500 Internal Server Error`: Server internal error or database operation failed
///
/// # Example
///
/// ```http
/// POST /v1/instances
/// Content-Type: application/json
///
/// {
///   "instance": {
///     "instance_id": "123e4567-e89b-12d3-a456-426614174000",
///     "network": "testnet",
///     "from_addr": "tb1q...",
///     "to_addr": "0x...",
///     "amount": 20000,
///     "fees": [1000, 0, 0],
///     "input_utxos": "[{\"txid\":\"...\",\"vout\":0,\"amount\":20000}]",
///     "status": "UserInited",
///     "pegin_request_tx_hash": "0x...",
///     "pegin_request_height": 123456,
///     "user_xonly_pubkey": [241,77,222,197,156,70,127,106,169,155,155,10,242,194,183,203,19,29,8,122,11,205,201,232,191,12,70,128,82,184,61,74],
///     "user_change_addr": "tb1q...",
///     "user_refund_addr": "tb1q...",
///     "pegin_prepare_txid": null,
///     "pegin_confirm_txid": null,
///     "pegin_cancel_txid": null,
///     "unsign_pegin_confirm_tx": null,
///     "committees_answers": {},
///     "pegin_data_tx_hash": "",
///     "pegin_prepare_height": 0,
///     "created_at": 1640995200,
///     "updated_at": 1640995200
///   }
/// }
/// ```
///
/// Response example:
/// ```json
/// {}
/// ```
#[axum::debug_handler]
pub async fn create_instance(
    State(app_state): State<Arc<AppState>>,
    Json(payload): Json<InstanceUpdateRequest>,
) -> (StatusCode, Json<InstanceUpdateResponse>) {
    let async_fn = || async move {
        let mut storage_process = app_state.local_db.acquire().await?;
        storage_process.upsert_instance(&payload.instance).await?;
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

/// Update existing bridge instance
///
/// Update information for a specified bridge instance, including status, transaction IDs, and other fields.
/// This endpoint is used to update the state of an existing pegin (bridge-in) process.
/// All fields in the request body will completely replace the existing instance data.
///
/// # Parameters
///
/// - `instance_id`: Instance ID (UUID format) - must match the instance_id in the request body
///
/// # Request Body
///
/// Contains complete instance information wrapped in an InstanceUpdateRequest.
/// All fields will be updated with the provided values. Missing fields will be set to null/empty.
///
/// # Returns
///
/// - `200 OK`: Successfully updated instance
/// - `400 Bad Request`: Instance ID in path doesn't match the one in request body
/// - `500 Internal Server Error`: Server internal error or database operation failed
///
/// # Example
///
/// ```http
/// PUT /v1/instances/123e4567-e89b-12d3-a456-426614174000
/// Content-Type: application/json
///
/// {
///   "instance": {
///     "instance_id": "123e4567-e89b-12d3-a456-426614174000",
///     "network": "testnet",
///     "from_addr": "tb1q...",
///     "to_addr": "0x...",
///     "amount": 20000,
///     "fees": [1000, 0, 0],
///     "input_utxos": "[{\"txid\":\"...\",\"vout\":0,\"amount\":20000}]",
///     "status": "Presigned",
///     "pegin_request_tx_hash": "0x...",
///     "pegin_request_height": 123456,
///     "user_xonly_pubkey": [241,77,222,197,156,70,127,106,169,155,155,10,242,194,183,203,19,29,8,122,11,205,201,232,191,12,70,128,82,184,61,74],
///     "user_change_addr": "tb1q...",
///     "user_refund_addr": "tb1q...",
///     "pegin_prepare_txid": "18f553006e17b0adc291a75f48e77687cdd58e0049bb4a976d69e5358ba3f59b",
///     "pegin_confirm_txid": null,
///     "pegin_cancel_txid": null,
///     "unsign_pegin_confirm_tx": null,
///     "committees_answers": {},
///     "pegin_data_tx_hash": "",
///     "pegin_prepare_height": 123456,
///     "created_at": 1640995200,
///     "updated_at": 1640995200
///   }
/// }
/// ```
///
/// Response example:
/// ```json
/// {}
/// ```
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
        storage_process.upsert_instance(&payload.instance).await?;
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

/// Get bridge instance list
///
/// Get bridge instance list based on query parameters, supports filtering by address and pagination.
/// Each instance includes confirmation status for the pegin confirm transaction.
///
/// # Query Parameters
///
/// - `from_addr`: Source address filter (optional) - filters instances by source Bitcoin address
/// - `offset`: Pagination offset (default: 0) - number of items to skip
/// - `limit`: Items per page (default: 10) - maximum number of items to return
///
/// # Returns
///
/// - `200 OK`: Successfully returns instance list with confirmation status
/// - Response includes total count and paginated instance data
///
/// # Example
///
/// ```http
/// GET /v1/instances?from_addr=tb1q...&offset=0&limit=10
/// ```
///
/// Response example:
/// ```json
/// {
///   "instance_wraps": [
///     {
///       "instance": {
///         "instance_id": "123e4567-e89b-12d3-a456-426614174000",
///         "status": "Presigned",
///         "amount": 20000,
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
pub async fn get_instances(
    Query(params): Query<InstanceListRequest>,
    State(app_state): State<Arc<AppState>>,
) -> (StatusCode, Json<InstanceListResponse>) {
    let async_fn = || async move {
        let mut storage_process = app_state.local_db.acquire().await?;
        let mut query = InstanceQuery::default();
        if let Some(from_addr) = params.from_addr {
            query = query.with_from_addr(from_addr);
        }
        if let (Some(offset), Some(limit)) = (params.offset, params.limit) {
            query = query.with_pagination(offset, limit);
        }

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

/// Get detailed information for a specific bridge instance
///
/// Get detailed information for a single bridge instance based on instance ID, including confirmation status.
/// Returns complete instance data with UTXO information and transaction confirmation details.
///
/// # Parameters
///
/// - `instance_id`: Instance ID (UUID format)
///
/// # Returns
///
/// - `200 OK`: Successfully returns instance details with confirmation status
/// - Returns empty instance wrap if instance not found
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
///       "status": "Presigned",
///       "amount": 20000,
///       ...
///     },
///     "confirmations": 3,
///     "target_confirmations": 6
///   }
/// }
/// ```
#[axum::debug_handler]
pub async fn get_instance(
    Path(instance_id): Path<String>,
    State(app_state): State<Arc<AppState>>,
) -> (StatusCode, Json<InstanceGetResponse>) {
    let async_fn = || async move {
        let instance_id = Uuid::parse_str(&instance_id)?;
        let mut storage_process = app_state.local_db.acquire().await?;
        if let Some(instance) = storage_process.find_instance(&instance_id).await? {
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
                instance_wrap: InstanceWrap {
                    utxo: Some(utxo),
                    instance: Some(instance),
                    confirmations,
                    target_confirmations,
                },
            })
        } else {
            tracing::info!("instance_id {} has no record in database", instance_id);
            Ok::<InstanceGetResponse, Box<dyn std::error::Error>>(InstanceGetResponse {
                instance_wrap: InstanceWrap::default(),
            })
        }
    };
    match async_fn().await {
        Ok(res) => (StatusCode::OK, Json(res)),
        Err(err) => {
            tracing::warn!("get_instances, err:{:?}", err);
            (StatusCode::OK, Json(InstanceGetResponse { instance_wrap: InstanceWrap::default() }))
        }
    }
}

/// Get bridge instance overview statistics
///
/// Returns overall statistics for the bridge system, including total amounts, transaction counts, online nodes, etc.
/// Provides a comprehensive overview of the bridge's operational status and performance metrics.
///
/// # Returns
///
/// - `200 OK`: Successfully returns overview information with bridge statistics
/// - `500 Internal Server Error`: Server internal error or database operation failed
///
/// # Statistics Included
///
/// - Bridge-in amounts and transaction counts
/// - Bridge-out amounts and transaction counts  
/// - Node status (online vs total)
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
///     "total_bridge_in_amount": 100000,
///     "total_bridge_in_txn": 50,
///     "total_bridge_out_amount": 80000,
///     "total_bridge_out_txn": 30,
///     "online_nodes": 5,
///     "total_nodes": 8
///   }
/// }
/// ```
#[axum::debug_handler]
pub async fn get_instances_overview(
    State(app_state): State<Arc<AppState>>,
) -> (StatusCode, Json<InstanceOverviewResponse>) {
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
                GraphStatus::Take1.to_string(),
                GraphStatus::Take2.to_string(),
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
                online_nodes: alive,
                total_nodes: total,
            },
        })
    };
    match async_fn().await {
        Ok(resp) => (StatusCode::OK, Json(resp)),
        Err(err) => {
            tracing::warn!("get_instances_overview  err:{:?}", err);
            (StatusCode::INTERNAL_SERVER_ERROR, Json(InstanceOverviewResponse::default()))
        }
    }
}

/// Get detailed information for a specific graph
///
/// Get detailed information for a single graph based on graph ID, excluding raw data.
/// Returns graph metadata with confirmation status and proof information.
///
/// # Parameters
///
/// - `graph_id`: Graph ID (UUID format)
///
/// # Returns
///
/// - `200 OK`: Successfully returns graph details with extended data
/// - Returns null graph if graph not found or conversion fails
///
/// # Note
///
/// Raw data is excluded from the response for performance reasons.
/// Use get_graph_tx or get_graph_txn for transaction hex data.
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
///     "graph_id": "123e4567-e89b-12d3-a456-426614174000",
///     "instance_id": "456e7890-e89b-12d3-a456-426614174000",
///     "status": "OperatorPresigned",
///     "amount": 1000,
///     ...
///   }
/// }
/// ```
#[axum::debug_handler]
pub async fn get_graph(
    Path(graph_id): Path<String>,
    State(app_state): State<Arc<AppState>>,
) -> (StatusCode, Json<GraphGetResponse>) {
    let async_fn = || async move {
        let graph_id = Uuid::parse_str(&graph_id).unwrap();
        let mut storage_process = app_state.local_db.acquire().await?;
        if let Some(graph) = storage_process.get_graph(&graph_id).await? {
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
        Ok(res) => (StatusCode::OK, Json(res)),
        Err(err) => {
            tracing::warn!("get_graph  err:{:?}", err);
            (StatusCode::OK, Json(GraphGetResponse { graph: None }))
        }
    }
}

/// Update information for a specific graph
///
/// Update information for a specified graph, including status, transaction IDs, and other fields.
/// The function uses INSERT OR REPLACE, so it can also create new graphs.
/// All fields in the request body will completely replace the existing graph data.
///
/// # Parameters
///
/// - `graph_id`: Graph ID (UUID format) - must match the graph_id in the request body
///
/// # Request Body
///
/// Contains complete graph information wrapped in a GraphUpdateRequest.
/// All fields will be updated with the provided values. Missing fields will be set to null/empty.
///
/// # Returns
///
/// - `200 OK`: Successfully updated/created graph
/// - `400 Bad Request`: Graph ID in path doesn't match the one in request body
/// - `500 Internal Server Error`: Server internal error or database operation failed
///
/// # Example
///
/// ```http
/// PUT /v1/graphs/123e4567-e89b-12d3-a456-426614174000
/// Content-Type: application/json
///
/// {
///   "graph": {
///     "graph_id": "123e4567-e89b-12d3-a456-426614174000",
///     "instance_id": "456e7890-e89b-12d3-a456-426614174000",
///     "graph_ipfs_base_url": "ipfs://...",
///     "pegin_txid": "18f553006e17b0adc291a75f48e77687cdd58e0049bb4a976d69e5358ba3f59b",
///     "amount": 1000,
///     "status": "OperatorPresigned",
///     "pre_kickoff_txid": null,
///     "kickoff_txid": null,
///     "challenge_txid": null,
///     "take1_txid": null,
///     "assert_init_txid": null,
///     "assert_commit_txids": null,
///     "assert_final_txid": null,
///     "take2_txid": null,
///     "disprove_txid": null,
///     "operator": "0x...",
///     "raw_data": null,
///     "bridge_out_start_at": 0,
///     "bridge_out_from_addr": "",
///     "bridge_out_to_addr": "",
///     "init_withdraw_txid": null,
///     "zkm_version": "v1.0.0",
///     "created_at": 1640995200,
///     "updated_at": 1640995200
///   }
/// }
/// ```
///
/// Response example:
/// ```json
/// {}
/// ```
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
        let _ = storage_process.upsert_graph(payload.graph).await?;
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
) -> (StatusCode, Json<GraphListResponse>) {
    let resp = GraphListResponse::default();
    let mut resp_clone = resp.clone();
    let async_fn = || async move {
        let mut storage_process = app_state.local_db.acquire().await?;
        let filter_params: GraphQuery = params.into();
        let (graphs, total) = storage_process.filter_graphs(filter_params).await?;
        resp_clone.total = total;
        if graphs.is_empty() {
            return Ok::<GraphListResponse, Box<dyn std::error::Error>>(resp_clone);
        }
        resp_clone.graphs =
            add_extend_data_to_graphs(&mut storage_process, &app_state.btc_client, graphs).await?;
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

// fn is_segwit_address(address: &str, network: &str) -> anyhow::Result<bool> {
//     let addr: Address<NetworkUnchecked> = Address::from_str(address)?;
//     let addr = addr.require_network(Network::from_str(network)?)?;
//     Ok(matches!(
//         addr.address_type(),
//         Some(AddressType::P2wpkh) | Some(AddressType::P2wsh) | Some(AddressType::P2tr)
//     ))
// }
