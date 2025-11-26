use crate::env;
use crate::rpc_service::proof::{
    BtcBlockDesc, BtcBlockDescListResponse, BtcBlockDescQueryParams, ProofDesc, ProofResponse,
    ProofType, ProofsQueryParams,
};
use crate::rpc_service::response::{ApiErrorExt, ApiResult};
use crate::rpc_service::{AppState, current_time_secs};
use axum::Json;
use axum::extract::{Query, State};
use client::btc_chain::mempool_v1_type::{V1Blocks, get_v1_blocks_url};
use http::{StatusCode, Uri};
use std::sync::Arc;

/// Get Bitcoin blocks description list
///
/// Returns a list of Bitcoin block descriptions with fee information and statistics. Supports
/// pagination and querying from a specific starting height in descending order.
///
/// # Query Parameters
///
/// - `start_height`: Starting block height (optional) - query blocks from this height in descending order
/// - `offset`: Pagination offset (optional) - number of items to skip
/// - `limit`: Items per page (default: 6) - maximum number of items to return
///
/// # Returns
///
/// - `200 OK`: Successfully returns blocks description list
/// - `500 Internal Server Error`: Server internal error or database operation failed
/// - Response includes block statistics such as median fee, fee range, total fees, and transaction count
///
/// # Use Case
///
/// Frontend applications use this to display Bitcoin block statistics, including fee market data
/// for users to understand network congestion and optimal transaction fee rates.
///
/// # Example
///
/// ```http
/// GET /v1/proofs/blocks?start_height=800000&offset=0&limit=6
/// ```
///
/// Response example:
/// ```json
/// {
///   "blocks_desc": [
///     {
///       "height": 800000,
///       "median_fee": 15.5,
///       "fee_range": [5.0, 10.0, 15.0, 20.0, 30.0],
///       "total_fees": 0.5,
///       "size":1.97,
///       "tx_count": 2500,
///       "timestamp": 1640995200
///     }
///   ],
///   "start": 800000,
///   "range": 6
/// }
/// ```
#[axum::debug_handler]
pub async fn get_blocks_desc(
    _uri: Uri,
    Query(params): Query<BtcBlockDescQueryParams>,
    State(app_state): State<Arc<AppState>>,
) -> ApiResult<BtcBlockDescListResponse> {
    let v1_blocks_url = get_v1_blocks_url(env::get_network(), params.start_height);
    let v1_blocks: V1Blocks = app_state
        .http_client
        .get_response_json(&v1_blocks_url)
        .await
        .api_error("GET_BLOCKS_DESC")?;
    let take_count = params.range.min(v1_blocks.len() as u32) as usize;
    let blocks_desc: Vec<BtcBlockDesc> =
        v1_blocks.into_iter().take(take_count).map(BtcBlockDesc::from).collect();
    Ok((
        StatusCode::OK,
        Json(BtcBlockDescListResponse {
            start: blocks_desc[0].height,
            range: blocks_desc.len() as u64,
            blocks_desc,
        }),
    ))
}

/// Get proof by block height and type
///
/// Returns detailed proof information for a specific block height and proof type.
/// Supports both header chain proofs and commit chain proofs.
///
/// # Query Parameters
///
/// - `height`: Block number/height (required) - the block number for which to retrieve the proof
/// - `proof_type`: Type of proof (required) - either "header_chain" or "commit_chain"
///
/// # Returns
///
/// - `200 OK`: Successfully returns proof details (or None if not found)
/// - `500 Internal Server Error`: Server internal error or database operation failed
/// - Response includes proof metadata, proving metrics, and verification data
///
/// # Use Case
///
/// Applications use this to retrieve zero-knowledge proofs for specific Bitcoin blocks,
/// including proving time, cycles, proof size, and public inputs for verification purposes.
///
/// # Example
///
/// ```http
/// GET /v1/proofs/proof?height=800000&proof_type=header_chain
/// ```
///
/// Response example:
/// ```json
/// {
///   "proof": {
///     "block_number": 800000,
///     "proof_type": "header_chain",
///     "state": "proved",
///     "proving_cycles": 1000000,
///     "proving_time": 120,
///     "contain_blocks": "799990-800000",
///     "total_time_to_proof": 180,
///     "proof_size": 2048.5,
///     "zkm_version": "v1.0.0",
///     "pub_inputs": "0x1234...",
///     "started_at": 1640995200,
///     "updated_at": 1640995380
///   }
/// }
/// ```
#[axum::debug_handler]
pub async fn get_proof(
    _uri: Uri,
    Query(_params): Query<ProofsQueryParams>,
    State(_app_state): State<Arc<AppState>>,
) -> ApiResult<ProofResponse> {
    // todo update
    Ok((
        StatusCode::OK,
        Json(ProofResponse {
            proof: Some(ProofDesc {
                block_number: 800000,
                proof_type: ProofType::HeaderChain,
                state: "proved".to_string(),
                proving_cycles: 1000000,
                proving_time: 120,
                contain_blocks: "799990-800000".to_string(),
                total_time_to_proof: 180,
                proof_size: 2048.5,
                zkm_version: "1.0.0".to_string(),
                pub_inputs: "0x1234".to_string(),
                started_at: current_time_secs(),
                updated_at: current_time_secs(),
            }),
        }),
    ))
}
