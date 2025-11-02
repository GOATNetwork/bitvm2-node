use crate::rpc_service::AppState;
use crate::rpc_service::proof::{
    BtcBlockDescListResponse, BtcBlockDescQueryParams, ProofResponse, ProofsQueryParams,
};
use crate::rpc_service::response::{ApiResult, ErrorResponse};
use axum::Json;
use axum::extract::{Query, State};
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
    Query(_params): Query<BtcBlockDescQueryParams>,
    State(_app_state): State<Arc<AppState>>,
) -> ApiResult<BtcBlockDescListResponse> {
    // todo update
    let async_fn = || async move {
        Ok::<BtcBlockDescListResponse, Box<dyn std::error::Error>>(BtcBlockDescListResponse {
            blocks_desc: vec![],
            start: 0,
            range: 0,
        })
    };
    match async_fn().await {
        Ok(res) => Ok((StatusCode::OK, Json(res))),
        Err(err) => {
            tracing::warn!("get blocks desc err:{:?}", err);
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "BLOCKS_DEC_ERROR".to_string(),
                    message: err.to_string(),
                }),
            ))
        }
    }
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
///     "state": "completed",
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
    let async_fn = || async move {
        Ok::<ProofResponse, Box<dyn std::error::Error>>(ProofResponse { proof: None })
    };
    match async_fn().await {
        Ok(res) => Ok((StatusCode::OK, Json(res))),
        Err(err) => {
            tracing::warn!("get proof err:{:?}", err);
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse { error: "PROOF_ERROR".to_string(), message: err.to_string() }),
            ))
        }
    }
}
