use crate::env::get_proof_build_rpc_host;
use crate::rpc_service::proof::{ChainProofDesc, ChainProofDescRequest, ChainProofDescResponse};
use crate::rpc_service::response::{ApiResult, ok_response, to_api_error};
use crate::rpc_service::{AppState, current_time_secs};
use crate::utils::generate_random_bytes;
use axum::body::Body;
use axum::extract::{Query, State};
use axum::http::Request;
use std::sync::Arc;
use store::ProofState;

/// Get chain proof description
///
/// Retrieves proof description information for a specific chain proof type. If the `GOAT_PROOF_BUILD_URL`
/// environment variable is set, the request is forwarded to the specified proof builder RPC service.
/// Otherwise, returns mock proof data for testing purposes. Includes loop detection to prevent infinite
/// forwarding when the environment variable points to the current service.
///
/// # Query Parameters
///
/// - `proof_type`: Proof type (required) - one of `header_chain`, `commit_chain`, or `state_chain`
/// - `height`: Block height (optional) - specific block height to query proof for
///
/// # Returns
///
/// - `200 OK`: Successfully returns proof description or mock data
/// - `500 Internal Server Error`: Server internal error or failed to forward request to proof builder service
/// - Response includes proof metadata such as block range, proof state, proving cycles, and timing information
///
/// # Use Case
///
/// Applications use this to retrieve proof generation status and metadata for different chain proof types
/// in the BitVM2 network. The endpoint supports forwarding requests to dedicated proof builder services
/// when configured via environment variables.
///
/// # Example
///
/// ```http
/// GET /v1/proofs/chain_proofs_desc?proof_type=header_chain&height=100000&is_start_height=false
/// ```
///
/// Response example:
/// ```json
/// {
///   "proof_desc": {
///     "block_start": 10000,
///     "block_end": 20000,
///     "proof_type": "header_chain",
///     "state": "Proven",
///     "proving_cycles": 10000,
///     "proving_time": 100000,
///     "total_time_to_proof": 100010,
///     "proof_size": 333.0,
///     "zkm_version": "zkm_1.0.0",
///     "pub_values": "abc123...",
///     "created_at": 1640995200,
///     "updated_at": 1640995200
///   },
///   "error": null
/// }
/// ```
#[axum::debug_handler]
pub async fn get_chain_proof(
    Query(params): Query<ChainProofDescRequest>,
    State(app_state): State<Arc<AppState>>,
    request: Request<Body>,
) -> ApiResult<ChainProofDescResponse> {
    let uri = request.uri();
    match get_proof_build_rpc_host() {
        Some(host) => {
            if let Some(request_host) = request.headers().get("host").and_then(|h| h.to_str().ok())
                && (host == request_host
                    || host
                        .starts_with(&format!("{}:", request_host.split(':').next().unwrap_or(""))))
            {
                tracing::warn!(
                    "GOAT_PROOF_BUILD_URL points to self ({host}), returning mock data to avoid loop"
                );
                return ok_response(ChainProofDescResponse {
                    proof_desc: Some(ChainProofDesc {
                        block_start: 10000,
                        block_end: 20000,
                        proof_type: params.proof_type.to_string(),
                        state: ProofState::Proven.to_string(),
                        proving_cycles: 10000,
                        proving_time: 100000,
                        total_time_to_proof: 100010,
                        proof_size: 333.0,
                        zkm_version: "zkm_1.0.0".to_string(),
                        pub_values: hex::encode(generate_random_bytes(64)),
                        created_at: current_time_secs(),
                        updated_at: current_time_secs(),
                    }),
                    error: None,
                });
            }
            let url = format!("http://{host}{uri}");
            let resp = app_state
                .http_client
                .get_response_json::<ChainProofDescResponse>(&url)
                .await
                .map_err(|e| {
                    to_api_error(
                        "GET_CHAIN_PROOF_ERROR",
                        format!("fail to get proof from url: {host}, error: {e}"),
                    )
                })?;
            ok_response(resp)
        }
        None => ok_response(ChainProofDescResponse {
            proof_desc: Some(ChainProofDesc {
                block_start: 10000,
                block_end: 20000,
                proof_type: params.proof_type.to_string(),
                state: ProofState::Proven.to_string(),
                proving_cycles: 10000,
                proving_time: 100000,
                total_time_to_proof: 100010,
                proof_size: 333.0,
                zkm_version: "zkm_1.0.0".to_string(),
                pub_values: hex::encode(generate_random_bytes(64)),
                created_at: current_time_secs(),
                updated_at: current_time_secs(),
            }),
            error: None,
        }),
    }
}
