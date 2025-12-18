use crate::env::get_proof_build_rpc_host;
use crate::rpc_service::proof::{
    ChainProofDescRequest, OperatorProofDescRequest, ProofDesc, ProofDescResponse,
};
use crate::rpc_service::response::{ApiResult, ok_response, to_api_error};
use crate::rpc_service::{AppState, current_time_secs};
use crate::utils::generate_random_bytes;
use axum::body::Body;
use axum::extract::{Query, State};
use axum::http::{HeaderMap, Request, Uri};
use std::sync::Arc;
use store::ProofState;

/// Checks if the request host matches the configured proof builder host to prevent forwarding loops.
fn is_loop_detected(host: &str, request_host: Option<&str>) -> bool {
    if let Some(request_host) = request_host {
        host == request_host
            || host.starts_with(&format!("{}:", request_host.split(':').next().unwrap_or("")))
    } else {
        false
    }
}

/// Creates mock proof description data for testing purposes.
fn create_mock_proof_desc(proof_type: String) -> ProofDesc {
    ProofDesc {
        block_start: 10000,
        block_end: 20000,
        proof_type,
        state: ProofState::Proven.to_string(),
        proving_cycles: 10000,
        proving_time: 100000,
        total_time_to_proof: 100010,
        proof_size: 333.0,
        zkm_version: "zkm_1.0.0".to_string(),
        pub_values: hex::encode(generate_random_bytes(64)),
        prev_proof_number: Some(1000),
        next_proof_number: Some(1000),
        created_at: current_time_secs(),
        updated_at: current_time_secs(),
    }
}

/// Handles forwarding to proof builder service or returning mock data.
async fn handle_proof_desc_forwarding(
    uri: &Uri,
    headers: &HeaderMap,
    app_state: Arc<AppState>,
    proof_type: String,
    error_code: &str,
) -> ApiResult<ProofDescResponse> {
    match get_proof_build_rpc_host() {
        Some(host) => {
            let request_host = headers.get("host").and_then(|h| h.to_str().ok());
            if is_loop_detected(&host, request_host) {
                tracing::warn!(
                    "GOAT_PROOF_BUILD_URL points to self ({host}), returning mock data to avoid loop"
                );
                return ok_response(ProofDescResponse {
                    proof_desc: None,
                    error: Some("request host is eq self host".to_string()),
                });
            }
            let url = format!("http://{host}{uri}");
            let resp =
                app_state.http_client.get_response_json::<ProofDescResponse>(&url).await.map_err(
                    |e| {
                        to_api_error(
                            error_code,
                            format!("fail to get proof from url: {host}, error: {e}"),
                        )
                    },
                )?;
            ok_response(resp)
        }
        None => ok_response(ProofDescResponse {
            proof_desc: Some(create_mock_proof_desc(proof_type)),
            error: None,
        }),
    }
}

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
/// Returns `ApiResult<ProofDescResponse>` which wraps the response in HTTP status code and JSON format:
///
/// - **Success (200 OK)**: Returns `ProofDescResponse` JSON containing:
///   - `proof_desc`: Optional `ProofDesc` object with proof metadata (block range, proof state, proving cycles, timing information, etc.)
///   - `error`: Optional error message string (may be present even with 200 status if forwarding loop detected)
///
/// - **Error (500 Internal Server Error)**: Returns `ErrorResponse` JSON containing:
///   - `error`: Error code string (e.g., "GET_CHAIN_PROOF_ERROR")
///   - `message`: Detailed error message describing what went wrong
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
/// Success response example (200 OK):
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
///     "prev_proof_number": 1000,
///     "next_proof_number": 1000,
///     "created_at": 1640995200,
///     "updated_at": 1640995200
///   },
///   "error": null
/// }
/// ```
///
/// Error response example (500 Internal Server Error):
/// ```json
/// {
///   "error": "GET_CHAIN_PROOF_ERROR",
///   "message": "fail to get proof from url: example.com, error: connection failed"
/// }
/// ```
#[axum::debug_handler]
pub async fn get_chain_proof_desc(
    Query(params): Query<ChainProofDescRequest>,
    State(app_state): State<Arc<AppState>>,
    request: Request<Body>,
) -> ApiResult<ProofDescResponse> {
    handle_proof_desc_forwarding(
        request.uri(),
        request.headers(),
        app_state,
        params.proof_type.to_string(),
        "GET_CHAIN_PROOF_ERROR",
    )
    .await
}

/// Get operator proof description
///
/// Retrieves proof description information for operator proofs. If the `GOAT_PROOF_BUILD_URL`
/// environment variable is set, the request is forwarded to the specified proof builder RPC service.
/// Otherwise, returns mock proof data for testing purposes. Includes loop detection to prevent infinite
/// forwarding when the environment variable points to the current service.
///
/// # Query Parameters
///
/// - `instance_id`: Instance ID (required) - the identifier of the BitVM2 instance
/// - `graph_id`: Graph ID (required) - the identifier of the graph within the instance
///
/// # Returns
///
/// Returns `ApiResult<ProofDescResponse>` which wraps the response in HTTP status code and JSON format:
///
/// - **Success (200 OK)**: Returns `ProofDescResponse` JSON containing:
///   - `proof_desc`: Optional `ProofDesc` object with proof metadata (block range, proof state, proving cycles, timing information, etc.)
///   - `error`: Optional error message string (may be present even with 200 status if forwarding loop detected)
///
/// - **Error (500 Internal Server Error)**: Returns `ErrorResponse` JSON containing:
///   - `error`: Error code string (e.g., "GET_OPERATOR_PROOF_ERROR")
///   - `message`: Detailed error message describing what went wrong
///
/// # Use Case
///
/// Applications use this to retrieve proof generation status and metadata for operator proofs
/// in the BitVM2 network. The endpoint supports forwarding requests to dedicated proof builder services
/// when configured via environment variables.
///
/// # Example
///
/// ```http
/// GET /v1/proofs/operator_proofs_desc?instance_id=instance123&graph_id=graph456
/// ```
///
/// Success response example (200 OK):
/// ```json
/// {
///   "proof_desc": {
///     "block_start": 10000,
///     "block_end": 20000,
///     "proof_type": "OperatorProof",
///     "state": "Proven",
///     "proving_cycles": 10000,
///     "proving_time": 100000,
///     "total_time_to_proof": 100010,
///     "proof_size": 333.0,
///     "zkm_version": "zkm_1.0.0",
///     "pub_values": "abc123...",
///     "prev_proof_number": 1000,
///     "next_proof_number": 1000,
///     "created_at": 1640995200,
///     "updated_at": 1640995200
///   },
///   "error": null
/// }
/// ```
///
/// Error response example (500 Internal Server Error):
/// ```json
/// {
///   "error": "GET_OPERATOR_PROOF_ERROR",
///   "message": "fail to get proof from url: example.com, error: connection failed"
/// }
/// ```
#[axum::debug_handler]
pub async fn get_operator_proof_desc(
    Query(_params): Query<OperatorProofDescRequest>,
    State(app_state): State<Arc<AppState>>,
    request: Request<Body>,
) -> ApiResult<ProofDescResponse> {
    handle_proof_desc_forwarding(
        request.uri(),
        request.headers(),
        app_state,
        "OperatorProof".to_string(),
        "GET_OPERATOR_PROOF_ERROR",
    )
    .await
}
