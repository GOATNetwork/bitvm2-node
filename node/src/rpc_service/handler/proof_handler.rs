use crate::env;
use crate::rpc_service::proof::{
    BlockDescQueryParams, CommitChainBlockDesc, CommitChainBlockDescListResponse,
    HeaderChainBlockDesc, HeaderChainBlockDescListResponse, ProofDesc, ProofResponse, ProofType,
    ProofsQueryParams,
};
use crate::rpc_service::response::{ApiErrorExt, ApiResult};
use crate::rpc_service::{AppState, current_time_secs};
use crate::utils::generate_random_bytes;
use axum::Json;
use axum::extract::{Query, State};
use client::btc_chain::mempool_v1_type::{
    MempoolBlocks, V1Blocks, get_v1_blocks_url, get_v1_mempool_blocks_url,
};
use http::{StatusCode, Uri};
use std::sync::Arc;
use store::ProofStatus;

/// Fetch a descending list of Header chain block descriptors
///
/// Queries the mempool.space V1 Blocks endpoint, takes the requested number of records from the newest block
/// downward, and enriches each block with the local proof status.
///
/// # Query Parameters
///
/// - `start_height`: Optional. Starting block height in descending order. Defaults to the latest height when omitted.
/// - `range`: Optional. Number of blocks to return (max and default 15). The actual length never exceeds the remote payload.
///
/// # Returns
///
/// - `200 OK`: Successfully returns a list of block descriptors.
/// - `500 Internal Server Error`: Failed to call or parse the mempool API.
/// - The payload includes `start`, `range`, and a `blocks_desc` array containing fee stats, size, tx count,
///   timestamp, and the derived `proof_status` for each block.
///
/// # Use Case
///
/// dashboards, monitoring services, or explorers
/// the current proof progress for header chains.
///
/// # Example
///
/// ```http
/// GET /v1/proofs/blocks-desc/header-chain?start_height=800000&range=10
/// ```
///
/// Response example:
/// ```json
/// {
///   "start": 800000,
///   "range": 10,
///   "blocks_desc": [
///     {
///       "height": 800000,
///       "median_fee": 50000,
///       "fee_range": [10000.0, 20000.0, 50000.0, 100000.0, 200000.0],
///       "total_fees": 5000000,
///       "size": 1500000,
///       "tx_count": 2500,
///       "timestamp": 1640995200,
///       "proof_status": "Pending"
///     }
///   ]
/// }
/// ```
#[axum::debug_handler]
pub async fn get_header_chain_blocks_desc(
    _uri: Uri,
    Query(params): Query<BlockDescQueryParams>,
    State(app_state): State<Arc<AppState>>,
) -> ApiResult<HeaderChainBlockDescListResponse> {
    let v1_blocks_url = get_v1_blocks_url(env::get_network(), params.start_height);
    let v1_blocks: V1Blocks = app_state
        .http_client
        .get_response_json(&v1_blocks_url)
        .await
        .api_error("GET_BLOCKS_DESC")?;
    let take_count = params.range.min(v1_blocks.len() as u32) as usize;
    let mut blocks_desc: Vec<HeaderChainBlockDesc> =
        v1_blocks.into_iter().take(take_count).map(HeaderChainBlockDesc::from).collect();
    if take_count > 2 {
        blocks_desc[0].proof_status = ProofStatus::Failed;
        blocks_desc[1].proof_status = ProofStatus::Pending;
    }
    Ok((
        StatusCode::OK,
        Json(HeaderChainBlockDescListResponse {
            start: blocks_desc[0].height,
            range: blocks_desc.len() as u64,
            blocks_desc,
        }),
    ))
}

/// Fetch a list of Header chain mempool block descriptors
///
/// Queries the mempool.space V1 Mempool Blocks endpoint to retrieve blocks currently in the mempool.
/// Each mempool block is enriched with estimated height (based on current blockchain height),
/// projected timestamp, and proof status. The height is calculated as current_height + index + 1,
/// and timestamps are projected forward with offsets based on block position.
///
/// # Returns
///
/// - `200 OK`: Successfully returns a list of mempool block descriptors.
/// - `500 Internal Server Error`: Failed to call or parse the mempool API, or failed to get current blockchain height.
/// - The payload includes `start` (height of the first mempool block), `range` (number of blocks),
///   and a `blocks_desc` array containing fee stats, size, tx count, projected timestamp,
///   estimated height, and proof status for each mempool block.
///
/// # Use Case
///
/// Dashboards, monitoring services, or explorers can use this endpoint to track
/// pending blocks in the mempool and their projected inclusion in the header chain.
///
/// # Example
///
/// ```http
/// GET /v1/proofs/blocks-desc/header-chain/mempool-blocks
/// ```
///
/// Response example:
/// ```json
/// {
///   "start": 800001,
///   "range": 5,
///   "blocks_desc": [
///     {
///       "height": 800001,
///       "median_fee": 50000,
///       "fee_range": [10000.0, 20000.0, 50000.0, 100000.0, 200000.0],
///       "total_fees": 5000000,
///       "size": 1500000,
///       "tx_count": 2500,
///       "timestamp": 1640995800,
///       "proof_status": "Pending"
///     }
///   ]
/// }
/// ```
#[axum::debug_handler]
pub async fn get_header_chain_mempool_blocks_desc(
    _uri: Uri,
    State(app_state): State<Arc<AppState>>,
) -> ApiResult<HeaderChainBlockDescListResponse> {
    let current_height =
        app_state.btc_client.get_height().await.api_error("GET_MEMPOOL_BLOCKS_DESC")? as u64;
    let mempool_blocks_url = get_v1_mempool_blocks_url(env::get_network());
    let mempool_blocks: MempoolBlocks = app_state
        .http_client
        .get_response_json(&mempool_blocks_url)
        .await
        .api_error("GET_MEMPOOL_BLOCKS_DESC")?;

    let current_time = current_time_secs() as u64;
    let blocks_desc: Vec<HeaderChainBlockDesc> = mempool_blocks
        .into_iter()
        .enumerate()
        .map(|(index, block)| {
            let time_offset = match index {
                0..=1 => (index as u64 + 1) * 600,
                2..=4 => (index as u64 + 1) * 600 + 60,
                _ => (index as u64 + 1) * 600 + 120,
            };
            let mut block_desc: HeaderChainBlockDesc = block.into();
            block_desc.timestamp = current_time + time_offset;
            block_desc.height = current_height + index as u64 + 1;
            block_desc
        })
        .collect();
    Ok((
        StatusCode::OK,
        Json(HeaderChainBlockDescListResponse {
            start: blocks_desc[0].height,
            range: blocks_desc.len() as u64,
            blocks_desc,
        }),
    ))
}

/// Fetch a descending list of Commit chain block descriptors
///
/// Returns a list of commit chain blocks in descending order by height, enriched with
/// sequencer information, commit IDs, and proof status for each block.
///
/// # Query Parameters
///
/// - `start_height`: Optional. Starting block height in descending order. Defaults to 920136 when omitted.
/// - `range`: Optional. Number of blocks to return (max and default 15). The actual length never exceeds the remote payload.
///
/// # Returns
///
/// - `200 OK`: Successfully returns a list of commit chain block descriptors.
/// - `500 Internal Server Error`: Server internal error or failed operation.
/// - The payload includes `start`, `range`, and a `blocks_desc` array containing height, size,
///   tx count, timestamp, sequencer number, sequencer set hash, commit ID, and proof status for each block.
///
/// # Use Case
///
/// Dashboards, monitoring services, or explorers can use this endpoint to track
/// commit chain block production and proof verification status.
///
/// # Example
///
/// ```http
/// GET /v1/proofs/blocks-desc/commit-chain?start_height=920136&range=10
/// ```
///
/// Response example:
/// ```json
/// {
///   "start": 920136,
///   "range": 10,
///   "blocks_desc": [
///     {
///       "height": 920136,
///       "size": 9275,
///       "tx_count": 100,
///       "timestamp": 1640995200,
///       "sequencer_number": 100,
///       "sequencer_set_hash": "0x1234...",
///       "commit_id": "0xabcd...",
///       "proof_status": "Failed"
///     }
///   ]
/// }
/// ```
pub async fn get_commit_chain_blocks_desc(
    _uri: Uri,
    Query(params): Query<BlockDescQueryParams>,
    State(_app_state): State<Arc<AppState>>,
) -> ApiResult<CommitChainBlockDescListResponse> {
    let start_height = params.start_height.unwrap_or(920136);
    let mut blocks_desc: Vec<CommitChainBlockDesc> = vec![];

    for i in 0..params.range {
        let proof_status = match i {
            0 => ProofStatus::Failed,
            1 => ProofStatus::Pending,
            _ => ProofStatus::Proved,
        };
        let block_number = start_height - i as u64;
        if block_number == 0 {
            break;
        }
        blocks_desc.push(CommitChainBlockDesc {
            height: block_number,
            size: 9275,
            tx_count: 100,
            timestamp: current_time_secs() as u64,
            sequencer_number: 100,
            sequencer_set_hash: format!("0x{}", hex::encode(generate_random_bytes(32))),
            commit_id: format!("0x{}", hex::encode(generate_random_bytes(32))),
            proof_status,
        })
    }

    Ok((
        StatusCode::OK,
        Json(CommitChainBlockDescListResponse {
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
