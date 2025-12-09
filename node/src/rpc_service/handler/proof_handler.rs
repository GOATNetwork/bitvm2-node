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
            start: blocks_desc.first().map_or(0, |block| block.height),
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
/// GET /v1/proofs?height=800000&proof_type=header_chain
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
    Query(params): Query<ProofsQueryParams>,
    State(_app_state): State<Arc<AppState>>,
) -> ApiResult<ProofResponse> {
    // todo update
    let pub_inputs = match params.proof_type {
        ProofType::HeaderChain => {
            r#"{"vk_hash":[0,0,0,0,0,0,0,0],"pv_hash":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],"prev_proof":"GenesisBlock","block_headers":[{"version":874340352,"prev_block_hash":[85,187,159,189,150,107,62,162,220,66,208,194,39,34,228,192,193,114,159,173,23,33,1,0,0,0,0,0,0,0,0,0],"merkle_root":[85,8,127,171,12,143,63,137,248,188,253,77,242,108,80,77,129,176,168,142,4,144,113,97,131,140,12,83,0,26,240,145],"time":1690168629,"bits":386218132,"nonce":106861918},{"version":536977408,"prev_block_hash":[84,160,40,39,215,168,183,86,1,39,90,22,2,121,163,197,118,141,228,193,196,167,2,0,0,0,0,0,0,0,0,0],"merkle_root":[57,77,220,106,93,224,53,135,76,250,34,22,123,254,146,57,83,24,123,90,25,251,184,78,24,109,234,60,120,253,135,28],"time":1690168731,"bits":386218132,"nonce":2352794101}]}"#
        }
        ProofType::CommitChain => {
            r#"{"vk_hash":[0,0,0,0,0,0,0,0],"pv_hash":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],"prev_proof":"GenesisBlock","commits":[{"commit_txn":{"version":1,"lock_time":0,"input":[{"previous_output":"0000000000000000000000000000000000000000000000000000000000000000:4294967295","script_sig":"0393384400fe20e13100fe214f07000963676d696e6572343208760000000000000000","sequence":4294967295,"witness":["0000000000000000000000000000000000000000000000000000000000000000"]}],"output":[{"value":6106,"script_pubkey":"76a914349514f43295c41764ee036aaa8520dac4b1468c88ac"},{"value":0,"script_pubkey":"6a24aa21a9ed6229b05f1985ef7852e32d53f8a2a6e1f2c2b973ebf2b8aa53ec2cf157078122"}]},"genesis_txid":[85,110,218,173,174,159,216,250,98,250,2,152,245,160,242,16,136,221,5,151,207,214,0,169,238,243,136,233,24,75,67,203],"sequencer_set_hash":[119,143,242,6,41,98,189,153,210,117,109,34,4,251,217,57,27,151,214,24,218,251,238,29,134,228,62,100,48,52,68,248],"publisher_public_keys":["0277d8bae5febdabb96e9b5e5788556cdd39755936027721df39b8a339b9f0c982"],"threshold":0}]}"#
        }
    };

    Ok((
        StatusCode::OK,
        Json(ProofResponse {
            proof: Some(ProofDesc {
                block_number: 800000,
                proof_type: params.proof_type,
                state: "proved".to_string(),
                proving_cycles: 1000000,
                proving_time: 120,
                contain_blocks: "799990-800000".to_string(),
                total_time_to_proof: 180,
                proof_size: 2048.5,
                zkm_version: "1.0.0".to_string(),
                pub_inputs: pub_inputs.to_string(),
                started_at: current_time_secs(),
                updated_at: current_time_secs(),
            }),
        }),
    ))
}
