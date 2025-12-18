use crate::api::ApiState;
use crate::api::proofs::{
    ChainProofDesc, ChainProofDescRequest, ChainProofDescResponse, OperatorProofRequest,
    OperatorProofResponse, WatchtowerProofRequest,
};
use crate::api::response::{ApiErrorExt, ApiResult, ok_response};
use crate::api::validation::InputValidator;
use crate::task::{
    add_operator_task, add_watchtower_task, current_time_secs, find_operator_task,
    find_watchtower_task,
};
use axum::Json;
use axum::extract::{Query, State};
use std::sync::Arc;
use store::{OperatorProof, ProofState, WatchtowerProof};
use tracing::info;

#[axum::debug_handler]
pub(super) async fn get_chain_proof_task(
    State(api_state): State<Arc<ApiState>>,
    Query(payload): Query<ChainProofDescRequest>,
) -> ApiResult<ChainProofDescResponse> {
    let mut storage_process =
        api_state.local_db.acquire().await.api_error("GET_CHAIN_PROOF_ERROR")?;

    let proof = if let Some(height) = payload.height {
        storage_process
            .find_long_running_task_proof_including_block_number(
                height,
                payload.proof_type.get_chain_name().to_string(),
            )
            .await
            .api_error("GET_CHAIN_PROOF_ERROR")?
    } else {
        storage_process
            .find_latest_long_running_task_proof_by_name(
                payload.proof_type.get_chain_name().to_string(),
            )
            .await
            .api_error("GET_CHAIN_PROOF_ERROR")?
    };

    match proof {
        Some(proof) => {
            let total_time_to_proof = if proof.proof_state == ProofState::Proven.to_i64() {
                proof.updated_at - proof.created_at
            } else {
                0
            };
            ok_response(ChainProofDescResponse {
                proof_desc: Some(ChainProofDesc {
                    block_start: proof.block_start,
                    block_end: proof.block_start,
                    proof_type: payload.proof_type.to_string(),
                    state: ProofState::from_i64(proof.proof_state)
                        .unwrap_or_else(|| ProofState::New)
                        .to_string(),
                    proving_cycles: proof.cycles,
                    proving_time: proof.proving_time,
                    total_time_to_proof,
                    proof_size: 0.0,
                    zkm_version: proof.zkm_version,
                    pub_values: "".to_string(),
                    created_at: proof.created_at,
                    updated_at: proof.updated_at,
                }),
                error: None,
            })
        }

        None => ok_response(ChainProofDescResponse {
            proof_desc: None,
            error: Some("No proof found".to_string()),
        }),
    }
}

#[axum::debug_handler]
pub(super) async fn post_operator_proof_task(
    State(api_state): State<Arc<ApiState>>,
    Json(payload): Json<OperatorProofRequest>,
) -> ApiResult<OperatorProofResponse> {
    let instance_id = InputValidator::validate_uuid(&payload.instance_id, "instance_id")?;
    let graph_id = InputValidator::validate_uuid(&payload.graph_id, "graph_id")?;
    let operator_proof = find_operator_task(&api_state.local_db, instance_id, graph_id)
        .await
        .api_error("POST_OPERATOR_PROOF_TASK_ERROR")?;
    match operator_proof {
        Some(operator_proof) => {
            // todo update
            info!("Get Operator Proof:{operator_proof:?}");
        }
        None => {
            add_operator_task(
                &api_state.local_db,
                instance_id,
                graph_id,
                payload.execution_layer_block_number,
            )
            .await
            .api_error("POST_OPERATOR_PROOF_TASK_ERROR")?;
        }
    }
    ok_response(OperatorProofResponse {})
}

#[axum::debug_handler]
pub(super) async fn post_watchtower_proof_task(
    State(api_state): State<Arc<ApiState>>,
    Json(payload): Json<WatchtowerProofRequest>,
) -> ApiResult<OperatorProofResponse> {
    let instance_id = InputValidator::validate_uuid(&payload.instance_id, "instance_id")?;
    let graph_id = InputValidator::validate_uuid(&payload.graph_id, "graph_id")?;
    let challenge_txid =
        InputValidator::validate_btc_txid(&payload.challenge_txid, "challenge_txid")?.into();
    let challenge_init_txid =
        InputValidator::validate_btc_txid(&payload.challenge_init_txid, "challenge_init_txid")?
            .into();
    let mut storage_process =
        api_state.local_db.acquire().await.api_error("POST_WATCHTOWER_PROOF_TASK_ERROR")?;

    let watchtower_proofs = find_watchtower_task(&api_state.local_db, instance_id, graph_id)
        .await
        .api_error("POST_WATCHTOWER_PROOF_TASK_ERROR")?;

    if watchtower_proofs.is_empty() {
        add_watchtower_task(
            &api_state.local_db,
            instance_id,
            graph_id,
            payload.public_key,
            challenge_txid,
            challenge_init_txid,
            payload.execution_layer_block_number,
        )
        .await
        .api_error("POST_WATCHTOWER_PROOF_TASK_ERROR")?;
    } else {
        // todo update
        info!("Get watchtower Proof:{:?}", watchtower_proofs[0]);
    }

    ok_response(OperatorProofResponse {})
}
