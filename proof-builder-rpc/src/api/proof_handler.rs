use crate::api::ApiState;
use crate::api::proofs::{
    ChainProofDescRequest, OperatorProofDescRequest, OperatorProofRequest, OperatorProofResponse,
    ProofData, ProofDesc, ProofDescResponse, ProofType, WatchtowerProofRequest,
    WatchtowerProofResponse,
};
use crate::api::response::{ApiErrorExt, ApiResult, ok_response};
use crate::api::validation::InputValidator;
use crate::task::{
    add_operator_task, add_watchtower_task, find_operator_task, find_watchtower_task,
};
use axum::Json;
use axum::extract::{Query, State};
use std::sync::Arc;
use store::ProofState;
use tracing::info;

#[axum::debug_handler]
pub(super) async fn get_chain_proof_task_desc(
    State(api_state): State<Arc<ApiState>>,
    Query(payload): Query<ChainProofDescRequest>,
) -> ApiResult<ProofDescResponse> {
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
            let prev_proof_number = storage_process
                .find_long_running_task_proof_including_block_number(
                    proof.block_start - 1,
                    payload.proof_type.get_chain_name().to_string(),
                )
                .await
                .api_error("GET_CHAIN_PROOF_ERROR")?
                .map(|v| v.block_end - 1);
            let next_proof_number = storage_process
                .find_long_running_task_proof_including_block_number(
                    proof.block_end,
                    payload.proof_type.get_chain_name().to_string(),
                )
                .await
                .api_error("GET_CHAIN_PROOF_ERROR")?
                .map(|v| v.block_start);

            ok_response(ProofDescResponse {
                proof_desc: Some(ProofDesc {
                    block_start: proof.block_start,
                    block_end: proof.block_end,
                    proof_type: payload.proof_type.to_string(),
                    state: ProofState::from_i64(proof.proof_state)
                        .unwrap_or_else(|| ProofState::New)
                        .to_string(),
                    proving_cycles: proof.cycles,
                    proving_time: proof.proving_time,
                    total_time_to_proof: proof.proving_time,
                    proof_size: proof.proof_size as f64 / 1000.0, // use KiB
                    zkm_version: proof.zkm_version,
                    pub_values: proof.public_value_hex.unwrap_or("".to_string()),
                    prev_proof_number,
                    next_proof_number,
                    created_at: proof.created_at,
                    updated_at: proof.updated_at,
                }),
                error: None,
            })
        }

        None => ok_response(ProofDescResponse {
            proof_desc: None,
            error: Some("No proof found".to_string()),
        }),
    }
}

#[axum::debug_handler]
pub(super) async fn get_operator_proof_task_desc(
    State(api_state): State<Arc<ApiState>>,
    Query(payload): Query<OperatorProofDescRequest>,
) -> ApiResult<ProofDescResponse> {
    let instance_id = InputValidator::validate_uuid(&payload.instance_id, "instance_id")?;
    let graph_id = InputValidator::validate_uuid(&payload.graph_id, "graph_id")?;
    let operator_proof = find_operator_task(&api_state.local_db, instance_id, graph_id)
        .await
        .api_error("POST_OPERATOR_PROOF_TASK_ERROR")?;
    match operator_proof {
        Some(operator_proof) => {
            info!("Get Operator Proof:{operator_proof:?}");
            ok_response(ProofDescResponse {
                proof_desc: Some(ProofDesc {
                    block_start: operator_proof.execution_layer_block_number,
                    block_end: operator_proof.execution_layer_block_number + 1,
                    proof_type: "Operator".to_string(),
                    state: ProofState::from_i64(operator_proof.proof_state)
                        .unwrap_or_else(|| ProofState::New)
                        .to_string(),
                    proving_cycles: operator_proof.cycles,
                    proving_time: operator_proof.proving_time,
                    total_time_to_proof: operator_proof.proving_time,
                    proof_size: operator_proof.proof_size as f64 / 1000.0, // use KiB
                    zkm_version: operator_proof.zkm_version,
                    pub_values: operator_proof.public_value_hex.unwrap_or("".to_string()),
                    prev_proof_number: None,
                    next_proof_number: None,
                    created_at: operator_proof.created_at,
                    updated_at: operator_proof.updated_at,
                }),
                error: None,
            })
        }
        None => ok_response(ProofDescResponse {
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
        Some(operator_proof)
            if operator_proof.proof_state == ProofState::Proven.to_i64()
                && operator_proof.path_to_proof.is_some() =>
        {
            ok_response(OperatorProofResponse {
                proof_data: Some(ProofData::load_proof_data(
                    &operator_proof.path_to_proof.unwrap(),
                    ProofType::Operator,
                )),
                error: None,
            })
        }
        Some(operator_proof) => ok_response(OperatorProofResponse {
            proof_data: None,
            error: Some(format!(
                "No proof is not ready, state {}, path:{:?}",
                operator_proof.proof_state, operator_proof.path_to_proof
            )),
        }),

        None => {
            add_operator_task(
                &api_state.local_db,
                instance_id,
                graph_id,
                payload.execution_layer_block_number,
            )
            .await
            .api_error("POST_OPERATOR_PROOF_TASK_ERROR")?;
            ok_response(OperatorProofResponse {
                proof_data: None,
                error: Some("No proof found".to_string()),
            })
        }
    }
}

#[axum::debug_handler]
pub(super) async fn post_watchtower_proof_task(
    State(api_state): State<Arc<ApiState>>,
    Json(payload): Json<WatchtowerProofRequest>,
) -> ApiResult<WatchtowerProofResponse> {
    let instance_id = InputValidator::validate_uuid(&payload.instance_id, "instance_id")?;
    let graph_id = InputValidator::validate_uuid(&payload.graph_id, "graph_id")?;
    let challenge_txid =
        InputValidator::validate_btc_txid(&payload.challenge_txid, "challenge_txid")?.to_string();
    let challenge_init_txid =
        InputValidator::validate_btc_txid(&payload.challenge_init_txid, "challenge_init_txid")?
            .to_string();

    let watchtower_proof =
        find_watchtower_task(&api_state.local_db, instance_id, graph_id, &payload.public_key)
            .await
            .api_error("POST_WATCHTOWER_PROOF_TASK_ERROR")?;

    match watchtower_proof {
        Some(watchtower_proof)
            if watchtower_proof.proof_state == ProofState::Proven.to_i64()
                && watchtower_proof.path_to_proof.is_some() =>
        {
            ok_response(WatchtowerProofResponse {
                proof_data: Some(ProofData::load_proof_data(
                    &watchtower_proof.path_to_proof.unwrap(),
                    ProofType::Watchtower,
                )),
                error: None,
            })
        }
        Some(watchtower_proof) => ok_response(WatchtowerProofResponse {
            proof_data: None,
            error: Some(format!(
                "No proof is not ready, state {}, path:{:?}",
                watchtower_proof.proof_state, watchtower_proof.path_to_proof
            )),
        }),

        None => {
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
            ok_response(WatchtowerProofResponse {
                proof_data: None,
                error: Some("No proof found".to_string()),
            })
        }
    }
}
