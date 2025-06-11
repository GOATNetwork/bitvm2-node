use crate::rpc_service::AppState;
use crate::rpc_service::proof::{ProofItem, Proofs, ProofsQueryParams};
use axum::Json;
use axum::extract::{Path, Query, State};
use http::StatusCode;
use std::sync::Arc;
use store::ProofType;

#[axum::debug_handler]
pub async fn get_proofs(
    Query(params): Query<ProofsQueryParams>,
    Path(block_number): Path<i64>,
    State(app_state): State<Arc<AppState>>,
) -> (StatusCode, Json<Option<Proofs>>) {
    let async_fn = || async move {
        let convert_to_proof_items = |input: Vec<(i64, String, i64, i64, i64)>| -> Vec<ProofItem> {
            input
                .into_iter()
                .map(|(block_number, proof_state, pure_proof_cast, started_at, ended_at)| {
                    ProofItem { block_number, proof_state, pure_proof_cast, started_at, ended_at }
                })
                .collect()
        };

        let mut storage_process = app_state.local_db.acquire().await?;
        let block_proofs = convert_to_proof_items(
            storage_process
                .get_range_proofs(
                    ProofType::BlockProof,
                    block_number - params.block_range + 1,
                    block_number,
                )
                .await?,
        );

        let aggregation_proofs = convert_to_proof_items(
            storage_process
                .get_range_proofs(
                    ProofType::AggregationProof,
                    block_number - params.block_range + 1,
                    block_number,
                )
                .await?,
        );
        let groth16_proofs = convert_to_proof_items(
            storage_process
                .get_range_proofs(
                    ProofType::Groth16Proof,
                    block_number - params.block_range + 1,
                    block_number,
                )
                .await?,
        );
        Ok::<Option<Proofs>, Box<dyn std::error::Error>>(Some(Proofs {
            block_number,
            block_proofs,
            aggregation_proofs,
            groth16_proofs,
        }))
    };
    match async_fn().await {
        Ok(res) => (StatusCode::OK, Json(res)),
        Err(err) => {
            tracing::warn!("get_proofs failed, error:{}", err);
            (StatusCode::INTERNAL_SERVER_ERROR, Json(None))
        }
    }
}
