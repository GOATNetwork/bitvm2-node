use crate::rpc_service::AppState;
use crate::rpc_service::proof::{ProofItem, Proofs, ProofsQueryParams};
use axum::Json;
use axum::extract::{Query, State};
use http::StatusCode;
use std::str::FromStr;
use std::sync::Arc;
use store::{GoatTxType, ProofType};
use uuid::Uuid;

#[axum::debug_handler]
pub async fn get_proofs(
    Query(params): Query<ProofsQueryParams>,
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

        if params.block_number.is_none() && params.graph_id.is_none() {
            return Err("block number and graph id all is none".into());
        }

        let mut storage_process = app_state.local_db.acquire().await?;
        let block_number = if let Some(block_number) = params.block_number {
            block_number
        } else {
            let graph_id = params.graph_id.unwrap();
            let tx_record = storage_process
                .get_graph_goat_tx_record(
                    &Uuid::from_str(&graph_id)?,
                    &GoatTxType::ProceedWithdraw.to_string(),
                )
                .await?;
            if tx_record.is_none() {
                return Err(format!("get tx record is none for graph id {graph_id}").into());
            }
            tx_record.unwrap().height
        };

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
