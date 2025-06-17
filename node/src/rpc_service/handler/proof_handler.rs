use crate::rpc_service::node::ALIVE_TIME_JUDGE_THRESHOLD;
use crate::rpc_service::proof::{
    BlockProofs, ProofItem, Proofs, ProofsOverview, ProofsQueryParams,
};
use crate::rpc_service::{AppState, current_time_secs};
use anyhow::bail;
use axum::Json;
use axum::extract::{Path, Query, State};
use bitvm2_lib::actors::Actor;
use http::{StatusCode, Uri};
use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Arc;
use store::localdb::LocalDB;
use store::{GoatTxType, NODE_STATUS_ONLINE, ProofType};
use uuid::Uuid;

#[axum::debug_handler]
pub async fn get_proof(
    uri: Uri,
    Path(block_number): Path<i64>,
    State(app_state): State<Arc<AppState>>,
) -> (StatusCode, Json<Option<Proofs>>) {
    let async_fn = || async move {
        if app_state.actor == Actor::Relayer {
            let operator_url = get_online_operator_url(&app_state.local_db).await?;
            let resp = app_state.client.get(format!("http://{operator_url}{uri}")).send().await?;
            if !resp.status().is_success() {
                return Err(format!("fail to get response from {operator_url}").into());
            }
            let res = resp.json::<Option<Proofs>>().await?;
            return Ok::<Option<Proofs>, Box<dyn std::error::Error>>(res);
        }
        let mut storage_process = app_state.local_db.acquire().await?;
        let block_proofs_map = convert_to_proof_items(
            storage_process
                .get_range_proofs(ProofType::BlockProof, block_number, block_number)
                .await?,
        );

        let aggregation_proofs_map = convert_to_proof_items(
            storage_process
                .get_range_proofs(ProofType::AggregationProof, block_number, block_number)
                .await?,
        );
        let groth16_proofs_map = convert_to_proof_items(
            storage_process
                .get_range_proofs(ProofType::Groth16Proof, block_number, block_number)
                .await?,
        );
        Ok::<Option<Proofs>, Box<dyn std::error::Error>>(Some(Proofs {
            block_proofs: vec![BlockProofs {
                block_number,
                block_proof: block_proofs_map.get(&block_number).cloned(),
                aggregation_proof: aggregation_proofs_map.get(&block_number).cloned(),
                groth16_proof: groth16_proofs_map.get(&block_number).cloned(),
            }],
        }))
    };
    match async_fn().await {
        Ok(res) => (StatusCode::OK, Json(res)),
        Err(err) => {
            tracing::warn!("get_proof failed, error:{}", err);
            (StatusCode::INTERNAL_SERVER_ERROR, Json(None))
        }
    }
}

#[axum::debug_handler]
pub async fn get_proofs(
    uri: Uri,
    Query(params): Query<ProofsQueryParams>,
    State(app_state): State<Arc<AppState>>,
) -> (StatusCode, Json<Option<Proofs>>) {
    let async_fn = || async move {
        if app_state.actor == Actor::Relayer {
            let operator_url = get_online_operator_url(&app_state.local_db).await?;
            let resp = app_state.client.get(format!("http://{operator_url}{uri}")).send().await?;
            if !resp.status().is_success() {
                return Err(format!("fail to get response from {operator_url}").into());
            }
            let res = resp.json::<Option<Proofs>>().await?;
            return Ok::<Option<Proofs>, Box<dyn std::error::Error>>(res);
        }

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

        let block_proofs_map = convert_to_proof_items(
            storage_process
                .get_range_proofs(
                    ProofType::BlockProof,
                    block_number - params.block_range + 1,
                    block_number,
                )
                .await?,
        );

        let aggregation_proofs_map = convert_to_proof_items(
            storage_process
                .get_range_proofs(
                    ProofType::AggregationProof,
                    block_number - params.block_range + 1,
                    block_number,
                )
                .await?,
        );
        let groth16_proofs_map = convert_to_proof_items(
            storage_process
                .get_range_proofs(
                    ProofType::Groth16Proof,
                    block_number - params.block_range + 1,
                    block_number,
                )
                .await?,
        );
        let mut block_proofs = vec![];
        for block_number in block_number - params.block_range + 1..block_number + 1 {
            block_proofs.push(BlockProofs {
                block_number,
                block_proof: block_proofs_map.get(&block_number).cloned(),
                aggregation_proof: aggregation_proofs_map.get(&block_number).cloned(),
                groth16_proof: groth16_proofs_map.get(&block_number).cloned(),
            })
        }

        Ok::<Option<Proofs>, Box<dyn std::error::Error>>(Some(Proofs { block_proofs }))
    };
    match async_fn().await {
        Ok(res) => (StatusCode::OK, Json(res)),
        Err(err) => {
            tracing::warn!("get_proofs failed, error:{}", err);
            (StatusCode::INTERNAL_SERVER_ERROR, Json(None))
        }
    }
}
#[axum::debug_handler]
pub async fn get_proofs_overview(
    uri: Uri,
    State(app_state): State<Arc<AppState>>,
) -> (StatusCode, Json<Option<ProofsOverview>>) {
    let async_fn = || async move {
        if app_state.actor == Actor::Relayer {
            let operator_url = get_online_operator_url(&app_state.local_db).await?;
            let resp = app_state.client.get(format!("http://{operator_url}{uri}")).send().await?;
            if !resp.status().is_success() {
                return Err(format!("fail to get response from {operator_url}").into());
            }
            let res = resp.json::<Option<ProofsOverview>>().await?;
            return Ok::<Option<ProofsOverview>, Box<dyn std::error::Error>>(res);
        }

        let mut storage_process = app_state.local_db.acquire().await?;
        let (total_blocks, avg_block_proof) =
            storage_process.get_proof_overview(ProofType::BlockProof).await?;
        let (_, avg_aggregation_proof) =
            storage_process.get_proof_overview(ProofType::AggregationProof).await?;
        let (_, avg_groth16_proof) =
            storage_process.get_proof_overview(ProofType::Groth16Proof).await?;
        Ok::<Option<ProofsOverview>, Box<dyn std::error::Error>>(Some(ProofsOverview {
            total_blocks,
            avg_block_proof,
            avg_aggregation_proof,
            avg_groth16_proof,
        }))
    };
    match async_fn().await {
        Ok(res) => (StatusCode::OK, Json(res)),
        Err(err) => {
            tracing::warn!("get_proofs_overview failed, error:{}", err);
            (StatusCode::INTERNAL_SERVER_ERROR, Json(None))
        }
    }
}

fn convert_to_proof_items(
    input: Vec<(i64, String, i64, i64, String, i64, i64)>,
) -> HashMap<i64, ProofItem> {
    input
        .into_iter()
        .map(
            |(
                block_number,
                state,
                proving_time,
                proof_size,
                zkm_version,
                started_at,
                updated_at,
            )| {
                let total_time_to_proof =
                    if updated_at >= started_at { updated_at - started_at } else { 0 };
                (
                    block_number,
                    ProofItem {
                        state,
                        proving_time,
                        total_time_to_proof,
                        proof_size,
                        zkm_version,
                        started_at,
                        updated_at,
                    },
                )
            },
        )
        .collect()
}

async fn get_online_operator_url(local_db: &LocalDB) -> anyhow::Result<String> {
    let mut storage_processor = local_db.acquire().await?;
    let time_threshold = current_time_secs() - ALIVE_TIME_JUDGE_THRESHOLD;
    let (nodes, _) = storage_processor
        .node_list(
            Some(Actor::Operator.to_string()),
            None,
            None,
            None,
            time_threshold,
            Some(NODE_STATUS_ONLINE.to_string()),
        )
        .await?;
    if nodes.is_empty() {
        bail!("no operator is online")
    }
    Ok(nodes[0].socket_addr.clone())
}
