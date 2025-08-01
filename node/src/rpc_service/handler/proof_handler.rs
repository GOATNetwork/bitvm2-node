use crate::env::get_proof_server_url;
use crate::rpc_service::AppState;
use crate::rpc_service::proof::{
    BlockProofs, Groth16ProofValue, ProofItem, Proofs, ProofsOverview, ProofsOverviewQueryParams,
    ProofsQueryParams,
};
use anyhow::bail;
use axum::Json;
use axum::extract::{Path, Query, State};
use bitvm2_lib::actors::Actor;
use http::{StatusCode, Uri};
use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Arc;
use store::localdb::LocalDB;
use store::{GoatTxType, ProofInfo, ProofType};
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

        let groth16_proof = storage_process
            .get_groth16_proof_info(block_number)
            .await?
            .map(|groth16_proof_info| groth16_proof_info.into());
        Ok::<Option<Proofs>, Box<dyn std::error::Error>>(Some(Proofs {
            block_proofs: vec![BlockProofs {
                block_number,
                block_proof: block_proofs_map.get(&block_number).cloned(),
                aggregation_proof: aggregation_proofs_map.get(&block_number).cloned(),
                groth16_proof,
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
    Query(params): Query<ProofsOverviewQueryParams>,
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
        let (total_blocks, sum_block_proof_time, block_proof_count) = storage_process
            .get_proof_overview(ProofType::BlockProof, params.block_proof_count)
            .await?;
        let (_, sum_aggregation_proof_time, aggregation_proof_count) = storage_process
            .get_proof_overview(ProofType::AggregationProof, params.agg_proof_count)
            .await?;
        let (_, sum_groth16_proof_times, groth16_proof_count) = storage_process
            .get_proof_overview(ProofType::Groth16Proof, params.groth16_proof_count)
            .await?;
        let (block_proof_conc, agg_proof_conc, groth16_proof_conc) =
            get_proof_config(&app_state.local_db).await?;
        Ok::<Option<ProofsOverview>, Box<dyn std::error::Error>>(Some(ProofsOverview {
            total_blocks,
            avg_block_proof: calculate_proof_avg_proof_time(
                sum_block_proof_time,
                block_proof_count,
                block_proof_conc,
            ),
            avg_aggregation_proof: calculate_proof_avg_proof_time(
                sum_aggregation_proof_time,
                aggregation_proof_count,
                agg_proof_conc,
            ),
            avg_groth16_proof: calculate_proof_avg_proof_time(
                sum_groth16_proof_times,
                groth16_proof_count,
                groth16_proof_conc,
            ),
            block_proof_count,
            aggregation_proof_count,
            groth16_proof_count,
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

fn convert_to_proof_items(input: Vec<ProofInfo>) -> HashMap<i64, ProofItem> {
    input.into_iter().map(|proof_info| (proof_info.block_number, proof_info.into())).collect()
}

// get_detail_proof
#[axum::debug_handler]
pub async fn get_groth16_proof(
    uri: Uri,
    Path(block_number): Path<i64>,
    State(app_state): State<Arc<AppState>>,
) -> (StatusCode, Json<Option<Groth16ProofValue>>) {
    let async_fn = || async move {
        if app_state.actor == Actor::Relayer {
            let operator_url = get_online_operator_url(&app_state.local_db).await?;
            let resp = app_state.client.get(format!("http://{operator_url}{uri}")).send().await?;
            if !resp.status().is_success() {
                return Err(format!("fail to get response from {operator_url}").into());
            }
            let res = resp.json::<Option<Groth16ProofValue>>().await?;
            return Ok::<Option<Groth16ProofValue>, Box<dyn std::error::Error>>(res);
        }
        let mut storage_process = app_state.local_db.acquire().await?;
        let (proof, public_values, verifier_id, zkm_version) =
            storage_process.get_groth16_proof(block_number).await?;

        if proof.is_empty() {
            return Err(format!("Groth16 proof is not ready at {block_number}").into());
        }
        let groth16_vk = storage_process.get_groth16_vk(&zkm_version).await?;
        Ok::<Option<Groth16ProofValue>, Box<dyn std::error::Error>>(Some(Groth16ProofValue {
            proof,
            public_values,
            verifier_id,
            zkm_version,
            groth16_vk,
        }))
    };
    match async_fn().await {
        Ok(res) => (StatusCode::OK, Json(res)),
        Err(err) => {
            tracing::warn!("get_detail_proof failed, error:{}", err);
            (StatusCode::INTERNAL_SERVER_ERROR, Json(None))
        }
    }
}

async fn get_online_operator_url(local_db: &LocalDB) -> anyhow::Result<String> {
    let env_set_url = get_proof_server_url();
    if let Some(url) = env_set_url {
        return Ok(url);
    }
    let mut storage_processor = local_db.acquire().await?;
    if let Some(node) = storage_processor.get_proof_server_node().await? {
        Ok(node.socket_addr.clone())
    } else {
        bail!("no operator is online")
    }
}

fn calculate_proof_avg_proof_time(sum_time: i64, proof_counts: i64, concurrency: i64) -> f64 {
    if proof_counts * concurrency == 0 {
        return 0.0;
    }
    sum_time as f64 / (concurrency as f64 * proof_counts as f64)
}

async fn get_proof_config(local_db: &LocalDB) -> anyhow::Result<(i64, i64, i64)> {
    let (block_concurrency, aggregated_block_count, _) =
        groth16::get_proof_config(local_db).await?;
    Ok((block_concurrency, aggregated_block_count, 1))
}

#[cfg(test)]
mod tests {
    use crate::client::create_local_db;
    use crate::env::ENV_PROOF_SEVER_URL;
    use crate::rpc_service::handler::proof_handler::{
        calculate_proof_avg_proof_time, get_online_operator_url,
    };
    use crate::utils::temp_file;
    use bitvm2_lib::actors::Actor;
    use store::Node;

    #[tokio::test]
    async fn test_get_online_operator_url_with_env() {
        let remote_proof_server = "123.12.11.1:1234";
        unsafe {
            std::env::set_var(ENV_PROOF_SEVER_URL, remote_proof_server);
        }
        let local_db = create_local_db(&temp_file()).await;
        let proof_server =
            get_online_operator_url(&local_db).await.expect("Failed to get online operator url");
        assert_eq!(proof_server, remote_proof_server);
    }
    #[tokio::test]
    async fn test_get_online_operator_url_without_env() {
        let remote_proof_server = "123.12.11.1:1234";
        let local_db = create_local_db(&temp_file()).await;
        let mut storage_processor =
            local_db.acquire().await.expect("Failed to get online operator url");
        storage_processor
            .update_node(Node {
                peer_id: "peerId".to_string(),
                actor: Actor::Operator.to_string(),
                socket_addr: remote_proof_server.to_string(),
                ..Default::default()
            })
            .await
            .expect("Failed to update node");
        let proof_server =
            get_online_operator_url(&local_db).await.expect("Failed to get online operator url");
        assert_eq!(proof_server, remote_proof_server);
    }

    #[test]
    fn test_calculate_proof_avg_proof_time() {
        assert_eq!(calculate_proof_avg_proof_time(100, 5, 0), 0.0);
        assert_eq!(calculate_proof_avg_proof_time(100, 0, 1), 0.0);
        assert_eq!(calculate_proof_avg_proof_time(0, 1, 1), 0.0);
        assert_eq!(calculate_proof_avg_proof_time(100, 5, 2), 10.0);
    }
}
