use crate::ProofBuilderConfig;
use crate::task::create_commit_chain_proof;
use crate::task::fetch_latest_long_running_task;
use crate::task::fetch_next_commit_task_index;
use commit_chain_proof::CommitChainProofBuilder;
use commit_chain_proof::fetch_commit_chain;
use commit_chain_proof::load_upgrade_commits;
use proof_builder::{ProofBuilder, ProofRequest};
use std::time::Duration;
use store::localdb::LocalDB;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tracing::info;

use crate::api::metrics_service::{ApiMetricsState, COMMIT_CHAIN_PROOF};

#[tracing::instrument(level = "info", skip(local_db, metrics_state, cancellation_token))]
pub(crate) fn spawn_commit_chain_proof_task(
    args: commit_chain_proof::Args,
    local_db: LocalDB,
    metrics_state: ApiMetricsState,
    interval: u64,
    initial_delay: u64,
    cancellation_token: CancellationToken,
) -> JoinHandle<anyhow::Result<commit_chain_proof::Args>> {
    let mut args = args.clone();
    tokio::spawn(async move {
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_secs(initial_delay)) => {}
            _ = cancellation_token.cancelled() => {
                anyhow::bail!("Commit chain proof generate task cancelled");
            }
        }

        let builder = CommitChainProofBuilder::new();
        loop {
            tokio::select! {
                _ = tokio::time::sleep(Duration::from_secs(interval)) => {
                    let starts_from_genesis = args.starts_from_genesis();
                    if !starts_from_genesis {
                        let next_task = fetch_latest_long_running_task(&local_db, CommitChainProofBuilder::name()).await?;
                        if let Some(next_task) = next_task {
                            info!("Commit chain's next task: {next_task:?}");
                            args.start = fetch_next_commit_task_index(&local_db).await?;
                            args.input_proof = next_task.path_to_proof.unwrap();
                            args.commit_info = format!(
                                "{}/commit_info.json.{}",
                                std::path::Path::new(&args.output_proof).parent().unwrap().to_str().unwrap(),
                                args.start,
                            );
                            args.output_proof = format!(
                                "{}/{}-{}.bin",
                                std::path::Path::new(&args.output_proof).parent().unwrap().to_str().unwrap(),
                                args.start,
                                args.batch_size
                            );
                            args.commits = format!(
                                "{}/{}-{}.bin.commits",
                                std::path::Path::new(&args.output_proof).parent().unwrap().to_str().unwrap(),
                                args.start,
                                args.batch_size
                            );
                            args.init_input = false;
                        }
                    }
                    info!("Commit chain proof generate task: generate proof, args: {args:?}");

                    let mut commits = match fetch_commit_chain(&args.esplora_url, &args.commit_info, &args.commits, args.bitcoin_network).await {
                        Ok(d) => d,
                        Err(err) => {
                            tracing::warn!("Fetch commit chain error, {err:?}, continuing");
                            continue;
                        }
                    };
                    if let Some(path) = args.upgrade_commits.as_deref() {
                        commits = match load_upgrade_commits(path, &commits[0]) {
                            Ok(commits) => commits,
                            Err(err) => {
                                tracing::warn!("Load upgrade commits error, {err:?}, continuing");
                                continue;
                            }
                        };
                    }
                    let block_start = commits.first().unwrap().block_height as i64;
                    let ctx =
                        ProofRequest::CommitChainProofRequest {
                            init_input: starts_from_genesis,
                            input_proof: args.input_proof.clone(),
                            output_proof: args.output_proof.clone(),
                            commit_info: args.commit_info.clone(),
                            commits,
                    };
                    let proving_start = tokio::time::Instant::now();
                    let (input, proof, cycles, proving_time) = match builder.build_proof(&ctx) {
                        Ok(data) => data,
                        Err(error) => {
                            metrics_state.record_attempt(
                                COMMIT_CHAIN_PROOF,
                                "failed",
                                proving_start.elapsed(),
                            );
                            tracing::error!("Build proof error: {error:?}");
                            continue;
                        }
                    };
                    let proving_duration = proving_start.elapsed().as_secs_f32() * 1000.0;
                    let zkm_version = proof.zkm_version.clone();
                    let (public_value_hex, proof_size) =
                        match builder.save_proof(&ctx, &input, cycles, proof) {
                            Ok(data) => data,
                            Err(error) => {
                                metrics_state.record_attempt(
                                    COMMIT_CHAIN_PROOF,
                                    "failed",
                                    proving_start.elapsed(),
                                );
                                return Err(error);
                            }
                        };
                    let persist_result = create_commit_chain_proof(
                        &local_db,
                        block_start,
                        0xffffffff_i64 - block_start,
                        args.output_proof.clone(),
                        public_value_hex,
                        proof_size as i64,
                        cycles,
                        CommitChainProofBuilder::name(),
                        starts_from_genesis,
                        proving_duration as i64,
                        proving_time as i64,
                        store::ProofState::Proven,
                        zkm_version,
                    )
                    .await;
                    let outcome = if matches!(&persist_result, Ok(affected) if *affected > 0) {
                        "success"
                    } else {
                        "failed"
                    };
                    metrics_state.record_attempt(
                        COMMIT_CHAIN_PROOF,
                        outcome,
                        proving_start.elapsed(),
                    );
                    persist_result?;
                    args = ProofBuilderConfig::run_next(args, CommitChainProofBuilder::name())?;
                }
                _ = cancellation_token.cancelled() => {
                    anyhow::bail!("Commit chain proof generate task cancelled");
                }
            }
        }
    })
}
