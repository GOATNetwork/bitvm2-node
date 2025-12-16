use crate::ProofBuilderConfig;
use crate::task::update_long_running_task;
use commit_chain_proof::CommitChainProofBuilder;
use commit_chain_proof::fetch_commit_chain;
use proof_builder::{Context, ProofBuilder, ProofRequest};
use std::time::Duration;
use store::localdb::LocalDB;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tracing::info;

#[tracing::instrument(level = "info", skip(cancellation_token))]
pub(crate) fn spawn_commit_chain_proof_task(
    args: commit_chain_proof::Args,
    local_db: LocalDB,
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
                    info!("Commit chain proof generate task: generate proof");
                    match fetch_commit_chain(&args.esplora_url, &args.commit_info, &args.commits, args.start, args.batch_size).await {
                        Ok(()) => {},
                        Err(err) => {
                            tracing::error!("Fetch commit chain error, {err:?}");
                            continue;
                        }
                    };
                    let ctx = Context {
                        request: ProofRequest::CommitChainProofRequest {
                            init_input: args.init_input,
                            input_proof: args.input_proof.clone(),
                            output_proof: args.output_proof.clone(),
                            commit_info: args.commit_info.clone(),
                            commits: args.commits.clone(),
                        },
                    };
                    let proving_start = tokio::time::Instant::now();
                    let (input, proof, cycles) = match builder.build_proof(&ctx) {
                        Ok(data) => data,
                        Err(err) => {
                            tracing::error!("Build proof error, {err:?}");
                            continue;
                        }
                    };
                    let proving_duration = proving_start.elapsed().as_secs_f32() * 1000.0;
                    let zkm_version = proof.zkm_version.clone();
                    builder.save_proof(&ctx, &input, cycles, proof).unwrap();
                    update_long_running_task(&local_db, args.start as u64, args.batch_size as u64, &args.output_proof, cycles, CommitChainProofBuilder::name(), proving_duration as i64, zkm_version).await?;
                    args = ProofBuilderConfig::run_next(args, CommitChainProofBuilder::name()).unwrap();
                }
                _ = cancellation_token.cancelled() => {
                    anyhow::bail!("Commit chain proof generate task cancelled");
                }
            }
        }
    })
}
