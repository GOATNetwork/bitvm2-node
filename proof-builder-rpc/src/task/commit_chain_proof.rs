use crate::ProofBuilderConfig;
use commit_chain_proof::CommitChainProofBuilder;
use commit_chain_proof::fetch_commit_chain;
use proof_builder::{Context, ProofBuilder, ProofRequest};
use std::time::Duration;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tracing::info;

#[tracing::instrument(level = "info", skip(cancellation_token))]
pub(crate) fn spawn_commit_chain_proof_task(
    args: commit_chain_proof::Args,
    interval: u64,
    initial_delay: u64,
    cancellation_token: CancellationToken,
) -> JoinHandle<anyhow::Result<commit_chain_proof::Args>> {
    let mut args = args.clone();
    tokio::spawn(async move {
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_secs(initial_delay)) => {}
            _ = cancellation_token.cancelled() => {
                return Err(anyhow::anyhow!("Commit chain proof generate task cancelled"));
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
                    let (input, proof, cycles) = match builder.build_proof(&ctx) {
                        Ok(data) => data,
                        Err(err) => {
                            tracing::error!("Build proof error, {err:?}");
                            continue;
                        }
                    };
                    builder.save_proof(&ctx, &input, cycles, proof).unwrap();
                    args = ProofBuilderConfig::save(args).unwrap();
                }
                _ = cancellation_token.cancelled() => {
                    return Err(anyhow::anyhow!("Commit chain proof generate task cancelled"));
                }
            }
        }
    })
}
