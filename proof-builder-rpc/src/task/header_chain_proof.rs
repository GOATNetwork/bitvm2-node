use header_chain_proof::{HeaderChainProofBuilder, fetch_header_chain};
use proof_builder::{Context, ProofBuilder, ProofRequest};
use std::time::Duration;
use store::localdb::LocalDB;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tracing::info;

use crate::config::ProofBuilderConfig;
use crate::task::{fetch_latest_long_running_task, update_long_running_task};

#[tracing::instrument(level = "info", skip(cancellation_token))]
pub(crate) fn spawn_header_chain_proof_task(
    args: header_chain_proof::Args,
    local_db: LocalDB,
    interval: u64,
    initial_delay: u64,
    cancellation_token: CancellationToken,
) -> JoinHandle<anyhow::Result<header_chain_proof::Args>> {
    let mut args = args.clone();
    tokio::spawn(async move {
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_secs(initial_delay)) => {}
            _ = cancellation_token.cancelled() => {
                anyhow::bail!("Header chain proof generate task cancelled");
            }
        }

        let builder = HeaderChainProofBuilder::new();
        loop {
            tokio::select! {
                // TODO: handle err and retry
                _ = tokio::time::sleep(Duration::from_secs(interval)) => {
                    let next_task = fetch_latest_long_running_task(&local_db, HeaderChainProofBuilder::name()).await?;
                    if let Some(next_task) = next_task {
                        info!("Header chain's next task: {next_task:?}");
                        args.start = next_task.block_end as usize;
                        args.input_proof = next_task.path_to_proof.unwrap();
                        args.output_proof = format!(
                            "{}/{}-{}.bin",
                            std::path::Path::new(&args.output_proof).parent().unwrap().to_str().unwrap(),
                            args.start,
                            args.batch_size
                        );
                        args.init_input = false;
                    }
                    info!("Header chain proof generate task: generate proof, args: {args:?}");
                    let total_block_headers = match fetch_header_chain(
                        &args.esplora_url,
                        args.start,
                        args.batch_size,
                        &args.block_headers,
                        args.force_fetch,
                    ).await {
                        Ok(data) => data,
                        Err(err) => {
                            tracing::error!("Fetch header blocks error, {err:?}");
                            continue;
                        }
                    };

                    let ctx = Context {
                       request: ProofRequest::HeaderChainProofRequest {
                           init_input: args.init_input,
                           input_proof: args.input_proof.clone(),
                           output_proof: args.output_proof.clone(),
                           start: args.start,
                           batch_size: args.batch_size,
                           total_block_headers,
                       }
                    };
                    let proving_start = tokio::time::Instant::now();
                    let (input, proof, cycles) = builder.build_proof(&ctx).unwrap();
                    let proving_duration = proving_start.elapsed().as_secs_f32() * 1000.0;
                    let zkm_version = proof.zkm_version.clone();
                    builder.save_proof(&ctx, &input, cycles, proof).unwrap();
                    update_long_running_task(&local_db, args.start as u64, args.batch_size as u64, &args.output_proof, cycles, HeaderChainProofBuilder::name(), proving_duration as i64, zkm_version).await?;
                    args = ProofBuilderConfig::run_next(args, HeaderChainProofBuilder::name()).unwrap();
                }
                _ = cancellation_token.cancelled() => {
                    anyhow::bail!("Header chain proof generate task cancelled");
                }
            }
        }
    })
}
