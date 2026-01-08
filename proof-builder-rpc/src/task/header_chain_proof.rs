use header_chain_proof::{HeaderChainProofBuilder, fetch_header_chain};
use proof_builder::{ProofBuilder, ProofRequest};
use std::time::Duration;
use store::localdb::LocalDB;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tracing::info;

use crate::config::ProofBuilderConfig;
use crate::task::{create_long_running_task, fetch_latest_long_running_task};

#[tracing::instrument(level = "info", skip(local_db, cancellation_token))]
pub(crate) fn spawn_header_chain_proof_task(
    args: header_chain_proof::Args,
    local_db: LocalDB,
    interval: u64,
    initial_delay: u64,
    cancellation_token: CancellationToken,
) -> JoinHandle<anyhow::Result<header_chain_proof::Args>> {
    let mut args = args.clone();
    let mut large_interval = interval;
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
                _ = tokio::time::sleep(Duration::from_secs(large_interval)) => {
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
                        args.bitcoin_network,
                    ).await {
                        Ok(data) => data,
                        Err(err) => {
                            tracing::error!("Fetch header blocks error, {err:?}");
                            large_interval = 30;
                            continue;
                        }
                    };
                    large_interval = interval;

                    let ctx =
                       ProofRequest::HeaderChainProofRequest {
                           init_input: args.init_input,
                           input_proof: args.input_proof.clone(),
                           output_proof: args.output_proof.clone(),
                           start: args.start,
                           batch_size: args.batch_size,
                           total_block_headers,
                    };
                    let proving_start = tokio::time::Instant::now();
                    let (input, proof, cycles, proving_time) = match builder.build_proof(&ctx){
                        Ok(d) => d,
                        Err(err) => {
                            tracing::error!("Build proof error: {err}");
                            continue;
                        }
                    };
                    let proving_duration = proving_start.elapsed().as_secs_f32() * 1000.0;
                    let zkm_version = proof.zkm_version.clone();
                    let (public_value_hex, proof_size) = builder.save_proof(&ctx, &input, cycles, proof)?;
                    create_long_running_task(&local_db, args.start as u64, args.batch_size as u64, args.output_proof.clone(), public_value_hex, proof_size as i64, cycles, HeaderChainProofBuilder::name(), proving_duration as i64, proving_time as i64, store::ProofState::Proven, zkm_version).await?;
                    args = ProofBuilderConfig::run_next(args, HeaderChainProofBuilder::name())?;
                }
                _ = cancellation_token.cancelled() => {
                    anyhow::bail!("Header chain proof generate task cancelled");
                }
            }
        }
    })
}
