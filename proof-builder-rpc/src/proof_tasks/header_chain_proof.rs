use header_chain_proof::{HeaderChainProofBuilder, fetch_header_chain};
use proof_builder::{ArgsRotator, Context, ProofBuilder, ProofRequest};
use std::time::Duration;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tracing::info;

use crate::config::ProofBuilderConfig;

pub(crate) fn spawn_header_chain_proof_task(
    args: header_chain_proof::Args,
    interval: u64,
    initial_delay: u64,
    cancellation_token: CancellationToken,
) -> JoinHandle<anyhow::Result<header_chain_proof::Args>> {
    let mut args = args.clone();
    let mut internal = interval;
    tokio::spawn(async move {
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_secs(initial_delay)) => {}
            _ = cancellation_token.cancelled() => {
                return Err(anyhow::anyhow!("Header chain proof generate task cancelled"));
            }
        }

        loop {
            tokio::select! {
                // TODO: handle err and retry
                _ = tokio::time::sleep(Duration::from_secs(interval)) => {
                    info!("Header chain proof generate task: generate proof");
                    let total_block_headers = fetch_header_chain(
                        &args.esplora_url,
                        args.start,
                        args.batch_size,
                        &args.block_headers,
                        args.force_fetch,
                    ).await;

                    let builder = HeaderChainProofBuilder::new();

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
                    let (input, proof, cycles) = builder.build_proof(&ctx).unwrap();
                    tracing::info!("header chain proof cycles: {cycles}");
                    builder.save_proof(&ctx, &input, proof).unwrap();
                    args = ProofBuilderConfig::save(args).unwrap();
                }
                _ = cancellation_token.cancelled() => {
                    return Err(anyhow::anyhow!("Header chain proof generate task cancelled"));
                }
            }
        }
    })
}
