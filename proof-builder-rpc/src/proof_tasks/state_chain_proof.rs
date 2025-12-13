use crate::ProofBuilderConfig;
use proof_builder::{Context, ProofBuilder, ProofRequest};
use state_chain_proof::{StateChainProofBuilder, fetch_state_chain};
use std::time::Duration;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tracing::info;

pub(crate) fn spawn_state_chain_proof_task(
    args: state_chain_proof::Args,
    interval: u64,
    initial_delay: u64,
    cancellation_token: CancellationToken,
) -> JoinHandle<anyhow::Result<state_chain_proof::Args>> {
    let mut args = args.clone();
    let mut internal = interval;
    tokio::spawn(async move {
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_secs(initial_delay)) => {}
            _ = cancellation_token.cancelled() => {
                return Err(anyhow::anyhow!("state chain proof generate task cancelled"));
            }
        }

        loop {
            tokio::select! {
                _ = tokio::time::sleep(Duration::from_secs(interval)) => {
                    info!("state chain proof generate task: generate proof");
                    let blocks = fetch_state_chain(
                        &args.l2_contract_address,
                        &args.proceed_withdraw_method_id,
                        args.start,
                        args.batch_size,
                        &args.execution_layer_rpc,
                        &args.blocks,
                    )
                    .await;

                    let builder = StateChainProofBuilder::new();

                    let ctx = Context {
                        request: ProofRequest::StateChainProofRequest {
                            init_input: args.init_input,
                            input_proof: args.input_proof.clone(),
                            output_proof: args.output_proof.clone(),
                            start: args.start,
                            l2_contract_address: args.l2_contract_address.clone(),
                            batch_size: args.batch_size,
                            blocks,
                        },
                    };
                    let (input, proof, cycles) = builder.build_proof(&ctx).unwrap();
                    tracing::info!("header chain proof cycles: {cycles}");
                    builder.save_proof(&ctx, &input, proof).unwrap();
                    args = ProofBuilderConfig::save(args).unwrap();
                }
                _ = cancellation_token.cancelled() => {
                    return Err(anyhow::anyhow!("state chain proof generate task cancelled"));
                }
            }
        }
    })
}
