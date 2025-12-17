use crate::task::update_long_running_task;
use crate::{ProofBuilderConfig, task::fetch_latest_long_running_task};
use proof_builder::{Context, ProofBuilder, ProofRequest};
use state_chain_proof::{StateChainProofBuilder, fetch_state_chain};
use std::time::Duration;
use store::localdb::LocalDB;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tracing::info;

#[tracing::instrument(level = "info", skip(cancellation_token))]
pub(crate) fn spawn_state_chain_proof_task(
    args: state_chain_proof::Args,
    local_db: LocalDB,
    interval: u64,
    initial_delay: u64,
    cancellation_token: CancellationToken,
) -> JoinHandle<anyhow::Result<state_chain_proof::Args>> {
    let mut args = args.clone();
    tokio::spawn(async move {
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_secs(initial_delay)) => {}
            _ = cancellation_token.cancelled() => {
                anyhow::bail!("state chain proof generate task cancelled");
            }
        }

        let builder = StateChainProofBuilder::new();
        loop {
            tokio::select! {
                _ = tokio::time::sleep(Duration::from_secs(interval)) => {
                    let next_task = fetch_latest_long_running_task(&local_db, StateChainProofBuilder::name()).await?;
                    if let Some(next_task) = next_task {
                        info!("State chain's next task: {next_task:?}");
                        args.start = next_task.block_end as u64;
                        args.input_proof = next_task.path_to_proof.unwrap();
                        args.output_proof = format!(
                            "{}/{}-{}.bin",
                            std::path::Path::new(&args.output_proof).parent().unwrap().to_str().unwrap(),
                            args.start,
                            args.batch_size
                        );
                        args.init_input = false;
                    }
                    info!("state chain proof generate task: generate proof, args: {args:?}");
                    let blocks = fetch_state_chain(
                        &args.l2_contract_address,
                        &args.proceed_withdraw_method_id,
                        args.start,
                        args.batch_size,
                        &args.execution_layer_rpc,
                        &args.blocks,
                    )
                    .await;

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
                    let proving_start = tokio::time::Instant::now();
                    let (input, proof, cycles) = builder.build_proof(&ctx).unwrap();
                    let proving_duration = proving_start.elapsed().as_secs_f32() * 1000.0;
                    let zkm_version = proof.zkm_version.clone();
                    builder.save_proof(&ctx, &input, cycles, proof).unwrap();
                    update_long_running_task(&local_db, args.start, args.batch_size, &args.output_proof, cycles, StateChainProofBuilder::name(), proving_duration as i64, zkm_version).await?;
                    args = ProofBuilderConfig::run_next(args, StateChainProofBuilder::name()).unwrap();
                }
                _ = cancellation_token.cancelled() => {
                    anyhow::bail!("state chain proof generate task cancelled");
                }
            }
        }
    })
}
