use crate::ProofBuilderConfig;
use crate::task::{fetch_on_demand_task, update_watchtower_task};
use proof_builder::{Context, ProofBuilder, ProofRequest};
use std::time::Duration;
use store::localdb::LocalDB;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tracing::info;
use watchtower_proof::{WatchtowerProofBuilder, fetch_target_block};

#[tracing::instrument(level = "info", skip(cancellation_token))]
pub(crate) fn spawn_watchtower_proof_task(
    args: watchtower_proof::Args,
    local_db: LocalDB,
    interval: u64,
    initial_delay: u64,
    cancellation_token: CancellationToken,
) -> JoinHandle<anyhow::Result<watchtower_proof::Args>> {
    let mut args = args.clone();
    tokio::spawn(async move {
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_secs(initial_delay)) => {}
            _ = cancellation_token.cancelled() => {
                anyhow::bail!("Watchtower proof generate task cancelled");
            }
        }

        let builder = WatchtowerProofBuilder::new();
        loop {
            tokio::select! {
                _ = tokio::time::sleep(Duration::from_secs(interval)) => {
                    info!("Watchtower proof generate task: generate proof");
                    // fetch args from the database by instance id and graph id.
                    let next_task = fetch_on_demand_task(&local_db, args.index, true).await.unwrap();

                    args.latest_sequencer_commit_txid = next_task.latest_sequencer_commit_txid;
                    args.header_chain_input_proof = next_task.header_chain_input_proof;
                    args.commit_chain_input_proof = next_task.commit_chain_input_proof;
                    args.state_chain_input_proof = next_task.state_chain_input_proof;

                    let (block_pos, target_block, latest_sequencer_commit_tx) =
                        match fetch_target_block(&args.esplora_url, &args.latest_sequencer_commit_txid).await {
                            Ok(data) => data,
                            Err(e) => {
                                tracing::error!("Fetch target block error: {e}");
                                continue;
                            }
                        };
                    let ctx = Context {
                        request: ProofRequest::WatchtowerProofRequest {
                            genesis_sequencer_commit_txid: args.genesis_sequencer_commit_txid.clone(),
                            latest_sequencer_commit_txid: args.latest_sequencer_commit_txid.clone(),
                            header_chain_input_proof: args.header_chain_input_proof.clone(),
                            commit_chain_input_proof: args.commit_chain_input_proof.clone(),
                            state_chain_input_proof: args.state_chain_input_proof.clone(),
                            output: args.output.clone(),
                            target_block,
                            block_pos,
                            latest_sequencer_commit_tx,
                        },
                    };
                    let proving_start = tokio::time::Instant::now();
                    let (input, proof, cycles) = match builder.build_proof(&ctx) {
                        Ok(data) => data,
                        Err(e) => {
                            tracing::error!("build proof error, {e}");
                            continue;
                        }
                    };
                    let proving_duration = proving_start.elapsed().as_secs_f32() * 1000.0;
                    let zkm_version = proof.zkm_version.clone();
                    builder.save_proof(&ctx, &input, cycles, proof)?;
                    update_watchtower_task(&local_db, args.index, &args.output, cycles, proving_duration as i64, zkm_version).await?;
                    args = ProofBuilderConfig::run_next(args, WatchtowerProofBuilder::name())?;
                }
                _ = cancellation_token.cancelled() => {
                    anyhow::bail!("Watchtower proof generate task cancelled");
                }
            }
        }
    })
}
