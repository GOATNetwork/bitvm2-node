use crate::ProofBuilderConfig;
use crate::task::{ProofState, fetch_on_demand_task, update_watchtower_task};
use proof_builder::{ProofBuilder, ProofRequest};
use std::time::Duration;
use store::localdb::LocalDB;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tracing::info;
use watchtower_proof::{WatchtowerProofBuilder, fetch_target_block};

#[tracing::instrument(level = "info", skip(local_db, cancellation_token))]
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
                    // fetch args from the database by instance id and graph id.
                    let task_index;
                    if let Some(next_task) = fetch_on_demand_task(&local_db, true).await? {
                        args.latest_sequencer_commit_txid = next_task.latest_sequencer_commit_txid;
                        args.header_chain_input_proof = next_task.header_chain_input_proof;
                        args.commit_chain_input_proof = next_task.commit_chain_input_proof;
                        args.state_chain_input_proof = next_task.state_chain_input_proof;
                        args.output = format!("{}/{}.bin",
                            std::path::Path::new(&args.output).parent().unwrap().to_str().unwrap(),
                            next_task.task_index,
                        );
                        task_index = next_task.task_index;
                    } else {
                        tracing::info!("Wait for the next task");
                        tokio::time::sleep(Duration::from_secs(5)).await;
                        continue;
                    };
                    info!("Watchtower proof generate task: generate proof, args: {args:?}");

                    let (block_pos, target_block, latest_sequencer_commit_tx) =
                        match fetch_target_block(&args.esplora_url, &args.latest_sequencer_commit_txid, args.bitcoin_network).await {
                            Ok(data) => data,
                            Err(e) => {
                                tracing::error!("Fetch target block error: {e}");
                                tokio::time::sleep(Duration::from_secs(5)).await;
                                continue;
                            }
                        };
                    let ctx = ProofRequest::WatchtowerProofRequest {
                            genesis_sequencer_commit_txid: args.genesis_sequencer_commit_txid.clone(),
                            latest_sequencer_commit_txid: args.latest_sequencer_commit_txid.clone(),
                            header_chain_input_proof: args.header_chain_input_proof.clone(),
                            commit_chain_input_proof: args.commit_chain_input_proof.clone(),
                            state_chain_input_proof: args.state_chain_input_proof.clone(),
                            output: args.output.clone(),
                            target_block,
                            block_pos,
                            latest_sequencer_commit_tx,
                    };
                    let proving_start = tokio::time::Instant::now();
                    let (cycles, proving_time, public_value_hex, proof_size, proof_state, zkm_version) = match builder.build_proof(&ctx) {
                        Ok((input, proof, cycles, proving_time)) => {
                            let zkm_version = proof.zkm_version.clone();
                            let (public_value_hex, proof_size, proof_state) = match builder.save_proof(&ctx, &input, cycles, proof) {
                                Ok((pvh, pf)) => (pvh, pf, ProofState::Proven),
                                Err(e) => {
                                    tracing::error!("Generate watchtower proof, error: {e:?}");
                                    ("".to_string(), 0, ProofState::Failed)
                                }
                            };
                            (cycles, proving_time, public_value_hex, proof_size, proof_state, zkm_version)
                        },
                        Err(err) => {
                            tracing::error!("Build proof error: {err}");
                            tokio::time::sleep(Duration::from_secs(5)).await;
                            (0u64, 0.0, "".to_string(), 0usize, ProofState::Failed, "".to_string())
                        }
                    };
                    let proving_duration = proving_start.elapsed().as_secs_f32() * 1000.0;
                    let affected = update_watchtower_task(&local_db, task_index, args.output.clone(), public_value_hex, proof_size as i64, cycles, proof_state, proving_duration as i64, proving_time as i64, zkm_version).await?;
                    tracing::info!("update watchtower task: {args:?}, cycles: {cycles}, index: {}, affected row: {affected}", task_index);
                    args = ProofBuilderConfig::run_next(args, WatchtowerProofBuilder::name())?;
                }
                _ = cancellation_token.cancelled() => {
                    anyhow::bail!("Watchtower proof generate task cancelled");
                }
            }
        }
    })
}
