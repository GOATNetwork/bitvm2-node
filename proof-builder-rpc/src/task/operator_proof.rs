use crate::{
    config::ProofBuilderConfig,
    task::{fetch_on_demand_task, update_operator_task},
};
use operator_proof::{OperatorProofBuilder, fetch_target_block_and_watchtower_tx};
use proof_builder::{ProofBuilder, ProofRequest};
use std::time::Duration;
use store::localdb::LocalDB;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tracing::info;
use util::hex_parse;

#[tracing::instrument(level = "info", skip(cancellation_token))]
pub(crate) fn spawn_operator_proof_task(
    args: operator_proof::Args,
    local_db: LocalDB,
    interval: u64,
    initial_delay: u64,
    cancellation_token: CancellationToken,
) -> JoinHandle<anyhow::Result<operator_proof::Args>> {
    let mut args = args.clone();
    tokio::spawn(async move {
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_secs(initial_delay)) => {}
            _ = cancellation_token.cancelled() => {
                anyhow::bail!("Operator proof generate task cancelled");
            }
        }

        let builder = OperatorProofBuilder::new();
        loop {
            tokio::select! {
                _ = tokio::time::sleep(Duration::from_secs(interval)) => {
                    // fetch args from the database.
                    if let Some(next_task) = fetch_on_demand_task(&local_db, args.index, false).await? {
                        args.latest_sequencer_commit_txid = next_task.latest_sequencer_commit_txid;
                        args.header_chain_input_proof = next_task.header_chain_input_proof;
                        args.commit_chain_input_proof = next_task.commit_chain_input_proof;
                        args.state_chain_input_proof = next_task.state_chain_input_proof;
                        args.watchtower_challenge_init_txid = next_task.watchtower_challenge_init_txid.unwrap().clone();
                        args.watchtower_challenge_txids = next_task.watchtower_challenge_txids.unwrap().join(",");
                        args.watchtower_public_keys = next_task.watchtower_public_keys.unwrap().join(",");
                    } else {
                        tracing::info!("Wait for the next task");
                        continue;
                    };
                    info!("Operator proof generate task: generate proof, args: {args:?}");

                    let (
                        block_pos,
                        target_block,
                        operator_latest_sequencer_commit_txn,
                        watchtower_challenge_txns,
                        watchtower_challenge_txn_prev_outs,
                        watchtower_challenge_txn_prev_indices,
                        watchtower_challenge_txn_pubkeys,
                        watchtower_challenge_txn_scripts,
                    ) = match fetch_target_block_and_watchtower_tx(
                        &args.esplora_url,
                        &args.latest_sequencer_commit_txid,
                        &args.watchtower_challenge_init_txid,
                        &args.watchtower_challenge_txids,
                        &args.watchtower_public_keys,
                        args.btc_network,
                    )
                    .await {
                        Ok(data) => data,
                        Err(err) => {
                            tracing::error!("Fetch target block and watchtower txns error, {err:?}");
                            continue;
                        }
                    };
                    let ctx = ProofRequest::OperatorProofRequest {
                        included_watchtowers: args.included_watchtowers.clone(),
                            graph_id: hex_parse::<16>(&args.graph_id).unwrap(),
                            genesis_sequencer_commit_txid: args.genesis_sequencer_commit_txid.clone(),

                            header_chain_input_proof: args.header_chain_input_proof.clone(),
                            commit_chain_input_proof: args.commit_chain_input_proof.clone(),
                            state_chain_input_proof: args.state_chain_input_proof.clone(),
                            execution_layer_block_number: args.execution_layer_block_number,

                            output: args.output.clone(),

                            block_pos,
                            target_block,
                            operator_latest_sequencer_commit_txn,

                            watchtower_challenge_txns,
                            watchtower_challenge_txn_prev_outs,
                            watchtower_challenge_txn_prev_indices,
                            watchtower_challenge_txn_pubkeys,
                            watchtower_challenge_txn_scripts,
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
                    let (public_value_hex, proof_size) = builder.save_proof(&ctx, &input, cycles, proof)?;
                    update_operator_task(&local_db, args.index, args.output.clone(), public_value_hex, proof_size as i64, cycles, proving_duration as i64, zkm_version).await?;
                    args = ProofBuilderConfig::run_next(args, OperatorProofBuilder::name())?;

                }
                _ = cancellation_token.cancelled() => {
                    anyhow::bail!("Operator proof generate task cancelled");
                }
            }
        }
    })
}
