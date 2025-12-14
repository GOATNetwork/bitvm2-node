use std::time::Duration;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tracing::info;
use proof_builder::{ProofBuilder, ProofRequest, Context};
use operator_proof::{fetch_target_block_and_watchtower_tx, OperatorProofBuilder};
use util::hex_parse;

pub(crate) fn spawn_operator_proof_task(
    args: operator_proof::Args,
    interval: u64,
    initial_delay: u64,
    cancellation_token: CancellationToken,
) -> JoinHandle<anyhow::Result<operator_proof::Args>> {
    tokio::spawn(async move {
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_secs(initial_delay)) => {}
            _ = cancellation_token.cancelled() => {
                return Err(anyhow::anyhow!("Operator proof generate task cancelled"));
            }
        }

        loop {
            tokio::select! {
                _ = tokio::time::sleep(Duration::from_secs(interval)) => {
                    info!("Operator proof generate task: generate proof");
                    // TODO: fetch args from the database.
                    let (
                        block_pos,
                        target_block,
                        operator_latest_sequencer_commit_txn,
                        watchtower_challenge_txns,
                        watchtower_challenge_txn_prev_outs,
                        watchtower_challenge_txn_prev_indices,
                        watchtower_challenge_txn_pubkeys,
                        watchtower_challenge_txn_scripts,
                    ) = fetch_target_block_and_watchtower_tx(
                        &args.esplora_url,
                        &args.latest_sequencer_commit_txid,
                        &args.watchtower_challenge_init_txid,
                        &args.watchtower_challenge_txids,
                        &args.watchtower_public_keys,
                    )
                    .await
                    .unwrap();

                    let builder = OperatorProofBuilder::new();

                    let ctx = Context {
                        request: ProofRequest::OperatorProofRequest {
                            included_watchtowers: args.included_watchtowers.clone(),
                            graph_id: hex_parse::<16>(&args.graph_id).unwrap(),
                            genesis_sequencer_commit_txid: args.genesis_sequencer_commit_txid.clone(),

                            header_chain_input_proof: args.header_chain_input_proof.clone(),
                            commit_chain_input_proof: args.commit_chain_input_proof.clone(),
                            state_chain_input_proof: args.state_chain_input_proof.clone(),
                            execution_layer_block_number: args.execution_layer_block_number,

                            output: args.output.clone(),
                            btc_block_headers: args.btc_block_headers.clone(),

                            block_pos,
                            target_block,
                            operator_latest_sequencer_commit_txn,

                            watchtower_challenge_txns,
                            watchtower_challenge_txn_prev_outs,
                            watchtower_challenge_txn_prev_indices,
                            watchtower_challenge_txn_pubkeys,
                            watchtower_challenge_txn_scripts,
                        },
                    };
                    let (input, proof, cycles) = builder.build_proof(&ctx).unwrap();
                    tracing::info!("Operator proof cycles: {cycles}");
                    builder.save_proof(&ctx, &input, proof).unwrap();
                }
                _ = cancellation_token.cancelled() => {
                    return Err(anyhow::anyhow!("Operator proof generate task cancelled"));
                }
            }
        }
    })
}
