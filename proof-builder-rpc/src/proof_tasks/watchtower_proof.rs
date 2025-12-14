use std::time::Duration;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tracing::info;
use proof_builder::{Context, ProofBuilder, ProofRequest};
use watchtower_proof::{WatchtowerProofBuilder, fetch_target_block};

pub(crate) fn spawn_watchtower_proof_task(
    args: watchtower_proof::Args,
    interval: u64,
    initial_delay: u64,
    cancellation_token: CancellationToken,
) -> JoinHandle<anyhow::Result<watchtower_proof::Args>> {
    tokio::spawn(async move {
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_secs(initial_delay)) => {}
            _ = cancellation_token.cancelled() => {
                return Err(anyhow::anyhow!("Watchtower proof generate task cancelled"));
            }
        }

        loop {
            tokio::select! {
                _ = tokio::time::sleep(Duration::from_secs(interval)) => {
                    info!("Watchtower proof generate task: generate proof");
                    // TODO: fetch args from the database.
                    let (block_pos, target_block, latest_sequencer_commit_tx) =
                        fetch_target_block(&args.esplora_url, &args.latest_sequencer_commit_txid).await.unwrap();
                    let builder = WatchtowerProofBuilder::new();

                    let ctx = Context {
                        request: ProofRequest::WatchtowerProofRequest {
                            genesis_sequencer_commit_txid: args.genesis_sequencer_commit_txid.clone(),
                            latest_sequencer_commit_txid: args.latest_sequencer_commit_txid.clone(),
                            header_chain_input_proof: args.header_chain_input_proof.clone(),
                            commit_chain_input_proof: args.commit_chain_input_proof.clone(),
                            state_chain_input_proof: args.state_chain_input_proof.clone(),
                            output: args.output.clone(),
                            btc_block_headers: args.btc_block_headers.clone(),
                            target_block,
                            block_pos,
                            latest_sequencer_commit_tx,
                        },
                    };
                    let (input, proof, cycles) = builder.build_proof(&ctx).unwrap();
                    tracing::info!("Watchtower proof cycles: {cycles}");
                    builder.save_proof(&ctx, &input, proof).unwrap();
                }
                _ = cancellation_token.cancelled() => {
                    return Err(anyhow::anyhow!("Watchtower proof generate task cancelled"));
                }
            }
        }
    })
}
