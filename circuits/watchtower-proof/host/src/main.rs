#![feature(trim_prefix_suffix)]
//! Generate watchtower proof
use clap::Parser;
use proof_builder::{Context, ProofBuilder, ProofRequest};
use watchtower_proof::{Args, WatchtowerProofBuilder, fetch_target_block};

#[tokio::main]
async fn main() {
    dotenv::dotenv().ok();
    let args = Args::parse();
    // Setup the logger.
    zkm_sdk::utils::setup_logger();
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
    builder.save_proof(&ctx, &input, cycles, proof).unwrap();
}
