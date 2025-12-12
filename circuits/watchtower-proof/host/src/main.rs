#![feature(trim_prefix_suffix)]
//! Generate watchtower proof
use proof_builder::{Context, ProofBuilder, ProofRequest};

use clap::Parser;

use watchtower_proof::{WatchtowerProofBuilder, fetch_target_block};

// The arguments for the cli.
#[derive(Debug, Clone, Parser)]
pub struct Args {
    #[arg(long, default_value = "http://127.0.0.1:3002")]
    esplora_url: String,

    #[clap(long, env)]
    genesis_sequencer_commit_txid: String,

    #[clap(long, env)]
    latest_sequencer_commit_txid: String,

    #[clap(long, env, short)]
    header_chain_input_proof: String,

    #[clap(long, env, short)]
    commit_chain_input_proof: String,

    #[clap(long, env, short)]
    state_chain_input_proof: String,

    #[clap(long, env)]
    output: String,

    #[clap(long, env, default_value = "data/header-chain/block_headers.bin")]
    block_headers: String,
}

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
            block_headers: args.block_headers.clone(),
            target_block,
            block_pos,
            latest_sequencer_commit_tx,
        },
    };
    let (input, proof, cycles) = builder.build_proof(&ctx).unwrap();
    tracing::info!("Watchtower proof cycles: {cycles}");
    builder.save_proof(&ctx, &input, proof).unwrap();
}
