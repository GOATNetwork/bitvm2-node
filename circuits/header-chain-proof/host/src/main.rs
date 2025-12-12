//! Generate header chain proof
use header_chain_proof::{HeaderChainProofBuilder, fetch_header_chain};
use proof_builder::{Context, ProofBuilder};

use clap::Parser;

/// The arguments for the cli.
#[derive(Debug, Clone, Parser)]
pub struct Args {
    #[arg(long, default_value = "http://127.0.0.1:3002")]
    esplora_url: String,

    #[clap(long, env, default_value_t = 4)]
    batch_size: usize,

    #[clap(long, env, default_value_t = 0)]
    start: usize,

    #[clap(long, env, default_value_t = false)]
    init_input: bool,

    #[clap(long, env, default_value = "block_headers.bin")]
    block_headers: String,

    #[clap(long, env, default_value = "input_proof.bin")]
    input_proof: String,

    #[clap(long, env, default_value = "output_proof.bin")]
    output_proof: String,

    #[clap(long, default_value_t = false)]
    force_fetch: bool,
}

#[tokio::main]
async fn main() {
    dotenv::dotenv().ok();
    let args = Args::parse();
    // Setup the logger.
    zkm_sdk::utils::setup_logger();

    let total_block_headers = fetch_header_chain(
        &args.esplora_url,
        args.start,
        args.batch_size,
        &args.block_headers,
        args.force_fetch,
    )
    .await;

    let builder = HeaderChainProofBuilder::new();

    let ctx = Context {
        request: proof_builder::ProofRequest::HeaderChainProofRequest {
            init_input: args.init_input,
            input_proof: args.input_proof.clone(),
            output_proof: args.output_proof.clone(),
            start: args.start,
            batch_size: args.batch_size,
            total_block_headers,
        },
    };
    let (input, proof, cycles) = builder.build_proof(&ctx).unwrap();
    tracing::info!("header chain proof cycles: {cycles}");
    builder.save_proof(&ctx, &input, proof).unwrap();
}
