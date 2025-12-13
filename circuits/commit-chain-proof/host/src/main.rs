//! Generate commit chain proof
use clap::Parser;
use commit_chain_proof::{CommitChainProofBuilder, fetch_commit_chain};
use proof_builder::{Context, ProofBuilder, ProofRequest};

/// The arguments for the cli.
#[derive(Debug, Clone, Parser)]
pub struct Args {
    #[arg(long, default_value = "http://127.0.0.1:3002")]
    esplora_url: String,

    #[arg(long, env)]
    commit_info: String,

    #[arg(long, default_value = "commits.bin")]
    commits: String,

    #[clap(long, env, default_value_t = false)]
    init_input: bool,

    #[clap(long, env, default_value = "input.bin")]
    input_proof: String,

    #[clap(long, env, default_value = "output.bin")]
    output_proof: String,
}

#[tokio::main]
async fn main() {
    dotenv::dotenv().ok();
    let args = Args::parse();
    tracing::info!("args: {:?}", args);
    fetch_commit_chain(&args.esplora_url, &args.commit_info, &args.commits).await;
    // Setup the logger.
    zkm_sdk::utils::setup_logger();

    let builder = CommitChainProofBuilder::new();

    let ctx = Context {
        request: ProofRequest::CommitChainProofRequest {
            init_input: args.init_input,
            input_proof: args.input_proof.clone(),
            output_proof: args.output_proof.clone(),
            commit_info: args.commit_info.clone(),
            commits: args.commits.clone(),
        },
    };
    let (input, proof, cycles) = builder.build_proof(&ctx).unwrap();
    tracing::info!("commit chain proof cycles: {cycles}");
    builder.save_proof(&ctx, &input, proof).unwrap();
}
