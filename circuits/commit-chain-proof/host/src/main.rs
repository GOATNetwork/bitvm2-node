//! Generate commit chain proof
use clap::Parser;
use commit_chain_proof::{Args, CommitChainProofBuilder, fetch_commit_chain};
use proof_builder::{ProofBuilder, ProofRequest};

#[tokio::main]
async fn main() {
    dotenv::dotenv().ok();
    let args = Args::parse();
    tracing::info!("args: {:?}", args);
    // Setup the logger.
    zkm_sdk::utils::setup_logger();

    let commits = fetch_commit_chain(
        &args.esplora_url,
        &args.commit_info,
        &args.commits,
        args.start,
        args.batch_size,
        args.btc_network,
    )
    .await
    .unwrap();
    let builder = CommitChainProofBuilder::new();

    let ctx = ProofRequest::CommitChainProofRequest {
        init_input: args.init_input,
        input_proof: args.input_proof.clone(),
        output_proof: args.output_proof.clone(),
        commit_info: args.commit_info.clone(),
        commits,
    };
    let (input, proof, cycles, _) = builder.build_proof(&ctx).unwrap();
    tracing::info!("commit chain proof cycles: {cycles}");
    builder.save_proof(&ctx, &input, cycles, proof).unwrap();
}
