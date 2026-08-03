//! Generate commit chain proof
use clap::Parser;
use commit_chain_proof::{Args, CommitChainProofBuilder, fetch_commit_chain, load_upgrade_commits};
use proof_builder::{ProofBuilder, ProofRequest};

#[tokio::main]
async fn main() {
    dotenv::dotenv().ok();
    let args = Args::parse();
    // Setup the logger.
    zkm_sdk::utils::setup_logger();
    tracing::info!("args: {:?}", args);

    let builder = CommitChainProofBuilder::new();
    if args.print_program_id {
        println!("{}", hex::encode(builder.program_id().unwrap()));
        return;
    }

    let mut commits = fetch_commit_chain(
        &args.esplora_url,
        &args.commit_info,
        &args.commits,
        args.bitcoin_network,
    )
    .await
    .unwrap();
    if let Some(path) = args.upgrade_commits.as_deref() {
        commits = load_upgrade_commits(path, &commits[0]).unwrap();
    }
    let ctx = ProofRequest::CommitChainProofRequest {
        init_input: args.starts_from_genesis(),
        input_proof: args.input_proof.clone(),
        output_proof: args.output_proof.clone(),
        commit_info: args.commit_info.clone(),
        commits,
    };
    let (input, proof, cycles, _) = builder.build_proof(&ctx).unwrap();
    tracing::info!("commit chain proof cycles: {cycles}");
    builder.save_proof(&ctx, &input, cycles, proof).unwrap();
}
