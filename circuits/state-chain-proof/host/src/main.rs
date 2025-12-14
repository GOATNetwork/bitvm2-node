#![feature(trim_prefix_suffix)]
use clap::Parser;
use proof_builder::{Context, ProofBuilder, ProofRequest};

use state_chain_proof::{Args, StateChainProofBuilder, fetch_state_chain};

#[tokio::main]
async fn main() {
    dotenv::dotenv().ok();
    let args = Args::parse();
    tracing::info!("args: {:?}", args);
    // Setup the logger.
    zkm_sdk::utils::setup_logger();
    let blocks = fetch_state_chain(
        &args.l2_contract_address,
        &args.proceed_withdraw_method_id,
        args.start,
        args.batch_size,
        &args.execution_layer_rpc,
        &args.blocks,
    )
    .await;

    let builder = StateChainProofBuilder::new();

    let ctx = Context {
        request: ProofRequest::StateChainProofRequest {
            init_input: args.init_input,
            input_proof: args.input_proof.clone(),
            output_proof: args.output_proof.clone(),
            start: args.start,
            l2_contract_address: args.l2_contract_address.clone(),
            batch_size: args.batch_size,
            blocks,
        },
    };
    let (input, proof, cycles) = builder.build_proof(&ctx).unwrap();
    tracing::info!("header chain proof cycles: {cycles}");
    builder.save_proof(&ctx, &input, cycles, proof).unwrap();
}
