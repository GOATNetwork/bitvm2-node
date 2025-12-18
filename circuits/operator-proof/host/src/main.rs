//! Generate operator proof
use clap::Parser;
use operator_proof::{Args, OperatorProofBuilder, fetch_target_block_and_watchtower_tx};
use proof_builder::{ProofBuilder, ProofRequest};
use util::hex_parse;

#[tokio::main]
async fn main() {
    dotenv::dotenv().ok();
    let args = Args::parse();
    // Setup the logger.
    zkm_sdk::utils::setup_logger();

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
        args.btc_network,
    )
    .await
    .unwrap();

    let builder = OperatorProofBuilder::new();

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
    let (input, proof, cycles) = builder.build_proof(&ctx).unwrap();
    tracing::info!("Operator proof cycles: {cycles}");
    builder.save_proof(&ctx, &input, cycles, proof).unwrap();
}
