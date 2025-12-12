//! Generate operator proof
use clap::Parser;
use hex::FromHex;

use operator_proof::{OperatorProofBuilder, fetch_target_block_and_watchtower_tx};
use proof_builder::{Context, ProofBuilder, ProofRequest};

pub fn hex_parse(s: &str) -> Result<[u8; 16], String> {
    let mut s = s;
    if s.starts_with("0x") {
        s = &s[2..];
    }
    let b = Vec::from_hex(s).map_err(|e| e.to_string())?;
    b.try_into().map_err(|_| "len must be 16".to_string())
}

/// The arguments for the cli.
#[derive(Debug, Clone, Parser)]
pub struct Args {
    #[arg(long, default_value = "http://127.0.0.1:3002")]
    esplora_url: String,

    #[clap(long, env)]
    included_watchtowers: String,

    #[clap(long, env, value_parser = hex_parse)]
    graph_id: [u8; 16],

    #[clap(long, env)]
    latest_sequencer_commit_txid: String,

    #[clap(long, env)]
    genesis_sequencer_commit_txid: String,

    #[clap(long, env, short)]
    header_chain_input_proof: String,

    #[clap(long, env, short)]
    commit_chain_input_proof: String,

    #[clap(long, env, short)]
    state_chain_input_proof: String,

    #[clap(long, env, short)]
    execution_layer_block_number: u64,

    #[clap(long, env, short, value_delimiter = ',')]
    watchtower_challenge_txids: Vec<String>,

    #[clap(long, env, short, value_delimiter = ',')]
    watchtower_public_keys: Vec<String>,

    #[clap(long, env, short)]
    watchtower_challenge_init_txid: String,

    #[clap(long, env, default_value = "commit-proof.bin")]
    output: String,

    #[clap(long, env, default_value = "data/header-chain/block_headers.bin")]
    btc_block_headers: String,
}

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
    )
    .await
    .unwrap();

    let builder = OperatorProofBuilder::new();

    let ctx = Context {
        request: ProofRequest::OperatorProofRequest {
            included_watchtowers: args.included_watchtowers.clone(),
            graph_id: args.graph_id.clone(),
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
