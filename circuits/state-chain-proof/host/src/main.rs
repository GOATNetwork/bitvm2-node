#![feature(trim_prefix_suffix)]
use clap::Parser;
use hex::FromHex;
use proof_builder::{Context, ProofBuilder, ProofRequest};

/// The arguments for the cli.
#[derive(Debug, Clone, Parser)]
pub struct Args {
    #[clap(long, env, short, default_value = "https://rpc.testnet3.goat.network")]
    execution_layer_rpc: String,

    #[arg(long, default_value = "blocks.bin")]
    blocks: String,

    #[clap(long, env, default_value_t = false)]
    init_input: bool,

    #[clap(long, env, default_value = "input.bin")]
    input_proof: String,

    #[clap(long, env, default_value = "output.bin")]
    output_proof: String,

    #[clap(long, env, default_value_t = 4)]
    batch_size: u64,

    #[clap(long, env, default_value_t = 0)]
    start: u64,

    #[clap(long, env, default_value = "99f6Dc59fB6B5b13578BeBb223e373Cb817Ac8f6")]
    l2_contract_address: String,

    // https://explorer.testnet3.goat.network/address/0x9F0A61ce47678F43A326dB9F8964C56a924cd3D0?tab=read_write_contract
    #[clap(long, env, value_parser=hex_parse::<4>, default_value = "0xc3342df3")]
    proceed_withdraw_method_id: [u8; 4],
}

pub fn hex_parse<const N: usize>(s: &str) -> Result<[u8; N], String> {
    let mut s = s;
    if s.starts_with("0x") {
        s = &s[2..];
    }
    let b = Vec::from_hex(s).map_err(|e| e.to_string())?;
    b.try_into().map_err(|_| "len must be {N}".to_string())
}

use state_chain_proof::{StateChainProofBuilder, fetch_state_chain};

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
        args.blocks.clone(),
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
    builder.save_proof(&ctx, &input, proof).unwrap();
}
