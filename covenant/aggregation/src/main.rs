use std::sync::{mpsc::sync_channel, Arc};

use clap::Parser;
use cli::Args;
use store::localdb::LocalDB;
use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};
use zkm_sdk::{include_elf, ProverClient, ZKMVerifyingKey};

mod cli;
mod db;
mod executor;

use crate::db::*;
use crate::executor::*;

pub const AGGREGATION_ELF: &[u8] = include_elf!("guest-aggregation");
pub const GROTH16_ELF: &[u8] = include_elf!("guest-groth16");

#[tokio::main]
async fn main() {
    // Initialize the environment variables.
    dotenv::dotenv().ok();

    if std::env::var("RUST_LOG").is_err() {
        std::env::set_var("RUST_LOG", "info");
    }

    // Initialize the logger.
    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(
            EnvFilter::from_default_env()
                .add_directive("zkm_core_machine=warn".parse().unwrap())
                .add_directive("zkm_core_executor=warn".parse().unwrap())
                .add_directive("zkm_prover=warn".parse().unwrap()),
        )
        .init();

    let args = Args::parse();

    let local_db: LocalDB = LocalDB::new(&format!("sqlite:{}", args.database_url), true).await;
    let local_db = Arc::new(Db::new(Arc::new(local_db)));
    let client = Arc::new(ProverClient::new());

    let agg_executor =
        AggregationExecutor::new(local_db.clone(), client.clone(), AGGREGATION_ELF).await;
    let groth16_executor = Groth16Executor::new(local_db, client, GROTH16_ELF).await;

    let (block_number_tx, block_number_rx) = sync_channel::<u64>(2);
    let (input_tx, input_rx) = sync_channel::<AggreationInput>(1);
    let (agg_proof_tx, agg_proof_rx) = sync_channel::<ProofWithPublicValues>(1);
    let (groth16_proof_tx, groth16_proof_rx) =
        sync_channel::<(ProofWithPublicValues, Arc<ZKMVerifyingKey>)>(1);
    let agg_executor_clone = agg_executor.clone();

    block_number_tx.send(args.block_number).unwrap();

    let handle1 =
        tokio::spawn(agg_executor_clone.data_preparer(block_number_rx, input_tx, agg_proof_rx));
    let handle2 = tokio::spawn(agg_executor.proof_aggregator(
        block_number_tx,
        input_rx,
        agg_proof_tx,
        groth16_proof_tx,
    ));
    let handle3 = tokio::spawn(groth16_executor.proof_generator(groth16_proof_rx));

    let _ = tokio::join!(handle1, handle2, handle3);
}
