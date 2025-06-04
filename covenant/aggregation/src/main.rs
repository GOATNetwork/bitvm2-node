use std::sync::{mpsc::sync_channel, Arc};

use clap::Parser;
use cli::Args;
use store::localdb::LocalDB;
use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};
use zkm_sdk::include_elf;

mod cli;
mod db;
mod executor;

use crate::db::*;
use crate::executor::*;

pub const AGGREGATION_ELF: &[u8] = include_elf!("guest-aggregation");

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

    let executor = AggregationExecutor::new(local_db, AGGREGATION_ELF).await;

    let (block_number_tx, block_number_rx) = sync_channel::<u64>(2);
    let (input_tx, input_rx) = sync_channel::<AggreationInput>(1);
    let (proof_tx, proof_rx) = sync_channel::<ProofWithPublicValues>(1);
    let executor_clone = executor.clone();

    block_number_tx.send(args.block_number).unwrap();

    let handle1 =
        tokio::spawn(executor_clone.data_preparer(block_number_rx, input_tx.clone(), proof_rx));
    let handle2 = tokio::spawn(executor.proof_aggregator(
        block_number_tx.clone(),
        input_rx,
        proof_tx.clone(),
    ));

    let _ = tokio::join!(handle1, handle2);
}
