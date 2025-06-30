use std::sync::{mpsc::sync_channel, Arc};

use clap::Parser;
use cli::Args;
use logroller::{LogRollerBuilder, Rotation, RotationAge};
use store::localdb::LocalDB;
use tracing_subscriber::util::SubscriberInitExt;
use zkm_sdk::{include_elf, ProverClient};

mod cli;
mod db;
mod executor;

use crate::db::*;
use crate::executor::*;

pub const AGGREGATION_ELF: &[u8] = include_elf!("guest-aggregation");

const LOG_FILE: &str = "aggregation.log";
const LOG_FIELS_COUNT: u64 = 2;

#[tokio::main]
async fn main() {
    // Initialize the environment variables.
    dotenv::dotenv().ok();

    if std::env::var("RUST_LOG").is_err() {
        std::env::set_var("RUST_LOG", "info");
    }

    let args = Args::parse();
    assert!(args.block_number > 1, "Block number must be greater than 1");

    // Initialize the logger.
    let appender = LogRollerBuilder::new(args.log_dir.as_ref(), LOG_FILE)
        .rotation(Rotation::AgeBased(RotationAge::Daily))
        .max_keep_files(LOG_FIELS_COUNT)
        .build()
        .unwrap();
    let (non_blocking, _guard) = tracing_appender::non_blocking(appender);
    tracing_subscriber::fmt()
        .with_env_filter(
            "aggregation=info,zkm_core_machine=warn,zkm_core_executor=error,zkm_prover=warn",
        )
        .with_writer(non_blocking)
        .with_ansi(false)
        .finish()
        .init();

    let local_db: LocalDB = LocalDB::new(&format!("sqlite:{}", args.database_url), true).await;
    let local_db = Arc::new(Db::new(Arc::new(local_db)));
    let client = Arc::new(ProverClient::new());

    // Setup the proving and verifying keys.
    let (pk, vk) = client.setup(AGGREGATION_ELF);
    let pk = Arc::new(pk);
    let vk = Arc::new(vk);

    let agg_executor = AggregationExecutor::new(
        local_db.clone(),
        client.clone(),
        pk.clone(),
        vk.clone(),
        args.block_number,
        args.start,
    )
    .await;
    let groth16_executor = Groth16Executor::new(local_db, client, pk, vk).await;

    let (block_number_tx, block_number_rx) = sync_channel::<u64>(20);
    let (input_tx, input_rx) = sync_channel::<AggreationInput>(20);
    let (agg_proof_tx, agg_proof_rx) = sync_channel::<ProofWithPublicValues>(20);
    let (groth16_proof_tx, groth16_proof_rx) = sync_channel::<ProofWithPublicValues>(20);
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
