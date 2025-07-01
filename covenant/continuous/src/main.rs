use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use alloy_provider::{network::Ethereum, Provider};
use clap::Parser;
use cli::Args;
use host_executor::{
    alerting::AlertingClient, create_eth_block_execution_strategy_factory, BlockExecutor,
    EthExecutorComponents, ExecutorComponents, FullExecutor,
};
use logroller::{LogRollerBuilder, Rotation, RotationAge};
use provider::create_provider;
use store::localdb::LocalDB;
use tokio::{sync::Semaphore, task};
use tracing::{error, info, instrument, warn};
use tracing_subscriber::util::SubscriberInitExt;
use zkm_sdk::{include_elf, ProverClient};

mod cli;
mod db;

const LOG_FILE: &str = "continuous.log";
const LOG_FIELS_COUNT: u64 = 2;

#[tokio::main]
async fn main() -> eyre::Result<()> {
    // Initialize the environment variables.
    dotenv::dotenv().ok();

    if std::env::var("RUST_LOG").is_err() {
        std::env::set_var("RUST_LOG", "info");
    }

    let args = Args::parse();

    // Initialize the logger.
    let appender = LogRollerBuilder::new(args.log_dir.as_ref(), LOG_FILE)
        .rotation(Rotation::AgeBased(RotationAge::Daily))
        .max_keep_files(LOG_FIELS_COUNT)
        .build()
        .unwrap();
    let (non_blocking, _guard) = tracing_appender::non_blocking(appender);
    tracing_subscriber::fmt()
        .with_env_filter(
            "continuous=info,host-executor=info,zkm_core_machine=warn,zkm_core_executor=error,zkm_prover=warn",
        )
        .with_writer(non_blocking)
        .with_max_level(tracing::Level::INFO)
        .with_ansi(false)
        .finish()
        .init();

    let config = args.as_config().await?;

    let elf = include_elf!("covenant-guest").to_vec();
    let block_execution_strategy_factory =
        create_eth_block_execution_strategy_factory(&config.genesis, None);

    let local_db = LocalDB::new(&format!("sqlite:{}", args.database_url), true).await;
    let sqlite_db = db::PersistToDB::new(&local_db).await;
    let local_db = Arc::new(local_db);

    let http_provider = create_provider(args.provider.rpc_url.unwrap());
    let alerting_client =
        args.pager_duty_integration_key.map(|key| Arc::new(AlertingClient::new(key)));
    let prover_client = Arc::new(ProverClient::new());

    let executor = Arc::new(
        FullExecutor::<EthExecutorComponents<_>, _>::try_new(
            http_provider,
            elf,
            block_execution_strategy_factory,
            prover_client,
            sqlite_db,
            config,
        )
        .await?,
    );

    let concurrent_executions_semaphore = Arc::new(Semaphore::new(args.max_concurrent_executions));
    let mut block_number = args.block_number;

    let failed = Arc::new(AtomicBool::new(false));

    loop {
        info!("process block: {:?}", block_number);

        let executor = executor.clone();
        let alerting_client = alerting_client.clone();
        let permit = concurrent_executions_semaphore.clone().acquire_owned().await?;
        let local_db = local_db.clone();
        let flag = Arc::clone(&failed);

        task::spawn(async move {
            match process_block(block_number, executor, args.execution_retries).await {
                Ok(_) => info!("Successfully processed block {block_number}"),
                Err(err) => {
                    let error_message = format!("Error executing block {block_number}: {err}");
                    error!("{error_message}");

                    if let Some(alerting_client) = &alerting_client {
                        alerting_client.send_alert(error_message).await;
                    }

                    if let Err(err) = db::task_failed(local_db, block_number, err.to_string()).await
                    {
                        let error_message = format!(
                            "Database error while updating block {block_number} status: {err}",
                        );

                        error!("{error_message}",);

                        if let Some(alerting_client) = &alerting_client {
                            alerting_client.send_alert(error_message).await;
                        }
                    }

                    flag.store(true, Ordering::Relaxed);
                }
            }

            drop(permit);
        });

        if failed.load(Ordering::Relaxed) {
            error!("Exit due to the exit of the child thread");
            return Ok(());
        }

        block_number += 1;
    }
}

#[instrument(skip(executor, max_retries))]
async fn process_block<C, P>(
    number: u64,
    executor: Arc<FullExecutor<C, P>>,
    max_retries: usize,
) -> eyre::Result<()>
where
    C: ExecutorComponents<Network = Ethereum>,
    P: Provider<Ethereum> + Clone,
{
    let mut retry_count = 0;

    // Wait for the block to be available in the HTTP provider
    executor.wait_for_block(number).await?;

    loop {
        match executor.execute(number).await {
            Ok(_) => {
                return Ok(());
            }
            Err(err) => {
                warn!("Failed to execute block {number}: {err}, retrying...");
                retry_count += 1;
                if retry_count > max_retries {
                    error!("Max retries reached for block: {number}");
                    return Err(err);
                }
            }
        }
    }
}
