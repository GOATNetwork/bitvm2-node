mod api;
mod proof_tasks;

use crate::proof_tasks::run_gen_proof_tasks;
use clap::{Parser, command};
use futures::future;
use tokio::signal;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tracing_subscriber::EnvFilter;

#[derive(Debug, Parser)]
#[command(author, version, about, long_about = None)]
struct Opts {
    /// Local RPC service address
    #[arg(long, default_value = "0.0.0.0:8080")]
    pub rpc_addr: String,

    /// Local Sqlite database file path
    #[arg(long, default_value = "/tmp/bitvm2-node.db")]
    pub db_path: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenv::dotenv().ok();
    let opt = Opts::parse();
    let _ = tracing_subscriber::fmt().with_env_filter(EnvFilter::from_default_env()).try_init();
    // Create cancellation token for graceful shutdown
    let cancellation_token = CancellationToken::new();
    let local_db = store::create_local_db(&opt.db_path).await;
    let local_db_clone1 = local_db.clone();
    let mut task_handles: Vec<JoinHandle<anyhow::Result<String, String>>> = vec![];
    let cancel_token_clone = cancellation_token.clone();
    let opt_rpc_addr = opt.rpc_addr.clone();
    task_handles.push(tokio::spawn(async move {
        match api::serve(opt_rpc_addr, local_db_clone1, cancel_token_clone).await {
            Ok(tag) => Ok(tag),
            Err(e) => {
                tracing::error!("RPC service error: {}", e);
                Err("rpc_error".to_string())
            }
        }
    }));
    let cancel_token_clone = cancellation_token.clone();
    task_handles.push(tokio::spawn(async move {
        match run_gen_proof_tasks(local_db, 5, cancel_token_clone).await {
            Ok(tag) => Ok(tag),
            Err(e) => {
                tracing::error!("Generate proof tasks error: {}", e);
                Err("Generate error".to_string())
            }
        }
    }));
    // Wait for shutdown signal or any task completion
    let task_count = task_handles.len();
    tokio::select! {
        (result, index, remaining_handles) = future::select_all(task_handles) => {
            // Log the specific failure
            let failure_reason = match &result {
                Ok(Ok(tag)) => {
                    tracing::warn!("Task {} completed unexpectedly: {}", index, tag);
                    "unexpected completion"
                }
                Ok(Err(error)) => {
                    tracing::error!("Task {} failed with business error: {}", index, error);
                    "business error"
                }
                Err(join_error) => {
                    tracing::error!("Task {} failed with join error: {}", index, join_error);
                    "join error"
                }
            };

            tracing::info!("Triggering shutdown due to {} in task {}/{}", failure_reason, index + 1, task_count);

            // Initiate graceful shutdown
            cancellation_token.cancel();

            // Wait a moment for graceful shutdown, then force abort remaining tasks
            tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

            // Force abort any tasks that didn't respond to cancellation
            remaining_handles.into_iter().for_each(|handle| handle.abort());

            tracing::info!("All tasks stopped");

            // Handle panic propagation
            if let Err(join_error) = result && join_error.is_panic() {
                    std::panic::resume_unwind(join_error.into_panic());

            }
        }
        _ = shutdown_signal() => {
            tracing::info!("Received shutdown signal, initiating graceful shutdown...");
            cancellation_token.cancel();

            // Give tasks some time to shutdown gracefully
            tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
            tracing::info!("Graceful shutdown completed");
        }
    }
    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c().await.expect("Failed to install Ctrl+C handler");
    };
    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("Failed to install signal handler")
            .recv()
            .await;
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();
    tokio::select! {
        _ = ctrl_c => {
            tracing::info!("Received Ctrl+C signal, starting graceful shutdown...");
        },
        _ = terminate => {
            tracing::info!("Received SIGTERM signal, starting graceful shutdown...");
        },
    }
}
