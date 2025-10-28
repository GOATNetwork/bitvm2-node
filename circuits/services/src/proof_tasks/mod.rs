use std::time::Duration;
use store::localdb::LocalDB;
use tokio_util::sync::CancellationToken;
use tracing::info;

pub(crate) async fn run_gen_proof_tasks(
    _local_db: LocalDB,
    interval: u64,
    cancellation_token: CancellationToken,
) -> anyhow::Result<String> {
    loop {
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_secs(interval)) => {
                // Execute the normal monitoring logic
                // TODO add proof generator tasks
                info!("gen proof");
            }
            _ = cancellation_token.cancelled() => {
                tracing::info!("Watch event task received shutdown signal");
                return Ok("watch_shutdown".to_string());
            }
        }
    }
}
