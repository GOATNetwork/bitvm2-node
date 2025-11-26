use std::time::Duration;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tracing::info;

pub(crate) fn spawn_header_chain_proof_task(
    interval: u64,
    initial_delay: u64,
    cancellation_token: CancellationToken,
) -> JoinHandle<anyhow::Result<()>> {
    tokio::spawn(async move {
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_secs(initial_delay)) => {}
            _ = cancellation_token.cancelled() => {
                return Err(anyhow::anyhow!("Header chain proof generate task cancelled"));
            }
        }

        loop {
            tokio::select! {
                _ = tokio::time::sleep(Duration::from_secs(interval)) => {
                    info!("Header chain proof generate task: generate proof");
                }
                _ = cancellation_token.cancelled() => {
                    return Err(anyhow::anyhow!("Header chain proof generate task cancelled"));
                }
            }
        }
    })
}
