pub mod alert;
pub mod monitor;

use alert::{dispatch_alerts, AlertConfig};
use client::btc_chain::BTCClient;
use monitor::scan_stale_challenges;
use std::sync::Arc;
use std::time::Duration;
use store::localdb::LocalDB;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

pub async fn run_watchdog_task(
    local_db: LocalDB,
    btc_client: Arc<BTCClient>,
    interval_secs: u64,
    cancellation_token: CancellationToken,
) -> anyhow::Result<String> {
    let alert_config = AlertConfig::from_env();
    info!("watchdog: starting challenger liveness monitor (interval={}s)", interval_secs);

    loop {
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_secs(interval_secs)) => {
                match scan_stale_challenges(&local_db, &btc_client).await {
                    Ok(alerts) if !alerts.is_empty() => {
                        warn!("watchdog: {} liveness alert(s) detected", alerts.len());
                        dispatch_alerts(alerts, &alert_config).await;
                    }
                    Ok(_) => info!("watchdog: all challenge graphs healthy"),
                    Err(e) => warn!("watchdog: scan error: {e}"),
                }
            }
            _ = cancellation_token.cancelled() => {
                info!("watchdog: received shutdown signal");
                return Ok("watchdog_shutdown".to_string());
            }
        }
    }
}
