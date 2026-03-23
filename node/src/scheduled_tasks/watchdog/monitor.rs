use crate::env::get_network;
use crate::scheduled_tasks::graph_maintenance_tasks::{AssertCommitStatus, ChallengeSubStatus};
use client::btc_chain::BTCClient;
use store::localdb::{GraphQuery, LocalDB};
use store::GraphStatus;
use tracing::{info, warn};
use uuid::Uuid;

use bitvm2_lib::challenger::assert_commit_timeout_timelock;
use bitvm2_lib::operator::watchtower_challenge_timeout_timelock;

#[derive(Debug, Clone)]
pub struct LivenessAlert {
    pub graph_id: Uuid,
    pub instance_id: Uuid,
    pub alert_type: AlertType,
    pub blocks_until_timeout: i64,
    pub kickoff_txid: String,
}

#[derive(Debug, Clone)]
pub enum AlertType {
    /// Kickoff confirmed but Assert-Init not detected, approaching WT challenge timeout
    AssertInitMissing,
    /// Assert-Init detected but Assert-Commit not complete, approaching assert timeout
    AssertCommitStall,
}

fn alert_margin_blocks() -> i64 {
    std::env::var("WATCHDOG_ALERT_MARGIN_BLOCKS").ok().and_then(|v| v.parse().ok()).unwrap_or(6)
}

pub async fn scan_stale_challenges(
    local_db: &LocalDB,
    btc_client: &BTCClient,
) -> anyhow::Result<Vec<LivenessAlert>> {
    let current_height = btc_client.get_height().await? as i64;
    let assert_timelock = assert_commit_timeout_timelock(get_network()) as i64;
    let wt_timelock = watchtower_challenge_timeout_timelock(get_network()) as i64;
    let margin = alert_margin_blocks();

    let mut storage = local_db.acquire().await?;
    let (graphs, _) = storage
        .find_graphs(GraphQuery::default().with_status(GraphStatus::Challenge.to_string()))
        .await?;

    info!("watchdog: scanning {} challenge graph(s) at height {}", graphs.len(), current_height);

    let mut alerts = vec![];

    for graph in graphs {
        let sub_status: ChallengeSubStatus =
            serde_json::from_str(&graph.sub_status).unwrap_or_default();

        // Already resolved — skip
        if sub_status.is_disproved() || sub_status.is_all_commit_success() {
            continue;
        }

        let kickoff_txid_str =
            graph.kickoff_txid.as_ref().map(|t| t.0.to_string()).unwrap_or_default();

        // Check: kickoff confirmed but assert-init not yet seen
        if graph.assert_init_txid.is_none() {
            if let Some(ref txid) = graph.kickoff_txid {
                match btc_client.get_tx_status(&txid.0).await {
                    Ok(status) if status.confirmed => {
                        if let Some(height) = status.block_height {
                            let blocks_left = (height as i64 + wt_timelock) - current_height;
                            if blocks_left < margin {
                                alerts.push(LivenessAlert {
                                    graph_id: graph.graph_id,
                                    instance_id: graph.instance_id,
                                    alert_type: AlertType::AssertInitMissing,
                                    blocks_until_timeout: blocks_left,
                                    kickoff_txid: kickoff_txid_str.clone(),
                                });
                            }
                        }
                    }
                    Ok(_) => {} // not confirmed yet
                    Err(e) => {
                        warn!(
                            "watchdog: failed to get kickoff tx status for {}: {e}",
                            graph.graph_id
                        )
                    }
                }
            }
        }

        // Check: assert-init seen but assert-commit stalled
        if sub_status.assert_commit_status == AssertCommitStatus::OperatorInit {
            if let Some(ref txid) = graph.assert_init_txid {
                match btc_client.get_tx_status(&txid.0).await {
                    Ok(status) if status.confirmed => {
                        if let Some(height) = status.block_height {
                            let blocks_left = (height as i64 + assert_timelock) - current_height;
                            if blocks_left < margin {
                                alerts.push(LivenessAlert {
                                    graph_id: graph.graph_id,
                                    instance_id: graph.instance_id,
                                    alert_type: AlertType::AssertCommitStall,
                                    blocks_until_timeout: blocks_left,
                                    kickoff_txid: kickoff_txid_str,
                                });
                            }
                        }
                    }
                    Ok(_) => {}
                    Err(e) => {
                        warn!(
                            "watchdog: failed to get assert_init tx status for {}: {e}",
                            graph.graph_id
                        )
                    }
                }
            }
        }
    }

    Ok(alerts)
}
