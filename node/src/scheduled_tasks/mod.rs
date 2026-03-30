mod event_watch_task;
pub mod graph_maintenance_tasks;
pub mod instance_maintenance_tasks;
mod node_maintenance_tasks;
mod sequencer_set_hash_monitor_task;
mod spv_maintenance_tasks;

use crate::action::GOATMessageContent;
use crate::env::{get_maintenance_run_timeout_secs, is_enable_update_spv_contract, is_relayer};
use crate::scheduled_tasks::graph_maintenance_tasks::{
    detect_init_withdraw_call, detect_kickoff, detect_take1_or_challenge, process_graph_challenge,
};
use crate::scheduled_tasks::instance_maintenance_tasks::{
    instance_answers_monitor, instance_bridge_out_monitor, instance_btc_tx_monitor,
    instance_committee_key_cleanup_monitor, instance_expiration_monitor,
    instance_window_expiration_monitor,
};
use crate::scheduled_tasks::node_maintenance_tasks::node_available_pbtc_update_monitor;
use crate::scheduled_tasks::spv_maintenance_tasks::spv_header_hash_update;
use bitvm2_lib::actors::Actor;
use client::btc_chain::BTCClient;
use client::goat_chain::GOATClient;
pub use event_watch_task::{is_processing_gateway_history_events, run_watch_event_task};
pub use sequencer_set_hash_monitor_task::run_sequencer_set_hash_monitor_task;
use std::sync::Arc;
use std::time::{Duration, Instant};
use store::localdb::{LocalDB, StorageProcessor};
use store::{Graph, MessageType};
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};

async fn fetch_on_turn_graph_by_status<'a>(
    storage_processor: &mut StorageProcessor<'a>,
    graph_status: &str,
) -> anyhow::Result<Vec<Graph>> {
    let graphs_ori =
        storage_processor.find_graphs_by_status_group_by_operator(graph_status).await?;
    let mut graphs: Vec<Graph> = vec![];
    let mut pre_operator_pubkey = "".to_string();
    // Only process one graph for each operator each time
    for graph in graphs_ori {
        if graph.operator_pubkey != pre_operator_pubkey {
            pre_operator_pubkey = graph.operator_pubkey.clone();
            graphs.push(graph);
        }
    }
    Ok(graphs)
}
async fn run(
    actor: Actor,
    local_db: &LocalDB,
    btc_client: Arc<BTCClient>,
    goat_client: Arc<GOATClient>,
) -> anyhow::Result<()> {
    let btc_client = btc_client.as_ref();
    let goat_client = goat_client.as_ref();

    if (actor == Actor::Operator || is_relayer())
        && let Err(err) = node_available_pbtc_update_monitor(local_db, goat_client).await
    {
        warn!("node_available_pbtc_update_monitor, err {:?}", err)
    }

    if is_enable_update_spv_contract()
        && let Err(err) = spv_header_hash_update(btc_client, goat_client).await
    {
        warn!("spv_header_hash_update, err {:?}", err)
    }

    if is_processing_gateway_history_events(local_db, goat_client).await? {
        warn!("Still in history events processing");
        return Ok(());
    }

    if let Err(err) = instance_answers_monitor(local_db, btc_client, goat_client).await {
        warn!("instance_answers_monitor, err {:?}", err)
    }
    if let Err(err) = instance_window_expiration_monitor(local_db, goat_client).await {
        warn!("instance_window_expiration_monitor, err {:?}", err)
    }

    if let Err(err) = instance_expiration_monitor(local_db, btc_client).await {
        warn!("instance_expiration_monitor, err {:?}", err)
    }

    if let Err(err) = instance_btc_tx_monitor(local_db, btc_client).await {
        warn!("instance_btc_tx_monitor, err {:?}", err)
    }

    if let Err(err) = instance_committee_key_cleanup_monitor(local_db, btc_client).await {
        warn!("instance_committee_key_cleanup_monitor, err {:?}", err)
    }

    if let Err(err) = instance_bridge_out_monitor(local_db).await {
        warn!("instance_bridge_out_monitor, err {:?}", err)
    }

    if let Err(err) = detect_init_withdraw_call(local_db).await {
        warn!("detect_init_withdraw_call, err {:?}", err)
    }

    if let Err(err) = detect_kickoff(local_db, btc_client).await {
        warn!("detect_kickoff, err {:?}", err)
    }

    if let Err(err) = detect_take1_or_challenge(local_db, btc_client).await {
        warn!("detect_take1_or_challenge, err {:?}", err)
    }

    if let Err(err) = process_graph_challenge(local_db, btc_client).await {
        warn!("process_grpah_challenge, err {:?}", err)
    }
    Ok(())
}

pub async fn run_maintenance_tasks(
    actor: Actor,
    local_db: LocalDB,
    btc_client: Arc<BTCClient>,
    goat_client: Arc<GOATClient>,
    interval: u64,
    cancellation_token: CancellationToken,
) -> anyhow::Result<String> {
    let mut tick: u64 = 0;
    let maintenance_run_timeout = Duration::from_secs(get_maintenance_run_timeout_secs());
    loop {
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_secs(interval)) => {
                tick += 1;
                let tick_start = Instant::now();
                info!(tick, interval_secs = interval, "maintenance task tick start");
                // Execute the normal monitoring logic
                match tokio::time::timeout(
                    maintenance_run_timeout,
                    run(actor.clone(),&local_db,btc_client.clone(),goat_client.clone()),
                ).await {
                    Ok(Ok(_)) => {}
                    Ok(Err(err)) => {error!("run_scheduled_tasks, err {:?}", err)}
                    Err(_) => {
                        error!(
                            tick,
                            timeout_secs = maintenance_run_timeout.as_secs(),
                            "maintenance run timeout"
                        )
                    }
                }
                info!(tick, elapsed_ms = tick_start.elapsed().as_millis() as u64, "maintenance task tick end");
            }
            _ = cancellation_token.cancelled() => {
                tracing::info!("maintenance task received shutdown signal");
                return Ok("maintenance_shutdown".to_string());
            }
        }
    }
}

pub fn get_goat_message_content_type(content: &GOATMessageContent) -> MessageType {
    match content {
        GOATMessageContent::PeginRequest(_) => MessageType::PeginRequest,
        GOATMessageContent::CreateGraph(_) => MessageType::CreateGraph,
        GOATMessageContent::ConfirmInstance(_) => MessageType::ConfirmInstance,
        GOATMessageContent::NonceGeneration(_) => MessageType::NonceGeneration,
        GOATMessageContent::CommitteePresign(_) => MessageType::CommitteePresign,
        GOATMessageContent::GraphFinalize(_) => MessageType::GraphFinalize,
        GOATMessageContent::EndorseGraph(_) => MessageType::EndorseGraph,
        GOATMessageContent::PeginConfirmNonce(_) => MessageType::PeginConfirmNonce,
        GOATMessageContent::PeginConfirmPartialSig(_) => MessageType::PeginConfirmPartialSig,
        GOATMessageContent::PostReady(_) => MessageType::PostReady,
        GOATMessageContent::KickoffReady(_) => MessageType::KickoffReady,
        GOATMessageContent::KickoffSent(_) => MessageType::KickoffSent,
        GOATMessageContent::PreKickoffSent(_) => MessageType::PreKickoffSent,
        GOATMessageContent::ChallengeSent(_) => MessageType::ChallengeSent,
        GOATMessageContent::WatchtowerChallengeInitSent(_) => {
            MessageType::WatchtowerChallengeInitSent
        }
        GOATMessageContent::WatchtowerChallengeSent(_) => MessageType::WatchtowerChallengeSent,
        GOATMessageContent::WatchtowerChallengeTimeout(_) => {
            MessageType::WatchtowerChallengeTimeout
        }
        GOATMessageContent::OperatorAckTimeout(_) => MessageType::OperatorAckTimeout,
        GOATMessageContent::OperatorCommitBlockHashReady(_) => {
            MessageType::OperatorCommitBlockHashReady
        }
        GOATMessageContent::OperatorCommitBlockHashTimeout(_) => {
            MessageType::OperatorCommitBlockHashTimeout
        }
        GOATMessageContent::AssertInitReady(_) => MessageType::AssertInitReady,
        GOATMessageContent::AssertCommitTimeout(_) => MessageType::AssertCommitTimeout,
        GOATMessageContent::DisproveReady(_) => MessageType::DisproveReady,
        GOATMessageContent::DisproveSent(_) => MessageType::DisproveSent,
        GOATMessageContent::Take1Ready(_) => MessageType::Take1Ready,
        GOATMessageContent::Take1Sent(_) => MessageType::Take1Sent,
        GOATMessageContent::Take2Ready(_) => MessageType::Take2Ready,
        GOATMessageContent::Take2Sent(_) => MessageType::Take2Sent,
        GOATMessageContent::RequestNodeInfo(_) => MessageType::RequestNodeInfo,
        GOATMessageContent::ResponseNodeInfo(_) => MessageType::ResponseNodeInfo,
        GOATMessageContent::SyncGraphRequest(_) => MessageType::SyncGraphRequest,
        GOATMessageContent::SyncGraph(_) => MessageType::SyncGraph,
        GOATMessageContent::InstanceDiscarded(_) => MessageType::InstanceDiscarded,
        GOATMessageContent::Tick => MessageType::Tick,
    }
}

fn get_timestamp_from_contract_data(input: &[u8; 32]) -> i64 {
    let mut timestamp_bytes = [0u8; 8];
    timestamp_bytes.copy_from_slice(&input[24..32]);
    i64::from_be_bytes(timestamp_bytes)
}
