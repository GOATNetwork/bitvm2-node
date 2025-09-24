mod event_watch_task;
pub mod graph_maintenance_tasks;
pub mod instance_maintenance_tasks;

use crate::action::GOATMessageContent;
use crate::middleware::AllBehaviours;
use crate::scheduled_tasks::graph_maintenance_tasks::{
    detect_init_withdraw_call, detect_kickoff, detect_take1_or_challenge, process_graph_challenge,
    scan_obsolete_sibling_graphs,
};
use crate::scheduled_tasks::instance_maintenance_tasks::{
    instance_answers_monitor, instance_btc_tx_monitor, instance_expiration_monitor,
    instance_window_expiration_monitor, scan_post_graph_data, scan_post_pegin_data,
};
use client::btc_chain::BTCClient;
use client::goat_chain::GOATClient;
pub use event_watch_task::{is_processing_history_events, run_watch_event_task};
use libp2p::Swarm;
use store::MessageType;
use store::localdb::LocalDB;
use tracing::warn;

pub async fn relayer_scheduled_tasks(
    swarm: &mut Swarm<AllBehaviours>,
    local_db: &LocalDB,
    btc_client: &BTCClient,
    goat_client: &GOATClient,
) -> anyhow::Result<()> {
    if is_processing_history_events(local_db, goat_client).await? {
        warn!("Still in history events processing");
        return Ok(());
    }

    if let Err(err) = instance_window_expiration_monitor(local_db, goat_client).await {
        warn!("instance_window_expiration_monitor, err {:?}", err)
    }

    if let Err(err) = instance_expiration_monitor(local_db, btc_client).await {
        warn!("instance_expiration_monitor, err {:?}", err)
    }

    if let Err(err) = instance_btc_tx_monitor(swarm, local_db, btc_client).await {
        warn!("instance_btc_tx_monitor, err {:?}", err)
    }

    if let Err(err) = scan_obsolete_sibling_graphs(local_db).await {
        warn!("scan_obsolete_sibling_graphs, err {:?}", err)
    }

    if let Err(err) = scan_post_pegin_data(swarm, local_db, btc_client, goat_client).await {
        warn!("scan_post_operator_data, err {:?}", err)
    }

    if let Err(err) = scan_post_graph_data(swarm, local_db, goat_client).await {
        warn!("scan_post_operator_data, err {:?}", err)
    }

    if let Err(err) = detect_init_withdraw_call(swarm, local_db, goat_client, btc_client).await {
        warn!("detect_init_withdraw_call, err {:?}", err)
    }

    if let Err(err) = detect_kickoff(swarm, local_db, btc_client, goat_client).await {
        warn!("detect_kickoff, err {:?}", err)
    }
    if let Err(err) = detect_take1_or_challenge(swarm, local_db, btc_client, goat_client).await {
        warn!("detect_take1_or_challenge, err {:?}", err)
    }

    if let Err(err) = process_graph_challenge(swarm, local_db, btc_client, goat_client).await {
        warn!("process_grpah_challenge, err {:?}", err)
    }
    Ok(())
}

pub async fn committee_scheduled_tasks(
    _swarm: &mut Swarm<AllBehaviours>,
    local_db: &LocalDB,
    _btc_client: &BTCClient,
    goat_client: &GOATClient,
) -> anyhow::Result<()> {
    if is_processing_history_events(local_db, goat_client).await? {
        warn!("Still in history events processing");
        return Ok(());
    }

    if let Err(err) = instance_answers_monitor(local_db, goat_client).await {
        warn!("instance_window_expiration_monitor, err {:?}", err)
    }

    // if let Err(err) = instance_window_expiration_monitor(local_db,  goat_client).await {
    //     warn!("instance_window_expiration_monitor, err {:?}", err)
    // }
    //
    // if let Err(err) = instance_expiration_monitor( local_db).await {
    //     warn!("instance_expiration_monitor, err {:?}", err)
    // }
    // if let Err(err) = instance_btc_tx_monitor(swarm, local_db, btc_client).await {
    //     warn!("instance_btc_tx_monitor, err {:?}", err)
    // }
    Ok(())
}

#[allow(dead_code)]
fn get_goat_message_content_type(content: &GOATMessageContent) -> MessageType {
    match content {
        GOATMessageContent::CreateGraph(_) => MessageType::CreateGraph,
        GOATMessageContent::NonceGeneration(_) => MessageType::NonceGeneration,
        GOATMessageContent::CommitteePresign(_) => MessageType::CommitteePresign,
        GOATMessageContent::GraphFinalize(_) => MessageType::GraphFinalize,
        GOATMessageContent::KickoffReady(_) => MessageType::KickoffReady,
        GOATMessageContent::KickoffSent(_) => MessageType::KickoffSent,
        GOATMessageContent::Take1Ready(_) => MessageType::Take1Ready,
        GOATMessageContent::Take1Sent(_) => MessageType::Take1Sent,
        GOATMessageContent::ChallengeSent(_) => MessageType::ChallengeSent,
        GOATMessageContent::Take2Ready(_) => MessageType::Take2Ready,
        GOATMessageContent::Take2Sent(_) => MessageType::Take2Sent,
        GOATMessageContent::RequestNodeInfo(_) => MessageType::RequestNodeInfo,
        GOATMessageContent::ResponseNodeInfo(_) => MessageType::ResponseNodeInfo,
        GOATMessageContent::SyncGraphRequest(_) => MessageType::SyncGraphRequest,
        GOATMessageContent::SyncGraph(_) => MessageType::SyncGraph,
        GOATMessageContent::InstanceDiscarded(_) => MessageType::InstanceDiscarded,
        _ => todo!("other message type"),
    }
}
