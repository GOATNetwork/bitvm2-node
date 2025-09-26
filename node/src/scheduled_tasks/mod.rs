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
    instance_window_expiration_monitor,
};
use client::btc_chain::BTCClient;
use client::goat_chain::GOATClient;
pub use event_watch_task::{is_processing_history_events, run_watch_event_task};
use libp2p::Swarm;
use store::localdb::{LocalDB, StorageProcessor};
use store::{Graph, MessageType};
use tracing::warn;

async fn fetch_on_turn_graph_by_status<'a>(
    storage_processor: &mut StorageProcessor<'a>,
    graph_status: &str,
) -> anyhow::Result<Vec<Graph>> {
    let graphs_ori =
        storage_processor.find_graphs_by_status_group_by_operator(graph_status).await?;
    // todo add other logic later
    let mut graphs: Vec<Graph> = vec![];
    let mut pre_operator_pubkey = "".to_string();
    for graph in graphs_ori {
        if graph.operator_pubkey != pre_operator_pubkey {
            pre_operator_pubkey = graph.operator_pubkey.clone();
            graphs.push(graph);
        }
    }
    Ok(graphs)
}
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

    if let Err(err) = instance_answers_monitor(local_db).await {
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
        GOATMessageContent::OperatorCommitBlockHashSent(_) => {
            MessageType::OperatorCommitBlockHashSent
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
    }
}
