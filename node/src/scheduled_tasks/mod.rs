mod event_watch_task;
pub mod graph_maintenance_tasks;
pub mod instance_maintenance_tasks;

use crate::action::{GOATMessage, GOATMessageContent};
use crate::env::{MESSAGE_BROADCAST_MAX_TIMES, MESSAGE_RESEND_INTERVAL_SECOND};
use crate::middleware::AllBehaviours;
use crate::rpc_service::current_time_secs;
use crate::scheduled_tasks::graph_maintenance_tasks::{
    detect_init_withdraw_call, detect_kickoff, detect_take1_or_challenge, process_graph_challenge,
    scan_obsolete_sibling_graphs,
};
use crate::scheduled_tasks::instance_maintenance_tasks::{
    instance_answers_monitor, instance_btc_tx_monitor, instance_expiration_monitor,
    instance_window_expiration_monitor, scan_post_pegin_data,
};
use bitvm2_lib::actors::Actor;
use client::btc_chain::BTCClient;
use client::goat_chain::GOATClient;
pub use event_watch_task::{is_processing_history_events, run_watch_event_task};
use libp2p::Swarm;
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};
use store::localdb::{LocalDB, StorageProcessor};
use store::{Graph, Message, MessageBroadcast, MessageState, MessageType};
use tracing::warn;
use uuid::Uuid;

fn is_need_to_send_msg(pre_send_times: i64, last_send_at: i64) -> bool {
    // if msg never been sent, last_send_at value is 0
    let current_time = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64;
    (pre_send_times % MESSAGE_BROADCAST_MAX_TIMES != 0)
        || (current_time - last_send_at) > MESSAGE_RESEND_INTERVAL_SECOND
}

pub struct BroadcastMessageDetail {
    pub actor: Actor,
    pub message_content: GOATMessageContent,
    pub graph_id: Uuid,
    pub graph_status: String,
    pub msg_type: String,
    pub pre_send_times: i64,
    pub last_send_at: i64,
}
async fn broadcast_message_and_record(
    local_db: &LocalDB,
    msg_detail: BroadcastMessageDetail,
) -> anyhow::Result<()> {
    if is_need_to_send_msg(msg_detail.pre_send_times, msg_detail.last_send_at) {
        let mut tx = local_db.start_transaction().await?;
        broadcast_message_and_record_with_storage(&mut tx, msg_detail).await?;
        tx.commit().await?;
    }
    Ok(())
}

async fn broadcast_message_and_record_with_storage(
    storage_processor: &mut StorageProcessor<'_>,
    msg_detail: BroadcastMessageDetail,
) -> anyhow::Result<()> {
    if is_need_to_send_msg(msg_detail.pre_send_times, msg_detail.last_send_at) {
        let message =
            GOATMessage::from_typed(msg_detail.actor.clone(), &msg_detail.message_content)?;
        storage_processor
            .create_message(Message {
                id: 0,
                actor: msg_detail.actor.to_string(),
                from_peer: "self".to_string(),
                msg_type: get_goat_message_content_type(&msg_detail.message_content).to_string(),
                content: serde_json::to_vec(&message)?,
                state: MessageState::Pending.to_string(),
                weight: 0,
                lock_time_until: current_time_secs(),
            })
            .await?;

        storage_processor
            .add_message_broadcast_times(
                &msg_detail.graph_id,
                &msg_detail.graph_status,
                &msg_detail.msg_type,
                1,
            )
            .await?;
    }
    Ok(())
}
fn gen_broadcast_record_map_key(graph_id: Uuid, graph_status: &str, msg_type: &str) -> String {
    format!("{}_{}_{}", graph_id, graph_status, msg_type)
}
async fn fetch_graph_and_broadcast_record_map<'a>(
    storage_processor: &mut StorageProcessor<'a>,
    graph_status: &str,
) -> anyhow::Result<(Vec<Graph>, HashMap<String, MessageBroadcast>)> {
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

    let broadcasts = storage_processor.find_message_broadcasts(graph_status).await?;
    let broadcast_record_map: HashMap<String, MessageBroadcast> = broadcasts
        .into_iter()
        .map(|v| (gen_broadcast_record_map_key(v.graph_id, &v.graph_status, &v.msg_type), v))
        .collect();
    Ok((graphs, broadcast_record_map))
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

    if let Err(err) = scan_post_pegin_data(swarm, local_db, btc_client).await {
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
