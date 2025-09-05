use crate::action::{GOATMessage, GOATMessageContent, KickoffReady, KickoffSent, send_to_peer};
use crate::client::btc_chain::BTCClient;
use crate::client::goat_chain::{GOATClient, WithdrawStatus};
use crate::env::{MESSAGE_BROADCAST_MAX_TIMES, MESSAGE_RESEND_INTERVAL_SECOND};
use crate::middleware::AllBehaviours;
use crate::utils::{
    create_goat_tx_record, get_graph, outpoint_spent_txid, tx_on_chain, update_graph_fields,
};
use bitcoin::Txid;
use bitvm2_lib::actors::Actor;
use libp2p::Swarm;
use std::time::{SystemTime, UNIX_EPOCH};
use store::localdb::LocalDB;
use store::{GoatTxProcessingStatus, GoatTxType, GraphStatus, GraphWithBroadcastInfo, MessageType};
use tracing::{info, warn};
use uuid::Uuid;

fn is_need_to_send_msg(pre_send_times: i64, last_send_at: i64) -> bool {
    // if msg never been sent, last_send_at value is 0
    let current_time = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64;
    (pre_send_times % MESSAGE_BROADCAST_MAX_TIMES != 0)
        || (current_time - last_send_at) > MESSAGE_RESEND_INTERVAL_SECOND
}
async fn fetch_graph_with_broadcast_info(
    local_db: &LocalDB,
    status: GraphStatus,
    msg_type: String,
) -> Result<Vec<GraphWithBroadcastInfo>, Box<dyn std::error::Error>> {
    // If instance corresponding to the graph has already been consumed, the graph is excluded.
    // When a graph enters the take1/take2 status, mark its corresponding instance as consumed.
    let mut storage_process = local_db.acquire().await?;
    Ok(storage_process
        .fetch_graph_with_broadcast_info(status.to_string().as_str(), &msg_type)
        .await?)
}

async fn get_message_broadcast_times(
    local_db: &LocalDB,
    instance_id: &Uuid,
    graph_id: &Uuid,
    msg_type: &str,
) -> Result<(i64, i64), Box<dyn std::error::Error>> {
    let mut storage_process = local_db.acquire().await?;
    Ok(storage_process.get_message_broadcast_times(instance_id, graph_id, msg_type).await?)
}

async fn add_message_broadcast_times(
    local_db: &LocalDB,
    instance_id: &Uuid,
    graph_id: &Uuid,
    msg_type: &str,
    add_times: i64,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut storage_process = local_db.acquire().await?;
    Ok(storage_process
        .add_message_broadcast_times(instance_id, graph_id, msg_type, add_times)
        .await?)
}

pub async fn get_initialized_graphs(
    goat_client: &GOATClient,
) -> Result<Vec<(Uuid, Uuid)>, Box<dyn std::error::Error>> {
    // call L2 contract : getInitializedInstanceIds
    // returns Vec<(instance_id, graph_id)>
    Ok(goat_client.gateway_get_initialized_ids().await?)
}

// tick_task1
pub async fn scan_withdraw(
    swarm: &mut Swarm<AllBehaviours>,
    local_db: &LocalDB,
    goat_client: &GOATClient,
    btc_client: &BTCClient,
) -> Result<(), Box<dyn std::error::Error>> {
    info!("start tick action: scan_withdraw");
    let graphs = get_initialized_graphs(goat_client).await?;
    for (instance_id, graph_id) in graphs {
        if let Ok(graph) = get_graph(local_db, Some(instance_id), graph_id).await {
            if graph.kickoff_txid.is_none() {
                warn!("{graph_id} kickoff txid is None");
                continue;
            }
            if graph.kickoff_txid.is_none() {
                warn!("{instance_id} kickoff txid decode ressult is None");
                continue;
            }
            if tx_on_chain(btc_client, &graph.kickoff_txid.unwrap().0).await? {
                // kickoff is send, but goat contract func ProceedWithdraw not call
                tracing::trace!(
                    "{graph_id} kickoff has been sent, so no need to send kickoffReady message"
                );
                continue;
            }
            let (msg_times, last_send_at) = get_message_broadcast_times(
                local_db,
                &instance_id,
                &graph_id,
                &MessageType::KickoffReady.to_string(),
            )
            .await?;
            if is_need_to_send_msg(msg_times, last_send_at) {
                let message_content =
                    GOATMessageContent::KickoffReady(KickoffReady { instance_id, graph_id });
                send_to_peer(swarm, GOATMessage::from_typed(Actor::Operator, &message_content)?)?;
                add_message_broadcast_times(
                    local_db,
                    &instance_id,
                    &graph_id,
                    &MessageType::KickoffReady.to_string(),
                    1,
                )
                .await?;
            }
        }
    }
    Ok(())
}

// Tick-Task-2:
pub async fn scan_kickoff(
    swarm: &mut Swarm<AllBehaviours>,
    local_db: &LocalDB,
    btc_client: &BTCClient,
    goat_client: &GOATClient,
) -> Result<(), Box<dyn std::error::Error>> {
    info!("start tick action: scan_kickoff");
    let mut graph_datas = fetch_graph_with_broadcast_info(
        local_db,
        GraphStatus::OperatorDataPushed,
        MessageType::KickoffSent.to_string(),
    )
    .await?;
    let mut graph_datas_kickoff = fetch_graph_with_broadcast_info(
        local_db,
        GraphStatus::KickOff,
        MessageType::KickoffSent.to_string(),
    )
    .await?;
    graph_datas.append(&mut graph_datas_kickoff);
    info!("scan_kickoff get graph datas size: {}", graph_datas.len());
    for graph_data in graph_datas {
        let mut send_message = false;
        let instance_id = graph_data.instance_id;
        let graph_id = graph_data.graph_id;
        if graph_data.kickoff_txid.is_none() {
            warn!("graph_id {}, kickoff txid is none", graph_data.graph_id);
            continue;
        }
        let kickoff_txid: Txid = graph_data.kickoff_txid.unwrap().into();
        if graph_data.status == GraphStatus::OperatorDataPushed.to_string() {
            if !tx_on_chain(btc_client, &kickoff_txid).await? {
                warn!(
                    "graph_id:{} kickoff:{:?} is not onchain ",
                    graph_data.graph_id, kickoff_txid
                );
                continue;
            }
            let withdraw_data = goat_client.gateway_get_withdraw_data(&graph_id).await?;
            if withdraw_data.status != WithdrawStatus::Initialized {
                info!("scan_kickoff {graph_id}, kickoff:{kickoff_txid} in evil way");
                send_message = true;
            } else {
                let kickoff_tx = btc_client.fetch_btc_tx(&kickoff_txid).await?;
                match goat_client
                    .gateway_process_withdraw(btc_client, &graph_data.graph_id, &kickoff_tx)
                    .await
                {
                    Ok(tx_hash) => {
                        info!(
                            "instance_id: {}, graph_id:{}  finish withdraw, tx hash :{}",
                            instance_id, graph_id, tx_hash
                        );

                        create_goat_tx_record(
                            local_db,
                            goat_client,
                            graph_id,
                            instance_id,
                            &tx_hash,
                            GoatTxType::ProceedWithdraw,
                            GoatTxProcessingStatus::Skipped.to_string(),
                        )
                        .await?;

                        send_message = true;
                        update_graph_fields(
                            local_db,
                            graph_data.graph_id,
                            Some(GraphStatus::KickOff.to_string()),
                            None,
                            None,
                            None,
                            None,
                        )
                        .await?;
                    }
                    Err(err) => {
                        warn!("scan_kickoff: err:{err:?}");
                    }
                }
            }
        } else if graph_data.status == GraphStatus::KickOff.to_string() {
            send_message = true;
        }
        if !send_message {
            continue;
        }

        // check kickoff tx output is been spent, refer graph in new status: take1/challenge
        if outpoint_spent_txid(btc_client, &kickoff_txid, 1).await?.is_some() {
            tracing::trace!(
                "{graph_id} kickoff {kickoff_txid} output has been spend, no need to send kickoffSent message"
            );
            continue;
        }
        if is_need_to_send_msg(graph_data.msg_times, graph_data.last_msg_send_at) {
            let message_content = GOATMessageContent::KickoffSent(KickoffSent {
                instance_id,
                graph_id,
                kickoff_txid,
            });
            send_to_peer(swarm, GOATMessage::from_typed(Actor::All, &message_content)?)?;
            add_message_broadcast_times(
                local_db,
                &graph_data.instance_id,
                &graph_data.graph_id,
                &MessageType::KickoffSent.to_string(),
                1,
            )
            .await?;
        }
    }
    Ok(())
}

//Tick-Task-3:
pub async fn scan_assert(
    _swarm: &mut Swarm<AllBehaviours>,
    _local_db: &LocalDB,
    _btc_client: &BTCClient,
) -> Result<(), Box<dyn std::error::Error>> {
    Ok(())
}

//Tick-Task-4
pub async fn scan_take1(
    _swarm: &mut Swarm<AllBehaviours>,
    _local_db: &LocalDB,
    _btc_client: &BTCClient,
    _goat_client: &GOATClient,
) -> Result<(), Box<dyn std::error::Error>> {
    Ok(())
}

//Tick-Task-5:
pub async fn scan_take2(
    _swarm: &mut Swarm<AllBehaviours>,
    _local_db: &LocalDB,
    _btc_client: &BTCClient,
    _goat_client: &GOATClient,
) -> Result<(), Box<dyn std::error::Error>> {
    Ok(())
}
