use crate::action::{
    ChallengeSent, GOATMessage, GOATMessageContent, KickoffReady, KickoffSent, Take1Ready,
    send_to_peer,
};
use crate::env::{MESSAGE_BROADCAST_MAX_TIMES, MESSAGE_RESEND_INTERVAL_SECOND, get_network};
use crate::middleware::AllBehaviours;
use crate::rpc_service::current_time_secs;
use crate::scheduled_tasks::get_goat_message_content_type;
use crate::utils::{get_graph, outpoint_spent_txid, tx_on_chain};
use bitcoin::Txid;
use bitvm2_lib::actors::Actor;
use client::btc_chain::BTCClient;
use client::goat_chain::{GOATClient, WithdrawStatus};
use goat::constants::CONNECTOR_3_TIMELOCK;
use goat::utils::num_blocks_per_network;
use libp2p::Swarm;
use std::time::{SystemTime, UNIX_EPOCH};
use store::localdb::{GraphUpdate, LocalDB, StorageProcessor};
use store::{
    GoatTxProcessingStatus, GoatTxRecord, GoatTxType, GraphStatus, GraphWithBroadcastInfo,
    MessageType,
};
use tracing::{info, warn};
use uuid::Uuid;

fn is_need_to_send_msg(pre_send_times: i64, last_send_at: i64) -> bool {
    // if msg never been sent, last_send_at value is 0
    let current_time = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64;
    (pre_send_times % MESSAGE_BROADCAST_MAX_TIMES != 0)
        || (current_time - last_send_at) > MESSAGE_RESEND_INTERVAL_SECOND
}

async fn broadcast_message_and_record(
    swarm: &mut Swarm<AllBehaviours>,
    storage_processor: &mut StorageProcessor<'_>,
    actor: Actor,
    message_content: GOATMessageContent,
    graph_data: &GraphWithBroadcastInfo,
) -> Result<(), Box<dyn std::error::Error>> {
    if is_need_to_send_msg(graph_data.msg_times, graph_data.last_msg_send_at) {
        send_to_peer(swarm, GOATMessage::from_typed(actor, &message_content)?)?;
        let msg_type = get_goat_message_content_type(&message_content);
        storage_processor
            .add_message_broadcast_times(
                &graph_data.instance_id,
                &graph_data.graph_id,
                &msg_type.to_string(),
                1,
            )
            .await?;
    }
    Ok(())
}
/// Fetch graph data with specified status and message type combinations
/// Supports querying multiple combinations of status and message types
async fn fetch_graphs_with_status_and_msg_type<'a>(
    storage_processor: &mut StorageProcessor<'a>,
    status_with_msg_type: Vec<(GraphStatus, MessageType)>,
) -> Result<Vec<GraphWithBroadcastInfo>, Box<dyn std::error::Error>> {
    let mut all_graph_datas = Vec::new();

    for (status, msg_type) in status_with_msg_type {
        let mut graph_datas = storage_processor
            .fetch_graph_with_broadcast_info(&status.to_string(), &msg_type.to_string())
            .await?;
        all_graph_datas.append(&mut graph_datas);
    }

    Ok(all_graph_datas)
}

#[allow(dead_code)]
pub async fn get_initialized_graphs(
    goat_client: &GOATClient,
) -> Result<Vec<(Uuid, Uuid)>, Box<dyn std::error::Error>> {
    // call L2 contract : getInitializedInstanceIds
    // returns Vec<(instance_id, graph_id)>
    Ok(goat_client.gateway_get_initialized_ids().await?)
}

pub async fn get_user_init_withdraw_graphs<'a>(
    storage_processor: &mut StorageProcessor<'a>,
) -> anyhow::Result<Vec<(Uuid, Uuid)>> {
    let goat_tx_records = storage_processor
        .get_goat_tx_record_by_processing_status(
            &GoatTxType::InitWithdraw.to_string(),
            &GoatTxProcessingStatus::Pending.to_string(),
        )
        .await?;
    Ok(goat_tx_records.iter().map(|v| (v.instance_id, v.graph_id)).collect())
}

// tick_task1
pub async fn scan_withdraw(
    swarm: &mut Swarm<AllBehaviours>,
    local_db: &LocalDB,
    _goat_client: &GOATClient,
    btc_client: &BTCClient,
) -> Result<(), Box<dyn std::error::Error>> {
    info!("start tick action: scan_withdraw");
    // contract not has method get_initialized_graphs, use monitor event instead
    // let graphs = get_initialized_graphs(goat_client).await?;
    let mut storage_process = local_db.acquire().await?;
    let graphs = get_user_init_withdraw_graphs(&mut storage_process).await?;
    let mut storage_processor = local_db.acquire().await?;
    for (instance_id, graph_id) in graphs {
        if let Ok(graph) = get_graph(local_db, Some(instance_id), graph_id).await
            && let Some(kickoff_txid) = graph.kickoff_txid.clone()
        {
            if tx_on_chain(btc_client, &kickoff_txid.0).await? {
                // kickoff is send, but goat contract func ProceedWithdraw not call
                tracing::trace!(
                    "{graph_id} kickoff has been sent, so no need to send kickoffReady message"
                );
                storage_processor
                    .update_goat_tx_record_processing_status(
                        &graph_id,
                        &instance_id,
                        &GoatTxType::InitWithdraw.to_string(),
                        &GoatTxProcessingStatus::Processed.to_string(),
                    )
                    .await?;
                continue;
            }
            let (msg_times, last_send_at) = storage_processor
                .get_message_broadcast_times(
                    &instance_id,
                    &graph_id,
                    &MessageType::KickoffReady.to_string(),
                )
                .await?;
            if is_need_to_send_msg(msg_times, last_send_at) {
                let message_content =
                    GOATMessageContent::KickoffReady(KickoffReady { instance_id, graph_id });
                send_to_peer(swarm, GOATMessage::from_typed(Actor::Operator, &message_content)?)?;
                storage_processor
                    .add_message_broadcast_times(
                        &instance_id,
                        &graph_id,
                        &MessageType::KickoffReady.to_string(),
                        1,
                    )
                    .await?;
            }
        } else {
            warn!(
                "instance_id: {instance_id} graph_id: {graph_id} fail to get graph from db or kickoff_txid is none"
            );
        }
    }
    Ok(())
}

async fn process_operator_data_pushed_graph(
    btc_client: &BTCClient,
    goat_client: &GOATClient,
    local_db: &LocalDB,
    graph_id: &Uuid,
    instance_id: &Uuid,
    kickoff_txid: &Txid,
) -> Result<bool, Box<dyn std::error::Error>> {
    if outpoint_spent_txid(btc_client, &kickoff_txid, 1).await?.is_some() {
        tracing::trace!(
            "graph_id:{graph_id} kickoff:{kickoff_txid:?} output has been spend, no need to send kickoffSent message",
        );
        return Ok(false);
    }
    let tx_info = btc_client.fetch_btc_tx_info(kickoff_txid).await?;
    if !tx_info.status.confirmed {
        warn!("graph_id:{graph_id} kickoff:{kickoff_txid:?} is not onchain ");
        return Ok(false);
    }
    let withdraw_data = goat_client.gateway_get_withdraw_data(graph_id).await?;
    if withdraw_data.status != WithdrawStatus::Initialized {
        info!("graph_id:{graph_id} kickoff:{kickoff_txid:?} in evil way");
        return Ok(true);
    }

    let kickoff_tx = tx_info.to_tx();
    match goat_client.gateway_process_withdraw(btc_client, graph_id, &kickoff_tx).await {
        Ok(tx_hash) => {
            info!(
                "instance_id: {instance_id}, graph_id:{graph_id} finish withdraw, tx hash: {tx_hash}"
            );

            let block_height = match goat_client.get_tx_receipt(&tx_hash).await? {
                Some(receipt) => receipt.block_number.unwrap_or(0),
                None => 0,
            };
            let mut tx = local_db.start_transaction().await?;
            tx.upsert_goat_tx_record(&GoatTxRecord {
                instance_id: instance_id.clone(),
                graph_id: graph_id.clone(),
                tx_type: GoatTxType::ProceedWithdraw.to_string(),
                tx_hash,
                height: block_height as i64,
                is_local: true,
                processing_status: GoatTxProcessingStatus::Skipped.to_string(),
                extra: None,
                created_at: current_time_secs(),
            })
            .await?;
            tx.update_graph_fields(
                GraphUpdate::new(graph_id.clone()).with_status(GraphStatus::KickOff.to_string()),
            )
            .await?;
            tx.commit().await?;
            Ok(true)
        }
        Err(err) => {
            warn!("scan_kickoff: err:{err:?}");
            Ok(false)
        }
    }
}

// Tick-Task-2:
pub async fn scan_kickoff(
    swarm: &mut Swarm<AllBehaviours>,
    local_db: &LocalDB,
    btc_client: &BTCClient,
    goat_client: &GOATClient,
) -> Result<(), Box<dyn std::error::Error>> {
    info!("start tick action: scan_kickoff");
    let mut storage_processor = local_db.acquire().await?;
    let graph_datas = fetch_graphs_with_status_and_msg_type(
        &mut storage_processor,
        vec![
            (GraphStatus::OperatorDataPushed, MessageType::KickoffSent),
            (GraphStatus::KickOff, MessageType::KickoffSent),
        ],
    )
    .await?;
    info!("scan_kickoff get graph datas size: {}", graph_datas.len());
    for graph_data in graph_datas {
        if let Some(kickoff_txid) = graph_data.kickoff_txid.clone() {
            let kickoff_txid: Txid = kickoff_txid.into();
            let should_send_message = match graph_data.status.clone().as_str() {
                status if status == GraphStatus::OperatorDataPushed.to_string() => {
                    process_operator_data_pushed_graph(
                        btc_client,
                        goat_client,
                        local_db,
                        &graph_data.graph_id,
                        &graph_data.instance_id,
                        &kickoff_txid,
                    )
                    .await?
                }
                status if status == GraphStatus::KickOff.clone().to_string() => true,
                _ => false,
            };

            if !should_send_message {
                continue;
            }
            broadcast_message_and_record(
                swarm,
                &mut storage_processor,
                Actor::All,
                GOATMessageContent::KickoffSent(KickoffSent {
                    instance_id: graph_data.instance_id,
                    graph_id: graph_data.graph_id,
                    kickoff_txid,
                }),
                &graph_data.clone(),
            )
            .await?;
        } else {
            warn!("graph_id {}, kickoff txid is none", graph_data.graph_id);
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
pub async fn scan_take1_or_challenge(
    swarm: &mut Swarm<AllBehaviours>,
    local_db: &LocalDB,
    btc_client: &BTCClient,
    goat_client: &GOATClient,
) -> Result<(), Box<dyn std::error::Error>> {
    info!("start tick action: scan_take1_or_challenge");
    let mut storage_processor = local_db.acquire().await?;
    let graph_datas = fetch_graphs_with_status_and_msg_type(
        &mut storage_processor,
        vec![
            (GraphStatus::KickOff, MessageType::Take1Ready),
            (GraphStatus::Challenge, MessageType::ChallengeSent),
        ],
    )
    .await?;
    info!("scan_kickoff get graph datas size: {}", graph_datas.len());
    let current_height = btc_client.get_height().await?;
    // TODO update
    let lock_blocks = num_blocks_per_network(get_network(), CONNECTOR_3_TIMELOCK);
    for graph_data in graph_datas {
        let mut message: Option<(Actor, GOATMessageContent)> = None;
        match graph_data.status.as_str() {
            status if status == GraphStatus::KickOff.to_string() => {
                if let Some(kickoff_txid) = graph_data.kickoff_txid.clone()
                    && let Some(take1_txid) = graph_data.take1_txid.clone()
                {
                    let kickoff_txid: Txid = kickoff_txid.clone().into();
                    let take1_txid: Txid = take1_txid.clone().into();
                    if let Some(spent_txid) =
                        outpoint_spent_txid(btc_client, &kickoff_txid, 1).await?
                    {
                        if spent_txid == take1_txid {
                            // take1 sent, try to call finish_withdraw_happy_path
                            info!(
                                "graph_id:{},  take-1 sent, txid: {spent_txid}",
                                graph_data.graph_id
                            );
                            let take1_tx = btc_client.fetch_btc_tx(&take1_txid).await?;
                            match goat_client
                                .gateway_finish_withdraw_happy_path(
                                    btc_client,
                                    &graph_data.graph_id,
                                    &take1_tx,
                                )
                                .await
                            {
                                Err(err) => {
                                    // call finish_withdraw_happy_path later
                                    warn!(
                                        "scan_take1 at graph:{}, finish_withdraw_happy_path err:{:?}",
                                        graph_data.graph_id, err
                                    );
                                }
                                Ok(tx_hash) => {
                                    info!(
                                        "instance_id: {}, graph_id:{} take1 finish send, tx hash :{}",
                                        graph_data.instance_id, graph_data.graph_id, tx_hash
                                    );

                                    let block_height =
                                        match goat_client.get_tx_receipt(&tx_hash).await? {
                                            Some(receipt) => receipt.block_number.unwrap_or(0),
                                            None => 0,
                                        };
                                    let mut tx = local_db.start_transaction().await?;
                                    tx.upsert_goat_tx_record(&GoatTxRecord {
                                        instance_id: graph_data.instance_id,
                                        graph_id: graph_data.graph_id,
                                        tx_type: GoatTxType::WithdrawHappyPath.to_string(),
                                        tx_hash,
                                        height: block_height as i64,
                                        is_local: true,
                                        processing_status: GoatTxProcessingStatus::Skipped
                                            .to_string(),
                                        extra: None,
                                        created_at: current_time_secs(),
                                    })
                                    .await?;
                                    tx.update_graph_fields(
                                        GraphUpdate::new(graph_data.graph_id)
                                            .with_status(GraphStatus::Take1.to_string()),
                                    )
                                    .await?;
                                    tx.commit().await?;
                                }
                            }
                        } else {
                            info!(
                                "graph_id:{},  challenge sent, txid: {spent_txid}",
                                graph_data.graph_id
                            );
                            let mut storage_processor = local_db.acquire().await?;
                            storage_processor
                                .update_graph_fields(
                                    GraphUpdate::new(graph_data.graph_id)
                                        .with_status(GraphStatus::Challenge.to_string())
                                        .with_challenge_txid(spent_txid.into()),
                                )
                                .await?;
                        }
                    } else {
                        if is_need_to_send_msg(graph_data.msg_times, graph_data.last_msg_send_at) {
                            // check if kickoff's timelock for take1 is expired
                            if let Some(kickoff_height) =
                                btc_client.get_tx_status(&kickoff_txid).await?.block_height
                            {
                                info!(
                                    "graph_id:{}, kickoff_height:{kickoff_height}, lock_blocks:{lock_blocks}, current_height:{current_height}",
                                    graph_data.graph_id
                                );
                                if kickoff_height + lock_blocks <= current_height {
                                    message = Some((
                                        Actor::Operator,
                                        GOATMessageContent::Take1Ready(Take1Ready {
                                            instance_id: graph_data.instance_id,
                                            graph_id: graph_data.graph_id,
                                        }),
                                    ));
                                }
                            } else {
                                info!(
                                    "graph_id:{},  kickoff_txid{}  not no chain",
                                    graph_data.graph_id,
                                    kickoff_txid.to_string()
                                )
                            }
                        }
                    }
                } else {
                    warn!("graph_id:{}, kickoff  or take1 is none", graph_data.graph_id);
                    continue;
                }
            }
            status if status == GraphStatus::Challenge.to_string() => {
                if let Some(challenge_txid) = graph_data.challenge_txid.clone() {
                    message = Some((
                        Actor::Operator,
                        GOATMessageContent::ChallengeSent(ChallengeSent {
                            instance_id: graph_data.instance_id,
                            graph_id: graph_data.graph_id,
                            challenge_txid: challenge_txid.into(),
                        }),
                    ));
                }
            }
            _ => {}
        }
        if let Some((actor, content)) = message {
            broadcast_message_and_record(
                swarm,
                &mut storage_processor,
                actor,
                content,
                &graph_data.clone(),
            )
            .await?;
        }
    }

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

pub async fn scan_obsolete_sibling_graphs(
    local_db: &LocalDB,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut tx = local_db.start_transaction().await?;
    let mut tx_records = tx
        .get_goat_tx_record_by_processing_status(
            &GoatTxType::WithdrawHappyPath.to_string(),
            &GoatTxProcessingStatus::Pending.to_string(),
        )
        .await?;

    let mut unhappy_path_records = tx
        .get_goat_tx_record_by_processing_status(
            &GoatTxType::WithdrawUnhappyPath.to_string(),
            &GoatTxProcessingStatus::Pending.to_string(),
        )
        .await?;
    tx_records.append(&mut unhappy_path_records);

    for tx_record in tx_records {
        tx.update_graphs_status_with_instance_id(
            tx_record.instance_id,
            Some(tx_record.graph_id),
            &GraphStatus::Obsoleted.to_string(),
        )
        .await?;
        tx.update_goat_tx_record_processing_status(
            &tx_record.graph_id,
            &tx_record.instance_id,
            &tx_record.tx_type,
            &GoatTxProcessingStatus::Processed.to_string(),
        )
        .await?
    }
    tx.commit().await?;
    Ok(())
}
