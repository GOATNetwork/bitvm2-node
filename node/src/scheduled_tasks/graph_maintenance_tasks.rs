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
use tracing::{error, info, warn};
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

/// Handle Take1 transaction completion
async fn handle_take1_completion(
    btc_client: &BTCClient,
    goat_client: &GOATClient,
    local_db: &LocalDB,
    graph_data: &GraphWithBroadcastInfo,
    take1_txid: Txid,
) -> Result<(), Box<dyn std::error::Error>> {
    info!(
        "Processing Take1 completion for graph_id: {}, take1_txid: {}",
        graph_data.graph_id, take1_txid
    );

    let take1_tx = btc_client
        .fetch_btc_tx(&take1_txid)
        .await
        .map_err(|e| format!("Failed to fetch Take1 transaction {}: {}", take1_txid, e))?;

    match goat_client
        .gateway_finish_withdraw_happy_path(btc_client, &graph_data.graph_id, &take1_tx)
        .await
    {
        Err(err) => {
            warn!(
                "Failed to finish withdraw happy path for graph_id: {}, error: {:?}. Will retry later.",
                graph_data.graph_id, err
            );
        }
        Ok(tx_hash) => {
            info!(
                "Successfully finished withdraw happy path for instance_id: {}, graph_id: {}, tx_hash: {}",
                graph_data.instance_id, graph_data.graph_id, tx_hash
            );

            let block_height = match goat_client.get_tx_receipt(&tx_hash).await? {
                Some(receipt) => receipt.block_number.unwrap_or(0),
                None => {
                    warn!("No receipt found for tx_hash: {}", tx_hash);
                    0
                }
            };

            let mut tx = local_db
                .start_transaction()
                .await
                .map_err(|e| format!("Failed to start transaction: {}", e))?;

            tx.upsert_goat_tx_record(&GoatTxRecord {
                instance_id: graph_data.instance_id,
                graph_id: graph_data.graph_id,
                tx_type: GoatTxType::WithdrawHappyPath.to_string(),
                tx_hash,
                height: block_height as i64,
                is_local: true,
                processing_status: GoatTxProcessingStatus::Skipped.to_string(),
                extra: None,
                created_at: current_time_secs(),
            })
            .await
            .map_err(|e| format!("Failed to upsert goat tx record: {}", e))?;

            tx.update_graph_fields(
                GraphUpdate::new(graph_data.graph_id).with_status(GraphStatus::Take1.to_string()),
            )
            .await
            .map_err(|e| format!("Failed to update graph fields: {}", e))?;

            tx.commit().await.map_err(|e| format!("Failed to commit transaction: {}", e))?;

            info!(
                "Successfully updated database for graph_id: {} to Take1 status",
                graph_data.graph_id
            );
        }
    }
    Ok(())
}

/// Handle Challenge transaction detection
async fn handle_challenge_detected(
    storage_processor: &mut StorageProcessor<'_>,
    graph_data: &GraphWithBroadcastInfo,
    challenge_txid: Txid,
) -> Result<(), Box<dyn std::error::Error>> {
    info!(
        "Challenge detected for graph_id: {}, challenge_txid: {}",
        graph_data.graph_id, challenge_txid
    );

    storage_processor
        .update_graph_fields(
            GraphUpdate::new(graph_data.graph_id)
                .with_status(GraphStatus::Challenge.to_string())
                .with_challenge_txid(challenge_txid.into()),
        )
        .await
        .map_err(|e| format!("Failed to update graph fields for challenge: {}", e))?;

    info!("Successfully updated graph_id: {} to Challenge status", graph_data.graph_id);
    Ok(())
}

/// Check if Take1Ready message needs to be sent
async fn check_take1_ready_condition(
    btc_client: &BTCClient,
    graph_data: &GraphWithBroadcastInfo,
    kickoff_txid: Txid,
    lock_blocks: u32,
    current_height: u32,
) -> Result<Option<GOATMessageContent>, Box<dyn std::error::Error>> {
    if !is_need_to_send_msg(graph_data.msg_times, graph_data.last_msg_send_at) {
        return Ok(None);
    }

    let kickoff_height = match btc_client.get_tx_status(&kickoff_txid).await?.block_height {
        Some(height) => height,
        None => {
            info!(
                "graph_id:{}, kickoff_txid {} not on chain",
                graph_data.graph_id,
                kickoff_txid.to_string()
            );
            return Ok(None);
        }
    };

    info!(
        "graph_id:{}, kickoff_height:{kickoff_height}, lock_blocks:{lock_blocks}, current_height:{current_height}",
        graph_data.graph_id
    );

    if kickoff_height + lock_blocks <= current_height {
        Ok(Some(GOATMessageContent::Take1Ready(Take1Ready {
            instance_id: graph_data.instance_id,
            graph_id: graph_data.graph_id,
        })))
    } else {
        Ok(None)
    }
}

/// Process graph data in KickOff status
async fn process_kickoff_graph(
    btc_client: &BTCClient,
    goat_client: &GOATClient,
    local_db: &LocalDB,
    storage_processor: &mut StorageProcessor<'_>,
    graph_data: &GraphWithBroadcastInfo,
    lock_blocks: u32,
    current_height: u32,
) -> Result<Option<(Actor, GOATMessageContent)>, Box<dyn std::error::Error>> {
    let (kickoff_txid, take1_txid) =
        match (graph_data.kickoff_txid.clone(), graph_data.take1_txid.clone()) {
            (Some(kickoff), Some(take1)) => (kickoff.into(), take1.into()),
            _ => {
                warn!("graph_id:{}, kickoff or take1 is none", graph_data.graph_id);
                return Ok(None);
            }
        };

    let spent_txid = match outpoint_spent_txid(btc_client, &kickoff_txid, 1).await? {
        Some(txid) => txid,
        None => {
            // kickoff output not spent, check if we need to send Take1Ready
            if let Some(content) = check_take1_ready_condition(
                btc_client,
                graph_data,
                kickoff_txid,
                lock_blocks,
                current_height,
            )
            .await?
            {
                return Ok(Some((Actor::Operator, content)));
            }
            return Ok(None);
        }
    };

    if spent_txid == take1_txid {
        // Take1 was sent
        handle_take1_completion(btc_client, goat_client, local_db, graph_data, take1_txid).await?;
    } else {
        // Challenge was sent
        handle_challenge_detected(storage_processor, graph_data, spent_txid).await?;
    }

    Ok(None)
}

/// Process graph data in Challenge status
fn process_challenge_graph(
    graph_data: &GraphWithBroadcastInfo,
) -> Option<(Actor, GOATMessageContent)> {
    graph_data.challenge_txid.clone().map(|challenge_txid| {
        (
            Actor::Operator,
            GOATMessageContent::ChallengeSent(ChallengeSent {
                instance_id: graph_data.instance_id,
                graph_id: graph_data.graph_id,
                challenge_txid: challenge_txid.into(),
            }),
        )
    })
}

//Tick-Task-4
pub async fn scan_take1_or_challenge(
    swarm: &mut Swarm<AllBehaviours>,
    local_db: &LocalDB,
    btc_client: &BTCClient,
    goat_client: &GOATClient,
) -> Result<(), Box<dyn std::error::Error>> {
    info!("Starting scan_take1_or_challenge task");

    let mut storage_processor = local_db
        .acquire()
        .await
        .map_err(|e| format!("Failed to acquire database connection: {}", e))?;

    let graph_datas = fetch_graphs_with_status_and_msg_type(
        &mut storage_processor,
        vec![
            (GraphStatus::KickOff, MessageType::Take1Ready),
            (GraphStatus::Challenge, MessageType::ChallengeSent),
        ],
    )
    .await
    .map_err(|e| format!("Failed to fetch graph data: {}", e))?;

    info!("Found {} graphs to process", graph_datas.len());

    let current_height = btc_client
        .get_height()
        .await
        .map_err(|e| format!("Failed to get current BTC height: {}", e))?;
    let lock_blocks = num_blocks_per_network(get_network(), CONNECTOR_3_TIMELOCK);

    let mut processed_count = 0;
    let mut error_count = 0;

    for graph_data in graph_datas {
        match process_kickoff_challenge_graph(
            btc_client,
            goat_client,
            local_db,
            &mut storage_processor,
            &graph_data,
            lock_blocks,
            current_height,
        )
        .await
        {
            Ok(Some((actor, content))) => {
                if let Err(e) = broadcast_message_and_record(
                    swarm,
                    &mut storage_processor,
                    actor,
                    content,
                    &graph_data,
                )
                .await
                {
                    error!(
                        "Failed to broadcast message for graph_id {}: {}",
                        graph_data.graph_id, e
                    );
                    error_count += 1;
                } else {
                    processed_count += 1;
                }
            }
            Ok(None) => {
                // No message to send, but processing was successful
                processed_count += 1;
            }
            Err(e) => {
                error!("Failed to process graph_id {}: {}", graph_data.graph_id, e);
                error_count += 1;
            }
        }
    }

    info!(
        "Completed scan_take1_or_challenge: {} processed, {} errors",
        processed_count, error_count
    );

    Ok(())
}

/// Process kickoff or challenge graph data
async fn process_kickoff_challenge_graph(
    btc_client: &BTCClient,
    goat_client: &GOATClient,
    local_db: &LocalDB,
    storage_processor: &mut StorageProcessor<'_>,
    graph_data: &GraphWithBroadcastInfo,
    lock_blocks: u32,
    current_height: u32,
) -> Result<Option<(Actor, GOATMessageContent)>, Box<dyn std::error::Error>> {
    match graph_data.status.as_str() {
        status if status == GraphStatus::KickOff.to_string() => {
            process_kickoff_graph(
                btc_client,
                goat_client,
                local_db,
                storage_processor,
                graph_data,
                lock_blocks,
                current_height,
            )
            .await
        }
        status if status == GraphStatus::Challenge.to_string() => {
            Ok(process_challenge_graph(graph_data))
        }
        _ => Ok(None),
    }
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
