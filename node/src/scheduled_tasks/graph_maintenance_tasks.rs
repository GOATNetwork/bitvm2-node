use crate::action::{
    ChallengeSent, GOATMessage, GOATMessageContent, KickoffReady, KickoffSent, Take1Ready,
    send_to_peer,
};
use crate::env::{MESSAGE_BROADCAST_MAX_TIMES, MESSAGE_RESEND_INTERVAL_SECOND, get_network};
use crate::middleware::AllBehaviours;
use crate::rpc_service::current_time_secs;
use crate::scheduled_tasks::get_goat_message_content_type;
use crate::utils::{get_graph, outpoint_spent_txid};
use bitcoin::Txid;
use bitvm2_lib::actors::Actor;
use client::btc_chain::BTCClient;
use client::goat_chain::{GOATClient, WithdrawStatus};
use goat::constants::CONNECTOR_3_TIMELOCK;
use goat::utils::num_blocks_per_network;
use indexmap::IndexMap;
use libp2p::Swarm;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};
use store::localdb::{GraphUpdate, LocalDB, StorageProcessor};
use store::{
    GoatTxProcessingStatus, GoatTxRecord, GoatTxType, GraphBtcTxVoutMonitor, GraphStatus,
    GraphWithBroadcastInfo, MessageType, SerializableTxid,
};
use strum::{Display, EnumString};
use tracing::{info, warn};
use uuid::Uuid;

const BLOCKHASH_COMMIT_VIN_MARGIN: i64 = 3;
const ASSERT_COMMIT_VIN_MARGIN: i64 = 2;

/// Watchtower init tx vout item status
#[derive(Clone, Debug, Serialize, Deserialize, Default, Eq, PartialEq, Display, EnumString)]
pub enum WTInitTxVoutItemStatus {
    #[default]
    Init,
    Challenge,
    ChallengeTimeout,
    Ack,
    AckTimeout,
}
/// Watchtower init tx vout data
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct WTInitTxVoutMonitorData {
    pub data_map: IndexMap<i32, WTInitTxVoutItemStatus>,
    pub disproved_indexes: Vec<i32>,
    pub is_commit_blockhash_timeout: bool,
}

impl WTInitTxVoutMonitorData {
    pub async fn monitor_vout(
        &mut self,
        btc_client: &BTCClient,
        txid: &Txid,
        challenge_timeout_txids: &[SerializableTxid],
        nack_txids: &[SerializableTxid],
    ) -> anyhow::Result<()> {
        for (k, status) in self.data_map.iter_mut() {
            let index = *k;
            if *status == WTInitTxVoutItemStatus::Init
                && let Some(spend_txid) =
                    outpoint_spent_txid(btc_client, &txid, (index * 2) as u64).await?
            {
                if challenge_timeout_txids.iter().any(|v| v.0 == spend_txid) {
                    *status = WTInitTxVoutItemStatus::ChallengeTimeout;
                } else {
                    *status = WTInitTxVoutItemStatus::Challenge;
                }
            }

            if *status == WTInitTxVoutItemStatus::Challenge
                && let Some(spend_txid) =
                    outpoint_spent_txid(btc_client, &txid, (index * 2 + 1) as u64).await?
            {
                if nack_txids.iter().any(|v| v.0 == spend_txid) {
                    *status = WTInitTxVoutItemStatus::AckTimeout;
                } else {
                    *status = WTInitTxVoutItemStatus::Ack;
                }
            }
        }
        Ok(())
    }

    fn update_disprove_indexes(&mut self) {
        for (index, status) in self.data_map.iter() {
            if *status == WTInitTxVoutItemStatus::Init
                || *status == WTInitTxVoutItemStatus::Challenge
            {
                self.disproved_indexes.push(*index);
            }
        }
    }

    pub fn is_challenged(&self) -> bool {
        !self.disproved_indexes.is_empty() || self.is_commit_blockhash_timeout
    }
}

/// Assert init tx vout item status
#[derive(Clone, Debug, Serialize, Deserialize, Default, Eq, PartialEq, Display, EnumString)]
pub enum AssertInitTxVoutItemStatus {
    #[default]
    Init,
    Commit,
    CommitTimeout,
}
/// Assert init tx vout data
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct AssertInitTxVoutMonitorData {
    pub data_map: IndexMap<i32, AssertInitTxVoutItemStatus>,
    pub disproved_indexes: Vec<i32>, // default -1
}

impl AssertInitTxVoutMonitorData {
    pub async fn monitor_vout(
        &mut self,
        btc_client: &BTCClient,
        txid: &Txid,
        committ_timeout_txids: &[SerializableTxid],
    ) -> anyhow::Result<()> {
        for (k, status) in self.data_map.iter_mut() {
            let index = *k;
            if *status == AssertInitTxVoutItemStatus::Init
                && let Some(spend_txid) =
                    outpoint_spent_txid(btc_client, &txid, (index * 2) as u64).await?
            {
                if committ_timeout_txids.iter().any(|v| v.0 == spend_txid) {
                    *status = AssertInitTxVoutItemStatus::CommitTimeout;
                } else {
                    *status = AssertInitTxVoutItemStatus::Commit;
                }
            }
        }
        Ok(())
    }

    fn update_disprove_indexes(&mut self) {
        for (index, status) in self.data_map.iter() {
            if *status == AssertInitTxVoutItemStatus::Init {
                self.disproved_indexes.push(*index);
            }
        }
    }

    pub fn is_challenged(&self) -> bool {
        !self.disproved_indexes.is_empty()
    }
}

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
) -> anyhow::Result<()> {
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
) -> anyhow::Result<Vec<GraphWithBroadcastInfo>> {
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
pub async fn get_initialized_graphs(goat_client: &GOATClient) -> anyhow::Result<Vec<(Uuid, Uuid)>> {
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
pub async fn detect_init_withdraw_call(
    swarm: &mut Swarm<AllBehaviours>,
    local_db: &LocalDB,
    _goat_client: &GOATClient,
    btc_client: &BTCClient,
) -> anyhow::Result<()> {
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
            if btc_client.get_tx_status(&kickoff_txid.0).await?.confirmed {
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
) -> anyhow::Result<bool> {
    if outpoint_spent_txid(btc_client, &kickoff_txid, 0).await?.is_some() {
        tracing::trace!(
            "graph_id:{graph_id} kickoff:{kickoff_txid:?} output has been spend, no need to send kickoffSent message",
        );
        return Ok(false);
    }
    let tx_info = btc_client
        .get_tx_info(kickoff_txid)
        .await?
        .ok_or_else(|| anyhow::anyhow!("kickoff_txid {} not found", kickoff_txid.to_string()))?;
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
                GraphUpdate::new(graph_id.clone())
                    .with_status(GraphStatus::OperatorKickOff.to_string()),
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
pub async fn detect_kickoff(
    _swarm: &mut Swarm<AllBehaviours>,
    local_db: &LocalDB,
    btc_client: &BTCClient,
    goat_client: &GOATClient,
) -> anyhow::Result<()> {
    info!("start tick action: detect_kickoff");
    let mut storage_processor = local_db.acquire().await?;
    let graph_datas = fetch_graphs_with_status_and_msg_type(
        &mut storage_processor,
        vec![(GraphStatus::OperatorDataPushed, MessageType::KickoffSent)],
    )
    .await?;
    for graph_data in graph_datas {
        let kickoff_txid: Txid = match graph_data.kickoff_txid.clone() {
            Some(txid) => txid.into(),
            None => {
                warn!("graph_id {}, kickoff txid is none", graph_data.graph_id);
                continue;
            }
        };
        process_operator_data_pushed_graph(
            btc_client,
            goat_client,
            local_db,
            &graph_data.graph_id,
            &graph_data.instance_id,
            &kickoff_txid,
        )
        .await?;
    }

    Ok(())
}

pub async fn detect_take1_or_challenge(
    swarm: &mut Swarm<AllBehaviours>,
    local_db: &LocalDB,
    btc_client: &BTCClient,
    goat_client: &GOATClient,
) -> anyhow::Result<()> {
    info!("start tick action: detect_take1_or_challenge");
    let mut storage_processor = local_db.acquire().await?;
    let graph_datas = fetch_graphs_with_status_and_msg_type(
        &mut storage_processor,
        vec![
            (GraphStatus::OperatorKickOff, MessageType::KickoffSent),
            (GraphStatus::OperatorKickOff, MessageType::Take1Ready),
        ],
    )
    .await?;

    let mut graph_map: HashMap<Uuid, GraphWithBroadcastInfo> = HashMap::new();
    for graph_data in graph_datas {
        graph_map
            .entry(graph_data.graph_id)
            .and_modify(|v| {
                if graph_data.msg_type == MessageType::Take1Ready.to_string()
                    && graph_data.msg_times > 0
                {
                    *v = graph_data.clone()
                }
            })
            .or_insert(graph_data);
    }
    let current_height = btc_client.get_height().await?;
    // todo Update lock_blocks
    let lock_blocks = num_blocks_per_network(get_network(), CONNECTOR_3_TIMELOCK);

    for (_graph_id, mut graph_data) in graph_map {
        if graph_data.msg_type == MessageType::KickoffSent.to_string() {
            broadcast_message_and_record(
                swarm,
                &mut storage_processor,
                Actor::All,
                GOATMessageContent::KickoffSent(KickoffSent {
                    instance_id: graph_data.instance_id,
                    graph_id: graph_data.graph_id,
                    kickoff_txid: graph_data.kickoff_txid.clone().unwrap().0,
                }),
                &graph_data.clone(),
            )
            .await?;
            match process_kickoff_graph(
                btc_client,
                goat_client,
                local_db,
                &mut storage_processor,
                &graph_data,
                lock_blocks,
                current_height,
            )
            .await?
            {
                Some((actor, content)) => {
                    // first detected take1 ready
                    graph_data.msg_times = 0;
                    graph_data.last_msg_send_at = 0;
                    broadcast_message_and_record(
                        swarm,
                        &mut storage_processor,
                        actor,
                        content,
                        &graph_data,
                    )
                    .await?;
                }
                None => {}
            }
        } else {
            // Send P2P msg take1Ready
            broadcast_message_and_record(
                swarm,
                &mut storage_processor,
                Actor::Operator,
                GOATMessageContent::Take1Ready(Take1Ready {
                    instance_id: graph_data.instance_id,
                    graph_id: graph_data.graph_id,
                }),
                &graph_data.clone(),
            )
            .await?;
        }
    }
    Ok(())
}

pub async fn detect_watchtower_assert_init(
    swarm: &mut Swarm<AllBehaviours>,
    local_db: &LocalDB,
    btc_client: &BTCClient,
    _goat_client: &GOATClient,
) -> anyhow::Result<()> {
    info!("start tick action: detect_take1_or_challenge");
    let mut storage_processor = local_db.acquire().await?;
    let graph_datas = fetch_graphs_with_status_and_msg_type(
        &mut storage_processor,
        vec![(GraphStatus::Challenge, MessageType::ChallengeSent)],
    )
    .await?;

    for graph_data in graph_datas {
        let (challenge_txid, kickoff_txid, watchtower_challenge_init_txid, assert_init_txid): (
            Txid,
            Txid,
            Txid,
            Txid,
        ) = match (
            graph_data.challenge_txid.clone(),
            graph_data.kickoff_txid.clone(),
            graph_data.watchtower_challenge_init_txid.clone(),
            graph_data.assert_init_txid.clone(),
        ) {
            (
                Some(challenge_txid),
                Some(kickoff_txid),
                Some(watchtower_challenge_init_txid),
                Some(assert_init_txid),
            ) => (
                challenge_txid.into(),
                kickoff_txid.into(),
                watchtower_challenge_init_txid.into(),
                assert_init_txid.into(),
            ),
            _ => {
                warn!(
                    "graph_id {}, challenge or kickoff or watchtower challenge init or assert init txid  is none",
                    graph_data.graph_id
                );
                continue;
            }
        };
        // broadcast p2p message challengeSent
        broadcast_message_and_record(
            swarm,
            &mut storage_processor,
            Actor::Operator,
            GOATMessageContent::ChallengeSent(ChallengeSent {
                instance_id: graph_data.instance_id,
                graph_id: graph_data.graph_id,
                challenge_txid: challenge_txid.into(),
            }),
            &graph_data.clone(),
        )
        .await?;
        process_challenge_status_graph(
            btc_client,
            local_db,
            &graph_data,
            kickoff_txid,
            watchtower_challenge_init_txid,
            assert_init_txid,
        )
        .await?;
    }
    Ok(())
}
/// Handle Take1 transaction completion
async fn handle_take1_completion(
    btc_client: &BTCClient,
    goat_client: &GOATClient,
    local_db: &LocalDB,
    graph_data: &GraphWithBroadcastInfo,
    take1_txid: Txid,
) -> anyhow::Result<()> {
    info!(
        "Processing Take1 completion for graph_id: {}, take1_txid: {}",
        graph_data.graph_id, take1_txid
    );

    let take1_tx = btc_client
        .get_tx(&take1_txid)
        .await?
        .ok_or_else(|| anyhow::anyhow!("take1 {} not found", take1_txid.to_string()))?;

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

            let mut tx = local_db.start_transaction().await?;

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
            .await?;

            tx.update_graph_fields(
                GraphUpdate::new(graph_data.graph_id)
                    .with_status(GraphStatus::OperatorTake1.to_string()),
            )
            .await?;

            tx.commit().await?;

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
) -> anyhow::Result<()> {
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
        .await?;

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
) -> anyhow::Result<Option<GOATMessageContent>> {
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
) -> anyhow::Result<Option<(Actor, GOATMessageContent)>> {
    let (kickoff_txid, take1_txid) =
        match (graph_data.kickoff_txid.clone(), graph_data.take1_txid.clone()) {
            (Some(kickoff), Some(take1)) => (kickoff.into(), take1.into()),
            _ => {
                warn!("graph_id:{}, kickoff or take1 is none", graph_data.graph_id);
                return Ok(None);
            }
        };

    let spent_txid = match outpoint_spent_txid(btc_client, &kickoff_txid, 0).await? {
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

//Tick-Task-5:
pub async fn detected_take2(
    _swarm: &mut Swarm<AllBehaviours>,
    _local_db: &LocalDB,
    _btc_client: &BTCClient,
    _goat_client: &GOATClient,
) -> anyhow::Result<()> {
    Ok(())
}

pub async fn scan_obsolete_sibling_graphs(local_db: &LocalDB) -> anyhow::Result<()> {
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

/// Process watchtower challenge init transaction detection
async fn handle_watchtower_challenge_init_detection(
    btc_client: &BTCClient,
    local_db: &LocalDB,
    graph_data: &GraphWithBroadcastInfo,
    kickoff_txid: Txid,
    watchtower_challenge_init_txid: Txid,
) -> anyhow::Result<()> {
    if let Some(spent_txid) = outpoint_spent_txid(btc_client, &kickoff_txid, 1).await?
        && spent_txid == watchtower_challenge_init_txid
    {
        info!(
            "graph_id: {} watchtower_challenge_init_txid {} has been broadcasted",
            graph_data.graph_id,
            watchtower_challenge_init_txid.to_string()
        );

        let watchtower_challenge_init_tx =
            btc_client.get_tx_info(&watchtower_challenge_init_txid).await?.ok_or_else(|| {
                anyhow::anyhow!(
                    "watchtower_challenge_init_txid {} not found",
                    watchtower_challenge_init_txid.to_string()
                )
            })?;

        let mut tx = local_db.start_transaction().await?;
        tx.update_graph_fields(
            GraphUpdate::new(graph_data.graph_id)
                .with_status(GraphStatus::OperatorWatchtowerAndAssertInit.to_string()),
        )
        .await?;
        tx.upsert_graph_btc_tx_vout_monitor(&GraphBtcTxVoutMonitor {
            graph_id: graph_data.graph_id,
            txid: watchtower_challenge_init_txid.into(),
            height: watchtower_challenge_init_tx.status.block_height.unwrap_or_default() as i64,
            vout_len: watchtower_challenge_init_tx.vout.len() as i64,
            monitor_data: serde_json::to_string(&WTInitTxVoutMonitorData::default())?,
            created_at: current_time_secs(),
            updated_at: current_time_secs(),
        })
        .await?;
        tx.commit().await?;
    }
    Ok(())
}

/// Process assert init transaction detection
async fn handle_assert_init_detection(
    btc_client: &BTCClient,
    local_db: &LocalDB,
    graph_data: &GraphWithBroadcastInfo,
    kickoff_txid: Txid,
    assert_init_txid: Txid,
) -> anyhow::Result<()> {
    if let Some(spent_txid) = outpoint_spent_txid(btc_client, &kickoff_txid, 2).await?
        && spent_txid == assert_init_txid
    {
        info!(
            "graph_id: {} assert_init_txid {} has been broadcasted",
            graph_data.graph_id,
            assert_init_txid.to_string()
        );

        let assert_init_tx = btc_client.get_tx_info(&assert_init_txid).await?.ok_or_else(|| {
            anyhow::anyhow!("assert_init_txid {} not found", assert_init_txid.to_string())
        })?;

        let mut tx = local_db.start_transaction().await?;
        tx.update_graph_fields(
            GraphUpdate::new(graph_data.graph_id)
                .with_status(GraphStatus::OperatorWatchtowerAndAssertInit.to_string()),
        )
        .await?;
        tx.upsert_graph_btc_tx_vout_monitor(&GraphBtcTxVoutMonitor {
            graph_id: graph_data.graph_id,
            txid: assert_init_txid.into(),
            height: assert_init_tx.status.block_height.unwrap_or_default() as i64,
            vout_len: assert_init_tx.vout.len() as i64,
            monitor_data: serde_json::to_string(&AssertInitTxVoutMonitorData::default())?,
            created_at: current_time_secs(),
            updated_at: current_time_secs(),
        })
        .await?;
        tx.commit().await?;
    }
    Ok(())
}

/// Parse monitor data from JSON string
fn parse_monitor_data<T>(monitor_data: &str) -> anyhow::Result<T>
where
    T: serde::de::DeserializeOwned,
{
    serde_json::from_str(monitor_data)
        .map_err(|e| anyhow::anyhow!("Failed to parse monitor data: {}", e))
}

/// Check if watchtower challenge is already finished and return monitor data if exists
async fn check_watchtower_challenge_finished(
    storage_processor: &mut StorageProcessor<'_>,
    graph_data: &GraphWithBroadcastInfo,
    watchtower_challenge_init_txid: Txid,
) -> anyhow::Result<(bool, Option<(WTInitTxVoutMonitorData, i64, i64)>)> {
    let watchtower_init_out_monitor = storage_processor
        .get_graph_btc_tx_vout_monitor(&graph_data.graph_id, &watchtower_challenge_init_txid.into())
        .await?;

    if let Some(out_monitor) = watchtower_init_out_monitor {
        if let Ok(vout_monitor_data) =
            parse_monitor_data::<WTInitTxVoutMonitorData>(&out_monitor.monitor_data)
        {
            let is_finished = vout_monitor_data.is_challenged();
            return Ok((
                is_finished,
                Some((vout_monitor_data, out_monitor.height, out_monitor.vout_len)),
            ));
        }
    }
    Ok((false, None))
}

/// Check if assert commit is already finished and return monitor data if exists
async fn check_assert_commit_finished(
    storage_processor: &mut StorageProcessor<'_>,
    graph_data: &GraphWithBroadcastInfo,
    assert_init_txid: Txid,
) -> anyhow::Result<(bool, Option<(AssertInitTxVoutMonitorData, i64, i64)>)> {
    let assert_init_out_monitor = storage_processor
        .get_graph_btc_tx_vout_monitor(&graph_data.graph_id, &assert_init_txid.into())
        .await?;

    if let Some(out_monitor) = assert_init_out_monitor {
        if let Ok(vout_monitor_data) =
            parse_monitor_data::<AssertInitTxVoutMonitorData>(&out_monitor.monitor_data)
        {
            let is_finished = vout_monitor_data.is_challenged();
            return Ok((
                is_finished,
                Some((vout_monitor_data, out_monitor.height, out_monitor.vout_len)),
            ));
        }
    }
    Ok((false, None))
}

/// Process watchtower challenge monitoring
async fn process_watchtower_challenge_monitoring(
    btc_client: &BTCClient,
    storage_processor: &mut StorageProcessor<'_>,
    graph_data: &GraphWithBroadcastInfo,
    kickoff_txid: Txid,
    watchtower_challenge_init_txid: Txid,
    watchtower_challenge_timelock: i64,
    ack_timelock: i64,
    blockhash_commit_timeout_lock: i64,
    current_height: i64,
    monitor_data: Option<(WTInitTxVoutMonitorData, i64, i64)>,
) -> anyhow::Result<()> {
    if let Some((mut vout_monitor_data, height, vout_len)) = monitor_data {
        if vout_monitor_data.is_challenged() {
            // TODO send p2p message: watchtower_challenge_finish
            return Ok(());
        }

        let is_challenge_timeout = height + watchtower_challenge_timelock > current_height;
        let is_ack_timeout = height + ack_timelock > current_height;
        let is_blockhash_commit_timeout = height + blockhash_commit_timeout_lock > current_height;

        if !is_ack_timeout {
            if is_challenge_timeout {
                info!("watchtower challenge timeout");
                // TODO send p2p message watchtower challenge timeout
            } else {
                info!("watchtower challenge init sent");
                // TODO send p2p message watchtower challenge init sent
            }

            vout_monitor_data
                .monitor_vout(
                    btc_client,
                    &watchtower_challenge_init_txid,
                    &graph_data.watchtower_challenge_timeout_txids,
                    &graph_data.nack_txids,
                )
                .await?;

            if is_blockhash_commit_timeout {
                let spend_txid = outpoint_spent_txid(
                    btc_client,
                    &watchtower_challenge_init_txid,
                    (vout_len - BLOCKHASH_COMMIT_VIN_MARGIN) as u64,
                )
                .await?;
                if spend_txid.is_none() {
                    vout_monitor_data.is_commit_blockhash_timeout = true;
                } else {
                    if let Some(txid) = graph_data.blockhash_commit_timeout_txid.clone()
                        && txid.0 == spend_txid.unwrap()
                    {
                        vout_monitor_data.is_commit_blockhash_timeout = true;
                    }
                }
            }

            for (_index, status) in vout_monitor_data.data_map.iter() {
                if *status == WTInitTxVoutItemStatus::Challenge {
                    info!("watchtower challenge tx has been sent");
                    // TODO send p2p message: watchtower challenge tx sent
                }
            }

            storage_processor
                .update_graph_btc_tx_vout_monitor_data(
                    &graph_data.graph_id,
                    serde_json::to_string(&vout_monitor_data)?,
                )
                .await?;
        } else {
            vout_monitor_data.update_disprove_indexes();
        }
        // TODO commit block hash check
    } else {
        // Create monitor if watchtower challenge init transaction is detected
        if let Some(spent_txid) = outpoint_spent_txid(btc_client, &kickoff_txid, 1).await?
            && spent_txid == watchtower_challenge_init_txid
        {
            info!(
                "graph_id: {} watchtower_challenge_init_txid {} has been broadcasted",
                graph_data.graph_id,
                watchtower_challenge_init_txid.to_string()
            );

            let watchtower_challenge_init_tx = btc_client
                .get_tx_info(&watchtower_challenge_init_txid)
                .await?
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "watchtower_challenge_init_txid {} not found",
                        watchtower_challenge_init_txid.to_string()
                    )
                })?;

            storage_processor
                .upsert_graph_btc_tx_vout_monitor(&GraphBtcTxVoutMonitor {
                    graph_id: graph_data.graph_id,
                    txid: watchtower_challenge_init_txid.into(),
                    height: watchtower_challenge_init_tx.status.block_height.unwrap_or_default()
                        as i64,
                    vout_len: watchtower_challenge_init_tx.vout.len() as i64,
                    monitor_data: serde_json::to_string(&WTInitTxVoutMonitorData::default())?,
                    created_at: current_time_secs(),
                    updated_at: current_time_secs(),
                })
                .await?;
        }
    }

    Ok(())
}

/// Process assert commit monitoring
async fn process_assert_commit_monitoring(
    btc_client: &BTCClient,
    storage_processor: &mut StorageProcessor<'_>,
    graph_data: &GraphWithBroadcastInfo,
    kickoff_txid: Txid,
    assert_init_txid: Txid,
    assert_commit_timeout_lock: i64,
    current_height: i64,
    monitor_data: Option<(AssertInitTxVoutMonitorData, i64, i64)>,
) -> anyhow::Result<()> {
    if let Some((mut vout_monitor_data, height, _vout_len)) = monitor_data {
        if vout_monitor_data.is_challenged() {
            // TODO send p2p message: assert_commit_finish
            return Ok(());
        }

        let is_assert_commit_timeout = height + assert_commit_timeout_lock > current_height;

        if !is_assert_commit_timeout {
            info!("assert commit monitoring active");
            // TODO send p2p message assert commit monitoring

            vout_monitor_data
                .monitor_vout(
                    btc_client,
                    &assert_init_txid,
                    &graph_data.assert_commit_timeout_txids,
                )
                .await?;
            storage_processor
                .update_graph_btc_tx_vout_monitor_data(
                    &graph_data.graph_id,
                    serde_json::to_string(&vout_monitor_data)?,
                )
                .await?;
        } else {
            vout_monitor_data.update_disprove_indexes();
        }
    } else {
        // Create monitor if assert init transaction is detected
        if let Some(spent_txid) = outpoint_spent_txid(btc_client, &kickoff_txid, 2).await?
            && spent_txid == assert_init_txid
        {
            info!(
                "graph_id: {} assert_init_txid {} has been broadcasted",
                graph_data.graph_id,
                assert_init_txid.to_string()
            );

            let assert_init_tx =
                btc_client.get_tx_info(&assert_init_txid).await?.ok_or_else(|| {
                    anyhow::anyhow!("assert_init_txid {} not found", assert_init_txid.to_string())
                })?;

            storage_processor
                .upsert_graph_btc_tx_vout_monitor(&GraphBtcTxVoutMonitor {
                    graph_id: graph_data.graph_id,
                    txid: assert_init_txid.into(),
                    height: assert_init_tx.status.block_height.unwrap_or_default() as i64,
                    vout_len: assert_init_tx.vout.len() as i64,
                    monitor_data: serde_json::to_string(&AssertInitTxVoutMonitorData::default())?,
                    created_at: current_time_secs(),
                    updated_at: current_time_secs(),
                })
                .await?;
        }
    }

    Ok(())
}

/// Process graph data in Challenge status
async fn process_challenge_status_graph(
    btc_client: &BTCClient,
    local_db: &LocalDB,
    graph_data: &GraphWithBroadcastInfo,
    kickoff_txid: Txid,
    watchtower_challenge_init_txid: Txid,
    assert_init_txid: Txid,
) -> anyhow::Result<()> {
    // Handle watchtower challenge init detection
    handle_watchtower_challenge_init_detection(
        btc_client,
        local_db,
        graph_data,
        kickoff_txid,
        watchtower_challenge_init_txid,
    )
    .await?;

    // Handle assert init detection
    handle_assert_init_detection(btc_client, local_db, graph_data, kickoff_txid, assert_init_txid)
        .await?;

    Ok(())
}

/// Process graph data in OperatorWatchtowerAndAssertInit status
async fn process_watchtower_assert_init_graph(
    btc_client: &BTCClient,
    storage_processor: &mut StorageProcessor<'_>,
    graph_data: &GraphWithBroadcastInfo,
    kickoff_txid: Txid,
    watchtower_challenge_init_txid: Txid,
    assert_init_txid: Txid,
    watchtower_challenge_timelock: i64,
    ack_timelock: i64,
    blockhash_commit_timeout_lock: i64,
    assert_commit_timeout_lock: i64,
    current_height: i64,
) -> anyhow::Result<()> {
    // Check if either process is already finished before calling the monitoring functions
    let (watchtower_finished, watchtower_monitor_data) = check_watchtower_challenge_finished(
        storage_processor,
        graph_data,
        watchtower_challenge_init_txid,
    )
    .await?;

    let (assert_finished, assert_monitor_data) =
        check_assert_commit_finished(storage_processor, graph_data, assert_init_txid).await?;

    // If either process is finished, skip both monitoring functions
    if watchtower_finished || assert_finished {
        if watchtower_finished {
            info!(
                "Watchtower challenge already finished, skipping both monitoring for graph {}",
                graph_data.graph_id
            );
        }
        if assert_finished {
            info!(
                "Assert commit already finished, skipping both monitoring for graph {}",
                graph_data.graph_id
            );
        }
        return Ok(());
    }

    // Process watchtower challenge monitoring with pre-parsed data
    process_watchtower_challenge_monitoring(
        btc_client,
        storage_processor,
        graph_data,
        kickoff_txid,
        watchtower_challenge_init_txid,
        watchtower_challenge_timelock,
        ack_timelock,
        blockhash_commit_timeout_lock,
        current_height,
        watchtower_monitor_data,
    )
    .await?;

    // Process assert commit monitoring with pre-parsed data
    process_assert_commit_monitoring(
        btc_client,
        storage_processor,
        graph_data,
        kickoff_txid,
        assert_init_txid,
        assert_commit_timeout_lock,
        current_height,
        assert_monitor_data,
    )
    .await?;

    Ok(())
}

/// Get timelock configurations
fn get_timelock_configs() -> (i64, i64, i64, i64) {
    let network = get_network();
    // TODO: Update lock_blocks - these may need different values based on protocol requirements
    let base_timelock = num_blocks_per_network(network, CONNECTOR_3_TIMELOCK) as i64;
    let watchtower_challenge_timelock = base_timelock;
    let ack_timelock = base_timelock;
    let assert_commit_timeout_lock = base_timelock;
    let blockhash_commit_timeout_lock = base_timelock;
    (
        watchtower_challenge_timelock,
        ack_timelock,
        blockhash_commit_timeout_lock,
        assert_commit_timeout_lock,
    )
}

pub async fn monitor_watchtower_assert(
    _swarm: &mut Swarm<AllBehaviours>,
    local_db: &LocalDB,
    btc_client: &BTCClient,
    _goat_client: &GOATClient,
) -> anyhow::Result<()> {
    info!("Starting monitor_watchtower_assert task");

    let mut storage_processor = local_db.acquire().await?;
    let graph_datas = fetch_graphs_with_status_and_msg_type(
        &mut storage_processor,
        vec![(GraphStatus::OperatorWatchtowerAndAssertInit, MessageType::None)],
    )
    .await?;
    info!("Found {} graphs to process in monitor_watchtower_assert", graph_datas.len());
    let current_height = btc_client.get_height().await? as i64;

    let (
        watchtower_challenge_timelock,
        ack_timelock,
        blockhash_commit_timeout_lock,
        assert_commit_timeout_lock,
    ) = get_timelock_configs();

    for graph_data in graph_datas {
        let (kickoff_txid, watchtower_challenge_init_txid, assert_init_txid) = match (
            graph_data.kickoff_txid.clone(),
            graph_data.watchtower_challenge_init_txid.clone(),
            graph_data.assert_init_txid.clone(),
        ) {
            (Some(kickoff_txid), Some(watchtower_challenge_init_txid), Some(assert_init_txid)) => (
                kickoff_txid.into(),
                watchtower_challenge_init_txid.into(),
                assert_init_txid.into(),
            ),
            _ => {
                warn!(
                    "graph_id {}  kickoff or watchtower challenge init or assert init txid  is none",
                    graph_data.graph_id
                );
                continue;
            }
        };
        process_watchtower_assert_init_graph(
            btc_client,
            &mut storage_processor,
            &graph_data,
            kickoff_txid,
            watchtower_challenge_init_txid,
            assert_init_txid,
            watchtower_challenge_timelock,
            ack_timelock,
            blockhash_commit_timeout_lock,
            assert_commit_timeout_lock,
            current_height,
        )
        .await?;
    }
    Ok(())
}
