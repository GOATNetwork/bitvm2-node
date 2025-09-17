use crate::action::{
    ChallengeSent, GOATMessage, GOATMessageContent, KickoffReady, KickoffSent, Take1Ready,
    Take2Ready, send_to_peer,
};
use crate::env::{MESSAGE_BROADCAST_MAX_TIMES, MESSAGE_RESEND_INTERVAL_SECOND, get_network};
use crate::middleware::AllBehaviours;
use crate::rpc_service::current_time_secs;
use crate::utils::{get_graph, outpoint_spent_txid};
use bitcoin::Txid;
use bitvm2_lib::actors::Actor;
use client::btc_chain::BTCClient;
use client::goat_chain::{DisproveTxType, GOATClient, WithdrawStatus};
use goat::constants::CONNECTOR_3_TIMELOCK;
use goat::utils::num_blocks_per_network;
use indexmap::IndexMap;
use libp2p::Swarm;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};
use store::localdb::{GraphQuery, GraphUpdate, LocalDB, StorageProcessor};
use store::{
    GoatTxProcessingStatus, GoatTxRecord, GoatTxType, Graph, GraphBtcTxVoutMonitor, GraphStatus,
    MessageBroadcast, MessageType, SerializableTxid,
};
use strum::{Display, EnumString};
use tracing::{info, trace, warn};
use uuid::Uuid;

const BLOCKHASH_COMMIT_VIN_MARGIN: i64 = 3;
const _ASSERT_COMMIT_VIN_MARGIN: i64 = 2;

#[derive(Clone, Debug, Eq, PartialEq, Display, EnumString)]
enum OperatorWithdrawType {
    Take1,
    Take2,
}

/// Watchtower init tx vout item status
#[derive(Clone, Debug, Serialize, Deserialize, Default, Eq, PartialEq, Display, EnumString)]
pub enum WatchtowerChallengeStatus {
    #[default]
    None,
    OperatorInit,
    Challenge,
    ChallengeTimeout,
    OperatorACK,
    OperatorNACK,
}
#[derive(Clone, Debug, Serialize, Deserialize, Default, Eq, PartialEq, Display, EnumString)]
pub enum CommitBlockHashStatus {
    #[default]
    None,
    OperatorInit,
    OperatorCommit,
    OperatorCommitTimeout,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct ChallengeSubStatus {
    pub watchtower_challenge_status: WatchtowerChallengeStatus,
    pub commit_blockhash_status: CommitBlockHashStatus,
    pub assert_commit_status: AssertCommitStatus,
}

impl ChallengeSubStatus {
    pub fn is_no_init(&self) -> bool {
        self.watchtower_challenge_status == WatchtowerChallengeStatus::None
            && self.assert_commit_status == AssertCommitStatus::None
    }

    #[allow(dead_code)]
    pub fn is_processing(&self) -> bool {
        vec![
            WatchtowerChallengeStatus::OperatorInit,
            WatchtowerChallengeStatus::Challenge,
            WatchtowerChallengeStatus::ChallengeTimeout,
        ]
        .contains(&self.watchtower_challenge_status)
            && self.assert_commit_status == AssertCommitStatus::OperatorInit
    }

    pub fn is_watchtower_challenge_finished(&self) -> bool {
        vec![WatchtowerChallengeStatus::OperatorACK, WatchtowerChallengeStatus::OperatorNACK]
            .contains(&self.watchtower_challenge_status)
            && [CommitBlockHashStatus::OperatorCommit, CommitBlockHashStatus::OperatorCommitTimeout]
                .contains(&self.commit_blockhash_status)
    }

    pub fn is_disproved(&self) -> bool {
        self.watchtower_challenge_status == WatchtowerChallengeStatus::OperatorNACK
            || self.commit_blockhash_status == CommitBlockHashStatus::OperatorCommitTimeout
            || self.assert_commit_status == AssertCommitStatus::OperatorCommitTimeout
    }

    pub fn is_normal_finished(&self) -> bool {
        self.watchtower_challenge_status == WatchtowerChallengeStatus::OperatorACK
            && self.commit_blockhash_status == CommitBlockHashStatus::OperatorCommit
            && self.assert_commit_status == AssertCommitStatus::OperatorCommit
    }

    pub fn is_assert_commit_finished(&self) -> bool {
        [AssertCommitStatus::OperatorCommitTimeout, AssertCommitStatus::OperatorCommit]
            .contains(&self.assert_commit_status)
    }
}
/// Watchtower init tx vout data
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WTInitTxVoutMonitorData {
    pub data_map: IndexMap<i32, WatchtowerChallengeStatus>,
    pub require_disproved_indexes: Vec<i32>,
    pub commit_blockhash_status: CommitBlockHashStatus,
    pub is_complete_in_time: bool,
}

impl WTInitTxVoutMonitorData {
    pub fn new(index_size: i32) -> Self {
        let mut data_map: IndexMap<i32, WatchtowerChallengeStatus> = IndexMap::new();
        for i in 0..index_size {
            data_map.insert(i, WatchtowerChallengeStatus::OperatorInit);
        }
        Self {
            data_map,
            require_disproved_indexes: vec![],
            commit_blockhash_status: CommitBlockHashStatus::OperatorInit,
            is_complete_in_time: false,
        }
    }
    pub async fn monitor_vout(
        &mut self,
        btc_client: &BTCClient,
        txid: &Txid,
        challenge_timeout_txids: &[SerializableTxid],
        nack_txids: &[SerializableTxid],
    ) -> anyhow::Result<i32> {
        let mut vout_spent_detect = 0;
        for (k, status) in self.data_map.iter_mut() {
            let index = *k;
            if *status == WatchtowerChallengeStatus::OperatorInit
                && let Some(spend_txid) =
                    outpoint_spent_txid(btc_client, &txid, (index * 2) as u64).await?
            {
                if challenge_timeout_txids.iter().any(|v| v.0 == spend_txid) {
                    *status = WatchtowerChallengeStatus::ChallengeTimeout;
                } else {
                    *status = WatchtowerChallengeStatus::Challenge;
                }
                vout_spent_detect += 1;
            }

            if *status == WatchtowerChallengeStatus::Challenge
                && let Some(spend_txid) =
                    outpoint_spent_txid(btc_client, &txid, (index * 2 + 1) as u64).await?
            {
                if nack_txids.iter().any(|v| v.0 == spend_txid) {
                    *status = WatchtowerChallengeStatus::OperatorNACK;
                } else {
                    *status = WatchtowerChallengeStatus::OperatorACK;
                }
                vout_spent_detect += 1;
            }
        }
        if vout_spent_detect > 0 {
            self.is_complete_in_time = self
                .data_map
                .values()
                .all(|status| *status == WatchtowerChallengeStatus::OperatorACK);
        }
        Ok(vout_spent_detect)
    }

    fn update_disprove_indexes(&mut self) {
        self.require_disproved_indexes = vec![];
        for (index, status) in self.data_map.iter() {
            if *status == WatchtowerChallengeStatus::OperatorInit
                || *status == WatchtowerChallengeStatus::Challenge
            {
                self.require_disproved_indexes.push(*index);
            }
        }
    }

    pub fn is_challenged(&self) -> bool {
        !self.require_disproved_indexes.is_empty()
            || self.commit_blockhash_status == CommitBlockHashStatus::OperatorCommitTimeout
    }

    #[allow(dead_code)]
    pub fn get_disprove_type(&self) -> Option<DisproveTxType> {
        if self.commit_blockhash_status == CommitBlockHashStatus::OperatorCommitTimeout {
            return Some(DisproveTxType::OperatorCommitTimeout);
        }
        if !self.require_disproved_indexes.is_empty() {
            return Some(DisproveTxType::OperatorNack);
        }
        None
    }

    #[allow(dead_code)]
    pub fn is_complete_in_time(&self) -> bool {
        self.is_complete_in_time
    }

    #[allow(dead_code)]
    pub fn is_finished(&self) -> bool {
        self.is_complete_in_time || self.is_challenged()
    }
}

/// Assert init tx vout item status
#[derive(Clone, Debug, Serialize, Deserialize, Default, Eq, PartialEq, Display, EnumString)]
pub enum AssertCommitStatus {
    #[default]
    None,
    OperatorInit,
    OperatorCommit,
    OperatorCommitTimeout,
}
/// Assert init tx vout data
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AssertInitTxVoutMonitorData {
    pub data_map: IndexMap<i32, AssertCommitStatus>,
    pub require_disproved_indexes: Vec<i32>,
    pub is_complete_in_time: bool,
}

impl AssertInitTxVoutMonitorData {
    pub fn new(index_size: i32) -> Self {
        let mut data_map: IndexMap<i32, AssertCommitStatus> = IndexMap::new();
        for i in 0..index_size {
            data_map.insert(i, AssertCommitStatus::OperatorInit);
        }
        Self { data_map, require_disproved_indexes: vec![], is_complete_in_time: false }
    }
    pub async fn monitor_vout(
        &mut self,
        btc_client: &BTCClient,
        txid: &Txid,
        committ_timeout_txids: &[SerializableTxid],
    ) -> anyhow::Result<i32> {
        let mut vout_spent_detect = 0;
        for (k, status) in self.data_map.iter_mut() {
            if *status == AssertCommitStatus::OperatorInit
                && let Some(spend_txid) = outpoint_spent_txid(btc_client, &txid, *k as u64).await?
            {
                if committ_timeout_txids.iter().any(|v| v.0 == spend_txid) {
                    *status = AssertCommitStatus::OperatorCommitTimeout;
                } else {
                    *status = AssertCommitStatus::OperatorCommit;
                }
                vout_spent_detect += 1
            }
        }
        if vout_spent_detect > 0 {
            self.is_complete_in_time =
                self.data_map.values().all(|status| *status == AssertCommitStatus::OperatorCommit);
        }

        Ok(vout_spent_detect)
    }

    fn update_disprove_indexes(&mut self) {
        self.require_disproved_indexes = vec![];
        for (index, status) in self.data_map.iter() {
            if *status == AssertCommitStatus::OperatorInit {
                self.require_disproved_indexes.push(*index);
            }
        }
    }

    #[allow(dead_code)]
    pub fn is_challenged(&self) -> bool {
        !self.require_disproved_indexes.is_empty()
    }

    #[allow(dead_code)]
    pub fn get_disprove_type(&self) -> Option<DisproveTxType> {
        if !self.require_disproved_indexes.is_empty() {
            return Some(DisproveTxType::AssertTimeout);
        }
        None
    }

    #[allow(dead_code)]
    pub fn is_complete_in_time(&self) -> bool {
        self.is_complete_in_time
    }

    #[allow(dead_code)]
    pub fn is_finished(&self) -> bool {
        self.is_complete_in_time || self.is_challenged()
    }
}

/// Parse monitor data from JSON string
fn parse_monitor_data<T>(monitor_data: &str) -> anyhow::Result<T>
where
    T: serde::de::DeserializeOwned,
{
    serde_json::from_str(monitor_data)
        .map_err(|e| anyhow::anyhow!("Failed to parse monitor data: {}", e))
}

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
    swarm: &mut Swarm<AllBehaviours>,
    storage_processor: &mut StorageProcessor<'_>,
    msg_detail: BroadcastMessageDetail,
) -> anyhow::Result<()> {
    if is_need_to_send_msg(msg_detail.pre_send_times, msg_detail.last_send_at) {
        send_to_peer(
            swarm,
            GOATMessage::from_typed(msg_detail.actor, &msg_detail.message_content)?,
        )?;
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
    let (graphs, _) = storage_processor
        .find_graphs(GraphQuery::default().with_status(graph_status.to_string()))
        .await?;

    let broadcasts = storage_processor.find_message_broadcasts(graph_status).await?;
    let broadcast_record_map: HashMap<String, MessageBroadcast> = broadcasts
        .into_iter()
        .map(|v| (gen_broadcast_record_map_key(v.graph_id, &v.graph_status, &v.msg_type), v))
        .collect();
    Ok((graphs, broadcast_record_map))
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
    trace!("start tick action: detect_init_withdraw_call");
    let mut storage_process = local_db.acquire().await?;
    let graphs = get_user_init_withdraw_graphs(&mut storage_process).await?;
    info!("start tick action: detect_init_withdraw_call get graphs:{}", graphs.len());
    let mut storage_processor = local_db.acquire().await?;
    for (instance_id, graph_id) in graphs {
        if let Ok(graph) = get_graph(local_db, Some(instance_id), graph_id).await
            && let Some(kickoff_txid) = graph.kickoff_txid.clone()
        {
            if btc_client.get_tx_status(&kickoff_txid.0).await?.confirmed {
                info!(
                    "{graph_id} kickoff has been sent, so no need to send kickoffReady message, update goat tx processing status to processed"
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
            trace!("{graph_id} on kickoff status need to send KickoffReady");
            let (msg_times, last_send_at) = storage_processor
                .get_message_broadcast_times(
                    &graph_id,
                    &GraphStatus::OperatorDataPushed.to_string(),
                    &MessageType::KickoffReady.to_string(),
                )
                .await?;
            if is_need_to_send_msg(msg_times, last_send_at) {
                trace!(
                    "{graph_id} on kickoff send KickoffReady at send info msg_times: {msg_times}, last_send_at:{last_send_at}"
                );
                let message_content =
                    GOATMessageContent::KickoffReady(KickoffReady { instance_id, graph_id });
                send_to_peer(swarm, GOATMessage::from_typed(Actor::Operator, &message_content)?)?;
                storage_processor
                    .add_message_broadcast_times(
                        &graph_id,
                        &GraphStatus::OperatorDataPushed.to_string(),
                        &MessageType::KickoffReady.to_string(),
                        1,
                    )
                    .await?;
            }
        } else {
            warn!(
                "instance_id: {instance_id} graph_id: {graph_id} fail to get graph from db or kickoff txid is none"
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
    trace!("start tick action: process_operator_data_pushed_graph");
    if outpoint_spent_txid(btc_client, &kickoff_txid, 0).await?.is_some() {
        trace!(
            "graph_id:{graph_id} kickoff: {} output has been spend, no need to send kickoffSent message",
            kickoff_txid.to_string()
        );
        return Ok(false);
    }
    let tx_info = btc_client
        .get_tx_info(kickoff_txid)
        .await?
        .ok_or_else(|| anyhow::anyhow!("kickoff {} not found", kickoff_txid.to_string()))?;
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
            warn!("process_operator_data_pushed_graph: err:{err:?}");
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
    trace!("start tick action: detect_kickoff");
    let mut storage_processor = local_db.acquire().await?;
    let (graphs, _broadcast_record_map) = fetch_graph_and_broadcast_record_map(
        &mut storage_processor,
        &GraphStatus::OperatorDataPushed.to_string(),
    )
    .await?;
    info!("start tick action: detect_kickoff, graphs: {}", graphs.len());
    for graph in graphs {
        let kickoff_txid: Txid = match graph.kickoff_txid.clone() {
            Some(txid) => txid.into(),
            None => {
                warn!("graph_id {}, kickoff txid is none", graph.graph_id);
                continue;
            }
        };
        process_operator_data_pushed_graph(
            btc_client,
            goat_client,
            local_db,
            &graph.graph_id,
            &graph.instance_id,
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
    trace!("start tick action: detect_take1_or_challenge");
    let mut storage_processor = local_db.acquire().await?;
    let (graphs, broadcast_record_map) = fetch_graph_and_broadcast_record_map(
        &mut storage_processor,
        &GraphStatus::OperatorKickOff.to_string(),
    )
    .await?;
    let current_height = btc_client.get_height().await?;
    info!(
        "start tick action: detect_take1_or_challenge, graphs: {current_height}, current_height: {}",
        graphs.len()
    );
    // todo Update lock_blocks
    let lock_blocks = num_blocks_per_network(get_network(), CONNECTOR_3_TIMELOCK);
    for graph in graphs {
        let take1_ready_record = broadcast_record_map
            .get(&gen_broadcast_record_map_key(
                graph.graph_id,
                &graph.sub_status,
                &MessageType::Take1Ready.to_string(),
            ))
            .unwrap_or(&Default::default())
            .clone();
        if take1_ready_record.msg_times == 0 {
            trace!("no take1 ready or challenge detected, need to send  kickoff sent message");
            let kickoff_sent_record = broadcast_record_map
                .get(&gen_broadcast_record_map_key(
                    graph.graph_id,
                    &graph.sub_status,
                    &MessageType::KickoffSent.to_string(),
                ))
                .unwrap_or(&Default::default())
                .clone();
            // take1 not ready
            broadcast_message_and_record(
                swarm,
                &mut storage_processor,
                BroadcastMessageDetail {
                    actor: Actor::All,
                    message_content: GOATMessageContent::KickoffSent(KickoffSent {
                        instance_id: graph.instance_id,
                        graph_id: graph.graph_id,
                        kickoff_txid: graph.kickoff_txid.clone().unwrap().0,
                    }),
                    graph_id: graph.graph_id,
                    graph_status: GraphStatus::OperatorKickOff.to_string(),
                    msg_type: MessageType::KickoffSent.to_string(),
                    pre_send_times: kickoff_sent_record.msg_times,
                    last_send_at: kickoff_sent_record.updated_at,
                },
            )
            .await?;
        }
        match process_kickoff_graph(
            btc_client,
            goat_client,
            local_db,
            &graph,
            lock_blocks,
            current_height,
        )
        .await?
        {
            Some((actor, message_content)) => {
                info!("process_kickoff_graph detect take1 ready");
                // first detected take1 ready
                broadcast_message_and_record(
                    swarm,
                    &mut storage_processor,
                    BroadcastMessageDetail {
                        actor,
                        message_content,
                        graph_id: graph.graph_id,
                        graph_status: GraphStatus::OperatorKickOff.to_string(),
                        msg_type: MessageType::Take1Ready.to_string(),
                        pre_send_times: take1_ready_record.msg_times,
                        last_send_at: take1_ready_record.updated_at,
                    },
                )
                .await?;
            }
            None => {}
        }
    }
    Ok(())
}

pub async fn process_graph_challenge(
    swarm: &mut Swarm<AllBehaviours>,
    local_db: &LocalDB,
    btc_client: &BTCClient,
    goat_client: &GOATClient,
) -> anyhow::Result<()> {
    info!("start tick action: process_graph_challenge");
    let mut storage_processor = local_db.acquire().await?;
    let (graphs, broadcast_record_map) = fetch_graph_and_broadcast_record_map(
        &mut storage_processor,
        &GraphStatus::Challenge.to_string(),
    )
    .await?;
    let current_height = btc_client.get_height().await? as i64;

    for graph in graphs {
        let mut sub_status: ChallengeSubStatus = match serde_json::from_str(&graph.sub_status) {
            Ok(sub_status) => sub_status,
            Err(_) => {
                warn!(
                    "process_graph_challenge failed to deserialize sub_status at graph:{}, {}",
                    graph.graph_id, graph.sub_status
                );
                continue;
            }
        };
        let challenge_txid: Txid = match graph.challenge_txid.clone() {
            Some(challenge_txid) => challenge_txid.into(),
            _ => {
                warn!(
                    "process_graph_challenge graph_id {}, challenge txid is none",
                    graph.graph_id
                );
                return Ok(());
            }
        };

        if !sub_status.is_disproved() {
            trace!("process_graph_challenge graph:{} is not disproved", graph.graph_id);
            if sub_status.is_no_init() {
                let challenge_sent_record = broadcast_record_map
                    .get(&gen_broadcast_record_map_key(
                        graph.graph_id,
                        &graph.status,
                        &MessageType::ChallengeSent.to_string(),
                    ))
                    .unwrap_or(&MessageBroadcast::default())
                    .clone();
                // broadcast p2p message challengeSent
                broadcast_message_and_record(
                    swarm,
                    &mut storage_processor,
                    BroadcastMessageDetail {
                        actor: Actor::Operator,
                        message_content: GOATMessageContent::ChallengeSent(ChallengeSent {
                            instance_id: graph.instance_id,
                            graph_id: graph.graph_id,
                            challenge_txid,
                        }),
                        graph_id: Default::default(),
                        graph_status: graph.sub_status.clone(),
                        msg_type: MessageType::ChallengeSent.to_string(),
                        pre_send_times: challenge_sent_record.msg_times,
                        last_send_at: challenge_sent_record.updated_at,
                    },
                )
                .await?;
            }
            if !sub_status.is_assert_commit_finished() {
                trace!(
                    "process_graph_challenge graph:{} is assert commit is processing",
                    graph.graph_id
                );
                process_assert_commit_monitoring(
                    btc_client,
                    &mut storage_processor,
                    &graph,
                    &mut sub_status,
                    current_height,
                )
                .await?;
            }

            if !sub_status.is_watchtower_challenge_finished() {
                trace!(
                    "process_graph_challenge graph:{} is not watchtower challenge is processing",
                    graph.graph_id
                );
                process_watchtower_challenge_monitoring(
                    btc_client,
                    &mut storage_processor,
                    &graph,
                    &mut sub_status,
                    current_height,
                )
                .await?;
            }

            if sub_status.is_normal_finished() {
                trace!(
                    "process_graph_challenge graph:{} is not watchtower challenge and assert commit is finished",
                    graph.graph_id
                );
                detect_take2(btc_client, goat_client, local_db, &graph, current_height).await?;
            }
        } else {
            trace!("process_graph_challenge graph:{} is not disproved", graph.graph_id);
            process_graph_watchtower_assert_disproved(
                btc_client,
                goat_client,
                local_db,
                &graph,
                &mut sub_status,
            )
            .await?;
        }
    }

    Ok(())
}

/// Handle Take1 transaction completion
async fn handle_operator_withdraw_completion(
    btc_client: &BTCClient,
    goat_client: &GOATClient,
    storage_processor: &mut StorageProcessor<'_>,
    instance_id: Uuid,
    graph_id: Uuid,
    withdraw_type: OperatorWithdrawType,
    txid: Txid,
) -> anyhow::Result<bool> {
    info!(
        "handle_operator_withdraw_completion for graph_id: {graph_id}, {withdraw_type} txid: {}",
        txid.to_string()
    );

    let btc_tx = btc_client.get_tx(&txid).await?.ok_or_else(|| {
        anyhow::anyhow!("graph_id: {graph_id}, {withdraw_type} {} not found", txid.to_string())
    })?;

    let (call_contract_res, status, tx_type) = match withdraw_type {
        OperatorWithdrawType::Take1 => (
            goat_client.gateway_finish_withdraw_happy_path(btc_client, &graph_id, &btc_tx).await,
            GraphStatus::OperatorTake1.to_string(),
            GoatTxType::WithdrawHappyPath.to_string(),
        ),
        OperatorWithdrawType::Take2 => (
            goat_client.gateway_finish_withdraw_unhappy_path(btc_client, &graph_id, &btc_tx).await,
            GraphStatus::OperatorTake2.to_string(),
            GoatTxType::WithdrawUnhappyPath.to_string(),
        ),
    };

    let data_change = match call_contract_res {
        Err(err) => {
            warn!(
                "failed to operator withdraw {withdraw_type} for graph_id: {graph_id}, error: {err:?}. Will retry later."
            );
            false
        }
        Ok(tx_hash) => {
            info!(
                "successfully  operator withdraw {withdraw_type} for graph_id: {graph_id}, tx_hash: {tx_hash}"
            );

            let block_height = match goat_client.get_tx_receipt(&tx_hash).await? {
                Some(receipt) => receipt.block_number.unwrap_or(0),
                None => {
                    warn!("No receipt found for tx_hash: {}", tx_hash);
                    0
                }
            };

            storage_processor
                .upsert_goat_tx_record(&GoatTxRecord {
                    instance_id,
                    graph_id,
                    tx_type,
                    tx_hash,
                    height: block_height as i64,
                    is_local: true,
                    processing_status: GoatTxProcessingStatus::Skipped.to_string(),
                    extra: None,
                    created_at: current_time_secs(),
                })
                .await?;

            storage_processor
                .update_graph_fields(GraphUpdate::new(graph_id).with_status(status))
                .await?;
            info!(
                "successfully updated database for graph_id: {graph_id} to operator withdraw {withdraw_type}",
            );
            true
        }
    };
    Ok(data_change)
}

/// Handle Challenge transaction detection
async fn handle_challenge_detected(
    storage_processor: &mut StorageProcessor<'_>,
    graph_id: Uuid,
    challenge_txid: Txid,
) -> anyhow::Result<()> {
    info!(
        "handle_challenge_detected for graph_id: {graph_id}, challenge_txid: {}",
        challenge_txid.to_string()
    );

    let sub_status = serde_json::to_string(&ChallengeSubStatus::default())?;
    storage_processor
        .update_graph_fields(
            GraphUpdate::new(graph_id)
                .with_status(GraphStatus::Challenge.to_string())
                .with_challenge_txid(challenge_txid.into())
                .with_sub_status(sub_status),
        )
        .await?;

    info!("successfully updated graph_id: {graph_id} to challenge status");
    Ok(())
}

/// Check if Take1Ready Take2Ready message needs to be sent
async fn check_operator_withdraw_ready_condition(
    btc_client: &BTCClient,
    storage_processor: &mut StorageProcessor<'_>,
    graph_id: Uuid,
    check_tx_items: Vec<(Txid, OperatorWithdrawType, i64, i64)>, // (txid, tag,  height, lock_blocks)
    current_height: i64,
) -> anyhow::Result<(bool, bool)> {
    info!(
        "check_operator_withdraw_ready_condition for graph_id: {graph_id}, check tx size: {}",
        check_tx_items.len()
    );

    let mut ready = true;
    let mut data_change = false;
    for (txid, operator_withdraw_type, height, lock_blocks) in check_tx_items {
        let height = if height <= 0 {
            let current_times = current_time_secs();
            let (height, vout_len) = match btc_client.get_tx_info(&txid).await? {
                Some(tx_info) => (
                    tx_info.status.block_height.unwrap_or_default() as i64,
                    tx_info.vout.len() as i64,
                ),
                None => {
                    info!(
                        "graph_id:{graph_id}, {operator_withdraw_type} txid {} not on chain",
                        txid.to_string()
                    );
                    return Ok((false, data_change));
                }
            };
            storage_processor
                .upsert_graph_btc_tx_vout_monitor(&GraphBtcTxVoutMonitor {
                    graph_id,
                    txid: txid.into(),
                    height,
                    vout_len,
                    monitor_data: "".to_string(),
                    created_at: current_times,
                    updated_at: current_times,
                })
                .await?;
            data_change = true;
            height
        } else {
            height
        };

        if height == 0 || height > 0 && height + lock_blocks > current_height {
            ready = false;
            break;
        }
    }
    Ok((ready, data_change))
}

/// Process graph data in KickOff status
async fn process_kickoff_graph(
    btc_client: &BTCClient,
    goat_client: &GOATClient,
    local_db: &LocalDB,
    graph: &Graph,
    lock_blocks: u32,
    current_height: u32,
) -> anyhow::Result<Option<(Actor, GOATMessageContent)>> {
    trace!("process_kickoff_graph: {}", graph.graph_id);
    let (kickoff_txid, take1_txid) = match (graph.kickoff_txid.clone(), graph.take1_txid.clone()) {
        (Some(kickoff), Some(take1)) => (kickoff.into(), take1.into()),
        _ => {
            warn!("process_kickoff_graph graph_id:{}, kickoff or take1 is none", graph.graph_id);
            return Ok(None);
        }
    };

    let mut tx = local_db.start_transaction().await?;
    let spent_txid = match outpoint_spent_txid(btc_client, &kickoff_txid, 0).await? {
        Some(txid) => txid,
        None => {
            // kickoff output not spent, check if we need to send Take1Ready
            let height = tx
                .get_graph_btc_tx_vout_monitor(&graph.graph_id, &kickoff_txid.into())
                .await?
                .unwrap_or_default()
                .height;
            let (ready, data_change) = check_operator_withdraw_ready_condition(
                btc_client,
                &mut tx,
                graph.graph_id,
                vec![(kickoff_txid, OperatorWithdrawType::Take1, height, lock_blocks as i64)],
                current_height as i64,
            )
            .await?;
            if data_change {
                tx.commit().await?;
            }

            if ready {
                info!(
                    "process_kickoff_graph graph_id:{}, take1 is ready to send to btc chain",
                    graph.graph_id
                );
                return Ok(Some((
                    Actor::Operator,
                    GOATMessageContent::Take1Ready(Take1Ready {
                        instance_id: graph.instance_id,
                        graph_id: graph.graph_id,
                    }),
                )));
            } else {
                trace!("process_kickoff_graph graph_id:{}, take1 not ready", graph.graph_id);
            }
            return Ok(None);
        }
    };
    let mut tx = local_db.start_transaction().await?;
    let data_change = if spent_txid == take1_txid {
        info!(
            "process_kickoff_graph graph_id:{}, take1 is on chain, will try call contract",
            graph.graph_id
        );
        // Take1 was sent
        handle_operator_withdraw_completion(
            btc_client,
            goat_client,
            &mut tx,
            graph.instance_id,
            graph.graph_id,
            OperatorWithdrawType::Take1,
            take1_txid,
        )
        .await?
    } else {
        info!(
            "process_kickoff_graph graph_id:{}, challenge txid: {} has been detected.",
            graph.graph_id,
            spent_txid.to_string()
        );
        // Challenge was sent
        handle_challenge_detected(&mut tx, graph.graph_id, spent_txid).await?;
        true
    };
    if data_change {
        tx.commit().await?;
    }

    Ok(None)
}

pub async fn scan_obsolete_sibling_graphs(local_db: &LocalDB) -> anyhow::Result<()> {
    trace!("scan_obsolete_sibling_graphs");
    let mut tx = local_db.start_transaction().await?;
    let mut tx_records = tx
        .get_goat_tx_record_by_processing_status(
            &GoatTxType::WithdrawHappyPath.to_string(),
            &GoatTxProcessingStatus::Pending.to_string(),
        )
        .await?;
    info!("scan_obsolete_sibling_graphs:  take1 finished recently:{}", tx_records.len());
    let mut unhappy_path_records = tx
        .get_goat_tx_record_by_processing_status(
            &GoatTxType::WithdrawUnhappyPath.to_string(),
            &GoatTxProcessingStatus::Pending.to_string(),
        )
        .await?;
    info!("scan_obsolete_sibling_graphs:  take2 finished recently:{}", unhappy_path_records.len());
    tx_records.append(&mut unhappy_path_records);
    info!("scan_obsolete_sibling_graphs: {:?}", tx_records.len());

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

/// Process watchtower challenge monitoring
async fn process_watchtower_challenge_monitoring(
    btc_client: &BTCClient,
    storage_processor: &mut StorageProcessor<'_>,
    graph: &Graph,
    sub_status: &mut ChallengeSubStatus,
    current_height: i64,
) -> anyhow::Result<()> {
    trace!("process_watchtower_challenge_monitoring start");
    let (
        watchtower_challenge_timelock,
        ack_timelock,
        blockhash_commit_timeout_lock,
        _assert_commit_timeout_lock,
    ) = get_timelock_configs();
    let (kickoff_txid, watchtower_challenge_init_txid, blockhash_commit_timeout_txid): (
        Txid,
        Txid,
        Txid,
    ) = match (
        graph.kickoff_txid.clone(),
        graph.watchtower_challenge_init_txid.clone(),
        graph.blockhash_commit_timeout_txid.clone(),
    ) {
        (
            Some(kickoff_txid),
            Some(watchtower_challenge_init_txid),
            Some(blockhash_commit_timeout_txid),
        ) => (
            kickoff_txid.into(),
            watchtower_challenge_init_txid.into(),
            blockhash_commit_timeout_txid.into(),
        ),
        _ => {
            warn!(
                "process_watchtower_challenge_monitoring graph_id {}  kickoff txid, watchtower challenge init txid  or blockhash commit timeout txid is none",
                graph.graph_id
            );
            return Ok(());
        }
    };

    if let Some(out_monitor) = storage_processor
        .get_graph_btc_tx_vout_monitor(&graph.graph_id, &watchtower_challenge_init_txid.into())
        .await?
    {
        let mut vout_monitor_data = match parse_monitor_data::<WTInitTxVoutMonitorData>(
            &out_monitor.monitor_data,
        ) {
            Ok(vout_monitor_data) => vout_monitor_data,
            Err(_) => {
                warn!(
                    "process_watchtower_challenge_monitoring graph_id {} fail to parse monitor data",
                    graph.graph_id
                );
                return Ok(());
            }
        };
        if vout_monitor_data.is_challenged() {
            trace!(
                "process_watchtower_challenge_monitoring graph id :{} need to send p2p message: watchtower challenge is challenged",
                graph.graph_id
            );
            // TODO send p2p message: assert_commit_finish
            return Ok(());
        }
        let is_challenge_timeout =
            out_monitor.height + watchtower_challenge_timelock > current_height;
        let is_ack_timeout = out_monitor.height + ack_timelock > current_height;
        let is_blockhash_commit_timeout =
            out_monitor.height + blockhash_commit_timeout_lock > current_height;
        let mut data_change = false;
        if !is_ack_timeout {
            if is_challenge_timeout {
                info!(
                    "process_watchtower_challenge_monitoring watchtower challenge timeout for graph id :{}",
                    graph.graph_id
                );
                if vout_monitor_data
                    .data_map
                    .iter()
                    .any(|(_, v)| *v == WatchtowerChallengeStatus::OperatorInit)
                {
                    sub_status.watchtower_challenge_status =
                        WatchtowerChallengeStatus::ChallengeTimeout;
                    data_change = true;
                }
                // TODO send p2p message watchtower challenge timeout
            } else {
                trace!(
                    "process_watchtower_challenge_monitoring graph id :{} need to send p2p message: watchtower challenge init on chain",
                    graph.graph_id
                );
                // TODO send p2p message watchtower challenge init sent
            }
            if vout_monitor_data
                .monitor_vout(
                    btc_client,
                    &watchtower_challenge_init_txid,
                    &graph.watchtower_challenge_timeout_txids,
                    &graph.nack_txids,
                )
                .await?
                > 0
            {
                trace!(
                    "process_watchtower_challenge_monitoring graph id :{} monitor_vout detect vout spent",
                    graph.graph_id
                );
                data_change = true;
                if sub_status.watchtower_challenge_status == WatchtowerChallengeStatus::OperatorInit
                    && !vout_monitor_data
                        .data_map
                        .iter()
                        .any(|(_, v)| *v == WatchtowerChallengeStatus::OperatorInit)
                {
                    info!(
                        "process_watchtower_challenge_monitoring graph id :{} sub status update to  WatchtowerChallengeStatus::Challenge",
                        graph.graph_id
                    );
                    // all in challenge
                    sub_status.watchtower_challenge_status = WatchtowerChallengeStatus::Challenge;
                    data_change = true;
                }
            }

            if vout_monitor_data.commit_blockhash_status == CommitBlockHashStatus::OperatorInit {
                if !is_blockhash_commit_timeout {
                    if let Some(spend_txid) = outpoint_spent_txid(
                        btc_client,
                        &watchtower_challenge_init_txid,
                        (out_monitor.vout_len - BLOCKHASH_COMMIT_VIN_MARGIN) as u64,
                    )
                    .await?
                        && blockhash_commit_timeout_txid != spend_txid
                    {
                        info!(
                            "process_watchtower_challenge_monitoring graph id :{} sub status update to CommitBlockHashStatus::OperatorCommit",
                            graph.graph_id
                        );
                        vout_monitor_data.commit_blockhash_status =
                            CommitBlockHashStatus::OperatorCommit;
                        data_change = true;
                    }
                } else {
                    info!(
                        "process_watchtower_challenge_monitoring graph id :{} sub status update to CommitBlockHashStatus::OperatorCommitTimeout",
                        graph.graph_id
                    );
                    vout_monitor_data.commit_blockhash_status =
                        CommitBlockHashStatus::OperatorCommitTimeout;
                    sub_status.commit_blockhash_status =
                        CommitBlockHashStatus::OperatorCommitTimeout;
                    data_change = true;
                }
            }

            if is_blockhash_commit_timeout {
                trace!(
                    "process_watchtower_challenge_monitoring graph id :{} send p2p msg: blockhash commit timeout",
                    graph.graph_id
                );
                // TODO send p2p message: commit blockhash timeout
            }
            for (index, status) in vout_monitor_data.data_map.iter() {
                if *status == WatchtowerChallengeStatus::Challenge {
                    trace!(
                        "process_watchtower_challenge_monitoring graph id :{} send p2p msg: challenge status at vout index:{index}",
                        graph.graph_id
                    );
                    // TODO send p2p message: watchtower challenge tx sent
                }
            }
        } else {
            trace!(
                "process_watchtower_challenge_monitoring graph id :{} ack timeout",
                graph.graph_id
            );
            vout_monitor_data.update_disprove_indexes();
            if vout_monitor_data.require_disproved_indexes.is_empty() {
                trace!(
                    "process_watchtower_challenge_monitoring graph id :{} sub status update to WatchtowerChallengeStatus::OperatorACK",
                    graph.graph_id
                );
                sub_status.watchtower_challenge_status = WatchtowerChallengeStatus::OperatorACK;
            } else {
                trace!(
                    "process_watchtower_challenge_monitoring graph id :{} sub status update to WatchtowerChallengeStatus::OperatorNACK",
                    graph.graph_id
                );
                sub_status.watchtower_challenge_status = WatchtowerChallengeStatus::OperatorNACK;
            }
            data_change = true;
        }
        if data_change {
            storage_processor
                .update_graph_fields(
                    GraphUpdate::new(graph.graph_id)
                        .with_sub_status(serde_json::to_string(sub_status).unwrap()),
                )
                .await?;
            storage_processor
                .update_graph_btc_tx_vout_monitor_data(
                    &graph.graph_id,
                    serde_json::to_string(&vout_monitor_data)?,
                )
                .await?;
        }
    } else {
        trace!(
            "process_watchtower_challenge_monitoring graph id :{} watchtower challenge init is not on chain",
            graph.graph_id
        );
        // Create monitor if watchtower challenge init transaction is detected
        if let Some(spent_txid) = outpoint_spent_txid(btc_client, &kickoff_txid, 1).await?
            && spent_txid == watchtower_challenge_init_txid
        {
            info!(
                "process_watchtower_challenge_monitoring graph_id: {} watchtower_challenge_init_txid {} has been broadcasted",
                graph.graph_id,
                watchtower_challenge_init_txid.to_string()
            );
            sub_status.watchtower_challenge_status = WatchtowerChallengeStatus::OperatorInit;

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
                .update_graph_fields(
                    GraphUpdate::new(graph.graph_id)
                        .with_sub_status(serde_json::to_string(sub_status).unwrap()),
                )
                .await?;

            storage_processor
                .upsert_graph_btc_tx_vout_monitor(&GraphBtcTxVoutMonitor {
                    graph_id: graph.graph_id,
                    txid: watchtower_challenge_init_txid.into(),
                    height: watchtower_challenge_init_tx.status.block_height.unwrap_or_default()
                        as i64,
                    vout_len: watchtower_challenge_init_tx.vout.len() as i64,
                    monitor_data: serde_json::to_string(&WTInitTxVoutMonitorData::new(
                        watchtower_challenge_init_tx.vout.len() as i32,
                    ))?,
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
    graph: &Graph,
    sub_status: &mut ChallengeSubStatus,
    current_height: i64,
) -> anyhow::Result<()> {
    trace!("process_assert_commit_monitoring start");
    let (
        _watchtower_challenge_timelock,
        _ack_timelock,
        _blockhash_commit_timeout_lock,
        assert_commit_timeout_lock,
    ) = get_timelock_configs();
    let (kickoff_txid, assert_init_txid): (Txid, Txid) = match (
        graph.kickoff_txid.clone(),
        graph.assert_init_txid.clone(),
    ) {
        (Some(kickoff_txid), Some(assert_init_txid)) => {
            (kickoff_txid.into(), assert_init_txid.into())
        }
        _ => {
            warn!(
                "process_assert_commit_monitoring graph_id {} kickoff_txid or assert_init_txid is none",
                graph.graph_id
            );
            return Ok(());
        }
    };

    if let Some(out_monitor) = storage_processor
        .get_graph_btc_tx_vout_monitor(&graph.graph_id, &assert_init_txid.into())
        .await?
    {
        let mut vout_monitor_data =
            match parse_monitor_data::<AssertInitTxVoutMonitorData>(&out_monitor.monitor_data) {
                Ok(vout_monitor_data) => vout_monitor_data,
                Err(_) => {
                    warn!(
                        "process_assert_commit_monitoring graph_id {} fail to parse monitor data",
                        graph.graph_id
                    );
                    return Ok(());
                }
            };
        if vout_monitor_data.is_challenged() {
            trace!(
                "process_assert_commit_monitoring graph id :{} need to send p2p message: assert commit is challenged",
                graph.graph_id
            );
            // TODO send p2p message: assert_commit_finish
            return Ok(());
        }
        let is_assert_commit_timeout =
            out_monitor.height + assert_commit_timeout_lock > current_height;
        let mut data_change = false;
        if !is_assert_commit_timeout {
            trace!(
                "process_assert_commit_monitoring graph id :{} assert commit monitor",
                graph.graph_id
            );
            // TODO send p2p message assert commit monitoring
            let vout_spent_len = vout_monitor_data
                .monitor_vout(btc_client, &assert_init_txid, &graph.assert_commit_timeout_txids)
                .await?;

            data_change = data_change || vout_spent_len > 0;
        } else {
            info!(
                "process_assert_commit_monitoring graph id :{} assert commit timeout",
                graph.graph_id
            );
            vout_monitor_data.update_disprove_indexes();
            if vout_monitor_data.require_disproved_indexes.is_empty() {
                info!(
                    "process_assert_commit_monitoring graph id :{} sub status update to AssertCommitStatus::OperatorCommit",
                    graph.graph_id
                );
                sub_status.assert_commit_status = AssertCommitStatus::OperatorCommit;
            } else {
                info!(
                    "process_assert_commit_monitoring graph id :{} sub status update to AssertCommitStatus::OperatorCommitTimeout",
                    graph.graph_id
                );
                sub_status.assert_commit_status = AssertCommitStatus::OperatorCommitTimeout;
                // TODO send p2p message: assert_commit_timeout
            }
            data_change = true;
        }
        if data_change {
            storage_processor
                .update_graph_fields(
                    GraphUpdate::new(graph.graph_id)
                        .with_sub_status(serde_json::to_string(sub_status).unwrap()),
                )
                .await?;
            storage_processor
                .update_graph_btc_tx_vout_monitor_data(
                    &graph.graph_id,
                    serde_json::to_string(&vout_monitor_data)?,
                )
                .await?;
        }
    } else {
        trace!(
            "process_assert_commit_monitoring graph_id: {} assert_init_txid {} not been broadcasted, start to detect",
            graph.graph_id,
            assert_init_txid.to_string()
        );

        // Create monitor if assert init transaction is detected
        if let Some(spent_txid) = outpoint_spent_txid(btc_client, &kickoff_txid, 2).await?
            && spent_txid == assert_init_txid
        {
            info!(
                "process_assert_commit_monitoring graph_id: {} assert_init_txid {} has been broadcasted",
                graph.graph_id,
                assert_init_txid.to_string()
            );

            let assert_init_tx =
                btc_client.get_tx_info(&assert_init_txid).await?.ok_or_else(|| {
                    anyhow::anyhow!("assert_init_txid {} not found", assert_init_txid.to_string())
                })?;
            sub_status.assert_commit_status = AssertCommitStatus::OperatorInit;
            storage_processor
                .update_graph_fields(
                    GraphUpdate::new(graph.graph_id)
                        .with_sub_status(serde_json::to_string(sub_status).unwrap()),
                )
                .await?;
            storage_processor
                .upsert_graph_btc_tx_vout_monitor(&GraphBtcTxVoutMonitor {
                    graph_id: graph.graph_id,
                    txid: assert_init_txid.into(),
                    height: assert_init_tx.status.block_height.unwrap_or_default() as i64,
                    vout_len: assert_init_tx.vout.len() as i64,
                    monitor_data: serde_json::to_string(&AssertInitTxVoutMonitorData::new(
                        assert_init_tx.vout.len() as i32,
                    ))?,
                    created_at: current_time_secs(),
                    updated_at: current_time_secs(),
                })
                .await?;
        }
    }

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

/// Find the spend transaction for a disproved index
async fn find_spend_tx_for_disproved_index(
    btc_client: &BTCClient,
    storage_processor: &mut StorageProcessor<'_>,
    graph_id: &Uuid,
    txid: &SerializableTxid,
    index_calculator: impl Fn(i32) -> u64,
) -> anyhow::Result<Option<(Txid, i32)>> {
    let out_monitor = storage_processor.get_graph_btc_tx_vout_monitor(graph_id, txid).await?;

    let Some(out_monitor) = out_monitor else {
        return Ok(None);
    };

    let vout_monitor_data =
        parse_monitor_data::<WTInitTxVoutMonitorData>(&out_monitor.monitor_data)
            .map_err(|e| anyhow::anyhow!("Failed to parse monitor data: {}", e))?;

    for &index in &vout_monitor_data.require_disproved_indexes {
        let calculated_index = index_calculator(index);
        if let Some(spend_txid) =
            outpoint_spent_txid(btc_client, &txid.clone().into(), calculated_index).await?
        {
            return Ok(Some((spend_txid, index)));
        }
    }

    Ok(None)
}

/// Find the spend transaction for assert timeout
async fn find_assert_timeout_spend_tx(
    btc_client: &BTCClient,
    storage_processor: &mut StorageProcessor<'_>,
    graph_id: &Uuid,
    assert_init_txid: &SerializableTxid,
) -> anyhow::Result<Option<(Txid, i32)>> {
    let out_monitor =
        storage_processor.get_graph_btc_tx_vout_monitor(graph_id, assert_init_txid).await?;

    let Some(out_monitor) = out_monitor else {
        return Ok(None);
    };

    let vout_monitor_data =
        parse_monitor_data::<AssertInitTxVoutMonitorData>(&out_monitor.monitor_data)
            .map_err(|e| anyhow::anyhow!("Failed to parse assert monitor data: {}", e))?;

    for &index in &vout_monitor_data.require_disproved_indexes {
        if let Some(spend_txid) =
            outpoint_spent_txid(btc_client, &assert_init_txid.clone().into(), index as u64).await?
        {
            return Ok(Some((spend_txid, index)));
        }
    }

    Ok(None)
}

async fn detect_disproved_txids(
    btc_client: &BTCClient,
    storage_processor: &mut StorageProcessor<'_>,
    graph: &Graph,
    sub_status: &mut ChallengeSubStatus,
) -> anyhow::Result<Option<(DisproveTxType, Txid, Txid, i32)>> {
    trace!("detecting disproved txids graph_id {}", graph.graph_id);
    let (
        kickoff_txid,
        challenge_txid,
        watchtower_challenge_init_txid,
        blockhash_commit_timeout_txid,
        assert_init_txid,
        take2_txid,
    ): (Txid, Txid, Txid, Txid, Txid, Txid) = match (
        graph.kickoff_txid.clone(),
        graph.challenge_txid.clone(),
        graph.watchtower_challenge_init_txid.clone(),
        graph.blockhash_commit_timeout_txid.clone(),
        graph.assert_init_txid.clone(),
        graph.take2_txid.clone(),
    ) {
        (
            Some(kickoff_txid),
            Some(challenge_txid),
            Some(watchtower_challenge_init_txid),
            Some(blockhash_commit_timeout_txid),
            Some(assert_init_txid),
            Some(take2_txid),
        ) => (
            kickoff_txid.into(),
            challenge_txid.into(),
            watchtower_challenge_init_txid.into(),
            blockhash_commit_timeout_txid.into(),
            assert_init_txid.into(),
            take2_txid.into(),
        ),
        _ => return Ok(None),
    };
    if sub_status.assert_commit_status == AssertCommitStatus::OperatorCommitTimeout {
        return Ok(
            match find_assert_timeout_spend_tx(
                btc_client,
                storage_processor,
                &graph.graph_id,
                &assert_init_txid.into(),
            )
            .await?
            {
                Some((finish_txid, index)) => {
                    Some((DisproveTxType::AssertTimeout, challenge_txid, finish_txid, index))
                }
                None => None,
            },
        );
    }

    if sub_status.watchtower_challenge_status == WatchtowerChallengeStatus::OperatorNACK {
        return Ok(
            match find_spend_tx_for_disproved_index(
                btc_client,
                storage_processor,
                &graph.graph_id,
                &watchtower_challenge_init_txid.into(),
                |index| (index * 2 + 1) as u64,
            )
            .await?
            {
                Some((finish_txid, index)) => {
                    Some((DisproveTxType::OperatorNack, challenge_txid, finish_txid, index))
                }
                None => None,
            },
        );
    }

    if sub_status.watchtower_challenge_status == WatchtowerChallengeStatus::ChallengeTimeout {
        return Ok(Some((
            DisproveTxType::OperatorCommitTimeout,
            challenge_txid,
            blockhash_commit_timeout_txid,
            0,
        )));
    }

    if let Some(spent_txid) = outpoint_spent_txid(btc_client, &kickoff_txid, 3).await?
        && spent_txid == take2_txid
    {
        return Ok(Some((DisproveTxType::Disprove, challenge_txid, spent_txid, 0)));
    }

    Ok(None)
}

async fn process_graph_watchtower_assert_disproved(
    btc_client: &BTCClient,
    goat_client: &GOATClient,
    local_db: &LocalDB,
    graph: &Graph,
    sub_status: &mut ChallengeSubStatus,
) -> anyhow::Result<()> {
    let mut tx = local_db.start_transaction().await?;
    if let Some((disprove_type, start_txid, finish_txid, tx_index)) =
        detect_disproved_txids(btc_client, &mut tx, graph, sub_status).await?
    {
        info!(
            "process_graph_watchtower_assert_disproved disprove_type: {disprove_type}, challenge start tx: {}, challenge finish tx: {}, tx_index: {tx_index}",
            start_txid.to_string(),
            finish_txid.to_string()
        );
        let challenge_start_tx = btc_client.get_tx(&start_txid.into()).await?.ok_or_else(|| {
            anyhow::anyhow!("Challenge start tx not found for graph {}", graph.graph_id)
        })?;
        let challenge_finish_tx =
            btc_client.get_tx(&finish_txid.into()).await?.ok_or_else(|| {
                anyhow::anyhow!("Challenge start tx not found for graph {}", graph.graph_id)
            })?;

        match goat_client
            .gateway_finish_withdraw_disproved(
                btc_client,
                &graph.graph_id,
                disprove_type,
                tx_index as u64,
                &challenge_start_tx,
                &challenge_finish_tx,
            )
            .await
        {
            Err(err) => {
                warn!(
                    "process_graph_watchtower_assert_disproved graph_id: {}, error: {err:?}. Will retry later.",
                    graph.graph_id
                );
            }
            Ok(tx_hash) => {
                info!(
                    " process_graph_watchtower_assert_disproved graph_id: {} success to call contract tx_hash: {tx_hash}",
                    graph.graph_id
                );

                let block_height = match goat_client.get_tx_receipt(&tx_hash).await? {
                    Some(receipt) => receipt.block_number.unwrap_or(0),
                    None => {
                        warn!("No receipt found for tx_hash: {}", tx_hash);
                        0
                    }
                };

                tx.upsert_goat_tx_record(&GoatTxRecord {
                    instance_id: graph.instance_id,
                    graph_id: graph.graph_id,
                    tx_type: GoatTxType::WithdrawDisproved.to_string(),
                    tx_hash,
                    height: block_height as i64,
                    is_local: true,
                    processing_status: GoatTxProcessingStatus::Skipped.to_string(),
                    extra: None,
                    created_at: current_time_secs(),
                })
                .await?;

                tx.update_graph_fields(
                    GraphUpdate::new(graph.graph_id).with_status(GraphStatus::Disprove.to_string()),
                )
                .await?;
                tx.commit().await?;
                info!(
                    "process_graph_watchtower_assert_disproved successfully updated database for graph_id: {} to disprove",
                    graph.graph_id
                );
            }
        }
    } else {
        trace!("process_graph_watchtower_assert_disproved get disproved tx is none");
    }
    Ok(())
}

/// Process graph data in Watchtower Assert Normal status
async fn detect_take2(
    btc_client: &BTCClient,
    goat_client: &GOATClient,
    local_db: &LocalDB,
    graph: &Graph,
    current_height: i64,
) -> anyhow::Result<Option<(Actor, GOATMessageContent)>> {
    trace!("detecting detect_take2 graph_id {}", graph.graph_id);
    let watchtower_lock_blocks = num_blocks_per_network(get_network(), CONNECTOR_3_TIMELOCK);
    let assert_lock_blocks = num_blocks_per_network(get_network(), CONNECTOR_3_TIMELOCK);
    let (kickoff_txid, watchtower_challenge_init_txid, assert_init_txid, take2_txid): (
        Txid,
        Txid,
        Txid,
        Txid,
    ) = match (
        graph.kickoff_txid.clone(),
        graph.watchtower_challenge_init_txid.clone(),
        graph.assert_init_txid.clone(),
        graph.take2_txid.clone(),
    ) {
        (
            Some(kickoff_txid),
            Some(watchtower_challenge_init_txid),
            Some(assert_init_txid),
            Some(take2_txid),
        ) => (
            kickoff_txid.into(),
            watchtower_challenge_init_txid.into(),
            assert_init_txid.into(),
            take2_txid.into(),
        ),
        _ => {
            warn!(
                "detect_take2 graph_id:{}, kickoff_txid, watchtower_challenge_init_txid, assert_init_txid or take2_txid is none",
                graph.graph_id
            );
            return Ok(None);
        }
    };

    let mut tx = local_db.start_transaction().await?;
    let spent_txid = match outpoint_spent_txid(btc_client, &kickoff_txid, 3).await? {
        Some(txid) => txid,
        None => {
            trace!(
                "detecting detect_take2 graph_id {} take2 or disprove is not on chain",
                graph.graph_id
            );
            let watchtower_init_height = tx
                .get_graph_btc_tx_vout_monitor(
                    &graph.graph_id,
                    &watchtower_challenge_init_txid.into(),
                )
                .await?
                .unwrap_or_default()
                .height;

            let assert_init_height = tx
                .get_graph_btc_tx_vout_monitor(&graph.graph_id, &assert_init_txid.into())
                .await?
                .unwrap_or_default()
                .height;
            let (ready, data_change) = check_operator_withdraw_ready_condition(
                btc_client,
                &mut tx,
                graph.graph_id,
                vec![
                    (
                        watchtower_challenge_init_txid,
                        OperatorWithdrawType::Take2,
                        watchtower_init_height,
                        watchtower_lock_blocks as i64,
                    ),
                    (
                        assert_init_txid,
                        OperatorWithdrawType::Take2,
                        assert_init_height,
                        assert_lock_blocks as i64,
                    ),
                ],
                current_height,
            )
            .await?;
            if data_change {
                tx.commit().await?;
            }

            if ready {
                info!(
                    "detecting detect_take2 graph_id {} take2 is ready to send to btc chain",
                    graph.graph_id
                );
                return Ok(Some((
                    Actor::Operator,
                    GOATMessageContent::Take2Ready(Take2Ready {
                        instance_id: graph.instance_id,
                        graph_id: graph.graph_id,
                    }),
                )));
            }
            return Ok(None);
        }
    };
    let mut tx = local_db.start_transaction().await?;
    let data_change = if spent_txid == take2_txid {
        info!(
            "detecting detect_take2 graph_id {} take2:{} is on btc chain",
            graph.graph_id,
            spent_txid.to_string()
        );
        // Take1 was sent
        handle_operator_withdraw_completion(
            btc_client,
            goat_client,
            &mut tx,
            graph.instance_id,
            graph.graph_id,
            OperatorWithdrawType::Take2,
            take2_txid,
        )
        .await?
    } else {
        false
    };
    if data_change {
        tx.commit().await?;
    }
    Ok(None)
}
