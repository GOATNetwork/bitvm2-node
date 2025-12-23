use crate::action::{
    AssertCommitTimeout, AssertInitReady, ChallengeSent, DisproveReady, DisproveSent,
    GOATMessageContent, KickoffReady, KickoffSent, OperatorAckTimeout,
    OperatorCommitBlockHashReady, OperatorCommitBlockHashTimeout, PreKickoffSent, Take1Ready,
    Take1Sent, Take2Ready, Take2Sent, WatchtowerChallengeInitSent, WatchtowerChallengeSent,
    WatchtowerChallengeTimeout,
};
use crate::env::get_network;
use crate::rpc_service::current_time_secs;
use crate::scheduled_tasks::fetch_on_turn_graph_by_status;
use crate::utils::{outpoint_spent_txid, upsert_message};
use bitcoin::Txid;
use bitvm2_lib::actors::Actor;
use bitvm2_lib::challenger::{
    assert_commit_timeout_timelock, commit_blockhash_timeout_timelock, nack_timelock,
};
use bitvm2_lib::operator::{
    take1_timelock, take2_timelocks, watchtower_challenge_timeout_timelock,
};
use client::btc_chain::BTCClient;
use client::goat_chain::{DisproveTxType, GOATClient};
use indexmap::IndexMap;
use serde::{Deserialize, Serialize};
use store::localdb::{GraphUpdate, LocalDB, StorageProcessor};
use store::{
    GoatTxProcessingStatus, GoatTxType, Graph, GraphBtcTxVoutMonitor, GraphStatus, SerializableTxid,
};
use strum::{Display, EnumString};
use tracing::{info, trace, warn};
use uuid::Uuid;

const CONNECTOR_G_MARGIN: i64 = 3;
const CONNECTOR_D_MARGIN: u64 = 2;
const CONNECTOR_F_MARGIN: u64 = 2;
const CONNECTOR_GUARDIAN_MARGIN: u64 = 2;

const MONITE_BTC_TX_NAME_KICKOFF: &str = "kickoff";
const MONITE_BTC_TX_NAME_WATCHTOWER_INIT: &str = "watchtower_init";
const MONITE_BTC_TX_NAME_ASSERT_INIT: &str = "assert_init";

#[derive(Clone, Debug)]
pub struct ChallengeTimeLockConfig {
    pub watchtower_challenge_timelock: i64,
    pub watchtower_ack_timelock: i64,
    pub watchtower_blockhash_commit_timelock: i64,
    pub assert_commit_timelock: i64,
}

fn get_challenge_timelock_config() -> ChallengeTimeLockConfig {
    ChallengeTimeLockConfig {
        watchtower_challenge_timelock: watchtower_challenge_timeout_timelock(get_network()) as i64,
        watchtower_ack_timelock: nack_timelock(get_network()) as i64,
        watchtower_blockhash_commit_timelock: commit_blockhash_timeout_timelock(get_network())
            as i64,
        assert_commit_timelock: assert_commit_timeout_timelock(get_network()) as i64,
    }
}

fn get_take1_timelock_config() -> i64 {
    take1_timelock(get_network()) as i64
}

pub struct Take2TimeLockConfig {
    pub assert_init_out_timelock: i64,
    pub watchtower_challenge_init_out_timelock: i64,
}
fn get_take2_timelock_config() -> Take2TimeLockConfig {
    let (watchtower_challenge_init_out_timelock, assert_init_out_timelock) =
        take2_timelocks(get_network());
    Take2TimeLockConfig {
        assert_init_out_timelock: assert_init_out_timelock as i64,
        watchtower_challenge_init_out_timelock: watchtower_challenge_init_out_timelock as i64,
    }
}
#[derive(Clone, Debug, Eq, PartialEq, Display, EnumString)]
enum OperatorWithdrawType {
    Take1,
    Take2,
}

/// Watchtower init tx vout item status watchtower processed
#[derive(
    Copy, Clone, Debug, Serialize, Deserialize, Default, Eq, PartialEq, Display, EnumString,
)]
pub enum CommitBlockHashStatus {
    #[default]
    None,
    WatchtowerChallengeProcessed,
    OperatorCommit,
    OperatorCommitTimeout,
}

#[derive(
    Copy, Clone, Debug, Serialize, Deserialize, Default, Eq, PartialEq, Display, EnumString,
)]
pub enum AssertCommitStatus {
    #[default]
    None,
    OperatorInit,
    OperatorCommit,
    OperatorCommitTimeout,
}

#[derive(
    Copy, Clone, Debug, Serialize, Deserialize, Default, Eq, PartialEq, Display, EnumString,
)]
pub enum WatchtowerChallengeStatus {
    #[default]
    None,
    OperatorInit,
    WatchtowerChallenge,                 // all Watchtower challenge
    WatchtowerChallengeTimeout,          // Some Watchtower did not challenge, and timelock expired
    OperatorACKTimeout, // Operator did not send ACK for some Watchtower, and timelock expired
    WatchtowerChallengeNormalFinished, // Normal Finished
    WatchtowerChallengeDisproveFinished, // Disproved Finished
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, Serialize, Deserialize, Default)]
pub struct ChallengeSubStatus {
    pub watchtower_challenge_status: WatchtowerChallengeStatus,
    pub commit_blockhash_status: CommitBlockHashStatus,
    pub assert_commit_status: AssertCommitStatus,
    pub disprove_type: Option<DisproveTxType>,
    pub disprove_index: i32,
}

impl ChallengeSubStatus {
    pub fn is_watchtower_challenge_normal_finished(&self) -> bool {
        self.watchtower_challenge_status
            == WatchtowerChallengeStatus::WatchtowerChallengeNormalFinished
            && self.commit_blockhash_status == CommitBlockHashStatus::OperatorCommit
    }

    pub fn is_disproved(&self) -> bool {
        self.disprove_type.is_some()
    }

    pub fn is_normal_finished(&self) -> bool {
        self.is_watchtower_challenge_normal_finished() && self.is_assert_commit_normal_finished()
    }

    pub fn is_assert_commit_normal_finished(&self) -> bool {
        self.assert_commit_status == AssertCommitStatus::OperatorCommit
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, Default, Eq, PartialEq, Display, EnumString)]
pub enum WatchtowerChallengeItemStatus {
    #[default]
    None,
    OperatorInit,
    Challenge,
    ChallengeTimeout,
    OperatorACK,
    OperatorNACK,
}

/// Watchtower init tx vout data
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WTInitTxVoutMonitorData {
    pub data_map: IndexMap<i32, WatchtowerChallengeItemStatus>,
    pub require_disproved_indexes: Vec<usize>,
    pub commit_blockhash_status: CommitBlockHashStatus,
    pub is_challenge_timeout_sent: bool,
}

impl WTInitTxVoutMonitorData {
    pub fn new(index_size: i32) -> Self {
        let mut data_map: IndexMap<i32, WatchtowerChallengeItemStatus> = IndexMap::new();
        for i in 0..index_size {
            data_map.insert(i, WatchtowerChallengeItemStatus::OperatorInit);
        }
        Self {
            data_map,
            require_disproved_indexes: vec![],
            commit_blockhash_status: CommitBlockHashStatus::None,
            is_challenge_timeout_sent: false,
        }
    }
    pub async fn monitor_vout(
        &mut self,
        btc_client: &BTCClient,
        txid: &Txid,
        input_challenge_timeout_txids: &[SerializableTxid],
        nack_txids: &[SerializableTxid],
    ) -> anyhow::Result<(Vec<(usize, Txid)>, Vec<(usize, Txid)>, Vec<(usize, Txid)>)> {
        let mut challenge_txids: Vec<(usize, Txid)> = Vec::new();
        let mut challenge_timeout_txids: Vec<(usize, Txid)> = Vec::new();
        let mut ack_txids: Vec<(usize, Txid)> = Vec::new();
        for (k, status) in self.data_map.iter_mut() {
            let index = *k;
            if *status == WatchtowerChallengeItemStatus::OperatorInit
                && let Some(spend_txid) =
                    outpoint_spent_txid(btc_client, txid, (index * 2) as u64).await?
            {
                if input_challenge_timeout_txids.iter().any(|v| v.0 == spend_txid) {
                    *status = WatchtowerChallengeItemStatus::ChallengeTimeout;
                    challenge_timeout_txids.push((index as usize, spend_txid));
                } else {
                    *status = WatchtowerChallengeItemStatus::Challenge;
                    challenge_txids.push((index as usize, spend_txid));
                }
            }

            if *status == WatchtowerChallengeItemStatus::Challenge
                && let Some(spend_txid) =
                    outpoint_spent_txid(btc_client, txid, (index * 2 + 1) as u64).await?
            {
                if nack_txids.iter().any(|v| v.0 == spend_txid) {
                    *status = WatchtowerChallengeItemStatus::OperatorNACK;
                } else {
                    *status = WatchtowerChallengeItemStatus::OperatorACK;
                    ack_txids.push((index as usize, spend_txid));
                }
            }
        }
        Ok((challenge_txids, challenge_timeout_txids, ack_txids))
    }

    fn update_disprove_indexes(&mut self) {
        self.require_disproved_indexes = vec![];
        for (index, status) in self.data_map.iter() {
            if *status == WatchtowerChallengeItemStatus::OperatorInit
                || *status == WatchtowerChallengeItemStatus::Challenge
            {
                self.require_disproved_indexes.push(*index as usize);
            }
        }
    }

    fn get_require_disproved_string(&self) -> String {
        format!(
            "[{}]",
            self.require_disproved_indexes
                .iter()
                .map(|v| v.to_string())
                .collect::<Vec<String>>()
                .join("_")
        )
    }

    pub fn get_challenge_process_desc(&self) -> (usize, usize) {
        (
            self.data_map
                .iter()
                .filter(|(_, v)| {
                    **v == WatchtowerChallengeItemStatus::Challenge
                        || **v == WatchtowerChallengeItemStatus::OperatorACK
                })
                .count(),
            self.data_map.len(),
        )
    }

    pub fn get_challenge_timeout_process_desc(&self) -> (usize, usize) {
        if self.is_challenge_timeout_sent {
            (
                self.data_map.len()
                    - self
                        .data_map
                        .iter()
                        .filter(|(_, v)| {
                            **v == WatchtowerChallengeItemStatus::Challenge
                                || **v == WatchtowerChallengeItemStatus::OperatorACK
                        })
                        .count(),
                self.data_map.len(),
            )
        } else {
            (0, self.data_map.len())
        }
    }

    pub fn get_commit_block_hash_desc(&self) -> (usize, usize) {
        match self.commit_blockhash_status {
            CommitBlockHashStatus::OperatorCommit => (1, 1),
            _ => (0, 1),
        }
    }

    pub fn get_commit_block_hash_timeout_desc(&self) -> (usize, usize) {
        match self.commit_blockhash_status {
            CommitBlockHashStatus::OperatorCommitTimeout => (1, 1),
            _ => (0, 1),
        }
    }

    pub fn get_ack_process_desc(&self) -> (usize, usize) {
        (
            self.data_map
                .iter()
                .filter(|(_, v)| **v == WatchtowerChallengeItemStatus::OperatorACK)
                .count(),
            self.data_map
                .iter()
                .filter(|(_, v)| {
                    **v == WatchtowerChallengeItemStatus::Challenge
                        || **v == WatchtowerChallengeItemStatus::OperatorACK
                })
                .count(),
        )
    }

    #[allow(dead_code)]
    pub fn is_challenged(&self) -> bool {
        !self.require_disproved_indexes.is_empty()
            || self.commit_blockhash_status == CommitBlockHashStatus::OperatorCommitTimeout
    }

    pub fn check_watchtower_challenge_normal_finished(&self) -> bool {
        self.data_map.values().all(|status| {
            matches!(
                status,
                WatchtowerChallengeItemStatus::OperatorACK
                    | WatchtowerChallengeItemStatus::ChallengeTimeout
            )
        })
    }

    pub fn is_commit_blockhash_ready(&self) -> bool {
        self.data_map.values().all(|status| {
            matches!(
                status,
                WatchtowerChallengeItemStatus::OperatorACK
                    | WatchtowerChallengeItemStatus::ChallengeTimeout
                    | WatchtowerChallengeItemStatus::Challenge
            )
        })
    }
}

/// Assert init tx vout item status
#[derive(Clone, Debug, Serialize, Deserialize, Default, Eq, PartialEq, Display, EnumString)]
pub enum AssertCommitItemStatus {
    #[default]
    None,
    OperatorInit,
    OperatorCommit,
    OperatorCommitTimeout,
}
/// Assert init tx vout data
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AssertInitTxVoutMonitorData {
    pub data_map: IndexMap<i32, AssertCommitItemStatus>,
    pub require_disproved_indexes: Vec<usize>,
}

impl AssertInitTxVoutMonitorData {
    pub fn new(index_size: i32) -> Self {
        let mut data_map: IndexMap<i32, AssertCommitItemStatus> = IndexMap::new();
        for i in 0..index_size {
            data_map.insert(i, AssertCommitItemStatus::OperatorInit);
        }
        Self { data_map, require_disproved_indexes: vec![] }
    }
    pub async fn monitor_vout(
        &mut self,
        btc_client: &BTCClient,
        txid: &Txid,
        committ_timeout_txids: &[SerializableTxid],
    ) -> anyhow::Result<i32> {
        let mut vout_spent_detect = 0;
        for (k, status) in self.data_map.iter_mut() {
            if *status == AssertCommitItemStatus::OperatorInit
                && let Some(spend_txid) = outpoint_spent_txid(btc_client, txid, *k as u64).await?
            {
                if committ_timeout_txids.iter().any(|v| v.0 == spend_txid) {
                    *status = AssertCommitItemStatus::OperatorCommitTimeout;
                } else {
                    *status = AssertCommitItemStatus::OperatorCommit;
                }
                vout_spent_detect += 1
            }
        }
        Ok(vout_spent_detect)
    }

    pub fn check_normal_finished(&self) -> bool {
        self.data_map.values().all(|status| *status == AssertCommitItemStatus::OperatorCommit)
    }

    pub fn get_commit_process_desc(&self) -> (usize, usize) {
        (
            self.data_map
                .iter()
                .filter(|(_, v)| **v == AssertCommitItemStatus::OperatorCommit)
                .count(),
            self.data_map.len(),
        )
    }

    fn update_disprove_indexes(&mut self) {
        self.require_disproved_indexes = vec![];
        for (index, status) in self.data_map.iter() {
            if *status == AssertCommitItemStatus::OperatorInit {
                self.require_disproved_indexes.push(*index as usize);
            }
        }
    }
}

/// Parse monitor data from JSON string
fn parse_monitor_data<T>(monitor_data: &str) -> anyhow::Result<T>
where
    T: serde::de::DeserializeOwned,
{
    serde_json::from_str(monitor_data)
        .map_err(|e| anyhow::anyhow!("Failed to parse monitor data: {e}"))
}

#[allow(dead_code)]
pub async fn get_initialized_graphs(goat_client: &GOATClient) -> anyhow::Result<Vec<(Uuid, Uuid)>> {
    // call L2 contract : getInitializedInstanceIds
    // returns Vec<(instance_id, graph_id)>
    goat_client.gateway_get_initialized_ids().await
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
pub async fn detect_init_withdraw_call(local_db: &LocalDB) -> anyhow::Result<()> {
    trace!("start tick action: detect_init_withdraw_call");
    let graphs = {
        let mut storage_processor = local_db.acquire().await?;
        get_user_init_withdraw_graphs(&mut storage_processor).await?
    };
    info!("start tick action: detect_init_withdraw_call get graphs:{}", graphs.len());
    for (instance_id, graph_id) in graphs {
        let mut tx = local_db.start_transaction().await?;
        if let Ok(Some(graph)) = tx.find_graph(&graph_id).await {
            if graph.instance_id.ne(&instance_id) {
                warn!(
                    "Graph:{graph_id} recorded instance_id:{} not equal expected instance_id:{instance_id}",
                    graph.instance_id
                );
                continue;
            }
            upsert_message(
                &mut tx,
                false,
                graph_id,
                None,
                "self".to_string(),
                Actor::Operator,
                GOATMessageContent::KickoffReady(KickoffReady { instance_id, graph_id }),
                0,
                0,
            )
            .await?;
        } else {
            warn!(
                "instance_id: {instance_id} graph_id: {graph_id} fail to get graph from db or kickoff txid is none"
            );
        }
        tx.update_goat_tx_record_processing_status(
            &graph_id,
            &instance_id,
            &GoatTxType::InitWithdraw.to_string(),
            &GoatTxProcessingStatus::Processed.to_string(),
        )
        .await?;
        tx.commit().await?;
    }
    Ok(())
}

pub async fn detect_kickoff(local_db: &LocalDB, btc_client: &BTCClient) -> anyhow::Result<()> {
    trace!("start tick action: detect_kickoff");
    let graphs = {
        let mut storage_processor = local_db.acquire().await?;
        fetch_on_turn_graph_by_status(
            &mut storage_processor,
            &GraphStatus::OperatorDataPushed.to_string(),
        )
        .await?
    };
    info!("start tick action: detect_kickoff, graphs: {}", graphs.len());
    for graph in graphs {
        let kickoff_txid: Txid = match graph.kickoff_txid.clone() {
            Some(kickoff_txid) => kickoff_txid.into(),
            _ => {
                warn!("graph_id {}, kickoff txid or next_pre_kickoff is none", graph.graph_id);
                continue;
            }
        };

        if let Ok(tx_status) = btc_client.get_tx_status(&kickoff_txid).await
            && tx_status.confirmed
        {
            let mut storage_processor = local_db.acquire().await?;
            upsert_message(
                &mut storage_processor,
                false,
                graph.graph_id,
                None,
                "self".to_string(),
                Actor::All,
                GOATMessageContent::KickoffSent(KickoffSent {
                    instance_id: graph.instance_id,
                    graph_id: graph.graph_id,
                }),
                0,
                0,
            )
            .await?;
        } else {
            warn!("graph_id:{} kickoff:{kickoff_txid:?} is not onchain", graph.graph_id);
            continue;
        }
    }
    Ok(())
}

pub async fn detect_take1_or_challenge(
    local_db: &LocalDB,
    btc_client: &BTCClient,
) -> anyhow::Result<()> {
    trace!("start tick action: detect_take1_or_challenge");

    let graphs = {
        let mut storage_processor = local_db.acquire().await?;
        fetch_on_turn_graph_by_status(
            &mut storage_processor,
            &GraphStatus::OperatorKickOff.to_string(),
        )
        .await?
    };
    let current_height = btc_client.get_height().await? as i64;
    info!(
        "start tick action: detect_take1_or_challenge, graphs: {}, current_height: {current_height}",
        graphs.len()
    );
    let lock_blocks = get_take1_timelock_config();
    for graph in graphs {
        if detect_kickoff_ref_disprove_tx(btc_client, local_db, &graph).await? {
            warn!(
                "process_graph_challenge detect_kickoff_ref_disprove_tx happened at graph:{}",
                graph.graph_id
            );
            continue;
        }
        if let Some((actor, message_content)) =
            process_kickoff_graph(btc_client, local_db, &graph, lock_blocks, current_height).await?
        {
            info!("process_kickoff_graph detect take1 ready or take1 sent or challenge sent");
            let mut storage_processor = local_db.acquire().await?;
            upsert_message(
                &mut storage_processor,
                false,
                graph.graph_id,
                None,
                "self".to_string(),
                actor,
                message_content,
                0,
                0,
            )
            .await?;
        }
    }
    Ok(())
}

pub async fn process_graph_challenge(
    local_db: &LocalDB,
    btc_client: &BTCClient,
) -> anyhow::Result<()> {
    info!("start tick action: process_graph_challenge");
    let graphs = {
        let mut storage_processor = local_db.acquire().await?;
        fetch_on_turn_graph_by_status(&mut storage_processor, &GraphStatus::Challenge.to_string())
            .await?
    };
    let current_height = btc_client.get_height().await? as i64;
    for graph in graphs {
        // if detect_kickoff_ref_disprove_tx(btc_client, local_db, &graph).await? {
        //     warn!(
        //         "process_graph_challenge detect_kickoff_ref_disprove_tx happened at graph:{}",
        //         graph.graph_id
        //     );
        //     continue;
        // }
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
        if !sub_status.is_disproved() && !sub_status.is_normal_finished() {
            trace!("process_graph_challenge graph:{} is not disproved", graph.graph_id);
            if !sub_status.is_watchtower_challenge_normal_finished() {
                info!(
                    "process_graph_challenge graph:{} watchtower challenge is processing",
                    graph.graph_id
                );
                process_watchtower_challenge_monitoring(
                    btc_client,
                    local_db,
                    &graph,
                    &mut sub_status,
                    current_height,
                )
                .await?;
            } else if !sub_status.is_assert_commit_normal_finished() {
                info!(
                    "process_graph_challenge graph:{} assert commit is processing",
                    graph.graph_id
                );
                process_assert_commit_monitoring(
                    btc_client,
                    local_db,
                    &graph,
                    &mut sub_status,
                    current_height,
                )
                .await?;
            }
        } else if sub_status.is_normal_finished() {
            let mut storage_processor = local_db.acquire().await?;
            upsert_message(
                &mut storage_processor,
                false,
                graph.graph_id,
                None,
                "self".to_string(),
                Actor::Challenger,
                GOATMessageContent::DisproveReady(DisproveReady {
                    instance_id: graph.instance_id,
                    graph_id: graph.graph_id,
                }),
                0,
                0,
            )
            .await?;
            info!(
                "process_graph_challenge graph:{} watchtower challenge and assert commit is finished",
                graph.graph_id
            );
            if let Some((actor, message_content)) =
                detect_take2(btc_client, local_db, &graph, current_height).await?
            {
                let mut storage_processor = local_db.acquire().await?;
                upsert_message(
                    &mut storage_processor,
                    false,
                    graph.graph_id,
                    None,
                    "self".to_string(),
                    actor,
                    message_content,
                    0,
                    0,
                )
                .await?;
            }
        } else {
            info!(
                "process_graph_challenge graph:{} is disproved, waiting dispove tx sent",
                graph.graph_id
            )
        }
        process_graph_watchtower_assert_disproved(btc_client, local_db, &graph, &mut sub_status)
            .await?;
    }

    Ok(())
}

/// Handle Challenge transaction detection
async fn handle_challenge_detected(
    local_db: &LocalDB,
    graph_id: Uuid,
    challenge_txid: Txid,
) -> anyhow::Result<()> {
    info!(
        "handle_challenge_detected for graph_id: {graph_id}, challenge_txid: {}",
        challenge_txid.to_string()
    );

    let sub_status = serde_json::to_string(&ChallengeSubStatus::default())?;
    let mut storage_processor = local_db.acquire().await?;
    storage_processor
        .update_graph(
            &GraphUpdate::new(graph_id)
                // .with_status(GraphStatus::Challenge.to_string())
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
    local_db: &LocalDB,
    graph_id: Uuid,
    check_tx_items: Vec<(Txid, String, OperatorWithdrawType, i64, i64)>, // (txid, tag,  height, lock_blocks)
    current_height: i64,
) -> anyhow::Result<bool> {
    info!(
        "check_operator_withdraw_ready_condition for graph_id: {graph_id}, check tx size: {}, detail:{check_tx_items:?}",
        check_tx_items.len()
    );
    let mut ready = true;
    for (txid, tx_name, operator_withdraw_type, height, lock_blocks) in check_tx_items {
        let height = if height <= 0 {
            let current_times = current_time_secs();
            let (height, vout_len) = match btc_client.get_tx_info(&txid).await? {
                Some(tx_info) => (
                    tx_info.status.block_height.unwrap_or_default() as i64,
                    tx_info.vout.len() as i64,
                ),
                None => {
                    info!("graph_id:{graph_id}, {operator_withdraw_type} txid {txid} not on chain",);
                    return Ok(false);
                }
            };
            let mut storage_processor = local_db.acquire().await?;
            storage_processor
                .upsert_graph_btc_tx_vout_monitor(&GraphBtcTxVoutMonitor {
                    graph_id,
                    tx_name,
                    txid: txid.into(),
                    height,
                    vout_len,
                    monitor_data: "".to_string(),
                    created_at: current_times,
                    updated_at: current_times,
                })
                .await?;
            height
        } else {
            height
        };

        info!(
            "graph_id:{graph_id}, {operator_withdraw_type} txid {txid}  at height {height} lock_blocks {lock_blocks}, current height: {current_height}  ",
        );

        if height == 0 || height > 0 && height + lock_blocks > current_height {
            ready = false;
            break;
        }
    }
    Ok(ready)
}

/// Process graph data in KickOff status
async fn process_kickoff_graph(
    btc_client: &BTCClient,
    local_db: &LocalDB,
    graph: &Graph,
    lock_blocks: i64,
    current_height: i64,
) -> anyhow::Result<Option<(Actor, GOATMessageContent)>> {
    trace!("process_kickoff_graph: {}", graph.graph_id);
    let (kickoff_txid, take1_txid) = match (graph.kickoff_txid.clone(), graph.take1_txid.clone()) {
        (Some(kickoff), Some(take1)) => (kickoff.into(), take1.into()),
        _ => {
            warn!("process_kickoff_graph graph_id:{}, kickoff or take1 is none", graph.graph_id);
            return Ok(None);
        }
    };
    let spent_txid = match outpoint_spent_txid(btc_client, &kickoff_txid, 0).await? {
        Some(txid) => txid,
        None => {
            // kickoff output not spent, check if we need to send Take1Ready
            let height = {
                let mut storage_processor = local_db.acquire().await?;
                storage_processor
                    .find_graph_btc_tx_vout_monitor(&graph.graph_id, &kickoff_txid.into())
                    .await?
                    .unwrap_or_default()
                    .height
            };
            if check_operator_withdraw_ready_condition(
                btc_client,
                local_db,
                graph.graph_id,
                vec![(
                    kickoff_txid,
                    MONITE_BTC_TX_NAME_KICKOFF.to_string(),
                    OperatorWithdrawType::Take1,
                    height,
                    lock_blocks,
                )],
                current_height,
            )
            .await?
            {
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
    if spent_txid == take1_txid {
        info!(
            "process_kickoff_graph graph_id:{}, take1 is on chain, will try call contract",
            graph.graph_id
        );
        Ok(Some((
            Actor::Committee,
            GOATMessageContent::Take1Sent(Take1Sent {
                instance_id: graph.instance_id,
                graph_id: graph.graph_id,
            }),
        )))
    } else {
        info!(
            "process_kickoff_graph graph_id:{}, challenge txid: {} has been detected.",
            graph.graph_id,
            spent_txid.to_string()
        );
        // Challenge was sent
        handle_challenge_detected(local_db, graph.graph_id, spent_txid).await?;
        Ok(Some((
            Actor::Operator,
            GOATMessageContent::ChallengeSent(ChallengeSent {
                instance_id: graph.instance_id,
                graph_id: graph.graph_id,
                challenge_txid: spent_txid,
            }),
        )))
    }
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
    local_db: &LocalDB,
    graph: &Graph,
    sub_status: &mut ChallengeSubStatus,
    current_height: i64,
) -> anyhow::Result<()> {
    trace!("process_watchtower_challenge_monitoring start");
    let timelock_config = get_challenge_timelock_config();
    info!("process_watchtower_challenge_monitoring timelock_config: {timelock_config:?}");
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

    let out_monitor = {
        let mut storage_processor = local_db.acquire().await?;
        storage_processor
            .find_graph_btc_tx_vout_monitor(&graph.graph_id, &watchtower_challenge_init_txid.into())
            .await?
    };

    if let Some(out_monitor) = out_monitor {
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
        let is_challenge_timeout =
            out_monitor.height + timelock_config.watchtower_challenge_timelock < current_height;
        let is_ack_timeout =
            out_monitor.height + timelock_config.watchtower_ack_timelock < current_height;
        let is_blockhash_commit_timeout = out_monitor.height
            + timelock_config.watchtower_blockhash_commit_timelock
            < current_height;
        let mut data_change = false;
        let mut is_commit_block_hash_ready = false;
        let mut p2p_message_contents: Vec<(Actor, GOATMessageContent, Option<String>)> = vec![];
        info!(
            "is_ack_timeout_{is_ack_timeout}, is_challenge_timeout_{is_challenge_timeout}, \
            is_blockhash_commit_timeout_{is_blockhash_commit_timeout}, out_monitor.height:{}, current_height:{current_height} ",
            out_monitor.height
        );

        if !is_blockhash_commit_timeout
            && vout_monitor_data.commit_blockhash_status
                == CommitBlockHashStatus::WatchtowerChallengeProcessed
        {
            if let Some(spend_txid) = outpoint_spent_txid(
                btc_client,
                &watchtower_challenge_init_txid,
                (out_monitor.vout_len - CONNECTOR_G_MARGIN) as u64,
            )
            .await?
                && blockhash_commit_timeout_txid != spend_txid
            {
                info!(
                    "process_watchtower_challenge_monitoring graph id :{} sub status update to CommitBlockHashStatus::OperatorCommit",
                    graph.graph_id
                );
                vout_monitor_data.commit_blockhash_status = CommitBlockHashStatus::OperatorCommit;
                sub_status.commit_blockhash_status = CommitBlockHashStatus::OperatorCommit;
                data_change = true;
            }
        } else if is_blockhash_commit_timeout {
            info!(
                "process_watchtower_challenge_monitoring graph id :{} sub status update to CommitBlockHashStatus::OperatorCommitTimeout",
                graph.graph_id
            );
            vout_monitor_data.commit_blockhash_status =
                CommitBlockHashStatus::OperatorCommitTimeout;
            sub_status.commit_blockhash_status = CommitBlockHashStatus::OperatorCommitTimeout;
            sub_status.disprove_type = Some(DisproveTxType::OperatorCommitTimeout);
            p2p_message_contents.push((
                Actor::Challenger,
                GOATMessageContent::OperatorCommitBlockHashTimeout(
                    OperatorCommitBlockHashTimeout {
                        instance_id: graph.instance_id,
                        graph_id: graph.graph_id,
                    },
                ),
                None,
            ));
            data_change = true;
        }

        if !is_ack_timeout {
            if is_challenge_timeout {
                info!(
                    "process_watchtower_challenge_monitoring watchtower challenge timeout for graph id :{}, vout_monitor_data:{:?}",
                    graph.graph_id, vout_monitor_data
                );
                let watchtower_indexes: Vec<usize> = vout_monitor_data
                    .data_map
                    .iter()
                    .filter_map(|(&index, status)| match status {
                        WatchtowerChallengeItemStatus::OperatorInit => Some(index as usize),
                        _ => None,
                    })
                    .collect();
                if !watchtower_indexes.is_empty() && !vout_monitor_data.is_challenge_timeout_sent {
                    let sub_type = format!(
                        "[{}]",
                        watchtower_indexes
                            .iter()
                            .map(|v| v.to_string())
                            .collect::<Vec<String>>()
                            .join("_")
                    );
                    p2p_message_contents.push((
                        Actor::Operator,
                        GOATMessageContent::WatchtowerChallengeTimeout(
                            WatchtowerChallengeTimeout {
                                instance_id: graph.instance_id,
                                graph_id: graph.graph_id,
                                watchtower_indexes,
                            },
                        ),
                        Some(sub_type),
                    ));
                    sub_status.watchtower_challenge_status =
                        WatchtowerChallengeStatus::WatchtowerChallengeTimeout;
                    vout_monitor_data.is_challenge_timeout_sent = true;
                    data_change = true;
                }
            }

            let (challenge_txids, challenge_timeout_txids, ack_txids) = vout_monitor_data
                .monitor_vout(
                    btc_client,
                    &watchtower_challenge_init_txid,
                    &graph.watchtower_challenge_timeout_txids,
                    &graph.nack_txids,
                )
                .await?;

            if !challenge_txids.is_empty() {
                data_change = true;
                //  contain the situations:
                //      1. all watchtower challenge
                //      2,challenge timeout. operator not send challenge timeout, but watchtower send challenge tx

                if [
                    WatchtowerChallengeStatus::OperatorInit,
                    WatchtowerChallengeStatus::WatchtowerChallengeTimeout,
                ]
                .contains(&sub_status.watchtower_challenge_status)
                    && !vout_monitor_data
                        .data_map
                        .iter()
                        .any(|(_, v)| *v == WatchtowerChallengeItemStatus::OperatorInit)
                {
                    info!(
                        "process_watchtower_challenge_monitoring graph id :{} sub status update to WatchtowerChallengeStatus::Challenge",
                        graph.graph_id
                    );
                    // all in challenge
                    sub_status.watchtower_challenge_status =
                        WatchtowerChallengeStatus::WatchtowerChallenge;
                }
                p2p_message_contents.push((
                    Actor::Operator,
                    GOATMessageContent::WatchtowerChallengeSent(WatchtowerChallengeSent {
                        instance_id: graph.instance_id,
                        graph_id: graph.graph_id,
                        watchtower_challenge_txids: challenge_txids,
                    }),
                    None,
                ));
            }

            if !ack_txids.is_empty() || !challenge_timeout_txids.is_empty() {
                data_change = true;
            }

            if vout_monitor_data.commit_blockhash_status == CommitBlockHashStatus::None
                && vout_monitor_data.is_commit_blockhash_ready()
            {
                data_change = true;
                sub_status.commit_blockhash_status =
                    CommitBlockHashStatus::WatchtowerChallengeProcessed;
                vout_monitor_data.commit_blockhash_status =
                    CommitBlockHashStatus::WatchtowerChallengeProcessed;
                is_commit_block_hash_ready = true;
            }

            if vout_monitor_data.check_watchtower_challenge_normal_finished() {
                data_change = true;
                sub_status.watchtower_challenge_status =
                    WatchtowerChallengeStatus::WatchtowerChallengeNormalFinished;
            }
        } else {
            info!(
                "process_watchtower_challenge_monitoring graph id :{} ack timeout",
                graph.graph_id
            );
            vout_monitor_data.update_disprove_indexes();
            if vout_monitor_data.require_disproved_indexes.is_empty() {
                trace!(
                    "process_watchtower_challenge_monitoring graph id :{} sub status update to WatchtowerChallengeStatus::OperatorACK",
                    graph.graph_id
                );
                sub_status.watchtower_challenge_status =
                    WatchtowerChallengeStatus::WatchtowerChallengeNormalFinished;
            } else {
                trace!(
                    "process_watchtower_challenge_monitoring graph id :{} sub status update to WatchtowerChallengeStatus::OperatorNACK",
                    graph.graph_id
                );
                sub_status.watchtower_challenge_status =
                    WatchtowerChallengeStatus::WatchtowerChallengeDisproveFinished;
                sub_status.disprove_type = Some(DisproveTxType::OperatorNack);
                p2p_message_contents.push((
                    Actor::Challenger,
                    GOATMessageContent::OperatorAckTimeout(OperatorAckTimeout {
                        instance_id: graph.instance_id,
                        graph_id: graph.graph_id,
                    }),
                    Some(vout_monitor_data.get_require_disproved_string()),
                ));
            }
            data_change = true;
        }
        if data_change {
            let mut tx = local_db.start_transaction().await?;
            tx.update_graph(
                &GraphUpdate::new(graph.graph_id)
                    .with_sub_status(serde_json::to_string(sub_status).unwrap()),
            )
            .await?;
            if is_commit_block_hash_ready {
                upsert_message(
                    &mut tx,
                    false,
                    graph.graph_id,
                    None,
                    "self".to_string(),
                    Actor::Operator,
                    GOATMessageContent::OperatorCommitBlockHashReady(
                        OperatorCommitBlockHashReady {
                            instance_id: graph.instance_id,
                            graph_id: graph.graph_id,
                        },
                    ),
                    0,
                    0,
                )
                .await?;
            }

            tx.update_graph_btc_tx_vout_monitor_data(
                &graph.graph_id,
                &watchtower_challenge_init_txid.into(),
                serde_json::to_string(&vout_monitor_data)?,
            )
            .await?;
            for (actor, message_content, sub_type) in p2p_message_contents {
                upsert_message(
                    &mut tx,
                    false,
                    graph.graph_id,
                    sub_type,
                    "self".to_string(),
                    actor,
                    message_content,
                    0,
                    0,
                )
                .await?;
            }
            tx.commit().await?;
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
            if let Ok(Some(watchtower_challenge_init_tx)) =
                btc_client.get_tx_info(&watchtower_challenge_init_txid).await
                && watchtower_challenge_init_tx.status.block_height.unwrap_or_default() > 0
            {
                sub_status.watchtower_challenge_status = WatchtowerChallengeStatus::OperatorInit;
                let mut tx = local_db.start_transaction().await?;
                tx.update_graph(
                    &GraphUpdate::new(graph.graph_id)
                        .with_sub_status(serde_json::to_string(sub_status).unwrap()),
                )
                .await?;

                tx.upsert_graph_btc_tx_vout_monitor(&GraphBtcTxVoutMonitor {
                    graph_id: graph.graph_id,
                    tx_name: MONITE_BTC_TX_NAME_WATCHTOWER_INIT.to_string(),
                    txid: watchtower_challenge_init_txid.into(),
                    height: watchtower_challenge_init_tx.status.block_height.unwrap_or_default()
                        as i64,
                    vout_len: watchtower_challenge_init_tx.vout.len() as i64,
                    monitor_data: serde_json::to_string(&WTInitTxVoutMonitorData::new(
                        (watchtower_challenge_init_tx.vout.len() as i32
                            - CONNECTOR_G_MARGIN as i32)
                            / 2,
                    ))?,
                    created_at: current_time_secs(),
                    updated_at: current_time_secs(),
                })
                .await?;
                upsert_message(
                    &mut tx,
                    false,
                    graph.graph_id,
                    None,
                    "self".to_string(),
                    Actor::Watchtower,
                    GOATMessageContent::WatchtowerChallengeInitSent(WatchtowerChallengeInitSent {
                        instance_id: graph.instance_id,
                        graph_id: graph.graph_id,
                    }),
                    0,
                    0,
                )
                .await?;
                tx.commit().await?;
            } else {
                warn!(
                    "process_assert_commit_monitoring graph_id: {}, watchtower_challenge_init_txid {watchtower_challenge_init_txid} not found on chain",
                    graph.graph_id
                );
            }
        }
    }

    Ok(())
}

/// Process assert commit monitoring
async fn process_assert_commit_monitoring(
    btc_client: &BTCClient,
    local_db: &LocalDB,
    graph: &Graph,
    sub_status: &mut ChallengeSubStatus,
    current_height: i64,
) -> anyhow::Result<()> {
    trace!("process_assert_commit_monitoring start");
    let timelock_config = get_challenge_timelock_config();
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
    let out_monitor = {
        let mut storage_processor = local_db.acquire().await?;
        storage_processor
            .find_graph_btc_tx_vout_monitor(&graph.graph_id, &assert_init_txid.into())
            .await?
    };

    if let Some(out_monitor) = out_monitor {
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
        let is_assert_commit_timeout =
            out_monitor.height + timelock_config.assert_commit_timelock < current_height;
        info!(
            "process_assert_commit_monitoring: graph id :{} is_assert_commit_timeout:{is_assert_commit_timeout},\
         out_monitor.height:{}, timelock_config.assert_commit_timelock:{}, current_height:{current_height}",
            graph.graph_id, out_monitor.height, timelock_config.assert_commit_timelock
        );
        let mut data_change = false;
        let mut message_content: Option<(Actor, GOATMessageContent)> = None;
        if !is_assert_commit_timeout {
            trace!(
                "process_assert_commit_monitoring graph id :{} assert commit monitor",
                graph.graph_id
            );
            let vout_spent_len = vout_monitor_data
                .monitor_vout(btc_client, &assert_init_txid, &graph.assert_commit_timeout_txids)
                .await?;

            if vout_monitor_data.check_normal_finished() {
                sub_status.assert_commit_status = AssertCommitStatus::OperatorCommit;
            }

            info!(
                "process_assert_commit_monitoring graph id :{} vout_spent_len:{vout_spent_len}",
                graph.graph_id
            );
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
                sub_status.disprove_type = Some(DisproveTxType::AssertTimeout);
                message_content = Some((
                    Actor::Challenger,
                    GOATMessageContent::AssertCommitTimeout(AssertCommitTimeout {
                        instance_id: graph.instance_id,
                        graph_id: graph.graph_id,
                    }),
                ));
            }
            data_change = true;
        }
        if data_change {
            let mut tx = local_db.start_transaction().await?;
            tx.update_graph(
                &GraphUpdate::new(graph.graph_id)
                    .with_sub_status(serde_json::to_string(sub_status).unwrap()),
            )
            .await?;
            tx.update_graph_btc_tx_vout_monitor_data(
                &graph.graph_id,
                &assert_init_txid.into(),
                serde_json::to_string(&vout_monitor_data)?,
            )
            .await?;
            if let Some((actor, message_content)) = message_content {
                upsert_message(
                    &mut tx,
                    false,
                    graph.graph_id,
                    None,
                    "self".to_string(),
                    actor,
                    message_content,
                    0,
                    0,
                )
                .await?;
            }
            tx.commit().await?;
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

            if let Ok(Some(assert_init_tx)) = btc_client.get_tx_info(&assert_init_txid).await
                && assert_init_tx.status.block_height.unwrap_or_default() > 0
            {
                sub_status.assert_commit_status = AssertCommitStatus::OperatorInit;
                let mut tx = local_db.start_transaction().await?;
                tx.update_graph(
                    &GraphUpdate::new(graph.graph_id)
                        .with_sub_status(serde_json::to_string(sub_status).unwrap()),
                )
                .await?;
                tx.upsert_graph_btc_tx_vout_monitor(&GraphBtcTxVoutMonitor {
                    graph_id: graph.graph_id,
                    tx_name: MONITE_BTC_TX_NAME_ASSERT_INIT.to_string(),
                    txid: assert_init_txid.into(),
                    height: assert_init_tx.status.block_height.unwrap_or_default() as i64,
                    vout_len: assert_init_tx.vout.len() as i64,
                    monitor_data: serde_json::to_string(&AssertInitTxVoutMonitorData::new(
                        assert_init_tx.vout.len() as i32 - 2,
                    ))?,
                    created_at: current_time_secs(),
                    updated_at: current_time_secs(),
                })
                .await?;
                tx.commit().await?;
            } else {
                warn!(
                    "process_assert_commit_monitoring graph_id: {}, assert_init_txid {assert_init_txid} not found on chain",
                    graph.graph_id
                );
            }
        } else {
            let mut storage_processor = local_db.acquire().await?;
            upsert_message(
                &mut storage_processor,
                false,
                graph.graph_id,
                None,
                "self".to_string(),
                Actor::Operator,
                GOATMessageContent::AssertInitReady(AssertInitReady {
                    instance_id: graph.instance_id,
                    graph_id: graph.graph_id,
                }),
                0,
                0,
            )
            .await?;
        }
    }

    Ok(())
}

/// Find the spend transaction for a disproved index
async fn find_challenge_nack_tx(
    btc_client: &BTCClient,
    storage_processor: &mut StorageProcessor<'_>,
    graph_id: &Uuid,
    watchtower_challenge_init_txid: &SerializableTxid,
) -> anyhow::Result<Option<(Txid, i32)>> {
    info!("find_challenge_nack_tx for graph_id: {graph_id}");
    let out_monitor = storage_processor
        .find_graph_btc_tx_vout_monitor(graph_id, watchtower_challenge_init_txid)
        .await?;

    let Some(out_monitor) = out_monitor else {
        return Ok(None);
    };

    if let Some(spend_txid) = outpoint_spent_txid(
        btc_client,
        &watchtower_challenge_init_txid.clone().into(),
        out_monitor.vout_len as u64 - CONNECTOR_F_MARGIN,
    )
    .await?
        && let Some(tx) = btc_client.get_tx(&spend_txid).await?
    {
        let index = tx.input[0].previous_output.vout as i32;
        if index == out_monitor.vout_len as i32 - 3_i32 {
            return Ok(None);
        }

        return Ok(Some((spend_txid, index / 2)));
    }

    Ok(None)
}

/// Find the spend transaction for assert timeout
async fn find_assert_timeout_tx(
    btc_client: &BTCClient,
    storage_processor: &mut StorageProcessor<'_>,
    graph_id: &Uuid,
    assert_init_txid: &SerializableTxid,
) -> anyhow::Result<Option<(Txid, i32)>> {
    info!("find_assert_timeout_tx for graph_id: {graph_id}");
    let out_monitor =
        storage_processor.find_graph_btc_tx_vout_monitor(graph_id, assert_init_txid).await?;

    let Some(out_monitor) = out_monitor else {
        return Ok(None);
    };

    if let Some(spend_txid) = outpoint_spent_txid(
        btc_client,
        &assert_init_txid.clone().into(),
        out_monitor.vout_len as u64 - CONNECTOR_D_MARGIN,
    )
    .await?
        && let Some(tx) = btc_client.get_tx(&spend_txid).await?
    {
        return Ok(Some((spend_txid, tx.input[0].previous_output.vout as i32)));
    }

    Ok(None)
}

async fn detect_kickoff_ref_disprove_tx(
    btc_client: &BTCClient,
    local_db: &LocalDB,
    graph: &Graph,
) -> anyhow::Result<bool> {
    let mut detected = false;
    let (kickoff_txid, take1_txid, take2_txid, next_pre_kickoff): (
        Txid,
        Txid,
        Txid,
        SerializableTxid,
    ) = match (
        graph.kickoff_txid.clone(),
        graph.take1_txid.clone(),
        graph.take2_txid.clone(),
        graph.next_prekickoff.clone(),
    ) {
        (Some(kickoff_txid), Some(take1_txid), Some(take2_txid), Some(next_pre_kickoff)) => {
            (kickoff_txid.into(), take1_txid.into(), take2_txid.into(), next_pre_kickoff)
        }
        _ => {
            warn!("graph:{} kickoff_txid/take1_txid/take2_txid  has none value", graph.graph_id);
            return Ok(detected);
        }
    };
    let pre_sents = check_pre_kickoff_sent(local_db, btc_client, next_pre_kickoff, 2).await?;
    if pre_sents > 0 {
        info!("graph_id:{} next {pre_sents} graphs's pre_kickoff has been sent!", graph.graph_id);
        detected = true;
    }
    let out_monitor = {
        let mut storage_processor = local_db.acquire().await?;
        storage_processor
            .find_graph_btc_tx_vout_monitor(&graph.graph_id, &kickoff_txid.into())
            .await?
    };

    let Some(out_monitor) = out_monitor else {
        return Ok(false);
    };

    if let Some(spend_txid) = outpoint_spent_txid(
        btc_client,
        &kickoff_txid,
        out_monitor.vout_len as u64 - CONNECTOR_GUARDIAN_MARGIN,
    )
    .await?
        && let Some(tx) = btc_client.get_tx(&spend_txid).await?
    {
        if spend_txid == take1_txid || spend_txid == take2_txid || tx.input.len() < 2 {
            return Ok(false);
        }

        let disprove_type = if tx.input[1].previous_output.vout == 0 {
            DisproveTxType::QuickChallenge
        } else {
            DisproveTxType::ChallengeIncompleteKickoff
        };

        info!(
            "graph_id:{} is disproved, spent txid:{}, disprove_type:{}",
            graph.graph_id, spend_txid, disprove_type
        );
        let challenge_start_txid: Option<Txid> = graph.challenge_txid.clone().map(|v| v.into());
        let mut storage_processor = local_db.acquire().await?;
        upsert_message(
            &mut storage_processor,
            false,
            graph.graph_id,
            None,
            "self".to_string(),
            Actor::Committee,
            GOATMessageContent::DisproveSent(DisproveSent {
                instance_id: graph.instance_id,
                graph_id: graph.graph_id,
                disprove_type,
                index: 0,
                challenge_start_txid,
                challenge_finish_txid: spend_txid,
            }),
            0,
            0,
        )
        .await?;
        detected = true;
    }
    Ok(detected)
}

async fn fetch_challenge_txid(
    btc_client: &BTCClient,
    storage_processor: &mut StorageProcessor<'_>,
    graph_id: Uuid,
    kickoff_txid: &Option<SerializableTxid>,
    take1_txid: &Option<SerializableTxid>,
) -> anyhow::Result<Option<SerializableTxid>> {
    info!("fetch_challenge_txid for graph_id:{}", graph_id);
    let (kickoff_txid, take1_txid): (Txid, Txid) = match (kickoff_txid, take1_txid) {
        (Some(kickoff_txid), Some(take1_txid)) => (kickoff_txid.0, take1_txid.0),
        _ => {
            warn!("graph:{graph_id} kickoff_txid or take1_txid none");
            return Ok(None);
        }
    };

    if let Ok(Some(txid)) = outpoint_spent_txid(btc_client, &kickoff_txid, 0).await {
        if txid == take1_txid {
            warn!("graph:{graph_id} take1 has been sent!");
            Ok(None)
        } else {
            info!("graph:{graph_id} detected challenge txid :{txid}");
            storage_processor
                .update_graph(&GraphUpdate::new(graph_id).with_challenge_txid(txid.into()))
                .await?;
            Ok(Some(txid.into()))
        }
    } else {
        warn!("graph:{graph_id} fail to detect challenge txid  will try later");
        Ok(None)
    }
}

async fn detect_disproved_txids(
    btc_client: &BTCClient,
    storage_processor: &mut StorageProcessor<'_>,
    graph: &Graph,
    sub_status: &mut ChallengeSubStatus,
) -> anyhow::Result<Option<(DisproveTxType, Txid, Txid, i32)>> {
    info!("detecting disproved txids graph_id {}", graph.graph_id);
    let challenge_txid: Txid = match graph.challenge_txid.clone() {
        Some(challenge_txid) => challenge_txid.into(),
        None => {
            warn!("graph:{} challenge_txid is none", graph.graph_id);
            if let Ok(Some(txid)) = fetch_challenge_txid(
                btc_client,
                storage_processor,
                graph.graph_id,
                &graph.kickoff_txid,
                &graph.take1_txid,
            )
            .await
            {
                txid.into()
            } else {
                return Ok(None);
            }
        }
    };

    if let Some(disprove_type) = sub_status.disprove_type
        && let Some(disprove_txid) = graph.disprove_txid.clone()
    {
        return Ok(Some((
            disprove_type,
            challenge_txid,
            disprove_txid.into(),
            sub_status.disprove_index,
        )));
    }

    let (
        kickoff_txid,
        watchtower_challenge_init_txid,
        blockhash_commit_timeout_txid,
        assert_init_txid,
        take2_txid,
    ): (Txid, Txid, Txid, Txid, Txid) = match (
        graph.kickoff_txid.clone(),
        graph.watchtower_challenge_init_txid.clone(),
        graph.blockhash_commit_timeout_txid.clone(),
        graph.assert_init_txid.clone(),
        graph.take2_txid.clone(),
    ) {
        (
            Some(kickoff_txid),
            Some(watchtower_challenge_init_txid),
            Some(blockhash_commit_timeout_txid),
            Some(assert_init_txid),
            Some(take2_txid),
        ) => (
            kickoff_txid.into(),
            watchtower_challenge_init_txid.into(),
            blockhash_commit_timeout_txid.into(),
            assert_init_txid.into(),
            take2_txid.into(),
        ),
        _ => {
            warn!(
                "graph:{} kickoff_txid/watchtower_challenge_init_txid/blockhash_commit_timeout_txid/\
                    assert_init_txid/take2_txid  has none value",
                graph.graph_id
            );
            return Ok(None);
        }
    };
    match sub_status.disprove_type {
        Some(DisproveTxType::AssertTimeout) => {
            return Ok(find_assert_timeout_tx(
                btc_client,
                storage_processor,
                &graph.graph_id,
                &assert_init_txid.into(),
            )
            .await?
            .map(|(finish_txid, index)| {
                (DisproveTxType::AssertTimeout, challenge_txid, finish_txid, index)
            }));
        }

        Some(DisproveTxType::OperatorNack) => {
            return Ok(find_challenge_nack_tx(
                btc_client,
                storage_processor,
                &graph.graph_id,
                &watchtower_challenge_init_txid.into(),
            )
            .await?
            .map(|(finish_txid, index)| {
                (DisproveTxType::OperatorNack, challenge_txid, finish_txid, index)
            }));
        }

        Some(DisproveTxType::OperatorCommitTimeout) => {
            return Ok(Some((
                DisproveTxType::OperatorCommitTimeout,
                challenge_txid,
                blockhash_commit_timeout_txid,
                0,
            )));
        }
        _ => {}
    }

    // QuickChallenge  ChallengeIncompleteKickoff detect in status Operator kickoff
    if let Some(spent_txid) = outpoint_spent_txid(btc_client, &kickoff_txid, 3).await?
        && spent_txid != take2_txid
    {
        sub_status.disprove_type = Some(DisproveTxType::Disprove);
        return Ok(Some((DisproveTxType::Disprove, challenge_txid, spent_txid, 0)));
    }

    Ok(None)
}
async fn process_graph_watchtower_assert_disproved(
    btc_client: &BTCClient,
    local_db: &LocalDB,
    graph: &Graph,
    sub_status: &mut ChallengeSubStatus,
) -> anyhow::Result<()> {
    info!("process_graph_watchtower_assert_disproved for graph:{}", graph.graph_id);
    let mut tx = local_db.start_transaction().await?;
    match detect_disproved_txids(btc_client, &mut tx, graph, sub_status).await? {
        Some((disprove_type, start_txid, finish_txid, tx_index)) => {
            if graph.disprove_txid.is_none() {
                sub_status.disprove_index = tx_index;
                tx.update_graph(
                    &GraphUpdate::new(graph.graph_id)
                        .with_disprove_txid(finish_txid.into())
                        .with_sub_status(serde_json::to_string(sub_status).unwrap()),
                )
                .await?;
            }

            info!(
                "process_graph_watchtower_assert_disproved: graph:{} disprove_type:{}, start_txid:{}. finsh_txid{}. tx_index:{} ",
                graph.graph_id, disprove_type, start_txid, finish_txid, tx_index
            );

            upsert_message(
                &mut tx,
                false,
                graph.graph_id,
                None,
                "self".to_string(),
                Actor::Committee,
                GOATMessageContent::DisproveSent(DisproveSent {
                    instance_id: graph.instance_id,
                    graph_id: graph.graph_id,
                    disprove_type,
                    index: tx_index as usize,
                    challenge_start_txid: Some(start_txid),
                    challenge_finish_txid: finish_txid,
                }),
                0,
                0,
            )
            .await?;
            tx.commit().await?;
        }
        None => {
            trace!("process_graph_watchtower_assert_disproved get disproved tx is none");
        }
    }
    Ok(())
}

/// Process graph data in Watchtower Assert Normal status
async fn detect_take2(
    btc_client: &BTCClient,
    local_db: &LocalDB,
    graph: &Graph,
    current_height: i64,
) -> anyhow::Result<Option<(Actor, GOATMessageContent)>> {
    trace!("detect_take2 graph_id {}", graph.graph_id);
    let timelock_config = get_take2_timelock_config();
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

    let spent_txid = match outpoint_spent_txid(btc_client, &kickoff_txid, 3).await? {
        Some(txid) => txid,
        None => {
            trace!("detect_take2 graph_id {} take2 or disprove is not on chain", graph.graph_id);
            let mut storage_processor = local_db.acquire().await?;
            let watchtower_init_height = storage_processor
                .find_graph_btc_tx_vout_monitor(
                    &graph.graph_id,
                    &watchtower_challenge_init_txid.into(),
                )
                .await?
                .unwrap_or_default()
                .height;

            let assert_init_height = storage_processor
                .find_graph_btc_tx_vout_monitor(&graph.graph_id, &assert_init_txid.into())
                .await?
                .unwrap_or_default()
                .height;
            let ready = check_operator_withdraw_ready_condition(
                btc_client,
                local_db,
                graph.graph_id,
                vec![
                    (
                        watchtower_challenge_init_txid,
                        MONITE_BTC_TX_NAME_WATCHTOWER_INIT.to_string(),
                        OperatorWithdrawType::Take2,
                        watchtower_init_height,
                        timelock_config.watchtower_challenge_init_out_timelock,
                    ),
                    (
                        assert_init_txid,
                        MONITE_BTC_TX_NAME_ASSERT_INIT.to_string(),
                        OperatorWithdrawType::Take2,
                        assert_init_height,
                        timelock_config.assert_init_out_timelock,
                    ),
                ],
                current_height,
            )
            .await?;

            if ready {
                info!(
                    "detect_take2 graph_id {} take2 is ready to send to btc chain",
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

    if spent_txid == take2_txid {
        info!(
            "detect_take2 graph_id {} take2:{} is on btc chain",
            graph.graph_id,
            spent_txid.to_string()
        );
        Ok(Some((
            Actor::Committee,
            GOATMessageContent::Take2Sent(Take2Sent {
                instance_id: graph.instance_id,
                graph_id: graph.graph_id,
            }),
        )))
    } else {
        Ok(None)
    }
}

async fn check_pre_kickoff_sent(
    local_db: &LocalDB,
    btc_client: &BTCClient,
    pre_kickoff: SerializableTxid,
    check_level: i32,
) -> anyhow::Result<usize> {
    let check_graphs = {
        let mut check_graphs: Vec<(Uuid, Uuid, Txid)> = vec![];
        let mut storage_processor = local_db.acquire().await?;
        let mut check_level = check_level;
        let mut pre_kickoff = pre_kickoff;

        while check_level > 0 {
            if let Some((graph_id, instance_id, cur_pre_kickoff, next_pre_kickoff)) =
                storage_processor
                    .get_graph_pre_kickoff_chain_by_cur_pre_kickoff(pre_kickoff.clone())
                    .await?
            {
                check_graphs.push((graph_id, instance_id, cur_pre_kickoff.into()));
                pre_kickoff = next_pre_kickoff;
                check_level -= 1;
            } else {
                break;
            }
        }
        check_graphs
    };
    let mut pre_sents = 0;
    for (graph_id, instance_id, cur_pre_kickoff) in check_graphs {
        if btc_client.get_tx_status(&cur_pre_kickoff).await?.confirmed {
            let mut storage_processor = local_db.acquire().await?;
            upsert_message(
                &mut storage_processor,
                false,
                graph_id,
                None,
                "self".to_string(),
                Actor::Challenger,
                GOATMessageContent::PreKickoffSent(PreKickoffSent { instance_id, graph_id }),
                0,
                0,
            )
            .await?;
            pre_sents += 1;
        }
    }
    Ok(pre_sents)
}
