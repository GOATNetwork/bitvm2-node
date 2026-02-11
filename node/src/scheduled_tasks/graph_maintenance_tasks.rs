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
use crate::utils::{SELF_SENDER, outpoint_spent_txid, upsert_message};
use bitcoin::Txid;
use bitvm2_lib::actors::Actor;
use bitvm2_lib::challenger::{
    assert_commit_timeout_timelock, commit_blockhash_timeout_timelock, nack_timelock,
};
use bitvm2_lib::operator::{
    take1_timelock, take2_timelocks, watchtower_challenge_timeout_timelock,
};
use client::btc_chain::BTCClient;
use client::goat_chain::DisproveTxType;
use indexmap::IndexMap;
use serde::{Deserialize, Serialize};
use store::localdb::{LocalDB, StorageProcessor};
use store::{
    GoatTxProcessingStatus, GoatTxType, Graph, GraphBtcTxVoutMonitor, GraphStatus, SerializableTxid,
};
use strum::{Display, EnumString};
use tracing::{info, trace, warn};
use uuid::Uuid;

const CONNECTOR_G_MARGIN: i64 = 3;
// const CONNECTOR_D_MARGIN: u64 = 2;
// const CONNECTOR_F_MARGIN: u64 = 2;
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
    WatchtowerChallengeProcessed, // watchtower challenge processed, but commit blockhash not detected yet
    OperatorCommit,               // commit blockhash detected
    OperatorCommitTimeout,        // commit blockhash not detected, but timelock expired
}

#[derive(
    Copy, Clone, Debug, Serialize, Deserialize, Default, Eq, PartialEq, Display, EnumString,
)]
pub enum AssertCommitStatus {
    #[default]
    None,
    OperatorInit,   // assert init vout detected, but some assert commit not detected yet
    OperatorCommit, // all assert commit sent
    OperatorCommitTimeout, // some assert commit not sent, but timelock expired
}

#[derive(
    Copy, Clone, Debug, Serialize, Deserialize, Default, Eq, PartialEq, Display, EnumString,
)]
pub enum WatchtowerChallengeStatus {
    #[default]
    None,
    OperatorInit,        // watchtower init detected, but no challenge detected yet
    WatchtowerChallenge, // Some Watchtower challenge, and timelock not expired
    WatchtowerChallengeTimeout, // Some Watchtower did not challenge, and timelock expired
    OperatorACKTimeout,  // Operator did not send ACK for some Watchtower, and timelock expired
    WatchtowerChallengeNormalFinished, // Normal Finished, TODO: rename it
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
    pub fn is_watchtower_challenge_success(&self) -> bool {
        self.watchtower_challenge_status
            == WatchtowerChallengeStatus::WatchtowerChallengeNormalFinished
            && self.commit_blockhash_status == CommitBlockHashStatus::OperatorCommit
    }

    pub fn is_disproved(&self) -> bool {
        self.disprove_type.is_some()
    }

    pub fn is_all_commit_success(&self) -> bool {
        self.is_watchtower_challenge_success() && self.is_assert_commit_success()
    }

    pub fn is_assert_commit_success(&self) -> bool {
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
        }
    }
    pub async fn monitor_vout(
        &mut self,
        btc_client: &BTCClient,
        txid: &Txid,
        input_challenge_timeout_txids: &[SerializableTxid],
        nack_txids: &[SerializableTxid],
        commit_blockhash_timeout_txid: &SerializableTxid,
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
        let connector_g_vout = self.data_map.len() as i32 * 2;
        if matches!(
            self.commit_blockhash_status,
            CommitBlockHashStatus::None | CommitBlockHashStatus::WatchtowerChallengeProcessed
        ) && let Some(spend_txid) =
            outpoint_spent_txid(btc_client, txid, connector_g_vout as u64).await?
        {
            if commit_blockhash_timeout_txid.0 == spend_txid {
                self.commit_blockhash_status = CommitBlockHashStatus::OperatorCommitTimeout;
            } else {
                self.commit_blockhash_status = CommitBlockHashStatus::OperatorCommit;
            }
        } else if self.commit_blockhash_status == CommitBlockHashStatus::None
            && self.is_commit_blockhash_ready()
        {
            self.commit_blockhash_status = CommitBlockHashStatus::WatchtowerChallengeProcessed;
        }
        Ok((challenge_txids, challenge_timeout_txids, ack_txids))
    }

    fn update_disprove_indexes(&mut self) {
        self.require_disproved_indexes = vec![];
        for (index, status) in self.data_map.iter() {
            if matches!(
                *status,
                WatchtowerChallengeItemStatus::OperatorInit
                    | WatchtowerChallengeItemStatus::Challenge
            ) {
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
                    matches!(
                        **v,
                        WatchtowerChallengeItemStatus::Challenge
                            | WatchtowerChallengeItemStatus::OperatorACK
                    )
                })
                .count(),
            self.data_map.len(),
        )
    }

    pub fn get_challenge_timeout_process_desc(&self) -> (usize, usize) {
        (
            self.data_map
                .iter()
                .filter(|(_, v)| **v == WatchtowerChallengeItemStatus::ChallengeTimeout)
                .count(),
            self.data_map.len(),
        )
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
                    matches!(
                        **v,
                        WatchtowerChallengeItemStatus::Challenge
                            | WatchtowerChallengeItemStatus::OperatorACK
                            | WatchtowerChallengeItemStatus::OperatorNACK
                    )
                })
                .count(),
        )
    }

    pub fn is_watchtower_challenge_success(&self) -> bool {
        self.data_map.values().all(|status| {
            matches!(
                status,
                WatchtowerChallengeItemStatus::OperatorACK
                    | WatchtowerChallengeItemStatus::ChallengeTimeout
            )
        }) && self.commit_blockhash_status == CommitBlockHashStatus::OperatorCommit
    }

    pub fn is_commit_blockhash_processed(&self) -> bool {
        matches!(
            self.commit_blockhash_status,
            CommitBlockHashStatus::OperatorCommit | CommitBlockHashStatus::OperatorCommitTimeout
        )
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

    pub fn is_disproved(&self) -> bool {
        self.data_map.values().any(|status| *status == WatchtowerChallengeItemStatus::OperatorNACK)
            || self.commit_blockhash_status == CommitBlockHashStatus::OperatorCommitTimeout
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

    pub fn is_assert_success(&self) -> bool {
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

    fn is_disproved(&self) -> bool {
        self.data_map
            .values()
            .any(|status| *status == AssertCommitItemStatus::OperatorCommitTimeout)
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

/// may trigger: KickoffReady
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
                SELF_SENDER.to_string(),
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

/// may trigger: KickoffSent
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
                SELF_SENDER.to_string(),
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

/// may trigger: Take1Ready, Take1Sent, ChallengeSent
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
        // process_kickoff_graph may trigger Take1Ready, Take1Sent or ChallengeSent
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
                SELF_SENDER.to_string(),
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

#[tracing::instrument(level = "info", skip(local_db, btc_client))]
pub async fn process_graph_challenge(
    local_db: &LocalDB,
    btc_client: &BTCClient,
) -> anyhow::Result<()> {
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
                    "failed to deserialize sub_status at graph:{}, reset to default, old sub_status {}",
                    graph.graph_id, graph.sub_status
                );
                ChallengeSubStatus::default()
            }
        };
        let mut is_watchtower_challenge_success = sub_status.is_watchtower_challenge_success();
        let mut is_assert_commit_success = sub_status.is_assert_commit_success();
        let mut is_all_commit_success = is_watchtower_challenge_success && is_assert_commit_success;
        if !sub_status.is_disproved() && !is_all_commit_success {
            trace!("graph:{} is not disproved", graph.graph_id);
            if !is_watchtower_challenge_success {
                info!("graph:{} watchtower challenge is processing", graph.graph_id);
                // process_watchtower_challenge_monitoring may trigger: WatchtowerChallengeSent, WatchtowerChallengeTimeout, OperatorAckTimeout, DisproveSent(OperatorCommitTimeout/OperatorNack), OperatorCommitBlockHashReady, OperatorCommitBlockHashTimeout
                is_watchtower_challenge_success = process_watchtower_challenge_monitoring(
                    btc_client,
                    local_db,
                    &graph,
                    &mut sub_status,
                    current_height,
                )
                .await?;
            }
            if is_watchtower_challenge_success && !is_assert_commit_success {
                info!("graph:{} assert commit is processing", graph.graph_id);
                // upsert AssertInitReady message whenever watchtower challenge is finished normally, repeated inserts are idempotent
                upsert_message(
                    &mut local_db.acquire().await?,
                    false,
                    graph.graph_id,
                    None,
                    SELF_SENDER.to_string(),
                    Actor::Operator,
                    GOATMessageContent::AssertInitReady(AssertInitReady {
                        instance_id: graph.instance_id,
                        graph_id: graph.graph_id,
                    }),
                    0,
                    0,
                )
                .await?;
                // process_assert_commit_monitoring may trigger: DisproveSent(AssertTimeout), AssertCommitTimeout
                is_assert_commit_success = process_assert_commit_monitoring(
                    btc_client,
                    local_db,
                    &graph,
                    &mut sub_status,
                    current_height,
                )
                .await?;
            }
            is_all_commit_success = is_watchtower_challenge_success && is_assert_commit_success;
        }
        if !sub_status.is_disproved() && is_all_commit_success {
            let mut storage_processor = local_db.acquire().await?;
            info!("graph:{} watchtower challenge and assert commit is finished", graph.graph_id);
            // upsert DisproveReady whenever both watchtower-challenge and assert is finished normally, repeated inserts are idempotent
            upsert_message(
                &mut storage_processor,
                false,
                graph.graph_id,
                None,
                SELF_SENDER.to_string(),
                Actor::Challenger,
                GOATMessageContent::DisproveReady(DisproveReady {
                    instance_id: graph.instance_id,
                    graph_id: graph.graph_id,
                }),
                0,
                0,
            )
            .await?;
            // detect_take2 may return: Take2Ready, Take2Sent, DisproveSent(Disprove)
            if let Some((actor, message_content)) =
                detect_take2(btc_client, local_db, &graph, current_height).await?
            {
                let mut storage_processor = local_db.acquire().await?;
                upsert_message(
                    &mut storage_processor,
                    false,
                    graph.graph_id,
                    None,
                    SELF_SENDER.to_string(),
                    actor,
                    message_content,
                    0,
                    0,
                )
                .await?;
            }
        }
    }

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
            let txid_serial: SerializableTxid = txid.into();
            let mut storage_processor = local_db.acquire().await?;
            let existing =
                storage_processor.find_graph_btc_tx_vout_monitor(&graph_id, &txid_serial).await?;
            let (monitor_data, created_at, tx_name_to_use) = match existing {
                Some(existing) => (existing.monitor_data, existing.created_at, existing.tx_name),
                None => ("".to_string(), current_times, tx_name.clone()),
            };
            storage_processor
                .upsert_graph_btc_tx_vout_monitor(&GraphBtcTxVoutMonitor {
                    graph_id,
                    tx_name: tx_name_to_use,
                    txid: txid_serial,
                    height,
                    vout_len,
                    monitor_data,
                    created_at,
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
/// may return: Take1Ready, Take1Sent, ChallengeSent
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
            // NOTE: revert to previous status?
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

/// Process watchtower challenge monitoring
/// may trigger: WatchtowerChallengeSent, WatchtowerChallengeTimeout, OperatorAckTimeout, DisproveSent(OperatorCommitTimeout/OperatorNack), OperatorCommitBlockHashReady, OperatorCommitBlockHashTimeout
/// return Ok(true) if watchtower challenge is success
#[tracing::instrument(level = "info", skip(btc_client, local_db))]
async fn process_watchtower_challenge_monitoring(
    btc_client: &BTCClient,
    local_db: &LocalDB,
    graph: &Graph,
    _sub_status: &mut ChallengeSubStatus,
    current_height: i64,
) -> anyhow::Result<bool> {
    // WatchtowerChallengeInitSent will be pushed inside refresh_watchtower_challenge_monitor_data
    let (mut vout_monitor_data, watchtower_challenge_init_height, monitor_result) =
        match refresh_watchtower_challenge_monitor_data(local_db, btc_client, graph).await? {
            Some((data, init_height, monitor_result)) => (data, init_height, monitor_result),
            None => {
                warn!(
                    "graph_id {} fail to get vout monitor data, maybe watchtower-challenge-init-tx not confirmed yet",
                    graph.graph_id
                );
                return Ok(false);
            }
        };

    let timelock_config = get_challenge_timelock_config();
    info!("timelock_config: {timelock_config:?}");
    let is_challenge_timeout = watchtower_challenge_init_height
        + timelock_config.watchtower_challenge_timelock
        < current_height;
    let is_ack_timeout =
        watchtower_challenge_init_height + timelock_config.watchtower_ack_timelock < current_height;
    let is_blockhash_commit_timeout = watchtower_challenge_init_height
        + timelock_config.watchtower_blockhash_commit_timelock
        < current_height;
    info!(
        "is_ack_timeout_{is_ack_timeout}, is_challenge_timeout_{is_challenge_timeout}, \
        is_blockhash_commit_timeout_{is_blockhash_commit_timeout}, watchtower_challenge_init_height:{watchtower_challenge_init_height}, current_height:{current_height} ",
    );
    if vout_monitor_data.is_watchtower_challenge_success() {
        info!("graph_id {} watchtower challenge is success", graph.graph_id);
        return Ok(true);
    }
    if vout_monitor_data.is_disproved() {
        let challenge_start_txid = graph.challenge_txid.clone().map(|v| v.into());
        let (disprove_type, index, challenge_finish_txid) = if vout_monitor_data
            .commit_blockhash_status
            == CommitBlockHashStatus::OperatorCommitTimeout
        {
            let blockhash_commit_timeout_txid = graph.blockhash_commit_timeout_txid.clone().ok_or_else(|| anyhow::anyhow!(
                "graph_id {} is disproved by OperatorCommitTimeout but blockhash_commit_timeout_txid is none",
                graph.graph_id
            ))?;
            (DisproveTxType::OperatorCommitTimeout, 0, blockhash_commit_timeout_txid.into())
        } else if let Some((&index, _)) = vout_monitor_data
            .data_map
            .iter()
            .find(|(_, status)| **status == WatchtowerChallengeItemStatus::OperatorNACK)
        {
            let nack_txid = graph.nack_txids.get(index as usize).cloned().ok_or_else(|| {
                anyhow::anyhow!(
                    "graph_id {} is disproved by OperatorNACK at index {} but nack_txid is none",
                    graph.graph_id,
                    index
                )
            })?;
            (DisproveTxType::OperatorNack, index as usize, nack_txid.into())
        } else {
            anyhow::bail!(
                "graph_id {} vout monitor data is disproved but no OperatorNACK or OperatorCommitBlockHashTimeout found",
                graph.graph_id
            )
        };
        upsert_message(
            &mut local_db.acquire().await?,
            false,
            graph.graph_id,
            None,
            SELF_SENDER.to_string(),
            Actor::Operator,
            GOATMessageContent::DisproveSent(DisproveSent {
                instance_id: graph.instance_id,
                graph_id: graph.graph_id,
                disprove_type,
                index,
                challenge_start_txid,
                challenge_finish_txid,
            }),
            0,
            0,
        )
        .await?;
        return Ok(false); // already disproved, no need to process further
    }
    if !vout_monitor_data.is_commit_blockhash_processed()
        && vout_monitor_data.is_commit_blockhash_ready()
    {
        upsert_message(
            &mut local_db.acquire().await?,
            false,
            graph.graph_id,
            None,
            SELF_SENDER.to_string(),
            Actor::Operator,
            GOATMessageContent::OperatorCommitBlockHashReady(OperatorCommitBlockHashReady {
                instance_id: graph.instance_id,
                graph_id: graph.graph_id,
            }),
            0,
            0,
        )
        .await?;
    }
    if !vout_monitor_data.is_commit_blockhash_processed() && is_blockhash_commit_timeout {
        upsert_message(
            &mut local_db.acquire().await?,
            false,
            graph.graph_id,
            None,
            SELF_SENDER.to_string(),
            Actor::Challenger,
            GOATMessageContent::OperatorCommitBlockHashTimeout(OperatorCommitBlockHashTimeout {
                instance_id: graph.instance_id,
                graph_id: graph.graph_id,
            }),
            0,
            0,
        )
        .await?;
    }
    if vout_monitor_data
        .data_map
        .values()
        .any(|status| *status == WatchtowerChallengeItemStatus::Challenge)
    {
        let watchtower_challenge_txids = monitor_result.0;
        if watchtower_challenge_txids.is_empty() {
            warn!(
                "graph_id {} watchtower challenge txids is empty when some vout status is Challenge",
                graph.graph_id
            );
        } else {
            upsert_message(
                &mut local_db.acquire().await?,
                false,
                graph.graph_id,
                None,
                SELF_SENDER.to_string(),
                Actor::Operator,
                GOATMessageContent::WatchtowerChallengeSent(WatchtowerChallengeSent {
                    instance_id: graph.instance_id,
                    graph_id: graph.graph_id,
                    watchtower_challenge_txids,
                }),
                0,
                0,
            )
            .await?;
        }
    }
    if is_ack_timeout {
        // Re-sends an OperatorAckTimeout message whenever the disproved indexes change.
        vout_monitor_data.update_disprove_indexes();
        if !vout_monitor_data.require_disproved_indexes.is_empty() {
            upsert_message(
                &mut local_db.acquire().await?,
                false,
                graph.graph_id,
                Some(vout_monitor_data.get_require_disproved_string()),
                SELF_SENDER.to_string(),
                Actor::Challenger,
                GOATMessageContent::OperatorAckTimeout(OperatorAckTimeout {
                    instance_id: graph.instance_id,
                    graph_id: graph.graph_id,
                }),
                0,
                0,
            )
            .await?;
        }
    }
    if is_challenge_timeout {
        // Re-sends an WatchtowerChallengeTimeout message whenever the watchtower indexes change.
        let watchtower_indexes: Vec<usize> = vout_monitor_data
            .data_map
            .iter()
            .filter_map(|(&index, status)| match status {
                WatchtowerChallengeItemStatus::OperatorInit => Some(index as usize),
                _ => None,
            })
            .collect();
        if !watchtower_indexes.is_empty() {
            let sub_type = format!(
                "[{}]",
                watchtower_indexes.iter().map(|v| v.to_string()).collect::<Vec<String>>().join("_")
            );
            upsert_message(
                &mut local_db.acquire().await?,
                false,
                graph.graph_id,
                Some(sub_type),
                SELF_SENDER.to_string(),
                Actor::Operator,
                GOATMessageContent::WatchtowerChallengeTimeout(WatchtowerChallengeTimeout {
                    instance_id: graph.instance_id,
                    graph_id: graph.graph_id,
                    watchtower_indexes,
                }),
                0,
                0,
            )
            .await?;
        }
    }
    Ok(false)
}

/// Process assert commit monitoring
/// may trigger: DisproveSent(AssertTimeout), AssertCommitTimeout
/// return Ok(true) if assert commit is success
async fn process_assert_commit_monitoring(
    btc_client: &BTCClient,
    local_db: &LocalDB,
    graph: &Graph,
    _sub_status: &mut ChallengeSubStatus,
    current_height: i64,
) -> anyhow::Result<bool> {
    let (mut vout_monitor_data, assert_init_height, _monitor_result) =
        match refresh_assert_monitor_data(local_db, btc_client, graph).await? {
            Some((data, init_height, monitor_result)) => (data, init_height, monitor_result),
            None => {
                warn!(
                    "graph_id {} fail to get vout monitor data, maybe assert-init-tx not confirmed yet",
                    graph.graph_id
                );
                return Ok(false);
            }
        };

    let timelock_config = get_challenge_timelock_config();
    let is_assert_commit_timeout =
        assert_init_height + timelock_config.assert_commit_timelock < current_height;
    info!(
        "process_assert_commit_monitoring: graph id :{} is_assert_commit_timeout:{is_assert_commit_timeout},\
        assert_init_height:{assert_init_height}, timelock_config.assert_commit_timelock:{}, current_height:{current_height}",
        graph.graph_id, timelock_config.assert_commit_timelock
    );
    if vout_monitor_data.is_assert_success() {
        info!("graph_id {} assert commit is success", graph.graph_id);
        return Ok(true);
    }
    if vout_monitor_data.is_disproved() {
        let challenge_start_txid = graph.challenge_txid.clone().map(|v| v.into());
        let disprove_type = DisproveTxType::AssertTimeout;
        let index = vout_monitor_data
            .data_map
            .iter()
            .find(|(_, status)| **status == AssertCommitItemStatus::OperatorCommitTimeout)
            .map(|(&index, _)| index as usize)
            .ok_or_else(|| anyhow::anyhow!("graph_id {} assert vout monitor data is disproved but no OperatorCommitTimeout found", graph.graph_id))?;
        let challenge_finish_txid = graph.assert_commit_timeout_txids.get(index).cloned().ok_or_else(|| anyhow::anyhow!(
            "graph_id {} is disproved by OperatorCommitTimeout at index {} but assert_commit_timeout_txid is none",
            graph.graph_id,
            index
        ))?.into();
        upsert_message(
            &mut local_db.acquire().await?,
            false,
            graph.graph_id,
            None,
            SELF_SENDER.to_string(),
            Actor::Operator,
            GOATMessageContent::DisproveSent(DisproveSent {
                instance_id: graph.instance_id,
                graph_id: graph.graph_id,
                disprove_type,
                index,
                challenge_start_txid,
                challenge_finish_txid,
            }),
            0,
            0,
        )
        .await?;
        return Ok(false); // already disproved, no need to process further
    }
    if is_assert_commit_timeout {
        vout_monitor_data.update_disprove_indexes();
        if !vout_monitor_data.require_disproved_indexes.is_empty() {
            upsert_message(
                &mut local_db.acquire().await?,
                false,
                graph.graph_id,
                Some(vout_monitor_data.get_require_disproved_string()),
                SELF_SENDER.to_string(),
                Actor::Challenger,
                GOATMessageContent::AssertCommitTimeout(AssertCommitTimeout {
                    instance_id: graph.instance_id,
                    graph_id: graph.graph_id,
                }),
                0,
                0,
            )
            .await?;
        }
    }

    Ok(false)
}

/// may trigger: DisproveSent(QuickChallenge/ChallengeIncompleteKickoff)
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
            SELF_SENDER.to_string(),
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

/// Process graph data in Watchtower Assert Normal status
/// may trigger: Take2Ready, Take2Sent, DisproveSent(Disprove)
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
            Actor::All,
            GOATMessageContent::Take2Sent(Take2Sent {
                instance_id: graph.instance_id,
                graph_id: graph.graph_id,
            }),
        )))
    } else {
        let disprove_type = DisproveTxType::Disprove;
        let challenge_start_txid = graph.challenge_txid.clone().map(|v| v.into());
        Ok(Some((
            Actor::All,
            GOATMessageContent::DisproveSent(DisproveSent {
                instance_id: graph.instance_id,
                graph_id: graph.graph_id,
                disprove_type,
                index: 0,
                challenge_start_txid,
                challenge_finish_txid: spent_txid,
            }),
        )))
    }
}

/// may trigger: PreKickoffSent
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
                SELF_SENDER.to_string(),
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

pub(crate) async fn refresh_watchtower_challenge_monitor_data(
    local_db: &LocalDB,
    btc_client: &BTCClient,
    graph: &Graph,
) -> anyhow::Result<
    Option<(
        WTInitTxVoutMonitorData,
        i64,
        (Vec<(usize, Txid)>, Vec<(usize, Txid)>, Vec<(usize, Txid)>),
    )>,
> {
    let watchtower_challenge_init_txid =
        graph.watchtower_challenge_init_txid.clone().ok_or_else(|| {
            anyhow::anyhow!("graph_id:{} watchtower_challenge_init_txid is none", graph.graph_id)
        })?;
    let out_monitor = {
        let mut storage_processor = local_db.acquire().await?;
        storage_processor
            .find_graph_btc_tx_vout_monitor(&graph.graph_id, &watchtower_challenge_init_txid)
            .await?
    };

    let mut init_height;
    let mut monitor_meta_update: Option<(i64, i64)> = None;
    let mut existing_meta: Option<(String, i64)> = None;
    let mut vout_monitor_data = if let Some(out_monitor) = out_monitor {
        existing_meta = Some((out_monitor.tx_name.clone(), out_monitor.created_at));
        init_height = out_monitor.height;
        match parse_monitor_data::<WTInitTxVoutMonitorData>(&out_monitor.monitor_data) {
            Ok(vout_monitor_data) => vout_monitor_data,
            Err(err) => {
                warn!(
                    "graph_id:{} fail to parse watchtower monitor_data, rebuild default: {err}",
                    graph.graph_id
                );
                let mut new_height = out_monitor.height;
                let mut new_vout_len = out_monitor.vout_len;
                if new_height <= 0 || new_vout_len <= 0 {
                    let txid: Txid = watchtower_challenge_init_txid.clone().into();
                    if let Some(tx) = btc_client.get_tx_info(&txid).await? {
                        if new_height <= 0 {
                            new_height = tx.status.block_height.unwrap_or_default() as i64;
                        }
                        if new_vout_len <= 0 {
                            new_vout_len = tx.vout.len() as i64;
                        }
                    }
                }
                init_height = new_height;
                let index_size = (new_vout_len as i32 - CONNECTOR_G_MARGIN as i32) / 2;
                if index_size <= 0 {
                    warn!(
                        "graph_id:{} watchtower_challenge_init_txid {} invalid index_size {index_size}, skip refresh",
                        graph.graph_id, watchtower_challenge_init_txid.0
                    );
                    return Ok(None);
                }
                if new_height != out_monitor.height || new_vout_len != out_monitor.vout_len {
                    monitor_meta_update = Some((new_height, new_vout_len));
                }
                WTInitTxVoutMonitorData::new(index_size)
            }
        }
    } else {
        let txid: Txid = watchtower_challenge_init_txid.clone().into();
        let watchtower_challenge_init_tx = match btc_client
            .get_tx_info(&txid)
            .await?
            .filter(|tx| tx.status.block_height.unwrap_or_default() > 0)
        {
            Some(tx) => tx,
            None => {
                warn!(
                    "graph_id:{} watchtower_challenge_init_txid not on chain, skip refresh",
                    graph.graph_id
                );
                return Ok(None);
            }
        };

        init_height = watchtower_challenge_init_tx.status.block_height.unwrap_or_default() as i64;
        let vout_monitor_data = WTInitTxVoutMonitorData::new(
            (watchtower_challenge_init_tx.vout.len() as i32 - CONNECTOR_G_MARGIN as i32) / 2,
        );

        let current_times = current_time_secs();
        let mut tx = local_db.start_transaction().await?;
        tx.upsert_graph_btc_tx_vout_monitor(&GraphBtcTxVoutMonitor {
            graph_id: graph.graph_id,
            tx_name: MONITE_BTC_TX_NAME_WATCHTOWER_INIT.to_string(),
            txid: watchtower_challenge_init_txid.clone(),
            height: watchtower_challenge_init_tx.status.block_height.unwrap_or_default() as i64,
            vout_len: watchtower_challenge_init_tx.vout.len() as i64,
            monitor_data: serde_json::to_string(&vout_monitor_data)?,
            created_at: current_times,
            updated_at: current_times,
        })
        .await?;
        tx.commit().await?;

        vout_monitor_data
    };

    if init_height <= 0 {
        warn!(
            "graph_id:{} watchtower_challenge_init_txid {} height is not confirmed, skip refresh",
            graph.graph_id, watchtower_challenge_init_txid.0
        );
        return Ok(None);
    }
    let block_hash_commit_timeout_txid =
        graph.blockhash_commit_timeout_txid.clone().ok_or_else(|| {
            anyhow::anyhow!("graph_id:{} blockhash_commit_timeout_txid is empty", graph.graph_id)
        })?;
    let monitor_result = vout_monitor_data
        .monitor_vout(
            btc_client,
            &watchtower_challenge_init_txid.clone().into(),
            &graph.watchtower_challenge_timeout_txids,
            &graph.nack_txids,
            &block_hash_commit_timeout_txid,
        )
        .await?;
    let mut tx = local_db.start_transaction().await?;
    if let (Some((height, vout_len)), Some((tx_name, created_at))) =
        (monitor_meta_update, existing_meta)
    {
        tx.upsert_graph_btc_tx_vout_monitor(&GraphBtcTxVoutMonitor {
            graph_id: graph.graph_id,
            tx_name,
            txid: watchtower_challenge_init_txid.clone(),
            height,
            vout_len,
            monitor_data: serde_json::to_string(&vout_monitor_data)?,
            created_at,
            updated_at: current_time_secs(),
        })
        .await?;
    } else {
        tx.update_graph_btc_tx_vout_monitor_data(
            &graph.graph_id,
            &watchtower_challenge_init_txid,
            serde_json::to_string(&vout_monitor_data)?,
        )
        .await?;
    }
    // Always insert WatchtowerChallengeInitSent to avoid missing; repeated inserts are idempotent
    upsert_message(
        &mut tx,
        false,
        graph.graph_id,
        None,
        SELF_SENDER.to_string(),
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

    Ok(Some((vout_monitor_data, init_height, monitor_result)))
}

pub(crate) async fn refresh_assert_monitor_data(
    local_db: &LocalDB,
    btc_client: &BTCClient,
    graph: &Graph,
) -> anyhow::Result<Option<(AssertInitTxVoutMonitorData, i64, i32)>> {
    let assert_init_txid = graph
        .assert_init_txid
        .clone()
        .ok_or_else(|| anyhow::anyhow!("graph_id:{} assert_init_txid is none", graph.graph_id))?;
    let out_monitor = {
        let mut storage_processor = local_db.acquire().await?;
        storage_processor.find_graph_btc_tx_vout_monitor(&graph.graph_id, &assert_init_txid).await?
    };

    let mut init_height;
    let mut monitor_meta_update: Option<(i64, i64)> = None;
    let mut existing_meta: Option<(String, i64)> = None;
    let mut vout_monitor_data = if let Some(out_monitor) = out_monitor {
        existing_meta = Some((out_monitor.tx_name.clone(), out_monitor.created_at));
        init_height = out_monitor.height;
        match parse_monitor_data::<AssertInitTxVoutMonitorData>(&out_monitor.monitor_data) {
            Ok(vout_monitor_data) => vout_monitor_data,
            Err(err) => {
                warn!(
                    "graph_id:{} fail to parse assert monitor_data, rebuild default: {err}",
                    graph.graph_id
                );
                let mut new_height = out_monitor.height;
                let mut new_vout_len = out_monitor.vout_len;
                if new_height <= 0 || new_vout_len <= 0 {
                    let txid: Txid = assert_init_txid.clone().into();
                    if let Some(tx) = btc_client.get_tx_info(&txid).await? {
                        if new_height <= 0 {
                            new_height = tx.status.block_height.unwrap_or_default() as i64;
                        }
                        if new_vout_len <= 0 {
                            new_vout_len = tx.vout.len() as i64;
                        }
                    }
                }
                init_height = new_height;
                let index_size = new_vout_len as i32 - 2;
                if index_size <= 0 {
                    warn!(
                        "graph_id:{} assert_init_txid {} invalid index_size {index_size}, skip refresh",
                        graph.graph_id, assert_init_txid.0
                    );
                    return Ok(None);
                }
                if new_height != out_monitor.height || new_vout_len != out_monitor.vout_len {
                    monitor_meta_update = Some((new_height, new_vout_len));
                }
                AssertInitTxVoutMonitorData::new(index_size)
            }
        }
    } else {
        let txid: Txid = assert_init_txid.clone().into();
        let assert_init_tx = match btc_client
            .get_tx_info(&txid)
            .await?
            .filter(|tx| tx.status.block_height.unwrap_or_default() > 0)
        {
            Some(tx) => tx,
            None => {
                warn!("graph_id:{} assert_init_txid not on chain, skip refresh", graph.graph_id);
                return Ok(None);
            }
        };

        init_height = assert_init_tx.status.block_height.unwrap_or_default() as i64;
        let vout_monitor_data =
            AssertInitTxVoutMonitorData::new(assert_init_tx.vout.len() as i32 - 2);
        let current_times = current_time_secs();
        let mut tx = local_db.start_transaction().await?;
        tx.upsert_graph_btc_tx_vout_monitor(&GraphBtcTxVoutMonitor {
            graph_id: graph.graph_id,
            tx_name: MONITE_BTC_TX_NAME_ASSERT_INIT.to_string(),
            txid: assert_init_txid.clone(),
            height: assert_init_tx.status.block_height.unwrap_or_default() as i64,
            vout_len: assert_init_tx.vout.len() as i64,
            monitor_data: serde_json::to_string(&vout_monitor_data)?,
            created_at: current_times,
            updated_at: current_times,
        })
        .await?;
        tx.commit().await?;

        vout_monitor_data
    };

    if init_height <= 0 {
        warn!(
            "graph_id:{} assert_init_txid {} height is not confirmed, skip refresh",
            graph.graph_id, assert_init_txid.0
        );
        return Ok(None);
    }
    let monitor_result = vout_monitor_data
        .monitor_vout(
            btc_client,
            &assert_init_txid.clone().into(),
            &graph.assert_commit_timeout_txids,
        )
        .await?;
    let mut tx = local_db.start_transaction().await?;
    if let (Some((height, vout_len)), Some((tx_name, created_at))) =
        (monitor_meta_update, existing_meta)
    {
        tx.upsert_graph_btc_tx_vout_monitor(&GraphBtcTxVoutMonitor {
            graph_id: graph.graph_id,
            tx_name,
            txid: assert_init_txid.clone(),
            height,
            vout_len,
            monitor_data: serde_json::to_string(&vout_monitor_data)?,
            created_at,
            updated_at: current_time_secs(),
        })
        .await?;
    } else {
        tx.update_graph_btc_tx_vout_monitor_data(
            &graph.graph_id,
            &assert_init_txid,
            serde_json::to_string(&vout_monitor_data)?,
        )
        .await?;
    }
    tx.commit().await?;

    Ok(Some((vout_monitor_data, init_height, monitor_result)))
}
