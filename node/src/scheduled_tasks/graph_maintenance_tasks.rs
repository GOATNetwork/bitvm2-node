use crate::action::{
    AssertSent, ChallengeSent, DisproveSent, GOATMessage, GOATMessageContent, KickoffReady,
    KickoffSent, Take1Ready, Take2Ready, send_to_peer,
};
use crate::client::btc_chain::BTCClient;
use crate::client::goat_chain::{GOATClient, WithdrawStatus};
use crate::env::{MESSAGE_BROADCAST_MAX_TIMES, MESSAGE_RESEND_INTERVAL_SECOND, get_network};
use crate::middleware::AllBehaviours;
use crate::utils::{
    create_goat_tx_record, finish_withdraw_disproved, get_graph, obsolete_sibling_graphs,
    outpoint_spent_txid, tx_on_chain, update_graph_fields,
};
use bitcoin::Txid;
use bitcoin::consensus::encode::{deserialize_hex, serialize_hex};
use bitcoin::hashes::Hash;
use bitvm2_lib::actors::Actor;
use goat::constants::{CONNECTOR_3_TIMELOCK, CONNECTOR_4_TIMELOCK};
use goat::transactions::assert::utils::COMMIT_TX_NUM;
use goat::utils::num_blocks_per_network;
use libp2p::Swarm;
use std::time::{SystemTime, UNIX_EPOCH};
use store::localdb::LocalDB;
use store::{
    GoatTxProcessingStatus, GoatTxType, GraphStatus, GraphTickActionMetaData, MessageType,
};
use tracing::{info, warn};
use uuid::Uuid;

#[derive(Clone, Debug)]
pub struct GraphTickActionData {
    pub instance_id: Uuid,
    pub graph_id: Uuid,
    pub graph_status: String,
    pub msg_times: i64,
    #[allow(dead_code)]
    pub msg_type: String,
    pub kickoff_txid: Option<Txid>,
    pub take1_txid: Option<Txid>,
    pub take2_txid: Option<Txid>,
    pub assert_init_txid: Option<Txid>,
    pub assert_commit_txids: Option<[Txid; COMMIT_TX_NUM]>,
    pub assert_final_txid: Option<Txid>,
    pub challenge_txid: Option<Txid>,
    pub last_msg_send_at: i64,
}

impl From<GraphTickActionMetaData> for GraphTickActionData {
    fn from(value: GraphTickActionMetaData) -> Self {
        let tx_convert = |v: Option<String>| -> Option<Txid> {
            match v {
                None => None,
                Some(v) => deserialize_hex(&v).ok(),
            }
        };
        let assert_commit_txids = if let Some(tx_ids) = value.assert_commit_txids {
            match serde_json::from_str::<Vec<String>>(&tx_ids) {
                Err(_) => None,
                Ok(tx_id_strs) => {
                    let mut assert_commit_txids = [Txid::all_zeros(); COMMIT_TX_NUM];
                    for i in 0..COMMIT_TX_NUM {
                        let covert_res = deserialize_hex(&tx_id_strs[i]);
                        if covert_res.is_err() {
                            continue;
                        }
                        assert_commit_txids[i] = covert_res.unwrap();
                    }
                    Some(assert_commit_txids)
                }
            }
        } else {
            None
        };

        Self {
            instance_id: value.instance_id,
            graph_id: value.graph_id,
            graph_status: value.status,
            msg_times: value.msg_times,
            msg_type: value.msg_type,
            kickoff_txid: tx_convert(value.kickoff_txid),
            take1_txid: tx_convert(value.take1_txid),
            take2_txid: tx_convert(value.take2_txid),
            assert_init_txid: tx_convert(value.assert_init_txid),
            assert_commit_txids,
            assert_final_txid: tx_convert(value.assert_final_txid),
            challenge_txid: tx_convert(value.challenge_txid),
            last_msg_send_at: value.last_msg_send_at,
        }
    }
}

fn is_need_to_send_msg(pre_send_times: i64, last_send_at: i64) -> bool {
    // if msg never been sent, last_send_at value is 0
    let current_time = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64;
    (pre_send_times % MESSAGE_BROADCAST_MAX_TIMES != 0)
        || (current_time - last_send_at) > MESSAGE_RESEND_INTERVAL_SECOND
}
async fn get_relayer_caring_graph_data(
    local_db: &LocalDB,
    status: GraphStatus,
    msg_type: String,
) -> Result<Vec<GraphTickActionData>, Box<dyn std::error::Error>> {
    // If instance corresponding to the graph has already been consumed, the graph is excluded.
    // When a graph enters the take1/take2 status, mark its corresponding instance as consumed.
    let mut storage_process = local_db.acquire().await?;
    let meta_data =
        storage_process.get_graph_tick_action_datas(status.to_string().as_str(), &msg_type).await?;
    Ok(meta_data.into_iter().map(|v| v.into()).collect())
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
    Ok(goat_client.get_initialized_ids().await?)
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
            let kickoff_txid: Option<Txid> = deserialize_hex(&graph.kickoff_txid.unwrap()).ok();
            if kickoff_txid.is_none() {
                warn!("{instance_id} kickoff txid decode ressult is None");
                continue;
            }
            if tx_on_chain(btc_client, &kickoff_txid.unwrap()).await? {
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
    let mut graph_datas = get_relayer_caring_graph_data(
        local_db,
        GraphStatus::OperatorDataPushed,
        MessageType::KickoffSent.to_string(),
    )
    .await?;
    let mut graph_datas_kickoff = get_relayer_caring_graph_data(
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
        let kickoff_txid = graph_data.kickoff_txid.unwrap();
        if graph_data.graph_status == GraphStatus::OperatorDataPushed.to_string() {
            if !tx_on_chain(btc_client, &kickoff_txid).await? {
                warn!(
                    "graph_id:{} kickoff:{:?} is not onchain ",
                    graph_data.graph_id, kickoff_txid
                );
                continue;
            }
            let withdraw_data = goat_client.get_withdraw_data(&graph_id).await?;
            if withdraw_data.status != WithdrawStatus::Initialized {
                info!("scan_kickoff {graph_id}, kickoff:{kickoff_txid} in evil way");
                send_message = true;
            } else {
                let kickoff_tx = btc_client.fetch_btc_tx(&kickoff_txid).await?;
                match goat_client
                    .process_withdraw(btc_client, &graph_data.graph_id, &kickoff_tx)
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
        } else if graph_data.graph_status == GraphStatus::KickOff.to_string() {
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
    swarm: &mut Swarm<AllBehaviours>,
    local_db: &LocalDB,
    btc_client: &BTCClient,
) -> Result<(), Box<dyn std::error::Error>> {
    info!("start tick action: scan_assert");
    let mut graphs = get_relayer_caring_graph_data(
        local_db,
        GraphStatus::Challenge,
        MessageType::AssertSent.to_string(),
    )
    .await?;
    let mut graphs_kickoff = get_relayer_caring_graph_data(
        local_db,
        GraphStatus::KickOff,
        MessageType::AssertSent.to_string(),
    )
    .await?; // in case challenger never broadcast ChallengeSent
    let mut graphs_assert_sent = get_relayer_caring_graph_data(
        local_db,
        GraphStatus::Assert,
        MessageType::AssertSent.to_string(),
    )
    .await?;
    graphs.append(&mut graphs_kickoff);
    graphs.append(&mut graphs_assert_sent);
    info!("scan_assert get graph datas size: {}", graphs.len());
    for graph_data in graphs {
        let instance_id = graph_data.instance_id;
        let graph_id = graph_data.graph_id;
        if graph_data.assert_init_txid.is_none()
            | graph_data.assert_final_txid.is_none()
            | graph_data.assert_commit_txids.is_none()
        {
            warn!(
                "{graph_id} has none field about assert txs,detail: assert_init_txid:{:?}, assert_commit_txids:{:?}, assert_final_txid:{:?}",
                graph_data.assert_init_txid,
                graph_data.assert_commit_txids,
                graph_data.assert_final_txid
            );
            continue;
        }
        // check graph assert final tx is on chain
        let assert_final_txid = graph_data.assert_final_txid.unwrap();
        if graph_data.graph_status != GraphStatus::Assert.to_string() {
            if !tx_on_chain(btc_client, &assert_final_txid).await? {
                warn!(
                    "{graph_id}, assert_final_txid:{:?} not on chain",
                    graph_data.assert_final_txid
                );
                continue;
            }

            update_graph_fields(
                local_db,
                graph_data.graph_id,
                Some(GraphStatus::Assert.to_string()),
                None,
                None,
                None,
                None,
            )
            .await?
        }

        // check assert final tx output is been spent.  refer graph in new status: take2/disproved
        if outpoint_spent_txid(btc_client, &assert_final_txid, 1).await?.is_some() {
            tracing::trace!(
                "{graph_id} assert_final_txid {assert_final_txid} output has been spend, no need to send AssertSent message"
            );
            continue;
        }

        if is_need_to_send_msg(graph_data.msg_times, graph_data.last_msg_send_at) {
            let message_content = GOATMessageContent::AssertSent(AssertSent {
                instance_id,
                graph_id,
                assert_init_txid: graph_data.assert_init_txid.unwrap(),
                assert_commit_txids: graph_data.assert_commit_txids.unwrap(),
                assert_final_txid: graph_data.assert_final_txid.unwrap(),
            });
            send_to_peer(swarm, GOATMessage::from_typed(Actor::All, &message_content)?)?;
            add_message_broadcast_times(
                local_db,
                &graph_data.instance_id,
                &graph_data.graph_id,
                &MessageType::AssertSent.to_string(),
                1,
            )
            .await?;
        }
    }
    Ok(())
}

//Tick-Task-4
pub async fn scan_take1(
    swarm: &mut Swarm<AllBehaviours>,
    local_db: &LocalDB,
    btc_client: &BTCClient,
    goat_client: &GOATClient,
) -> Result<(), Box<dyn std::error::Error>> {
    info!("start tick action: scan_take1");
    let mut graph_datas = get_relayer_caring_graph_data(
        local_db,
        GraphStatus::KickOff,
        MessageType::Take1Ready.to_string(),
    )
    .await?;

    let mut graph_datas_challenge = get_relayer_caring_graph_data(
        local_db,
        GraphStatus::Challenge,
        MessageType::ChallengeSent.to_string(),
    )
    .await?;
    graph_datas.append(&mut graph_datas_challenge);
    let current_height = btc_client.get_height().await?;
    let lock_blocks = num_blocks_per_network(get_network(), CONNECTOR_3_TIMELOCK);
    info!("scan_take1 get graph datas size: {}", graph_datas.len());
    for graph_data in graph_datas {
        let instance_id = graph_data.instance_id;
        let graph_id = graph_data.graph_id;
        if graph_data.graph_status == GraphStatus::Challenge.to_string() {
            // handle graph status is challenge
            if graph_data.challenge_txid.is_none() {
                warn!(
                    "graph_id:{graph_id} status is Challenge, but challenge tx is decode failed, fix me"
                );
                continue;
            }
            let challenge_txid = graph_data.challenge_txid.unwrap();
            info!("graph_id:{graph_id},  challenge sent, txid: {challenge_txid}");
            if is_need_to_send_msg(graph_data.msg_times, graph_data.last_msg_send_at) {
                let message_content = GOATMessageContent::ChallengeSent(ChallengeSent {
                    instance_id,
                    graph_id,
                    challenge_txid,
                });
                send_to_peer(swarm, GOATMessage::from_typed(Actor::Operator, &message_content)?)?;
                add_message_broadcast_times(
                    local_db,
                    &instance_id,
                    &graph_id,
                    &MessageType::ChallengeSent.to_string(),
                    1,
                )
                .await?;
            }
            continue;
        }
        // handle graph status is kickoff
        if graph_data.take1_txid.is_none() {
            warn!("graph_id:{}, take1 txid is none", graph_id);
            continue;
        }
        if graph_data.kickoff_txid.is_none() {
            warn!("graph_id:{}, kickoff txid is none", graph_data.graph_id);
            continue;
        }
        let take1_txid = graph_data.take1_txid.unwrap();
        let kickoff_txid = graph_data.kickoff_txid.unwrap();
        if let Some(spent_txid) = outpoint_spent_txid(btc_client, &kickoff_txid, 1).await? {
            if spent_txid == take1_txid {
                // take1 sent, try to call finish_withdraw_happy_path
                info!("graph_id:{},  take-1 sent, txid: {spent_txid}", graph_data.graph_id);
                let take1_tx = btc_client.fetch_btc_tx(&take1_txid).await?;
                match goat_client.finish_withdraw_happy_path(btc_client, &graph_id, &take1_tx).await
                {
                    Err(err) => {
                        // call finish_withdraw_happy_path later
                        warn!(
                            "scan_take1 at graph:{}, finish_withdraw_happy_path err:{:?}",
                            graph_id, err
                        );
                    }
                    Ok(tx_hash) => {
                        info!(
                            "instance_id: {}, graph_id:{} take1 finish send, tx hash :{}",
                            instance_id, graph_id, tx_hash
                        );

                        create_goat_tx_record(
                            local_db,
                            goat_client,
                            graph_id,
                            instance_id,
                            &tx_hash,
                            GoatTxType::WithdrawHappyPath,
                            GoatTxProcessingStatus::Skipped.to_string(),
                        )
                        .await?;
                        update_graph_fields(
                            local_db,
                            graph_id,
                            Some(GraphStatus::Take1.to_string()),
                            None,
                            None,
                            None,
                            None,
                        )
                        .await?;
                        obsolete_sibling_graphs(local_db, instance_id, graph_id).await?;
                    }
                }
            } else {
                // challenge sent, broadcast ChallengeSent
                info!("graph_id:{},  challenge sent, txid: {spent_txid}", graph_data.graph_id);
                let message_content = GOATMessageContent::ChallengeSent(ChallengeSent {
                    instance_id,
                    graph_id,
                    challenge_txid: spent_txid,
                });
                send_to_peer(swarm, GOATMessage::from_typed(Actor::Operator, &message_content)?)?;
                add_message_broadcast_times(
                    local_db,
                    &instance_id,
                    &graph_id,
                    &MessageType::ChallengeSent.to_string(),
                    1,
                )
                .await?;
                // modify graph status and will no longer perform scan-take1 on this graph
                update_graph_fields(
                    local_db,
                    graph_id,
                    Some(GraphStatus::Challenge.to_string()),
                    None,
                    Some(serialize_hex(&spent_txid)),
                    None,
                    None,
                )
                .await?;
            }
            // if take-1/challenge already sent, no need for Take1Ready
            continue;
        } else {
            info!(
                "graph_id:{graph_id}, kickoff_txid: {kickoff_txid} output index 1 not been spent"
            );

            if is_need_to_send_msg(graph_data.msg_times, graph_data.last_msg_send_at) {
                // check if kickoff's timelock for take1 is expired
                if let Some(kickoff_height) =
                    btc_client.get_tx_status(&kickoff_txid).await?.block_height
                {
                    info!(
                        "graph_id:{graph_id}, kickoff_height:{kickoff_height}, lock_blocks:{lock_blocks}, current_height:{current_height}"
                    );
                    if kickoff_height + lock_blocks <= current_height {
                        let message_content =
                            GOATMessageContent::Take1Ready(Take1Ready { instance_id, graph_id });
                        send_to_peer(
                            swarm,
                            GOATMessage::from_typed(Actor::Operator, &message_content)?,
                        )?;
                        add_message_broadcast_times(
                            local_db,
                            &instance_id,
                            &graph_id,
                            &MessageType::Take1Ready.to_string(),
                            1,
                        )
                        .await?;
                        info!(
                            "finish send take1 ready for instance_id:{instance_id}, graph_id:{graph_id}"
                        );
                    }
                } else {
                    info!(
                        "graph_id:{},  kickoff_txid{}  not no chain",
                        graph_data.graph_id,
                        graph_data.kickoff_txid.unwrap().to_string()
                    )
                }
            }
        }
    }
    Ok(())
}

//Tick-Task-5:
pub async fn scan_take2(
    swarm: &mut Swarm<AllBehaviours>,
    local_db: &LocalDB,
    btc_client: &BTCClient,
    goat_client: &GOATClient,
) -> Result<(), Box<dyn std::error::Error>> {
    info!("start tick action: scan_take2");
    let graph_datas = get_relayer_caring_graph_data(
        local_db,
        GraphStatus::Assert,
        MessageType::Take2Ready.to_string(),
    )
    .await?;
    let current_height = btc_client.get_height().await?;
    let lock_blocks = num_blocks_per_network(get_network(), CONNECTOR_4_TIMELOCK);

    info!("scan_take2 get graph datas size: {}", graph_datas.len());
    for graph_data in graph_datas {
        let instance_id = graph_data.instance_id;
        let graph_id = graph_data.graph_id;
        if graph_data.take2_txid.is_none() {
            warn!("graph_id:{}, take2 txid is none", graph_id);
            continue;
        }
        if graph_data.assert_final_txid.is_none() {
            warn!("graph_id:{graph_id}, assert_final txid  is none");
            continue;
        }
        let take2_txid = graph_data.take2_txid.unwrap();
        let assert_final_txid = graph_data.assert_final_txid.unwrap();
        let kickoff_txid = graph_data.kickoff_txid.unwrap();
        if let Some(spent_txid) = outpoint_spent_txid(btc_client, &assert_final_txid, 1).await? {
            if spent_txid == take2_txid {
                // take2 sent, try to call finish_withdraw_unhappy_path
                info!("graph_id:{},  take-2 sent, txid: {spent_txid}", graph_data.graph_id);
                let take2_tx = btc_client.fetch_btc_tx(&take2_txid).await?;
                match goat_client
                    .finish_withdraw_unhappy_path(btc_client, &graph_id, &take2_tx)
                    .await
                {
                    Err(err) => {
                        // wiil call finish_unwithdraw_happy_path later
                        warn!(
                            "scan_take2 at graph:{}, finish_withdraw_unhappy_path err:{:?}",
                            graph_data.graph_id, err
                        );
                    }
                    Ok(tx_hash) => {
                        info!(
                            "instance_id: {}, graph_id:{}  finish take2, tx hash :{}",
                            instance_id, graph_id, tx_hash
                        );
                        create_goat_tx_record(
                            local_db,
                            goat_client,
                            graph_id,
                            instance_id,
                            &tx_hash,
                            GoatTxType::WithdrawUnhappyPath,
                            GoatTxProcessingStatus::Skipped.to_string(),
                        )
                        .await?;
                        update_graph_fields(
                            local_db,
                            graph_data.graph_id,
                            Some(GraphStatus::Take2.to_string()),
                            None,
                            None,
                            None,
                            None,
                        )
                        .await?;
                        obsolete_sibling_graphs(local_db, instance_id, graph_id).await?;
                    }
                }
            } else {
                // disprove sent, try to call finish_withdraw_disprove & broadcasr DisproveSent
                info!("graph_id:{},  disprove sent, txid: {spent_txid}", graph_data.graph_id);
                let disprove_txid = spent_txid;
                update_graph_fields(
                    local_db,
                    graph_id,
                    None,
                    None,
                    None,
                    Some(serialize_hex(&spent_txid)),
                    None,
                )
                .await?;

                let challenge_txid = if graph_data.challenge_txid.is_none() {
                    if let Some(spent_txid) =
                        outpoint_spent_txid(btc_client, &kickoff_txid, 1).await?
                        && spent_txid != graph_data.take1_txid.unwrap()
                    {
                        spent_txid
                    } else {
                        warn!(
                            "graph:{} challenge tx_id is none, can not start withdraw disproved, fix me",
                            graph_data.graph_id
                        );
                        continue;
                    }
                } else {
                    graph_data.challenge_txid.unwrap()
                };

                let tx_hash = finish_withdraw_disproved(
                    btc_client,
                    goat_client,
                    &graph_id,
                    &btc_client.fetch_btc_tx(&disprove_txid).await?,
                    &btc_client.fetch_btc_tx(&challenge_txid).await?,
                )
                .await?;

                create_goat_tx_record(
                    local_db,
                    goat_client,
                    graph_id,
                    instance_id,
                    &tx_hash,
                    GoatTxType::WithdrawDisproved,
                    GoatTxProcessingStatus::Skipped.to_string(),
                )
                .await?;
                // in case challenger never broadcast DisproveSent
                let message_content = GOATMessageContent::DisproveSent(DisproveSent {
                    instance_id,
                    graph_id,
                    disprove_txid: spent_txid,
                });
                send_to_peer(swarm, GOATMessage::from_typed(Actor::Operator, &message_content)?)?;
                add_message_broadcast_times(
                    local_db,
                    &instance_id,
                    &graph_id,
                    &MessageType::DisproveSent.to_string(),
                    1,
                )
                .await?;
                update_graph_fields(
                    local_db,
                    graph_id,
                    Some(GraphStatus::Disprove.to_string()),
                    None,
                    None,
                    None,
                    None,
                )
                .await?;
            }
            // if take-2/disprove already sent, no need for Take2Ready
            continue;
        } else {
            info!(
                "graph_id:{graph_id}, assert_final_txid: {assert_final_txid} output index 1 not been spent"
            );

            if is_need_to_send_msg(graph_data.msg_times, graph_data.last_msg_send_at) {
                // check if assert_final's timelock for take2 is expired
                if let Some(asset_final_height) =
                    btc_client.get_tx_status(&assert_final_txid).await?.block_height
                {
                    info!(
                        "graph_id:{graph_id}, asset_final_height:{asset_final_height}, lock_blocks:{lock_blocks}, current_height:{current_height}"
                    );
                    if asset_final_height + lock_blocks <= current_height {
                        let message_content =
                            GOATMessageContent::Take2Ready(Take2Ready { instance_id, graph_id });
                        send_to_peer(
                            swarm,
                            GOATMessage::from_typed(Actor::Operator, &message_content)?,
                        )?;
                        add_message_broadcast_times(
                            local_db,
                            &instance_id,
                            &graph_id,
                            &MessageType::Take2Ready.to_string(),
                            1,
                        )
                        .await?;
                        info!(
                            "finish send take2 ready for instance_id:{instance_id}, graph_id:{graph_id}"
                        );
                    }
                } else {
                    info!(
                        "graph_id:{},  assert_final_txid{}  not no chain",
                        graph_data.graph_id,
                        graph_data.assert_final_txid.unwrap().to_string()
                    )
                }
            }
        }
    }
    Ok(())
}
