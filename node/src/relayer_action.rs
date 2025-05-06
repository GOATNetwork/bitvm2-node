#![allow(dead_code)]

use crate::action::CreateInstance;
use crate::env::{MESSAGE_BROADCAST_MAX_TIMES, MESSAGE_EXPIRE_TIME};
use crate::rpc_service::P2pUserData;
use crate::utils::update_graph_fields;
use crate::{
    action::{
        AssertSent, GOATMessage, GOATMessageContent, KickoffReady, KickoffSent, Take1Ready,
        Take2Ready, send_to_peer,
    },
    env::get_network,
    middleware::AllBehaviours,
    utils::tx_on_chain,
};
use alloy::primitives::TxHash;
use bitcoin::Txid;
use bitcoin::consensus::encode::deserialize_hex;
use bitcoin::hashes::Hash;
use bitvm2_lib::actors::Actor;
use client::client::BitVM2Client;
use goat::transactions::assert::utils::COMMIT_TX_NUM;
use goat::{
    constants::{CONNECTOR_3_TIMELOCK, CONNECTOR_4_TIMELOCK},
    utils::num_blocks_per_network,
};
use libp2p::Swarm;
use std::str::FromStr;
use std::time::UNIX_EPOCH;
use store::{
    BridgeInStatus, BridgePath, GraphStatus, GraphTickActionMetaData, MessageState, MessageType,
};
use tracing::{info, warn};
use uuid::Uuid;

#[derive(Clone, Debug)]
pub struct GraphTickActionData {
    pub instance_id: Uuid,
    pub graph_id: Uuid,
    pub msg_times: i64,
    pub msg_type: String,
    pub kickoff_txid: Option<Txid>,
    pub take1_txid: Option<Txid>,
    pub take2_txid: Option<Txid>,
    pub assert_init_txid: Option<Txid>,
    pub assert_commit_txids: Option<[Txid; COMMIT_TX_NUM]>,
    pub assert_final_txid: Option<Txid>,
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
            msg_times: value.msg_times,
            msg_type: value.msg_type,
            kickoff_txid: tx_convert(value.kickoff_txid),
            take1_txid: tx_convert(value.take1_txid),
            take2_txid: tx_convert(value.take2_txid),
            assert_init_txid: tx_convert(value.assert_init_txid),
            assert_commit_txids,
            assert_final_txid: tx_convert(value.assert_final_txid),
        }
    }
}

pub async fn get_relayer_caring_graph_data(
    client: &BitVM2Client,
    status: GraphStatus,
    msg_type: String,
) -> Result<Vec<GraphTickActionData>, Box<dyn std::error::Error>> {
    // If instance corresponding to the graph has already been consumed, the graph is excluded.
    // When a graph enters the take1/take2 status, mark its corresponding instance as consumed.
    let mut storage_process = client.local_db.acquire().await?;
    let meta_data =
        storage_process.get_graph_tick_action_datas(status.to_string().as_str(), &msg_type).await?;
    Ok(meta_data.into_iter().map(|v| v.into()).collect())
}

pub async fn get_message_broadcast_times(
    client: &BitVM2Client,
    instance_id: &Uuid,
    graph_id: &Uuid,
    msg_type: &str,
) -> Result<i64, Box<dyn std::error::Error>> {
    let mut storage_process = client.local_db.acquire().await?;
    Ok(storage_process.get_message_broadcast_times(instance_id, graph_id, msg_type).await?)
}

pub async fn update_message_broadcast_times(
    client: &BitVM2Client,
    instance_id: &Uuid,
    graph_id: &Uuid,
    msg_type: &str,
    msg_times: i64,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut storage_process = client.local_db.acquire().await?;
    Ok(storage_process
        .update_message_broadcast_times(instance_id, graph_id, msg_type, msg_times)
        .await?)
}

pub async fn get_initialized_graphs(
    client: &BitVM2Client,
) -> Result<Vec<(Uuid, Uuid)>, Box<dyn std::error::Error>> {
    // call L2 contract : getInitializedInstanceIds
    // returns Vec<(instance_id, graph_id)>
    Ok(client.get_initialized_ids().await?)
}

pub async fn scan_bridge_in_prepare(
    swarm: &mut Swarm<AllBehaviours>,
    client: &BitVM2Client,
) -> Result<(), Box<dyn std::error::Error>> {
    info!("start tick scan_bridge_in_prepare");
    let mut storage_process = client.local_db.acquire().await?;
    let current_time =
        std::time::SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64;
    let messages = storage_process
        .filter_messages(
            MessageType::BridgeInData.to_string(),
            MessageState::Pending.to_string(),
            current_time - MESSAGE_EXPIRE_TIME,
        )
        .await?;

    let mut ids = vec![];
    info!("messages size :{}", messages.len());

    for message in messages {
        let p2p_data: P2pUserData = serde_json::from_slice(&message.content)?;
        let message_content = GOATMessageContent::CreateInstance(CreateInstance {
            instance_id: p2p_data.instance_id,
            network: p2p_data.network,
            depositor_evm_address: p2p_data.depositor_evm_address,
            pegin_amount: p2p_data.pegin_amount,
            user_inputs: p2p_data.user_inputs,
        });
        send_to_peer(swarm, GOATMessage::from_typed(Actor::Committee, &message_content)?)?;
        ids.push(message.id)
    }
    info!("send msg:{:?} for create instances", ids);
    storage_process
        .update_messages_state(&ids, MessageState::Processed.to_string(), current_time)
        .await?;
    // storage_process.set_messages_expired(current_time - MESSAGE_EXPIRE_TIME).await?;//TODO
    Ok(())
}

pub async fn scan_l1_broadcast_txs(
    _swarm: &mut Swarm<AllBehaviours>,
    client: &BitVM2Client,
) -> Result<(), Box<dyn std::error::Error>> {
    info!("Starting into scan_l1_broadcast_txs");
    let mut storage_process = client.local_db.acquire().await?;
    let (instances, _) = storage_process
        .instance_list(
            None,
            Some(BridgePath::BTCToPgBTC.to_u8()),
            Some(BridgeInStatus::Presigned.to_string()),
            None,
            None,
        )
        .await
        .unwrap();

    info!("Starting into scan_l1_broadcast_txs, need to check instance_size:{} ", instances.len());

    for instance in instances {
        if instance.pegin_txid.is_none() {
            warn!("instance:{}, pegin txid is none", instance.instance_id);
            continue;
        }
        let tx_id = deserialize_hex(instance.pegin_txid.unwrap().as_str())?;
        if tx_on_chain(client, &tx_id).await? {
            info!("scan_bridge_in: {} onchain ", tx_id.to_string());
            let update_res = storage_process
                .update_instance_fields(
                    &instance.instance_id,
                    Some(BridgeInStatus::L1Broadcasted.to_string()),
                    None,
                    None,
                )
                .await;
            if let Err(err) = update_res {
                warn!(
                    "instance {} update state to L1Broadcasted failed err:{:?} ,will try latter",
                    instance.instance_id, err
                );
                continue;
            }
        } else {
            info!("scan_l1_broadcast_txs: {} not onchain ", tx_id.to_string());
        }
    }
    Ok(())
}

pub async fn scan_bridge_in(
    _swarm: &mut Swarm<AllBehaviours>,
    client: &BitVM2Client,
) -> Result<(), Box<dyn std::error::Error>> {
    // scan bridge-in tx & relay to L2 contract: postPeginData & postOperatorData
    info!("Starting into scan_bridge_in");
    let mut storage_process = client.local_db.acquire().await?;
    let (instances, _) = storage_process
        .instance_list(
            None,
            Some(BridgePath::BTCToPgBTC.to_u8()),
            Some(BridgeInStatus::L1Broadcasted.to_string()),
            None,
            None,
        )
        .await
        .unwrap();

    info!("Starting into scan_bridge_in, need to send instance_size:{} ", instances.len());
    for instance in instances {
        if instance.pegin_txid.is_none() {
            warn!("instance:{}, pegin txid is none", instance.instance_id);
            continue;
        }
        let graphs = storage_process.get_graph_by_instance_id(&instance.instance_id).await?;
        if graphs.is_empty() {
            warn!("instance {}, status is presigned, but graph is none", instance.instance_id);
            continue;
        }
        if let Ok(tx_hash) = TxHash::from_str(&instance.goat_txid) {
            let is_finish_pegin =
                client.chain_service.adaptor.is_tx_execute_success(tx_hash).await?;
            if !is_finish_pegin {
                info!(
                    "scan_bridge_in, instance_id: {}, goat_tx:{} finish send to chain \
                but get receipt status is false, will try later",
                    instance.instance_id, instance.goat_txid
                );
                continue;
            }

            storage_process
                .update_instance_fields(
                    &instance.instance_id,
                    Some(BridgeInStatus::L2Minted.to_string()),
                    None,
                    None,
                )
                .await?;

            for graph in graphs {
                if graph.status != GraphStatus::CommitteePresigned.to_string() {
                    continue;
                }
                match client.post_operate_data(&instance.instance_id, &graph.graph_id, &graph).await
                {
                    Ok(tx_hash) => {
                        info!(
                            "finish post operate data for instance_id {}, graph_id:{} , tx hash:{}",
                            instance.instance_id, graph.graph_id, tx_hash
                        );
                    }
                    Err(err) => {
                        warn!("{} postOperatorData failed :err :{:?}", graph.graph_id, err)
                    }
                }
            }
        } else {
            let pegin_tx = client.fetch_btc_tx(&deserialize_hex(&graphs[0].pegin_txid)?).await?;
            match client.post_pegin_data(&instance.instance_id, &pegin_tx).await {
                Err(err) => {
                    warn!(
                        "instance id {}, tx:{} post_pegin_data failed err:{:?}",
                        instance.instance_id,
                        pegin_tx.compute_txid().to_string(),
                        err
                    );
                    continue;
                }
                Ok(tx_hash) => {
                    info!(
                        "finish post post_pegin_dataa for instance_id {} , tx hash:{}",
                        instance.instance_id, tx_hash
                    );
                    storage_process
                        .update_instance_fields(&instance.instance_id, None, None, Some(tx_hash))
                        .await?;
                }
            };
        }
    }
    Ok(())
}

// tick_task1
pub async fn scan_withdraw(
    swarm: &mut Swarm<AllBehaviours>,
    client: &BitVM2Client,
) -> Result<(), Box<dyn std::error::Error>> {
    info!("start tick action: scan_withdraw");
    let graphs = get_initialized_graphs(client).await?;
    for (instance_id, graph_id) in graphs {
        let message_content =
            GOATMessageContent::KickoffReady(KickoffReady { instance_id, graph_id });
        let msg_times = get_message_broadcast_times(
            client,
            &instance_id,
            &graph_id,
            &MessageType::KickoffReady.to_string(),
        )
        .await?;
        if msg_times <= MESSAGE_BROADCAST_MAX_TIMES {
            send_to_peer(swarm, GOATMessage::from_typed(Actor::Operator, &message_content)?)?;
            update_message_broadcast_times(
                client,
                &instance_id,
                &graph_id,
                &MessageType::KickoffReady.to_string(),
                msg_times + 1,
            )
            .await?;
        }
    }
    Ok(())
}

// Tick-Task-2:
pub async fn scan_kickoff(
    swarm: &mut Swarm<AllBehaviours>,
    client: &BitVM2Client,
) -> Result<(), Box<dyn std::error::Error>> {
    info!("start tick action: scan_kickoff");
    let graph_datas = get_relayer_caring_graph_data(
        client,
        GraphStatus::CommitteePresigned,
        MessageType::KickoffSent.to_string(),
    )
    .await?;
    info!("scan_kickoff get graph datas size: {}", graph_datas.len());
    for graph_data in graph_datas {
        if graph_data.kickoff_txid.is_none() {
            warn!("graph_id {}, kickoff txid is none", graph_data.graph_id);
            continue;
        }
        let kickoff_txid = graph_data.kickoff_txid.unwrap();
        if !tx_on_chain(client, &kickoff_txid).await? {
            warn!("graph_id:{} kickoff:{:?} is not onchain ", graph_data.graph_id, kickoff_txid);
            continue;
        }
        let instance_id = graph_data.instance_id;
        let graph_id = graph_data.graph_id;
        let message_content =
            GOATMessageContent::KickoffSent(KickoffSent { instance_id, graph_id, kickoff_txid });
        if graph_data.msg_times <= MESSAGE_BROADCAST_MAX_TIMES {
            send_to_peer(swarm, GOATMessage::from_typed(Actor::All, &message_content)?)?;
            update_message_broadcast_times(
                client,
                &graph_data.instance_id,
                &graph_data.graph_id,
                &MessageType::KickoffSent.to_string(),
                graph_data.msg_times + 1,
            )
            .await?;
        }
        if graph_data.msg_times == 0 {
            let kickoff_tx = client.fetch_btc_tx(&kickoff_txid).await?;
            match client.process_withdraw(&graph_data.graph_id, &kickoff_tx).await {
                Ok(tx_hash) => {
                    info!(
                        "instance_id: {}, graph_id:{}  finish withdraw, tx hash :{}",
                        instance_id, graph_id, tx_hash
                    );

                    update_graph_fields(
                        client,
                        graph_data.graph_id,
                        Some(GraphStatus::KickOff.to_string()),
                        None,
                        None,
                        None,
                    )
                    .await?
                }
                Err(err) => {
                    warn!("scan_kickoff: err:{err:?}");
                }
            }
        }
    }
    Ok(())
}

//Tick-Task-3:
pub async fn scan_assert(
    swarm: &mut Swarm<AllBehaviours>,
    client: &BitVM2Client,
) -> Result<(), Box<dyn std::error::Error>> {
    info!("start tick action: scan_assert");
    let mut graphs = get_relayer_caring_graph_data(
        client,
        GraphStatus::Challenge,
        MessageType::AssertSent.to_string(),
    )
    .await?;
    let mut graphs_kickoff = get_relayer_caring_graph_data(
        client,
        GraphStatus::KickOff,
        MessageType::AssertSent.to_string(),
    )
    .await?; // in case challenger never broadcast ChallengeSent
    graphs.append(&mut graphs_kickoff);
    info!("scan_assert get graph datas size: {}", graphs.len());
    for graph_data in graphs {
        if graph_data.assert_final_txid.is_none()
            | graph_data.assert_final_txid.is_none()
            | graph_data.assert_commit_txids.is_none()
        {
            warn!(
                "{}, has none field about assert txs,detail: assert_init_txid:{:?}, assert_commit_txids:{:?}, assert_final_txid:{:?}",
                graph_data.graph_id,
                graph_data.assert_init_txid,
                graph_data.assert_commit_txids,
                graph_data.assert_final_txid
            );
            continue;
        }
        if !tx_on_chain(client, &graph_data.assert_final_txid.unwrap()).await? {
            warn!(
                "{}, assert_final_txid:{:?} not on chain",
                graph_data.graph_id, graph_data.assert_final_txid
            );
            continue;
        }

        if graph_data.msg_times <= MESSAGE_BROADCAST_MAX_TIMES {
            let instance_id = graph_data.instance_id;
            let graph_id = graph_data.graph_id;
            let message_content = GOATMessageContent::AssertSent(AssertSent {
                instance_id,
                graph_id,
                assert_init_txid: graph_data.assert_init_txid.unwrap(),
                assert_commit_txids: graph_data.assert_commit_txids.unwrap(),
                assert_final_txid: graph_data.assert_final_txid.unwrap(),
            });
            send_to_peer(swarm, GOATMessage::from_typed(Actor::All, &message_content)?)?;
            update_message_broadcast_times(
                client,
                &graph_data.instance_id,
                &graph_data.graph_id,
                "AssertSent",
                graph_data.msg_times + 1,
            )
            .await?;
        }

        if graph_data.msg_times == 0 {
            update_graph_fields(
                client,
                graph_data.graph_id,
                Some(GraphStatus::Assert.to_string()),
                None,
                None,
                None,
            )
            .await?
        }
    }
    Ok(())
}

//Tick-Task-4
pub async fn scan_take1(
    swarm: &mut Swarm<AllBehaviours>,
    client: &BitVM2Client,
) -> Result<(), Box<dyn std::error::Error>> {
    info!("start tick action: scan_take1");
    let graph_datas = get_relayer_caring_graph_data(
        client,
        GraphStatus::KickOff,
        MessageType::Take1Ready.to_string(),
    )
    .await?;
    let current_height = client.esplora.get_height().await?;
    let lock_blocks = num_blocks_per_network(get_network(), CONNECTOR_3_TIMELOCK);
    info!("scan_take1 get graph datas size: {}", graph_datas.len());
    for graph_data in graph_datas {
        let instance_id = graph_data.instance_id;
        let graph_id = graph_data.graph_id;
        // if graph_data.msg_times >= MESSAGE_BROADCAST_MAX_TIMES {
        //     warn!("graph_id:{} take1 ready has send over max times", graph_id);
        //     continue;
        // }
        if graph_data.msg_times > 0 {
            if graph_data.take1_txid.is_none() {
                warn!("graph_id:{}, take1 txid is none", graph_id);
                continue;
            }
            let take1_txid = graph_data.take1_txid.unwrap();
            let take1_height = client.esplora.get_tx_status(&take1_txid).await?.block_height;
            if take1_height.is_some() {
                let take1_tx = client.fetch_btc_tx(&take1_txid).await?;
                match client.finish_withdraw_happy_path(&graph_id, &take1_tx).await {
                    Err(err) => {
                        // other place will do finish_withdraw_happy_path too
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
                        update_graph_fields(
                            client,
                            graph_id,
                            Some(GraphStatus::Take1.to_string()),
                            None,
                            None,
                            None,
                        )
                        .await?;
                    }
                }
            } else {
                info!(
                    "graph_id:{},  take1_txid{}  not no chain",
                    graph_data.graph_id,
                    take1_txid.to_string()
                )
            }
        } else {
            if graph_data.kickoff_txid.is_none() {
                warn!("graph_id:{}, kickoff txid is none", graph_data.graph_id);
                continue;
            }
            if let Some(kickoff_height) =
                client.esplora.get_tx_status(&graph_data.kickoff_txid.unwrap()).await?.block_height
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
                    update_message_broadcast_times(
                        client,
                        &instance_id,
                        &graph_id,
                        &MessageType::Take1Ready.to_string(),
                        graph_data.msg_times + 1,
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
    Ok(())
}

//Tick-Task-5:
pub async fn scan_take2(
    swarm: &mut Swarm<AllBehaviours>,
    client: &BitVM2Client,
) -> Result<(), Box<dyn std::error::Error>> {
    info!("start tick action: scan_take2");
    let graph_datas = get_relayer_caring_graph_data(
        client,
        GraphStatus::Assert,
        MessageType::Take2Ready.to_string(),
    )
    .await?;
    let current_height = client.esplora.get_height().await?;
    let lock_blocks = num_blocks_per_network(get_network(), CONNECTOR_4_TIMELOCK);

    info!("scan_take2 get graph datas size: {}", graph_datas.len());
    for graph_data in graph_datas {
        let instance_id = graph_data.instance_id;
        let graph_id = graph_data.graph_id;
        if graph_data.msg_times > 0 {
            if graph_data.take2_txid.is_none() {
                warn!("graph_id:{}, take2 txid is none", graph_id);
                continue;
            }
            let take2_txid = graph_data.take2_txid.unwrap();
            let take2_height = client.esplora.get_tx_status(&take2_txid).await?.block_height;
            if take2_height.is_some() {
                let take2_tx = client.fetch_btc_tx(&take2_txid).await?;
                match client.finish_withdraw_unhappy_path(&graph_id, &take2_tx).await {
                    Err(err) => {
                        // other place will do finish_unwithdraw_happy_path too
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
                        update_graph_fields(
                            client,
                            graph_data.graph_id,
                            Some(GraphStatus::Take2.to_string()),
                            None,
                            None,
                            None,
                        )
                        .await?;
                    }
                }
            } else {
                info!(
                    "graph_id:{},  take2_txid{}  not no chain",
                    graph_data.graph_id,
                    take2_txid.to_string()
                )
            }
        } else {
            if graph_data.assert_final_txid.is_none() {
                warn!("graph_id:{graph_id}, assert_final txid  is none");
                continue;
            }
            if let Some(asset_final_height) = client
                .esplora
                .get_tx_status(&graph_data.assert_final_txid.unwrap())
                .await?
                .block_height
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
                    update_message_broadcast_times(
                        client,
                        &instance_id,
                        &graph_id,
                        &MessageType::Take2Ready.to_string(),
                        graph_data.msg_times + 1,
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
    Ok(())
}

pub async fn do_tick_action(
    swarm: &mut Swarm<AllBehaviours>,
    client: &BitVM2Client,
) -> Result<(), Box<dyn std::error::Error>> {
    if let Err(err) = scan_bridge_in_prepare(swarm, client).await {
        warn!("scan_bridge_in_prepare, err {:?}", err)
    }

    if let Err(err) = scan_l1_broadcast_txs(swarm, client).await {
        warn!("scan_l1_broadcast_txs, err {:?}", err)
    }
    if let Err(err) = scan_bridge_in(swarm, client).await {
        warn!("scan_bridge_in, err {:?}", err)
    }

    if let Err(err) = scan_withdraw(swarm, client).await {
        warn!("scan_withdraw, err {:?}", err)
    }

    if let Err(err) = scan_kickoff(swarm, client).await {
        warn!("scan_kickoff, err {:?}", err)
    }

    if let Err(err) = scan_assert(swarm, client).await {
        warn!("scan_assert, err {:?}", err)
    }

    if let Err(err) = scan_take1(swarm, client).await {
        warn!("scan_take1, err {:?}", err)
    }

    if let Err(err) = scan_take2(swarm, client).await {
        warn!("scan_take2, err {:?}", err)
    }
    Ok(())
}
