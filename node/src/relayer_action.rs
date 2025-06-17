#![allow(dead_code)]

use crate::action::{ChallengeSent, CreateInstance, DisproveSent};
use crate::client::chain::chain_adaptor::WithdrawStatus;
use crate::client::graph_query::{
    BlockRange, CancelWithdrawEvent, GatewayEventEntity, InitWithdrawEvent, ProceedWithdrawEvent,
    UserGraphWithdrawEvent, WithdrawDisproved, WithdrawPathsEvent, get_gateway_events_query,
};
use crate::client::{BTCClient, GOATClient, GraphQueryClient};
use crate::env::{
    GRAPH_OPERATOR_DATA_UPLOAD_TIME_EXPIRED, INSTANCE_PRESIGNED_TIME_EXPIRED,
    LOAD_HISTORY_EVENT_NO_WOKING_MAX_SECS, MESSAGE_BROADCAST_MAX_TIMES, MESSAGE_EXPIRE_TIME,
};
use crate::rpc_service::{P2pUserData, current_time_secs};
use crate::utils::{
    create_goat_tx_record, finish_withdraw_disproved, obsolete_sibling_graphs, outpoint_spent_txid,
    strip_hex_prefix_owned, update_graph_fields,
};
use crate::{
    action::{
        AssertSent, GOATMessage, GOATMessageContent, KickoffReady, KickoffSent, Take1Ready,
        Take2Ready, send_to_peer,
    },
    env,
    env::get_network,
    middleware::AllBehaviours,
    utils::tx_on_chain,
};
use alloy::primitives::TxHash;
use bitcoin::Txid;
use bitcoin::consensus::encode::{deserialize_hex, serialize_hex};
use bitcoin::hashes::Hash;
use bitvm2_lib::actors::Actor;
use goat::transactions::assert::utils::COMMIT_TX_NUM;
use goat::{
    constants::{CONNECTOR_3_TIMELOCK, CONNECTOR_4_TIMELOCK},
    utils::num_blocks_per_network,
};
use libp2p::Swarm;
use std::error::Error;
use std::str::FromStr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use store::localdb::{LocalDB, StorageProcessor, UpdateGraphParams};
use store::{
    BridgeInStatus, BridgePath, GoatTxProveStatus, GoatTxRecord, GoatTxType, GraphStatus,
    GraphTickActionMetaData, MessageState, MessageType, WatchContract, WatchContractStatus,
};
use tokio::time::sleep;
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
    pub challenge_txid: Option<Txid>,
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
            challenge_txid: tx_convert(value.challenge_txid),
        }
    }
}

pub async fn get_relayer_caring_graph_data(
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

pub async fn get_message_broadcast_times(
    local_db: &LocalDB,
    instance_id: &Uuid,
    graph_id: &Uuid,
    msg_type: &str,
) -> Result<i64, Box<dyn std::error::Error>> {
    let mut storage_process = local_db.acquire().await?;
    Ok(storage_process.get_message_broadcast_times(instance_id, graph_id, msg_type).await?)
}

pub async fn update_message_broadcast_times(
    local_db: &LocalDB,
    instance_id: &Uuid,
    graph_id: &Uuid,
    msg_type: &str,
    msg_times: i64,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut storage_process = local_db.acquire().await?;
    Ok(storage_process
        .update_message_broadcast_times(instance_id, graph_id, msg_type, msg_times)
        .await?)
}

pub async fn get_initialized_graphs(
    goat_client: &GOATClient,
) -> Result<Vec<(Uuid, Uuid)>, Box<dyn std::error::Error>> {
    // call L2 contract : getInitializedInstanceIds
    // returns Vec<(instance_id, graph_id)>
    Ok(goat_client.get_initialized_ids().await?)
}

pub async fn fetch_and_handle_block_range_events<'a>(
    client: &GraphQueryClient,
    storage_processor: &mut StorageProcessor<'a>,
    event_entities: &[GatewayEventEntity],
    from_height: i64,
    to_height: i64,
) -> Result<(), Box<dyn std::error::Error>> {
    let query_res = client
        .execute_query(&get_gateway_events_query(
            event_entities,
            Some(BlockRange::new(from_height, to_height)),
        ))
        .await?;

    let mut init_withdraw_events: Vec<InitWithdrawEvent> = vec![];
    let mut cancel_withdraw_events = vec![];
    let mut proceed_withdraw_events: Vec<ProceedWithdrawEvent> = vec![];
    let mut withdraw_paths_events: Vec<WithdrawPathsEvent> = vec![];
    let mut withdraw_disproved_events: Vec<WithdrawDisproved> = vec![];
    for event_entity in event_entities {
        let entity = event_entity.clone();
        if let Some(value_vec) = query_res[entity.to_string()].as_array() {
            match entity {
                GatewayEventEntity::InitWithdraws => {
                    init_withdraw_events =
                        serde_json::from_value(serde_json::Value::Array(value_vec.clone()))?;
                }
                GatewayEventEntity::CancelWithdraws => {
                    cancel_withdraw_events =
                        serde_json::from_value(serde_json::Value::Array(value_vec.clone()))?;
                }
                GatewayEventEntity::ProceedWithdraws => {
                    proceed_withdraw_events =
                        serde_json::from_value(serde_json::Value::Array(value_vec.clone()))?;
                }
                GatewayEventEntity::WithdrawHappyPaths
                | GatewayEventEntity::WithdrawUnhappyPaths => {
                    let mut events: Vec<WithdrawPathsEvent> =
                        serde_json::from_value(serde_json::Value::Array(value_vec.clone()))?;
                    withdraw_paths_events.append(&mut events);
                }
                GatewayEventEntity::WithdrawDisproveds => {
                    withdraw_disproved_events =
                        serde_json::from_value(serde_json::Value::Array(value_vec.clone()))?;
                }
            };
        }
    }
    info!(
        "get user init withdraw events: {}, cancel withdraw events: {}, block range {from_height}:{to_height}",
        init_withdraw_events.len(),
        cancel_withdraw_events.len()
    );
    handle_user_withdraw_events(storage_processor, init_withdraw_events, cancel_withdraw_events)
        .await?;
    handle_proceed_withdraw_events(storage_processor, proceed_withdraw_events).await?;
    handle_withdraw_paths_events(storage_processor, withdraw_paths_events).await?;
    handle_withdraw_disproved_events(storage_processor, withdraw_disproved_events).await?;
    Ok(())
}

async fn handle_user_withdraw_events<'a>(
    storage_processor: &mut StorageProcessor<'a>,
    init_withdraw_events: Vec<InitWithdrawEvent>,
    cancel_withdraw_events: Vec<CancelWithdrawEvent>,
) -> Result<(), Box<dyn Error>> {
    let mut user_withdraw_events: Vec<UserGraphWithdrawEvent> =
        init_withdraw_events.into_iter().map(UserGraphWithdrawEvent::InitWithdraw).collect();
    let mut user_cancel_withdraw_events: Vec<UserGraphWithdrawEvent> =
        cancel_withdraw_events.into_iter().map(UserGraphWithdrawEvent::CancelWithdraw).collect();
    user_withdraw_events.append(&mut user_cancel_withdraw_events);
    user_withdraw_events.sort_by_key(|v| v.get_block_number());
    for event in user_withdraw_events {
        match event {
            UserGraphWithdrawEvent::InitWithdraw(init_event) => {
                let graph_id = Uuid::from_str(&strip_hex_prefix_owned(&init_event.graph_id))?;
                storage_processor
                    .update_graph_fields(UpdateGraphParams {
                        graph_id,
                        status: None,
                        ipfs_base_url: None,
                        challenge_txid: None,
                        disprove_txid: None,
                        bridge_out_start_at: Some(current_time_secs()),
                        init_withdraw_txid: Some(init_event.transaction_hash),
                    })
                    .await?;
            }
            UserGraphWithdrawEvent::CancelWithdraw(cancel_event) => {
                let graph_id = Uuid::from_str(&strip_hex_prefix_owned(&cancel_event.graph_id))?;
                storage_processor
                    .update_graph_fields(UpdateGraphParams {
                        graph_id,
                        status: None,
                        ipfs_base_url: None,
                        challenge_txid: None,
                        disprove_txid: None,
                        bridge_out_start_at: Some(0),
                        init_withdraw_txid: Some("".to_string()),
                    })
                    .await?;
            }
        }
    }
    Ok(())
}

async fn handle_proceed_withdraw_events<'a>(
    storage_processor: &mut StorageProcessor<'a>,
    proceed_withdraw_events: Vec<ProceedWithdrawEvent>,
) -> Result<(), Box<dyn Error>> {
    for event in proceed_withdraw_events {
        storage_processor
            .create_or_update_goat_tx_record(&GoatTxRecord {
                instance_id: Uuid::from_str(&strip_hex_prefix_owned(&event.instance_id))?,
                graph_id: Uuid::from_str(&strip_hex_prefix_owned(&event.graph_id))?,
                tx_type: GoatTxType::ProceedWithdraw.to_string(),
                tx_hash: event.transaction_hash,
                height: event.block_number.parse::<i64>()?,
                is_local: false,
                prove_status: GoatTxProveStatus::Pending.to_string(),
                extra: Some(event.kickoff_txid),
                created_at: current_time_secs(),
            })
            .await?
    }
    Ok(())
}

async fn handle_withdraw_paths_events<'a>(
    storage_processor: &mut StorageProcessor<'a>,
    withdraw_paths_events: Vec<WithdrawPathsEvent>,
) -> Result<(), Box<dyn Error>> {
    for event in withdraw_paths_events {
        let reward_add: i64 = event.reward_amount_sats.parse::<i64>()?;
        storage_processor.add_node_reward_by_addr(&event.operator_addr, reward_add).await?;
    }
    Ok(())
}

async fn handle_withdraw_disproved_events<'a>(
    storage_processor: &mut StorageProcessor<'a>,
    withdraw_disproved_events: Vec<WithdrawDisproved>,
) -> Result<(), Box<dyn Error>> {
    for event in withdraw_disproved_events {
        let challenger_reward_add: i64 = event.challenger_amount_sats.parse::<i64>()?;
        let disprover_reward_add: i64 = event.disprover_amount_sats.parse::<i64>()?;
        storage_processor
            .add_node_reward_by_addr(&event.challenger_addr, challenger_reward_add)
            .await?;
        storage_processor
            .add_node_reward_by_addr(&event.disprover_addr, disprover_reward_add)
            .await?;
    }
    Ok(())
}

pub async fn fetch_history_events(
    local_db: &LocalDB,
    query_client: &GraphQueryClient,
    watch_contract: WatchContract,
    event_entities: Vec<GatewayEventEntity>,
) -> Result<(), Box<dyn std::error::Error>> {
    info!("Start into fetch_history_events from:{}", watch_contract.from_height);
    let goat_client = GOATClient::new(env::goat_config_from_env().await, env::get_goat_network());
    let mut watch_contract = watch_contract.clone();
    let local_db_clone = local_db.clone();
    let addr = watch_contract.addr.clone();
    let async_fn = || async move {
        loop {
            let current_finalized =
                goat_client.chain_service.adaptor.get_finalized_block_number().await;
            if current_finalized.is_err() {
                warn!("fail to get finalize block, will try later");
                sleep(Duration::from_millis(500)).await;
                continue;
            }
            let current_finalized = current_finalized?;
            if watch_contract.from_height >= current_finalized {
                info!(
                    "Not need to fetch history events, as current finalize height: {current_finalized} is litter than watch from height: {}",
                    watch_contract.from_height,
                );
                break;
            }

            let to_height = current_finalized.min(watch_contract.from_height + watch_contract.gap);
            let mut tx = local_db.start_transaction().await?;

            fetch_and_handle_block_range_events(
                query_client,
                &mut tx,
                &event_entities,
                watch_contract.from_height,
                to_height,
            )
            .await?;
            info!(
                "finish load history event from: {}, to: {to_height}",
                watch_contract.from_height
            );
            watch_contract.from_height = to_height + 1;
            watch_contract.status = WatchContractStatus::Syncing.to_string();
            watch_contract.updated_at = current_time_secs();

            if to_height >= current_finalized {
                info!("Finish load history at {to_height}");
                watch_contract.status = WatchContractStatus::Synced.to_string();
                tx.create_or_update_watch_contract(&watch_contract).await?;
                tx.commit().await?;
                break;
            }
            tx.create_or_update_watch_contract(&watch_contract).await?;
            tx.commit().await?;
        }
        Ok::<(), Box<dyn std::error::Error>>(())
    };
    let err = match async_fn().await {
        Ok(_) => false,
        Err(err) => {
            warn!("fetch_history_events failed,err:{:?}", err);
            true
        }
    };
    if err {
        let mut storage_processor = local_db_clone.acquire().await?;
        let _ = storage_processor
            .update_watch_contract_status(
                &addr,
                &WatchContractStatus::Failed.to_string(),
                current_time_secs(),
            )
            .await;
    }
    Ok(())
}

pub async fn monitor_events(
    goat_client: &GOATClient,
    local_db: &LocalDB,
    event_entities: Vec<GatewayEventEntity>,
) -> Result<(), Box<dyn std::error::Error>> {
    info!("start tick monitor_events");
    let addr = env::get_goat_gateway_contract_from_env().to_string();
    let current = current_time_secs();
    let mut storage_processor = local_db.acquire().await?;
    let mut watch_contract =
        if let Some(watch_contract) = storage_processor.get_watch_contract(&addr).await? {
            watch_contract
        } else {
            WatchContract {
                addr,
                the_graph_url: env::get_goat_event_the_graph_url_from_env(),
                gap: env::get_goat_event_filter_gap_from_env(),
                from_height: env::get_goat_event_filter_from_from_env(),
                status: WatchContractStatus::UnSync.to_string(),
                extra: None,
                updated_at: current,
            }
        };
    let query_client = GraphQueryClient::new(watch_contract.the_graph_url.clone());
    let current_finalized = goat_client.chain_service.adaptor.get_finalized_block_number().await?;

    if watch_contract.from_height == 0 || watch_contract.from_height >= current_finalized {
        warn!(
            "watch_contract start height is zero or bigger than current height, not do watch jobs"
        );
        return Ok(());
    }

    if watch_contract.from_height + watch_contract.gap < current_finalized {
        if watch_contract.status == WatchContractStatus::Syncing.to_string()
            && watch_contract.updated_at + LOAD_HISTORY_EVENT_NO_WOKING_MAX_SECS > current
        {
            info!("Still in handle local event! will check later");
            return Ok(());
        }

        let watch_contract_clone = watch_contract.clone();
        let local_db_clone = local_db.clone();
        let query_client_clone = query_client.clone();
        let event_entities_clone = event_entities.clone();
        tokio::spawn(async move {
            let _ = fetch_history_events(
                &local_db_clone,
                &query_client_clone,
                watch_contract_clone,
                event_entities_clone,
            )
            .await;
        });
        return Ok(());
    }

    if watch_contract.status != WatchContractStatus::Synced.to_string() {
        info!("Event sync not finished ");
        return Ok(());
    }
    let to_height = current_finalized.min(watch_contract.from_height + watch_contract.gap);
    let mut tx = local_db.start_transaction().await?;
    fetch_and_handle_block_range_events(
        &query_client,
        &mut tx,
        &event_entities,
        watch_contract.from_height,
        to_height,
    )
    .await?;
    info!("finish monitor event from: {}, to: {to_height}", watch_contract.from_height);
    watch_contract.from_height = to_height + 1;
    watch_contract.updated_at = current_time_secs();
    tx.create_or_update_watch_contract(&watch_contract).await?;
    tx.commit().await?;
    Ok(())
}

pub async fn scan_bridge_in_prepare(
    swarm: &mut Swarm<AllBehaviours>,
    local_db: &LocalDB,
) -> Result<(), Box<dyn std::error::Error>> {
    info!("start tick scan_bridge_in_prepare");
    let mut storage_process = local_db.acquire().await?;
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

    let expired_num = storage_process
        .update_expired_instance(
            &BridgeInStatus::Submitted.to_string(),
            &BridgeInStatus::PresignedFailed.to_string(),
            current_time - INSTANCE_PRESIGNED_TIME_EXPIRED,
        )
        .await?;
    info!("Presigned expired instances is {expired_num}");

    Ok(())
}

pub async fn scan_l1_broadcast_txs(
    _swarm: &mut Swarm<AllBehaviours>,
    local_db: &LocalDB,
    btc_client: &BTCClient,
) -> Result<(), Box<dyn std::error::Error>> {
    info!("Starting into scan_l1_broadcast_txs");
    let mut storage_process = local_db.acquire().await?;
    let (instances, _) = storage_process
        .instance_list(
            None,
            Some(BridgePath::BTCToPgBTC.to_u8()),
            Some(BridgeInStatus::Presigned.to_string()),
            None,
            None,
            None,
        )
        .await?;

    info!("Starting into scan_l1_broadcast_txs, need to check instance_size:{} ", instances.len());

    for instance in instances {
        if instance.pegin_txid.is_none() {
            warn!("instance:{}, pegin txid is none", instance.instance_id);
            continue;
        }
        let tx_id = deserialize_hex(instance.pegin_txid.unwrap().as_str())?;
        if tx_on_chain(btc_client, &tx_id).await? {
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

pub async fn scan_post_pegin_data(
    _swarm: &mut Swarm<AllBehaviours>,
    local_db: &LocalDB,
    btc_client: &BTCClient,
    goat_client: &GOATClient,
) -> Result<(), Box<dyn std::error::Error>> {
    // scan bridge-in tx & relay to L2 contract: postPeginData & postOperatorData
    info!("Starting into post_pegin_data");
    let mut storage_process = local_db.acquire().await?;
    let (instances, _) = storage_process
        .instance_list(
            None,
            Some(BridgePath::BTCToPgBTC.to_u8()),
            Some(BridgeInStatus::L1Broadcasted.to_string()),
            None,
            None,
            None,
        )
        .await?;

    info!("Starting into scan post_pegin_data, need to send instance_size:{} ", instances.len());
    for instance in instances {
        if instance.pegin_txid.is_none() {
            warn!("scan post_pegin_data instance:{}, pegin txid is none", instance.instance_id);
            continue;
        }
        if let Ok(_tx_hash) = TxHash::from_str(&instance.goat_txid) {
            let receipt_op =
                goat_client.chain_service.adaptor.get_tx_receipt(&instance.goat_txid).await?;
            if receipt_op.is_none() {
                info!(
                    "scan post_pegin_data, instance_id: {}, goat_tx:{} finish send to chain \
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
        } else {
            let pegin_tx =
                btc_client.fetch_btc_tx(&deserialize_hex(&instance.pegin_txid.unwrap())?).await?;
            match goat_client.post_pegin_data(btc_client, &instance.instance_id, &pegin_tx).await {
                Err(err) => {
                    warn!(
                        "scan post_pegin_data instance id {}, tx:{} post_pegin_data failed err:{:?}",
                        instance.instance_id,
                        pegin_tx.compute_txid().to_string(),
                        err
                    );
                    continue;
                }
                Ok(tx_hash) => {
                    info!(
                        "scan post_pegin_data finish post post_pegin_dataa for instance_id {} , tx hash:{}",
                        instance.instance_id, tx_hash
                    );

                    create_goat_tx_record(
                        local_db,
                        goat_client,
                        Uuid::default(),
                        instance.instance_id,
                        &tx_hash,
                        GoatTxType::PostPeginData,
                        GoatTxProveStatus::NoNeed.to_string(),
                    )
                    .await?;

                    storage_process
                        .update_instance_fields(&instance.instance_id, None, None, Some(tx_hash))
                        .await?;
                }
            };
        }
    }
    Ok(())
}

pub async fn scan_post_operator_data(
    _swarm: &mut Swarm<AllBehaviours>,
    local_db: &LocalDB,
    goat_client: &GOATClient,
) -> Result<(), Box<dyn std::error::Error>> {
    info!("Starting into scan post_operator_data");
    let current_time = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64;
    let mut storage_process = local_db.acquire().await?;
    let (instances, _) = storage_process
        .instance_list(
            None,
            Some(BridgePath::BTCToPgBTC.to_u8()),
            Some(BridgeInStatus::L2Minted.to_string()),
            Some(current_time - GRAPH_OPERATOR_DATA_UPLOAD_TIME_EXPIRED),
            None,
            None,
        )
        .await
        .unwrap();

    info!("scan post_operator_data check instance size: {}", instances.len());
    for instance in instances {
        let graphs = storage_process.get_graph_by_instance_id(&instance.instance_id).await?;
        if graphs.is_empty() {
            warn!(
                " scan post_operator_data instance {}, status is L2Minted, but graph is none",
                instance.instance_id
            );
            continue;
        }
        for graph in graphs {
            if graph.status != GraphStatus::CommitteePresigned.to_string() {
                continue;
            }
            match goat_client
                .post_operate_data(&instance.instance_id, &graph.graph_id, &graph)
                .await
            {
                Ok(tx_hash) => {
                    info!(
                        "scan post_operator_data finish post operate data for instance_id {}, graph_id:{} , tx hash:{}",
                        instance.instance_id, graph.graph_id, tx_hash
                    );

                    create_goat_tx_record(
                        local_db,
                        goat_client,
                        graph.graph_id,
                        instance.instance_id,
                        &tx_hash,
                        GoatTxType::PostOperatorData,
                        GoatTxProveStatus::NoNeed.to_string(),
                    )
                    .await?;

                    storage_process
                        .update_graph_fields(UpdateGraphParams {
                            graph_id: graph.graph_id,
                            status: Some(GraphStatus::OperatorDataPushed.to_string()),
                            ipfs_base_url: None,
                            challenge_txid: None,
                            disprove_txid: None,
                            bridge_out_start_at: None,
                            init_withdraw_txid: None,
                        })
                        .await?
                }
                Err(err) => {
                    warn!(
                        "scan post_operator_data {} postOperatorData failed :err :{:?}",
                        graph.graph_id, err
                    )
                }
            }
        }
    }
    Ok(())
}

// tick_task1
pub async fn scan_withdraw(
    swarm: &mut Swarm<AllBehaviours>,
    local_db: &LocalDB,
    goat_client: &GOATClient,
) -> Result<(), Box<dyn std::error::Error>> {
    info!("start tick action: scan_withdraw");
    let graphs = get_initialized_graphs(goat_client).await?;
    for (instance_id, graph_id) in graphs {
        let message_content =
            GOATMessageContent::KickoffReady(KickoffReady { instance_id, graph_id });
        let msg_times = get_message_broadcast_times(
            local_db,
            &instance_id,
            &graph_id,
            &MessageType::KickoffReady.to_string(),
        )
        .await?;
        if msg_times < MESSAGE_BROADCAST_MAX_TIMES {
            send_to_peer(swarm, GOATMessage::from_typed(Actor::Operator, &message_content)?)?;
            update_message_broadcast_times(
                local_db,
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
    local_db: &LocalDB,
    btc_client: &BTCClient,
    goat_client: &GOATClient,
) -> Result<(), Box<dyn std::error::Error>> {
    info!("start tick action: scan_kickoff");
    let graph_datas = get_relayer_caring_graph_data(
        local_db,
        GraphStatus::OperatorDataPushed,
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
        if !tx_on_chain(btc_client, &kickoff_txid).await? {
            warn!("graph_id:{} kickoff:{:?} is not onchain ", graph_data.graph_id, kickoff_txid);
            continue;
        }
        let instance_id = graph_data.instance_id;
        let graph_id = graph_data.graph_id;

        let withdraw_data = goat_client.get_withdraw_data(&graph_id).await?;
        let mut send_message = false;
        if withdraw_data.status != WithdrawStatus::Initialized {
            info!("scan_kickoff {graph_id}, kickoff:{kickoff_txid} in evil way");
            send_message = true;
        } else {
            let kickoff_tx = btc_client.fetch_btc_tx(&kickoff_txid).await?;
            match goat_client.process_withdraw(btc_client, &graph_data.graph_id, &kickoff_tx).await
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
                        GoatTxProveStatus::Pending.to_string(),
                    )
                    .await?;

                    send_message = true;
                }
                Err(err) => {
                    warn!("scan_kickoff: err:{err:?}");
                }
            }
        }
        if send_message {
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
            let message_content = GOATMessageContent::KickoffSent(KickoffSent {
                instance_id,
                graph_id,
                kickoff_txid,
            });
            if graph_data.msg_times < MESSAGE_BROADCAST_MAX_TIMES {
                send_to_peer(swarm, GOATMessage::from_typed(Actor::All, &message_content)?)?;
                update_message_broadcast_times(
                    local_db,
                    &graph_data.instance_id,
                    &graph_data.graph_id,
                    &MessageType::KickoffSent.to_string(),
                    graph_data.msg_times + 1,
                )
                .await?;
            }
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
        if !tx_on_chain(btc_client, &graph_data.assert_final_txid.unwrap()).await? {
            warn!(
                "{}, assert_final_txid:{:?} not on chain",
                graph_data.graph_id, graph_data.assert_final_txid
            );
            continue;
        }

        if graph_data.msg_times < MESSAGE_BROADCAST_MAX_TIMES {
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
                local_db,
                &graph_data.instance_id,
                &graph_data.graph_id,
                "AssertSent",
                graph_data.msg_times + 1,
            )
            .await?;
        }

        if graph_data.msg_times == 0 {
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
    let graph_datas = get_relayer_caring_graph_data(
        local_db,
        GraphStatus::KickOff,
        MessageType::Take1Ready.to_string(),
    )
    .await?;
    let current_height = btc_client.esplora.get_height().await?;
    let lock_blocks = num_blocks_per_network(get_network(), CONNECTOR_3_TIMELOCK);
    info!("scan_take1 get graph datas size: {}", graph_datas.len());
    for graph_data in graph_datas {
        let instance_id = graph_data.instance_id;
        let graph_id = graph_data.graph_id;
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
                            GoatTxProveStatus::NoNeed.to_string(),
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
        }
        if graph_data.msg_times < MESSAGE_BROADCAST_MAX_TIMES {
            // check if kickoff's timelock for take1 is expired
            if let Some(kickoff_height) =
                btc_client.esplora.get_tx_status(&kickoff_txid).await?.block_height
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
                        local_db,
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
    let current_height = btc_client.esplora.get_height().await?;
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
                            GoatTxProveStatus::NoNeed.to_string(),
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
                let tx_hash = finish_withdraw_disproved(
                    btc_client,
                    goat_client,
                    &graph_id,
                    &btc_client.fetch_btc_tx(&disprove_txid).await?,
                    &btc_client
                        .fetch_btc_tx(
                            &graph_data.challenge_txid.expect("fail to get challenge txid"),
                        )
                        .await?,
                )
                .await?;

                create_goat_tx_record(
                    local_db,
                    goat_client,
                    graph_id,
                    instance_id,
                    &tx_hash,
                    GoatTxType::WithdrawDisproved,
                    GoatTxProveStatus::NoNeed.to_string(),
                )
                .await?;
                // in case challenger never broadcast DisproveSent
                let message_content = GOATMessageContent::DisproveSent(DisproveSent {
                    instance_id,
                    graph_id,
                    disprove_txid: spent_txid,
                });
                send_to_peer(swarm, GOATMessage::from_typed(Actor::Operator, &message_content)?)?;
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
        }
        if graph_data.msg_times < MESSAGE_BROADCAST_MAX_TIMES {
            // check if assert_final's timelock for take2 is expired
            if let Some(asset_final_height) =
                btc_client.esplora.get_tx_status(&assert_final_txid).await?.block_height
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
                        local_db,
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
    local_db: &LocalDB,
    btc_client: &BTCClient,
    goat_client: &GOATClient,
) -> Result<(), Box<dyn std::error::Error>> {
    if let Err(err) = scan_bridge_in_prepare(swarm, local_db).await {
        warn!("scan_bridge_in_prepare, err {:?}", err)
    }

    if let Err(err) = scan_l1_broadcast_txs(swarm, local_db, btc_client).await {
        warn!("scan_l1_broadcast_txs, err {:?}", err)
    }
    if let Err(err) = scan_post_pegin_data(swarm, local_db, btc_client, goat_client).await {
        warn!("scan_post_pegin_data, err {:?}", err)
    }

    if let Err(err) = scan_post_operator_data(swarm, local_db, goat_client).await {
        warn!("scan_post_operator_data, err {:?}", err)
    }

    if let Err(err) = scan_withdraw(swarm, local_db, goat_client).await {
        warn!("scan_withdraw, err {:?}", err)
    }

    if let Err(err) = scan_kickoff(swarm, local_db, btc_client, goat_client).await {
        warn!("scan_kickoff, err {:?}", err)
    }

    if let Err(err) = scan_assert(swarm, local_db, btc_client).await {
        warn!("scan_assert, err {:?}", err)
    }

    if let Err(err) = scan_take1(swarm, local_db, btc_client, goat_client).await {
        warn!("scan_take1, err {:?}", err)
    }

    if let Err(err) = scan_take2(swarm, local_db, btc_client, goat_client).await {
        warn!("scan_take2, err {:?}", err)
    }
    Ok(())
}
