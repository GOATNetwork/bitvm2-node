#![allow(dead_code)]

use crate::action::{ChallengeSent, CreateInstance, DisproveSent, InstanceDiscarded};
use crate::client::chain::chain_adaptor::WithdrawStatus;
use crate::client::graph_query::{
    BlockRange, CancelWithdrawEvent, GatewayEventEntity, InitWithdrawEvent, ProceedWithdrawEvent,
    UserGraphWithdrawEvent, WithdrawDisproved, WithdrawPathsEvent, get_gateway_events_query,
};
use crate::client::{BTCClient, GOATClient, GraphQueryClient};
use crate::env::{
    GRAPH_OPERATOR_DATA_UPLOAD_TIME_EXPIRED, INSTANCE_PRESIGNED_TIME_EXPIRED,
    LOAD_HISTORY_EVENT_NO_WOKING_MAX_SECS, MESSAGE_BROADCAST_MAX_TIMES, MESSAGE_EXPIRE_TIME,
    MESSAGE_RESEND_INTERVAL_SECOND,
};
use crate::rpc_service::{P2pUserData, UTXO, current_time_secs};
use crate::utils::{
    create_goat_tx_record, finish_withdraw_disproved, get_graph, obsolete_sibling_graphs,
    outpoint_spent_txid, reflect_goat_address, strip_hex_prefix_owned, update_graph_fields,
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
    pub graph_status: String,
    pub msg_times: i64,
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
) -> Result<(i64, i64), Box<dyn std::error::Error>> {
    let mut storage_process = local_db.acquire().await?;
    Ok(storage_process.get_message_broadcast_times(instance_id, graph_id, msg_type).await?)
}

pub async fn add_message_broadcast_times(
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

pub async fn fetch_and_handle_block_range_events<'a>(
    actor: Actor,
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
        "get user init withdraw events: {}, cancel withdraw events: {}, proceed_withdraw_events:{}, \
         withdraw_paths_events:{},  withdraw_disproved_events:{},  block range {from_height}:{to_height}",
        init_withdraw_events.len(),
        cancel_withdraw_events.len(),
        proceed_withdraw_events.len(),
        withdraw_paths_events.len(),
        withdraw_disproved_events.len(),
    );
    handle_user_withdraw_events(storage_processor, init_withdraw_events, cancel_withdraw_events)
        .await?;
    handle_proceed_withdraw_events(actor, storage_processor, proceed_withdraw_events).await?;
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
    actor: Actor,
    storage_processor: &mut StorageProcessor<'a>,
    proceed_withdraw_events: Vec<ProceedWithdrawEvent>,
) -> Result<(), Box<dyn Error>> {
    let prove_status = if actor == Actor::Operator && env::get_proof_server_url().is_none() {
        GoatTxProveStatus::Pending.to_string()
    } else {
        GoatTxProveStatus::NoNeed.to_string()
    };
    for event in proceed_withdraw_events {
        storage_processor
            .create_or_update_goat_tx_record(&GoatTxRecord {
                instance_id: Uuid::from_str(&strip_hex_prefix_owned(&event.instance_id))?,
                graph_id: Uuid::from_str(&strip_hex_prefix_owned(&event.graph_id))?,
                tx_type: GoatTxType::ProceedWithdraw.to_string(),
                tx_hash: event.transaction_hash,
                height: event.block_number.parse::<i64>()?,
                is_local: false,
                prove_status: prove_status.clone(),
                extra: None,
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
        let (flag, goat_addr) = reflect_goat_address(Some(event.operator_addr.clone()));
        if !flag {
            warn!(
                "handle_withdraw_paths_events failed as cast operator address failed, detail: {}, {}",
                event.transaction_hash, event.operator_addr
            );
            continue;
        }

        storage_processor.add_node_reward_by_addr(&goat_addr.unwrap(), reward_add).await?;
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
        let (flag, challenger_addr) = reflect_goat_address(Some(event.challenger_addr.clone()));
        if !flag {
            warn!(
                "handle_withdraw_disproved_events failed as cast challenger address failed, detail: {}, {}",
                event.transaction_hash, event.challenger_addr
            );
            continue;
        }
        let (flag, disprover_addr) = reflect_goat_address(Some(event.disprover_addr.clone()));
        if !flag {
            warn!(
                "handle_withdraw_disproved_events failed as cast disprover address failed, detail: {}, {}",
                event.transaction_hash, event.disprover_addr
            );
            continue;
        }

        storage_processor
            .add_node_reward_by_addr(&challenger_addr.unwrap(), challenger_reward_add)
            .await?;
        storage_processor
            .add_node_reward_by_addr(&disprover_addr.unwrap(), disprover_reward_add)
            .await?;
    }
    Ok(())
}

pub async fn fetch_history_events(
    actor: Actor,
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
            if watch_contract.from_height > current_finalized {
                info!(
                    "fetch history events will finish, as current finalize height: {current_finalized} is litter than watch from height: {}",
                    watch_contract.from_height,
                );
                continue;
            }

            let to_height = current_finalized.min(watch_contract.from_height + watch_contract.gap);
            let mut tx = local_db.start_transaction().await?;

            fetch_and_handle_block_range_events(
                actor.clone(),
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
    actor: Actor,
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
                actor.clone(),
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
        actor.clone(),
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
        .filter_type_messages(
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
    swarm: &mut Swarm<AllBehaviours>,
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
    let mut discarded_instances: Vec<Uuid> = vec![];
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
            if let Ok(is_discarded) = check_pegin_tx_input_status(
                btc_client,
                instance.instance_id,
                instance.input_uxtos.clone(),
            )
            .await
                && is_discarded
            {
                discarded_instances.push(instance.instance_id);
            }
        }
    }
    if !discarded_instances.is_empty() {
        info!("update_l1_broadcast_txs: {} discarded instances", discarded_instances.len());
        let mut tx = local_db.start_transaction().await?;
        tx.update_batch_instance_status(
            &BridgeInStatus::Discarded.to_string(),
            &discarded_instances,
        )
        .await?;
        tx.update_graphs_status_by_instance_ids(
            &GraphStatus::Discarded.to_string(),
            &discarded_instances,
        )
        .await?;
        for instance_id in discarded_instances.iter() {
            tx.add_message_broadcast_times(
                instance_id,
                &Uuid::nil(),
                &MessageType::InstanceDiscarded.to_string(),
                1,
            )
            .await?
        }
        let graph_infos =
            tx.get_graphs_ids_and_operator_by_instance_ids(&discarded_instances).await?;
        let message_content =
            GOATMessageContent::InstanceDiscarded(InstanceDiscarded { graph_infos });
        send_to_peer(swarm, GOATMessage::from_typed(Actor::Operator, &message_content)?)?;
        tx.commit().await?;
    }
    Ok(())
}

pub async fn check_pegin_tx_input_status(
    btc_client: &BTCClient,
    instance_id: Uuid,
    input_uxtos: String,
) -> Result<bool, Box<dyn std::error::Error>> {
    info!("check_pegin_tx_input_status for instance:{instance_id}");
    let utxos: Vec<UTXO> = serde_json::from_str(&input_uxtos)?;
    let mut input_utxo_used = false;
    for utxo in utxos {
        if outpoint_spent_txid(btc_client, &Txid::from_str(&utxo.txid)?, utxo.vout as u64)
            .await?
            .is_some()
        {
            info!(
                "check_pegin_tx_input_status for instance:{instance_id} input txid {} has been used",
                utxo.txid
            );
            input_utxo_used = true;
            break;
        }
    }
    Ok(input_utxo_used)
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
            // TODO update
            match goat_client
                .post_operate_data(&instance.instance_id, &graph.graph_id, &graph, &vec![])
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
                            GoatTxProveStatus::NoNeed.to_string(),
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
    let current_height = btc_client.esplora.get_height().await?;
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

    if let Err(err) = scan_withdraw(swarm, local_db, goat_client, btc_client).await {
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

fn is_need_to_send_msg(pre_send_times: i64, last_send_at: i64) -> bool {
    // if msg never been sent, last_send_at value is 0
    let current_time = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64;
    (pre_send_times % MESSAGE_BROADCAST_MAX_TIMES != 0)
        || (current_time - last_send_at) > MESSAGE_RESEND_INTERVAL_SECOND
}
