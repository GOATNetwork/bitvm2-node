use crate::client::btc_chain::BTCClient;
use crate::client::goat_chain::GOATClient;
use crate::client::graphs::GraphQueryClient;
use crate::client::graphs::graph_query::{
    BlockRange, BridgeInEvent, BridgeInRequestEvent, CancelWithdrawEvent, CommitteeResponseEvent,
    GatewayEventEntity, InitWithdrawEvent, ProceedWithdrawEvent, UserGraphWithdrawEvent,
    WithdrawDisprovedEvent, WithdrawPathsEvent, get_gateway_events_query,
};
use crate::env;
use crate::env::{
    LOAD_HISTORY_EVENT_NO_WOKING_MAX_SECS, get_goat_network, get_network, goat_config_from_env,
};
use crate::rpc_service::current_time_secs;
use crate::utils::{generate_instance_from_event, reflect_goat_address, strip_hex_prefix_owned};
use bitvm2_lib::actors::Actor;
use std::collections::HashMap;
use std::str::FromStr;
use std::time::Duration;
use store::localdb::{LocalDB, StorageProcessor, UpdateGraphParams};
use store::{
    GoatTxProcessingStatus, GoatTxRecord, GoatTxType, InstanceStatus, WatchContract,
    WatchContractStatus,
};
use tokio::time::sleep;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};
use uuid::Uuid;

pub async fn fetch_and_handle_block_range_events<'a>(
    actor: Actor,
    btc_client: &BTCClient,
    client: &GraphQueryClient,
    storage_processor: &mut StorageProcessor<'a>,
    event_entities: &[GatewayEventEntity],
    from_height: i64,
    to_height: i64,
) -> anyhow::Result<()> {
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
    let mut withdraw_disproved_events: Vec<WithdrawDisprovedEvent> = vec![];
    let mut bridge_in_request_events: Vec<BridgeInRequestEvent> = vec![];
    let mut committee_response_events: Vec<CommitteeResponseEvent> = vec![];
    let mut bridge_in_events: Vec<BridgeInEvent> = vec![];
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
                GatewayEventEntity::BridgeInRequests => {
                    bridge_in_request_events =
                        serde_json::from_value(serde_json::Value::Array(value_vec.clone()))?;
                }
                GatewayEventEntity::CommitteeResponses => {
                    committee_response_events =
                        serde_json::from_value(serde_json::Value::Array(value_vec.clone()))?;
                }
                GatewayEventEntity::BridgeIns => {
                    bridge_in_events =
                        serde_json::from_value(serde_json::Value::Array(value_vec.clone()))?;
                }
            };
        }
    }
    info!(
        "get user init withdraw events: {}, cancel withdraw events: {}, proceed_withdraw_events: {}, \
         withdraw_paths_events: {},  withdraw_disproved_events: {}, bridge_in_request_events: {}  \
         committee_response_events: {}, bridge_in_events: {} block range {from_height}:{to_height}",
        init_withdraw_events.len(),
        cancel_withdraw_events.len(),
        proceed_withdraw_events.len(),
        withdraw_paths_events.len(),
        withdraw_disproved_events.len(),
        bridge_in_request_events.len(),
        committee_response_events.len(),
        bridge_in_events.len()
    );
    handle_user_withdraw_events(storage_processor, init_withdraw_events, cancel_withdraw_events)
        .await?;
    handle_proceed_withdraw_events(actor.clone(), storage_processor, proceed_withdraw_events)
        .await?;
    handle_withdraw_paths_events(storage_processor, withdraw_paths_events).await?;
    handle_withdraw_disproved_events(storage_processor, withdraw_disproved_events).await?;
    handle_bridge_in_request_events(
        storage_processor,
        actor.clone(),
        btc_client,
        bridge_in_request_events,
    )
    .await?;
    handle_committee_response_events(storage_processor, committee_response_events).await?;
    handle_bridge_in_events(storage_processor, bridge_in_events).await?;
    Ok(())
}

async fn handle_user_withdraw_events<'a>(
    storage_processor: &mut StorageProcessor<'a>,
    init_withdraw_events: Vec<InitWithdrawEvent>,
    cancel_withdraw_events: Vec<CancelWithdrawEvent>,
) -> anyhow::Result<()> {
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
) -> anyhow::Result<()> {
    let processing_status = if actor == Actor::Operator && env::get_proof_server_url().is_none() {
        GoatTxProcessingStatus::Pending.to_string()
    } else {
        GoatTxProcessingStatus::Skipped.to_string()
    };
    for event in proceed_withdraw_events {
        storage_processor
            .upsert_goat_tx_record(&GoatTxRecord {
                instance_id: Uuid::from_str(&strip_hex_prefix_owned(&event.instance_id))?,
                graph_id: Uuid::from_str(&strip_hex_prefix_owned(&event.graph_id))?,
                tx_type: GoatTxType::ProceedWithdraw.to_string(),
                tx_hash: event.transaction_hash,
                height: event.block_number.parse::<i64>()?,
                is_local: false,
                processing_status: processing_status.clone(),
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
) -> anyhow::Result<()> {
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
    withdraw_disproved_events: Vec<WithdrawDisprovedEvent>,
) -> anyhow::Result<()> {
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

async fn handle_bridge_in_request_events<'a>(
    storage_processor: &mut StorageProcessor<'a>,
    actor: Actor,
    btc_client: &BTCClient,
    bridge_in_request_events: Vec<BridgeInRequestEvent>,
) -> anyhow::Result<()> {
    let processing_status = if actor == Actor::Committee {
        GoatTxProcessingStatus::Pending.to_string()
    } else {
        GoatTxProcessingStatus::Skipped.to_string()
    };
    for event in bridge_in_request_events {
        let instance_res = generate_instance_from_event(btc_client, &event).await;
        if instance_res.is_err() {
            warn!("generate instance failed from event:{event:?}");
            continue;
        }
        storage_processor.upsert_instance(&instance_res.unwrap()).await?;
        storage_processor
            .upsert_goat_tx_record(&GoatTxRecord {
                instance_id: Uuid::from_str(&strip_hex_prefix_owned(&event.instance_id))?,
                graph_id: Uuid::nil(),
                tx_type: GoatTxType::BridgeInRequest.to_string(),
                tx_hash: event.transaction_hash,
                height: event.block_number.parse::<i64>()?,
                is_local: false,
                processing_status: processing_status.clone(),
                extra: None,
                created_at: current_time_secs(),
            })
            .await?
    }
    Ok(())
}

async fn handle_committee_response_events<'a>(
    storage_processor: &mut StorageProcessor<'a>,
    committee_response_events: Vec<CommitteeResponseEvent>,
) -> anyhow::Result<()> {
    for event in committee_response_events {
        if let Ok(instance_id) = &Uuid::from_str(&strip_hex_prefix_owned(&event.instance_id)) {
            // Convert hex string to [u8; 32]
            if let Ok(pubkey_bytes) = hex::decode(&event.committee_xonly_pubkey) {
                if pubkey_bytes.len() == 32 {
                    let mut pubkey = [0u8; 32];
                    pubkey.copy_from_slice(&pubkey_bytes);
                    storage_processor
                        .update_instance_committee_answer(
                            instance_id,
                            &event.committee_address,
                            &pubkey,
                            None,
                            None,
                        )
                        .await?;
                } else {
                    warn!(
                        "committee_xonly_pubkey length is not 32 bytes: {}",
                        event.committee_xonly_pubkey
                    );
                }
            } else {
                warn!("failed to decode committee_xonly_pubkey: {}", event.committee_xonly_pubkey);
            }
        } else {
            warn!("failed to parse instance id:{event:?}");
        }
    }
    Ok(())
}

async fn handle_bridge_in_events<'a>(
    storage_processor: &mut StorageProcessor<'a>,
    bridge_in_events: Vec<BridgeInEvent>,
) -> anyhow::Result<()> {
    for event in bridge_in_events {
        if let Ok(instance_id) = &Uuid::from_str(&strip_hex_prefix_owned(&event.instance_id)) {
            storage_processor
                .update_instance_status(instance_id, &InstanceStatus::RelayerL2Minted.to_string())
                .await?;
        } else {
            warn!("failed to parse instance id:{event:?}");
        }
    }
    Ok(())
}

pub async fn fetch_history_events(
    actor: Actor,
    btc_client: &BTCClient,
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
            let current_finalized = goat_client.get_finalized_block_number().await;
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
                btc_client,
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
                tx.upsert_watch_contract(&watch_contract).await?;
                tx.commit().await?;
                break;
            }
            tx.upsert_watch_contract(&watch_contract).await?;
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
    btc_client: &BTCClient,
    local_db: &LocalDB,
    event_entities: Vec<GatewayEventEntity>,
) -> Result<(), Box<dyn std::error::Error>> {
    info!("start tick monitor_events");
    let mut storage_processor = local_db.acquire().await?;
    let mut watch_contract = get_watch_contract(&mut storage_processor).await?;
    let query_client = GraphQueryClient::new(watch_contract.the_graph_url.clone());
    let current_finalized = goat_client.get_finalized_block_number().await?;

    if watch_contract.from_height == 0 || watch_contract.from_height >= current_finalized {
        warn!(
            "watch_contract start height is zero or bigger than current height, not do watch jobs"
        );
        return Ok(());
    }

    if watch_contract.from_height + watch_contract.gap < current_finalized {
        if watch_contract.status == WatchContractStatus::Syncing.to_string()
            && watch_contract.updated_at + LOAD_HISTORY_EVENT_NO_WOKING_MAX_SECS
                > current_time_secs()
        {
            info!("Still in handle local event! will check later");
            return Ok(());
        }

        let watch_contract_clone = watch_contract.clone();
        let local_db_clone = local_db.clone();
        let query_client_clone = query_client.clone();
        let event_entities_clone = event_entities.clone();
        let btc_client_clone = btc_client.clone();
        tokio::spawn(async move {
            let _ = fetch_history_events(
                actor.clone(),
                &btc_client_clone,
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
        btc_client,
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
    tx.upsert_watch_contract(&watch_contract).await?;
    tx.commit().await?;
    Ok(())
}

pub async fn run_watch_event_task(
    actor: Actor,
    local_db: LocalDB,
    interval: u64,
    cancellation_token: CancellationToken,
) -> anyhow::Result<String> {
    let goat_client = GOATClient::new(goat_config_from_env().await, get_goat_network());
    let btc_client = BTCClient::new(None, get_network());
    let events_map: HashMap<Actor, Vec<GatewayEventEntity>> = HashMap::from([
        (
            Actor::Relayer,
            vec![
                GatewayEventEntity::InitWithdraws,
                GatewayEventEntity::CancelWithdraws,
                GatewayEventEntity::ProceedWithdraws,
                GatewayEventEntity::WithdrawHappyPaths,
                GatewayEventEntity::WithdrawUnhappyPaths,
                GatewayEventEntity::WithdrawDisproveds,
                GatewayEventEntity::BridgeInRequests,
            ],
        ),
        (
            Actor::Operator,
            vec![GatewayEventEntity::ProceedWithdraws, GatewayEventEntity::BridgeInRequests],
        ),
        (Actor::Committee, vec![GatewayEventEntity::BridgeInRequests]),
    ]);
    loop {
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_secs(interval)) => {
                // Execute the normal monitoring logic
                match monitor_events(
                        actor.clone(),
                        &goat_client,
                        &btc_client,
                        &local_db,
                        events_map.get(&actor).cloned().unwrap_or_default()
                    )
                    .await
                    {
                        Ok(_) => {}
                        Err(e) => {
                            tracing::error!(e)
                        }
                    }
            }
            _ = cancellation_token.cancelled() => {
                tracing::info!("Watch event task received shutdown signal");
                return Ok("watch_shutdown".to_string());
            }
        }
    }
}

async fn get_watch_contract<'a>(
    storage_processor: &mut StorageProcessor<'a>,
) -> anyhow::Result<WatchContract> {
    let addr = env::get_goat_gateway_contract_from_env().to_string();
    if let Some(watch_contract) = storage_processor.get_watch_contract(&addr).await? {
        Ok(watch_contract)
    } else {
        Ok(WatchContract {
            addr,
            the_graph_url: env::get_goat_event_the_graph_url_from_env(),
            gap: env::get_goat_event_filter_gap_from_env(),
            from_height: env::get_goat_event_filter_from_from_env(),
            status: WatchContractStatus::UnSync.to_string(),
            extra: None,
            updated_at: current_time_secs(),
        })
    }
}

pub async fn is_processing_history_events(
    local_db: &LocalDB,
    goat_client: &GOATClient,
) -> anyhow::Result<bool> {
    let mut storage_processor = local_db.acquire().await?;
    let current_finalized = goat_client.get_finalized_block_number().await?;
    let watch_contract = get_watch_contract(&mut storage_processor).await?;
    Ok(watch_contract.from_height + watch_contract.gap < current_finalized
        || watch_contract.status == WatchContractStatus::Syncing.to_string())
}
