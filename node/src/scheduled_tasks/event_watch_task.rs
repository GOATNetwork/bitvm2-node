use crate::env;
use crate::env::{
    ENV_GOAT_GATEWAY_CONTRACT_ADDRESS, ENV_GOAT_SWAP_CONTRACT_ADDRESS,
    LOAD_HISTORY_EVENT_NO_WOKING_MAX_SECS, get_goat_address_from_env,
    get_goat_gateway_event_filter_from_from_env, get_goat_gateway_event_filter_gap_from_env,
    get_goat_gateway_the_graph_urls_from_env, get_goat_swap_event_filter_from_from_env,
    get_goat_swap_event_filter_gap_from_env, get_goat_swap_the_graph_urls_from_env, get_network,
};
use crate::rpc_service::current_time_secs;
use crate::utils::evm_swap_utils::{extract_claim_data_from_tx, extract_escrow_data_from_tx};
use crate::utils::{
    GenerateInstanceParams, generate_instance, outpoint_available, reflect_goat_address,
    strip_hex_prefix_owned,
};
use alloy::primitives::Address as EvmAddress;
use alloy::sol_types::SolValue;
use bitcoin::address::NetworkUnchecked;
use bitcoin::hashes::Hash;
use bitcoin::{Address, Amount, OutPoint, Txid};
use bitvm2_lib::actors::Actor;
use bitvm2_lib::types::UserInfo;
use client::btc_chain::BTCClient;
use client::goat_chain::GOATClient;
use client::graphs::GraphQueryClient;
use client::graphs::graph_query::{
    BlockRange, BridgeInEvent, BridgeInRequestEvent, CancelWithdrawEvent, CommitteeResponseEvent,
    GatewayEventEntity, InitWithdrawEvent, PostGraphDataEvent, ProceedWithdrawEvent,
    SwapClaimEvent, SwapEventEntity, SwapInitializeEvent, SwapRefundEvent, TheGraphConfig,
    UserGraphWithdrawEvent, WatchContractType, WatchEventConfig, WithdrawDisprovedEvent,
    WithdrawHappyEvent, WithdrawPathsEvent, WithdrawUnhappyEvent, get_bridge_out_events_query,
    get_gateway_events_query,
};
use goat::transactions::base::Input;
use secp256k1::XOnlyPublicKey;
use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use store::localdb::{GraphUpdate, InstanceQuery, InstanceUpdate, LocalDB, StorageProcessor};
use store::{
    GoatTxProcessingStatus, GoatTxRecord, GoatTxType, GraphStatus, Instance,
    InstanceBridgeInStatus, InstanceBridgeOutStatus, WatchContract, WatchContractStatus,
};
use tokio::time::sleep;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};
use uuid::Uuid;
#[allow(clippy::too_many_arguments)]
pub async fn fetch_and_handle_block_range_events<'a>(
    actor: Actor,
    btc_client: Arc<BTCClient>,
    goat_client: Arc<GOATClient>,
    client: &GraphQueryClient,
    storage_processor: &mut StorageProcessor<'a>,
    watch_events_config: &WatchEventConfig,
    from_height: i64,
    to_height: i64,
) -> anyhow::Result<()> {
    match watch_events_config {
        WatchEventConfig::Gateway(config) => {
            fetch_and_handle_gateway_events(
                actor,
                btc_client,
                goat_client.clone(),
                client,
                storage_processor,
                &config.the_graph_url,
                &config.event_entities,
                from_height,
                to_height,
            )
            .await?;
        }
        WatchEventConfig::Swap(config) => {
            fetch_and_handle_bridge_out_events(
                goat_client.clone(),
                client,
                storage_processor,
                &config.address,
                &config.the_graph_url,
                &config.event_entities,
                from_height,
                to_height,
            )
            .await?;
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub async fn fetch_and_handle_gateway_events<'a>(
    actor: Actor,
    btc_client: Arc<BTCClient>,
    goat_client: Arc<GOATClient>,
    client: &GraphQueryClient,
    storage_processor: &mut StorageProcessor<'a>,
    graph_url: &str,
    event_entities: &[GatewayEventEntity],
    from_height: i64,
    to_height: i64,
) -> anyhow::Result<()> {
    let query_res = client
        .execute_query(
            graph_url,
            &get_gateway_events_query(
                event_entities,
                Some(BlockRange::new(from_height, to_height)),
            ),
        )
        .await?;

    let mut init_withdraw_events: Vec<InitWithdrawEvent> = vec![];
    let mut cancel_withdraw_events = vec![];
    let mut proceed_withdraw_events: Vec<ProceedWithdrawEvent> = vec![];
    let mut withdraw_paths_events: Vec<WithdrawPathsEvent> = vec![];
    let mut withdraw_disproved_events: Vec<WithdrawDisprovedEvent> = vec![];
    let mut bridge_in_request_events: Vec<BridgeInRequestEvent> = vec![];
    let mut committee_response_events: Vec<CommitteeResponseEvent> = vec![];
    let mut bridge_in_events: Vec<BridgeInEvent> = vec![];
    let mut post_graph_data_events: Vec<PostGraphDataEvent> = vec![];
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
                GatewayEventEntity::WithdrawHappyPaths => {
                    let events: Vec<WithdrawHappyEvent> =
                        serde_json::from_value(serde_json::Value::Array(value_vec.clone()))?;
                    let mut events: Vec<WithdrawPathsEvent> =
                        events.into_iter().map(WithdrawPathsEvent::WithdrawHappyEvent).collect();
                    withdraw_paths_events.append(&mut events);
                }
                GatewayEventEntity::WithdrawUnhappyPaths => {
                    let events: Vec<WithdrawUnhappyEvent> =
                        serde_json::from_value(serde_json::Value::Array(value_vec.clone()))?;
                    let mut events: Vec<WithdrawPathsEvent> =
                        events.into_iter().map(WithdrawPathsEvent::WithdrawUnhappyEvent).collect();
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
                GatewayEventEntity::PostGraphDatas => {
                    post_graph_data_events =
                        serde_json::from_value(serde_json::Value::Array(value_vec.clone()))?;
                }
            };
        }
    }
    info!(
        "get user init withdraw events: {}, cancel withdraw events: {}, proceed_withdraw_events: {}, \
         withdraw_paths_events: {},  withdraw_disproved_events: {}, bridge_in_request_events: {}  \
         committee_response_events: {}, bridge_in_events: {}  post_graph_data_events: {} block range {from_height}:{to_height}",
        init_withdraw_events.len(),
        cancel_withdraw_events.len(),
        proceed_withdraw_events.len(),
        withdraw_paths_events.len(),
        withdraw_disproved_events.len(),
        bridge_in_request_events.len(),
        committee_response_events.len(),
        bridge_in_events.len(),
        post_graph_data_events.len(),
    );
    handle_user_withdraw_events(storage_processor, init_withdraw_events, cancel_withdraw_events)
        .await?;
    handle_proceed_withdraw_events(actor.clone(), storage_processor, proceed_withdraw_events)
        .await?;
    handle_withdraw_paths_events(storage_processor, withdraw_paths_events).await?;
    handle_withdraw_disproved_events(storage_processor, withdraw_disproved_events).await?;
    handle_bridge_in_request_events(storage_processor, bridge_in_request_events).await?;
    handle_committee_response_events(storage_processor, committee_response_events).await?;
    handle_bridge_in_events(
        storage_processor,
        btc_client.clone(),
        goat_client.clone(),
        bridge_in_events,
    )
    .await?;
    handle_post_graph_data_events(storage_processor, post_graph_data_events).await?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub async fn fetch_and_handle_bridge_out_events<'a>(
    goat_client: Arc<GOATClient>,
    client: &GraphQueryClient,
    storage_processor: &mut StorageProcessor<'a>,
    contract_addr: &EvmAddress,
    graph_url: &str,
    event_entities: &[SwapEventEntity],
    from_height: i64,
    to_height: i64,
) -> anyhow::Result<()> {
    let query_res = client
        .execute_query(
            graph_url,
            &get_bridge_out_events_query(
                event_entities,
                Some(BlockRange::new(from_height, to_height)),
            ),
        )
        .await?;
    for event_entity in event_entities {
        let entity = event_entity.clone();
        if let Some(value_vec) = query_res[entity.to_string()].as_array() {
            match entity {
                SwapEventEntity::Initializes => {
                    handle_swap_init_events(
                        storage_processor,
                        goat_client.clone(),
                        contract_addr,
                        serde_json::from_value::<Vec<SwapInitializeEvent>>(
                            serde_json::Value::Array(value_vec.clone()),
                        )?,
                    )
                    .await?;
                }
                SwapEventEntity::Claims => {
                    handle_swap_claim_events(
                        storage_processor,
                        goat_client.clone(),
                        contract_addr,
                        serde_json::from_value::<Vec<SwapClaimEvent>>(serde_json::Value::Array(
                            value_vec.clone(),
                        ))?,
                    )
                    .await?;
                }
                SwapEventEntity::Refunds => {
                    handle_swap_refund_events(
                        storage_processor,
                        serde_json::from_value::<Vec<SwapRefundEvent>>(serde_json::Value::Array(
                            value_vec.clone(),
                        ))?,
                    )
                    .await?;
                }
            };
        }
    }
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
                let instance_id = Uuid::from_str(&strip_hex_prefix_owned(&init_event.instance_id))?;
                let graph_id = Uuid::from_str(&strip_hex_prefix_owned(&init_event.graph_id))?;
                storage_processor
                    .update_graph(
                        &GraphUpdate::new(graph_id)
                            .with_bridge_out_start_at(current_time_secs())
                            .with_init_withdraw_tx_hash(init_event.transaction_hash.clone()),
                    )
                    .await?;
                storage_processor
                    .upsert_goat_tx_record(&GoatTxRecord {
                        instance_id,
                        graph_id,
                        tx_type: GoatTxType::InitWithdraw.to_string(),
                        tx_hash: init_event.transaction_hash,
                        height: init_event.block_number.parse::<i64>()?,
                        is_local: false,
                        processing_status: GoatTxProcessingStatus::Pending.to_string(),
                        extra: None,
                        created_at: current_time_secs(),
                    })
                    .await?
            }
            UserGraphWithdrawEvent::CancelWithdraw(cancel_event) => {
                let instance_id =
                    Uuid::from_str(&strip_hex_prefix_owned(&cancel_event.instance_id))?;
                let graph_id = Uuid::from_str(&strip_hex_prefix_owned(&cancel_event.graph_id))?;
                storage_processor
                    .update_graph(
                        &GraphUpdate::new(graph_id)
                            .with_bridge_out_start_at(0)
                            .with_init_withdraw_tx_hash("".to_string()),
                    )
                    .await?;
                storage_processor
                    .upsert_goat_tx_record(&GoatTxRecord {
                        instance_id,
                        graph_id,
                        tx_type: GoatTxType::CancelWithdraw.to_string(),
                        tx_hash: cancel_event.transaction_hash,
                        height: cancel_event.block_number.parse::<i64>()?,
                        is_local: false,
                        processing_status: GoatTxProcessingStatus::Skipped.to_string(),
                        extra: None,
                        created_at: current_time_secs(),
                    })
                    .await?
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
        let graph_id = Uuid::from_str(&strip_hex_prefix_owned(&event.graph_id))?;
        let instance_id = Uuid::from_str(&strip_hex_prefix_owned(&event.instance_id))?;
        storage_processor
            .upsert_goat_tx_record(&GoatTxRecord {
                instance_id,
                graph_id,
                tx_type: GoatTxType::ProceedWithdraw.to_string(),
                tx_hash: event.transaction_hash,
                height: event.block_number.parse::<i64>()?,
                is_local: false,
                processing_status: processing_status.clone(),
                extra: None,
                created_at: current_time_secs(),
            })
            .await?;
        // for history events
        storage_processor
            .update_goat_tx_record_processing_status(
                &graph_id,
                &instance_id,
                &GoatTxType::InitWithdraw.to_string(),
                &GoatTxProcessingStatus::Processed.to_string(),
            )
            .await?;
    }
    Ok(())
}

async fn handle_withdraw_paths_events<'a>(
    storage_processor: &mut StorageProcessor<'a>,
    withdraw_paths_events: Vec<WithdrawPathsEvent>,
) -> anyhow::Result<()> {
    for event in withdraw_paths_events {
        let reward_add: i64 = event.reward_amount_sats();
        let (flag, goat_addr) = reflect_goat_address(Some(event.operator_addr()));
        if !flag {
            warn!(
                "handle_withdraw_paths_events failed as cast operator address failed, detail: {}, {}",
                event.tx_hash(),
                event.operator_addr()
            );
            continue;
        }
        storage_processor.add_node_reward_by_addr(&goat_addr.unwrap(), reward_add).await?;
        let (graph_id, instance_id, tx_type, status) = match event.clone() {
            WithdrawPathsEvent::WithdrawHappyEvent(v) => (
                v.graph_id.clone(),
                v.instance_id.clone(),
                GoatTxType::WithdrawHappyPath.to_string(),
                GraphStatus::OperatorTake1.to_string(),
            ),
            WithdrawPathsEvent::WithdrawUnhappyEvent(v) => (
                v.graph_id.clone(),
                v.instance_id.clone(),
                GoatTxType::WithdrawUnhappyPath.to_string(),
                GraphStatus::OperatorTake2.to_string(),
            ),
        };
        let graph_id = Uuid::from_str(&strip_hex_prefix_owned(&graph_id))?;
        let instance_id = Uuid::from_str(&strip_hex_prefix_owned(&instance_id))?;
        storage_processor
            .upsert_goat_tx_record(&GoatTxRecord {
                instance_id,
                graph_id,
                tx_type,
                tx_hash: event.tx_hash(),
                height: event.get_block_number(),
                is_local: false,
                processing_status: GoatTxProcessingStatus::Pending.to_string(),
                extra: None,
                created_at: current_time_secs(),
            })
            .await?;
        storage_processor.update_graph(&GraphUpdate::new(graph_id).with_status(status)).await?;
    }
    Ok(())
}

async fn handle_withdraw_disproved_events<'a>(
    storage_processor: &mut StorageProcessor<'a>,
    withdraw_disproved_events: Vec<WithdrawDisprovedEvent>,
) -> anyhow::Result<()> {
    for event in withdraw_disproved_events {
        let graph_id = Uuid::from_str(&strip_hex_prefix_owned(&event.graph_id))?;
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
        storage_processor
            .update_graph(
                &GraphUpdate::new(graph_id).with_status(GraphStatus::Disprove.to_string()),
            )
            .await?;
    }
    Ok(())
}

async fn handle_bridge_in_request_events<'a>(
    storage_processor: &mut StorageProcessor<'a>,
    bridge_in_request_events: Vec<BridgeInRequestEvent>,
) -> anyhow::Result<()> {
    for event in bridge_in_request_events {
        storage_processor
            .upsert_goat_tx_record(&GoatTxRecord {
                instance_id: Uuid::from_str(&strip_hex_prefix_owned(&event.instance_id))?,
                graph_id: Uuid::nil(),
                tx_type: GoatTxType::BridgeInRequest.to_string(),
                tx_hash: event.transaction_hash.clone(),
                height: event.block_number.parse::<i64>()?,
                is_local: false,
                processing_status: GoatTxProcessingStatus::Pending.to_string(),
                extra: Some(serde_json::to_string(&event)?),
                created_at: current_time_secs(),
            })
            .await?;
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
            if let Ok(pubkey_bytes) = hex::decode(&event.committee_pubkey) {
                if pubkey_bytes.len() == 33 {
                    let mut pubkey = [0u8; 33];
                    pubkey.copy_from_slice(&pubkey_bytes);
                    storage_processor
                        .update_instance_committee_answer(
                            instance_id,
                            &event.committee_address,
                            pubkey.to_vec(),
                        )
                        .await?;
                } else {
                    warn!("committee_pubkey length is not 32 bytes: {}", event.committee_pubkey);
                }
            } else {
                warn!("failed to decode committee_pubkey: {}", event.committee_pubkey);
            }
        } else {
            warn!("failed to parse instance id:{event:?}");
        }
    }
    Ok(())
}

async fn handle_bridge_in_events<'a>(
    storage_processor: &mut StorageProcessor<'a>,
    btc_client: Arc<BTCClient>,
    goat_client: Arc<GOATClient>,
    bridge_in_events: Vec<BridgeInEvent>,
) -> anyhow::Result<()> {
    for event in bridge_in_events {
        if let Ok(instance_id) = &Uuid::from_str(&strip_hex_prefix_owned(&event.instance_id)) {
            if !storage_processor
                .update_instance_status(
                    instance_id,
                    &InstanceBridgeInStatus::RelayerL2Minted.to_string(),
                )
                .await?
                && let Some(tx_record) = storage_processor
                    .get_graph_goat_tx_record(
                        instance_id,
                        &Uuid::nil(),
                        &GoatTxType::BridgeInRequest.to_string(),
                    )
                    .await?
            {
                // it will happened when handle history events
                warn!("Instance {instance_id} is finished but not find in db. we will create it");
                if let Some(extra) = tx_record.extra.as_ref()
                    && let Ok(bridge_event) = serde_json::from_str::<BridgeInRequestEvent>(extra)
                    && let Ok((mut instance, _)) = generate_instance_from_bridge_in_request_event(
                        btc_client.as_ref(),
                        goat_client.as_ref(),
                        &bridge_event,
                        false,
                    )
                    .await
                {
                    info!("Instance {instance_id} is created and set status to RelayerL2Minted");
                    instance.status = InstanceBridgeInStatus::RelayerL2Minted.to_string();
                    storage_processor.upsert_instance(&instance).await?;
                }

                if tx_record.processing_status == GoatTxProcessingStatus::Pending.to_string() {
                    info!(
                        "Instance {instance_id} related goat tx BridgeInRequest set event processing status skipped"
                    );
                    storage_processor
                        .update_goat_tx_record_processing_status(
                            &Uuid::nil(),
                            instance_id,
                            &GoatTxType::BridgeInRequest.to_string(),
                            &GoatTxProcessingStatus::Skipped.to_string(),
                        )
                        .await?;
                }
            }
        } else {
            warn!("failed to parse instance id:{event:?}");
        }
    }
    Ok(())
}

async fn handle_swap_init_events<'a>(
    storage_processor: &mut StorageProcessor<'a>,
    goat_client: Arc<GOATClient>,
    swap_contract_address: &EvmAddress,
    init_events: Vec<SwapInitializeEvent>,
) -> anyhow::Result<()> {
    for event in init_events {
        if let Some(escrow_data) = extract_escrow_data_from_tx(
            &goat_client,
            &event.transaction_hash,
            swap_contract_address,
            &hex::decode(strip_hex_prefix_owned(&event.escrow_hash))?.try_into().map_err(
                |v: Vec<u8>| anyhow::anyhow!("escrow_hash length is {}, expected 32", v.len()),
            )?,
        )
        .await?
        {
            // block_timestamp, instance_id, escrow_hash, goat_txid, amount
            info!(
                "{}, {},{}",
                event.escrow_hash,
                escrow_data.offerer.to_string(),
                escrow_data.claimer.to_string()
            );
            let create_time = event.block_timestamp.parse::<i64>()?;
            let instance_id = Uuid::new_v4();
            storage_processor
                .upsert_goat_tx_record(&GoatTxRecord {
                    instance_id,
                    graph_id: Uuid::nil(),
                    tx_type: GoatTxType::SwapInitialize.to_string(),
                    tx_hash: event.transaction_hash.clone(),
                    height: event.block_number.parse::<i64>()?,
                    is_local: false,
                    processing_status: GoatTxProcessingStatus::Skipped.to_string(),
                    extra: Some(hex::encode(escrow_data.abi_encode())),
                    created_at: create_time,
                })
                .await?;
            storage_processor
                .upsert_instance(&Instance {
                    instance_id,
                    is_bridge_in: false,
                    network: get_network().to_string(),
                    from_addr: escrow_data.offerer.to_string(),
                    to_addr: "".to_string(),
                    amount: escrow_data.amount.to::<i64>(),
                    fees: Default::default(),
                    input_utxos: "[]".to_string(),
                    status: InstanceBridgeOutStatus::Initialize.to_string(),
                    goat_tx_hash: event.transaction_hash.clone(),
                    goat_tx_height: event.block_number.parse::<i64>()?,
                    user_xonly_pubkey: Default::default(),
                    user_change_addr: escrow_data.claimer.to_string(),
                    user_refund_addr: escrow_data.offerer.to_string(),
                    btc_txid: None,
                    btc_height: 0,
                    pegin_confirm_txid: None,
                    pegin_cancel_txid: None,
                    committees_answers: Default::default(),
                    pegin_data_tx_hash: "".to_string(),
                    parameters: None,
                    escrow_hash: Some(event.escrow_hash.clone()),
                    status_updated_at: create_time,
                    created_at: create_time,
                    updated_at: create_time,
                })
                .await?;
        }
    }
    Ok(())
}

async fn handle_swap_claim_events<'a>(
    storage_processor: &mut StorageProcessor<'a>,
    goat_client: Arc<GOATClient>,
    swap_contract_address: &EvmAddress,
    claim_events: Vec<SwapClaimEvent>,
) -> anyhow::Result<()> {
    for event in claim_events {
        if let Some(claim_data) = extract_claim_data_from_tx(
            &goat_client,
            &event.transaction_hash,
            swap_contract_address,
            &hex::decode(strip_hex_prefix_owned(&event.escrow_hash))?.try_into().map_err(
                |v: Vec<u8>| anyhow::anyhow!("escrow_hash length is {}, expected 32", v.len()),
            )?,
        )
        .await?
            && let (instances, size) = storage_processor
                .find_instances(
                    InstanceQuery::default()
                        .with_is_bridge_in(false)
                        .with_escrow_hash(event.escrow_hash.clone()),
                )
                .await?
            && size > 0
        {
            let instance_id = instances[0].instance_id;
            let to_addr = Address::from_script(
                bitcoin::Script::from_bytes(&claim_data.output_script),
                get_network(),
            )?;
            storage_processor
                .upsert_goat_tx_record(&GoatTxRecord {
                    instance_id,
                    graph_id: Uuid::nil(),
                    tx_type: GoatTxType::SwapClaim.to_string(),
                    tx_hash: event.transaction_hash.clone(),
                    height: event.block_number.parse::<i64>()?,
                    is_local: false,
                    processing_status: GoatTxProcessingStatus::Skipped.to_string(),
                    extra: Some(claim_data.witness),
                    created_at: current_time_secs(),
                })
                .await?;
            storage_processor
                .update_instance(
                    &InstanceUpdate::new_with_escrow_hash(event.escrow_hash.clone())
                        .with_status(InstanceBridgeOutStatus::Claim.to_string())
                        .with_btc_txid(claim_data.txid.into())
                        .with_to_addr(to_addr.to_string()),
                )
                .await?;
        }
    }
    Ok(())
}

async fn handle_swap_refund_events<'a>(
    storage_processor: &mut StorageProcessor<'a>,
    refund_events: Vec<SwapRefundEvent>,
) -> anyhow::Result<()> {
    for event in refund_events {
        storage_processor
            .update_instance(
                &InstanceUpdate::new_with_escrow_hash(event.escrow_hash.clone())
                    .with_status(InstanceBridgeOutStatus::Refund.to_string()),
            )
            .await?;
    }
    Ok(())
}

pub(super) async fn generate_instance_from_bridge_in_request_event(
    btc_client: &BTCClient,
    goat_client: &GOATClient,
    event: &BridgeInRequestEvent,
    is_check_utxos: bool,
) -> anyhow::Result<(Instance, bool)> {
    let mut input_utxo_available = true;
    let instance_id = Uuid::from_str(&strip_hex_prefix_owned(&event.instance_id))?;
    let pegin_data = goat_client.gateway_get_pegin_data(&instance_id).await?;
    let inputs: Vec<Input> = pegin_data
        .user_inputs
        .iter()
        .map(|u| Input {
            outpoint: OutPoint { txid: Txid::from_byte_array(u.txid), vout: u.vout },
            amount: Amount::from_sat(u.amount_sats),
        })
        .collect();

    if is_check_utxos {
        for input in &inputs {
            if !outpoint_available(btc_client, &input.outpoint.txid, input.outpoint.vout.into())
                .await?
            {
                input_utxo_available = false;
                break;
            }
        }
    }

    let user_change_address: Address<NetworkUnchecked> =
        Address::from_str(&event.user_change_address)?;
    let user_refund_addr: Address<NetworkUnchecked> =
        Address::from_str(&event.user_refund_address)?;
    let network = get_network();
    let user_info = UserInfo {
        depositor_evm_address: EvmAddress::from_str(&event.depositor_address)?.into_array(),
        txn_fees: event.txn_fees.clone().map(|s| s.parse::<u64>().unwrap_or(0)),
        inputs,
        user_xonly_pubkey: XOnlyPublicKey::from_str(&strip_hex_prefix_owned(
            &event.user_xonly_pubkey,
        ))?,
        user_change_address: user_change_address.require_network(network)?,
        user_refund_address: user_refund_addr.require_network(network)?,
    };
    let instance = generate_instance(
        btc_client,
        GenerateInstanceParams {
            instance_id,
            user_info,
            pegin_amount: Amount::from_sat(event.pegin_amount_sats.parse::<u64>().unwrap_or(0)),
            pegin_request_tx_hash: event.transaction_hash.clone(),
            pegin_request_height: event.block_number.parse::<i64>().unwrap_or(0),
            pegin_timestamp: event.block_timestamp.parse::<i64>().unwrap_or(current_time_secs()),
        },
    )
    .await?;
    Ok((instance, input_utxo_available))
}
async fn handle_post_graph_data_events<'a>(
    storage_processor: &mut StorageProcessor<'a>,
    post_graph_data_events: Vec<PostGraphDataEvent>,
) -> anyhow::Result<()> {
    for event in post_graph_data_events {
        if let Ok(graph_id) = Uuid::from_str(&strip_hex_prefix_owned(&event.graph_id)) {
            storage_processor
                .update_graph(
                    &GraphUpdate::new(graph_id)
                        .with_status(GraphStatus::OperatorDataPushed.to_string()),
                )
                .await?;
        } else {
            warn!("failed to parse instance id:{event:?}");
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub async fn fetch_history_events(
    actor: Actor,
    btc_client: Arc<BTCClient>,
    goat_client: Arc<GOATClient>,
    local_db: &LocalDB,
    query_client: &GraphQueryClient,
    watch_contract: WatchContract,
    watch_events_config: WatchEventConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    let task_name = watch_events_config.get_watch_contract_type().to_string();
    info!("Start into fetch_history_events from:{} for {task_name}", watch_contract.from_height);
    // let goat_client = GOATClient::new(env::goat_config_from_env().await, env::get_goat_network());
    let mut watch_contract = watch_contract.clone();
    let local_db_clone = local_db.clone();
    let contract_addr = watch_contract.contract_addr.clone();
    let async_fn = || async move {
        let task_name = watch_events_config.get_watch_contract_type().to_string();
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
                    "Contract {task_name} fetch history events will finish, as current finalize height: {current_finalized} is litter than watch from height: {}",
                    watch_contract.from_height,
                );
                continue;
            }

            let to_height = current_finalized.min(watch_contract.from_height + watch_contract.gap);
            let mut tx = local_db.start_transaction().await?;

            fetch_and_handle_block_range_events(
                actor.clone(),
                btc_client.clone(),
                goat_client.clone(),
                query_client,
                &mut tx,
                &watch_events_config,
                watch_contract.from_height,
                to_height,
            )
            .await?;
            info!(
                "Contract {task_name} finish load history event from: {}, to: {to_height}",
                watch_contract.from_height
            );
            watch_contract.from_height = to_height + 1;
            watch_contract.status = WatchContractStatus::Syncing.to_string();
            watch_contract.updated_at = current_time_secs();

            if to_height >= current_finalized {
                info!("Contract {task_name} Finish load history at {to_height}");
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
            warn!("{task_name} fetch_history_events failed,err:{:?}", err);
            true
        }
    };
    if err {
        let mut storage_processor = local_db_clone.acquire().await?;
        let _ = storage_processor
            .update_watch_contract_status(
                &contract_addr,
                &WatchContractStatus::Failed.to_string(),
                current_time_secs(),
            )
            .await;
    }
    Ok(())
}

pub async fn monitor_events(
    actor: Actor,
    btc_client: Arc<BTCClient>,
    goat_client: Arc<GOATClient>,
    local_db: &LocalDB,
    watch_configs: Vec<WatchEventConfig>,
) -> anyhow::Result<()> {
    for watch_config in watch_configs {
        if watch_config.get_watch_events_len() == 0 {
            continue;
        }
        monitor_events_item(
            actor.clone(),
            btc_client.clone(),
            goat_client.clone(),
            local_db,
            watch_config,
        )
        .await?;
    }

    Ok(())
}

pub async fn monitor_events_item(
    actor: Actor,
    btc_client: Arc<BTCClient>,
    goat_client: Arc<GOATClient>,
    local_db: &LocalDB,
    watch_events_config: WatchEventConfig,
) -> anyhow::Result<()> {
    info!("start tick monitor_events");
    let mut storage_processor = local_db.acquire().await?;
    let mut watch_contract = get_watch_contract(
        &mut storage_processor,
        &watch_events_config.get_watch_contract().to_string(),
        watch_events_config.get_watch_contract_type(),
    )
    .await?;
    let query_client = GraphQueryClient::new();
    let current_finalized = goat_client.get_finalized_block_number().await?;

    if watch_contract.from_height == 0 || watch_contract.from_height >= current_finalized {
        warn!(
            "watch_contract start height is zero or bigger than current height, not do watch jobs"
        );
        return Ok(());
    }
    if watch_contract.status == WatchContractStatus::Syncing.to_string()
        && watch_contract.updated_at + LOAD_HISTORY_EVENT_NO_WOKING_MAX_SECS > current_time_secs()
    {
        info!("Event sync not finished ");
        return Ok(());
    }
    if watch_contract.from_height + watch_contract.gap < current_finalized {
        let watch_contract_clone = watch_contract.clone();
        let local_db_clone = local_db.clone();
        let query_client_clone = query_client.clone();
        let watch_events_config_clone = watch_events_config.clone();
        tokio::spawn(async move {
            let _ = fetch_history_events(
                actor.clone(),
                btc_client.clone(),
                goat_client,
                &local_db_clone,
                &query_client_clone,
                watch_contract_clone,
                watch_events_config_clone,
            )
            .await;
        });
        return Ok(());
    }

    let to_height = current_finalized.min(watch_contract.from_height + watch_contract.gap);
    let mut tx = local_db.start_transaction().await?;
    fetch_and_handle_block_range_events(
        actor.clone(),
        btc_client,
        goat_client,
        &query_client,
        &mut tx,
        &watch_events_config,
        watch_contract.from_height,
        to_height,
    )
    .await?;
    info!("finish monitor event from: {}, to: {to_height}", watch_contract.from_height);
    watch_contract.from_height = to_height + 1;
    watch_contract.status = WatchContractStatus::Synced.to_string();
    watch_contract.updated_at = current_time_secs();
    tx.upsert_watch_contract(&watch_contract).await?;
    tx.commit().await?;
    Ok(())
}

pub async fn run_watch_event_task(
    actor: Actor,
    local_db: LocalDB,
    btc_client: Arc<BTCClient>,
    goat_client: Arc<GOATClient>,
    interval: u64,
    cancellation_token: CancellationToken,
) -> anyhow::Result<String> {
    let gateway_contract: EvmAddress = get_goat_address_from_env(ENV_GOAT_GATEWAY_CONTRACT_ADDRESS)
        .ok_or(anyhow::anyhow!("need to set gateway contract address"))?;
    let swap_contract: EvmAddress = get_goat_address_from_env(ENV_GOAT_SWAP_CONTRACT_ADDRESS)
        .ok_or(anyhow::anyhow!("need to set swap contract address"))?;
    let events_map: HashMap<Actor, Vec<WatchEventConfig>> = HashMap::from([
        (
            Actor::Committee,
            vec![
                WatchEventConfig::Gateway(TheGraphConfig {
                    address: gateway_contract,
                    the_graph_url: get_goat_gateway_the_graph_urls_from_env(),
                    event_entities: vec![
                        GatewayEventEntity::InitWithdraws,
                        GatewayEventEntity::CancelWithdraws,
                        GatewayEventEntity::ProceedWithdraws,
                        GatewayEventEntity::WithdrawHappyPaths,
                        GatewayEventEntity::WithdrawUnhappyPaths,
                        GatewayEventEntity::WithdrawDisproveds,
                        GatewayEventEntity::BridgeInRequests,
                        GatewayEventEntity::BridgeIns,
                        GatewayEventEntity::PostGraphDatas,
                    ],
                }),
                WatchEventConfig::Swap(TheGraphConfig {
                    address: swap_contract,
                    the_graph_url: get_goat_swap_the_graph_urls_from_env(),
                    event_entities: vec![
                        SwapEventEntity::Initializes,
                        SwapEventEntity::Claims,
                        SwapEventEntity::Refunds,
                    ],
                }),
            ],
        ),
        (
            Actor::Operator,
            vec![WatchEventConfig::Gateway(TheGraphConfig {
                address: gateway_contract,
                the_graph_url: get_goat_gateway_the_graph_urls_from_env(),
                event_entities: vec![
                    GatewayEventEntity::InitWithdraws,
                    GatewayEventEntity::CancelWithdraws,
                    GatewayEventEntity::ProceedWithdraws,
                    GatewayEventEntity::WithdrawHappyPaths,
                    GatewayEventEntity::WithdrawUnhappyPaths,
                    GatewayEventEntity::WithdrawDisproveds,
                    GatewayEventEntity::BridgeInRequests,
                    GatewayEventEntity::BridgeIns,
                    GatewayEventEntity::PostGraphDatas,
                ],
            })],
        ),
        (
            Actor::Challenger,
            vec![WatchEventConfig::Gateway(TheGraphConfig {
                address: gateway_contract,
                the_graph_url: get_goat_gateway_the_graph_urls_from_env(),
                event_entities: vec![
                    GatewayEventEntity::InitWithdraws,
                    GatewayEventEntity::CancelWithdraws,
                    GatewayEventEntity::ProceedWithdraws,
                    GatewayEventEntity::WithdrawHappyPaths,
                    GatewayEventEntity::WithdrawUnhappyPaths,
                    GatewayEventEntity::WithdrawDisproveds,
                    GatewayEventEntity::BridgeInRequests,
                    GatewayEventEntity::BridgeIns,
                    GatewayEventEntity::PostGraphDatas,
                ],
            })],
        ),
        (
            Actor::Watchtower,
            vec![WatchEventConfig::Gateway(TheGraphConfig {
                address: gateway_contract,
                the_graph_url: get_goat_gateway_the_graph_urls_from_env(),
                event_entities: vec![
                    GatewayEventEntity::InitWithdraws,
                    GatewayEventEntity::CancelWithdraws,
                    GatewayEventEntity::ProceedWithdraws,
                    GatewayEventEntity::WithdrawHappyPaths,
                    GatewayEventEntity::WithdrawUnhappyPaths,
                    GatewayEventEntity::WithdrawDisproveds,
                    GatewayEventEntity::BridgeInRequests,
                    GatewayEventEntity::BridgeIns,
                    GatewayEventEntity::PostGraphDatas,
                ],
            })],
        ),
    ]);
    loop {
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_secs(interval)) => {
                // Execute the normal monitoring logic
                match monitor_events(
                        actor.clone(),
                        btc_client.clone(),
                        goat_client.clone(),
                        &local_db,
                       events_map.get(&actor).cloned().unwrap_or_default(),
                    )
                    .await
                    {
                        Ok(_) => {}
                        Err(e) => {
                            warn!("fail to monitor events: {e}");
                        }
                    }
            }
            _ = cancellation_token.cancelled() => {
                info!("Watch event task received shutdown signal");
                return Ok("watch_shutdown".to_string());
            }
        }
    }
}

async fn get_watch_contract<'a>(
    storage_processor: &mut StorageProcessor<'a>,
    contract_addr: &str,
    contract_type: WatchContractType,
) -> anyhow::Result<WatchContract> {
    let (from_height, the_graph_url, gap) = match contract_type {
        WatchContractType::Gateway => (
            get_goat_gateway_event_filter_from_from_env(),
            get_goat_gateway_the_graph_urls_from_env(),
            get_goat_gateway_event_filter_gap_from_env(),
        ),
        WatchContractType::Swap => (
            get_goat_swap_event_filter_from_from_env(),
            get_goat_swap_the_graph_urls_from_env(),
            get_goat_swap_event_filter_gap_from_env(),
        ),
    };

    if let Some(mut watch_contract) = storage_processor.get_watch_contract(contract_addr).await? {
        if from_height > watch_contract.from_height {
            watch_contract.from_height = from_height;
        }
        if the_graph_url != watch_contract.the_graph_url {
            watch_contract.the_graph_url = the_graph_url;
        }

        if gap != watch_contract.gap {
            watch_contract.gap = gap
        }
        Ok(watch_contract)
    } else {
        Ok(WatchContract {
            contract_addr: contract_addr.to_string(),
            the_graph_url,
            gap,
            from_height,
            status: WatchContractStatus::UnSync.to_string(),
            extra: None,
            updated_at: current_time_secs(),
            created_at: current_time_secs(),
        })
    }
}

pub async fn is_processing_gateway_history_events(
    local_db: &LocalDB,
    goat_client: &GOATClient,
) -> anyhow::Result<bool> {
    let gateway_contract: EvmAddress = get_goat_address_from_env(ENV_GOAT_GATEWAY_CONTRACT_ADDRESS)
        .ok_or(anyhow::anyhow!("need to set gateway contract address"))?;
    let mut storage_processor = local_db.acquire().await?;
    let current_finalized = goat_client.get_finalized_block_number().await?;
    let watch_contract = get_watch_contract(
        &mut storage_processor,
        &gateway_contract.to_string(),
        WatchContractType::Gateway,
    )
    .await?;
    Ok(watch_contract.from_height + watch_contract.gap < current_finalized
        || watch_contract.status == WatchContractStatus::Syncing.to_string())
}
