use crate::action::{ConfirmInstance, GOATMessageContent, PeginRequest, PostReady};
use crate::env::INSTANCE_PRESIGNED_TIME_EXPIRED;
use crate::rpc_service::current_time_secs;
use crate::scheduled_tasks::event_watch_task::generate_instance_from_bridge_in_request_event;
use crate::utils::{
    check_bridge_in_uxto_available_or_self_spent, gen_instance_parameters_local, upsert_message,
};
use bitvm2_lib::actors::Actor;
use bitvm2_lib::constants::CONNECTOR_Z_TIMELOCK;
use bitvm2_lib::transactions::base::BaseTransaction;
use client::Utxo;
use client::btc_chain::BTCClient;
use client::goat_chain::GOATClient;
use client::graphs::graph_query::BridgeInRequestEvent;
use std::str::FromStr;
use std::vec;
use store::localdb::{InstanceQuery, InstanceUpdate, LocalDB, StorageProcessor};
use store::{GoatTxProcessingStatus, GoatTxType, Instance, InstanceBridgeInStatus};
use tracing::{info, warn};

const MAX_INSTANCE: u32 = 50;

async fn update_instance<'a>(
    storage_processor: &mut StorageProcessor<'a>,
    params: &InstanceUpdate,
) -> anyhow::Result<()> {
    if let Err(err) = storage_processor.update_instance(params).await {
        warn!(
            "update_instance_status with input: {:?} failed {}, will try later",
            params,
            err.to_string()
        );
    } else {
        info!("update instance with input: {:?}", params);
    }
    Ok(())
}

/// for committee
pub async fn instance_answers_monitor(
    local_db: &LocalDB,
    btc_client: &BTCClient,
    goat_client: &GOATClient,
) -> anyhow::Result<()> {
    let tx_records = {
        let mut storage_processor = local_db.acquire().await?;
        storage_processor
            .get_goat_tx_record_by_processing_status(
                &GoatTxType::BridgeInRequest.to_string(),
                &GoatTxProcessingStatus::Pending.to_string(),
            )
            .await?
    };
    let current_height = goat_client.get_finalized_block_number().await?;
    let response_window_blocks = goat_client.gateway_get_response_window_blocks().await? as i64;
    for tx_record in tx_records {
        let mut tx = local_db.start_transaction().await?;
        if let Some(event) = tx_record.extra {
            let event: BridgeInRequestEvent = serde_json::from_str(&event)?;
            if tx_record.height + response_window_blocks < current_height {
                info!(
                    "instance_answers_monitor: instance_id:{} BridgeInRequest is outside the response window",
                    tx_record.instance_id
                );

                if let Ok((mut instance, input_utxo_available)) =
                    generate_instance_from_bridge_in_request_event(
                        btc_client,
                        goat_client,
                        &event,
                        true,
                    )
                    .await
                    && !input_utxo_available
                {
                    info!(
                        "instance_answers_monitor: instance_id:{} BridgeInRequest is outside the response window and input utxos not available",
                        tx_record.instance_id
                    );
                    // for the case: if bridgeIn confirm is broadcast,but L2 not minted,
                    // instance status will been updated to L2Minted when normal finished
                    instance.status = InstanceBridgeInStatus::UserDiscarded.to_string();
                    tx.upsert_instance(&instance).await?;
                }
            } else {
                upsert_message(
                    &mut tx,
                    false,
                    tx_record.instance_id,
                    None,
                    "self".to_string(),
                    Actor::All,
                    GOATMessageContent::PeginRequest(PeginRequest {
                        instance_id: tx_record.instance_id,
                        pegin_request_tx_hash: tx_record.tx_hash,
                        pegin_request_height: tx_record.height,
                        pegin_timestamp: event
                            .block_timestamp
                            .parse::<i64>()
                            .unwrap_or_else(|_| current_time_secs()),
                    }),
                    0,
                    0,
                )
                .await?;
            }
        }

        tx.update_goat_tx_record_processing_status(
            &tx_record.graph_id,
            &tx_record.instance_id,
            &tx_record.tx_type,
            &GoatTxProcessingStatus::Processed.to_string(),
        )
        .await?;
        tx.commit().await?;
    }
    Ok(())
}

pub async fn instance_window_expiration_monitor(
    local_db: &LocalDB,
    goat_client: &GOATClient,
) -> anyhow::Result<()> {
    let window_blocks = goat_client.gateway_get_response_window_blocks().await? as i64;
    let current_height = goat_client.get_latest_block_number().await?;
    let (instances, _) = {
        let mut storage_processor = local_db.acquire().await?;
        storage_processor
            .find_instances(
                InstanceQuery::default()
                    .with_is_bridge_in(true)
                    .with_status(InstanceBridgeInStatus::UserInited.to_string())
                    .with_pegin_request_height_threshold(current_height - window_blocks)
                    .with_order("created_at ASC".to_string())
                    .with_offset(0)
                    .with_limit(MAX_INSTANCE),
            )
            .await?
    };

    let committee_quorum_size = goat_client.committee_mana_quorum_size().await?;
    for mut instance in instances {
        match goat_client.gateway_get_pegin_data(&instance.instance_id).await {
            Ok(pegin_data) => {
                for (committee_addr, pubkey) in
                    pegin_data.committee_addresses.iter().zip(pegin_data.committee_pubkeys)
                {
                    instance
                        .committees_answers
                        .entry(committee_addr.to_string())
                        .and_modify(|existing| {
                            *existing = pubkey.clone();
                        })
                        .or_insert_with(|| pubkey);
                }

                if committee_quorum_size <= instance.committees_answers.len() as u64 {
                    instance.status = InstanceBridgeInStatus::CommitteesAnswered.to_string();
                    if let Err(err) = update_pegin_txids(&mut instance) {
                        warn!(
                            "instance_window_expiration_monitor fail to update_pegin_txids for instance {}, err: {:?}",
                            instance.instance_id, err
                        );
                    }
                } else {
                    instance.status =
                        InstanceBridgeInStatus::NoEnoughCommitteesAnswered.to_string();
                }
                let mut storage_processor = local_db.acquire().await?;
                if let Err(err) = storage_processor.upsert_instance(&instance).await {
                    warn!(
                        "failed to upsert instance {}, err: {}",
                        instance.instance_id,
                        err.to_string()
                    );
                }
            }
            Err(err) => {
                warn!(
                    "failed to get pegin data for instance {}, err: {}",
                    instance.instance_id,
                    err.to_string()
                );
            }
        }
    }

    Ok(())
}

fn update_pegin_txids(instance: &mut Instance) -> anyhow::Result<()> {
    let (pegin_deposit_tx, pegin_confirm_tx, pegin_refund_tx) =
        gen_instance_parameters_local(instance)?.build_pegin_tx()?;
    instance.btc_txid = Some(pegin_deposit_tx.tx().compute_txid().into());
    instance.pegin_confirm_txid = Some(pegin_confirm_tx.finalize().compute_txid().into());
    instance.pegin_cancel_txid = Some(pegin_refund_tx.finalize().compute_txid().into());
    Ok(())
}

pub async fn instance_expiration_monitor(
    local_db: &LocalDB,
    btc_client: &BTCClient,
) -> anyhow::Result<()> {
    let current_time = current_time_secs();
    let current_height = btc_client.get_height().await? as i64;
    let (instances, _) = {
        let mut storage_processor = local_db.acquire().await?;
        let expired_num = storage_processor
            .update_expired_instance(
                &InstanceBridgeInStatus::UserBroadcastPeginPrepare.to_string(),
                &InstanceBridgeInStatus::PresignedFailed.to_string(),
                current_time - INSTANCE_PRESIGNED_TIME_EXPIRED,
            )
            .await?;
        info!("Presigned expired instances is {expired_num}");
        storage_processor
            .find_instances(
                InstanceQuery::default()
                    .with_is_bridge_in(true)
                    .with_statuses(vec![
                        InstanceBridgeInStatus::Presigned.to_string(),
                        InstanceBridgeInStatus::PresignedFailed.to_string(),
                    ])
                    .with_order("created_at ASC".to_string())
                    .with_offset(0)
                    .with_limit(MAX_INSTANCE),
            )
            .await?
    };

    let lock_height = CONNECTOR_Z_TIMELOCK as i64;
    let mut storage_processor = local_db.acquire().await?;
    for instance in instances {
        if instance.btc_height > 0 && current_height > instance.btc_height + lock_height {
            update_instance(
                &mut storage_processor,
                &InstanceUpdate::new(instance.instance_id)
                    .with_status(InstanceBridgeInStatus::Timeout.to_string()),
            )
            .await?;
        } else {
            info!("instance;{} not expired", instance.instance_id);
        }
    }
    Ok(())
}

/// prepare cancel confirmed
pub async fn instance_btc_tx_monitor(
    local_db: &LocalDB,
    btc_client: &BTCClient,
) -> anyhow::Result<()> {
    info!("check user broadcast Pegin-Prepare");

    let (instances, _) = {
        let mut storage_processor = local_db.acquire().await?;
        storage_processor
            .find_instances(
                InstanceQuery::default()
                    .with_is_bridge_in(true)
                    .with_statuses(vec![
                        InstanceBridgeInStatus::UserInited.to_string(),
                        InstanceBridgeInStatus::CommitteesAnswered.to_string(),
                        InstanceBridgeInStatus::Presigned.to_string(),
                        InstanceBridgeInStatus::Timeout.to_string(),
                    ])
                    .with_offset(0)
                    .with_order("created_at ASC".to_string())
                    .with_limit(MAX_INSTANCE),
            )
            .await?
    };
    for instance in instances {
        let (txid_op, next_status) = match InstanceBridgeInStatus::from_str(&instance.status) {
            Ok(status) => match status {
                InstanceBridgeInStatus::UserInited => {
                    (None, InstanceBridgeInStatus::CommitteesAnswered)
                }
                InstanceBridgeInStatus::CommitteesAnswered => {
                    (instance.btc_txid.clone(), InstanceBridgeInStatus::UserBroadcastPeginPrepare)
                }
                InstanceBridgeInStatus::Presigned => (
                    instance.pegin_confirm_txid.clone(),
                    InstanceBridgeInStatus::RelayerL1Broadcasted,
                ),
                InstanceBridgeInStatus::Timeout => {
                    (instance.pegin_cancel_txid.clone(), InstanceBridgeInStatus::UserCanceled)
                }
                _ => (None, status),
            },
            Err(err) => {
                warn!(
                    "failed to parse instance:{}, {} status: {}",
                    instance.instance_id,
                    instance.status,
                    err.to_string()
                );
                continue;
            }
        };
        if let Some(txid) = txid_op.clone()
            && let Ok(status) = btc_client.get_tx_status(&txid.0).await
            && status.confirmed
        {
            let mut tx = local_db.start_transaction().await?;
            let mut instance_update =
                InstanceUpdate::new(instance.instance_id).with_status(next_status.to_string());
            match next_status {
                InstanceBridgeInStatus::UserBroadcastPeginPrepare => {
                    instance_update = instance_update
                        .with_btc_height(status.block_height.unwrap_or_default() as i64);
                    upsert_message(
                        &mut tx,
                        false,
                        instance.instance_id,
                        None,
                        "self".to_string(),
                        Actor::All,
                        GOATMessageContent::ConfirmInstance(ConfirmInstance {
                            instance_id: instance.instance_id,
                        }),
                        0,
                        0,
                    )
                    .await?;
                }
                InstanceBridgeInStatus::RelayerL1Broadcasted => {
                    upsert_message(
                        &mut tx,
                        false,
                        instance.instance_id,
                        None,
                        "self".to_string(),
                        Actor::All,
                        GOATMessageContent::PostReady(PostReady {
                            instance_id: instance.instance_id,
                        }),
                        0,
                        0,
                    )
                    .await?;
                }
                _ => {}
            }
            update_instance(&mut tx, &instance_update).await?;
            tx.commit().await?;
        } else {
            warn!(
                "instance:{}, status{}, check tx_id:{:?} is not chain ",
                instance.instance_id, instance.status, txid_op
            );
            if [
                InstanceBridgeInStatus::UserInited,
                InstanceBridgeInStatus::UserBroadcastPeginPrepare,
            ]
            .contains(&next_status)
                && let utxos = serde_json::from_str::<Vec<Utxo>>(&instance.input_utxos)?
                && let Some(user_prepare_tx) = instance.btc_txid
                && !check_bridge_in_uxto_available_or_self_spent(
                    btc_client,
                    Some(user_prepare_tx.0.to_string()),
                    &utxos,
                )
                .await?
            {
                warn!(
                    "instance:{}, pegin prepare tx input utxos has been spent in other tx",
                    instance.instance_id
                );
                let mut storage_processor = local_db.acquire().await?;
                update_instance(
                    &mut storage_processor,
                    &InstanceUpdate::new(instance.instance_id)
                        .with_status(InstanceBridgeInStatus::UserDiscarded.to_string()),
                )
                .await?;
            }
        }
    }
    Ok(())
}
