use crate::action::{ConfirmInstance, GOATMessageContent, PeginRequest, PostReady};
use crate::env::INSTANCE_PRESIGNED_TIME_EXPIRED;
use crate::rpc_service::current_time_secs;
use crate::utils::{gen_instance_parameters_local, upsert_message};
use bitvm2_lib::actors::Actor;
use bitvm2_lib::constants::CONNECTOR_Z_TIMELOCK;
use bitvm2_lib::transactions::base::BaseTransaction;
use client::btc_chain::BTCClient;
use client::goat_chain::GOATClient;
use client::graphs::graph_query::BridgeInRequestEvent;
use std::str::FromStr;
use store::localdb::{InstanceQuery, InstanceUpdate, LocalDB, StorageProcessor};
use store::{GoatTxProcessingStatus, GoatTxType, Instance, InstanceStatus};
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
pub async fn instance_answers_monitor(local_db: &LocalDB) -> anyhow::Result<()> {
    let tx_records = {
        let mut storage_processor = local_db.acquire().await?;
        storage_processor
            .get_goat_tx_record_by_processing_status(
                &GoatTxType::BridgeInRequest.to_string(),
                &GoatTxProcessingStatus::Pending.to_string(),
            )
            .await?
    };

    for tx_record in tx_records {
        let mut tx = local_db.start_transaction().await?;
        if let Some(event) = tx_record.extra {
            let _event: BridgeInRequestEvent = serde_json::from_str(&event)?;
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
                }),
                0,
                0,
            )
            .await?;
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
                    .with_status(InstanceStatus::UserInited.to_string())
                    .with_pegin_request_height_threshold(current_height - window_blocks)
                    .with_order("created_at DESC".to_string())
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
                    instance.status = InstanceStatus::CommitteesAnswered.to_string();
                } else {
                    instance.status = InstanceStatus::NoEnoughCommitteesAnswered.to_string();
                }

                let _ = update_pegin_txids(&mut instance);
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
                &InstanceStatus::CommitteesAnswered.to_string(),
                &InstanceStatus::PresignedFailed.to_string(),
                current_time - INSTANCE_PRESIGNED_TIME_EXPIRED,
            )
            .await?;
        info!("Presigned expired instances is {expired_num}");
        storage_processor
            .find_instances(
                InstanceQuery::default()
                    .with_is_bridge_in(true)
                    .with_status(InstanceStatus::PresignedFailed.to_string())
                    .with_order("created_at DESC".to_string())
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
                    .with_status(InstanceStatus::Timeout.to_string()),
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
                        InstanceStatus::CommitteesAnswered.to_string(),
                        InstanceStatus::Presigned.to_string(),
                        InstanceStatus::Timeout.to_string(),
                    ])
                    .with_offset(0)
                    .with_order("created_at DESC".to_string())
                    .with_limit(MAX_INSTANCE),
            )
            .await?
    };
    for instance in instances {
        let (tx_id_op, next_status) = match InstanceStatus::from_str(&instance.status) {
            Ok(status) => match status {
                InstanceStatus::CommitteesAnswered => {
                    (instance.btc_txid.clone(), InstanceStatus::UserBroadcastPeginPrepare)
                }
                InstanceStatus::Presigned => {
                    (instance.pegin_confirm_txid.clone(), InstanceStatus::RelayerL1Broadcasted)
                }
                InstanceStatus::Timeout => {
                    (instance.pegin_cancel_txid.clone(), InstanceStatus::UserCanceled)
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

        if tx_id_op.is_none() {
            warn!(
                "instance:{} status:{} get check tx id is none",
                instance.instance_id,
                instance.status.clone()
            );
            continue;
        }
        let tx_id = tx_id_op.unwrap().0;
        if let Ok(status) = btc_client.get_tx_status(&tx_id).await
            && status.confirmed
        {
            let mut tx = local_db.start_transaction().await?;
            let mut instance_update =
                InstanceUpdate::new(instance.instance_id).with_status(next_status.to_string());
            if next_status == InstanceStatus::UserBroadcastPeginPrepare {
                instance_update =
                    instance_update.with_btc_height(status.block_height.unwrap_or_default() as i64);

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
            if next_status == InstanceStatus::RelayerL1Broadcasted {
                upsert_message(
                    &mut tx,
                    false,
                    instance.instance_id,
                    None,
                    "self".to_string(),
                    Actor::All,
                    GOATMessageContent::PostReady(PostReady { instance_id: instance.instance_id }),
                    0,
                    0,
                )
                .await?;
            }

            update_instance(&mut tx, &instance_update).await?;
            tx.commit().await?;
        } else {
            warn!(
                "instance:{}, status{}, check tx_id:{} is not chain ",
                instance.instance_id,
                instance.status,
                tx_id.to_string()
            );
        }
    }
    Ok(())
}
