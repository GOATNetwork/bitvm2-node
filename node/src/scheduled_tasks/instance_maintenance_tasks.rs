use crate::client::btc_chain::BTCClient;
use crate::client::goat_chain::GOATClient;
use crate::env;
use crate::env::{GRAPH_OPERATOR_DATA_UPLOAD_TIME_EXPIRED, INSTANCE_PRESIGNED_TIME_EXPIRED};
use crate::middleware::AllBehaviours;
use crate::rpc_service::current_time_secs;
use crate::utils::create_goat_tx_record;
use alloy::primitives::TxHash;
use anyhow::anyhow;
use bitcoin::consensus::encode::deserialize_hex;
use bitvm2_lib::keys::CommitteeMasterKey;
use libp2p::Swarm;
use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH};
use store::localdb::{InstanceQuery, LocalDB, StorageProcessor, UpdateGraphParams};
use store::{CommitteeSignatures, GoatTxProcessingStatus, GoatTxType, GraphStatus, InstanceStatus};
use tracing::{info, warn};
use uuid::Uuid;

const MAX_INSTANCE: u32 = 50;

async fn update_instance_status<'a>(
    storage_processor: &mut StorageProcessor<'a>,
    instance_id: &Uuid,
    status: InstanceStatus,
) -> anyhow::Result<()> {
    if let Err(err) =
        storage_processor.update_instance_status(instance_id, &status.to_string()).await
    {
        warn!("update_instance_status:{instance_id} failed {}, will try later", err.to_string());
    } else {
        info!("update instance;{instance_id} to state:{status}");
    }
    Ok(())
}

/// for committee
pub async fn instance_answers_monitor(
    local_db: &LocalDB,
    goat_client: &GOATClient,
) -> anyhow::Result<()> {
    let mut storage_processor = local_db.acquire().await?;
    let tx_records = storage_processor
        .get_goat_tx_record_by_processing_status(
            &GoatTxType::BridgeInRequest.to_string(),
            &GoatTxProcessingStatus::Pending.to_string(),
        )
        .await?;

    for tx_record in tx_records {
        let instance = storage_processor.find_instance(&tx_record.instance_id).await?;
        if instance.is_none() || instance.unwrap().status != InstanceStatus::UserInited.to_string()
        {
            info!("instance:{} is none or not in UserInited, skipping ", tx_record.instance_id);
            storage_processor
                .update_goat_tx_record_processing_status(
                    &tx_record.graph_id,
                    &tx_record.instance_id,
                    &tx_record.tx_type,
                    &GoatTxProcessingStatus::Skipped.to_string(),
                )
                .await?;
            continue;
        }

        let master_key =
            CommitteeMasterKey::new(env::get_bitvm_key().map_err(|e| anyhow!("{}", e))?);
        let (xonly_pubkey, _) =
            master_key.keypair_for_instance(tx_record.instance_id).x_only_public_key();

        match goat_client
            .answer_pegin_request(&tx_record.instance_id, &xonly_pubkey.serialize())
            .await
        {
            Ok(tx_hash) => {
                info!("finish answer pegin request at hash {tx_hash}");
                storage_processor
                    .update_goat_tx_record_processing_status(
                        &tx_record.graph_id,
                        &tx_record.instance_id,
                        &tx_record.tx_type,
                        &GoatTxProcessingStatus::Processed.to_string(),
                    )
                    .await?
            }
            Err(err) => {
                warn!("failed to answer pegin request: {}", err.to_string());
            }
        }
    }
    Ok(())
}

pub async fn instance_window_expiration_monitor(
    local_db: &LocalDB,
    goat_client: &GOATClient,
) -> anyhow::Result<()> {
    let window_blocks = goat_client.get_response_window_blocks().await? as i64;
    let current_height = goat_client.get_latest_block_number().await?;
    let mut storage_processor = local_db.acquire().await?;
    let (instances, _) = storage_processor
        .find_instances(
            InstanceQuery::default()
                .with_status(InstanceStatus::UserInited.to_string())
                .with_pegin_request_height_threshold(current_height - window_blocks)
                .with_offset(0)
                .with_limit(MAX_INSTANCE),
        )
        .await?;

    for mut instance in instances {
        match goat_client.get_pegin_data(&instance.instance_id).await {
            Ok(pegin_data) => {
                for (committee_addr, xonly_pubkey) in
                    pegin_data.committee_addresses.iter().zip(pegin_data.committee_xonly_pubkeys)
                {
                    instance
                        .committees_answers
                        .entry(committee_addr.to_string())
                        .and_modify(|existing| {
                            existing.xonly_pubkey = xonly_pubkey;
                        })
                        .or_insert_with(|| CommitteeSignatures {
                            xonly_pubkey,
                            l1_sig: None,
                            l2_sig: None,
                        });
                }

                if env::get_min_committee_number() <= instance.committees_answers.len() as u32 {
                    instance.status = InstanceStatus::CommitteesAnswered.to_string();
                }

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

pub async fn instance_expiration_monitor(local_db: &LocalDB) -> anyhow::Result<()> {
    let mut storage_processor = local_db.acquire().await?;
    let current_time = current_time_secs();
    let expired_num = storage_processor
        .update_expired_instance(
            &InstanceStatus::CommitteesAnswered.to_string(),
            &InstanceStatus::PresignedFailed.to_string(),
            current_time - INSTANCE_PRESIGNED_TIME_EXPIRED,
        )
        .await?;
    info!("Presigned expired instances is {expired_num}");
    let (instances, _) = storage_processor
        .find_instances(
            InstanceQuery::default()
                .with_status(InstanceStatus::PresignedFailed.to_string())
                .with_offset(0)
                .with_limit(MAX_INSTANCE),
        )
        .await?;

    for instance in instances {
        if current_time > instance.timeout {
            update_instance_status(
                &mut storage_processor,
                &instance.instance_id,
                InstanceStatus::Timeout,
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
    _swarm: &mut Swarm<AllBehaviours>,
    local_db: &LocalDB,
    btc_client: &BTCClient,
) -> anyhow::Result<()> {
    info!("check user broadcast Pegin-Prepare");
    let mut storage_processor = local_db.acquire().await?;
    let (instances, _) = storage_processor
        .find_instances(
            InstanceQuery::default()
                .with_statuses(vec![
                    InstanceStatus::CommitteesAnswered.to_string(),
                    InstanceStatus::Presigned.to_string(),
                    InstanceStatus::Timeout.to_string(),
                ])
                .with_offset(0)
                .with_limit(MAX_INSTANCE),
        )
        .await?;
    for instance in instances {
        let (tx_id_op, next_status) = match InstanceStatus::from_str(&instance.status) {
            Ok(status) => match status {
                InstanceStatus::CommitteesAnswered => {
                    (instance.pegin_prepare_txid, InstanceStatus::UserBroadcastPeginPrepare)
                }
                InstanceStatus::Presigned => {
                    (instance.pegin_confirm_txid, InstanceStatus::RelayerL1Broadcasted)
                }
                InstanceStatus::Timeout => {
                    (instance.pegin_cancel_txid, InstanceStatus::UserCanceled)
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
                instance.instance_id, instance.status
            );
            continue;
        }

        let tx_id = deserialize_hex(tx_id_op.unwrap().as_str())?;
        if let Ok(status) = btc_client.get_tx_status(&tx_id).await
            && status.confirmed
        {
            if next_status == InstanceStatus::UserBroadcastPeginPrepare {
                // todo notify user broadcast pegin prepare
            }

            update_instance_status(&mut storage_processor, &instance.instance_id, next_status)
                .await?;
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

pub async fn scan_post_pegin_data(
    _swarm: &mut Swarm<AllBehaviours>,
    local_db: &LocalDB,
    btc_client: &BTCClient,
    goat_client: &GOATClient,
) -> Result<(), Box<dyn std::error::Error>> {
    info!("Starting into post_pegin_data");
    let mut storage_process = local_db.acquire().await?;
    let (instances, _) = storage_process
        .find_instances(
            InstanceQuery::default()
                .with_statuses(vec![InstanceStatus::RelayerL1Broadcasted.to_string()]),
        )
        .await?;

    info!("Starting into scan post_pegin_data, need to send instance_size:{} ", instances.len());
    for instance in instances {
        if instance.pegin_confirm_txid.is_none() {
            warn!(
                "scan post_pegin_data instance:{}, pegin confirm txid is none",
                instance.instance_id
            );
            continue;
        }
        if let Ok(_tx_hash) = TxHash::from_str(&instance.pegin_data_txid) {
            let receipt_op = goat_client.get_tx_receipt(&instance.pegin_data_txid).await?;
            if receipt_op.is_none() {
                info!(
                    "scan post_pegin_data, instance_id: {}, goat_tx:{} finish send to chain \
                but get receipt status is false, will try later",
                    instance.instance_id, instance.pegin_data_txid
                );
                continue;
            }
            storage_process
                .update_instance_status(
                    &instance.instance_id,
                    &InstanceStatus::RelayerL2Minted.to_string(),
                )
                .await?;
        } else {
            let pegin_confirm_tx = btc_client
                .fetch_btc_tx(&deserialize_hex(&instance.pegin_confirm_txid.unwrap())?)
                .await?;
            match goat_client
                .post_pegin_data(btc_client, &instance.instance_id, &pegin_confirm_tx)
                .await
            {
                Err(err) => {
                    warn!(
                        "scan post_pegin_data instance id {}, tx:{} post_pegin_data failed err:{:?}",
                        instance.instance_id,
                        pegin_confirm_tx.compute_txid().to_string(),
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
                        GoatTxProcessingStatus::Skipped.to_string(),
                    )
                    .await?;

                    storage_process
                        .update_instance_pegin_data_txid(&instance.instance_id, &tx_hash)
                        .await?;
                }
            };
        }
    }
    Ok(())
}

pub async fn scan_post_graph_data(
    _swarm: &mut Swarm<AllBehaviours>,
    local_db: &LocalDB,
    goat_client: &GOATClient,
) -> Result<(), Box<dyn std::error::Error>> {
    info!("Starting into scan post_operator_data");
    let current_time = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64;
    let mut storage_process = local_db.acquire().await?;
    let (instances, _) = storage_process
        .find_instances(
            InstanceQuery::default()
                .with_statuses(vec![InstanceStatus::RelayerL2Minted.to_string()])
                .with_earliest_updated(current_time - GRAPH_OPERATOR_DATA_UPLOAD_TIME_EXPIRED),
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
                .post_graph_data(&instance.instance_id, &graph.graph_id, &graph, &[])
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
                        GoatTxProcessingStatus::Skipped.to_string(),
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
