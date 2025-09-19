use crate::env;
use crate::env::{GRAPH_OPERATOR_DATA_UPLOAD_TIME_EXPIRED, INSTANCE_PRESIGNED_TIME_EXPIRED};
use crate::middleware::AllBehaviours;
use crate::rpc_service::current_time_secs;
use alloy::primitives::TxHash;
use anyhow::{anyhow, bail};
use bitcoin::hashes::Hash;
use bitcoin::PublicKey;
use bitvm2_lib::keys::CommitteeMasterKey;
use client::btc_chain::BTCClient;
use client::goat_chain::{GOATClient, GraphData};
use libp2p::Swarm;
use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH};
use store::localdb::{GraphUpdate, InstanceQuery, InstanceUpdate, LocalDB, StorageProcessor};
use store::{
    CommitteeSignatures, GoatTxProcessingStatus, GoatTxRecord, GoatTxType, Graph, GraphStatus,
    Instance, InstanceStatus,
};
use tracing::{info, warn};
use uuid::Uuid;

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
        let pubkey = master_key.keypair_for_instance(tx_record.instance_id).public_key();

        match goat_client
            .gateway_answer_pegin_request(&tx_record.instance_id, &pubkey.serialize())
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
    let window_blocks = goat_client.gateway_get_response_window_blocks().await? as i64;
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
                            existing.pubkey = pubkey.clone();
                        })
                        .or_insert_with(|| CommitteeSignatures {
                            pubkey,
                            l1_sig: vec![],
                            l2_sig: vec![],
                        });
                }

                if committee_quorum_size <= instance.committees_answers.len() as u64 {
                    instance.status = InstanceStatus::CommitteesAnswered.to_string();
                }

                if let Err(err) = storage_processor.upsert_instance(&instance).await {
                    warn!(
                        "failed to upsert instance {}, err: {}",
                        instance.instance_id,
                        err.to_string()
                    );
                }
                let _ = update_pegin_txids(&mut instance);
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

fn update_pegin_txids(_instance: &mut Instance) -> anyhow::Result<()> {
    // todo open it if goat rep updated
    // let committee_pubkeys: Vec<PublicKey> = instance
    //     .committees_answers
    //     .iter()
    //     .map(|(_k, v)| PublicKey::from_slice(&v.pubkey).unwrap())
    //     .collect();
    // let utxos: Vec<Utxo> = serde_json::from_str(&instance.input_utxos)?;
    //
    // let inputs = utxos
    //     .into_iter()
    //     .map(|utxo| Input {
    //         outpoint: OutPoint { txid: Txid::from_slice(&utxo.txid).unwrap(), vout: utxo.vout },
    //         amount: Amount::from_sat(utxo.amount_stats),
    //     })
    //     .collect();
    // let network = Network::from_str(&instance.network)?;
    // let user_change_address: Address<NetworkUnchecked> =
    //     Address::from_str(&instance.user_change_addr)?;
    // let user_refund_addr: Address<NetworkUnchecked> =
    //     Address::from_str(&instance.user_change_addr)?;
    //
    // let committee_agg_pubkey = generate_n_of_n_public_key(&committee_pubkeys).0;
    // let user_info = UserInfo {
    //     depositor_evm_address: EvmAddress::from_str(&instance.to_addr)?.into_array(),
    //     txn_fees: instance.fees.0,
    //     inputs,
    //     user_xonly_pubkey: XOnlyPublicKey::from_slice(&instance.user_xonly_pubkey.0)?,
    //     user_change_address: user_change_address.require_network(network)?,
    //     user_refund_address: user_refund_addr.require_network(network)?,
    // };
    // let instance_params = Bitvm2InstanceParameters {
    //     network,
    //     instance_id: instance.instance_id,
    //     user_info,
    //     pegin_amount: Amount::from_sat(instance.amount as u64),
    //     challenge_amount: Amount::from_sat(instance.amount as u64),
    //     committee_pubkeys,
    //     committee_agg_pubkey,
    // };
    //
    // let (pegin_deposit_tx, pegin_confirm_tx, _pegin_refund_tx) =
    //     instance_params.build_pegin_tx()?;
    // instance.pegin_prepare_txid = Some(pegin_deposit_tx.tx().compute_txid().into());
    // // instance.pegin_confirm_txid = Some(pegin_confirm_tx.tx().compute_txid().into());
    // // instance.pegin_cancel_txid = Some(pegin_refund_tx.tx().compute_txid().into());
    // instance.unsign_pegin_confirm_tx = Some(serde_json::to_string(&pegin_confirm_tx)?);
    Ok(())
}

pub async fn instance_expiration_monitor(
    local_db: &LocalDB,
    btc_client: &BTCClient,
) -> anyhow::Result<()> {
    let mut storage_processor = local_db.acquire().await?;
    let current_time = current_time_secs();
    let current_height = btc_client.get_height().await? as i64;
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

    // todo get from env
    let lock_height = 6 * 24 as i64;
    for instance in instances {
        if current_height > instance.pegin_prepare_height + lock_height {
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
        let tx_id = tx_id_op.unwrap().0;
        if let Ok(status) = btc_client.get_tx_status(&tx_id).await
            && status.confirmed
        {
            let mut instance_update =
                InstanceUpdate::new(instance.instance_id).with_status(next_status.to_string());
            if next_status == InstanceStatus::UserBroadcastPeginPrepare {
                // todo notify user broadcast pegin prepare
                instance_update = instance_update
                    .with_pegin_prepare_height(status.block_height.unwrap_or_default() as i64);
            }

            update_instance(&mut storage_processor, &instance_update).await?;
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
        let pegin_confirm_txid = match instance.pegin_confirm_txid {
            Some(txid) => txid.into(),
            None => {
                warn!(
                    "scan post_pegin_data instance:{}, pegin confirm txid is none",
                    instance.instance_id
                );
                continue;
            }
        };

        if instance.committees_answers.values().any(|v| v.l2_sig.is_empty()) {
            warn!(
                "scan post_pegin_data instance {} not collect all committee signs, call post pegin data will failed",
                instance.instance_id
            );
            continue;
        }

        if let Ok(_tx_hash) = TxHash::from_str(&instance.pegin_data_tx_hash) {
            let receipt_op = goat_client.get_tx_receipt(&instance.pegin_data_tx_hash).await?;
            if receipt_op.is_none() {
                info!(
                    "scan post_pegin_data, instance_id: {}, goat_tx:{} finish send to chain \
                but get receipt status is false, will try later",
                    instance.instance_id, instance.pegin_data_tx_hash
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
            let pegin_confirm_tx = btc_client.get_tx(&pegin_confirm_txid).await?.ok_or(format!(
                "pegin_confirm_txid {} not found",
                pegin_confirm_txid.to_string()
            ))?;

            let committee_signs: Vec<Vec<u8>> =
                instance.committees_answers.values().map(|v| v.clone().l2_sig).collect();
            match goat_client
                .gateway_post_pegin_data(
                    btc_client,
                    &instance.instance_id,
                    &pegin_confirm_tx,
                    &committee_signs,
                )
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
                    let block_height = match goat_client.get_tx_receipt(&tx_hash).await? {
                        Some(receipt) => receipt.block_number.unwrap_or(0),
                        None => 0,
                    };
                    let mut tx = local_db.start_transaction().await?;
                    tx.upsert_goat_tx_record(&GoatTxRecord {
                        instance_id: instance.instance_id,
                        graph_id: Uuid::default(),
                        tx_type: GoatTxType::PostPeginData.to_string(),
                        tx_hash: tx_hash.clone(),
                        height: block_height as i64,
                        is_local: true,
                        processing_status: GoatTxProcessingStatus::Skipped.to_string(),
                        extra: None,
                        created_at: current_time_secs(),
                    })
                    .await?;
                    tx.update_instance_pegin_data_txid(&instance.instance_id, &tx_hash).await?;
                    tx.commit().await?;
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
        if instance.committees_answers.values().any(|v| v.l2_sig.is_empty()) {
            warn!(
                "scan post_operator_data instance {} not collect all committee signs, call post pegin data will failed",
                instance.instance_id
            );
            continue;
        }

        let committee_signs: Vec<Vec<u8>> =
            instance.committees_answers.values().map(|v| v.clone().l2_sig).collect();

        let graphs = storage_process.get_graph_by_instance_id(&instance.instance_id).await?;
        if graphs.is_empty() {
            warn!(
                "scan post_operator_data instance {}, status is L2Minted, but graph is none",
                instance.instance_id
            );
            continue;
        }
        for graph in graphs {
            if graph.status != GraphStatus::CommitteePresigned.to_string() {
                continue;
            }

            let graph_data = cast_graph_to_graph_data(&graph)?;
            match goat_client
                .gateway_post_graph_data(
                    &instance.instance_id,
                    &graph.graph_id,
                    &graph_data,
                    &committee_signs,
                )
                .await
            {
                Ok(tx_hash) => {
                    info!(
                        "scan post_operator_data finish post operate data for instance_id {}, graph_id:{} , tx hash:{}",
                        instance.instance_id, graph.graph_id, tx_hash
                    );

                    let block_height = match goat_client.get_tx_receipt(&tx_hash).await? {
                        Some(receipt) => receipt.block_number.unwrap_or(0),
                        None => 0,
                    };
                    let mut tx = local_db.start_transaction().await?;
                    tx.upsert_goat_tx_record(&GoatTxRecord {
                        instance_id: instance.instance_id,
                        graph_id: graph.graph_id,
                        tx_type: GoatTxType::PostOperatorData.to_string(),
                        tx_hash,
                        height: block_height as i64,
                        is_local: true,
                        processing_status: GoatTxProcessingStatus::Skipped.to_string(),
                        extra: None,
                        created_at: current_time_secs(),
                    })
                    .await?;
                    tx.update_graph_fields(
                        GraphUpdate::new(graph.graph_id)
                            .with_status(GraphStatus::OperatorDataPushed.to_string()),
                    )
                    .await?;
                    tx.commit().await?;
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

pub fn cast_graph_to_graph_data(graph: &Graph) -> anyhow::Result<GraphData> {
    if graph.pegin_txid.is_none()
        || graph.kickoff_txid.is_none()
        || graph.take1_txid.is_none()
        || graph.take2_txid.is_none()
        || graph.blockhash_commit_timeout_txid.is_none()
        || graph.assert_commit_timeout_txids.is_empty()
        || graph.nack_txids.is_empty()
    {
        tracing::warn!("grap {}, has none field", graph.graph_id);
        bail!("grap {}, has none field", graph.graph_id);
    }

    // TODO Update
    let pubkey_vec = PublicKey::from_str(&graph.operator_pubkey)?.to_bytes();
    Ok(GraphData {
        operator_pubkey_prefix: pubkey_vec[0],
        operator_pubkey: pubkey_vec[1..33].try_into()?,
        pegin_txid: graph.pegin_txid.clone().unwrap().0.to_byte_array(),
        kickoff_txid: graph.kickoff_txid.clone().unwrap().0.to_byte_array(),
        take1_txid: graph.take1_txid.clone().unwrap().0.to_byte_array(),
        take2_txid: graph.take2_txid.clone().unwrap().0.to_byte_array(),
        commit_timout_txid: graph.blockhash_commit_timeout_txid.clone().unwrap().0.to_byte_array(),
        assert_timeout_txids: graph
            .assert_commit_timeout_txids
            .iter()
            .map(|x| x.0.to_byte_array())
            .collect(),
        nack_txids: graph.nack_txids.iter().map(|x| x.0.to_byte_array()).collect(),
    })
}
