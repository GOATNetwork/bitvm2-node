use crate::action::{ConfirmInstance, GOATMessageContent, PeginRequest};
use crate::env::{
    GRAPH_OPERATOR_DATA_UPLOAD_TIME_EXPIRED, INSTANCE_PRESIGNED_TIME_EXPIRED, get_network,
};
use crate::middleware::AllBehaviours;
use crate::rpc_service::current_time_secs;
use crate::utils::{create_message, strip_hex_prefix_owned};
use alloy::primitives::Address as EvmAddress;
use anyhow::bail;
use bitcoin::address::NetworkUnchecked;
use bitcoin::hashes::Hash;
use bitcoin::{Address, Amount, Denomination, Network, OutPoint, PublicKey, Transaction, Txid};
use bitvm2_lib::actors::Actor;
use bitvm2_lib::constants::CONNECTOR_Z_TIMELOCK;
use bitvm2_lib::contexts::base::generate_n_of_n_public_key;
use bitvm2_lib::transactions::base::{BaseTransaction, Input};
use bitvm2_lib::types::{Bitvm2InstanceParameters, UserInfo};
use client::Utxo;
use client::btc_chain::BTCClient;
use client::goat_chain::{GOATClient, GraphData};
use client::graphs::graph_query::BridgeInRequestEvent;
use libp2p::Swarm;
use secp256k1::XOnlyPublicKey;
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
        match tx_record.extra {
            Some(event) => {
                let event: BridgeInRequestEvent = serde_json::from_str(&event)?;
                create_message(
                    &mut tx,
                    tx_record.instance_id,
                    None,
                    "self".to_string(),
                    Actor::All,
                    GOATMessageContent::PeginRequest(PeginRequest {
                        instance_id: tx_record.instance_id,
                        network: get_network(),
                        pegin_amount: Amount::from_str_in(
                            &event.pegin_amount_sats,
                            Denomination::Satoshi,
                        )?,
                        user_info: generate_user_info_from_event(&event)?,
                    }),
                    0,
                    0,
                )
                .await?;
            }
            None => {}
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
                    .with_status(InstanceStatus::UserInited.to_string())
                    .with_pegin_request_height_threshold(current_height - window_blocks)
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

fn generate_user_info_from_event(event: &BridgeInRequestEvent) -> anyhow::Result<UserInfo> {
    let user_xonly_pubkey_bytes = hex::decode(strip_hex_prefix_owned(&event.user_xonly_pubkey))?;
    let user_xonly_pubkey_array: [u8; 32] = user_xonly_pubkey_bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("user_x_only_pubkey must be exactly 32 bytes"))?;

    let input_utxos: Vec<Utxo> = event
        .user_inputs
        .iter()
        .map(|v| {
            let txid_bytes = hex::decode(&strip_hex_prefix_owned(&v.txid))
                .map_err(|_| anyhow::anyhow!("Invalid txid hex format"))?;
            let txid_array: [u8; 32] = txid_bytes
                .try_into()
                .map_err(|_| anyhow::anyhow!("txid must be exactly 32 bytes"))?;
            Ok(Utxo {
                txid: txid_array,
                vout: v.vout,
                amount_stats: v.amount_sats.parse::<u64>().unwrap_or_default(),
            })
        })
        .collect::<anyhow::Result<Vec<Utxo>>>()?;

    let txn_fees = event.txn_fees.clone().map(|v| v.parse::<u64>().unwrap_or_default());
    gen_user_info(
        get_network(),
        &event.depositor_address,
        &strip_hex_prefix_owned(&event.user_change_address),
        &strip_hex_prefix_owned(&event.user_refund_address),
        input_utxos,
        txn_fees,
        &user_xonly_pubkey_array,
    )
}

fn gen_user_info(
    network: Network,
    depositor_evm_address: &str,
    user_change_addr: &str,
    user_refund_addr: &str,
    utxos: Vec<Utxo>,
    txn_fees: [u64; 3],
    user_xonly_pubkey: &[u8; 32],
) -> anyhow::Result<UserInfo> {
    let user_change_address: Address<NetworkUnchecked> = Address::from_str(user_change_addr)?;
    let user_refund_addr: Address<NetworkUnchecked> = Address::from_str(user_refund_addr)?;
    let inputs = utxos
        .into_iter()
        .map(|utxo| Input {
            outpoint: OutPoint { txid: Txid::from_slice(&utxo.txid).unwrap(), vout: utxo.vout },
            amount: Amount::from_sat(utxo.amount_stats),
        })
        .collect();
    Ok(UserInfo {
        depositor_evm_address: EvmAddress::from_str(&depositor_evm_address)?.into_array(),
        txn_fees,
        inputs,
        user_xonly_pubkey: XOnlyPublicKey::from_slice(user_xonly_pubkey)?,
        user_change_address: user_change_address.require_network(network)?,
        user_refund_address: user_refund_addr.require_network(network)?,
    })
}

fn get_instance_params(instance: &Instance) -> anyhow::Result<Bitvm2InstanceParameters> {
    let network = Network::from_str(&instance.network)?;
    let committee_pubkeys: Vec<PublicKey> = instance
        .committees_answers
        .iter()
        .map(|(_k, v)| PublicKey::from_slice(&v.pubkey).unwrap())
        .collect();

    let committee_agg_pubkey = generate_n_of_n_public_key(&committee_pubkeys).0;
    let utxos: Vec<Utxo> = serde_json::from_str(&instance.input_utxos)?;
    Ok(Bitvm2InstanceParameters {
        network,
        instance_id: instance.instance_id,
        user_info: gen_user_info(
            network,
            &instance.to_addr,
            &instance.user_change_addr.clone(),
            &instance.user_refund_addr.clone(),
            utxos,
            instance.fees.0,
            &instance.user_xonly_pubkey.0,
        )?,
        pegin_amount: Amount::from_sat(instance.amount as u64),
        committee_pubkeys,
        committee_agg_pubkey,
    })
}
fn update_pegin_txids(instance: &mut Instance) -> anyhow::Result<()> {
    let (pegin_deposit_tx, pegin_confirm_tx, pegin_refund_tx) =
        get_instance_params(instance)?.build_pegin_tx()?;
    instance.pegin_prepare_txid = Some(pegin_deposit_tx.tx().compute_txid().into());
    instance.pegin_confirm_txid = Some(pegin_confirm_tx.finalize().compute_txid().into());
    instance.pegin_cancel_txid = Some(pegin_refund_tx.finalize().compute_txid().into());
    instance.unsign_pegin_confirm_tx = Some(serde_json::to_string(&pegin_confirm_tx)?);
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
                    .with_status(InstanceStatus::PresignedFailed.to_string())
                    .with_offset(0)
                    .with_limit(MAX_INSTANCE),
            )
            .await?
    };

    let lock_height = CONNECTOR_Z_TIMELOCK as i64;
    let mut storage_processor = local_db.acquire().await?;
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
    local_db: &LocalDB,
    btc_client: &BTCClient,
) -> anyhow::Result<()> {
    info!("check user broadcast Pegin-Prepare");

    let (instances, _) = {
        let mut storage_processor = local_db.acquire().await?;
        storage_processor
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
            .await?
    };
    for instance in instances {
        let (tx_id_op, next_status) = match InstanceStatus::from_str(&instance.status) {
            Ok(status) => match status {
                InstanceStatus::CommitteesAnswered => {
                    (instance.pegin_prepare_txid.clone(), InstanceStatus::UserBroadcastPeginPrepare)
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
                // todo notify user broadcast pegin prepare
                instance_update = instance_update
                    .with_pegin_prepare_height(status.block_height.unwrap_or_default() as i64);

                create_message(
                    &mut tx,
                    instance.instance_id,
                    None,
                    "self".to_string(),
                    Actor::All,
                    GOATMessageContent::ConfirmInstance(ConfirmInstance {
                        instance_id: instance.instance_id,
                        network: Network::from_str(&instance.network.clone())?,
                        parameters: get_instance_params(&instance)?,
                    }),
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

#[allow(dead_code)]
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

#[allow(dead_code)]
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

#[allow(dead_code)]
async fn post_pegin_data(
    local_db: &LocalDB,
    btc_client: &BTCClient,
    goat_client: &GOATClient,
    instance_id: Uuid,
    committee_signs: Vec<Vec<u8>>,
    pegin_confirm_tx: &Transaction,
) -> anyhow::Result<()> {
    match goat_client
        .gateway_post_pegin_data(btc_client, &instance_id, &pegin_confirm_tx, &committee_signs)
        .await
    {
        Err(err) => {
            warn!(
                "scan post_pegin_data instance id {instance_id}, tx:{} post_pegin_data failed err:{:?}",
                pegin_confirm_tx.compute_txid().to_string(),
                err
            );
        }
        Ok(tx_hash) => {
            info!(
                "scan post_pegin_data finish post post_pegin_dataa for instance_id {instance_id} , tx hash:{}",
                tx_hash
            );
            let block_height = match goat_client.get_tx_receipt(&tx_hash).await? {
                Some(receipt) => receipt.block_number.unwrap_or(0),
                None => 0,
            };
            let mut tx = local_db.start_transaction().await?;
            tx.upsert_goat_tx_record(&GoatTxRecord {
                instance_id,
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
            tx.update_instance_pegin_data_txid(&instance_id, &tx_hash).await?;
            tx.commit().await?;
        }
    };
    Ok(())
}
