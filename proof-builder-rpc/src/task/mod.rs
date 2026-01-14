mod commit_chain_proof;
mod header_chain_proof;
mod operator_proof;
mod state_chain_proof;
mod watchtower_proof;
use crate::config::ProofBuilderConfig;
use crate::task::{
    commit_chain_proof::spawn_commit_chain_proof_task,
    header_chain_proof::spawn_header_chain_proof_task, operator_proof::spawn_operator_proof_task,
    state_chain_proof::spawn_state_chain_proof_task, watchtower_proof::spawn_watchtower_proof_task,
};
use ::commit_chain_proof::CommitChainProofBuilder;
use ::header_chain_proof::HeaderChainProofBuilder;
use ::state_chain_proof::StateChainProofBuilder;
use bitcoin::{Network, Txid};
use client::btc_chain::BTCClient;
use commit_chain::CircuitCommit;
use std::str::FromStr;
use std::time::UNIX_EPOCH;
use uuid::Uuid;

use futures::future::Either;
use proof_builder::{OnDemandTask, ProofBuilder};
use store::localdb::LocalDB;
use store::{LongRunningTaskProof, OperatorProof, ProofState, WatchtowerProof};
use tokio_util::sync::CancellationToken;
use tracing::{error, info};

pub(crate) fn is_start_generate_proof_tasks(cfg: &ProofBuilderConfig) -> bool {
    cfg.header_chain.enable
        || cfg.commit_chain.enable
        || cfg.state_chain.enable
        || cfg.watchtower.enable
        || cfg.operator.enable
}

pub(crate) async fn run_generate_proof_tasks(
    cfg: ProofBuilderConfig,
    local_db: LocalDB,
    interval: u64,
    cancellation_token: CancellationToken,
) -> anyhow::Result<String> {
    let header_chain_proof_future = if cfg.header_chain.enable {
        Either::Left(spawn_header_chain_proof_task(
            cfg.header_chain.clone(),
            local_db.clone(),
            interval,
            0,
            cancellation_token.clone(),
        ))
    } else {
        Either::Right(std::future::pending::<Result<anyhow::Result<_>, tokio::task::JoinError>>())
    };

    let commit_chain_proof_future = if cfg.commit_chain.enable {
        Either::Left(spawn_commit_chain_proof_task(
            cfg.commit_chain.clone(),
            local_db.clone(),
            interval,
            interval / 4,
            cancellation_token.clone(),
        ))
    } else {
        Either::Right(std::future::pending::<Result<anyhow::Result<_>, tokio::task::JoinError>>())
    };

    let state_chain_proof_future = if cfg.state_chain.enable {
        Either::Left(spawn_state_chain_proof_task(
            cfg.state_chain.clone(),
            local_db.clone(),
            interval,
            interval / 4,
            cancellation_token.clone(),
        ))
    } else {
        Either::Right(std::future::pending::<Result<anyhow::Result<_>, tokio::task::JoinError>>())
    };

    let operator_proof_future = if cfg.operator.enable {
        Either::Left(spawn_operator_proof_task(
            cfg.operator.clone(),
            local_db.clone(),
            interval,
            interval / 2,
            cancellation_token.clone(),
        ))
    } else {
        Either::Right(std::future::pending::<Result<anyhow::Result<_>, tokio::task::JoinError>>())
    };

    let watchtower_proof_future = if cfg.watchtower.enable {
        Either::Left(spawn_watchtower_proof_task(
            cfg.watchtower.clone(),
            local_db.clone(),
            interval,
            interval * 3 / 4,
            cancellation_token.clone(),
        ))
    } else {
        Either::Right(std::future::pending::<Result<anyhow::Result<_>, tokio::task::JoinError>>())
    };

    tokio::select! {
        result = header_chain_proof_future => {
            match result {
                Ok(Ok(_resp)) => {
                    info!("Header chain proof generate task completed successfully");
                }
                Ok(Err(e)) => {
                    error!("Header chain generate proof task error: {}", e);
                    return Err(e);
                }
                Err(e) => {
                   error!("Header chain proof generate task panic: {:?}", e);
                    anyhow::bail!("Header chain proof generate task panic: {:?}", e);
                }
            }
        }
        result = commit_chain_proof_future => {
            match result {
                Ok(Ok(_)) => {
                    info!("Commit chain proof generate task completed successfully");
                }
                Ok(Err(e)) => {
                    error!("Commit chain proof generate task error: {}", e);
                    return Err(e);
                }
                Err(e) => {
                   error!("Commit chain proof generate task panic: {:?}", e);
                    anyhow::bail!("Commit chain proof generate task panic: {:?}", e);
                }
            }
        },
        result = state_chain_proof_future => {
            match result {
                Ok(Ok(_)) => {
                    info!("State chain proof generate task completed successfully");
                }
                Ok(Err(e)) => {
                    error!("State chain proof generate task error: {}", e);
                    return Err(e);
                }
                Err(e) => {
                   error!("State chain proof generate task panic: {:?}", e);
                    anyhow::bail!("State chain proof generate task panic: {:?}", e);
                }
            }
        }
        result = operator_proof_future => {
            match result {
                Ok(Ok(_)) => {
                    info!("Operator proof generate task completed successfully");
                }
                Ok(Err(e)) => {
                    error!("Operator proof generate task error: {}", e);
                    return Err(e);
                }
                Err(e) => {
                   error!("Operator proof generate task panic: {:?}", e);
                    anyhow::bail!("Operator proof generate task panic: {:?}", e);
                }
            }
        }
        result = watchtower_proof_future => {
            match result {
                Ok(Ok(_)) => {
                    info!("Watchtower proof generate task completed successfully");
                }
                Ok(Err(e)) => {
                    error!("Watchtower proof generate task error: {}", e);
                    return Err(e);
                }
                Err(e) => {
                   error!("Watchtower proof generate task panic: {:?}", e);
                    anyhow::bail!("Watchtower proof generate task panic: {:?}", e);
                }
            }
        }
    }

    Ok("tasks_completed".to_string())
}

pub(crate) async fn fetch_latest_long_running_task(
    local_db: &LocalDB,
    chain_name: String,
) -> anyhow::Result<Option<LongRunningTaskProof>> {
    let mut storage_processor = local_db.acquire().await?;
    storage_processor.find_latest_long_running_task_proof_by_name(chain_name).await
}

pub(crate) async fn fetch_latest_long_running_task_by_state(
    local_db: &LocalDB,
    chain_name: String,
    proof_state: i64,
) -> anyhow::Result<Option<LongRunningTaskProof>> {
    let mut storage_processor = local_db.acquire().await?;
    storage_processor
        .find_latest_long_running_task_proof_by_name_and_state(chain_name, proof_state)
        .await
}

async fn read_watchtower_challenge_details<'a>(
    storage_processor: &mut store::localdb::StorageProcessor<'a>,
    is_watchtower: bool,
    bitcoin_network: Network,
    esplora_url: &str,
) -> anyhow::Result<(
    i64,
    i64,
    Option<String>,
    Vec<String>,
    Vec<bool>,
    Vec<String>,
    Option<String>,
    i64,
)> {
    let (
        task_index,
        execution_layer_block_number,
        watchtower_challenge_init_txid,
        watchtower_challenge_txids,
        included_watchtowers,
        watchtower_public_keys,
        graph_id,
    ) = if is_watchtower {
        match storage_processor.find_next_watchtower_proof().await? {
            Some(task) => {
                tracing::info!("watchtower task: {task:?}");
                let challenge_txids: Vec<String> = vec![task.challenge_txid.0.to_string()];
                let pubkeys: Vec<String> = vec![task.public_key.clone()];
                (
                    task.id,
                    task.execution_layer_block_number,
                    None,
                    challenge_txids,
                    vec![],
                    pubkeys,
                    Some(task.graph_id.as_simple().to_string()),
                )
            }
            None => {
                anyhow::bail!("no watchtower task found")
            }
        }
    } else {
        //fetch watchtower info
        let task = match storage_processor.find_next_operator_proof().await? {
            Some(task) => task,
            None => anyhow::bail!("no operator task found"),
        };
        tracing::info!("operator task: {task:?}");
        let watchtower_info: Vec<WatchtowerProof> = storage_processor
            .find_watchtower_proof_by_instance_and_graph(&task.instance_id, &task.graph_id)
            .await?;
        tracing::info!("watchtower info: {watchtower_info:?}");
        let challenge_init_txids: Vec<String> =
            watchtower_info.iter().map(|w| w.challenge_init_txid.0.to_string()).collect::<Vec<_>>();
        if challenge_init_txids.is_empty() {
            anyhow::bail!(
                "No watchtower challenge info found for instance {} and graph_id {}",
                task.instance_id,
                task.graph_id
            );
        }
        if let Some(first) = challenge_init_txids.first() {
            if !challenge_init_txids.iter().all(|x| first == x) {
                anyhow::bail!(
                    "Inconsistant watchtower challenge info from instance {} and graph_id {}",
                    task.instance_id,
                    task.graph_id
                );
            }
        }
        let challenge_txids: Vec<String> =
            watchtower_info.iter().map(|w| w.challenge_txid.0.to_string()).collect::<Vec<_>>();
        let challenge_public_keys: Vec<String> =
            watchtower_info.iter().map(|w| w.public_key.clone()).collect::<Vec<_>>();
        let included_watchtowers: Vec<bool> =
            watchtower_info.iter().map(|w| w.included).collect::<Vec<_>>();
        (
            task.id,
            task.execution_layer_block_number,
            challenge_init_txids.first().cloned(),
            challenge_txids,
            included_watchtowers,
            challenge_public_keys,
            Some(task.graph_id.as_simple().to_string()),
        )
    };

    let btc_block_number = {
        let btc_client = BTCClient::new(bitcoin_network, Some(esplora_url));
        let mut block_number = 0;
        for challenge_txid in watchtower_challenge_txids.iter() {
            // get block number by block hash
            let txid = Txid::from_str(challenge_txid).unwrap();
            match btc_client.get_tx_status(&txid).await {
                Ok(tx) => {
                    if let Some(height) = tx.block_height
                        && tx.confirmed
                        && (height as i64) > block_number
                    {
                        tracing::info!(
                            "Challenge txid {} is included in block {}, which is before the current block number {}",
                            challenge_txid,
                            height,
                            block_number
                        );
                        block_number = height as i64;
                    } else {
                        tracing::warn!("Challenge txid {} is not confirmed yet", challenge_txid);
                    }
                }
                Err(e) => {
                    tracing::warn!(
                        "Failed to get tx status for txid {}, error: {}",
                        challenge_txid,
                        e
                    );
                }
            }
        }
        block_number
    };

    tracing::info!(
        "is_watchtower {is_watchtower}, btc_block_number {btc_block_number}, execution_layer_block_number {execution_layer_block_number}"
    );
    Ok((
        task_index,
        execution_layer_block_number,
        watchtower_challenge_init_txid,
        watchtower_challenge_txids,
        included_watchtowers,
        watchtower_public_keys,
        graph_id,
        btc_block_number,
    ))
}

// fetch next task from watchtower or operator.
#[tracing::instrument(level = "info", skip(local_db))]
pub(crate) async fn fetch_on_demand_task(
    local_db: &LocalDB,
    is_watchtower: bool,
    bitcoin_network: Network,
    esplora_url: &str,
) -> anyhow::Result<Option<OnDemandTask>> {
    // btc header chain: always fetch the latest.
    let mut storage_processor = local_db.acquire().await?;
    // commit chain: always fetch the latest
    let commit_chain_input_proof = match storage_processor
        .find_latest_long_running_task_proof_by_name(CommitChainProofBuilder::name())
        .await?
    {
        Some(d) => d,
        None => {
            tracing::error!("Commit chain input proof is not ready");
            return Ok(None);
        }
    };
    tracing::info!("commit_chain_input_proof: {commit_chain_input_proof:?}");
    let start = commit_chain_input_proof.block_start;
    let batch_size = commit_chain_input_proof.block_end - commit_chain_input_proof.block_start;
    let commit_chain_input_proof = commit_chain_input_proof.path_to_proof.unwrap();
    let file = std::path::Path::new(&commit_chain_input_proof)
        .parent()
        .unwrap()
        .join(format!("{start}-{batch_size}.bin.commits"));
    let content = match std::fs::read_to_string(&file) {
        Ok(d) => d,
        Err(e) => {
            tracing::error!("read {file:?} error, {e}");
            return Ok(None);
        }
    };
    let commits: Vec<CircuitCommit> = serde_json::from_str(&content)?;
    let latest_sequencer_commit_txid = commits[0].commit_txn.compute_txid().to_string();

    let (
        task_index,
        execution_layer_block_number,
        watchtower_challenge_init_txid,
        watchtower_challenge_txids,
        included_watchtowers,
        watchtower_public_keys,
        graph_id,
        btc_block_number,
    ) = match read_watchtower_challenge_details(
        &mut storage_processor,
        is_watchtower,
        bitcoin_network,
        esplora_url,
    )
    .await
    {
        Ok(d) => d,
        Err(e) => {
            tracing::warn!("Failed to read watchtower challenge details, error: {}", e);
            return Ok(None);
        }
    };

    if !is_watchtower && btc_block_number == 0 {
        tracing::warn!("Watchtower challenge tx is not confirmed yet.");
        return Ok(None);
    }

    let header_chain_input_proof = if btc_block_number > 0 {
        match storage_processor
            .find_long_running_task_proof_including_block_number(
                btc_block_number,
                HeaderChainProofBuilder::name(),
            )
            .await?
        {
            Some(d) => d,
            None => {
                tracing::warn!(
                    "Header chain input proof is not ready for block: {btc_block_number}"
                );
                return Ok(None);
            }
        }
    } else {
        let header_chain_input_proof = match storage_processor
            .find_latest_long_running_task_proof_by_name(HeaderChainProofBuilder::name())
            .await?
        {
            Some(d) => d,
            None => {
                tracing::warn!("Header chain input proof is not ready");
                return Ok(None);
            }
        };
        tracing::info!("header_chain_input_proof: {header_chain_input_proof:?}");
        header_chain_input_proof
    };
    tracing::info!("header_chain_input_proof: {header_chain_input_proof:?}");
    let header_chain_input_proof = header_chain_input_proof.path_to_proof.unwrap();

    // state chain: find the proof that includes the execution_layer_block_number
    let state_chain_input_proof = match storage_processor
        .find_long_running_task_proof_including_block_number(
            execution_layer_block_number,
            StateChainProofBuilder::name(),
        )
        .await?
    {
        Some(d) => {
            if d.proof_state != ProofState::Proven.to_i64() {
                tracing::info!(
                    "State chain proof is not ready for block: {execution_layer_block_number}, proof not ready"
                );
                return Ok(None);
            } else {
                d
            }
        }
        None => {
            tracing::info!(
                "State chain proof is not ready for block: {execution_layer_block_number}, record not found"
            );
            return Ok(None);
        }
    };
    let state_chain_input_proof = state_chain_input_proof.path_to_proof.unwrap();

    Ok(Some(OnDemandTask {
        task_index,
        latest_sequencer_commit_txid,
        header_chain_input_proof,
        commit_chain_input_proof,
        state_chain_input_proof,
        watchtower_challenge_init_txid,
        watchtower_challenge_txids,
        included_watchtowers,
        watchtower_public_keys,
        graph_id,
    }))
}

/// table schema: (start, end, path_to_proof, cycles, update_time, table_name)
/// * table_name: header-chain | state-chain | commit-chain
pub(crate) async fn create_long_running_task(
    local_db: &LocalDB,
    start: u64,
    batch_size: u64,
    path_to_proof: String,
    public_value_hex: String,
    proof_size: i64,
    cycles: u64,
    chain_name: String,
    total_time_to_proof: i64,
    proving_time: i64,
    proof_state: ProofState,
    zkm_version: String,
) -> anyhow::Result<u64> {
    let mut storage_processor = local_db.acquire().await?;
    Ok(storage_processor
        .create_long_running_task_proof(&LongRunningTaskProof {
            block_start: start as i64,
            block_end: (start + batch_size) as i64,
            chain_name,
            path_to_proof: Some(path_to_proof),
            public_value_hex: Some(public_value_hex),
            proof_size,
            cycles: cycles as i64,
            proof_state: proof_state.to_i64(),
            total_time_to_proof,
            proving_time,
            zkm_version,
            extra: None,
            created_at: current_time_secs(),
            updated_at: current_time_secs(),
        })
        .await?)
}

pub(crate) async fn update_long_running_task(
    local_db: &LocalDB,
    start_index: i64,
    batch_size: i64,
    path_to_proof: String,
    public_value_hex: String,
    proof_size: i64,
    cycles: u64,
    proof_state: ProofState,
    chain_name: String,
    proving_time: i64,
    zkm_version: String,
) -> anyhow::Result<u64> {
    let mut storage_processor = local_db.acquire().await?;
    let task = storage_processor
        .find_long_running_task_proof_including_block_number(start_index as i64, chain_name.clone())
        .await?;
    if task.is_none() {
        anyhow::bail!(
            "Long running task not found for chain: {chain_name}, start_index: {start_index}"
        );
    }
    let total_time_to_proof = (current_time_secs() - task.unwrap().created_at) * 1000;
    Ok(storage_processor
        .update_long_running_task_proof_success(
            start_index,
            &chain_name,
            batch_size,
            path_to_proof,
            public_value_hex,
            proof_size,
            cycles as i64,
            proof_state.to_i64(),
            total_time_to_proof,
            proving_time,
            &zkm_version,
        )
        .await?)
}

/// table schema: (index, instance_id, graph_id, public_key, challenge_txid, challenge_init_txid, path_to_proof, cycles, state, update_time)
/// * index: incremental id
/// * state: 0-new, 1-doing, 2-done, 3-failed
/// Invocated by API
pub(crate) async fn add_watchtower_task(
    local_db: &LocalDB,
    instance_id: Uuid,
    graph_id: Uuid,
    public_key: String,
    challenge_txid: String,
    challenge_init_txid: String,
    execution_layer_block_number: i64,
) -> anyhow::Result<u64> {
    let mut storage_processor = local_db.acquire().await?;
    Ok(storage_processor
        .create_watchtower_proof(&WatchtowerProof {
            id: 1,
            instance_id,
            graph_id,
            public_key,
            challenge_txid: Txid::from_str(&challenge_txid)?.into(),
            challenge_init_txid: Txid::from_str(&challenge_init_txid)?.into(),
            proof_state: ProofState::New.to_i64(),
            created_at: current_time_secs(),
            updated_at: current_time_secs(),
            execution_layer_block_number,
            ..Default::default()
        })
        .await?)
}

pub(crate) async fn find_watchtower_task(
    local_db: &LocalDB,
    instance_id: Uuid,
    graph_id: Uuid,
    public_key: &str,
) -> anyhow::Result<Option<WatchtowerProof>> {
    let mut storage_processor = local_db.acquire().await?;
    storage_processor
        .find_watchtower_proof_by_instance_and_graph_and_pubkey(&instance_id, &graph_id, public_key)
        .await
}

pub(crate) async fn update_watchtower_task_state(
    local_db: &LocalDB,
    instance_id: Uuid,
    graph_id: Uuid,
    public_key: &str,
    old_proof_state: ProofState,
    new_proof_state: ProofState,
) -> anyhow::Result<u64> {
    let mut storage_processor = local_db.acquire().await?;
    storage_processor
        .update_watchtower_proof_state_with_instance_graph_pubkey(
            &instance_id,
            &graph_id,
            public_key,
            old_proof_state.to_i64(),
            new_proof_state.to_i64(),
        )
        .await
}

pub(crate) async fn update_watchtower_task(
    local_db: &LocalDB,
    index: i64,
    path_to_proof: String,
    public_value_hex: String,
    proof_size: i64,
    cycles: u64,
    proof_state: ProofState,
    total_time_to_proof: i64,
    proving_time: i64,
    zkm_version: String,
) -> anyhow::Result<u64> {
    let mut storage_processor = local_db.acquire().await?;
    Ok(storage_processor
        .update_watchtower_proof(
            index,
            path_to_proof,
            public_value_hex,
            proof_size,
            cycles as i64,
            proof_state.to_i64(),
            total_time_to_proof,
            proving_time,
            &zkm_version,
        )
        .await?)
}

/// table schema: (index, instance_id, graph_id, execution_layer_block_number, path_to_proof, cycles, state, update_time)
/// * state: 0-new, 1-doing, 2-done, 3-failed
/// * execution_layer_block_number: proceedWithdraw's block number
/// * index: incremental id
/// Invocated by API
#[tracing::instrument(level = "info", skip(local_db))]
pub(crate) async fn add_operator_task(
    local_db: &LocalDB,
    instance_id: Uuid,
    graph_id: Uuid,
    execution_layer_block_number: i64,
    watchtower_challenge_txids: Vec<String>,
    included_watchtowers: Vec<bool>,
    watchtower_challenge_init_txid: String,
    watchtower_challenge_pubkeys: Vec<String>,
) -> anyhow::Result<u64> {
    let mut storage_processor = local_db.start_transaction().await?;

    let existing_watchtower_proof_task = storage_processor
        .find_watchtower_proof_by_instance_and_graph(&instance_id, &graph_id)
        .await?;
    tracing::info!("existing_watchtower_proof_task: {:?}", existing_watchtower_proof_task);
    let timeout_watchtower_challenge_txids: Vec<String> = watchtower_challenge_txids
        .iter()
        .enumerate()
        .filter(|(node_index, _)| {
            !existing_watchtower_proof_task
                .iter()
                .any(|task| task.node_index as usize == *node_index)
        })
        .map(|(_, txid)| txid.clone())
        .collect();
    tracing::info!("timeout_watchtower_challenge_txids: {:?}", timeout_watchtower_challenge_txids);
    // insert timeout watchtower proof task with failed state.
    for txid in timeout_watchtower_challenge_txids.iter() {
        let node_index = watchtower_challenge_txids.iter().position(|t| t == txid).unwrap() as i32;
        let task = WatchtowerProof {
            id: 1,
            instance_id,
            graph_id,
            challenge_init_txid: Txid::from_str(&watchtower_challenge_init_txid)?.into(),
            challenge_txid: Txid::from_str(txid)?.into(),
            proof_state: ProofState::Failed.to_i64(),
            created_at: current_time_secs(),
            updated_at: current_time_secs(),
            execution_layer_block_number,
            public_key: watchtower_challenge_pubkeys[node_index as usize].clone(), // Note: this is a fake public key.
            node_index,
            ..Default::default()
        };
        let affected = storage_processor.create_watchtower_proof(&task).await?;
        tracing::info!(
            "mark timeout watchtower proof as failed, txid: {txid}, affected rows: {affected}",
        );
    }

    // update watchtower's challenge txid.
    for (i, txid) in watchtower_challenge_txids.iter().enumerate() {
        let affected = storage_processor
            .update_watchtower_proof_challenge_txid(
                &instance_id,
                &graph_id,
                i as i32,
                txid,
                included_watchtowers[i],
            )
            .await?;
        tracing::info!("update watchtower proof, node_index: {i} affected rows: {affected}",);
    }

    let affected_rows = storage_processor
        .create_operator_proof(&OperatorProof {
            id: 1,
            instance_id,
            graph_id,
            execution_layer_block_number: execution_layer_block_number as i64,
            proof_state: ProofState::New.to_i64(),
            created_at: current_time_secs(),
            updated_at: current_time_secs(),
            cycles: 0,
            ..Default::default()
        })
        .await?;
    storage_processor.commit().await?;
    Ok(affected_rows)
}

pub(crate) async fn find_operator_task(
    local_db: &LocalDB,
    instance_id: Uuid,
    graph_id: Uuid,
) -> anyhow::Result<Option<OperatorProof>> {
    let mut storage_processor = local_db.acquire().await?;
    storage_processor.find_operator_proof_by_instance_and_graph(&instance_id, &graph_id).await
}

pub(crate) async fn update_operator_task_state(
    local_db: &LocalDB,
    instance_id: Uuid,
    graph_id: Uuid,
    old_proof_state: ProofState,
    new_proof_state: ProofState,
) -> anyhow::Result<u64> {
    let mut storage_processor = local_db.acquire().await?;
    storage_processor
        .update_operator_proof_state_with_instance_graph(
            &instance_id,
            &graph_id,
            old_proof_state.to_i64(),
            new_proof_state.to_i64(),
        )
        .await
}

pub(crate) async fn update_operator_task(
    local_db: &LocalDB,
    index: i64,
    path_to_proof: String,
    public_value_hex: String,
    proof_size: i64,
    cycles: u64,
    proof_state: ProofState,
    total_time_to_proof: i64,
    proving_time: i64,
    zkm_version: String,
) -> anyhow::Result<u64> {
    let mut storage_processor = local_db.acquire().await?;
    Ok(storage_processor
        .update_operator_proof(
            index,
            path_to_proof,
            public_value_hex,
            proof_size,
            cycles as i64,
            proof_state.to_i64(),
            total_time_to_proof,
            proving_time,
            &zkm_version,
        )
        .await?)
}

#[inline(always)]
pub(crate) fn current_time_secs() -> i64 {
    std::time::SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::add_operator_task;
    use super::add_watchtower_task;
    use store::create_local_db;
    use uuid::Uuid;

    #[tokio::test]
    async fn test_add_watchtower_task() {
        let db_path = std::env::var("TEST_DB")
            .unwrap_or("sqlite:/tmp/.bitvm2-node-sd.db?mode=rwc".to_string());
        let local_db = create_local_db(&db_path).await;
        let instance_id = Uuid::from_str("00112233445566778899aabbccddeeff").unwrap();
        let graph_id = Uuid::from_str("00112233445566778899aabbccddeeff").unwrap();
        let public_key =
            "0272efe7ccae21d2541ad85d4f2961f2e5593c29dc8bc37bf87035fc2d5527a651".to_string();
        let challenge_txid =
            "3b155884a7f6dd65836045779c6cb5e0ebe11d4630f825fb45682b8cef1c79f0".to_string();
        let challenge_init_txid =
            "7f7b4344adb1b8937ddb7124e4f8bba80ee9adf5e8119de76ca8736816bda246".to_string();
        let number = 9511055;
        add_watchtower_task(
            &local_db,
            instance_id,
            graph_id,
            public_key,
            challenge_txid,
            challenge_init_txid,
            number,
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn test_add_operator_proof() {
        tracing_subscriber::fmt::init();
        let db_path =
            std::env::var("TEST_DB").unwrap_or("sqlite:.bitvm2-node-sd.db?mode=rwc".to_string());
        let local_db = create_local_db(&db_path).await;
        let instance_id = Uuid::from_str("00112233445566778899aabbccddeeff").unwrap();
        let graph_id = Uuid::from_str("00112233445566778899aabbccddeeff").unwrap();
        let number = 9511055;
        let watchtower_challenge_txids = vec![
            "4506cf35cd70b3006fe3ce4a87ca1f9b0a76f348cfb529423e2d4c163c28d604".to_string(),
            "f16286f143430a229c6d068798cd9ba751e83202de5045cc788aab227114cdb2".to_string(),
        ];
        let included_watchtowers = vec![true, false];
        add_operator_task(
            &local_db,
            instance_id,
            graph_id,
            number,
            watchtower_challenge_txids,
            included_watchtowers,
        )
        .await
        .unwrap();

        //use crate::task::read_watchtower_challenge_details;
        //let is_watchtower = false;
        //let bitcoin_network = bitcoin::Network::Regtest;
        //let esplora_url = "http://localhost:13002";
        //let mut storage_processor = local_db.acquire().await.unwrap();
        //let result = read_watchtower_challenge_details(&mut storage_processor, is_watchtower, bitcoin_network, esplora_url).await.unwrap();
        //println!("result: {:?}", result);
        //assert!(result.3.len() == 2);
    }
}
