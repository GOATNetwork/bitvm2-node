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
use bitcoin::Txid;
use std::str::FromStr;
use std::time::UNIX_EPOCH;

use futures::future::Either;
use proof_builder::OnDemandTask;
use store::localdb::LocalDB;
use store::{LongRunningTaskProof, OperatorProof, WatchtowerProof};
use tokio_util::sync::CancellationToken;
use tracing::{error, info};
use uuid::Uuid;

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
                    return Err(anyhow::anyhow!("Header chain proof generate task panic: {:?}", e));
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
                    return Err(anyhow::anyhow!("Commit chain proof generate task panic: {:?}", e));
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
                    return Err(anyhow::anyhow!("State chain proof generate task panic: {:?}", e));
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
                    return Err(anyhow::anyhow!("Operator proof generate task panic: {:?}", e));
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
                    return Err(anyhow::anyhow!("Watchtower proof generate task panic: {:?}", e));
                }
            }
        }
    }

    Ok("tasks_completed".to_string())
}

// fetch next task from watchtower or operator.
pub(crate) async fn fetch_on_demand_task(
    _local_db: &LocalDB,
    index: usize,
    is_watchtower: bool,
) -> anyhow::Result<OnDemandTask> {
    tracing::info!("fetch task: {index} for watchtower {is_watchtower}");
    // btc header chain: always fetch the latest
    // commit chain: always fetch the latest

    // state chain: find the proof that includes the execution_layer_block_number

    // handle operator
    //if !is_watchtower {
    // //fetch watchtower info
    //}

    todo!()
}

/// table schema: (start, end, path_to_proof, cycles, update_time, table_name)
/// * table_name: header-chain | state-chain | commit-chain
pub(crate) async fn update_long_running_task(
    local_db: &LocalDB,
    start: u64,
    batch_size: u64,
    path_to_proof: &str,
    cycles: u64,
    chain_name: String,
    proving_duration: i64,
    zkm_version: String,
) -> anyhow::Result<()> {
    let mut storage_proccessor = local_db.acquire().await?;
    storage_proccessor
        .create_long_running_task_proof(&LongRunningTaskProof {
            block_start: start as i64,
            block_end: (start + batch_size) as i64,
            chain_name,
            path_to_proof: Some(path_to_proof.to_string()),
            cycles: cycles as i64,
            proof_state: 2,
            proving_time: proving_duration,
            zkm_version,
            extra: None,
            created_at: current_time_secs(),
            updated_at: current_time_secs(),
        })
        .await?;
    Ok(())
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
) -> anyhow::Result<()> {
    let mut storage_proccessor = local_db.acquire().await?;
    let id = storage_proccessor.get_next_watchtower_proof_id().await?;
    storage_proccessor
        .create_watchtower_proof(&WatchtowerProof {
            id,
            instance_id,
            graph_id,
            public_key,
            challenge_txid: Txid::from_str(&challenge_txid)?.into(),
            challenge_init_txid: Txid::from_str(&challenge_init_txid)?.into(),
            path_to_proof: None,
            cycles: 0,
            proof_state: 0,
            proving_time: 0,
            zkm_version: "".to_string(),
            extra: None,
            created_at: current_time_secs(),
            updated_at: current_time_secs(),
        })
        .await?;
    Ok(())
}

pub(crate) async fn update_watchtower_task(
    local_db: &LocalDB,
    index: usize,
    path_to_proof: &str,
    cycles: u64,
    proving_duration: i64,
    zkm_version: &str,
) -> anyhow::Result<()> {
    let mut storage_proccessor = local_db.acquire().await?;
    storage_proccessor
        .update_operator_proof_success(
            index as i64,
            path_to_proof,
            cycles as i64,
            proving_duration,
            zkm_version,
        )
        .await?;
    Ok(())
}

pub(crate) async fn find_watchtower_unproved_tasks(
    local_db: &LocalDB,
) -> anyhow::Result<Vec<WatchtowerProof>> {
    let mut storage_proccessor = local_db.acquire().await?;
    let tasks = storage_proccessor.find_watchtower_proofs_unproved().await?;
    Ok(tasks)
}

/// table schema: (index, instance_id, graph_id, execution_layer_block_number, path_to_proof, cycles, state, update_time)
/// * state: 0-new, 1-doing, 2-done, 3-failed
/// * execution_layer_block_number: proceedWithdraw's block number
/// * index: incremental id
/// Invocated by API
pub(crate) async fn add_operator_task(
    local_db: &LocalDB,
    instance_id: Uuid,
    graph_id: Uuid,
    execution_layer_block_number: u64,
) -> anyhow::Result<()> {
    let mut storage_proccessor = local_db.acquire().await?;
    let id = storage_proccessor.get_next_operator_proof_id().await?;
    storage_proccessor
        .create_operator_proof(&OperatorProof {
            id,
            instance_id,
            graph_id,
            execution_layer_block_number: execution_layer_block_number as i64,
            path_to_proof: None,
            cycles: 0,
            proof_state: 0,
            proving_time: 0,
            zkm_version: "".to_string(),
            extra: None,
            created_at: current_time_secs(),
            updated_at: current_time_secs(),
        })
        .await?;
    Ok(())
}

pub(crate) async fn update_operator_task(
    local_db: &LocalDB,
    index: usize,
    path_to_proof: &str,
    cycles: u64,
    proving_duration: i64,
    zkm_version: &str,
) -> anyhow::Result<()> {
    let mut storage_proccessor = local_db.acquire().await?;
    storage_proccessor
        .update_operator_proof_success(
            index as i64,
            path_to_proof,
            cycles as i64,
            proving_duration,
            zkm_version,
        )
        .await?;
    Ok(())
}
pub(crate) async fn find_operator_unproved_task(
    local_db: &LocalDB,
) -> anyhow::Result<Vec<OperatorProof>> {
    let mut storage_proccessor = local_db.acquire().await?;
    let tasks = storage_proccessor.find_operator_proofs_unproved().await?;
    Ok(tasks)
}

#[inline(always)]
pub fn current_time_secs() -> i64 {
    std::time::SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64
}
