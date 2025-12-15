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

use futures::future::Either;
use proof_builder::OnDemandTask;
use store::localdb::LocalDB;
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
    _local_db: &LocalDB,
    _start: u64,
    _batch_size: u64,
    _path_to_proof: &str,
    _cycles: u64,
    _table_name: String,
) -> anyhow::Result<()> {
    todo!()
}

/// table schema: (index, instance_id, graph_id, public_key, challenge_txid, challenge_init_txid, path_to_proof, cycles, state, update_time)
/// * index: incremental id
/// * state: 0-new, 1-doing, 2-done, 3-failed
/// Invocated by API
pub(crate) async fn add_watchtower_task(
    _local_db: &LocalDB,
    _instance_id: String,
    _graph_id: String,
    _public_key: String,
    _challenge_txid: String,
    _challenge_init_txid: String,
) -> anyhow::Result<()> {
    todo!()
}

pub(crate) async fn update_watchtower_task(
    _index: usize,
    _path_to_proof: &str,
    _cycles: u64,
) -> anyhow::Result<()> {
    todo!()
}

/// table schema: (index, instance_id, graph_id, execution_layer_block_number, path_to_proof, cycles, state, update_time)
/// * state: 0-new, 1-doing, 2-done, 3-failed
/// * execution_layer_block_number: proceedWithdraw's block number
/// * index: incremental id
/// Invocated by API
pub(crate) async fn add_operator_task(
    _instance_id: String,
    _graph_id: String,
    _execution_layer_block_number: u64,
) -> anyhow::Result<()> {
    todo!()
}

pub(crate) async fn update_operator_task(
    _index: usize,
    _path_to_proof: &str,
    _cycles: u64,
) -> anyhow::Result<()> {
    todo!()
}
