mod commit_chain_proof;
mod header_chain_proof;
mod operator_proof;
mod watchtower_proof;

use crate::env::{
    is_start_commit_chain_proof_generate, is_start_heard_chain_proof_generate,
    is_start_operator_proof_generate, is_start_watchtower_proof_generate,
};
use crate::proof_tasks::commit_chain_proof::spawn_commit_chain_proof_task;
use crate::proof_tasks::header_chain_proof::spawn_header_chain_proof_task;
use crate::proof_tasks::operator_proof::spawn_operator_proof_task;
use crate::proof_tasks::watchtower_proof::spawn_watchtower_proof_task;
use futures::future::Either;
use store::localdb::LocalDB;
use tokio_util::sync::CancellationToken;
use tracing::{error, info};

pub(crate) fn is_start_generate_proof_tasks() -> bool {
    is_start_commit_chain_proof_generate()
        || is_start_heard_chain_proof_generate()
        || is_start_operator_proof_generate()
        || is_start_watchtower_proof_generate()
}
pub(crate) async fn run_generate_proof_tasks(
    _local_db: LocalDB,
    interval: u64,
    cancellation_token: CancellationToken,
) -> anyhow::Result<String> {
    let header_chain_proof_future = if is_start_heard_chain_proof_generate() {
        Either::Left(spawn_header_chain_proof_task(interval, 0, cancellation_token.clone()))
    } else {
        Either::Right(std::future::pending::<Result<anyhow::Result<()>, tokio::task::JoinError>>())
    };

    let commit_chain_proof_future = if is_start_commit_chain_proof_generate() {
        Either::Left(spawn_commit_chain_proof_task(
            interval,
            interval / 4,
            cancellation_token.clone(),
        ))
    } else {
        Either::Right(std::future::pending::<Result<anyhow::Result<()>, tokio::task::JoinError>>())
    };

    let operator_proof_future = if is_start_operator_proof_generate() {
        Either::Left(spawn_operator_proof_task(interval, interval / 2, cancellation_token.clone()))
    } else {
        Either::Right(std::future::pending::<Result<anyhow::Result<()>, tokio::task::JoinError>>())
    };

    let watchtower_proof_future = if is_start_watchtower_proof_generate() {
        Either::Left(spawn_watchtower_proof_task(
            interval,
            interval * 3 / 4,
            cancellation_token.clone(),
        ))
    } else {
        Either::Right(std::future::pending::<Result<anyhow::Result<()>, tokio::task::JoinError>>())
    };

    tokio::select! {
        result = header_chain_proof_future => {
            match result {
                Ok(Ok(_)) => {
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
