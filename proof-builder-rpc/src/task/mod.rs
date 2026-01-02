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
use bitcoin::Txid;
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

// fetch next task from watchtower or operator.
#[tracing::instrument(level = "info", skip(local_db))]
pub(crate) async fn fetch_on_demand_task(
    local_db: &LocalDB,
    index: usize,
    is_watchtower: bool,
) -> anyhow::Result<Option<OnDemandTask>> {
    tracing::info!("Fetch task for watchtower:{is_watchtower}");
    // btc header chain: always fetch the latest
    let mut storage_processor = local_db.acquire().await?;
    let header_chain_input_proof = match storage_processor
        .find_latest_long_running_task_proof_by_name(HeaderChainProofBuilder::name())
        .await?
    {
        Some(d) => d,
        None => {
            tracing::error!("Header chain input proof is not ready");
            return Ok(None);
        }
    };
    tracing::info!("header_chain_input_proof: {header_chain_input_proof:?}");
    let header_chain_input_proof = header_chain_input_proof.path_to_proof.unwrap();

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
    let commit_chain_input_proof = commit_chain_input_proof.path_to_proof.unwrap();
    let file = std::path::Path::new(&commit_chain_input_proof)
        .parent()
        .unwrap()
        .join(format!("commits.bin.{start}"));
    let content = match std::fs::read_to_string(&file) {
        Ok(d) => d,
        Err(e) => {
            tracing::error!("read {file:?} error, {e}");
            return Ok(None);
        }
    };
    let commits: Vec<CircuitCommit> = serde_json::from_str(&content)?;
    let latest_sequencer_commit_txid = commits[0].commit_txn.compute_txid().to_string();

    tracing::info!("fetch on-demand task");
    let (
        execution_layer_block_number,
        watchtower_challenge_init_txid,
        watchtower_challenge_txids,
        watchtower_public_keys,
    ) = if is_watchtower {
        match storage_processor.find_watchtower_proof_by_id(index as i64).await? {
            Some(task) => {
                tracing::info!("watchtower task: {task:?}");
                (task.execution_layer_block_number, None, None, None)
            }
            None => {
                return Ok(None);
            }
        }
    } else {
        //fetch watchtower info
        let task = match storage_processor.find_operator_proof_by_id(index as i64).await? {
            Some(task) => task,
            None => return Ok(None),
        };
        tracing::info!("operator task: {task:?}");
        let watchtower_info = storage_processor
            .find_watchtower_proof_by_instance_and_graph(&task.instance_id, &task.graph_id)
            .await?;
        tracing::info!("watchtower info: {watchtower_info:?}");
        let challenge_init_txids =
            watchtower_info.iter().map(|w| w.challenge_init_txid.0.to_string()).collect::<Vec<_>>();
        if let Some(first) = challenge_init_txids.first() {
            if !challenge_init_txids.iter().all(|x| first == x) {
                anyhow::bail!(
                    "Inconsistant watchtower challenge info from instance {} and graph_id {}",
                    task.instance_id,
                    task.graph_id
                );
            }
        }
        let challenge_txids =
            watchtower_info.iter().map(|w| w.challenge_txid.0.to_string()).collect::<Vec<_>>();
        let challenge_public_keys =
            watchtower_info.iter().map(|w| w.public_key.clone()).collect::<Vec<_>>();
        (
            task.execution_layer_block_number,
            Some(challenge_init_txids[0].clone()),
            Some(challenge_txids),
            Some(challenge_public_keys),
        )
    };

    // state chain: find the proof that includes the execution_layer_block_number
    let state_chain_input_proof = match storage_processor
        .find_long_running_task_proof_including_block_number(
            execution_layer_block_number,
            StateChainProofBuilder::name(),
        )
        .await?
    {
        Some(d) => d,
        None => {
            anyhow::bail!(
                "State chain proof is not ready for block: {execution_layer_block_number}"
            );
        }
    };
    let state_chain_input_proof = state_chain_input_proof.path_to_proof.unwrap();

    Ok(Some(OnDemandTask {
        latest_sequencer_commit_txid,
        header_chain_input_proof,
        commit_chain_input_proof,
        state_chain_input_proof,
        watchtower_challenge_init_txid,
        watchtower_challenge_txids,
        watchtower_public_keys,
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

pub(crate) async fn update_watchtower_task(
    local_db: &LocalDB,
    index: usize,
    path_to_proof: String,
    public_value_hex: String,
    proof_size: i64,
    cycles: u64,
    total_time_to_proof: i64,
    proving_time: i64,
    zkm_version: String,
) -> anyhow::Result<u64> {
    let mut storage_processor = local_db.acquire().await?;
    Ok(storage_processor
        .update_watchtower_proof_success(
            index as i64,
            path_to_proof,
            public_value_hex,
            proof_size,
            cycles as i64,
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
pub(crate) async fn add_operator_task(
    local_db: &LocalDB,
    instance_id: Uuid,
    graph_id: Uuid,
    execution_layer_block_number: i64,
) -> anyhow::Result<u64> {
    let mut storage_processor = local_db.acquire().await?;
    Ok(storage_processor
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
        .await?)
}

pub(crate) async fn find_operator_task(
    local_db: &LocalDB,
    instance_id: Uuid,
    graph_id: Uuid,
) -> anyhow::Result<Option<OperatorProof>> {
    let mut storage_processor = local_db.acquire().await?;
    storage_processor.find_operator_proof_by_instance_and_graph(&instance_id, &graph_id).await
}

pub(crate) async fn update_operator_task(
    local_db: &LocalDB,
    index: usize,
    path_to_proof: String,
    public_value_hex: String,
    proof_size: i64,
    cycles: u64,
    total_time_to_proof: i64,
    proving_time: i64,
    zkm_version: String,
) -> anyhow::Result<u64> {
    let mut storage_processor = local_db.acquire().await?;
    Ok(storage_processor
        .update_operator_proof_success(
            index as i64,
            path_to_proof,
            public_value_hex,
            proof_size,
            cycles as i64,
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

    use store::create_local_db;
    use uuid::Uuid;

    use super::add_operator_task;
    use super::add_watchtower_task;

    #[tokio::test]
    #[ignore]
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
    #[ignore]
    async fn test_add_operator_proof() {
        let db_path = std::env::var("TEST_DB")
            .unwrap_or("sqlite:/tmp/.bitvm2-node-sd.db?mode=rwc".to_string());
        let local_db = create_local_db(&db_path).await;
        let instance_id = Uuid::from_str("00112233445566778899aabbccddeeff").unwrap();
        let graph_id = Uuid::from_str("00112233445566778899aabbccddeeff").unwrap();
        let number = 9511055;
        add_operator_task(&local_db, instance_id, graph_id, number).await.unwrap();
    }
}
