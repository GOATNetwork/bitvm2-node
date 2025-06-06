use std::fmt::Display;
use std::sync::Arc;
use std::time::Duration;

use alloy_consensus::{Block, BlockHeader};
use eyre::eyre;
use host_executor::ExecutionHooks;
use reth_primitives_traits::NodePrimitives;
use store::localdb::LocalDB;
use zkm_sdk::{ExecutionReport, HashableKey, ZKMVerifyingKey};

#[derive(Clone)]
pub struct PersistToDB {
    pub local_db: LocalDB,
}

impl PersistToDB {
    pub async fn new(local_db: &LocalDB) -> Self {
        Self { local_db: local_db.clone() }
    }
}

impl ExecutionHooks for PersistToDB {
    async fn on_execution_start(&self, block_number: u64) -> eyre::Result<()> {
        let mut storage_process =
            self.local_db.acquire().await.map_err(|e| eyre!("Failed to acquire local db: {e}"))?;

        storage_process
            .create_block_proving_task(block_number as i64, ProvableBlockStatus::Queued.to_string())
            .await
            .map_err(|e| eyre!("Failed to start block execution: {e}"))?;

        Ok(())
    }

    async fn on_execution_end<P: NodePrimitives>(
        &self,
        executed_block: &Block<P::SignedTx>,
        _execution_report: &ExecutionReport,
    ) -> eyre::Result<()> {
        let mut storage_process =
            self.local_db.acquire().await.map_err(|e| eyre!("Failed to acquire local db: {e}"))?;

        storage_process
            .update_block_executed(
                executed_block.number() as i64,
                executed_block.body.transactions.len() as i64,
                executed_block.header.gas_used() as i64,
                ProvableBlockStatus::Executed.to_string(),
            )
            .await
            .map_err(|e| eyre!("Failed to end block execution: {e}"))?;

        Ok(())
    }

    async fn on_proving_end(
        &self,
        block_number: u64,
        proof_bytes: &[u8],
        public_values_bytes: &[u8],
        vk: &ZKMVerifyingKey,
        execution_report: &ExecutionReport,
        proving_duration: Duration,
    ) -> eyre::Result<()> {
        let mut storage_process =
            self.local_db.acquire().await.map_err(|e| eyre!("Failed to acquire local db: {e}"))?;

        storage_process
            .update_block_proved(
                block_number as i64,
                (proving_duration.as_secs_f32() * 1000.0) as i64,
                execution_report.total_instruction_count() as i64,
                proof_bytes,
                public_values_bytes,
                vk.bytes32(),
                ProvableBlockStatus::Proved.to_string(),
            )
            .await
            .map_err(|e| eyre!("Failed to end block proving: {e}"))?;

        let vk_bytes = bincode::serialize(vk).unwrap();
        storage_process
            .create_verifier_key(vk.bytes32(), vk_bytes.as_ref())
            .await
            .map_err(|e| eyre!("Failed to create vk: {e}"))?;

        Ok(())
    }
}

pub async fn task_failed(
    local_db: Arc<LocalDB>,
    block_number: u64,
    err: String,
) -> eyre::Result<()> {
    let mut storage_process =
        local_db.acquire().await.map_err(|e| eyre!("Failed to acquire local db: {e}"))?;

    storage_process
        .update_block_proving_failed(
            block_number as i64,
            ProvableBlockStatus::Failed.to_string(),
            err,
        )
        .await
        .map_err(|e| eyre!("Failed to mark task as failed: {e}"))?;

    Ok(())
}

#[derive(Debug)]
pub enum ProvableBlockStatus {
    Queued,
    Executed,
    Proved,
    Failed,
}

impl Display for ProvableBlockStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProvableBlockStatus::Queued => write!(f, "queued"),
            ProvableBlockStatus::Executed => write!(f, "executed"),
            ProvableBlockStatus::Proved => write!(f, "proved"),
            ProvableBlockStatus::Failed => write!(f, "failed"),
        }
    }
}
