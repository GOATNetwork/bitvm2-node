use std::fmt::Display;
use std::sync::Arc;

use anyhow::{anyhow, Result};
use store::localdb::LocalDB;
use tokio::time::{sleep, Duration};
use tracing::info;
use zkm_sdk::{
    ExecutionReport, HashableKey, ZKMProof, ZKMProofWithPublicValues, ZKMPublicValues,
    ZKMVerifyingKey,
};

/// An input to the aggregation program.
///
/// Consists of a proof and a verification key.
pub struct Proof {
    pub block_number: u64,
    pub proof: ZKMProof,
    pub public_values: ZKMPublicValues,
    pub vk: Arc<ZKMVerifyingKey>,
}

pub struct Db {
    db: Arc<LocalDB>,
}

impl Db {
    pub fn new(db: Arc<LocalDB>) -> Self {
        Self { db }
    }

    pub async fn on_aggregation_start(&self, block_number: u64) -> Result<()> {
        let mut storage_process = self.db.acquire().await?;

        storage_process
            .create_aggregation_task(block_number as i64, ProvableBlockStatus::Queued.to_string())
            .await?;

        Ok(())
    }

    pub async fn load_proof(&self, block_number: u64, is_aggregate: bool) -> Result<Proof> {
        let mut storage_process = self.db.acquire().await?;

        loop {
            let (proof, public_values, vk_id) = if is_aggregate {
                storage_process.get_aggregation_proof(block_number as i64).await?
            } else {
                storage_process.get_block_proof(block_number as i64).await?
            };

            if proof.is_empty() {
                sleep(Duration::from_millis(500)).await;
                if is_aggregate {
                    info!("waiting block proof: {}", block_number);
                } else {
                    info!("waiting aggregation proof: {}", block_number);
                }
                continue;
            }

            let proof: ZKMProof = bincode::deserialize(&proof)?;
            let public_values: ZKMPublicValues = bincode::deserialize(&public_values)?;

            let vk = storage_process.get_verifier_key(&vk_id).await?;
            if vk.is_empty() {
                return Err(anyhow!("vk is not exists: {}", vk_id));
            }
            let vk: ZKMVerifyingKey = bincode::deserialize(&vk)?;

            return Ok(Proof { block_number, proof, public_values, vk: Arc::new(vk) });
        }
    }

    pub async fn on_aggregation_end(
        &self,
        block_number: u64,
        proof: &ZKMProofWithPublicValues,
        vk: &ZKMVerifyingKey,
        execution_report: &ExecutionReport,
        proving_duration: Duration,
    ) -> Result<()> {
        let proof_bytes = bincode::serialize(&proof.proof).unwrap();
        let public_values_bytes = bincode::serialize(&proof.public_values).unwrap();

        let mut storage_process = self.db.acquire().await?;

        storage_process
            .update_aggregation_succ(
                block_number as i64,
                (proving_duration.as_secs_f32() * 1000.0) as i64,
                execution_report.total_instruction_count() as i64,
                &proof_bytes,
                &public_values_bytes,
                vk.bytes32(),
                ProvableBlockStatus::Proved.to_string(),
            )
            .await?;

        let vk_bytes = bincode::serialize(vk).unwrap();
        storage_process.create_verifier_key(vk.bytes32(), vk_bytes.as_ref()).await?;

        Ok(())
    }

    pub async fn on_aggregation_failed(&self, block_number: u64, err: String) -> Result<()> {
        let mut storage_process = self.db.acquire().await?;

        storage_process
            .update_aggregation_failed(
                block_number as i64,
                ProvableBlockStatus::Failed.to_string(),
                err,
            )
            .await?;

        Ok(())
    }
}

#[derive(Debug)]
pub enum ProvableBlockStatus {
    Queued,
    Proved,
    Failed,
}

impl Display for ProvableBlockStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProvableBlockStatus::Queued => write!(f, "queued"),
            ProvableBlockStatus::Proved => write!(f, "proved"),
            ProvableBlockStatus::Failed => write!(f, "failed"),
        }
    }
}
