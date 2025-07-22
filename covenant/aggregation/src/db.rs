use std::fmt::Display;
use std::sync::atomic::Ordering;
use std::sync::Arc;

use anyhow::{anyhow, Result};
use store::localdb::LocalDB;
use store::{GoatTxProveStatus, GoatTxType};
use tokio::time::{sleep, Duration};
use tracing::info;
use zkm_prover::ZKM_CIRCUIT_VERSION;
use zkm_sdk::{HashableKey, ZKMProof, ZKMProofWithPublicValues, ZKMPublicValues, ZKMVerifyingKey};
use zkm_verifier::GROTH16_VK_BYTES;

use crate::LAST_REMOVED_NUMBER;

const PROOF_COUNT: u64 = 20;

/// An input to the aggregation program.
///
/// Consists of a proof and a verification key.
pub struct Proof {
    pub block_number: u64,
    pub proof: ZKMProof,
    pub public_values: ZKMPublicValues,
    pub vk: Arc<ZKMVerifyingKey>,
    pub zkm_version: String,
}

pub struct Db {
    db: Arc<LocalDB>,
    aggregate_block_count: u64,
}

impl Db {
    pub fn new(db: Arc<LocalDB>, aggregate_block_count: u64) -> Self {
        Self { db, aggregate_block_count }
    }

    pub async fn set_aggregation_info(&self, start_aggregation_number: u64) -> Result<()> {
        let mut storage_process = self.db.acquire().await?;
        storage_process
            .set_aggregation_info(
                self.aggregate_block_count as i64,
                start_aggregation_number as i64,
            )
            .await?;
        Ok(())
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
            let (proof, public_values, vk_id, zkm_version) = if is_aggregate {
                storage_process.get_aggregation_proof(block_number as i64).await?
            } else {
                storage_process.get_block_proof(block_number as i64).await?
            };

            if proof.is_empty() {
                sleep(Duration::from_secs(1)).await;
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

            return Ok(Proof { block_number, proof, public_values, vk: Arc::new(vk), zkm_version });
        }
    }

    pub async fn on_aggregation_end(
        &self,
        block_number: u64,
        proof: &ZKMProofWithPublicValues,
        vk: &ZKMVerifyingKey,
        cycles: u64,
        proving_duration: Duration,
    ) -> Result<()> {
        assert_eq!(
            proof.zkm_version,
            ZKM_CIRCUIT_VERSION,
            "{}",
            format_args!(
                "Ziren version mismatch, expected {}, actual {}",
                ZKM_CIRCUIT_VERSION, proof.zkm_version,
            ),
        );

        let proof_bytes = bincode::serialize(&proof.proof).unwrap();
        let public_values_bytes = bincode::serialize(&proof.public_values).unwrap();

        let mut storage_process = self.db.acquire().await?;

        storage_process
            .update_aggregation_succ(
                block_number as i64,
                (proving_duration.as_secs_f32() * 1000.0) as i64,
                cycles as i64,
                &proof_bytes,
                &public_values_bytes,
                vk.bytes32(),
                &proof.zkm_version,
                ProvableBlockStatus::Proved.to_string(),
            )
            .await?;

        let vk_bytes = bincode::serialize(vk).unwrap();
        storage_process.create_verifier_key(vk.bytes32().as_ref(), vk_bytes.as_ref()).await?;

        self.remove_old_proofs(block_number).await?;

        Ok(())
    }

    async fn remove_old_proofs(&self, block_number: u64) -> Result<()> {
        let last_removed_number = LAST_REMOVED_NUMBER.load(Ordering::Relaxed);
        tracing::info!("last removed number: {}", last_removed_number);

        if block_number < last_removed_number + PROOF_COUNT {
            return Ok(());
        }

        let mut storage_process = self.db.acquire().await?;

        let remove_number = (block_number - PROOF_COUNT) as i64;
        storage_process.delete_block_proofs(remove_number).await?;
        storage_process.delete_aggregation_proofs(remove_number).await?;

        LAST_REMOVED_NUMBER.store(block_number, Ordering::Relaxed);
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

    pub async fn on_groth16_start(&self, block_number: u64) -> Result<bool> {
        let mut storage_process = self.db.acquire().await?;

        let block_numbers: Vec<i64> = storage_process
            .get_need_proved_goat_tx_heights(
                &GoatTxType::ProceedWithdraw.to_string(),
                &GoatTxProveStatus::Pending.to_string(),
                (block_number - self.aggregate_block_count) as i64,
                (self.aggregate_block_count) as i64,
            )
            .await?;

        if block_numbers.is_empty() {
            return Ok(false);
        }

        tracing::info!(
            "[groth16] block number: {}, real block numbers: {:?}",
            block_number,
            block_numbers
        );

        storage_process
            .create_groth16_task(block_number as i64, ProvableBlockStatus::Queued.to_string())
            .await?;

        Ok(true)
    }

    pub async fn on_groth16_end(
        &self,
        block_number: u64,
        proof: &ZKMProofWithPublicValues,
        vk: &ZKMVerifyingKey,
        proving_duration: Duration,
    ) -> Result<()> {
        assert_eq!(proof.zkm_version, ZKM_CIRCUIT_VERSION);

        let proof_bytes = bincode::serialize(&proof.proof).unwrap();
        let public_values_bytes = bincode::serialize(&proof.public_values).unwrap();

        let mut storage_process = self.db.acquire().await?;

        storage_process
            .update_groth16_succ(
                block_number as i64,
                (proving_duration.as_secs_f32() * 1000.0) as i64,
                0,
                &proof_bytes,
                &public_values_bytes,
                vk.bytes32(),
                ZKM_CIRCUIT_VERSION,
                ProvableBlockStatus::Proved.to_string(),
            )
            .await?;

        let vk_bytes = bincode::serialize(vk).unwrap();
        storage_process.create_verifier_key(vk.bytes32().as_ref(), vk_bytes.as_ref()).await?;

        storage_process.create_verifier_key(ZKM_CIRCUIT_VERSION, GROTH16_VK_BYTES.as_ref()).await?;

        Ok(())
    }

    pub async fn on_groth16_failed(&self, block_number: u64, err: String) -> Result<()> {
        let mut storage_process = self.db.acquire().await?;

        storage_process
            .update_groth16_failed(
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
