use anyhow::{anyhow, Result};
use store::localdb::LocalDB;
use tokio::time::{sleep, Duration};
use tracing::info;
use zkm_sdk::{ZKMProof, ZKMPublicValues, ZKMVerifyingKey};

pub struct AggregationProof {
    pub proof: ZKMProof,
    pub public_values: ZKMPublicValues,
}

pub async fn get_aggregation_proof(
    db: &LocalDB,
    block_number: u64,
) -> Result<(AggregationProof, ZKMVerifyingKey)> {
    let mut storage_process = db.acquire().await?;

    loop {
        let (proof, public_values, vk_id) =
            storage_process.get_aggregation_proof(block_number as i64).await?;

        if proof.is_empty() {
            sleep(Duration::from_millis(500)).await;
            info!("waiting aggregation proof: {}", block_number);
            continue;
        }

        let proof: ZKMProof = bincode::deserialize(&proof)?;
        let public_values: ZKMPublicValues = bincode::deserialize(&public_values)?;

        let vk = storage_process.get_verifier_key(&vk_id).await?;
        if vk.is_empty() {
            return Err(anyhow!("vk is not exists: {}", vk_id));
        }
        let vk: ZKMVerifyingKey = bincode::deserialize(&vk)?;

        return Ok((AggregationProof { proof, public_values }, vk));
    }
}
