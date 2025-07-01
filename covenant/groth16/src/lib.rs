use anyhow::Result;
use store::localdb::LocalDB;
use tokio::time::{Duration, sleep};
use tracing::info;
use zkm_prover::ZKM_CIRCUIT_VERSION;
use zkm_sdk::{ZKMProofWithPublicValues, ZKMStdin};
use zkm_verifier::{GROTH16_VK_BYTES, convert_ark, load_ark_groth16_verifying_key_from_bytes};

pub type VerifyingKey = ark_groth16::VerifyingKey<ark_bn254::Bn254>;
pub type Groth16Proof = ark_groth16::Proof<ark_bn254::Bn254>;
pub type PublicInputs = Vec<ark_bn254::Fr>;

pub fn get_latest_groth16_vk() -> Result<VerifyingKey> {
    Ok(load_ark_groth16_verifying_key_from_bytes(&GROTH16_VK_BYTES)?)
}

pub fn get_zkm_version() -> String {
    ZKM_CIRCUIT_VERSION.to_owned()
}

pub async fn get_groth16_vk(db: &LocalDB, zkm_version: &str) -> Result<VerifyingKey> {
    if zkm_version == ZKM_CIRCUIT_VERSION {
        return get_latest_groth16_vk();
    }
    let mut storage_process = db.acquire().await?;
    let groth16_vk_bytes = storage_process.get_groth16_vk(zkm_version).await?;
    if groth16_vk_bytes.is_empty() {
        return Err(anyhow::anyhow!("No Groth16 VK found for version: {}", zkm_version));
    }
    Ok(load_ark_groth16_verifying_key_from_bytes(&groth16_vk_bytes)?)
}

pub async fn get_groth16_proof(
    db: &LocalDB,
    block_number: u64,
) -> Result<(Groth16Proof, PublicInputs, VerifyingKey, String)> {
    let mut storage_process = db.acquire().await?;

    loop {
        let (proof, public_values, verifier_id, zkm_version) =
            storage_process.get_groth16_proof(block_number as i64).await?;

        if proof.is_empty() {
            sleep(Duration::from_secs(1)).await;
            info!("waiting groth16 proof: {}", block_number);
            continue;
        }

        let groth16_vk = storage_process.get_groth16_vk(&zkm_version).await?;

        let proof = ZKMProofWithPublicValues {
            proof: bincode::deserialize(&proof)?,
            public_values: bincode::deserialize(&public_values)?,
            zkm_version: zkm_version.to_string(),
            stdin: ZKMStdin::default(),
        };

        // Convert the gnark proof to an arkworks proof.
        let ark_proof = convert_ark(&proof, &verifier_id, &groth16_vk)?;

        return Ok((
            ark_proof.proof,
            ark_proof.public_inputs.to_vec(),
            ark_proof.groth16_vk.vk,
            zkm_version,
        ));
    }
}

#[cfg(test)]
mod tests {
    use ark_bn254::Bn254;
    use ark_groth16::{Groth16, r1cs_to_qap::LibsnarkReduction};
    use store::localdb::LocalDB;
    use tracing::Level;
    use zkm_prover::ZKM_CIRCUIT_VERSION;

    use super::*;

    #[tokio::test]
    async fn test_groth16_proof() {
        tracing_subscriber::fmt().with_max_level(Level::INFO).init();

        const DB_URL: &str = "/tmp/.bitvm2-node.db";
        let db: LocalDB = LocalDB::new(&format!("sqlite:{DB_URL}"), true).await;

        let (proof, public_inputs, groth16_vk, zkm_version) =
            get_groth16_proof(&db, 2).await.unwrap();

        assert_eq!(zkm_version, ZKM_CIRCUIT_VERSION);
        assert_eq!(&get_zkm_version(), ZKM_CIRCUIT_VERSION);

        let latest_groth16_vk = get_latest_groth16_vk().unwrap();
        let groth16_vk1 = get_groth16_vk(&db, &zkm_version).await.unwrap();
        assert_eq!(groth16_vk, latest_groth16_vk);
        assert_eq!(groth16_vk1, latest_groth16_vk);

        // Verify the arkworks proof.
        let ok = Groth16::<Bn254, LibsnarkReduction>::verify_proof(
            &groth16_vk.into(),
            &proof,
            &public_inputs,
        )
        .unwrap();
        assert!(ok);
    }
}
