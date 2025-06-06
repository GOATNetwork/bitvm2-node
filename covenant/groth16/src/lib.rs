use std::sync::Arc;

use anyhow::Result;
use store::localdb::LocalDB;
use tracing::{info, info_span};
use zkm_prover::components::DefaultProverComponents;
use zkm_sdk::{
    include_elf, ExecutionReport, HashableKey, Prover, ProverClient, ZKMProof, ZKMProofKind,
    ZKMProofWithPublicValues, ZKMProvingKey, ZKMPublicValues, ZKMStdin, ZKMVerifyingKey,
};
use zkm_verifier::{convert_ark, load_ark_groth16_verifying_key_from_bytes, GROTH16_VK_BYTES};

mod db;
#[cfg(test)]
mod test;

pub const ELF: &[u8] = include_elf!("guest-groth16");

use crate::db::*;

pub type VerifyingKey = ark_groth16::VerifyingKey<ark_bn254::Bn254>;
pub type Groth16Proof = ark_groth16::Proof<ark_bn254::Bn254>;
pub type PublicInputs = Vec<ark_bn254::Fr>;

pub fn get_groth16_vk() -> Result<VerifyingKey> {
    let ark_groth16_vk = load_ark_groth16_verifying_key_from_bytes(&GROTH16_VK_BYTES)?;
    Ok(ark_groth16_vk.into())
}

pub async fn get_groth16_proof(
    db: &LocalDB,
    block_number: u64,
) -> Result<(Groth16Proof, PublicInputs, VerifyingKey)> {
    let start = tokio::time::Instant::now();

    let (proof, vk) = generate_groth16_proof(db, block_number).await?;

    // Convert the gnark proof to an arkworks proof.
    let ark_proof = convert_ark(&proof, &vk.bytes32(), &GROTH16_VK_BYTES)?;

    let total_duration = start.elapsed();
    info!("total duration: {:?}s", total_duration.as_secs_f32());

    Ok((ark_proof.proof, ark_proof.public_inputs.to_vec(), ark_proof.groth16_vk.vk))
}

pub async fn generate_groth16_proof(
    db: &LocalDB,
    block_number: u64,
) -> Result<(ZKMProofWithPublicValues, ZKMVerifyingKey)> {
    let (agg_proof, agg_vk) = get_aggregation_proof(db, block_number).await?;
    info!("get aggregation proof: {}", block_number);

    // Initialize the proving client.
    let client = Arc::new(ProverClient::new());

    // Setup the proving and verifying keys.
    let (pk, vk) = client.setup(ELF);
    let pk = Arc::new(pk);

    let mut stdin = ZKMStdin::new();

    // Write the block number.
    stdin.write::<u64>(&block_number);

    // Write the verification key.
    stdin.write::<[u32; 8]>(&agg_vk.hash_u32());

    // Write the public values.
    stdin.write::<Vec<u8>>(&agg_proof.public_values.to_vec());

    // Write the proofs.
    //
    // Note: this data will not actually be read by the guest, instead it will be
    // witnessed by the prover during the recursive aggregation process inside zkMIPS itself.
    let ZKMProof::Compressed(proof) = agg_proof.proof else { panic!() };
    stdin.write_proof(*proof, agg_vk.vk);

    // Only execute the program.
    let (stdin, execute_result) =
        execute_client(block_number, client.clone(), pk.clone(), stdin).await?;

    let (mut public_values, execution_report) = execute_result?;

    let cycles: u64 = execution_report.total_instruction_count();
    info!("total cycles: {:?}", cycles);

    // Read block number.
    let block_number = public_values.read::<u64>();
    info!(?block_number, "Execution sucessful");

    let proving_start = tokio::time::Instant::now();

    // Generate the aggregation proof.
    let groth16_proof = prove(block_number, client.clone(), pk.clone(), stdin).await?;

    let proving_duration = proving_start.elapsed();
    info!("proving duration: {:?}s", proving_duration.as_secs_f32());

    Ok((groth16_proof, vk))
}

// Block execution in zkMIPS is a long-running, blocking task, so run it in a separate thread.
async fn execute_client(
    number: u64,
    client: Arc<dyn Prover<DefaultProverComponents>>,
    pk: Arc<ZKMProvingKey>,
    stdin: ZKMStdin,
) -> Result<(ZKMStdin, Result<(ZKMPublicValues, ExecutionReport)>)> {
    tokio::task::spawn_blocking(move || {
        info_span!("execute_client", number).in_scope(|| {
            let result = client.execute(&pk.elf, &stdin);
            (stdin, result)
        })
    })
    .await
    .map_err(|err| anyhow::anyhow!("{err}"))
}

async fn prove(
    number: u64,
    client: Arc<dyn Prover<DefaultProverComponents>>,
    pk: Arc<ZKMProvingKey>,
    stdin: ZKMStdin,
) -> Result<ZKMProofWithPublicValues> {
    tokio::task::spawn_blocking(move || {
        info_span!("proving", number).in_scope(|| {
            client.prove(
                pk.as_ref(),
                stdin,
                Default::default(),
                Default::default(),
                ZKMProofKind::Groth16,
            )
        })
    })
    .await?
}
