use std::sync::OnceLock;
use std::sync::{
    mpsc::{Receiver, SyncSender},
    Arc,
};

use anyhow::Result;
use sha2::{Digest, Sha256};
use tokio::time::Duration;
use tracing::{debug, error, info};
use zkm_prover::components::DefaultProverComponents;
use zkm_sdk::{
    HashableKey, Prover, ZKMProof, ZKMProofKind, ZKMProofWithPublicValues, ZKMProvingKey,
    ZKMPublicValues, ZKMStdin, ZKMVerifyingKey,
};
use zkm_verifier::{Groth16Verifier, GROTH16_VK_BYTES};

use crate::db::*;

pub struct AggreationInput(Vec<Proof>);

static ELF_ID: OnceLock<String> = OnceLock::new();

#[derive(Debug, Clone)]
pub struct ProofWithPublicValues {
    pub block_number: u64,
    pub proof: ZKMProof,
    pub public_values: ZKMPublicValues,
    pub zkm_version: String,
}

#[derive(Clone)]
pub struct AggregationExecutor {
    db: Arc<Db>,
    client: Arc<dyn Prover<DefaultProverComponents>>,
    pk: Arc<ZKMProvingKey>,
    vk: Arc<ZKMVerifyingKey>,
    block_number: u64,
    is_start_block: bool,
    exec: bool,
    agg_count: u64,
}

impl AggregationExecutor {
    pub async fn new(
        db: Arc<Db>,
        client: Arc<dyn Prover<DefaultProverComponents>>,
        pk: Arc<ZKMProvingKey>,
        vk: Arc<ZKMVerifyingKey>,
        block_number: u64,
        is_start_block: bool,
        agg_count: u64,
        exec: bool,
    ) -> Self {
        db.set_aggregate_block_count().await.unwrap();
        Self { db, client, pk, vk, block_number, is_start_block, agg_count, exec }
    }

    pub async fn data_preparer(
        self,
        block_number_rx: Receiver<u64>,
        input_tx: SyncSender<AggreationInput>,
        agg_proof_rx: Receiver<ProofWithPublicValues>,
    ) -> Result<()> {
        let mut restart = true;

        loop {
            let block_number = block_number_rx.recv();
            if let Ok(block_number) = block_number {
                let mut proofs = vec![];
                let start_number = if self.agg_count == 1 {
                    block_number - 1
                } else {
                    block_number - self.agg_count + 1
                };

                for number in start_number..=block_number {
                    let block_proof = self.db.load_proof(number, false).await?;
                    proofs.push(block_proof);
                }

                let agg_input = if self.is_start_block && block_number == self.block_number {
                    restart = false;
                    AggreationInput(proofs)
                } else {
                    let pre_agg_proof = if restart {
                        restart = false;
                        self.db.load_proof(block_number - self.agg_count, true).await?
                    } else {
                        let agg_proof = agg_proof_rx.recv()?;
                        assert_eq!(agg_proof.block_number, block_number - self.agg_count);
                        Proof {
                            block_number: block_number - self.agg_count,
                            proof: agg_proof.proof,
                            public_values: agg_proof.public_values,
                            vk: self.vk.clone(),
                            zkm_version: agg_proof.zkm_version,
                        }
                    };

                    proofs.insert(0, pre_agg_proof);
                    AggreationInput(proofs)
                };

                self.db.on_aggregation_start(block_number).await?;
                input_tx.send(agg_input)?;
                info!(
                    "Successfully load proofs: {}-{}",
                    block_number - self.agg_count,
                    block_number
                );
            }
        }
    }

    pub async fn proof_aggregator(
        self,
        block_number_tx: SyncSender<u64>,
        input_rx: Receiver<AggreationInput>,
        agg_proof_tx: SyncSender<ProofWithPublicValues>,
        groth16_proof_tx: SyncSender<ProofWithPublicValues>,
    ) -> Result<()> {
        loop {
            let proofs = input_rx.recv();
            if let Ok(proofs) = proofs {
                let block_number = proofs.0.last().unwrap().block_number;
                match self.generate_aggregation_proof(proofs.0).await {
                    Ok((agg_proof, cycles, proving_duration)) => {
                        info!("Successfully generate aggregation proof: {}", block_number);
                        self.db
                            .on_aggregation_end(
                                block_number,
                                &agg_proof,
                                &self.vk,
                                cycles,
                                proving_duration,
                            )
                            .await?;

                        let proof = ProofWithPublicValues {
                            block_number,
                            proof: agg_proof.proof,
                            public_values: agg_proof.public_values,
                            zkm_version: agg_proof.zkm_version,
                        };

                        groth16_proof_tx.send(proof.clone())?;
                        agg_proof_tx.send(proof)?;
                    }
                    Err(err) => {
                        error!("Error generate aggregation proof {}: {}", block_number, err);
                        self.db.on_aggregation_failed(block_number, err.to_string()).await?;
                    }
                }
                block_number_tx.send(block_number + self.agg_count)?;
            }
        }
    }

    async fn generate_aggregation_proof(
        &self,
        inputs: Vec<Proof>,
    ) -> Result<(ZKMProofWithPublicValues, u64, Duration)> {
        inputs.iter().for_each(|input| {
            assert_eq!(
                input.zkm_version,
                self.client.version(),
                "{}",
                format_args!(
                    "Ziren version mismatch, expected {}, actual {}",
                    self.client.version(),
                    input.zkm_version,
                ),
            );
        });

        let block_numbers: Vec<u64> =
            inputs.iter().map(|input| input.block_number).collect::<Vec<_>>();

        let mut stdin = ZKMStdin::new();

        // Write the verification keys.
        let vkeys = inputs.iter().map(|input| input.vk.hash_u32()).collect::<Vec<_>>();
        stdin.write::<Vec<[u32; 8]>>(&vkeys);

        // Write the public values.
        let public_values =
            inputs.iter().map(|input| input.public_values.to_vec()).collect::<Vec<_>>();
        stdin.write::<Vec<Vec<u8>>>(&public_values);

        // Write the proofs.
        //
        // Note: this data will not actually be read by the aggregation program, instead it will be
        // witnessed by the prover during the recursive aggregation process inside zkMIPS itself.
        for input in inputs {
            let ZKMProof::Compressed(proof) = input.proof else { panic!() };
            stdin.write_proof(*proof, input.vk.vk.clone());
        }

        // Only execute the program.
        if self.exec {
            let execute_result = self.client.execute(&self.pk.elf, &stdin);

            let (_public_values, execution_report) = execute_result?;

            let cycles: u64 = execution_report.total_instruction_count();
            info!("[Aggregation] total cycles: {:?}", cycles);

            info!(?block_numbers, "[Aggregation] Execution successful");
        }

        let client_clone = self.client.clone();
        let pk = self.pk.clone();

        let elf_id = if ELF_ID.get().is_none() {
            ELF_ID.set(hex::encode(Sha256::digest(&pk.elf))).unwrap();
            None
        } else {
            Some(ELF_ID.get().unwrap().clone())
        };
        tracing::info!("elf id: {:?}", elf_id);

        let proving_start = tokio::time::Instant::now();

        // Generate the aggregation proof.
        let (agg_proof, cycles) = tokio::task::spawn_blocking(move || {
            client_clone.prove_with_cycles(&pk, &stdin, ZKMProofKind::Compressed, elf_id)
        })
        .await??;

        let proving_duration = proving_start.elapsed();
        let block_number = block_numbers.last().unwrap();
        info!(
            "[Aggregation] [{}] proving duration: {:?}s, cycles: {:?}",
            block_number,
            proving_duration.as_secs_f32(),
            cycles
        );

        Ok((agg_proof, cycles, proving_duration))
    }
}

#[derive(Clone)]
pub struct Groth16Executor {
    db: Arc<Db>,
    client: Arc<dyn Prover<DefaultProverComponents>>,
    pk: Arc<ZKMProvingKey>,
    vk: Arc<ZKMVerifyingKey>,
}

impl Groth16Executor {
    pub async fn new(
        db: Arc<Db>,
        client: Arc<dyn Prover<DefaultProverComponents>>,
        pk: Arc<ZKMProvingKey>,
        vk: Arc<ZKMVerifyingKey>,
    ) -> Self {
        Self { db, client, pk, vk }
    }

    pub async fn proof_generator(self, groth16_rx: Receiver<ProofWithPublicValues>) -> Result<()> {
        loop {
            let recv = groth16_rx.recv();
            if let Ok(agg_proof) = recv {
                let block_number = agg_proof.block_number;

                let should_generate_proof = self.db.on_groth16_start(block_number).await?;
                if !should_generate_proof {
                    debug!("Skip groth16 proof generation for block {}", block_number);
                    continue;
                }

                match self.generate_groth16_proof(block_number, agg_proof).await {
                    Ok((groth16_proof, proving_duration)) => {
                        info!("Successfully generate groth16 proof {}", block_number);
                        self.db
                            .on_groth16_end(
                                block_number,
                                &groth16_proof,
                                &self.vk,
                                proving_duration,
                            )
                            .await?;

                        Groth16Verifier::verify(
                            &groth16_proof.bytes(),
                            &groth16_proof.public_values.to_vec(),
                            &self.vk.bytes32(),
                            &GROTH16_VK_BYTES,
                        )
                        .expect("Groth16 proof is invalid");
                    }
                    Err(err) => {
                        error!("Error generate groth16 proof {}: {}", block_number, err);
                        self.db.on_groth16_failed(block_number, err.to_string()).await?;
                    }
                }
            }
        }
    }

    async fn generate_groth16_proof(
        &self,
        block_number: u64,
        agg_proof: ProofWithPublicValues,
    ) -> Result<(ZKMProofWithPublicValues, Duration)> {
        assert_eq!(
            agg_proof.zkm_version,
            self.client.version(),
            "{}",
            format_args!(
                "Ziren version mismatch, expected {}, actual {}",
                self.client.version(),
                agg_proof.zkm_version
            ),
        );

        let mut stdin = ZKMStdin::new();
        stdin.write::<ZKMPublicValues>(&agg_proof.public_values);

        let ZKMProof::Compressed(proof) = agg_proof.proof else { panic!() };
        stdin.write_proof(*proof, self.vk.vk.clone());

        let proving_start = tokio::time::Instant::now();

        let client = self.client.clone();
        let pk = self.pk.clone();

        let groth16_proof = tokio::task::spawn_blocking(move || {
            client.prove(&pk, stdin, ZKMProofKind::CompressToGroth16)
        })
        .await??;

        let proving_duration = proving_start.elapsed();
        info!(
            "[Groth16] [{}] proving duration: {:?}s",
            block_number,
            proving_duration.as_secs_f32()
        );

        Ok((groth16_proof, proving_duration))
    }
}
