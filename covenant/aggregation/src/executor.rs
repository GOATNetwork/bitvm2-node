use std::sync::{
    mpsc::{Receiver, SyncSender},
    Arc,
};
use std::sync::RwLock;

use anyhow::Result;
use tokio::time::Duration;
use lazy_static::lazy_static;
use tracing::{debug, error, info};
use zkm_sdk::{
    HashableKey, Prover, ZKMProof, ZKMProofKind, ZKMProofWithPublicValues,
    ZKMProvingKey, ZKMPublicValues, ZKMStdin, ZKMVerifyingKey, NetworkProver, ProverClient,
};
use sha2::{Digest, Sha256};
use zkm_verifier::{Groth16Verifier, GROTH16_VK_BYTES};
use zkm_prover::components::DefaultProverComponents;

use crate::db::*;

pub struct AggreationInput((Proof, Proof));

#[derive(Debug, Clone)]
pub struct ProofWithPublicValues {
    pub block_number: u64,
    pub proof: ZKMProof,
    pub public_values: ZKMPublicValues,
    pub zkm_version: String,
}

#[derive(Clone)]
pub struct AggregationExecutor<P>
where 
    P: Prover<DefaultProverComponents> + MaybeProveWithCycles + 'static
{
    db: Arc<Db>,
    client: Arc<P>,
    pk: Arc<ZKMProvingKey>,
    vk: Arc<ZKMVerifyingKey>,
    block_number: u64,
    is_start_block: bool,
    exec: bool,
}

impl<P> AggregationExecutor<P>
where 
    P: Prover<DefaultProverComponents> + MaybeProveWithCycles + 'static
{
    pub async fn new(
        db: Arc<Db>,
        client: Arc<P>,
        pk: Arc<ZKMProvingKey>,
        vk: Arc<ZKMVerifyingKey>,
        block_number: u64,
        is_start_block: bool,
        exec: bool,
    ) -> Self {
        Self { db, client, pk, vk, block_number, is_start_block, exec }
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
                let agg_input = if self.is_start_block && block_number == self.block_number {
                    restart = false;
                    let block_proof1 = self.db.load_proof(block_number - 1, false).await?;
                    let block_proof2 = self.db.load_proof(block_number, false).await?;
                    AggreationInput((block_proof1, block_proof2))
                } else {
                    let block_proof = self.db.load_proof(block_number, false).await?;
                    let pre_agg_proof = if restart {
                        restart = false;
                        self.db.load_proof(block_number - 1, true).await?
                    } else {
                        let agg_proof = agg_proof_rx.recv()?;
                        assert_eq!(agg_proof.block_number, block_number - 1);
                        Proof {
                            block_number: block_number - 1,
                            proof: agg_proof.proof,
                            public_values: agg_proof.public_values,
                            vk: self.vk.clone(),
                            zkm_version: agg_proof.zkm_version,
                        }
                    };
                    AggreationInput((pre_agg_proof, block_proof))
                };

                self.db.on_aggregation_start(block_number).await?;
                input_tx.send(agg_input)?;
                info!("Successfully load proofs: {}, {}", block_number - 1, block_number);
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
                let block_number = proofs.0 .1.block_number;
                match self.generate_aggregation_proof(vec![proofs.0 .0, proofs.0 .1]).await {
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
                block_number_tx.send(block_number + 1)?;
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

        for input in inputs {
            stdin.write::<[u32; 8]>(&input.vk.hash_u32());

            stdin.write::<Vec<u8>>(&input.public_values.to_vec());

            // Note: this data will not actually be read by the aggregation program, instead it will be
            // witnessed by the prover during the recursive aggregation process inside Ziren itself.
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

        let proving_start = tokio::time::Instant::now();

        // Generate the aggregation proof.
        let (agg_proof, cycles) = self.client.prove_with_cycles(self.pk.as_ref(), &stdin, ZKMProofKind::Compressed).await?;

        let proving_duration = proving_start.elapsed();
        let block_number = block_numbers.last().unwrap();
        info!("[Aggregation] [{}] proving duration: {:?}s", block_number, proving_duration.as_secs_f32());

        Ok((agg_proof, cycles.unwrap_or_default(), proving_duration))
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

        let groth16_proof = self.client.prove(self.pk.as_ref(), stdin, ZKMProofKind::CompressToGroth16)?;

        let proving_duration = proving_start.elapsed();
        info!("[Groth16] [{}] proving duration: {:?}s", block_number, proving_duration.as_secs_f32());

        Ok((groth16_proof, proving_duration))
    }
}


lazy_static! {
    static ref ELF_ID: RwLock<String> = RwLock::new(Default::default());
}

pub trait MaybeProveWithCycles {
    fn prove_with_cycles(
        &self,
        pk: &ZKMProvingKey,
        stdin: &ZKMStdin,
        mode: ZKMProofKind,
    ) -> impl std::future::Future<
        Output = Result<(ZKMProofWithPublicValues, Option<u64>)>,
    > + Send;
}

impl MaybeProveWithCycles for ProverClient {
    async fn prove_with_cycles(
        &self,
        pk: &ZKMProvingKey,
        stdin: &ZKMStdin,
        mode: ZKMProofKind,
    ) -> Result<(ZKMProofWithPublicValues, Option<u64>)> {
        let mut prove = self.prove(pk, stdin.clone());
        prove = match mode {
            ZKMProofKind::Core => prove.core(),
            ZKMProofKind::Compressed => prove.compressed(),
            ZKMProofKind::Groth16 => prove.groth16(),
            ZKMProofKind::Plonk => prove.plonk(),
            ZKMProofKind::CompressToGroth16 => unreachable!(),
        };
        let proof = prove.run()?;

        Ok((proof, None))
    }
}

impl MaybeProveWithCycles for NetworkProver {
    async fn prove_with_cycles(
        &self,
        pk: &ZKMProvingKey,
        stdin: &ZKMStdin,
        mode: ZKMProofKind,
    ) -> Result<(ZKMProofWithPublicValues, Option<u64>)> {
        let elf_id = hex::encode(Sha256::digest(&pk.elf));

        let (elf, elf_id) = if *ELF_ID.read().unwrap() != elf_id {
            let mut id = ELF_ID.write().unwrap();
            *id = elf_id;

            (&pk.elf, None)
        } else {
            (&Default::default(), Some(elf_id))
        };
        tracing::info!("elf id: {:?}", elf_id);

        let (proof, cycles) = self
            .prove_with_cycles(elf, stdin.clone(), mode, elf_id, None)
            .await?;

        return Ok((proof, Some(cycles)));
    }
}
