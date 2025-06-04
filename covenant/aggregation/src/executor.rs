use std::sync::{
    mpsc::{Receiver, SyncSender},
    Arc,
};

use anyhow::Result;
use tokio::time::Duration;
use tracing::{error, info, info_span};
use zkm_prover::components::DefaultProverComponents;
use zkm_sdk::{
    ExecutionReport, HashableKey, Prover, ProverClient, ZKMProof, ZKMProofKind,
    ZKMProofWithPublicValues, ZKMProvingKey, ZKMPublicValues, ZKMStdin, ZKMVerifyingKey,
};

use crate::db::*;

pub struct AggreationInput((Proof, Proof));

#[derive(Debug, Clone)]
pub struct ProofWithPublicValues {
    pub proof: ZKMProof,
    pub public_values: ZKMPublicValues,
}

#[derive(Clone)]
pub struct AggregationExecutor {
    db: Arc<Db>,
    client: Arc<dyn Prover<DefaultProverComponents>>,
    pk: Arc<ZKMProvingKey>,
    vk: Arc<ZKMVerifyingKey>,
}

impl AggregationExecutor {
    pub async fn new(db: Arc<Db>, elf: &[u8]) -> Self {
        // Initialize the proving client.
        let client = Arc::new(ProverClient::new());

        // Setup the proving and verifying keys.
        let (pk, vk) = client.setup(elf);

        Self { db, client, pk: Arc::new(pk), vk: Arc::new(vk) }
    }

    pub async fn data_preparer(
        self,
        block_number_rx: Receiver<u64>,
        input_tx: SyncSender<AggreationInput>,
        proof_rx: Receiver<ProofWithPublicValues>,
    ) -> Result<()> {
        let mut restart = true;

        loop {
            let block_number = block_number_rx.recv();
            if let Ok(block_number) = block_number {
                self.db.on_aggregation_start(block_number).await?;

                let agg_input = match block_number {
                    2 => {
                        restart = false;
                        let block_proof1 = self.db.load_proof(1, false).await?;
                        let block_proof2 = self.db.load_proof(2, false).await?;
                        AggreationInput((block_proof1, block_proof2))
                    }
                    n if n > 2 => {
                        let block_proof = self.db.load_proof(block_number, false).await?;
                        let pre_agg_proof = if restart {
                            restart = false;
                            self.db.load_proof(block_number - 1, true).await?
                        } else {
                            let agg_proof = proof_rx.recv()?;
                            Proof {
                                block_number: block_number - 1,
                                proof: agg_proof.proof,
                                public_values: agg_proof.public_values,
                                vk: self.vk.clone(),
                            }
                        };
                        AggreationInput((pre_agg_proof, block_proof))
                    }
                    _ => panic!("block number >= 2"),
                };

                input_tx.send(agg_input)?;
                info!("Successfully load proofs: {}, {}", block_number - 1, block_number);
            } else {
                break;
            }
        }
        Ok(())
    }

    pub async fn proof_aggregator(
        self,
        block_number_tx: SyncSender<u64>,
        input_rx: Receiver<AggreationInput>,
        proof_tx: SyncSender<ProofWithPublicValues>,
    ) -> Result<()> {
        loop {
            let proofs = input_rx.recv();
            if let Ok(proofs) = proofs {
                let block_number = proofs.0 .1.block_number;
                match self.generate_aggregation_proof(vec![proofs.0 .0, proofs.0 .1]).await {
                    Ok((agg_proof, ref exec_report, proving_duration)) => {
                        info!("Successfully processed block {}", block_number);
                        self.db
                            .on_aggregation_end(
                                block_number,
                                &agg_proof,
                                &self.vk,
                                exec_report,
                                proving_duration,
                            )
                            .await?;
                        proof_tx.send(ProofWithPublicValues {
                            proof: agg_proof.proof,
                            public_values: agg_proof.public_values,
                        })?;
                    }
                    Err(err) => {
                        error!("Error executing block {}: {}", block_number, err);
                        self.db.on_aggregation_failed(block_number, err.to_string()).await?;
                    }
                }
                block_number_tx.send(block_number + 1)?;
            } else {
                break;
            }
        }
        Ok(())
    }

    async fn generate_aggregation_proof(
        &self,
        inputs: Vec<Proof>,
    ) -> Result<(ZKMProofWithPublicValues, ExecutionReport, Duration)> {
        let mut stdin = ZKMStdin::new();

        // Write the block numbers.
        let block_numbers: Vec<u64> =
            inputs.iter().map(|input| input.block_number).collect::<Vec<_>>();
        stdin.write::<Vec<u64>>(&block_numbers);

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
        let block_number = block_numbers.last().unwrap().to_owned();
        let (stdin, execute_result) =
            execute_client(block_number, self.client.clone(), self.pk.clone(), stdin).await?;

        let (mut public_values, execution_report) = execute_result?;

        let cycles: u64 = execution_report.total_instruction_count();
        info!("total cycles: {:?}", cycles);

        // Read block numbers.
        let block_numbers = public_values.read::<Vec<u64>>();
        info!(?block_numbers, "Execution sucessful");

        let proving_start = tokio::time::Instant::now();

        // Generate the aggregation proof.
        let client = self.client.clone();
        let pk = self.pk.clone();
        let agg_proof = tokio::task::spawn_blocking(move || {
            client.prove(
                pk.as_ref(),
                stdin,
                Default::default(),
                Default::default(),
                ZKMProofKind::Compressed,
            )
        })
        .await??;

        let proving_duration = proving_start.elapsed();
        info!("proving duration: {:?}s", proving_duration.as_secs_f32());

        self.client.verify(&agg_proof, &self.vk).unwrap();

        Ok((agg_proof, execution_report, proving_duration))
    }
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
