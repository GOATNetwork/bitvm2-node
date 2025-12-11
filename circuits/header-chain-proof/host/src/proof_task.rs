use anyhow::bail;
use bitcoin::Network;
use std::time::UNIX_EPOCH;

#[inline(always)]
fn current_time_secs() -> i64 {
    std::time::SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64
}
use client::btc_chain::BTCClient;
use header_chain::{CircuitBlockHeader, HeaderChainCircuitInput, HeaderChainPrevProofType};
use sha2::{Digest, Sha256};
use std::fs;
use std::sync::OnceLock;
use std::time::Duration;
use store::localdb::LocalDB;
use store::{HeaderChainProof, ProofDataLocation, ProofStatus};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};
use zkm_prover::{HashableKey, ZKMProvingKey, ZKMVerifyingKey};
use zkm_sdk::{
    Prover, ProverClient, ZKMProof, ZKMProofKind, ZKMProofWithPublicValues, ZKMStdin, include_elf,
};
const HEADER_CHAIN: &[u8] = include_elf!("guest");

/// Configuration for header chain proof task
#[derive(Debug, Clone)]
pub struct HeaderChainProofConfig {
    pub local_db: LocalDB,
    pub esplora_url: String,
    pub data_dir: String,
    pub batch_size: i64,
    pub is_save_to_file: bool,
}

static ELF_ID: OnceLock<String> = OnceLock::new();
async fn fetch_header_chain(
    btc_client: &BTCClient,
    start: i64,
    batch_size: i64,
) -> anyhow::Result<Vec<CircuitBlockHeader>> {
    let mut block_headers = vec![];
    for i in start..(start + batch_size) {
        let block = btc_client.get_block_by_height(i as u32).await?;
        block_headers.push(block.header.into());
    }
    Ok(block_headers)
}

fn get_pre_proof(
    pre_proof_task: &Option<HeaderChainProof>,
) -> anyhow::Result<(Option<ZKMProofWithPublicValues>, HeaderChainPrevProofType, [u8; 32])> {
    match pre_proof_task {
        Some(pre_proof_task) => {
            if pre_proof_task.status != ProofStatus::Proved.to_string() {
                bail!("input pre proof task not finished!")
            }

            let proof_bytes = if pre_proof_task.data_location == ProofDataLocation::File.to_string()
            {
                fs::read(&pre_proof_task.proof)?
            } else {
                hex::decode(&pre_proof_task.proof)?
            };
            let mut proof: ZKMProofWithPublicValues = bincode::deserialize(&proof_bytes)?;
            let pv_hash: [u8; 32] =
                proof.public_values.hash().try_into().expect("fail to cast to public_values hash");
            Ok((
                Some(proof.clone()),
                HeaderChainPrevProofType::PrevProof(proof.public_values.read()),
                pv_hash,
            ))
        }

        None => Ok((None, HeaderChainPrevProofType::GenesisBlock, [0; 32])),
    }
}

fn get_file_path(data_dir: &str, start: i64, batch: i64) -> String {
    format!("{}/header-chain/{start}_{batch}.bin", data_dir)
}

async fn run_task(
    btc_client: &BTCClient,
    prove_client: &ProverClient,
    pk: &ZKMProvingKey,
    vk: &ZKMVerifyingKey,
    config: HeaderChainProofConfig,
) -> anyhow::Result<()> {
    let latest_proof_task = {
        let mut storage_processor = config.local_db.acquire().await?;
        storage_processor.find_latest_header_chain_proof_task().await?
    };
    let (mut id, start, batch_size, latest_proof_task) = match latest_proof_task {
        Some(latest_proof_task) => {
            if latest_proof_task.status != ProofStatus::Proved.to_string() {
                warn!("latest header chain proof task not Proved  {}", latest_proof_task.id);
                (0, latest_proof_task.start, latest_proof_task.batch_size, Some(latest_proof_task))
            } else {
                (
                    latest_proof_task.id,
                    latest_proof_task.start + latest_proof_task.batch_size + 1,
                    config.batch_size,
                    Some(latest_proof_task),
                )
            }
        }
        None => (0, 0, config.batch_size, None),
    };
    if start + batch_size - 1 > btc_client.get_height().await? as i64 {
        return Ok(());
    }
    let data_location = if config.is_save_to_file {
        ProofDataLocation::File.to_string()
    } else {
        ProofDataLocation::DB.to_string()
    };
    let vk_hash = vk.hash_u32();
    let (prev_receipt, prev_proof, pv_hash) = get_pre_proof(&latest_proof_task)?;
    let input: HeaderChainCircuitInput = HeaderChainCircuitInput {
        vk_hash,
        prev_proof,
        pv_hash,
        block_headers: fetch_header_chain(&btc_client, start, batch_size).await?,
    };
    if latest_proof_task.is_none() {
        let mut tx = config.local_db.start_transaction().await?;
        id = tx
            .create_header_chain_proof(&HeaderChainProof {
                id: 0,
                data_location: data_location.clone(),
                batch_size,
                start,
                proof: "".to_string(),
                verifier_id: vk.bytes32(),
                public_inputs: hex::encode(&bincode::serialize(&input)?),
                status: ProofStatus::Pending.to_string(),
                proving_cycles: 0,
                proof_size: 0,
                proving_time: 0,
                zkm_version: "".to_string(),
                created_at: current_time_secs(),
                updated_at: current_time_secs(),
            })
            .await?;
        tx.create_verifier_key(&vk.bytes32(), &bincode::serialize(&vk)?).await?;
        tx.commit().await?;
        info!("created header chain proof at id {id}");
    };

    let mut stdin = ZKMStdin::new();
    stdin.write(&input);
    if let Some(proof) = prev_receipt {
        let ZKMProof::Compressed(compressed_proof) = proof.proof else {
            bail!("pre proof is not compressed")
        };
        stdin.write_proof(*compressed_proof, vk.vk.clone());
    }
    let proving_start = tokio::time::Instant::now();
    let (proof, cycles) =
        prove_client.prove_with_cycles(&pk, &stdin, ZKMProofKind::Compressed, get_elf_id(&pk))?;
    let zkm_version = proof.zkm_version.clone();
    let proving_duration = proving_start.elapsed().as_secs();
    if let Err(e) = prove_client.verify(&proof, &vk) {
        bail!(
            "header chain proof task: start at {start}, batch:{batch_size} proof verify failed, err: {}",
            e
        );
    }
    let proof_bytes = bincode::serialize(&proof)?;
    let proof = if data_location == ProofDataLocation::File.to_string() {
        let file_path = get_file_path(&config.data_dir, start, batch_size);
        fs::write(file_path.clone(), &proof_bytes)?;
        file_path
    } else {
        hex::encode(&proof_bytes)
    };
    let mut tx = config.local_db.start_transaction().await?;
    tx.update_header_chain_proof(
        id,
        &vk.bytes32(),
        &proof,
        &hex::encode(&bincode::serialize(&input)?),
        cycles as i64,
        proof_bytes.len() as i64,
        &zkm_version,
        proving_duration as i64,
        &ProofStatus::Proved.to_string(),
    )
    .await?;
    tx.create_verifier_key(&vk.bytes32(), &bincode::serialize(&vk)?).await?;
    tx.commit().await?;
    Ok(())
}

fn get_elf_id(pk: &&ZKMProvingKey) -> Option<String> {
    let elf_id = if ELF_ID.get().is_none() {
        ELF_ID.set(hex::encode(Sha256::digest(&pk.elf))).unwrap();
        None
    } else {
        Some(ELF_ID.get().unwrap().clone())
    };
    elf_id
}

pub fn spawn_header_chain_proof_task(
    interval: u64,
    initial_delay: u64,
    cancellation_token: CancellationToken,
    config: HeaderChainProofConfig,
) -> JoinHandle<anyhow::Result<()>> {
    tokio::spawn(async move {
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_secs(initial_delay)) => {}
            _ = cancellation_token.cancelled() => {
                return Err(anyhow::anyhow!("Header chain proof generate task cancelled"));
            }
        }
        let btc_client = BTCClient::new(Network::Regtest, Some(&config.esplora_url));
        let client = ProverClient::new();
        let (pk, vk) = client.setup(HEADER_CHAIN);
        loop {
            tokio::select! {
                _ = tokio::time::sleep(Duration::from_secs(interval)) => {
                    info!("Header chain proof generate task: generate proof");
                    match run_task(&btc_client, &client, &pk , &vk, config.clone()).await{
                        Ok(_) => {}
                        Err(err) => {
                            warn!("Header chain proof generate task: fail to generate proof:{}", err);
                        }
                    }
                }
                _ = cancellation_token.cancelled() => {
                    return Err(anyhow::anyhow!("Header chain proof generate task cancelled"));
                }
            }
        }
    })
}
