use bitcoin::Network;
use borsh::{BorshDeserialize, BorshSerialize};
use client::btc_chain::BTCClient;
use header_chain::{
    BlockHeaderCircuitOutput, CircuitBlockHeader, HeaderChainCircuitInput, HeaderChainPrevProofType,
};
use proof_builder::{LongRunning, ProofBuilder, ProofRequest};
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::{Read, Seek},
};
use zkm_sdk::ZKMProofKind;
use zkm_sdk::{
    HashableKey, Prover, ProverClient, ZKMProof, ZKMProofWithPublicValues, ZKMStdin, include_elf,
};
static ELF_ID: OnceLock<String> = OnceLock::new();
use anyhow::Context;
use clap::Parser;
use std::sync::OnceLock;

/// The arguments for the cli.
#[derive(Debug, Clone, Parser, serde::Deserialize, serde::Serialize)]
pub struct Args {
    #[arg(long, default_value_t = true)]
    pub enable: bool,

    #[arg(long, default_value = "http://127.0.0.1:3002")]
    pub esplora_url: String,

    #[arg(long, default_value_t = Network::Regtest)]
    pub btc_network: Network,

    #[clap(long, env, default_value_t = 4)]
    pub batch_size: usize,

    #[clap(long, env, default_value_t = 0)]
    pub start: usize,

    #[clap(long, env, default_value_t = false)]
    pub init_input: bool,

    #[clap(long, env, default_value = "block_headers.bin")]
    pub block_headers: String,

    #[clap(long, env, default_value = "input_proof.bin")]
    pub input_proof: String,

    #[clap(long, env, default_value = "output_proof.bin")]
    pub output_proof: String,

    #[clap(long, default_value_t = false)]
    pub force_fetch: bool,
}

impl LongRunning for Args {
    fn rotate(&self) -> Self {
        let mut next_args = self.clone();
        next_args.input_proof = self.output_proof.clone();
        next_args.init_input = false;
        next_args.start = self.start + self.batch_size;
        next_args.output_proof = format!(
            "{}/{}-{}.bin",
            std::path::Path::new(&self.output_proof).parent().unwrap().to_str().unwrap(),
            next_args.start,
            self.batch_size
        );
        next_args
    }
}

pub async fn fetch_header_chain(
    esplora_url: &str,
    start: usize,
    batch_size: usize,
    block_header_file: &str,
    force_fetch: bool,
    network: Network,
) -> anyhow::Result<Vec<CircuitBlockHeader>> {
    let btc_client = BTCClient::new(network, Some(esplora_url));

    let mut writer = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .open(block_header_file)
        .expect(&format!("Open {block_header_file} error"));

    let mut headers: Vec<u8> = Vec::new();
    writer.read_to_end(&mut headers)?;

    let mut block_headers: Vec<_> = headers
        .chunks(80)
        .map(|header| CircuitBlockHeader::try_from_slice(header).unwrap())
        .collect::<Vec<CircuitBlockHeader>>();

    if force_fetch {
        block_headers.truncate(start);
    }
    assert!(block_headers.len() == start, "Invalid starting block number");

    writer.seek(std::io::SeekFrom::Start((block_headers.len() * 80) as u64))?;

    for i in start..(start + batch_size) {
        let block = btc_client.get_block_by_height(i as u32).await?;
        tracing::info!("block_id {i}: {}", block.block_hash().to_string());
        let header: header_chain::CircuitBlockHeader = block.header.into();
        block_headers.push(header.clone());
        header.serialize(&mut writer)?;
    }
    writer.set_len((block_headers.len() * 80) as u64)?;
    let backup_file = format!(
        "{}/{}-{}.bin.blocks",
        std::path::Path::new(block_header_file).parent().unwrap().to_str().unwrap(),
        start,
        batch_size,
    );
    std::fs::copy(block_header_file, backup_file).context("copy error")?;
    Ok(block_headers)
}

/// A program that aggregates the proofs of the simple program.
pub const HEADER_CHAIN: &[u8] = include_elf!("guest");
pub struct HeaderChainProofBuilder {
    client: ProverClient,
    proving_key: zkm_sdk::ZKMProvingKey,
    verifying_key: zkm_sdk::ZKMVerifyingKey,
    // database handle
}

impl HeaderChainProofBuilder {
    pub fn new() -> Self {
        let client = ProverClient::new();
        let (proving_key, verifying_key) = client.setup(HEADER_CHAIN);
        Self { client, proving_key, verifying_key }
    }
}

impl ProofBuilder for HeaderChainProofBuilder {
    fn client(&self) -> &zkm_sdk::ProverClient {
        &self.client
    }

    fn pk(&self) -> &zkm_sdk::ZKMProvingKey {
        &self.proving_key
    }

    fn vk(&self) -> &zkm_sdk::ZKMVerifyingKey {
        &self.verifying_key
    }

    fn name() -> String {
        "header-chain".to_string()
    }

    fn build_proof(
        &self,
        ctx: &ProofRequest,
    ) -> anyhow::Result<(Vec<u8>, ZKMProofWithPublicValues, u64, f32)> {
        let ProofRequest::HeaderChainProofRequest {
            init_input,
            input_proof,
            start,
            batch_size,
            total_block_headers,
            ..
        } = ctx
        else {
            anyhow::bail!("Invalid proof request type");
        };

        let vk_hash = self.verifying_key.hash_u32();
        let mut _start = 0;
        // Set the previous proof type based on input_proof argument
        let prev_receipt = if *init_input {
            None
        } else {
            let proof_bytes = fs::read(&input_proof).context("read error")?;
            let proof: ZKMProofWithPublicValues = bincode::deserialize(&proof_bytes)?;
            Some(proof)
        };
        let (prev_proof, pv_hash) = match prev_receipt.clone() {
            Some(mut receipt) => {
                let request: BlockHeaderCircuitOutput = receipt.public_values.read();
                _start = request.chain_state.block_height as usize + 1;
                let pv_hash: [u8; 32] = receipt.public_values.hash().try_into().unwrap();
                (HeaderChainPrevProofType::PrevProof(request), pv_hash)
            }
            None => (HeaderChainPrevProofType::GenesisBlock, [0u8; 32]),
        };
        tracing::info!(
            "header-chain length: {}, start: {}, batch_size: {}",
            total_block_headers.len(),
            start,
            batch_size
        );

        let block_headers = (&total_block_headers[*start..*start + *batch_size]).to_vec();
        let input: HeaderChainCircuitInput =
            HeaderChainCircuitInput { vk_hash, prev_proof, pv_hash, block_headers };

        // Generate the proofs.
        let (proof, cycles, proving_time) = tracing::info_span!("generate proof").in_scope(
            || -> anyhow::Result<(ZKMProofWithPublicValues, u64, f32)> {
                let mut stdin = ZKMStdin::new();
                stdin.write(&input);
                if let Some(proof) = prev_receipt {
                    tracing::info!("Generate proof from block {}", _start);
                    let ZKMProof::Compressed(compressed_proof) = proof.proof else { panic!() };
                    stdin.write_proof(*compressed_proof, self.verifying_key.vk.clone());
                } else {
                    tracing::info!("Generate proof from genesis block");
                }
                let elf_id = if ELF_ID.get().is_none() {
                    ELF_ID
                        .set(hex::encode(Sha256::digest(&self.proving_key.elf)))
                        .map_err(anyhow::Error::msg)?;
                    None
                } else {
                    Some(ELF_ID.get().unwrap().clone())
                };

                let proving_start = tokio::time::Instant::now();
                let (proof, cycles) = self.client.prove_with_cycles(
                    &self.proving_key,
                    &stdin,
                    ZKMProofKind::Compressed,
                    elf_id,
                )?;
                let proving_duration = proving_start.elapsed().as_secs_f32() * 1000.0;
                Ok((proof, cycles, proving_duration))
            },
        )?;

        tracing::info!("Header chain proof cycles: {}", cycles);

        if let Err(e) = self.client.verify(&proof, &self.verifying_key) {
            panic!("{}", e);
        }

        let input = bincode::serialize(&input)?;
        Ok((input, proof, cycles, proving_time))
    }

    fn save_proof(
        &self,
        ctx: &ProofRequest,
        input: &[u8],
        _cycles: u64,
        proof: ZKMProofWithPublicValues,
    ) -> anyhow::Result<(String, usize)> {
        let ProofRequest::HeaderChainProofRequest { output_proof, .. } = ctx else {
            anyhow::bail!("invalid context");
        };
        fs::write(&output_proof, bincode::serialize(&proof)?)?;
        let public_value_hex = hex::encode(proof.public_values.as_slice());
        let proof_size = proof.bytes().len();
        fs::write(&format!("{}.vk", output_proof), bincode::serialize(&self.verifying_key)?)?;
        fs::write(&format!("{}.in", output_proof), input)?;
        tracing::info!("Generate proof successfully, proof: {:?}", proof);
        Ok((public_value_hex, proof_size))
    }
}
