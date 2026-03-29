use anyhow::{Context, Result, anyhow, bail};
use bitcoin::secp256k1::{PublicKey, SecretKey};
use bitcoin_light_client_circuit::{
    append_part_stark_vk_and_sign_with_signers, part_stark_vk_attestation_dir,
    resign_current_part_stark_vk_root_with_signers,
};
use clap::{Parser, Subcommand};
use commit_chain::CommitInfo;
use std::path::PathBuf;
use std::str::FromStr;
use zkm_verifier::Groth16Verifier;

#[derive(Debug, Clone)]
struct PublisherSignerArg {
    signer_pubkey_index: usize,
    secret_key: SecretKey,
}

impl FromStr for PublisherSignerArg {
    type Err = anyhow::Error;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let (signer_pubkey_index, secret_key) = value
            .split_once(':')
            .ok_or_else(|| anyhow!("invalid signer format, expected <index>:<secret_key_hex>"))?;
        Ok(Self {
            signer_pubkey_index: signer_pubkey_index
                .parse()
                .context("invalid signer_pubkey_index")?,
            secret_key: SecretKey::from_str(secret_key).context("invalid secret_key hex")?,
        })
    }
}

#[derive(Debug, Parser)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    Append {
        #[arg(long)]
        part_stark_vk_file: Option<PathBuf>,
        #[arg(long)]
        zkm_version: Option<String>,
        #[arg(long)]
        commit_info_file: PathBuf,
        #[arg(long, value_delimiter = ',')]
        publisher_signers: Vec<PublisherSignerArg>,
        #[arg(long)]
        attestation_dir: Option<PathBuf>,
    },
    ResignCurrentRoot {
        #[arg(long)]
        commit_info_file: PathBuf,
        #[arg(long, value_delimiter = ',')]
        publisher_signers: Vec<PublisherSignerArg>,
        #[arg(long)]
        attestation_dir: Option<PathBuf>,
    },
}

fn resolve_attestation_dir(attestation_dir: Option<PathBuf>) -> PathBuf {
    attestation_dir.unwrap_or_else(part_stark_vk_attestation_dir)
}

fn resolve_signers(publisher_signers: &[PublisherSignerArg]) -> Result<Vec<(usize, &SecretKey)>> {
    if publisher_signers.is_empty() {
        bail!("publisher_signers is empty");
    }
    Ok(publisher_signers
        .iter()
        .map(|signer| (signer.signer_pubkey_index, &signer.secret_key))
        .collect())
}

fn load_publisher_set(commit_info_file: &PathBuf) -> Result<(Vec<PublicKey>, u16)> {
    let bytes = std::fs::read(commit_info_file).with_context(|| {
        format!("failed to read commit_info file '{}'", commit_info_file.display())
    })?;
    let commit_info: CommitInfo = serde_json::from_slice(&bytes).with_context(|| {
        format!("failed to decode commit_info file '{}'", commit_info_file.display())
    })?;
    if commit_info.publisher_public_keys.is_empty() {
        bail!("commit_info publisher_public_keys is empty");
    }
    if commit_info.threshold == 0 {
        bail!("commit_info threshold must be greater than 0");
    }
    let publisher_public_keys = commit_info
        .publisher_public_keys
        .iter()
        .map(|compressed_pk| {
            PublicKey::from_str(compressed_pk)
                .with_context(|| format!("invalid publisher public key '{}'", compressed_pk))
        })
        .collect::<Result<Vec<_>>>()?;
    if usize::from(commit_info.threshold) > publisher_public_keys.len() {
        bail!(
            "commit_info threshold {} exceeds publisher_public_keys length {}",
            commit_info.threshold,
            publisher_public_keys.len()
        );
    }
    Ok((publisher_public_keys, commit_info.threshold))
}

fn load_part_stark_vk(
    part_stark_vk_file: Option<PathBuf>,
    zkm_version: Option<String>,
) -> Result<Vec<u8>> {
    match (part_stark_vk_file, zkm_version) {
        (Some(_), Some(_)) => bail!("part_stark_vk_file and zkm_version are mutually exclusive"),
        (None, None) => bail!("either part_stark_vk_file or zkm_version must be provided"),
        (Some(path), None) => std::fs::read(&path)
            .with_context(|| format!("failed to read part_stark_vk file '{}'", path.display())),
        (None, Some(zkm_version)) => Ok(Groth16Verifier::get_part_stark_vk(&zkm_version).to_vec()),
    }
}

fn main() -> Result<()> {
    dotenv::dotenv().ok();
    let cli = Cli::parse();

    match cli.command {
        Command::Append {
            part_stark_vk_file,
            zkm_version,
            commit_info_file,
            publisher_signers,
            attestation_dir,
        } => {
            let attestation_dir = resolve_attestation_dir(attestation_dir);
            let part_stark_vk = load_part_stark_vk(part_stark_vk_file, zkm_version)?;
            let (publisher_public_keys, threshold) = load_publisher_set(&commit_info_file)?;
            let signer_refs = resolve_signers(&publisher_signers)?;
            let bundle = append_part_stark_vk_and_sign_with_signers(
                &attestation_dir,
                part_stark_vk,
                &publisher_public_keys,
                threshold,
                &signer_refs,
            )
            .map_err(anyhow::Error::msg)?;
            println!("{}", serde_json::to_string_pretty(&bundle)?);
        }
        Command::ResignCurrentRoot { commit_info_file, publisher_signers, attestation_dir } => {
            let attestation_dir = resolve_attestation_dir(attestation_dir);
            let (publisher_public_keys, threshold) = load_publisher_set(&commit_info_file)?;
            let signer_refs = resolve_signers(&publisher_signers)?;
            resign_current_part_stark_vk_root_with_signers(
                &attestation_dir,
                &publisher_public_keys,
                threshold,
                &signer_refs,
            )
            .map_err(anyhow::Error::msg)?;
            println!("resigned part_stark_vk root attestations in {}", attestation_dir.display());
        }
    }

    Ok(())
}
