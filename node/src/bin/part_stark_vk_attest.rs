use anyhow::{Context, Result, bail};
use bitcoin::PrivateKey;
use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
use bitcoin_light_client_circuit::{
    part_stark_vk_attestation_dir, save_latest_part_stark_vk_attestation_snapshot,
    sign_latest_part_stark_vk_snapshot,
};
use clap::{Parser, Subcommand};
use commit_chain::CommitInfo;
use semver::Version;
use std::path::PathBuf;
use std::str::FromStr;
use zkm_verifier::Groth16Verifier;

#[derive(Debug, Parser)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    BuildTree {
        #[arg(long, value_delimiter = ',')]
        versions: Vec<String>,
        #[arg(long)]
        attestation_dir: Option<PathBuf>,
    },
    SignRoot {
        #[arg(long, value_delimiter = ',')]
        versions: Vec<String>,
        #[arg(long)]
        commit_info_file: PathBuf,
        #[arg(long, value_parser = decode_publisher_secret_key_wif)]
        publisher_secret_key_wif: SecretKey,
        #[arg(long)]
        attestation_dir: Option<PathBuf>,
    },
}

fn resolve_attestation_dir(attestation_dir: Option<PathBuf>) -> PathBuf {
    attestation_dir.unwrap_or_else(part_stark_vk_attestation_dir)
}

fn normalize_version(version: &str) -> Result<Version> {
    let raw_version = version.trim();
    if raw_version.is_empty() {
        bail!("version cannot be empty");
    }
    let normalized = raw_version
        .strip_prefix('v')
        .or_else(|| raw_version.strip_prefix('V'))
        .unwrap_or(raw_version);
    Version::parse(normalized).with_context(|| format!("invalid semver version '{version}'"))
}

/// Sort versions by semantic version while rejecting duplicate normalized versions.
fn order_versions(versions: &[String]) -> Result<Vec<String>> {
    if versions.is_empty() {
        bail!("versions is empty");
    }

    let mut keyed_versions = versions
        .iter()
        .map(|version| Ok((normalize_version(version)?, version.clone())))
        .collect::<Result<Vec<_>>>()?;
    keyed_versions.sort_by(|left, right| left.0.cmp(&right.0).then(left.1.cmp(&right.1)));

    let mut ordered_versions = Vec::with_capacity(keyed_versions.len());
    let mut previous: Option<Version> = None;
    for (normalized, original) in keyed_versions {
        if previous.as_ref() == Some(&normalized) {
            bail!("duplicate version '{original}'");
        }
        previous = Some(normalized);
        ordered_versions.push(original);
    }
    Ok(ordered_versions)
}

fn load_publisher_set(commit_info_file: &PathBuf) -> Result<(Vec<PublicKey>, u16)> {
    let bytes = std::fs::read(commit_info_file).with_context(|| {
        format!("failed to read commit_info file '{}'", commit_info_file.display())
    })?;
    let commit_info: CommitInfo = serde_json::from_slice(&bytes).with_context(|| {
        format!("failed to decode commit_info file '{}'", commit_info_file.display())
    })?;
    let (encoded_public_keys, threshold) = commit_info.active_publisher_set();
    if encoded_public_keys.is_empty() {
        bail!("commit_info publisher_public_keys is empty");
    }
    if threshold == 0 {
        bail!("commit_info threshold must be greater than 0");
    }
    let publisher_public_keys = encoded_public_keys
        .iter()
        .map(|compressed_pk| {
            PublicKey::from_str(compressed_pk)
                .with_context(|| format!("invalid publisher public key '{}'", compressed_pk))
        })
        .collect::<Result<Vec<_>>>()?;
    if usize::from(threshold) > publisher_public_keys.len() {
        bail!(
            "commit_info threshold {} exceeds publisher_public_keys length {}",
            threshold,
            publisher_public_keys.len()
        );
    }
    Ok((publisher_public_keys, threshold))
}

fn load_part_stark_vk_for_version(zkm_version: &str) -> Result<Vec<u8>> {
    std::panic::catch_unwind(|| Groth16Verifier::get_part_stark_vk(zkm_version).to_vec())
        .map_err(|_| anyhow::anyhow!("failed to load part_stark_vk for version '{zkm_version}'"))
}

fn load_part_stark_vks_for_versions(ordered_versions: &[String]) -> Result<Vec<Vec<u8>>> {
    ordered_versions.iter().map(|version| load_part_stark_vk_for_version(version)).collect()
}

fn decode_publisher_secret_key_wif(value: &str) -> Result<SecretKey, String> {
    let private_key =
        PrivateKey::from_wif(value).map_err(|err| format!("invalid publisher WIF key: {err}"))?;
    Ok(private_key.inner)
}

/// Resolve the signer index by matching the secret key derived public key against the active set.
fn resolve_signer_index(
    secret_key: &SecretKey,
    publisher_public_keys: &[PublicKey],
) -> Result<usize> {
    let signer_public_key = PublicKey::from_secret_key(&Secp256k1::new(), secret_key);
    publisher_public_keys.iter().position(|public_key| *public_key == signer_public_key).ok_or_else(
        || anyhow::anyhow!("publisher_secret_key_wif does not belong to active publisher set"),
    )
}

fn main() -> Result<()> {
    dotenv::dotenv().ok();
    let cli = Cli::parse();

    match cli.command {
        Command::BuildTree { versions, attestation_dir } => {
            let attestation_dir = resolve_attestation_dir(attestation_dir);
            let ordered_versions = order_versions(&versions)?;
            let part_stark_vks = load_part_stark_vks_for_versions(&ordered_versions)?;
            save_latest_part_stark_vk_attestation_snapshot(
                &attestation_dir,
                &ordered_versions,
                &part_stark_vks,
                None,
                None,
                None,
                vec![],
            )
            .map_err(anyhow::Error::msg)?;
            println!(
                "built latest part_stark_vk snapshot in {} for versions {}",
                attestation_dir.display(),
                ordered_versions.join(",")
            );
        }
        Command::SignRoot {
            versions,
            commit_info_file,
            publisher_secret_key_wif,
            attestation_dir,
        } => {
            let attestation_dir = resolve_attestation_dir(attestation_dir);
            let ordered_versions = order_versions(&versions)?;
            let part_stark_vks = load_part_stark_vks_for_versions(&ordered_versions)?;
            let (publisher_public_keys, threshold) = load_publisher_set(&commit_info_file)?;
            let signer_pubkey_index =
                resolve_signer_index(&publisher_secret_key_wif, &publisher_public_keys)?;
            let manifest = sign_latest_part_stark_vk_snapshot(
                &attestation_dir,
                &ordered_versions,
                &part_stark_vks,
                &publisher_public_keys,
                threshold,
                signer_pubkey_index,
                &publisher_secret_key_wif,
            )
            .map_err(anyhow::Error::msg)?;
            println!("{}", serde_json::to_string_pretty(&manifest)?);
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::Network;
    use bitcoin::secp256k1::Secp256k1;

    #[test]
    fn test_decode_publisher_secret_key_wif_accepts_wif() {
        let secret_key =
            SecretKey::from_str("0101010101010101010101010101010101010101010101010101010101010101")
                .unwrap();
        let private_key = PrivateKey::new(secret_key, Network::Regtest);

        let decoded = decode_publisher_secret_key_wif(&private_key.to_wif()).unwrap();

        assert_eq!(decoded, secret_key);
    }

    #[test]
    fn test_order_versions_sorts_semver_with_v_prefix() {
        let ordered =
            order_versions(&["v1.2.10".to_string(), "v1.2.4".to_string(), "v1.2.5".to_string()])
                .unwrap();
        assert_eq!(ordered, vec!["v1.2.4", "v1.2.5", "v1.2.10"]);
    }

    #[test]
    fn test_order_versions_rejects_duplicate_versions() {
        let err = order_versions(&["v1.2.5".to_string(), "v1.2.5".to_string()]).unwrap_err();
        assert!(err.to_string().contains("duplicate"));
    }

    #[test]
    fn test_resolve_signer_index_matches_active_publisher_set_order() {
        let secp = Secp256k1::new();
        let secret_key_0 =
            SecretKey::from_str("0101010101010101010101010101010101010101010101010101010101010101")
                .unwrap();
        let secret_key_1 =
            SecretKey::from_str("0202020202020202020202020202020202020202020202020202020202020202")
                .unwrap();
        let secret_key_2 =
            SecretKey::from_str("0303030303030303030303030303030303030303030303030303030303030303")
                .unwrap();
        let publisher_public_keys = vec![
            PublicKey::from_secret_key(&secp, &secret_key_2),
            PublicKey::from_secret_key(&secp, &secret_key_0),
            PublicKey::from_secret_key(&secp, &secret_key_1),
        ];

        let signer_index = resolve_signer_index(&secret_key_0, &publisher_public_keys).unwrap();

        assert_eq!(signer_index, 1);
    }
}
