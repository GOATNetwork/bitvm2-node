use anyhow::Context;
use proof_builder::LongRunning;
use proof_builder::api_auth::normalize_public_key;
use secp256k1::XOnlyPublicKey;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct ProofBuilderConfig {
    pub api_auth: ApiAuthConfig,
    pub header_chain: header_chain_proof::Args,
    pub commit_chain: commit_chain_proof::Args,
    pub state_chain: state_chain_proof::Args,
    pub watchtower: watchtower_proof::Args,
    pub operator: operator_proof::Args,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) struct ApiAuthConfig {
    pub trusted_operator_public_keys: Vec<String>,
    pub trusted_watchtower_public_keys: Vec<String>,
}

#[derive(Clone, Debug)]
pub(crate) struct TrustedApiKeys {
    pub operator: HashSet<XOnlyPublicKey>,
    pub watchtower: HashSet<XOnlyPublicKey>,
}

impl ApiAuthConfig {
    /// Parses and validates the fail-closed role-specific API allowlists.
    pub(crate) fn trusted_keys(&self) -> anyhow::Result<TrustedApiKeys> {
        let operator =
            parse_keys("trusted_operator_public_keys", &self.trusted_operator_public_keys)?;
        let watchtower =
            parse_keys("trusted_watchtower_public_keys", &self.trusted_watchtower_public_keys)?;
        Ok(TrustedApiKeys { operator, watchtower })
    }
}

impl ProofBuilderConfig {
    pub(crate) fn new(url: &str) -> anyhow::Result<Self> {
        Self::load(url)
    }

    fn load(url: &str) -> anyhow::Result<Self> {
        let content =
            std::fs::read_to_string(url).context(format!("Failed to read config file: {url}"))?;
        Ok(toml::from_str(&content)?)
    }

    pub(crate) fn run_next<R: LongRunning + serde::Serialize>(
        args: R,
        name: String,
    ) -> anyhow::Result<R> {
        let new_args = args.rotate();
        let contents = toml::to_string_pretty(&new_args)?;
        std::fs::write(format!("{name}.ckpt"), contents)?;
        Ok(new_args)
    }
}

/// Normalizes one configured allowlist and rejects empty or invalid lists.
fn parse_keys(name: &str, values: &[String]) -> anyhow::Result<HashSet<XOnlyPublicKey>> {
    anyhow::ensure!(!values.is_empty(), "api_auth.{name} must not be empty");
    values
        .iter()
        .map(|value| {
            normalize_public_key(value)
                .with_context(|| format!("invalid public key in api_auth.{name}"))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use secp256k1::{Keypair, SECP256K1};

    fn public_keys() -> (String, String) {
        let operator = Keypair::from_seckey_slice(SECP256K1, &[7; 32]).unwrap();
        let watchtower = Keypair::from_seckey_slice(SECP256K1, &[9; 32]).unwrap();
        (operator.public_key().to_string(), watchtower.x_only_public_key().0.to_string())
    }

    #[test]
    fn api_auth_accepts_compressed_and_x_only_keys_and_deduplicates() {
        let (operator, watchtower) = public_keys();
        let config = ApiAuthConfig {
            trusted_operator_public_keys: vec![operator.clone(), operator],
            trusted_watchtower_public_keys: vec![watchtower],
        };
        let keys = config.trusted_keys().unwrap();
        assert_eq!(keys.operator.len(), 1);
        assert_eq!(keys.watchtower.len(), 1);
    }

    #[test]
    fn api_auth_rejects_empty_or_invalid_lists() {
        let (operator, watchtower) = public_keys();
        assert!(
            ApiAuthConfig {
                trusted_operator_public_keys: vec![],
                trusted_watchtower_public_keys: vec![watchtower.clone()],
            }
            .trusted_keys()
            .is_err()
        );
        assert!(
            ApiAuthConfig {
                trusted_operator_public_keys: vec![operator],
                trusted_watchtower_public_keys: vec!["not-a-public-key".to_string()],
            }
            .trusted_keys()
            .is_err()
        );
        assert!(toml::from_str::<ApiAuthConfig>("").is_err());
    }
}
