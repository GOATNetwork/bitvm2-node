use anyhow::{Result, bail};
use bitcoin::Network;
use goat::constants::TimelockConfig;

pub const NODE_BITCOIN_BLOCK_INTERVAL_SECS: i64 = 600;
pub const NODE_TESTNET_BLOCK_INTERVAL_SECS: i64 = 300;
pub const NODE_SIGNET_BLOCK_INTERVAL_SECS: i64 = 60;
pub const NODE_REGTEST_BLOCK_INTERVAL_SECS: i64 = 60;

pub const NODE_BITCOIN_TIMELOCK_CONFIG: TimelockConfig = TimelockConfig {
    connector_z: 144,
    connector_a: 144,
    prover_connector: 144,
    connector_d: 432,
    watchtower_challenge: 144,
    operator_ack: 288,
    operator_commit: 432,
    connector_f: 576,
};
pub const NODE_TESTNET_TIMELOCK_CONFIG: TimelockConfig = TimelockConfig {
    connector_z: 100,
    connector_a: 16,
    prover_connector: 20,
    connector_d: 40,
    watchtower_challenge: 20,
    operator_ack: 32,
    operator_commit: 40,
    connector_f: 52,
};
pub const NODE_SIGNET_TIMELOCK_CONFIG: TimelockConfig = TimelockConfig {
    connector_z: 6,
    connector_a: 6,
    prover_connector: 6,
    connector_d: 18,
    watchtower_challenge: 6,
    operator_ack: 12,
    operator_commit: 18,
    connector_f: 24,
};
pub const NODE_REGTEST_TIMELOCK_CONFIG: TimelockConfig = TimelockConfig {
    connector_z: 1,
    connector_a: 2,
    prover_connector: 1,
    connector_d: 3,
    watchtower_challenge: 1,
    operator_ack: 2,
    operator_commit: 3,
    connector_f: 4,
};

pub fn default_timelock_config(network: Network) -> TimelockConfig {
    match network {
        Network::Bitcoin => NODE_BITCOIN_TIMELOCK_CONFIG,
        Network::Testnet | Network::Testnet4 => NODE_TESTNET_TIMELOCK_CONFIG,
        Network::Signet => NODE_SIGNET_TIMELOCK_CONFIG,
        Network::Regtest => NODE_REGTEST_TIMELOCK_CONFIG,
    }
}

pub fn estimated_block_interval_secs(network: Network) -> i64 {
    match network {
        Network::Bitcoin => NODE_BITCOIN_BLOCK_INTERVAL_SECS,
        Network::Testnet | Network::Testnet4 => NODE_TESTNET_BLOCK_INTERVAL_SECS,
        Network::Signet => NODE_SIGNET_BLOCK_INTERVAL_SECS,
        Network::Regtest => NODE_REGTEST_BLOCK_INTERVAL_SECS,
    }
}

const MIN_REACTION_SECS: i64 = 3600;

fn min_reaction_blocks(network: Network) -> u32 {
    match network {
        Network::Bitcoin | Network::Testnet | Network::Testnet4 => {
            let interval = estimated_block_interval_secs(network);
            ((MIN_REACTION_SECS + interval - 1) / interval) as u32
        }
        Network::Signet | Network::Regtest => 1,
    }
}

pub fn validate_timelock_config(network: Network, config: &TimelockConfig) -> Result<()> {
    let min_blocks = min_reaction_blocks(network);
    for (name, value) in [
        ("connector_z", config.connector_z),
        ("connector_a", config.connector_a),
        ("prover_connector", config.prover_connector),
        ("connector_d", config.connector_d),
        ("watchtower_challenge", config.watchtower_challenge),
        ("operator_ack", config.operator_ack),
        ("operator_commit", config.operator_commit),
        ("connector_f", config.connector_f),
    ] {
        if value < min_blocks {
            bail!(
                "timelock_config.{name} must be at least {min_blocks} blocks \
                 (~{MIN_REACTION_SECS}s reaction window), got {value}"
            );
        }
    }
    let default_connector_z = default_timelock_config(network).connector_z;
    if config.connector_z != default_connector_z {
        bail!(
            "timelock_config.connector_z must remain {} because connector-z is fixed before graph construction",
            default_connector_z
        );
    }

    ensure_reaction_margin(
        "prover_connector",
        config.prover_connector,
        "connector_d",
        config.connector_d,
        min_blocks,
    )?;
    ensure_gt("connector_a", config.connector_a, "min_reaction_blocks", min_blocks)?;
    ensure_lt(
        "watchtower_challenge",
        config.watchtower_challenge,
        "operator_ack",
        config.operator_ack,
    )?;
    ensure_lt("operator_ack", config.operator_ack, "operator_commit", config.operator_commit)?;
    ensure_lt("operator_commit", config.operator_commit, "connector_f", config.connector_f)?;

    Ok(())
}

fn ensure_reaction_margin(
    left_name: &str,
    left: u32,
    right_name: &str,
    right: u32,
    min_margin: u32,
) -> Result<()> {
    if left.saturating_add(min_margin) >= right {
        bail!(
            "timelock_config.{left_name} must be more than {min_margin} blocks less than \
             timelock_config.{right_name}"
        );
    }
    Ok(())
}

fn ensure_lt(left_name: &str, left: u32, right_name: &str, right: u32) -> Result<()> {
    if left >= right {
        bail!("timelock_config.{left_name} must be < timelock_config.{right_name}");
    }
    Ok(())
}

fn ensure_gt(left_name: &str, left: u32, right_name: &str, right: u32) -> Result<()> {
    if left <= right {
        bail!("timelock_config.{left_name} must be > {right_name} ({right})");
    }
    Ok(())
}

pub fn timelock_blocks(_network: Network, blocks: u32) -> u32 {
    blocks
}

pub fn connector_z_timelock_blocks(network: Network, config: &TimelockConfig) -> u32 {
    timelock_blocks(network, config.connector_z)
}

pub fn default_connector_z_timelock_blocks(network: Network) -> u32 {
    connector_z_timelock_blocks(network, &default_timelock_config(network))
}

pub fn take1_timelock_blocks(network: Network, config: &TimelockConfig) -> u32 {
    timelock_blocks(network, config.connector_a)
}

pub fn take2_timelock_blocks(network: Network, config: &TimelockConfig) -> u32 {
    timelock_blocks(network, config.connector_d)
}

pub fn connector_f_timelock_blocks(network: Network, config: &TimelockConfig) -> u32 {
    timelock_blocks(network, config.connector_f)
}

pub fn disprove_timelock_blocks(network: Network, config: &TimelockConfig) -> u32 {
    timelock_blocks(network, config.prover_connector)
}

pub fn watchtower_challenge_timelock_blocks(network: Network, config: &TimelockConfig) -> u32 {
    timelock_blocks(network, config.watchtower_challenge)
}

pub fn operator_ack_timelock_blocks(network: Network, config: &TimelockConfig) -> u32 {
    timelock_blocks(network, config.operator_ack)
}

pub fn operator_commit_timelock_blocks(network: Network, config: &TimelockConfig) -> u32 {
    timelock_blocks(network, config.operator_commit)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_default_timelock_configs_validate() {
        for (network, config) in [
            (Network::Bitcoin, NODE_BITCOIN_TIMELOCK_CONFIG),
            (Network::Testnet, NODE_TESTNET_TIMELOCK_CONFIG),
            (Network::Testnet4, NODE_TESTNET_TIMELOCK_CONFIG),
            (Network::Signet, NODE_SIGNET_TIMELOCK_CONFIG),
            (Network::Regtest, NODE_REGTEST_TIMELOCK_CONFIG),
        ] {
            assert_eq!(default_timelock_config(network), config);
            validate_timelock_config(network, &config).unwrap();
        }
    }
}
