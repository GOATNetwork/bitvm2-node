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
    prover_connector: 22,
    // Was 34: exactly prover_connector(22) + min_reaction_blocks(12), which
    // means Disprove's and Take2's earliest-spendable heights on ConnectorD
    // could land at the exact same block - a coin-flip on miner/mempool
    // ordering, not a guaranteed win for the honest Disprove path. Bumped by
    // 1 block to restore strict margin. Caught by
    // node/tla/Take2DisproveRace.tla.
    connector_d: 35,
    watchtower_challenge: 34,
    operator_ack: 46,
    operator_commit: 58,
    connector_f: 70,
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
    connector_a: 1,
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

/// Minimum wall-clock reaction time (in blocks) any single timelock window
/// must provide off-chain parties (watchtowers/verifiers/committee) to
/// notice an on-chain event and respond, on networks where real value is at
/// stake. Signet/Regtest are pure test networks where short timelocks are
/// used deliberately for fast iteration, so no floor is enforced there.
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
        // Was `value == 0`: nonzero alone doesn't stop a malicious graph
        // proposal (e.g. connector_a/take1, which has no other relative
        // check anywhere) from setting a 1-block window on mainnet, leaving
        // watchtowers/the committee essentially no real time to react.
        if value < min_blocks {
            bail!(
                "timelock_config.{name} must be at least {min_blocks} blocks \
                 (~{MIN_REACTION_SECS}s of reaction time), got {value}"
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

    // connector_d's CSV clock starts at OperatorAssert's confirmation;
    // prover_connector's clock starts at VerifierAssert's confirmation - and
    // VerifierAssert can only confirm strictly *after* OperatorAssert, since
    // it spends OperatorAssert's output. A plain `<=` comparison ignores
    // that real-world gap and could leave zero actual margin for the
    // committee's cooperative Disprove fallback to mature before the
    // operator's Take2 on the same UTXO race. Require at least one reaction
    // window of slack to account for it.
    ensure_margin(
        "prover_connector",
        config.prover_connector,
        "connector_d",
        config.connector_d,
        min_blocks,
    )?;
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

fn ensure_margin(
    left_name: &str,
    left: u32,
    right_name: &str,
    right: u32,
    min_margin: u32,
) -> Result<()> {
    // Strict: `left + min_margin == right` is NOT enough. DisproveTransaction
    // and Take2Transaction spend different leaves of the same ConnectorD
    // output; if their earliest-spendable heights are exactly equal, which
    // one actually confirms first is mempool/miner luck, not a protocol
    // guarantee. Formally checked in node/tla/Take2DisproveRace.tla, which
    // is what caught this - a non-strict `>` here originally let the
    // boundary case through.
    if left.saturating_add(min_margin) >= right {
        bail!(
            "timelock_config.{left_name} must be strictly more than {min_margin} blocks less \
             than timelock_config.{right_name} ({left_name}'s clock starts later on-chain and \
             needs margin for that, with room to spare - not exactly equal)"
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
