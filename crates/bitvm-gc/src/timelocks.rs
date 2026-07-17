use anyhow::{Result, bail};
use bitcoin::Network;
use goat::constants::TimelockConfig;

// The four `prover_connector`/`connector_d`/`connector_f` values per network
// below, plus `min_reaction_blocks`'s output for each network, are hardcoded
// in `node/tla/Take2DisproveRace.tla` (checked against `Take2DisproveRace.cfg`).
// That spec is what caught the testnet4 `connector_d` boundary bug this file
// was fixed for. `tla_model_matches_shipped_timelock_configs` (bottom of this
// file) reads that .tla file directly and cross-checks it against these
// values on every `cargo test` - if you change a constant here, that test
// will tell you the spec is now stale instead of staying silently wrong.
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

#[cfg(test)]
mod tla_model_tripwire_tests {
    use super::*;

    /// Reads the *actual* `node/tla/Take2DisproveRace.tla` file and checks
    /// its `ProverConnector`/`ConnectorD`/`ConnectorF`/`MinReactionBlocks`
    /// lines against the live Rust values - as opposed to a second
    /// hand-copied set of numbers living only in this test, which can drift
    /// from the spec exactly as easily as the spec can drift from the code
    /// (whoever edits one has no reason to notice the other needs editing
    /// too, and a copy-paste mistake in either place would happily match its
    /// twin instead of getting caught). This test has no twin to keep in
    /// sync - it's cross-checked against the file that actually gets fed to
    /// TLC, so drift in either direction fails it.
    ///
    /// Deliberately does NOT hand-parse the `.tla` syntax (brackets, commas,
    /// `|->`): a first version of this test did, and it broke on the very
    /// first real run because `ConnectorD`/`ConnectorF` are right-padded
    /// with extra spaces in the file to align the `==` column - one of
    /// several formatting variations a hand-rolled parser has to keep
    /// anticipating. Instead this *generates* the expected line straight
    /// from the Rust values (the one thing this test actually needs to get
    /// right) and compares it to the real line as whitespace-normalized
    /// tokens, so any amount of spacing/alignment is a non-issue and there's
    /// no bracket/comma parsing to get subtly wrong.
    ///
    /// If this test fails: either the `.tla` line is stale (copy the
    /// "expected" value from the panic message into the file, then re-run
    /// `java -jar tla2tools.jar -config Take2DisproveRace.cfg
    /// Take2DisproveRace.tla`, see root README.md), or your Rust change made
    /// it stale (same fix).
    #[test]
    fn tla_model_matches_shipped_timelock_configs() {
        let tla_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../node/tla/Take2DisproveRace.tla");
        let tla_source = std::fs::read_to_string(&tla_path).unwrap_or_else(|e| {
            panic!(
                "could not read {} ({e}) - did node/tla/Take2DisproveRace.tla move? \
                 update `tla_path` above if so",
                tla_path.display()
            )
        });

        assert_tla_line_matches(
            &tla_source,
            "ProverConnector",
            [
                ("Bitcoin", NODE_BITCOIN_TIMELOCK_CONFIG.prover_connector),
                ("Testnet4", NODE_TESTNET_TIMELOCK_CONFIG.prover_connector),
                ("Signet", NODE_SIGNET_TIMELOCK_CONFIG.prover_connector),
                ("Regtest", NODE_REGTEST_TIMELOCK_CONFIG.prover_connector),
            ],
        );
        assert_tla_line_matches(
            &tla_source,
            "ConnectorD",
            [
                ("Bitcoin", NODE_BITCOIN_TIMELOCK_CONFIG.connector_d),
                ("Testnet4", NODE_TESTNET_TIMELOCK_CONFIG.connector_d),
                ("Signet", NODE_SIGNET_TIMELOCK_CONFIG.connector_d),
                ("Regtest", NODE_REGTEST_TIMELOCK_CONFIG.connector_d),
            ],
        );
        assert_tla_line_matches(
            &tla_source,
            "ConnectorF",
            [
                ("Bitcoin", NODE_BITCOIN_TIMELOCK_CONFIG.connector_f),
                ("Testnet4", NODE_TESTNET_TIMELOCK_CONFIG.connector_f),
                ("Signet", NODE_SIGNET_TIMELOCK_CONFIG.connector_f),
                ("Regtest", NODE_REGTEST_TIMELOCK_CONFIG.connector_f),
            ],
        );
        assert_tla_line_matches(
            &tla_source,
            "MinReactionBlocks",
            [
                ("Bitcoin", min_reaction_blocks(Network::Bitcoin)),
                ("Testnet4", min_reaction_blocks(Network::Testnet4)),
                ("Signet", min_reaction_blocks(Network::Signet)),
                ("Regtest", min_reaction_blocks(Network::Regtest)),
            ],
        );
    }

    /// Generates the canonical `NAME == [Bitcoin |-> N, ...]` line from
    /// `values`, finds the line in `tla_source` whose first whitespace-
    /// separated token is `name`, and asserts the two are equal once both
    /// are split on whitespace (so alignment padding, tabs, etc. never
    /// matter - only the actual tokens do).
    fn assert_tla_line_matches(tla_source: &str, name: &str, values: [(&str, u32); 4]) {
        let expected_line = {
            let parts: Vec<String> =
                values.iter().map(|(net, v)| format!("{net} |-> {v}")).collect();
            format!("{name} == [{}]", parts.join(", "))
        };
        let expected_tokens: Vec<&str> = expected_line.split_whitespace().collect();

        let actual_line =
            tla_source.lines().find(|l| l.split_whitespace().next() == Some(name)).unwrap_or_else(
                || panic!("could not find a line starting with `{name}` in the .tla file"),
            );
        let actual_tokens: Vec<&str> = actual_line.split_whitespace().collect();

        assert_eq!(
            expected_tokens,
            actual_tokens,
            "node/tla/Take2DisproveRace.tla's `{name}` line has drifted from the shipped Rust \
             values.\n  expected (from Rust): {expected_line}\n  found in .tla file:   {}",
            actual_line.trim()
        );
    }

    /// Sanity check that the shipped configs actually pass validation -
    /// this alone doesn't catch TLA+ model drift (that's the test above),
    /// but it would catch someone editing a value without re-running
    /// validate_timelock_config in their head.
    #[test]
    fn shipped_timelock_configs_are_individually_valid() {
        for network in [Network::Bitcoin, Network::Testnet4, Network::Signet, Network::Regtest] {
            validate_timelock_config(network, &default_timelock_config(network)).unwrap();
        }
    }
}
