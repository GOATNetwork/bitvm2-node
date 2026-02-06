//! pegout: operator pegout helper (Gateway.initWithdraw).
//!
//! Flow:
//! 1) Read local DB and select the minimal kickoff-index graph with status OperatorDataPushed
//! 2) Check L2 status: pegin is Withdrawable and withdraw status is None
//! 3) Call Gateway.initWithdraw (ensure pegBTC allowance in advance)
//!
//! Modes:
//! - once: single pegout for one graph
//! - batch: repeat until balance insufficient or target reached
//!
//! Env:
//! - BITVM_SECRET: node BTC private key (used to derive operator pubkey)
//! - GOAT_PRIVATE_KEY: node GoatNetwork private key
//! - BITCOIN_NETWORK: bitcoin | testnet | testnet4 | signet | regtest
//! - GOAT_CHAIN_URL: GoatNetwork RPC URL
//! - GOAT_GATEWAY_CONTRACT_ADDRESS: Gateway contract address
//!
//! Example:
//! - cargo run -p bitvm2-noded --bin pegout -- once \
//!     --db-path sqlite:/tmp/bitvm2-node.db \
//!     --operator-pubkey <pubkey>

use std::str::FromStr;

use alloy::primitives::U256;
use anyhow::{Result, anyhow, bail};
use bitcoin::PublicKey;
use clap::{Parser, Subcommand};
use dotenv::dotenv;
use tokio::time::{Duration, sleep};
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;
use uuid::Uuid;

use bitvm2_noded::env::{
    get_goat_gateway_contract_from_env, get_goat_network, get_node_goat_address, get_node_pubkey,
    goat_config_from_env,
};
use client::goat_chain::{GOATClient, PeginStatus, WithdrawStatus};
use store::localdb::{GraphQuery, LocalDB};
use store::{Graph, GraphStatus, create_local_db};

#[derive(Parser, Debug)]
#[command(
    name = "send-pegout",
    version,
    about = "Operator pegout helper",
    long_about = "Initiate pegout by calling Gateway.initWithdraw for eligible graphs"
)]
struct Args {
    /// Local Sqlite database file path
    #[arg(long, default_value = "sqlite:/tmp/bitvm2-node.db")]
    db_path: String,

    /// Optional operator BTC pubkey (override env-derived key)
    #[arg(long)]
    operator_pubkey: Option<String>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Initiate a single pegout on the next eligible graph
    Once {
        /// Optional explicit graph id; if not provided, pick minimal kickoff-index
        #[arg(long)]
        graph_id: Option<Uuid>,

        /// Dry run (do not call Gateway.initWithdraw)
        #[arg(long, default_value_t = false)]
        dry_run: bool,
    },
    /// Initiate pegouts repeatedly until balance insufficient or target reached
    Batch {
        /// Stop after total pegout amount reaches this target (sats)
        #[arg(long)]
        max_total_amount_sats: u64,

        /// Optional limit on number of pegouts to initiate
        #[arg(long, default_value_t = 0)]
        max_count: u32,

        /// Dry run (do not call Gateway.initWithdraw)
        #[arg(long, default_value_t = false)]
        dry_run: bool,

        /// Poll interval seconds for checking readiness between pegouts
        #[arg(long, default_value_t = 300)]
        poll_interval_secs: u64,

        /// Max wait seconds for a graph to be ready before stopping
        #[arg(long, default_value_t = 36000)]
        max_wait_secs: u64,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    dotenv().ok();
    let _ = tracing_subscriber::fmt().with_env_filter(EnvFilter::from_default_env()).try_init();

    let args = Args::parse();
    let local_db = create_local_db(&args.db_path).await;
    let goat_client = GOATClient::new(goat_config_from_env().await, get_goat_network());

    let operator_pubkey = match args.operator_pubkey {
        Some(v) => validate_operator_pubkey(&v)?,
        None => get_node_pubkey()?.to_string(),
    };
    let operator_goat_addr = get_node_goat_address().ok_or_else(|| {
        anyhow!("missing operator goat address; set GOAT_PRIVATE_KEY or GOAT_ADDRESS")
    })?;
    let gateway_addr = get_goat_gateway_contract_from_env();

    let balance = goat_client.peg_btc_balance(&operator_goat_addr.0).await?;
    info!("pegBTC balance for operator {}: {}", operator_goat_addr, balance);

    match args.command {
        Commands::Once { graph_id, dry_run } => {
            let graph = select_graph(&local_db, &operator_pubkey, graph_id).await?;
            if let Some(graph) = graph {
                let _ = init_withdraw_for_graph(
                    &goat_client,
                    &graph,
                    balance,
                    &operator_goat_addr,
                    &gateway_addr,
                    true,
                    dry_run,
                )
                .await?;
            } else {
                info!("no eligible graph found for operator {}", operator_pubkey);
            }
        }
        Commands::Batch {
            max_total_amount_sats,
            max_count,
            dry_run,
            poll_interval_secs,
            max_wait_secs,
        } => {
            if max_total_amount_sats == 0 {
                bail!("max_total_amount_sats must be > 0 for batch mode");
            }
            run_batch(
                &local_db,
                &goat_client,
                &operator_pubkey,
                balance,
                &operator_goat_addr,
                &gateway_addr,
                max_total_amount_sats,
                max_count,
                dry_run,
                poll_interval_secs,
                max_wait_secs,
            )
            .await?;
        }
    }

    Ok(())
}

async fn select_graph(
    local_db: &LocalDB,
    operator_pubkey: &str,
    graph_id: Option<Uuid>,
) -> Result<Option<Graph>> {
    info!("select_graph start: operator_pubkey {}, graph_id {:?}", operator_pubkey, graph_id);
    let mut storage_processor = local_db.acquire().await?;
    if let Some(graph_id) = graph_id {
        let graph = storage_processor.find_graph(&graph_id).await?;
        if let Some(graph) = graph {
            if graph.operator_pubkey != operator_pubkey {
                bail!("graph {} not owned by operator {}", graph_id, operator_pubkey);
            }
            if graph.status != GraphStatus::OperatorDataPushed.to_string() {
                bail!("graph {} status {} is not OperatorDataPushed", graph_id, graph.status);
            }
            if graph.init_withdraw_tx_hash.is_some() {
                bail!("graph {} already initialized withdraw", graph_id);
            }
            if !is_graph_ready_by_previous(&mut storage_processor, &graph).await? {
                bail!("graph {} not ready due to previous graph status", graph_id);
            }
            info!(
                "select_graph picked explicit graph {} kickoff_index {} amount {}",
                graph.graph_id, graph.kickoff_index, graph.amount
            );
            return Ok(Some(graph));
        }
        info!("select_graph: graph {} not found", graph_id);
        return Ok(None);
    }

    let graphs = storage_processor
        .get_operator_graphs(
            GraphQuery::default()
                .with_operator_pubkey(operator_pubkey.to_string())
                .with_status(GraphStatus::OperatorDataPushed.to_string())
                .with_raw_condition("init_withdraw_tx_hash IS NULL".to_string())
                .with_order("kickoff_index ASC".to_string())
                .with_limit(1),
        )
        .await?;
    if let Some(graph) = graphs.into_iter().next() {
        if !is_graph_ready_by_previous(&mut storage_processor, &graph).await? {
            info!("select_graph: graph {} not ready due to previous status", graph.graph_id);
            return Ok(None);
        }
        info!(
            "select_graph picked graph {} kickoff_index {} amount {}",
            graph.graph_id, graph.kickoff_index, graph.amount
        );
        Ok(Some(graph))
    } else {
        info!("select_graph: no graph matched query");
        Ok(None)
    }
}

async fn is_graph_ready_by_previous(
    storage_processor: &mut store::localdb::StorageProcessor<'_>,
    graph: &Graph,
) -> Result<bool> {
    if graph.kickoff_index <= 0 {
        return Ok(true);
    }
    let pre_graphs = storage_processor
        .get_operator_graphs(
            GraphQuery::default()
                .with_operator_pubkey(graph.operator_pubkey.clone())
                .with_kickoff_index(graph.kickoff_index - 1),
        )
        .await?;
    if pre_graphs.is_empty() {
        return Ok(true);
    }
    let pre_status = &pre_graphs[0].status;
    Ok(![
        GraphStatus::OperatorDataPushed.to_string(),
        GraphStatus::OperatorKickOff.to_string(),
        GraphStatus::Challenge.to_string(),
    ]
    .contains(pre_status))
}

async fn init_withdraw_for_graph(
    goat_client: &GOATClient,
    graph: &Graph,
    balance: U256,
    operator_goat_addr: &alloy::primitives::Address,
    gateway_addr: &alloy::primitives::Address,
    ensure_allowance: bool,
    dry_run: bool,
) -> Result<U256> {
    let amount = if graph.amount > 0 {
        graph.amount as u64
    } else {
        bail!("graph {} amount {} is invalid", graph.graph_id, graph.amount);
    };

    let amount_u256 = U256::from(amount);
    if balance < amount_u256 {
        bail!("insufficient pegBTC balance: need {}, available {}", amount, balance);
    }

    let pegin_data = goat_client.gateway_get_pegin_data(&graph.instance_id).await?;
    if pegin_data.status != PeginStatus::Withdrawable {
        bail!(
            "graph {} instance {} pegin status is {:?}, not Withdrawable",
            graph.graph_id,
            graph.instance_id,
            pegin_data.status
        );
    }
    let withdraw_data = goat_client.gateway_get_withdraw_data(&graph.graph_id).await?;
    if withdraw_data.status != WithdrawStatus::None {
        bail!("graph {} withdraw status is {:?}, not None", graph.graph_id, withdraw_data.status);
    }

    info!(
        "initWithdraw graph {} (instance {} kickoff_index {}) amount {} sats",
        graph.graph_id, graph.instance_id, graph.kickoff_index, amount
    );

    if dry_run {
        info!("dry-run enabled: skip Gateway.initWithdraw call");
        return Ok(balance - amount_u256);
    }

    if ensure_allowance {
        ensure_peg_btc_allowance(goat_client, operator_goat_addr, gateway_addr, amount_u256)
            .await?;
    }

    let tx_hash = goat_client.gateway_init_withdraw(&graph.instance_id, &graph.graph_id).await?;
    info!("initWithdraw submitted: graph {} tx_hash {}", graph.graph_id, tx_hash);

    Ok(balance - amount_u256)
}

async fn ensure_peg_btc_allowance(
    goat_client: &GOATClient,
    owner: &alloy::primitives::Address,
    spender: &alloy::primitives::Address,
    amount: U256,
) -> Result<()> {
    let allowance = goat_client.peg_btc_allowance(&owner.0, &spender.0).await?;
    if allowance >= amount {
        return Ok(());
    }
    info!("pegBTC allowance {} < required {}, approving spender {}", allowance, amount, spender);
    let tx_hash = goat_client.peg_btc_approve(&spender.0, amount).await?;
    info!("pegBTC approve submitted: {tx_hash}");

    let mut retries = 0u32;
    loop {
        let current = goat_client.peg_btc_allowance(&owner.0, &spender.0).await?;
        if current >= amount {
            info!("pegBTC allowance updated: {}", current);
            return Ok(());
        }
        retries += 1;
        if retries >= 30 {
            bail!("pegBTC allowance not updated after approve");
        }
        sleep(Duration::from_secs(5)).await;
    }
}

async fn run_batch(
    local_db: &LocalDB,
    goat_client: &GOATClient,
    operator_pubkey: &str,
    balance: U256,
    operator_goat_addr: &alloy::primitives::Address,
    gateway_addr: &alloy::primitives::Address,
    max_total_amount_sats: u64,
    max_count: u32,
    dry_run: bool,
    poll_interval_secs: u64,
    max_wait_secs: u64,
) -> Result<()> {
    info!(
        "batch start: operator_pubkey {}, max_total_amount_sats {}, max_count {}, dry_run {}",
        operator_pubkey, max_total_amount_sats, max_count, dry_run
    );
    let mut remaining_balance = balance;
    let mut total_sent: u64 = 0;
    let mut count: u32 = 0;

    if !dry_run {
        let target_allowance = U256::from(max_total_amount_sats);
        ensure_peg_btc_allowance(goat_client, operator_goat_addr, gateway_addr, target_allowance)
            .await?;
    }

    loop {
        if max_count > 0 && count >= max_count {
            info!("batch stop: reached max_count {max_count}");
            break;
        }
        if total_sent >= max_total_amount_sats {
            info!("batch stop: reached target total {} sats", max_total_amount_sats);
            break;
        }

        let graph = select_graph(local_db, operator_pubkey, None).await?;
        let Some(graph) = graph else {
            if dry_run {
                info!("batch stop: no eligible graph found (dry-run)");
                break;
            }
            if let Some(in_progress) = find_in_progress_graph(local_db, operator_pubkey).await? {
                info!(
                    "batch found in-progress graph {}, waiting before next pegout",
                    in_progress.graph_id
                );
                wait_until_next_ready(
                    local_db,
                    in_progress.graph_id,
                    poll_interval_secs,
                    max_wait_secs,
                )
                .await?;
                continue;
            }
            info!("batch stop: no eligible graph found");
            break;
        };

        let amount = if graph.amount > 0 { graph.amount as u64 } else { 0 };
        if amount == 0 {
            warn!("skip graph {} with invalid amount {}", graph.graph_id, graph.amount);
            break;
        }
        if total_sent + amount > max_total_amount_sats {
            info!(
                "batch stop: next amount {} would exceed target {}",
                amount, max_total_amount_sats
            );
            break;
        }

        info!(
            "batch initWithdraw: graph {} amount {} remaining_balance {}",
            graph.graph_id, amount, remaining_balance
        );

        let new_balance = init_withdraw_for_graph(
            goat_client,
            &graph,
            remaining_balance,
            operator_goat_addr,
            gateway_addr,
            false,
            dry_run,
        )
        .await?;

        remaining_balance = new_balance;
        total_sent = total_sent.saturating_add(amount);
        count = count.saturating_add(1);

        info!(
            "batch progress: count {}, total {} sats, remaining balance {}",
            count, total_sent, remaining_balance
        );

        if !dry_run {
            info!("batch waiting for graph {} to be ready before next pegout", graph.graph_id);
            wait_until_next_ready(local_db, graph.graph_id, poll_interval_secs, max_wait_secs)
                .await?;
        }
    }

    Ok(())
}

async fn find_in_progress_graph(
    local_db: &LocalDB,
    operator_pubkey: &str,
) -> Result<Option<Graph>> {
    let mut storage_processor = local_db.acquire().await?;
    let in_progress_condition = format!(
        "status IN ('{}','{}','{}') AND init_withdraw_tx_hash IS NOT NULL",
        GraphStatus::OperatorDataPushed.to_string(),
        GraphStatus::OperatorKickOff.to_string(),
        GraphStatus::Challenge.to_string()
    );
    let graphs = storage_processor
        .get_operator_graphs(
            GraphQuery::default()
                .with_operator_pubkey(operator_pubkey.to_string())
                .with_raw_condition(in_progress_condition)
                .with_order("kickoff_index DESC".to_string())
                .with_limit(1),
        )
        .await?;
    Ok(graphs.into_iter().next())
}

async fn wait_until_next_ready(
    local_db: &LocalDB,
    graph_id: Uuid,
    poll_interval_secs: u64,
    max_wait_secs: u64,
) -> Result<()> {
    let mut waited = 0u64;
    let mut last_status: Option<String> = None;
    loop {
        let mut storage_processor = local_db.acquire().await?;
        let graph = storage_processor.find_graph(&graph_id).await?;
        if let Some(graph) = graph {
            if ![
                GraphStatus::OperatorDataPushed.to_string(),
                GraphStatus::OperatorKickOff.to_string(),
                GraphStatus::Challenge.to_string(),
            ]
            .contains(&graph.status)
            {
                info!("graph {} ready for next pegout, status {}", graph_id, graph.status);
                return Ok(());
            }
            if last_status.as_deref() != Some(graph.status.as_str()) {
                info!("waiting graph {} to be ready, current status {}", graph_id, graph.status);
                last_status = Some(graph.status.clone());
            }
        } else {
            warn!("graph {} not found while waiting, proceed", graph_id);
            return Ok(());
        }

        if waited >= max_wait_secs {
            bail!("waited {}s but graph {} still not ready", max_wait_secs, graph_id);
        }
        sleep(Duration::from_secs(poll_interval_secs)).await;
        waited = waited.saturating_add(poll_interval_secs);
    }
}

fn validate_operator_pubkey(pubkey: &str) -> Result<String> {
    let parsed = PublicKey::from_str(pubkey)
        .map_err(|e| anyhow!("invalid operator_pubkey '{pubkey}': {e}"))?;
    Ok(parsed.to_string())
}
