#![feature(trivial_bounds)]
use base64::Engine;
use bitvm2_lib::actors::Actor;
use bitvm2_noded::client::{btc_chain::BTCClient, goat_chain::GOATClient};
use bitvm2_noded::env::{
    self, ENV_PEER_KEY, check_node_info, get_ipfs_url, get_network, get_node_pubkey,
};
use clap::{Parser, Subcommand, command};
use libp2p::PeerId;
use libp2p_metrics::Registry;
use std::error::Error;
use std::sync::{Arc, Mutex};
use store::ipfs::IPFS;
use tracing_subscriber::EnvFilter;

use bitvm2_noded::rpc_service;
use bitvm2_noded::utils::{
    self, generate_local_key, run_watch_event_task, save_local_info,
    set_node_external_socket_addr_env,
};

use anyhow::Result;
use bitvm2_noded::middleware::swarm::{Bitvm2SwarmConfig, BitvmNetworkManager};
use bitvm2_noded::p2p_msg_handler::BitvmNodeProcessor;
use futures::future;
use tokio::signal;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

#[derive(Debug, Parser)]
#[command(author, version, about, long_about = None)]
struct Opts {
    /// Setup the bootnode p2p port
    #[arg(long, default_value = "0")]
    p2p_port: u16,

    /// Local RPC service address
    #[arg(long, default_value = "0.0.0.0:8080")]
    pub rpc_addr: String,

    /// Local Sqlite database file path
    #[arg(long, default_value = "/tmp/bitvm2-node.db")]
    pub db_path: String,

    /// Peer nodes as the bootnodes
    #[arg(long)]
    bootnodes: Vec<String>,

    /// Metric endpoint path.
    #[arg(long, default_value = "/metrics")]
    metrics_path: String,

    /// Whether to run the libp2p Kademlia protocol and join the BitVM2 DHT.
    #[arg(long, default_value = "true")]
    enable_kademlia: bool,

    #[command(subcommand)]
    cmd: Option<Commands>,
}

#[derive(Subcommand, Debug, Clone)]
enum Commands {
    Key(KeyArg),
    Peer(PeerArg),
}

#[derive(Parser, Debug, Clone)]
struct KeyArg {
    #[arg(long, default_value = "ed25519")]
    kind: String,
    #[command(subcommand)]
    cmd: KeyCommands,
}

#[derive(Parser, Debug, Clone)]
struct PeerArg {
    #[clap(subcommand)]
    peer_cmd: PeerCommands,
}

#[derive(Parser, Debug, Clone)]
enum PeerCommands {
    GetPeers {
        #[clap(long)]
        peer_id: Option<PeerId>,
    },
}

#[derive(Subcommand, Debug, Clone)]
enum KeyCommands {
    /// Generate peer secret key and peer id
    Peer,
    /// Generate the funding address with the Hex-Encoded private key in .env
    FundingAddress,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    dotenv::dotenv().ok();
    let actor = env::get_actor();
    let opt = Opts::parse();
    if let Some(Commands::Key(key_arg)) = opt.cmd {
        match key_arg.cmd {
            KeyCommands::Peer => {
                let local_key = generate_local_key();
                let base64_key = base64::engine::general_purpose::STANDARD
                    .encode(&local_key.to_protobuf_encoding()?);
                let peer_id = local_key.public().to_peer_id().to_string();
                println!("{ENV_PEER_KEY}={base64_key}");
                println!("PEER_ID={peer_id}");
            }
            KeyCommands::FundingAddress => {
                let public_key = get_node_pubkey()?;
                let p2wsh_addr = utils::node_p2wsh_address(get_network(), &public_key);
                println!("Funding P2WSH address (for operator and challenger): {p2wsh_addr}");
            }
        }
        return Ok(());
    }
    let _ = tracing_subscriber::fmt().with_env_filter(EnvFilter::from_default_env()).try_init();
    let mut metric_registry = Registry::default();

    // Create cancellation token for graceful shutdown
    let cancellation_token = CancellationToken::new();
    let mut task_handles: Vec<JoinHandle<Result<String, String>>> = vec![];
    // init bitvm2swarm
    let bitvm_network_manager = BitvmNetworkManager::new(
        Bitvm2SwarmConfig {
            local_key: env::get_peer_key(),
            p2p_port: opt.p2p_port,
            bootnodes: opt.bootnodes,
            topic_names: vec![
                Actor::Committee.to_string(),
                Actor::Challenger.to_string(),
                Actor::Operator.to_string(),
                Actor::Relayer.to_string(),
                Actor::All.to_string(),
            ],
            heartbeat_interval: env::HEARTBEAT_INTERVAL_SECOND,
            regular_task_interval: env::REGULAR_TASK_INTERVAL_SECOND,
        },
        &mut metric_registry,
    )?;
    let peer_id_string = bitvm_network_manager.get_peer_id_string();
    let local_db = bitvm2_noded::client::create_local_db(&opt.db_path).await;
    let handler = BitvmNodeProcessor {
        local_db: local_db.clone(),
        btc_client: BTCClient::new(None, env::get_network()),
        goat_client: GOATClient::new(env::goat_config_from_env().await, env::get_goat_network()),
        ipfs: IPFS::new(&get_ipfs_url()),
    };

    let actor_clone1 = actor.clone();
    let actor_clone2 = actor.clone();
    let local_db_clone1 = local_db.clone();
    let local_db_clone2 = local_db.clone();
    let opt_rpc_addr = opt.rpc_addr.clone();
    let peer_id_string_clone = peer_id_string.clone();
    let metric_registry_clone = Arc::new(Mutex::new(metric_registry));

    tracing::debug!("RPC service listening on {}", &opt.rpc_addr);
    if actor == Actor::Operator {
        set_node_external_socket_addr_env(&opt.rpc_addr).await?;
    }
    // validate node info
    check_node_info().await;
    save_local_info(&local_db).await;

    // Spawn RPC service task with cancellation support
    let cancel_token_clone = cancellation_token.clone();
    task_handles.push(tokio::spawn(async move {
        match rpc_service::serve(
            opt_rpc_addr,
            local_db_clone1,
            actor_clone1,
            peer_id_string_clone,
            metric_registry_clone,
            cancel_token_clone,
        )
        .await
        {
            Ok(tag) => Ok(tag),
            Err(e) => {
                tracing::error!("RPC service error: {}", e);
                Err("rpc_error".to_string())
            }
        }
    }));
    if actor == Actor::Relayer || actor == Actor::Operator || actor == Actor::Committee {
        let cancel_token_clone = cancellation_token.clone();
        task_handles.push(tokio::spawn(async move {
            match run_watch_event_task(actor_clone2, local_db_clone2, 5, cancel_token_clone).await {
                Ok(tag) => Ok(tag),
                Err(e) => {
                    tracing::error!("Watch event task error: {}", e);
                    Err("watch_error".to_string())
                }
            }
        }));
    }

    let swarm_actor = actor.clone();
    let cancel_token_clone = cancellation_token.clone();
    task_handles.push(tokio::spawn(async move {
        let result = tokio::task::spawn_blocking(move || {
            let rt = tokio::runtime::Handle::current();
            rt.block_on(async {
                start_handle_swarm_msg_task(
                    swarm_actor,
                    bitvm_network_manager,
                    handler,
                    cancel_token_clone,
                )
                .await
            })
        })
        .await;
        match result {
            Ok(tag) => Ok(tag),
            Err(e) => {
                tracing::error!("Swarm task spawn error: {}", e);
                Err("swarm_spawn_error".to_string())
            }
        }
    }));

    // Wait for shutdown signal or any task completion
    let task_count = task_handles.len();

    tokio::select! {
        (result, index, remaining_handles) = future::select_all(task_handles) => {
            // Log the specific failure
            let failure_reason = match &result {
                Ok(Ok(tag)) => {
                    tracing::warn!("Task {} completed unexpectedly: {}", index, tag);
                    "unexpected completion"
                }
                Ok(Err(error)) => {
                    tracing::error!("Task {} failed with business error: {}", index, error);
                    "business error"
                }
                Err(join_error) => {
                    tracing::error!("Task {} failed with join error: {}", index, join_error);
                    "join error"
                }
            };

            tracing::info!("Triggering shutdown due to {} in task {}/{}", failure_reason, index + 1, task_count);

            // Initiate graceful shutdown
            cancellation_token.cancel();

            // Wait a moment for graceful shutdown, then force abort remaining tasks
            tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

            // Force abort any tasks that didn't respond to cancellation
            remaining_handles.into_iter().for_each(|handle| handle.abort());

            tracing::info!("All tasks stopped");

            // Handle panic propagation
            if let Err(join_error) = result && join_error.is_panic() {
                    std::panic::resume_unwind(join_error.into_panic());

            }
        }
        _ = shutdown_signal() => {
            tracing::info!("Received shutdown signal, initiating graceful shutdown...");
            cancellation_token.cancel();

            // Give tasks some time to shutdown gracefully
            tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
            tracing::info!("Graceful shutdown completed");
        }
    }

    Ok(())
}

/// Listen for shutdown signals (Ctrl+C, SIGTERM, etc.)
async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c().await.expect("Failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("Failed to install signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {
            tracing::info!("Received Ctrl+C signal, starting graceful shutdown...");
        },
        _ = terminate => {
            tracing::info!("Received SIGTERM signal, starting graceful shutdown...");
        },
    }
}

pub async fn start_handle_swarm_msg_task(
    actor: Actor,
    mut swarm: BitvmNetworkManager,
    handler: BitvmNodeProcessor,
    cancellation_token: CancellationToken,
) -> String {
    swarm.run(actor, handler, cancellation_token).await.unwrap_or_else(|e| {
        tracing::error!("Swarm run error: {}", e);
        "swarm_error".to_string()
    })
}
