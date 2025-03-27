use std::{error::Error, time::Duration, net::Ipv4Addr};
use std::io::{Read, Write};
use clap::{Parser, Subcommand};
use libp2p::futures::StreamExt;
use libp2p::{
    kad,
    noise,
    swarm::{NetworkBehaviour, SwarmEvent},
    multiaddr::{Multiaddr, Protocol},
    tcp, yamux,
};
use libp2p::identity::Keypair;
use libp2p_metrics::{Registry, Metrics};

use opentelemetry::{trace::TracerProvider as _, KeyValue};
use opentelemetry_otlp::SpanExporter;
use opentelemetry_sdk::{runtime, trace::TracerProvider};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter, Layer};

use zeroize::Zeroizing;

use bitvm2_lib::actors::Actor;
use identity;

mod middleware;
mod rpc_service;
mod metrics_service;
mod config;

pub use middleware::authenticator;


#[derive(Debug, Parser)]
#[command(author, version, about, long_about = None)]
struct Opts {
    #[arg(short)]
    daemon: bool,

    /// Path to BootNode config file.
    //#[arg(long)]
    //config: std::path::PathBuf,

    /// Metric endpoint path.
    #[arg(long, default_value = "/metrics")]
    metrics_path: String,

    /// Whether to run the libp2p Kademlia protocol and join the BitVM2 DHT.
    #[arg(long, default_value = "true")]
    enable_kademlia: bool,

    // /// Whether to run the libp2p Autonat protocol.
    // #[arg(long)]
    // enable_autonat: bool,

    #[command(subcommand)]
    cmd: Option<Commands>
}

#[derive(Subcommand, Debug, Clone)]
enum Commands {
    Key(KeyArg),
    Set {
        key: String,
        value: String,
        is_true: bool
    },
}

#[derive(Parser, Debug, Clone)]
struct KeyArg {
    #[arg(long, default_value = "ed25519")]
    kind: String,
    #[arg(long, default_value = "/tmp/localkey.bin")]
    path: String,
    #[command(subcommand)]
    cmd: KeyCommands
}

#[derive(Subcommand, Debug, Clone)]
enum KeyCommands {
    Gen,
    Get,
}


#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let opt = Opts::parse();
    match opt.cmd {
        Some(Commands::Key(key_arg)) => {
            match key_arg.cmd {
                KeyCommands::Get => {
                    let mut fs = std::fs::File::open(&key_arg.path)?;
                    let mut key_encoded = vec![];
                    fs.read_to_end(&mut key_encoded)?;
                    let key = libp2p::identity::Keypair::from_protobuf_encoding(&key_encoded)?;
                    println!("{:?}", key);
                }
                KeyCommands::Gen => {
                    let local_key = identity::generate_local_key();
                    let mut fs = std::fs::File::create(&key_arg.path)?;
                    fs.write_all(&local_key.to_protobuf_encoding()?)?;
                }
            }
            return Ok(());
        }
        Some(Commands::Set { key, value, is_true }) => {
            return Ok(());
        }
        _ => {
            if ! opt.daemon {
                println!("help!");
                return Ok(());
            }
        },
    }
    // load role
    let actor = std::env::var("ACTOR").unwrap_or("Challenger".to_string());
    let actor = Actor::try_from(actor.as_str()).unwrap();
    println!("actor: {:?}", actor);

    let _ = tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .try_init();

    //let config = Zeroizing::new(config::Config::from_file(opt.config.as_path())?);

    let mut metric_registry = Registry::default();

    // FIXME: use local key https://github.com/libp2p/rust-libp2p/blob/master/misc/server/src/main.rs#L55
    let mut swarm = libp2p::SwarmBuilder::with_new_identity()
        .with_tokio()
        .with_tcp(
            tcp::Config::default(),
            noise::Config::new,
            yamux::Config::default,
        )?
        .with_bandwidth_metrics(&mut metric_registry)
        .with_behaviour(|key|crate::middleware::AllBehaviours::new(key))?
        .with_swarm_config(|cfg| cfg.with_idle_connection_timeout(Duration::from_secs(u64::MAX)))
        .build();
    // Tell the swarm to listen on all interfaces and a random, OS-assigned
    // port.
    swarm.listen_on("/ip4/0.0.0.0/tcp/0".parse()?)?;

    // // Dial the peer identified by the multi-address given as the second
    // // command-line argument, if any.
    // if let Some(addr) = std::env::args().nth(1) {
    //     println!("Dialing {addr}");
    //     let remote: libp2p::Multiaddr = addr.parse()?;
    //     swarm.dial(remote)?;
    //     println!("Dialed {addr}")
    // }

    let metrics = Metrics::new(&mut metric_registry);
    tokio::spawn(metrics_service::metrics_server(metric_registry));

    // run a http server for front-end

    let address = loop {
        if let SwarmEvent::NewListenAddr { address, .. } = swarm.select_next_some().await {
            if address
                .iter()
                .any(|e| e == Protocol::Ip4(Ipv4Addr::LOCALHOST))
            {
                tracing::debug!(
                    "Ignoring localhost address to make sure the example works in Firefox"
                );
                continue;
            }

            tracing::info!(%address, "Listening");

            break address;
        }
    };

    let addr = address.with(Protocol::P2p(*swarm.local_peer_id()));
    println!("Static file listening on {}", addr);
    tokio::spawn(rpc_service::serve(addr));


    loop {
        match swarm.select_next_some().await {
            SwarmEvent::NewListenAddr { address, .. } => println!("Listening on {address:?}"),
            SwarmEvent::Behaviour(event) => {
                // handle all the events
                println!("{event:?}")
            },
            _ => {}
        }
    }
    Ok(())
}
