use std::{error::Error, time::Duration};
use clap::Parser;
use libp2p::futures::StreamExt;
use libp2p::{
    kad,
    noise,
    swarm::{NetworkBehaviour, SwarmEvent},
    tcp, yamux,
};

use libp2p_metrics::{Registry, Metrics};

use opentelemetry::{trace::TracerProvider as _, KeyValue};
use opentelemetry_otlp::SpanExporter;
use opentelemetry_sdk::{runtime, trace::TracerProvider};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter, Layer};


use zeroize::Zeroizing;
use bitvm2_lib::actors::Actor;

mod middleware;
mod metrics_service;
mod config;

pub use middleware::authenticator;


#[derive(Debug, Parser)]
#[command(name = "libp2p server", about = "A rust-libp2p server binary.")]
struct Opts {
    /// Path to IPFS config file.
    #[arg(long)]
    config: std::path::PathBuf,

    /// Metric endpoint path.
    #[arg(long, default_value = "/metrics")]
    metrics_path: String,

    /// Whether to run the libp2p Kademlia protocol and join the IPFS DHT.
    #[arg(long)]
    enable_kademlia: bool,

    // /// Whether to run the libp2p Autonat protocol.
    // #[arg(long)]
    // enable_autonat: bool,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // load role
    let actor = std::env::var("ACTOR").unwrap_or("Challenger".to_string());
    let actor = Actor::try_from(actor.as_str()).unwrap();
    println!("actor: {:?}", actor);

    let _ = tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .try_init();

    let opt = Opts::parse();
    let config = Zeroizing::new(config::Config::from_file(opt.config.as_path())?);

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

    // Dial the peer identified by the multi-address given as the second
    // command-line argument, if any.
    if let Some(addr) = std::env::args().nth(1) {
        println!("Dialing {addr}");
        let remote: libp2p::Multiaddr = addr.parse()?;
        swarm.dial(remote)?;
        println!("Dialed {addr}")
    }

    let metrics = Metrics::new(&mut metric_registry);
    tokio::spawn(metrics_service::metrics_server(metric_registry));

    // TODO: run a http server for front-end
    // https://github.com/tokio-rs/tokio/blob/master/examples/tinyhttp.rs#L36

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
